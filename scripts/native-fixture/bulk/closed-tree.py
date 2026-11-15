import hashlib,json,os,stat,sys,tarfile
from pathlib import Path

def fail(message):raise ValueError(message)
def digest(path):
 with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def durable(path,value):
 raw=json.dumps(value,separators=(',',':'),sort_keys=True).encode()+b'\n'
 with path.open('xb') as stream:
  os.chmod(path,0o600);stream.write(raw);stream.flush();os.fsync(stream.fileno())
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
def checked_root(value):
 root=Path(value)
 if not root.is_absolute() or str(root)!=os.path.normpath(root) or root.resolve()!=root or root.is_symlink() or not root.is_dir():fail('exact admitted root required')
 return root
def inventory(root,spec):
 rows=[];total=0
 def walk(path):
  nonlocal total
  info=path.lstat();relative=str(path.relative_to(root))
  expected_gid=spec.get('rootGID',spec['gid']) if path==root else spec['gid']
  if info.st_uid!=spec['uid'] or info.st_gid!=expected_gid:fail('actual component uid/gid differs')
  if path.is_symlink() or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):fail('unsupported component object')
  if os.listxattr(path,follow_symlinks=False):fail('extra ACL/xattrs need explicit archival support')
  directory=stat.S_ISDIR(info.st_mode)
  if not directory and info.st_nlink!=1:fail('single-link regular component file required')
  data=dict(name=relative,directory=directory,mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid,bytes=0 if directory else info.st_size,mtimeNS=info.st_mtime_ns,ctimeNS=info.st_ctime_ns,device=info.st_dev,inode=info.st_ino)
  if not directory:
   total+=info.st_size
   if total>spec['maximumBytes']:fail('component exceeds admitted physical bytes')
   data['sha256']=digest(path)
  rows.append(data)
  if len(rows)>spec['maximumEntries']:fail('component exceeds admitted entry count')
  if directory:
   for child in sorted(path.iterdir(),key=lambda p:p.name):walk(child)
 walk(root)
 return rows,total

def backup(spec):
 source=checked_root('/source');output=checked_root('/checkpoint')
 if any(output.iterdir()):fail('fresh private component checkpoint directory required')
 if 'pg'==spec['component'] and list(source.rglob('postmaster.pid')):fail('PostgreSQL must be actually stopped before cold copy')
 before,total=inventory(source,spec)
 archive=output/'component.tar'
 with archive.open('xb') as stream:
  os.chmod(archive,0o600)
  with tarfile.open(fileobj=stream,mode='w|',format=tarfile.PAX_FORMAT) as tar:
   for row in before:
    name=row['name'];original=source if name=='.' else source/name
    info=tarfile.TarInfo(name);info.mode=row['mode'];info.uid=row['uid'];info.gid=row['gid'];info.size=row['bytes'];info.type=tarfile.DIRTYPE if row['directory'] else tarfile.REGTYPE
    seconds,nanos=divmod(row['mtimeNS'],10**9);info.pax_headers={'mtime':f'{seconds}.{nanos:09d}'}
    if row['directory']:tar.addfile(info)
    else:
     with original.open('rb') as content:tar.addfile(info,content)
  stream.flush();os.fsync(stream.fileno())
 after,after_bytes=inventory(source,spec)
 if before!=after or total!=after_bytes:fail('closed original component changed during archive')
 proof=dict(schema='pluto.bulk-closed-component.v1',scope=spec['scope'],component=spec['component'],originalRoot='/source',uid=spec['uid'],gid=spec['gid'],files=sum(not row['directory'] for row in before),bytes=total,entries=before,archiveSHA256=digest(archive),archiveBytes=archive.stat().st_size,originalUnchanged=True,productOpened=False)
 durable(output/'component.json',proof)
 summary={key:proof[key] for key in ('schema','scope','component','uid','gid','files','bytes','archiveSHA256','archiveBytes','originalUnchanged','productOpened')};summary['inventorySHA256']=digest(output/'component.json')
 print(json.dumps(summary,separators=(',',':')))

def restore(spec):
 checkpoint=checked_root('/checkpoint');target=checked_root('/restore')
 if any(target.iterdir()):fail('fresh admitted independent restore root required')
 proof_path=checkpoint/'component.json';raw=proof_path.read_bytes()
 if len(raw)>16*1024*1024 or hashlib.sha256(raw).hexdigest()!=spec['inventorySHA256']:fail('exact component inventory SHA required')
 proof=json.loads(raw)
 if proof['schema']!='pluto.bulk-closed-component.v1' or proof['scope']!=spec['scope'] or proof['component']!=spec['component'] or not proof['originalUnchanged']:fail('wrong component proof')
 rows={row['name']:row for row in proof['entries']}
 if len(rows)!=len(proof['entries']) or len(rows)>spec['maximumEntries'] or '.' not in rows:fail('bounded complete inventory required')
 archive=checkpoint/'component.tar'
 if digest(archive)!=proof['archiveSHA256'] or archive.stat().st_size!=proof['archiveBytes']:fail('exact closed archive required')
 total=0;seen=set();directories=[]
 with tarfile.open(archive,'r|') as tar:
  for member in tar:
   name=member.name;relative=Path(name)
   if relative.is_absolute() or '..' in relative.parts or name not in rows or name in seen:fail('unadmitted archive member')
   seen.add(name);row=rows[name];path=target if name=='.' else target/relative
   if member.mode!=row['mode'] or member.uid!=row['uid'] or member.gid!=row['gid'] or member.size!=row['bytes'] or member.isdir()!=row['directory']:fail('archive metadata differs')
   expected_gid=spec.get('rootGID',spec['gid']) if name=='.' else spec['gid']
   if member.uid!=spec['uid'] or member.gid!=expected_gid:fail('exact archived component ownership differs')
   if member.isdir():
    if name!='.':path.mkdir(mode=0o700)
    directories.append((path,row))
   elif member.isfile():
    content=tar.extractfile(member)
    if content is None:fail('missing regular member body')
    h=hashlib.sha256();size=0
    with path.open('xb') as stream:
     while True:
      block=content.read(65536)
      if not block:break
      size+=len(block);total+=len(block);h.update(block)
      if total>spec['maximumBytes'] or size>row['bytes']:fail('restore exceeds admitted bytes')
      stream.write(block)
     stream.flush();os.fchmod(stream.fileno(),row['mode']);os.fsync(stream.fileno())
    if size!=row['bytes'] or h.hexdigest()!=row['sha256']:fail('actual restored body differs')
    os.utime(path,ns=(row['mtimeNS'],row['mtimeNS']),follow_symlinks=False)
    if 'rootGID' in spec:os.chown(path,row['uid'],row['gid'],follow_symlinks=False)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
   else:fail('links or special entries are not admitted')
 if seen!=set(rows) or total!=proof['bytes']:fail('complete archive graph required')
 for path,row in reversed(directories):
  os.chmod(path,row['mode']);os.utime(path,ns=(row['mtimeNS'],row['mtimeNS']),follow_symlinks=False)
  if 'rootGID' in spec:os.chown(path,row['uid'],row['gid'],follow_symlinks=False)
  fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(fd)
  finally:os.close(fd)
 actual,actual_bytes=inventory(target,spec)
 portable=lambda row:{key:value for key,value in row.items() if key not in ('device','inode','ctimeNS')}
 if [portable(row) for row in actual]!=[portable(row) for row in proof['entries']] or actual_bytes!=proof['bytes']:fail('actual complete restored metadata/bytes differs')
 if any((left['device'],left['inode'])==(right['device'],right['inode']) for left,right in zip(proof['entries'],actual)):fail('independent copied inodes required; original custody cannot be transplanted')
 result=dict(schema='pluto.bulk-closed-component-restore.v1',scope=spec['scope'],component=spec['component'],files=proof['files'],bytes=total,archiveSHA256=proof['archiveSHA256'],actualInventorySHA256=hashlib.sha256(json.dumps(actual,sort_keys=True,separators=(',',':')).encode()).hexdigest(),allPortableMetadataAndBytesEqual=True,independentInodes=True,relocatedCustodyClaimed=False,productOpened=False)
 print(json.dumps(result,separators=(',',':')))

def main(mode,file,expected):
 raw=Path(file).read_bytes()
 if hashlib.sha256(raw).hexdigest()!=expected:fail('exact closed component manifest required')
 spec=json.loads(raw)
 if spec['schema']!='pluto.bulk-closed-component-command.v1' or mode not in ('backup','restore'):fail('typed component command required')
 if type(spec['uid']) is not int or type(spec['gid']) is not int:fail('actual component uid/gid must be integers')
 mixed='rootGID' in spec
 if mixed and not (spec['component']=='pg' and spec['uid']==70 and spec['gid']==70 and spec['rootGID']==0):fail('only genuine qualified PG70:0 root exception admitted')
 expected_identity=(0,0) if mixed and mode=='restore' else (spec['uid'],spec['gid'])
 if (os.getuid(),os.getgid())!=expected_identity:fail('exact archive or new-copy restore process identity differs')
 status=Path('/proc/self/status').read_text().splitlines()
 for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'):
  expected_caps='0000000000000003' if mixed and mode=='restore' and key in ('CapPrm','CapEff','CapBnd') else '0000000000000000'
  if next(line.split()[1] for line in status if line.startswith(key+':'))!=expected_caps:fail('exact bounded archive/new-copy metadata capability set required')
 if next(line.split()[1] for line in status if line.startswith('NoNewPrivs:'))!='1':fail('no-new-privileges required')
 if type(spec['maximumBytes']) is not int or not 0<spec['maximumBytes']<=1024**3 or type(spec['maximumEntries']) is not int or not 0<spec['maximumEntries']<=16384:fail('explicit bounded graph required')
 if spec['component'] not in ('pg','sftp','fixture-config'):fail('unadmitted component')
 (backup if mode=='backup' else restore)(spec)
if __name__=='__main__':main(*sys.argv[1:])
