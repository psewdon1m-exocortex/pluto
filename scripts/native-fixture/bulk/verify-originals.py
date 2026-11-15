import hashlib,json,os,stat,sys
from pathlib import Path

def main(file,expected):
 raw=Path(file).read_bytes()
 if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('exact Root-bound native verification input')
 spec=json.loads(raw);before_file=Path(spec['nativeBackupDirectory'])/'native-before.json';body=before_file.read_bytes()
 if hashlib.sha256(body).hexdigest()!=spec['nativeBeforeSHA256']:raise ValueError('genuine before-profile proof differs')
 before=json.loads(body)
 if before['requestID']!=spec['requestID'] or before['base']!=spec['base'] or before['case']!='TestCompletionNativeBulkReadbackPauseRestartNoCopies':raise ValueError('native exact scope differs')
 if not before['initialSQLiteAbsent'] or before['nativeChildStarted']:raise ValueError('genuine pre-first-child profile required')
 if len(before['originalPhysical'])>8192:raise ValueError('bounded original profile/source graph')
 checked=0
 for original in before['originalPhysical']:
  name=original['Path'];path=Path(name)
  if not name.startswith(spec['base']+'/') or path.resolve()!=path:raise ValueError('exact original path required')
  info=path.lstat()
  if info.st_uid!=os.getuid() or stat.S_ISLNK(info.st_mode):raise ValueError('original owner/type differs')
  row=dict(Path=name,Kind='directory',SHA256='',Device=info.st_dev,Inode=info.st_ino,Mode=info.st_mode,Bytes=info.st_size,MTimeNS=info.st_mtime_ns,CTimeNS=info.st_ctime_ns)
  if not stat.S_ISDIR(info.st_mode):
   if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise ValueError('single-link original file required')
   row['Kind']='file'
   with path.open('rb') as stream:row['SHA256']=hashlib.file_digest(stream,'sha256').hexdigest()
  if row!=original:raise ValueError('original inode/bytes/mode/time changed: '+name)
  checked+=1
 print(json.dumps(dict(schema='pluto.bulk-native-original-verification.v1',requestID=spec['requestID'],nativeBeforeSHA256=spec['nativeBeforeSHA256'],originalPhysicalUnchanged=True,entries=checked,actualUID=os.getuid(),nativeChildStarted=False),separators=(',',':')))
if __name__=='__main__':main(*sys.argv[1:])
