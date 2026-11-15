import base64,hashlib,json,os,sqlite3,stat,sys
from pathlib import Path
h=lambda b:hashlib.sha256(b).hexdigest()
def read(p):return json.loads(Path(p).read_bytes())
def gojson(v):
 s=json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)
 for c,e in [('&',r'\u0026'),('<',r'\u003c'),('>',r'\u003e'),(chr(8232),r'\u2028'),(chr(8233),r'\u2029')]:s=s.replace(c,e)
 return s
raw=Path(sys.argv[1]).read_bytes();assert h(raw)==sys.argv[2];cfg=json.loads(raw)
assert cfg['schema']=='pluto.native-bulk-final-cold-command.v1' and (os.getuid(),os.getgid())==(10001,10001)
status=Path('/proc/self/status').read_text().splitlines()
for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'):assert next(l.split()[1] for l in status if l.startswith(key+':'))=='0000000000000000'
assert next(l.split()[1] for l in status if l.startswith('NoNewPrivs:'))=='1'
case='TestCompletionNativeBulkReadbackPauseRestartNoCopies';backup=Path(cfg['nativeBackupDirectory']);assert str(backup).startswith('/checkpoint/native/bulk-closed-')
beforeRaw=(backup/'native-before.json').read_bytes();assert h(beforeRaw)==cfg['nativeBeforeSHA256'];before=json.loads(beforeRaw)
afterRaw=(backup/'native-after.json').read_bytes();assert len(afterRaw)<=16777216;after=json.loads(afterRaw)
assert after['schema']=='pluto.native-bulk-local-result.v1' and after['case']==case and after['requestID']==cfg['requestID']
assert before['requestID']==cfg['requestID'] and after['nativeArchiveSHA256']==before['archiveSHA256']==cfg['nativeArchiveSHA256']
assert after['nativeDaemonJoinedBeforeProof'] and after['lostCommittedAckObserved'] and after['actualSourceFiles']==32
assert after['checkpoint']['originalBackendResumed'] and after['checkpoint']['graphSHA256']==cfg['graphSHA256']
for key in ('state','source','config','ca'):assert after[key]==cfg[key]
expected=after['expectedFinal'];assert len(expected)==32
physical=after['finalPhysical'];assert len(physical)<=8192;paths={r['Path']:r for r in physical};assert len(paths)==len(physical)
for row in physical:
 p=Path(row['Path']);s=p.lstat();assert not p.is_symlink() and s.st_uid==10001
 assert (s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(row['Device'],row['Inode'],row['Mode'],row['Bytes'],row['MTimeNS'],row['CTimeNS'])
 if row['Kind']=='file':assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and h(p.read_bytes())==row['SHA256']
 else:assert row['Kind']=='directory' and stat.S_ISDIR(s.st_mode)
source=Path(after['source']);actual={str(p.relative_to(source)):h(p.read_bytes()) for p in source.rglob('*') if p.is_file()};assert actual==expected
protected=0
for old in before['originalPhysical']:
 p=old['Path']
 if p in (after['config'],after['ca']) or p==after['source'] or p.startswith(after['source']+'/'):
  now=paths[p]
  if p==after['source']+'/example.md':assert (old['Device'],old['Inode'],old['Mode'])==(now['Device'],now['Inode'],now['Mode'])
  elif p==after['config']:
   assert all(old[k]==now[k] for k in ('Device','Mode','Kind','Bytes','SHA256'))
   assert json.loads((backup/'restored/config.json').read_bytes())==json.loads(Path(after['config']).read_bytes())
  else:assert old==now
  protected+=1
file=Path(after['state'])/'indexed/sync-state.sqlite';assert h(file.read_bytes())==after['profileSQLiteSHA256']==cfg['profileSQLiteSHA256']
for suffix in ('-wal','-journal'):
 p=Path(str(file)+suffix);assert not p.exists() or p.stat().st_size==0
con=sqlite3.connect(file.as_uri()+'?mode=ro&immutable=1',uri=True);assert con.execute('PRAGMA integrity_check').fetchall()==[('ok',)]
version=con.execute('PRAGMA user_version').fetchone()[0];assert version==8
schema=[list(r) for r in con.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")]
payload={'version':version,'schema':schema};count=0;tables={};operationStages={}
for name in sorted(r[1] for r in schema if r[0]=='table'):
 cursor=con.execute('SELECT * FROM "'+name.replace('"','""')+'"');columns=[c[0] for c in cursor.description];strings=[];records=[]
 for row in cursor:
  values=[base64.b64encode(v).decode() if isinstance(v,bytes) else v for v in row];assert not any(isinstance(v,float) for v in values)
  strings.append(gojson(values));records.append(dict(zip(columns,values)));count+=1
 strings.sort();payload[name]={'columns':columns,'rows':strings or None};tables[name]=len(strings)
 if name=='operations':
  for r in records:operationStages[r['stage']]=operationStages.get(r['stage'],0)+1
con.close();assert count==after['profileLogicalRows'];logical=gojson(payload).encode();assert h(logical)==after['profileLogicalSHA256']
bulkFile=Path('/retained/endurance-bulk-current/client-output/pluto-bulk.json');bulkRaw=bulkFile.read_bytes();bulk=json.loads(bulkRaw)
assert bulk['status']=='PASS' and bulk['count']==32 and bulk['pauseRestart'] and bulk['pauseResumeSameProcess'] and bulk['bulkLostAckCrashRecovery'] and bulk['localManifest']==expected
owner=read('/retained/endurance-bulk-current/evidence/owner-final.json');assert owner['all_products_joined'] and owner['no_adopted_children'] and not owner['failures']
g=owner['go_actual'];assert g['Observed'] and g['Exited'] and not g['Signaled'] and g['ExitCode']==g['RawStatus']==0 and g['PID']==cfg['goPID']
waits={}
def collect(v):
 if isinstance(v,dict):
  if {'PID','Observed','Exited','Signaled','ExitCode','Signal','RawStatus'}<=set(v) and v['Observed']:waits[(v['PID'],v['RawStatus'])]=v
  for x in v.values():collect(x)
 elif isinstance(v,list):
  for x in v:collect(x)
for p in Path('/retained/endurance-bulk-current/evidence').rglob('*.json'):
 assert p.is_file() and not p.is_symlink() and p.stat().st_size<=4194304
 collect(json.loads(p.read_bytes()))
crashes=[w for w in waits.values() if w['Signaled'] and w['Signal']==9];assert len(crashes)==1
out=Path('/out')
for name,data in [('native-after.json',afterRaw),('pluto-bulk.json',bulkRaw),('sqlite-logical.json',logical)]:
 with (out/name).open('xb') as f:os.fchmod(f.fileno(),0o600);f.write(data);f.flush();os.fsync(f.fileno())
result=dict(schema='pluto.native-bulk-final-cold.v1',status='PASS_INDEPENDENT_NATIVE_FINAL_SQLITE_SOURCE_AND_ACTUAL_WAITS',requestID=cfg['requestID'],nativeAfterSHA256=h(afterRaw),bulkSHA256=h(bulkRaw),profileSQLiteSHA256=after['profileSQLiteSHA256'],logicalSHA256=h(logical),tables=tables,rows=count,operationStages=operationStages,sourceFiles=len(actual),protectedOriginalsCompared=protected,deliberateEditedFileSameInode=True,allFinalPhysicalUnchanged=True,goActual=g,reviewedCrashWaits=crashes,actualWaits=list(waits.values()),historicalReaderExecuted=False,fullCI=False)
with (out/'result.json').open('x') as f:os.fchmod(f.fileno(),0o600);json.dump(result,f,separators=(',',':'));f.write(chr(10));f.flush();os.fsync(f.fileno())
print(json.dumps(dict(status=result['status'],tables=len(tables),rows=count,sourceFiles=len(actual),reviewedCrashes=len(crashes)),separators=(',',':')))
