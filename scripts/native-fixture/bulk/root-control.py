import hashlib,json,os,re,stat,subprocess,sys,threading
from pathlib import Path

def durable(file,value,mode=0o444):
 raw=json.dumps(value,separators=(',',':'),sort_keys=True).encode()+bytes([10])
 with os.fdopen(os.open(file,os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_WRONLY,0o400),'wb') as f:f.write(raw);f.flush();os.fchmod(f.fileno(),mode);os.fsync(f.fileno())
def main(file,pin):
 raw=Path(file).read_bytes()
 if (os.getuid(),os.getgid())!=(0,0) or hashlib.sha256(raw).hexdigest()!=pin:raise ValueError('exact Root manifest required')
 manifest=json.loads(raw);expected=Path('/bulk-backup-expected.json').read_bytes();token=json.loads(expected)
 if hashlib.sha256(expected).hexdigest()!=manifest['Cases'][token['case']]['Faults'][token['site']]['BackupSHA']:raise ValueError('exact expected Root backup token')
 # Separate read-only host mount: neither Go nor API can write this approval.
 approval=Path('/root-control/approval.json')
 owner=subprocess.Popen(['/usr/bin/setpriv','--reuid=10001','--regid=10001','--clear-groups','--inh-caps=-all','--ambient-caps=-all','--bounding-set=-all','--no-new-privs','/pluto-native-owner',file,pin],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 errors=[];actual={};done=threading.Event()
 def drain():
  try:
   while True:
    block=owner.stdout.read(65536)
    if not block:break
    sys.stdout.buffer.write(block);sys.stdout.buffer.flush()
  except BaseException as e:errors.append(str(e))
  finally:owner.stdout.close()
 def wait():
  while True:
   try:pid,status=os.waitpid(owner.pid,0);break
   except InterruptedError:continue
  owner.returncode=os.waitstatus_to_exitcode(status)
  actual.update(PID=pid,Observed=True,Exited=os.WIFEXITED(status),Signaled=os.WIFSIGNALED(status),ExitCode=os.WEXITSTATUS(status) if os.WIFEXITED(status) else None,Signal=os.WTERMSIG(status) if os.WIFSIGNALED(status) else 0,RawStatus=status)
  try:durable('/bulk-owner-actual-wait.json',actual)
  except BaseException as e:errors.append('numeric wait metadata write failed: '+str(e))
  finally:done.set()
 drain_thread=threading.Thread(target=drain);wait_thread=threading.Thread(target=wait);drain_thread.start();wait_thread.start();published=False
 while not done.wait(0.05):
  if published or not approval.exists():continue
  try:
   info=approval.lstat()
   if not stat.S_ISREG(info.st_mode) or info.st_size>65536:raise ValueError('bounded Root approval required')
   a=json.loads(approval.read_bytes())
   if a.get('schema')!='pluto.native-bulk-root-approval.v1' or a.get('manifestSHA256')!=pin:raise ValueError('Root approval manifest differs')
   for name in ('run','scope','nonce','containerId','case','site','base'):
    if a.get(name)!=token[name]:raise ValueError('Root approval scope differs: '+name)
   for name in ('graphSHA256','nativeBeforeSHA256','fullRestoreProofSHA256'):
    if not isinstance(a.get(name),str) or not re.fullmatch('[a-f0-9]{64}',a[name]):raise ValueError('exact restore proof SHA required')
   for name in ('postgreSQLRestored','fullSQLRowsCompared','physicalSFTPRestored','allPhysicalBytesCompared','actualProductReadback','authorityConfigRestored','originalIdentitiesRetained'):
    if a.get(name) is not True:raise ValueError('restore prerequisite missing: '+name)
   with os.fdopen(os.open('/bulk-backup-receipt.json',os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_WRONLY,0o400),'wb') as f:f.write(expected);f.flush();os.fchmod(f.fileno(),0o444);os.fsync(f.fileno())
   parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
   try:os.fsync(parent)
   finally:os.close(parent)
   durable('/bulk-root-authorization.json',dict(schema='pluto.bulk-root-authorization.v1',manifestSHA256=pin,approvalSHA256=hashlib.sha256(approval.read_bytes()).hexdigest(),backupReceiptSHA256=hashlib.sha256(expected).hexdigest(),graphSHA256=a['graphSHA256'],actualRootWriterPID=os.getpid(),ownerPID=owner.pid))
   print('BULK_ROOT_BACKUP_AUTHORIZED '+hashlib.sha256(expected).hexdigest(),flush=True);published=True
  except BaseException as e:
   errors.append('Root approval refused: '+str(e));published=True;print('BULK_ROOT_BACKUP_REFUSED',flush=True)
 wait_thread.join();drain_thread.join()
 durable('/bulk-root-controller-result.json',dict(schema='pluto.bulk-root-controller-result.v1',actualOwnerWait=actual,drainsJoined=True,rootBackupIssued=Path('/bulk-backup-receipt.json').exists(),errors=errors))
 print('BULK_OWNER_ACTUAL_WAIT '+json.dumps(actual,separators=(',',':')),flush=True)
 return owner.returncode if owner.returncode!=0 else (0 if not errors else 1)
if __name__=='__main__':raise SystemExit(main(*sys.argv[1:]))
