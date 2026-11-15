import hashlib,json,os,re,secrets,socket,stat,sys,time
from pathlib import Path
CASE='TestCompletionNativeBulkReadbackPauseRestartNoCopies'
ROOT='/retained/endurance-bulk-current'
def artifact(file,expected):
 p=Path(file);s=p.lstat()
 if not re.fullmatch('[a-f0-9]{64}',expected) or not stat.S_ISREG(s.st_mode) or stat.S_IMODE(s.st_mode)!=0o555 or (s.st_uid,s.st_gid)!=(0,0) or not 0<s.st_size<=128*1024*1024:raise ValueError('exact Root-staged artifact required')
 with p.open('rb') as f:actual=hashlib.file_digest(f,'sha256').hexdigest()
 if actual!=expected:raise ValueError('Root-staged artifact SHA differs')
 return dict(Path=file,SHA256=expected,Bytes=s.st_size)
def write(file,raw,mode):
 with os.fdopen(os.open(file,os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_WRONLY,0o400),'wb') as f:f.write(raw);f.flush();os.fchmod(f.fileno(),mode);os.fsync(f.fileno())
def main(cid,owner_sha,test_sha,cli_sha,run,scope):
 if (os.getuid(),os.getgid())!=(0,0) or not re.fullmatch('[a-f0-9]{64}',cid) or socket.gethostname()!=cid[:12]:raise ValueError('actual isolated Root bootstrap/CID required')
 s=Path(ROOT).lstat()
 if not stat.S_ISDIR(s.st_mode) or stat.S_IMODE(s.st_mode)!=0o700 or (s.st_uid,s.st_gid)!=(10001,10001):raise ValueError('fresh private retained root required')
 for value in (run,scope):
  if not re.fullmatch('[a-zA-Z0-9_.-]{1,128}',value):raise ValueError('exact scope/run')
 nonce=secrets.token_hex(16)
 token=dict(schema='pluto.native-bulk-root-backup-authorization.v1',run=run,scope=scope,nonce=nonce,containerId=cid,case=CASE,site='bulk-lost-committed-ack',base=ROOT+'/f-0001',condition='genuine closed current PGDATA/SFTP/buffers/profile/source/TLS/authority archives; independent full SQL/schema/roles and physical restore; actual product readback; original identities retained')
 expected=json.dumps(token,separators=(',',':'),sort_keys=True).encode()+bytes([10]);write('/bulk-backup-expected.json',expected,0o400)
 manifest=dict(Schema='nativefixture.owner.v2',Run=run,Scope=scope,Nonce=nonce,ContainerID=cid,Hostname=cid[:12],Namespaces=[os.readlink('/proc/self/ns/'+name) for name in ('mnt','pid','user')],ExpiresUnixMs=time.time_ns()//1000000+3900000,Socket=ROOT+'/owner.sock',RetainedRoot=ROOT,EvidenceRoot=ROOT+'/evidence',Owner=artifact('/pluto-native-owner',owner_sha),GoTest=artifact('/pluto-native-metadata.test',test_sha),GoArgs=['-test.run=^'+CASE+'$','-test.count=1','-test.timeout=3600s','-test.v'],Artifacts=dict(current=artifact('/pluto-current',cli_sha)),Cases={CASE:dict(Actions=dict.fromkeys(['daemon','status','pause','resume','checkpoint','backup'],45000),MaxFixtures=1,Faults={'bulk-lost-committed-ack':dict(Site='bulk-lost-committed-ack',BackupPath='/bulk-backup-receipt.json',BackupSHA=hashlib.sha256(expected).hexdigest(),BarrierRequired=True)})},Environment=['STAGE3_PLUTO_BINARY=/pluto-current','GOMAXPROCS=2','COMPLETION_CONFIG='+ROOT+'/client-output/clients.private.json','COMPLETION_HOST_IP=127.0.0.1','ENDURANCE_TIER=8','ENDURANCE_SYNC_FILES=32','PLUTO_BULK_BACKUP_DIR=/checkpoint/native','PLUTO_BULK_CHECKPOINT_TOKEN_FILE='+ROOT+'/client-output/checkpoint-token','STAGE3_C_EVIDENCE='+ROOT+'/client-output'],OutputPrefixBytes=1048576)
 raw=json.dumps(manifest,separators=(',',':')).encode()+bytes([10]);write('/bulk-manifest.json',raw,0o444);print(hashlib.sha256(raw).hexdigest())
if __name__=='__main__':main(*sys.argv[1:])
