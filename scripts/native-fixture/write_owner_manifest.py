"""Root bootstrap for exact reviewed nonfault native cases; no archival reader substitution."""
import hashlib,json,os,re,secrets,socket,stat,sys,time
from pathlib import Path
def artifact(p,expected):
 f=Path(p);s=f.lstat();assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o555 and s.st_uid==s.st_gid==0
 assert 0<s.st_size<=128*1024*1024 and re.fullmatch('[a-f0-9]{64}',expected)
 with f.open('rb') as stream:actual=hashlib.file_digest(stream,'sha256').hexdigest()
 assert actual==expected;return dict(Path=p,SHA256=actual,Bytes=s.st_size)
def main(cid,owner_sha,test_sha,cli_sha,run,scope,root,case):
 assert os.getuid()==os.getgid()==0 and re.fullmatch('[a-f0-9]{64}',cid) and socket.gethostname()==cid[:12]
 assert re.fullmatch('/retained/endurance-ci-[a-f0-9]{16}',root)
 info=Path(root).lstat();assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode)==0o700 and info.st_uid==info.st_gid==10001
 assert all(re.fullmatch('[a-zA-Z0-9_.-]{1,128}',x) for x in (run,scope))
 policy=json.loads(Path('/owner-policy.json').read_bytes());assert policy['schema']=='pluto.native-owner-case-policy.v1'
 cases={k:v for k,v in policy['cases'].items() if k.split('/')[0]==case};assert cases
 assert all(set(v)=={'Actions','MaxFixtures'} and v['MaxFixtures']==1 and v['Actions'] and all(ms==45000 for ms in v['Actions'].values()) for v in cases.values())
 manifest=dict(Schema='nativefixture.owner.v2',Run=run,Scope=scope,Nonce=secrets.token_hex(16),ContainerID=cid,Hostname=cid[:12],Namespaces=[os.readlink('/proc/self/ns/'+n) for n in ('mnt','pid','user')],ExpiresUnixMs=time.time_ns()//1000000+900000,Socket=root+'/owner.sock',RetainedRoot=root,EvidenceRoot=root+'/evidence',Owner=artifact('/pluto-native-owner',owner_sha),GoTest=artifact('/pluto-native-metadata.test',test_sha),GoArgs=['-test.run=^'+case+'$','-test.count=1','-test.timeout=10m','-test.v'],Artifacts={'current':artifact('/pluto-current',cli_sha)},Cases=cases,Environment=['STAGE3_PLUTO_BINARY=/pluto-current','GOMAXPROCS=2'],OutputPrefixBytes=4*1024*1024)
 raw=json.dumps(manifest,separators=(',',':')).encode()+b'\n';assert len(raw)<=65536
 with open('/native-owner-manifest.json','xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 os.chmod('/native-owner-manifest.json',0o444);print(hashlib.sha256(raw).hexdigest())
if __name__=='__main__':main(*sys.argv[1:])
