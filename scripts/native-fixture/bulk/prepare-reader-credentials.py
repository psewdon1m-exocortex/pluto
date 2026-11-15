import hashlib,json,os,stat,sys
from pathlib import Path

def main(input_file,expected):
 if (os.getuid(),os.getgid())!=(0,0):raise ValueError('own fresh credential provisioning root required')
 body=Path(input_file).read_bytes()
 if hashlib.sha256(body).hexdigest()!=expected:raise ValueError('exact owned reader input')
 target=Path('/credentials');source=Path('/authority')
 if target.is_symlink() or not target.is_dir() or any(target.iterdir()):raise ValueError('fresh private service-account credential volume')
 files=[(source/'ssh/client-key',target/'sftp-client-key'),(source/'ssh/sftp-env.private.json',target/'sftp-env.private.json')]
 directory=target/'sftp-secrets';directory.mkdir(mode=0o700)
 for name in ('owner','auth','drop','share','device','backup'):files.append((source/'sftp-secrets'/name,directory/name))
 proofs=[]
 for original,copy in files:
  info=original.lstat()
  if not stat.S_ISREG(info.st_mode) or original.is_symlink() or info.st_size>65536:raise ValueError('bounded genuine restored credential')
  content=original.read_bytes()
  with copy.open('xb') as f:os.fchmod(f.fileno(),0o600);f.write(content);f.flush();os.fsync(f.fileno())
  proofs.append(dict(name=copy.name,sha256=hashlib.sha256(content).hexdigest(),bytes=len(content)))
  os.chown(copy,10001,10001)
 spec=target/'reader-input.private.json'
 with spec.open('xb') as f:os.fchmod(f.fileno(),0o600);f.write(body);f.flush();os.fsync(f.fileno())
 os.chown(spec,10001,10001);os.chown(directory,10001,10001);os.chmod(target,0o700);os.chown(target,10001,10001)
 print(json.dumps(dict(schema='pluto.bulk-reader-service-credentials.v1',actualSource='genuine restored authority archive',newServiceUID=10001,sourceArchivesOrOriginalACLModified=False,inputSHA256=expected,files=proofs),separators=(',',':')))
if __name__=='__main__':main(*sys.argv[1:])
