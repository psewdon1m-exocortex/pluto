import base64,hashlib,json,os,stat,sys
from pathlib import Path
assert (os.getuid(),os.getgid())==(10001,10001)
result={};total=0
for name in sys.argv[1:]:
 assert name and Path(name).name==name and name not in result
 p=Path('/source')/name;s=p.lstat();assert stat.S_ISREG(s.st_mode) and not p.is_symlink() and s.st_nlink==1
 body=p.read_bytes();total+=len(body);assert total<=16777216
 result[name]=dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest(),base64=base64.b64encode(body).decode())
print(json.dumps(dict(schema='pluto.bulk-ci-private-output.v1',files=result),separators=(',',':')))
