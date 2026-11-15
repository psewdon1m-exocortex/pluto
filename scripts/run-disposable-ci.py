#!/usr/bin/env python3
"""Run the original negative installer rollback test in a fresh attested container.

The declared schema7 descriptor is a negative unit fixture, never an archival reader.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys

CASE='TestStage3C12NativeIncompatibleRollbackRetainsJournal'

ENTRY=r'''
import hashlib,json,os,subprocess,time
from pathlib import Path
root=Path('/retained');assert not list(root.iterdir());os.chmod(root,0o700)
backup=root/'backups';backup.mkdir(mode=0o700)
env=os.environ.copy()|{'PLUTO_ROLLBACK_BACKUP_DIR':str(backup),'GOMAXPROCS':'2'}
args=['/test-binary','-test.run=^TestStage3C12NativeIncompatibleRollbackRetainsJournal$','-test.count=1','-test.timeout=10m','-test.v']
with (root/'stdout.log').open('xb') as out:
 p=subprocess.Popen(args,env=env,stdout=out,stderr=subprocess.STDOUT)
 observed=None;observation_error=''
 try:
  for _ in range(200):
   try:
    exe=os.readlink('/proc/'+str(p.pid)+'/exe')
    if exe=='/test-binary':break
   except FileNotFoundError:pass
   time.sleep(.001)
  else:raise RuntimeError('actual Go afterexec tuple not observed')
  status=dict(line.split(':',1) for line in Path('/proc/'+str(p.pid)+'/status').read_text().splitlines() if ':' in line)
  stat=Path('/proc/'+str(p.pid)+'/stat').read_text()
  observed=dict(pid=p.pid,executable=exe,argv=Path('/proc/'+str(p.pid)+'/cmdline').read_bytes().split(bytes([0]))[:-1],stat=stat,
                profile={key:status[key].strip() for key in ('Uid','Gid','Groups','CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs','Seccomp')})
  observed['argv']=[x.decode() for x in observed['argv']]
  assert observed['argv']==args and observed['profile']['Uid'].split()==['0']*4
  assert all(int(observed['profile'][key],16)==0 for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
 except Exception as error:observation_error=str(error) or repr(error)
 finally:actual=p.wait()
record=dict(actualGoExit=actual,actualJoin=True,noKill=True,observed=observed,observationError=observation_error)
with (root/'actual-process.json').open('x') as f:json.dump(record,f)
raise SystemExit(actual if actual else (1 if observation_error else 0))
'''

COLLECT=r'''
import base64,hashlib,json,subprocess
from pathlib import Path
r=Path('/retained');files={}
for p in sorted(r.rglob('*')):
 if p.is_file():
  b=p.read_bytes();assert len(b)<=4194304
  files[p.relative_to(r).as_posix()]=dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),base64=base64.b64encode(b).decode())
converted=subprocess.run(['/converter','-t','-p','pluto/internal/pluto'],input=(r/'stdout.log').read_bytes(),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
assert converted.returncode==0 and not converted.stderr
b=converted.stdout;files['events.jsonl']=dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),base64=base64.b64encode(b).decode())
print(json.dumps(dict(files=files,converterActualExit=converted.returncode)))
'''

def digest(p):
    with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def save(p,value):
    with Path(p).open('x') as f:json.dump(value,f,indent=2);f.write('\n')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('output','test-binary','converter','image','docker','docker-host','run','workspace'):
        p.add_argument('--'+name,required=True)
    p.add_argument('--allow-running-id',action='append',default=[])
    a=p.parse_args();os.umask(0o077)
    output=Path(a.output).resolve();output.mkdir(mode=0o700,parents=True,exist_ok=False)
    command=[a.docker,'--host',a.docker_host]
    def docker(*args,data=None,check=True):
        r=subprocess.run(command+list(args),input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if check and r.returncode:raise RuntimeError('Docker '+args[0]+' failed: '+r.stderr.decode(errors='replace')[-2048:])
        return r
    def text(*args):return docker(*args).stdout.decode().strip()
    def bind(source,target):return ['--mount','type=bind,source='+str(Path(source).resolve())+',target='+target+',readonly']
    assert re.fullmatch('sha256:[a-f0-9]{64}',a.image) and a.run.startswith('release-candidate-')
    image=json.loads(text('image','inspect',a.image))[0]
    assert image['Id']==a.image and image['Architecture']=='amd64' and image['Os']=='linux'
    running=text('ps','--no-trunc','--format','{{.ID}}').splitlines();assert sorted(running)==sorted(a.allow_running_id)
    nonce=secrets.token_hex(32);scope='pluto-native-ci-'+nonce[:16]
    labels={'exocortex.ci.scope':scope,'exocortex.ci.case':CASE}
    values=['volume','create','--driver','local']
    for key,value in labels.items():values+=['--label',key+'='+value]
    volume=text(*values,scope+'-rollback-data');v=json.loads(text('volume','inspect',volume))[0]
    assert v['Labels']==labels and v['Driver']=='local' and not v.get('Options')
    marker=output/'fixture-marker.json';marker.write_bytes(b'')
    entry=output/'entry.py';entry.write_text(ENTRY);entry.chmod(0o444)
    create=['create','--name',scope,'--platform','linux/amd64','--network','none','--pull=never','--user','0:0',
            '--cap-drop','ALL','--security-opt','no-new-privileges','--cpus','2','--memory','512m','--memory-swap','512m','--pids-limit','64']
    for key,value in labels.items():create+=['--label',key+'='+value]
    for key,value in {'PLUTO_NATIVE_FIXTURE_RUN':a.run,'PLUTO_NATIVE_FIXTURE_NONCE':nonce,'PLUTO_NATIVE_FIXTURE_SCOPE':scope}.items():create+=['-e',key+'='+value]
    assert Path(a.workspace).is_absolute() and Path(a.workspace).is_dir() and not Path(a.workspace).is_symlink()
    create+=bind(a.test_binary,'/test-binary')+bind(entry,'/entry.py')+bind(marker,'/run/pluto-disposable-fixture.json')+bind(a.workspace,'/workspace')
    create+=['--mount','type=volume,source='+volume+',target=/retained,volume-nocopy','--entrypoint','python3',a.image,'-I','-B','/entry.py']
    cid=text(*create);c=json.loads(text('inspect',cid))[0];h=c['HostConfig']
    assert re.fullmatch('[a-f0-9]{64}',cid) and c['Image']==a.image and c['Config']['Hostname']==cid[:12]
    assert c['Config']['Labels']==((image['Config'].get('Labels') or {})|labels) and c['State']['Status']=='created'
    assert h['NetworkMode']=='none' and not h['Privileged'] and not h['AutoRemove'] and not h['CapAdd']
    assert h['Memory']==h['MemorySwap']==512*1024**2 and h['NanoCpus']==2*10**9 and h['PidsLimit']==64
    assert [x.removeprefix('CAP_') for x in h['CapDrop']]==['ALL'] and len(c['Mounts'])==5
    for target in ('/test-binary','/entry.py','/run/pluto-disposable-fixture.json','/workspace'):
        assert sum(x['Destination']==target and x['Type']=='bind' and not x['RW'] for x in c['Mounts'])==1
    assert sum(x['Destination']=='/retained' and x['Name']==volume and x['RW'] for x in c['Mounts'])==1
    attestation=dict(Schema='pluto.disposable-native-fixture.v1',Run=a.run,Scope=scope,Nonce=nonce,ContainerID=cid,Created=c['Created'],Image=a.image)
    with marker.open('wb') as f:f.write(json.dumps(attestation).encode());f.flush();os.fsync(f.fileno())
    marker.chmod(0o444)
    save(output/'producer-spec.json',dict(container=c,volume=v,argv=create,marker=attestation,testBinarySHA256=digest(a.test_binary),converterSHA256=digest(a.converter)))
    actual=docker('start','--attach',cid,check=False)
    (output/'container.stdout').write_bytes(actual.stdout);(output/'container.stderr').write_bytes(actual.stderr)
    c=json.loads(text('inspect',cid))[0]
    assert not c['State']['Running'] and not c['State']['OOMKilled']
    collected=json.loads(text('run','--rm','--pull=never','--network','none','--read-only','--user','0:0','--cap-drop','ALL','--security-opt','no-new-privileges',
        '--memory','128m','--memory-swap','128m','--pids-limit','32','--mount','type=volume,source='+volume+',target=/retained,readonly,volume-nocopy',
        *bind(a.converter,'/converter'),'--entrypoint','python3',a.image,'-I','-B','-c',COLLECT))
    for name,item in collected['files'].items():
        target=output/'evidence'/name;assert target.resolve().is_relative_to((output/'evidence').resolve())
        raw=base64.b64decode(item['base64'],validate=True);assert len(raw)==item['bytes']<=4194304 and hashlib.sha256(raw).hexdigest()==item['sha256']
        target.parent.mkdir(mode=0o700,parents=True,exist_ok=True);target.write_bytes(raw)
    process=json.loads((output/'evidence/actual-process.json').read_bytes())
    events=[json.loads(x) for x in (output/'evidence/events.jsonl').read_bytes().splitlines()]
    assert actual.returncode==c['State']['ExitCode']==process['actualGoExit']==0 and process['actualJoin'] and not process['observationError']
    assert [x['Action'] for x in events if x.get('Test')==CASE and x['Action'] in ('pass','fail','skip')]==['pass']
    assert not any(x['Action'] in ('skip','fail') for x in events)
    proofs=list((output/'evidence/backups').glob('snapshot-*/verified-backup.json'));assert len(proofs)==1
    before=json.loads(proofs[0].read_bytes());after=json.loads(proofs[0].with_name('verified-after.json').read_bytes())
    assert before['case']==after['case']==CASE and before['historicalReader'] is after['historicalReader'] is False
    assert not before['DBPresent'] and not before['configPresent'] and len(before['files'])==4
    assert after['originalFilesUnchanged'] and after['files']==before['files']
    assert sorted(text('ps','--no-trunc','--format','{{.ID}}').splitlines())==sorted(running)
    result=dict(status='PASS_SCOPED_ORIGINAL_DISPOSABLE_NEGATIVE_ROLLBACK',case=CASE,actualGoExit=process['actualGoExit'],actualContainerExit=c['State']['ExitCode'],
        actualAttachedExit=actual.returncode,containerId=cid,volume=v,process=process,sourceMarker=attestation,backup=before,after=after,
        historicalReader=False,historicalV8CompatibilityConfirmed=False,fullOrdinaryCiGreen=False,stoppedContainerAndBackupRetained=True)
    save(output/'result.json',result);print(json.dumps(dict(status=result['status'],case=CASE,actualGoExit=0)))
    return 0

if __name__=='__main__':raise SystemExit(main())
