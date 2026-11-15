#!/usr/bin/env python3
"""Produce one of three reviewed native CI scopes; preserve actual receipts and volumes."""
import argparse
import base64
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time

PROJECT=Path(__file__).resolve().parents[1]
HELPERS=PROJECT/'scripts/native-fixture'
CASE='TestStage3C01OrdinaryDaemonRestartBackupSemantics'
CASES={"c01":"TestStage3C01OrdinaryDaemonRestartBackupSemantics","proxy":"TestCompletionDaemonProxyReopenRetainsDeletedSourceOriginal","route":"TestCompletionDaemonRestartsAfterOwnedRouteLossWithoutFileEvent"}


def reporter():
    spec=importlib.util.spec_from_file_location('c01_ci_report',PROJECT/'scripts/check-go-ci.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def digest(file):
    with Path(file).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def publish(file,value,mode=0o600):
    with Path(file).open('x',encoding='utf-8') as stream:
        os.chmod(file,mode);json.dump(value,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())


def host_available_gib():
    if os.name=='nt':
        class Memory(ctypes.Structure):
            _fields_=[('length',ctypes.c_ulong),('load',ctypes.c_ulong)]+[(name,ctypes.c_ulonglong) for name in
                ('totalPhysical','availablePhysical','totalPage','availablePage','totalVirtual','availableVirtual','extended')]
        value=Memory();value.length=ctypes.sizeof(value)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(value)):raise OSError('host RAM observation failed')
        return value.availablePhysical/2**30
    text=Path('/proc/meminfo').read_text()
    match=re.search(r'^MemAvailable:\s+(\d+)\s+kB$',text,re.M)
    if not match:raise ValueError('host available RAM unproven')
    return int(match[1])/2**20


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case',choices=tuple(CASES.values()),default=CASE)
    parser.add_argument('--record-source',type=Path)
    parser.add_argument('--source-inputs',type=Path)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--test-binary',type=Path)
    parser.add_argument('--cli',type=Path)
    parser.add_argument('--owner',type=Path)
    parser.add_argument('--converter',type=Path)
    parser.add_argument('--image')
    parser.add_argument('--docker',default=shutil.which('docker'))
    parser.add_argument('--docker-host')
    parser.add_argument('--allow-running-id',action='append',default=[])
    args=parser.parse_args()
    case=args.case
    label=next(label for label,value in CASES.items() if value==case)
    report=reporter()
    if args.record_source:
        publish(args.record_source,dict(schema='pluto.c01-ci-source.v1',testBinarySHA256=None,inputs=report.c01_source_inputs(PROJECT)))
        return 0
    for name in ('source_inputs','output','test_binary','cli','owner','converter','image','docker'):
        if getattr(args,name) is None:raise ValueError('required producer argument: '+name)
    if not re.fullmatch(r'sha256:[a-f0-9]{64}',args.image):raise ValueError('immutable Linux amd64 image ID required')
    output=args.output.resolve();output.mkdir(mode=0o700,parents=True,exist_ok=False)
    for name in ('test_binary','cli','owner','converter'):
        file=getattr(args,name).resolve()
        if file.is_symlink() or not file.is_file() or not 0<file.stat().st_size<=128*1024*1024:raise ValueError('bounded regular artifact required: '+name)
        setattr(args,name,file)
    source=json.loads(args.source_inputs.read_bytes())
    if source.get('schema')!='pluto.c01-ci-source.v1' or source.get('inputs')!=report.c01_source_inputs(PROJECT):
        raise ValueError('source inputs changed since the explicit pre-build record')
    source['testBinarySHA256']=digest(args.test_binary)
    bound_source=output/'bound-source-inputs.json';publish(bound_source,source,0o444)
    command=[args.docker]+(['--host',args.docker_host] if args.docker_host else [])
    def docker(*values,data=None,capture=True):
        done=subprocess.run(command+list(values),input=data,stdout=subprocess.PIPE if capture else None,stderr=subprocess.PIPE if capture else None,check=False)
        if done.returncode:raise RuntimeError('Docker '+values[0]+' failed: '+(done.stderr or b'').decode(errors='replace')[-4096:])
        return done.stdout.decode().strip() if capture else done.returncode
    running=docker('ps','--no-trunc','--format','{{.ID}}').splitlines()
    if sorted(running)!=sorted(args.allow_running_id):raise ValueError('running workload differs from explicit admission inventory')
    image=json.loads(docker('image','inspect',args.image))[0]
    if image['Id']!=args.image or image['Os']!='linux' or image['Architecture']!='amd64':raise ValueError('qualified Linux amd64 runtime image required')
    ram=host_available_gib();disk=shutil.disk_usage(output).free/2**30
    if ram<11 or disk<85:raise ValueError('Native admission requires11GiB free RAM (8GiB reserve+2GiB cap+1GiB margin) and85GiB free disk')
    vm=float(docker('run','--rm','--pull=never','--network','none','--read-only','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges','--cpus','1','--memory','128m','--memory-swap','128m','--pids-limit','32',args.image,'python3','-I','-B','-c',"from pathlib import Path;print(int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))/1048576)"))
    if vm<11:raise ValueError('Docker VM available RAM below11GiB')
    publish(output/'admission.json',dict(hostRamGiB=ram,vmAvailableGiB=vm,diskGiB=disk,reserveRamGiB=8,containerCapGiB=2,allowedRunning=running))
    nonce=secrets.token_hex(8);prefix='pluto-native-'+label+'-ci-'+nonce
    labels={'exocortex.ci.scope':prefix,'exocortex.ci.case':case}
    volumes=[]
    for suffix in ('data','checkpoint'):
        name=prefix+'-'+suffix
        if name in docker('volume','ls','--format','{{.Name}}').splitlines():raise ValueError('fresh volume name occupied')
        values=['volume','create','--driver','local']
        for key,value in labels.items():values+=['--label',key+'='+value]
        if docker(*values,name)!=name:raise ValueError('volume creation identity differs')
        observed=json.loads(docker('volume','inspect',name))[0]
        if observed['Labels']!=labels or observed['Driver']!='local' or observed['Scope']!='local' or observed.get('Options'):raise ValueError('new local volume metadata differs')
        volumes.append(observed)
    retained='/retained/endurance-ci-'+nonce
    create=['create','--rm','--interactive','--pull=never','--name',prefix,'--label','exocortex.ci.scope='+prefix,'--platform','linux/amd64','--network','none','--cap-drop','ALL']
    for capability in ('CHOWN','SETPCAP','SETUID','SETGID'):create+=['--cap-add',capability]
    create+=['--security-opt','no-new-privileges','--user','0:0','--cpus','2','--memory','2g','--memory-swap','2g','--pids-limit','64','--tmpfs','/tmp:rw,nosuid,nodev,size=96m']
    def bind(file,target):return ['--mount','type=bind,source='+str(file.resolve()).replace('\\','/')+',target='+target+',readonly']
    for name,target in [('test_binary','/test-input'),('cli','/cli-input'),('owner','/owner-input')]:create+=bind(getattr(args,name),target)
    helper_files=('run_c01_checkpoint.sh','write_c01_checkpoint_manifest.py','c01_checkpoint_worker.py','c01_checkpoint_control.py') if case==CASE else ('run_network_checkpoint.sh','write_network_checkpoint_manifest.py','network_checkpoint_worker.py','network_checkpoint_control.py')
    for file,target in zip(helper_files,('/native-prepared-entry.sh','/native-prepared-manifest-writer.py','/backup-worker-input','/backup-control-input')):create+=bind(HELPERS/file,target)
    create+=['--mount','type=volume,source='+volumes[0]['Name']+',target=/retained,volume-nocopy','--mount','type=volume,source='+volumes[1]['Name']+',target=/checkpoint,volume-nocopy','--entrypoint','/bin/sh',args.image,'/native-prepared-entry.sh',digest(args.owner),digest(args.test_binary),digest(args.cli),prefix,prefix,retained,'/checkpoint']
    if case!=CASE:create.append(case)
    cid=docker(*create)
    if not re.fullmatch('[a-f0-9]{64}',cid):raise ValueError('exact created CID required')
    observed=json.loads(docker('inspect',cid))[0];host=observed['HostConfig']
    if (observed['Id']!=cid or observed['Image']!=args.image or observed['Config']['Hostname']!=cid[:12] or
        observed['Name']!='/'+prefix or observed['State']['Status']!='created' or host['Privileged'] or
        host['NetworkMode']!='none' or not host['AutoRemove'] or host['Memory']!=2*2**30 or host['MemorySwap']!=host['Memory'] or
        host['PidsLimit']!=64 or host['NanoCpus']!=2*10**9 or observed['Config']['User']!='0:0' or
        sorted(cap.removeprefix('CAP_') for cap in host['CapAdd'])!=['CHOWN','SETGID','SETPCAP','SETUID'] or
        [cap.removeprefix('CAP_') for cap in host['CapDrop']]!=['ALL'] or
        host['SecurityOpt'] not in (['no-new-privileges'],['no-new-privileges=true'],['no-new-privileges:true'])):raise ValueError('created native container admission differs')
    publish(output/'producer-spec.json',dict(schema='pluto.native-ci-producer.v1',case=case,containerId=cid,image=args.image,retainedRoot=retained,volumes=volumes,argv=create,sourceInputs=source,artifacts={name:dict(path=str(getattr(args,name)),sha256=digest(getattr(args,name))) for name in ('test_binary','cli','owner','converter')}))
    with (output/'producer.stdout.log').open('xb') as stdout,(output/'producer.stderr.log').open('xb') as stderr:
        runtime=subprocess.run(command+['start','--attach','--interactive',cid],input=(cid+'\n').encode(),stdout=stdout,stderr=stderr,check=False)
    publish(output/'execution.json',dict(schema='pluto.native-ci-execution.v1',case=case,containerId=cid,actualAttachedExit=runtime.returncode,ordinarySuiteExecuted=False))
    if runtime.returncode:return runtime.returncode
    if sorted(docker('ps','--no-trunc','--format','{{.ID}}').splitlines())!=sorted(running):raise ValueError('native runtime did not leave original workload inventory')
    collector=['run','--rm','--pull=never','--name',prefix+'-collector','--platform','linux/amd64','--network','none','--read-only','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges','--cpus','1','--memory','128m','--memory-swap','128m','--pids-limit','32']
    collector+=['--mount','type=volume,source='+volumes[0]['Name']+',target=/retained,readonly,volume-nocopy','--mount','type=volume,source='+volumes[1]['Name']+',target=/checkpoint,readonly,volume-nocopy']
    collector+=bind(HELPERS/'export_c01_ci.py','/export.py')+bind(args.converter,'/converter')+bind(bound_source,'/source-inputs.json')
    collector+=['--entrypoint','python3',args.image,'-I','-B','/export.py','--retained',retained,'--converter','/converter','--converter-sha',digest(args.converter),'--source-inputs','/source-inputs.json','--case',case]
    packet=json.loads(docker(*collector))
    if packet.get('schema')!='pluto.native-ci-export.v1' or packet.get('case')!=case or packet.get('converterActualExit')!=0:raise ValueError('actual native collector failed')
    expected={'events.jsonl','stdout.log','actual-wait.json','joined-streams.json','prepared-before-Start.json','observed-after-exec.json','owner-final.json','source-inputs.json'}
    if set(packet.get('files',{}))!=expected:raise ValueError('exact native evidence file set required')
    for name,item in packet['files'].items():
        data=base64.b64decode(item['base64'],validate=True)
        if len(data)!=item['bytes'] or len(data)>4*1024*1024 or hashlib.sha256(data).hexdigest()!=item['sha256']:raise ValueError('exported native evidence digest differs')
        with (output/name).open('xb') as stream:os.chmod(output/name,0o600);stream.write(data);stream.flush();os.fsync(stream.fileno())
    _,code,proof=report.native_shard(output,PROJECT,case)
    if code!=0:raise ValueError('native native Go actual exit nonzero')
    publish(output/'producer-result.json',dict(schema='pluto.native-ci-producer-result.v1',case=case,status='PASS_REQUIRED_NATIVE_SCOPE',actualAttachedExit=runtime.returncode,converterActualExit=packet['converterActualExit'],proof=proof,volumesPreserved=[v['Name'] for v in volumes],fullOrdinaryCiGreen=False))
    print(json.dumps(dict(status='PASS_REQUIRED_NATIVE_SCOPE',case=case,evidence=str(output),actualGoExit=code,fullOrdinaryCiGreen=False)))
    return 0


if __name__=='__main__':raise SystemExit(main())
