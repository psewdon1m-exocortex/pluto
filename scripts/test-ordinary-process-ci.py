#!/usr/bin/env python3
"""Kernel lifecycle model only: dead adopted children are reaped; live children fail admission."""
import argparse
import hashlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys

ENTRY = r'''
import importlib.util,json,os,signal,threading,time
from pathlib import Path
assert os.getpid()==1 and os.getuid()==os.getgid()==10001
status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
assert all(int(status[key],16)==0 for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
assert status['NoNewPrivs'].strip()=='1' and status['Seccomp'].strip()=='2'
spec=importlib.util.spec_from_file_location('reviewed_ordinary_worker','/worker.py')
worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(worker)
results={}
for mode in ('terminal-killed','live'):
 evidence=Path('/evidence')/mode;evidence.mkdir(mode=0o700)
 ready_r,ready_w=os.pipe();gate_r,gate_w=os.pipe()
 parent=os.fork()
 if parent==0:
  child=os.fork()
  if child==0:
   os.close(ready_r);os.close(gate_w);os.write(ready_w,b'R');os.close(ready_w)
   os.read(gate_r,1);os._exit(0)
  os.close(ready_w);os.close(gate_r);os.read(ready_r,1)
  if mode=='terminal-killed':
   os.kill(child,signal.SIGKILL)
   while True:
    event=os.waitid(os.P_PID,child,os.WEXITED|os.WNOHANG|os.WNOWAIT)
    if event is not None:break
    time.sleep(.001)
  os._exit(0)
 os.close(ready_r);os.close(ready_w);os.close(gate_r)
 pid,raw=os.waitpid(parent,0);assert pid==parent and os.WIFEXITED(raw) and os.WEXITSTATUS(raw)==0
 release=None
 if mode=='live':
  def release_after_observation():
   deadline=time.monotonic()+2
   while not (evidence/'adopted-children-pending.json').exists() and time.monotonic()<deadline:time.sleep(.001)
   os.write(gate_w,b'G');os.close(gate_w)
  release=threading.Thread(target=release_after_observation);release.start()
 result=worker.reap_adopted(evidence)
 if release:release.join()
 else:os.close(gate_w)
 assert result['allAdoptedChildrenReapedBeforePID1Exit'] and result['noKill'] and not worker.children()
 assert len(result['adoptedWaits'])==1 and not result['unreviewedAfterInitial']
 if mode=='terminal-killed':
  item=result['adoptedWaits'][0];assert result['noLiveAdoptedChildren'] and not result['liveAtRootExit']
  assert item['kernelTerminalBeforeReap'] and os.WIFSIGNALED(item['rawStatus']) and os.WTERMSIG(item['rawStatus'])==9
 else:
  assert not result['noLiveAdoptedChildren'] and len(result['liveAtRootExit'])==1
  assert result['adoptedWaits'][0]['result']=='LIVE_AT_BOUNDARY_DESCENDANT_JOINED_LATER'
 results[mode]=result
print(json.dumps(dict(status='PASS_SCOPED_KERNEL_OBSERVER_MODEL_ONLY',cases=results,productTestsExecuted=0,noForcedCleanup=True)),flush=True)
'''


def declared_running_ids(raw):
    try:
        value = json.loads(raw)
    except (TypeError, ValueError) as error:
        raise ValueError('Explicit running container inventory must be JSON') from error
    if not isinstance(value, list) or any(not isinstance(item, str) or not re.fullmatch(r'[a-f0-9]{64}', item) for item in value):
        raise ValueError('Explicit running container inventory requires full lowercase Docker IDs')
    if len(value) != len(set(value)):
        raise ValueError('Explicit running container inventory contains duplicate IDs')
    return sorted(value)


def require_running_inventory(observed, declared):
    if sorted(observed) != declared:
        raise ValueError('Running workload differs from the explicit admission inventory')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--docker', default=os.environ.get('PLUTO_GO_CI_DOCKER', 'docker'))
    parser.add_argument('--docker-host', default=os.environ.get('PLUTO_GO_CI_DOCKER_HOST') or os.environ.get('DOCKER_HOST') or 'unix:///var/run/docker.sock')
    args = parser.parse_args()
    allowed = declared_running_ids(os.environ.get('PLUTO_GO_CI_C01_ALLOWED_RUNNING_IDS', '[]'))
    assert re.fullmatch('sha256:[a-f0-9]{64}', args.image)
    output = Path(args.output).resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    worker = Path(__file__).parent / 'native-fixture/ordinary/worker.py'
    worker_copy = output / 'readonly-worker.py'
    with worker_copy.open('xb') as stream:
        stream.write(worker.read_bytes())
        os.fchmod(stream.fileno(), 0o444)
        stream.flush()
        os.fsync(stream.fileno())
    command = [args.docker, '--host', args.docker_host]

    def docker(*values):
        process = subprocess.run(command + list(values), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if process.returncode:
            raise RuntimeError('observer Docker ' + values[0] + ': ' + process.stderr.decode(errors='replace'))
        return process.stdout.decode().strip()

    running = sorted(docker('ps', '--no-trunc', '--format', '{{.ID}}').splitlines())
    require_running_inventory(running, allowed)
    image = json.loads(docker('image', 'inspect', args.image))[0]
    assert image['Id'] == args.image and image['Os'] == 'linux' and image['Architecture'] == 'amd64'
    name = 'pluto-observer-model-' + secrets.token_hex(8)
    cid = docker('create', '--name', name, '--pull=never', '--init=false', '--network', 'none',
        '--read-only', '--user', '10001:10001', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
        '--memory', '128m', '--memory-swap', '128m', '--cpus', '1', '--pids-limit', '16',
        '--label', 'exocortex.ci.scope=' + name,
        '--tmpfs', '/evidence:rw,nosuid,nodev,size=1m,mode=0700,uid=10001,gid=10001',
        '--mount', 'type=bind,source=' + str(worker_copy) + ',target=/worker.py,readonly',
        '--entrypoint', 'python3', args.image, '-I', '-B', '-c', ENTRY)
    info = json.loads(docker('inspect', cid))[0]
    assert info['Image'] == args.image and info['State']['Status'] == 'created'
    (output / 'created-container.json').write_text(json.dumps(info, indent=2))
    actual = subprocess.run(command + ['start', '-a', cid], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (output / 'stdout.log').write_bytes(actual.stdout)
    (output / 'stderr.log').write_bytes(actual.stderr)
    terminal = json.loads(docker('inspect', cid))[0]
    wait = int(docker('wait', cid))
    (output / 'terminal-container.json').write_text(json.dumps(terminal, indent=2))
    assert not terminal['State']['Running'] and terminal['State']['Pid'] == 0 and not terminal['State']['OOMKilled']
    assert actual.returncode == wait == terminal['State']['ExitCode'] == 0 and not actual.stderr
    result = json.loads(actual.stdout)
    assert result['status'] == 'PASS_SCOPED_KERNEL_OBSERVER_MODEL_ONLY' and result['productTestsExecuted'] == 0
    consumer_spec = importlib.util.spec_from_file_location('ordinary_receipt_consumer', Path(__file__).with_name('run-container-go-ci.py'))
    consumer = importlib.util.module_from_spec(consumer_spec)
    consumer_spec.loader.exec_module(consumer)
    consumer.validate_descendants(result['cases']['terminal-killed'])
    rejected = []
    mutations = {'live': result['cases']['live']}
    for name in ('wrong-wait', 'wrong-uid', 'running-state', 'duplicate-wait', 'observer-error', 'not-reaped'):
        value = copy.deepcopy(result['cases']['terminal-killed'])
        if name == 'wrong-wait':value['adoptedWaits'][0]['rawStatus'] = 0
        elif name == 'wrong-uid':value['adoptedAtRootExit'][0]['uid'] = ['0'] * 4
        elif name == 'running-state':value['adoptedAtRootExit'][0]['state'] = 'R (running)'
        elif name == 'duplicate-wait':value['adoptedWaits'].append(copy.deepcopy(value['adoptedWaits'][0]))
        elif name == 'observer-error':value['observerError'] = 'negative unit mutation'
        elif name == 'not-reaped':value['allAdoptedChildrenReapedBeforePID1Exit'] = False
        mutations[name] = value
    for name, value in mutations.items():
        try:
            consumer.validate_descendants(value)
        except AssertionError:
            rejected.append(name)
        else:
            raise AssertionError('receipt consumer accepted negative case: ' + name)
    result['consumerNegativeCasesRejected'] = rejected
    assert sorted(docker('ps', '--no-trunc', '--format', '{{.ID}}').splitlines()) == running
    result.update(allowedRunningIds=allowed, containerId=cid, actualContainerExit=wait, actualAttachExit=actual.returncode,
                  workerSHA256=hashlib.sha256(worker.read_bytes()).hexdigest())
    (output / 'result.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(status=result['status'], productTestsExecuted=0, actualContainerExit=wait)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
