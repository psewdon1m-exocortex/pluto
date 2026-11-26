#!/usr/bin/env python3
"""Run one explicit source-bound ordinary Go shard in a fresh private container."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time

PROJECT = Path(__file__).resolve().parents[1]
PACKAGES = {'pluto/internal/pluto', 'pluto/internal/pluto/syncstate', 'pluto/internal/network',
            'pluto/internal/syncproto', 'pluto/internal/testsupport/nativeprocess',
            'pluto/internal/testsupport/nativeprocess/custody'}


def worktree_source(project, qualified_manifest=None):
    """Pin this checkout; never implicitly select an earlier qualification."""
    project = Path(project).resolve(strict=True)
    maximum_file, maximum_total = 8 * 2**20, 64 * 2**20

    def regular(name):
        relative = PurePosixPath(name)
        if (not isinstance(name, str) or not name or relative.is_absolute() or
                relative.as_posix() != name or '\\' in name or ':' in name or
                any(part in ('.', '..', '.git') for part in relative.parts) or
                any(ord(char) < 32 or ord(char) == 127 for char in name)):
            raise ValueError('regular bounded checkout-relative source path required')
        file = project
        for part in relative.parts:
            file = file / part
            if file.is_symlink() or getattr(file, 'is_junction', lambda: False)():
                raise ValueError('source reparse/symlink is not permitted')
        if not file.resolve(strict=True).is_relative_to(project) or not stat.S_ISREG(file.lstat().st_mode):
            raise ValueError('source must be a regular file within this checkout')
        size = file.stat().st_size
        if not 0 <= size <= maximum_file:
            raise ValueError('source file exceeds its bound')
        raw = file.read_bytes()
        if len(raw) != size or len(raw) > maximum_file:
            raise ValueError('source changed during bounded observation')
        return raw

    manifest = None
    if qualified_manifest is None:
        tracked = subprocess.run(['git', '-C', str(project), 'ls-files', '--cached', '-z'],
                                 check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        names = [name.decode('utf-8') for name in tracked.stdout.split(b'\0') if name]
        declared = None
        mode = 'CURRENT_GIT_TRACKED_FILES'
    else:
        selected = Path(qualified_manifest)
        if selected.is_absolute():
            try:
                selected = selected.relative_to(project)
            except ValueError:
                raise ValueError('qualified manifest must be within this checkout') from None
        name = selected.as_posix()
        raw = regular(name)
        if len(raw) > 2 * 2**20:
            raise ValueError('qualified source manifest exceeds its bound')
        frozen = json.loads(raw)
        if not isinstance(frozen, dict) or frozen.get('schema') != 'exocortex.package3.frozen-source.v1':
            raise ValueError('reviewed qualified source manifest schema required')
        declared = frozen.get('files')
        if not isinstance(declared, list) or not all(isinstance(row, dict) for row in declared):
            raise ValueError('qualified source file inventory required')
        names = [row.get('path') for row in declared]
        manifest = dict(path=name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        mode = 'EXPLICIT_QUALIFIED_MANIFEST'
    if (not 0 < len(names) <= 4096 or not all(isinstance(name, str) for name in names) or
            len(set(names)) != len(names)):
        raise ValueError('bounded distinct source file inventory required')
    expected = {row['path']: row for row in declared} if declared is not None else None
    files, total = [], 0
    for name in sorted(names):
        if expected is not None:
            row = expected[name]
            if (type(row.get('bytes')) is not int or not 0 <= row['bytes'] <= maximum_file or
                    not isinstance(row.get('sha256'), str) or not re.fullmatch('[a-f0-9]{64}', row['sha256'])):
                raise ValueError('exact bounded qualified source bytes/SHA required')
        raw = regular(name)
        observed = dict(path=name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        if expected is not None and any(observed[key] != expected[name][key] for key in ('bytes', 'sha256')):
            raise ValueError('actual raw qualified source bytes differ: ' + name)
        total += len(raw)
        if total > maximum_total:
            raise ValueError('source inventory exceeds its total byte bound')
        files.append(observed)
    return dict(schema='pluto.ordinary-ci-worktree-source.v1', mode=mode, manifest=manifest, files=files)


def digest(file):
    with Path(file).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(file, value, mode=0o600):
    with Path(file).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        os.fchmod(stream.fileno(), mode)
        stream.flush()
        os.fsync(stream.fileno())


def public_copy(source, target, executable=False):
    source, target = Path(source), Path(target)
    assert source.is_file() and not source.is_symlink()
    with source.open('rb') as src, target.open('xb') as dest:
        shutil.copyfileobj(src, dest, 65536)
        os.fchmod(dest.fileno(), 0o555 if executable else 0o444)
        dest.flush()
        os.fsync(dest.fileno())
    assert digest(source) == digest(target)
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'package', 'cases', 'source-inputs', 'test-binary', 'converter',
                 'image', 'docker', 'docker-host'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--allow-running-id', action='append', default=[])
    parser.add_argument('--workspace-source-manifest',
                        default=os.environ.get('PLUTO_GO_CI_WORKTREE_SOURCE_MANIFEST') or None)
    args = parser.parse_args()
    os.umask(0o077)
    assert args.package in PACKAGES and re.fullmatch('sha256:[a-f0-9]{64}', args.image)
    output = Path(args.output).resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    names = json.loads(Path(args.cases).read_bytes())
    assert isinstance(names, list) and 0 < len(names) <= 512 and len(names) == len(set(names))
    assert all(re.fullmatch('Test[A-Za-z0-9_]+', name) for name in names)
    spec = importlib.util.spec_from_file_location('ordinary_ci_source', PROJECT / 'scripts/run-c01-ci.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    report = helper.reporter()
    source = json.loads(Path(args.source_inputs).read_bytes())
    assert source['schema'] == 'pluto.c01-ci-source.v1'
    assert source['inputs'] == report.c01_source_inputs(PROJECT)
    worktree = worktree_source(PROJECT, args.workspace_source_manifest)
    assert helper.host_available_gib() >= 17 and shutil.disk_usage(output).free >= 85 * 2**30
    command = [args.docker, '--host', args.docker_host]

    def docker(*values):
        actor = subprocess.run(command + list(values), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if actor.returncode:
            write(output / ('docker-failure-' + secrets.token_hex(4) + '.json'),
                  dict(verb=values[0], actualExit=actor.returncode,
                       stdoutBase64=base64.b64encode(actor.stdout).decode(),
                       stderrBase64=base64.b64encode(actor.stderr).decode()))
            raise RuntimeError('Docker ' + values[0] + ' exit ' + str(actor.returncode))
        return actor.stdout.decode().strip()

    running = docker('ps', '--no-trunc', '--format', '{{.ID}}').splitlines()
    assert sorted(running) == sorted(args.allow_running_id)
    engine = docker('info', '--format', '{{.ID}}')
    image = json.loads(docker('image', 'inspect', args.image))[0]
    assert image['Id'] == args.image and image['Os'] == 'linux' and image['Architecture'] == 'amd64'
    assert not image['Config'].get('Volumes')
    scope = 'pluto-ordinary-ci-' + secrets.token_hex(8)
    labels = {'exocortex.ci.scope': scope, 'exocortex.ci.kind': 'ordinary-unprivileged'}
    vm_available = float(docker('run', '--rm', '--name', scope + '-vm-probe',
        '--label', 'exocortex.ci.scope=' + scope, '--pull=never',
        '--network', 'none', '--read-only', '--user', '10001:10001', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges', '--cpus', '1', '--memory', '128m',
        '--memory-swap', '128m', '--pids-limit', '32', args.image, 'python3', '-I', '-B', '-c',
        "from pathlib import Path;print(int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))/1048576)"))
    assert vm_available >= 17
    write(output / 'effect-plan.json', dict(scope=scope, labels=labels, engine=engine,
        package=args.package, cases=names, allowedRunning=running, reserveRAMGiB=8,
        vmAvailableGiB=vm_available, containerCapGiB=4))
    # Public copies are newly created; original source and artifact modes stay untouched.
    view = output / 'readonly-source'
    view.mkdir(mode=0o755)
    os.chmod(view, 0o755)
    for row in worktree['files']:
        relative = Path(row['path'])
        assert not relative.is_absolute() and '..' not in relative.parts
        original = PROJECT / relative
        target = view / relative
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        parent = target.parent
        while parent != view:
            os.chmod(parent, 0o755)
            parent = parent.parent
        public_copy(original, target)
        assert target.stat().st_size == row['bytes'] and digest(target) == row['sha256']
    assert report.c01_source_inputs(view) == source['inputs']
    write(output / 'worktree-source-inputs.json', worktree)
    helpers = output / 'readonly-helpers'
    helpers.mkdir(mode=0o700)
    bootstrap = public_copy(PROJECT / 'scripts/native-fixture/ordinary/bootstrap.py', helpers / 'bootstrap.py')
    worker = public_copy(PROJECT / 'scripts/native-fixture/ordinary/worker.py', helpers / 'worker.py')
    binary = public_copy(args.test_binary, helpers / 'test-input', executable=True)
    converter = public_copy(args.converter, helpers / 'converter', executable=True)
    source = dict(source, testBinarySHA256=digest(binary))
    write(output / 'source-inputs.json', source)
    volumes = []
    for suffix in ('data', 'backups'):
        name = scope + '-' + suffix
        assert name not in docker('volume', 'ls', '--format', '{{.Name}}').splitlines()
        create = ['volume', 'create', '--driver', 'local']
        for key, value in labels.items():
            create += ['--label', key + '=' + value]
        assert docker(*create, name) == name
        observed = json.loads(docker('volume', 'inspect', name))[0]
        assert observed['Labels'] == labels and observed['Driver'] == 'local' and not observed.get('Options')
        volumes.append(observed)

    def bind(file, target):
        return ['--mount', 'type=bind,source=' + str(Path(file).resolve()) + ',target=' + target + ',readonly']

    worker_input = output / 'worker-input.json'
    write(worker_input, {})
    create = ['create', '--name', scope, '--platform', 'linux/amd64', '--network', 'none',
              '--pull=never', '--init=false', '--read-only', '--user', '0:0', '--cap-drop', 'ALL',
              '--security-opt', 'no-new-privileges', '--cpus', '4', '--memory', '4g',
              '--memory-swap', '4g', '--pids-limit', '128',
              '--tmpfs', '/runtime:rw,exec,nosuid,nodev,size=96m,mode=0755',
              '--tmpfs', '/tmp:rw,nosuid,nodev,size=96m']
    for capability in ('CHOWN', 'SETUID', 'SETGID', 'SETPCAP'):
        create += ['--cap-add', capability]
    for key, value in labels.items():
        create += ['--label', key + '=' + value]
    for file, target in ((bootstrap, '/bootstrap.py'), (worker, '/worker.py'),
                         (binary, '/test-input'), (worker_input, '/input.json'), (view, '/workspace')):
        create += bind(file, target)
    for item, target in zip(volumes, ('/retained', '/backups')):
        create += ['--mount', 'type=volume,source=' + item['Name'] + ',target=' + target + ',volume-nocopy']
    create += ['--entrypoint', 'python3', args.image, '-I', '-B', '/bootstrap.py']
    assert docker('info', '--format', '{{.ID}}') == engine
    cid = docker(*create)
    actual = json.loads(docker('inspect', cid))[0]
    write(output / 'created-container.json', actual)
    host = actual['HostConfig']
    assert re.fullmatch('[a-f0-9]{64}', cid) and actual['Id'] == cid and actual['Image'] == args.image
    assert actual['Config']['Hostname'] == cid[:12] and actual['State']['Status'] == 'created'
    assert host['NetworkMode'] == 'none' and not host['Privileged'] and not host['AutoRemove']
    assert host['ReadonlyRootfs'] and host['Memory'] == host['MemorySwap'] == 4 * 2**30
    assert host['Init'] is False
    assert host['NanoCpus'] == 4 * 10**9 and host['PidsLimit'] == 128 and not host['PidMode']
    assert sorted(value.removeprefix('CAP_') for value in host['CapAdd']) == ['CHOWN', 'SETGID', 'SETPCAP', 'SETUID']
    assert [value.removeprefix('CAP_') for value in host['CapDrop']] == ['ALL']
    assert not host['PortBindings'] and len(actual['Mounts']) == 7
    for target in ('/bootstrap.py', '/worker.py', '/test-input', '/input.json', '/workspace'):
        assert sum(item['Destination'] == target and item['Type'] == 'bind' and not item['RW']
                   for item in actual['Mounts']) == 1
    data = dict(schema='pluto.ordinary-ci-worker-input.v1', containerId=cid, package=args.package,
                cases=names, testBinarySHA256=digest(binary),
                workingDirectory='/workspace/' + args.package.removeprefix('pluto/'))
    with worker_input.open('w') as stream:
        json.dump(data, stream)
        stream.flush()
        os.fsync(stream.fileno())
    worker_input.chmod(0o444)
    write(output / 'producer-spec.json', dict(container=actual, engine=engine, volumes=volumes,
                                            argv=create, workerInput=data, source=source))
    docker('start', cid)
    deadline = time.monotonic() + 720
    while True:
        state = json.loads(docker('inspect', cid))[0]['State']
        if not state['Running']:
            break
        if time.monotonic() >= deadline:
            write(output / 'pending.json', dict(status='PENDING_RETAINED_NO_KILL', containerId=cid,
                                               admissionClosed=True, state=state))
            return 1
        time.sleep(0.25)
    waited = docker('wait', cid)
    assert int(waited) == state['ExitCode'] and not state['OOMKilled']
    write(output / 'terminal-container.json', json.loads(docker('inspect', cid))[0])
    logs = subprocess.run(command + ['logs', cid], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (output / 'container.stdout').write_bytes(logs.stdout)
    (output / 'container.stderr').write_bytes(logs.stderr)
    assert logs.returncode == 0
    # A short readonly collector is separate from every private state writer.
    collector_code = """import base64,hashlib,json,subprocess
from pathlib import Path
root=Path('/retained/evidence');files={}
for name in ('stdout.log','actual-wait.json','started.json','process.json','inventory.stdout','adopted-descendants.json'):
 p=root/name;b=p.read_bytes();assert len(b)<=16*1024*1024
 files[name]=dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),base64=base64.b64encode(b).decode())
converted=subprocess.run(['/converter','-t','-p',__import__('sys').argv[1]],input=(root/'stdout.log').read_bytes(),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
assert converted.returncode==0 and not converted.stderr and len(converted.stdout)<=16*1024*1024
b=converted.stdout;files['events.jsonl']=dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),base64=base64.b64encode(b).decode())
inventory=[]
for p in sorted(Path('/backups/store').rglob('*')):
 assert not p.is_symlink()
 if p.is_file():
  with p.open('rb') as f:pin=hashlib.file_digest(f,'sha256').hexdigest()
  inventory.append(dict(path=p.relative_to('/backups/store').as_posix(),bytes=p.stat().st_size,sha256=pin))
 assert len(inventory)<=4096
files['backup-inventory.json']=dict(data=inventory)
print(json.dumps(dict(files=files,converterActualExit=converted.returncode)))
"""
    packet = json.loads(docker('run', '--rm', '--name', scope + '-collector',
        '--label', 'exocortex.ci.scope=' + scope, '--pull=never', '--network', 'none', '--read-only',
        '--user', '10001:10001', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
        '--cpus', '1', '--memory', '256m', '--memory-swap', '256m', '--pids-limit', '32',
        '--mount', 'type=volume,source=' + volumes[0]['Name'] + ',target=/retained,readonly,volume-nocopy',
        '--mount', 'type=volume,source=' + volumes[1]['Name'] + ',target=/backups,readonly,volume-nocopy',
        *bind(converter, '/converter'), '--entrypoint', 'python3', args.image, '-I', '-B', '-c',
        collector_code, args.package))
    for name, meta in packet['files'].items():
        assert re.fullmatch('[a-zA-Z0-9_.-]+', name)
        if name == 'backup-inventory.json':
            write(output / name, meta['data'])
            continue
        raw = base64.b64decode(meta['base64'], validate=True)
        assert len(raw) == meta['bytes'] <= 16 * 1024 * 1024
        assert hashlib.sha256(raw).hexdigest() == meta['sha256']
        with (output / name).open('xb') as stream:
            stream.write(raw)
    process = json.loads((output / 'process.json').read_bytes())
    waited_go = json.loads((output / 'actual-wait.json').read_bytes())
    raw_stdout = (output / 'stdout.log').read_bytes()
    assert process['actualWait'] == waited_go and process['stdoutBytes'] == len(raw_stdout)
    assert process['stdoutSHA256'] == hashlib.sha256(raw_stdout).hexdigest()
    events = list(report.events(output / 'events.jsonl'))
    inventory = [dict(Package=args.package, Action='output', Output=name + '\n') for name in names]
    conditional = {key: item for key, item in report.conditional_policy(PROJECT, {}).items()
                   if key[0] == args.package and key[1] in names}
    accounting = report.audit(inventory, events, 0 if waited_go['Exited'] and waited_go['ExitCode'] == 0 else 1,
                              packet['converterActualExit'], conditional=conditional)
    accounting['fullOrdinaryCIGreen'] = False
    accounting['inventoryScope'] = 'EXACT_DECLARED_SHARD_ONLY'
    write(output / 'case-accounting.json', accounting)
    assert docker('info', '--format', '{{.ID}}') == engine
    assert sorted(docker('ps', '--no-trunc', '--format', '{{.ID}}').splitlines()) == sorted(running)
    result = dict(schema='pluto.ordinary-ci-shard.v1', package=args.package, cases=names,
                  containerId=cid, actualContainerExit=state['ExitCode'], actualWait=process['actualWait'],
                  converterActualExit=packet['converterActualExit'], process=process,
                  testBinarySHA256=digest(binary), volumesPreserved=[item['Name'] for item in volumes],
                  worktreeSourceInputsSHA256=digest(output / 'worktree-source-inputs.json'),
                  caseAccounting=accounting, fullOrdinaryCiGreen=False)
    result['status'] = ('PASS_SCOPED_ACTUAL_UNPRIVILEGED_GO_SHARD'
                        if state['ExitCode'] == 0 and process['status'] == 'PASS_ACTUAL_UNPRIVILEGED_GO_SHARD'
                        and not accounting['errors']
                        else 'FAIL')
    write(output / 'producer-result.json', result)
    print(json.dumps(dict(status=result['status'], package=args.package, cases=len(names),
                          actualContainerExit=state['ExitCode'], fullOrdinaryCiGreen=False)))
    return 0 if result['status'].startswith('PASS_') else 1


if __name__ == '__main__':
    raise SystemExit(main())
