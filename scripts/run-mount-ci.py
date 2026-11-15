#!/usr/bin/env python3
"""Run the two original mount tests through the qualified drop-only supervisor."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tarfile
import threading

PROJECT = Path(__file__).resolve().parents[1]
CASES = ['TestStage3C02NativeUnmountGap', 'TestStage3C03NativeDiskFullPreservesCommit']
PACKAGE = 'pluto/internal/pluto/syncstate'
RUN = 'release-candidate-20261102T192007Z-587ea6af'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def save(file, value):
    with Path(file).open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def single_tar(name, raw, mode):
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w') as tar:
        item = tarfile.TarInfo(name)
        item.size, item.mode, item.uid, item.gid = len(raw), mode, 0, 0
        tar.addfile(item, io.BytesIO(raw))
    return archive.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'source-inputs', 'test-binary', 'converter', 'image', 'docker', 'docker-host'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--allow-running-id', action='append', default=[])
    args = parser.parse_args()
    os.umask(0o077)
    output = Path(args.output).resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    assert re.fullmatch('sha256:[a-f0-9]{64}', args.image)
    module_spec = importlib.util.spec_from_file_location('mount_ci_source', PROJECT / 'scripts/run-c01-ci.py')
    helper = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(helper)
    report = helper.reporter()
    source = json.loads(Path(args.source_inputs).read_bytes())
    assert source['schema'] == 'pluto.c01-ci-source.v1'
    assert source['inputs'] == report.c01_source_inputs(PROJECT)
    assert helper.host_available_gib() >= 12 and shutil.disk_usage(output).free >= 85 * 2**30
    command = [args.docker, '--host', args.docker_host]
    receipts = []

    def docker(*values, data=None, check=True):
        actor = subprocess.run(command + list(values), input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert len(actor.stdout) <= 65 * 1024 * 1024 and len(actor.stderr) <= 1024 * 1024
        receipt = dict(verb=values[0], actualExit=actor.returncode, actualJoin=True,
                       stdoutSHA256=digest(actor.stdout), stderrSHA256=digest(actor.stderr))
        receipts.append(receipt)
        if check and actor.returncode:
            save(output / ('docker-failure-' + str(len(receipts)) + '.json'),
                 dict(**receipt, stderr=actor.stderr.decode(errors='replace')))
            raise RuntimeError('Docker ' + values[0] + ' exit ' + str(actor.returncode))
        return actor

    def text(*values):
        return docker(*values).stdout.decode().strip()

    running = text('ps', '--no-trunc', '--format', '{{.ID}}').splitlines()
    assert sorted(running) == sorted(args.allow_running_id)
    engine = text('info', '--format', '{{.ID}}')
    image = json.loads(text('image', 'inspect', args.image))[0]
    assert image['Id'] == args.image and image['Os'] == 'linux' and image['Architecture'] == 'amd64'
    assert not image['Config'].get('Volumes')
    nonce = secrets.token_hex(32)
    scope = 'PLUTO-NATIVE-MOUNT-PHASE2-' + nonce[:16]
    name = 'pluto-mount-ci-' + nonce[:16]
    prefix = '/exocortex-native-mount-p2-' + nonce[:16]
    base = '/fixture-p2-' + nonce[:16]
    save(output / 'effect-plan.json', dict(scope=scope, name=name, image=args.image, engine=engine,
         cases=CASES, capabilities=['SYS_ADMIN', 'SETPCAP', 'SETUID', 'SETGID'], hostMounts=0,
         containerMemoryGiB=1, reserveRAMGiB=8, noKillRemovePrune=True))
    assert name not in text('ps', '-a', '--format', '{{.Names}}').splitlines()
    create = ['create', '--pull=never', '--interactive', '--init=false', '--name', name,
              '--label', 'exocortex.ci.scope=' + scope, '--network', 'none', '--user', '0:0',
              '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
              '--memory', '1024m', '--memory-swap', '1024m', '--cpus', '1', '--pids-limit', '64']
    for capability in ('SYS_ADMIN', 'SETPCAP', 'SETUID', 'SETGID'):
        create += ['--cap-add', capability]
    create += ['--entrypoint', '/usr/local/bin/python3.13', args.image,
               '-I', '-B', '-u', prefix + '.py', '--role', 'bootstrap', '--marker', prefix + '.json']
    assert text('info', '--format', '{{.ID}}') == engine
    cid = text(*create)
    actual = json.loads(text('inspect', cid))[0]
    save(output / 'created-container.json', actual)

    def admit(info):
        host = info['HostConfig']
        assert info['Id'] == cid and info['Image'] == args.image and info['Name'] == '/' + name
        assert info['Created'] == actual['Created'] and info['Config']['Hostname'] == cid[:12]
        assert info['State']['Status'] == 'created' and info['State']['Pid'] == 0
        assert info['Config']['Labels']['exocortex.ci.scope'] == scope
        assert host['NetworkMode'] == 'none' and not host['Privileged'] and not host['Init']
        assert host['Memory'] == host['MemorySwap'] == 2**30
        assert host['NanoCpus'] == 10**9 and host['PidsLimit'] == 64
        assert not info['Mounts'] and not host.get('Binds') and not host.get('Mounts') and not host.get('VolumesFrom')
        assert not host['PidMode'] and not host['UTSMode'] and host['IpcMode'] in ('', 'private')
        assert host['SecurityOpt'] == ['no-new-privileges:true']
        assert [x.removeprefix('CAP_') for x in host['CapDrop']] == ['ALL']
        assert sorted(x.removeprefix('CAP_') for x in host['CapAdd']) == ['SETGID', 'SETPCAP', 'SETUID', 'SYS_ADMIN']

    admit(actual)
    binary = Path(args.test_binary).read_bytes()
    assert 0 < len(binary) <= 64 * 1024 * 1024
    actors = (PROJECT / 'scripts/native-fixture/mount/actors.py').read_bytes()
    base_code = (PROJECT / 'scripts/native-fixture/mount/base.py').read_bytes()
    marker = dict(schema='native-mount-phase2.v1', run=RUN, scope=scope, nonce=nonce,
                  container_id=cid, created=actual['Created'], image=args.image, prefix=prefix, base=base,
                  base_python_sha256=digest(base_code), helper_python_sha256=digest(actors),
                  test_binary_sha256=digest(binary), source_manifest_sha256=digest(Path(args.source_inputs).read_bytes()),
                  go_argv=[prefix + '.test', '-test.run=^(' + '|'.join(CASES) + ')$',
                           '-test.v', '-test.count=1', '-test.timeout=0'])
    save(output / 'ownership.json', marker)
    for suffix, raw, mode in [('.base.py', base_code, 0o444), ('.py', actors, 0o444),
                              ('.test', binary, 0o555), ('.json', json.dumps(marker).encode(), 0o444)]:
        admit(json.loads(text('inspect', cid))[0])
        target = prefix + suffix
        absent = docker('cp', cid + ':' + target, '-', check=False)
        assert absent.returncode == 1 and not absent.stdout
        assert absent.stderr.decode().strip() == 'Error response from daemon: Could not find the file ' + target + ' in container ' + cid
        basename = target[1:]
        docker('cp', '-', cid + ':/', data=single_tar(basename, raw, mode))
        with tarfile.open(fileobj=io.BytesIO(docker('cp', cid + ':' + target, '-').stdout)) as tar:
            members = tar.getmembers()
            assert len(members) == 1 and members[0].isfile() and members[0].name == basename
            item = members[0]
            assert (item.uid, item.gid, item.mode) == (0, 0, mode) and tar.extractfile(item).read() == raw
    admit(json.loads(text('inspect', cid))[0])
    assert text('info', '--format', '{{.ID}}') == engine
    with (output / 'container.stdout').open('xb') as stdout, (output / 'container.stderr').open('xb') as stderr:
        process = subprocess.Popen(command + ['start', '-ai', cid], stdin=subprocess.PIPE, stdout=stdout, stderr=stderr)
        stopped = threading.Event()

        def request_stop():
            stopped.set()
            try:
                process.stdin.write((json.dumps(dict(op='STOP', nonce=nonce)) + '\n').encode())
                process.stdin.flush()
            except (BrokenPipeError, OSError):
                pass

        observer = threading.Timer(60, request_stop)
        observer.start()
        actual_attach = process.wait()
        observer.cancel()
        observer.join()
        process.stdin.close()
    save(output / 'actual-attach-wait.json', dict(pid=process.pid, actualExit=actual_attach, actualJoin=True, noKill=True))
    ended = json.loads(text('inspect', cid))[0]
    save(output / 'terminal-container.json', ended)
    assert ended['Id'] == cid and ended['Created'] == actual['Created'] and ended['Image'] == args.image
    assert not ended['State']['Running'] and ended['State']['Pid'] == 0 and not ended['State']['OOMKilled']
    wait = int(text('wait', cid))
    assert wait == ended['State']['ExitCode']
    archive = docker('cp', cid + ':' + base, '-').stdout
    (output / 'overlay-receipts.tar').write_bytes(archive)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for name, target in [('native.stdout', 'stdout.log'), ('native.stderr', 'go.stderr'), ('controller/final.json', 'actor-result.json')]:
            member = tar.getmember(base[1:] + '/' + name)
            assert member.isfile() and member.size <= 4 * 1024 * 1024
            (output / target).write_bytes(tar.extractfile(member).read())
    actor_result = json.loads((output / 'actor-result.json').read_bytes())
    go_actor = [item for item in actor_result['actors'] if item['role'] == 'native']
    assert len(go_actor) == 1 and isinstance(go_actor[0]['exit_code'], int)
    converter = subprocess.run([args.converter, '-t', '-p', PACKAGE], input=(output / 'stdout.log').read_bytes(),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'PATH': '/usr/bin:/bin', 'GOMAXPROCS': '2'})
    (output / 'events.jsonl').write_bytes(converter.stdout)
    (output / 'converter.stderr').write_bytes(converter.stderr)
    accounting = report.audit([dict(Package=PACKAGE, Action='output', Output=case + '\n') for case in CASES],
                              report.events(output / 'events.jsonl'), go_actor[0]['exit_code'], converter.returncode)
    accounting['fullOrdinaryCIGreen'] = False
    accounting['inventoryScope'] = 'EXACT_NATIVE_MOUNT_TWO_ONLY'
    assert text('info', '--format', '{{.ID}}') == engine
    assert sorted(text('ps', '--no-trunc', '--format', '{{.ID}}').splitlines()) == sorted(running)
    passed = (actual_attach == wait == 0 and not stopped.is_set() and not converter.returncode and not converter.stderr
              and actor_result['status'] == 'PASS_EXACT_TWO_NATIVE_TESTS' and not accounting['errors']
              and len(actor_result['actors']) == 3 and all(item['exit_code'] == 0 for item in actor_result['actors']))
    result = dict(schema='pluto.native-mount-ci-shard.v1', status='PASS_SCOPED_ORIGINAL_NATIVE_MOUNT_TWO' if passed else 'FAIL',
                  package=PACKAGE, cases=CASES, containerId=cid, image=args.image,
                  actualAttachExit=actual_attach, actualContainerExit=wait, actualGoExit=go_actor[0]['exit_code'],
                  converterActualExit=converter.returncode, stopSent=stopped.is_set(), actorResult=actor_result,
                  caseAccounting=accounting, testBinarySHA256=digest(binary), sourceInputs=source,
                  fullOrdinaryCiGreen=False, noKillRemovePrune=True,
                  productionPermissionEquivalence=False, seccompLimitation='Built-in seccomp sees four bootstrap capabilities.')
    save(output / 'command-receipts.json', receipts)
    save(output / 'producer-result.json', result)
    print(json.dumps(dict(status=result['status'], actualGoExit=result['actualGoExit'], cases=2)))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
