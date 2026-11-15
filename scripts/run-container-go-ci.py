#!/usr/bin/env python3
"""Run and independently account every ordinary/special scope after native preflight."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

PROJECT = Path(__file__).resolve().parents[1]
DISPOSABLE = ('pluto/internal/pluto', 'TestStage3C12NativeIncompatibleRollbackRetainsJournal')
MOUNT = [('pluto/internal/pluto/syncstate', name) for name in
         ('TestStage3C02NativeUnmountGap', 'TestStage3C03NativeDiskFullPreservesCommit')]
HEAVY = ('pluto/internal/pluto/syncstate', 'TestStage3C04Parents501ThreeLevels')


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def digest(file):
    with Path(file).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(file, value):
    with Path(file).open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def profile(record):
    assert record['Uid'].split() == record['Gid'].split() == ['10001'] * 4
    assert record['Groups'] == '' and record['NoNewPrivs'] == '1' and record['Seccomp'] == '2'
    assert all(int(record[key], 16) == 0 for key in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'inventory', 'native-shards', 'binaries', 'source-inputs',
                 'converter', 'image', 'docker', 'docker-host'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--allow-running-id', action='append', default=[])
    args = parser.parse_args()
    os.umask(0o077)
    output = Path(args.output).resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = module('container_go_report', PROJECT / 'scripts/check-go-ci.py')
    partition = module('container_go_accounting', PROJECT / 'scripts/container-ci-accounting.py')
    ordinary_helper = module('container_ordinary_helper', PROJECT / 'scripts/run-unprivileged-go-ci.py')
    inventory = list(report.events(args.inventory))
    expected = partition.discovered_tests(inventory)
    native = report.native_scopes(args.native_shards, PROJECT)
    native_preflight = report.preflight_native_scopes(inventory, native)
    assert not native_preflight['errors']
    source = report.bounded_json(args.source_inputs)
    assert source['inputs'] == report.c01_source_inputs(PROJECT)
    binaries = report.bounded_json(args.binaries)
    assert binaries['schema'] == 'pluto.ci-test-binaries.v1'
    assert binaries['sourceInputsSHA256'] == digest(args.source_inputs)
    assert set(binaries['packages']) == ordinary_helper.PACKAGES
    for package, item in binaries['packages'].items():
        binary = Path(item['path'])
        assert binary.is_absolute() and not binary.is_symlink() and binary.is_file()
        assert item['bytes'] == binary.stat().st_size and item['sha256'] == digest(binary)
    for case, proof in native.items():
        assert proof['evidence']['testBinarySHA256'] == binaries['packages'][report.native_package(case)]['sha256']
    reserved = {(report.native_package(case), case) for case in report.NATIVE_CASES}
    assert len(reserved) == len(report.NATIVE_CASES) and reserved <= expected
    special = {DISPOSABLE, HEAVY, *MOUNT}
    assert len(special) == 4 and special <= expected and not reserved & special
    remaining = expected - reserved - special
    assert {package for package, _ in remaining} <= ordinary_helper.PACKAGES
    assert not any(name == report.ARCHIVAL_TEST for _, name in expected)
    scopes = []
    for case, proof in native.items():
        package = report.native_package(case)
        accounting = report.audit([dict(Package=package, Action='output', Output=case + '\n')],
                                  proof['events'], proof['goExit'], proof['captureExit'])
        accounting['fullOrdinaryCIGreen'] = False
        scopes.append(dict(name='native-' + case, assigned=[(package, case)],
                           directory=str(proof['evidence'].get('directory', 'native-receipt:' + case)),
                           accounting=accounting, actualRunnerExit=proof['runnerExit'], actualCaptureExit=proof['captureExit']))
    save(output / 'assignment.json', dict(expected=[list(key) for key in sorted(expected)],
         native=[list(key) for key in sorted(reserved)], special=[list(key) for key in sorted(special)],
         ordinary=[list(key) for key in sorted(remaining)], sourceInputsSHA256=digest(args.source_inputs), binaries=binaries))
    common = ['--image', args.image, '--docker', args.docker, '--docker-host', args.docker_host,
              '--converter', args.converter]
    for cid in args.allow_running_id:
        common += ['--allow-running-id', cid]

    def invoke(name, script, arguments):
        with (output / (name + '.stdout')).open('xb') as stdout, (output / (name + '.stderr')).open('xb') as stderr:
            process = subprocess.Popen([sys.executable, '-I', '-B', str(PROJECT / 'scripts' / script), *arguments],
                                       stdout=stdout, stderr=stderr, cwd=PROJECT)
            actual = process.wait()
            stdout.flush()
            stderr.flush()
            os.fsync(stdout.fileno())
            os.fsync(stderr.fileno())
        save(output / (name + '-wait.json'), dict(pid=process.pid, actualExit=actual, actualJoin=True, noKill=True))
        assert actual == 0, name + ' actual producer exit ' + str(actual)
        return actual

    def account(name, directory, package, names, actual_go, converter_exit, runner_exit):
        events = list(report.events(directory / 'events.jsonl'))
        assert all(event.get('Package') == package for event in events)
        assert [event['Action'] for event in events if not event.get('Test') and
                event['Action'] in ('pass', 'fail', 'skip')] == ['pass']
        conditional = {key: value for key, value in report.conditional_policy(PROJECT, {}).items()
                       if key[0] == package and key[1] in names}
        accounting = report.audit([dict(Package=package, Action='output', Output=name + '\n') for name in names],
                                  events, actual_go, converter_exit, conditional=conditional)
        accounting['fullOrdinaryCIGreen'] = False
        scopes.append(dict(name=name, directory=str(directory), assigned=[(package, case) for case in names],
                           accounting=accounting, actualRunnerExit=runner_exit, actualCaptureExit=0))
        assert not accounting['errors'], name + ' raw event accounting failed'

    try:
        # The root installer negative is confined to its separately attested disposable container.
        disposable = output / 'disposable'
        actual = invoke('disposable', 'run-disposable-ci.py', ['--output', str(disposable), '--test-binary',
                        binaries['packages'][DISPOSABLE[0]]['path'], '--workspace', str(PROJECT),
                        '--run', 'release-candidate-container-ci', *common])
        proof = report.bounded_json(disposable / 'result.json')
        spec = report.bounded_json(disposable / 'producer-spec.json')
        assert proof['status'] == 'PASS_SCOPED_ORIGINAL_DISPOSABLE_NEGATIVE_ROLLBACK'
        assert proof['actualGoExit'] == proof['actualContainerExit'] == proof['actualAttachedExit'] == 0
        assert spec['testBinarySHA256'] == binaries['packages'][DISPOSABLE[0]]['sha256']
        assert proof['historicalReader'] is False and proof['after']['originalFilesUnchanged']
        assert proof['after']['files'] == proof['backup']['files'] and len(proof['backup']['files']) == 4
        account('disposable', disposable / 'evidence', DISPOSABLE[0], [DISPOSABLE[1]], proof['actualGoExit'], 0, actual)

        mount = output / 'mount'
        actual = invoke('mount', 'run-mount-ci.py', ['--output', str(mount), '--source-inputs', args.source_inputs,
                        '--test-binary', binaries['packages'][MOUNT[0][0]]['path'], *common])
        proof = report.bounded_json(mount / 'producer-result.json')
        assert proof['status'] == 'PASS_SCOPED_ORIGINAL_NATIVE_MOUNT_TWO'
        assert proof['sourceInputs']['inputs'] == source['inputs']
        assert proof['testBinarySHA256'] == binaries['packages'][MOUNT[0][0]]['sha256']
        assert proof['actualGoExit'] == proof['actualContainerExit'] == proof['actualAttachExit'] == proof['converterActualExit'] == 0
        assert not proof['stopSent'] and len(proof['actorResult']['actors']) == 3
        assert all(actor['exit_code'] == 0 for actor in proof['actorResult']['actors'])
        records = proof['actorResult']['records']
        assert [record['bytes'] for record in records if record.get('op') == 'MOUNT'] == [8 * 2**20, 64 * 2**20]
        assert [record['flags'] for record in records if record.get('op') == 'UNMOUNT'] == [0, 0]
        account('mount', mount, MOUNT[0][0], [case for _, case in MOUNT], proof['actualGoExit'], proof['converterActualExit'], actual)

        shards = [('parents501', HEAVY[0], [HEAVY[1]])]
        for index, package in enumerate(sorted(ordinary_helper.PACKAGES)):
            names = sorted(name for pkg, name in remaining if pkg == package)
            for offset in range(0, len(names), 96):
                shards.append(('ordinary-' + str(index) + '-' + str(offset // 96), package, names[offset:offset + 96]))
        for name, package, names in shards:
            directory = output / name
            names_file = output / (name + '-cases.json')
            save(names_file, names)
            actual = invoke(name, 'run-unprivileged-go-ci.py', ['--output', str(directory), '--package', package,
                            '--cases', str(names_file), '--source-inputs', args.source_inputs,
                            '--test-binary', binaries['packages'][package]['path'], *common])
            proof = report.bounded_json(directory / 'producer-result.json')
            process = report.bounded_json(directory / 'process.json')
            wait = report.bounded_json(directory / 'actual-wait.json')
            terminal = report.bounded_json(directory / 'terminal-container.json')
            assert proof['status'] == 'PASS_SCOPED_ACTUAL_UNPRIVILEGED_GO_SHARD'
            assert proof['package'] == package and proof['cases'] == names
            assert proof['testBinarySHA256'] == binaries['packages'][package]['sha256']
            shard_source = report.bounded_json(directory / 'source-inputs.json')
            assert shard_source['inputs'] == source['inputs']
            assert shard_source['testBinarySHA256'] == proof['testBinarySHA256']
            assert wait == process['actualWait'] == proof['actualWait']
            assert wait['Observed'] and wait['Exited'] and not wait['Signaled'] and wait['ExitCode'] == wait['RawStatus'] == 0
            assert process['status'] == 'PASS_ACTUAL_UNPRIVILEGED_GO_SHARD' and process['actualJoin']
            assert process['pidfdTerminal'] and process['noAdoptedChildren'] and not process['observationError']
            assert process['containerId'] == proof['containerId'] == terminal['Id'] and terminal['Image'] == args.image
            assert terminal['State']['Status'] == 'exited' and terminal['State']['Pid'] == 0
            assert terminal['State']['ExitCode'] == proof['actualContainerExit'] == proof['converterActualExit'] == 0
            assert not terminal['State']['OOMKilled']
            observed = process['observed']
            profile(observed['profile'])
            assert observed['exeSHA256'] == proof['testBinarySHA256']
            assert observed['argv'] == ['/runtime/go-test', '-test.run=^(' + '|'.join(names) + ')$',
                                        '-test.count=1', '-test.timeout=10m', '-test.v']
            assert process['stdoutSHA256'] == digest(directory / 'stdout.log')
            assert process['stdoutBytes'] == (directory / 'stdout.log').stat().st_size
            account(name, directory, package, names, wait['ExitCode'], proof['converterActualExit'], actual)
        result = partition.partition_report(expected, scopes, report.ARCHIVAL_TEST)
    except Exception as error:
        result = partition.partition_report(expected, scopes, report.ARCHIVAL_TEST)
        result['errors'] = sorted(set(result['errors'] + ['SCOPE_EXECUTION_OR_RECEIPT_FAILED: ' + str(error)]))
        result.update(status='FAIL_REQUIRED_ORDINARY_GO_TEST_SUITE', completeInventoryAccounted=False, fullOrdinaryCIGreen=False)
    save(output / 'report.json', result)
    print(json.dumps({key: result[key] for key in ('status', 'ordinaryDiscovered', 'ordinaryAssigned', 'ordinaryPassed',
                                                   'completeInventoryAccounted', 'fullOrdinaryCIGreen', 'errors')}))
    return 1 if result['errors'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
