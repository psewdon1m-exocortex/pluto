"""Observe and join an actual unprivileged Go shard; retain PID1 on orphaned work."""
import hashlib
import json
import os
from pathlib import Path
import re
import select
import subprocess
import sys
import time


def digest(file):
    with Path(file).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(file, value):
    with Path(file).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def children():
    return [int(pid) for pid in Path('/proc/self/task/1/children').read_text().split()]


def _reap_adopted(evidence):
    """Reap kernel-confirmed terminal descendants; a live orphan still fails admission."""
    adopted = children()
    initial, reaped, live = [], [], []
    for pid in adopted:
        event = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        proc = Path('/proc') / str(pid)
        status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
        snapshot = dict(pid=pid, stat=(proc / 'stat').read_text(),
                        state=status['State'].strip(), parentPID=int(status['PPid']),
                        uid=status['Uid'].split())
        assert snapshot['parentPID'] == 1 and snapshot['uid'] == ['10001'] * 4
        snapshot['terminalWaitEvent'] = (dict(pid=event.si_pid, uid=event.si_uid,
                                            code=event.si_code, status=event.si_status)
                                         if event is not None else None)
        initial.append(snapshot)
        if event is None:
            live.append(pid)
            continue
        assert event.si_pid == pid and event.si_uid == 10001
        assert snapshot['state'].startswith('Z')
        assert event.si_code in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED)
        actual_pid, raw_status = os.waitpid(pid, 0)
        assert actual_pid == pid
        if event.si_code == os.CLD_EXITED:
            assert os.WIFEXITED(raw_status) and os.WEXITSTATUS(raw_status) == event.si_status
        else:
            assert os.WIFSIGNALED(raw_status) and os.WTERMSIG(raw_status) == event.si_status
        reaped.append(dict(pid=pid, rawStatus=raw_status, kernelTerminalBeforeReap=True,
                           waitEvent=snapshot['terminalWaitEvent'], result='TERMINAL_DESCENDANT_REAPED'))
        write(evidence / ('adopted-wait-' + str(pid) + '.json'), reaped[-1])
    unreviewed = [pid for pid in children() if pid not in live]
    if live or children():
        write(evidence / 'adopted-children-pending.json', dict(pids=children(), noKill=True,
                                                            admissionClosed=True))
        # PID1 must remain alive while any descendant can still execute.
        # Join naturally, retain the FAIL, and never turn this into success.
        while children():
            while True:
                pid, raw_status = os.waitpid(-1, os.WNOHANG)
                if not pid:
                    break
                reaped.append(dict(pid=pid, rawStatus=raw_status, kernelTerminalBeforeReap=False,
                                   result='LIVE_AT_BOUNDARY_DESCENDANT_JOINED_LATER'))
                write(evidence / ('adopted-wait-' + str(pid) + '.json'), reaped[-1])
                if not children():
                    break
            time.sleep(0.1)
    result = dict(adoptedAtRootExit=initial, adoptedWaits=reaped, liveAtRootExit=live,
                  noLiveAdoptedChildren=not live, unreviewedAfterInitial=unreviewed,
                  allAdoptedChildrenReapedBeforePID1Exit=not children(), noKill=True,
                  observerError='')
    write(evidence / 'adopted-descendants.json', result)
    return result


def reap_adopted(evidence):
    try:
        return _reap_adopted(evidence)
    except BaseException as error:
        # Even an observer/metadata error cannot make PID1 kill a live actor.
        pending = children()
        waits = []
        while children():
            pid, raw_status = os.waitpid(-1, 0)
            waits.append(dict(pid=pid, rawStatus=raw_status))
        result = dict(adoptedAtRootExit=[], adoptedWaits=waits, liveAtRootExit=pending,
                      noLiveAdoptedChildren=False, unreviewedAfterInitial=pending,
                      allAdoptedChildrenReapedBeforePID1Exit=not children(), noKill=True,
                      observerError=str(error) or repr(error))
        try:
            write(evidence / 'adopted-descendants-observer-error.json', result)
        except OSError:
            pass
        return result


def main():
    os.umask(0o077)
    assert os.getpid() == 1 and os.getuid() == os.getgid() == 10001
    spec = json.loads(Path('/input.json').read_bytes())
    assert spec['schema'] == 'pluto.ordinary-ci-worker-input.v1'
    assert re.fullmatch('[a-f0-9]{64}', spec['containerId'])
    assert os.uname().nodename == spec['containerId'][:12]
    names = spec['cases']
    assert 0 < len(names) <= 512 and len(names) == len(set(names))
    assert all(re.fullmatch('Test[A-Za-z0-9_]+', name) for name in names)
    binary = '/runtime/go-test'
    assert digest(binary) == spec['testBinarySHA256']
    evidence = Path('/retained/evidence')
    argv = [binary, '-test.run=^(' + '|'.join(names) + ')$', '-test.count=1',
            '-test.timeout=10m', '-test.v']
    environment = dict(PATH='/usr/local/bin:/usr/bin:/bin', LANG='C.UTF-8',
                       HOME='/retained/inputs', GOMAXPROCS='4', TMPDIR='/retained/inputs',
                       PLUTO_FAULT_INPUT_DIR='/retained/inputs',
                       PLUTO_FAULT_BACKUP_DIR='/backups/store',
                       P02_WIRE_OUTPUT='/retained/evidence/p02-wire.json')
    listed = subprocess.run([binary, '-test.list=^Test'], cwd=spec['workingDirectory'],
                            env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert listed.returncode == 0 and not listed.stderr and len(listed.stdout) <= 1024 * 1024
    discovered = listed.stdout.decode().splitlines()
    assert len(discovered) == len(set(discovered)) and set(names) <= set(discovered)
    with (evidence / 'inventory.stdout').open('xb') as inventory:
        inventory.write(listed.stdout)
        inventory.flush()
        os.fsync(inventory.fileno())
    observed = None
    observation_error = ''
    pidfd = None
    with (evidence / 'stdout.log').open('xb') as output:
        process = subprocess.Popen(argv, cwd=spec['workingDirectory'], env=environment,
                                   stdin=subprocess.DEVNULL, stdout=output,
                                   stderr=subprocess.STDOUT)
        write(evidence / 'started.json', dict(pid=process.pid, argv=argv,
                                             package=spec['package'], cases=names))
        try:
            pidfd = os.pidfd_open(process.pid)
            for _ in range(1000):
                try:
                    executable = os.readlink(f'/proc/{process.pid}/exe')
                    if executable == binary:
                        break
                except FileNotFoundError:
                    pass
                time.sleep(0.001)
            else:
                raise ValueError('actual Go executable was not observed after exec')
            proc = Path('/proc') / str(process.pid)
            status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines()
                          if ':' in line)
            profile = {key: status[key].strip() for key in
                       ('Uid', 'Gid', 'Groups', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd',
                        'CapAmb', 'NoNewPrivs', 'Seccomp')}
            actual_argv = [part.decode() for part in (proc / 'cmdline').read_bytes().split(b'\0')[:-1]]
            observed = dict(pid=process.pid, executable=executable, exeSHA256=digest(executable),
                            argv=actual_argv, stat=(proc / 'stat').read_text(),
                            parentPID=os.getpid(), parentStat=Path('/proc/self/stat').read_text(),
                            profile=profile, namespaces=[os.readlink('/proc/self/ns/' + name)
                                                         for name in ('mnt', 'pid', 'user')])
            assert actual_argv == argv and observed['exeSHA256'] == spec['testBinarySHA256']
            assert profile['Uid'].split() == profile['Gid'].split() == ['10001'] * 4
            assert profile['Groups'] == '' and profile['NoNewPrivs'] == '1' and profile['Seccomp'] == '2'
            assert all(int(profile[key], 16) == 0 for key in
                       ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'))
        except Exception as error:
            observation_error = str(error) or repr(error)
        finally:
            actual_pid, raw_status = os.waitpid(process.pid, 0)
            assert actual_pid == process.pid
            process.returncode = os.waitstatus_to_exitcode(raw_status)
            actual = dict(PID=actual_pid, Observed=True, Exited=os.WIFEXITED(raw_status),
                          Signaled=os.WIFSIGNALED(raw_status),
                          ExitCode=os.WEXITSTATUS(raw_status) if os.WIFEXITED(raw_status) else 0,
                          Signal=os.WTERMSIG(raw_status) if os.WIFSIGNALED(raw_status) else 0,
                          RawStatus=raw_status)
            # Numeric wait is durable before optional post-exit metadata.
            write(evidence / 'actual-wait.json', actual)
        output.flush()
        os.fsync(output.fileno())
    terminal = False
    if pidfd is not None:
        poll = select.poll()
        poll.register(pidfd, select.POLLIN)
        terminal = bool(poll.poll(1000))
        os.close(pidfd)
    descendants = reap_adopted(evidence)
    raw = evidence / 'stdout.log'
    result = dict(schema='pluto.ordinary-ci-process.v2', package=spec['package'], cases=names,
                  containerId=spec['containerId'], actualWait=actual, actualJoin=True,
                  pidfdTerminal=terminal, observed=observed, observationError=observation_error,
                  noAdoptedChildren=not descendants['adoptedAtRootExit'],
                  descendants=descendants, noKill=True,
                  stdoutBytes=raw.stat().st_size, stdoutSHA256=digest(raw),
                  inputRoot='/retained/inputs', backupRoot='/backups/store')
    passed = (actual['Exited'] and not actual['Signaled'] and actual['ExitCode'] == 0
              and terminal and observed and not observation_error
              and descendants['noLiveAdoptedChildren']
              and not descendants['unreviewedAfterInitial']
              and descendants['allAdoptedChildrenReapedBeforePID1Exit'])
    result['status'] = 'PASS_ACTUAL_UNPRIVILEGED_GO_SHARD' if passed else 'FAIL'
    write(evidence / 'process.json', result)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
