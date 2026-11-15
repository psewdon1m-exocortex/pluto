"""Phase2 REVIEW ONLY. Imports the frozen/qualified Phase1 drop and IPC code.

No compile/start/mount effects are authorized by possession of this source.
"""
import argparse
import ctypes
import datetime
import hashlib
import importlib.util
import json
import os
import signal
import socket
import stat
import sys
import time
import traceback

SELECTION = "^(TestStage3C02NativeUnmountGap|TestStage3C03NativeDiskFullPreservesCommit)$"
import re
RUN = "release-candidate-20261102T192007Z-587ea6af"
BASE = None


def sha_file(filename, limit=64 << 20):
    with open(filename, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise RuntimeError("bounded regular public input required")
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def load_marker(filename):
    global BASE
    info = os.lstat(filename)
    if not stat.S_ISREG(info.st_mode) or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (0, 0, 0o444) or info.st_size > 4096:
        raise RuntimeError("readonly bounded root marker required")
    with open(filename, "rb") as stream:
        marker = json.load(stream)
    nonce = marker["nonce"]
    prefix = "/exocortex-native-mount-p2-" + nonce[:16]
    if (len(nonce) != 64 or any(c not in "0123456789abcdef" for c in nonce) or
            marker["schema"] != "native-mount-phase2.v1" or marker["run"] != RUN or
            marker["scope"] != "PLUTO-NATIVE-MOUNT-PHASE2-" + nonce[:16] or
            marker["prefix"] != prefix or marker["base"] != "/fixture-p2-"+nonce[:16] or
            filename != prefix+".json" or os.path.abspath(__file__) != prefix+".py" or
            not re.fullmatch("sha256:[a-f0-9]{64}", marker["image"]) or len(marker["container_id"]) != 64 or
            os.uname().nodename != marker["container_id"][:12] or not os.path.isfile("/.dockerenv")):
        raise RuntimeError("fresh scope/container association refused")
    age = (datetime.datetime.now(datetime.timezone.utc)-datetime.datetime.fromisoformat(marker["created"].replace("Z", "+00:00"))).total_seconds()
    if age < 0 or age > 180:
        raise RuntimeError("created lease expired")
    for suffix, key in ((".py", "helper_python_sha256"), (".base.py", "base_python_sha256"), (".test", "test_binary_sha256")):
        current = os.lstat(prefix+suffix)
        mode = 0o555 if suffix == ".test" else 0o444
        if (current.st_uid, current.st_gid, stat.S_IMODE(current.st_mode)) != (0, 0, mode) or not stat.S_ISREG(current.st_mode) or sha_file(prefix+suffix) != marker[key]:
            raise RuntimeError("staged public byte/owner/mode custody refused")
    if marker["go_argv"] != [prefix+".test", "-test.run="+SELECTION, "-test.v", "-test.count=1", "-test.timeout=0"]:
        raise RuntimeError("only exact two native tests admitted")
    spec = importlib.util.spec_from_file_location("qualified_phase1", prefix+".base.py")
    BASE = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(BASE)
    BASE.ACTIVE_MARKER = marker
    signal.signal(signal.SIGTERM, BASE.on_term)
    signal.signal(signal.SIGINT, BASE.on_term)
    return marker


def directory_identity(path, mode):
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (10001, 10001, mode) or os.path.realpath(path) != path:
        raise RuntimeError("fresh nonroot real directory ownership refused")
    return {"dev": info.st_dev, "ino": info.st_ino, "uid": info.st_uid, "gid": info.st_gid, "mode": oct(stat.S_IMODE(info.st_mode))}


def go_root(marker, path, expected=None):
    if os.path.dirname(path) != marker["base"]+"/work" or not os.path.basename(path).startswith("go-"+marker["nonce"][:16]+"-"):
        raise RuntimeError("fixed fresh GoTempDir scope required")
    actual = directory_identity(path, 0o711)
    if BASE.mount_entry(path) is not None or (expected is not None and actual != expected):
        raise RuntimeError("GoTempDir mount/incarnation changed")
    return actual


def native_identity(marker, pid, ticks):
    before = BASE.snapshot(pid)
    BASE.check_role(before, "probe")
    if before["start_ticks"] != ticks or before["ppid"] != 1:
        raise RuntimeError("own forked Go PID/start/parent changed")
    executable = os.readlink(f"/proc/{pid}/exe")
    with open(f"/proc/{pid}/cmdline", "rb") as stream:
        argv = [part.decode() for part in stream.read(8193).rstrip(b"\0").split(b"\0")]
    actual_sha = sha_file(f"/proc/{pid}/exe")
    if executable != marker["prefix"]+".test" or argv != marker["go_argv"] or actual_sha != marker["test_binary_sha256"] or BASE.snapshot(pid) != before:
        raise RuntimeError("independent actual Go exe/hash/argv/incarnation refused")
    parent = BASE.snapshot(1)
    BASE.check_role(parent, "controller")
    return {"identity": before, "exe": executable, "argv": argv, "exe_sha256": actual_sha, "parent": parent}


def witness(marker, sock):
    BASE.check_role(BASE.snapshot(os.getpid()), "probe")
    BASE.send(sock, marker, op="READY", role="witness", identity=BASE.snapshot(os.getpid()))
    deadline, sequence, native = time.monotonic()+75, 0, None
    while True:
        request = BASE.receive(sock, marker, deadline, 1, 0)
        if request.get("seq") != sequence+1:
            raise RuntimeError("witness sequence refused")
        sequence += 1
        if request.get("op") == "STOP":
            return 0
        if request.get("op") == "VERIFY_NATIVE" and native is None:
            native = {"pid": request["pid"], "ticks": request["ticks"], "root": request["go_temp"]}
            result = native_identity(marker, native["pid"], native["ticks"])
            native["root_identity"] = go_root(marker, native["root"])
            if os.listdir(native["root"]):
                raise RuntimeError("fresh GoTempDir must be empty before RUN")
            result.update(go_temp=native["root"], root_identity=native["root_identity"])
        elif request.get("op") == "VERIFY_TARGET" and native is not None and request.get("kind") in ("small", "large"):
            result = native_identity(marker, native["pid"], native["ticks"])
            go_root(marker, native["root"], native["root_identity"])
            target = native["root"]+"/"+request["kind"]
            actual = directory_identity(target, 0o700)
            if BASE.mount_entry(target) is not None or os.listdir(target):
                raise RuntimeError("fresh exact mount target must be empty/unmounted")
            result.update(target=target, target_identity=actual)
        else:
            raise RuntimeError("witness fixed once-native/fixed-kind protocol refused")
        BASE.send(sock, marker, op="RESULT", seq=sequence, result=result)


def supervisor(marker, sock):
    BASE.check_role(BASE.snapshot(os.getpid()), "supervisor")
    mounted, records, sequence, root, root_identity = {}, [], 0, None, None
    directory = marker["base"]+"/supervisor"
    os.mkdir(directory, 0o700)
    BASE.send(sock, marker, op="READY", role="supervisor", identity=BASE.snapshot(os.getpid()))
    failure = None
    try:
        while True:
            request = BASE.receive(sock, marker, time.monotonic()+75, 1, 0)
            if request.get("seq") != sequence+1:
                raise RuntimeError("supervisor sequence refused")
            sequence += 1
            op, kind = request.get("op"), request.get("kind")
            if op == "STOP":
                break
            if op == "BIND_ROOT" and root is None:
                root = request["go_temp"]
                root_identity = go_root(marker, root, request["root_identity"])
                receipt = {"op": op, "go_temp": root, "root_identity": root_identity}
            elif root is not None and op in ("MOUNT", "UNMOUNT") and kind in ("small", "large"):
                go_root(marker, root, root_identity)
                target = root+"/"+kind
                if request.get("target") != target:
                    raise RuntimeError("fixed exact target refused")
                if op == "MOUNT":
                    if kind in mounted or BASE.mount_entry(target) is not None or directory_identity(target, 0o700) != request["target_identity"]:
                        raise RuntimeError("fresh target inode/no-existing-mount refused")
                    size = (8 if kind == "small" else 64) << 20
                    data = f"size={size},uid=10001,gid=10001,mode=0700".encode()
                    if BASE.native_libc().mount(b"tmpfs", target.encode(), b"tmpfs", 2|4|8, data) != 0:
                        raise OSError(ctypes.get_errno(), "actual native mount refused")
                    mounted[kind] = {"id": None, "target": target}
                    entry = BASE.mount_entry(target)
                    if entry is None or entry["type"] != "tmpfs":
                        raise RuntimeError("actual mount receipt absent")
                    mounted[kind] = entry
                    receipt = {"op": op, "kind": kind, "mount": entry, "bytes": size}
                else:
                    if kind not in mounted or request.get("mount_id") != mounted[kind]["id"] or BASE.mount_entry(target) != mounted[kind]:
                        raise RuntimeError("normal unmount exact incarnation refused")
                    # Durable record of the owned mount BEFORE every umount.
                    BASE.durable(directory+f"/pre-unmount-{sequence}.json", mounted[kind])
                    decision = BASE.cleanup_owned_mount(mounted, kind, BASE.mount_entry, lambda path, flags: BASE.native_libc().umount2(path.encode(), flags))
                    if decision["status"] != "NORMAL_UMOUNT_VERIFIED":
                        raise RuntimeError("normal unmount retained: "+repr(decision))
                    receipt = {"op": op, "kind": kind, "mount_id_removed": decision["id"], "flags": 0}
            else:
                raise RuntimeError("fixed supervisor operation refused")
            records.append(receipt)
            BASE.durable(directory+f"/operation-{sequence}.json", receipt)
            BASE.send(sock, marker, op="RESULT", seq=sequence, result=receipt)
    except BaseException as error:
        failure = repr(error)
    finally:
        try:
            BASE.durable(directory+"/final-before-cleanup.json", {"failure": failure, "records": records, "mounted": mounted})
        except BaseException:
            while mounted:
                time.sleep(1)
            raise
        decisions = [BASE.cleanup_owned_mount(mounted, kind, BASE.mount_entry, lambda path, flags: BASE.native_libc().umount2(path.encode(), flags)) for kind in list(mounted)]
        BASE.durable(directory+"/cleanup.json", {"remaining": mounted, "decisions": decisions})
        while mounted:
            time.sleep(1)  # Retain unknown/replacement/busy namespace; no fallback.
            for kind in list(mounted):
                BASE.cleanup_owned_mount(mounted, kind, BASE.mount_entry, lambda path, flags: BASE.native_libc().umount2(path.encode(), flags))
        sock.close()
    return 0 if failure is None else 1


def launch(marker, role):
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    for channel in (parent, child):
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    caps = ["--bounding-set=-all,+sys_admin"] if role == "supervisor" else ["--reuid=10001", "--regid=10001", "--clear-groups", "--bounding-set=-all"]
    program = marker["go_argv"] if role == "native" else ["/usr/local/bin/python3.13", "-I", "-B", "-u", marker["prefix"]+".py", "--role", role, "--marker", ARGS.marker, "--fd", str(child.fileno())]
    argv = ["/usr/bin/setpriv", *caps, "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--", *program]
    output = os.open(marker["base"]+f"/{role}.stdout", os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0o600)
    error = os.open(marker["base"]+f"/{role}.stderr", os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0o600)
    pid = os.fork()
    if pid == 0:
        try:
            null = os.open("/dev/null", os.O_RDONLY)
            os.dup2(null, 0); os.dup2(output, 1); os.dup2(error, 2)
            child.set_inheritable(True)
            for name in os.listdir("/proc/self/fd"):
                fd = int(name)
                if fd not in (0, 1, 2, child.fileno()):
                    try: os.close(fd)
                    except OSError: pass
            env = dict(os.environ)
            if role == "native":
                env.update(STAGE3_NATIVE_MOUNT_MARKER=ARGS.marker, STAGE3_NATIVE_MOUNT_FD=str(child.fileno()), TMPDIR=marker["base"]+"/work", GOMAXPROCS="2")
            os.execve(argv[0], argv, env)
        except BaseException:
            traceback.print_exc(); os._exit(77)
    os.close(output); os.close(error); child.close()
    ticks = BASE.snapshot(pid)["start_ticks"]  # Captured by own parent, not Go.
    return {"pid": pid, "start_ticks": ticks, "fd": parent.detach(), "role": role, "seq": 0}


def controller(marker, state):
    BASE.IS_CONTROLLER = True
    actors = state["actors"]
    channels = {actor["role"]: BASE.channel(actor["fd"]) for actor in actors}
    native = next(actor for actor in actors if actor["role"] == "native")
    records, failure, claimed_exit = [], None, None
    deadline = time.monotonic()+60
    def receive(role, until=deadline):
        actor = next(item for item in actors if item["role"] == role)
        return BASE.receive(channels[role], marker, until, actor["pid"], 0 if role == "supervisor" else 10001)
    def rpc(role, op, **fields):
        actor = next(item for item in actors if item["role"] == role)
        actor["seq"] += 1
        BASE.send(channels[role], marker, op=op, seq=actor["seq"], **fields)
        reply = receive(role, min(deadline, time.monotonic()+5))
        if reply.get("op") != "RESULT" or reply.get("seq") != actor["seq"]:
            raise RuntimeError("exact RPC result sequence required")
        records.append(reply["result"])
        return reply["result"]
    try:
        for actor in actors:
            ready = receive(actor["role"])
            actual = BASE.snapshot(actor["pid"])
            BASE.check_role(actual, "supervisor" if actor["role"] == "supervisor" else "probe")
            if ready.get("op") != "READY" or ready.get("identity") != actual or actual["start_ticks"] != actor["start_ticks"] or actual["ppid"] != 1:
                raise RuntimeError("independent after-exec role/start gate refused")
            records.append({"role": actor["role"], "independent": actual})
            if actor["role"] == "native":
                native_root = ready["go_temp"]
        custody = rpc("witness", "VERIFY_NATIVE", pid=native["pid"], ticks=native["start_ticks"], go_temp=native_root)
        if custody["identity"] != BASE.snapshot(native["pid"]) or custody["exe_sha256"] != marker["test_binary_sha256"]:
            raise RuntimeError("independent actual Go witness differs")
        BASE.check_role(BASE.snapshot(1), "controller")
        rpc("supervisor", "BIND_ROOT", go_temp=native_root, root_identity=custody["root_identity"])
        BASE.durable(marker["base"]+"/controller/roles-and-custody-before-RUN.json", {"records": records, "controller": BASE.snapshot(1), "custody": custody, "source_manifest_sha256": marker["source_manifest_sha256"]})
        BASE.send(channels["native"], marker, op="RUN", seq=0)
        expected = [("MOUNT", "small"), ("UNMOUNT", "small"), ("MOUNT", "large"), ("UNMOUNT", "large")]
        for sequence, (operation, kind) in enumerate(expected, 1):
            request = receive("native")
            if request.get("op") == "DONE":
                raise RuntimeError("native tests ended before all required real mount transitions")
            actual = BASE.snapshot(native["pid"]); BASE.check_role(actual, "probe")
            if actual["start_ticks"] != native["start_ticks"] or request.get("seq") != sequence or (request.get("op"), request.get("kind")) != (operation, kind) or request.get("target") != native_root+"/"+kind:
                raise RuntimeError("fixed Go native operation/pid/scope sequence refused")
            fields = {"kind": kind, "target": native_root+"/"+kind}
            if operation == "MOUNT":
                target = rpc("witness", "VERIFY_TARGET", kind=kind)
                fields["target_identity"] = target["target_identity"]
            else:
                fields["mount_id"] = request["mount_id"]
            result = rpc("supervisor", operation, **fields)
            BASE.send(channels["native"], marker, op="RESULT", seq=sequence, result=result)
        done = receive("native")
        if done.get("op") != "DONE" or done.get("seq") != 5 or type(done.get("exit")) is not int:
            raise RuntimeError("native DONE contract refused")
        claimed_exit = done["exit"]
    except BaseException as error:
        failure = repr(error)
    finally:
        for role in ("native", "witness", "supervisor"):
            actor = next(item for item in actors if item["role"] == role)
            if role != "native" or failure is not None:
                try:
                    actor["seq"] += 1; BASE.send(channels[role], marker, op="STOP", seq=actor["seq"])
                except BaseException: pass
            code = BASE.actual_exit(actor, time.monotonic()+10)
            channels[role].close()
            if code is None:
                code = BASE.actual_exit(actor, time.monotonic()+80)
            if code is None:
                failure = failure or "owned actor retained awaiting natural join"
        while any("exit_code" not in actor for actor in actors):
            print(json.dumps({"event": "BLOCKED_RETAINED_OWNER", "failure": failure}), flush=True)
            for actor in actors:
                if "exit_code" not in actor: BASE.actual_exit(actor, time.monotonic()+1)
        unexpected = []
        with open("/proc/self/mountinfo") as stream:
            unexpected = [line.rstrip() for line in stream if line.split()[4].startswith(marker["base"]+"/")]
        while unexpected:
            print(json.dumps({"event": "BLOCKED_RETAINED_NAMESPACE", "mounts": unexpected}), flush=True); time.sleep(1)
            with open("/proc/self/mountinfo") as stream:
                unexpected = [line.rstrip() for line in stream if line.split()[4].startswith(marker["base"]+"/")]
        success = failure is None and claimed_exit == 0 and all(actor["exit_code"] == 0 for actor in actors)
        result = {"status": "PASS_EXACT_TWO_NATIVE_TESTS" if success else "FAIL_EXACT_TWO_NATIVE_TESTS", "failure": failure, "claimed_go_exit": claimed_exit, "actors": actors, "records": records, "full_race_suite_pass": False, "production_permission_equivalence": False}
        BASE.durable(marker["base"]+"/controller/final.json", result)
        print(json.dumps({"event": "FINAL", "summary": result}), flush=True)
    return 0 if success else 1


def bootstrap(marker):
    if os.getpid() != 1: raise RuntimeError("private PID1 required")
    BASE.check_role(BASE.snapshot(1), "bootstrap")
    for target in (marker["base"], "/etc/pluto", "/var/lib/pluto", "/run/pluto", "/usr/local/bin/pluto"):
        if os.path.lexists(target): raise RuntimeError("fresh/protected-path absence refused")
    os.mkdir(marker["base"], 0o755); os.mkdir(marker["base"]+"/controller", 0o700)
    os.mkdir(marker["base"]+"/work", 0o777); os.chmod(marker["base"]+"/work", 0o1777)
    actors = []
    try:
        for role in ("supervisor", "witness", "native"): actors.append(launch(marker, role))
        state = {"actors": actors}
        BASE.durable(marker["base"]+"/controller/own-fork-identities.json", state)
        return BASE.enter_loaded_controller(marker, state, BASE.LinuxPid1DropOnly(), controller)
    finally:
        for actor in actors:
            if "exit_code" not in actor:
                try: os.close(actor["fd"])
                except OSError: pass
        while any("exit_code" not in actor for actor in actors):
            for actor in actors:
                if "exit_code" not in actor: BASE.actual_exit(actor, time.monotonic()+1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=("bootstrap", "supervisor", "witness"), required=True)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--fd", type=int)
    ARGS = parser.parse_args()
    try:
        marker = load_marker(ARGS.marker)
        if ARGS.role == "bootstrap": code = bootstrap(marker)
        else:
            channel = BASE.channel(ARGS.fd)
            code = supervisor(marker, channel) if ARGS.role == "supervisor" else witness(marker, channel)
    except BaseException:
        traceback.print_exc()
        if os.getpid() == 1:
            os.closerange(3, 1024)
            while True:
                try:
                    pid, status = os.waitpid(-1, 0)
                    print(json.dumps({"event": "ACTOR_EXIT_EMERGENCY", "pid": pid, "actual_exit_code": os.waitstatus_to_exitcode(status)}), flush=True)
                except ChildProcessError: break
        sys.exit(77)
    sys.exit(code)
