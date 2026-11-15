"""Tiny Phase1 only. setpriv changes child capabilities; PID1 stays loaded.

No Go/native tests, no source/compiler, no host mounts, no production acceptance.
All positive fixture effects wait for independent after-exec /proc gates.
"""
import argparse
import ctypes
import datetime
import errno
import hashlib
import json
import os
import select
import signal
import socket
import stat
import struct
import sys
import time
import traceback

RUN = "release-candidate-20261102T192007Z-587ea6af"
CAPS = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
ADMIN = 1 << 21
BOOT = ADMIN | (1 << 8) | (1 << 7) | (1 << 6)
MAX_FRAME = 4096
STOP = False
HOST_INPUT = bytearray()
ACTIVE_MARKER = None
IS_CONTROLLER = False
LIBC = None


def native_libc():
    global LIBC
    if LIBC is None:
        LIBC = ctypes.CDLL(None, use_errno=True)
        LIBC.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                              ctypes.c_ulong, ctypes.c_char_p]
        LIBC.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
    return LIBC


def on_term(_sig, _frame):
    global STOP
    STOP = True


def poll_host_stop():
    global STOP
    if os.getpid() != 1 or ACTIVE_MARKER is None or not IS_CONTROLLER:
        return
    ready, _, _ = select.select([0], [], [], 0)
    if not ready:
        return
    data = os.read(0, MAX_FRAME + 1)
    if not data:
        STOP = True
        return
    HOST_INPUT.extend(data)
    if len(HOST_INPUT) > MAX_FRAME:
        raise RuntimeError("host control frame exceeded limit")
    if b"\n" in HOST_INPUT:
        raw, _, tail = HOST_INPUT.partition(b"\n")
        HOST_INPUT[:] = tail
        value = decode(bytes(raw))
        if value != {"op": "STOP", "nonce": ACTIVE_MARKER["nonce"]}:
            raise RuntimeError("host stop token refused")
        STOP = True


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def decode(raw):
    if not raw or len(raw) > MAX_FRAME:
        raise ValueError("bounded JSON frame required")
    return json.loads(raw, object_pairs_hook=unique_pairs)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def durable(path, value):
    raw = (json.dumps(value, sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        raise
    return {"path": path, "sha256": digest(raw), "bytes": len(raw)}


def snapshot(pid):
    with open(f"/proc/{pid}/status", encoding="ascii") as stream:
        fields = dict(line.rstrip().split(":", 1) for line in stream)
    with open(f"/proc/{pid}/stat", encoding="ascii") as stream:
        raw = stream.read()
    tail = raw[raw.rfind(")") + 2:].split()
    return {"pid": int(fields["Pid"]), "ppid": int(fields["PPid"]),
            "start_ticks": int(tail[19]),
            "uid": [int(n) for n in fields["Uid"].split()],
            "gid": [int(n) for n in fields["Gid"].split()],
            "groups": [int(n) for n in fields["Groups"].split()],
            "caps": {name: int(fields[name], 16) for name in CAPS},
            "nnp": int(fields["NoNewPrivs"]),
            "seccomp": int(fields["Seccomp"])}


def check_role(actual, role):
    uid = 10001 if role == "probe" else 0
    mask = BOOT if role == "bootstrap" else ADMIN if role == "supervisor" else 0
    expected = {"CapInh": 0, "CapPrm": mask, "CapEff": mask,
                "CapBnd": mask, "CapAmb": 0}
    if (actual["uid"] != [uid] * 4 or actual["gid"] != [uid] * 4 or
            actual["caps"] != expected or actual["nnp"] != 1 or
            actual["seccomp"] != 2 or (role == "probe" and actual["groups"])):
        raise RuntimeError(f"after-exec identity/capability gate refused {role}: {actual}")


class LinuxPid1DropOnly:
    """No adds/restores, UID changes, keepcaps or exec. Four known bits only."""
    def identity(self):
        return snapshot(os.getpid())

    def thread_count(self):
        return len(os.listdir("/proc/self/task"))

    def clear_ambient(self):
        # PR_CAP_AMBIENT / PR_CAP_AMBIENT_CLEAR_ALL.
        if native_libc().prctl(47, 4, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "drop ambient capabilities")

    def drop_bounding(self, cap):
        if cap not in (21, 7, 6, 8):
            raise RuntimeError("only four reviewed bounding bits may be dropped")
        if native_libc().prctl(24, cap, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "PR_CAPBSET_DROP")

    def clear_sets(self):
        class Header(ctypes.Structure):
            _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]
        class Data(ctypes.Structure):
            _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                        ("inheritable", ctypes.c_uint32)]
        header, data = Header(0x20080522, 0), (Data * 2)()
        if native_libc().capset(ctypes.byref(header), ctypes.byref(data)) != 0:
            raise OSError(ctypes.get_errno(), "drop-only zero capset")


def drop_pid1_known_caps(api):
    check_role(api.identity(), "bootstrap")
    if api.thread_count() != 1:
        raise RuntimeError("PID1 must be single-threaded while dropping per-thread capabilities")
    api.clear_ambient()
    remaining = BOOT
    for cap in (21, 7, 6, 8):  # SETPCAP is dropped from Bnd last; P/E still held.
        api.drop_bounding(cap)
        remaining &= ~(1 << cap)
        actual = api.identity()
        expected = {"CapInh": 0, "CapPrm": BOOT, "CapEff": BOOT,
                    "CapBnd": remaining, "CapAmb": 0}
        if (actual["caps"] != expected or actual["uid"] != [0]*4 or
                actual["gid"] != [0]*4 or actual["nnp"] != 1 or actual["seccomp"] != 2):
            raise RuntimeError("bounding drop was not the exact irreversible known-bit transition")
    api.clear_sets()
    check_role(api.identity(), "controller")


def enter_loaded_controller(marker, state, drop_api, run_controller):
    drop_pid1_known_caps(drop_api)
    return run_controller(marker, state)


def marker_load(path):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0:
        raise RuntimeError("root-owned regular marker required")
    with open(path, "rb") as stream:
        marker = decode(stream.read(MAX_FRAME + 1))
    required = {"schema", "run", "scope", "nonce", "container_id", "created",
                "image", "script_sha256", "prefix"}
    if (set(marker) != required or marker["schema"] != "native-mount-phase1.v1" or
            marker["run"] != RUN or len(marker["nonce"]) != 64 or
            any(c not in "0123456789abcdef" for c in marker["nonce"]) or
            marker["scope"] != "PLUTO-NATIVE-MOUNT-PHASE1-" + marker["nonce"][:16] or
            marker["prefix"] != "/exocortex-native-mount-" + marker["nonce"][:16] or
            len(marker["container_id"]) != 64 or
            any(c not in "0123456789abcdef" for c in marker["container_id"]) or
            marker["image"] != "sha256:d3c2282af752028b4ce933bc4c5fe9ec1b757a0527757c17967890ac9f97a60a" or
            os.path.abspath(__file__) != marker["prefix"] + ".py" or
            path != marker["prefix"] + ".json" or
            os.uname().nodename != marker["container_id"][:12]):
        raise RuntimeError("fresh container/nonce/run/scope marker refused")
    created = datetime.datetime.fromisoformat(marker["created"].replace("Z", "+00:00"))
    age = (datetime.datetime.now(datetime.timezone.utc) - created).total_seconds()
    if age < 0 or age > 180:
        raise RuntimeError("fresh created-container lease expired")
    own = os.lstat(os.path.abspath(__file__))
    with open(__file__, "rb") as stream:
        script_hash = digest(stream.read())
    if not stat.S_ISREG(own.st_mode) or own.st_uid != 0 or script_hash != marker["script_sha256"]:
        raise RuntimeError("script byte/ownership gate refused")
    if not os.path.isfile("/.dockerenv"):
        raise RuntimeError("container evidence required")
    marker["base"] = "/fixture-" + marker["nonce"][:16]
    return marker


def channel(fd):
    sock = socket.socket(fileno=fd)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    return sock


def packet(marker, **body):
    return {"run": marker["run"], "scope": marker["scope"],
            "nonce": marker["nonce"], **body}


def send(sock, marker, **body):
    raw = json.dumps(packet(marker, **body), separators=(",", ":")).encode()
    if len(raw) > MAX_FRAME:
        raise RuntimeError("outbound frame exceeded limit")
    sock.sendall(raw)


def receive(sock, marker, deadline, expected_pid, expected_uid):
    while time.monotonic() < deadline:
        poll_host_stop()
        if STOP:
            raise InterruptedError("ordinary stop requested")
        ready, _, _ = select.select([sock], [], [], min(0.2, max(0, deadline-time.monotonic())))
        if not ready:
            continue
        raw, ancillary, flags, _ = sock.recvmsg(MAX_FRAME, socket.CMSG_SPACE(12))
        if not raw:
            raise EOFError("owner/control EOF")
        credentials = [struct.unpack("3i", data[:12]) for level, kind, data in ancillary
                       if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS]
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(credentials) != 1:
            raise RuntimeError("kernel sender credentials/frame refused")
        pid, uid, _gid = credentials[0]
        if pid != expected_pid or uid != expected_uid:
            raise RuntimeError("wrong live kernel sender identity")
        value = decode(raw)
        if any(value.get(key) != marker[key] for key in ("run", "scope", "nonce")):
            raise RuntimeError("stale nonce/run/scope frame")
        return value
    raise TimeoutError("finite control lease expired")


def mount_entry(path):
    with open("/proc/self/mountinfo", encoding="ascii") as stream:
        found = []
        for line in stream:
            left, right = line.rstrip().split(" - ", 1)
            fields = left.split()
            if fields[4] == path:
                tail = right.split()
                found.append({"id": int(fields[0]), "target": path,
                              "type": tail[0], "options": tail[2]})
    if len(found) > 1:
        raise RuntimeError("ambiguous mount stack")
    return found[0] if found else None


def cleanup_owned_mount(mounted, kind, query, unmount):
    """No syscall for unknown, missing or replaced incarnation. Retain it."""
    expected = mounted[kind]
    if type(expected.get("id")) is not int or expected["id"] <= 0:
        return {"kind": kind, "status": "RETAIN_UNKNOWN_ID"}
    target = expected["target"]
    try:
        current = query(target)
    except Exception as error:
        return {"kind": kind, "status": "RETAIN_QUERY_FAILURE", "error": repr(error)}
    if current != expected:
        return {"kind": kind, "status": "RETAIN_CHANGED_INCARNATION", "expected": expected,
                "current": current}
    if unmount(target, 0) != 0:
        return {"kind": kind, "status": "RETAIN_NORMAL_UMOUNT_FAILURE", "id": expected["id"]}
    try:
        after = query(target)
    except Exception as error:
        return {"kind": kind, "status": "RETAIN_POST_UMOUNT_QUERY_FAILURE", "error": repr(error)}
    if after is not None:
        return {"kind": kind, "status": "RETAIN_POST_UMOUNT_REPLACEMENT", "current": after}
    mounted.pop(kind)
    return {"kind": kind, "status": "NORMAL_UMOUNT_VERIFIED", "id": expected["id"], "flags": 0}


def supervisor(marker, sock):
    check_role(snapshot(os.getpid()), "supervisor")
    mounted = {}
    receipts = []
    directory = marker["base"] + "/supervisor"
    os.mkdir(directory, 0o700)
    deadline = time.monotonic() + 75
    sequence = 0
    send(sock, marker, op="READY", role="supervisor", identity=snapshot(os.getpid()),
         mount_ns=os.stat("/proc/self/ns/mnt").st_ino)
    failure = None
    try:
        while True:
            request = receive(sock, marker, deadline, 1, 0)
            if request.get("seq") != sequence + 1:
                raise RuntimeError("supervisor sequence refused")
            sequence += 1
            op, kind = request.get("op"), request.get("kind")
            if op == "STOP":
                break
            if kind not in ("small", "large") or op not in ("MOUNT", "UNMOUNT"):
                raise RuntimeError("fixed operation/case enum required")
            target = marker["base"] + "/mounts/" + kind
            if op == "MOUNT":
                if kind in mounted or os.path.lexists(target):
                    raise RuntimeError("fresh mount target required")
                os.mkdir(target, 0o755)
                size = (8 if kind == "small" else 64) << 20
                data = f"size={size},uid=10001,gid=10001,mode=0700".encode()
                if native_libc().mount(b"tmpfs", target.encode(), b"tmpfs", 2 | 4 | 8, data) != 0:
                    raise OSError(ctypes.get_errno(), "native mount denied")
                mounted[kind] = {"id": None, "target": target}
                entry = mount_entry(target)
                if entry is None or entry["type"] != "tmpfs":
                    raise RuntimeError("real tmpfs mount receipt missing")
                mounted[kind] = entry
                receipt = {"op": op, "kind": kind, "mount": entry, "bytes": size}
            else:
                if kind not in mounted or mount_entry(target) != mounted[kind]:
                    raise RuntimeError("mount ownership/incarnation changed")
                if native_libc().umount2(target.encode(), 0) != 0:
                    raise OSError(ctypes.get_errno(), "normal umount blocked")
                if mount_entry(target) is not None:
                    raise RuntimeError("mount ID remained after normal umount")
                receipt = {"op": op, "kind": kind, "mount_id_removed": mounted.pop(kind)["id"], "flags": 0}
            receipts.append(receipt)
            durable(directory + f"/operation-{sequence}.json", receipt)
            send(sock, marker, op="RESULT", seq=sequence, result=receipt)
    except BaseException as error:
        failure = repr(error)
    finally:
        # Tiny Phase1 has no DB: save durable overlay receipts BEFORE cleanup.
        try:
            durable(directory + "/final-before-cleanup.json", {"failure": failure, "receipts": receipts,
                                                              "mounted": mounted})
        except BaseException as error:
            print("durable receipt blocked; retain mounted namespace: " + repr(error), file=sys.stderr, flush=True)
            while mounted:
                time.sleep(0.2)
            raise
        unmount = lambda target, flags: native_libc().umount2(target.encode(), flags)
        decisions = [cleanup_owned_mount(mounted, kind, mount_entry, unmount) for kind in list(mounted)]
        durable(directory + "/cleanup.json", {"remaining": mounted, "decisions": decisions,
                                              "normal_flags": 0})
        # Refuse PID1 exit over a busy live supervisor. No detach/kill fallback.
        while mounted:
            time.sleep(0.2)
            for kind in list(mounted):
                cleanup_owned_mount(mounted, kind, mount_entry, unmount)
        if decisions:
            durable(directory + "/cleanup-after-wait.json", {"remaining": mounted})
        sock.close()
    return 0 if failure is None else 1


def probe(marker, sock):
    check_role(snapshot(os.getpid()), "probe")
    profile = marker["base"] + "/work/probe-" + marker["nonce"][:16]
    os.mkdir(profile, 0o700)
    deadline, sequence = time.monotonic() + 45, 0
    receipts = []
    failure = None
    send(sock, marker, op="READY", role="probe", identity=snapshot(os.getpid()),
         mount_ns=os.stat("/proc/self/ns/mnt").st_ino)
    try:
        while True:
            request = receive(sock, marker, deadline, 1, 0)
            if request.get("seq") != sequence + 1:
                raise RuntimeError("probe sequence refused")
            sequence += 1
            op = request.get("op")
            if op == "STOP":
                break
            check_role(snapshot(os.getpid()), "probe")
            if op == "NEGATIVE_MOUNT":
                target = profile + "/negative"
                os.mkdir(target, 0o700)
                before = mount_entry(target)
                result = native_libc().mount(b"tmpfs", target.encode(), b"tmpfs", 0, b"size=8m")
                code = ctypes.get_errno() if result != 0 else 0
                receipt = {"op": op, "return": result, "errno": code,
                           "mount_table_unchanged": before == mount_entry(target)}
                receipts.append(receipt)
                durable(profile + f"/operation-{sequence}.json", receipt)
                if result != -1 or code != errno.EPERM or not receipt["mount_table_unchanged"]:
                    raise RuntimeError("actual non-admin mount was not EPERM/no-effect")
            elif op == "ACCESS" and request.get("kind") in ("small", "large"):
                kind = request["kind"]
                target = marker["base"] + "/mounts/" + kind
                entry, info, fs = mount_entry(target), os.stat(target), os.statvfs(target)
                expected = (8 if kind == "small" else 64) << 20
                if (entry is None or entry["type"] != "tmpfs" or info.st_uid != 10001 or
                        info.st_gid != 10001 or stat.S_IMODE(info.st_mode) != 0o700 or
                        fs.f_blocks * fs.f_frsize != expected):
                    raise RuntimeError("real tmpfs size/ownership/mode differs")
                with open(target + "/one-byte", "xb") as stream:
                    stream.write(b"x")
                    stream.flush()
                    os.fsync(stream.fileno())
                with open(target + "/one-byte", "rb") as stream:
                    if stream.read() != b"x":
                        raise RuntimeError("ordinary non-admin readback differs")
                receipt = {"op": op, "kind": kind, "mount": entry, "bytes": expected,
                           "uid": info.st_uid, "gid": info.st_gid, "mode": oct(stat.S_IMODE(info.st_mode)),
                           "one_byte_sha256": digest(b"x"), "identity": snapshot(os.getpid())}
                receipts.append(receipt)
                durable(profile + f"/operation-{sequence}.json", receipt)
            else:
                raise RuntimeError("fixed probe operation required")
            send(sock, marker, op="RESULT", seq=sequence, result=receipt)
    except BaseException as error:
        failure = repr(error)
    finally:
        durable(profile + "/final.json", {"failure": failure, "receipts": receipts})
        sock.close()
    return 0 if failure is None else 1


def launch(marker, role):
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    for sock in (parent, child):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    caps = ["--bounding-set=-all,+sys_admin"] if role == "supervisor" else [
        "--reuid=10001", "--regid=10001", "--clear-groups", "--bounding-set=-all"]
    args = ["/usr/bin/setpriv", *caps, "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",
            "--", "/usr/local/bin/python3.13", "-I", "-B", "-u", os.path.abspath(__file__),
            "--role", role, "--marker", ARGS.marker, "--fd", str(child.fileno())]
    error_fd = os.open(marker["base"] + f"/{role}.stderr", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    pid = os.fork()
    if pid == 0:
        try:
            null = os.open("/dev/null", os.O_RDWR)
            os.dup2(null, 0)
            os.dup2(null, 1)
            os.dup2(error_fd, 2)
            child.set_inheritable(True)
            keep = {0, 1, 2, child.fileno()}
            for name in os.listdir("/proc/self/fd"):
                fd = int(name)
                if fd not in keep:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            os.execv(args[0], args)
        except BaseException:
            traceback.print_exc()
            os._exit(77)
    else:
        os.close(error_fd)
        child.close()
    parent.set_inheritable(True)
    return {"pid": pid, "fd": parent.detach(), "role": role, "seq": 0}


def actual_exit(actor, deadline):
    while time.monotonic() < deadline:
        try:
            pid, status = os.waitpid(actor["pid"], os.WNOHANG)
        except ChildProcessError:
            return actor.get("exit_code")
        if pid:
            code = os.waitstatus_to_exitcode(status)
            actor["exit_code"] = code
            # This numeric exit is emitted BEFORE any post-exit metadata write.
            print(json.dumps({"event": "ACTOR_EXIT", "role": actor["role"], "pid": pid,
                              "actual_exit_code": code}), flush=True)
            return code
        time.sleep(0.05)
    return None


def controller(marker, state):
    global IS_CONTROLLER
    IS_CONTROLLER = True
    actors = state["actors"]
    sockets = {actor["role"]: channel(actor["fd"]) for actor in actors}
    records, failure = [], None
    check_role(snapshot(os.getpid()), "controller")
    deadline = state["deadline"]
    try:
        for actor in actors:
            uid = 10001 if actor["role"] == "probe" else 0
            ready = receive(sockets[actor["role"]], marker, deadline, actor["pid"], uid)
            independent = snapshot(actor["pid"])
            check_role(independent, actor["role"])
            if (ready.get("op") != "READY" or ready.get("identity") != independent or
                    independent["ppid"] != 1 or ready.get("mount_ns") != state["mount_ns"]):
                raise RuntimeError("independent actor/namespace ready gate differs")
            actor["start_ticks"] = independent["start_ticks"]
            records.append({"role": actor["role"], "independent": independent})
        records.append({"role": "controller", "independent": snapshot(os.getpid())})
        durable(marker["base"] + "/controller/roles-before-effects.json", records)

        def rpc(role, op, **fields):
            actor = next(a for a in actors if a["role"] == role)
            check_role(snapshot(actor["pid"]), role)
            if snapshot(actor["pid"])["start_ticks"] != actor["start_ticks"]:
                raise RuntimeError("owned actor incarnation changed")
            actor["seq"] += 1
            send(sockets[role], marker, op=op, seq=actor["seq"], **fields)
            response = receive(sockets[role], marker, min(deadline, time.monotonic()+5),
                               actor["pid"], 10001 if role == "probe" else 0)
            if response.get("op") != "RESULT" or response.get("seq") != actor["seq"]:
                raise RuntimeError("matching result required")
            records.append(response["result"])
            return response["result"]

        rpc("probe", "NEGATIVE_MOUNT")
        for kind in ("small", "large"):
            rpc("supervisor", "MOUNT", kind=kind)
            rpc("probe", "ACCESS", kind=kind)
            rpc("supervisor", "UNMOUNT", kind=kind)
    except BaseException as error:
        failure = repr(error)
    finally:
        # Probe first: it durably records its own data while mounts still exist.
        for role in ("probe", "supervisor"):
            actor = next(a for a in actors if a["role"] == role)
            if "exit_code" not in actor:
                try:
                    actor["seq"] += 1
                    send(sockets[role], marker, op="STOP", seq=actor["seq"])
                except BaseException:
                    pass
                code = actual_exit(actor, time.monotonic()+10)
                if code is None:
                    # EOF releases finite child wait gates; no signal escalation.
                    sockets[role].close()
                    code = actual_exit(actor, time.monotonic()+80)
                if code is None:
                    failure = failure or "owned child not joined; retention required"
            sockets[role].close()
        while any("exit_code" not in actor for actor in actors):
            print(json.dumps({"event": "BLOCKED_RETAINED_OWNER", "failure": failure}), flush=True)
            for actor in actors:
                if "exit_code" not in actor:
                    actual_exit(actor, time.monotonic()+1)
        remaining = {kind: mount_entry(marker["base"] + "/mounts/" + kind)
                     for kind in ("small", "large")}
        with open("/proc/self/mountinfo", encoding="ascii") as stream:
            unexpected = [line.rstrip() for line in stream
                          if line.split()[4].startswith(marker["base"] + "/")]
        while unexpected:
            print(json.dumps({"event": "BLOCKED_RETAINED_NAMESPACE", "mounts": unexpected}), flush=True)
            time.sleep(1)
            with open("/proc/self/mountinfo", encoding="ascii") as stream:
                unexpected = [line.rstrip() for line in stream
                              if line.split()[4].startswith(marker["base"] + "/")]
        success = failure is None and all(a["exit_code"] == 0 for a in actors) and not any(remaining.values())
        summary = {"schema": "native-mount-phase1.result.v1", "scope": marker["scope"],
                   "nonce": marker["nonce"], "status": "PASS_TINY_CANARY_ONLY" if success else "FAIL_TINY_CANARY",
                   "failure": failure, "actors": actors, "records": records, "remaining_mounts": remaining,
                   "full_native_tests_run": False, "production_permission_equivalence": False,
                   "seccomp_limitation": "builtin profile uses FOUR bootstrap caps; its conditional allowances can be broader than a cap0 production container"}
        try:
            durable(marker["base"] + "/controller/final.json", summary)
        except BaseException as error:
            print(json.dumps({"event": "REPORTING_ERROR", "error": repr(error),
                              "actual_actor_exits": [a.get("exit_code") for a in actors]}), flush=True)
            return 70
        print(json.dumps({"event": "FINAL", "summary": summary}), flush=True)
    return 0 if success else 1


def bootstrap(marker):
    if os.getpid() != 1:
        raise RuntimeError("bootstrap must be private namespace PID1")
    check_role(snapshot(1), "bootstrap")
    for target in (marker["base"], "/etc/pluto", "/var/lib/pluto", "/run/pluto", "/usr/local/bin/pluto"):
        if os.path.lexists(target):
            raise RuntimeError("occupied fresh fixture/protected path")
    os.chmod(__file__, 0o444)
    os.chmod(ARGS.marker, 0o444)
    os.mkdir(marker["base"], 0o755)
    os.mkdir(marker["base"] + "/mounts", 0o755)
    os.mkdir(marker["base"] + "/controller", 0o700)
    os.mkdir(marker["base"] + "/work", 0o777)
    os.chmod(marker["base"] + "/work", 0o1777)
    actors = []
    try:
        actors.append(launch(marker, "supervisor"))
        actors.append(launch(marker, "probe"))
        state = {"actors": actors, "deadline": time.monotonic()+30,
                 "mount_ns": os.stat("/proc/self/ns/mnt").st_ino}
        durable(marker["base"] + "/controller/bootstrap-state.json", state)
        # Keep the Python PID1/reaper loaded. Drop-only failures return to this
        # same finally block; there is no exec/Python-startup gap over children.
        return enter_loaded_controller(marker, state, LinuxPid1DropOnly(), controller)
    finally:
        # On every path this same PID1 still owns and can reap its children.
        # Pre-run drop failures close channels; finite EOF/leases release waits.
        for actor in actors:
            if "exit_code" in actor:
                continue
            try:
                os.close(actor["fd"])
            except OSError:
                pass
        while any("exit_code" not in actor for actor in actors):
            for actor in actors:
                if "exit_code" not in actor:
                    actual_exit(actor, time.monotonic()+1)


def main():
    global ACTIVE_MARKER
    marker = marker_load(ARGS.marker)
    ACTIVE_MARKER = marker
    if ARGS.role == "bootstrap":
        return bootstrap(marker)
    sock = channel(ARGS.fd)
    return supervisor(marker, sock) if ARGS.role == "supervisor" else probe(marker, sock)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=("bootstrap", "supervisor", "probe"), required=True)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--fd", type=int)
    ARGS = parser.parse_args()
    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    try:
        sys.exit(main())
    except Exception as error:
        traceback.print_exc()
        # PID1 must never leave live children. Unknown reexec failures close
        # its role channels and wait for finite EOF/leases instead of killing.
        if os.getpid() == 1:
            os.closerange(3, 1024)
            while True:
                try:
                    pid, status = os.waitpid(-1, 0)
                    print(json.dumps({"event": "ACTOR_EXIT_EMERGENCY", "pid": pid,
                                      "actual_exit_code": os.waitstatus_to_exitcode(status)}), flush=True)
                except ChildProcessError:
                    break
        sys.exit(77)
