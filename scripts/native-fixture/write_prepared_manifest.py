import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import sys
import time


CASE = "TestStage3C12NativeReviewedPolicyScopesAndRestart"
SELECTOR = "^" + CASE + "$"
ACTIONS = ["daemon", "status", "pause", "resume", "migrate-plan", "adopt", "policy-plan", "policy-apply", "checkpoint", "backup"]
MANIFEST = "/native-prepared-manifest.json"


def artifact(path, expected):
    if not re.fullmatch(r"[a-f0-9]{64}", expected):
        raise ValueError(f"missing exact SHA-256 for {path}")
    file = Path(path)
    metadata = file.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o555
        or (metadata.st_uid, metadata.st_gid) != (0, 0)
        or not 0 < metadata.st_size <= 128 * 1024 * 1024
    ):
        raise ValueError(f"unsafe staged artifact {path}")
    with file.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != expected:
        raise ValueError(f"staged artifact SHA-256 differs for {path}")
    return {"Path": path, "SHA256": actual, "Bytes": metadata.st_size}


def main(cid, owner_sha, test_sha, cli_sha, run, scope, retained_root, checkpoint_root):
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}",run) or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}",scope) or not re.fullmatch(r"/retained/endurance-[a-zA-Z0-9_.-]{1,128}",retained_root) or not re.fullmatch(r"/[a-zA-Z0-9_-]{1,64}",checkpoint_root):
        raise ValueError("explicit finite isolated scope and checkpoint paths required")
    RUN=run
    ROOT=retained_root
    if (os.getuid(), os.getgid()) != (0, 0):
        raise ValueError("manifest writer requires the isolated root bootstrap")
    hostname = socket.gethostname()
    if not re.fullmatch(r"[a-f0-9]{64}", cid) or hostname != cid[:12]:
        raise ValueError("the attached Docker CID and hostname do not match")
    retained = Path(ROOT).lstat()
    if (
        not stat.S_ISDIR(retained.st_mode)
        or stat.S_IMODE(retained.st_mode) != 0o700
        or (retained.st_uid, retained.st_gid) != (10001, 10001)
    ):
        raise ValueError("retained root must be fresh and private to UID/GID 10001")
    manifest = {
        "Schema": "nativefixture.owner.v2",
        "Run": RUN,
        "Scope": scope,
        "Nonce": secrets.token_hex(16),
        "ContainerID": cid,
        "Hostname": hostname,
        "Namespaces": [os.readlink(f"/proc/self/ns/{name}") for name in ("mnt", "pid", "user")],
        "ExpiresUnixMs": time.time_ns() // 1_000_000 + 390_000,
        "Socket": f"{ROOT}/owner.sock",
        "RetainedRoot": ROOT,
        "EvidenceRoot": f"{ROOT}/evidence",
        "Owner": artifact("/pluto-native-owner", owner_sha),
        "GoTest": artifact("/pluto-native-metadata.test", test_sha),
        "GoArgs": [f"-test.run={SELECTOR}", "-test.count=1", "-test.timeout=360s", "-test.v"],
        "Artifacts": {"current": artifact("/pluto-current", cli_sha)},
        "Cases": {
            name: {"Actions": dict.fromkeys(actions, 45_000), "MaxFixtures": 1}
            for name, actions in {CASE:ACTIONS}.items()
        },
        "Environment": ["STAGE3_PLUTO_BINARY=/pluto-current", "GOMAXPROCS=2"],
        "OutputPrefixBytes": 262_144,
    }
    token = dict(schema="pluto.prepared-backup-root-authorization.v1",run=RUN,scope=manifest["Scope"],
        nonce=manifest["Nonce"],containerId=cid,case="TestStage3C12NativeReviewedPolicyScopesAndRestart",site="adoption-prepared-changes-entry",
        base=ROOT+"/f-0001",evidence=checkpoint_root+"/verified-backup.json",
        condition="independent archive restore, every-file SHA, actual v8 open and default-trust TLS readback of 260 originals")
    expected_raw=json.dumps(token,separators=(",",":"),sort_keys=True).encode()+b"\n"
    expected="/native-prepared-backup-expected.json"
    with os.fdopen(os.open(expected,os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_WRONLY,0o400),"wb") as stream:
        stream.write(expected_raw)
        stream.flush()
        os.fsync(stream.fileno())
    manifest["Cases"]["TestStage3C12NativeReviewedPolicyScopesAndRestart"]["Faults"]={"adoption-prepared-changes-entry":dict(Site="adoption-prepared-changes-entry",
        BackupPath="/native-prepared-backup-receipt.json",BackupSHA=hashlib.sha256(expected_raw).hexdigest(),CheckpointRoot=checkpoint_root,BarrierRequired=True)}
    raw = json.dumps(manifest, separators=(",", ":")).encode("utf-8") + b"\n"
    flags = os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY
    with os.fdopen(os.open(MANIFEST, flags, 0o400), "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fchmod(stream.fileno(), 0o444)
        os.fsync(stream.fileno())
    print(hashlib.sha256(raw).hexdigest())


if __name__ == "__main__":
    main(*sys.argv[1:])
