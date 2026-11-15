
import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import tarfile
import time
import sys

ROOT=None
BASE=None
STOP=None
CASE="TestStage3C12NativeReviewedPolicyScopesAndRestart"

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def read_json(file):
    info=file.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=10001 or info.st_nlink!=1 or info.st_size>4*1024*1024:
        raise ValueError("private bounded checkpoint JSON required")
    return json.loads(file.read_bytes())

def publish(name, data):
    file=ROOT/name
    raw=json.dumps(data,separators=(",",":"),sort_keys=True).encode()+b"\n"
    with file.open("xb") as stream:
        os.chmod(file,0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return sha(raw)

def wait_json(name, seconds):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if STOP.exists():
            raise RuntimeError("owner already exited before checkpoint completion")
        file=ROOT/name
        if file.exists():
            return read_json(file)
        time.sleep(0.1)
    raise RuntimeError("finite checkpoint observation expired: "+name)

def inventory(directory):
    result=[]
    total=0
    for p in sorted(directory.rglob("*")):
        relative=p.relative_to(directory).as_posix()
        info=p.lstat()
        if info.st_uid!=10001 or info.st_gid!=10001 or info.st_nlink<1:
            raise ValueError("same fixture owner required")
        if stat.S_ISDIR(info.st_mode):
            result.append(dict(path=relative,kind="directory",mode=stat.S_IMODE(info.st_mode)))
        elif stat.S_ISREG(info.st_mode) and info.st_nlink==1:
            total+=info.st_size
            if total>256*1024*1024 or len(result)>4096:
                raise ValueError("checkpoint resource admission")
            with p.open("rb") as stream:
                digest=hashlib.file_digest(stream,"sha256").hexdigest()
            result.append(dict(path=relative,kind="file",mode=stat.S_IMODE(info.st_mode),bytes=info.st_size,sha256=digest))
        else:
            raise ValueError("no links, sockets or external filesystem objects in stopped checkpoint")
    return result

def sqlite_check(file):
    database=sqlite3.connect(file.as_uri()+"?mode=ro&immutable=1",uri=True)
    try:
        if database.execute("PRAGMA quick_check").fetchall()!=[("ok",)]:
            raise ValueError("restored SQLite integrity")
        version=database.execute("PRAGMA user_version").fetchone()[0]
        if version!=8:
            raise ValueError("same profile schema v8 required")
        acknowledged=database.execute("SELECT count(*) FROM operations WHERE stage='CLIENT_ACKED'").fetchone()[0]
        pending=database.execute("SELECT count(*) FROM operations WHERE stage<>'CLIENT_ACKED'").fetchone()[0]
        file_operations=database.execute("SELECT count(*) FROM operations WHERE kind='PUT' AND stage='CLIENT_ACKED'").fetchone()[0]
        directory_operations=database.execute("SELECT count(*) FROM operations WHERE kind='ENSURE_DIRECTORY' AND stage='CLIENT_ACKED'").fetchone()[0]
        if acknowledged!=266 or file_operations!=260 or directory_operations!=6 or pending!=0:
            raise ValueError("same stopped originals and acknowledged operations required")
        return dict(schemaVersion=version,acknowledged=acknowledged,pending=pending,fileOperations=file_operations,directoryOperations=directory_operations)
    finally:
        database.close()

def main(manifest_path, manifest_sha):
    global ROOT, BASE, STOP
    manifest_file=Path(manifest_path)
    info=manifest_file.lstat()
    raw=manifest_file.read_bytes()
    if not stat.S_ISREG(info.st_mode) or (info.st_uid,info.st_gid)!=(0,0) or stat.S_IMODE(info.st_mode)!=0o444 or info.st_nlink!=1 or len(raw)>65536 or sha(raw)!=manifest_sha:
        raise ValueError("Root-pinned manifest required for checkpoint worker")
    manifest=json.loads(raw)
    fault=manifest["Cases"][CASE]["Faults"]["adoption-prepared-changes-entry"]
    ROOT=Path(fault["CheckpointRoot"])
    BASE=Path(manifest["RetainedRoot"])/"f-0001"
    STOP=manifest_file.parent/"native-prepared-stop"
    if manifest["Schema"]!="nativefixture.owner.v2" or not ROOT.is_absolute() or ROOT.parent!=Path("/") or not str(BASE).startswith("/retained/endurance-") or ROOT.is_symlink():
        raise ValueError("exact owner-admitted checkpoint paths required")
    if (os.geteuid(),os.getegid())!=(10001,10001):
        raise ValueError("capless fixture identity required")
    request=wait_json("request.json",180)
    if request["schema"]!="pluto.prepared-checkpoint-request.v1" or request["case"]!=CASE or request["base"]!=str(BASE):
        raise ValueError("exact existing profile checkpoint required")
    backup=Path(request["backupFile"])
    if not backup.is_absolute() or not backup.is_relative_to(BASE) or backup.is_symlink():
        raise ValueError("native backup outside exact profile")
    if sha(backup.read_bytes())!=request["backupSHA256"]:
        raise ValueError("native backup SHA differs")
    backend=BASE/"reviewed-backup-backend.json"
    if sha(backend.read_bytes())!=request["backendSHA256"]:
        raise ValueError("receiver authority graph SHA differs")
    before=inventory(BASE)
    archive=ROOT/"coherent-profile.tar"
    with tarfile.open(archive,"x") as tar:
        for entry in before:
            tar.add(BASE/entry["path"],arcname=entry["path"],recursive=False)
    os.chmod(archive,0o600)
    with archive.open("rb") as stream:
        os.fsync(stream.fileno())
    if before!=inventory(BASE):
        raise ValueError("source graph changed during coherent copy")
    restore=ROOT/"restored"
    restore.mkdir(mode=0o700)
    with tarfile.open(archive,"r") as tar:
        for member in tar.getmembers():
            target=restore/member.name
            if Path(member.name).is_absolute() or not target.resolve().is_relative_to(restore) or not (member.isdir() or member.isfile()):
                raise ValueError("nonlocal checkpoint member")
        tar.extractall(restore,filter="data")
    restored=inventory(restore)
    if before!=restored:
        raise ValueError("all restored file SHA and modes must match")
    for entry in restored:
        if entry["kind"]=="file":
            with (restore/entry["path"]).open("rb") as stream:
                os.fsync(stream.fileno())
    for directory in [p for p in restore.rglob("*") if p.is_dir()]+[restore]:
        descriptor=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    for entry in before:
        if entry["kind"]=="file" and (BASE/entry["path"]).stat().st_ino==(restore/entry["path"]).stat().st_ino:
            raise ValueError("physical restore aliases original inode")
    database=sqlite_check(restore/"state/indexed/sync-state.sqlite")
    sqlite_check(restore/backup.relative_to(BASE))
    image=read_json(restore/"reviewed-backup-backend.json")
    if len(image["Uploads"])!=260:
        raise ValueError("all receiver original bytes required")
    expected={}
    for i in range(260):
        source=restore/("source" if i<130 else "second/.hidden")/("file-%03d"%i)
        content=source.read_bytes()
        if content!=bytes([i%256]):
            raise ValueError("source original mismatch")
        digest=sha(content)
        expected[digest]=expected.get(digest,0)+1
    for upload in image["Uploads"].values():
        content=base64.b64decode(upload["Bytes"],validate=True)
        digest=sha(content)
        if upload["Result"] is None or upload["Input"]["intent"]["sha256"]!=digest or expected.get(digest,0)<1:
            raise ValueError("physical uploaded original mismatch")
        expected[digest]-=1
    if any(expected.values()):
        raise ValueError("receiver source multiset differs")
    archive_sha=hashlib.file_digest(archive.open("rb"),"sha256").hexdigest()
    inventory_sha=publish("inventory.json",before)
    ready=dict(Restored=str(restore),ArchiveSHA256=archive_sha,InventorySHA256=inventory_sha,Database=database)
    publish("restore-ready.json",ready)
    proof=wait_json("restore-go-proof.json",70)
    exact=dict(schema="pluto.prepared-checkpoint-go-proof.v1",case=CASE,base=str(BASE),
        planDigest=request["planDigest"],archiveSHA256=archive_sha,backupSHA256=request["backupSHA256"],
        backendSHA256=request["backendSHA256"],sourceFiles=260,uploads=260,acknowledged=database["acknowledged"],
        schemaVersion=8,productStoreOpened=True,trustedReceiverHttpStatus=200)
    if proof!=exact:
        raise ValueError("actual restored product and authenticated TLS readback proof differs")
    after_original=inventory(BASE)
    after_restored=inventory(restore)
    old_files={item["path"]:item for item in before}
    current_original={item["path"]:item for item in after_original}
    current_restored={item["path"]:item for item in after_restored}
    if after_original!=after_restored or any(current_original.get(name)!=value for name,value in old_files.items()):
        raise ValueError("original checkpoint file bytes changed during product readback")
    extras=set(current_original)-set(old_files)
    allowed={"state/indexed/sync-state.sqlite-wal":0,"state/indexed/sync-state.sqlite-shm":32768}
    if extras!=set(allowed):
        raise ValueError("unexpected product readback filesystem effect")
    for name,size in allowed.items():
        item=current_original[name]
        if item["kind"]!="file" or item["bytes"]!=size or item["mode"]!=0o600:
            raise ValueError("unexpected SQLite readback sidecar shape")
    if current_original["state/indexed/sync-state.sqlite-wal"]["sha256"]!=sha(b""):
        raise ValueError("readback must leave the WAL empty")
    sidecars=[current_original[name] for name in sorted(extras)]

    result=dict(schema="pluto.prepared-checkpoint-qualified.v1",case=CASE,base=str(BASE),archiveSHA256=archive_sha,
        inventorySHA256=inventory_sha,backupSHA256=request["backupSHA256"],backendSHA256=request["backendSHA256"],
        planDigest=request["planDigest"],database=database,restoredFiles=sum(x["kind"]=="file" for x in before),
        sourceFiles=260,uploads=260,productStoreOpened=True,trustedReceiverHttpStatus=200,readbackSidecars=sidecars)
    publish("verified-backup.json",result)
    print(json.dumps(result,separators=(",",":")),flush=True)

if __name__=="__main__":
    main(*sys.argv[1:])
