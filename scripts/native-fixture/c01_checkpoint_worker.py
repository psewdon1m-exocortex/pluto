
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
CASE="TestStage3C01OrdinaryDaemonRestartBackupSemantics"

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
        elif stat.S_ISSOCK(info.st_mode) and relative=="control.sock":
            pass # live IPC is explicitly outside the recoverable data graph
        else:
            raise ValueError("no unreviewed links, sockets or external objects in checkpoint")
    return result

def sqlite_check(file):
    database=sqlite3.connect(file.as_uri()+"?mode=ro&immutable=1",uri=True)
    try:
        if database.execute("PRAGMA quick_check").fetchall()!=[("ok",)]:
            raise ValueError("restored SQLite integrity")
        version=database.execute("PRAGMA user_version").fetchone()[0]
        pending=database.execute("SELECT count(*) FROM operations WHERE stage<>'CLIENT_ACKED'").fetchone()[0]
        acknowledged=database.execute("SELECT count(*) FROM operations WHERE stage='CLIENT_ACKED'").fetchone()[0]
        file_pending=database.execute("SELECT count(*) FROM operations WHERE kind='PUT' AND stage<>'CLIENT_ACKED'").fetchone()[0]
        all_files=database.execute("SELECT count(*) FROM operations WHERE kind='PUT'").fetchone()[0]
        retained=database.execute("SELECT count(*) FROM local_artifacts WHERE phase<>'GONE'").fetchone()[0]
        if version!=8 or pending<1 or file_pending!=1 or all_files!=1 or retained<1:
            raise ValueError("C01 schema8 and original single pending retained PUT required")
        tables=[]
        encode=lambda value:dict(blob=base64.b64encode(value).decode()) if isinstance(value,bytes) else value
        for name,sql in database.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name"):
            cursor=database.execute('SELECT * FROM "'+name.replace('"','""')+'"')
            rows=[[encode(value) for value in row] for row in cursor]
            rows.sort(key=lambda row:json.dumps(row,sort_keys=True,separators=(",",":")))
            tables.append(dict(name=name,schema=sql,columns=[column[0] for column in cursor.description],rows=rows))
        logical=json.dumps(tables,sort_keys=True,separators=(",",":")).encode()
        return dict(schemaVersion=version,acknowledged=acknowledged,pending=pending,filePending=file_pending,fileOperations=all_files,retainedArtifacts=retained,tableCount=len(tables),rowCount=sum(len(table["rows"]) for table in tables),logicalSHA256=sha(logical),tables=tables)
    finally:
        database.close()

def physical(directory):
    result={}
    for file in sorted(directory.rglob("*")):
        info=file.lstat()
        if stat.S_ISREG(info.st_mode):
            result[file.relative_to(directory).as_posix()]=dict(dev=info.st_dev,inode=info.st_ino,mode=stat.S_IMODE(info.st_mode),bytes=info.st_size,mtimeNs=info.st_mtime_ns,ctimeNs=info.st_ctime_ns)
    return result

def main(manifest_path, manifest_sha):
    global ROOT, BASE, STOP
    manifest_file=Path(manifest_path)
    info=manifest_file.lstat()
    raw=manifest_file.read_bytes()
    if not stat.S_ISREG(info.st_mode) or (info.st_uid,info.st_gid)!=(0,0) or stat.S_IMODE(info.st_mode)!=0o444 or info.st_nlink!=1 or len(raw)>65536 or sha(raw)!=manifest_sha:
        raise ValueError("Root-pinned manifest required for checkpoint worker")
    manifest=json.loads(raw)
    fault=manifest["Cases"][CASE]["Faults"]["c01-sealed-pending-original"]
    ROOT=Path("/checkpoint")
    if manifest["Environment"].count("PLUTO_C01_CHECKPOINT_ROOT=/checkpoint")!=1:
        raise ValueError("exact C01 checkpoint env required")
    BASE=Path(manifest["RetainedRoot"])/"f-0001"
    STOP=manifest_file.parent/"native-prepared-stop"
    if manifest["Schema"]!="nativefixture.owner.v2" or not ROOT.is_absolute() or ROOT.parent!=Path("/") or not str(BASE).startswith("/retained/endurance-") or ROOT.is_symlink():
        raise ValueError("exact owner-admitted checkpoint paths required")
    if (os.geteuid(),os.getegid())!=(10001,10001):
        raise ValueError("capless fixture identity required")
    request=wait_json("request.json",180)
    if request["schema"]!="pluto.c01-checkpoint-request.v1" or request["case"]!=CASE or request["base"]!=str(BASE):
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
    physical_before=physical(BASE)
    publish("original-physical.json",physical_before)
    ipc=BASE/"control.sock"
    excluded_ipc=[]
    if ipc.exists():
        ipc_info=ipc.lstat()
        if not stat.S_ISSOCK(ipc_info.st_mode): raise ValueError("control endpoint must be live socket")
        excluded_ipc=[dict(path="control.sock",kind="socket",inode=ipc_info.st_ino,reason="LIVE_IPC_NOT_RECOVERABLE_DATA")]
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
    # data_filter deliberately grants owner-write to regular files; restore
    # only original private reviewed modes, then enforce exact SHA/mode equality.
    for entry in before:
        allowed=(0o700,) if entry["kind"]=="directory" else (0o400,0o600)
        if entry["mode"] not in allowed: raise ValueError("unreviewed checkpoint mode")
        os.chmod(restore/entry["path"],entry["mode"],follow_symlinks=False)
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
    backup_database=sqlite_check(restore/backup.relative_to(BASE))
    if database!=backup_database: raise ValueError("whole live SQLite/actual product backup logical rows differ")
    publish("logical-database.json",database.pop("tables"))
    image=read_json(restore/"reviewed-backup-backend.json")
    if len(image["Uploads"])!=1:
        raise ValueError("C01 exact original pending upload required")
    source=restore/"source/COMLPT1.md"
    content=source.read_bytes()
    if content!=b"fixture bytes" or not (restore/"source/empty").is_dir():
        raise ValueError("C01 real original file and empty directory required")
    for upload_id,upload in image["Uploads"].items():
        payload=base64.b64decode(upload["Bytes"],validate=True)
        if upload["Result"] is not None or payload!=content or upload["Input"]["intent"]["sha256"]!=sha(payload):
            raise ValueError("C01 pending original payload/intent mismatch")
    retained_payloads=[entry for entry in before if entry["kind"]=="file" and entry["path"].startswith("state/indexed/") and entry["sha256"]==sha(content) and entry["mode"]==0o400]
    if not retained_payloads: raise ValueError("C01 real sealed0400 retained original required")
    archive_sha=hashlib.file_digest(archive.open("rb"),"sha256").hexdigest()
    inventory_sha=publish("inventory.json",before)
    ready=dict(Restored=str(restore),ArchiveSHA256=archive_sha,InventorySHA256=inventory_sha,Database=database)
    publish("restore-ready.json",ready)
    proof=wait_json("restore-go-proof.json",70)
    exact=dict(schema="pluto.c01-checkpoint-go-proof.v1",case=CASE,base=str(BASE),archiveSHA256=archive_sha,backupSHA256=request["backupSHA256"],backendSHA256=request["backendSHA256"],sourceFiles=1,sourceBytes=len(content),uploads=1,pendingOperations=database["pending"],retainedArtifacts=database["retainedArtifacts"],schemaVersion=8,productStoreOpened=True,trustedReceiverHttpStatus=200,receiverNodes=len(image["Nodes"]),relocatedRecoveryAdmitted=False)
    if proof!=exact: raise ValueError("actual restored product/pending original/default-trust TLS proof differs")
    after_original=inventory(BASE)
    after_restored=inventory(restore)
    old_files={item["path"]:item for item in before}
    current_original={item["path"]:item for item in after_original}
    current_restored={item["path"]:item for item in after_restored}
    for actual in [current_original,current_restored]:
        if any(actual.get(name)!=value for name,value in old_files.items()):
            raise ValueError("original/restored checkpoint bytes changed during product readback")
        extras=set(actual)-set(old_files)
        allowed={"state/indexed/sync-state.sqlite-wal":0,"state/indexed/sync-state.sqlite-shm":32768}
        if extras-set(allowed): raise ValueError("unexpected product readback file effect")
        for name in extras:
            item=actual[name]
            if item["kind"]!="file" or item["bytes"]!=allowed[name] or item["mode"]!=0o600: raise ValueError("unexpected readback sidecar shape")
            if name.endswith("-wal") and item["sha256"]!=sha(b""): raise ValueError("readback WAL must remain empty")
    physical_after=physical(BASE)
    if any(physical_after.get(name)!=value for name,value in physical_before.items()): raise ValueError("original physical inodes/mode/mtime/ctime changed")
    publish("original-physical-after.json",physical_after)
    result=dict(schema="pluto.c01-checkpoint-qualified.v1",case=CASE,base=str(BASE),archiveSHA256=archive_sha,inventorySHA256=inventory_sha,backupSHA256=request["backupSHA256"],backendSHA256=request["backendSHA256"],database=database,restoredFiles=sum(x["kind"]=="file" for x in before),sourceFiles=1,sourceBytes=len(content),uploads=1,productStoreOpened=True,trustedReceiverHttpStatus=200,originalPhysicalUnchanged=True,excludedLiveIPC=excluded_ipc,retainedPayloads=retained_payloads,readbackSidecars=dict(original=[current_original[name] for name in sorted(set(current_original)-set(old_files))],restored=[current_restored[name] for name in sorted(set(current_restored)-set(old_files))]),relocatedRecoveryAdmitted=False)
    publish("verified-backup.json",result)
    print(json.dumps(result,separators=(",",":")),flush=True)

if __name__=="__main__":
    main(*sys.argv[1:])
