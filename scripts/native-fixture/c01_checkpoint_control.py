
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import stat
import sys

SETPRIV=["/usr/bin/setpriv","--reuid=10001","--regid=10001","--clear-groups","--inh-caps=-all","--ambient-caps=-all","--bounding-set=-all","--no-new-privs"]
EXPECTED=Path("/native-prepared-backup-expected.json")

def root_publish(file, raw):
    flags=os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_WRONLY
    with os.fdopen(os.open(file,flags,0o400),"wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fchmod(stream.fileno(),0o444)
        os.fsync(stream.fileno())

def main(manifest_path, manifest_pin):
    manifest_file=Path(manifest_path)
    info=manifest_file.lstat()
    manifest_raw=manifest_file.read_bytes()
    if not stat.S_ISREG(info.st_mode) or (info.st_uid,info.st_gid)!=(0,0) or stat.S_IMODE(info.st_mode)!=0o444 or info.st_nlink!=1 or len(manifest_raw)>65536 or hashlib.sha256(manifest_raw).hexdigest()!=manifest_pin:
        raise ValueError("exact Root-pinned native owner manifest required")
    manifest=json.loads(manifest_raw)
    case="TestStage3C01OrdinaryDaemonRestartBackupSemantics"
    fault=manifest["Cases"][case]["Faults"]["c01-sealed-pending-original"]
    TARGET=Path(fault["BackupPath"])
    stop=manifest_file.parent/"native-prepared-stop"
    if TARGET.parent!=Path("/") or TARGET.is_symlink() or manifest["Schema"]!="nativefixture.owner.v2":
        raise ValueError("exact fresh root receipt namespace required")
    if (os.getuid(),os.getgid())!=(0,0) or TARGET.exists():
        raise ValueError("fresh root authorization required")
    expected=EXPECTED.read_bytes()
    token=json.loads(expected)
    if token["schema"]!="pluto.c01-backup-root-authorization.v1" or token["case"]!="TestStage3C01OrdinaryDaemonRestartBackupSemantics":
        raise ValueError("exact reviewed fault authorization required")
    if hashlib.sha256(expected).hexdigest()!=fault["BackupSHA"] or any(token.get(key)!=value for key,value in dict(run=manifest["Run"],scope=manifest["Scope"],nonce=manifest["Nonce"],containerId=manifest["ContainerID"],case=case,site=fault["Site"],base=manifest["RetainedRoot"]+"/f-0001",evidence="/checkpoint"+"/verified-backup.json").items()):
        raise ValueError("same container, nonce, case and restore authorization required")
    worker=subprocess.Popen(SETPRIV+[sys.executable,"-I","-B","/native-prepared-worker.py",manifest_path,manifest_pin],stdout=subprocess.PIPE)
    print("NATIVE_C01_BACKUP_WORKER_STARTED "+str(worker.pid),flush=True)
    pin=manifest_pin
    try:
        actor=subprocess.Popen(SETPRIV+[manifest["Owner"]["Path"],manifest_path,pin])
    except Exception:
        root_publish(stop,b"owner start failed\n")
        worker.communicate()
        raise
    print("NATIVE_C01_OWNER_STARTED "+str(actor.pid),flush=True)
    admitted=False
    worker_done=False
    worker_exit=None
    while actor.poll() is None:
        if not worker_done and worker.poll() is not None:
            output=worker.stdout.read(65537)
            worker_exit=worker.wait()
            worker_done=True
            print("NATIVE_C01_BACKUP_WORKER_EXIT="+str(worker_exit),flush=True)
            try:
                if worker_exit==0:
                    proof=json.loads(output)
                    if proof["case"]!=token["case"] or proof["base"]!=token["base"] or not proof["productStoreOpened"] or proof["trustedReceiverHttpStatus"]!=200:
                        raise ValueError("verified same-profile restore authority differs")
                    root_publish(TARGET,expected)
                    admitted=True
                    print("NATIVE_C01_BACKUP_ATTESTED "+json.dumps(dict(receiptSHA256=hashlib.sha256(expected).hexdigest(),
                        proofSHA256=hashlib.sha256(output).hexdigest(),archiveSHA256=proof["archiveSHA256"],pendingOperations=proof["database"]["pending"],
                        acknowledged=proof["database"]["acknowledged"],sourceFiles=proof["sourceFiles"],uploads=proof["uploads"]),separators=(",",":")),flush=True)
            except Exception as error:
                print("NATIVE_C01_BACKUP_ATTESTATION_REFUSED "+str(error),flush=True)
        time.sleep(0.1)
    owner_exit=actor.wait()
    print("NATIVE_C01_OWNER_ACTUAL_EXIT="+str(owner_exit),flush=True)
    if not worker_done:
        root_publish(stop,b"owner actually exited\n")
        output=worker.stdout.read(65537)
        worker_exit=worker.wait()
        print("NATIVE_C01_BACKUP_WORKER_EXIT="+str(worker_exit),flush=True)
    return owner_exit if owner_exit!=0 else (0 if admitted and worker_exit==0 else 1)

if __name__=="__main__":
    raise SystemExit(main(*sys.argv[1:]))
