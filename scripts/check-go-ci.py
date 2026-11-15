#!/usr/bin/env python3
"""Audit ordinary Go CI against discovery; keep owner waivers out of PASS."""

import argparse
import hashlib
import itertools
import json
import re
from pathlib import Path


ARCHIVAL_TEST = "TestStage3C03ActualHistoricalWriterRefusesV8"
MAX_EVENT_BYTES = 4 * 1024 * 1024
MAX_LOG_BYTES = 256 * 1024 * 1024
C01_PACKAGE = "pluto/internal/pluto"
C01_TEST = "TestStage3C01OrdinaryDaemonRestartBackupSemantics"
PREPARED_TEST = "TestStage3C12NativeReviewedPolicyScopesAndRestart"
NATIVE_CASES = ["TestStage3C01OrdinaryDaemonRestartBackupSemantics", "TestCompletionDaemonProxyReopenRetainsDeletedSourceOriginal", "TestCompletionDaemonRestartsAfterOwnedRouteLossWithoutFileEvent", "TestCompletionNativeBulkReadbackPauseRestartNoCopies", PREPARED_TEST]
OWNER_POLICY=json.loads((Path(__file__).parent/'native-fixture/owner-case-policy.json').read_bytes())
if OWNER_POLICY.get('schema')!='pluto.native-owner-case-policy.v1':raise ValueError('reviewed owner case policy required')
NATIVE_CASES+=sorted({name.split('/')[0] for name in OWNER_POLICY['cases']})


def events(file, maximum=MAX_LOG_BYTES):
    total = 0
    with Path(file).open("rb") as stream:
        for number, raw in enumerate(iter(lambda: stream.readline(MAX_EVENT_BYTES + 1), b""), 1):
            total += len(raw)
            if len(raw) > MAX_EVENT_BYTES or total > maximum:
                raise ValueError(f"bounded Go JSON log required: line {number}")
            event = json.loads(raw)
            if not isinstance(event, dict):
                raise ValueError(f"Go JSON object required: line {number}")
            if any(key in event and not isinstance(event[key], str)
                   for key in ("Package", "Test", "Action", "Output")):
                raise ValueError(f"Go JSON string fields required: line {number}")
            yield event


def audit(inventory, actual, go_exit, capture_exit):
    expected = set()
    errors = []
    for event in inventory:
        package = event.get("Package", "")
        if event.get("Action") == "fail":
            errors.append(f"DISCOVERY_FAILED: {package}")
        if event.get("Action") != "output":
            continue
        for line in event.get("Output", "").splitlines():
            if line.startswith("Test") and not any(c.isspace() for c in line) and "/" not in line:
                key = (package, line)
                if not package or key in expected:
                    errors.append(f"INVALID_DISCOVERY_ENTRY: {package} {line}")
                expected.add(key)
    if not expected:
        errors.append("EMPTY_ORDINARY_TEST_INVENTORY")
    started = set()
    terminal = {}
    packages = {}
    skipped = []
    failed = []
    for event in actual:
        package, name, action = (event.get(key, "") for key in ("Package", "Test", "Action"))
        if not name:
            if action in ("pass", "fail", "skip"):
                packages[package] = action
            if action == "fail":
                errors.append(f"PACKAGE_FAILED: {package}")
            continue
        key = (package, name)
        root = (package, name.split("/", 1)[0])
        if root not in expected:
            errors.append(f"UNDISCOVERED_TEST: {package} {name}")
        if action == "run":
            if key in started:
                errors.append(f"DUPLICATE_TEST_START: {package} {name}")
            started.add(key)
        if action in ("pass", "fail", "skip"):
            if key in terminal:
                errors.append(f"DUPLICATE_TEST_RESULT: {package} {name}")
            terminal[key] = action
        if action == "skip":
            skipped.append(key)
        if action == "fail":
            failed.append(key)
    unfinished_tests = sorted(key for key in started if terminal.get(key) not in ("pass", "fail", "skip"))
    results_without_start = sorted(set(terminal) - started)
    if unfinished_tests:
        errors.append("STARTED_TESTS_NOT_FINISHED")
    if results_without_start:
        errors.append("TEST_RESULTS_WITHOUT_START")
    ordinary = {key for key in expected if key[1] != ARCHIVAL_TEST}
    missing = sorted(key for key in ordinary if key not in started or terminal.get(key) != "pass")
    unfinished_packages = sorted(package for package, _ in ordinary if packages.get(package) != "pass")
    archival_present = any(name == ARCHIVAL_TEST for _, name in expected | started | set(terminal))
    if archival_present:
        errors.append("ARCHIVAL_TEST_PRESENT_IN_ORDINARY_CI")
    if go_exit != 0:
        errors.append(f"ACTUAL_GO_EXIT: {go_exit}")
    if capture_exit != 0:
        errors.append(f"ACTUAL_CAPTURE_EXIT: {capture_exit}")
    if skipped:
        errors.append("REQUIRED_TESTS_SKIPPED")
    if failed:
        errors.append("REQUIRED_TESTS_FAILED")
    if missing:
        errors.append("REQUIRED_TESTS_NOT_PASSED")
    if unfinished_packages:
        errors.append("REQUIRED_PACKAGES_NOT_PASSED")
    def named(items):
        return [dict(package=p, test=n) for p, n in sorted(set(items))]
    return dict(
        schema="pluto.ordinary-go-ci.v1",
        status="PASS_REQUIRED_ORDINARY_GO_TEST_SUITE" if not errors else "FAIL_REQUIRED_ORDINARY_GO_TEST_SUITE",
        actualGoExit=go_exit, actualCaptureExit=capture_exit,
        ordinaryDiscovered=len(ordinary),
        ordinaryPassed=sum(key in started and terminal.get(key) == "pass" for key in ordinary),
        skipped=named(skipped), failed=named(failed), missingOrNotPassed=named(missing),
        unfinishedTests=named(unfinished_tests), resultsWithoutStart=named(results_without_start),
        packagesNotPassed=sorted(set(unfinished_packages)), errors=sorted(set(errors)),
        archival=dict(test=ARCHIVAL_TEST, status="WAIVED_BY_OWNER",
                      reason="ARCHIVAL_INPUT_UNAVAILABLE",
                      runtime="UNEXPECTED_ORDINARY_LANE_RESULT" if archival_present else "NOT_RUN",
                      historicalV8CompatibilityConfirmed=False, downgradeSafetyConfirmed=False),
    )


def audit_lanes(inventory, ordinary, c01, go_exit, capture_exit, c01_go_exit, c01_runner_exit, c01_capture_exit):
    """The fixed C01 test stays mandatory when its native scope runs separately."""
    inventory = list(inventory)
    lane_errors = []
    ended = {"ordinary": {}, "c01": {}}

    def lane_events(lane, stream):
        for event in stream:
            package, name, action = (event.get(key, "") for key in ("Package", "Test", "Action"))
            root = name.split("/", 1)[0]
            if lane == "ordinary" and package == C01_PACKAGE and root == C01_TEST:
                lane_errors.append("C01_EXECUTED_IN_ORDINARY_SCOPE")
            if lane == "c01" and (package != C01_PACKAGE or name and root != C01_TEST):
                lane_errors.append("UNEXPECTED_TEST_IN_C01_SCOPE")
            if not name and action in ("pass", "fail", "skip"):
                if package in ended[lane]:
                    lane_errors.append("DUPLICATE_PACKAGE_RESULT_IN_" + lane.upper())
                ended[lane][package] = action
            yield event

    result = audit(inventory, itertools.chain(lane_events("ordinary", ordinary), lane_events("c01", c01)),
                   go_exit, capture_exit)
    if not any(event.get("Package") == C01_PACKAGE and
               C01_TEST in event.get("Output", "").splitlines() for event in inventory):
        lane_errors.append("REQUIRED_C01_TEST_NOT_DISCOVERED")
    required_ordinary_packages = {event.get("Package", "") for event in inventory
                                  if event.get("Action") == "output" and any(
                                      line.startswith("Test") and not any(c.isspace() for c in line) and
                                      "/" not in line and (event.get("Package"), line) != (C01_PACKAGE, C01_TEST)
                                      for line in event.get("Output", "").splitlines())}
    if any(ended["ordinary"].get(package) != "pass" for package in required_ordinary_packages):
        lane_errors.append("ORDINARY_SCOPE_PACKAGES_NOT_PASSED")
    if ended["c01"] != {C01_PACKAGE: "pass"}:
        lane_errors.append("C01_SCOPE_PACKAGE_NOT_PASSED")
    for name, code in (("GO", c01_go_exit), ("RUNNER", c01_runner_exit), ("CAPTURE", c01_capture_exit)):
        if code != 0:
            lane_errors.append(f"ACTUAL_C01_{name}_EXIT: {code}")
    result["errors"] = sorted(set(result["errors"] + lane_errors))
    result["status"] = "FAIL_REQUIRED_ORDINARY_GO_TEST_SUITE" if result["errors"] else "PASS_REQUIRED_ORDINARY_GO_TEST_SUITE"
    result["lanes"] = dict(ordinary=dict(actualGoExit=go_exit, actualCaptureExit=capture_exit),
                           c01=dict(package=C01_PACKAGE, test=C01_TEST, required=True,
                                    actualGoExit=c01_go_exit, actualRunnerExit=c01_runner_exit,
                                    actualCaptureExit=c01_capture_exit))
    return result


def bounded_bytes(file):
    with Path(file).open("rb") as stream:
        raw = stream.read(MAX_EVENT_BYTES + 1)
    if len(raw) > MAX_EVENT_BYTES:
        raise ValueError("bounded C01 source/metadata/output required")
    return raw


def bounded_json(file):
    return json.loads(bounded_bytes(file))


def c01_source_inputs(root):
    root = Path(root).resolve()
    files = {"go.mod", "go.sum", "internal/pluto/runtime-notices.tar"}
    embeddings = []
    for file in root.rglob("*.go"):
        relative = file.relative_to(root).as_posix()
        if any(part.startswith(".") for part in file.relative_to(root).parts):
            continue
        if file.is_symlink():
            raise ValueError("regular module source inputs required")
        files.add(relative)
        embeddings += [(relative, value.strip()) for value in
                       re.findall(r"^//go:embed (.+)$", bounded_bytes(file).decode("utf-8"), re.M)]
    if embeddings != [("internal/pluto/runtime_contract.go", "runtime-notices.tar")]:
        raise ValueError("C01 source-input schema needs review for changed Go embed inputs")
    if len(files) > 4096:
        raise ValueError("bounded C01 source-input set required")
    result = []
    for relative in sorted(files):
        file = root / relative
        if file.is_symlink() or not file.is_file():
            raise ValueError("regular C01 source input required: " + relative)
        data = bounded_bytes(file)
        result.append(dict(relative=relative, bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
    return result


BULK_TEST = "TestCompletionNativeBulkReadbackPauseRestartNoCopies"
BULK_PUBLIC_FILES = {'backend-inputs.json','ci-source-inputs.json','backend-image.json','checkpoint-complete.json','checkpoint-graph.json','native-final.json','bulk-assertions.json','final-graph.json','final-product.json'}


def bulk_ci_script_inputs(project):
    project=Path(project).resolve();root=project/'scripts/native-fixture/bulk'
    names={'scripts/run-bulk-ci.mjs','scripts/prepare-bulk-backend-inputs.mjs','scripts/check-go-ci.py','scripts/native-fixture/export_c01_ci.py','scripts/go-ci.py','scripts/run-c01-ci.py','scripts/prepare-c01-ci.sh'}
    for file in root.rglob('*'):
        if file.is_symlink():raise ValueError('regular bulk helper source required')
        if file.is_file():names.add(file.relative_to(project).as_posix())
    result=[]
    for name in sorted(names):
        raw=bounded_bytes(project/name)
        result.append(dict(path=name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
    return result


def bulk_ci_evidence(directory,project,actual,elf):
    proof=bounded_json(directory/'bulk-evidence.json')
    if (proof.get('schema')!='pluto.bulk-ci-proof.v1' or proof.get('test')!=BULK_TEST or
        proof.get('status')!='PASS_GENUINE_BULK_NATIVE_CHECKPOINT_RESTORE_AND_FINAL_READBACK' or
        proof.get('testBinarySHA256')!=elf or proof.get('actualGoWait')!=actual or proof.get('sourceFiles')!=32 or
        proof.get('realSaturnPGSFTP') is not True or proof.get('originalBackendResumed') is not True or
        proof.get('fullOrdinaryCiGreen') is not False or proof.get('containerClosure',{}).get('status')!='STOPPED_RETAINED'):
        raise ValueError('complete actual bulk native/closed backend proof required')
    files=proof.get('files',{})
    if set(files)!=BULK_PUBLIC_FILES:raise ValueError('all nine exact bulk evidence files required')
    records={}
    for name in sorted(BULK_PUBLIC_FILES):
        meta=files[name];raw=bounded_bytes(directory/name)
        if type(meta.get('bytes')) is not int or meta['bytes']!=len(raw) or meta.get('sha256')!=hashlib.sha256(raw).hexdigest():
            raise ValueError('actual bulk evidence bytes/SHA differ: '+name)
        records[name]=json.loads(raw)
    script=records['ci-source-inputs.json']
    if script.get('schema')!='pluto.bulk-ci-script-source.v1' or script.get('inputs')!=bulk_ci_script_inputs(project):
        raise ValueError('actual bulk CI helpers differ from this checkout')
    backend=records['backend-inputs.json'];policyRaw=bounded_bytes(project/'scripts/native-fixture/bulk/backend-policy.json');policy=json.loads(policyRaw)
    cohort=backend.get('files',[])
    if (backend.get('schema')!='pluto.bulk-ci-backend-inputs.v1' or backend.get('policySHA256')!=hashlib.sha256(policyRaw).hexdigest() or
        [f.get('path') for f in cohort]!=policy.get('files') or len(cohort)!=602 or backend.get('sourceCohortSHA256')!=proof.get('sourceCohortSHA256') or
        hashlib.sha256(json.dumps(cohort,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()!=backend.get('sourceCohortSHA256')):
        raise ValueError('complete approved backend source cohort required')
    image=records['backend-image.json'];images=proof.get('images',{})
    if (set(images)!={'native','saturn','postgres','sftp'} or not all(isinstance(v,str) and re.fullmatch('sha256:[a-f0-9]{64}',v) for v in images.values()) or
        backend.get('images')!={k:images[k] for k in ('saturn','postgres','sftp')} or image.get('schema')!='pluto.bulk-ci-backend-image.v1' or
        image.get('status')!='PASS_EXACT_602_IMAGE_FILES' or image.get('files')!=602 or image.get('image')!=images['saturn'] or
        image.get('sourceCohortSHA256')!=backend.get('sourceCohortSHA256') or image.get('policySHA256')!=backend.get('policySHA256')):
        raise ValueError('actual immutable backend image byte check required')
    containers=proof.get('containers',[])
    if not containers or len({c.get('id') for c in containers})!=len(containers):raise ValueError('actual distinct container closure required')
    for c in containers:
        if (not isinstance(c.get('id'),str) or not re.fullmatch('[a-f0-9]{64}',c['id']) or type(c.get('actualExitCode')) is not int or
            c['actualExitCode']!=0 or c.get('oomKilled') is not False or c.get('running') is not False):raise ValueError('all bulk components must actually join0')
    byId={c['id']:c for c in containers};checkpoint=records['checkpoint-complete.json'];graph=records['checkpoint-graph.json']
    flags=('postgreSQLRestored','fullSQLRowsCompared','physicalSFTPRestored','allPhysicalBytesCompared','actualProductReadback','authorityConfigRestored','originalBackendStoppedReceipt','originalBackendResumed')
    if (checkpoint.get('schema')!='pluto.native-bulk-checkpoint-proof.v1' or checkpoint.get('status')!='PASS_GENUINE_FULL_GRAPH_RESTORE' or
        any(checkpoint.get(k) is not True for k in flags) or checkpoint.get('canaryBytes',0)<=0 or
        checkpoint.get('graphSHA256')!=files['checkpoint-graph.json']['sha256'] or checkpoint.get('requestID')!=graph.get('requestID')):
        raise ValueError('genuine full pre-fault graph restore and actual original backend resume required')
    def components(value,expected):
        cs=value.get('components',{})
        if set(cs)!=expected:raise ValueError('complete bulk component set required')
        for c in cs.values():
            b=c.get('backup',{});r=c.get('restore',{})
            if (b.get('originalUnchanged') is not True or r.get('allPortableMetadataAndBytesEqual') is not True or r.get('independentInodes') is not True or
                r.get('relocatedCustodyClaimed') is not False or b.get('archiveSHA256')!=r.get('archiveSHA256') or
                not isinstance(b.get('archiveSHA256'),str) or not re.fullmatch('[a-f0-9]{64}',b['archiveSHA256']) or
                b.get('files')!=r.get('files') or b.get('bytes')!=r.get('bytes')):raise ValueError('actual full immutable-original/independent-restored component proof required')
    components(graph,{'pg','sftp','fixtures','authority'})
    for role,key in [('native','native'),('pg','postgres'),('sftp','sftp')]:
        c=byId.get(graph.get('sourceTuples',{}).get(role),{})
        if c.get('image')!=images[key]:raise ValueError('bulk source container/image binding differs')
    pre=graph.get('product',{})
    if (pre.get('status')!='PASS_ACTUAL_RESTORED_PRODUCT_READBACK' or pre.get('requestID')!=checkpoint['requestID'] or
        pre.get('nativeArchiveSHA256')!=checkpoint.get('nativeArchiveSHA256') or pre.get('canaryRead') is not True or
        pre.get('clonedBackendWriterStarted') is not False or graph.get('nativeOriginalVerification',{}).get('originalPhysicalUnchanged') is not True):
        raise ValueError('actual restored product/canary and unchanged native originals before fault required')
    native=records['native-final.json'];bulk=records['bulk-assertions.json'];finalGraph=records['final-graph.json'];product=records['final-product.json']
    if (native.get('status')!='PASS_INDEPENDENT_NATIVE_FINAL_SQLITE_SOURCE_AND_ACTUAL_WAITS' or native.get('requestID')!=checkpoint['requestID'] or
        native.get('goActual')!=actual or native.get('sourceFiles')!=32 or native.get('allFinalPhysicalUnchanged') is not True or
        native.get('deliberateEditedFileSameInode') is not True or set(native.get('operationStages',{}))!={'CLIENT_ACKED'} or
        native.get('tables',{}).get('operation_retry')!=0):raise ValueError('independent closed current native SQLite/source proof required')
    waits=native.get('actualWaits',[]);crashes=native.get('reviewedCrashWaits',[])
    if len(crashes)!=1 or crashes[0].get('Signaled') is not True or crashes[0].get('Signal')!=9 or crashes[0].get('RawStatus')!=9 or crashes[0] not in waits:
        raise ValueError('one actual reviewed native SIGKILL wait required')
    if actual not in waits or any(w.get('Observed') is not True or type(w.get('PID')) is not int or w['PID']<=0 or
        not (w==crashes[0] or w.get('Exited') is True and w.get('Signaled') is False and w.get('ExitCode')==0 and w.get('RawStatus')==0) for w in waits):
        raise ValueError('all bulk actual waits must be complete normal0 or reviewed SIGKILL')
    components(finalGraph,{'pg','sftp'})
    if (finalGraph.get('schema')!='pluto.native-bulk-final-cold-graph.v1' or finalGraph.get('requestID')!=checkpoint['requestID'] or
        finalGraph.get('product')!=product or finalGraph.get('nativeFinalProof',{}).get('sha256')!=files['native-final.json']['sha256'] or
        product.get('status')!='PASS_FINAL_SQL_IDS_VERSIONS_AND_ALL_SFTP_BYTES' or product.get('requestID')!=checkpoint['requestID'] or
        product.get('canaryRead') is not True or product.get('clonedBackendWriterStarted') is not False):raise ValueError('actual final cold PG/SFTP physical/product readback required')
    if (bulk.get('status')!='PASS' or bulk.get('count')!=32 or any(bulk.get(k) is not True for k in ('bulkLostAckCrashRecovery','pauseRestart','pauseResumeSameProcess')) or
        len(bulk.get('localManifest',{}))!=32):raise ValueError('all original bulk/fault/pause assertions required')
    initial=bulk.get('initial',{}).get('Files',[]);final=bulk.get('final',{}).get('Files',[]);observed=[f for f in product.get('files',[]) if f.get('kind')=='pluto']
    if len(initial)!=32 or len(final)!=32 or len(observed)!=32 or len({f.get('ID') for f in initial})!=32 or len({f.get('ID') for f in final})!=32 or len({f.get('resourceId') for f in observed})!=32:
        raise ValueError('all exact32 bulk resource identities required')
    before={f['ID']:f for f in initial};after={f['ID']:f for f in final}
    if set(before)!=set(after) or bulk.get('initial',{}).get('Folders')!=bulk.get('final',{}).get('Folders'):
        raise ValueError('bulk source resource/folder identities changed')
    for actualFile in observed:
        f=after.get(actualFile.get('resourceId'));old=before.get(actualFile.get('resourceId'))
        if not f or not old:raise ValueError('unexpected final bulk resource ID')
        versions=actualFile.get('versions',[]);required=2 if f['Path']=='example.md' else 1
        if (actualFile.get('versionId')!=f.get('Version') or actualFile.get('sha256')!=f.get('Sha256') or
            actualFile.get('bytes')!=f.get('Size') or len(versions)!=required or old.get('Version') not in versions or
            f.get('Version') not in versions or f.get('VersionCount')!=required or bulk['localManifest'].get(f['Path'])!=f.get('Sha256')):
            raise ValueError('exact final IDs/versions/physical SHA/bytes differ')
        if f['Path']!='example.md' and f!=old:raise ValueError('unchanged bulk file acquired a new version')
    dbs=product.get('databases',[])
    if len(dbs)!=2 or {d.get('kind') for d in dbs}!={'windows','pluto'} or any(d.get('migrations')!=117 or d.get('backendState')!='STOPPED' for d in dbs):
        raise ValueError('final original backend identities must be actually STOPPED on117migrations')
    return dict(schema='pluto.bulk-ci-evidence.v1',requestID=checkpoint['requestID'],sourceFiles=32,plutoVersions=33,actualSIGKILL=crashes[0],fullOrdinaryCiGreen=False,sourceCohortSHA256=backend['sourceCohortSHA256'])


def prepared_ci_evidence(directory):
    """Bind the reviewed C12 fault to its actual, independently restored checkpoint."""
    proof = bounded_json(directory / 'prepared-backup.json')
    inventory_raw = bounded_bytes(directory / 'prepared-inventory.json')
    inventory = json.loads(inventory_raw)
    manifest = bounded_json(directory / 'prepared-manifest.json')
    receipt_raw = bounded_bytes(directory / 'prepared-fault-receipt.json')
    receipt = json.loads(receipt_raw)
    if (not isinstance(proof, dict) or not isinstance(inventory, list) or not inventory or
            not isinstance(manifest, dict) or not isinstance(receipt, dict)):
        raise ValueError('prepared checkpoint objects required')
    fault = manifest.get('Cases', {}).get(PREPARED_TEST, {}).get('Faults', {}).get('adoption-prepared-changes-entry', {})
    root = manifest.get('RetainedRoot', '')
    if (manifest.get('Schema') != 'nativefixture.owner.v2' or
            not re.fullmatch(r'/retained/endurance-[a-zA-Z0-9_.-]{1,128}', root) or
            manifest.get('GoArgs', []).count('-test.run=^'+PREPARED_TEST+'$') != 1 or
            fault.get('BarrierRequired') is not True or fault.get('Site') != 'adoption-prepared-changes-entry' or
            fault.get('BackupSHA') != hashlib.sha256(receipt_raw).hexdigest() or
            fault.get('BackupPath') != '/native-prepared-backup-receipt.json' or
            fault.get('CheckpointRoot') != '/checkpoint'):
        raise ValueError('exact prepared owner manifest and fault barrier required')
    expected_receipt = dict(schema='pluto.prepared-backup-root-authorization.v1', run=manifest.get('Run'),
        scope=manifest.get('Scope'), nonce=manifest.get('Nonce'), containerId=manifest.get('ContainerID'),
        case=PREPARED_TEST, site=fault['Site'], base=root+'/f-0001', evidence='/checkpoint/verified-backup.json',
        condition='independent archive restore, every-file SHA, actual v8 open and default-trust TLS readback of 260 originals')
    if receipt != expected_receipt:
        raise ValueError('same container, case and checkpoint authorization required')
    database = dict(schemaVersion=8, acknowledged=266, pending=0, fileOperations=260, directoryOperations=6)
    if (proof.get('schema') != 'pluto.prepared-checkpoint-qualified.v1' or proof.get('case') != PREPARED_TEST or
            proof.get('base') != root+'/f-0001' or proof.get('database') != database or
            proof.get('sourceFiles') != 260 or proof.get('uploads') != 260 or
            proof.get('productStoreOpened') is not True or proof.get('trustedReceiverHttpStatus') != 200 or
            proof.get('inventorySHA256') != hashlib.sha256(inventory_raw).hexdigest() or
            any(not re.fullmatch('[a-f0-9]{64}', proof.get(key, '')) for key in
                ('archiveSHA256', 'backupSHA256', 'backendSHA256', 'planDigest'))):
        raise ValueError('complete independent restore, v8 open and TLS readback proof required')
    files = {}
    for item in inventory:
        if not isinstance(item, dict): raise ValueError('prepared inventory entry required')
        name = item.get('path', '')
        if (not name or name.startswith('/') or '\\' in name or
                any(part in ('', '.', '..') for part in name.split('/')) or name in files):
            raise ValueError('unique local checkpoint member required')
        if item.get('kind') not in ('file', 'directory'): raise ValueError('regular checkpoint graph required')
        if item['kind'] == 'file':
            if type(item.get('bytes')) is not int or item['bytes'] < 0 or not re.fullmatch('[a-f0-9]{64}', item.get('sha256', '')):
                raise ValueError('checkpoint file size and SHA required')
        files[name] = item
    if proof.get('restoredFiles') != sum(item['kind']=='file' for item in inventory):
        raise ValueError('every checkpoint file must be restored')
    for index in range(260):
        name = ('source' if index < 130 else 'second/.hidden') + '/file-%03d' % index
        item = files.get(name, {})
        if item.get('kind') != 'file' or item.get('bytes') != 1 or item.get('sha256') != hashlib.sha256(bytes([index % 256])).hexdigest():
            raise ValueError('all260 actual original source pins required')
    return dict(status='PASS_REVIEWED_C12_BACKUP_BARRIER', database=database, sourceFiles=260,
                archiveSHA256=proof['archiveSHA256'], inventorySHA256=proof['inventorySHA256'],
                declaredFault='adoption-prepared-changes-entry', faultIsGraceful=False,
                historicalReaderExecuted=False, realSaturnCredit=False)


def native_shard(directory, project, case):
    """Read actual native-owner receipts; no inferred zero exit or waived test."""
    if case not in NATIVE_CASES:
        raise ValueError("unreviewed native case")
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("explicit native evidence directory required")
    names = ("events.jsonl", "stdout.log", "actual-wait.json", "joined-streams.json",
             "prepared-before-Start.json", "observed-after-exec.json", "owner-final.json", "source-inputs.json")
    for name in names:
        file = directory / name
        if file.is_symlink() or not file.is_file():
            raise ValueError("missing regular native evidence: " + name)
    actual = bounded_json(directory / "actual-wait.json")
    joined = bounded_json(directory / "joined-streams.json")
    prepared = bounded_json(directory / "prepared-before-Start.json")
    final = bounded_json(directory / "owner-final.json")
    source = bounded_json(directory / "source-inputs.json")
    observed = bounded_json(directory / "observed-after-exec.json")
    if not all(isinstance(value, dict) for value in (actual, joined, prepared, final, source, observed)):
        raise ValueError("native metadata objects required")
    artifact = prepared.get("artifact")
    argv = prepared.get("args")
    if (not isinstance(artifact, dict) or not isinstance(argv, list) or
            not argv or not all(isinstance(value, str) for value in argv) or
            not isinstance(artifact.get("SHA256"), str) or not re.fullmatch("[a-f0-9]{64}", artifact["SHA256"]) or
            argv[0] != artifact.get("Path") or argv.count(f"-test.run=^{case}$") != 1 or
            len([value for value in argv if value.startswith("-test.run=")]) != 1 or "-test.count=1" not in argv):
        raise ValueError("exact native test artifact and argv required")
    if prepared.get("role") != "go-test" or f"-test.run=^{case}$" not in prepared.get("args", []):
        raise ValueError("exact original native native test argv required")
    result = joined.get("result", {})
    if not isinstance(result, dict):
        raise ValueError("native native result object required")
    if (actual.get("Observed") is not True or type(actual.get("ExitCode")) is not int or
            actual != result.get("Actual") or actual.get("Exited") is not True or actual.get("Signaled") is not False or
            type(actual.get("PID")) is not int or actual["PID"] <= 0 or
            actual.get("Signal") != 0 or actual.get("RawStatus") != actual["ExitCode"] << 8):
        raise ValueError("actual normal numeric native Go Wait receipt required")
    if (joined.get("actual_wait_durable") is not True or any(result.get(key) is not True for key in
            ("IntentProven", "NumericDurable", "DrainsJoined", "StrongTupleObserved")) or
            result.get("LifecycleError") != "" or any(result.get(key) is not False for key in
            ("DeadlineExpired", "JoinWatchdogExpired", "Truncated"))):
        raise ValueError("native native lifecycle/custody/output closure is incomplete")
    if (not final.get("all_products_joined") or not final.get("no_adopted_children") or
            final.get("go_actual") != actual or final.get("go_lifecycle") or final.get("failures")):
        raise ValueError("native owner did not actually close every native process")
    core = observed.get("Core", {})
    profile = core.get("Profile", {}) if isinstance(core, dict) else {}
    birth = core.get("Birth", {}) if isinstance(core, dict) else {}
    parent = core.get("Parent", {}) if isinstance(core, dict) else {}
    namespaces = observed.get("Namespaces")
    if (not isinstance(core, dict) or not isinstance(profile, dict) or
            not isinstance(birth, dict) or not isinstance(parent, dict) or
            type(birth.get("Ticks")) is not int or birth["Ticks"] <= 0 or
            type(parent.get("Ticks")) is not int or parent["Ticks"] <= 0 or
            type(parent.get("PID")) is not int or parent["PID"] <= 0 or
            birth.get("PPID") != parent["PID"] or observed.get("Group") != actual["PID"] or
            type(observed.get("Session")) is not int or observed["Session"] <= 0 or
            not isinstance(namespaces, list) or len(namespaces) != 3 or
            not all(isinstance(value, str) and re.fullmatch(name + r":\[\d+\]", value)
                    for name, value in zip(("mnt", "pid", "user"), namespaces)) or
            core.get("Exe") != artifact.get("Path") or
            not isinstance(core.get("Birth"), dict) or core["Birth"].get("PID") != actual["PID"] or
            core.get("PIDFDTarget") != actual["PID"] or core.get("ExeSHA256") != artifact["SHA256"] or
            core.get("Argv") != argv or profile.get("UID") != [10001] * 4 or
            profile.get("GID") != [10001] * 4 or profile.get("Caps") != [0] * 5 or
            profile.get("NNP") != 1 or profile.get("Seccomp") != 2 or profile.get("Groups")):
        raise ValueError("actual native after-exec tuple does not match native Wait/artifact/argv/profile")
    raw = bounded_bytes(directory / "stdout.log")
    if (len(raw) > MAX_EVENT_BYTES or not result.get("CombinedMode") or
            len(raw) != joined.get("stdout_total_bytes") or len(raw) != joined.get("stdout_stored_prefix_bytes") or
            hashlib.sha256(raw).hexdigest() != joined.get("stdout_full_sha256") or
            hashlib.sha256(raw).hexdigest() != joined.get("stdout_stored_prefix_sha256") or
            joined.get("output_error") != "<nil>" or joined.get("numeric_error") != "<nil>"):
        raise ValueError("actual complete native Go output and stream digests required")
    actual_events = list(events(directory / "events.jsonl", maximum=MAX_EVENT_BYTES))
    if "".join(event.get("Output", "") for event in actual_events) != raw.decode("utf-8").replace("\x16", ""):
        raise ValueError("native JSON events do not preserve actual Go stdout")
    scoped = audit([dict(Package=C01_PACKAGE, Action="output", Output=case+"\n")],
                   actual_events, actual["ExitCode"], 0)
    package_results = [event.get("Action") for event in actual_events if not event.get("Test")
                       and event.get("Action") in ("pass", "fail", "skip")]
    if (scoped["errors"] or package_results != ["pass"] or any(event.get("Package") != C01_PACKAGE or
            event.get("Test") and event["Test"].split("/", 1)[0] != case for event in actual_events)):
        raise ValueError("native scope must actually pass every started test and subtest exactly once")
    if (source.get("schema") != "pluto.c01-ci-source.v1" or
            source.get("testBinarySHA256") != prepared.get("artifact", {}).get("SHA256") or
            source.get("inputs") != c01_source_inputs(project)):
        raise ValueError("native compiled source inputs do not match this checkout")
    proof = dict(schema="pluto.native-ci-evidence.v1", test=case, testBinarySHA256=source["testBinarySHA256"],
        sourceInputs=len(source["inputs"]), actualWait=actual, allProductsJoined=True,
        stdoutSHA256=hashlib.sha256(raw).hexdigest())
    if case==BULK_TEST:proof['bulk']=bulk_ci_evidence(directory,project,actual,source['testBinarySHA256'])
    if case==PREPARED_TEST:proof['prepared']=prepared_ci_evidence(directory)
    return actual_events,actual['ExitCode'],proof


def c01_shard(directory, project):
    return native_shard(directory, project, C01_TEST)


def preflight_c01(inventory, native, go_exit, runner_exit, capture_exit):
    """Qualify only the fixed native scope before admitting the ordinary scope."""
    inventory=list(inventory)
    native=list(native)
    discovered=[(event.get('Package'),line) for event in inventory if event.get('Action')=='output'
                for line in event.get('Output','').splitlines()]
    errors=[]
    if any(event.get("Package")!=C01_PACKAGE or event.get("Test") and event["Test"].split("/",1)[0]!=C01_TEST for event in native):
        errors.append("UNEXPECTED_TEST_IN_C01_SCOPE")
    if discovered.count((C01_PACKAGE,C01_TEST))!=1:errors.append('REQUIRED_C01_TEST_NOT_DISCOVERED')
    if any(event.get('Action')=='fail' for event in inventory):errors.append('DISCOVERY_FAILED')
    if any(name==ARCHIVAL_TEST for _,name in discovered):errors.append('ARCHIVAL_TEST_PRESENT_IN_ORDINARY_CI')
    selected=[dict(Package=C01_PACKAGE,Action='output',Output=C01_TEST+'\n')]
    scoped=audit(selected,native,go_exit,capture_exit)
    errors+=scoped['errors']
    if runner_exit!=0:errors.append(f'ACTUAL_C01_RUNNER_EXIT: {runner_exit}')
    return dict(schema='pluto.c01-ci-preflight.v1',
                status='FAIL_REQUIRED_C01_NATIVE_SCOPE' if errors else 'PASS_REQUIRED_C01_NATIVE_SCOPE',
                package=C01_PACKAGE,test=C01_TEST,actualGoExit=go_exit,
                actualRunnerExit=runner_exit,actualCaptureExit=capture_exit,
                errors=sorted(set(errors)),ordinaryRuntime='NOT_RUN',fullOrdinaryCiGreen=False,
                archival=scoped['archival'])


def preflight_native(inventory, native, go_exit, runner_exit, capture_exit, case):
    """Validate one reviewed native scope; ordinary execution stays NOT_RUN."""
    if case not in NATIVE_CASES: raise ValueError("unreviewed native case")
    inventory, native = list(inventory), list(native)
    discovered = [(event.get('Package'), line) for event in inventory if event.get('Action') == 'output'
                  for line in event.get('Output', '').splitlines()]
    errors = []
    if discovered.count((C01_PACKAGE, case)) != 1: errors.append('REQUIRED_NATIVE_TEST_NOT_DISCOVERED: ' + case)
    if any(event.get('Action') == 'fail' for event in inventory): errors.append('DISCOVERY_FAILED')
    if any(name == ARCHIVAL_TEST for _, name in discovered): errors.append('ARCHIVAL_TEST_PRESENT_IN_ORDINARY_CI')
    ended = []
    for event in native:
        name = event.get('Test', '')
        if event.get('Package') != C01_PACKAGE or name and name.split('/', 1)[0] != case:
            errors.append('UNEXPECTED_TEST_IN_NATIVE_SCOPE: ' + case)
        if not name and event.get('Action') in ('pass', 'fail', 'skip'): ended.append(event.get('Action'))
    if ended != ['pass']: errors.append('NATIVE_SCOPE_PACKAGE_NOT_PASSED_ONCE: ' + case)
    selected = [dict(Package=C01_PACKAGE, Action='output', Output=case+'\n')]
    scoped = audit(selected, native, go_exit, capture_exit)
    errors += scoped['errors']
    if type(runner_exit) is not int or runner_exit != 0: errors.append('ACTUAL_NATIVE_RUNNER_EXIT: ' + str(runner_exit))
    return dict(schema='pluto.native-ci-preflight.v1', test=case,
                status='FAIL_REQUIRED_NATIVE_SCOPE' if errors else 'PASS_REQUIRED_NATIVE_SCOPE',
                actualGoExit=go_exit, actualRunnerExit=runner_exit, actualCaptureExit=capture_exit,
                errors=sorted(set(errors)), ordinaryRuntime='NOT_RUN', fullOrdinaryCiGreen=False,
                archival=scoped['archival'])


def native_scopes(file, project):
    """Read the complete fixed scope manifest and genuine native receipts."""
    manifest = Path(file)
    if manifest.is_symlink() or not manifest.is_file(): raise ValueError('regular native scope manifest required')
    record = bounded_json(manifest)
    if not isinstance(record, dict) or set(record) != {'schema', 'scopes'} or record['schema'] != 'pluto.native-ci-scopes.v1':
        raise ValueError('exact native scope manifest schema required')
    scopes = record['scopes']
    if not isinstance(scopes, dict) or set(scopes) != set(NATIVE_CASES):
        raise ValueError('all reviewed native scopes are required')
    result = {}
    directories = set()
    for case in NATIVE_CASES:
        scope = scopes[case]
        if not isinstance(scope, dict) or set(scope) != {'directory', 'actualRunnerExit', 'actualCaptureExit'}:
            raise ValueError('explicit native directory and both actual exits required')
        for key in ('actualRunnerExit', 'actualCaptureExit'):
            if type(scope[key]) is not int: raise ValueError('actual numeric native exits required')
        if not isinstance(scope['directory'], str) or not Path(scope['directory']).is_absolute():
            raise ValueError('absolute native evidence directory required')
        directory = Path(scope['directory']).resolve()
        if directory in directories: raise ValueError('native scopes must have distinct evidence directories')
        directories.add(directory)
        actual, code, proof = native_shard(scope['directory'], project, case)
        result[case] = dict(events=actual, goExit=code, runnerExit=scope['actualRunnerExit'],
                            captureExit=scope['actualCaptureExit'], evidence=proof)
    if len({scope['evidence']['testBinarySHA256'] for scope in result.values()}) != 1:
        raise ValueError('all native scopes must use the same source-bound test ELF')
    return result


def preflight_native_scopes(inventory, scopes):
    inventory = list(inventory)
    if set(scopes) != set(NATIVE_CASES): raise ValueError('all reviewed native scopes required')
    reports = {case: preflight_native(inventory, scopes[case]['events'], scopes[case]['goExit'],
                 scopes[case]['runnerExit'], scopes[case]['captureExit'], case) for case in NATIVE_CASES}
    errors = sorted({error for report in reports.values() for error in report['errors']})
    return dict(schema='pluto.native-ci-preflight.v1', status='FAIL_REQUIRED_NATIVE_SCOPES' if errors else 'PASS_REQUIRED_NATIVE_SCOPES',
                scopes=reports, errors=errors, ordinaryRuntime='NOT_RUN', fullOrdinaryCiGreen=False,
                archival=next(iter(reports.values()))['archival'])


def audit_native_lanes(inventory, ordinary, scopes, go_exit, capture_exit):
    inventory, ordinary = list(inventory), list(ordinary)
    preflight = preflight_native_scopes(inventory, scopes)
    errors = list(preflight['errors'])
    ended = {}
    for event in ordinary:
        package, name, action = (event.get(key, '') for key in ('Package', 'Test', 'Action'))
        if package == C01_PACKAGE and name.split('/', 1)[0] in NATIVE_CASES:
            errors.append('NATIVE_TEST_EXECUTED_IN_ORDINARY_SCOPE: ' + name)
        if not name and action in ('pass', 'fail', 'skip'):
            if package in ended: errors.append('DUPLICATE_PACKAGE_RESULT_IN_ORDINARY_SCOPE: ' + package)
            ended[package] = action
    required = {event.get('Package', '') for event in inventory if event.get('Action') == 'output'
                and any(line.startswith('Test') and not any(c.isspace() for c in line) and '/' not in line
                    and (event.get('Package'), line) not in {(C01_PACKAGE, case) for case in NATIVE_CASES}
                    for line in event.get('Output', '').splitlines())}
    if any(ended.get(package) != 'pass' for package in required): errors.append('ORDINARY_SCOPE_PACKAGES_NOT_PASSED')
    merged = itertools.chain(ordinary, *(scopes[case]['events'] for case in NATIVE_CASES))
    result = audit(inventory, merged, go_exit, capture_exit)
    result['errors'] = sorted(set(result['errors'] + errors))
    result['status'] = 'FAIL_REQUIRED_ORDINARY_GO_TEST_SUITE' if result['errors'] else 'PASS_REQUIRED_ORDINARY_GO_TEST_SUITE'
    result['lanes'] = dict(ordinary=dict(actualGoExit=go_exit, actualCaptureExit=capture_exit),
                          native=preflight['scopes'])
    result['nativeEvidence'] = {case: scopes[case]['evidence'] for case in NATIVE_CASES}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--events")
    parser.add_argument("--go-exit", type=int)
    parser.add_argument("--capture-exit", type=int)
    parser.add_argument("--report", required=True)
    parser.add_argument("--native-shards")
    parser.add_argument("--validate-native-shards", action="store_true")
    parser.add_argument("--validate-c01-shard", action="store_true")
    parser.add_argument("--c01-shard")
    parser.add_argument("--c01-runner-exit", type=int)
    parser.add_argument("--c01-capture-exit", type=int)
    parser.add_argument("--source-root", default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        if args.native_shards:
            if args.validate_c01_shard or any(value is not None for value in (args.c01_shard, args.c01_runner_exit, args.c01_capture_exit)):
                raise ValueError("cannot mix native scope manifests with legacy C01 arguments")
            scopes = native_scopes(args.native_shards, args.source_root)
            if args.validate_native_shards:
                report = preflight_native_scopes(events(args.inventory), scopes)
            else:
                if any(value is None for value in (args.events, args.go_exit, args.capture_exit)):
                    raise ValueError("actual ordinary events and both ordinary exits required")
                report = audit_native_lanes(events(args.inventory), events(args.events), scopes, args.go_exit, args.capture_exit)
        elif args.validate_native_shards:
            raise ValueError("complete native scope manifest required for preflight")
        elif any(value is not None for value in (args.c01_shard, args.c01_runner_exit, args.c01_capture_exit)):
            if any(value is None for value in (args.c01_shard, args.c01_runner_exit, args.c01_capture_exit)):
                raise ValueError("all explicit C01 scope evidence and actual exits are required")
            native_events, native_exit, native_proof = c01_shard(args.c01_shard, args.source_root)
            if args.validate_c01_shard:
                report = preflight_c01(events(args.inventory), native_events, native_exit,
                                       args.c01_runner_exit, args.c01_capture_exit)
            else:
                if any(value is None for value in (args.events, args.go_exit, args.capture_exit)):
                    raise ValueError("actual ordinary events and both ordinary exits required")
                report = audit_lanes(events(args.inventory), events(args.events), native_events,
                                     args.go_exit, args.capture_exit, native_exit,
                                     args.c01_runner_exit, args.c01_capture_exit)
            report["c01Evidence"] = native_proof
        else:
            if args.validate_c01_shard or any(value is None for value in (args.events, args.go_exit, args.capture_exit)):
                raise ValueError("complete ordinary evidence or explicit C01 preflight required")
            report = audit(events(args.inventory), events(args.events), args.go_exit, args.capture_exit)
    except (OSError, ValueError, TypeError) as error:
        report = dict(schema="pluto.ordinary-go-ci.v1", status="FAIL_INVALID_CI_EVIDENCE", error=str(error))
    raw = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    with Path(args.report).open("x", encoding="utf-8") as stream:
        stream.write(raw)
    print(raw, end="")
    return 0 if report["status"] in ("PASS_REQUIRED_ORDINARY_GO_TEST_SUITE", "PASS_REQUIRED_C01_NATIVE_SCOPE", "PASS_REQUIRED_NATIVE_SCOPES") else 1


if __name__ == "__main__":
    raise SystemExit(main())
