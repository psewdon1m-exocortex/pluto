#!/usr/bin/env python3
"""Pure JSON reporter regressions; these execute no product or archival reader."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("go_ci_report", Path(__file__).with_name("check-go-ci.py"))
reporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reporter)


def discovery(name="TestExample"):
    return [dict(Package="example", Action="output", Output=name + "\n"),
            dict(Package="example", Action="pass")]


def completed(name="TestExample", result="pass"):
    return [dict(Package="example", Test=name, Action="run"),
            dict(Package="example", Test=name, Action=result),
            dict(Package="example", Action="pass")]


class OrdinaryCIReportTests(unittest.TestCase):
    def test_source_bound_default_skip_is_explicit_not_run_never_pass(self):
        policy=reporter.conditional_policy(Path(__file__).resolve().parents[1],{})
        self.assertEqual(len(policy),16)
        key,item=next(iter(policy.items()));package,name=key
        inventory=[dict(Package=package,Action='output',Output=name+'\n')]
        actual=[dict(Package=package,Test=name,Action='run'),dict(Package=package,Test=name,Action='output',Output=item['skipMessage']+'\n'),dict(Package=package,Test=name,Action='skip'),dict(Package=package,Action='pass')]
        result=reporter.audit(inventory,actual,0,0,conditional={key:item})
        self.assertEqual(result['status'],'PASS_DEFAULT_ORDINARY_WITH_EXPLICIT_CONDITIONAL_NOT_RUN')
        self.assertEqual(result['ordinaryPassed'],0);self.assertEqual(len(result['conditionalNotRun']),1)
        self.assertEqual(result['conditionalNotRun'][0]['status'],'NOT_RUN')
        self.assertFalse(result['conditionalNotRun'][0]['ownerWaiver']);self.assertFalse(result['fullOrdinaryCIGreen'])
        self.assertFalse(result['conditionalQualificationComplete'])
        for mutation in ('missing','wrong-message','nested-skip','failed','configured'):
            changed=[dict(row) for row in actual];selected={key:item}
            if mutation=='missing':changed=[]
            if mutation=='wrong-message':changed[1]['Output']='another skip'
            if mutation=='nested-skip':changed+=[dict(Package=package,Test=name+'/child',Action='run'),dict(Package=package,Test=name+'/child',Action='skip')]
            if mutation=='failed':changed[2]['Action']='fail'
            if mutation=='configured':selected={}
            with self.subTest(mutation=mutation):self.assertTrue(reporter.audit(inventory,changed,0,0,conditional=selected)['status'].startswith('FAIL_'))

    def test_conditional_registry_cannot_cover_configured_or_changed_source(self):
        project=Path(__file__).resolve().parents[1]
        policy=json.loads((project/'scripts/default-ci-conditional-policy.json').read_bytes())
        env={key:'1' for item in policy['cases'].values() for key in item['environment']}
        self.assertEqual(reporter.conditional_policy(project,env),{})
        self.assertNotIn(reporter.ARCHIVAL_TEST,policy['cases'])
        self.assertTrue(all(item['ownerWaiver'] is False for item in policy['cases'].values()))
        with tempfile.TemporaryDirectory() as directory:
            copy=Path(directory);(copy/'scripts').mkdir()
            (copy/'scripts/default-ci-conditional-policy.json').write_text(json.dumps(policy))
            for relative in {item['source'] for item in policy['cases'].values()}:
                target=copy/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((project/relative).read_bytes())
            for relative in {item['source'] for item in policy['cases'].values()}:
                target=copy/relative;target.write_bytes(target.read_bytes().replace(b'\r\n',b'\n').replace(b'\n',b'\r\n'))
            self.assertEqual(len(reporter.conditional_policy(copy,{})),16)
            chosen=copy/next(iter(policy['cases'].values()))['source'];chosen.write_bytes(chosen.read_bytes()+b'//changed guard source\n')
            with self.assertRaisesRegex(ValueError,'source guard changed'):reporter.conditional_policy(copy,{})

    def test_pass_keeps_archival_waiver_separate(self):
        result = reporter.audit(discovery(), completed(), 0, 0)
        self.assertEqual(result["status"], "PASS_REQUIRED_ORDINARY_GO_TEST_SUITE")
        self.assertEqual(result["ordinaryPassed"], 1)
        self.assertEqual(result["archival"]["status"], "WAIVED_BY_OWNER")
        self.assertEqual(result["archival"]["runtime"], "NOT_RUN")
        self.assertFalse(result["archival"]["downgradeSafetyConfirmed"])

    def test_skipped_subtest_blocks_parent_pass(self):
        actual = completed() + completed("TestExample/missing-input", "skip")
        self.assertIn("REQUIRED_TESTS_SKIPPED", reporter.audit(discovery(), actual, 0, 0)["errors"])

    def test_missing_test_blocks_zero_exit(self):
        result = reporter.audit(discovery(), [], 0, 0)
        self.assertEqual(result["ordinaryPassed"], 0)
        self.assertIn("REQUIRED_TESTS_NOT_PASSED", result["errors"])

    def test_actual_go_and_capture_failures_cannot_be_erased(self):
        for go_exit, capture_exit in [(1, 0), (0, 1)]:
            result = reporter.audit(discovery(), completed(), go_exit, capture_exit)
            self.assertTrue(result["status"].startswith("FAIL_"))

    def test_archival_test_cannot_enter_ordinary_pass_count(self):
        name = reporter.ARCHIVAL_TEST
        result = reporter.audit(discovery(name), completed(name), 0, 0)
        self.assertIn("ARCHIVAL_TEST_PRESENT_IN_ORDINARY_CI", result["errors"])
        self.assertEqual(result["ordinaryPassed"], 0)

    def test_empty_duplicate_and_failed_results_are_rejected(self):
        self.assertIn("EMPTY_ORDINARY_TEST_INVENTORY", reporter.audit([], [], 0, 0)["errors"])
        self.assertTrue(any(error.startswith("DUPLICATE_TEST_RESULT") for error in
                            reporter.audit(discovery(), completed() + completed(), 0, 0)["errors"]))
        self.assertIn("REQUIRED_TESTS_FAILED", reporter.audit(discovery(), completed(result="fail"), 0, 0)["errors"])

    def test_unfinished_subtest_cannot_hide_behind_parent_pass(self):
        actual = [dict(Package="example", Test="TestExample/child", Action="run")] + completed()
        result = reporter.audit(discovery(), actual, 0, 0)
        self.assertIn("STARTED_TESTS_NOT_FINISHED", result["errors"])
        self.assertEqual(result["unfinishedTests"], [dict(package="example", test="TestExample/child")])
        self.assertTrue(result["status"].startswith("FAIL_"))

    def test_result_without_start_is_rejected_for_subtests(self):
        actual = completed() + [dict(Package="example", Test="TestExample/child", Action="pass")]
        result = reporter.audit(discovery(), actual, 0, 0)
        self.assertIn("TEST_RESULTS_WITHOUT_START", result["errors"])
        self.assertEqual(result["resultsWithoutStart"], [dict(package="example", test="TestExample/child")])

    def test_duplicate_start_cannot_be_hidden_by_one_pass(self):
        actual = completed()
        actual.insert(1, dict(Package="example", Test="TestExample", Action="run"))
        self.assertTrue(any(error.startswith("DUPLICATE_TEST_START") for error in
                            reporter.audit(discovery(), actual, 0, 0)["errors"]))

    def test_complete_nested_subtests_are_accepted(self):
        actual = [dict(Package="example", Test="TestExample", Action="run"),
                  dict(Package="example", Test="TestExample/child", Action="run"),
                  dict(Package="example", Test="TestExample/child", Action="pass"),
                  dict(Package="example", Test="TestExample", Action="pass"),
                  dict(Package="example", Action="pass")]
        result = reporter.audit(discovery(), actual, 0, 0)
        self.assertEqual(result["status"], "PASS_REQUIRED_ORDINARY_GO_TEST_SUITE")
        self.assertEqual(result["unfinishedTests"], [])
        self.assertEqual(result["resultsWithoutStart"], [])

    def lane_inventory(self):
        return discovery() + [dict(Package=reporter.C01_PACKAGE, Action="output", Output=reporter.C01_TEST+"\n")]

    def native_completed(self):
        return [dict(Package=reporter.C01_PACKAGE, Test=reporter.C01_TEST, Action="run"),
                dict(Package=reporter.C01_PACKAGE, Test=reporter.C01_TEST, Action="pass"),
                dict(Package=reporter.C01_PACKAGE, Action="pass")]

    def test_explicit_c01_scope_is_required_and_keeps_waiver_not_run(self):
        result = reporter.audit_lanes(self.lane_inventory(), completed(), self.native_completed(), 0, 0, 0, 0, 0)
        self.assertEqual(result["status"], "PASS_REQUIRED_ORDINARY_GO_TEST_SUITE")
        self.assertEqual(result["ordinaryPassed"], 2)
        self.assertTrue(result["lanes"]["c01"]["required"])
        self.assertEqual(result["archival"]["runtime"], "NOT_RUN")

    def test_c01_cannot_be_omitted_or_executed_twice(self):
        missing = reporter.audit_lanes(self.lane_inventory(), completed(), [], 0, 0, 0, 0, 0)
        self.assertIn("REQUIRED_TESTS_NOT_PASSED", missing["errors"])
        duplicate = reporter.audit_lanes(self.lane_inventory(), completed()+self.native_completed(), self.native_completed(), 0, 0, 0, 0, 0)
        self.assertIn("C01_EXECUTED_IN_ORDINARY_SCOPE", duplicate["errors"])
        self.assertTrue(any(error.startswith("DUPLICATE_TEST_RESULT") for error in duplicate["errors"]))

    def test_c01_only_accepts_its_exact_package_and_test(self):
        for extra in [dict(Package="other", Action="pass"),
                      dict(Package=reporter.C01_PACKAGE, Test="TestOther", Action="run")]:
            result = reporter.audit_lanes(self.lane_inventory(), completed(), self.native_completed()+[extra], 0, 0, 0, 0, 0)
            self.assertIn("UNEXPECTED_TEST_IN_C01_SCOPE", result["errors"])

    def test_each_c01_actual_exit_is_mandatory(self):
        for go_exit, runner_exit, capture_exit in [(1,0,0),(0,1,0),(0,0,1)]:
            result = reporter.audit_lanes(self.lane_inventory(), completed(), self.native_completed(), 0, 0, go_exit, runner_exit, capture_exit)
            self.assertTrue(result["status"].startswith("FAIL_"))
            self.assertEqual(result["lanes"]["c01"]["actualGoExit"], go_exit)

    def test_package_pass_from_one_scope_cannot_hide_other_scope_incomplete(self):
        inventory = self.lane_inventory()+[dict(Package=reporter.C01_PACKAGE, Action="output", Output="TestOrdinary\n")]
        ordinary = completed()+[dict(Package=reporter.C01_PACKAGE, Test="TestOrdinary", Action="run"),
                                dict(Package=reporter.C01_PACKAGE, Test="TestOrdinary", Action="pass")]
        result = reporter.audit_lanes(inventory, ordinary, self.native_completed(), 0, 0, 0, 0, 0)
        self.assertIn("ORDINARY_SCOPE_PACKAGES_NOT_PASSED", result["errors"])
        result = reporter.audit_lanes(self.lane_inventory(), completed(), self.native_completed()[:-1], 0, 0, 0, 0, 0)
        self.assertIn("C01_SCOPE_PACKAGE_NOT_PASSED", result["errors"])
        self.assertFalse(result["fullOrdinaryCIGreen"])

    def test_c01_scope_still_rejects_unfinished_and_skipped_subtests(self):
        child = dict(Package=reporter.C01_PACKAGE, Test=reporter.C01_TEST+"/child", Action="run")
        actual = [child]+self.native_completed()
        result = reporter.audit_lanes(self.lane_inventory(), completed(), actual, 0, 0, 0, 0, 0)
        self.assertIn("STARTED_TESTS_NOT_FINISHED", result["errors"])
        actual += [dict(child, Action="skip")]
        self.assertIn("REQUIRED_TESTS_SKIPPED", reporter.audit_lanes(self.lane_inventory(), completed(), actual, 0, 0, 0, 0, 0)["errors"])

    def native_receipt_fixture(self, directory, case=None):
        case = case or reporter.C01_TEST
        directory = Path(directory)
        project, shard = directory / "project", directory / "shard"
        source = project / "internal/pluto/runtime_contract.go"
        source.parent.mkdir(parents=True)
        source.write_text("package pluto\n//go:embed runtime-notices.tar\n", encoding="utf-8")
        (project / "go.mod").write_text("module pluto\n", encoding="utf-8")
        (project / "go.sum").write_text("", encoding="utf-8")
        (source.parent / "runtime-notices.tar").write_bytes(b"unit metadata fixture only")
        shard.mkdir()
        argv = ["/pluto-native-metadata.test", "-test.run=^"+case+"$", "-test.count=1", "-test.v"]
        wait = dict(PID=77, Observed=True, Exited=True, Signaled=False, ExitCode=0, Signal=0, RawStatus=0)
        output = "=== RUN   "+case+"\n--- PASS: "+case+" (0.01s)\nPASS\n"
        raw = output.encode()
        digest = hashlib.sha256(raw).hexdigest()
        result = dict(Actual=wait, IntentProven=True, NumericDurable=True, DrainsJoined=True,
                      StrongTupleObserved=True, LifecycleError="", DeadlineExpired=False,
                      JoinWatchdogExpired=False, Truncated=False, CombinedMode=True)
        joined = dict(result=result, actual_wait_durable=True, stdout_total_bytes=len(raw),
                      stdout_stored_prefix_bytes=len(raw), stdout_full_sha256=digest,
                      stdout_stored_prefix_sha256=digest, output_error="<nil>", numeric_error="<nil>")
        prepared = dict(role="go-test", args=argv, artifact=dict(Path=argv[0], SHA256="a"*64))
        observed = dict(Core=dict(Birth=dict(PID=77, PPID=70, Ticks=123), Parent=dict(PID=70, Ticks=100),
                       PIDFDTarget=77, Exe=argv[0], ExeSHA256="a"*64, Argv=argv,
                       Profile=dict(UID=[10001]*4,GID=[10001]*4,Groups=[],Caps=[0]*5,NNP=1,Seccomp=2)),
                       Group=77, Session=70, Namespaces=["mnt:[1]", "pid:[2]", "user:[3]"])
        final = dict(all_products_joined=True, no_adopted_children=True, go_actual=wait, go_lifecycle="", failures=None)
        records = {"actual-wait.json": wait, "joined-streams.json": joined,
                   "prepared-before-Start.json": prepared, "observed-after-exec.json": observed,
                   "owner-final.json": final, "source-inputs.json": dict(schema="pluto.c01-ci-source.v1",
                       testBinarySHA256="a"*64, inputs=reporter.c01_source_inputs(project))}
        for name, value in records.items():
            (shard / name).write_text(json.dumps(value), encoding="utf-8")
        (shard / "stdout.log").write_bytes(raw)
        actual = [dict(Package=reporter.native_package(case), Test=case, Action="run"),
                  dict(Package=reporter.native_package(case), Action="output", Output=output),
                  dict(Package=reporter.native_package(case), Test=case, Action="pass"),
                  dict(Package=reporter.native_package(case), Action="pass")]
        (shard / "events.jsonl").write_text("".join(json.dumps(event)+"\n" for event in actual), encoding="utf-8")
        if case==reporter.BULK_TEST:self.bulk_metadata_fixture(project,shard,wait)
        if case==reporter.PREPARED_TEST:self.prepared_metadata_fixture(shard)
        if case in reporter.API_CASES:self.api_metadata_fixture(project,shard,wait,case)
        if case==reporter.BATCH_TEST:
            records['backup-inventory.json']=[dict(path='snapshot-%d/%s'%(n,name),bytes=1,sha256='b'*64) for n in range(6) for name in (['coherent-fixture.tar','engine-cli-restore.json'] if n<3 else ['coherent-fixture.tar'])]
            (shard/'backup-inventory.json').write_text(json.dumps(records['backup-inventory.json']))
        return project, shard, records

    def test_batch_requires_its_syncstate_package_and_actual_backup_receipts(self):
        for mutation in ('wrong-package','missing-backup','duplicate-file','invalid-digest','missing-restore'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as directory:
                project,shard,records=self.native_receipt_fixture(directory,reporter.BATCH_TEST)
                if mutation=='wrong-package':
                    items=[json.loads(line) for line in (shard/'events.jsonl').read_text().splitlines()]
                    for item in items:item['Package']=reporter.C01_PACKAGE
                    (shard/'events.jsonl').write_text(''.join(json.dumps(item)+'\n' for item in items))
                elif mutation=='missing-backup':(shard/'backup-inventory.json').unlink()
                else:
                    inventory=records['backup-inventory.json']
                    if mutation=='duplicate-file':inventory.append(inventory[0])
                    if mutation=='invalid-digest':inventory[0]['sha256']='invalid'
                    if mutation=='missing-restore':inventory[:]=[x for x in inventory if not x['path'].endswith('/engine-cli-restore.json')]
                    (shard/'backup-inventory.json').write_text(json.dumps(inventory))
                with self.assertRaises((ValueError,FileNotFoundError)):reporter.native_shard(shard,project,reporter.BATCH_TEST)

    def prepared_metadata_fixture(self, shard):
        # Synthetic metadata for checker unit tests only; never runtime evidence.
        root='/retained/endurance-unit'
        receipt=dict(schema='pluto.prepared-backup-root-authorization.v1',run='unit',scope='unit',nonce='a'*32,
                     containerId='b'*64,case=reporter.PREPARED_TEST,site='adoption-prepared-changes-entry',
                     base=root+'/f-0001',evidence='/checkpoint/verified-backup.json',
                     condition='independent archive restore, every-file SHA, actual v8 open and default-trust TLS readback of 260 originals')
        receipt_raw=json.dumps(receipt).encode()
        manifest=dict(Schema='nativefixture.owner.v2',Run='unit',Scope='unit',Nonce='a'*32,ContainerID='b'*64,
                      RetainedRoot=root,GoArgs=['-test.run=^'+reporter.PREPARED_TEST+'$'],
                      Cases={reporter.PREPARED_TEST:dict(Faults={'adoption-prepared-changes-entry':dict(
                          Site=receipt['site'],BackupPath='/native-prepared-backup-receipt.json',
                          BackupSHA=hashlib.sha256(receipt_raw).hexdigest(),CheckpointRoot='/checkpoint',BarrierRequired=True)})})
        inventory=[dict(path=('source' if i<130 else 'second/.hidden')+'/file-%03d'%i,kind='file',mode=0o600,
                        bytes=1,sha256=hashlib.sha256(bytes([i%256])).hexdigest()) for i in range(260)]
        raw=json.dumps(inventory).encode()
        proof=dict(schema='pluto.prepared-checkpoint-qualified.v1',case=reporter.PREPARED_TEST,base=root+'/f-0001',
                   database=dict(schemaVersion=8,acknowledged=266,pending=0,fileOperations=260,directoryOperations=6),
                   restoredFiles=260,sourceFiles=260,uploads=260,productStoreOpened=True,trustedReceiverHttpStatus=200,
                   inventorySHA256=hashlib.sha256(raw).hexdigest(),archiveSHA256='c'*64,backupSHA256='d'*64,
                   backendSHA256='e'*64,planDigest='f'*64)
        (shard/'prepared-fault-receipt.json').write_bytes(receipt_raw)
        (shard/'prepared-inventory.json').write_bytes(raw)
        for name,value in [('prepared-manifest.json',manifest),('prepared-backup.json',proof)]:
            (shard/name).write_text(json.dumps(value))

    def test_prepared_fault_requires_complete_same_case_restore_and_actual_source_pins(self):
        for name,change in [('prepared-backup.json',lambda x:x.update(productStoreOpened=False)),
                            ('prepared-backup.json',lambda x:x['database'].update(pending=1)),
                            ('prepared-fault-receipt.json',lambda x:x.update(containerId='c'*64)),
                            ('prepared-manifest.json',lambda x:x['Cases'][reporter.PREPARED_TEST]['Faults']['adoption-prepared-changes-entry'].update(BarrierRequired=False)),
                            ('prepared-inventory.json',lambda x:x[0].update(sha256='0'*64))]:
            with self.subTest(file=name),tempfile.TemporaryDirectory() as directory:
                project,shard,_=self.native_receipt_fixture(directory,reporter.PREPARED_TEST)
                value=json.loads((shard/name).read_bytes());change(value)
                (shard/name).write_text(json.dumps(value))
                with self.assertRaises(ValueError):reporter.native_shard(shard,project,reporter.PREPARED_TEST)

    def test_native_c01_receipts_match_output_source_and_actual_wait(self):
        with tempfile.TemporaryDirectory() as directory:
            project, shard, _ = self.native_receipt_fixture(directory)
            actual, code, proof = reporter.c01_shard(shard, project)
            self.assertEqual(code, 0)
            self.assertTrue(proof["allProductsJoined"])
            self.assertEqual(proof["testBinarySHA256"], "a"*64)
            self.assertEqual(actual[-1]["Action"], "pass")

    def test_c01_rejects_missing_metadata_output_change_and_source_change(self):
        for mutation in ("missing", "output", "source", "events"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                project, shard, _ = self.native_receipt_fixture(directory)
                if mutation == "missing": (shard/"owner-final.json").unlink()
                if mutation == "output": (shard/"stdout.log").write_bytes(b"PASS\n")
                if mutation == "source": (project/"go.mod").write_text("module changed\n", encoding="utf-8")
                if mutation == "events": (shard/"events.jsonl").write_text("", encoding="utf-8")
                with self.assertRaises(ValueError): reporter.c01_shard(shard, project)

    def test_c01_rejects_incomplete_native_custody_or_owner_join(self):
        for name, mutate in [
            ("actual-wait.json", lambda value: value.update(RawStatus=9)),
            ("joined-streams.json", lambda value: value["result"].update(StrongTupleObserved=False)),
            ("owner-final.json", lambda value: value.update(all_products_joined=False)),
            ("prepared-before-Start.json", lambda value: value["args"].append("-test.run=TestOther")),
            ("observed-after-exec.json", lambda value: value["Core"].update(ExeSHA256="b"*64)),
            ("observed-after-exec.json", lambda value: value["Core"]["Profile"].update(Caps=[0,0,1,0,0])),
            ("observed-after-exec.json", lambda value: value["Core"].pop("Parent")),
            ("source-inputs.json", lambda value: value.update(testBinarySHA256="b"*64)),
        ]:
            with self.subTest(file=name), tempfile.TemporaryDirectory() as directory:
                project, shard, records = self.native_receipt_fixture(directory)
                value = records[name]; mutate(value)
                (shard/name).write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaises(ValueError): reporter.c01_shard(shard, project)

    def test_changed_embed_inputs_require_schema_review(self):
        with tempfile.TemporaryDirectory() as directory:
            project, _, _ = self.native_receipt_fixture(directory)
            source = project/"internal/pluto/runtime_contract.go"
            source.write_text("package pluto\n//go:embed other.tar\n", encoding="utf-8")
            with self.assertRaises(ValueError): reporter.c01_source_inputs(project)

    def test_c01_native_evidence_reads_have_a_small_bound(self):
        for name in ("source-inputs.json", "stdout.log", "events.jsonl", "source.go"):
            with self.subTest(file=name), tempfile.TemporaryDirectory() as directory:
                project, shard, _ = self.native_receipt_fixture(directory)
                file = project/"source.go" if name == "source.go" else shard/name
                file.write_bytes(b"x"*(reporter.MAX_EVENT_BYTES+1))
                with self.assertRaises(ValueError): reporter.c01_shard(shard, project)

    def test_preflight_is_explicitly_only_c01(self):
        result=reporter.preflight_c01(self.lane_inventory(),self.native_completed(),0,0,0)
        self.assertEqual(result["status"],"PASS_REQUIRED_C01_NATIVE_SCOPE")
        self.assertEqual(result["ordinaryRuntime"],"NOT_RUN")
        self.assertFalse(result["fullOrdinaryCiGreen"])

    def test_preflight_refuses_missing_discovery_and_unexpected_scope(self):
        self.assertIn("REQUIRED_C01_TEST_NOT_DISCOVERED",reporter.preflight_c01(discovery(),self.native_completed(),0,0,0)["errors"])
        actual=self.native_completed()+[dict(Package="other",Action="pass")]
        self.assertIn("UNEXPECTED_TEST_IN_C01_SCOPE",reporter.preflight_c01(self.lane_inventory(),actual,0,0,0)["errors"])
        self.assertTrue(reporter.preflight_c01(self.lane_inventory(),self.native_completed(),0,1,0)["status"].startswith("FAIL_"))

    def test_malformed_and_oversized_evidence_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "events.jsonl"
            for raw in [b"[]\n", b"broken\n", b'{"Action":"output","Output":[]}\n',
                        b"x" * (reporter.MAX_EVENT_BYTES + 1)]:
                file.write_bytes(raw)
                with self.assertRaises(ValueError):
                    list(reporter.events(file))

    def test_producer_receipt_validation_cannot_pass_skip_unfinished_or_foreign_events(self):
        for case in reporter.NATIVE_CASES:
            for mutation in ('skip','unfinished','duplicate-package','foreign'):
                with self.subTest(case=case,mutation=mutation),tempfile.TemporaryDirectory() as directory:
                    project,shard,_=self.native_receipt_fixture(directory,case)
                    events=[json.loads(line) for line in (shard/'events.jsonl').read_text().splitlines()]
                    if mutation=='skip':events[-2]['Action']='skip'
                    if mutation=='unfinished':events.insert(1,dict(Package=reporter.C01_PACKAGE,Test=case+'/child',Action='run'))
                    if mutation=='duplicate-package':events.append(dict(events[-1]))
                    if mutation=='foreign':events.insert(1,dict(Package='foreign',Action='start'))
                    (shard/'events.jsonl').write_text(''.join(json.dumps(event)+'\n' for event in events))
                    with self.assertRaises(ValueError):reporter.native_shard(shard,project,case)

    def all_native_inventory(self):
        return discovery()+[dict(Package=reporter.native_package(case), Action='output', Output=case+'\n')
                            for case in reporter.NATIVE_CASES]

    def all_native_events(self):
        return {case:dict(events=[dict(Package=reporter.native_package(case), Test=case, Action='run'),
                                 dict(Package=reporter.native_package(case), Test=case, Action='pass'),
                                 dict(Package=reporter.native_package(case), Action='pass')],
                          goExit=0, runnerExit=0, captureExit=0, evidence={'test':case})
                for case in reporter.NATIVE_CASES}

    def test_four_native_scopes_merge_without_waiving_any_discovered_test(self):
        result=reporter.audit_native_lanes(self.all_native_inventory(),completed(),self.all_native_events(),0,0)
        self.assertEqual(result['status'],'PASS_REQUIRED_ORDINARY_GO_TEST_SUITE')
        self.assertEqual(result['ordinaryPassed'],1+len(reporter.NATIVE_CASES))
        self.assertEqual(set(result['lanes']['native']),set(reporter.NATIVE_CASES))
        self.assertEqual(result['archival']['runtime'],'NOT_RUN')
        for scope in result['lanes']['native'].values():self.assertFalse(scope['fullOrdinaryCiGreen'])

    def test_missing_native_scope_fails_closed(self):
        for case in reporter.NATIVE_CASES:
            scopes=self.all_native_events();del scopes[case]
            with self.subTest(case=case),self.assertRaises(ValueError):
                reporter.audit_native_lanes(self.all_native_inventory(),completed(),scopes,0,0)

    def test_every_native_scope_requires_actual_runner_capture_and_go_success(self):
        for case in reporter.NATIVE_CASES:
            for field in ('runnerExit','captureExit','goExit'):
                scopes=self.all_native_events();scopes[case][field]=7
                with self.subTest(case=case,field=field):
                    result=reporter.audit_native_lanes(self.all_native_inventory(),completed(),scopes,0,0)
                    self.assertTrue(result['status'].startswith('FAIL_'))

    def test_each_native_scope_rejects_skipped_unfinished_and_foreign_tests(self):
        for case in reporter.NATIVE_CASES:
            for mutation in ('skip','unfinished','foreign','missing-package','duplicate-package'):
                scopes=self.all_native_events();stream=scopes[case]['events']
                if mutation=='skip':stream[1]['Action']='skip'
                if mutation=='unfinished':stream.insert(1,dict(Package=reporter.C01_PACKAGE,Test=case+'/child',Action='run'))
                if mutation=='foreign':stream.insert(1,dict(Package=reporter.C01_PACKAGE,Test='TestForeign',Action='run'))
                if mutation=='missing-package':stream.pop()
                if mutation=='duplicate-package':stream.append(dict(stream[-1]))
                with self.subTest(case=case,mutation=mutation):
                    self.assertTrue(reporter.audit_native_lanes(self.all_native_inventory(),completed(),scopes,0,0)['status'].startswith('FAIL_'))

    def test_native_pass_cannot_hide_missing_ordinary_package_terminal(self):
        inventory=self.all_native_inventory()+[dict(Package=reporter.C01_PACKAGE,Action='output',Output='TestOrdinary\n')]
        ordinary=completed()+[dict(Package=reporter.C01_PACKAGE,Test='TestOrdinary',Action='run'),
                              dict(Package=reporter.C01_PACKAGE,Test='TestOrdinary',Action='pass')]
        self.assertIn('ORDINARY_SCOPE_PACKAGES_NOT_PASSED',reporter.audit_native_lanes(inventory,ordinary,self.all_native_events(),0,0)['errors'])

    def test_native_execution_in_both_scopes_is_rejected(self):
        for case in reporter.NATIVE_CASES:
            scopes=self.all_native_events();ordinary=completed()+scopes[case]['events']
            result=reporter.audit_native_lanes(self.all_native_inventory(),ordinary,scopes,0,0)
            self.assertIn('NATIVE_TEST_EXECUTED_IN_ORDINARY_SCOPE: '+case,result['errors'])

    def test_selected_native_receipt_must_match_exact_case_and_current_source(self):
        for case in reporter.NATIVE_CASES:
            with self.subTest(case=case),tempfile.TemporaryDirectory() as directory:
                project,shard,_=self.native_receipt_fixture(directory,case)
                _,code,proof=reporter.native_shard(shard,project,case)
                self.assertEqual(code,0);self.assertEqual(proof['test'],case)
                wrong=next(other for other in reporter.NATIVE_CASES if other!=case)
                with self.assertRaises(ValueError):reporter.native_shard(shard,project,wrong)

    def test_scope_manifest_rejects_omission_reuse_boolean_exit_and_unknown_scope(self):
        for mutation in ('valid','missing','reuse','boolean','unknown'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);scopes={};project=None
                for index,case in enumerate(reporter.NATIVE_CASES):
                    parent=root/str(index);parent.mkdir()
                    project,shard,_=self.native_receipt_fixture(parent,case)
                    if case==reporter.BULK_TEST:shared_project=project
                    scopes[case]=dict(directory=str(shard.resolve()),actualRunnerExit=0,actualCaptureExit=0)
                first,second=reporter.NATIVE_CASES[:2]
                if mutation=='missing':del scopes[first]
                if mutation=='reuse':scopes[second]['directory']=scopes[first]['directory']
                if mutation=='boolean':scopes[first]['actualRunnerExit']=False
                if mutation=='unknown':scopes['TestUnreviewed']=scopes.pop(first)
                file=root/'scopes.json';file.write_text(json.dumps(dict(schema='pluto.native-ci-scopes.v1',scopes=scopes)))
                if mutation=='valid':
                    result=reporter.preflight_native_scopes(self.all_native_inventory(),reporter.native_scopes(file,shared_project))
                    self.assertEqual(result['status'],'PASS_REQUIRED_NATIVE_SCOPES')
                    self.assertEqual(result['ordinaryRuntime'],'NOT_RUN')
                else:
                    with self.assertRaises(ValueError):reporter.native_scopes(file,shared_project)



    def api_metadata_fixture(self,project,shard,actual,case):
        # Synthetic unit metadata only; never an actual API or process result.
        self.bulk_metadata_fixture(project,shard,actual)
        backend=json.loads((shard/'backend-inputs.json').read_bytes());bulk=json.loads((shard/'bulk-evidence.json').read_bytes())
        image=(shard/'backend-image.json').read_bytes();(shard/'api-backend-image.json').write_bytes(image)
        (shard/'ci-source-inputs.json').write_text(json.dumps(dict(schema='pluto.native-api-ci-script-source.v1',inputs=reporter.api_ci_script_inputs(project))))
        images=bulk['images'];roles=[('anchor','native','1'),('postgres','postgres','2'),('api','saturn','4'),('sftp','sftp','3')]
        containers=[dict(id=letter*64,created='synthetic-unit',image=images[kind],actualExitCode=0,oomKilled=False,running=False,publishedPorts={},networkMode='none' if role=='anchor' else 'container:'+'1'*64) for role,kind,letter in roles]
        ready={role:letter*64 for role,kind,letter in roles};ready.update(loopbackOnly=True,networkNamespace='net:[1]',roots=['unit-root-one','unit-root-two'])
        proof=dict(schema='pluto.native-api-ci-proof.v1',case=case,status='PASS_ORIGINAL_CASE_GENUINE_API_PG_SFTP_TYPED_LIFECYCLE',testBinarySHA256='a'*64,actualGoWait=actual,containerClosure=dict(status='STOPPED_RETAINED'),images=images,sourceCohortSHA256=backend['sourceCohortSHA256'],backendImageSHA256=hashlib.sha256(image).hexdigest(),containers=containers,apiReady=ready,fullOrdinaryCiGreen=False,processCrashFaults=0,independentFullGraphRestoreClaimed=False)
        (shard/'api-evidence.json').write_text(json.dumps(proof))

    def test_api_receipts_refuse_wrong_backend_identity_or_open_actor(self):
        case=next(iter(reporter.API_CASES))
        for mutation in ('wrong-case','wrong-pg','wrong-image','running','port','nonzero','full-claim'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as directory:
                project,shard,_=self.native_receipt_fixture(directory,case);file=shard/'api-evidence.json';proof=json.loads(file.read_bytes())
                if mutation=='wrong-case':proof['case']='TestUnreviewed'
                if mutation=='wrong-pg':proof['apiReady']['postgres']='f'*64
                if mutation=='wrong-image':proof['images']['saturn']='sha256:'+'f'*64
                if mutation=='running':proof['containers'][0]['running']=True
                if mutation=='port':proof['containers'][0]['publishedPorts']={'443/tcp':[] }
                if mutation=='nonzero':proof['containers'][0]['actualExitCode']=1
                if mutation=='full-claim':proof['fullOrdinaryCiGreen']=True
                file.write_text(json.dumps(proof))
                with self.assertRaises(ValueError):reporter.native_shard(shard,project,case)

    def bulk_metadata_fixture(self, project, shard, actual):
        """Synthetic unit metadata only; never product/runtime acceptance evidence."""
        source=Path(__file__).resolve().parents[1]
        names=list({row["path"]:row for row in reporter.bulk_ci_script_inputs(source)+reporter.api_ci_script_inputs(source)}.values())
        for row in names:
            dest=project/row['path'];dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_bytes((source/row['path']).read_bytes())
        policy_raw=(project/'scripts/native-fixture/bulk/backend-policy.json').read_bytes()
        policy=json.loads(policy_raw)
        cohort=[dict(path=name,bytes=1,sha256='b'*64) for name in policy['files']]
        digest=lambda raw:hashlib.sha256(raw).hexdigest()
        encode=lambda value:json.dumps(value,separators=(',',':')).encode()
        cohort_sha=digest(encode(cohort))
        images={kind:'sha256:'+letter*64 for kind,letter in zip(('native','saturn','postgres','sftp'),'abcd')}
        containers=[dict(id=letter*64,image=images[kind],running=False,oomKilled=False,actualExitCode=0)
                    for kind,letter in zip(('native','postgres','sftp'),'123')]
        component=lambda:dict(backup=dict(originalUnchanged=True,archiveSHA256='e'*64,files=1,bytes=1),
                              restore=dict(allPortableMetadataAndBytesEqual=True,independentInodes=True,
                              relocatedCustodyClaimed=False,archiveSHA256='e'*64,files=1,bytes=1))
        request='synthetic-unit-only'
        graph=dict(requestID=request,components={k:component() for k in ('pg','sftp','fixtures','authority')},
                   sourceTuples=dict(native='1'*64,pg='2'*64,sftp='3'*64),
                   product=dict(status='PASS_ACTUAL_RESTORED_PRODUCT_READBACK',requestID=request,
                                nativeArchiveSHA256='f'*64,canaryRead=True,clonedBackendWriterStarted=False),
                   nativeOriginalVerification=dict(originalPhysicalUnchanged=True))
        crash=dict(PID=78,Observed=True,Exited=False,Signaled=True,ExitCode=0,Signal=9,RawStatus=9)
        native=dict(status='PASS_INDEPENDENT_NATIVE_FINAL_SQLITE_SOURCE_AND_ACTUAL_WAITS',requestID=request,
                    goActual=actual,sourceFiles=32,allFinalPhysicalUnchanged=True,deliberateEditedFileSameInode=True,
                    operationStages={'CLIENT_ACKED':54},tables={'operation_retry':0},
                    actualWaits=[actual,crash],reviewedCrashWaits=[crash])
        initial=[dict(ID=str(i),Path='example.md' if i==0 else str(i)+'.md',Version='old'+str(i),
                      Sha256='b'*64,Size=1,VersionCount=1) for i in range(32)]
        final=[dict(f) for f in initial];final[0].update(Version='new0',Sha256='c'*64,Size=2,VersionCount=2)
        observed=[dict(kind='pluto',resourceId=f['ID'],versionId=f['Version'],sha256=f['Sha256'],bytes=f['Size'],
                       versions=['old'+str(i),'new0'] if i==0 else [f['Version']]) for i,f in enumerate(final)]
        product=dict(status='PASS_FINAL_SQL_IDS_VERSIONS_AND_ALL_SFTP_BYTES',requestID=request,
                     canaryRead=True,clonedBackendWriterStarted=False,files=observed,
                     databases=[dict(kind=k,migrations=122,backendState='STOPPED') for k in ('windows','pluto')])
        records={
            'backend-inputs.json':dict(schema='pluto.bulk-ci-backend-inputs.v1',policySHA256=digest(policy_raw),
                                      files=cohort,images={k:images[k] for k in ('saturn','postgres','sftp')},
                                      sourceCohortSHA256=cohort_sha),
            'ci-source-inputs.json':dict(schema='pluto.bulk-ci-script-source.v1',inputs=reporter.bulk_ci_script_inputs(project)),
            'backend-image.json':dict(schema='pluto.bulk-ci-backend-image.v1',status='PASS_EXACT_612_IMAGE_FILES',
                                      files=612,image=images['saturn'],sourceCohortSHA256=cohort_sha,policySHA256=digest(policy_raw)),
            'checkpoint-graph.json':graph,
            'checkpoint-complete.json':dict(schema='pluto.native-bulk-checkpoint-proof.v1',status='PASS_GENUINE_FULL_GRAPH_RESTORE',
                                           requestID=request,graphSHA256=digest(encode(graph)),nativeArchiveSHA256='f'*64,canaryBytes=1,
                                           **{k:True for k in ('postgreSQLRestored','fullSQLRowsCompared','physicalSFTPRestored',
                                              'allPhysicalBytesCompared','actualProductReadback','authorityConfigRestored',
                                              'originalBackendStoppedReceipt','originalBackendResumed')}),
            'native-final.json':native,
            'bulk-assertions.json':dict(status='PASS',count=32,bulkLostAckCrashRecovery=True,pauseRestart=True,
                                       pauseResumeSameProcess=True,initial=dict(Files=initial,Folders=[]),
                                       final=dict(Files=final,Folders=[]),localManifest={f['Path']:f['Sha256'] for f in final}),
            'final-graph.json':dict(schema='pluto.native-bulk-final-cold-graph.v1',requestID=request,
                                   components={k:component() for k in ('pg','sftp')},product=product,
                                   nativeFinalProof=dict(sha256=digest(encode(native)))),
            'final-product.json':product,
        }
        proof=dict(schema='pluto.bulk-ci-proof.v1',test=reporter.BULK_TEST,
                   status='PASS_GENUINE_BULK_NATIVE_CHECKPOINT_RESTORE_AND_FINAL_READBACK',testBinarySHA256='a'*64,
                   actualGoWait=actual,sourceFiles=32,realSaturnPGSFTP=True,originalBackendResumed=True,
                   fullOrdinaryCiGreen=False,containerClosure=dict(status='STOPPED_RETAINED'),
                   containers=containers,images=images,sourceCohortSHA256=cohort_sha,files={})
        for name,value in records.items():
            raw=encode(value);(shard/name).write_bytes(raw)
            proof['files'][name]=dict(bytes=len(raw),sha256=digest(raw))
        (shard/'bulk-evidence.json').write_bytes(encode(proof))

    def mutate_bulk_record(self,shard,name,mutate):
        """Rebind file hash so semantic rejection is tested, not only hash rejection."""
        file=shard/name;value=json.loads(file.read_bytes());mutate(value)
        raw=json.dumps(value,separators=(',',':')).encode();file.write_bytes(raw)
        proof=json.loads((shard/'bulk-evidence.json').read_bytes())
        proof['files'][name]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        (shard/'bulk-evidence.json').write_text(json.dumps(proof))

    def test_bulk_rejects_missing_and_changed_proof_files(self):
        for name in sorted(reporter.BULK_PUBLIC_FILES|{'bulk-evidence.json'}):
            for mutation in ('missing','changed'):
                with self.subTest(name=name,mutation=mutation),tempfile.TemporaryDirectory() as directory:
                    project,shard,_=self.native_receipt_fixture(directory,reporter.BULK_TEST)
                    file=shard/name
                    if mutation=='missing':file.unlink()
                    else:file.write_text('{}')
                    with self.assertRaises((ValueError,FileNotFoundError)):reporter.native_shard(shard,project,reporter.BULK_TEST)

    def test_bulk_rejects_semantic_restore_fault_and_final_state_contradictions(self):
        mutations=[
            ('backend-image.json',lambda v:v.update(files=602,status='PASS_EXACT_602_IMAGE_FILES')),
            ('backend-image.json',lambda v:v.update(files=611)),
            ('checkpoint-complete.json',lambda v:v.update(originalBackendResumed=False)),
            ('checkpoint-graph.json',lambda v:v['components']['pg']['restore'].update(independentInodes=False)),
            ('native-final.json',lambda v:v.update(reviewedCrashWaits=[])),
            ('native-final.json',lambda v:v['tables'].update(operation_retry=1)),
            ('native-final.json',lambda v:v.update(goActual=dict(v['goActual'],PID=999))),
            ('bulk-assertions.json',lambda v:v.update(pauseRestart=False)),
            ('bulk-assertions.json',lambda v:v['final']['Files'][1].update(VersionCount=2)),
            ('final-graph.json',lambda v:v['components'].pop('sftp')),
            ('final-product.json',lambda v:v['files'][1].update(resourceId=v['files'][0]['resourceId'])),
            ('final-product.json',lambda v:v['databases'][0].update(backendState='RUNNING')),
        ]
        for name,mutate in mutations:
            with self.subTest(name=name,mutate=mutate),tempfile.TemporaryDirectory() as directory:
                project,shard,_=self.native_receipt_fixture(directory,reporter.BULK_TEST)
                self.mutate_bulk_record(shard,name,mutate)
                with self.assertRaises(ValueError):reporter.native_shard(shard,project,reporter.BULK_TEST)

    def test_bulk_rejects_legacy_or_incomplete_final_migration_set(self):
        for migrations in (117,121,123):
            with self.subTest(migrations=migrations),tempfile.TemporaryDirectory() as directory:
                project,shard,_=self.native_receipt_fixture(directory,reporter.BULK_TEST)
                self.mutate_bulk_record(shard,'final-product.json',
                    lambda value: [row.update(migrations=migrations) for row in value['databases']])
                product=json.loads((shard/'final-product.json').read_bytes())
                self.mutate_bulk_record(shard,'final-graph.json',lambda value:value.update(product=product))
                with self.assertRaisesRegex(ValueError,'STOPPED on122migrations'):
                    reporter.native_shard(shard,project,reporter.BULK_TEST)

    def test_bulk_rejects_current_helper_change_and_full_green_claim(self):
        for mutation in ('helper','green','container'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as directory:
                project,shard,_=self.native_receipt_fixture(directory,reporter.BULK_TEST)
                if mutation=='helper':
                    (project/'scripts/run-bulk-ci.mjs').write_text('// changed')
                else:
                    file=shard/'bulk-evidence.json';value=json.loads(file.read_bytes())
                    if mutation=='green':value['fullOrdinaryCiGreen']=True
                    else:value['containers'][0]['actualExitCode']=False
                    file.write_text(json.dumps(value))
                with self.assertRaises(ValueError):reporter.native_shard(shard,project,reporter.BULK_TEST)


if __name__ == "__main__":
    unittest.main()
