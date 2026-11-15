"""Dispatcher control-flow regressions; no Go product test or archival reader is run."""
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('go_ci_dispatch',Path(__file__).with_name('go-ci.py'))
dispatch=importlib.util.module_from_spec(spec);spec.loader.exec_module(dispatch)
producer_spec=importlib.util.spec_from_file_location('native_ci_producer',Path(__file__).with_name('run-c01-ci.py'))
producer=importlib.util.module_from_spec(producer_spec);producer_spec.loader.exec_module(producer)


class DispatchTests(unittest.TestCase):
    def test_public_helper_copy_preserves_private_source_mode_and_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'export.py';source.write_bytes(b'public helper only\n')
            source.chmod(0o600);mode=source.stat().st_mode
            target=root/'inputs';target.mkdir()
            copy,proof=producer.stage_public_helper(source,target)
            self.assertEqual(copy.read_bytes(),source.read_bytes())
            self.assertEqual(source.stat().st_mode,mode)
            self.assertEqual(copy.stat().st_mode&0o222,0)
            self.assertEqual(proof['sha256'],producer.digest(source))
            with self.assertRaises(FileExistsError):producer.stage_public_helper(source,target)

    def test_public_helper_staging_refuses_empty_directory_and_oversized_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);target=root/'inputs';target.mkdir()
            for name,content in [('empty',b''),('oversized',b'x'*(4*1024*1024+1))]:
                source=root/name;source.write_bytes(content)
                with self.assertRaises(ValueError):producer.stage_public_helper(source,target)
            with self.assertRaises(ValueError):producer.stage_public_helper(root,target)

    def run_case(self,env=None,fail=None,args=None):
        with tempfile.TemporaryDirectory() as directory:
            values={'PLUTO_GO_CI_EVIDENCE_DIR':directory}
            values.update(env or {})
            if values.get('PLUTO_GO_CI_C01_SOURCE_INPUTS') and 'PLUTO_GO_CI_BULK_INPUTS' not in values:
                backend=Path(directory)/'backend-inputs.json';backend.write_text('{}')
                values['PLUTO_GO_CI_BULK_INPUTS']=str(backend.resolve())
            if values.get('PLUTO_GO_CI_C01_SOURCE_INPUTS'):
                values.setdefault('PLUTO_GO_CI_NODE','/unit-node')
            calls=[]
            def capture(argv,file,**unused):
                calls.append(argv)
                Path(file).write_bytes(b'')
                return fail(argv) if fail else (0,0)
            with patch.dict(os.environ,values,clear=True),patch.object(dispatch,'capture',side_effect=capture),patch('sys.stdout',io.StringIO()):
                code=dispatch.main(args or [])
            reports=list(Path(directory).glob('ordinary-*/report.json'))
            return code,calls,json.loads(reports[0].read_bytes()) if reports else None

    def native_env(self):
        return dict(PLUTO_GO_CI_C01_IMAGE='sha256:'+'a'*64,PLUTO_GO_CI_C01_SOURCE_INPUTS='/inputs',
                    PLUTO_GO_CI_C01_TEST_BINARY='/test',STAGE3_PLUTO_BINARY='/cli',PLUTO_GO_CI_C01_OWNER='/owner',
                    PLUTO_GO_CI_C01_CONVERTER='/converter',PLUTO_GO_CI_SYNCSTATE_TEST_BINARY='/syncstate-test')

    def test_default_keeps_c01_in_whole_ordinary_run(self):
        code,calls,_=self.run_case()
        self.assertEqual(code,0)
        ordinary=next(argv for argv in calls if argv[:3]==['go','test','-race'])
        self.assertNotIn('-skip',ordinary)
        self.assertFalse(any('run-c01-ci.py' in ' '.join(argv) for argv in calls))

    def test_native_exclusion_only_after_all_four_producers_and_preflight(self):
        code,calls,_=self.run_case(self.native_env())
        self.assertEqual(code,0)
        producers=[i for i,argv in enumerate(calls) if any(arg.endswith(('run-c01-ci.py','run-bulk-ci.mjs')) for arg in argv)]
        preflight=next(i for i,argv in enumerate(calls) if '--validate-native-shards' in argv)
        ordinary=next(i for i,argv in enumerate(calls) if argv[:3]==['go','test','-race'])
        self.assertEqual(len(producers),len(dispatch.NATIVE_SCOPES))
        self.assertEqual([calls[i][calls[i].index('--case')+1] for i in producers],list(dispatch.NATIVE_SCOPES.values()))
        self.assertLess(max(producers),preflight);self.assertLess(preflight,ordinary)
        self.assertEqual(calls[ordinary][calls[ordinary].index('-skip')+1],'^('+'|'.join(dispatch.NATIVE_SCOPES.values())+')$')
        audit=next(argv for argv in calls if any(arg.endswith('check-go-ci.py') for arg in argv) and '--validate-native-shards' not in argv)
        self.assertIn('--native-shards',audit)

    def test_batch_uses_its_own_race_package_binary(self):
        code,calls,_=self.run_case(self.native_env());self.assertEqual(code,0)
        for call in calls:
            if any(arg.endswith('run-c01-ci.py') for arg in call):
                case=call[call.index('--case')+1]
                expected='/syncstate-test' if case=='TestSmallBatchEngineActualCLIProcessesMixedAndLostReply' else '/test'
                self.assertEqual(call[call.index('--test-binary')+1],expected)

    def test_each_producer_failure_closes_ordinary_admission(self):
        for case in dispatch.NATIVE_SCOPES.values():
            for outcome in ((7,0),(0,1)):
                with self.subTest(case=case,outcome=outcome):
                    def fail(argv):return outcome if '--case' in argv and argv[argv.index('--case')+1]==case else (0,0)
                    code,calls,report=self.run_case(self.native_env(),fail)
                    self.assertEqual(code,1);self.assertEqual(report['case'],case)
                    self.assertEqual(report['actualNativeProducerExit'],outcome[0])
                    self.assertEqual(report['actualNativeCaptureExit'],outcome[1])
                    self.assertEqual(report['ordinaryRuntime'],'NOT_RUN')
                    self.assertFalse(any(argv[:3]==['go','test','-race'] for argv in calls))

    def test_preflight_failure_closes_ordinary_admission(self):
        for outcome in ((1,0),(0,1)):
            with self.subTest(outcome=outcome):
                def fail(argv):return outcome if '--validate-native-shards' in argv else (0,0)
                code,calls,report=self.run_case(self.native_env(),fail)
                self.assertEqual(code,1);self.assertEqual(report['status'],'FAIL_NATIVE_PREFLIGHT')
                self.assertFalse(any(argv[:3]==['go','test','-race'] for argv in calls))

    def test_missing_configuration_and_discovery_failure_stop_before_runtime(self):
        code,calls,report=self.run_case({'PLUTO_GO_CI_C01_IMAGE':'sha256:'+'a'*64})
        self.assertEqual(code,1);self.assertEqual(report['status'],'FAIL_NATIVE_PROVISIONING')
        code,calls,report=self.run_case(fail=lambda argv:(3,0))
        self.assertEqual(code,1);self.assertEqual(len(calls),1);self.assertEqual(report['ordinaryRuntime'],'NOT_RUN')

    def test_invalid_running_inventory_stops_before_any_native_or_ordinary_runtime(self):
        for raw in ('broken','false','[7]'):
            with self.subTest(raw=raw):
                env=self.native_env();env['PLUTO_GO_CI_C01_ALLOWED_RUNNING_IDS']=raw
                code,calls,report=self.run_case(env)
                self.assertEqual(code,1);self.assertEqual(report['status'],'FAIL_NATIVE_PROVISIONING')
                self.assertEqual(report['ordinaryRuntime'],'NOT_RUN');self.assertEqual(len(calls),1)

    def test_go_and_capture_nonzero_cannot_be_erased_by_reporter(self):
        for outcome in ((1,0),(0,1)):
            with self.subTest(outcome=outcome):
                def fail(argv):return outcome if argv[:3]==['go','test','-race'] else (0,0)
                code,calls,_=self.run_case(fail=fail)
                self.assertEqual(code,1);self.assertFalse(any(argv[:2]==['go','vet'] for argv in calls))

    def test_go_json_stdout_is_not_mixed_with_stderr_diagnostics(self):
        class Console:
            def __init__(self):self.buffer=io.BytesIO()
        with tempfile.TemporaryDirectory() as directory,patch('sys.stdout',Console()),patch('sys.stderr',Console()):
            file=Path(directory)/'events.jsonl'
            actual,captured=dispatch.capture([sys.executable,'-I','-B','-c',
                "import sys;sys.stdout.buffer.write(b'{\"Action\":\"pass\"}\\n');sys.stderr.buffer.write(b'go: module diagnostic\\n')"],file,separate_stderr=True)
            self.assertEqual((actual,captured),(0,0))
            self.assertEqual(file.read_bytes(),b'{"Action":"pass"}\n')
            self.assertEqual(file.with_suffix('.stderr.log').read_bytes(),b'go: module diagnostic\n')

    def test_capture_drains_and_joins_after_console_failure(self):
        class Console:
            @property
            def buffer(self):return self
            def write(self,data):raise BrokenPipeError('unit output sink')
        with tempfile.TemporaryDirectory() as directory,patch('sys.stdout',Console()):
            file=Path(directory)/'actual.log'
            actual,captured=dispatch.capture([sys.executable,'-I','-B','-c',"import sys;sys.stdout.write('real child output');sys.exit(7)"],file)
            self.assertEqual(actual,7);self.assertEqual(captured,1)
            self.assertEqual(file.read_bytes(),b'real child output')


    def test_native_only_reports_no_ordinary_runtime_or_full_green(self):
        code,calls,report=self.run_case(self.native_env(),args=['--native-preflight-only'])
        self.assertEqual(code,0)
        self.assertEqual(report['status'],'PASS_REQUIRED_NATIVE_PREFLIGHT_ORDINARY_NOT_RUN')
        self.assertEqual(report['ordinaryRuntime'],'NOT_RUN')
        self.assertFalse(report['fullOrdinaryCiGreen'])
        self.assertEqual(report['archival']['status'],'WAIVED_BY_OWNER')
        self.assertEqual(len(report['nativeScopes']),len(dispatch.NATIVE_SCOPES))
        self.assertFalse(any(argv[:3]==['go','test','-race'] or argv[:2]==['go','vet'] for argv in calls))

    def test_bulk_input_is_required_before_any_producer(self):
        for value in ('','relative.json','/absent/backend-inputs.json'):
            with self.subTest(value=value):
                env=self.native_env();env['PLUTO_GO_CI_BULK_INPUTS']=value
                code,calls,report=self.run_case(env)
                self.assertEqual(code,1)
                self.assertEqual(report['status'],'FAIL_NATIVE_PROVISIONING')
                self.assertEqual(len(calls),1)
                self.assertEqual(report['ordinaryRuntime'],'NOT_RUN')

    def test_native_only_without_image_cannot_pass(self):
        code,calls,report=self.run_case(args=['--native-preflight-only'])
        self.assertEqual(code,1)
        self.assertEqual(report['status'],'FAIL_NATIVE_PROVISIONING')
        self.assertFalse(report['fullOrdinaryCiGreen'])


if __name__=='__main__':unittest.main()
