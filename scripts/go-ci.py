#!/usr/bin/env python3
"""Run complete ordinary CI with explicit, source-bound native scopes."""
import argparse
import json
import shutil
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading

PROJECT=Path(__file__).resolve().parents[1]
C01='TestStage3C01OrdinaryDaemonRestartBackupSemantics'
NATIVE_SCOPES={"c01":"TestStage3C01OrdinaryDaemonRestartBackupSemantics","proxy":"TestCompletionDaemonProxyReopenRetainsDeletedSourceOriginal","route":"TestCompletionDaemonRestartsAfterOwnedRouteLossWithoutFileEvent","bulk":"TestCompletionNativeBulkReadbackPauseRestartNoCopies","prepared":"TestStage3C12NativeReviewedPolicyScopesAndRestart"}
OWNER_POLICY=json.loads((PROJECT/'scripts/native-fixture/owner-case-policy.json').read_bytes())
if OWNER_POLICY.get('schema')!='pluto.native-owner-case-policy.v1':raise ValueError('reviewed owner case policy required')
NATIVE_SCOPES.update({f'owner-{index}':case for index,case in enumerate(sorted({name.split('/')[0] for name in OWNER_POLICY['cases']}))})

API_POLICY=json.loads((PROJECT/'scripts/native-fixture/api/case-policy.json').read_bytes())
if API_POLICY.get('schema')!='pluto.native-api-ci-case-policy.v1':raise ValueError('reviewed API case policy required')
API_CASES=API_POLICY['cases'];NATIVE_SCOPES.update({'api-'+str(index):case for index,case in enumerate(API_CASES)})

def capture(argv, file, *, cwd=PROJECT, separate_stderr=False):
    """Join the actual process and both drains; keep Go JSON stdout unmixed."""
    failed=[]
    with Path(file).open('xb') as stored:
        error_file=Path(file).with_suffix('.stderr.log').open('xb') if separate_stderr else None
        process=subprocess.Popen(argv,cwd=cwd,stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE if separate_stderr else subprocess.STDOUT)
        def drain(source,destination,console):
            while True:
                block=source.read(65536)
                if not block:break
                try:destination.write(block)
                except OSError:failed.append(True)
                try:console.buffer.write(block);console.buffer.flush()
                except (OSError,BrokenPipeError):failed.append(True)
            source.close()
            try:destination.flush();os.fsync(destination.fileno())
            except OSError:failed.append(True)
        stderr_thread=None
        if separate_stderr:
            stderr_thread=threading.Thread(target=drain,args=(process.stderr,error_file,sys.stderr))
            stderr_thread.start()
        drain(process.stdout,stored,sys.stdout)
        actual=process.wait()
        if stderr_thread:stderr_thread.join()
        if error_file:error_file.close()
    return actual,1 if failed else 0


def not_run_report(evidence,status,**fields):
    result=dict(schema='pluto.ordinary-go-ci.v1',status=status,ordinaryRuntime='NOT_RUN',
                fullOrdinaryCiGreen=False,archival=dict(test='TestStage3C03ActualHistoricalWriterRefusesV8',
                status='WAIVED_BY_OWNER',reason='ARCHIVAL_INPUT_UNAVAILABLE',runtime='NOT_RUN',
                historicalV8CompatibilityConfirmed=False,downgradeSafetyConfirmed=False),**fields)
    with (evidence/'report.json').open('x',encoding='utf-8') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps(result))


def failure(evidence,status,**fields):
    not_run_report(evidence,status,**fields)
    return 1


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-preflight-only",action="store_true",help="Prepare and verify every required native scope; ordinary runtime remains NOT_RUN")
    args=parser.parse_args(argv)
    os.umask(0o077)
    base=Path(os.environ.get('PLUTO_GO_CI_EVIDENCE_DIR',PROJECT/'.release-evidence/go-ci'))
    base.mkdir(parents=True,exist_ok=True)
    evidence=Path(tempfile.mkdtemp(prefix='ordinary-',dir=base))
    print('Ordinary Go CI evidence: '+str(evidence),flush=True)
    print('Archival C03: WAIVED_BY_OWNER / ARCHIVAL_INPUT_UNAVAILABLE; runtime NOT_RUN; old reader v8/downgrade UNCONFIRMED.',flush=True)
    discovery,captured=capture(['go','test','-list','.','-json','./...'],evidence/'inventory.jsonl',separate_stderr=True)
    if discovery or captured:return failure(evidence,'FAIL_DISCOVERY',actualDiscoveryExit=discovery,actualCaptureExit=captured)
    image=os.environ.get('PLUTO_GO_CI_C01_IMAGE')
    native_args=[]
    ordinary=['go','test','-race','-count=1','-json']
    if image:
        required={'source-inputs':'PLUTO_GO_CI_C01_SOURCE_INPUTS','test-binary':'PLUTO_GO_CI_C01_TEST_BINARY',
                  'cli':'STAGE3_PLUTO_BINARY','owner':'PLUTO_GO_CI_C01_OWNER','converter':'PLUTO_GO_CI_C01_CONVERTER'}
        missing=[value for value in required.values() if not os.environ.get(value)]
        syncstate=os.environ.get('PLUTO_GO_CI_SYNCSTATE_TEST_BINARY')
        if not syncstate:missing.append('PLUTO_GO_CI_SYNCSTATE_TEST_BINARY')
        binaries=os.environ.get('PLUTO_GO_CI_TEST_BINARIES')
        if not binaries and not args.native_preflight_only:missing.append('PLUTO_GO_CI_TEST_BINARIES')
        backend=os.environ.get('PLUTO_GO_CI_BULK_INPUTS');node=os.environ.get('PLUTO_GO_CI_NODE') or shutil.which('node')
        if not backend:missing.append('PLUTO_GO_CI_BULK_INPUTS')
        if not node:missing.append('PLUTO_GO_CI_NODE or node on PATH')
        if missing:return failure(evidence,'FAIL_NATIVE_PROVISIONING',missing=missing)
        if not Path(backend).is_absolute() or not Path(backend).is_file() or Path(backend).is_symlink():return failure(evidence,'FAIL_NATIVE_PROVISIONING',error='regular absolute backend cohort manifest required')
        common=['--image',image]
        for key,value in required.items():common+=['--'+key,os.environ[value]]
        for key,value in (('docker','PLUTO_GO_CI_DOCKER'),('docker-host','PLUTO_GO_CI_DOCKER_HOST')):
            if os.environ.get(value):common+=['--'+key,os.environ[value]]
        try:allowed=json.loads(os.environ.get('PLUTO_GO_CI_C01_ALLOWED_RUNNING_IDS','[]'))
        except ValueError:return failure(evidence,'FAIL_NATIVE_PROVISIONING',error='invalid running ID JSON inventory')
        if not isinstance(allowed,list) or not all(isinstance(value,str) for value in allowed):
            return failure(evidence,'FAIL_NATIVE_PROVISIONING',error='explicit allowed running ID array required')
        for value in allowed:common+=['--allow-running-id',value]
        scopes={}
        for label,case in NATIVE_SCOPES.items():
            output=evidence/label
            if case in API_CASES:
                case_common=list(common)
                if API_CASES[case]['package']=='pluto/internal/pluto/syncstate':case_common[case_common.index('--test-binary')+1]=syncstate
                producer=[node,str(PROJECT/'scripts/run-api-ci.mjs'),'--case',case,'--output',str(output),'--backend-inputs',backend,'--python',sys.executable,*case_common]
                if os.environ.get('PLUTO_GO_CI_BULK_PRIVATE_BASE'):producer+=['--private-base',os.environ['PLUTO_GO_CI_BULK_PRIVATE_BASE']]
            elif label=='bulk':
                producer=[node,str(PROJECT/'scripts/run-bulk-ci.mjs'),'--case',case,'--output',str(output),'--backend-inputs',backend,'--python',sys.executable,*common]
                if os.environ.get('PLUTO_GO_CI_BULK_PRIVATE_BASE'):producer+=['--private-base',os.environ['PLUTO_GO_CI_BULK_PRIVATE_BASE']]
            else:
                case_common=list(common)
                if case=='TestSmallBatchEngineActualCLIProcessesMixedAndLostReply':case_common[case_common.index('--test-binary')+1]=syncstate
                producer=[sys.executable,'-I','-B',str(PROJECT/'scripts/run-c01-ci.py'),
                          '--case',case,'--output',str(output),*case_common]
            actual,captured=capture(producer,evidence/(label+'-producer.log'))
            scopes[case]=dict(directory=str(output.resolve()),actualRunnerExit=actual,actualCaptureExit=captured)
            if actual or captured:
                return failure(evidence,'FAIL_NATIVE_PRODUCER',case=case,
                               actualNativeProducerExit=actual,actualNativeCaptureExit=captured,
                               completedNativeScopes=scopes)
        scope_file=evidence/'native-scopes.json'
        with scope_file.open('x',encoding='utf-8') as stream:
            json.dump(dict(schema='pluto.native-ci-scopes.v1',scopes=scopes),stream,indent=2)
            stream.write('\n');stream.flush();os.fsync(stream.fileno())
        native_args=['--native-shards',str(scope_file)]
        preflight=[sys.executable,'-I','-B',str(PROJECT/'scripts/check-go-ci.py'),
                   '--inventory',str(evidence/'inventory.jsonl'),'--validate-native-shards',
                   *native_args,'--report',str(evidence/'native-preflight.json')]
        actual,captured=capture(preflight,evidence/'native-preflight.log')
        if actual or captured:
            return failure(evidence,'FAIL_NATIVE_PREFLIGHT',actualPreflightExit=actual,actualPreflightCaptureExit=captured)
        selector='^('+'|'.join(NATIVE_SCOPES.values())+')$'
        print('All required native scopes passed actual producer/capture and receipt preflight; exact ordinary exclusion: '+selector,flush=True)
        ordinary+=['-skip',selector]
        if args.native_preflight_only:
            not_run_report(evidence,'PASS_REQUIRED_NATIVE_PREFLIGHT_ORDINARY_NOT_RUN',nativeScopes=scopes)
            return 0
        container_output=evidence/'container-scopes'
        driver=[sys.executable,'-I','-B',str(PROJECT/'scripts/run-container-go-ci.py'),
                '--output',str(container_output),'--inventory',str(evidence/'inventory.jsonl'),
                '--native-shards',str(scope_file),'--binaries',binaries,
                '--source-inputs',os.environ['PLUTO_GO_CI_C01_SOURCE_INPUTS'],
                '--converter',os.environ['PLUTO_GO_CI_C01_CONVERTER'],'--image',image,
                '--docker',os.environ.get('PLUTO_GO_CI_DOCKER','docker'),
                '--docker-host',os.environ.get('PLUTO_GO_CI_DOCKER_HOST','unix:///var/run/docker.sock')]
        for value in allowed:driver+=['--allow-running-id',value]
        actual,captured=capture(driver,evidence/'container-driver.log')
        try:
            result=json.loads((container_output/'report.json').read_bytes())
            if result.get('schema')!='pluto.container-ordinary-ci.v1' or not isinstance(result.get('errors'),list):raise ValueError('container accounting report required')
        except (OSError,ValueError) as error:
            result=dict(schema='pluto.container-ordinary-ci.v1',status='FAIL_INVALID_CONTAINER_CI_REPORT',
                        ordinaryRuntime='PARTIAL_OR_NOT_RUN',errors=[str(error)],fullOrdinaryCIGreen=False)
        result.update(actualContainerDriverExit=actual,actualContainerDriverCaptureExit=captured)
        if actual or captured or result['errors'] or not result.get('completeInventoryAccounted'):
            result.update(status='FAIL_REQUIRED_ORDINARY_GO_TEST_SUITE',fullOrdinaryCIGreen=False)
            result['errors']+=['ACTUAL_CONTAINER_DRIVER_OR_ACCOUNTING_FAILED']
        else:
            vet_exit,vet_capture=capture(['go','vet','./...'],evidence/'vet.log')
            result.update(actualVetExit=vet_exit,actualVetCaptureExit=vet_capture)
            if vet_exit or vet_capture:
                result.update(status='FAIL_REQUIRED_ORDINARY_GO_TEST_SUITE',fullOrdinaryCIGreen=False)
                result['errors']+=['ACTUAL_VET_OR_CAPTURE_FAILED']
        with (evidence/'report.json').open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
        print(json.dumps(result))
        return 1 if result['errors'] else 0
    elif args.native_preflight_only:
        return failure(evidence,'FAIL_NATIVE_PROVISIONING',missing=['PLUTO_GO_CI_C01_IMAGE'])
    go_exit,capture_exit=capture(ordinary+['./...'],evidence/'events.jsonl',separate_stderr=True)
    audit=[sys.executable,'-I','-B',str(PROJECT/'scripts/check-go-ci.py'),'--inventory',str(evidence/'inventory.jsonl'),
           '--events',str(evidence/'events.jsonl'),'--go-exit',str(go_exit),'--capture-exit',str(capture_exit),
           *native_args,'--report-source-bound-conditionals','--report',str(evidence/'report.json')]
    audit_exit,audit_capture=capture(audit,evidence/'report.log')
    if audit_exit or audit_capture or go_exit or capture_exit:return 1
    vet_exit,vet_capture=capture(['go','vet','./...'],evidence/'vet.log')
    return 0 if vet_exit==0 and vet_capture==0 else 1


if __name__=='__main__':raise SystemExit(main())
