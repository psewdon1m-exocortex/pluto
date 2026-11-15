"""Convert one reviewed, actually closed native scope with standard Go test2json."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess


CASES = ["TestStage3C01OrdinaryDaemonRestartBackupSemantics","TestCompletionDaemonProxyReopenRetainsDeletedSourceOriginal","TestCompletionDaemonRestartsAfterOwnedRouteLossWithoutFileEvent","TestCompletionNativeBulkReadbackPauseRestartNoCopies"]


def collect(retained, converter, converter_sha, source_file, case=CASES[0]):
    if case not in CASES: raise ValueError("unreviewed native case")
    root=Path(retained); evidence=root/'evidence'; actor=evidence/'a-000001'
    sha=lambda data:hashlib.sha256(data).hexdigest()
    prepared=json.loads((actor/'prepared-before-Start.json').read_bytes())
    if prepared.get('role')!='go-test' or prepared.get('args',[]).count('-test.run=^'+case+'$')!=1:
        raise ValueError('actual native case selector differs')
    raw=(actor/'stdout-prefix.log').read_bytes()
    if len(raw)>4*1024*1024:raise ValueError('bounded complete native output required')
    wait=json.loads((actor/'actual-wait.json').read_bytes())
    joined=json.loads((actor/'joined-streams.json').read_bytes())
    final=json.loads((evidence/'owner-final.json').read_bytes())
    if (wait['ExitCode']!=0 or not wait['Exited'] or wait['Signaled'] or joined['result']['Actual']!=wait or
        not joined['result']['NumericDurable'] or not joined['result']['DrainsJoined'] or
        final['go_actual']!=wait or not final['all_products_joined'] or not final['no_adopted_children']):
        raise ValueError('actual successful closed native native scope required')
    if sha(raw)!=joined['stdout_full_sha256'] or len(raw)!=joined['stdout_total_bytes']:
        raise ValueError('complete actual native stdout digest differs')
    converter=Path(converter)
    if sha(converter.read_bytes())!=converter_sha:raise ValueError('qualified converter SHA differs')
    converted=subprocess.run([str(converter),'-t','-p','pluto/internal/pluto'],input=raw,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
    if converted.returncode!=0 or converted.stderr or len(converted.stdout)>4*1024*1024:
        raise ValueError('standard Go test2json conversion failed')
    files={'events.jsonl':converted.stdout,'stdout.log':raw,
           'actual-wait.json':(actor/'actual-wait.json').read_bytes(),
           'joined-streams.json':(actor/'joined-streams.json').read_bytes(),
           'prepared-before-Start.json':(actor/'prepared-before-Start.json').read_bytes(),
           'observed-after-exec.json':(actor/'observed-after-exec.json').read_bytes(),
           'owner-final.json':(evidence/'owner-final.json').read_bytes(),
           'source-inputs.json':Path(source_file).read_bytes()}
    return dict(schema='pluto.native-ci-export.v1',case=case,converterActualExit=converted.returncode,actualGoWait=wait,
                files={name:dict(bytes=len(body),sha256=sha(body),base64=base64.b64encode(body).decode()) for name,body in files.items()})


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case',choices=CASES,default=CASES[0])
    parser.add_argument('--retained',required=True)
    parser.add_argument('--converter',required=True)
    parser.add_argument('--converter-sha',required=True)
    parser.add_argument('--source-inputs',required=True)
    args=parser.parse_args()
    print(json.dumps(collect(args.retained,args.converter,args.converter_sha,args.source_inputs,args.case),separators=(',',':')))


if __name__=='__main__':main()
