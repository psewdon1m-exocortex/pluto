import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {runContainer} from '../bulk/container.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const read=async p=>JSON.parse(await fs.readFile(p,'utf8'));
async function write(p,value){const f=await fs.open(p,'wx',0o600);try{await f.writeFile(JSON.stringify(value,null,2)+'\n');await f.sync();}finally{await f.close();}}
export async function collectApiEvidence(spec,outcome){
 const result=outcome.report,owner=outcome.ownerInstance;
 assert.equal(result.case,spec.case);assert.equal(result.status,'PASS_REQUIRED_NATIVE_API_RUNTIME');
 for(const actor of [...owner.objects].reverse().filter(x=>x.kind==='container'&&!x.removed))owner.stop(actor.name,15000);
 for(const actor of owner.objects.filter(x=>x.kind==='container'&&!x.removed)){const actual=owner.checked('container',actor.name).observed;assert(!actual.State.Running&&!actual.State.OOMKilled&&actual.State.ExitCode===0,'all original API actors must really join0 before collection');}
 const collect=await runContainer(owner,{name:spec.id+'-api-export',image:spec.goImage,card:spec.id,user:'10001:10001',memoryMiB:128,cpus:1,pids:32,mounts:[{volume:result.native.volume,target:'/retained'},{bind:spec.pins.exporter.path,target:'/export.py'},{bind:spec.pins.converter.path,target:'/converter'},{bind:spec.pins.casePolicy.path,target:'/api-case-policy.json'},{bind:spec.boundSourcePath,target:'/source-inputs.json'}],entrypoint:'python3',command:['-I','-B','/export.py','--retained','/retained/endurance-api-current','--converter','/converter','--converter-sha',spec.pins.converter.sha256,'--source-inputs','/source-inputs.json','--case',spec.case]});
 const packet=JSON.parse(collect.stdout);assert.equal(packet.schema,'pluto.native-ci-export.v1');assert.equal(packet.case,spec.case);assert.equal(packet.converterActualExit,0);
 const names=['events.jsonl','stdout.log','actual-wait.json','joined-streams.json','prepared-before-Start.json','observed-after-exec.json','owner-final.json','source-inputs.json'];assert.deepEqual(Object.keys(packet.files).sort(),[...names].sort());
 for(const name of names){const meta=packet.files[name],body=Buffer.from(meta.base64,'base64');assert.equal(body.toString('base64'),meta.base64);assert(body.length<=4194304);assert.equal(body.length,meta.bytes);assert.equal(sha(body),meta.sha256);const dest=path.join(spec.output,name);if(name==='source-inputs.json')assert.equal(sha(await fs.readFile(dest)),sha(body));else await fs.writeFile(dest,body,{flag:'wx',mode:0o600});}
 const actual=JSON.parse(Buffer.from(packet.files['actual-wait.json'].base64,'base64'));assert.deepEqual(actual,packet.actualGoWait);assert(actual.Observed&&actual.Exited&&!actual.Signaled&&actual.ExitCode===0&&actual.RawStatus===0);
 const imageRaw=await fs.readFile(result.backendImage.path);await fs.writeFile(path.join(spec.output,'api-backend-image.json'),imageRaw,{flag:'wx',mode:0o600});
 const containers=[];for(const obj of owner.objects.filter(x=>x.kind==='container'&&!x.removed)){const c=owner.checked('container',obj.name).observed;assert(!c.State.Running&&!c.State.OOMKilled&&c.State.ExitCode===0);containers.push({name:obj.name,id:c.Id,created:c.Created,image:c.Image,actualExitCode:c.State.ExitCode,oomKilled:c.State.OOMKilled,running:c.State.Running,networkMode:c.HostConfig.NetworkMode,publishedPorts:c.HostConfig.PortBindings??{}});}
 const backendImage=JSON.parse(imageRaw);const proof={schema:'pluto.native-api-ci-proof.v1',case:spec.case,status:'PASS_ORIGINAL_CASE_GENUINE_API_PG_SFTP_TYPED_LIFECYCLE',testBinarySHA256:spec.pins.nativeTest.sha256,actualGoWait:actual,containerClosure:null,images:{native:spec.goImage,saturn:spec.saturnImage,postgres:spec.pgImage,sftp:spec.sftpImage},sourceCohortSHA256:spec.backendInputs.sourceCohortSHA256,backendImageSHA256:sha(imageRaw),containers,apiReady:result.apiReady,privateRetainedState:outcome.privateRoot,fullOrdinaryCiGreen:false,processCrashFaults:0,independentFullGraphRestoreClaimed:false};
 assert.equal(backendImage.image,spec.saturnImage);assert.equal(backendImage.files,612);assert.equal(backendImage.sourceCohortSHA256,proof.sourceCohortSHA256);await write(path.join(spec.output,'api-evidence-draft.json'),proof);
}

export async function publishApiEvidence(spec,outcome){
 assert.equal(outcome.report.status,'PASS_REQUIRED_NATIVE_API_RUNTIME');assert.equal(outcome.report.closure.status,'STOPPED_RETAINED');
 const proof=await read(path.join(spec.output,'api-evidence-draft.json'));assert.equal(proof.case,spec.case);assert.equal(proof.containerClosure,null);
 for(const actor of outcome.ownerInstance.objects.filter(x=>x.kind==='container'&&!x.removed)){const c=outcome.ownerInstance.checked('container',actor.name).observed;assert(!c.State.Running&&!c.State.OOMKilled&&c.State.ExitCode===0);}
 proof.containerClosure=outcome.report.closure;await write(path.join(spec.output,'api-evidence.json'),proof);
}
