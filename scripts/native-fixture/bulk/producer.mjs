import assert from 'node:assert/strict';
import {checkpointBridge} from './checkpoint-bridge.mjs';
import {qualifyBackendImage} from './verify-backend.mjs';
import {finishBulk} from './finish.mjs';
import {runCommand} from './stage13-command.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {createHash,randomBytes} from 'node:crypto';
import {createIsolation,OwnedDocker} from './stage13-runtime.mjs';

export function assertOnlyRunningContainerIds(output,expected){
  const ids=output.trim().split(/\r?\n/).filter(Boolean);
  for(const id of ids)assert.match(id,/^[a-f0-9]{64}$/,'Docker must return complete container IDs');
  assert.deepEqual(ids.sort(),[...expected].sort());
}

class OwnedLoopbackDocker extends OwnedDocker {
  checked(kind,name){
    if(kind!=='network'||!this.loopbackPeer||name!=='container:'+this.loopbackPeer)return super.checked(kind,name);
    const peer=super.checked('container',this.loopbackPeer);
    const c=peer.observed;
    assert.ok(c.State.Running&&!c.State.Paused&&c.HostConfig.NetworkMode==='none');
    assert.equal(Object.keys(c.HostConfig.PortBindings??{}).length,0);
    assert.ok(Object.values(c.NetworkSettings.Ports??{}).every(x=>!x||x.length===0));
    return peer;
  }
}

export async function runBulk(spec){
const run=spec.output;const read=async p=>JSON.parse(await fs.readFile(p,'utf8'));const sha=b=>createHash('sha256').update(b).digest('hex');const pin=async p=>{const b=await fs.readFile(p);return {path:p,bytes:b.length,sha256:sha(b)};};const save=async(p,v,mode=0o600)=>{const f=await fs.open(p,'wx',0o600);try{await f.writeFile(v);await f.chmod(mode);await f.sync();}finally{await f.close();}};
for(const p of [...Object.values(spec.pins),...spec.inspectShim,...spec.loopbackOverlay])assert.deepEqual(await pin(p.path),p);
const iso=spec.isolation,owner=new OwnedLoopbackDocker({...iso,cwd:spec.project,docker:spec.docker,expectedEngineId:spec.engine});owner.budgets.wallClockMs=4500000;owner.budgets.stopJoinMs=15000;
const suffix='stand-'+randomBytes(5).toString('hex');
const name=role=>iso.namespace+'-'+suffix+'-'+role;
const pg=name('pg'),api=name('api'),pluto=name('pluto'),volume=name('pgdata'),handoff=name('private-handoff'),seeder=name('handoff-owner'),nativeVolume=name('native-state'),sftp=name('sftp'),sftpHome=name('sftp-home'),sftpData=name('sftp-data');
const checkpointVolume=name('checkpoint');
const labels=['--label','exocortex.ci.scope='+spec.id,'--label','exocortex.ci.case=TestCompletionNativeBulkReadbackPauseRestartNoCopies','--label','exocortex.sync-performance.run='+spec.id];
const common=['--pids-limit','128','--security-opt','no-new-privileges','--cap-drop','ALL'];
const bind=(file,target,mode='ro')=>file+':'+target+':'+mode;
const state=(n)=>owner.checked('container',n).observed;
const report={schema_version:1,at:new Date().toISOString(),scope:'Â§3.1.6/Â§6.4â€“5 original native bulk32/Tier8 lostACK16 with genuine full current PG/SFTP/profile/authority backuprestore and exact original native wait/readback',status:'FAIL',owner:owner.manifestPath};
const delay=ms=>new Promise(r=>setTimeout(r,ms));
let readyMarker, apiStop, started=false, testStarted=false, testFinished=false, goLog, apiLog;
async function until(limit,probe,interval=200){
  const end=Date.now()+limit;
  do {
    const found=await probe();
    if(found)return found;
    assert.ok(os.freemem()>=8*1024**3,'bulk CI reserve admission closed');
    await delay(interval);
  }while(Date.now()<end);
  throw new Error('bulk CI bounded observation deadline');
}
function runningOnly(expected){
  assertOnlyRunningContainerIds(owner.cli(['ps','--no-trunc','--format','{{.ID}}']).stdout,expected);
}
try{
  runningOnly(spec.allowedRunning);
  report.backendImage=await qualifyBackendImage(owner,spec);
  const root=iso.root, controls=path.join(root,'completion'), fixtures=path.join(root,'fixture-out'), shim=path.join(root,'input'), inspection=path.join(root,'inspection');
  await Promise.all([controls,fixtures,shim,inspection].map(p=>fs.mkdir(p)));
  await Promise.all(['fixtures','stage3'].map(p=>fs.mkdir(path.join(fixtures,p))));
  for(const [index,p]of spec.inspectShim.entries())await fs.copyFile(p.path,path.join(shim,['docker','inspect-client.mjs'][index]));
  const password=randomBytes(32).toString('hex'), nonce=randomBytes(32).toString('hex');
  const secret=path.join(root,'pg-password');
  await save(secret,password+'\n');
  apiStop=path.join(controls,'api-stop');readyMarker=path.join(controls,'api-ready.json');
  const gate=path.join(root,'anchor-gate');
  await fs.mkdir(gate,{mode:0o700});await fs.chmod(gate,0o755);
  owner.resource('volume',handoff,labels);
  owner.resource('volume',nativeVolume,labels);
  owner.resource('volume',checkpointVolume,labels);
  const approvalDirectory=path.join(root,'root-control');await fs.mkdir(approvalDirectory,{mode:0o700});await fs.chmod(approvalDirectory,0o755);
  const checkpointToken=path.join(root,'checkpoint-token');await save(checkpointToken,randomBytes(32).toString('hex')+'\n');
  const nativeMounts=[
    [nativeVolume,'/retained','rw'],[handoff,'/handoff','ro'],[gate,'/input-gate','ro'],
    [spec.pins.nativeTest.path,'/test-input','ro'],[spec.pins.nativeCli.path,'/cli-input','ro'],
    [spec.pins.nativeOwner.path,'/owner-input','ro'],[spec.pins.nativeEntry.path,'/bulk-entry.sh','ro'],
    [spec.pins.nativeManifestWriter.path,'/bulk-manifest-writer.py','ro'],
    [spec.pins.nativeRootControl.path,'/bulk-root-control.py','ro'],
    [checkpointVolume,'/checkpoint','rw'],[approvalDirectory,'/root-control','ro'],
  ];
  const nativeArgs=['--name',pluto,...labels,'--label','exocortex.stage13.namespace='+iso.namespace,
    ...common,'--network','none','--pull=never','--platform','linux/amd64',
    '--memory','2048m','--memory-swap=2048m','--cpus','2','--tmpfs','/tmp:rw,nosuid,nodev,size=96m',
    ...['SETGID','SETPCAP','SETUID'].flatMap(cap=>['--cap-add',cap]),'--user','0:0',
    ...nativeMounts.flatMap(([source,target,mode])=>['-v',bind(source,target,mode)]),
    '--entrypoint','/bin/sh',owner.image(spec.goImage),'/bulk-entry.sh',
    spec.pins.nativeOwner.sha256,spec.pins.nativeTest.sha256,spec.pins.nativeCli.sha256,spec.id,'native-bulk-ci'];
  assert.ok(!owner.lookup('container',pluto));
  owner.validateMounts(nativeArgs);
  const cid=owner.cli(['create',...nativeArgs]).stdout.trim();
  assert.match(cid,/^[a-f0-9]{64}$/);
  owner.record('container',pluto,owner.inspect('container',cid));
  const test=state(pluto);
  const host=test.HostConfig;
  assert.equal(test.Id,cid);assert.equal(test.State.Status,'created');
  assert.equal(test.Image,spec.goImage);assert.equal(test.Config.Hostname,cid.slice(0,12));
  assert.equal(test.Config.User,'0:0');assert.equal(test.Config.OpenStdin,false);
  assert.equal(host.NetworkMode,'none');
  assert.equal(host.Memory,2147483648);assert.equal(host.MemorySwap,host.Memory);
  assert.equal(host.NanoCpus,2e9);assert.equal(host.PidsLimit,128);
  assert.equal(host.Privileged,false);assert.equal(host.AutoRemove,false);
  assert.deepEqual(host.CapDrop.map(c=>c.replace(/^CAP_/,'')),['ALL']);
  assert.deepEqual(host.CapAdd.map(c=>c.replace(/^CAP_/,'' )).sort(),['SETGID','SETPCAP','SETUID']);
  assert.ok(host.SecurityOpt.some(v=>/^no-new-privileges(?::true|=true)?$/.test(v)));
  assert.deepEqual(host.Tmpfs,{'/tmp':'rw,nosuid,nodev,size=96m'});
  assert.equal(Object.keys(host.PortBindings??{}).length,0);
  assert.equal(test.Mounts.length,nativeMounts.length);
  for(const [source,target,mode] of nativeMounts){
    const observed=test.Mounts.find(m=>m.Destination===target);
    assert.ok(observed&&observed.RW===(mode==='rw'));
    if(['/retained','/handoff','/checkpoint'].includes(target)){assert.equal(observed.Name,source);owner.checked('volume',source);}
    else assert.equal(observed.Type,'bind');
  }
  await save(path.join(gate,'cid'),cid+String.fromCharCode(10),0o444);
  const boot=owner.run(['start',pluto]);
  started=true;
  await until(12000,()=>{const p=state(pluto);return p.State.Running&&owner.run(['logs',pluto]).stdout.includes('BULK_WAITING_FOR_HANDOFF');});
  const anchor=state(pluto);
  assert.equal(anchor.Config.Hostname,cid.slice(0,12));
  owner.loopbackPeer=cid;
  const anchorNet=owner.run(['exec',pluto,'readlink','/proc/self/ns/net']).stdout.trim();
  assert.match(anchorNet,/^net:\[\d+\]$/);
  owner.resource('volume',volume,labels);
  owner.run(['run','-d','--name',pg,...labels,...common,'--network','container:'+cid,'--cpus','1','--memory','512m','--memory-swap=512m',
    '--read-only',...['CHOWN','DAC_OVERRIDE','FOWNER','SETGID','SETUID'].flatMap(x=>['--cap-add',x]),'--tmpfs','/tmp:rw,noexec,nosuid,size=32m,mode=1777',
    '--tmpfs','/run/postgresql:rw,noexec,nosuid,size=16m','-e','POSTGRES_USER=postgres','-e','POSTGRES_DB=postgres','-e','POSTGRES_PASSWORD_FILE=/password',
    '-e','POSTGRES_INITDB_ARGS=--auth-local=trust --auth-host=scram-sha-256','-v',bind(spec.pins.sqlCapture.path,'/input/capture.sql'),'-v',bind(secret,'/password'),'-v',bind(volume,'/var/lib/postgresql','rw'),spec.pgImage,'postgres','-c','listen_addresses=127.0.0.1']);
  started=true;
  await until(30000,()=>owner.run(['exec',pg,'pg_isready','-q','-h','127.0.0.1','-U','postgres'],process.env,true).status===0);
  const pc=state(pg);
  assert.equal(pc.HostConfig.NetworkMode,'container:'+cid);
  assert.ok(Object.values(pc.NetworkSettings.Ports??{}).every(x=>!x||x.length===0));
  assert.equal(Object.keys(pc.HostConfig.PortBindings??{}).length,0);
  assert.equal(owner.run(['exec',pg,'readlink','/proc/self/ns/net']).stdout.trim(),anchorNet);
  assert.equal(pc.HostConfig.Memory,536870912);
  assert.equal(pc.HostConfig.NanoCpus,1e9);
  assert.equal(pc.HostConfig.MemorySwap,536870912);
  const fixture=path.join(root,'pg.private.json');
  await save(fixture,JSON.stringify({containerId:pc.Id,runId:spec.id,created:pc.Created,databaseUrl:'postgresql://postgres:'+password+'@127.0.0.1:5432/postgres',
    fixtureDirectory:'/fixture-out/fixtures',endpointMode:'owned-shared-loopback',networkAnchorCID:cid,resourceBudget:{nanoCpus:1e9,memoryBytes:536870912}}));

  const ssh=path.join(root,'ssh');await fs.mkdir(ssh,{mode:0o700});
  const hostKey=path.join(ssh,'host-key'),clientKey=path.join(ssh,'client-key');
  const keygen=args=>{
    const r=runCommand(spec.pins.keygen.path,args,{root,cwd:run,env:process.env,encoding:'utf8',timeout:15000});
    if(r.status===null||r.error){owner.pending=true;owner.persist();throw Error('SFTP key actor pending');}
    assert.equal(r.status,0);assert.equal(r.signal,null);return r.stdout.trim();
  };
  for(const [file,kind] of [[hostKey,'host'],[clientKey,'client']])keygen(['-q','-t','ed25519','-N','','-C','bulk-ci-'+kind,'-f',file]);
  const fingerprint=keygen(['-l','-E','sha256','-f',hostKey+'.pub']).split(/\s+/)[1];
  assert.match(fingerprint,/^SHA256:[A-Za-z0-9+/]{43}$/);
  const users=path.join(ssh,'users.conf');await save(users,'vault::1001:1001:gateway\n');
  owner.resource('volume',sftpHome,labels);owner.resource('volume',sftpData,labels);
  owner.run(['run','-d','--name',sftp,...labels,'--label','exocortex.endurance.run='+spec.id,
    '--label','com.docker.compose.service=sftp','--network','container:'+cid,
    '--cpus','1','--memory','192m','--memory-swap=192m','--pids-limit','128','--security-opt','no-new-privileges',
    '--entrypoint','/bin/sh','-v',bind(spec.pins.sftpEntrypoint.path,'/bootstrap/entrypoint.sh'),
    '-v',bind(users,'/etc/sftp/users.conf'),'-v',bind(hostKey,'/hostkeys/ssh_host_ed25519_key'),
    '-v',bind(clientKey+'.pub','/home/vault/.ssh/keys/dev_client_ed25519.pub'),
    '-v',bind(sftpHome,'/home','rw'),'-v',bind(sftpData,'/home/vault/gateway','rw'),spec.sftpImage,'/bootstrap/entrypoint.sh']);
  await until(12000,()=>owner.run(['exec',sftp,'pgrep','sshd'],process.env,true).status===0);
  const sc=state(sftp);
  assert.equal(sc.Image,spec.sftpImage);assert.equal(sc.HostConfig.NetworkMode,'container:'+cid);
  assert.equal(sc.HostConfig.Memory,201326592);assert.equal(sc.HostConfig.MemorySwap,sc.HostConfig.Memory);
  assert.equal(sc.HostConfig.Privileged,false);assert.equal(Object.keys(sc.HostConfig.PortBindings??{}).length,0);
  assert.ok(Object.values(sc.NetworkSettings.Ports??{}).every(ports=>!ports||ports.length===0));
  assert.ok(sc.Mounts.some(m=>m.Type==='volume'&&m.Name===sftpData&&m.Destination==='/home/vault/gateway'&&m.RW));
  assert.equal(owner.run(['exec',sftp,'readlink','/proc/self/ns/net']).stdout.trim(),anchorNet);
  assert.equal(owner.run(['exec',sftp,'stat','-c','%u:%g','/home/vault/gateway']).stdout.trim(),'1001:1001');
  assert.equal(owner.run(['exec',sftp,'find','/home/vault/gateway','-mindepth','1']).stdout.trim(),'');
  const prefix='acceptance-'+randomBytes(16).toString('hex');
  const secrets=path.join(root,'sftp-secrets');
  await fs.mkdir(secrets,{mode:0o700});
  const secretPaths={};
  for(const [name,variable] of [['owner','OWNER_BOOTSTRAP_TOKEN_FILE'],['auth','AUTH_PEPPER_FILE'],['drop','DROP_PEPPER_FILE'],['share','SHARE_PEPPER_FILE'],['device','DEVICE_PEPPER_FILE'],['backup','BACKUP_PEPPER_FILE']]){
    await save(path.join(secrets,name),randomBytes(32).toString('hex')+'\n');
    secretPaths[variable]='/run/sftp-secrets/'+name;
  }
  const backendEnv=path.join(ssh,'sftp-env.private.json'),backendManifest=path.join(ssh,'sftp.private.json');
  await save(backendEnv,JSON.stringify({NODE_ENV:'test',DATABASE_URL:(await read(fixture)).databaseUrl,
    ...secretPaths,STORAGE_BACKEND:'sftp',STORAGE_HOST:'127.0.0.1',
    STORAGE_PORT:'22',STORAGE_USER:'vault',STORAGE_ROOT:'gateway',STORAGE_HOST_FINGERPRINT:fingerprint,
    STORAGE_AUTH_MODE:'private_key_file',STORAGE_PRIVATE_KEY_FILE:'/run/sftp-client-key',
    STORAGE_OPERATION_TIMEOUT_MS:'30000',STORAGE_HEALTH_TIMEOUT_MS:'2000',STORAGE_MAX_CONNECTIONS:'4',STORAGE_REQUIRE_FSYNC:'true'}));
  await save(backendManifest,JSON.stringify({containerId:sc.Id,created:sc.Created,runId:spec.id,prefix,networkAnchorCID:cid,environmentFile:'/run/sftp-env.private.json'}));
  const projectedSftp={Id:sc.Id,Created:sc.Created,Image:sc.Image,Config:{Labels:sc.Config.Labels},State:{Running:true,Paused:false},
    HostConfig:{NanoCpus:sc.HostConfig.NanoCpus,Memory:sc.HostConfig.Memory,NetworkMode:sc.HostConfig.NetworkMode},NetworkSettings:{Ports:sc.NetworkSettings.Ports??{}}};
  const sftpInspect=path.join(shim,'sftp.inspect.json');await save(sftpInspect,JSON.stringify({nonce,data:[projectedSftp]}));
  report.sftp={id:sc.Id,created:sc.Created,image:sc.Image,networkMode:sc.HostConfig.NetworkMode,networkNamespace:anchorNet,dataVolume:sftpData,hostFingerprint:fingerprint,inspection:await pin(sftpInspect)};

  const apiCommand=[
    'set -eu','umask 077',
    'test "$(sha256sum /workspace/apps/api/src/completion-clients.integration.test.ts | cut -d \' \' -f 1)" = "$PLUTO_BULK_API_SHA" || { echo "bulk API fixture source hash differs" >&2; exit 72; }',
    'test -f /workspace/scripts/sync-lifecycle.mts && test -f /workspace/scripts/stage13-command.mjs',
    'mkdir -m 0700 /tmp/bulk-ci-tools','cp /input/docker /tmp/bulk-ci-tools/docker','chmod 0500 /tmp/bulk-ci-tools/docker',
    'export PATH=/tmp/bulk-ci-tools:$PATH','cd /workspace/apps/api',
    'exec node node_modules/vitest/vitest.mjs run src/completion-clients.integration.test.ts --pool=threads --maxWorkers=1 --no-file-parallelism --bail=1 --configLoader runner --cache=false --reporter=json --outputFile=/fixture-out/vitest.json'
  ].join('\n');
  owner.run(['run','-d','--name',api,...labels,...common,'--user',spec.hostUID+':'+spec.hostGID,'--network','container:'+cid,'--cpus','2','--memory','2048m','--memory-swap=2048m',
    '--entrypoint','/bin/sh','-e','CI=true','-e','COREPACK_ENABLE_NETWORK=0','-e','NODE_OPTIONS=--max-old-space-size=384',
    '-e','QUALITY_SFTP_ID='+sc.Id,'-e','COMPLETION_SHARED_BACKEND=/run/sftp.private.json',
    '-v',bind(backendManifest,'/run/sftp.private.json'),'-v',bind(backendEnv,'/run/sftp-env.private.json'),'-v',bind(clientKey,'/run/sftp-client-key'),'-v',bind(secrets,'/run/sftp-secrets'),
    '-v',bind(spec.pins.sharedBackend.path,'/workspace/apps/api/src/completion-shared-backend.fixture.ts'),'-v',bind(spec.pins.adoptionFixture.path,'/workspace/apps/api/src/completion-adoption.fixture.ts'),'-v',bind(spec.pins.resumeFixture.path,'/workspace/apps/api/src/completion-resume.fixture.ts'),
    '-e','QUALITY_PG_ID='+pc.Id,'-e','QUALITY_INSPECT_NONCE='+nonce,'-e','PLUTO_BULK_API_SHA='+spec.pins.controlOverlay.sha256,
    '-e','STAGE3_CHAT_A_FIXTURE=/run/saturn-pg.private.json','-e','STAGE3_CHAT_A_EVIDENCE=/fixture-out/stage3',
    '-e','COMPLETION_EVIDENCE=/completion','-e','ENDURANCE_SERVER_TIMEOUT_MS=4500000','-e','BULK_CURRENT_MIGRATION_CUTOFF=131','-e','BULK_CHECKPOINT_TOKEN_FILE=/run/checkpoint-token','-v',bind(checkpointToken,'/run/checkpoint-token'),'-v',bind(spec.pins.checkpointTS.path,'/workspace/apps/api/src/completion-bulk-checkpoint.fixture.ts'),'-e','ENDURANCE_TIER=8','-v',bind(shim,'/input'),
    '-v',bind(inspection,'/inspection','rw'),'-v',bind(controls,'/completion','rw'),'-v',bind(fixtures,'/fixture-out','rw'),
    '-v',bind(fixture,'/run/saturn-pg.private.json'),'-v',bind(spec.loopbackOverlay[0].path,'/workspace/apps/api/src/stage3-chat-a.fixture.ts'),
    '-v',bind(spec.loopbackOverlay[1].path,'/workspace/apps/api/src/docker-container.fixture.ts'),
    '-v',bind(spec.pins.controlOverlay.path,'/workspace/apps/api/src/completion-clients.integration.test.ts'),
    '-v',bind(spec.pins.operatorLifecycle.path,'/workspace/scripts/sync-lifecycle.mts'),
    '-v',bind(spec.pins.commandSupervisor.path,'/workspace/scripts/stage13-command.mjs'),spec.saturnImage,'-ec',apiCommand]);
  const ac=state(api);
  assert.equal(ac.HostConfig.NetworkMode,'container:'+cid);
  assert.equal(owner.run(['exec',api,'readlink','/proc/self/ns/net']).stdout.trim(),anchorNet);
  assert.equal(ac.HostConfig.MemorySwap,2147483648);
  const request=path.join(inspection,'request.json'), response=path.join(inspection,'response.json');
  let answered=false;
  await until(180000,async()=>{
    assert.ok(state(api).State.Running,'Saturn fixture exited before readiness');
    if(!answered){
      const req=await fs.lstat(request).catch(e=>e.code==='ENOENT'?null:Promise.reject(e));
      if(req){
        assert.ok(req.isFile()&&!req.isSymbolicLink()&&req.size<256);
        assert.deepEqual(await read(request),{nonce,cid:pc.Id});
        const c=state(pg);assert.equal(c.Created,pc.Created);assert.ok(c.State.Running);
        const projected={Id:c.Id,Created:c.Created,Image:c.Image,Config:{Labels:c.Config.Labels},State:{Running:true,Paused:c.State.Paused},
          HostConfig:{NanoCpus:c.HostConfig.NanoCpus,Memory:c.HostConfig.Memory,NetworkMode:c.HostConfig.NetworkMode},NetworkSettings:{Ports:c.NetworkSettings.Ports??{}}};
        await save(response+'.tmp',JSON.stringify({nonce,data:[projected]}));await fs.rename(response+'.tmp',response);
        report.inspectFromActualDocker=true;answered=true;
      }
    }
    return answered&&await fs.stat(readyMarker).then(x=>x.isFile(),()=>false);
  });
  const ready=await read(readyMarker);
  const config=path.join(controls,'clients.private.json');
  const configs=await read(config);
  assert.equal(configs.length,2);assert.deepEqual(configs.map(x=>x.kind),['windows','pluto']);
  assert.deepEqual(configs.map(x=>x.binding.root_id),ready.roots);
  assert.ok(configs.every(x=>x.origin==='http://127.0.0.1:'+ready.frontPort+'/'&&x.faultOrigin==='http://127.0.0.1:'+ready.middlePort+'/'));
  assert.equal(state(pluto).Config.Hostname,cid.slice(0,12));
  assert.equal(state(pluto).HostConfig.NetworkMode,'none');
  runningOnly([...spec.allowedRunning,cid,pc.Id,ac.Id,sc.Id]);
  testStarted=true;
  const seedConfig=owner.run(['run','--name',seeder,...labels,...common,'--network','none','--memory','64m','--cpus','0.25',
    '--read-only','--cap-add','CHOWN','--cap-add','DAC_OVERRIDE','--entrypoint','/bin/sh',
    '-v',bind(config,'/client-config'),'-v',bind(checkpointToken,'/checkpoint-token'),'-v',bind(handoff,'/handoff','rw'),spec.goImage,'-ec',
    'umask 077; mkdir -m 0700 /handoff/client; mkdir -m 0700 /handoff/client/tmp; cp /client-config /handoff/client/clients.private.json; cp /checkpoint-token /handoff/client/checkpoint-token; chmod 0600 /handoff/client/clients.private.json /handoff/client/checkpoint-token; chown 10001:10001 /handoff/client/clients.private.json /handoff/client/checkpoint-token /handoff/client/tmp /handoff/client']);
  assert.equal(seedConfig.status,0);
  report.apiReady={roots:ready.roots,postgres:pc.Id,networkMode:ac.HostConfig.NetworkMode,loopbackOnly:true,apiImage:ac.Image,anchor:cid,networkNamespace:anchorNet};
  const authorityInput=path.join(root,'authority-input');await fs.mkdir(authorityInput,{mode:0o700});
  const authorityProvenance=[];
  async function copyInput(source,target){const info=await fs.lstat(source);assert(!info.isSymbolicLink());if(info.isDirectory()){await fs.mkdir(target,{mode:0o700});for(const leaf of (await fs.readdir(source)).sort())await copyInput(path.join(source,leaf),path.join(target,leaf));}else{assert(info.isFile()&&info.size<=1048576);const raw=await fs.readFile(source);await save(target,raw);assert.equal(sha(await fs.readFile(source)),sha(raw));authorityProvenance.push({source,target,bytes:raw.length,sha256:sha(raw)});}}
  await copyInput(ssh,path.join(authorityInput,'ssh'));await copyInput(secrets,path.join(authorityInput,'sftp-secrets'));await copyInput(secret,path.join(authorityInput,'postgres-password'));await copyInput(fixture,path.join(authorityInput,'pg.private.json'));await copyInput(config,path.join(authorityInput,'clients.private.json'));await copyInput(checkpointToken,path.join(authorityInput,'checkpoint-token'));
  const migrations=await read(spec.pins.migrations.path);assert.equal(migrations.upMigrations,122);assert.equal(migrations.cutoff,131);const migrationNames=migrations.files.filter(x=>x.name.endsWith('.up.sql')).map(x=>x.name.replace(/\.up\.sql$/,'')).sort();
  let bridge,handled=false,stopped;const end=Date.now()+3900000;
  for(;;){
    if(!handled&&await fs.stat(path.join(controls,'bulk-checkpoint-request.json')).then(i=>i.isFile(),()=>false)){
      handled=true;
      bridge=await checkpointBridge({owner,spec,name,controls,fixtures,approvalDirectory,authorityInput,authorityProvenance,configs,databaseUrl:(await read(fixture)).databaseUrl,migrationNames,nativeName:pluto,nativeVolume,pgName:pg,pgVolume:volume,sftpName:sftp,sftpDataVolume:sftpData,checkpointVolume,labels});report.checkpoint=bridge;
    }
    const observed=state(pluto);if(!observed.State.Running){stopped=observed;break;}
    if(Date.now()>=end){owner.pending=true;owner.persist();throw Error('native bulk observation elapsed; actor retained without kill');}
    assert(os.freemem()>=8*1024**3,'8GiB free RAM reserve');await delay(300);
  }
  testFinished=true;assert.equal(stopped.State.ExitCode,0);assert.equal(stopped.State.OOMKilled,false);assert(handled&&bridge);
  const log=owner.run(['logs',pluto]);goLog=path.join(root,'pluto-bulk-race.log');await save(goLog,log.stdout+'\n'+log.stderr);report.goLog=await pin(goLog);report.native={id:cid,actualContainerExit:stopped.State.ExitCode,volume:nativeVolume,checkpointVolume};
  assert(log.stdout.includes('--- PASS: TestCompletionNativeBulkReadbackPauseRestartNoCopies'));assert(!log.stdout.includes('--- SKIP:'));
  const complete=await read(path.join(controls,'bulk-checkpoint-complete.json'));assert(complete.originalBackendResumed);report.checkpointComplete=await pin(path.join(controls,'bulk-checkpoint-complete.json'));
  await save(apiStop,'owned cooperative completion\n');const apiJoined=await until(30000,()=>!state(api).State.Running&&state(api));assert.equal(apiJoined.State.ExitCode,0);assert.equal(apiJoined.State.OOMKilled,false);report.apiExit=apiJoined.State.ExitCode;report.apiReport=await pin(path.join(fixtures,'vitest.json'));report.finalBackendReceipt=await pin(path.join(controls,'api-receipts-final.json'));
  report.status='PASS_ORIGINAL_NATIVE_BULK_RUNTIME_INDEPENDENT_COLD_PENDING';report.independentColdPending=true;report.acceptanceCredit=0;
  await save(path.join(iso.root,'native-runtime.json'),JSON.stringify(report,null,2)+String.fromCharCode(10));
  report.finished=await finishBulk({owner,spec,name,root:iso.root,nativeName:pluto,nativeVolume,checkpointVolume,pgName:pg,pgVolume:volume,sftpName:sftp,sftpDataVolume:sftpData,controls,fixtures,configs,migrationNames,labels,runtimePath:path.join(iso.root,'native-runtime.json')});report.status='PASS_REQUIRED_NATIVE_BULK_SCOPE';report.independentColdPending=false;
}catch(error){
 report.error=String(error);report.status='FAIL_OR_PENDING_NO_CREDIT';process.exitCode=1;
 if(!owner.pending){report.failureLogs={};for(const n of [api,pluto]){if(!owner.objects.some(o=>o.kind==='container'&&o.name===n))continue;const logs=owner.run(['logs',n],process.env,true);const file=path.join(iso.root,n===api?'api-failure.log':'native-failure.log');await save(file,logs.stdout+'\n'+logs.stderr);report.failureLogs[n===api?'api':'native']=await pin(file);}}
}finally{
 if(started&&!owner.pending&&testStarted&&!testFinished&&owner.objects.some(o=>o.kind==='container'&&o.name===pluto)&&state(pluto).State.Running){owner.pending=true;owner.persist();}
 if(started&&!owner.pending&&(!testStarted||testFinished)&&apiStop&&owner.objects.some(o=>o.kind==='container'&&o.name===api)&&state(api).State.Running){await save(apiStop,'owned cooperative completion\n').catch(e=>{if(e.code!=='EEXIST')throw e;});try{await until(30000,()=>!state(api).State.Running);}catch(error){owner.pending=true;owner.persist();report.closeError=String(error);}}
 report.closure=owner.close(false);if(started&&report.closure.status!=='STOPPED_RETAINED'){report.status='PENDING_OR_FAIL';process.exitCode=1;}
 if(report.closure.status==='STOPPED_RETAINED')runningOnly(spec.allowedRunning);report.owner=owner.manifestPath;
  await save(path.join(iso.root,'producer-private-result.json'),JSON.stringify(report,null,2)+String.fromCharCode(10));
}

return {report,owner:owner.manifestPath,privateRoot:iso.root,ownerInstance:owner};
}
