import {privateOutput,collectOutput} from './outputs.mjs';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {runContainer,newOwnedDirectories,until} from './container.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const json=async p=>JSON.parse(await fs.readFile(p,'utf8'));
const save=async(p,value,mode=0o600)=>{const raw=Buffer.from(JSON.stringify(value,null,2)+'\n');const f=await fs.open(p,'wx',0o600);try{await f.write(raw);await f.chmod(mode);await f.sync();}finally{await f.close();}return {path:p,bytes:raw.length,sha256:sha(raw)};};
const parseLine=(output,schema)=>{const line=output.split(/\r?\n/).find(v=>v.startsWith('{')&&JSON.parse(v).schema===schema);assert(line,'actual component proof missing');return JSON.parse(line);};
const normalDump=raw=>raw.split(/\r?\n/).filter(line=>!/^\\(?:un)?restrict [a-zA-Z0-9]+$/.test(line)).join('\n');
export async function checkpointBridge(ctx){
 const {owner,spec,name}=ctx,work=path.join(owner.root,'checkpoint-bridge');await fs.mkdir(work);
 const closed=await json(path.join(ctx.controls,'bulk-checkpoint-request.json')),request=closed.request;
 assert.equal(closed.schema,'saturn.native-bulk-checkpoint-closed.v1');assert(closed.httpRequestsJoined&&closed.actualFixtureCloseReturned&&closed.retentionJoined&&closed.pendingHTTP===0);
 assert.equal(request.case,'TestCompletionNativeBulkReadbackPauseRestartNoCopies');assert.equal(request.base,'/retained/endurance-bulk-current/f-0001');assert.equal(request.nativeChildStarted,false);
 const native=owner.checked('container',ctx.nativeName).observed,pg=owner.checked('container',ctx.pgName).observed,sftp=owner.checked('container',ctx.sftpName).observed;
 assert(native.State.Running&&pg.State.Running&&sftp.State.Running);
 assert.equal(pg.HostConfig.NetworkMode,'container:'+native.Id);assert.equal(sftp.HostConfig.NetworkMode,'container:'+native.Id);
 const manifestRaw=owner.run(['exec',ctx.nativeName,'cat','/bulk-manifest.json']).stdout,manifest=JSON.parse(manifestRaw),manifestSHA=sha(manifestRaw);
 assert.equal(manifest.ContainerID,native.Id);assert.equal(manifest.GoTest.SHA256,spec.pins.nativeTest.sha256);assert.equal(manifest.Artifacts.current.SHA256,spec.pins.nativeCli.sha256);
 const expectedRaw=owner.run(['exec',ctx.nativeName,'cat','/bulk-backup-expected.json']).stdout,expected=JSON.parse(expectedRaw);
 assert.equal(expected.base,request.base);assert.equal(expected.case,request.case);assert.equal(expected.nonce,manifest.Nonce);
 const pgdata=pg.Config.Env.find(v=>v.startsWith('PGDATA=')).slice(7);assert(path.posix.isAbsolute(pgdata)&&path.posix.normalize(pgdata)===pgdata);
 assert.equal(owner.run(['exec',ctx.pgName,'readlink','-f',pgdata]).stdout.trim(),pgdata);
 const pgMount=pg.Mounts.find(m=>m.Type==='volume'&&(pgdata===m.Destination||pgdata.startsWith(m.Destination+'/')));assert(pgMount&&pgMount.Name===ctx.pgVolume);
 const pgSubpath=path.posix.relative(pgMount.Destination,pgdata);assert(!pgSubpath.startsWith('..'));
 const uid=Number(owner.run(['exec',ctx.pgName,'id','-u','postgres']).stdout.trim()),gid=Number(owner.run(['exec',ctx.pgName,'id','-g','postgres']).stdout.trim());assert.equal(uid,70);assert.equal(gid,70);const actualRootMetadata=owner.run(['exec',ctx.pgName,'stat','-c','%u:%g:%a',pgdata]).stdout.trim();assert.equal(actualRootMetadata,'70:0:700','genuine pinned-image PG root ownership must match qualified mixed-GID archive policy');
 async function capture(stage,container){
  const result={databases:[],globals:''};const globals=owner.run(['exec',container,'pg_dumpall','-U','postgres','--globals-only']).stdout;await fs.writeFile(path.join(work,stage+'-globals.private.sql'),globals,{flag:'wx',mode:0o600});result.globals=normalDump(globals);
  for(const c of ctx.configs){assert(/^stage3_[a-f0-9]{32}$/.test(c.databaseName));
   const rows=owner.run(['exec',container,'psql','-U','postgres','-d',c.databaseName,'-qXAt','-v','ON_ERROR_STOP=1','-f','/input/capture.sql']).stdout;assert(Buffer.byteLength(rows)<=16777216);await fs.writeFile(path.join(work,stage+'-'+c.kind+'-rows.private.jsonl'),rows,{flag:'wx',mode:0o600});
   const records=rows.trim().split(/\r?\n/).map(x=>JSON.parse(x));assert.equal(records[0].kind,'database');assert.equal(records[0].name,c.databaseName);assert.equal(records.at(-1).kind,'finished');assert.equal(records.at(-1).readOnly,'on');
   const ddl=owner.run(['exec',container,'pg_dump','-U','postgres','-d',c.databaseName,'--schema-only','--quote-all-identifiers']).stdout;await fs.writeFile(path.join(work,stage+'-'+c.kind+'-schema.private.sql'),ddl,{flag:'wx',mode:0o600});
   result.databases.push({name:c.databaseName,rows:records,schema:normalDump(ddl)});
  }
  return result;
 }
 const originalSQL=await capture('original',ctx.pgName);await save(path.join(work,'original-sql-fingerprints.json'),{schema:'pluto.bulk-full-sql-source.v1',sha256:sha(JSON.stringify(originalSQL)),databases:originalSQL.databases.map(db=>({name:db.name,tables:db.rows.filter(r=>r.kind==='table').length,rows:db.rows.filter(r=>r.kind==='table').reduce((n,r)=>n+r.rows.length,0),schemaSHA256:sha(db.schema)}))});
 // Both product executors and SQL clients were actually joined by the API route.
 // Stop exactly this newly owned postgres using its supported fast-shutdown API.
 owner.checked('container',ctx.pgName);const stopCommand=owner.cli(['exec','--user',uid+':'+gid,pg.Id,'pg_ctl','-D',pgdata,'stop','-m','fast','-w','-t','30'],{allowFailure:true});assert([0,137].includes(stopCommand.status),'supported in-container shutdown utility status required');
 await until(owner,10000,()=>!owner.checked('container',ctx.pgName).observed.State.Running);
 const pgStopped=owner.checked('container',ctx.pgName).observed;assert.equal(pgStopped.State.ExitCode,0);assert.equal(pgStopped.State.OOMKilled,false);await save(path.join(work,'actual-pg-shutdown.json'),{schema:'pluto.bulk-supported-pg-shutdown.v1',containerId:pg.Id,utilityExitCode:stopCommand.status,actualServerExitCode:pgStopped.State.ExitCode,actualServerOOMKilled:pgStopped.State.OOMKilled,meaning:stopCommand.status===137?'Docker ended the in-container utility after actual PID1 exited0; clean pg_controldata remains mandatory':'utility joined0'});
 owner.stop(ctx.sftpName,15000);const sftpStopped=owner.checked('container',ctx.sftpName).observed;assert(!sftpStopped.State.Running);assert.equal(sftpStopped.State.ExitCode,0);
 await newOwnedDirectories(owner,{name:name('checkpoint-directories'),image:spec.goImage,card:spec.id,volume:ctx.checkpointVolume,directories:[{name:'pg',uid,gid},{name:'sftp',uid:1001,gid:1001},{name:'fixtures',uid:spec.hostUID,gid:spec.hostGID},{name:'authority',uid:spec.hostUID,gid:spec.hostGID}]});
 const common={image:spec.goImage,card:spec.id,memoryMiB:128,cpus:1,pids:32};
 const controlTmp={'/var/run/postgresql':'rw,nosuid,nodev,size=16m,mode=1777'};
 if(pgMount.Destination!==pgdata)controlTmp[pgMount.Destination]='rw,nosuid,nodev,size=1m,mode=755';
 const control=await runContainer(owner,{name:name('pg-control'),image:spec.pgImage,card:spec.id,user:uid+':'+gid,memoryMiB:128,cpus:1,tmpfs:controlTmp,mounts:[{volume:ctx.pgVolume,subpath:pgSubpath,target:'/source'}],environment:{LC_ALL:'C'},entrypoint:'pg_controldata',command:['/source']});
 assert(/Database cluster state:\s+shut down\s*$/m.test(control.stdout),'actual clean PG shutdown required');
 const components={};
 async function component(label,kind,user,source,maxBytes,maxEntries){
  const command={schema:'pluto.bulk-closed-component-command.v1',scope:spec.id,component:kind,uid:user[0],gid:user[1],maximumBytes:maxBytes,maximumEntries:maxEntries,...(kind==='pg'?{rootGID:0}:{})};
  const pin=await save(path.join(work,label+'-backup.json'),command,0o444);
  const backup=await runContainer(owner,{...common,name:name(label+'-backup'),user:user.join(':'),mounts:[source,{volume:ctx.checkpointVolume,subpath:label,target:'/checkpoint',rw:true},{bind:spec.pins.closedTree.path,target:'/tool.py'},{bind:pin.path,target:'/command.json'}],entrypoint:'python3',command:['-I','-B','/tool.py','backup','/command.json',pin.sha256]});
  const copied=parseLine(backup.stdout,'pluto.bulk-closed-component.v1');assert(copied.originalUnchanged&&copied.component===kind&&copied.scope===spec.id&&copied.inventorySHA256);
  const target=name(label+'-restored-data');owner.resource('volume',target,ctx.labels);
  await runContainer(owner,{...common,name:name(label+'-restore-owner'),user:'0:0',capAdd:['CHOWN'],memoryMiB:64,cpus:0.25,mounts:[{volume:target,target:'/volume',rw:true}],entrypoint:'python3',command:['-I','-B','-c','import os;from pathlib import Path;p=Path("/volume");assert not p.is_symlink() and p.is_dir() and not any(p.iterdir());os.chmod(p,0o700);os.chown(p,'+(kind==='pg'?0:user[0])+','+(kind==='pg'?0:user[1])+')']});
  const restorePin=await save(path.join(work,label+'-restore.json'),{...command,inventorySHA256:copied.inventorySHA256},0o444);
  const restored=await runContainer(owner,{...common,name:name(label+'-restore'),user:kind==='pg'?'0:0':user.join(':'),...(kind==='pg'?{capAdd:['CHOWN','DAC_OVERRIDE']}:{ }),mounts:[{volume:ctx.checkpointVolume,subpath:label,target:'/checkpoint'},{volume:target,target:'/restore',rw:true},{bind:spec.pins.closedTree.path,target:'/tool.py'},{bind:restorePin.path,target:'/command.json'}],entrypoint:'python3',command:['-I','-B','/tool.py','restore','/command.json',restorePin.sha256]});
  const proof=parseLine(restored.stdout,'pluto.bulk-closed-component-restore.v1');assert(proof.allPortableMetadataAndBytesEqual&&proof.independentInodes&&!proof.relocatedCustodyClaimed&&proof.archiveSHA256===copied.archiveSHA256);
  components[label]={backup:copied,restore:proof,restoredVolume:target,originalSource:source};
  await save(path.join(work,label+'-actual-copy.json'),components[label]);return target;
 }
 const pgRestored=await component('pg','pg',[uid,gid],{volume:ctx.pgVolume,subpath:pgSubpath,target:'/source'},1073741824,16384);
 const sftpRestored=await component('sftp','sftp',[1001,1001],{volume:ctx.sftpDataVolume,target:'/source'},67108864,8192);
 const fixtureRestored=await component('fixtures','fixture-config',[spec.hostUID,spec.hostGID],{bind:ctx.fixtures,target:'/source'},67108864,8192);
 const authorityRestored=await component('authority','fixture-config',[spec.hostUID,spec.hostGID],{bind:ctx.authorityInput,target:'/source'},67108864,8192);
 const restorePGName=name('restored-pg');
 const tmpfs={'/tmp':'rw,noexec,nosuid,nodev,size=32m,mode=1777','/var/run/postgresql':'rw,noexec,nosuid,nodev,size=16m,mode=1777'};if(pgMount.Destination!==pgdata)tmpfs[pgMount.Destination]='rw,nosuid,nodev,size=1m,mode=755';
 const clonePG=await runContainer(owner,{name:restorePGName,image:spec.pgImage,card:spec.id,user:uid+':'+gid,memoryMiB:512,cpus:1,pids:128,detached:true,tmpfs,mounts:[{volume:pgRestored,target:pgdata,rw:true},{bind:spec.pins.sqlCapture.path,target:'/input/capture.sql'}],environment:{PGDATA:pgdata,POSTGRES_USER:'postgres'},entrypoint:'/usr/local/bin/docker-entrypoint.sh',command:['postgres','-c','listen_addresses=127.0.0.1']});
 await until(owner,30000,()=>owner.run(['exec',restorePGName,'pg_isready','-q','-h','127.0.0.1','-U','postgres'],process.env,true).status===0);
 const clonedSQL=await capture('restored',restorePGName);assert.deepEqual(clonedSQL,originalSQL,'all user SQL rows/sequences/schema/roles/passwords/grants/functions must match');
 const restoreHome=name('restored-sftp-home');owner.resource('volume',restoreHome,ctx.labels);
 const sshEntrypoint=path.join(work,'restored-sftp-entrypoint.sh');await fs.writeFile(sshEntrypoint,['#!/bin/sh','set -eu','mkdir -p /home/vault/gateway /home/vault/.ssh/keys /etc/sftp','chown 1001:1001 /home/vault/gateway','cp /authority/ssh/host-key /etc/ssh/ssh_host_ed25519_key','chmod 0600 /etc/ssh/ssh_host_ed25519_key','cp /authority/ssh/users.conf /etc/sftp/users.conf','cp /authority/ssh/client-key.pub /home/vault/.ssh/keys/dev_client_ed25519.pub','exec /entrypoint',''].join('\n'),{flag:'wx',mode:0o600});
 const cloneSFTPName=name('restored-sftp');await runContainer(owner,{name:cloneSFTPName,image:spec.sftpImage,card:spec.id,user:'0:0',memoryMiB:192,cpus:1,pids:128,readOnly:false,detached:true,network:'container:'+clonePG.cid,capAdd:['CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETGID','SETUID','SETPCAP','SETFCAP','NET_BIND_SERVICE','SYS_CHROOT','KILL','AUDIT_WRITE','NET_RAW','MKNOD'],mounts:[{volume:restoreHome,target:'/home',rw:true},{volume:sftpRestored,target:'/home/vault/gateway',rw:true},{volume:authorityRestored,target:'/authority'},{bind:sshEntrypoint,target:'/restore-entry.sh'}],entrypoint:'/bin/sh',command:['/restore-entry.sh']});
 await until(owner,15000,()=>owner.run(['exec',cloneSFTPName,'pgrep','sshd'],process.env,true).status===0);
 const clients=[];for(const c of ctx.configs){const owned=await json(path.join(ctx.fixtures,'fixtures',c.databaseName,'shared-backend.json'));assert.equal(owned.containerId,sftp.Id);clients.push({kind:c.kind,databaseName:c.databaseName,rootId:c.binding.root_id,backendIdentity:c.backendIdentity,storageRoot:owned.root});}
 const canary=await json(path.join(ctx.controls,'bulk-checkpoint-canary.json'));
 const readerInput={schema:'pluto.native-bulk-restored-product-input.v1',requestID:request.requestID,databaseUrl:ctx.databaseUrl,storageEnvironmentFile:'/run/sftp-env.private.json',nativeBackupDirectory:request.nativeBackupDirectory,nativeBeforeSHA256:request.nativeBeforeSHA256,nativeArchiveSHA256:request.nativeArchiveSHA256,clients,canary:{rootId:canary.rootId,name:canary.name,bytes:canary.bytes,sha256:canary.sha256},migrationNames:ctx.migrationNames};
 const readerPin=await save(path.join(work,'reader-input.private.json'),readerInput),credentials=name('reader-credentials');owner.resource('volume',credentials,ctx.labels);
 await runContainer(owner,{...common,name:name('reader-credentials-provision'),user:'0:0',memoryMiB:64,cpus:0.25,capAdd:['CHOWN','DAC_OVERRIDE'],mounts:[{volume:authorityRestored,target:'/authority'},{volume:credentials,target:'/credentials',rw:true},{bind:spec.pins.readerCredentials.path,target:'/tool.py'},{bind:readerPin.path,target:'/input.json'}],entrypoint:'python3',command:['-I','-B','/tool.py','/input.json',readerPin.sha256]});
 const readback=path.join(work,'product-readback');await fs.mkdir(readback);const outputVolume=await privateOutput(owner,spec,name('product-output'));
 await runContainer(owner,{name:name('actual-product-readback'),image:spec.saturnImage,card:spec.id,user:'10001:10001',memoryMiB:1024,cpus:2,pids:128,readOnly:false,network:'container:'+clonePG.cid,mounts:[{volume:credentials,target:'/run'},{volume:ctx.checkpointVolume,target:'/checkpoint'},{bind:spec.pins.restoredReader.path,target:'/workspace/apps/api/src/bulk-restored-product.integration.test.ts'},{volume:outputVolume,target:'/readback',rw:true}],environment:{CI:'true',COREPACK_ENABLE_NETWORK:'0',NODE_OPTIONS:'--max-old-space-size=512',BULK_RESTORE_INPUT:'/run/reader-input.private.json',BULK_RESTORE_OUTPUT:'/readback/result.json'},workdir:'/workspace/apps/api',entrypoint:'node',command:['node_modules/vitest/vitest.mjs','run','src/bulk-restored-product.integration.test.ts','--configLoader','runner','--cache=false','--pool=threads','--maxWorkers=1','--no-file-parallelism','--bail=1','--reporter=json','--outputFile=/readback/vitest.json'],timeoutMs:210000});
 await collectOutput(owner,spec,outputVolume,readback,['result.json','vitest.json'],name('product-output-collect'));const product=await json(path.join(readback,'result.json'));assert.equal(product.status,'PASS_ACTUAL_RESTORED_PRODUCT_READBACK');assert(product.canaryRead&&product.databases.length===2&&product.databases.every(d=>d.backendState==='STOPPED'&&d.migrations===117)&&!product.clonedBackendWriterStarted);
 const nativeVerifyPin=await save(path.join(work,'native-verify.json'),{requestID:request.requestID,base:request.base,nativeBackupDirectory:request.nativeBackupDirectory,nativeBeforeSHA256:request.nativeBeforeSHA256},0o444);
 const nativeVerified=await runContainer(owner,{...common,name:name('native-originals-verify'),user:'10001:10001',mounts:[{volume:ctx.nativeVolume,target:'/retained'},{volume:ctx.checkpointVolume,target:'/checkpoint'},{bind:spec.pins.nativeOriginalVerifier.path,target:'/tool.py'},{bind:nativeVerifyPin.path,target:'/input.json'}],entrypoint:'python3',command:['-I','-B','/tool.py','/input.json',nativeVerifyPin.sha256]});
 const preserved=parseLine(nativeVerified.stdout,'pluto.bulk-native-original-verification.v1');assert(preserved.originalPhysicalUnchanged&&preserved.nativeBeforeSHA256===request.nativeBeforeSHA256);
 // Restore original service containers with their exact original IDs/configs.
 owner.run(['start',ctx.pgName]);await until(owner,30000,()=>owner.run(['exec',ctx.pgName,'pg_isready','-q','-h','127.0.0.1','-U','postgres'],process.env,true).status===0);
 owner.run(['start',ctx.sftpName]);await until(owner,15000,()=>owner.run(['exec',ctx.sftpName,'pgrep','sshd'],process.env,true).status===0);
 assert.equal(owner.checked('container',ctx.pgName).observed.Id,pg.Id);assert.equal(owner.checked('container',ctx.sftpName).observed.Id,sftp.Id);
 const graph={schema:'pluto.native-bulk-closed-graph.v1',requestID:request.requestID,components,sqlSHA256:sha(JSON.stringify(originalSQL)),product,nativeOriginalVerification:preserved,sourceTuples:{native:native.Id,pg:pg.Id,sftp:sftp.Id},clonedTuples:{pg:clonePG.cid,sftp:owner.checked('container',cloneSFTPName).id},authorityInput:ctx.authorityProvenance,nativeArchiveSHA256:request.nativeArchiveSHA256};
 const graphPin=await save(path.join(work,'complete-graph.json'),graph);
 const proof={schema:'pluto.native-bulk-checkpoint-proof.v1',status:'PASS_GENUINE_FULL_GRAPH_RESTORE',requestID:request.requestID,graphSHA256:graphPin.sha256,postgreSQLRestored:true,fullSQLRowsCompared:true,physicalSFTPRestored:true,allPhysicalBytesCompared:true,actualProductReadback:true,authorityConfigRestored:true,originalBackendStoppedReceipt:true,originalBackendResumed:false,canaryBytes:product.canaryBytes,nativeArchiveSHA256:request.nativeArchiveSHA256};
 const proofPin=await save(path.join(work,'full-restore-proof.json'),proof);
 const approval={...expected,schema:'pluto.native-bulk-root-approval.v1',manifestSHA256:manifestSHA,graphSHA256:graphPin.sha256,nativeBeforeSHA256:request.nativeBeforeSHA256,fullRestoreProofSHA256:proofPin.sha256,postgreSQLRestored:true,fullSQLRowsCompared:true,physicalSFTPRestored:true,allPhysicalBytesCompared:true,actualProductReadback:true,authorityConfigRestored:true,originalIdentitiesRetained:true};
 await save(path.join(ctx.approvalDirectory,'approval.json'),approval,0o444);
 await until(owner,15000,()=>owner.run(['logs',ctx.nativeName]).stdout.includes('BULK_ROOT_BACKUP_AUTHORIZED'));
 const temporary=path.join(ctx.controls,'bulk-checkpoint-restored.json.tmp');await save(temporary,proof);await fs.rename(temporary,path.join(ctx.controls,'bulk-checkpoint-restored.json'));
 return {proof:proofPin,graph:graphPin,product,components,sourcePGStoppedExit:pgStopped.State.ExitCode,sourceSFTPStoppedExit:sftpStopped.State.ExitCode,restoredFixtureVolume:fixtureRestored};
}
