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
 const {owner,spec,name}=ctx,work=path.join(owner.root,'final-cold-a448');await fs.mkdir(work);
 const closed=await json(path.join(ctx.controls,'bulk-checkpoint-request.json')),request=closed.request;
 assert.equal(closed.schema,'saturn.native-bulk-checkpoint-closed.v1');assert(closed.httpRequestsJoined&&closed.actualFixtureCloseReturned&&closed.retentionJoined&&closed.pendingHTTP===0);
 assert.equal(request.case,'TestCompletionNativeBulkReadbackPauseRestartNoCopies');assert.equal(request.base,'/retained/endurance-bulk-current/f-0001');assert.equal(request.nativeChildStarted,false);
 const native=owner.checked('container',ctx.nativeName).observed,pg=owner.checked('container',ctx.pgName).observed,sftp=owner.checked('container',ctx.sftpName).observed;
 assert(!native.State.Running&&native.State.ExitCode===0&&!pg.State.Running&&pg.State.ExitCode===0&&!sftp.State.Running&&sftp.State.ExitCode===0);
 assert.equal(pg.HostConfig.NetworkMode,'container:'+native.Id);assert.equal(sftp.HostConfig.NetworkMode,'container:'+native.Id);
 const manifestRaw=await fs.readFile(ctx.nativeManifestPath,'utf8'),manifest=JSON.parse(manifestRaw),manifestSHA=sha(manifestRaw);
 assert.equal(manifest.ContainerID,native.Id);assert.equal(manifest.GoTest.SHA256,spec.pins.nativeTest.sha256);assert.equal(manifest.Artifacts.current.SHA256,spec.pins.nativeCli.sha256);
 const pgdata=pg.Config.Env.find(v=>v.startsWith('PGDATA=')).slice(7);assert(path.posix.isAbsolute(pgdata)&&path.posix.normalize(pgdata)===pgdata);
 assert.equal(pgdata,'/var/lib/postgresql/18/docker');
 const pgMount=pg.Mounts.find(m=>m.Type==='volume'&&(pgdata===m.Destination||pgdata.startsWith(m.Destination+'/')));assert(pgMount&&pgMount.Name===ctx.pgVolume);
 const pgSubpath=path.posix.relative(pgMount.Destination,pgdata);assert(!pgSubpath.startsWith('..'));
 const uid=70,gid=70;
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
 const pgStopped=pg,sftpStopped=sftp;
 await newOwnedDirectories(owner,{name:name('checkpoint-directories'),image:spec.goImage,card:spec.id,volume:ctx.checkpointVolume,directories:[{name:'pg',uid,gid},{name:'sftp',uid:1001,gid:1001},{name:'fixtures',uid:0,gid:0},{name:'authority',uid:0,gid:0}]});
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
 const authorityRestored=ctx.authorityVolume;owner.checked('volume',authorityRestored);
 const restorePGName=name('restored-pg');
 const tmpfs={'/tmp':'rw,noexec,nosuid,nodev,size=32m,mode=1777','/var/run/postgresql':'rw,noexec,nosuid,nodev,size=16m,mode=1777'};if(pgMount.Destination!==pgdata)tmpfs[pgMount.Destination]='rw,nosuid,nodev,size=1m,mode=755';
 const clonePG=await runContainer(owner,{name:restorePGName,image:spec.pgImage,card:spec.id,user:uid+':'+gid,memoryMiB:512,cpus:1,pids:128,detached:true,tmpfs,mounts:[{volume:pgRestored,target:pgdata,rw:true},{bind:spec.pins.sqlCapture.path,target:'/input/capture.sql'}],environment:{PGDATA:pgdata,POSTGRES_USER:'postgres'},entrypoint:'/usr/local/bin/docker-entrypoint.sh',command:['postgres','-c','listen_addresses=127.0.0.1']});
 await until(owner,30000,()=>owner.run(['exec',restorePGName,'pg_isready','-q','-h','127.0.0.1','-U','postgres'],process.env,true).status===0);
 const clonedSQL=await capture('final-restored',restorePGName);assert.equal(clonedSQL.globals,normalDump(await fs.readFile(path.join(ctx.previousWork,'original-globals.private.sql'),'utf8')),'global roles/passwords must be unchanged');for(let i=0;i<ctx.configs.length;i++)assert.equal(clonedSQL.databases[i].schema,normalDump(await fs.readFile(path.join(ctx.previousWork,'original-'+ctx.configs[i].kind+'-schema.private.sql'),'utf8')),'all schema/function/grant bytes must be unchanged');await save(path.join(work,'full-current-sql.json'),{schema:'pluto.native-bulk-final-full-sql.v1',sha256:sha(JSON.stringify(clonedSQL)),databases:clonedSQL.databases.map(db=>({name:db.name,tables:db.rows.filter(r=>r.kind==='table').length,rows:db.rows.filter(r=>r.kind==='table').reduce((n,r)=>n+r.rows.length,0)}))});
 const restoreHome=name('restored-sftp-home');owner.resource('volume',restoreHome,ctx.labels);
 const sshEntrypoint=path.join(work,'restored-sftp-entrypoint.sh');await fs.writeFile(sshEntrypoint,['#!/bin/sh','set -eu','mkdir -p /home/vault/gateway /home/vault/.ssh/keys /etc/sftp','chown 1001:1001 /home/vault/gateway','cp /authority/ssh/host-key /etc/ssh/ssh_host_ed25519_key','chmod 0600 /etc/ssh/ssh_host_ed25519_key','cp /authority/ssh/users.conf /etc/sftp/users.conf','cp /authority/ssh/client-key.pub /home/vault/.ssh/keys/dev_client_ed25519.pub','exec /entrypoint',''].join('\n'),{flag:'wx',mode:0o600});
 const cloneSFTPName=name('restored-sftp');await runContainer(owner,{name:cloneSFTPName,image:spec.sftpImage,card:spec.id,user:'0:0',memoryMiB:192,cpus:1,pids:128,readOnly:false,detached:true,network:'container:'+clonePG.cid,capAdd:['CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETGID','SETUID','SETPCAP','SETFCAP','NET_BIND_SERVICE','SYS_CHROOT','KILL','AUDIT_WRITE','NET_RAW','MKNOD'],mounts:[{volume:restoreHome,target:'/home',rw:true},{volume:sftpRestored,target:'/home/vault/gateway',rw:true},{volume:authorityRestored,target:'/authority'},{bind:sshEntrypoint,target:'/restore-entry.sh'}],entrypoint:'/bin/sh',command:['/restore-entry.sh']});
 await until(owner,15000,()=>owner.run(['exec',cloneSFTPName,'pgrep','sshd'],process.env,true).status===0);
 const clients=[];for(const c of ctx.configs){const owned=await json(path.join(ctx.fixtures,'fixtures',c.databaseName,'shared-backend.json'));assert.equal(owned.containerId,sftp.Id);clients.push({kind:c.kind,databaseName:c.databaseName,rootId:c.binding.root_id,backendIdentity:c.backendIdentity,storageRoot:owned.root});}
 const canary=await json(path.join(ctx.controls,'bulk-checkpoint-canary.json'));
 const readerInput={schema:'pluto.native-bulk-final-product-input.v1',bulkInitial:ctx.bulk.initial,bulkFinal:ctx.bulk.final,sourceBase:path.posix.basename(ctx.sourcePath),nativeFinalProofSHA256:ctx.nativeFinalProof.sha256,requestID:request.requestID,databaseUrl:ctx.databaseUrl,storageEnvironmentFile:'/run/sftp-env.private.json',nativeBackupDirectory:request.nativeBackupDirectory,nativeBeforeSHA256:request.nativeBeforeSHA256,nativeArchiveSHA256:request.nativeArchiveSHA256,clients,canary:{rootId:canary.rootId,name:canary.name,bytes:canary.bytes,sha256:canary.sha256},migrationNames:ctx.migrationNames};
 const readerPin=await save(path.join(work,'reader-input.private.json'),readerInput),credentials=name('reader-credentials');owner.resource('volume',credentials,ctx.labels);
 await runContainer(owner,{...common,name:name('reader-credentials-provision'),user:'0:0',memoryMiB:64,cpus:0.25,capAdd:['CHOWN','DAC_OVERRIDE'],mounts:[{volume:authorityRestored,target:'/authority'},{volume:credentials,target:'/credentials',rw:true},{bind:spec.pins.readerCredentials.path,target:'/tool.py'},{bind:readerPin.path,target:'/input.json'}],entrypoint:'python3',command:['-I','-B','/tool.py','/input.json',readerPin.sha256]});
 const readback=path.join(work,'product-readback');await fs.mkdir(readback);const outputVolume=await privateOutput(owner,spec,name('product-output'));
 await runContainer(owner,{name:name('actual-product-readback'),image:spec.saturnImage,card:spec.id,user:'10001:10001',memoryMiB:1024,cpus:2,pids:128,readOnly:false,network:'container:'+clonePG.cid,mounts:[{volume:credentials,target:'/run'},{volume:ctx.nativeCheckpointVolume,target:'/checkpoint'},{bind:spec.pins.restoredReader.path,target:'/workspace/apps/api/src/bulk-final-product-a447.integration.test.ts'},{volume:outputVolume,target:'/readback',rw:true}],environment:{CI:'true',COREPACK_ENABLE_NETWORK:'0',NODE_OPTIONS:'--max-old-space-size=512',BULK_RESTORE_INPUT:'/run/reader-input.private.json',BULK_RESTORE_OUTPUT:'/readback/result.json'},workdir:'/workspace/apps/api',entrypoint:'node',command:['node_modules/vitest/vitest.mjs','run','src/bulk-final-product-a447.integration.test.ts','--configLoader','runner','--cache=false','--pool=threads','--maxWorkers=1','--no-file-parallelism','--bail=1','--reporter=json','--outputFile=/readback/vitest.json'],timeoutMs:210000});
 await collectOutput(owner,spec,outputVolume,readback,['result.json','vitest.json'],name('product-output-collect'));const product=await json(path.join(readback,'result.json'));assert.equal(product.status,'PASS_FINAL_SQL_IDS_VERSIONS_AND_ALL_SFTP_BYTES');assert(product.canaryRead&&product.databases.length===2&&product.databases.every(d=>d.backendState==='STOPPED'&&d.migrations===122)&&!product.clonedBackendWriterStarted);
 const graph={schema:'pluto.native-bulk-final-cold-graph.v1',requestID:request.requestID,components,fullSQLSHA256:sha(JSON.stringify(clonedSQL)),product,nativeFinalProof:ctx.nativeFinalProof,originalRuntime:ctx.runtimePin,sourceTuples:{native:native.Id,pg:pg.Id,sftp:sftp.Id},clonedTuples:{pg:clonePG.cid,sftp:owner.checked('container',cloneSFTPName).id}};const graphPin=await save(path.join(work,'final-complete-graph.json'),graph);return {status:'PASS_FINAL_COLD_PG_SFTP_AND_PRODUCT_IDS_VERSIONS_BYTES',graph:graphPin,product,components,fullSQLSHA256:graph.fullSQLSHA256};
}
