import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { createHash, createPrivateKey, X509Certificate } from "node:crypto";
import { it } from "vitest";
import { Database } from "@saturn/database";
import { loadEnvironment } from "@saturn/config";
import { SftpStorageAdapter } from "@saturn/storage";

type Input = {
 schema: string; requestID: string; databaseUrl: string; storageEnvironmentFile: string;
 nativeBackupDirectory: string; nativeBeforeSHA256: string; nativeArchiveSHA256: string;
 clients: {kind:"windows"|"pluto";databaseName:string;rootId:string;backendIdentity:string;storageRoot:string}[];
 canary:{rootId:string;name:string;bytes:number;sha256:string}; migrationNames:string[];
};
const hash=(bytes:Uint8Array)=>createHash("sha256").update(bytes).digest("hex");
it("native bulk checkpoint reads genuine restored profile SQL and SFTP",async()=>{
 const inputFile=process.env.BULK_RESTORE_INPUT,output=process.env.BULK_RESTORE_OUTPUT;
 assert(inputFile&&output&&path.isAbsolute(inputFile)&&path.isAbsolute(output),"explicit owned restored fixture files required");
 const raw=await fs.readFile(inputFile);assert(raw.length<=1048576);
 const spec=JSON.parse(raw.toString("utf8")) as Input;
 assert.equal(spec.schema,"pluto.native-bulk-restored-product-input.v1");
 assert(/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(spec.requestID));
 const endpoint=new URL(spec.databaseUrl);assert.equal(endpoint.hostname,"127.0.0.1");assert.equal(endpoint.port,"5432");
 assert.equal(spec.clients.length,2);assert.deepEqual(spec.clients.map(c=>c.kind),["windows","pluto"]);
 assert.equal(new Set(spec.clients.map(c=>c.databaseName)).size,2);assert.equal(spec.migrationNames.length,117);
 assert(spec.nativeBackupDirectory.startsWith("/checkpoint/native/")&&path.posix.normalize(spec.nativeBackupDirectory)===spec.nativeBackupDirectory);
 const beforeFile=path.posix.join(spec.nativeBackupDirectory,"native-before.json"),beforeRaw=await fs.readFile(beforeFile);
 assert.equal(hash(beforeRaw),spec.nativeBeforeSHA256);
 const before=JSON.parse(beforeRaw.toString("utf8")) as {schema:string;case:string;requestID:string;archiveSHA256:string;initialSQLiteAbsent:boolean;nativeChildStarted:boolean;actualProductLoadConfig:boolean;actualTLSKeyPairLoaded:boolean;entries:{Name:string;Directory:boolean;Mode:number;Bytes:number;SHA256:string}[]};
 assert.equal(before.schema,"pluto.native-bulk-local-backup.v1");assert.equal(before.case,"TestCompletionNativeBulkReadbackPauseRestartNoCopies");
 assert.equal(before.requestID,spec.requestID);assert.equal(before.archiveSHA256,spec.nativeArchiveSHA256);
 assert(before.initialSQLiteAbsent&&!before.nativeChildStarted&&before.actualProductLoadConfig&&before.actualTLSKeyPairLoaded);
 const archive=await fs.readFile(path.posix.join(spec.nativeBackupDirectory,"native-profile-source-authority.tar"));assert(archive.length<=67108864+8388608);assert.equal(hash(archive),spec.nativeArchiveSHA256);
 let copiedSourceFiles=0,copiedBytes=0;
 for(const entry of before.entries){
  assert(entry.Name&&!path.posix.isAbsolute(entry.Name)&&!entry.Name.split("/").includes(".."));
  const file=path.posix.join(spec.nativeBackupDirectory,"restored",entry.Name),info=await fs.lstat(file);
  assert(!info.isSymbolicLink());assert.equal(info.isDirectory(),entry.Directory);assert.equal(info.mode&0o777,entry.Mode);
  if(!entry.Directory){assert(info.isFile()&&info.nlink===1);assert.equal(info.size,entry.Bytes);copiedBytes+=info.size;assert(copiedBytes<=67108864);assert.equal(hash(await fs.readFile(file)),entry.SHA256);if(entry.Name.startsWith("source/"))copiedSourceFiles++;}
 }
 assert(copiedSourceFiles>=8&&copiedSourceFiles<=4096);
 const missing=await fs.lstat(path.posix.join(spec.nativeBackupDirectory,"restored/state/indexed/sync-state.sqlite")).catch((e:NodeJS.ErrnoException)=>{assert.equal(e.code,"ENOENT");return undefined;});assert.equal(missing,undefined);
 const certificate=new X509Certificate(await fs.readFile(path.posix.join(spec.nativeBackupDirectory,"restored/fixture-tls/chain.pem")));
 assert(certificate.checkPrivateKey(createPrivateKey(await fs.readFile(path.posix.join(spec.nativeBackupDirectory,"restored/fixture-tls/key.pem")))));
 const environment=JSON.parse(await fs.readFile(spec.storageEnvironmentFile,"utf8")) as Record<string,string>;
 const config=loadEnvironment(environment,process.cwd(),false).storage;
 assert.equal(config.host,"127.0.0.1");assert.equal(config.port,22);
 const databases=[],files=[];let canaryRead=false;
 for(const client of spec.clients){
  assert(/^stage3_[a-f0-9]{32}$/.test(client.databaseName));assert(/^[a-f0-9-]{36}$/.test(client.rootId));
  assert(client.storageRoot.startsWith(config.root+"/acceptance-")&&path.posix.normalize(client.storageRoot)===client.storageRoot);
  const url=new URL(spec.databaseUrl);url.pathname="/"+client.databaseName;
  const db=new Database(url.toString(),{max:1}),storage=new SftpStorageAdapter({...config,root:client.storageRoot});
  try{
   const migrations=await db.withSql(sql=>sql<{name:string}[]>`SELECT name FROM _vault_migrations ORDER BY name`);
   assert.deepEqual(migrations.map(row=>row.name),spec.migrationNames);
   const backend=await db.withSql(sql=>sql<{backend_identity:string;state:string;stopped_receipt:unknown}[]>`SELECT backend_identity,state,stopped_receipt FROM sync_backend_executor WHERE backend_identity=${client.backendIdentity}`);
   assert.equal(backend.length,1);assert.equal(backend[0]?.state,"STOPPED");assert(backend[0]?.stopped_receipt);
   const root=await db.withSql(sql=>sql<{root_id:string;namespace_state:string}[]>`SELECT root_id,namespace_state FROM sync_root_clock WHERE root_id=${client.rootId}`);
   assert.equal(root.length,1);assert.equal(root[0]?.namespace_state,"ACTIVE");
   const catalog=await db.withSql(sql=>sql<{id:string;name:string;storage_path:string;sha256:string;size_bytes:string;current_version_id:string}[]>`WITH RECURSIVE tree AS (SELECT id,parent_id,name,type,status,storage_path,sha256,size_bytes,current_version_id FROM resources WHERE id=${client.rootId} UNION ALL SELECT r.id,r.parent_id,r.name,r.type,r.status,r.storage_path,r.sha256,r.size_bytes,r.current_version_id FROM resources r JOIN tree t ON r.parent_id=t.id) SELECT id,name,storage_path,sha256,size_bytes::text,current_version_id FROM tree WHERE type='file' AND status='active' ORDER BY id`);
   const checked=new Map<string,{bytes:number;sha256:string}>();
   const read=async(filename:string,expectedSize:string,expectedSHA:string)=>{
    assert(filename&&!path.posix.isAbsolute(filename)&&!filename.split("/").includes(".."));
    const known=checked.get(filename);if(known){assert.equal(String(known.bytes),expectedSize);assert.equal(known.sha256,expectedSHA);return known;}
    const digest=createHash("sha256");let bytes=0;
    for await(const chunk of await storage.openRead(filename)){const raw=Buffer.from(chunk as Uint8Array);bytes+=raw.length;assert(bytes<=67108864);digest.update(raw);}
    const result={bytes,sha256:digest.digest("hex")};assert.equal(String(bytes),expectedSize);assert.equal(result.sha256,expectedSHA);checked.set(filename,result);return result;
   };
   for(const row of catalog){
    const actual=await read(row.storage_path,row.size_bytes,row.sha256);
    const versions=await db.withSql(sql=>sql<{id:string;storage_path:string;sha256:string;size_bytes:string}[]>`SELECT id,storage_path,sha256,size_bytes::text FROM file_versions WHERE resource_id=${row.id} ORDER BY id`);
    assert(versions.some(version=>version.id===row.current_version_id));
    for(const version of versions)await read(version.storage_path,version.size_bytes,version.sha256);
    files.push({kind:client.kind,resourceId:row.id,versionId:row.current_version_id,name:row.name,...actual,versions:versions.map(v=>v.id)});
    if(client.rootId===spec.canary.rootId&&row.name===spec.canary.name){assert.equal(actual.bytes,spec.canary.bytes);assert.equal(actual.sha256,spec.canary.sha256);canaryRead=true;}
   }
   databases.push({kind:client.kind,databaseName:client.databaseName,rootId:client.rootId,backendIdentity:client.backendIdentity,migrations:migrations.length,backendState:"STOPPED",physicalFiles:checked.size});
  }finally{await storage.close();await db.close();}
 }
 assert(canaryRead&&spec.canary.bytes>0);
 const result={schema:"pluto.native-bulk-restored-product.v1",requestID:spec.requestID,status:"PASS_ACTUAL_RESTORED_PRODUCT_READBACK",actualProductMethods:["Database.withSql","SftpStorageAdapter.openRead","SftpStorageAdapter.close"],nativeBeforeSHA256:spec.nativeBeforeSHA256,nativeArchiveSHA256:spec.nativeArchiveSHA256,copiedSourceFiles,copiedNativeBytes:copiedBytes,initialSQLiteAbsencePreserved:true,actualTLSKeyPairRead:true,databases,files,canaryRead:true,canaryBytes:spec.canary.bytes,clonedBackendWriterStarted:false,historicalReaderExecuted:false,fullCI:false};
 const file=await fs.open(output,"wx",0o600);try{await file.writeFile(JSON.stringify(result,null,2)+"\n");await file.sync();}finally{await file.close();}
},180000);
