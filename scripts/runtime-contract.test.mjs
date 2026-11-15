import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,constants,sign} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {buildRuntimeContract,validateRuntimeContract,requiresContract,parseUniqueJSON,verifyLinkedRuntime,verifyEmbeddedArchive,inspectLinkedModules} from './runtime-contract.mjs';
import {verifyManifest,verifyRelease} from './verify-release.mjs';
import {verifyNotices} from './runtime-notices.mjs';

test('authentic published 0.1.4 metadata retains its signature and old payload fingerprints',()=>{
  const directory=fileURLToPath(new URL('../testdata/releases/pluto-v0.1.4/',import.meta.url));
  const raw=fs.readFileSync(path.join(directory,'pluto-release.json')),signature=fs.readFileSync(path.join(directory,'pluto-release.json.sig.json')),key=fs.readFileSync(path.join(directory,'release-public.pem'));
  const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
  assert.equal(hash(raw),'18e45f92b3c2c4570ef9841cdbdd23714aa548a19a75ae0e7b0c0b50f7fe5d40');
  assert.equal(hash(signature),'19f564088650795972505e001e0256b5ef20805f7a696ac0e59e45ec21c00e70');
  assert.equal(hash(key),'2e7e2b857ceb0bf0d2488c5f1ca9c1248b38d759728e549b17545be764508b29');
  const manifest=verifyManifest(raw,signature,key,{version:'0.1.4',revision:'28b114b26754f43fd2cdd95d71e5cd5fdfa1c1a2',repository:'https://github.com/psewdon1m-exocortex/pluto'});
  assert.equal(manifest.toolchain,'go1.26.9');assert.equal(validateRuntimeContract(manifest),false);
  assert.deepEqual(Object.fromEntries(Object.entries(manifest.artifacts).map(([arch,item])=>[arch,{size:item.size,sha256:item.sha256}])),{
    'linux-amd64':{size:7172258,sha256:'59d12873a01aee77cc7bdf36f1166dc008ea8f846c6909fb70fe5e17c037a9b0'},
    'linux-arm64':{size:6684834,sha256:'e56bbe0e2e76571ff66a80f1be145ab2dc23640bc0c7df7a7fa4b81b0ef6ad5d'},
  });
});

test('compiled contract boundary rejects re-signed stripping and ambiguous JSON',()=>{
  const keys=generateKeyPairSync('rsa',{modulusLength:3072}),key=keys.publicKey.export({type:'spki',format:'pem'});
  const identity={version:'0.1.5',revision:'a'.repeat(40),repository:'https://github.com/example/pluto'};
  const item={url:identity.repository+'/releases/download/pluto-v0.1.5/pluto-runtime-notices.tar',size:86528,sha256:'b'.repeat(64)};
  const base={schema:1,version:identity.version,sourceRevision:identity.revision,toolchain:'go1.26.11',artifacts:Object.fromEntries(['amd64','arm64'].map(arch=>['linux-'+arch,{url:identity.repository+'/releases/download/pluto-v0.1.5/pluto-linux-'+arch,size:1,sha256:'a'.repeat(64)}])),runtimeNotices:{format:'pluto-runtime-notices.tar.v1',artifact:item},runtimeContract:buildRuntimeContract(item)};
  const verify=raw=>{const envelope=Buffer.from(JSON.stringify({schema:'exocortex.release-signature.v1',algorithm:'RSA-PSS-SHA256',key_id:createHash('sha256').update(keys.publicKey.export({type:'spki',format:'der'})).digest('hex'),signature:sign('sha256',raw,{key:keys.privateKey,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32}).toString('base64')}));return verifyManifest(raw,envelope,key,identity);};
  const raw=Buffer.from(JSON.stringify(base));assert.equal(verify(raw).schema,1);
  for(const mutate of [m=>delete m.runtimeContract,m=>m.runtimeContract=null,m=>m.runtimeContract.policy='legacy',m=>m.runtimeContract.requiredSince='0.1.6',m=>m.runtimeContract.extra=true,m=>m.runtimeContract.embedded.command='daemon',m=>m.runtimeContract.embedded.size++,m=>m.runtimeContract.embedded.sha256='c'.repeat(64),m=>m.runtimeNotices=null,m=>m.toolchain='go1.26.9',m=>m.toolchain='go1.26.10']){const m=structuredClone(base);mutate(m);assert.throws(()=>verify(Buffer.from(JSON.stringify(m))));}
  for(const prefix of ['"version":"0.1.3",','"\\u0076ersion":"0.1.3",','"runtimeContract":null,'])assert.throws(()=>verify(Buffer.from('{'+prefix+raw.toString().slice(1))),/Duplicate/);
  for(const v of ['0.1.5','0.2.0','1.0.0','999999999999999999999999999999999999.0.0'])assert(requiresContract(v));
  for(const v of ['0.1.0','0.1.1','0.1.3','0.1.4'])assert(!requiresContract(v));
  for(const v of ['0.01.4','01.0.0','0.1.04','0.1.-1'])assert.throws(()=>requiresContract(v));
  const legacy={schema:1,version:'0.1.3'};assert.equal(validateRuntimeContract(legacy),false);
  assert.throws(()=>validateRuntimeContract({...legacy,runtimeContract:null}));assert.throws(()=>validateRuntimeContract({...legacy,runtimeNotices:null}));
  assert.throws(()=>parseUniqueJSON(Buffer.from('['.repeat(18)+'0'+']'.repeat(18))),/nesting/);
});

test('actual runtime evidence cannot waive contract by a falsely old version',()=>{
  const modules=[{path:'modernc.org/sqlite',version:'v1.60.1',sum:'h1:fixture'}];
  assert.throws(()=>verifyLinkedRuntime(modules,{schema:1,version:'0.1.4'},undefined,'linux-amd64'),/cannot use legacy/);
  assert.doesNotThrow(()=>verifyLinkedRuntime([],{schema:1,version:'0.1.4'},undefined,'linux-amd64'));
  assert.throws(()=>verifyLinkedRuntime(modules,{runtimeContract:{}},{linkedModules:{'linux-amd64':[]}},'linux-amd64'),/differs/);
  assert.doesNotThrow(()=>verifyLinkedRuntime(modules,{runtimeContract:{}},{linkedModules:{'linux-amd64':modules}},'linux-amd64'));
  const archive=Buffer.from('bounded exact archive');verifyEmbeddedArchive(Buffer.concat([Buffer.from('header'),archive]),archive);
  assert.throws(()=>verifyEmbeddedArchive(Buffer.from('different'),archive));
});

test('actual both-arch packages expose exact embedded archives and linked inventories',async t=>{
  if(!process.env.PLUTO_RELEASE_FIXTURE_DIR)return t.skip('actual produced release separately enabled in qualified build');
  const directory=process.env.PLUTO_RELEASE_FIXTURE_DIR,manifest=JSON.parse(fs.readFileSync(path.join(directory,'pluto-release.json'))),archive=fs.readFileSync(path.join(directory,'pluto-runtime-notices.tar'));
  assert.equal(manifest.schema,1);assert(validateRuntimeContract(manifest));
  const inventory=JSON.parse(verifyNotices(archive).get('INVENTORY.json'));
  for(const arch of ['amd64','arm64']){
    const filename=path.join(directory,'pluto-linux-'+arch),modules=inspectLinkedModules(filename,{architecture:'linux-'+arch,qualified:true});
    verifyLinkedRuntime(modules,manifest,inventory,'linux-'+arch);verifyEmbeddedArchive(fs.readFileSync(filename),archive);
    assert.throws(()=>verifyLinkedRuntime(modules,{schema:1,version:'0.1.4'},undefined,'linux-'+arch));
  }
  const legacy=process.env.PLUTO_LEGACY_FIXTURE_BINARY;assert(legacy,'actual candidate qualification also requires the authentic legacy payload');
  const oldDirectory=fileURLToPath(new URL('../testdata/releases/pluto-v0.1.4/',import.meta.url)),oldManifest=JSON.parse(fs.readFileSync(path.join(oldDirectory,'pluto-release.json'))),oldBytes=fs.readFileSync(legacy);
  assert.equal(oldBytes.length,oldManifest.artifacts['linux-amd64'].size);assert.equal(createHash('sha256').update(oldBytes).digest('hex'),oldManifest.artifacts['linux-amd64'].sha256);
  const legacyModules=inspectLinkedModules(legacy);assert.deepEqual(legacyModules,[]);verifyLinkedRuntime(legacyModules,oldManifest,undefined,'linux-amd64');
  assert(execFileSync(path.join(directory,'pluto-linux-amd64'),['licenses','--archive'],{timeout:5000,maxBuffer:2*1024*1024}).equals(archive));
  const repository=manifest.artifacts['linux-amd64'].url.split('/releases/download/')[0];
  assert.equal((await verifyRelease({directory,keyPath:path.join(directory,'release-public.pem'),version:manifest.version,revision:manifest.sourceRevision,repository})).status,'PASS');
});
