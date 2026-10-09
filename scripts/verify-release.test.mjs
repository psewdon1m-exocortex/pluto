import {generateKeyPairSync,constants,sign,createHash} from 'node:crypto';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {verifyManifest,verifyBytes,verifyRelease,download,compareReports,verifyPublishedReport} from './verify-release.mjs';
const keys=generateKeyPairSync('rsa',{modulusLength:3072});
const publicKey=keys.publicKey.export({type:'spki',format:'pem'});
const bytes=Buffer.from('qualified fixture');
const identity={version:'0.1.1',revision:'a'.repeat(40),repository:'https://github.com/example/pluto'};
function fixture(changes={}) {
 const manifest={schema:1,version:identity.version,sourceRevision:identity.revision,toolchain:'go1.26.9',artifacts:Object.fromEntries(['amd64','arm64'].map(arch=>['linux-'+arch,{url:identity.repository+'/releases/download/pluto-v'+identity.version+'/pluto-linux-'+arch,sha256:createHash('sha256').update(bytes).digest('hex'),size:bytes.length}])),...changes};
 const raw=Buffer.from(JSON.stringify(manifest));
 const envelope=Buffer.from(JSON.stringify({schema:'exocortex.release-signature.v1',algorithm:'RSA-PSS-SHA256',key_id:createHash('sha256').update(keys.publicKey.export({type:'spki',format:'der'})).digest('hex'),signature:sign('sha256',raw,{key:keys.privateKey,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32}).toString('base64')}));
 return {manifest,raw,envelope};
}
test('verifies signed source/toolchain identity and rejects tampered bytes or metadata',()=>{
 const f=fixture();assert.equal(verifyManifest(f.raw,f.envelope,publicKey,identity).version,identity.version);
 verifyBytes(bytes,f.manifest.artifacts['linux-amd64']);
 assert.throws(()=>verifyBytes(Buffer.from('corrupt'),f.manifest.artifacts['linux-amd64']));
 assert.throws(()=>verifyManifest(Buffer.concat([f.raw,Buffer.from(' ')]),f.envelope,publicKey,identity));
 for(const changes of [{sourceRevision:null},{sourceRevision:'b'.repeat(40)},{toolchain:'go1.24.13'},{version:'0.1.0'}]) {const invalid=fixture(changes);assert.throws(()=>verifyManifest(invalid.raw,invalid.envelope,publicKey,identity));}
 assert.throws(()=>verifyManifest(f.raw,f.envelope,publicKey,{...identity,repository:'https://github.com/else/pluto'}));
});

async function withCandidate(run) {
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'pluto-publication-test-'));
 const f=fixture(),base=identity.repository+'/releases/download/pluto-v'+identity.version+'/',api='https://api.github.com/repos/example/pluto';
 const files={
  'pluto-release.json':f.raw,'pluto-release.json.sig.json':f.envelope,'release-public.pem':Buffer.from(publicKey),
  'bootstrap.sh':Buffer.from("PUBLIC_KEY='"+Buffer.from(publicKey).toString('base64')+"'\nVERSION='"+identity.version+"'\nREPOSITORY='"+identity.repository+"'\n"),
  'pluto-linux-amd64':bytes,'pluto-linux-arm64':bytes,
 };
 const release={tag_name:'pluto-v'+identity.version,draft:false,prerelease:true,assets:Object.entries(files).map(([name,raw])=>({name,size:raw.length,state:'uploaded',browser_download_url:base+name}))};
 const responses=new Map([
  [api+'/releases/tags/pluto-v'+identity.version,release],
  [api+'/git/ref/tags/pluto-v'+identity.version,{object:{type:'commit',sha:identity.revision}}],
  ...Object.entries(files).map(([name,raw])=>[base+name,raw]),
 ]);
 const requests=[];
 const options={...identity,directory,keyPath:path.join(directory,'.pinned.pem'),mode:'published',fetchBytes:async(url,maximum)=>{
  requests.push(url);
  assert(responses.has(url),'unexpected download: '+url);
  const value=responses.get(url),raw=Buffer.isBuffer(value)?value:Buffer.from(JSON.stringify(value));
  if(raw.length>maximum) throw Error('Release download exceeds limit');
  return raw;
 }};
 try {
  await fs.writeFile(options.keyPath,publicKey);
  for(const [name,raw] of Object.entries(files)) await fs.writeFile(path.join(directory,name),raw);
  await run({options,files,responses,release,requests,base,api});
 } finally {
  assert.equal(path.dirname(directory),os.tmpdir());
  await fs.rm(directory,{recursive:true,force:true});
 }
}

test('anonymous candidate verification binds all six assets and resolves annotated tags',async()=>withCandidate(async({options,responses,requests,api,base})=>{
 const annotation='b'.repeat(40);
 responses.set(api+'/git/ref/tags/pluto-v'+identity.version,{object:{type:'tag',sha:annotation}});
 responses.set(api+'/git/tags/'+annotation,{object:{type:'commit',sha:identity.revision}});
 const result=await verifyRelease(options);
 assert.equal(result.status,'PASS');assert.equal(result.anonymous,true);
 assert.equal(requests.filter(url=>url.startsWith(base)).length,6);
}));

test('rejects draft, already promoted and wrong-tag candidates',async()=>withCandidate(async({options,release})=>{
 for(const change of [{draft:true},{prerelease:false},{tag_name:'pluto-v0.1.0'}]) {
  const original={...release};Object.assign(release,change);
  await assert.rejects(verifyRelease(options),/visible prerelease/);Object.assign(release,original);
 }
}));

test('rejects a changed tag commit and cyclic annotated tags',async()=>withCandidate(async({options,responses,api})=>{
 const ref=api+'/git/ref/tags/pluto-v'+identity.version,annotation='b'.repeat(40);
 responses.set(ref,{object:{type:'commit',sha:annotation}});
 await assert.rejects(verifyRelease(options),/revision mismatch/);
 responses.set(ref,{object:{type:'tag',sha:annotation}});
 responses.set(api+'/git/tags/'+annotation,{object:{type:'tag',sha:annotation}});
 await assert.rejects(verifyRelease(options),/revision mismatch/);
}));

test('rejects missing, duplicate and unexpected release assets',async()=>withCandidate(async({options,release})=>{
 const original=release.assets;
 for(const assets of [original.slice(1),[...original,original[0]],[...original,{name:'private.pem'}]]) {
  release.assets=assets;await assert.rejects(verifyRelease(options),/inventory mismatch/);
 }
}));

test('rejects incorrect upload state, asset URL and advertised size',async()=>withCandidate(async({options,release})=>{
 const original={...release.assets[0]};
 for(const change of [{state:'new'},{size:1},{browser_download_url:'https://elsewhere.invalid/manifest'}]) {
  Object.assign(release.assets[0],original,change);
  await assert.rejects(verifyRelease(options),/metadata mismatch/);
 }
}));

test('rejects same-size substitution of binaries, manifests, signatures, trust key and bootstrap',async()=>withCandidate(async({options,responses,base,files})=>{
 for(const [name,raw] of Object.entries(files)) {
  responses.set(base+name,Buffer.concat([Buffer.from([raw[0]^1]),raw.subarray(1)]));
  await assert.rejects(verifyRelease(options),/bytes differ/);responses.set(base+name,raw);
 }
 responses.set(base+'bootstrap.sh',files['bootstrap.sh'].subarray(1));
 await assert.rejects(verifyRelease(options),/bytes differ/);
 responses.set(base+'bootstrap.sh',Buffer.concat([files['bootstrap.sh'],Buffer.from('x')]));
 await assert.rejects(verifyRelease(options),/exceeds limit/);
}));

test('local verification rejects a different public key, invalid binary and mode typo',async()=>withCandidate(async({options,files})=>{
 await assert.rejects(verifyRelease({...options,mode:'publised'}),/Unknown/);
 await fs.writeFile(path.join(options.directory,'release-public.pem'),'different key');
 await assert.rejects(verifyRelease({...options,mode:'local'}),/differs from pinned trust/);
 await fs.writeFile(path.join(options.directory,'release-public.pem'),files['release-public.pem']);
 await fs.writeFile(path.join(options.directory,'pluto-linux-amd64'),'corrupt');
 await assert.rejects(verifyRelease({...options,mode:'local'}),/bytes rejected/);
}));

test('anonymous streaming download enforces byte limits without Content-Length and HTTPS',async()=>{
 const requests=[];
 const fetcher=async(url,options)=>{
  requests.push({url,options});
  return {ok:true,url:'https://release-assets.githubusercontent.com/fixture',headers:new Headers(),body:(async function*(){yield Buffer.from('12345');yield Buffer.from('67890');})()};
 };
 assert.equal((await download('https://github.com/fixture',10,fetcher)).toString(),'1234567890');
 assert.equal(Object.keys(requests[0].options.headers).some(key=>key.toLowerCase()==='authorization'),false);
 await assert.rejects(download('https://github.com/fixture',9,fetcher),/exceeds limit/);
 await assert.rejects(download('http://github.com/fixture',10,fetcher),/HTTPS/);
 await assert.rejects(download('https://github.com/fixture',10,async()=>({...await fetcher(),url:'http://github.com/fixture'})),/download failed/);
});

test('report retry accepts the same qualified tuple but rejects different identity or unresolved checks',async()=>withCandidate(async({options,responses,base})=>{
 const expected={service:'pluto',revision:identity.revision,release_tag:'pluto-v'+identity.version,catalog_sha256:'c'.repeat(64),supplemental_sha256:'d'.repeat(64),phase:'final',release_qualification:true,run_id:'2:1',checks:[{id:'REL-01',status:'PASS',deferred:false,evidence:[{log_sha256:'a'.repeat(64)}]}]};
 const previous=structuredClone(expected);previous.run_id='1:1';previous.checks[0].evidence=[{log_sha256:'b'.repeat(64)}];
 compareReports(expected,previous);
 const reportPath=path.join(options.directory,'.qualification.json');await fs.writeFile(reportPath,JSON.stringify(expected));
 responses.set(base+'known-problems-report.json',Buffer.from(JSON.stringify(previous)));
 assert.equal((await verifyPublishedReport({...options,reportPath})).status,'PASS');
 for(const changes of [{revision:'b'.repeat(40)},{catalog_sha256:'e'.repeat(64)},{supplemental_sha256:'e'.repeat(64)},{release_tag:'pluto-v0.1.0'},{release_qualification:false},{phase:'pre-signing'}]) assert.throws(()=>compareReports(expected,{...previous,...changes}));
 for(const [status,deferred] of [['UNKNOWN',false],['FAIL',false],['PASS',true]]) {
  const invalid=structuredClone(previous);Object.assign(invalid.checks[0],{status,deferred});assert.throws(()=>compareReports(expected,invalid));
 }
}));
