import {generateKeyPairSync,constants,sign,createHash} from 'node:crypto';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {verifyManifest,verifyBytes} from './verify-release.mjs';
const keys=generateKeyPairSync('rsa',{modulusLength:3072});
const publicKey=keys.publicKey.export({type:'spki',format:'pem'});
const bytes=Buffer.from('qualified fixture');
const identity={version:'0.1.1',revision:'a'.repeat(40),repository:'https://github.com/example/pluto'};
function fixture(changes={}) {
 const manifest={schema:1,version:identity.version,sourceRevision:identity.revision,toolchain:'go1.26.8',artifacts:Object.fromEntries(['amd64','arm64'].map(arch=>['linux-'+arch,{url:identity.repository+'/releases/download/pluto-v'+identity.version+'/pluto-linux-'+arch,sha256:createHash('sha256').update(bytes).digest('hex'),size:bytes.length}])),...changes};
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
