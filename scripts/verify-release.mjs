import {constants,createHash,createPublicKey,verify} from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';

export function verifyManifest(raw,envelopeBytes,pinnedKey,{version,revision,repository}) {
  if(raw.length>65536||envelopeBytes.length>4096) throw Error('Release metadata exceeds limit');
  const key=createPublicKey(pinnedKey),envelope=JSON.parse(envelopeBytes),manifest=JSON.parse(raw);
  const keyId=createHash('sha256').update(key.export({type:'spki',format:'der'})).digest('hex');
  if(key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails.modulusLength<3072||envelope.schema!=='exocortex.release-signature.v1'||envelope.algorithm!=='RSA-PSS-SHA256'||envelope.key_id!==keyId||!verify('sha256',raw,{key,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32},Buffer.from(envelope.signature,'base64'))) throw Error('Release signature rejected');
  if(manifest.schema!==1||manifest.version!==version||manifest.sourceRevision!==revision||!/^\d+\.\d+\.\d+$/.test(version)||!/^[a-f0-9]{40}$/.test(revision)||manifest.toolchain!=='go1.26.8') throw Error('Release identity rejected');
  if(!/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+$/.test(repository)) throw Error('Release repository rejected');
  for(const arch of ['amd64','arm64']) {
    const item=manifest.artifacts['linux-'+arch];
    if(item?.url!==repository+'/releases/download/pluto-v'+version+'/pluto-linux-'+arch||!Number.isSafeInteger(item.size)||item.size<1||item.size>64*1024*1024||!/^([a-f0-9]{64})$/.test(item.sha256)) throw Error('Release artifact rejected');
  }
  return manifest;
}
export function verifyBytes(bytes,item) {
  if(bytes.length!==item.size||createHash('sha256').update(bytes).digest('hex')!==item.sha256) throw Error('Release bytes rejected');
}
async function download(url,maximum) {
  const response=await fetch(url,{signal:AbortSignal.timeout(120000)});
  if(!response.ok||!response.url.startsWith('https://')) throw Error('Anonymous release download failed');
  const chunks=[];let size=0;
  for await(const chunk of response.body) {size+=chunk.length;if(size>maximum) throw Error('Release download exceeds limit');chunks.push(chunk);}
  return Buffer.concat(chunks);
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href) {
  const [directory,keyPath,version,revision,repository,mode]=process.argv.slice(2);
  const base=repository+'/releases/download/pluto-v'+version+'/';
  const read=(name,max)=>mode==='published'?download(base+name,max):fs.readFile(path.join(directory,name));
  const key=await fs.readFile(keyPath);
  const manifest=verifyManifest(await read('pluto-release.json',65536),await read('pluto-release.json.sig.json',4096),key,{version,revision,repository});
  for(const arch of ['amd64','arm64']) verifyBytes(await read('pluto-linux-'+arch,64*1024*1024),manifest.artifacts['linux-'+arch]);
  const bootstrap=(await read('bootstrap.sh',65536)).toString();
  if(!bootstrap.includes("PUBLIC_KEY='"+key.toString('base64')+"'")) throw Error('Bootstrap trust root differs');
  if(!bootstrap.includes("VERSION='"+version+"'")||!bootstrap.includes("REPOSITORY='"+repository+"'")) throw Error('Bootstrap identity differs');
  console.log(JSON.stringify({status:'PASS',mode:mode??'local',version,revision,toolchain:manifest.toolchain,anonymous:mode==='published',sha256:createHash('sha256').update(JSON.stringify(manifest)).digest('hex')}));
}
