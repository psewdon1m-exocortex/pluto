import {constants,createHash,createPublicKey,verify} from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {isDeepStrictEqual} from 'node:util';

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
export async function download(url,maximum,fetcher=fetch) {
  if(!url.startsWith('https://')) throw Error('Anonymous release download requires HTTPS');
  const response=await fetcher(url,{signal:AbortSignal.timeout(120000),headers:{'User-Agent':'pluto-release-verifier'}});
  if(!response.ok||!response.url.startsWith('https://')) throw Error('Anonymous release download failed');
  const length=response.headers.get('content-length');
  if(length!==null&&(!/^\d+$/.test(length)||Number(length)>maximum)) throw Error('Release download exceeds limit');
  const chunks=[];let size=0;
  for await(const chunk of response.body) {size+=chunk.length;if(size>maximum) throw Error('Release download exceeds limit');chunks.push(chunk);}
  return Buffer.concat(chunks);
}

export function compareReports(expected,actual) {
  const stable=report=>{
    if(report?.phase!=='final'||report.release_qualification!==true) throw Error('Report is not a final qualification');
    if(!Array.isArray(report.checks)||!report.checks.length||report.checks.some(item=>!item||!['PASS','N/A'].includes(item.status)||item.deferred!==false)) throw Error('Report has unresolved or deferred checks');
    if(new Set(report.checks.map(item=>item.id)).size!==report.checks.length) throw Error('Report has duplicate checks');
    const {run_id,checks,...identity}=report;
    return {...identity,checks:checks.map(({evidence,...result})=>result)};
  };
  if(!isDeepStrictEqual(stable(expected),stable(actual))) throw Error('Published qualification report identity/results differ');
}

export async function verifyPublishedReport({reportPath,version,revision,repository,fetchBytes=download}) {
  if(!/^\d+\.\d+\.\d+$/.test(version)||!/^[a-f0-9]{40}$/.test(revision)||!/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+$/.test(repository)) throw Error('Invalid report release identity');
  const expected=JSON.parse(await fs.readFile(reportPath));
  if(expected.service!=='pluto'||expected.revision!==revision||expected.release_tag!=='pluto-v'+version) throw Error('Local qualification report/source identity mismatch');
  const actual=JSON.parse(await fetchBytes(repository+'/releases/download/pluto-v'+version+'/known-problems-report.json',2*1024*1024));
  compareReports(expected,actual);
  return {status:'PASS',mode:'report',anonymous:true,version,revision};
}

export async function verifyRelease({directory,keyPath,version,revision,repository,mode='local',fetchBytes=download}) {
  if(!['local','published'].includes(mode)) throw Error('Unknown release verification mode');
  const read=async(name,maximum)=>{
    const file=path.join(directory,name),stat=await fs.stat(file);
    if(!stat.isFile()||stat.size<1||stat.size>maximum) throw Error('Local release asset exceeds limit: '+name);
    return fs.readFile(file);
  };
  const key=await fs.readFile(keyPath);
  const manifest=verifyManifest(await read('pluto-release.json',65536),await read('pluto-release.json.sig.json',4096),key,{version,revision,repository});
  if(!(await read('release-public.pem',16384)).equals(key)) throw Error('Published public key differs from pinned trust');
  const bootstrap=(await read('bootstrap.sh',65536)).toString();
  if(!bootstrap.includes("PUBLIC_KEY='"+key.toString('base64')+"'")) throw Error('Bootstrap trust root differs');
  if(!bootstrap.includes("VERSION='"+version+"'")||!bootstrap.includes("REPOSITORY='"+repository+"'")) throw Error('Bootstrap identity differs');
  const inventory={
    'pluto-release.json':65536,'pluto-release.json.sig.json':4096,
    'release-public.pem':16384,'bootstrap.sh':65536,
    'pluto-linux-amd64':64*1024*1024,'pluto-linux-arm64':64*1024*1024,
  };
  const tag='pluto-v'+version,base=repository+'/releases/download/'+tag+'/',api='https://api.github.com/repos/'+repository.slice('https://github.com/'.length);
  let assets;
  if(mode==='published') {
    const json=async(url)=>JSON.parse(await fetchBytes(url,2*1024*1024));
    const release=await json(api+'/releases/tags/'+tag);
    if(release.tag_name!==tag||release.draft!==false||release.prerelease!==true) throw Error('Release must be the visible prerelease candidate');
    let target=(await json(api+'/git/ref/tags/'+tag)).object;
    for(let depth=0;target?.type==='tag'&&depth<4;depth++) {
      if(!/^[a-f0-9]{40}$/.test(target.sha)) throw Error('Invalid annotated tag');
      target=(await json(api+'/git/tags/'+target.sha)).object;
    }
    if(target?.type!=='commit'||target.sha!==revision) throw Error('Published tag/source revision mismatch');
    if(!Array.isArray(release.assets)||!release.assets.every(item=>item&&typeof item==='object')) throw Error('Invalid release inventory');
    assets=new Map(release.assets.map(item=>[item.name,item]));
    if(assets.size!==release.assets.length||Object.keys(inventory).some(name=>!assets.has(name))||[...assets.keys()].some(name=>!Object.hasOwn(inventory,name)&&name!=='known-problems-report.json')) throw Error('Published release inventory mismatch');
  }
  for(const [name,maximum] of Object.entries(inventory)) {
    const candidate=await read(name,maximum);
    if(name.startsWith('pluto-linux-')) verifyBytes(candidate,manifest.artifacts[name.slice('pluto-'.length)]);
    if(mode==='published') {
      const item=assets.get(name);
      if(item.state!=='uploaded'||item.size!==candidate.length||item.browser_download_url!==base+name) throw Error('Published asset metadata mismatch: '+name);
      if(!(await fetchBytes(base+name,candidate.length)).equals(candidate)) throw Error('Published bytes differ from candidate: '+name);
    }
  }
  return {status:'PASS',mode,version,revision,toolchain:manifest.toolchain,anonymous:mode==='published',sha256:createHash('sha256').update(JSON.stringify(manifest)).digest('hex')};
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href) {
  const [directory,keyPath,version,revision,repository,mode,reportPath]=process.argv.slice(2);
  try {console.log(JSON.stringify(mode==='report'?await verifyPublishedReport({reportPath,version,revision,repository}):await verifyRelease({directory,keyPath,version,revision,repository,mode})));}
  catch(error) {console.error('Pluto release verification: '+error.message);process.exitCode=1;}
}
