import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {constants,createHash,generateKeyPairSync,sign} from 'node:crypto';
import {buildNotices,noticeAsset,noticeFormat} from './runtime-notices.mjs';
import {buildRuntimeContract} from './runtime-contract.mjs';

test('new bootstrap rejects stripped contract and bounded invalid probes before installation',async()=>{
  assert.equal(process.env.PLUTO_BOOTSTRAP_FIXTURE,'1');await fs.access('/.dockerenv');
  const directory=await fs.mkdtemp(path.join(os.tmpdir(),'pluto-bootstrap-contract-'));
  const assets=path.join(directory,'assets'),commands=path.join(directory,'commands');await fs.mkdir(assets);await fs.mkdir(commands);
  const keys=generateKeyPairSync('rsa',{modulusLength:3072}),key=keys.publicKey.export({type:'spki',format:'pem'}),sha=b=>createHash('sha256').update(b).digest('hex');
  const version='0.1.5',repository='https://github.com/example/pluto';
  const modules=Object.fromEntries(['linux-amd64','linux-arm64'].map(arch=>[arch,[{path:'modernc.org/sqlite',version:'v1.60.1',sum:'h1:fixture'},{path:'modernc.org/libc',version:'v1.77.1',sum:'h1:fixture'}]]));
  const archive=buildNotices(process.cwd(),modules);await fs.writeFile(path.join(assets,noticeAsset),archive);
  const noticeItem={url:repository+'/releases/download/pluto-v'+version+'/'+noticeAsset,size:archive.length,sha256:sha(archive)};
  const template=(await fs.readFile('packaging/bootstrap.sh','utf8')).replaceAll('@REPOSITORY@',repository).replaceAll('@VERSION@',version).replaceAll('@PUBLIC_KEY@',Buffer.from(key).toString('base64')).replace('@SYSTEMD_UNIT@',await fs.readFile('packaging/pluto.service','utf8')).replace('@NOTICE_VERIFIER@',await fs.readFile('packaging/verify-runtime-notices.py','utf8')).replaceAll('@CONTRACT_VERIFIER@',await fs.readFile('packaging/verify-runtime-contract.py','utf8'));
  const script=path.join(directory,'bootstrap.sh');await fs.writeFile(script,template);
  await fs.writeFile(path.join(commands,'curl'),'#!/bin/sh\nfor last do :; done\ncat "$FIXTURE_ASSETS/${last##*/}"\n',{mode:0o755});
  await fs.writeFile(path.join(commands,'systemctl'),'#!/bin/sh\necho unsafe-systemctl >> "$FIXTURE_ACTIONS"\nexit 1\n',{mode:0o755});
  const env={...process.env,PATH:commands+':'+process.env.PATH,FIXTURE_ASSETS:assets,FIXTURE_ACTIONS:path.join(directory,'actions')};
  const protectedPaths=['/usr/local/bin/pluto','/usr/local/bin/pluto.notices','/etc/systemd/system/pluto.service','/etc/exocortex/release-trust/pluto.pem'];
  for(const filename of protectedPaths)await assert.rejects(fs.access(filename));
  try{
    for(const variant of ['missing-contract','altered-policy','duplicate-key','invalid-archive','oversized-version','oversized-archive','archive-deadline']){
      let versionCommand='echo 0.1.5',archiveCommand='printf invalid';
      if(variant==='oversized-version')versionCommand='head -c 1025 /dev/zero';
      if(variant==='oversized-archive')archiveCommand='head -c 2097153 /dev/zero';
      if(variant==='archive-deadline')archiveCommand='sleep 30';
      const binary=Buffer.from('#!/bin/sh\ncase "$1" in --version) '+versionCommand+';; licenses) '+archiveCommand+';; esac\n');
      const manifest={schema:1,version,sourceRevision:'a'.repeat(40),toolchain:'go1.26.11',artifacts:Object.fromEntries(['amd64','arm64'].map(arch=>['linux-'+arch,{url:repository+'/releases/download/pluto-v'+version+'/pluto-linux-'+arch,size:binary.length,sha256:sha(binary)}])),runtimeNotices:{format:noticeFormat,artifact:noticeItem},runtimeContract:buildRuntimeContract(noticeItem)};
      if(variant==='missing-contract'){delete manifest.runtimeContract;delete manifest.runtimeNotices;}
      if(variant==='altered-policy')manifest.runtimeContract.policy='optional';
      let raw=Buffer.from(JSON.stringify(manifest));if(variant==='duplicate-key')raw=Buffer.from('{"version":"0.1.3",'+raw.toString().slice(1));
      const envelope=Buffer.from(JSON.stringify({schema:'exocortex.release-signature.v1',algorithm:'RSA-PSS-SHA256',key_id:sha(keys.publicKey.export({type:'spki',format:'der'})),signature:sign('sha256',raw,{key:keys.privateKey,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32}).toString('base64')}));
      await fs.writeFile(path.join(assets,'pluto-release.json'),raw);await fs.writeFile(path.join(assets,'pluto-release.json.sig.json'),envelope);for(const arch of ['amd64','arm64'])await fs.writeFile(path.join(assets,'pluto-linux-'+arch),binary);
      const started=Date.now(),result=spawnSync('sh',[script],{env,encoding:'utf8',timeout:12000,maxBuffer:65536});
      assert.notEqual(result.status,0,'unsafe install '+variant);assert(!result.error,'fixture timed out '+variant);assert(Date.now()-started<10000,'probe deadline exceeded '+variant);
      for(const filename of protectedPaths)await assert.rejects(fs.access(filename),undefined,'installation mutated '+filename+' '+variant);
      await assert.rejects(fs.access(env.FIXTURE_ACTIONS));
    }
  }finally{await fs.rm(directory,{recursive:true,force:true});}
});
