import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync,spawnSync} from 'node:child_process';
import {constants,createHash,generateKeyPairSync,sign} from 'node:crypto';

// Fixed installation paths are exercised only in a disposable Linux container.
test('bootstrap bounds downloads, proves health and removes a failed partial install',async()=>{
  assert.equal(process.env.PLUTO_BOOTSTRAP_FIXTURE,'1');await fs.access('/.dockerenv');
  const directory=await fs.mkdtemp(path.join(os.tmpdir(),'pluto-bootstrap-'));
  const keys=generateKeyPairSync('rsa',{modulusLength:3072});const key=keys.publicKey.export({type:'spki',format:'pem'});
  const repository='https://github.com/example/pluto',version='0.1.1';
  const binary=Buffer.from('#!/bin/sh\ncase "$1" in --version) echo 0.1.1;; status) [ "$FIXTURE_BAD_HEALTH" != 1 ] && echo \'{"version":"0.1.1"}\';; esac\n');
  const sha=b=>createHash('sha256').update(b).digest('hex');
  await fs.mkdir(path.join(directory,'commands'));await fs.mkdir(path.join(directory,'assets'));
  const manifest=Buffer.from(JSON.stringify({schema:1,version,sourceRevision:'a'.repeat(40),toolchain:'go1.26.9',artifacts:Object.fromEntries(['amd64','arm64'].map(arch=>['linux-'+arch,{url:repository+'/releases/download/pluto-v'+version+'/pluto-linux-'+arch,size:binary.length,sha256:sha(binary)}]))}));
  const envelope=Buffer.from(JSON.stringify({schema:'exocortex.release-signature.v1',algorithm:'RSA-PSS-SHA256',key_id:sha(keys.publicKey.export({type:'spki',format:'der'})),signature:sign('sha256',manifest,{key:keys.privateKey,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32}).toString('base64')}));
  const assets=path.join(directory,'assets');await fs.writeFile(path.join(assets,'pluto-release.json'),manifest);await fs.writeFile(path.join(assets,'pluto-release.json.sig.json'),envelope);for(const arch of ['amd64','arm64'])await fs.writeFile(path.join(assets,'pluto-linux-'+arch),binary);
  await fs.writeFile(path.join(directory,'commands/curl'),'#!/bin/sh\nfor last do :; done\ncat "$FIXTURE_ASSETS/${last##*/}"\n',{mode:0o755});
  await fs.writeFile(path.join(directory,'commands/systemctl'),'#!/bin/sh\nexit 0\n',{mode:0o755});
  const bootstrap=(await fs.readFile('packaging/bootstrap.sh','utf8')).replaceAll('@REPOSITORY@',repository).replaceAll('@VERSION@',version).replaceAll('@PUBLIC_KEY@',Buffer.from(key).toString('base64')).replace('@SYSTEMD_UNIT@',await fs.readFile('packaging/pluto.service','utf8'));
  const script=path.join(directory,'bootstrap.sh');await fs.writeFile(script,bootstrap);
  const env={...process.env,PATH:path.join(directory,'commands')+':'+process.env.PATH,FIXTURE_ASSETS:assets};
  const installed=['/usr/local/bin/pluto','/etc/systemd/system/pluto.service'];
  for(const file of installed) await assert.rejects(fs.access(file));
  try {
    execFileSync('sh',[script],{env,stdio:['ignore','pipe','pipe']});
    assert.equal((await fs.readFile('/usr/local/bin/pluto')).toString(),binary.toString());
    const existing=spawnSync('sh',[script],{env,encoding:'utf8'});assert.notEqual(existing.status,0);assert.match(existing.stderr,/already installed/);
    for(const file of installed) await fs.rm(file);
    const unhealthy=spawnSync('sh',[script],{env:{...env,FIXTURE_BAD_HEALTH:'1'},encoding:'utf8',timeout:35000});
    assert.notEqual(unhealthy.status,0);assert.match(unhealthy.stderr,/health\/version check|health\/version/);
    for(const file of installed) await assert.rejects(fs.access(file));
    await fs.writeFile(path.join(assets,'pluto-release.json'),Buffer.alloc(65537,120));
    const oversized=spawnSync('sh',[script],{env,encoding:'utf8'});assert.notEqual(oversized.status,0);assert.match(oversized.stderr,/exceeds byte limit/);
    for(const file of installed) await assert.rejects(fs.access(file));
    await fs.writeFile(path.join(assets,'pluto-release.json'),manifest);await fs.writeFile(path.join(assets,'pluto-linux-amd64'),'corrupt');
    const corrupt=spawnSync('sh',[script],{env,encoding:'utf8'});assert.notEqual(corrupt.status,0);
    for(const file of installed) await assert.rejects(fs.access(file));
  }finally{for(const file of installed)await fs.rm(file,{force:true});await fs.rm(directory,{recursive:true,force:true});}
});
