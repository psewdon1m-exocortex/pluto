import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {pinnedNotices,noticeAsset} from './runtime-notices.mjs';

// Actual signed fixture assets and the real daemon run only inside a disposable container.
test('actual compatible schema-1 bootstrap installs verified runtime notices and one disabled daemon',async()=>{
  assert.equal(process.env.PLUTO_BOOTSTRAP_FIXTURE,'1');await fs.access('/.dockerenv');
  assert(process.env.PLUTO_RELEASE_FIXTURE_DIR);
  const assets=process.env.PLUTO_RELEASE_FIXTURE_DIR,manifest=JSON.parse(await fs.readFile(path.join(assets,'pluto-release.json')));
  assert.equal(manifest.schema,1);
  assert.equal(manifest.runtimeContract.schema,'pluto-runtime-contract.v1');
  const fixture=await fs.mkdtemp(path.join(os.tmpdir(),'pluto-real-bootstrap-'));await fs.mkdir(path.join(fixture,'commands'));
  await fs.writeFile(path.join(fixture,'commands/curl'),'#!/bin/sh\nfor last do :; done\ncat "$FIXTURE_ASSETS/${last##*/}"\n',{mode:0o755});
  await fs.writeFile(path.join(fixture,'commands/systemctl'),`#!/bin/sh
set -eu
pidfile="$FIXTURE_WORK/daemon.pid"
case "$1" in
enable|start|restart)
  if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then echo duplicate-start >&2; exit 1; fi
  nohup /usr/local/bin/pluto daemon > "$FIXTURE_WORK/daemon.log" 2>&1 < /dev/null &
  echo "$!" > "$pidfile"
  echo start >> "$FIXTURE_WORK/actions"
  ;;
stop|disable)
  if [ -f "$pidfile" ]; then
    pid=$(cat "$pidfile")
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid"
      attempt=0
      while kill -0 "$pid" 2>/dev/null; do
        attempt=$((attempt + 1))
        if [ "$attempt" -ge 100 ]; then echo daemon-stop-did-not-join >&2; exit 1; fi
        sleep 0.1
      done
    fi
    rm -f "$pidfile"
  fi
  echo stop >> "$FIXTURE_WORK/actions"
  ;;
esac
`,{mode:0o755});
  const env={...process.env,PATH:path.join(fixture,'commands')+':'+process.env.PATH,FIXTURE_ASSETS:assets,FIXTURE_WORK:fixture};
  // Fresh binary installation can retain an existing legacy profile. A brand-new
  // unconfigured daemon intentionally has no config.json until settings are saved.
  await fs.mkdir('/etc/pluto',{recursive:true,mode:0o700});await fs.mkdir('/var/lib/pluto',{recursive:true,mode:0o700});
  const profileBytes=Buffer.from(JSON.stringify({kernelURL:'https://kernel.fixture.invalid',outdoorToken:'fixture-outdoor',saturnURL:'https://saturn.fixture.invalid',accessToken:'fixture-access',connectionName:'legacy fixture',sources:['/fixture/source'],intervalSeconds:86400,enabled:false}));
  await fs.writeFile('/etc/pluto/config.json',profileBytes,{mode:0o600});await fs.writeFile('/var/lib/pluto/legacy-identity','unchanged fixture state',{mode:0o600});
  try {
    const outcome=spawnSync('sh',[path.join(assets,'bootstrap.sh')],{env,encoding:'utf8',timeout:40000});
    assert.equal(outcome.status,0,outcome.stdout+'\n'+outcome.stderr);
    const status=spawnSync('/usr/local/bin/pluto',['status'],{env,encoding:'utf8'});assert.equal(status.status,0,status.stderr);
    const state=JSON.parse(status.stdout);assert.equal(state.version,manifest.version);assert.equal(state.running,false);
    for(const name of Object.keys(pinnedNotices)) assert((await fs.readFile('/usr/local/bin/pluto.notices/'+name)).equals(await fs.readFile('packaging/sqlite-v1.60.1/'+name)));
    const downloaded=await fs.readFile(path.join(assets,noticeAsset));assert.equal(downloaded.length,manifest.runtimeNotices.artifact.size);
    assert.equal((await fs.readFile(path.join(fixture,'actions'),'utf8')).split('\n').filter(s=>s==='start').length,1);
    const profile=await fs.readFile('/etc/pluto/config.json');assert(profile.equals(profileBytes));assert.equal(await fs.readFile('/var/lib/pluto/legacy-identity','utf8'),'unchanged fixture state');assert.equal(state.observation.enabled,false);assert.deepEqual(state.sources,['/fixture/source']);assert.equal(state.connectionName,'legacy fixture');
    const existing=spawnSync('sh',[path.join(assets,'bootstrap.sh')],{env,encoding:'utf8'});assert.notEqual(existing.status,0);assert.match(existing.stderr,/already installed/);assert((await fs.readFile('/etc/pluto/config.json')).equals(profile));
  } finally {
    const stop=spawnSync(path.join(fixture,'commands/systemctl'),['stop'],{env,encoding:'utf8'});
    assert.equal(stop.status,0,'fixture daemon did not stop and join: '+stop.stderr);
    for(const file of ['/usr/local/bin/pluto','/etc/systemd/system/pluto.service'])await fs.rm(file,{force:true});
    await fs.rm('/usr/local/bin/pluto.notices',{recursive:true,force:true});
    await fs.rm(fixture,{recursive:true,force:true});
  }
});
