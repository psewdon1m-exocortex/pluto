// Explicit maintainer action only. Normal builds never rewrite the embedded source.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {createHash,randomUUID} from 'node:crypto';
import {buildNotices} from './runtime-notices.mjs';
import {inspectLinkedModules} from './runtime-contract.mjs';
const root=fileURLToPath(new URL('../',import.meta.url)),go=process.env.GO_BINARY??'go';
if(execFileSync(go,['env','GOVERSION'],{cwd:root,encoding:'utf8'}).trim()!=='go1.26.11')throw Error('Use qualified Go 1.26.11.');
const temporaryParent=path.resolve(os.tmpdir());
const temporary=path.resolve(fs.mkdtempSync(path.join(temporaryParent,'pluto-notice-source-')));
if(path.dirname(temporary)!==temporaryParent||!path.basename(temporary).startsWith('pluto-notice-source-'))throw Error('Temporary notice build target is outside its explicitly owned directory.');
const target=path.join(root,'internal/pluto/runtime-notices.tar'),staged=target+'.next-'+randomUUID();
try{
  const modules={};
  for(const arch of ['amd64','arm64']){
    const binary=path.join(temporary,'pluto-linux-'+arch);
    execFileSync(go,['build','-mod=readonly','-trimpath','-o',binary,'./cmd/pluto'],{cwd:root,stdio:'inherit',env:{...process.env,GOMAXPROCS:'2',GOTOOLCHAIN:'local',CGO_ENABLED:'0',GOOS:'linux',GOARCH:arch}});
    modules['linux-'+arch]=inspectLinkedModules(binary,{architecture:'linux-'+arch,qualified:true});
  }
  const bytes=buildNotices(root,modules);
  fs.writeFileSync(staged,bytes,{flag:'wx'});fs.renameSync(staged,target);
  console.log(JSON.stringify({bytes:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex'),reviewRequired:'Compare every dependency/notice source change before signing a release.'}));
}finally{
  fs.rmSync(staged,{force:true});fs.rmSync(temporary,{recursive:true,force:true});
}
