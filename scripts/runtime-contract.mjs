import {execFileSync} from 'node:child_process';
import {isDeepStrictEqual} from 'node:util';
import {noticeFormat,noticeMaximum} from './runtime-notices.mjs';

// First new SQLite-bearing release. Published 0.1.4 is a stdlib-only legacy CLI.
export const contractRequiredSince='0.1.5';
export const qualifiedToolchain='go1.26.11';
export const contractSchema='pluto-runtime-contract.v1';
export const contractPolicy='sqlite-runtime-notices.v1';
export const canonicalVersion=/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
export function requiresContract(version){
  if(!canonicalVersion.test(version))throw Error('Noncanonical release version');
  const parts=version.split('.'),floor=contractRequiredSince.split('.');
  for(let i=0;i<3;i++)if(parts[i]!==floor[i])return parts[i].length!==floor[i].length?parts[i].length>floor[i].length:parts[i]>floor[i];
  return true;
}
export function buildRuntimeContract(item){return {schema:contractSchema,policy:contractPolicy,requiredSince:contractRequiredSince,embedded:{format:noticeFormat,command:'licenses --archive',size:item.size,sha256:item.sha256}};}
export function validateRuntimeContract(manifest){
  if(manifest.runtimeContract===undefined){
    if(requiresContract(manifest.version))throw Error('Release requires embedded runtime contract');
    if(manifest.schema===1&&manifest.runtimeNotices!==undefined)throw Error('Legacy manifest cannot declare runtime notices');
    return false;
  }
  if(!requiresContract(manifest.version)||!manifest.runtimeNotices?.artifact||!isDeepStrictEqual(manifest.runtimeContract,buildRuntimeContract(manifest.runtimeNotices.artifact)))throw Error('Runtime contract shape or policy rejected');
  return true;
}
export function parseUniqueJSON(raw,maximum=65536){
  if(raw.length>maximum)throw Error('Release JSON exceeds limit');
  const source=raw.toString('utf8'),parsed=JSON.parse(source);let at=0;
  const space=()=>{while(/[ \t\n\r]/.test(source[at]??'!'))at++;};
  const string=()=>{const start=at++;while(at<source.length){const c=source[at++];if(c==='\\')at++;else if(c==='"')return JSON.parse(source.slice(start,at));}throw Error('Invalid JSON string');};
  const value=depth=>{
    if(depth>16)throw Error('Release JSON nesting exceeds limit');space();
    if(source[at]==='{'){
      at++;space();const keys=new Set();
      while(source[at]!=='}'){
        const key=string();if(keys.has(key))throw Error('Duplicate release JSON key');keys.add(key);space();at++;value(depth+1);space();if(source[at]!==',')break;at++;space();
      }at++;
    }else if(source[at]==='['){at++;space();while(source[at]!==']'){value(depth+1);space();if(source[at]!==',')break;at++;space();}at++;}
    else if(source[at]==='"')string();
    else {while(at<source.length&&!/[ \t\n\r,}\]]/.test(source[at]))at++;}
  };
  value(0);space();if(at!==source.length)throw Error('Release JSON trailing content');return parsed;
}
export function inspectLinkedModules(filename,{architecture,qualified=false}={}){
  const output=execFileSync(process.env.GO_BINARY??'go',['version','-m',filename],{encoding:'utf8',timeout:10000,maxBuffer:65536,stdio:['ignore','pipe','pipe']});
  if(!/^.+:\s+go\d+\.\d+/m.test(output))throw Error('Candidate has no readable Go build info');
  if(output.split('\n').some(line=>line.startsWith('\t=>')))throw Error('Candidate uses an unqualified module replacement');
  if(qualified){
    const settings=new Map(output.split('\n').filter(line=>line.startsWith('\tbuild\t')).map(line=>line.slice(7).split('=')));
    if(!output.split('\n')[0].endsWith(qualifiedToolchain)||settings.get('GOOS')!=='linux'||'linux-'+settings.get('GOARCH')!==architecture||settings.get('CGO_ENABLED')!=='0')throw Error('Candidate architecture/toolchain/CGO policy differs');
  }
  return output.split('\n').filter(line=>line.startsWith('\tdep\t')).map(line=>{const [, ,path,version,sum]=line.split('\t');return {path,version,sum};}).sort((a,b)=>a.path.localeCompare(b.path,'en'));
}
export function verifyLinkedRuntime(modules,manifest,inventory,arch){
  const sqlite=modules.some(item=>item.path==='modernc.org/sqlite');
  if(!manifest.runtimeContract){if(sqlite)throw Error('SQLite-linked binary cannot use legacy envelope');return;}
  if(!sqlite||!isDeepStrictEqual(modules,inventory?.linkedModules?.[arch]))throw Error('Actual linked runtime differs from notices');
}
export function verifyEmbeddedArchive(binary,archive){
  if(archive.length<1||archive.length>noticeMaximum||binary.indexOf(archive)===-1)throw Error('Binary does not contain the exact embedded archive');
}
