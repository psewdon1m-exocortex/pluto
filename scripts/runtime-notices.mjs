import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const noticeAsset='pluto-runtime-notices.tar';
export const noticeFormat='pluto-runtime-notices.tar.v1';
export const noticeMaximum=2*1024*1024;
export const pinnedNotices={
  'LICENSE':'c6fe05491a60ae13bcd223088d2705e36dede24e5587226231d2459ada5c4822',
  'LICENSE-3RD-PARTY.md':'b4366b9c27a9364633e015011a231913ed19bf1228f335bf617e50a6f7b168a6',
  'LICENSE-SQLITE':'8438c9c89b849131ead81d5435cb97fcf052df5b0b286dda8a2d4c29e6cb3fd0',
  'LICENSE-SQLITE_VEC':'6ce72bbe12d975bd5286e5ab0a064c069693300c47bccbc57bec18485f1621ea',
};
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
function tarFile(name,bytes) {
  const header=Buffer.alloc(512);
  header.write(name,0,100,'ascii');
  for(const [offset,width,value] of [[100,8,0o644],[108,8,0],[116,8,0],[124,12,bytes.length],[136,12,0]]) header.write(value.toString(8).padStart(width-1,'0')+'\0',offset,width,'ascii');
  header.fill(32,148,156);header[156]=48;header.write('ustar\0',257,6,'ascii');header.write('00',263,2,'ascii');
  const sum=header.reduce((a,b)=>a+b,0);header.write(sum.toString(8).padStart(6,'0')+'\0 ',148,8,'ascii');
  return Buffer.concat([header,bytes,Buffer.alloc((512-bytes.length%512)%512)]);
}
export function buildNotices(root,modulesByArchitecture) {
  const files=Object.entries(pinnedNotices).map(([name,sha256])=>{
    const bytes=fs.readFileSync(path.join(root,'packaging/sqlite-v1.60.1',name));
    if(digest(bytes)!==sha256) throw Error('Pinned upstream notice bytes differ: '+name);
    return {name,sha256,size:bytes.length,bytes};
  });
  const inventory=Buffer.from(JSON.stringify({schema:1,driver:'modernc.org/sqlite@v1.60.1',files:files.map(({bytes,...item})=>item),linkedModules:modulesByArchitecture},null,2)+'\n');
  const archive=Buffer.concat([...files.map(item=>tarFile(item.name,item.bytes)),tarFile('INVENTORY.json',inventory),Buffer.alloc(1024)]);
  verifyNotices(archive);return archive;
}
export function verifyNotices(archive) {
  if(archive.length>noticeMaximum||archive.length%512!==0) throw Error('Notice archive size rejected');
  const files=new Map();let offset=0;
  while(offset+512<=archive.length&&archive.subarray(offset,offset+512).some(byte=>byte!==0)) {
    const h=archive.subarray(offset,offset+512),name=h.subarray(0,100).toString('ascii').replace(/\0.*$/s,''),sizeText=h.subarray(124,136).toString('ascii');
    const checksum=Buffer.from(h);checksum.fill(32,148,156);
    const sum=h.subarray(148,156).toString('ascii').replace(/[\0 ]+$/g,'');
    if(!/^[0-7]+\0$/.test(sizeText)||! /^[0-7]+$/.test(sum)||parseInt(sum,8)!==checksum.reduce((a,b)=>a+b,0)||h[156]!==48||h.subarray(257,263).toString()!=='ustar\0'||h.subarray(345,500).some(Boolean)||files.has(name)||!(Object.hasOwn(pinnedNotices,name)||name==='INVENTORY.json')) throw Error('Notice archive entry rejected');
    const size=parseInt(sizeText,8),bytes=archive.subarray(offset+512,offset+512+size);
    if(size<1||size>noticeMaximum||bytes.length!==size) throw Error('Notice archive entry size rejected');
    files.set(name,bytes);offset+=512+Math.ceil(size/512)*512;
  }
  if(archive.length-offset<1024||archive.subarray(offset).some(Boolean)||files.size!==5) throw Error('Notice archive inventory rejected');
  for(const [name,sha] of Object.entries(pinnedNotices)) if(digest(files.get(name)??Buffer.alloc(0))!==sha) throw Error('Notice source bytes rejected: '+name);
  const inventory=JSON.parse(files.get('INVENTORY.json'));
  if(inventory.schema!==1||inventory.driver!=='modernc.org/sqlite@v1.60.1'||inventory.files?.length!==4) throw Error('Notice inventory rejected');
  for(const [name,sha256] of Object.entries(pinnedNotices)) {
    const found=inventory.files.filter(item=>item.name===name);
    if(found.length!==1||found[0].sha256!==sha256||found[0].size!==files.get(name).length) throw Error('Notice inventory/source mismatch');
  }
  for(const arch of ['linux-amd64','linux-arm64']) {
    const modules=inventory.linkedModules?.[arch];
    if(!Array.isArray(modules)||!modules.some(item=>item.path==='modernc.org/sqlite'&&item.version==='v1.60.1')||!modules.some(item=>item.path==='modernc.org/libc'&&item.version==='v1.77.1')||new Set(modules.map(item=>item.path)).size!==modules.length||modules.some(item=>!item.path||!item.version||!/^h1:/.test(item.sum))) throw Error('Notice linked runtime inventory rejected');
  }
  return files;
}
