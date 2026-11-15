import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {setTimeout as delay} from 'node:timers/promises';

export async function runContainer(owner,cfg){
 assert(os.freemem()>=(8+cfg.memoryMiB/1024+0.25)*1024**3,'8GiB free reserve plus new component cap and margin required');
 assert(cfg.name.startsWith(owner.namespace+'-')&&!owner.lookup('container',cfg.name));
 const image=owner.image(cfg.image),user=cfg.user??'0:0',mounts=cfg.mounts??[],tmpfs=cfg.tmpfs??{};
 assert(/^\d+:\d+$/.test(user)&&cfg.memoryMiB>0&&cfg.memoryMiB<=4096&&cfg.cpus>0&&cfg.cpus<=2);
 const network=cfg.network??'none';
 if(network!=='none'){
  assert(network.startsWith('container:'));
  const peer=owner.checked('container',network.slice(10)).observed;
  assert(peer.State.Running&&!peer.State.Paused&&peer.HostConfig.NetworkMode==='none');
  assert.equal(Object.keys(peer.HostConfig.PortBindings??{}).length,0);
 }
 const args=['create','--name',cfg.name,'--label','exocortex.stage13.namespace='+owner.namespace,'--label','exocortex.release-run=587ea6af','--label','exocortex.card='+cfg.card,'--platform','linux/amd64','--network',network,'--pull=never','--user',user,'--cap-drop','ALL','--security-opt','no-new-privileges','--cpus',String(cfg.cpus),'--memory',String(cfg.memoryMiB)+'m','--memory-swap',String(cfg.memoryMiB)+'m','--pids-limit',String(cfg.pids??64)];
 if(cfg.readOnly!==false)args.push('--read-only');
 for(const cap of cfg.capAdd??[])args.push('--cap-add',cap);
 for(const [target,options] of Object.entries(tmpfs))args.push('--tmpfs',target+':'+options);
 for(const m of mounts){
  assert(m.target.startsWith('/')&&path.posix.normalize(m.target)===m.target&&!m.target.includes(','));
  let value;
  if(m.volume){owner.checked('volume',m.volume);assert(!m.volume.includes(','));value='type=volume,source='+m.volume+',target='+m.target+',volume-nocopy';if(m.subpath){assert(!m.subpath.includes(',')&&!path.posix.isAbsolute(m.subpath)&&!m.subpath.split('/').includes('..'));value+=',volume-subpath='+m.subpath;}}
  else{
   assert(path.isAbsolute(m.bind)&&!m.bind.includes(','));
   const real=await fs.realpath(m.bind);assert.equal(real,path.resolve(m.bind));
   if(m.rw){const rel=path.relative(owner.root,real);assert(rel&&!path.isAbsolute(rel)&&!rel.startsWith('..'));}
   value='type=bind,source='+real.replaceAll('\\','/')+',target='+m.target;
  }
  if(!m.rw)value+=',readonly';args.push('--mount',value);
 }
 const targets=[...mounts.map(m=>m.target),...Object.keys(tmpfs)];
 for(const target of owner.images.find(i=>i.id===image).declaredVolumes??[])assert(targets.some(m=>target===m||target.startsWith(m+'/')),'every declared image volume must have an explicit admitted mount');
 for(const [key,value] of Object.entries(cfg.environment??{})){assert(/^[A-Z][A-Z0-9_]*$/.test(key));args.push('-e',key+'='+value);}
 if(cfg.workdir)args.push('--workdir',cfg.workdir);if(cfg.entrypoint)args.push('--entrypoint',cfg.entrypoint);
 args.push(image,...(cfg.command??[]));
 const cid=owner.cli(args).stdout.trim();assert(/^[a-f0-9]{64}$/.test(cid));
 owner.record('container',cfg.name,owner.inspect('container',cid));
 const c=owner.checked('container',cfg.name).observed,h=c.HostConfig;
 assert.equal(c.Id,cid);assert.equal(c.Image,image);assert.equal(c.State.Status,'created');assert.equal(c.State.Pid,0);
 assert.equal(c.Config.User,user);assert.equal(h.NetworkMode,network);assert.equal(h.Privileged,false);
 assert.equal(h.Memory,cfg.memoryMiB*1048576);assert.equal(h.MemorySwap,h.Memory);assert.equal(h.NanoCpus,cfg.cpus*1e9);assert.equal(h.PidsLimit,cfg.pids??64);
 assert.deepEqual((h.CapDrop??[]).map(v=>v.replace(/^CAP_/,'')),['ALL']);
 assert.deepEqual((h.CapAdd??[]).map(v=>v.replace(/^CAP_/,'')).sort(),[...(cfg.capAdd??[])].sort());
 assert(h.SecurityOpt.some(v=>/^no-new-privileges(?::true|=true)?$/.test(v)));
 assert.equal(h.ReadonlyRootfs,cfg.readOnly!==false);
 assert.equal(Object.keys(h.PortBindings??{}).length,0);
 for(const m of mounts){const actual=c.Mounts.find(x=>x.Destination===m.target);assert(actual);assert.equal(actual.RW,!!m.rw);if(m.volume)assert.equal(actual.Name,m.volume);else assert.equal(actual.Type,'bind');}
 assert.equal(c.Mounts.filter(m=>m.Type==='volume'||m.Type==='bind').length,mounts.length);
 owner.cli(['start',cid]);
 if(cfg.detached)return {cid,observed:c};
 const until=Date.now()+(cfg.timeoutMs??240000);let state;
 for(;;){state=owner.checked('container',cfg.name).observed.State;if(!state.Running)break;if(Date.now()>=until){owner.pending=true;owner.persist();throw Error('owned component did not join; retained without kill: '+cfg.name);}await delay(100);}
 const logs=owner.cli(['logs',cid],{allowFailure:true});
 owner.commands.push({operation:'bulk-component-actual-exit',id:cid,exitCode:state.ExitCode,oom:state.OOMKilled});owner.persist();
 if(state.ExitCode!==0||state.OOMKilled)throw Error('owned component failed exit='+state.ExitCode+': '+cfg.name+'; private logs retained');
 return {cid,exitCode:state.ExitCode,stdout:logs.stdout,stderr:logs.stderr,observed:owner.checked('container',cfg.name).observed};
}
export async function until(owner,timeout,probe,interval=200){const end=Date.now()+timeout;for(;;){const value=await probe();if(value)return value;if(Date.now()>=end)throw Error('bounded owned observation deadline');await delay(interval);}}
export async function newOwnedDirectories(owner,cfg){
 const code="import os,sys;from pathlib import Path;root=Path('/volume');assert root.is_dir() and not root.is_symlink();"+cfg.directories.map(d=>"p=root/"+JSON.stringify(d.name)+";p.mkdir(mode=0o700);os.chown(p,"+d.uid+","+d.gid+");").join('');
 return runContainer(owner,{name:cfg.name,image:cfg.image,card:cfg.card,user:'0:0',memoryMiB:64,cpus:0.25,capAdd:['CHOWN'],mounts:[{volume:cfg.volume,target:'/volume',rw:true}],entrypoint:'python3',command:['-I','-B','-c',code]});
}
