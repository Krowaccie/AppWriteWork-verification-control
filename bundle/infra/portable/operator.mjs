import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {randomBytes,createHash} from 'node:crypto';
import {OWNER} from './compose.mjs';
import {workerAllowed,validateHoldFiles} from './upgrade-contract.mjs';
import {deployment,volumeNames,edgeEnabled,edgeProfile} from './deployment.mjs';
export const HERE=path.dirname(fileURLToPath(import.meta.url)),ROOT=path.resolve(HERE,'../..');
const execute=promisify(execFile);
export const read=async p=>JSON.parse(await fs.readFile(p,'utf8'));
export async function write(p,v){
  const temp=p+'.'+randomBytes(8).toString('hex')+'.pending';
  const file=await fs.open(temp,'wx',0o600);
  try{await file.writeFile(JSON.stringify(v,null,2)+'\n');await file.sync();}finally{await file.close();}
  await fs.rename(temp,p);
  if(process.platform!=='win32'){const dir=await fs.open(path.dirname(p),'r');try{await dir.sync();}finally{await dir.close();}}
}
export const sha=b=>createHash('sha256').update(b).digest('hex');
export function requireThat(v,c){if(!v)throw new Error(c);}
export async function load(dir) {
  dir=path.resolve(dir);const s=await read(path.join(dir,'profile.json'));
  requireThat(/^sm[89]-[a-z0-9-]{6,36}$/.test(s.project)&&s.version===1,'PORTABLE_PROFILE_INVALID');
  requireThat((await fs.realpath(dir)).toLowerCase()===dir.toLowerCase(),'PORTABLE_STATE_LINK_REJECTED');
  return {...s,dir};
}
export async function save(s){const {dir,...v}=s;await write(path.join(dir,'profile.json'),v);}
export async function redact(s,text) {
  const values=[];
  for(const dir of ['secrets','worker','private']){
    for(const n of await fs.readdir(path.join(s.dir,dir)).catch(()=>[])){
      if(!/password$|private\.json$|\.env$/.test(n))continue;
      const value=await fs.readFile(path.join(s.dir,dir,n),'utf8');
      if(n.endsWith('json')){
        const visit=v=>{if(typeof v==='string'&&v.length>=8)values.push(v);else if(v&&typeof v==='object')Object.values(v).forEach(visit);};
        visit(JSON.parse(value));
      }else if(n.endsWith('.env')){
        for(const line of value.split(/\r?\n/)){const i=line.indexOf('=');if(i>0&&line.length>i+1)values.push(line.slice(i+1));}
      }else values.push(value.trim());
    }
  }
  for(const v of values.sort((a,b)=>b.length-a.length))text=text.split(v).join('[REDACTED]');
  return text.replace(/\beyJ[A-Za-z0-9_.-]+/g,'[TOKEN_REDACTED]');
}
export async function docker(s,args,{timeout=60000}={}) {
  try{return (await execute('docker',['--context',s.context,...args],{cwd:s.dir,windowsHide:true,timeout,maxBuffer:16*1024*1024})).stdout.trim();}
  catch(e){const safe=await redact(s,String(e.stderr||e.stdout||e.message));await fs.mkdir(path.join(s.dir,'evidence'),{recursive:true});await fs.writeFile(path.join(s.dir,'evidence','docker-'+args[0].replace(/[^a-z]/g,'')+'-'+Date.now()+'.log'),safe,{mode:0o600});const error=new Error('PORTABLE_DOCKER_'+args[0].toUpperCase()+(e.killed?'_TIMEOUT':'')+': '+safe.slice(-2000));error.timedOut=Boolean(e.killed);throw error;}
}
export async function engine(s) {
  const x=JSON.parse(await docker(s,['context','inspect',s.context]))[0].Endpoints.docker.Host;
  requireThat(x.startsWith('unix:///')||/^npipe:\/\/\/\/\.\/pipe\/dockerDesktopLinuxEngine$/i.test(x),'PORTABLE_LOCAL_ENGINE_REQUIRED');
  const info=JSON.parse(await docker(s,['info','--format','{{json .}}']));
  requireThat(info.OSType==='linux','PORTABLE_LINUX_REQUIRED');
  return {version:info.ServerVersion,memoryBytes:info.MemTotal,cpus:info.NCPU,endpoint:x};
}
export async function render(s,{control=false}={}) {
  const pins=await read(path.join(s.dir,'images.lock.json'));
  const data=deployment(s,pins);
  if(!control)await validateHoldFiles(s);
  if(edgeProfile(s))await (await import('./public-lifecycle.mjs')).renderEdge(s);
  // Stopping/inspecting a broken installation must not need its SMTP secret.
  if(control)for(const service of Object.values(data.services))delete service.env_file;
  await write(path.join(s.dir,control?'compose.control.json':'compose.json'),data);
  return data;
}
export async function dc(s,args,options) {
  const control=args.some(a=>['stop','down','port','ps','logs'].includes(a));
  if(!control&&edgeEnabled(s))await (await import('./public-lifecycle.mjs')).validateFiles(s);
  await render(s,{control});
  return docker(s,['compose','--project-name',s.project,'--env-file',path.join(s.dir,'runtime.private.env'),'-f',path.join(s.dir,control?'compose.control.json':'compose.json'),...args],options);
}
export async function inventory(s) {
  const ids=(await docker(s,['ps','-aq','--no-trunc','--filter','label=com.docker.compose.project='+s.project])).split(/\s+/).filter(Boolean);
  const rows=ids.length?JSON.parse(await docker(s,['inspect',...ids])):[];
  for(const x of rows)requireThat(x.Config.Labels?.[OWNER]===s.project,'PORTABLE_CONTAINER_OWNERSHIP');
  const networkNames=(await docker(s,['network','ls','--format','{{.Name}}'])).split(/\s+/);
  for(const n of [s.project+'-network',s.project+'_private',s.project+'_ingress',s.project+'_public-ingress',s.project+'_mail-egress'])if(networkNames.includes(n)){
    const v=JSON.parse(await docker(s,['network','inspect',n]))[0];
    requireThat(v.Labels?.[OWNER]===s.project,'PORTABLE_NETWORK_OWNERSHIP');
  }
  const existingVolumes=(await docker(s,['volume','ls','-q'])).split(/\s+/);
  for(const n of volumeNames(s))if(existingVolumes.includes(s.project+'-'+n)){
    const v=JSON.parse(await docker(s,['volume','inspect',s.project+'-'+n]))[0];
    requireThat(v.Labels?.[OWNER]===s.project,'PORTABLE_VOLUME_OWNERSHIP');
  }
  return rows;
}
export async function runtimeFilePermissions(s) {
  if(process.platform==='win32')return; // Docker Desktop does not enforce these POSIX bind modes.
  for(const relative of ['', 'secrets', 'worker', 'private']){
    const st=await fs.lstat(path.join(s.dir,relative));
    requireThat(st.isDirectory()&&!st.isSymbolicLink()&&(st.mode&0o077)===0,'PORTABLE_PRIVATE_DIRECTORY_REQUIRED');
  }
  // Bind mounts retain Linux host modes. These public files are read after the
  // database images drop root; the enclosing state directory stays private.
  const publicFiles=['images.lock.json','clickhouse-config.xml','clickhouse-init.sh',
    ...['Caddyfile','postgres-tls.sh','pg_hba.conf','temporal-server.sh','temporal-schema.sh',
      'temporal-namespace.sh','temporal-init.sh','health.py','init-cert.sh'].map(n=>'config/'+n),
    'secrets/ca.crt','secrets/server.crt','worker/ca.crt',
    ...(edgeProfile(s)?['config/Caddyfile.public',...(s.publicEdge.config.mode==='rehearsal'?['secrets/edge.crt','secrets/smtp-ca-bundle.crt']:[])]:[])];
  // These two files are consumed by both postgres and Temporal (different UIDs).
  // 0444 is the standard container secret mode. Host traversal remains 0700 and
  // Compose grants each container only its explicitly selected read-only mount.
  for(const [names,mode] of [[publicFiles,0o644],
    [['secrets/temporal-migrator.password','secrets/temporal-runtime.password'],0o444]]) {
    for(const name of names){
      const target=path.join(s.dir,name),st=await fs.lstat(target);
      requireThat(st.isFile()&&!st.isSymbolicLink(),'PORTABLE_RUNTIME_FILE_INVALID');
      await fs.chmod(target,mode);
    }
  }
}
export async function init({dir,project,context='default',port=0,networkSubnets, deploymentBinding}) {
  requireThat(/^sm[89]-[a-z0-9-]{6,36}$/.test(project),'PORTABLE_PROJECT_INVALID');
  dir=path.resolve(dir);await fs.mkdir(dir,{recursive:false,mode:0o700});
  for(const sub of ['config','secrets','private','worker','evidence'])await fs.mkdir(path.join(dir,sub),{mode:0o700});
  const s={version:1,project,context,port,dir,createdAt:new Date().toISOString(),initialized:false,
    ...(networkSubnets?{networkSubnets}:{}),...(deploymentBinding?{deploymentBinding}:{})};
  await save(s);await engine(s);
  const existing=(await docker(s,['ps','-a','--format','{{.Names}}'])).split(/\s+/);
  requireThat(!existing.some(n=>n.startsWith(project+'-')),'PORTABLE_NEW_PROJECT_REQUIRED');
  const volumes=(await docker(s,['volume','ls','-q'])).split(/\s+/);
  requireThat(!volumes.some(n=>n.startsWith(project+'-')),'PORTABLE_NEW_VOLUMES_REQUIRED');
  const secrets={};
  for(const n of ['DB_PASSWORD','CLICKHOUSE_PASSWORD','OPENSSL_KEY','EXECUTOR_SECRET','JOBS_SECRET','GEO_SECRET'])
    secrets['R0_'+n]=randomBytes(32).toString('hex');
  const passwords=['app-postgres','temporal-postgres','temporal-migrator','temporal-runtime','app-migrator','app-runtime'];
  for(const n of passwords)await fs.writeFile(path.join(dir,'secrets',n+'.password'),randomBytes(32).toString('hex'),{mode:0o600});
  await write(path.join(dir,'private','appwrite.private.json'),{adminEmail:'operator@portable.invalid',adminPassword:randomBytes(32).toString('hex')});
  await fs.writeFile(path.join(dir,'runtime.private.env'),Object.entries(secrets).map(([k,v])=>k+'='+v).join('\n')+'\n',{mode:0o600});
  await write(path.join(dir,'private','secrets.private.json'),secrets);
  await fs.writeFile(path.join(dir,'jobs-key.private'),secrets.R0_JOBS_SECRET,{mode:0o600});
  const copyText=async (name,destination)=>fs.writeFile(destination,(await fs.readFile(path.join(HERE,name),'utf8')).replaceAll('\r\n','\n'),{mode:0o600});
  for(const name of ['images.lock.json','clickhouse-config.xml','clickhouse-init.sh'])await copyText(name,path.join(dir,name));
  for(const name of ['Caddyfile','postgres-tls.sh','pg_hba.conf','temporal-server.sh','temporal-schema.sh','temporal-namespace.sh','temporal-init.sh','health.py','init-cert.sh'])
    await copyText(name,path.join(dir,'config',name));
  const pins=await read(path.join(dir,'images.lock.json'));
  for(const p of Object.values(pins)){
    try{await docker(s,['image','inspect',p.reference,'--format','{{.Id}}']);}
    catch{console.log(JSON.stringify({event:'pull',image:p.tag}));await docker(s,['pull','--platform',p.platform,p.reference],{timeout:600000});}
  }
  await docker(s,['run','--rm','--network','none','--label',OWNER+'='+project,
    '--mount','type=bind,source='+path.join(dir,'secrets')+',target=/out',
    '--mount','type=bind,source='+path.join(dir,'config/init-cert.sh')+',target=/init-cert.sh,readonly',
    '--entrypoint','bash',pins['app-postgres'].reference,'/init-cert.sh']);
  await fs.copyFile(path.join(dir,'secrets/ca.crt'),path.join(dir,'worker/ca.crt'));
  await runtimeFilePermissions(s);await render(s);return s;
}
export async function build(s,source=ROOT) {
  const pins=await read(path.join(s.dir,'images.lock.json')),tag='salmora-portable-worker:'+s.project;
  const {sourceFiles}=await import('./source.mjs');
  const identity=await sourceFiles(source,['packages/backend-core-py/src','packages/catalog','services/execution-worker-py']);
  const context=path.join(s.dir,'private','worker-build-'+randomBytes(4).toString('hex'));await fs.mkdir(context);
  for(const [name,hash] of Object.entries(identity)){
    const bytes=await fs.readFile(path.join(source,name));requireThat(sha(bytes)===hash,'PORTABLE_BUILD_INPUT_DRIFT');
    const target=path.join(context,name);await fs.mkdir(path.dirname(target),{recursive:true});await fs.writeFile(target,bytes);
  }
  await docker(s,['build','--build-arg','BASE_IMAGE='+pins['worker-base'].reference,
    '--file',path.join(context,'services/execution-worker-py/Dockerfile'),'--tag',tag,context],{timeout:900000});
  s.workerImage=await docker(s,['image','inspect',tag,'--format','{{.Id}}']);
  await write(path.join(s.dir,'evidence/build.json'),{imageId:s.workerImage,inputs:identity});
  s.sourceDigest=sha(Buffer.from(JSON.stringify(identity)));await save(s);await render(s);
  return {imageId:s.workerImage,sourceDigest:s.sourceDigest,inputs:Object.keys(identity).length};
}
export async function recoverRuntimes(s) {
  // Runtime children are disposable; durable deployments live in the functions volume.
  // A host power loss can erase their /tmp bind mounts while restart=always survives.
  await engine(s);await inventory(s);
  const executor='r0e-'+sha(Buffer.from(s.project)).slice(0,10);
  const ids=(await docker(s,['ps','-aq','--filter','label=openruntimes-executor='+executor])).split(/\s+/).filter(Boolean);
  const recovered=[];
  for(const id of ids){
    const x=JSON.parse(await docker(s,['inspect',id]))[0];
    requireThat(x.Config.Labels?.['openruntimes-executor']===executor&&x.Name.startsWith('/'+executor+'-')
      &&Date.parse(x.Created)>=Date.parse(s.createdAt),'PORTABLE_CHILD_OWNERSHIP');
    if(!['restarting','exited'].includes(x.State.Status))continue;
    const log=await docker(s,['logs','--tail','12',id]);
    if(!log.includes('Code path /tmp/code.tar.gz not found.'))continue;
    const runtime=x.Config.Labels['openruntimes-runtime-id'];
    requireThat(/^[A-Za-z0-9_.-]{1,64}$/.test(runtime),'PORTABLE_RUNTIME_ID');
    await write(path.join(s.dir,'evidence','runtime-recovery-'+id.slice(0,12)+'.json'),
      {container:id,runtime,state:x.State.Status,reason:'ephemeral code missing after host restart',at:new Date().toISOString()});
    // Use the executor API so its cache and disposable container agree. Never delete volumes.
    const code='$c=curl_init("http://localhost/v1/runtimes/".$argv[1]);curl_setopt_array($c,[CURLOPT_CUSTOMREQUEST=>"DELETE",CURLOPT_RETURNTRANSFER=>true,CURLOPT_HTTPHEADER=>["Authorization: Bearer ".getenv("OPR_EXECUTOR_SECRET")]]);curl_exec($c);$n=curl_getinfo($c,CURLINFO_RESPONSE_CODE);echo $n;exit(in_array($n,[200,404],true)?0:1);';
    const status=await docker(s,['exec',executor,'php','-r',code,runtime]);
    requireThat(['200','404'].includes(status),'PORTABLE_RUNTIME_RECOVERY');
    if(status==='404'){
      // Restarted executor has no entry for the orphan. Recheck before removal.
      const current=JSON.parse(await docker(s,['inspect',id]))[0];
      requireThat(['restarting','exited'].includes(current.State.Status)&&current.Config.Labels['openruntimes-executor']===executor,'PORTABLE_RUNTIME_CHANGED');
      await docker(s,['rm','--force',id]);
    }
    recovered.push(runtime);
  }
  return {status:'RECOVERED',runtimes:recovered};
}
export async function refreshEndpoint(s) {
  const endpoint=await dc(s,['port','gateway','443']);
  requireThat(/^127\.0\.0\.1:\d+$/.test(endpoint),'PORTABLE_LOOPBACK_PORT_REQUIRED');
  s.port=Number(endpoint.split(':')[1]); // Keep the assigned port across the next engine restart.
  s.endpoint='https://localhost:'+s.port+'/v1';
  if(edgeEnabled(s)){
    const ports={};
    for(const [name,target] of [['http','80'],['https','443']]){
      const bound=await dc(s,['port','public-edge',target]);
      const host=s.publicEdge.config.mode==='rehearsal'?'127.0.0.1':'0.0.0.0';
      requireThat(bound.startsWith(host+':')&&/^\d+$/.test(bound.slice(host.length+1)),'PUBLIC_BINDING_DRIFT');
      ports[name]=Number(bound.slice(host.length+1));
    }
    s.publicEdge.ports=ports;
  }
  await save(s);return s.endpoint;
}
export async function up(s) {
  requireThat(!s.restorePending,'PORTABLE_RESTORE_INCOMPLETE');
  await engine(s);await inventory(s);await render(s);await runtimeFilePermissions(s);
  const start=performance.now();
  const base=['postgresql','redis','clickhouse','geo','executor','orchestrator','appwrite','worker','app-postgres','temporal-postgres',...(edgeEnabled(s)&&s.publicEdge.config.mode==='rehearsal'?['mailpit']:[])];
  await dc(s,['up','-d','--pull','never','--wait','--wait-timeout','240',...base],{timeout:270000});
  await recoverRuntimes(s);
  if(!s.initialized) {
    await dc(s,['run','--rm','--no-deps','-T','temporal-schema'],{timeout:120000});
    s.initialized=true;await save(s);
  }
  await dc(s,['up','-d','--wait','--wait-timeout','120','temporal','gateway',...(edgeEnabled(s)?['public-edge']:[])],{timeout:150000});
  await dc(s,['run','--rm','--no-deps','-T','temporal-namespace'],{timeout:150000});
  await refreshEndpoint(s);s.quiesced=false;await save(s);
  const result={status:'READY',endpoint:s.endpoint,seconds:(performance.now()-start)/1000,containers:(await inventory(s)).length};
  await write(path.join(s.dir,'evidence/startup.json'),result);return result;
}
export async function runTool(s,script,args=[],{writeState=false}={}) {
  requireThat(/^infra\/portable\/[a-z_]+\.py$|^dev\/labs\/(?:hosting-m8|migration-m9|backup-b2)\/[a-z_]+\.py$/.test(script),'PORTABLE_TOOL_INVALID');
  const name=s.project+'-tool-'+randomBytes(4).toString('hex');
  return docker(s,['run','--rm','--name',name,'--label',OWNER+'='+s.project,'--network',s.project+'_private',
    '--mount','type=bind,source='+ROOT+',target=/source,readonly',
    '--mount','type=bind,source='+s.dir+',target=/run/portable'+(writeState?'':',readonly'),
    s.workerImage,'python','/source/'+script,...args],{timeout:900000});
}
export async function stop(s) {
  await engine(s);await inventory(s);
  // Close ingress and dispatchers before stopping databases. Unknown children block backup.
  await dc(s,['stop','-t','45',...(edgeEnabled(s)?['public-edge']:[]),'gateway',...(s.product?.mcpOAuth?['mcp']:[]),'execution-worker','worker','appwrite','orchestrator','executor'],{timeout:180000});
  const network=JSON.parse(await docker(s,['network','inspect',s.project+'-network']))[0];
  requireThat(network.Labels?.[OWNER]===s.project,'PORTABLE_NETWORK_OWNERSHIP');
  const ids=Object.keys(network.Containers||{});
  const containers=ids.length?JSON.parse(await docker(s,['inspect',...ids])):[];
  const executor='r0e-'+sha(Buffer.from(s.project)).slice(0,10);
  for(const x of containers){
    if(x.Config.Labels?.[OWNER]===s.project)continue;
    requireThat(x.Config.Labels?.['openruntimes-executor']===executor&&x.Name.startsWith('/'+executor+'-')
      &&Date.parse(x.Created)>=Date.parse(s.createdAt),'PORTABLE_UNKNOWN_RUNTIME_CHILD');
    await docker(s,['stop','-t','30',x.Id]);
  }
  await dc(s,['stop','-t','60'],{timeout:180000});
  requireThat((await inventory(s)).every(x=>!x.State.Running),'PORTABLE_WRITER_STILL_RUNNING');
  for(const n of volumeNames(s))requireThat(!(await docker(s,['ps','-q','--filter','volume='+s.project+'-'+n])),'PORTABLE_VOLUME_WRITER_STILL_RUNNING');
  s.quiesced=true;s.checkpointAt=new Date().toISOString();await save(s);
  return {status:'QUIESCED',checkpointAt:s.checkpointAt};
}
export async function workers(s,{upgradeBinding}={}) {
  workerAllowed(s,upgradeBinding);
  requireThat(!s.restorePending,'PORTABLE_RESTORE_INCOMPLETE');
  requireThat(s.workerImage,'PORTABLE_BUILD_REQUIRED');
  await dc(s,['up','-d','--no-deps','--pull','never','execution-worker']);
  return {status:'STARTED',imageId:s.workerImage};
}
async function main() {
  const [action,dir,...rest]=process.argv.slice(2);
  if(action==='init'){const [project,context='default']=rest;const s=await init({dir,project,context});console.log(JSON.stringify({status:'INITIALIZED',project:s.project,dir:s.dir}));return;}
  const s=await load(dir);
  const result=action==='build'?await build(s,rest[0]||ROOT):
    action==='recover'?{...await recoverRuntimes(s),endpoint:await refreshEndpoint(s)}:action==='up'?await up(s):action==='stop'?await stop(s):action==='workers'?await workers(s):
    action==='status'?{engine:await engine(s),containers:(await inventory(s)).map(x=>({name:x.Name,state:x.State.Status,health:x.State.Health?.Status,image:x.Image}))}:
    action==='migrate'?JSON.parse(await runTool(s,'infra/portable/migrate.py',[],{writeState:true})):
    (()=>{throw new Error('PORTABLE_UNKNOWN_COMMAND');})();
  console.log(JSON.stringify(result));
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))
  main().catch(e=>{console.error(e.message);process.exitCode=1;});
