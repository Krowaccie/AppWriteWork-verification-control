// Local self-hosted installer. Cloud endpoints are rejected by localApi.
import fs from 'node:fs/promises';
import path from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';
import {randomBytes} from 'node:crypto';
import {ROOT,HERE,load,read,write,save,sha,docker,engine,dc,up,stop,workers,inventory,requireThat,refreshEndpoint} from './operator.mjs';
import {mcpRoutes} from './mcp-profile.mjs';
import {edgeEnabled} from './deployment.mjs';
import {localApi} from './api.mjs';
import {prepareArchive,deploy,poll,verifyFunctionConfiguration} from './native-functions.mjs';
const execute=promisify(execFile);
export async function credentials(s){
 const ca=await fs.readFile(path.join(s.dir,'secrets/ca.crt'));
 const c=await read(path.join(s.dir,'private/appwrite.private.json'));
 const anon=localApi(s.endpoint,ca,{'x-appwrite-project':'console'});
 if(!c.consoleCreated){
   try{await anon('POST','/account',{userId:'unique()',email:c.adminEmail,password:c.adminPassword,name:'Local portable operator'});}
   catch(e){if(e.status!==409)throw e;}
   c.consoleCreated=true;await write(path.join(s.dir,'private/appwrite.private.json'),c);
 }
 const session=await anon('POST','/account/sessions/email',{email:c.adminEmail,password:c.adminPassword});
 const admin=localApi(s.endpoint,ca,{'x-appwrite-project':'console','x-fallback-cookies':session.fallbackCookies});
 return {ca,c,admin,close:()=>admin('DELETE','/account/sessions/current')};
}
export async function provision(s){
 await engine(s);const {ca,c,admin,close}=await credentials(s);
 try{
  if(!c.projectId){
   const suffix=randomBytes(6).toString('hex');
   c.projectId='portable'+suffix;c.teamId='portableteam'+suffix;c.bucketId='portablebytes'+suffix;
   await admin('POST','/teams',{teamId:c.teamId,name:'Portable installation'});
   await admin('POST','/projects',{projectId:c.projectId,teamId:c.teamId,region:'default',name:'Salmora portable'});
   await write(path.join(s.dir,'private/appwrite.private.json'),c);
   for(const hostname of ['localhost','127.0.0.1','host.docker.internal'])
    await admin('POST','/projects/'+c.projectId+'/platforms',{platformId:'unique()',type:'web',name:'Local Docker',hostname});
  }
  if(!c.apiKey){
   const scopes=['users.read','users.write','buckets.read','buckets.write','files.read','files.write',
     'functions.read','functions.write','execution.read','execution.write','databases.read','databases.write',
     'tables.read','tables.write','columns.read','columns.write','indexes.read','indexes.write','rows.read','rows.write','sites.read'];
   const result=await admin('POST','/projects/'+c.projectId+'/keys',{keyId:'unique()',name:'Local installation operator',scopes,
      expire:new Date(Date.now()+7*86400000).toISOString()});
   c.apiKey=result.value.secret;c.apiKeyId=result.value.$id;await write(path.join(s.dir,'private/appwrite.private.json'),c);
  }
  if(!c.workerKey){
   const result=await admin('POST','/projects/'+c.projectId+'/keys',{keyId:'unique()',name:'Local Storage runtime',
      scopes:['buckets.read','files.read','files.write'],expire:new Date(Date.now()+7*86400000).toISOString()});
   c.workerKey=result.value.secret;c.workerKeyId=result.value.$id;await write(path.join(s.dir,'private/appwrite.private.json'),c);
  }
  const api=localApi(s.endpoint,ca,{'x-appwrite-project':c.projectId,'x-appwrite-key':c.apiKey});
  let bucket;try{bucket=(await api('GET','/storage/buckets/'+c.bucketId)).value;}catch(e){if(e.status!==404)throw e;}
  if(!bucket)await api('POST','/storage/buckets',{bucketId:c.bucketId,name:'Private product bytes',permissions:[],fileSecurity:true,
    enabled:true,maximumFileSize:30000000,allowedFileExtensions:[],compression:'none',encryption:false,antivirus:false});
  s.product={...s.product,version:1,profile:'salmora-portable-no-key.v1',projectId:c.projectId};await save(s);
  return {status:'PROVISIONED',projectId:c.projectId,bucketId:c.bucketId};
 }finally{await close();}
}
export async function functionEnvironment(s,c,fixtureMode=s.product?.deviceFixtureEnabled??true){
 return {APPWRITE_ENDPOINT:'http://appwrite/v1',APPWRITE_PROJECT_ID:c.projectId,
  SALMORA_METADATA_BACKEND:'postgres',SALMORA_CONTENT_BUCKET_ID:c.bucketId,SALMORA_SQL_HOST:'app-postgres',
  SALMORA_SQL_PORT:'5432',SALMORA_SQL_DATABASE:'salmora',SALMORA_SQL_USER:'salmora_runtime',
  SALMORA_SQL_PASSWORD:(await fs.readFile(path.join(s.dir,'secrets/app-runtime.password'),'utf8')).trim(),
  SALMORA_SQL_SCHEMA:'salmora_app',SALMORA_SQL_SSLROOTCERT:'/usr/local/server/src/function/m1-ca.crt',
  SALMORA_EXECUTION_ENGINE_ID:'temporal',SALMORA_LOCAL_AGENT_ENABLED:'true',
  SALMORA_LOCAL_DEVICE_ENABLED:'1',SALMORA_LOCAL_DEVICE_FIXTURE_ENABLED:fixtureMode?'1':'0'};
}
export async function installFunctions(s,{python='python',source=ROOT,update=false,retryFailed=false,fixtureMode=s.product?.deviceFixtureEnabled??true}={}){
 // Updating an installed cohort never provisions an account, key or project.
 const c=await read(path.join(s.dir,'private/appwrite.private.json'));
 const ca=await fs.readFile(path.join(s.dir,'secrets/ca.crt'));
 requireThat(c.consoleCreated&&c.apiKey&&c.projectId===s.product?.projectId,'PORTABLE_INSTALL_REQUIRED');
 const manifest=await read(path.join(HERE,'product-manifest.json'));
 const request=localApi(s.endpoint,ca,{'x-appwrite-project':c.projectId,'x-appwrite-key':c.apiKey});
 const listed=(await request('GET','/functions?'+new URLSearchParams([['queries[]',JSON.stringify({method:'limit',values:[100]})]]))).value;
 const rows=listed.functions;requireThat(rows.length===listed.total,'PORTABLE_FUNCTION_INVENTORY_TRUNCATED');
 requireThat(rows.every(f=>manifest.functions.includes(f.$id)),'PORTABLE_FOREIGN_FUNCTION');
 if(update)requireThat(rows.length===manifest.functions.length,'PORTABLE_UPDATE_COHORT_INCOMPLETE');
 const output=path.join(s.dir,'private','functions-'+randomBytes(4).toString('hex'));await fs.mkdir(output);
 const baseEnvironment=await functionEnvironment(s,c,fixtureMode);
 const receipts={},updated=[],resumed=[],reused=[];
 for(const component of manifest.functions){
   const environment={...baseEnvironment,...(component==='mcp-gateway-py'&&s.product?.mcpOAuth
     ?{SALMORA_MCP_OAUTH_CONFIG:JSON.stringify(s.product.mcpOAuth)}:{})};
   console.log(JSON.stringify({event:'CHECK_FUNCTION',component}));
   const evidence=[];const capture=async(label,value)=>{
      evidence.push({label,...(value?.value?.$id?{id:value.value.$id}:{})});
      await write(path.join(output,component+'-events.json'),evidence);
      if(label.endsWith('-failed'))await write(path.join(output,component+'-failure.private.json'),value);
   };
   const existing=rows.find(f=>f.$id===component),prior=s.product.functions?.[component];
   const archive=await prepareArchive({sourceRoot:source,output,component,python,
     publicCa:path.join(s.dir,'secrets/ca.crt'),allowedComponents:manifest.functions});
   const executeRoles=['mcp-gateway-py','salmora-devices-py'].includes(component)?['any']:['users'];
   const scopes=component==='salmora-devices-py'?[]:undefined;
   if(existing)await verifyFunctionConfiguration({request,functionId:component,environment,executeRoles,scopes});
   let pending=s.product.pendingFunctions?.[component];
   if(pending&&retryFailed){
     const observed=(await request('GET','/functions/'+component+'/deployments/'+pending.deploymentId)).value;
     if(['failed','canceled'].includes(observed.status)){
       requireThat(existing?.deploymentId===pending.previousDeploymentId&&prior?.deploymentId===pending.previousDeploymentId,'PORTABLE_FAILED_BUILD_ACTIVE');
       s.product.failedFunctions=[...(s.product.failedFunctions??[]),{...pending,status:observed.status}];
       delete s.product.pendingFunctions[component];await save(s);pending=null;
     }
   }
   if(pending){
     requireThat(pending.nativeInputsSha256===archive.identity.inputsSha256&&pending.publicCaSha256===archive.publicCaSha256,'PORTABLE_PENDING_SOURCE_DRIFT');
     requireThat(existing&&[pending.previousDeploymentId,pending.deploymentId].includes(existing.deploymentId),'PORTABLE_FUNCTION_SOURCE_UNKNOWN');
     await poll({label:component,save:capture,
       read:async()=>(await request('GET','/functions/'+component+'/deployments/'+pending.deploymentId)).value,
       ready:value=>value.status==='ready',failed:value=>['failed','canceled'].includes(value.status)});
     const active=(await request('GET','/functions/'+component)).value;
     requireThat(active.deploymentId===pending.deploymentId,'PORTABLE_FUNCTION_ACTIVATION_UNCONFIRMED');
     const {previousDeploymentId,...receipt}=pending;
     receipts[component]=receipt;resumed.push(component);
   }else if(existing){
     requireThat(prior?.deploymentId===existing.deploymentId,'PORTABLE_FUNCTION_SOURCE_UNKNOWN');
     requireThat(prior.publicCaSha256===archive.publicCaSha256,'PORTABLE_FUNCTION_CA_DRIFT');
     const ready=(await request('GET','/functions/'+component+'/deployments/'+prior.deploymentId)).value;
     requireThat(ready.status==='ready'&&existing.enabled&&!existing.schedule&&!existing.events.length,'PORTABLE_FUNCTION_CONFIG_DRIFT');
     if(prior.nativeInputsSha256===archive.identity.inputsSha256){receipts[component]=prior;reused.push(component);continue;}
     requireThat(update,'PORTABLE_FUNCTION_INPUT_DRIFT');
   }
   const wrapped=(method,route,body,headers)=>request(method,route,
     method==='POST'&&route==='/functions'?{...body,name:component,logging:false,
       scopes:component==='salmora-devices-py'?[]:body.scopes}:body,headers);
   if(!receipts[component]){
   console.log(JSON.stringify({event:'DEPLOY_FUNCTION',component}));
   receipts[component]=await deploy({request:wrapped,component,functionId:component,archive,environment,save:capture,
     existing:Boolean(existing),scopes:component==='salmora-devices-py'?[]:undefined,
     executeRoles:['mcp-gateway-py','salmora-devices-py'].includes(component)?['any']:['users'],
     register:async value=>{
       await write(path.join(output,component+'-deployment.json'),value);
       Object.assign(s,await load(s.dir));
       s.product.pendingFunctions={...s.product.pendingFunctions,[component]:{
         functionId:component,deploymentId:value.deploymentId,component,
         nativeInputsSha256:archive.identity.inputsSha256,archiveSha256:archive.archiveSha256,
         publicCaSha256:archive.publicCaSha256,previousDeploymentId:existing?.deploymentId??null}};
       await save(s);
     }});
   updated.push(component);
   }
   Object.assign(s,await load(s.dir));
   s.product.functions={...s.product.functions,[component]:receipts[component]};
   if(s.product.pendingFunctions)delete s.product.pendingFunctions[component];
   if(prior&&prior.deploymentId!==receipts[component].deploymentId)
     s.product.previousFunctions={...s.product.previousFunctions,[component]:prior};
   await save(s);
 }
 await write(path.join(s.dir,'evidence/product-functions.json'),{status:'PASS',functions:receipts});
 return {status:'INSTALLED',count:Object.keys(receipts).length,updated,resumed,reused};
}
async function copyTree(source,destination){
 await fs.mkdir(destination,{recursive:true});
 for(const item of await fs.readdir(source,{withFileTypes:true})){
  if(item.name.startsWith('.')||['node_modules','dist','__pycache__'].includes(item.name))continue;
  requireThat(!item.isSymbolicLink(),'PORTABLE_BUILD_SYMLINK');
  if(item.isDirectory())await copyTree(path.join(source,item.name),path.join(destination,item.name));
  else if(item.isFile())await fs.copyFile(path.join(source,item.name),path.join(destination,item.name));
 }
}
export async function buildWeb(s,source=ROOT,{activate=true}={}){
 const manifest=await read(path.join(HERE,'product-manifest.json')),pins=await read(path.join(s.dir,'images.lock.json'));
 const context=path.join(s.dir,'private','web-'+randomBytes(4).toString('hex'));await fs.mkdir(context);
 for(const name of ['apps/web','apps/mcp-bridge','packages/catalog','packages/shared-contracts','packages/contracts','packages/local-runtime-protocol','dev/tests/fixtures','services/appwrite-functions/runs-create-py','tools/build','infra/portable']){
  if(await fs.stat(path.join(source,name)).catch(()=>null))await copyTree(path.join(source,name),path.join(context,name));
 }
 for(const name of ['package.json','package-lock.json'])await fs.copyFile(path.join(source,name),path.join(context,name));
 const revision=(await execute('git',['rev-parse','HEAD'],{cwd:source,windowsHide:true})).stdout.trim();
 const inputs={};
 async function hashes(dir){for(const x of await fs.readdir(dir,{withFileTypes:true})){
  const p=path.join(dir,x.name);if(x.isDirectory())await hashes(p);else inputs[path.relative(context,p).replaceAll('\\','/')]=sha(await fs.readFile(p));}}
 await hashes(context);
 await write(path.join(context,'public-build.json'),{schemaVersion:'salmora.portable-build.v1',sourceCommit:revision,
   sourceInputs:inputs,projectId:s.product.projectId,profile:manifest.profile,components:manifest.functions});
 const tag='salmora-portable-web:'+s.project;
 await docker(s,['build','--build-arg','NODE_IMAGE='+pins.node.reference,'--build-arg','CADDY_IMAGE='+pins.caddy.reference,
   '-f',path.join(context,'infra/portable/Web.Dockerfile'),'-t',tag,context],{timeout:900000});
 Object.assign(s,await load(s.dir));
 s.product.webImage=await docker(s,['image','inspect',tag,'--format','{{.Id}}']);
 s.product.webSourceDigest=sha(Buffer.from(JSON.stringify(inputs)));
 s.product.webMcpVersion=1;
 await fs.writeFile(path.join(s.dir,'config/Caddyfile'),(await fs.readFile(path.join(HERE,'Caddyfile.product'),'utf8')).replaceAll('\r\n','\n').replace('# F09_MCP_ROUTES',mcpRoutes(Boolean(s.product.mcpOAuth))));
 await save(s);
 if(activate){
  await dc(s,['up','-d','--no-deps','--pull','never',...(s.product.mcpOAuth?['mcp']:[]),'gateway',...(edgeEnabled(s)?['public-edge']:[])]);
  await refreshEndpoint(s);
 }
 await write(path.join(s.dir,'evidence/product-web.json'),{status:'PASS',image:s.product.webImage,sourceCommit:revision,inputs});
 return {status:'BUILT',image:s.product.webImage,sourceCommit:revision};
}
export async function configureWorker(s,tenants){
 const c=await read(path.join(s.dir,'private/appwrite.private.json'));
 requireThat(Array.isArray(tenants)&&tenants.length&&tenants.every(t=>/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(t)),'PORTABLE_TENANTS_REQUIRED');
 await write(path.join(s.dir,'worker/worker.private.json'),{version:1,
  temporal:{target:'temporal:7233',namespace:'salmora',task_queue:'salmora-portable'},
  sql:{host:'app-postgres',port:5432,dbname:'salmora',schema:'salmora_app',user:'salmora_runtime',
    password:(await fs.readFile(path.join(s.dir,'secrets/app-runtime.password'),'utf8')).trim(),
    sslmode:'verify-full',sslrootcert:'/run/worker/ca.crt'},
  bytes:{provider:'appwrite',endpoint:'http://appwrite/v1',project_id:c.projectId,bucket_id:c.bucketId,api_key:c.workerKey,max_artifact_bytes:16777216},
  tenants,local_agent_enabled:true,
  worker:{max_activities:4,max_workflows:8,continue_after_nodes:20,session_lease_seconds:12,heartbeat_seconds:2}});
 return {status:'CONFIGURED',tenants:tenants.length};
}
export async function networkMode(s,sealed){
 requireThat(s.product?.webImage&&s.product?.functions,'PORTABLE_INSTALL_REQUIRED');
 await stop(s);
 const executor='r0e-'+sha(Buffer.from(s.project)).slice(0,10);
 const ids=(await docker(s,['ps','-aq','--filter','label=openruntimes-executor='+executor])).split(/\s+/).filter(Boolean);
 for(const id of ids){
  const x=JSON.parse(await docker(s,['inspect',id]))[0];
  requireThat(!x.State.Running&&x.Name.startsWith('/'+executor+'-')&&Date.parse(x.Created)>=Date.parse(s.createdAt),'PORTABLE_CHILD_OWNERSHIP');
  await docker(s,['rm',id]);
 }
 // Include the opt-in worker so no stopped container keeps a deleted network ID.
 await inventory(s);await dc(s,['--profile','execution','down'],{timeout:120000});
 // Upgrade keeps the public TLS listener in 503 mode through the temporary build network.
 // Ordinary function maintenance still disables public ingress completely.
 if(s.publicEdge&&!s.upgradeHold){
   if(!sealed&&s.publicEdge.state==='enabled')s.publicEdge={...s.publicEdge,state:'held',reason:'maintenance'};
   else if(sealed&&s.publicEdge.state==='held'&&s.publicEdge.reason==='maintenance')s.publicEdge={...s.publicEdge,state:'enabled',reason:undefined};
 }
 s.cloudBlocked=sealed;await save(s);await up(s);
 if(sealed&&!s.upgradeHold&&await fs.stat(path.join(s.dir,'worker/worker.private.json')).catch(()=>false))await workers(s);
 return {status:sealed?'SEALED':'BUILD_MAINTENANCE',runtimeExternalEgress:!sealed};
}
export async function seal(s){return networkMode(s,true);}

export async function maintainFunctions(s,options={}){
 requireThat(!s.upgradeHold,'UPGRADE_MAINTENANCE_HELD');
 // Explicit maintenance only: allow dependency downloads while this owned
 // installation is restarted, then restore Cloud-blocked runtime in finally.
 requireThat(s.cloudBlocked===true,'PORTABLE_SEALED_INSTALL_REQUIRED');
 const report={status:'IN_PROGRESS',startedAt:new Date().toISOString()};
 const evidence=path.join(s.dir,'evidence','function-maintenance-'+randomBytes(4).toString('hex')+'.json');
 await write(evidence,report);
 try{
   await networkMode(s,false);
   report.functions=await installFunctions(s,{...options,update:true,retryFailed:true});
   report.status='PASS';
 }catch(error){report.status='FAIL';report.code=error.message;throw error;}
 finally{
   Object.assign(s,await load(s.dir));
   try{report.network=await seal(s);}
   catch(error){report.status='FAIL';report.networkError=error.message;throw error;}
   finally{report.finishedAt=new Date().toISOString();await write(evidence,report);}
 }
 return report;
}

async function main(){
 const [action,dir,...rest]=process.argv.slice(2);const s=await load(dir);await engine(s);
 const result=action==='provision'?await provision(s):
  action==='functions'?await installFunctions(s,{python:rest[0]||'python'}):
  action==='update-functions'?await installFunctions(s,{python:rest[0]||'python',update:true}):
  action==='maintain-functions'?await maintainFunctions(s,{python:rest[0]||'python'}):
  action==='web'?await buildWeb(s):action==='worker'?await configureWorker(s,rest):
  action==='seal'?await seal(s):(()=>{throw new Error('PORTABLE_PRODUCT_COMMAND_INVALID');})();
 console.log(JSON.stringify(result));
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))
 main().catch(e=>{console.error(e.message);process.exitCode=1;});
