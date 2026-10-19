import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {load,read,docker,engine,inventory,save,write,sha,requireThat} from '../../../infra/portable/operator.mjs';
import {volumeNames} from '../../../infra/portable/deployment.mjs';
import {cleanupBuilds} from './cleanup-builds.mjs';
import {minimalContainerInventory,observeForeignDrift,assertOwnedRemovalTarget,assertSentinel,exactContainerAbsent} from '../../../verification/adapters/portable/sentinel.mjs';
const lines=raw=>raw.trim().split(/\r?\n/).filter(Boolean);
const ids=raw=>raw.trim().split(/\s+/).filter(Boolean);
const owner='io.appwritework.portable';
const cid=value=>requireThat(/^[a-f0-9]{64}$/.test(value),'CLEAN_TRIAL_CONTAINER_ID_INVALID');
const publicCodes=new Set(['CLEAN_TRIAL_SENTINEL_REQUIRED','CLEAN_TRIAL_CONTAINER_ID_INVALID','CLEAN_TRIAL_CHILD_INVENTORY',
  'CLEAN_TRIAL_COMPOSE_OWNERSHIP','CLEAN_TRIAL_CHILD_OWNERSHIP','CLEAN_TRIAL_DUPLICATE_CONTAINER','CLEAN_TRIAL_QUIESCENCE_REQUIRED',
  'CLEAN_TRIAL_NETWORK_OWNERSHIP','CLEAN_TRIAL_VOLUME_OWNERSHIP','CLEAN_TRIAL_VOLUME_IN_USE','CLEAN_TRIAL_CONTAINER_REMAINS',
  'CLEAN_TRIAL_VOLUME_REMAINS','CLEAN_TRIAL_NETWORK_REMAINS','CLEAN_TRIAL_TARGET_CHANGED','CLEAN_TRIAL_ONLY','CLEAN_BUILD_METADATA',
  'CLEAN_BUILD_OWNERSHIP','CLEAN_BUILD_VOLUME_BINDING','CLEAN_BUILD_SIDECAR_OWNERSHIP','CLEAN_BUILD_COMPOSE_COHORT',
  'CLEAN_BUILD_WORKSPACE_OWNERSHIP','CLEAN_BUILD_WORKSPACE_IN_USE','SENTINEL_RECORD_INVALID','SENTINEL_INSPECTION_INVALID',
  'SENTINEL_SURVIVAL_UNCONFIRMED','SENTINEL_IDENTITY_CHANGED','SENTINEL_CONFIGURATION_CHANGED','SENTINEL_INVENTORY_INVALID','SENTINEL_OUTSIDE_OWNED_REMOVAL_SET',
  'OWNED_CONTAINER_ABSENCE_UNCONFIRMED']);
const safeCode=error=>publicCodes.has(error.message)?error.message:'CLEAN_TRIAL_OPERATOR_FAILED';

// Sentinel failures remain FAIL without bypassing the independently owned teardown.
// This helper never releases a sentinel; that operation belongs to the parent.
export async function cleanupTrial({state,beforeFile,output,sentinelFile},dependencies={}) {
  const api={load,read,docker,engine,inventory,save,write,cleanupBuilds,
    writeFailures:async(s,errors)=>{if(errors.length)await fs.appendFile(path.join(s.dir,'private/cleanup-error.private.log'),errors.join('\n')+'\n',{mode:0o600});},
    readBefore:async file=>lines(await fs.readFile(file,'utf8')).map(JSON.parse),...dependencies};
  const s=await api.load(state),run=async(args,options)=>{await api.engine(s);return api.docker(s,args,options);};
  requireThat(/^sm9-m10-clean-[a-z0-9-]+$/.test(s.project)&&s.deploymentBinding,'CLEAN_TRIAL_BINDING');
  const report={status:'IN_PROGRESS',project:s.project,failures:[],sentinel:{before:{status:'NOT_RUN'},after:{status:'NOT_RUN'}}};
  const rawFailures=[];
  const failed=(phase,error)=>{rawFailures.push(phase+': '+String(error.stack??error));report.failures.push({phase,code:safeCode(error)});};
  let sentinel,before=[],owned=[],children=[],builds={};
  try { await api.engine(s); } catch(error) {
    failed('local-engine',error);report.status='FAIL';report.checkedAt=new Date().toISOString();
    await api.writeFailures(s,rawFailures);await api.write(output,report);return report;
  }
  try {
    requireThat(sentinelFile,'CLEAN_TRIAL_SENTINEL_REQUIRED');sentinel=await api.read(sentinelFile);
    report.sentinel.before=await assertSentinel({docker:run,record:sentinel});
  } catch(error) { report.sentinel.before={status:'FAIL',code:safeCode(error)};failed('sentinel-before',error); }
  try { before=await api.readBefore(beforeFile); } catch(error) { failed('inventory-before',error); }
  try {
    owned=await api.inventory(s);
    const executor='r0e-'+sha(Buffer.from(s.project)).slice(0,10);
    const childIds=ids(await run(['ps','-aq','--no-trunc','--filter','label=openruntimes-executor='+executor]));
    childIds.forEach(cid);
    children=childIds.length?JSON.parse(await run(['inspect',...childIds])):[];
    requireThat(children.length===childIds.length,'CLEAN_TRIAL_CHILD_INVENTORY');
    // Resolve and validate the complete removal cohort before its first mutation.
    for(const row of owned) {
      cid(row.Id);const labels=row.Config?.Labels??{};
      requireThat(labels[owner]===s.project&&labels['com.docker.compose.project']===s.project
        &&typeof labels['com.docker.compose.service']==='string'&&labels['com.docker.compose.service'].length>0
        &&(labels['com.docker.compose.service']==='executor'?row.Name==='/'+executor:row.Name.startsWith('/'+s.project+'-'))
        &&Date.parse(row.Created)>=Date.parse(s.createdAt),'CLEAN_TRIAL_COMPOSE_OWNERSHIP');
    }
    for(const row of children) {
      cid(row.Id);
      requireThat(childIds.includes(row.Id)&&row.Config?.Labels?.['openruntimes-executor']===executor
        &&row.Name.startsWith('/'+executor+'-')&&Date.parse(row.Created)>=Date.parse(s.createdAt),'CLEAN_TRIAL_CHILD_OWNERSHIP');
    }
    const ownedIds=[...owned,...children].map(row=>row.Id);
    requireThat(new Set(ownedIds).size===ownedIds.length,'CLEAN_TRIAL_DUPLICATE_CONTAINER');
    for(const id of ownedIds)assertOwnedRemovalTarget(id,ownedIds,sentinel?.id);
    const absent=new Set(),removed=new Set();
    async function confirmedAbsent(id){
      if(!await exactContainerAbsent({docker:run,id,ownedIds,sentinelId:sentinel?.id}))return false;
      absent.add(id);return true;
    }
    async function mutateContainer(args,id){
      assertOwnedRemovalTarget(id,ownedIds,sentinel?.id);
      try{await run(args);return true;}
      catch(error){if(await confirmedAbsent(id))return false;throw error;}
    }
    async function revalidate(original) {
      let raw;
      try{raw=await run(['inspect',original.Id]);}
      catch(error){if(await confirmedAbsent(original.Id))return null;throw error;}
      const rows=JSON.parse(raw),row=rows[0];
      requireThat(rows.length===1&&row.Id===original.Id&&row.Name===original.Name&&row.Created===original.Created,'CLEAN_TRIAL_TARGET_CHANGED');
      const labels=row.Config?.Labels??{};
      if(owned.includes(original))requireThat(labels[owner]===s.project&&labels['com.docker.compose.project']===s.project
        &&labels['com.docker.compose.service']===original.Config.Labels['com.docker.compose.service'],'CLEAN_TRIAL_COMPOSE_OWNERSHIP');
      else requireThat(labels['openruntimes-executor']===executor,'CLEAN_TRIAL_CHILD_OWNERSHIP');
      return row;
    }
    const order=['public-edge','gateway','mcp','execution-worker','worker','appwrite','orchestrator','executor'];
    const attemptTarget=async(phase,action)=>{
      try{return {ok:true,value:await action()};}
      catch(error){failed(phase,error);return {ok:false};}
    };
    const early=owned.filter(row=>order.includes(row.Config.Labels['com.docker.compose.service']))
      .sort((a,b)=>order.indexOf(a.Config.Labels['com.docker.compose.service'])-order.indexOf(b.Config.Labels['com.docker.compose.service']));
    for(const row of [...early,...children,...owned.filter(row=>!early.includes(row))]) {
      await attemptTarget('owned-stop',async()=>{
        assertOwnedRemovalTarget(row.Id,ownedIds,sentinel?.id);
        if((await revalidate(row))?.State.Running)await mutateContainer(['stop','-t','60',row.Id],row.Id);
      });
    }
    let quiesced=true;
    for(const original of [...owned,...children]) {
      const checked=await attemptTarget('owned-quiescence',async()=>{
        const row=await revalidate(original);
        requireThat(row===null||!row.State.Running,'CLEAN_TRIAL_QUIESCENCE_REQUIRED');
      });
      if(!checked.ok)quiesced=false;
    }
    if(quiesced){
      s.quiesced=true;s.checkpointAt=new Date().toISOString();await api.save(s);
      const built=await attemptTarget('owned-builds',async()=>{await api.engine(s);return api.cleanupBuilds(s,{sentinelId:sentinel?.id,
        onFailure:async error=>failed('owned-build-target',error)});});
      if(built.ok)builds=built.value;
    }
    for(const row of [...children,...owned]) {
      await attemptTarget('owned-remove',async()=>{
        assertOwnedRemovalTarget(row.Id,ownedIds,sentinel?.id);
        const current=await revalidate(row);
        if(current===null)return;
        requireThat(!current.State.Running,'CLEAN_TRIAL_QUIESCENCE_REQUIRED');
        if(await mutateContainer(['rm',row.Id],row.Id))removed.add(row.Id);
      });
    }
    const expectedNetworks=new Set([s.project+'-network',s.project+'_private',s.project+'_ingress',s.project+'_public-ingress',s.project+'_mail-egress']);
    const networks=ids(await run(['network','ls','-q','--no-trunc','--filter','label='+owner+'='+s.project]));
    for(const id of networks) {
      await attemptTarget('owned-network',async()=>{
      cid(id);const rows=JSON.parse(await run(['network','inspect',id])),network=rows[0];
      requireThat(rows.length===1&&network.Id===id&&expectedNetworks.has(network.Name)&&network.Labels?.[owner]===s.project
        &&Object.keys(network.Containers??{}).length===0,'CLEAN_TRIAL_NETWORK_OWNERSHIP');
      await run(['network','rm',id]);
      });
    }
    const expectedVolumes=new Set(volumeNames(s).map(name=>s.project+'-'+name));
    const volumes=lines(await run(['volume','ls','--format','{{.Name}}'])).filter(name=>name.startsWith(s.project+'-'));
    for(const name of volumes) {
      await attemptTarget('owned-volume',async()=>{
      const rows=JSON.parse(await run(['volume','inspect',name])),volume=rows[0];
      requireThat(rows.length===1&&expectedVolumes.has(name)&&volume.Name===name&&volume.Labels?.[owner]===s.project,'CLEAN_TRIAL_VOLUME_OWNERSHIP');
      requireThat(!ids(await run(['ps','-aq','--no-trunc','--filter','volume='+name])).length,'CLEAN_TRIAL_VOLUME_IN_USE');
      await run(['volume','rm',name]);
      });
    }
    const after=await minimalContainerInventory(run);
    report.foreignDrift=observeForeignDrift(before,after,[...ownedIds,...(sentinel?.id?[sentinel.id]:[])]);
    const c=await api.read(path.join(s.dir,'private/appwrite.private.json'));
    const remainingContainers=after.filter(row=>row.Names.startsWith(s.project+'-')||row.Names===executor||row.Names.startsWith(executor+'-')||row.Names.startsWith('job-'+c.projectId+'-'));
    const remainingVolumes=lines(await run(['volume','ls','--format','{{.Name}}'])).filter(name=>name.startsWith(s.project+'-')||name.startsWith('job-'+c.projectId+'-'));
    const remainingNetworks=ids(await run(['network','ls','-q','--no-trunc','--filter','label='+owner+'='+s.project]));
    Object.assign(report,{composeContainersRemovedThisPass:owned.filter(row=>removed.has(row.Id)).length,
      runtimeChildrenRemovedThisPass:children.filter(row=>removed.has(row.Id)).length,alreadyAbsentOwnedContainers:[...absent],...builds,
      remainingOwnedContainers:remainingContainers.length,remainingOwnedVolumes:remainingVolumes.length,
      remainingOwnedNetworks:remainingNetworks.length,resumedAfterComposeRemoval:owned.length===0});
    requireThat(!remainingContainers.length,'CLEAN_TRIAL_CONTAINER_REMAINS');
    requireThat(!remainingVolumes.length,'CLEAN_TRIAL_VOLUME_REMAINS');
    requireThat(!remainingNetworks.length,'CLEAN_TRIAL_NETWORK_REMAINS');
  } catch(error) { failed('owned-cleanup',error); }
  try { report.sentinel.after=await assertSentinel({docker:run,record:sentinel}); }
  catch(error) { report.sentinel.after={status:'FAIL',code:safeCode(error)};failed('sentinel-after',error); }
  report.status=report.failures.length?'FAIL':'PASS';report.checkedAt=new Date().toISOString();
  await api.writeFailures(s,rawFailures);await api.write(output,report);return report;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  const [state,beforeFile,output,sentinelFile]=process.argv.slice(2);
  cleanupTrial({state,beforeFile,output,sentinelFile}).then(report=>{
    console.log(JSON.stringify({status:report.status,project:report.project,failures:report.failures}));
    if(report.status!=='PASS')process.exitCode=1;
  }).catch(()=>{console.error('CLEAN_TRIAL_OPERATOR_FAILED');process.exitCode=1;});
}
