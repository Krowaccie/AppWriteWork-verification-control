// Disposable M10 trial builds only. Never print Docker labels: callback keys are secrets.
import path from 'node:path';
import {read,docker,engine,requireThat,inventory} from '../../../infra/portable/operator.mjs';
import {assertOwnedRemovalTarget,exactContainerAbsent} from '../../../verification/adapters/portable/sentinel.mjs';

export function ownedBuild(x,s,c,jobsSecret){
  let meta;try{meta=JSON.parse(x.Config.Labels?.['job.meta']);}catch{throw new Error('CLEAN_BUILD_METADATA');}
  const receipt=s.product?.functions?.[meta.resourceId];
  const stem='job-'+c.projectId+'-'+meta.deploymentId+'-build';
  requireThat(!x.State.Running&&x.Config.Labels['managed-by']==='jobs-service'&&x.Config.Labels['job.type']==='worker'&&
    x.Config.Labels['job.callback.key']===jobsSecret&&meta.projectId===c.projectId&&meta.resourceType==='functions'&&
    receipt?.deploymentId===meta.deploymentId&&x.Name==='/'+stem+'-worker'&&
    Date.parse(x.Created)>=Date.parse(s.createdAt),'CLEAN_BUILD_OWNERSHIP');
  const names=x.Mounts.filter(m=>m.Type==='volume').map(m=>m.Name).sort();
  requireThat(names.length===2&&names.includes(s.project+'-builds')&&names.includes(stem+'-workspace'),'CLEAN_BUILD_VOLUME_BINDING');
  return {id:x.Id,workspace:stem+'-workspace',deploymentId:meta.deploymentId};
}
export function ownedSidecar(x,s,c,job,image){
  const stem='job-'+c.projectId+'-'+job.deploymentId+'-build';
  requireThat(!x.State.Running&&x.Name==='/'+stem+'-sidecar'&&x.Config.Image===image&&
    x.Config.Labels?.['managed-by']==='jobs-service'&&x.Config.Labels['job.type']==='sidecar'&&
    x.Config.Labels['job.id']===stem.slice(4)&&Date.parse(x.Created)>=Date.parse(s.createdAt)&&
    x.Mounts.length===1&&x.Mounts[0].Type==='volume'&&x.Mounts[0].Name===job.workspace,'CLEAN_BUILD_SIDECAR_OWNERSHIP');
  return {id:x.Id,workspace:job.workspace,deploymentId:job.deploymentId};
}
// These stopped Compose services legitimately mount the shared builds volume.
// They are left to the later Compose teardown, never adopted as build jobs.
export function buildJobMounters(rows,s,cohort){
  const known=new Map(cohort.map(x=>[x.Id,x]));
  return rows.filter(x=>{
    const expected=known.get(x.Id);
    if(!expected)return true; // The strict native-build proof still applies.
    const labels=x.Config.Labels??{},service=labels['com.docker.compose.service'];
    requireThat(!x.State.Running&&!expected.State.Running&&
      labels['io.appwritework.portable']===s.project&&labels['com.docker.compose.project']===s.project&&
      expected.Config.Labels?.['io.appwritework.portable']===s.project&&
      expected.Config.Labels?.['com.docker.compose.project']===s.project&&
      expected.Config.Labels?.['com.docker.compose.service']===service&&
      ['appwrite','worker','executor','orchestrator'].includes(service)&&
      !labels['job.meta']&&!labels['job.type']&&!labels['managed-by']&&
      Date.parse(x.Created)>=Date.parse(s.createdAt),'CLEAN_BUILD_COMPOSE_COHORT');
    return false;
  });
}
export async function cleanupBuilds(s,{sentinelId,onFailure}={},dependencies={}){
  const api={read,docker,engine,inventory,...dependencies};
  await api.engine(s);
  const c=await api.read(path.join(s.dir,'private/appwrite.private.json'));
  requireThat(/^sm9-m10-clean-[a-z0-9-]+$/.test(s.project)&&s.quiesced===true&&c.cleanBinding===s.deploymentBinding&&
    c.owner?.email.endsWith('@portable.invalid')&&!c.source,'CLEAN_TRIAL_ONLY');
  const secrets=await api.read(path.join(s.dir,'private/secrets.private.json'));
  const ids=(await api.docker(s,['ps','-aq','--no-trunc','--filter','volume='+s.project+'-builds'])).split(/\s+/).filter(Boolean);
  const rows=ids.length?JSON.parse(await api.docker(s,['inspect',...ids])):[];
  const cohort=await api.inventory(s);
  const jobs=buildJobMounters(rows,s,cohort).map(x=>ownedBuild(x,s,c,secrets.R0_JOBS_SECRET));
  // Resolve the entire deletion set before removing anything. Known receipt IDs
  // also reconcile a crash after container removal but before workspace removal.
  const existing=(await api.docker(s,['volume','ls','--format','{{.Name}}'])).split(/\s+/);
  const workspaces=[],sidecars=[];
  const pins=await api.read(path.join(s.dir,'images.lock.json'));
  for(const receipt of Object.values(s.product.functions??{})){
    const name='job-'+c.projectId+'-'+receipt.deploymentId+'-build-workspace';
    if(!existing.includes(name))continue;
    const v=JSON.parse(await api.docker(s,['volume','inspect',name]))[0];
    requireThat(v.Name===name&&v.Driver==='local'&&Date.parse(v.CreatedAt)>=Date.parse(s.createdAt),'CLEAN_BUILD_WORKSPACE_OWNERSHIP');
    const users=(await api.docker(s,['ps','-aq','--no-trunc','--filter','volume='+name])).split(/\s+/).filter(Boolean);
    for(const id of users){
      if(jobs.some(j=>j.id===id&&j.workspace===name))continue;
      const x=JSON.parse(await api.docker(s,['inspect',id]))[0];
      sidecars.push(ownedSidecar(x,s,c,{workspace:name,deploymentId:receipt.deploymentId},pins.jobSidecar.reference));
    }
    workspaces.push(name);
  }
  const ownedIds=[...sidecars,...jobs].map(row=>row.id);
  for(const id of ownedIds)assertOwnedRemovalTarget(id,ownedIds,sentinelId);
  const failures=[],absent=new Set(),removed=new Set(),removedWorkspaces=new Set();
  const run=async args=>{await api.engine(s);return api.docker(s,args);};
  const attempt=async action=>{try{await action();}catch(error){failures.push(error);if(onFailure)await onFailure(error);}};
  const confirmAbsent=async id=>{
    if(!await exactContainerAbsent({docker:run,id,ownedIds,sentinelId}))return false;
    absent.add(id);return true;
  };
  async function remove(row,validate){
    let raw;
    try{raw=await run(['inspect',row.id]);}catch(error){if(await confirmAbsent(row.id))return;throw error;}
    const inspected=JSON.parse(raw);
    requireThat(inspected.length===1&&inspected[0].Id===row.id,'CLEAN_BUILD_OWNERSHIP');validate(inspected[0]);
    assertOwnedRemovalTarget(row.id,ownedIds,sentinelId);
    try{await run(['rm',row.id]);removed.add(row.id);}catch(error){if(!await confirmAbsent(row.id))throw error;}
  }
  for(const sidecar of sidecars)await attempt(()=>remove(sidecar,x=>ownedSidecar(x,s,c,sidecar,pins.jobSidecar.reference)));
  for(const job of jobs)await attempt(()=>remove(job,x=>ownedBuild(x,s,c,secrets.R0_JOBS_SECRET)));
  for(const name of workspaces){
    await attempt(async()=>{
    requireThat(!(await api.docker(s,['ps','-aq','--filter','volume='+name])),'CLEAN_BUILD_WORKSPACE_IN_USE');
    await api.engine(s);await api.docker(s,['volume','rm',name]);removedWorkspaces.add(name);
    });
  }
  if(failures.length&&!onFailure)throw new AggregateError(failures,'CLEAN_BUILD_TARGET_FAILURE');
  return {buildWorkersRemoved:jobs.filter(row=>removed.has(row.id)).length,
    buildSidecarsRemoved:sidecars.filter(row=>removed.has(row.id)).length,
    buildWorkspacesRemoved:removedWorkspaces.size,
    alreadyAbsentBuildContainers:[...absent],buildTargetFailures:failures.length};
}
