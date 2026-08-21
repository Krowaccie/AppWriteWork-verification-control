import { createHash, randomBytes as cryptoRandomBytes } from 'node:crypto';
import { types as utilTypes } from 'node:util';
import { canonicalJson, sha256Bytes } from './canonical-json.mjs';
import {
  isAuthenticTestEnvironmentContext,
  isAuthenticTestRecoveryEnvironmentContext,
} from './test-cloud-environment.mjs';
import { isAuthenticTestCloudPreflightResult } from './test-cloud-preflight.mjs';
import { isAuthenticProviderRecoveryControlStore } from './test-cloud-provider-control-store.mjs';
import {
  CLEANUP_PROTOCOL_DIGEST,
  QUALIFIED_CLEANUP_PROTOCOL,
  RECOVERY_CHECKPOINT_SCHEMA_VERSION,
  advanceCleanupPhaseDigest,
  advanceCleanupProgressDigest,
  advanceCleanupProofDigest,
  createCleanupPhaseGenesisDigest,
  createCleanupProgressGenesisDigest,
  createCleanupProofGenesisDigest,
  createOrdinaryExecutionEvidenceDigest,
  createRecoveryAuditEventDigest,
  createRecoveryCheckpointDigest,
  createRecoveryCurrentIntentSetDigest,
  createRecoveryIntentSetDigest,
  deriveRecoveryPosition,
  validateRecoveryAuditEvent,
  validateRecoveryCheckpoint,
  validateRecoveryCheckpointSuccessor,
  validateRecoveryIntentRow,
} from './test-cloud-cleanup-protocol.mjs';
import inventory from '../../dev/verification/environments/test-cloud.inventory.v1.json' with { type: 'json' };

const V1_INTENT_KEYS=['schemaVersion','intentId','runId','environmentDigest','resourceType','resourceId','providerResourceIds','ownerMarker','dependencyOrder','lifecycleClass','state','intentVersion','observationDigest','retentionExpiresAt','createdAt','updatedAt'];
const V2_CLEANUP_KEYS=['cleanupCursor','cleanupProgressDigest','cleanupProofDigest','cleanupRunnerExecutionPlanDigest','cleanupRunnerExecutionCursor','cleanupRunnerExecutionSlotsJson','cleanupRunnerExecutionRecordDigest','cleanupRunnerExecutionRetentionExpiresAt'];
const V2_INTENT_KEYS=['schemaVersion','intentId','runId','environmentDigest','resourceType','resourceId','providerAggregateJson','providerAggregateDigest','ownerMarker','dependencyOrder','lifecycleClass','state','intentVersion','observationDigest','retentionExpiresAt',...V2_CLEANUP_KEYS,'createdAt','updatedAt'];
const V1_INTENT_IDENTITY_KEYS=['intentId','runId','environmentDigest','resourceType','resourceId','ownerMarker','dependencyOrder','lifecycleClass','createdAt'];
const V2_INTENT_IDENTITY_KEYS=['intentId','runId','environmentDigest','resourceType','resourceId','ownerMarker','dependencyOrder','lifecycleClass','createdAt'];
const INTENT_ID=/^[0-9a-f]{64}$/u;
const RECOVERY_ACCOUNT_SESSION_ID=/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const OWNER_MARKER=/^verification-owner\.v1:sha256:[0-9a-f]{64}$/u;
const EXECUTION_SLOT_KEYS=['logicalPosition','attemptOrdinal','retainedExecutionId','safeStateDigest','retentionExpiresAt'];
const CLEANUP_DEPENDENCY_ORDER=Object.freeze({'primary-share':30,'primary-graph':20,'primary-project':10});
const CLEANUP_RESOURCE_LIMITS=Object.freeze(Object.fromEntries(
  Object.entries(QUALIFIED_CLEANUP_PROTOCOL.resources).map(([resourceType,catalog])=>[
    resourceType,Object.freeze({cleanupCursor:catalog.mutation.length,preflightCount:catalog.preflight.length,
      knownCalls:catalog.executionPlan.knownCalls,
      slotCount:catalog.executionPlan.slotCount,dependencyOrder:CLEANUP_DEPENDENCY_ORDER[resourceType]}),
  ]),
));
export const PRIMARY_EXECUTION_RETENTION_MAX_SECONDS=inventory.control.primaryExecutionRetentionMaxSeconds;
if(PRIMARY_EXECUTION_RETENTION_MAX_SECONDS!==86400)throw new TypeError('primary execution retention policy');
const IS_PROXY=utilTypes.isProxy;
const exactObject=(value,keys)=>{try{return value!==null&&typeof value==='object'&&!Array.isArray(value)&&!IS_PROXY(value)&&Reflect.ownKeys(value).length===keys.length&&keys.every((key)=>{const descriptor=Object.getOwnPropertyDescriptor(value,key);return descriptor?.enumerable===true&&Object.hasOwn(descriptor,'value');});}catch{return false;}};
const DIGEST=/^sha256:[0-9a-f]{64}$/u;
const GENESIS={leaseRowId:'appwrite_test_verification',schemaVersion:'verification-audit-genesis.v1'};
export const GENESIS_LEDGER_DIGEST=sha256Bytes(new TextEncoder().encode(canonicalJson(GENESIS)));
const HANDOFFS=new WeakMap(), USED_HANDOFFS=new WeakSet(), CAPS=new WeakMap(), INVALID_CAPS=new WeakSet(), RUNNER_REQUESTS=new WeakMap();
const encoder=new TextEncoder();
const pass=(value)=>Object.freeze({status:'PASS',value,diagnostics:Object.freeze([])});
const blocked=(code,retryable=false)=>Object.freeze({status:'BLOCKED',value:null,diagnostics:Object.freeze([Object.freeze({code,safeMessage:'Verification control transition was blocked.',retryable})])});
const freeze=(v)=>{if(v&&typeof v==='object'&&!Object.isFrozen(v)){for(const x of Object.values(v))freeze(x);Object.freeze(v);}return v;};
const digest=(v)=>sha256Bytes(encoder.encode(canonicalJson(v)));
const CLEANUP_LEDGER_CEILINGS=freeze({
  semanticTransitions:QUALIFIED_CLEANUP_PROTOCOL.counts.semanticTransitions,
  readOnlyCheckpoints:QUALIFIED_CLEANUP_PROTOCOL.counts.readOnlyCheckpoints,
  knownSuccessStoreTransitions:QUALIFIED_CLEANUP_PROTOCOL.counts.knownSuccessStoreTransitions,
  absoluteStoreTransitions:QUALIFIED_CLEANUP_PROTOCOL.counts.absoluteStoreTransitions,
  resources:Object.fromEntries(Object.entries(CLEANUP_RESOURCE_LIMITS).map(([resourceType,limits])=>[
    resourceType,freeze({...limits,executionPlanDigest:QUALIFIED_CLEANUP_PROTOCOL.resources[resourceType].executionPlan.digest}),
  ])),
});
const iso=(seconds)=>new Date(seconds*1000).toISOString();
const copy=(v)=>structuredClone(v);
const exactIdle=(v)=>v&&v.leaseRowId==='appwrite_test_verification'&&v.state==='idle'&&v.ownerRunId===null&&v.ownerWorkflowRunId===null&&v.environmentDigest===null&&v.acquiredAt===null&&v.renewedAt===null&&v.expiresAt===null&&v.leaseTokenDigest===null&&v.cleanupDebt===false&&Number.isSafeInteger(v.leaseVersion)&&DIGEST.test(v.ledgerDigest);

function initialLease(){return freeze({leaseRowId:'appwrite_test_verification',leaseVersion:0,state:'idle',ownerRunId:null,ownerWorkflowRunId:null,environmentDigest:null,acquiredAt:null,renewedAt:null,expiresAt:null,ledgerDigest:GENESIS_LEDGER_DIGEST,leaseTokenDigest:null,cleanupDebt:false});}
function eventDigest(event){return digest(event);}
function contentId(value){return digest(value).slice(7);}
function validPrimaryExecutionRetentionMaximum(value){return Number.isSafeInteger(value)&&value>=1&&value<=PRIMARY_EXECUTION_RETENTION_MAX_SECONDS;}
function cap(token,lease,context,primaryExecutionRetentionMaxSeconds,providerContractDigest){if(!validPrimaryExecutionRetentionMaximum(primaryExecutionRetentionMaxSeconds)||!DIGEST.test(providerContractDigest))throw new TypeError('capability binding');const value=freeze(Object.create(null));CAPS.set(value,{token,runId:context.runId,environmentDigest:context.environmentDigest,leaseVersion:lease.leaseVersion,ledgerDigest:lease.ledgerDigest,expiresAt:lease.expiresAt,primaryExecutionRetentionMaxSeconds,providerContractDigest});return value;}
function verifyCap(capability,lease,context,now){const b=CAPS.get(capability);return !!b&&!INVALID_CAPS.has(capability)&&b.runId===context.runId&&b.environmentDigest===context.environmentDigest&&b.leaseVersion===lease.leaseVersion&&b.ledgerDigest===lease.ledgerDigest&&b.expiresAt===lease.expiresAt&&Date.parse(lease.expiresAt)>now*1000;}
function rotateCap(old,token,lease,context){const binding=CAPS.get(old);if(!binding)throw new TypeError('capability');INVALID_CAPS.add(old);return cap(token,lease,context,binding.primaryExecutionRetentionMaxSeconds,binding.providerContractDigest);}
function tokenBytes(randomBytes){const bytes=Buffer.from((randomBytes??cryptoRandomBytes)(32));if(bytes.length!==32)throw new TypeError('random');return bytes;}
function tokenDigest(bytes){return`sha256:${createHash('sha256').update(bytes).digest('hex')}`;}
function workflowId(runId){return runId.split('-').at(-2);}
function makeEvent({lease,transition,runId,intentId=null,intentProjectionDigest=null}){return freeze({schemaVersion:'verification-audit-event.v1',previousLedgerDigest:lease.ledgerDigest,runId,leaseVersionBefore:lease.leaseVersion,leaseVersionAfter:lease.leaseVersion+1,transition,intentId,intentProjectionDigest});}

export function createInMemoryControlStore({lease=initialLease()}={}){
  let current=copy(lease);const events=new Map(),snapshots=new Map(),projections=new Map();
  const put=(map,id,value)=>{const bytes=canonicalJson(value);if(map.has(id)&&canonicalJson(map.get(id))!==bytes)return false;map.set(id,copy(value));return true;};
  return Object.freeze({
    async getLease(){return copy(current);}, peekLease(){return copy(current);},
    async transact({expectedLeaseVersion,expectedLedgerDigest,event,snapshot=null,nextLease,nextIntent=null}){if(current.leaseVersion!==expectedLeaseVersion||current.ledgerDigest!==expectedLedgerDigest)return blocked('LEASE_VERSION_MISMATCH',true);const eid=eventDigest(event).slice(7),sid=snapshot?contentId(snapshot):null,eventBytes=canonicalJson(event),snapshotBytes=snapshot?canonicalJson(snapshot):null;if(events.has(eid)&&canonicalJson(events.get(eid))!==eventBytes)return blocked('AUDIT_CHAIN_MISMATCH');if(snapshot&&snapshots.has(sid)&&canonicalJson(snapshots.get(sid))!==snapshotBytes)return blocked('AUDIT_CHAIN_MISMATCH');events.set(eid,copy(event));if(snapshot){snapshots.set(sid,copy(snapshot));if(nextIntent)projections.set(nextIntent.intentId,copy(nextIntent));}current=copy(nextLease);return pass(copy(current));},
    async getAuditEventByDigest(value){return events.has(value.slice(7))?copy(events.get(value.slice(7))):null;},
    async getIntentSnapshotByDigest(value){return snapshots.has(value.slice(7))?copy(snapshots.get(value.slice(7))):null;},
    async getIntentProjection(id){return projections.has(id)?copy(projections.get(id)):null;},
    testingTamperLeaseHead(value){current.ledgerDigest=value;},
  });
}

export function createTestCloudPreflightHandoff(input){
  try{
    if(!exactObject(input,['clock','context','preflight']))return blocked('LEASE_READBACK_MISMATCH');
    const {context,preflight,clock}=input;
    if(
      !isAuthenticTestEnvironmentContext(context)
      ||!isAuthenticTestCloudPreflightResult(preflight,context)
      ||typeof clock?.nowEpochSeconds!=='function'
    )return blocked('LEASE_READBACK_MISMATCH');
    const now=clock.nowEpochSeconds(),value=preflight.value,lease=value?.lease;
    const safeDigests={
      environmentDigest:value?.environmentDigest,
      providerContractDigest:value?.providerContractDigest,
      identityBindingsDigest:value?.identityBindingsDigest,
      providerSetupReadbackDigest:value?.providerSetupReadbackDigest,
      runnerVariableReadbackDigest:value?.runnerVariableReadbackDigest,
    };
    const primaryExecutionRetentionMaxSeconds=value?.primaryExecutionRetentionMaxSeconds;
    if(
      safeDigests.environmentDigest!==context.environmentDigest
      ||!Object.values(safeDigests).every((entry)=>DIGEST.test(entry))
      ||!exactIdle(lease)
      ||!validPrimaryExecutionRetentionMaximum(primaryExecutionRetentionMaxSeconds)
      ||!Number.isSafeInteger(now)
      ||now<0
    )return blocked('LEASE_READBACK_MISMATCH');
    const h=freeze({
      ...safeDigests,
      observedLeaseVersion:lease.leaseVersion,
      observedLedgerDigest:lease.ledgerDigest,
      observedAtEpochSeconds:now,
    });
    HANDOFFS.set(h,{context,primaryExecutionRetentionMaxSeconds,providerContractDigest:value.providerContractDigest});
    return pass(h);
  }catch{return blocked('LEASE_READBACK_MISMATCH');}
}

async function exactCommittedReadback(store,next,event,snapshot){const lease=await store.getLease();if(canonicalJson(lease)!==canonicalJson(next))return false;const observedEvent=await store.getAuditEventByDigest(next.ledgerDigest);if(!observedEvent||canonicalJson(observedEvent)!==canonicalJson(event))return false;if(snapshot){const observedSnapshot=await store.getIntentSnapshotByDigest(digest(snapshot));if(!observedSnapshot||canonicalJson(observedSnapshot)!==canonicalJson(snapshot))return false;}return true;}
async function exactStagedRowsAbsent(store,event,snapshot){try{if(await store.getAuditEventByDigest(eventDigest(event))!==null)return false;if(snapshot&&await store.getIntentSnapshotByDigest(digest(snapshot))!==null)return false;return true;}catch{return false;}}
async function commitBounded(store,operation,oldLease,next,event,snapshot){for(let attempt=0;attempt<2;attempt+=1){try{const result=await store.transact(operation);if(result.status!=='PASS')return result;if(!await exactCommittedReadback(store,next,event,snapshot))return blocked('LEASE_READBACK_MISMATCH');return result;}catch{const observed=await store.getLease();if(canonicalJson(observed)===canonicalJson(next))return await exactCommittedReadback(store,next,event,snapshot)?pass(next):blocked('AUDIT_CHAIN_MISMATCH');if(canonicalJson(observed)!==canonicalJson(oldLease)||attempt===1)return blocked('LEASE_VERSION_MISMATCH');if(!await exactStagedRowsAbsent(store,event,snapshot))return blocked('AUDIT_CHAIN_MISMATCH');}}return blocked('LEASE_VERSION_MISMATCH');}

export async function acquireLease({context,store,handoff,clock,randomBytes}){try{const now=clock.nowEpochSeconds(),binding=HANDOFFS.get(handoff);if(!isAuthenticTestEnvironmentContext(context)||binding?.context!==context||USED_HANDOFFS.has(handoff)||!Number.isSafeInteger(now)||now-handoff.observedAtEpochSeconds>60||now<handoff.observedAtEpochSeconds)return blocked('LEASE_CONFLICT');USED_HANDOFFS.add(handoff);const lease=await store.getLease();if(!exactIdle(lease)||lease.leaseVersion!==handoff.observedLeaseVersion||lease.ledgerDigest!==handoff.observedLedgerDigest)return blocked('LEASE_VERSION_MISMATCH');const bytes=tokenBytes(randomBytes),event=makeEvent({lease,transition:'lease.acquire',runId:context.runId});const next=freeze({...lease,leaseVersion:lease.leaseVersion+1,state:'active',ownerRunId:context.runId,ownerWorkflowRunId:workflowId(context.runId),environmentDigest:context.environmentDigest,acquiredAt:iso(now),renewedAt:iso(now),expiresAt:iso(now+3600),ledgerDigest:eventDigest(event),leaseTokenDigest:tokenDigest(bytes),cleanupDebt:false}),operation={expectedLeaseVersion:lease.leaseVersion,expectedLedgerDigest:lease.ledgerDigest,event,nextLease:next};const committed=await commitBounded(store,operation,lease,next,event,null);if(committed.status!=='PASS')return committed;return pass(freeze({lease:next,capability:cap(bytes,next,context,binding.primaryExecutionRetentionMaxSeconds,binding.providerContractDigest)}));}catch{return blocked('LEASE_CONFLICT');}}

async function transitionLease({context,store,lease,capability,clock,transition,nextState,snapshot=null,nextIntent=null}){try{const now=clock.nowEpochSeconds();if(!isAuthenticTestEnvironmentContext(context)||!verifyCap(capability,lease,context,now))return blocked('LEASE_VERSION_MISMATCH');const current=await store.getLease();if(canonicalJson(current)!==canonicalJson(lease))return blocked('LEASE_VERSION_MISMATCH');const snapshotDigest=snapshot?digest(snapshot):null;const event=makeEvent({lease,transition,runId:context.runId,intentId:snapshot?.intentId??null,intentProjectionDigest:snapshotDigest});const next=freeze({...lease,...nextState,leaseVersion:lease.leaseVersion+1,ledgerDigest:eventDigest(event)}),operation={expectedLeaseVersion:lease.leaseVersion,expectedLedgerDigest:lease.ledgerDigest,event,snapshot,nextLease:next,nextIntent};const committed=await commitBounded(store,operation,lease,next,event,snapshot);if(committed.status!=='PASS')return committed;const binding=CAPS.get(capability);return pass(freeze({lease:next,capability:rotateCap(capability,binding.token,next,context),event,snapshot}));}catch{return blocked('LEASE_VERSION_MISMATCH');}}

export async function renewLease({context,store,lease,capability,clock,randomBytes}){const now=clock.nowEpochSeconds(),prior=Date.parse(lease?.renewedAt)/1000;if(lease.state!=='active'||!Number.isSafeInteger(now)||!Number.isFinite(prior)||now<=prior)return blocked('LEASE_CONFLICT');const bytes=tokenBytes(randomBytes);const transitioned=await transitionLease({context,store,lease,capability,clock,transition:'lease.renew',nextState:{renewedAt:iso(now),expiresAt:iso(now+3600),leaseTokenDigest:tokenDigest(bytes)}});if(transitioned.status!=='PASS')return transitioned;const binding=CAPS.get(transitioned.value.capability);INVALID_CAPS.add(transitioned.value.capability);return pass(freeze({lease:transitioned.value.lease,capability:cap(bytes,transitioned.value.lease,context,binding?.primaryExecutionRetentionMaxSeconds,binding?.providerContractDigest)}));}
export async function markCleanupDebt({context,store,lease,capability,clock}){if(lease?.state!=='active')return blocked('LEASE_CONFLICT');const r=await transitionLease({context,store,lease,capability,clock,transition:'lease.cleanup_debt',nextState:{state:'cleanup-debt',cleanupDebt:true}});if(r.status==='PASS')INVALID_CAPS.add(r.value.capability);return r.status==='PASS'?pass(r.value.lease):r;}

function validIso(value){
  if(typeof value!=='string'||!Number.isFinite(Date.parse(value)))return false;
  try{return new Date(value).toISOString()===value;}catch{return false;}
}
function intentSchemaVersion(value){
  if(value===null||typeof value!=='object'||Array.isArray(value)||IS_PROXY(value))return null;
  try{
    const descriptor=Object.getOwnPropertyDescriptor(value,'schemaVersion');
    return descriptor?.enumerable===true&&Object.hasOwn(descriptor,'value')?descriptor.value:null;
  }catch{return null;}
}
function intentKeys(value){return intentSchemaVersion(value)==='verification-intent-snapshot.v2'?V2_INTENT_KEYS:intentSchemaVersion(value)==='verification-intent-snapshot.v1'?V1_INTENT_KEYS:null;}
function intentIdentityKeys(value){return intentSchemaVersion(value)==='verification-intent-snapshot.v2'?V2_INTENT_IDENTITY_KEYS:V1_INTENT_IDENTITY_KEYS;}
function exactIntentObject(value){const keys=intentKeys(value);return keys!==null&&exactObject(value,keys);}
function descriptorSafeIntentCopy(value){
  const keys=intentKeys(value);
  if(keys===null)return null;
  const result={};
  for(const key of keys){
    const descriptor=Object.getOwnPropertyDescriptor(value,key);
    if(descriptor?.enumerable!==true||!Object.hasOwn(descriptor,'value'))return null;
    const item=descriptor.value;
    if(Array.isArray(item)){
      if(IS_PROXY(item)||Reflect.ownKeys(item).length!==item.length+1)return null;
      const copied=[];
      for(let index=0;index<item.length;index+=1){
        const element=Object.getOwnPropertyDescriptor(item,String(index));
        if(element?.enumerable!==true||!Object.hasOwn(element,'value')||typeof element.value!=='string')return null;
        copied.push(element.value);
      }
      result[key]=copied;
    }else result[key]=item;
  }
  return freeze(result);
}
function sortedUniqueProviderIds(value){
  return Array.isArray(value)&&value.every((id)=>typeof id==='string'&&id.length>0)&&new Set(value).size===value.length&&value.every((id,index)=>index===0||value[index-1]<id);
}
function validPrimaryExecutionSnapshot(value,maximumRetentionSeconds){
  if(!validPrimaryExecutionRetentionMaximum(maximumRetentionSeconds)||value.resourceType!=='primary-execution'||value.lifecycleClass!=='provider-retained-observation'||value.dependencyOrder!==50||!validIso(value.createdAt)||!validIso(value.updatedAt)||Date.parse(value.updatedAt)<Date.parse(value.createdAt)||!sortedUniqueProviderIds(value.providerResourceIds))return false;
  if(value.state==='planned')return [1,2].includes(value.intentVersion)&&value.providerResourceIds.length===0&&value.observationDigest===null&&value.retentionExpiresAt===null;
  if(value.state!=='created'||![3,4].includes(value.intentVersion)||value.providerResourceIds.length!==value.intentVersion-2||!DIGEST.test(value.observationDigest)||!validIso(value.retentionExpiresAt))return false;
  const created=Date.parse(value.createdAt),expires=Date.parse(value.retentionExpiresAt);
  return expires>created&&expires-created<=maximumRetentionSeconds*1000;
}
function sameExcept(prior,next,keys){
  const excluded=new Set(keys);
  return intentKeys(prior).filter((key)=>!excluded.has(key)).every((key)=>canonicalJson(prior[key])===canonicalJson(next[key]));
}
function validPrimaryExecutionSuccessor(prior,next,maximumRetentionSeconds){
  if(!validPrimaryExecutionSnapshot(prior,maximumRetentionSeconds)||!validPrimaryExecutionSnapshot(next,maximumRetentionSeconds)||next.intentVersion!==prior.intentVersion+1||Date.parse(next.updatedAt)<Date.parse(prior.updatedAt))return false;
  if(prior.intentVersion===1)return next.intentVersion===2&&prior.state==='planned'&&next.state==='planned'&&sameExcept(prior,next,['intentVersion','updatedAt']);
  if(prior.intentVersion===2)return next.intentVersion===3&&prior.state==='planned'&&next.state==='created'&&prior.providerResourceIds.length===0&&next.providerResourceIds.length===1&&sameExcept(prior,next,['providerResourceIds','state','intentVersion','observationDigest','retentionExpiresAt','updatedAt']);
  if(prior.intentVersion===3)return next.intentVersion===4&&prior.state==='created'&&next.state==='created'&&next.providerResourceIds.length===prior.providerResourceIds.length+1&&prior.providerResourceIds.every((id)=>next.providerResourceIds.includes(id))&&sameExcept(prior,next,['providerResourceIds','intentVersion','updatedAt']);
  return false;
}
function cleanupFieldsNull(value){return V2_CLEANUP_KEYS.every((key)=>value[key]===null);}
function parseCleanupSlots(value){
  const limits=CLEANUP_RESOURCE_LIMITS[value.resourceType];
  try{
    const slots=JSON.parse(value.cleanupRunnerExecutionSlotsJson);
    if(!Array.isArray(slots)||slots.length!==limits.slotCount||canonicalJson(slots)!==value.cleanupRunnerExecutionSlotsJson)return null;
    const retainedExecutionIds=new Set();
    for(let index=0;index<slots.length;index+=1){
      const slot=slots[index];
      if(slot===null)continue;
      if(!exactObject(slot,EXECUTION_SLOT_KEYS)||slot.logicalPosition!==Math.floor(index/2)||slot.attemptOrdinal!==index%2+1||typeof slot.retainedExecutionId!=='string'||slot.retainedExecutionId.length===0||!DIGEST.test(slot.safeStateDigest)||slot.retentionExpiresAt!==value.cleanupRunnerExecutionRetentionExpiresAt)return null;
      if(retainedExecutionIds.has(slot.retainedExecutionId))return null;
      retainedExecutionIds.add(slot.retainedExecutionId);
    }
    for(let position=0;position<limits.knownCalls;position+=1){
      const first=slots[position*2],second=slots[position*2+1];
      if(second!==null&&first===null)return null;
      if(position<value.cleanupRunnerExecutionCursor&&first===null)return null;
      if(position>value.cleanupRunnerExecutionCursor&&(first!==null||second!==null))return null;
    }
    return slots;
  }catch{return null;}
}
function validGlobalCleanupState(latest,replacement=null){
  const retainedExecutionIds=new Set();let retentionExpiresAt=null;
  const candidates=replacement===null?latest:[
    ...latest.filter((value)=>value.intentId!==replacement.intentId),replacement,
  ];
  for(const value of candidates){
    if(value.schemaVersion!=='verification-intent-snapshot.v2'||value.cleanupRunnerExecutionSlotsJson===null)continue;
    const slots=parseCleanupSlots(value);
    if(slots===null)return false;
    if(retentionExpiresAt===null)retentionExpiresAt=value.cleanupRunnerExecutionRetentionExpiresAt;
    else if(value.cleanupRunnerExecutionRetentionExpiresAt!==retentionExpiresAt)return false;
    for(const slot of slots){
      if(slot===null)continue;
      if(retainedExecutionIds.has(slot.retainedExecutionId))return false;
      retainedExecutionIds.add(slot.retainedExecutionId);
    }
  }
  return true;
}
function cleanupRecordDigest(resourceType,slots){return digest({schemaVersion:'verification-cleanup-execution-record.v1',logicalResource:resourceType,slots});}
const CLEANUP_RESULT='desired-projection-proven';
function cleanupGenesis(root,providerContractDigest,phase,extra={}){
  const catalog=QUALIFIED_CLEANUP_PROTOCOL.resources[root.resourceType];
  const steps=phase==='preflight'?catalog.preflight:phase==='cleanup'?catalog.mutation:catalog.proof;
  return {
    schemaVersion:QUALIFIED_CLEANUP_PROTOCOL.schemaVersion,
    environmentDigest:root.environmentDigest,
    providerContractDigest,
    providerAggregateDigest:root.providerAggregateDigest,
    intentId:root.intentId,
    intentVersion:root.intentVersion,
    intentProjectionDigest:digest(root),
    logicalResource:root.resourceType,
    phase,
    phaseStepCount:steps.length,
    cleanupRunnerExecutionPlanDigest:catalog.executionPlan.digest,
    ...extra,
  };
}
function preflightDigestAt(root,providerContractDigest,cursor){
  const catalog=QUALIFIED_CLEANUP_PROTOCOL.resources[root.resourceType];
  let value=createCleanupPhaseGenesisDigest(cleanupGenesis(root,providerContractDigest,'preflight'));
  for(let phaseCursor=0;phaseCursor<cursor;phaseCursor+=1)value=advanceCleanupPhaseDigest({priorPhaseDigest:value,logicalResource:root.resourceType,phase:'preflight',phaseCursor,stepId:catalog.preflight[phaseCursor].stepId,result:CLEANUP_RESULT});
  return value;
}
function completePreflightDigest(root,providerContractDigest){return preflightDigestAt(root,providerContractDigest,QUALIFIED_CLEANUP_PROTOCOL.resources[root.resourceType].preflight.length);}
function cleanupProgressGenesis(root,providerContractDigest){
  return createCleanupProgressGenesisDigest(cleanupGenesis(root,providerContractDigest,'cleanup',{
    preflightDigest:completePreflightDigest(root,providerContractDigest),
  }));
}
function proofDigestAt(root,providerContractDigest,finalCleanupProgressDigest,cursor){
  const catalog=QUALIFIED_CLEANUP_PROTOCOL.resources[root.resourceType];
  let value=createCleanupProofGenesisDigest(cleanupGenesis(root,providerContractDigest,'proof',{finalCleanupProgressDigest}));
  for(let proofCursor=0;proofCursor<cursor;proofCursor+=1)value=advanceCleanupProofDigest({priorCleanupProofDigest:value,logicalResource:root.resourceType,proofCursor,stepId:catalog.proof[proofCursor].stepId,result:CLEANUP_RESULT});
  return value;
}
function completeProofDigest(root,providerContractDigest,finalCleanupProgressDigest){return proofDigestAt(root,providerContractDigest,finalCleanupProgressDigest,QUALIFIED_CLEANUP_PROTOCOL.resources[root.resourceType].proof.length);}
function validV2Snapshot(value){
  const limits=CLEANUP_RESOURCE_LIMITS[value.resourceType];
  if(!limits||value.schemaVersion!=='verification-intent-snapshot.v2'||!INTENT_ID.test(value.intentId)||typeof value.runId!=='string'||value.runId.length===0||!DIGEST.test(value.environmentDigest)||typeof value.resourceId!=='string'||value.resourceId.length===0||!OWNER_MARKER.test(value.ownerMarker)||value.dependencyOrder!==limits.dependencyOrder||value.lifecycleClass!=='fixture'||!['planned','created','cleaning','absent'].includes(value.state)||!Number.isSafeInteger(value.intentVersion)||value.intentVersion<1||value.observationDigest!==null||value.retentionExpiresAt!==null||!validIso(value.createdAt)||!validIso(value.updatedAt)||Date.parse(value.updatedAt)<Date.parse(value.createdAt)||typeof value.providerAggregateJson!=='string'||!DIGEST.test(value.providerAggregateDigest))return false;
  try{const aggregate=JSON.parse(value.providerAggregateJson);if(canonicalJson(aggregate)!==value.providerAggregateJson||digest(aggregate)!==value.providerAggregateDigest)return false;}catch{return false;}
  if(value.state==='planned')return cleanupFieldsNull(value);
  if(value.state==='created'&&cleanupFieldsNull(value))return true;
  if(!Number.isSafeInteger(value.cleanupCursor)||value.cleanupCursor<0||value.cleanupCursor>limits.cleanupCursor||!DIGEST.test(value.cleanupProgressDigest)||(value.cleanupProofDigest!==null&&!DIGEST.test(value.cleanupProofDigest))||value.cleanupRunnerExecutionPlanDigest!==CLEANUP_LEDGER_CEILINGS.resources[value.resourceType].executionPlanDigest||!Number.isSafeInteger(value.cleanupRunnerExecutionCursor)||value.cleanupRunnerExecutionCursor<0||value.cleanupRunnerExecutionCursor>limits.knownCalls||!DIGEST.test(value.cleanupRunnerExecutionRecordDigest)||!validIso(value.cleanupRunnerExecutionRetentionExpiresAt))return false;
  const slots=parseCleanupSlots(value);
  if(slots===null||cleanupRecordDigest(value.resourceType,slots)!==value.cleanupRunnerExecutionRecordDigest)return false;
  if(value.state==='created')return value.cleanupCursor===0&&value.cleanupProofDigest===null&&value.cleanupRunnerExecutionCursor<limits.preflightCount;
  if(value.cleanupRunnerExecutionCursor<limits.preflightCount)return false;
  if(value.state==='absent')return value.cleanupProofDigest!==null&&value.cleanupCursor===limits.cleanupCursor&&value.cleanupRunnerExecutionCursor===limits.knownCalls;
  if(value.cleanupProofDigest!==null)return value.cleanupCursor===limits.cleanupCursor&&value.cleanupRunnerExecutionCursor===limits.knownCalls-1;
  const mutationExecutionCursor=limits.preflightCount+value.cleanupCursor;
  return value.cleanupCursor<limits.cleanupCursor
    ? value.cleanupRunnerExecutionCursor===mutationExecutionCursor
    : value.cleanupRunnerExecutionCursor>=mutationExecutionCursor&&value.cleanupRunnerExecutionCursor<limits.knownCalls-1;
}
function changedSlotIndexes(prior,next){const changed=[];for(let i=0;i<prior.length;i+=1)if(canonicalJson(prior[i])!==canonicalJson(next[i]))changed.push(i);return changed;}
function exactCleanupDigestSuccessor(prior,next,{providerContractDigest=null,cleanupRoot=null}={}){
  if(providerContractDigest===null)return true;
  if(!DIGEST.test(providerContractDigest)||cleanupRoot===null||cleanupRoot.state!=='created')return false;
  if(prior.state==='created'){
    if(next.cleanupProofDigest!==null)return false;
    return next.state==='created'
      ? next.cleanupProgressDigest===preflightDigestAt(cleanupRoot,providerContractDigest,next.cleanupRunnerExecutionCursor)
      : next.state==='cleaning'&&next.cleanupProgressDigest===cleanupProgressGenesis(cleanupRoot,providerContractDigest);
  }
  if(next.cleanupCursor===prior.cleanupCursor+1){
    const step=QUALIFIED_CLEANUP_PROTOCOL.resources[prior.resourceType].mutation[prior.cleanupCursor];
    if(!step||next.cleanupProgressDigest!==advanceCleanupProgressDigest({priorCleanupProgressDigest:prior.cleanupProgressDigest,logicalResource:prior.resourceType,cleanupCursor:prior.cleanupCursor,stepId:step.stepId,result:CLEANUP_RESULT}))return false;
  }else if(next.cleanupProgressDigest!==prior.cleanupProgressDigest)return false;
  if(next.cleanupProofDigest!==prior.cleanupProofDigest){
    return prior.cleanupProofDigest===null&&next.cleanupProofDigest===completeProofDigest(cleanupRoot,providerContractDigest,next.cleanupProgressDigest);
  }
  return true;
}
function validV2CleanupSuccessor(prior,next,validationContext){
  const limits=CLEANUP_RESOURCE_LIMITS[prior.resourceType];
  if(prior.providerAggregateJson!==next.providerAggregateJson||prior.providerAggregateDigest!==next.providerAggregateDigest)return false;
  if(prior.state==='created'&&cleanupFieldsNull(prior)){
    const slots=parseCleanupSlots(next);
    if(next.state!=='created'||next.cleanupCursor!==0||next.cleanupProofDigest!==null||!slots
      ||![0,1].includes(next.cleanupRunnerExecutionCursor)
      ||slots.slice(2).some((slot)=>slot!==null)||slots[0]===null||slots[1]!==null)return false;
    const exactSafeState=validationContext.providerContractDigest===null
      ||slots[0].safeStateDigest===preflightDigestAt(validationContext.cleanupRoot,validationContext.providerContractDigest,next.cleanupRunnerExecutionCursor);
    return exactSafeState&&exactCleanupDigestSuccessor(prior,next,validationContext);
  }
  if(prior.state==='created'){
    if(prior.cleanupRunnerExecutionPlanDigest!==next.cleanupRunnerExecutionPlanDigest||prior.cleanupRunnerExecutionRetentionExpiresAt!==next.cleanupRunnerExecutionRetentionExpiresAt||next.cleanupCursor!==0||next.cleanupProofDigest!==null)return false;
    if(next.cleanupRunnerExecutionCursor<prior.cleanupRunnerExecutionCursor||next.cleanupRunnerExecutionCursor>prior.cleanupRunnerExecutionCursor+1||next.cleanupRunnerExecutionCursor>limits.preflightCount)return false;
    const expectedState=next.cleanupRunnerExecutionCursor===limits.preflightCount?'cleaning':'created';
    if(next.state!==expectedState)return false;
    const priorSlots=parseCleanupSlots(prior),nextSlots=parseCleanupSlots(next);
    if(priorSlots===null||nextSlots===null)return false;
    const changed=changedSlotIndexes(priorSlots,nextSlots);
    if(changed.some((index)=>priorSlots[index]!==null||nextSlots[index]===null)||changed.length!==1)return false;
    const position=prior.cleanupRunnerExecutionCursor,firstIndex=position*2,secondIndex=firstIndex+1;
    const executionAdvanced=next.cleanupRunnerExecutionCursor===position+1;
    if(executionAdvanced){if(!(changed[0]===firstIndex||(changed[0]===secondIndex&&priorSlots[firstIndex]!==null)))return false;}
    else if(!((changed[0]===firstIndex&&priorSlots[firstIndex]===null)
      ||(changed[0]===secondIndex&&priorSlots[firstIndex]!==null&&priorSlots[secondIndex]===null)))return false;
    const exactSafeState=validationContext.providerContractDigest===null
      ||nextSlots[changed[0]].safeStateDigest===preflightDigestAt(validationContext.cleanupRoot,validationContext.providerContractDigest,next.cleanupRunnerExecutionCursor);
    return exactSafeState&&exactCleanupDigestSuccessor(prior,next,validationContext);
  }
  if(prior.state!=='cleaning'||prior.cleanupRunnerExecutionPlanDigest!==next.cleanupRunnerExecutionPlanDigest||prior.cleanupRunnerExecutionRetentionExpiresAt!==next.cleanupRunnerExecutionRetentionExpiresAt)return false;
  if(next.cleanupCursor<prior.cleanupCursor||next.cleanupCursor>prior.cleanupCursor+1||next.cleanupRunnerExecutionCursor<prior.cleanupRunnerExecutionCursor||next.cleanupRunnerExecutionCursor>prior.cleanupRunnerExecutionCursor+1)return false;
  if(prior.cleanupProofDigest!==null&&next.cleanupProofDigest!==prior.cleanupProofDigest)return false;
  if(next.cleanupCursor>prior.cleanupCursor&&next.cleanupProgressDigest===prior.cleanupProgressDigest)return false;
  const priorSlots=parseCleanupSlots(prior),nextSlots=parseCleanupSlots(next);
  if(priorSlots===null||nextSlots===null)return false;
  const changed=changedSlotIndexes(priorSlots,nextSlots);
  if(changed.some((index)=>priorSlots[index]!==null||nextSlots[index]===null)||changed.length>1)return false;
  const position=prior.cleanupRunnerExecutionCursor,firstIndex=position*2,secondIndex=firstIndex+1;
  if(next.state==='absent')return prior.cleanupProofDigest!==null&&prior.cleanupCursor===limits.cleanupCursor&&prior.cleanupRunnerExecutionCursor===limits.knownCalls-1&&next.cleanupCursor===prior.cleanupCursor&&next.cleanupProgressDigest===prior.cleanupProgressDigest&&next.cleanupProofDigest===prior.cleanupProofDigest&&next.cleanupRunnerExecutionCursor===limits.knownCalls&&changed.length===1&&(changed[0]===firstIndex||(changed[0]===secondIndex&&priorSlots[firstIndex]!==null))&&nextSlots[changed[0]].safeStateDigest===prior.cleanupProofDigest&&exactCleanupDigestSuccessor(prior,next,validationContext);
  if(prior.cleanupProofDigest!==null)return next.state==='cleaning'
    &&next.cleanupCursor===prior.cleanupCursor
    &&next.cleanupProgressDigest===prior.cleanupProgressDigest
    &&next.cleanupProofDigest===prior.cleanupProofDigest
    &&next.cleanupRunnerExecutionCursor===prior.cleanupRunnerExecutionCursor
    &&changed.length===1
    &&((changed[0]===firstIndex&&priorSlots[firstIndex]===null)
      ||(changed[0]===secondIndex&&priorSlots[firstIndex]!==null&&priorSlots[secondIndex]===null))
    &&nextSlots[changed[0]].safeStateDigest===prior.cleanupProofDigest
    &&exactCleanupDigestSuccessor(prior,next,validationContext);
  if(next.state!=='cleaning'||prior.cleanupProofDigest!==null)return false;
  const executionAdvanced=next.cleanupRunnerExecutionCursor===prior.cleanupRunnerExecutionCursor+1;
  if(executionAdvanced){if(changed.length!==1||!(changed[0]===firstIndex||(changed[0]===secondIndex&&priorSlots[firstIndex]!==null)))return false;}
  else if(changed.length===1&&!((changed[0]===firstIndex&&priorSlots[firstIndex]===null)
    ||(changed[0]===secondIndex&&priorSlots[firstIndex]!==null&&priorSlots[secondIndex]===null)))return false;
  if(prior.cleanupCursor<limits.cleanupCursor){
    if(changed.length!==1)return false;
    const expectedSafeStateDigest=executionAdvanced?next.cleanupProgressDigest:prior.cleanupProgressDigest;
    if(nextSlots[changed[0]].safeStateDigest!==expectedSafeStateDigest)return false;
  }else if(prior.cleanupProofDigest===null&&validationContext.providerContractDigest!==null){
    if(changed.length!==1)return false;
    const proofCursor=prior.cleanupRunnerExecutionCursor-limits.preflightCount-limits.cleanupCursor;
    const expectedSafeStateDigest=proofDigestAt(validationContext.cleanupRoot,validationContext.providerContractDigest,
      prior.cleanupProgressDigest,proofCursor+(executionAdvanced?1:0));
    if(nextSlots[changed[0]].safeStateDigest!==expectedSafeStateDigest)return false;
  }
  if(!executionAdvanced&&changed.length===0&&next.cleanupCursor===prior.cleanupCursor&&next.cleanupProgressDigest===prior.cleanupProgressDigest&&next.cleanupProofDigest===prior.cleanupProofDigest)return false;
  if(next.cleanupProofDigest!==null&&prior.cleanupProofDigest===null&&(next.cleanupCursor!==limits.cleanupCursor||next.cleanupRunnerExecutionCursor!==limits.knownCalls-1))return false;
  return exactCleanupDigestSuccessor(prior,next,validationContext);
}
function validV2Successor(prior,next,validationContext){
  if(!validV2Snapshot(prior)||!validV2Snapshot(next)||next.intentVersion!==prior.intentVersion+1||V2_INTENT_IDENTITY_KEYS.some((key)=>canonicalJson(prior[key])!==canonicalJson(next[key]))||Date.parse(next.updatedAt)<Date.parse(prior.updatedAt))return false;
  if(prior.state==='planned')return (next.state==='planned'||next.state==='created')&&cleanupFieldsNull(next);
  return validV2CleanupSuccessor(prior,next,validationContext);
}
function validIntentSuccessor(prior,next,maximumRetentionSeconds,validationContext){
  if(prior.schemaVersion!==next.schemaVersion||next.intentVersion!==prior.intentVersion+1||intentIdentityKeys(prior).some((key)=>canonicalJson(prior[key])!==canonicalJson(next[key]))||!validIso(next.updatedAt)||Date.parse(next.updatedAt)<Date.parse(prior.updatedAt))return false;
  if(prior.schemaVersion==='verification-intent-snapshot.v2')return validV2Successor(prior,next,validationContext);
  if(prior.resourceType==='primary-execution')return validPrimaryExecutionSuccessor(prior,next,maximumRetentionSeconds);
  return prior.observationDigest===null&&next.observationDigest===null&&canonicalJson(prior.providerResourceIds)===canonicalJson(next.providerResourceIds)&&prior.retentionExpiresAt===next.retentionExpiresAt&&((prior.state==='planned'&&next.state==='created')||(prior.state==='created'&&next.state==='absent'));
}
function validInitialIntent(value,maximumRetentionSeconds){
  if(value.schemaVersion==='verification-intent-snapshot.v2')return value.state==='planned'&&value.intentVersion===1&&validV2Snapshot(value);
  return value.state==='planned'&&value.intentVersion===1&&(value.resourceType==='primary-execution'?validPrimaryExecutionSnapshot(value,maximumRetentionSeconds):value.observationDigest===null);
}
function transitionForSnapshot(prior,snapshot){
  if(snapshot.schemaVersion==='verification-intent-snapshot.v1')return snapshot.resourceType==='primary-execution'?(snapshot.state==='planned'?'observation.planned':'observation.observed'):`intent.${snapshot.state}`;
  if(prior===null||prior===undefined)return'intent.planned';
  if(prior.state==='planned'&&snapshot.state==='created')return'intent.created';
  if(snapshot.state==='absent')return'intent.absent';
  if(prior.state==='created'&&snapshot.state==='cleaning')return'intent.cleanup_started';
  if(prior.cleanupProofDigest===null&&snapshot.cleanupProofDigest!==null)return'intent.cleanup_proof_recorded';
  if(prior.cleanupRunnerExecutionCursor===snapshot.cleanupRunnerExecutionCursor&&prior.cleanupRunnerExecutionSlotsJson!==snapshot.cleanupRunnerExecutionSlotsJson)return'intent.cleanup_execution_recorded';
  return'intent.cleanup_progressed';
}
export async function commitIntentSnapshot(args){
  const source=args?.snapshot,binding=CAPS.get(args?.capability),maximumRetentionSeconds=binding?.primaryExecutionRetentionMaxSeconds;
  if(!validPrimaryExecutionRetentionMaximum(maximumRetentionSeconds)||!exactIntentObject(source)||source.runId!==args.context?.runId||!Number.isSafeInteger(source.intentVersion))return blocked('INTENT_INVALID_TRANSITION');
  const snapshot=descriptorSafeIntentCopy(source);if(snapshot===null)return blocked('INTENT_INVALID_TRANSITION');
  const reconstructed=await reconstructAuthoritativeState({store:args.store,lease:args.lease,primaryExecutionRetentionMaxSeconds:maximumRetentionSeconds,providerContractDigest:binding.providerContractDigest});
  if(reconstructed.status!=='PASS')return blocked('AUDIT_CHAIN_MISMATCH');
  const prior=reconstructed.value.latest.find((value)=>value.intentId===snapshot.intentId)??null;
  if(prior&&canonicalJson(prior)===canonicalJson(snapshot))return pass(freeze({lease:args.lease,capability:args.capability,event:null,snapshot:prior}));
  const validationContext={providerContractDigest:binding.providerContractDigest,cleanupRoot:reconstructed.value.cleanupRoots.get(snapshot.intentId)??(prior?.state==='created'?prior:null)};
  if((prior===null&&!validInitialIntent(snapshot,maximumRetentionSeconds))||(prior!==null&&!validIntentSuccessor(prior,snapshot,maximumRetentionSeconds,validationContext)))return blocked('INTENT_INVALID_TRANSITION');
  if(!validGlobalCleanupState(reconstructed.value.latest,snapshot))return blocked('INTENT_INVALID_TRANSITION');
  return transitionLease({...args,snapshot,transition:transitionForSnapshot(prior,snapshot),nextState:{},nextIntent:snapshot});
}

export async function reconcilePrimaryExecutionRunnerObservation({context,store,lease,capability,intent,clock}){
  try{
    const now=clock.nowEpochSeconds(),binding=CAPS.get(capability),maximumRetentionSeconds=binding?.primaryExecutionRetentionMaxSeconds;
    if(!isAuthenticTestEnvironmentContext(context)||!verifyCap(capability,lease,context,now)||!validPrimaryExecutionRetentionMaximum(maximumRetentionSeconds)||!exactIntentObject(intent)||!validPrimaryExecutionSnapshot(intent,maximumRetentionSeconds)||intent.intentVersion!==1)return blocked('INTENT_INVALID_TRANSITION');
    const current=await store.getLease();
    const normalizedCurrent={...current,leaseVersion:lease.leaseVersion,ledgerDigest:lease.ledgerDigest};
    if(current.leaseVersion!==lease.leaseVersion+2||canonicalJson(normalizedCurrent)!==canonicalJson(lease))return blocked('LEASE_VERSION_MISMATCH');
    const priorEvent=await store.getAuditEventByDigest(lease.ledgerDigest);
    const observedEvent=await store.getAuditEventByDigest(current.ledgerDigest);
    const plannedEvent=observedEvent?.previousLedgerDigest?await store.getAuditEventByDigest(observedEvent.previousLedgerDigest):null;
    if(
      !priorEvent||!plannedEvent||!observedEvent
      ||priorEvent.transition!=='observation.planned'||priorEvent.intentId!==intent.intentId||priorEvent.intentProjectionDigest!==digest(intent)
      ||plannedEvent.transition!=='observation.planned'||plannedEvent.runId!==context.runId||plannedEvent.intentId!==intent.intentId||plannedEvent.previousLedgerDigest!==lease.ledgerDigest||plannedEvent.leaseVersionBefore!==lease.leaseVersion||plannedEvent.leaseVersionAfter!==lease.leaseVersion+1
      ||observedEvent.transition!=='observation.observed'||observedEvent.runId!==context.runId||observedEvent.intentId!==intent.intentId||observedEvent.leaseVersionBefore!==lease.leaseVersion+1||observedEvent.leaseVersionAfter!==lease.leaseVersion+2||eventDigest(observedEvent)!==current.ledgerDigest
    )return blocked('AUDIT_CHAIN_MISMATCH');
    const planned=await store.getIntentSnapshotByDigest(plannedEvent.intentProjectionDigest);
    const observed=await store.getIntentSnapshotByDigest(observedEvent.intentProjectionDigest);
    if(
      !exactIntentObject(planned)||!exactIntentObject(observed)
      ||digest(planned)!==plannedEvent.intentProjectionDigest||digest(observed)!==observedEvent.intentProjectionDigest
      ||!validIntentSuccessor(intent,planned,maximumRetentionSeconds)||!validIntentSuccessor(planned,observed,maximumRetentionSeconds)
      ||observed.intentVersion!==3||observed.state!=='created'||observed.providerResourceIds.length!==1
    )return blocked('AUDIT_CHAIN_MISMATCH');
    const reconstructed=await reconstructAuthoritativeIntents({store,lease:current,primaryExecutionRetentionMaxSeconds:maximumRetentionSeconds});
    const authoritative=reconstructed.status==='PASS'?reconstructed.value.find((value)=>value.intentId===intent.intentId):null;
    if(!authoritative||canonicalJson(authoritative)!==canonicalJson(observed))return blocked('AUDIT_CHAIN_MISMATCH');
    return pass(freeze({lease:current,capability:rotateCap(capability,binding.token,current,context),intent:observed,stateDigest:digest(observed)}));
  }catch{return blocked('AUDIT_CHAIN_MISMATCH');}
}

export async function closeLease({context,store,lease,capability,clock}){const binding=CAPS.get(capability),maximumRetentionSeconds=binding?.primaryExecutionRetentionMaxSeconds;if(!validPrimaryExecutionRetentionMaximum(maximumRetentionSeconds))return blocked('CLEANUP_AMBIGUOUS');const reconstructed=await reconstructAuthoritativeState({store,lease,primaryExecutionRetentionMaxSeconds:maximumRetentionSeconds,providerContractDigest:binding.providerContractDigest});if(reconstructed.status!=='PASS'||!validGlobalCleanupState(reconstructed.value.latest)||reconstructed.value.latest.some((i)=>i.lifecycleClass==='provider-retained-observation'?!(validPrimaryExecutionSnapshot(i,maximumRetentionSeconds)&&i.state==='created'&&i.intentVersion===4&&i.providerResourceIds.length===2):i.state!=='absent'))return blocked('CLEANUP_AMBIGUOUS');const r=await transitionLease({context,store,lease,capability,clock,transition:'lease.close',nextState:{state:'idle',ownerRunId:null,ownerWorkflowRunId:null,environmentDigest:null,acquiredAt:null,renewedAt:null,expiresAt:null,leaseTokenDigest:null,cleanupDebt:false}});if(r.status==='PASS')INVALID_CAPS.add(r.value.capability);return r.status==='PASS'?pass(r.value.lease):r;}

function legalSnapshotSuccessor(prior,snapshot,primaryExecutionRetentionMaxSeconds,validationContext){
  if(prior===undefined)return validInitialIntent(snapshot,primaryExecutionRetentionMaxSeconds);
  return validIntentSuccessor(prior,snapshot,primaryExecutionRetentionMaxSeconds,validationContext);
}
function transitionMatchesSnapshot(prior,snapshot,transition){
  if(snapshot.schemaVersion==='verification-intent-snapshot.v1')return transition===transitionForSnapshot(prior,snapshot);
  if(prior!==undefined&&prior.state==='planned'&&snapshot.state==='planned')return transition.startsWith('intent.provider_');
  return transition===transitionForSnapshot(prior,snapshot);
}
async function reconstructAuthoritativeState({store,lease,primaryExecutionRetentionMaxSeconds,providerContractDigest=null}){try{
  if(!validPrimaryExecutionRetentionMaximum(primaryExecutionRetentionMaxSeconds))return blocked('AUDIT_CHAIN_MISMATCH');
  if(providerContractDigest!==null&&!DIGEST.test(providerContractDigest))return blocked('AUDIT_CHAIN_MISMATCH');
  if(lease.ledgerDigest===GENESIS_LEDGER_DIGEST)return pass(freeze({latest:freeze([]),cleanupRoots:new Map()}));
  let head=lease.ledgerDigest;const seen=new Set(),events=[];
  while(head!==GENESIS_LEDGER_DIGEST){
    if(seen.has(head))return blocked('AUDIT_CHAIN_MISMATCH');seen.add(head);
    const event=await store.getAuditEventByDigest(head);
    if(!event||eventDigest(event)!==head||event.leaseVersionAfter!==event.leaseVersionBefore+1)return blocked('AUDIT_CHAIN_MISMATCH');
    events.push(event);head=event.previousLedgerDigest;
  }
  events.reverse();
  for(let i=1;i<events.length;i++)if(events[i].leaseVersionBefore!==events[i-1].leaseVersionAfter)return blocked('AUDIT_CHAIN_MISMATCH');
  const latest=new Map(),cleanupRoots=new Map();let activeRun=null;
  for(const event of events){
    if(event.transition==='lease.acquire'){if(activeRun!==null||event.intentId!==null||event.intentProjectionDigest!==null)return blocked('AUDIT_CHAIN_MISMATCH');activeRun=event.runId;}
    else if(event.runId!==activeRun)return blocked('AUDIT_CHAIN_MISMATCH');
    if(event.transition==='lease.close')activeRun=null;
    if(event.intentProjectionDigest){
      const snapshot=await store.getIntentSnapshotByDigest(event.intentProjectionDigest),prior=latest.get(event.intentId);
      const validationContext={providerContractDigest,cleanupRoot:cleanupRoots.get(snapshot.intentId)??(prior?.state==='created'?prior:null)};
      if(!exactIntentObject(snapshot)||digest(snapshot)!==event.intentProjectionDigest||snapshot.intentId!==event.intentId||snapshot.runId!==event.runId||!legalSnapshotSuccessor(prior,snapshot,primaryExecutionRetentionMaxSeconds,validationContext)||!transitionMatchesSnapshot(prior,snapshot,event.transition))return blocked('AUDIT_CHAIN_MISMATCH');
      if(snapshot.schemaVersion==='verification-intent-snapshot.v2'&&snapshot.state==='created'&&!cleanupRoots.has(snapshot.intentId))cleanupRoots.set(snapshot.intentId,freeze(snapshot));
      latest.set(snapshot.intentId,freeze(snapshot));
    }else if(event.intentId!==null)return blocked('AUDIT_CHAIN_MISMATCH');
  }
  for(const snapshot of latest.values()){const cache=await store.getIntentProjection(snapshot.intentId);if(cache!==null&&canonicalJson(cache)!==canonicalJson(snapshot))return blocked('AUDIT_CHAIN_MISMATCH');}
  return pass(freeze({latest:freeze([...latest.values()].sort((a,b)=>a.intentId<b.intentId?-1:a.intentId>b.intentId?1:0)),cleanupRoots}));
}catch{return blocked('AUDIT_CHAIN_MISMATCH');}}
export async function reconstructAuthoritativeIntents(args){const result=await reconstructAuthoritativeState(args);return result.status==='PASS'?pass(result.value.latest):result;}
export function createRunnerRequest({capability,lease,context,clock,scenario}){try{const now=clock.nowEpochSeconds();if(!verifyCap(capability,lease,context,now)||!scenario||typeof scenario!=='object'||Array.isArray(scenario)||Reflect.ownKeys(scenario).length!==2||typeof scenario.scenarioId!=='string'||!scenario.parameters||typeof scenario.parameters!=='object'||Array.isArray(scenario.parameters))return blocked('LEASE_VERSION_MISMATCH');const request=freeze(Object.create(null));RUNNER_REQUESTS.set(request,{context,runId:context.runId,scenarioId:scenario.scenarioId,parameters:freeze(structuredClone(scenario.parameters)),leaseToken:CAPS.get(capability).token.toString('base64url'),primaryExecutionRetentionMaxSeconds:CAPS.get(capability).primaryExecutionRetentionMaxSeconds});return pass(request);}catch{return blocked('LEASE_VERSION_MISMATCH');}}
export function consumeRunnerRequest({context,runnerRequest}){const binding=RUNNER_REQUESTS.get(runnerRequest);if(!binding||binding.context!==context)throw new TypeError('runner request');return freeze({runId:binding.runId,scenarioId:binding.scenarioId,parameters:binding.parameters,leaseToken:binding.leaseToken,primaryExecutionRetentionMaxSeconds:binding.primaryExecutionRetentionMaxSeconds});}

// Recovery authority is deliberately additive. Ordinary CAPS and ordinary store
// receivers above never enter these private maps.
const RECOVERY_LEASE_KEYS=[
  'leaseRowId','leaseVersion','state','ownerRunId','ownerWorkflowRunId','environmentDigest',
  'acquiredAt','renewedAt','expiresAt','ledgerDigest','leaseTokenDigest','cleanupDebt',
];
const ORDINARY_AUDIT_KEYS=[
  'schemaVersion','previousLedgerDigest','runId','leaseVersionBefore','leaseVersionAfter',
  'transition','intentId','intentProjectionDigest',
];
const RECOVERY_AUDIT_KEYS=[...ORDINARY_AUDIT_KEYS,
  'recoveryCheckpointJson','recoveryCheckpointDigest','recoveryPreviousCheckpointDigest'];
const RECOVERY_SNAPSHOT_KEYS=['lease','auditTrail','intentProjections'];
const RECOVERY_ENTRY_KEYS=['digest','event','snapshot'];
const RECOVERY_PROJECTION_KEYS=['intentId','projection'];
const RECOVERY_RESOURCE_TYPES=new Set(QUALIFIED_CLEANUP_PROTOCOL.resourceOrder);
const RECOVERY_TRANSITIONS=new Set([
  'recovery.checkpoint_started','recovery.mutation_issued','recovery.mutation_not_committed',
  'recovery.step_committed','recovery.step_blocked','intent.recovery_absent',
  'recovery.resources_completed',
]);
const RECOVERY_ORDINARY_TRANSITIONS=new Set([
  'lease.acquire','lease.renew','lease.cleanup_debt','lease.recover','lease.close',
  'intent.planned','intent.created','intent.absent','intent.provider_bound',
  'intent.provider_values_bound','intent.provider_operation_issued',
  'intent.provider_operation_reconciled','intent.provider_phase_reconciled',
  'intent.provider_create_issued','intent.provider_id_discovered',
  'intent.cleanup_started','intent.cleanup_progressed','intent.cleanup_proof_recorded',
  'intent.cleanup_execution_recorded','observation.planned','observation.observed',
]);
const RECOVERY_SESSIONS=new WeakMap();
const ACTIVE_RECOVERY_SESSIONS=new WeakMap();
const RECOVERY_STEP_HANDLES=new WeakMap();
const RECOVERY_MUTATION_PERMITS=new WeakMap();
const USED_RECOVERY_STEP_HANDLES=new WeakSet();
const USED_RECOVERY_MUTATION_PERMITS=new WeakSet();
const RECOVERY_ACCOUNT_SESSION_LIST_HANDLES=new WeakMap();
const RECOVERY_ACCOUNT_SESSION_DELETE_PERMITS=new WeakMap();
const RECOVERY_ACCOUNT_SESSION_OBSERVATIONS=new WeakMap();
const USED_RECOVERY_ACCOUNT_SESSION_LIST_HANDLES=new WeakSet();
const USED_RECOVERY_ACCOUNT_SESSION_DELETE_PERMITS=new WeakSet();
const USED_RECOVERY_ACCOUNT_SESSION_OBSERVATIONS=new WeakSet();
const RECOVERY_ACCOUNT_SESSION_ABSENCE_DIGEST=digest({
  schemaVersion:'verification-account-session-absence.v1',originallyObservedIntentIds:[],
});
const RECOVERY_GENESIS_PREFIX_BY_ABSENT_COUNT=Object.freeze([0,21,32,42]);
const RECOVERY_PRODUCT_DATABASE_ID='core_runtime_db';
const RECOVERY_PRODUCT_FILE_BUCKET_ID='project-files';
const RECOVERY_PRODUCT_BINDINGS=Object.freeze({
  P0:Object.freeze({resourceType:'primary-project',slot:'projectFacade',kind:'row'}),
  P1:Object.freeze({resourceType:'primary-project',slot:'rootArtifact',kind:'row'}),
  P2:Object.freeze({resourceType:'primary-project',slot:'rootVersionInitial',kind:'row'}),
  P3:Object.freeze({resourceType:'primary-project',slot:'rootManifestInitial',kind:'file'}),
  P4:Object.freeze({resourceType:'primary-project',slot:'rootVersionSaved',kind:'row'}),
  P5:Object.freeze({resourceType:'primary-project',slot:'rootManifestSaved',kind:'file'}),
  G0:Object.freeze({resourceType:'primary-graph',slot:'entrypointArtifact',kind:'row'}),
  G1:Object.freeze({resourceType:'primary-graph',slot:'entrypointVersionInitial',kind:'row'}),
  G2:Object.freeze({resourceType:'primary-graph',slot:'entrypointSourceInitial',kind:'file'}),
  G3:Object.freeze({resourceType:'primary-graph',slot:'entrypointVersionSaved',kind:'row'}),
  G4:Object.freeze({resourceType:'primary-graph',slot:'entrypointSourceSaved',kind:'file'}),
  V0:Object.freeze({resourceType:'primary-graph',slot:'visualModelSourceSaved',kind:'file'}),
  V1:Object.freeze({resourceType:'primary-graph',slot:'visualModelArtifact',kind:'row'}),
  V2:Object.freeze({resourceType:'primary-graph',slot:'visualModelVersionSaved',kind:'row'}),
  S0:Object.freeze({resourceType:'primary-share',slot:'editorShare',kind:'row'}),
  S1:Object.freeze({resourceType:'primary-share',slot:'viewerShare',kind:'row'}),
});
const RECOVERY_PRODUCT_TABLE_IDS=Object.freeze({
  projects:'first_dataset','project-shares':'project_shares',
  'project-snapshots':'project_snapshots',
  'project-artifact-references':'project_artifact_references',
  'project-artifacts':'project_artifacts',
  'project-artifact-versions':'project_artifact_versions',
});
const RECOVERY_PRODUCT_QUERY_STEPS=Object.freeze({
  'share.start':Object.freeze({method:'queryBoundProjectShares',bindingName:'project-shares',
    expectedTotal:2,aliases:Object.freeze(['S0','S1'])}),
  'project.phase.after-share-cleanup':Object.freeze({method:'queryBoundProjectSnapshots',
    bindingName:'project-snapshots',expectedTotal:0,aliases:Object.freeze([])}),
  'graph.phase.after-share-cleanup':Object.freeze({method:'queryBoundProjectArtifactReferences',
    bindingName:'project-artifact-references',expectedTotal:0,aliases:Object.freeze([])}),
  'share.phase.after-share-cleanup':Object.freeze({method:'queryBoundProjectArtifactsExactSet',
    bindingName:'project-artifacts',expectedTotal:3,aliases:Object.freeze(['P1','G0','V1'])}),
  'share.absent':Object.freeze({method:'queryBoundProjectArtifactVersionsExactSet',
    bindingName:'project-artifact-versions',expectedTotal:5,
    aliases:Object.freeze(['P2','P4','G1','G3','V2'])}),
  'graph.start':Object.freeze({method:'queryBoundProjectArtifactReferences',
    bindingName:'project-artifact-references',expectedTotal:0,aliases:Object.freeze([])}),
  'graph.phase.after-graph-cleanup':Object.freeze({method:'queryBoundProjectArtifactReferences',
    bindingName:'project-artifact-references',expectedTotal:0,aliases:Object.freeze([])}),
  'graph.absent':Object.freeze({method:'queryBoundProjectArtifactVersionsExactSet',
    bindingName:'project-artifact-versions',expectedTotal:2,
    aliases:Object.freeze(['P2','P4'])}),
  'project.phase.after-graph-cleanup':Object.freeze({method:'queryBoundProjectArtifactsExactSet',
    bindingName:'project-artifacts',expectedTotal:1,aliases:Object.freeze(['P1'])}),
  'project.start':Object.freeze({method:'queryBoundProjectArtifactReferences',
    bindingName:'project-artifact-references',expectedTotal:0,aliases:Object.freeze([])}),
  'project.phase.fully-clean':Object.freeze({method:'queryBoundProjectArtifactsExactSet',
    bindingName:'project-artifacts',expectedTotal:0,aliases:Object.freeze([])}),
  'project.absent':Object.freeze({method:'queryBoundProjectArtifactVersionsExactSet',
    bindingName:'project-artifact-versions',expectedTotal:0,aliases:Object.freeze([])}),
});
const RECOVERY_PRODUCT_EXTRA_QUERY_STEPS=Object.freeze({
  'share.phase.after-share-cleanup':Object.freeze([
    Object.freeze({method:'queryBoundProjectShares',bindingName:'project-shares',
      expectedTotal:0,aliases:Object.freeze([])}),
  ]),
});

function recoveryFields(value,keys){
  if(!exactObject(value,keys))return null;
  const fields={};
  for(const key of keys)fields[key]=Object.getOwnPropertyDescriptor(value,key).value;
  return fields;
}
function recoveryDenseArray(value){
  try{
    if(!Array.isArray(value)||IS_PROXY(value)||Reflect.ownKeys(value).length!==value.length+1)return null;
    const result=[];
    for(let index=0;index<value.length;index+=1){
      const descriptor=Object.getOwnPropertyDescriptor(value,String(index));
      if(descriptor?.enumerable!==true||!Object.hasOwn(descriptor,'value'))return null;
      result.push(descriptor.value);
    }
    return result;
  }catch{return null;}
}
function recoveryOwnValue(value,key){
  if(value===null||typeof value!=='object'||Array.isArray(value)||IS_PROXY(value))
    throw new TypeError('recovery provider binding');
  const descriptor=Object.getOwnPropertyDescriptor(value,key);
  if(descriptor?.enumerable!==true||!Object.hasOwn(descriptor,'value'))
    throw new TypeError('recovery provider binding');
  return descriptor.value;
}
function recoveryProviderAggregate(sourceIntent){
  const aggregate=JSON.parse(sourceIntent.providerAggregateJson);
  if(canonicalJson(aggregate)!==sourceIntent.providerAggregateJson
    ||digest(aggregate)!==sourceIntent.providerAggregateDigest)
    throw new TypeError('recovery provider binding');
  return aggregate;
}
function recoverySourceIntentFor(binding,resourceType){
  const source=binding.reconstruction.sourceIntents
    .find((intent)=>intent.resourceType===resourceType);
  if(source===undefined)throw new TypeError('recovery provider binding');
  return source;
}
function recoveryOwnedMember(binding,specification){
  const source=recoverySourceIntentFor(binding,specification.resourceType);
  const members=recoveryDenseArray(recoveryOwnValue(recoveryProviderAggregate(source),'ownedMembers'));
  if(members===null)throw new TypeError('recovery provider binding');
  const matches=members.filter((member)=>{
    try{
      const memberBinding=recoveryOwnValue(member,'memberBinding');
      const identity=recoveryOwnValue(member,'providerIdentity');
      return recoveryOwnValue(member,'bindingState')==='bound'
        &&recoveryOwnValue(memberBinding,'slot')===specification.slot
        &&recoveryOwnValue(identity,'providerId')===recoveryOwnValue(member,'providerId');
    }catch{return false;}
  });
  if(matches.length!==1)throw new TypeError('recovery provider binding');
  return matches[0];
}
function recoveryOwnerUserId(binding){
  const member=recoveryOwnedMember(binding,RECOVERY_PRODUCT_BINDINGS.S0);
  const values=recoveryDenseArray(recoveryOwnValue(member,'logicalValueBindings'));
  if(values===null)throw new TypeError('recovery provider binding');
  const matches=values.filter((entry)=>{
    try{return recoveryOwnValue(entry,'name')==='sharedByUserId'
      &&recoveryOwnValue(entry,'state')==='bound'
      &&typeof recoveryOwnValue(entry,'value')==='string';}catch{return false;}
  });
  if(matches.length!==1)throw new TypeError('recovery provider binding');
  return recoveryOwnValue(matches[0],'value');
}
function recoveryProductMemberTarget(binding,alias){
  const specification=RECOVERY_PRODUCT_BINDINGS[alias];
  if(specification===undefined)throw new TypeError('recovery provider binding');
  const member=recoveryOwnedMember(binding,specification);
  const identity=recoveryOwnValue(member,'providerIdentity');
  const providerId=recoveryOwnValue(member,'providerId');
  const bindingName=recoveryOwnValue(identity,'bindingName');
  const providerKind=recoveryOwnValue(identity,'providerKind');
  const expectedProviderKind=specification.kind==='row'?'tablesdb-row':'storage-file';
  if(typeof providerId!=='string'||providerId.length===0||providerKind!==expectedProviderKind)
    throw new TypeError('recovery provider binding');
  const ownerUserId=recoveryOwnerUserId(binding);
  const ownerPermissions=freeze(['read','update','delete'].map(
    (operation)=>`${operation}("user:${ownerUserId}")`));
  if(specification.kind==='file'){
    if(bindingName!==RECOVERY_PRODUCT_FILE_BUCKET_ID)throw new TypeError('recovery provider binding');
    return freeze({kind:'file',bucketId:RECOVERY_PRODUCT_FILE_BUCKET_ID,fileId:providerId,
      ownerPermissions});
  }
  const tableId=RECOVERY_PRODUCT_TABLE_IDS[bindingName];
  if(tableId===undefined)throw new TypeError('recovery provider binding');
  return freeze({kind:'row',databaseId:RECOVERY_PRODUCT_DATABASE_ID,tableId,rowId:providerId,
    ownerPermissions});
}
function recoveryProductQueryTarget(binding,query){
  const project=recoveryProductMemberTarget(binding,'P0');
  const tableId=RECOVERY_PRODUCT_TABLE_IDS[query.bindingName];
  if(tableId===undefined)throw new TypeError('recovery provider binding');
  return freeze({databaseId:RECOVERY_PRODUCT_DATABASE_ID,tableId,projectId:project.rowId,
    expectedTotal:query.expectedTotal});
}
function recoveryProductQueryRows(binding,query){
  const project=recoveryProductMemberTarget(binding,'P0');
  return freeze(query.aliases.map((alias)=>{
    const target=recoveryProductMemberTarget(binding,alias);
    if(target.kind!=='row')throw new TypeError('recovery provider binding');
    return freeze({$id:target.rowId,projectId:project.rowId});
  }).sort((left,right)=>left.$id<right.$id?-1:left.$id>right.$id?1:0));
}
function recoveryProductQueryProjectionDigest(binding,query){
  const rows=recoveryProductQueryRows(binding,query);
  return digest({schemaVersion:'tablesdb-query-state.v1',total:query.expectedTotal,
    rowsDigest:digest(rows)});
}
function recoveryProductQueryDigestOrNull(binding,query){
  try{return recoveryProductQueryProjectionDigest(binding,query);}catch{return null;}
}
function recoveryProductAuthorization(record){
  const query=record.productQuery??RECOVERY_PRODUCT_QUERY_STEPS[record.stepId];
  if(record.kind==='step'&&query!==undefined)return freeze({method:query.method,
    target:recoveryProductQueryTarget(record.sessionBinding,query)});
  const match=/\.(P[0-5]|G[0-4]|V[0-2])$/.exec(record.stepId)
    ??(/\.viewerShare$/.test(record.stepId)?[null,'S1']:null)
    ??(/\.editorShare$/.test(record.stepId)?[null,'S0']:null);
  if(match===null)throw new TypeError('recovery product authorization');
  const target=recoveryProductMemberTarget(record.sessionBinding,match[1]);
  const method=record.kind==='step'
    ?target.kind==='row'?'getBoundRow':'getBoundFile'
    :record.action==='delete-and-prove-absent'
      ?target.kind==='row'?'deleteBoundRow':'deleteBoundFile'
      :record.action==='converge-owner-only'
        ?target.kind==='row'?'convergeBoundRowOwnerPermissions'
          :'convergeBoundFileOwnerPermissions'
        :null;
  if(method===null)throw new TypeError('recovery product authorization');
  return freeze({method,target});
}
function recoveryStorePassValue(outcome,keys){
  const envelope=recoveryFields(outcome,['status','value','diagnostics']);
  if(envelope===null||envelope.status!=='PASS'||recoveryDenseArray(envelope.diagnostics)?.length!==0)return null;
  return recoveryFields(envelope.value,keys);
}
function recoveryEventHasCheckpoint(event){
  try{
    if(event===null||typeof event!=='object'||Array.isArray(event)||IS_PROXY(event))return false;
    const descriptor=Object.getOwnPropertyDescriptor(event,'recoveryCheckpointJson');
    return descriptor?.enumerable===true&&Object.hasOwn(descriptor,'value');
  }catch{return false;}
}
function recoveryIntent(value){
  try{return freeze(validateRecoveryIntentRow(value));}catch{return null;}
}
function recoveryV1AccountSession(value){
  const fields=recoveryFields(value,V1_INTENT_KEYS);
  if(fields===null||fields.schemaVersion!=='verification-intent-snapshot.v1'
    ||fields.resourceType!=='account-session-set'||typeof fields.intentId!=='string'
    ||!INTENT_ID.test(fields.intentId)||typeof fields.runId!=='string'
    ||fields.resourceId!=='owner'||fields.dependencyOrder!==40
    ||fields.lifecycleClass!=='session-aggregate'||!['planned','created','absent'].includes(fields.state)
    ||!Number.isSafeInteger(fields.intentVersion)||fields.intentVersion<1
    ||fields.observationDigest!==null||fields.retentionExpiresAt!==null
    ||!validIso(fields.createdAt)||!validIso(fields.updatedAt)
    ||Date.parse(fields.updatedAt)<Date.parse(fields.createdAt)
    ||!sortedUniqueProviderIds(fields.providerResourceIds)
    ||fields.providerResourceIds.length>4
    ||fields.providerResourceIds.some((id)=>!RECOVERY_ACCOUNT_SESSION_ID.test(id))
    ||(fields.state==='planned'&&fields.intentVersion!==1)
    ||(fields.state==='created'&&fields.intentVersion!==2)
    ||(fields.state==='absent'&&fields.intentVersion!==3))return null;
  return freeze(copy(fields));
}
function recoveryOrdinarySemanticIntent(value){
  try{
    if(intentSchemaVersion(value)==='verification-intent-snapshot.v2'){
      const recoveryDescriptor=Object.getOwnPropertyDescriptor(value,'recoveryCheckpointDigest');
      if(recoveryDescriptor!==undefined){
        const candidate=recoveryFields(value,[...V2_INTENT_KEYS,'recoveryCheckpointDigest']);
        if(candidate===null||candidate.recoveryCheckpointDigest!==null)return null;
        delete candidate.recoveryCheckpointDigest;
        return exactIntentObject(candidate)?freeze(candidate):null;
      }
    }
    return descriptorSafeIntentCopy(value);
  }catch{return null;}
}
function recoveryCurrentIntentDigest(intents,cursor){
  const terminalLink=cursor===0?null:(intents[cursor-1]?.recoveryCheckpointDigest??null);
  if(terminalLink===null){
    if(intents.some((intent)=>(intent.recoveryCheckpointDigest??null)!==null))
      throw new TypeError('recovery current intent links');
    return createRecoveryIntentSetDigest({intents});
  }
  return createRecoveryCurrentIntentSetDigest({intents,recoveryTerminalIndex:cursor-1});
}
function recoveryGenesisPositionFromSourceIntents(sourceIntents){
  let intentDispositionCursor=0;
  for(let index=0;index<sourceIntents.length;index+=1){
    const intent=sourceIntents[index];
    if((intent.recoveryCheckpointDigest??null)!==null)return null;
    if(intent.state==='absent'){
      if(index!==intentDispositionCursor)return null;
      intentDispositionCursor+=1;
    }else if(!['created','cleaning'].includes(intent.state))return null;
  }
  const prefixLength=RECOVERY_GENESIS_PREFIX_BY_ABSENT_COUNT[intentDispositionCursor];
  if(prefixLength===undefined)return null;
  try{
    deriveRecoveryPosition({prefixLength,intentDispositionCursor});
    return freeze({prefixLength,intentDispositionCursor});
  }catch{return null;}
}
function recoveryPositionEvidence(checkpoint){
  const position=deriveRecoveryPosition({
    prefixLength:checkpoint.prefixLength,intentDispositionCursor:checkpoint.intentDispositionCursor,
  });
  return freeze({prefixLength:checkpoint.prefixLength,
    intentDispositionCursor:checkpoint.intentDispositionCursor,logicalResource:position.logicalResource,
    stepId:position.stepId,phase:position.phase,action:position.action});
}
function recoveryTargetBindingDigest(sourceIntents,prefixLength,intentDispositionCursor){
  const position=deriveRecoveryPosition({prefixLength,intentDispositionCursor});
  if(position.logicalResource===null)return null;
  const source=sourceIntents.find(({resourceType})=>resourceType===position.logicalResource);
  if(source===undefined)throw new TypeError('recovery source target');
  return digest({schemaVersion:'verification-recovery-target-binding.v1',
    cleanupProtocolDigest:CLEANUP_PROTOCOL_DIGEST,logicalResource:position.logicalResource,
    stepId:position.stepId,phase:position.phase,action:position.action,intentId:source.intentId,
    resourceId:source.resourceId,providerAggregateDigest:source.providerAggregateDigest});
}
function recoveryGenesisProgressDigest(checkpoint){
  return digest({domain:'verification-recovery-progress-genesis.v1',payload:{
    schemaVersion:RECOVERY_CHECKPOINT_SCHEMA_VERSION,source:{
      environmentDigest:checkpoint.environmentDigest,cleanupProtocolDigest:checkpoint.cleanupProtocolDigest,
      sourceAuditHeadDigest:checkpoint.sourceAuditHeadDigest,
      sourceLeaseVersion:checkpoint.sourceLeaseVersion,sourceLedgerDigest:checkpoint.sourceLedgerDigest,
      sourceIntentSetDigest:checkpoint.sourceIntentSetDigest,
      currentIntentSetDigest:checkpoint.currentIntentSetDigest,
      ordinaryExecutionEvidenceDigest:checkpoint.ordinaryExecutionEvidenceDigest,
      accountSessionAbsenceDigest:checkpoint.accountSessionAbsenceDigest,
    },transition:'recovery.checkpoint_started',catalogPosition:recoveryPositionEvidence(checkpoint),
    targetBindingDigest:checkpoint.targetBindingDigest,providerObservationDigest:null,
  }});
}
function makeRecoveryGenesis(reconstruction){
  const sourceIntentSetDigest=createRecoveryIntentSetDigest({intents:reconstruction.sourceIntents});
  const genesisPosition=recoveryGenesisPositionFromSourceIntents(reconstruction.sourceIntents);
  if(genesisPosition===null)throw new TypeError('recovery genesis source');
  const {prefixLength,intentDispositionCursor}=genesisPosition;
  const position=deriveRecoveryPosition({prefixLength,intentDispositionCursor});
  let checkpoint={schemaVersion:RECOVERY_CHECKPOINT_SCHEMA_VERSION,
    environmentDigest:reconstruction.lease.environmentDigest,cleanupProtocolDigest:CLEANUP_PROTOCOL_DIGEST,
    sourceAuditHeadDigest:reconstruction.sourceAuditHeadDigest,
    sourceLeaseVersion:reconstruction.sourceLeaseVersion,
    sourceLedgerDigest:reconstruction.sourceAuditHeadDigest,sourceIntentSetDigest,
    currentIntentSetDigest:recoveryCurrentIntentDigest(
      reconstruction.sourceIntents,intentDispositionCursor),
    ordinaryExecutionEvidenceDigest:createOrdinaryExecutionEvidenceDigest({
      intents:reconstruction.sourceIntents,
    }),accountSessionAbsenceDigest:RECOVERY_ACCOUNT_SESSION_ABSENCE_DIGEST,
    priorCheckpointDigest:null,eventOrdinal:0,prefixLength,intentDispositionCursor,
    checkpointState:'ready',logicalResource:position.logicalResource,stepId:position.stepId,
    phase:position.phase,action:position.action,
    targetBindingDigest:recoveryTargetBindingDigest(reconstruction.sourceIntents,
      prefixLength,intentDispositionCursor),
    attemptOrdinal:null,preWriteProjectionDigest:null,desiredProjectionDigest:null,
    providerObservationDigest:null,recoveryProgressDigest:`sha256:${'0'.repeat(64)}`,
    cleanupProofDigest:null};
  checkpoint={...checkpoint,recoveryProgressDigest:recoveryGenesisProgressDigest(checkpoint)};
  return freeze(validateRecoveryCheckpoint(checkpoint));
}
function makeRecoveryEvent({checkpoint,transition,previousLedgerDigest,runId,intentSuccessor=null}){
  const checkpointDigest=createRecoveryCheckpointDigest(checkpoint);
  return freeze({schemaVersion:'verification-audit-event.v1',previousLedgerDigest,runId,
    leaseVersionBefore:checkpoint.sourceLeaseVersion+checkpoint.eventOrdinal,
    leaseVersionAfter:checkpoint.sourceLeaseVersion+checkpoint.eventOrdinal+1,transition,
    intentId:intentSuccessor?.intentId??null,
    intentProjectionDigest:intentSuccessor===null?null:digest(intentSuccessor),
    recoveryCheckpointJson:canonicalJson(checkpoint),recoveryCheckpointDigest:checkpointDigest,
    recoveryPreviousCheckpointDigest:checkpoint.priorCheckpointDigest});
}
function exactRecoverySourceBindings(checkpoint,reconstruction,currentIntents){
  return checkpoint.environmentDigest===reconstruction.lease.environmentDigest
    &&checkpoint.sourceAuditHeadDigest===reconstruction.sourceAuditHeadDigest
    &&checkpoint.sourceLeaseVersion===reconstruction.sourceLeaseVersion
    &&checkpoint.sourceLedgerDigest===reconstruction.sourceAuditHeadDigest
    &&checkpoint.sourceIntentSetDigest===createRecoveryIntentSetDigest({intents:reconstruction.sourceIntents})
    &&checkpoint.currentIntentSetDigest===recoveryCurrentIntentDigest(
      currentIntents,checkpoint.intentDispositionCursor)
    &&checkpoint.ordinaryExecutionEvidenceDigest===createOrdinaryExecutionEvidenceDigest({
      intents:reconstruction.sourceIntents,
    })
    &&checkpoint.accountSessionAbsenceDigest===RECOVERY_ACCOUNT_SESSION_ABSENCE_DIGEST
    &&checkpoint.targetBindingDigest===recoveryTargetBindingDigest(reconstruction.sourceIntents,
      checkpoint.prefixLength,checkpoint.intentDispositionCursor);
}

function recoverableSourceLeaseState(state, cleanupDebt) {
  return (state === 'active' && cleanupDebt === false)
    || (state === 'cleanup-debt' && cleanupDebt === true);
}

function recoverableCurrentLeaseState(state, cleanupDebt) {
  return recoverableSourceLeaseState(state, cleanupDebt)
    || (state === 'recovering' && cleanupDebt === true);
}

function recoverySourceIntentsFromResourceMap(resourceMap){
  const matches=QUALIFIED_CLEANUP_PROTOCOL.resourceOrder.map((resourceType)=>(
    [...resourceMap.values()].filter((intent)=>intent.resourceType===resourceType)
  ));
  if(matches.every((items)=>items.length===0))return [];
  if(matches.some((items)=>items.length!==1))throw new TypeError('recovery resource set');
  return matches.map(([intent])=>intent);
}

function reconstructRecoverySnapshot(snapshot){
  try{
    const root=recoveryFields(snapshot,RECOVERY_SNAPSHOT_KEYS);
    const lease=root===null?null:recoveryFields(root.lease,RECOVERY_LEASE_KEYS);
    const auditTrail=root===null?null:recoveryDenseArray(root.auditTrail);
    const intentProjections=root===null?null:recoveryDenseArray(root.intentProjections);
    if(lease===null||auditTrail===null||intentProjections===null
      ||lease.leaseRowId!=='appwrite_test_verification'||!Number.isSafeInteger(lease.leaseVersion)
      ||lease.leaseVersion<0||!DIGEST.test(lease.ledgerDigest)||!DIGEST.test(lease.environmentDigest)
      ||typeof lease.ownerRunId!=='string'||typeof lease.ownerWorkflowRunId!=='string'
      ||!recoverableCurrentLeaseState(lease.state,lease.cleanupDebt))return null;
    let expectedPrevious=GENESIS_LEDGER_DIGEST,expectedVersion=0,activeRun=null;
    let ordinaryLeaseState='idle';
    let resourceMap=new Map(),ordinaryLatest=new Map(),ordinaryCleanupRoots=new Map();
    let accountSessionIntent=null,accountSessionIntentIds=new Set(),recoveryStarted=false;
    let sourceIntents=null,sourceAuditHeadDigest=null,sourceLeaseVersion=null;
    let currentIntents=null,predecessorRecoveryEvent=null,checkpoint=null;
    const checkedTrail=[];
    for(const rawEntry of auditTrail){
      const entry=recoveryFields(rawEntry,RECOVERY_ENTRY_KEYS);
      if(entry===null||!DIGEST.test(entry.digest))return null;
      const isRecovery=recoveryEventHasCheckpoint(entry.event);
      let event,checkpointValue=null,eventDigestValue,checkedSnapshot=null;
      if(isRecovery){
        if(!exactObject(entry.event,RECOVERY_AUDIT_KEYS))return null;
        const validated=validateRecoveryAuditEvent(entry.event);
        event=validated.event;checkpointValue=validated.checkpoint;
        eventDigestValue=createRecoveryAuditEventDigest(event);
      }else{
        if(!exactObject(entry.event,ORDINARY_AUDIT_KEYS)||recoveryStarted)return null;
        event=copy(entry.event);eventDigestValue=digest(event);
        if(!RECOVERY_ORDINARY_TRANSITIONS.has(event.transition))return null;
      }
      if(eventDigestValue!==entry.digest||event.previousLedgerDigest!==expectedPrevious
        ||event.leaseVersionBefore!==expectedVersion
        ||event.leaseVersionAfter!==expectedVersion+1)return null;
      if(event.transition==='lease.acquire'){
        if(activeRun!==null||ordinaryLeaseState!=='idle'
          ||event.intentId!==null||event.intentProjectionDigest!==null)return null;
        activeRun=event.runId;resourceMap=new Map();ordinaryLatest=new Map();
        ordinaryCleanupRoots=new Map();accountSessionIntent=null;accountSessionIntentIds=new Set();
        ordinaryLeaseState='active';
      }else if(event.runId!==activeRun)return null;
      if(!isRecovery&&event.intentProjectionDigest===null){
        if(event.transition==='lease.renew'){
          if(ordinaryLeaseState!=='active')return null;
        }else if(event.transition==='lease.cleanup_debt'){
          if(ordinaryLeaseState!=='active')return null;
          ordinaryLeaseState='cleanup-debt';
        }else if(event.transition==='lease.recover'){
          if(ordinaryLeaseState!=='cleanup-debt')return null;
          ordinaryLeaseState='recovering';
        }else if(event.transition==='lease.close'){
          if(!['active','recovering'].includes(ordinaryLeaseState))return null;
          ordinaryLeaseState='idle';activeRun=null;
        }
      }
      if(!isRecovery){
        if(event.intentProjectionDigest===null){if(event.intentId!==null||entry.snapshot!==null)return null;}
        else{
          const sessionIntent=recoveryV1AccountSession(entry.snapshot);
          const resourceIntent=sessionIntent===null?recoveryIntent(entry.snapshot):null;
          const semanticIntent=recoveryOrdinarySemanticIntent(entry.snapshot);
          const primaryExecutionIntent=semanticIntent?.schemaVersion==='verification-intent-snapshot.v1'
            &&semanticIntent.resourceType==='primary-execution'?semanticIntent:null;
          const ordinarySessionIntent=semanticIntent?.schemaVersion==='verification-intent-snapshot.v1'
            &&semanticIntent.resourceType==='account-session'?semanticIntent:null;
          const normalizedIntent=resourceIntent??sessionIntent??primaryExecutionIntent
            ??ordinarySessionIntent;
          if(normalizedIntent===null||digest(normalizedIntent)!==event.intentProjectionDigest
            ||normalizedIntent.intentId!==event.intentId||normalizedIntent.runId!==event.runId)return null;
          if(semanticIntent===null)return null;
          const prior=ordinaryLatest.get(semanticIntent.intentId);
          const validationContext={providerContractDigest:null,
            cleanupRoot:ordinaryCleanupRoots.get(semanticIntent.intentId)
              ??(prior?.state==='created'?prior:null)};
          if(!legalSnapshotSuccessor(prior,semanticIntent,
            PRIMARY_EXECUTION_RETENTION_MAX_SECONDS,validationContext)
            ||!transitionMatchesSnapshot(prior,semanticIntent,event.transition))return null;
          if(semanticIntent.schemaVersion==='verification-intent-snapshot.v2'
            &&semanticIntent.state==='created'&&!ordinaryCleanupRoots.has(semanticIntent.intentId)){
            ordinaryCleanupRoots.set(semanticIntent.intentId,semanticIntent);
          }
          ordinaryLatest.set(semanticIntent.intentId,semanticIntent);
          checkedSnapshot=normalizedIntent;
          if(resourceIntent!==null&&RECOVERY_RESOURCE_TYPES.has(resourceIntent.resourceType)){
            if(resourceIntent.environmentDigest!==lease.environmentDigest)return null;
            resourceMap.set(resourceIntent.intentId,resourceIntent);
          }else if(sessionIntent!==null){
            accountSessionIntentIds.add(sessionIntent.intentId);
            if(accountSessionIntentIds.size!==1)return null;
            accountSessionIntent=sessionIntent;
          }
          else if(primaryExecutionIntent===null&&ordinarySessionIntent===null)return null;
        }
      }else{
        if(!recoveryStarted){
          if(!['active','cleanup-debt'].includes(ordinaryLeaseState))return null;
          recoveryStarted=true;sourceAuditHeadDigest=expectedPrevious;
          sourceLeaseVersion=event.leaseVersionBefore;
          sourceIntents=recoverySourceIntentsFromResourceMap(resourceMap);
          const genesisPosition=recoveryGenesisPositionFromSourceIntents(sourceIntents);
          if(sourceIntents.length!==3
            ||new Set(sourceIntents.map(({intentId})=>intentId)).size!==3
            ||genesisPosition===null
            ||sourceIntents.some((intent)=>intent.runId!==activeRun
              ||intent.environmentDigest!==lease.environmentDigest))return null;
          currentIntents=sourceIntents.map(copy);
          const sourceBinding={lease,sourceIntents,sourceAuditHeadDigest,sourceLeaseVersion};
          if(checkpointValue.eventOrdinal!==0||event.transition!=='recovery.checkpoint_started'
            ||checkpointValue.prefixLength!==genesisPosition.prefixLength
            ||checkpointValue.intentDispositionCursor!==genesisPosition.intentDispositionCursor
            ||entry.snapshot!==null||!exactRecoverySourceBindings(
              checkpointValue,sourceBinding,currentIntents))return null;
        }else{
          let terminalIntentTransition=null;
          if(event.transition==='intent.recovery_absent'){
            const cursor=checkpoint.intentDispositionCursor;
            const candidate=recoveryIntent(entry.snapshot);
            if(candidate===null||cursor<0||cursor>=currentIntents.length)return null;
            checkedSnapshot=candidate;
            const priorIntents=currentIntents.map(copy);
            const nextIntents=currentIntents.map((intent,index)=>index===cursor?candidate:intent);
            terminalIntentTransition={predecessor:priorIntents[cursor],candidate,
              sourceIntents,priorIntents,currentIntents:nextIntents};
            currentIntents=nextIntents;
          }else if(entry.snapshot!==null)return null;
          validateRecoveryCheckpointSuccessor({authenticatedAuditHeadDigest:expectedPrevious,
            predecessorEvent:predecessorRecoveryEvent,event,
            terminalIntentTransition});
          const sourceBinding={lease,sourceIntents,sourceAuditHeadDigest,sourceLeaseVersion};
          if(!exactRecoverySourceBindings(checkpointValue,sourceBinding,currentIntents))return null;
        }
        checkpoint=checkpointValue;predecessorRecoveryEvent=event;
      }
      checkedTrail.push(freeze({digest:entry.digest,event:freeze(event),
        snapshot:checkedSnapshot===null?null:freeze(copy(checkedSnapshot))}));
      expectedPrevious=entry.digest;expectedVersion=event.leaseVersionAfter;
    }
    if(activeRun!==lease.ownerRunId||lease.ownerWorkflowRunId===null
      ||expectedPrevious!==lease.ledgerDigest||expectedVersion!==lease.leaseVersion)return null;
    if(!recoveryStarted){
      sourceAuditHeadDigest=lease.ledgerDigest;sourceLeaseVersion=lease.leaseVersion;
      sourceIntents=recoverySourceIntentsFromResourceMap(resourceMap);
      const genesisPosition=recoveryGenesisPositionFromSourceIntents(sourceIntents);
      if(![0,3].includes(sourceIntents.length)
        ||new Set(sourceIntents.map(({intentId})=>intentId)).size!==sourceIntents.length
        ||genesisPosition===null
        ||sourceIntents.some((intent)=>intent.runId!==activeRun
          ||intent.environmentDigest!==lease.environmentDigest))return null;
      currentIntents=sourceIntents.map(copy);
      if(ordinaryLeaseState!==lease.state
        ||!recoverableSourceLeaseState(lease.state,lease.cleanupDebt))return null;
    }else if(lease.state!=='recovering'||lease.cleanupDebt!==true
      ||!['active','cleanup-debt'].includes(ordinaryLeaseState))return null;
    const projectionMap=new Map(),projectionIds=new Set();let priorProjectionId=null;
    for(const rawProjection of intentProjections){
      const item=recoveryFields(rawProjection,RECOVERY_PROJECTION_KEYS);
      if(item===null||typeof item.intentId!=='string'||item.projection===null
        ||item.intentId===priorProjectionId||projectionIds.has(item.intentId))return null;
      if(priorProjectionId!==null&&priorProjectionId>item.intentId)return null;
      priorProjectionId=item.intentId;projectionIds.add(item.intentId);
      const intent=recoveryIntent(item.projection);
      if(intent!==null&&intent.intentId===item.intentId&&RECOVERY_RESOURCE_TYPES.has(intent.resourceType)){
        projectionMap.set(item.intentId,intent);continue;
      }
      const sessionProjection=recoveryV1AccountSession(item.projection);
      if(sessionProjection!==null){
        const expected=ordinaryLatest.get(item.intentId);
        if(expected===undefined||canonicalJson(sessionProjection)!==canonicalJson(expected))return null;
        continue;
      }
      const semanticIntent=recoveryOrdinarySemanticIntent(item.projection);
      const ordinaryProjection=semanticIntent?.schemaVersion==='verification-intent-snapshot.v1'
        &&semanticIntent.resourceType==='primary-execution'?semanticIntent:null;
      const expectedOrdinary=ordinaryProjection===null?null:ordinaryLatest.get(item.intentId);
      if(ordinaryProjection===null||expectedOrdinary===undefined
        ||canonicalJson(ordinaryProjection)!==canonicalJson(expectedOrdinary))return null;
    }
    if(projectionMap.size!==currentIntents.length||currentIntents.some((intent)=>{
      const projection=projectionMap.get(intent.intentId);
      return projection===undefined||canonicalJson(projection)!==canonicalJson(intent);
    }))return null;
    return freeze({lease:freeze(copy(lease)),snapshot:freeze(copy(root)),
      auditTrail:freeze(checkedTrail),sourceIntents:freeze(sourceIntents.map(copy)),
      currentIntents:freeze(currentIntents.map(copy)),sourceAuditHeadDigest,sourceLeaseVersion,
      accountSessionIntent:accountSessionIntent===null?null:freeze(copy(accountSessionIntent)),
      checkpoint:checkpoint===null?null:freeze(copy(checkpoint)),
      recoveryEvent:predecessorRecoveryEvent===null?null:freeze(copy(predecessorRecoveryEvent))});
  }catch{return null;}
}

function bindRecoverySession({context,store,reconstruction,nextRequest,createCommitOperation=null}){
  const session=freeze(Object.create(null));
  const previous=ACTIVE_RECOVERY_SESSIONS.get(context);
  if(previous!==undefined)previous.invalid=true;
  RECOVERY_SESSIONS.set(session,{context,store,reconstruction,nextRequest,createCommitOperation,
    generation:0,invalid:false,liveStepHandles:new Map(),liveMutationPermits:new Map(),
    liveAccountSessionListHandles:new Map(),liveAccountSessionDeletePermits:new Map(),
    exhaustedStepDigests:new Set(),exhaustedMutationDigests:new Set()});
  ACTIVE_RECOVERY_SESSIONS.set(context,RECOVERY_SESSIONS.get(session));
  return session;
}
function updateRecoverySession(binding,reconstruction,nextRequest,createCommitOperation=null,
  advanceGeneration=true){
  binding.reconstruction=reconstruction;binding.nextRequest=nextRequest;
  binding.createCommitOperation=createCommitOperation;
  if(advanceGeneration){
    binding.generation+=1;binding.liveStepHandles.clear();binding.liveMutationPermits.clear();
    binding.liveAccountSessionListHandles.clear();binding.liveAccountSessionDeletePermits.clear();
  }
}
function recoveryAuthorization(binding,checkpoint,kind,options=freeze({})){
  const checkpointDigest=createRecoveryCheckpointDigest(checkpoint);
  const authorizationId=options.authorizationId??'default';
  const authorizationKey=`${checkpointDigest}:${authorizationId}`;
  const exhausted=kind==='step'?binding.exhaustedStepDigests:binding.exhaustedMutationDigests;
  const liveHandles=kind==='step'?binding.liveStepHandles:binding.liveMutationPermits;
  const map=kind==='step'?RECOVERY_STEP_HANDLES:RECOVERY_MUTATION_PERMITS;
  const used=kind==='step'?USED_RECOVERY_STEP_HANDLES:USED_RECOVERY_MUTATION_PERMITS;
  if(exhausted.has(authorizationKey))return null;
  const live=liveHandles.get(authorizationKey)??null,liveRecord=live===null?null:map.get(live);
  if(liveRecord!==null&&liveRecord!==undefined&&!used.has(live)
    &&liveRecord.generation===binding.generation
    &&liveRecord.authorizationKey===authorizationKey)return live;
  const value=freeze(Object.create(null));
  const record={kind,context:binding.context,sessionBinding:binding,generation:binding.generation,
    checkpointDigest,authorizationKey,productQuery:options.productQuery??null,
    prefixLength:checkpoint.prefixLength,
    intentDispositionCursor:checkpoint.intentDispositionCursor,logicalResource:checkpoint.logicalResource,
    stepId:checkpoint.stepId,phase:checkpoint.phase,action:checkpoint.action,
    targetBindingDigest:checkpoint.targetBindingDigest,attemptOrdinal:checkpoint.attemptOrdinal,
    preWriteProjectionDigest:checkpoint.preWriteProjectionDigest,
    desiredProjectionDigest:options.desiredProjectionDigest??checkpoint.desiredProjectionDigest};
  map.set(value,record);liveHandles.set(authorizationKey,value);
  return value;
}
function recoveryExtraQueryStepHandles(binding,checkpoint){
  const queries=RECOVERY_PRODUCT_EXTRA_QUERY_STEPS[checkpoint.stepId]??[];
  const handles={};
  for(const query of queries){
    const desiredProjectionDigest=recoveryProductQueryDigestOrNull(binding,query);
    if(desiredProjectionDigest===null)continue;
    const handle=recoveryAuthorization(binding,checkpoint,'step',{
      authorizationId:`query:${query.method}`,productQuery:query,
      desiredProjectionDigest,
    });
    if(handle!==null)handles[query.method]=handle;
  }
  return Object.keys(handles).length===0?null:freeze(handles);
}
function recoveryReadCapability(binding,checkpoint){
  if(checkpoint===null||checkpoint.prefixLength===42||checkpoint.checkpointState==='resources-complete'
    ||checkpoint.action===null)return {};
  if(checkpoint.checkpointState==='write-issued'
    &&['delete-and-prove-absent','converge-owner-only'].includes(checkpoint.action)
    &&DIGEST.test(checkpoint.preWriteProjectionDigest)
    &&DIGEST.test(checkpoint.desiredProjectionDigest)){
    const stepHandle=recoveryAuthorization(binding,checkpoint,'step');
    return freeze(stepHandle===null?{}:{stepHandle});
  }
  if(checkpoint.checkpointState!=='ready')return {};
  const query=RECOVERY_PRODUCT_QUERY_STEPS[checkpoint.stepId];
  const queryDigest=query===undefined?null:recoveryProductQueryDigestOrNull(binding,query);
  const stepHandle=recoveryAuthorization(binding,checkpoint,'step',queryDigest===null?freeze({})
    :freeze({desiredProjectionDigest:queryDigest}));
  const queryStepHandles=recoveryExtraQueryStepHandles(binding,checkpoint);
  return freeze({...(stepHandle===null?{}:{stepHandle}),
    ...(queryStepHandles===null?{}:{queryStepHandles})});
}
function recoveryCommitCapability(binding,checkpoint,transition){
  if(transition==='recovery.mutation_issued'){
    const mutationPermit=recoveryAuthorization(binding,checkpoint,'mutation');
    return mutationPermit===null?{}:{mutationPermit};
  }
  if(['recovery.checkpoint_started','recovery.step_committed','intent.recovery_absent'].includes(transition)
    &&checkpoint.checkpointState==='ready'&&checkpoint.prefixLength<42)
    return recoveryReadCapability(binding,checkpoint);
  return {};
}
function exactRecoverySession(binding,context,store){
  return binding!==undefined&&!binding.invalid&&binding.context===context&&binding.store===store
    &&ACTIVE_RECOVERY_SESSIONS.get(context)===binding;
}

function mintRecoveryAccountSessionAuthorization(binding,kind,target,authorizationId){
  const map=kind==='list'?RECOVERY_ACCOUNT_SESSION_LIST_HANDLES
    :RECOVERY_ACCOUNT_SESSION_DELETE_PERMITS;
  const live=kind==='list'?binding.liveAccountSessionListHandles
    :binding.liveAccountSessionDeletePermits;
  const existing=live.get(authorizationId),existingRecord=existing===undefined?undefined:map.get(existing);
  if(existingRecord!==undefined&&existingRecord.generation===binding.generation)return existing;
  const token=freeze(Object.create(null));
  map.set(token,{context:binding.context,sessionBinding:binding,generation:binding.generation,
    authorizationId,target:freeze(copy(target)),
    sessionIntentDigest:digest(binding.reconstruction.accountSessionIntent)});
  live.set(authorizationId,token);
  return token;
}

export async function openRecoveryAccountSessionStage(input){
  try{
    const fields=recoveryFields(input,['clock','context','request','store']);
    if(fields===null||!isAuthenticTestRecoveryEnvironmentContext(fields.context)
      ||!isAuthenticProviderRecoveryControlStore(fields.store,fields.context)
      ||recoveryFields(fields.clock,['nowEpochSeconds'])===null)
      return blocked('RECOVERY_ACCOUNT_SESSION_BINDING_INVALID');
    const now=fields.clock.nowEpochSeconds();
    if(!Number.isSafeInteger(now)||now<0)return blocked('RECOVERY_ACCOUNT_SESSION_LEASE_INVALID');
    const outcome=await fields.store.readRecoveryAccountSessionSource(fields.request);
    const createdRead=recoveryStorePassValue(outcome,
      ['createAbsenceOperation','nextRequest','snapshot']);
    const absentRead=createdRead===null
      ?recoveryStorePassValue(outcome,['nextRequest','snapshot']):null;
    const read=createdRead??absentRead;
    if(read===null){
      const sourceCode=outcome?.diagnostics?.length===1?outcome.diagnostics[0]?.code:null;
      if(['RECOVERY_ACCOUNT_SESSION_PROVIDER_READ_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROVIDER_PROOF_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROVIDER_INTENT_MISSING',
        'RECOVERY_ACCOUNT_SESSION_PROVIDER_INTENT_STATE_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_ACQUIRE_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_RUN_CHAIN_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_RENEW_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_CLEANUP_DEBT_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_RECOVER_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_CLOSE_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_SOURCE_STATE_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_OWNER_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_OWNER_RUN_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_OWNER_DEBT_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_OWNER_WORKFLOW_TYPE_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_OWNER_WORKFLOW_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_RECOVERY_STATE_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_PROVIDER_BINDING_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_INTENT_EVIDENCE_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_GLOBAL_CLEANUP_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_SESSION_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_INTENT_SET_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_INTENT_SET_CARDINALITY_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_PRIMARY_SHARE_MISSING',
        'RECOVERY_ACCOUNT_SESSION_PROOF_PRIMARY_SHARE_DUPLICATED',
        'RECOVERY_ACCOUNT_SESSION_PROOF_PRIMARY_GRAPH_MISSING',
        'RECOVERY_ACCOUNT_SESSION_PROOF_PRIMARY_GRAPH_DUPLICATED',
        'RECOVERY_ACCOUNT_SESSION_PROOF_PRIMARY_PROJECT_MISSING',
        'RECOVERY_ACCOUNT_SESSION_PROOF_PRIMARY_PROJECT_DUPLICATED',
        'RECOVERY_ACCOUNT_SESSION_PROOF_MISSING_PROJECT',
        'RECOVERY_ACCOUNT_SESSION_PROOF_MISSING_GRAPH',
        'RECOVERY_ACCOUNT_SESSION_PROOF_MISSING_GRAPH_PROJECT',
        'RECOVERY_ACCOUNT_SESSION_PROOF_MISSING_SHARE',
        'RECOVERY_ACCOUNT_SESSION_PROOF_MISSING_SHARE_PROJECT',
        'RECOVERY_ACCOUNT_SESSION_PROOF_MISSING_SHARE_GRAPH',
        'RECOVERY_ACCOUNT_SESSION_PROOF_MISSING_ALL_RESOURCES',
        'RECOVERY_ACCOUNT_SESSION_PROOF_INTENT_SET_POSITION_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_INTENT_SET_RUN_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_INTENT_SET_ENVIRONMENT_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_INTENT_SET_ACCOUNT_SESSION_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_RECOVERY_EVENT_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_PROJECTION_INVALID',
        'RECOVERY_ACCOUNT_SESSION_PROOF_PROJECTION_MISSING',
        'RECOVERY_ACCOUNT_SESSION_PROOF_PROJECTION_UNEXPECTED',
        'RECOVERY_ACCOUNT_SESSION_PROOF_PROJECTION_MISMATCH'].includes(sourceCode)){
        return blocked(sourceCode);
      }
      return blocked('RECOVERY_ACCOUNT_SESSION_SOURCE_INVALID');
    }
    const reconstruction=reconstructRecoverySnapshot(read.snapshot);
    const intent=reconstruction?.accountSessionIntent;
    if(reconstruction===null)return blocked('RECOVERY_ACCOUNT_SESSION_SNAPSHOT_INVALID');
    if(reconstruction.lease.ownerWorkflowRunId!==fields.context.sourceWorkflowRunId)
      return blocked('RECOVERY_ACCOUNT_SESSION_BINDING_INVALID');
    const freshDebt=reconstruction.checkpoint===null
      &&recoverableSourceLeaseState(reconstruction.lease.state,reconstruction.lease.cleanupDebt);
    const resumableRecovery=reconstruction.lease.state==='recovering'
      &&intent?.state==='absent';
    if((!freshDebt&&!resumableRecovery)
      ||!validIso(reconstruction.lease.expiresAt)
      ||Date.parse(reconstruction.lease.expiresAt)>now*1000)
      return blocked('RECOVERY_ACCOUNT_SESSION_LEASE_INVALID');
    if(intent===null&&reconstruction.sourceIntents.length===0){
      return pass(freeze({nextAuthority:read.nextRequest,
        sessionAbsenceDigest:RECOVERY_ACCOUNT_SESSION_ABSENCE_DIGEST,
        measurements:freeze({knownProductCalls:0,maximumProductCalls:0,
          knownStoreCalls:1,maximumStoreCalls:1})}));
    }
    if(intent===null)return blocked('RECOVERY_ACCOUNT_SESSION_INTENT_MISSING');
    if(intent.runId!==reconstruction.lease.ownerRunId
      ||intent.environmentDigest!==reconstruction.lease.environmentDigest)
      return blocked('RECOVERY_ACCOUNT_SESSION_BINDING_INVALID');
    if(absentRead!==null){
      if(intent.state!=='absent')return blocked('RECOVERY_ACCOUNT_SESSION_BINDING_INVALID');
      return pass(freeze({nextAuthority:read.nextRequest,
        sessionAbsenceDigest:RECOVERY_ACCOUNT_SESSION_ABSENCE_DIGEST,
        measurements:freeze({knownProductCalls:0,maximumProductCalls:10,
          knownStoreCalls:1,maximumStoreCalls:2})}));
    }
    if(reconstruction.checkpoint!==null||intent.state!=='created'
      ||typeof read.createAbsenceOperation!=='function')
      return blocked('RECOVERY_ACCOUNT_SESSION_BINDING_INVALID');
    const binding={context:fields.context,store:fields.store,reconstruction,nextRequest:read.nextRequest,
      createCommitOperation:null,createAbsenceOperation:read.createAbsenceOperation,
      generation:0,invalid:false,
      liveStepHandles:new Map(),liveMutationPermits:new Map(),
      liveAccountSessionListHandles:new Map(),liveAccountSessionDeletePermits:new Map(),
      exhaustedStepDigests:new Set(),exhaustedMutationDigests:new Set(),
      accountSessionStage:{boundIds:[...intent.providerResourceIds],callCount:0,
        issuedDeleteIds:new Set(),reconciledDeleteIds:new Set(),remainingIds:[],
        pendingDeleteId:null,phase:'initial-list'}};
    const session=freeze(Object.create(null));
    const prior=ACTIVE_RECOVERY_SESSIONS.get(fields.context);
    if(prior!==undefined)prior.invalid=true;
    RECOVERY_SESSIONS.set(session,binding);ACTIVE_RECOVERY_SESSIONS.set(fields.context,binding);
    const ownerUserId=recoveryOwnerUserId(binding);
    binding.accountSessionStage.ownerUserId=ownerUserId;
    const ids=intent.providerResourceIds;
    const listHandle=mintRecoveryAccountSessionAuthorization(binding,'list',
      {userId:ownerUserId,sessionIds:ids},'initial-list');
    return pass(freeze({session,listHandle}));
  }catch{return blocked('RECOVERY_ACCOUNT_SESSION_BINDING_INVALID');}
}

export async function openRecoveryCheckpoint(input){
  try{
    const fields=recoveryFields(input,['clock','context','request','store']);
    if(fields===null||!isAuthenticTestRecoveryEnvironmentContext(fields.context)
      ||!isAuthenticProviderRecoveryControlStore(fields.store,fields.context)
      ||recoveryFields(fields.clock,['nowEpochSeconds'])===null)return blocked('AUDIT_CHAIN_MISMATCH');
    const now=fields.clock.nowEpochSeconds();
    if(!Number.isSafeInteger(now)||now<0)return blocked('AUDIT_CHAIN_MISMATCH');
    const readOutcome=await fields.store.readRecoverySnapshot(fields.request);
    const read=recoveryStorePassValue(readOutcome,['createCommitOperation','nextRequest','snapshot']);
    if(read===null||typeof read.createCommitOperation!=='function')return blocked('AUDIT_CHAIN_MISMATCH');
    let reconstruction=reconstructRecoverySnapshot(read.snapshot);
    if(reconstruction===null
      ||reconstruction.lease.ownerWorkflowRunId!==fields.context.sourceWorkflowRunId)
      return blocked('AUDIT_CHAIN_MISMATCH');
    let nextRequest=read.nextRequest;
    if(reconstruction.checkpoint===null){
      if(!validIso(reconstruction.lease.expiresAt)||Date.parse(reconstruction.lease.expiresAt)>now*1000)
        return blocked('LEASE_VERSION_MISMATCH');
      if(reconstruction.sourceIntents.length===0){
        const session=bindRecoverySession({context:fields.context,store:fields.store,
          reconstruction,nextRequest});
        return pass(freeze({emptyResourceSet:true,session,
          snapshot:copy(reconstruction.snapshot)}));
      }
      const checkpoint=makeRecoveryGenesis(reconstruction);
      const event=makeRecoveryEvent({checkpoint,transition:'recovery.checkpoint_started',
        previousLedgerDigest:reconstruction.lease.ledgerDigest,runId:reconstruction.lease.ownerRunId});
      const nextLease=freeze({...reconstruction.lease,state:'recovering',
        leaseVersion:reconstruction.lease.leaseVersion+1,
        ledgerDigest:createRecoveryAuditEventDigest(event)});
      const operation=read.createCommitOperation({event,nextLease,intentSuccessor:null});
      const committedOutcome=await fields.store.commitRecoveryTransition(operation);
      const committed=recoveryStorePassValue(committedOutcome,['nextRequest','snapshot']);
      if(committed===null)return blocked('AUDIT_CHAIN_MISMATCH');
      reconstruction=reconstructRecoverySnapshot(committed.snapshot);
      if(reconstruction===null||reconstruction.checkpoint===null
        ||createRecoveryCheckpointDigest(reconstruction.checkpoint)!==createRecoveryCheckpointDigest(checkpoint))
        return blocked('AUDIT_CHAIN_MISMATCH');
      nextRequest=committed.nextRequest;
    }
    const session=bindRecoverySession({context:fields.context,store:fields.store,
      reconstruction,nextRequest});
    return pass(freeze({session,snapshot:copy(reconstruction.snapshot)}));
  }catch{return blocked('AUDIT_CHAIN_MISMATCH');}
}

export async function readRecoveryCheckpointSnapshot(input){
  try{
    const fields=recoveryFields(input,['context','session','store']);
    if(fields===null||!isAuthenticTestRecoveryEnvironmentContext(fields.context)
      ||!isAuthenticProviderRecoveryControlStore(fields.store,fields.context))
      return blocked('AUDIT_CHAIN_MISMATCH');
    const binding=RECOVERY_SESSIONS.get(fields.session);
    if(!exactRecoverySession(binding,fields.context,fields.store))return blocked('AUDIT_CHAIN_MISMATCH');
    const outcome=await fields.store.readRecoverySnapshot(binding.nextRequest);
    const read=recoveryStorePassValue(outcome,['createCommitOperation','nextRequest','snapshot']);
    if(read===null||typeof read.createCommitOperation!=='function')return blocked('AUDIT_CHAIN_MISMATCH');
    const reconstruction=reconstructRecoverySnapshot(read.snapshot);
    if(reconstruction===null||canonicalJson(reconstruction.snapshot)!==canonicalJson(binding.reconstruction.snapshot)){
      binding.invalid=true;return blocked('LEASE_VERSION_MISMATCH');
    }
    updateRecoverySession(binding,reconstruction,read.nextRequest,read.createCommitOperation,false);
    return pass(freeze({snapshot:copy(reconstruction.snapshot),
      ...recoveryReadCapability(binding,reconstruction.checkpoint)}));
  }catch{return blocked('AUDIT_CHAIN_MISMATCH');}
}

export async function commitRecoveryCheckpoint(input){
  let sessionBinding=null;
  try{
    const keys=exactObject(input,['checkpoint','context','session','store','transition'])
      ?['checkpoint','context','session','store','transition']
      :exactObject(input,['checkpoint','context','intentSuccessor','session','store','transition'])
        ?['checkpoint','context','intentSuccessor','session','store','transition']:null;
    const fields=keys===null?null:recoveryFields(input,keys);
    if(fields===null||!isAuthenticTestRecoveryEnvironmentContext(fields.context)
      ||!isAuthenticProviderRecoveryControlStore(fields.store,fields.context))
      return blocked('AUDIT_CHAIN_MISMATCH');
    const binding=RECOVERY_SESSIONS.get(fields.session);
    if(!exactRecoverySession(binding,fields.context,fields.store))return blocked('LEASE_VERSION_MISMATCH');
    sessionBinding=binding;
    const fail=(code)=>{binding.invalid=true;binding.createCommitOperation=null;return blocked(code);};
    if(typeof fields.transition!=='string'||!RECOVERY_TRANSITIONS.has(fields.transition)
      ||typeof binding.createCommitOperation!=='function')return fail('AUDIT_CHAIN_MISMATCH');
    const predecessor=binding.reconstruction;
    if(predecessor.checkpoint===null||predecessor.recoveryEvent===null)return fail('AUDIT_CHAIN_MISMATCH');
    const checkpoint=validateRecoveryCheckpoint(fields.checkpoint);
    const intentSuccessor=Object.hasOwn(fields,'intentSuccessor')&&fields.intentSuccessor!==null
      ?recoveryIntent(fields.intentSuccessor):null;
    if((fields.transition==='intent.recovery_absent')!==(intentSuccessor!==null))
      return fail('AUDIT_CHAIN_MISMATCH');
    const event=makeRecoveryEvent({checkpoint,transition:fields.transition,
      previousLedgerDigest:predecessor.lease.ledgerDigest,runId:predecessor.lease.ownerRunId,
      intentSuccessor});
    let terminalIntentTransition=null;
    if(intentSuccessor!==null){
      const cursor=predecessor.checkpoint.intentDispositionCursor;
      const priorIntents=predecessor.currentIntents.map(copy);
      const currentIntents=priorIntents.map((intent,index)=>index===cursor?intentSuccessor:intent);
      terminalIntentTransition={predecessor:priorIntents[cursor],candidate:intentSuccessor,
        sourceIntents:predecessor.sourceIntents,priorIntents,currentIntents};
    }
    validateRecoveryCheckpointSuccessor({authenticatedAuditHeadDigest:predecessor.lease.ledgerDigest,
      predecessorEvent:predecessor.recoveryEvent,event,terminalIntentTransition});
    const expectedCurrent=terminalIntentTransition?.currentIntents??predecessor.currentIntents;
    if(!exactRecoverySourceBindings(checkpoint,predecessor,expectedCurrent))
      return fail('AUDIT_CHAIN_MISMATCH');
    const nextLease=freeze({...predecessor.lease,state:'recovering',cleanupDebt:true,
      leaseVersion:event.leaseVersionAfter,ledgerDigest:createRecoveryAuditEventDigest(event)});
    const operation=binding.createCommitOperation({event,nextLease,intentSuccessor});
    binding.createCommitOperation=null;
    const outcome=await fields.store.commitRecoveryTransition(operation);
    const committed=recoveryStorePassValue(outcome,['nextRequest','snapshot']);
    if(committed===null)return fail('AUDIT_CHAIN_MISMATCH');
    const reconstruction=reconstructRecoverySnapshot(committed.snapshot);
    if(reconstruction===null||reconstruction.recoveryEvent===null
      ||reconstruction.lease.ledgerDigest!==nextLease.ledgerDigest
      ||createRecoveryCheckpointDigest(reconstruction.checkpoint)!==createRecoveryCheckpointDigest(checkpoint)){
      binding.invalid=true;return blocked('AUDIT_CHAIN_MISMATCH');
    }
    updateRecoverySession(binding,reconstruction,committed.nextRequest);
    const checkpointDigest=createRecoveryCheckpointDigest(checkpoint);
    return pass(freeze({checkpointDigest,...recoveryCommitCapability(binding,checkpoint,fields.transition)}));
  }catch{
    if(sessionBinding!==null){sessionBinding.invalid=true;sessionBinding.createCommitOperation=null;}
    return blocked('AUDIT_CHAIN_MISMATCH');
  }
}

function consumeRecoveryAuthorization(input,key,map,used,kind){
  const fields=recoveryFields(input,['context',key,'operation']);
  const token=fields?.[key];
  const record=token===undefined?undefined:map.get(token);
  if(fields===null||typeof fields.operation!=='string'||record===undefined||record.kind!==kind
    ||record.context!==fields.context||!isAuthenticTestRecoveryEnvironmentContext(fields.context)
    ||used.has(token)||record.sessionBinding.invalid
    ||ACTIVE_RECOVERY_SESSIONS.get(record.context)!==record.sessionBinding
    ||record.sessionBinding.generation!==record.generation)
    throw new TypeError(`recovery ${kind} authorization`);
  const legacy=record.action===fields.operation;
  const product=legacy?null:recoveryProductAuthorization(record);
  if(!legacy&&product.method!==fields.operation)
    throw new TypeError(`recovery ${kind} authorization`);
  used.add(token);
  if(kind==='step'){
    record.sessionBinding.exhaustedStepDigests.add(record.authorizationKey);
    if(record.sessionBinding.liveStepHandles.get(record.authorizationKey)===token)
      record.sessionBinding.liveStepHandles.delete(record.authorizationKey);
  }else{
    record.sessionBinding.exhaustedMutationDigests.add(record.authorizationKey);
    if(record.sessionBinding.liveMutationPermits.get(record.authorizationKey)===token)
      record.sessionBinding.liveMutationPermits.delete(record.authorizationKey);
  }
  if(legacy)return freeze({checkpointDigest:record.checkpointDigest,prefixLength:record.prefixLength,
    intentDispositionCursor:record.intentDispositionCursor,logicalResource:record.logicalResource,
    stepId:record.stepId,phase:record.phase,action:record.action,
    targetBindingDigest:record.targetBindingDigest,attemptOrdinal:record.attemptOrdinal,
    preWriteProjectionDigest:record.preWriteProjectionDigest,
    desiredProjectionDigest:record.desiredProjectionDigest});
  return freeze({checkpointDigest:record.checkpointDigest,prefixLength:record.prefixLength,
    intentDispositionCursor:record.intentDispositionCursor,logicalResource:record.logicalResource,
    stepId:record.stepId,phase:record.phase,targetBindingDigest:record.targetBindingDigest,
    method:product.method,target:product.target,
    oldProjectionDigest:record.preWriteProjectionDigest,
    desiredProjectionDigest:record.desiredProjectionDigest});
}
export function consumeRecoveryStepHandle(input){
  return consumeRecoveryAuthorization(input,'handle',RECOVERY_STEP_HANDLES,
    USED_RECOVERY_STEP_HANDLES,'step');
}
export function consumeRecoveryMutationPermit(input){
  return consumeRecoveryAuthorization(input,'permit',RECOVERY_MUTATION_PERMITS,
    USED_RECOVERY_MUTATION_PERMITS,'mutation');
}

function consumeRecoveryAccountSessionAuthorization(input,key,map,used,operation){
  const fields=recoveryFields(input,['context',key,'operation']);
  const token=fields?.[key],record=token===undefined?undefined:map.get(token);
  if(fields===null||fields.operation!==operation||record===undefined||record.context!==fields.context
    ||!isAuthenticTestRecoveryEnvironmentContext(fields.context)||used.has(token)
    ||record.sessionBinding.invalid||ACTIVE_RECOVERY_SESSIONS.get(record.context)!==record.sessionBinding
    ||record.sessionBinding.generation!==record.generation)throw new TypeError('recovery account session authorization');
  used.add(token);
  return freeze({target:record.target,sessionIntentDigest:record.sessionIntentDigest,
    generation:record.generation});
}
export function consumeRecoveryAccountSessionListHandle(input){
  return consumeRecoveryAccountSessionAuthorization(input,'handle',RECOVERY_ACCOUNT_SESSION_LIST_HANDLES,
    USED_RECOVERY_ACCOUNT_SESSION_LIST_HANDLES,'listBoundAccountSessions');
}
export function consumeRecoveryAccountSessionDeletePermit(input){
  return consumeRecoveryAccountSessionAuthorization(input,'permit',RECOVERY_ACCOUNT_SESSION_DELETE_PERMITS,
    USED_RECOVERY_ACCOUNT_SESSION_DELETE_PERMITS,'deleteBoundAccountSession');
}

function exactRecoveryAccountSessionBinding(binding,context,store){
  return exactRecoverySession(binding,context,store)&&binding.accountSessionStage!==undefined
    &&binding.reconstruction.accountSessionIntent?.state==='created';
}

export function recordRecoveryAccountSessionListObservation(input){
  const fields=recoveryFields(input,['context','handle','sessionIds']);
  const record=fields===null?undefined:RECOVERY_ACCOUNT_SESSION_LIST_HANDLES.get(fields.handle);
  const ids=fields===null?null:recoveryDenseArray(fields.sessionIds);
  if(record===undefined||ids===null||!USED_RECOVERY_ACCOUNT_SESSION_LIST_HANDLES.has(fields.handle)
    ||record.context!==fields.context
    ||!exactRecoveryAccountSessionBinding(record.sessionBinding,fields.context,record.sessionBinding.store)
    ||record.observationRecorded===true||ids.length>4
    ||ids.some((id)=>typeof id!=='string'||id.length===0||!record.target.sessionIds.includes(id))
    ||new Set(ids).size!==ids.length)throw new TypeError('recovery account session observation');
  const stage=record.sessionBinding.accountSessionStage;
  if(record.authorizationId!==stage.phase||stage.callCount>=10)
    throw new TypeError('recovery account session observation');
  record.observationRecorded=true;stage.callCount+=1;
  const observation=freeze(Object.create(null));
  RECOVERY_ACCOUNT_SESSION_OBSERVATIONS.set(observation,{context:fields.context,
    sessionBinding:record.sessionBinding,generation:record.generation,
    authorizationId:record.authorizationId,sessionIds:freeze([...ids])});
  return observation;
}

export function recordRecoveryAccountSessionDeleteDisposition(input){
  const fields=recoveryFields(input,['context','disposition','permit']);
  const record=fields===null?undefined:RECOVERY_ACCOUNT_SESSION_DELETE_PERMITS.get(fields.permit);
  if(record===undefined||!['acknowledged','blocked','unknown'].includes(fields.disposition)
    ||!USED_RECOVERY_ACCOUNT_SESSION_DELETE_PERMITS.has(fields.permit)
    ||record.context!==fields.context
    ||!exactRecoveryAccountSessionBinding(record.sessionBinding,fields.context,record.sessionBinding.store)
    ||record.deleteDisposition!==undefined
    ||record.sessionBinding.accountSessionStage.pendingDeleteId!==record.target.sessionId
    ||record.sessionBinding.accountSessionStage.callCount>=10)
    throw new TypeError('recovery account session delete disposition');
  record.deleteDisposition=fields.disposition;
  record.sessionBinding.accountSessionStage.callCount+=1;
}

function nextRecoveryAccountSessionAction(binding){
  const stage=binding.accountSessionStage;
  if(stage.remainingIds.length!==0){
    const sessionId=stage.remainingIds.shift();
    if(stage.issuedDeleteIds.has(sessionId))return null;
    stage.issuedDeleteIds.add(sessionId);stage.pendingDeleteId=sessionId;stage.phase=`delete:${sessionId}`;
    return freeze({deletePermit:mintRecoveryAccountSessionAuthorization(binding,'delete',
      {userId:stage.ownerUserId,sessionId},stage.phase)});
  }
  stage.phase='final-list';
  return freeze({listHandle:mintRecoveryAccountSessionAuthorization(binding,'list',
    {userId:stage.ownerUserId,sessionIds:stage.boundIds},stage.phase)});
}

async function commitRecoveryAccountSessionAbsence({binding,clock}){
  const now=clock.nowEpochSeconds(),prior=binding.reconstruction.accountSessionIntent;
  const priorUpdatedAt=Date.parse(prior.updatedAt);
  if(!Number.isSafeInteger(now)||now<0||!Number.isFinite(priorUpdatedAt)
    ||now*1000<priorUpdatedAt||typeof binding.createAbsenceOperation!=='function')
    return blocked('AUDIT_CHAIN_MISMATCH');
  const intentSuccessor=freeze({...copy(prior),state:'absent',intentVersion:prior.intentVersion+1,
    updatedAt:iso(now)});
  const event=makeEvent({lease:binding.reconstruction.lease,transition:'intent.absent',
    runId:binding.reconstruction.lease.ownerRunId,intentId:intentSuccessor.intentId,
    intentProjectionDigest:digest(intentSuccessor)});
  const nextLease=freeze({...binding.reconstruction.lease,
    leaseVersion:event.leaseVersionAfter,ledgerDigest:eventDigest(event)});
  const operation=binding.createAbsenceOperation({event,intentSuccessor,nextLease});
  binding.createAbsenceOperation=null;
  const outcome=await binding.store.commitRecoveryAccountSessionAbsence(operation);
  const committed=recoveryStorePassValue(outcome,['nextRequest','snapshot']);
  if(committed===null)return blocked('AUDIT_CHAIN_MISMATCH');
  const reconstruction=reconstructRecoverySnapshot(committed.snapshot);
  if(reconstruction===null||reconstruction.accountSessionIntent?.state!=='absent'
    ||reconstruction.accountSessionIntent.intentVersion!==3
    ||reconstruction.checkpoint!==null)return blocked('AUDIT_CHAIN_MISMATCH');
  binding.invalid=true;
  return pass(freeze({nextAuthority:committed.nextRequest,
    sessionAbsenceDigest:RECOVERY_ACCOUNT_SESSION_ABSENCE_DIGEST,
    measurements:freeze({knownProductCalls:binding.accountSessionStage.callCount,
      maximumProductCalls:10,knownStoreCalls:2,maximumStoreCalls:2})}));
}

export async function advanceRecoveryAccountSessionList(input){
  try{
    const fields=recoveryFields(input,['clock','context','observation','session','store']);
    if(fields===null||recoveryFields(fields.clock,['nowEpochSeconds'])===null)return blocked('AUDIT_CHAIN_MISMATCH');
    const binding=RECOVERY_SESSIONS.get(fields.session);
    const observation=RECOVERY_ACCOUNT_SESSION_OBSERVATIONS.get(fields.observation);
    if(!exactRecoveryAccountSessionBinding(binding,fields.context,fields.store)
      ||observation?.sessionBinding!==binding||observation.context!==fields.context
      ||observation.generation!==binding.generation
      ||USED_RECOVERY_ACCOUNT_SESSION_OBSERVATIONS.has(fields.observation)
      ||observation.authorizationId!==binding.accountSessionStage.phase)
      return blocked('AUDIT_CHAIN_MISMATCH');
    USED_RECOVERY_ACCOUNT_SESSION_OBSERVATIONS.add(fields.observation);
    const stage=binding.accountSessionStage,observed=[...observation.sessionIds];
    if(stage.phase==='initial-list'){
      stage.remainingIds=observed;stage.phase='delete-ready';
    }else if(stage.phase.startsWith('reconcile:')){
      const pending=stage.pendingDeleteId;
      if(pending===null||observed.includes(pending)){
        binding.invalid=true;return blocked('CLEANUP_AMBIGUOUS');
      }
      stage.pendingDeleteId=null;stage.phase='delete-ready';
    }else if(stage.phase==='final-list'){
      if(observed.length!==0){binding.invalid=true;return blocked('CLEANUP_AMBIGUOUS');}
      return await commitRecoveryAccountSessionAbsence({binding,clock:fields.clock});
    }else return blocked('AUDIT_CHAIN_MISMATCH');
    const next=nextRecoveryAccountSessionAction(binding);
    if(next===null){binding.invalid=true;return blocked('CLEANUP_AMBIGUOUS');}
    return pass(next);
  }catch{return blocked('AUDIT_CHAIN_MISMATCH');}
}

export async function advanceRecoveryAccountSessionDelete(input){
  try{
    const fields=recoveryFields(input,['clock','context','permit','session','store']);
    if(fields===null||recoveryFields(fields.clock,['nowEpochSeconds'])===null)return blocked('AUDIT_CHAIN_MISMATCH');
    const binding=RECOVERY_SESSIONS.get(fields.session);
    const record=RECOVERY_ACCOUNT_SESSION_DELETE_PERMITS.get(fields.permit);
    if(!exactRecoveryAccountSessionBinding(binding,fields.context,fields.store)
      ||record?.sessionBinding!==binding||record.context!==fields.context
      ||record.generation!==binding.generation
      ||record.target.sessionId!==binding.accountSessionStage.pendingDeleteId
      ||record.deleteDisposition===undefined)return blocked('AUDIT_CHAIN_MISMATCH');
    const stage=binding.accountSessionStage;
    if(record.deleteDisposition==='acknowledged'){
      stage.pendingDeleteId=null;stage.phase='delete-ready';
      const next=nextRecoveryAccountSessionAction(binding);
      if(next===null){binding.invalid=true;return blocked('CLEANUP_AMBIGUOUS');}
      return pass(next);
    }
    if(record.deleteDisposition==='unknown'){
      const sessionId=stage.pendingDeleteId;
      if(stage.reconciledDeleteIds.has(sessionId)){
        binding.invalid=true;return blocked('CLEANUP_AMBIGUOUS');
      }
      stage.reconciledDeleteIds.add(sessionId);stage.phase=`reconcile:${sessionId}`;
      return pass(freeze({listHandle:mintRecoveryAccountSessionAuthorization(binding,'list',
        {userId:stage.ownerUserId,sessionIds:stage.boundIds},stage.phase)}));
    }
    binding.invalid=true;return blocked('CLEANUP_AMBIGUOUS');
  }catch{return blocked('AUDIT_CHAIN_MISMATCH');}
}

export async function closeRecoveryLease(input){
  let binding=null;
  try{
    const fields=recoveryFields(input,['clock','context','session','store']);
    if(fields===null||!isAuthenticTestRecoveryEnvironmentContext(fields.context)
      ||!isAuthenticProviderRecoveryControlStore(fields.store,fields.context)
      ||recoveryFields(fields.clock,['nowEpochSeconds'])===null)return blocked('AUDIT_CHAIN_MISMATCH');
    const now=fields.clock.nowEpochSeconds();
    if(!Number.isSafeInteger(now)||now<0)return blocked('AUDIT_CHAIN_MISMATCH');
    binding=RECOVERY_SESSIONS.get(fields.session);
    if(!exactRecoverySession(binding,fields.context,fields.store))return blocked('LEASE_VERSION_MISMATCH');
    const predecessor=binding.reconstruction;
    const primaryExecutions=predecessor.snapshot.intentProjections.map(({projection})=>(
      recoveryOrdinarySemanticIntent(projection)
    )).filter((intent)=>intent?.schemaVersion==='verification-intent-snapshot.v1'
      &&intent.resourceType==='primary-execution');
    const completedResourceClose=predecessor.checkpoint?.checkpointState==='resources-complete'
      &&predecessor.checkpoint.prefixLength===42
      &&predecessor.checkpoint.intentDispositionCursor===3
      &&predecessor.currentIntents.every((intent)=>intent.state==='absent')
      &&predecessor.accountSessionIntent?.state==='absent'&&primaryExecutions.length===1
      &&primaryExecutions[0].state==='created'
      &&validPrimaryExecutionSnapshot(primaryExecutions[0],PRIMARY_EXECUTION_RETENTION_MAX_SECONDS);
    const emptyResourceClose=predecessor.checkpoint===null&&predecessor.recoveryEvent===null
      &&predecessor.sourceIntents.length===0&&predecessor.currentIntents.length===0
      &&(predecessor.accountSessionIntent===null||predecessor.accountSessionIntent.state==='absent')
      &&recoverableSourceLeaseState(predecessor.lease.state,predecessor.lease.cleanupDebt)
      &&validIso(predecessor.lease.expiresAt)&&Date.parse(predecessor.lease.expiresAt)<=now*1000
      &&primaryExecutions.length<=1
      &&(primaryExecutions.length===0||(['planned','created'].includes(primaryExecutions[0].state)
        &&validPrimaryExecutionSnapshot(primaryExecutions[0],PRIMARY_EXECUTION_RETENTION_MAX_SECONDS)));
    if(!completedResourceClose&&!emptyResourceClose)
      return blocked('AUDIT_CHAIN_MISMATCH');
    const sourceOutcome=await fields.store.readRecoveryCloseSource(binding.nextRequest);
    const source=recoveryStorePassValue(sourceOutcome,['createCloseOperation','snapshot']);
    if(source===null||typeof source.createCloseOperation!=='function'){
      binding.invalid=true;return blocked('AUDIT_CHAIN_MISMATCH');
    }
    const reconstruction=reconstructRecoverySnapshot(source.snapshot);
    if(reconstruction===null||canonicalJson(reconstruction.snapshot)!==canonicalJson(predecessor.snapshot)){
      binding.invalid=true;return blocked('LEASE_VERSION_MISMATCH');
    }
    const event=makeEvent({lease:reconstruction.lease,transition:'lease.close',
      runId:reconstruction.lease.ownerRunId});
    const recoveryCloseDigest=eventDigest(event);
    const nextLease=freeze({...reconstruction.lease,state:'idle',ownerRunId:null,
      ownerWorkflowRunId:null,environmentDigest:null,acquiredAt:null,renewedAt:null,
      expiresAt:null,leaseTokenDigest:null,cleanupDebt:false,
      leaseVersion:event.leaseVersionAfter,ledgerDigest:recoveryCloseDigest});
    const operation=source.createCloseOperation({event,nextLease});
    const outcome=await fields.store.commitRecoveryClose(operation);
    const committed=recoveryStorePassValue(outcome,['nextRequest','snapshot']);
    if(committed===null){binding.invalid=true;return blocked('AUDIT_CHAIN_MISMATCH');}
    const expected=copy(reconstruction.snapshot);
    expected.auditTrail.push({digest:recoveryCloseDigest,event:copy(event),snapshot:null});
    expected.lease=copy(nextLease);
    if(canonicalJson(committed.snapshot)!==canonicalJson(expected)){
      binding.invalid=true;return blocked('AUDIT_CHAIN_MISMATCH');
    }
    binding.invalid=true;binding.createCommitOperation=null;
    return pass(freeze({completion:'recovery-closed',recoveryCloseDigest,
      measurements:freeze({knownStoreCalls:2,maximumStoreCalls:2})}));
  }catch{
    if(binding!==null){binding.invalid=true;binding.createCommitOperation=null;}
    return blocked('AUDIT_CHAIN_MISMATCH');
  }
}

function recoverySuccessorProgressDigest(predecessor,candidate,transition){
  return digest({domain:'verification-recovery-progress-link.v1',payload:{
    schemaVersion:RECOVERY_CHECKPOINT_SCHEMA_VERSION,
    priorRecoveryProgressDigest:predecessor.recoveryProgressDigest,
    transition,catalogPosition:recoveryPositionEvidence(predecessor),
    targetBindingDigest:predecessor.targetBindingDigest,
    providerObservationDigest:candidate.providerObservationDigest,
  }});
}

function recoveryTerminalIntentDigests(checkpoint,logicalResource,cleanupCursor){
  const cleanupProgressDigest=digest({
    domain:'verification-recovery-terminal-cleanup-progress.v1',payload:{
      schemaVersion:RECOVERY_CHECKPOINT_SCHEMA_VERSION,
      sourceIntentSetDigest:checkpoint.sourceIntentSetDigest,
      logicalResource,cleanupCursor,recoveryProgressDigest:checkpoint.recoveryProgressDigest,
    },
  });
  const cleanupProofDigest=digest({
    domain:'verification-recovery-terminal-cleanup-proof.v1',payload:{
      schemaVersion:RECOVERY_CHECKPOINT_SCHEMA_VERSION,
      logicalResource,cleanupCursor,cleanupProgressDigest,
      providerObservationDigest:checkpoint.providerObservationDigest,
    },
  });
  return freeze({cleanupProgressDigest,cleanupProofDigest});
}

function recoveryResourcesProofDigest(checkpoint){
  return digest({domain:'verification-recovery-resources-proof.v1',payload:{
    schemaVersion:RECOVERY_CHECKPOINT_SCHEMA_VERSION,
    resourceOrder:QUALIFIED_CLEANUP_PROTOCOL.resourceOrder,
    recoveryProgressDigest:checkpoint.recoveryProgressDigest,
    currentIntentSetDigest:checkpoint.currentIntentSetDigest,
  }});
}

function recoveryNextPosition(binding,prefixLength,intentDispositionCursor){
  const position=deriveRecoveryPosition({prefixLength,intentDispositionCursor});
  return freeze({
    prefixLength,intentDispositionCursor,
    logicalResource:position.logicalResource,stepId:position.stepId,
    phase:position.phase,action:position.action,
    targetBindingDigest:recoveryTargetBindingDigest(
      binding.reconstruction.sourceIntents,prefixLength,intentDispositionCursor,
    ),
  });
}

function recoveryCandidateBase(binding,predecessor,transition,position,overrides){
  let candidate={
    ...copy(predecessor),
    priorCheckpointDigest:createRecoveryCheckpointDigest(predecessor),
    eventOrdinal:predecessor.eventOrdinal+1,
    prefixLength:position.prefixLength,
    intentDispositionCursor:position.intentDispositionCursor,
    logicalResource:position.logicalResource,
    stepId:position.stepId,
    phase:position.phase,
    action:position.action,
    targetBindingDigest:position.targetBindingDigest,
    ...overrides,
  };
  candidate.recoveryProgressDigest=recoverySuccessorProgressDigest(
    predecessor,candidate,transition,
  );
  return candidate;
}

function recoveryCheckpointBinding(input){
  const fields=recoveryFields(input,['context','session','store']);
  if(fields===null||!isAuthenticTestRecoveryEnvironmentContext(fields.context)
    ||!isAuthenticProviderRecoveryControlStore(fields.store,fields.context))return null;
  const binding=RECOVERY_SESSIONS.get(fields.session);
  return exactRecoverySession(binding,fields.context,fields.store)
    ?{fields,binding}:null;
}

function recoveryCheckpointProductDescriptor(binding,checkpoint){
  if(checkpoint.prefixLength===42||checkpoint.checkpointState==='resources-complete'){
    return freeze({readMethod:null,mutationMethod:null,extraQueryMethods:freeze([])});
  }
  const query=RECOVERY_PRODUCT_QUERY_STEPS[checkpoint.stepId];
  if(query!==undefined){
    return freeze({
      readMethod:query.method,mutationMethod:null,
      extraQueryMethods:freeze((RECOVERY_PRODUCT_EXTRA_QUERY_STEPS[checkpoint.stepId]??[])
        .map(({method})=>method)),
    });
  }
  const match=/\.(P[0-5]|G[0-4]|V[0-2])$/.exec(checkpoint.stepId)
    ??(/\.viewerShare$/.test(checkpoint.stepId)?[null,'S1']:null)
    ??(/\.editorShare$/.test(checkpoint.stepId)?[null,'S0']:null);
  if(match===null)throw new TypeError('recovery product descriptor');
  const target=recoveryProductMemberTarget(binding,match[1]);
  const readMethod=target.kind==='row'?'getBoundRow':'getBoundFile';
  const mutationMethod=checkpoint.action==='delete-and-prove-absent'
    ?target.kind==='row'?'deleteBoundRow':'deleteBoundFile'
    :checkpoint.action==='converge-owner-only'
      ?target.kind==='row'?'convergeBoundRowOwnerPermissions':'convergeBoundFileOwnerPermissions'
      :null;
  if(mutationMethod===null)throw new TypeError('recovery product descriptor');
  return freeze({readMethod,mutationMethod,extraQueryMethods:freeze([])});
}

export async function readRecoveryCheckpointStage(input){
  try{
    const bound=recoveryCheckpointBinding(input);
    if(bound===null)return blocked('AUDIT_CHAIN_MISMATCH');
    const read=await readRecoveryCheckpointSnapshot(input);
    if(read?.status!=='PASS'||read.value===null||typeof read.value!=='object'
      ||Array.isArray(read.value)||!Object.hasOwn(read.value,'snapshot'))return read;
    const binding=RECOVERY_SESSIONS.get(input.session);
    if(!exactRecoverySession(binding,input.context,input.store)
      ||binding.reconstruction.checkpoint===null)return blocked('AUDIT_CHAIN_MISMATCH');
    const checkpoint=binding.reconstruction.checkpoint;
    const capabilities=recoveryReadCapability(binding,checkpoint);
    return pass(freeze({
      snapshot:read.value.snapshot,checkpoint:copy(checkpoint),
      ...recoveryCheckpointProductDescriptor(binding,checkpoint),
      ...capabilities,
    }));
  }catch{return blocked('AUDIT_CHAIN_MISMATCH');}
}

export async function commitRecoveryMutationIssue(input){
  try{
    const fields=recoveryFields(input,[
      'context','desiredProjectionDigest','preWriteProjectionDigest','session','store',
    ]);
    if(fields===null||!DIGEST.test(fields.preWriteProjectionDigest)
      ||!DIGEST.test(fields.desiredProjectionDigest))return blocked('AUDIT_CHAIN_MISMATCH');
    const bound=recoveryCheckpointBinding({
      context:fields.context,session:fields.session,store:fields.store,
    });
    if(bound===null)return blocked('AUDIT_CHAIN_MISMATCH');
    const predecessor=bound.binding.reconstruction.checkpoint;
    if(predecessor===null||predecessor.prefixLength>=42
      ||!['ready','blocked'].includes(predecessor.checkpointState))
      return blocked('AUDIT_CHAIN_MISMATCH');
    const retry=predecessor.checkpointState==='blocked';
    const position=recoveryNextPosition(bound.binding,
      predecessor.prefixLength,predecessor.intentDispositionCursor);
    const candidate=recoveryCandidateBase(bound.binding,predecessor,
      'recovery.mutation_issued',position,{
        checkpointState:'write-issued',attemptOrdinal:retry?2:1,
        preWriteProjectionDigest:retry
          ?predecessor.preWriteProjectionDigest:fields.preWriteProjectionDigest,
        desiredProjectionDigest:retry
          ?predecessor.desiredProjectionDigest:fields.desiredProjectionDigest,
        providerObservationDigest:null,cleanupProofDigest:null,
      });
    return commitRecoveryCheckpoint({checkpoint:validateRecoveryCheckpoint(candidate),
      context:fields.context,session:fields.session,store:fields.store,
      transition:'recovery.mutation_issued'});
  }catch{return blocked('AUDIT_CHAIN_MISMATCH');}
}

export async function commitRecoveryStepObservation(input){
  try{
    const fields=recoveryFields(input,[
      'clock','context','providerObservationDigest','session','store',
    ]);
    if(fields===null||!DIGEST.test(fields.providerObservationDigest)
      ||recoveryFields(fields.clock,['nowEpochSeconds'])===null)
      return blocked('AUDIT_CHAIN_MISMATCH');
    const bound=recoveryCheckpointBinding({
      context:fields.context,session:fields.session,store:fields.store,
    });
    if(bound===null)return blocked('AUDIT_CHAIN_MISMATCH');
    const predecessor=bound.binding.reconstruction.checkpoint;
    if(predecessor===null||predecessor.prefixLength>=42
      ||!['ready','write-issued'].includes(predecessor.checkpointState))
      return blocked('AUDIT_CHAIN_MISMATCH');
    const mutation=predecessor.checkpointState==='write-issued';
    const desired=mutation
      &&fields.providerObservationDigest===predecessor.desiredProjectionDigest;
    let transition,position,overrides,intentSuccessor=null;
    if(mutation&&!desired){
      transition=predecessor.attemptOrdinal===1
        &&fields.providerObservationDigest===predecessor.preWriteProjectionDigest
        ?'recovery.mutation_not_committed':'recovery.step_blocked';
      position=recoveryNextPosition(bound.binding,
        predecessor.prefixLength,predecessor.intentDispositionCursor);
      overrides={checkpointState:'blocked',attemptOrdinal:predecessor.attemptOrdinal,
        preWriteProjectionDigest:predecessor.preWriteProjectionDigest,
        desiredProjectionDigest:predecessor.desiredProjectionDigest,
        providerObservationDigest:fields.providerObservationDigest,cleanupProofDigest:null};
    }else{
      const absent=predecessor.stepId.endsWith('.absent');
      transition=absent?'intent.recovery_absent':'recovery.step_committed';
      const nextPrefix=predecessor.prefixLength+1;
      const nextCursor=predecessor.intentDispositionCursor+(absent?1:0);
      position=recoveryNextPosition(bound.binding,nextPrefix,nextCursor);
      overrides={checkpointState:'ready',attemptOrdinal:null,
        preWriteProjectionDigest:null,desiredProjectionDigest:null,
        providerObservationDigest:fields.providerObservationDigest,cleanupProofDigest:null};
      if(absent){
        let candidate=recoveryCandidateBase(bound.binding,predecessor,transition,position,{
          ...overrides,currentIntentSetDigest:predecessor.currentIntentSetDigest,
        });
        const priorIntents=bound.binding.reconstruction.currentIntents.map(copy);
        const prior=priorIntents[predecessor.intentDispositionCursor];
        if(prior===undefined||prior.resourceType!==predecessor.logicalResource)
          return blocked('AUDIT_CHAIN_MISMATCH');
        const cleanupCursor=CLEANUP_RESOURCE_LIMITS[prior.resourceType].cleanupCursor;
        const terminalDigests=recoveryTerminalIntentDigests(
          candidate,prior.resourceType,cleanupCursor,
        );
        const now=fields.clock.nowEpochSeconds();
        if(!Number.isSafeInteger(now)||now<0)return blocked('AUDIT_CHAIN_MISMATCH');
        const updatedAt=new Date(Math.max(now*1000,Date.parse(prior.updatedAt))).toISOString();
        const placeholder=`sha256:${'0'.repeat(64)}`;
        let terminal=freeze({...copy(prior),state:'absent',intentVersion:prior.intentVersion+1,
          cleanupCursor,...terminalDigests,recoveryCheckpointDigest:placeholder,updatedAt});
        const currentIntents=priorIntents.map((intent,index)=>
          index===predecessor.intentDispositionCursor?terminal:intent);
        candidate.currentIntentSetDigest=createRecoveryCurrentIntentSetDigest({
          intents:currentIntents,recoveryTerminalIndex:predecessor.intentDispositionCursor,
        });
        candidate=validateRecoveryCheckpoint(candidate);
        terminal=freeze({...terminal,
          recoveryCheckpointDigest:createRecoveryCheckpointDigest(candidate)});
        currentIntents[predecessor.intentDispositionCursor]=terminal;
        if(createRecoveryCurrentIntentSetDigest({intents:currentIntents,
          recoveryTerminalIndex:predecessor.intentDispositionCursor})
          !==candidate.currentIntentSetDigest)return blocked('AUDIT_CHAIN_MISMATCH');
        intentSuccessor=terminal;
        overrides={...overrides,currentIntentSetDigest:candidate.currentIntentSetDigest};
      }
    }
    const candidate=validateRecoveryCheckpoint(recoveryCandidateBase(
      bound.binding,predecessor,transition,position,overrides,
    ));
    const request={checkpoint:candidate,context:fields.context,
      session:fields.session,store:fields.store,transition};
    if(intentSuccessor!==null)request.intentSuccessor=intentSuccessor;
    return commitRecoveryCheckpoint(request);
  }catch{return blocked('AUDIT_CHAIN_MISMATCH');}
}

export async function commitRecoveryResourcesComplete(input){
  try{
    const bound=recoveryCheckpointBinding(input);
    if(bound===null)return blocked('AUDIT_CHAIN_MISMATCH');
    const predecessor=bound.binding.reconstruction.checkpoint;
    if(predecessor===null||predecessor.prefixLength!==42
      ||predecessor.checkpointState!=='ready')return blocked('AUDIT_CHAIN_MISMATCH');
    const position=recoveryNextPosition(bound.binding,42,3);
    let candidate=recoveryCandidateBase(bound.binding,predecessor,
      'recovery.resources_completed',position,{
        checkpointState:'resources-complete',attemptOrdinal:null,
        preWriteProjectionDigest:null,desiredProjectionDigest:null,
        providerObservationDigest:null,cleanupProofDigest:null,
      });
    candidate.cleanupProofDigest=recoveryResourcesProofDigest(candidate);
    candidate=validateRecoveryCheckpoint(candidate);
    return commitRecoveryCheckpoint({checkpoint:candidate,context:input.context,
      session:input.session,store:input.store,transition:'recovery.resources_completed'});
  }catch{return blocked('AUDIT_CHAIN_MISMATCH');}
}
