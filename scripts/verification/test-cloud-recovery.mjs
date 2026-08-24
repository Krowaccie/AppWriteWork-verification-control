import { isPromise, isProxy } from 'node:util/types';

import { canonicalJson, sha256Bytes } from './canonical-json.mjs';
import {
  isAuthenticTestCloudRecoveryProductClient,
  readRecoveryOwnerOnlyProjectionDigest,
} from './test-cloud-appwrite.mjs';
import {
  GENESIS_LEDGER_DIGEST,
  commitRecoveryCheckpoint,
  closeRecoveryLease,
  advanceRecoveryAccountSessionDelete,
  advanceRecoveryAccountSessionList,
  openRecoveryAccountSessionStage,
  openRecoveryCheckpoint,
  readRecoveryCheckpointSnapshot,
} from './test-cloud-control-store.mjs';
import { isAuthenticProviderRecoveryControlStore } from './test-cloud-provider-control-store.mjs';
import {
  CLEANUP_PROTOCOL_DIGEST,
  QUALIFIED_CLEANUP_PROTOCOL,
  RECOVERY_CHECKPOINT_SCHEMA_VERSION,
  RECOVERY_COUNTS,
  createRecoveryCheckpointDigest,
  createRecoveryCurrentIntentSetDigest,
  createRecoveryIntentSetDigest,
  deriveRecoveryPosition,
  validateRecoveryCheckpoint,
  validateRecoveryIntentRow,
} from './test-cloud-cleanup-protocol.mjs';
import { isAuthenticTestRecoveryEnvironmentContext as isCurrentRecoveryEnvironmentContext } from './test-cloud-environment.mjs';
import { readExecutionObservationQualification } from './test-cloud-setup-check.mjs';
const encoder=new TextEncoder(), DIGEST=/^sha256:[0-9a-f]{64}$/u, SHA=/^[0-9a-f]{40}$/u, RUN=/^verify-[0-9a-f]{12}-[1-9][0-9]*-[1-9][0-9]*$/u;
const NATIVE_PROMISE=Promise,NATIVE_PROMISE_PROTOTYPE=Promise.prototype;
const NATIVE_PROMISE_THEN=Promise.prototype.then,REFLECT_APPLY=Reflect.apply;
const NATIVE_PROMISE_SPECIES_GETTER=Object.getOwnPropertyDescriptor(
  Promise,Symbol.species)?.get;
const CONTEXTS=new WeakMap(), RESOURCE_EXECUTORS=new WeakMap();
const FULL_RECOVERY_EXECUTORS=new WeakSet(),FULL_RECOVERY_CLOSE_RESULTS=new WeakMap();
const pass=(value)=>Object.freeze({status:'PASS',value,diagnostics:Object.freeze([])});
const blocked=(code)=>Object.freeze({status:'BLOCKED',value:null,diagnostics:Object.freeze([Object.freeze({code,safeMessage:'Recovery operation was blocked.',retryable:false})])});
const freeze=(v)=>{if(v&&typeof v==='object'&&!Object.isFrozen(v)){for(const x of Object.values(v))freeze(x);Object.freeze(v);}return v;};
const digest=(v)=>sha256Bytes(encoder.encode(canonicalJson(v)));
const exact=(v,keys)=>{try{if(!v||typeof v!=='object'||Array.isArray(v)||isProxy(v))return false;const descriptors=Object.getOwnPropertyDescriptors(v);return Reflect.ownKeys(descriptors).length===keys.length&&keys.every((key)=>{const descriptor=descriptors[key];return descriptor!==undefined&&descriptor.enumerable&&Object.hasOwn(descriptor,'value');});}catch{return false;}};
const dataValue=(v,key)=>Object.getOwnPropertyDescriptor(v,key)?.value;
const ENV_KEYS=['endpoint','projectId','siteId','origin'];
const FIXED={endpoint:'https://fra.cloud.appwrite.io/v1',projectId:'69137c5d003952a36d4c',siteId:'694579860016df0d2d3c',origin:'https://appwritework.appwrite.network'};
const SCOPE=['rows.read','rows.write','users.read','users.write'];
const RECOVERY_PRODUCT_METHODS=['listBoundAccountSessions','deleteBoundAccountSession','getBoundRow','deleteBoundRow','convergeBoundRowOwnerPermissions','getBoundFile','deleteBoundFile','convergeBoundFileOwnerPermissions','queryBoundProjectShares','queryBoundProjectSnapshots','queryBoundProjectArtifactReferences','queryBoundProjectArtifactsExactSet','queryBoundProjectArtifactVersionsExactSet'];
const RECOVERY_REQUEST_KEYS=['runId','originalWorkflowRunId','approvalRef','expectedLeaseVersion','expectedLedgerDigest','confirmedRunId'];
const RECOVERY_GITHUB_KEYS=['getRun','hasActiveTestCloudRun','getRecoveryApproval'];
const RECOVERY_FILE_ALIASES=new Set(['P3','P5','G2','G4','V0']);
const RECOVERY_QUERY_METHOD_BY_STEP=Object.freeze({
  'share.start':'queryBoundProjectShares',
  'project.phase.after-share-cleanup':'queryBoundProjectSnapshots',
  'graph.phase.after-share-cleanup':'queryBoundProjectArtifactReferences',
  'share.phase.after-share-cleanup':'queryBoundProjectArtifactsExactSet',
  'share.absent':'queryBoundProjectArtifactVersionsExactSet',
  'graph.start':'queryBoundProjectArtifactReferences',
  'graph.phase.after-graph-cleanup':'queryBoundProjectArtifactReferences',
  'graph.absent':'queryBoundProjectArtifactVersionsExactSet',
  'project.phase.after-graph-cleanup':'queryBoundProjectArtifactsExactSet',
  'project.start':'queryBoundProjectArtifactReferences',
  'project.phase.fully-clean':'queryBoundProjectArtifactsExactSet',
  'project.absent':'queryBoundProjectArtifactVersionsExactSet',
});
const RECOVERY_EXTRA_QUERY_BY_STEP=Object.freeze({
  'share.phase.after-share-cleanup':Object.freeze(['queryBoundProjectShares']),
});
const RECOVERY_PRODUCT_OBSERVED_WEIGHTS=Object.freeze({
  getBoundRow:3,
  getBoundFile:3,
  deleteBoundRow:2,
  deleteBoundFile:2,
  convergeBoundRowOwnerPermissions:2,
  convergeBoundFileOwnerPermissions:2,
  queryBoundProjectShares:3,
  queryBoundProjectSnapshots:1,
  queryBoundProjectArtifactReferences:1,
  queryBoundProjectArtifactsExactSet:4,
  queryBoundProjectArtifactVersionsExactSet:5,
});
export function parseRecoveryApprovalRef(ref,workflowId){try{if(typeof ref!=='string'||typeof workflowId!=='string'||!/^[1-9][0-9]*$/.test(workflowId)||/%/.test(ref))return blocked('RECOVERY_APPROVAL_INVALID');const expected=`https://github.com/Krowaccie/AppWriteWork-verification-control/actions/runs/${workflowId}`;if(ref!==expected)return blocked('RECOVERY_APPROVAL_INVALID');const url=new URL(ref);if(url.protocol!=='https:'||url.hostname!=='github.com'||url.username||url.password||url.port||url.search||url.hash)return blocked('RECOVERY_APPROVAL_INVALID');return pass(freeze({originalWorkflowRunId:workflowId,approvalRef:ref}));}catch{return blocked('RECOVERY_APPROVAL_INVALID');}}

export function createRecoveryResourceExecutor(args){try{
  if(!exact(args,['clock','context','controlStore','github','productClient','request']))
    return blocked('RECOVERY_SCOPE_INVALID');
  const {clock,context,controlStore,github,productClient,request}=args;
  const wrappedControlStore=exact(controlStore,['store','request']);
  const recoveryStore=wrappedControlStore?dataValue(controlStore,'store'):controlStore;
  const recoveryStoreRequest=wrappedControlStore?dataValue(controlStore,'request'):request;
  if(!isCurrentRecoveryEnvironmentContext(context)||!exact(request,RECOVERY_REQUEST_KEYS)
    ||!RUN.test(request.runId)||request.runId!==request.confirmedRunId
    ||request.originalWorkflowRunId!==context.originalWorkflowRunId
    ||request.approvalRef!==context.approvalRef
    ||parseRecoveryApprovalRef(request.approvalRef,request.originalWorkflowRunId).status!=='PASS'
    ||!Number.isSafeInteger(request.expectedLeaseVersion)||request.expectedLeaseVersion<0
    ||!DIGEST.test(request.expectedLedgerDigest)
    ||!exact(clock,['nowEpochSeconds'])
    ||typeof dataValue(clock,'nowEpochSeconds')!=='function'
    ||!exact(github,RECOVERY_GITHUB_KEYS)
    ||RECOVERY_GITHUB_KEYS.some((method)=>typeof dataValue(github,method)!=='function')
    ||!isAuthenticProviderRecoveryControlStore(recoveryStore,context)
    ||!isAuthenticTestCloudRecoveryProductClient(productClient,context)
    ||Reflect.ownKeys(productClient).some((key)=>typeof key!=='string')
    ||RECOVERY_PRODUCT_METHODS.some((method)=>typeof productClient[method]!=='function'))
    return blocked('RECOVERY_SCOPE_INVALID');
  const executor=freeze(Object.create(null));
  RESOURCE_EXECUTORS.set(executor,{clock,context,controlStore:recoveryStore,
    recoveryStoreRequest,github,productClient,request});
  return pass(executor);
}catch{return blocked('RECOVERY_SCOPE_INVALID');}}

function recoveryDomainDigest(domain,payload){return digest({domain,payload});}
function recoveryPositionEvidence(checkpoint){
  const position=deriveRecoveryPosition({prefixLength:checkpoint.prefixLength,
    intentDispositionCursor:checkpoint.intentDispositionCursor});
  return freeze({prefixLength:checkpoint.prefixLength,
    intentDispositionCursor:checkpoint.intentDispositionCursor,logicalResource:position.logicalResource,
    stepId:position.stepId,phase:position.phase,action:position.action});
}
function recoverySuccessorProgressDigest(predecessor,candidate,transition){
  return recoveryDomainDigest('verification-recovery-progress-link.v1',{
    schemaVersion:RECOVERY_CHECKPOINT_SCHEMA_VERSION,
    priorRecoveryProgressDigest:predecessor.recoveryProgressDigest,transition,
    catalogPosition:recoveryPositionEvidence(predecessor),
    targetBindingDigest:predecessor.targetBindingDigest,
    providerObservationDigest:candidate.providerObservationDigest,
  });
}
function recoveryTerminalIntentDigests(checkpoint,logicalResource,cleanupCursor){
  const cleanupProgressDigest=recoveryDomainDigest(
    'verification-recovery-terminal-cleanup-progress.v1',{
      schemaVersion:RECOVERY_CHECKPOINT_SCHEMA_VERSION,
      sourceIntentSetDigest:checkpoint.sourceIntentSetDigest,logicalResource,cleanupCursor,
      recoveryProgressDigest:checkpoint.recoveryProgressDigest,
    });
  const cleanupProofDigest=recoveryDomainDigest(
    'verification-recovery-terminal-cleanup-proof.v1',{
      schemaVersion:RECOVERY_CHECKPOINT_SCHEMA_VERSION,logicalResource,cleanupCursor,
      cleanupProgressDigest,providerObservationDigest:checkpoint.providerObservationDigest,
    });
  return freeze({cleanupProgressDigest,cleanupProofDigest});
}
function recoveryResourcesProofDigest(checkpoint){
  return recoveryDomainDigest('verification-recovery-resources-proof.v1',{
    schemaVersion:RECOVERY_CHECKPOINT_SCHEMA_VERSION,
    resourceOrder:QUALIFIED_CLEANUP_PROTOCOL.resourceOrder,
    recoveryProgressDigest:checkpoint.recoveryProgressDigest,
    currentIntentSetDigest:checkpoint.currentIntentSetDigest,
  });
}
function recoveryCurrentIntentDigest(intents,cursor){
  if(cursor===0)return createRecoveryIntentSetDigest({intents});
  return createRecoveryCurrentIntentSetDigest({intents,recoveryTerminalIndex:cursor-1});
}
function recoveryTargetBindingDigest(intents,prefixLength,intentDispositionCursor){
  const position=deriveRecoveryPosition({prefixLength,intentDispositionCursor});
  if(position.logicalResource===null)return null;
  const source=intents.find(({resourceType})=>resourceType===position.logicalResource);
  if(source===undefined)throw new TypeError('recovery target source');
  return digest({schemaVersion:'verification-recovery-target-binding.v1',
    cleanupProtocolDigest:CLEANUP_PROTOCOL_DIGEST,logicalResource:position.logicalResource,
    stepId:position.stepId,phase:position.phase,action:position.action,
    intentId:source.intentId,resourceId:source.resourceId,
    providerAggregateDigest:source.providerAggregateDigest});
}
function recoverySnapshotState(snapshot){
  const fields=exact(snapshot,['auditTrail','intentProjections','lease'])?snapshot:null;
  if(fields===null||!Array.isArray(fields.auditTrail)||!Array.isArray(fields.intentProjections))
    throw new TypeError('recovery snapshot');
  const events=fields.auditTrail.map((entry)=>entry?.event).filter(Boolean);
  const recoveryEvents=events.filter((event)=>typeof event?.recoveryCheckpointJson==='string');
  if(recoveryEvents.length===0)throw new TypeError('recovery checkpoint missing');
  const recoveryEvent=recoveryEvents.at(-1);
  const checkpoint=validateRecoveryCheckpoint(JSON.parse(recoveryEvent.recoveryCheckpointJson));
  const byResource=new Map();
  for(const item of fields.intentProjections){
    const projection=item?.projection;
    if(projection===null||typeof projection!=='object')continue;
    try{
      const intent=validateRecoveryIntentRow(projection);
      if(QUALIFIED_CLEANUP_PROTOCOL.resourceOrder.includes(intent.resourceType))
        byResource.set(intent.resourceType,intent);
    }catch{}
  }
  const currentIntents=QUALIFIED_CLEANUP_PROTOCOL.resourceOrder.map((resourceType)=>{
    const intent=byResource.get(resourceType);
    if(intent===undefined)throw new TypeError('recovery intents');
    return intent;
  });
  return freeze({checkpoint,recoveryEvent,currentIntents,lease:fields.lease});
}
function recoveryNextPosition(predecessor){
  const cursor=predecessor.intentDispositionCursor
    +(predecessor.stepId?.endsWith('.absent')?1:0);
  return freeze({prefixLength:predecessor.prefixLength+1,intentDispositionCursor:cursor});
}
function recoveryLinkedCheckpoint({predecessor,currentIntents,transition,providerObservationDigest,
  checkpointState='ready',position=null,attemptOrdinal=null,preWriteProjectionDigest=null,
  desiredProjectionDigest=null,currentIntentSetDigest=null,cleanupProofDigest=null}){
  const selected=position??{prefixLength:predecessor.prefixLength,
    intentDispositionCursor:predecessor.intentDispositionCursor};
  const derived=deriveRecoveryPosition(selected);
  let candidate={...predecessor,priorCheckpointDigest:createRecoveryCheckpointDigest(predecessor),
    eventOrdinal:predecessor.eventOrdinal+1,prefixLength:selected.prefixLength,
    intentDispositionCursor:selected.intentDispositionCursor,checkpointState,
    logicalResource:derived.logicalResource,stepId:derived.stepId,phase:derived.phase,
    action:derived.action,
    targetBindingDigest:recoveryTargetBindingDigest(currentIntents,selected.prefixLength,
      selected.intentDispositionCursor),
    attemptOrdinal,preWriteProjectionDigest,desiredProjectionDigest,providerObservationDigest,
    currentIntentSetDigest:currentIntentSetDigest??predecessor.currentIntentSetDigest,
    cleanupProofDigest,recoveryProgressDigest:`sha256:${'0'.repeat(64)}`};
  candidate={...candidate,recoveryProgressDigest:recoverySuccessorProgressDigest(
    predecessor,candidate,transition)};
  if(transition==='recovery.resources_completed')
    candidate={...candidate,cleanupProofDigest:recoveryResourcesProofDigest(candidate)};
  return freeze(validateRecoveryCheckpoint(candidate));
}
function recoveryTerminalCursor(resourceType){
  return QUALIFIED_CLEANUP_PROTOCOL.resources[resourceType].mutation.length;
}
function recoveryTerminalIntentSuccessor({predecessor,candidate,currentIntents,clock}){
  const cursor=predecessor.intentDispositionCursor;
  const prior=currentIntents[cursor];
  const placeholder=`sha256:${'0'.repeat(64)}`;
  const terminalDigests=recoveryTerminalIntentDigests(candidate,prior.resourceType,
    recoveryTerminalCursor(prior.resourceType));
  const draft=freeze({...prior,state:'absent',intentVersion:prior.intentVersion+1,
    cleanupCursor:recoveryTerminalCursor(prior.resourceType),
    cleanupProgressDigest:terminalDigests.cleanupProgressDigest,
    cleanupProofDigest:terminalDigests.cleanupProofDigest,
    recoveryCheckpointDigest:placeholder,
    updatedAt:new Date(clock.nowEpochSeconds()*1000).toISOString()});
  const nextIntents=currentIntents.map((intent,index)=>index===cursor?draft:intent);
  const currentIntentSetDigest=recoveryCurrentIntentDigest(nextIntents,cursor+1);
  const finalCheckpoint=freeze(validateRecoveryCheckpoint({
    ...candidate,currentIntentSetDigest,
  }));
  const authenticatedDigest=createRecoveryCheckpointDigest(finalCheckpoint);
  const intent=freeze({...draft,recoveryCheckpointDigest:authenticatedDigest});
  return freeze({checkpoint:finalCheckpoint,intent});
}
function recoveryReadMethod(stepId){
  const query=RECOVERY_QUERY_METHOD_BY_STEP[stepId];
  if(query!==undefined)return query;
  return RECOVERY_FILE_ALIASES.has(stepId.split('.').at(-1))?'getBoundFile':'getBoundRow';
}
function recoveryMutationMethod(stepId,action){
  const alias=stepId.split('.').at(-1);
  const file=RECOVERY_FILE_ALIASES.has(alias);
  if(action==='delete-and-prove-absent')return file?'deleteBoundFile':'deleteBoundRow';
  if(action==='converge-owner-only')return file?'convergeBoundFileOwnerPermissions'
    :'convergeBoundRowOwnerPermissions';
  throw new TypeError('recovery mutation method');
}
function recoveryAbsentProjectionDigest(method){
  if(method.endsWith('Row'))return digest({
    schemaVersion:'tablesdb-row-state.v1',presence:'absent',
    dataDigest:null,permissionsDigest:null,
  });
  if(method.endsWith('File'))return digest({
    schemaVersion:'storage-file-metadata-state.v1',presence:'absent',
    metadataDigest:null,permissionsDigest:null,
  });
  throw new TypeError('recovery absent digest');
}
function recoveryDesiredDigest(method,action,preWriteProjection){
  if(action==='delete-and-prove-absent')return recoveryAbsentProjectionDigest(method);
  if(action==='converge-owner-only'){
    const desired=readRecoveryOwnerOnlyProjectionDigest(preWriteProjection);
    if(DIGEST.test(desired))return desired;
  }
  return null;
}
function incrementRecoveryCounter(bucket,key){
  bucket[key]=(bucket[key]??0)+1;
}
function countRecoveryProduct(metrics,method,observedWeight=null){
  const weight=observedWeight??RECOVERY_PRODUCT_OBSERVED_WEIGHTS[method];
  if(!Number.isSafeInteger(weight)||weight<0)throw new TypeError('recovery product weight');
  incrementRecoveryCounter(metrics.productMethods,method);
  metrics.productObserved+=weight;
}
function countRecoveryStore(metrics,receiver,observedWeight=1){
  incrementRecoveryCounter(metrics.storeReceivers,receiver);
  metrics.storeObserved+=observedWeight;
}
async function recoveryProductRead(metrics,product,method,handle,observedWeight=null){
  countRecoveryProduct(metrics,method,observedWeight);
  const result=await product[method](handle);
  if(result?.status!=='PASS'||!exact(result.value,['projection','projectionDigest'])
    ||typeof result.value.projection!=='string'||!DIGEST.test(result.value.projectionDigest))
    return null;
  return result.value;
}
async function recoveryProductMutation(metrics,product,method,permit){
  countRecoveryProduct(metrics,method);
  const result=await product[method](permit);
  if(result?.status==='PASS'&&exact(result.value,['write','projectionDigest'])
    &&DIGEST.test(result.value.projectionDigest))return freeze({
      status:'PASS',projectionDigest:result.value.projectionDigest,
    });
  return freeze({status:'BLOCKED',projectionDigest:null});
}
function recoveryReadbackFailureDigest(checkpoint){
  return digest({schemaVersion:'verification-recovery-readback-failure.v1',
    checkpointDigest:createRecoveryCheckpointDigest(checkpoint),stepId:checkpoint.stepId,
    attemptOrdinal:checkpoint.attemptOrdinal});
}
function recoveryMetrics(){
  return {productObserved:0,storeObserved:0,
    productMethods:Object.create(null),storeReceivers:Object.create(null),
    countedSnapshotReads:0};
}
function recoveryMeasurements(metrics){
  if(metrics.productObserved>RECOVERY_COUNTS.maximumProductHttpCalls
    ||metrics.storeObserved>RECOVERY_COUNTS.maximumStoreCalls)
    throw new TypeError('recovery count overflow');
  return freeze({productHttp:freeze({observed:metrics.productObserved,
    known:RECOVERY_COUNTS.knownProductHttpCalls,
    maximum:RECOVERY_COUNTS.maximumProductHttpCalls}),
    store:freeze({observed:metrics.storeObserved,known:RECOVERY_COUNTS.knownStoreCalls,
      maximum:RECOVERY_COUNTS.maximumStoreCalls}),
    functionExecutions:RECOVERY_COUNTS.functionExecutions});
}
function recoveryResourcesCompleteValue(checkpoint,currentIntents,metrics){
  const value=freeze({completion:'resources-complete',
    recoveryCheckpointDigest:createRecoveryCheckpointDigest(checkpoint),
    resources:currentIntents.map((intent)=>freeze({
      logicalResource:intent.resourceType,status:intent.state,
      cleanupProofDigest:intent.cleanupProofDigest,
    })),
    measurements:recoveryMeasurements(metrics),
  });
  if(!exact(value,['completion','recoveryCheckpointDigest','resources','measurements'])
    ||value.completion!=='resources-complete'
    ||!DIGEST.test(value.recoveryCheckpointDigest)
    ||!Array.isArray(value.resources)||value.resources.length!==3
    ||value.resources.some((resource)=>!exact(resource,
      ['logicalResource','status','cleanupProofDigest'])
      ||!['primary-share','primary-graph','primary-project'].includes(resource.logicalResource)
      ||resource.status!=='absent'||!DIGEST.test(resource.cleanupProofDigest))
    ||!exact(value.measurements,['productHttp','store','functionExecutions'])
    ||!exact(value.measurements.productHttp,['observed','known','maximum'])
    ||!exact(value.measurements.store,['observed','known','maximum'])
    ||value.measurements.functionExecutions!==0)
    throw new TypeError('recovery result shape');
  return value;
}
async function recoveryCommit({metrics,context,store,session,checkpoint,transition,intentSuccessor=null}){
  countRecoveryStore(metrics,'commitRecoveryCheckpoint');
  const payload=intentSuccessor===null?{context,store,session,checkpoint,transition}
    :{context,store,session,checkpoint,transition,intentSuccessor};
  const result=await commitRecoveryCheckpoint(payload);
  return result.status==='PASS'?result:null;
}
async function approveRecoveryRun({github,context,request}){
  const run=await github.getRun(request.originalWorkflowRunId);
  const approval=await github.getRecoveryApproval(request.originalWorkflowRunId);
  if(!['completed','cancelled','failure','success','timed_out'].includes(run?.status)
    ||await github.hasActiveTestCloudRun()
    ||!exact(approval,['bundlePromoted','controllerBundleSha','environmentClass',
      'environmentDeploymentStatus'])
    ||approval.bundlePromoted!==true
    ||approval.controllerBundleSha!==context.controllerBundleSha
    ||approval.environmentClass!=='appwrite-cloud-test-recovery'
    ||approval.environmentDeploymentStatus!=='approved')return false;
  return true;
}

export async function recoverTestCloudResources(args){try{
  if(!exact(args,['executor'])||!RESOURCE_EXECUTORS.has(args.executor))
    return blocked('RECOVERY_SCOPE_INVALID');
  const binding=RESOURCE_EXECUTORS.get(args.executor);
  const {clock,context,controlStore,recoveryStoreRequest,github,productClient,request}=binding;
  const metrics=recoveryMetrics();
  if(!await approveRecoveryRun({github,context,request}))return blocked('RECOVERY_APPROVAL_INVALID');
  countRecoveryStore(metrics,'openRecoveryCheckpoint',4);
  const opened=await openRecoveryCheckpoint({context,store:controlStore,
    request:recoveryStoreRequest,clock});
  if(opened.status!=='PASS')return opened;
  const session=opened.value.session;
  for(let guard=0;guard<200;guard+=1){
    const readWeight=metrics.countedSnapshotReads<2?1:0;
    metrics.countedSnapshotReads+=1;
    countRecoveryStore(metrics,'readRecoveryCheckpointSnapshot',readWeight);
    const read=await readRecoveryCheckpointSnapshot({context,store:controlStore,session});
    if(read.status!=='PASS')return read;
    const state=recoverySnapshotState(read.value.snapshot);
    const checkpoint=state.checkpoint;
    if(checkpoint.checkpointState==='resources-complete'){
      const resources=recoveryResourcesCompleteValue(checkpoint,state.currentIntents,metrics);
      if(FULL_RECOVERY_EXECUTORS.has(args.executor)){
        const close=await closeRecoveryLease({context,store:controlStore,session,clock});
        if(close.status!=='PASS')return close;
        FULL_RECOVERY_CLOSE_RESULTS.set(args.executor,close.value);
      }
      return pass(resources);
    }
    if(checkpoint.checkpointState==='blocked'){
      if(checkpoint.attemptOrdinal===1){
        if(checkpoint.providerObservationDigest!==checkpoint.preWriteProjectionDigest
          ||!DIGEST.test(checkpoint.preWriteProjectionDigest)
          ||!DIGEST.test(checkpoint.desiredProjectionDigest))
          return blocked('RECOVERY_STEP_BLOCKED');
        const issued=recoveryLinkedCheckpoint({predecessor:checkpoint,
          currentIntents:state.currentIntents,transition:'recovery.mutation_issued',
          providerObservationDigest:null,checkpointState:'write-issued',attemptOrdinal:2,
          preWriteProjectionDigest:checkpoint.preWriteProjectionDigest,
          desiredProjectionDigest:checkpoint.desiredProjectionDigest});
        const committed=await recoveryCommit({metrics,context,store:controlStore,session,
          checkpoint:issued,transition:'recovery.mutation_issued'});
        if(committed===null)return blocked('AUDIT_CHAIN_MISMATCH');
        const method=recoveryMutationMethod(issued.stepId,issued.action);
        const mutation=await recoveryProductMutation(metrics,productClient,method,
          committed.value.mutationPermit);
        const afterIssueRead=await readRecoveryCheckpointSnapshot({context,store:controlStore,session});
        if(afterIssueRead.status!=='PASS')return afterIssueRead;
        const issuedState=recoverySnapshotState(afterIssueRead.value.snapshot);
        const issuedCheckpoint=issuedState.checkpoint;
        let observedDigest=mutation.projectionDigest;
        if(mutation.status!=='PASS'){
          const observed=await recoveryProductRead(metrics,productClient,
            recoveryReadMethod(issuedCheckpoint.stepId),afterIssueRead.value.stepHandle,0);
          observedDigest=observed===null?recoveryReadbackFailureDigest(issuedCheckpoint)
            :observed.projectionDigest;
        }
        const transition=observedDigest===issuedCheckpoint.desiredProjectionDigest
          ?'recovery.step_committed':'recovery.step_blocked';
        const position=transition==='recovery.step_committed'?recoveryNextPosition(issuedCheckpoint)
          :{prefixLength:issuedCheckpoint.prefixLength,
            intentDispositionCursor:issuedCheckpoint.intentDispositionCursor};
        const successor=recoveryLinkedCheckpoint({predecessor:issuedCheckpoint,
          currentIntents:issuedState.currentIntents,transition,
          providerObservationDigest:observedDigest,position,
          checkpointState:transition==='recovery.step_committed'?'ready':'blocked',
          attemptOrdinal:transition==='recovery.step_committed'?null:issuedCheckpoint.attemptOrdinal,
          preWriteProjectionDigest:transition==='recovery.step_committed'?null
            :issuedCheckpoint.preWriteProjectionDigest,
          desiredProjectionDigest:transition==='recovery.step_committed'?null
            :issuedCheckpoint.desiredProjectionDigest});
        const finalCommit=await recoveryCommit({metrics,context,store:controlStore,session,
          checkpoint:successor,transition});
        if(finalCommit===null)return blocked('AUDIT_CHAIN_MISMATCH');
        continue;
      }
      return blocked('RECOVERY_STEP_BLOCKED');
    }
    if(checkpoint.prefixLength===RECOVERY_COUNTS.semanticTransitions){
      const complete=recoveryLinkedCheckpoint({predecessor:checkpoint,
        currentIntents:state.currentIntents,transition:'recovery.resources_completed',
        providerObservationDigest:null,position:{prefixLength:checkpoint.prefixLength,
          intentDispositionCursor:checkpoint.intentDispositionCursor},
        checkpointState:'resources-complete',
        currentIntentSetDigest:checkpoint.currentIntentSetDigest});
      const committed=await recoveryCommit({metrics,context,store:controlStore,session,
        checkpoint:complete,transition:'recovery.resources_completed'});
      if(committed===null)return blocked('AUDIT_CHAIN_MISMATCH');
      continue;
    }
    const detail=deriveRecoveryPosition({prefixLength:checkpoint.prefixLength,
      intentDispositionCursor:checkpoint.intentDispositionCursor});
    const isMutation=['delete-and-prove-absent','converge-owner-only'].includes(detail.action);
    if(checkpoint.checkpointState==='ready'&&!isMutation){
      for(const extra of RECOVERY_EXTRA_QUERY_BY_STEP[detail.stepId]??[]){
        const extraValue=await recoveryProductRead(metrics,productClient,extra,read.value.queryStepHandles?.[extra]);
      if(extraValue===null||extraValue.projection!=='desired')
          return blocked('RECOVERY_STEP_BLOCKED');
      }
      const method=recoveryReadMethod(detail.stepId);
      const observed=await recoveryProductRead(metrics,productClient,method,read.value.stepHandle);
      if(observed===null||observed.projection!=='desired')return blocked('RECOVERY_STEP_BLOCKED');
      const next=recoveryNextPosition(checkpoint);
      let candidate=recoveryLinkedCheckpoint({predecessor:checkpoint,
        currentIntents:state.currentIntents,
        transition:detail.stepId.endsWith('.absent')?'intent.recovery_absent':'recovery.step_committed',
        providerObservationDigest:observed.projectionDigest,position:next});
      let intentSuccessor=null;
      if(detail.stepId.endsWith('.absent')){
        const terminal=recoveryTerminalIntentSuccessor({predecessor:checkpoint,candidate,
          currentIntents:state.currentIntents,clock});
        candidate=terminal.checkpoint;intentSuccessor=terminal.intent;
      }
      const committed=await recoveryCommit({metrics,context,store:controlStore,session,checkpoint:candidate,
        transition:detail.stepId.endsWith('.absent')?'intent.recovery_absent':'recovery.step_committed',
        intentSuccessor});
      if(committed===null)return blocked('AUDIT_CHAIN_MISMATCH');
      continue;
    }
    if(checkpoint.checkpointState==='ready'&&isMutation){
      const method=recoveryMutationMethod(detail.stepId,detail.action);
      const preWrite=await recoveryProductRead(metrics,productClient,recoveryReadMethod(detail.stepId),
        read.value.stepHandle);
      if(preWrite===null)return blocked('RECOVERY_STEP_BLOCKED');
      const preWriteProjectionDigest=preWrite.projectionDigest;
      const desiredProjectionDigest=recoveryDesiredDigest(method,detail.action,preWrite);
      if(!DIGEST.test(desiredProjectionDigest))return blocked('RECOVERY_STEP_BLOCKED');
      const issued=recoveryLinkedCheckpoint({predecessor:checkpoint,
        currentIntents:state.currentIntents,transition:'recovery.mutation_issued',
        providerObservationDigest:null,checkpointState:'write-issued',attemptOrdinal:1,
        preWriteProjectionDigest,desiredProjectionDigest});
      const committed=await recoveryCommit({metrics,context,store:controlStore,session,checkpoint:issued,
        transition:'recovery.mutation_issued'});
      if(committed===null)return blocked('AUDIT_CHAIN_MISMATCH');
      const mutation=await recoveryProductMutation(metrics,productClient,method,
        committed.value.mutationPermit);
      const afterIssueRead=await readRecoveryCheckpointSnapshot({context,store:controlStore,session});
      if(afterIssueRead.status!=='PASS')return afterIssueRead;
      const issuedState=recoverySnapshotState(afterIssueRead.value.snapshot);
      const issuedCheckpoint=issuedState.checkpoint;
      let observedDigest=mutation.projectionDigest;
      if(mutation.status!=='PASS'){
        const observed=await recoveryProductRead(metrics,productClient,
          recoveryReadMethod(issuedCheckpoint.stepId),afterIssueRead.value.stepHandle,0);
        observedDigest=observed===null?recoveryReadbackFailureDigest(issuedCheckpoint)
          :observed.projectionDigest;
      }
      const transition=observedDigest===issuedCheckpoint.desiredProjectionDigest
        ?'recovery.step_committed'
        :observedDigest===issuedCheckpoint.preWriteProjectionDigest
          &&issuedCheckpoint.attemptOrdinal===1
          ?'recovery.mutation_not_committed':'recovery.step_blocked';
      const position=transition==='recovery.step_committed'?recoveryNextPosition(issuedCheckpoint)
        :{prefixLength:issuedCheckpoint.prefixLength,
          intentDispositionCursor:issuedCheckpoint.intentDispositionCursor};
      const successor=recoveryLinkedCheckpoint({predecessor:issuedCheckpoint,
        currentIntents:issuedState.currentIntents,
        transition,providerObservationDigest:observedDigest,position,
        checkpointState:transition==='recovery.step_committed'?'ready':'blocked',
        attemptOrdinal:transition==='recovery.step_committed'?null:issuedCheckpoint.attemptOrdinal,
        preWriteProjectionDigest:transition==='recovery.step_committed'?null:preWriteProjectionDigest,
        desiredProjectionDigest:transition==='recovery.step_committed'?null:desiredProjectionDigest});
      const finalCommit=await recoveryCommit({metrics,context,store:controlStore,session,
        checkpoint:successor,transition});
      if(finalCommit===null)return blocked('AUDIT_CHAIN_MISMATCH');
      continue;
    }
    if(checkpoint.checkpointState==='write-issued'){
      const method=recoveryReadMethod(checkpoint.stepId);
      const observed=await recoveryProductRead(metrics,productClient,method,read.value.stepHandle);
      const observedDigest=observed===null?recoveryReadbackFailureDigest(checkpoint)
        :observed.projectionDigest;
      const transition=observedDigest===checkpoint.desiredProjectionDigest
        ?'recovery.step_committed'
        :observedDigest===checkpoint.preWriteProjectionDigest&&checkpoint.attemptOrdinal===1
          ?'recovery.mutation_not_committed':'recovery.step_blocked';
      const next=transition==='recovery.step_committed'?recoveryNextPosition(checkpoint)
        :{prefixLength:checkpoint.prefixLength,
          intentDispositionCursor:checkpoint.intentDispositionCursor};
      const successor=recoveryLinkedCheckpoint({predecessor:checkpoint,
        currentIntents:state.currentIntents,transition,
        providerObservationDigest:observedDigest,position:next,
        checkpointState:transition==='recovery.step_committed'?'ready':'blocked',
        attemptOrdinal:transition==='recovery.step_committed'?null:checkpoint.attemptOrdinal,
        preWriteProjectionDigest:transition==='recovery.step_committed'?null
          :checkpoint.preWriteProjectionDigest,
        desiredProjectionDigest:transition==='recovery.step_committed'?null
          :checkpoint.desiredProjectionDigest});
      const committed=await recoveryCommit({metrics,context,store:controlStore,session,
        checkpoint:successor,transition});
      if(committed===null)return blocked('AUDIT_CHAIN_MISMATCH');
      continue;
    }
  }
  return blocked('RECOVERY_SCOPE_INVALID');
}catch{return blocked('RECOVERY_SCOPE_INVALID');}}

export function createRecoveryEnvironmentContext(args){try{
  if(!exact(args,['environment','recoveryHandle','controllerBundleSha','approvalRef',
    'originalWorkflowRunId','executionObservationQualification']))
    return blocked('RECOVERY_SCOPE_INVALID');
  const environment=dataValue(args,'environment');
  const h=dataValue(args,'recoveryHandle');
  const controllerBundleSha=dataValue(args,'controllerBundleSha');
  const approvalRef=dataValue(args,'approvalRef');
  const originalWorkflowRunId=dataValue(args,'originalWorkflowRunId');
  const observation=readExecutionObservationQualification(
    dataValue(args,'executionObservationQualification'));
  if(observation===null||!exact(environment,ENV_KEYS)
    ||canonicalJson(environment)!==canonicalJson(FIXED)
    ||!SHA.test(controllerBundleSha)
    ||parseRecoveryApprovalRef(approvalRef,originalWorkflowRunId).status!=='PASS')
    return blocked('RECOVERY_SCOPE_INVALID');
  if(!exact(h,['credentialClass','variableName','scopes','readSecret'])
    ||h.credentialClass!=='test-recovery'
    ||h.variableName!=='APPWRITE_TEST_RECOVERY_API_KEY'
    ||canonicalJson(h.scopes)!==canonicalJson(SCOPE)
    ||typeof h.readSecret!=='function')
    return blocked('RECOVERY_SCOPE_INVALID');
  const value=freeze({environmentClass:'appwrite-cloud-test-recovery',
    endpoint:FIXED.endpoint,projectId:FIXED.projectId,siteId:FIXED.siteId,
    publicOrigin:FIXED.origin,controllerBundleSha,approvalRef,originalWorkflowRunId});
  CONTEXTS.set(value,{handle:h,
    primaryExecutionRetentionMaxSeconds:observation.maximumRetentionSeconds});
  return pass(value);
}catch{return blocked('RECOVERY_SCOPE_INVALID');}}
export function isAuthenticRecoveryEnvironmentContext(value){try{return CONTEXTS.has(value);}catch{return false;}}

export function createRecoveryClient(){return blocked('RECOVERY_SCOPE_INVALID');}

const FLAGS=['--run-id','--original-workflow-run-id','--approval-ref','--expected-lease-version','--expected-ledger-digest','--confirm-run-id'];
function recoveryCliDenseArray(value,length){
  try{
    if(!Array.isArray(value)||isProxy(value))return null;
    const descriptors=Object.getOwnPropertyDescriptors(value);
    const expected=[...Array(length).keys()].map(String);
    if(Reflect.ownKeys(descriptors).length!==length+1
      ||descriptors.length?.value!==length
      ||expected.some((key)=>descriptors[key]?.enumerable!==true
        ||!Object.hasOwn(descriptors[key],'value')))return null;
    return expected.map((key)=>descriptors[key].value);
  }catch{return null;}
}
function recoveryCliCountSet(value,keys){
  if(!exact(value,keys))return null;
  const counts=Object.fromEntries(keys.map((key)=>[key,dataValue(value,key)]));
  if(keys.some((key)=>!Number.isSafeInteger(counts[key])||counts[key]<0))return null;
  if(Object.hasOwn(counts,'known')&&Object.hasOwn(counts,'maximum')
    &&counts.known>counts.maximum)return null;
  if(Object.hasOwn(counts,'observed')
    &&counts.observed>counts.maximum)return null;
  return counts;
}
function exactRecoveryCliTerminal(value){
  try{
    if(!exact(value,['completion','session','resources','close','measurements','proofDigest']))
      return false;
    const completion=dataValue(value,'completion'),session=dataValue(value,'session');
    const resources=dataValue(value,'resources'),close=dataValue(value,'close');
    const measurements=dataValue(value,'measurements'),proofDigest=dataValue(value,'proofDigest');
    if(completion!=='recovery-complete'||!DIGEST.test(proofDigest)
      ||!exact(session,['status','proofDigest','productCalls'])
      ||dataValue(session,'status')!=='absent'||!DIGEST.test(dataValue(session,'proofDigest')))
      return false;
    const sessionProductCalls=recoveryCliCountSet(dataValue(session,'productCalls'),
      ['known','maximum']);
    if(sessionProductCalls===null||sessionProductCalls.maximum!==10)return false;
    if(!exact(resources,
      ['completion','recoveryCheckpointDigest','resources','measurements'])
      ||dataValue(resources,'completion')!=='resources-complete'
      ||!DIGEST.test(dataValue(resources,'recoveryCheckpointDigest')))return false;
    const resourceItems=recoveryCliDenseArray(dataValue(resources,'resources'),3);
    const logicalResources=['primary-share','primary-graph','primary-project'];
    if(resourceItems===null||resourceItems.some((resource,index)=>(
      !exact(resource,['logicalResource','status','cleanupProofDigest'])
      ||dataValue(resource,'logicalResource')!==logicalResources[index]
      ||dataValue(resource,'status')!=='absent'
      ||!DIGEST.test(dataValue(resource,'cleanupProofDigest'))
    )))return false;
    const resourceMeasurements=dataValue(resources,'measurements');
    if(!exact(resourceMeasurements,['productHttp','store','functionExecutions'])
      ||dataValue(resourceMeasurements,'functionExecutions')!==0)return false;
    const resourceProduct=recoveryCliCountSet(dataValue(resourceMeasurements,'productHttp'),
      ['observed','known','maximum']);
    const resourceStore=recoveryCliCountSet(dataValue(resourceMeasurements,'store'),
      ['observed','known','maximum']);
    if(resourceProduct===null||resourceStore===null
      ||resourceProduct.known!==RECOVERY_COUNTS.knownProductHttpCalls
      ||resourceProduct.maximum!==RECOVERY_COUNTS.maximumProductHttpCalls
      ||resourceStore.known!==RECOVERY_COUNTS.knownStoreCalls
      ||resourceStore.maximum!==RECOVERY_COUNTS.maximumStoreCalls)return false;
    if(!exact(close,['completion','recoveryCloseDigest','measurements'])
      ||dataValue(close,'completion')!=='recovery-closed'
      ||!DIGEST.test(dataValue(close,'recoveryCloseDigest')))return false;
    const closeStore=recoveryCliCountSet(dataValue(close,'measurements'),
      ['knownStoreCalls','maximumStoreCalls']);
    if(closeStore===null||closeStore.knownStoreCalls!==2||closeStore.maximumStoreCalls!==2)
      return false;
    if(!exact(measurements,
      ['sessionProductCalls','resourceProductHttp','storeCalls','functionExecutions'])
      ||dataValue(measurements,'functionExecutions')!==0)return false;
    const totalSessionProduct=recoveryCliCountSet(dataValue(measurements,'sessionProductCalls'),
      ['known','maximum']);
    const totalResourceProduct=recoveryCliCountSet(dataValue(measurements,'resourceProductHttp'),
      ['observed','known','maximum']);
    const totalStore=recoveryCliCountSet(dataValue(measurements,'storeCalls'),
      ['known','maximum']);
    const sessionStoreKnown=sessionProductCalls.known===0?1:2;
    if(totalSessionProduct===null||totalResourceProduct===null||totalStore===null
      ||canonicalJson(totalSessionProduct)!==canonicalJson(sessionProductCalls)
      ||canonicalJson(totalResourceProduct)!==canonicalJson(resourceProduct)
      ||totalStore.known!==resourceStore.known+closeStore.knownStoreCalls+sessionStoreKnown
      ||totalStore.maximum!==resourceStore.maximum+closeStore.maximumStoreCalls+2)
      return false;
    return proofDigest===digest({completion,session,resources,close,measurements});
  }catch{return false;}
}
function recoveryCliNativePromiseResult(value){
  try{
    if(value===null||!['object','function'].includes(typeof value)||isProxy(value)
      ||!isPromise(value)||Object.getPrototypeOf(value)!==NATIVE_PROMISE_PROTOTYPE)return null;
    const ownDescriptors=Object.getOwnPropertyDescriptors(value);
    if(Object.hasOwn(ownDescriptors,'then')||Object.hasOwn(ownDescriptors,'constructor')
      ||Object.hasOwn(ownDescriptors,Symbol.toStringTag))return null;
    const prototypeDescriptors=Object.getOwnPropertyDescriptors(NATIVE_PROMISE_PROTOTYPE);
    const speciesDescriptor=Object.getOwnPropertyDescriptor(NATIVE_PROMISE,Symbol.species);
    if(prototypeDescriptors.constructor?.value!==NATIVE_PROMISE
      ||prototypeDescriptors.then?.value!==NATIVE_PROMISE_THEN
      ||speciesDescriptor?.get!==NATIVE_PROMISE_SPECIES_GETTER)return null;
    return REFLECT_APPLY(NATIVE_PROMISE_THEN,value,[
      (result)=>Object.freeze({fulfilled:true,result}),
      ()=>Object.freeze({fulfilled:false,result:null}),
    ]);
  }catch{return null;}
}
export async function recoverTestCloud(args){try{
  if(!exact(args,['executor'])||!RESOURCE_EXECUTORS.has(args.executor))
    return blocked('RECOVERY_SCOPE_INVALID');
  const binding=RESOURCE_EXECUTORS.get(args.executor);
  const {clock,context,controlStore,github,productClient,request}=binding;
  if(!await approveRecoveryRun({github,context,request}))return blocked('RECOVERY_APPROVAL_INVALID');
  const opened=await openRecoveryAccountSessionStage({clock,context,
    request:binding.recoveryStoreRequest,store:controlStore});
  if(opened.status!=='PASS')return opened;
  let sessionResult=exact(opened.value,['nextAuthority','sessionAbsenceDigest','measurements'])
    ?opened.value:null;
  let action=sessionResult===null?freeze({listHandle:opened.value.listHandle}):null;
  for(let guard=0;guard<12&&sessionResult===null;guard+=1){
    if(exact(action,['listHandle'])){
      const listed=await productClient.listBoundAccountSessions(action.listHandle);
      if(listed.status!=='PASS'||!exact(listed.value,['observedCount','observation']))return listed;
      const advanced=await advanceRecoveryAccountSessionList({clock,context,
        observation:listed.value.observation,session:opened.value.session,store:controlStore});
      if(advanced.status!=='PASS')return advanced;
      if(exact(advanced.value,['nextAuthority','sessionAbsenceDigest','measurements'])){
        sessionResult=advanced.value;break;
      }
      action=advanced.value;continue;
    }
    if(exact(action,['deletePermit'])){
      await productClient.deleteBoundAccountSession(action.deletePermit);
      const advanced=await advanceRecoveryAccountSessionDelete({clock,context,
        permit:action.deletePermit,session:opened.value.session,store:controlStore});
      if(advanced.status!=='PASS')return advanced;
      action=advanced.value;continue;
    }
    return blocked('RECOVERY_SCOPE_INVALID');
  }
  if(sessionResult===null)return blocked('RECOVERY_SCOPE_INVALID');
  binding.recoveryStoreRequest=sessionResult.nextAuthority;
  FULL_RECOVERY_EXECUTORS.add(args.executor);
  let resources;
  try{resources=await recoverTestCloudResources({executor:args.executor});}
  finally{FULL_RECOVERY_EXECUTORS.delete(args.executor);}
  if(resources.status!=='PASS')return resources;
  const close=FULL_RECOVERY_CLOSE_RESULTS.get(args.executor);
  FULL_RECOVERY_CLOSE_RESULTS.delete(args.executor);
  if(close===undefined)return blocked('RECOVERY_SCOPE_INVALID');
  const session=freeze({status:'absent',proofDigest:sessionResult.sessionAbsenceDigest,
    productCalls:freeze({known:sessionResult.measurements.knownProductCalls,
      maximum:sessionResult.measurements.maximumProductCalls})});
  const measurements=freeze({sessionProductCalls:session.productCalls,
    resourceProductHttp:resources.value.measurements.productHttp,
    storeCalls:freeze({known:sessionResult.measurements.knownStoreCalls
      +resources.value.measurements.store.known+close.measurements.knownStoreCalls,
      maximum:sessionResult.measurements.maximumStoreCalls
        +resources.value.measurements.store.maximum+close.measurements.maximumStoreCalls}),
    functionExecutions:0});
  const value={completion:'recovery-complete',session,resources:resources.value,close,measurements,
    proofDigest:null};
  value.proofDigest=digest({completion:value.completion,session:value.session,
    resources:value.resources,close:value.close,measurements:value.measurements});
  return pass(freeze(value));
}catch{return blocked('RECOVERY_SCOPE_INVALID');}}

export async function runRecoveryCli(input){try{
  if(!exact(input,['argv','environment','dependencies']))return 1;
  const argv=dataValue(input,'argv');
  const environment=dataValue(input,'environment');
  const dependencies=dataValue(input,'dependencies');
  if(!Array.isArray(argv)||isProxy(argv))return 1;
  if(argv.length===1&&argv[0]==='--help')return 0;
  if(argv.length!==FLAGS.length*2+1||argv.at(-1)!=='--execute')return 1;
  const values={};
  for(let i=0;i<FLAGS.length;i++){
    const flag=argv[i*2],value=argv[i*2+1];
    if(flag!==FLAGS[i]||!value)return 1;
    values[flag]=value;
  }
  if(Object.values(values).some(v=>/salmora|production|APPWRITE_/i.test(v))
    ||!RUN.test(values['--run-id'])
    ||values['--run-id']!==values['--confirm-run-id']
    ||!/^[1-9][0-9]*$/.test(values['--original-workflow-run-id'])
    ||!Number.isSafeInteger(Number(values['--expected-lease-version']))
    ||Number(values['--expected-lease-version'])<0
    ||!DIGEST.test(values['--expected-ledger-digest'])
    ||parseRecoveryApprovalRef(values['--approval-ref'],
      values['--original-workflow-run-id']).status!=='PASS')
    return 1;
  const expected=['APPWRITE_TEST_RECOVERY_API_KEY','VERIFICATION_CONTROLLER_BUNDLE_SHA',
    'VERIFICATION_RECOVERY_APPROVAL_REF'];
  if(!exact(environment,expected))return 1;
  const apiKey=dataValue(environment,'APPWRITE_TEST_RECOVERY_API_KEY');
  const bundleSha=dataValue(environment,'VERIFICATION_CONTROLLER_BUNDLE_SHA');
  const envApproval=dataValue(environment,'VERIFICATION_RECOVERY_APPROVAL_REF');
  if(typeof apiKey!=='string'||apiKey.length<1||!SHA.test(bundleSha)
    ||envApproval!==values['--approval-ref'])
    return 1;
  if(!exact(dependencies,['execute'])||typeof dataValue(dependencies,'execute')!=='function')
    return 2;
  const pendingResult=dataValue(dependencies,'execute')({argv:values,environment});
  let result=pendingResult;
  if(!exact(result,['status','value'])){
    const nativeResult=recoveryCliNativePromiseResult(pendingResult);
    if(nativeResult===null)return 2;
    const settled=await nativeResult;
    if(!exact(settled,['fulfilled','result'])||dataValue(settled,'fulfilled')!==true)return 2;
    result=dataValue(settled,'result');
  }
  if(!exact(result,['status','value']))return 2;
  const status=dataValue(result,'status'),value=dataValue(result,'value');
  if(status==='BLOCKED'&&value===null)return 2;
  return status==='PASS'&&exactRecoveryCliTerminal(value)?0:2;
}catch{return 1;}}
