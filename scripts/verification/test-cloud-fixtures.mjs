import { types as utilTypes } from 'node:util';

import { canonicalJson, sha256Bytes } from './canonical-json.mjs';
import { isAuthenticTestEnvironmentContext } from './test-cloud-environment.mjs';
import inventory from '../../dev/verification/environments/test-cloud.inventory.v1.json' with { type: 'json' };
import {
  commitIntentSnapshot, markCleanupDebt, reconcilePrimaryExecutionRunnerObservation,
} from './test-cloud-control-store.mjs';
import {
  authenticateTestCloudRuntimeActive,
  isAuthenticTestCloudBootstrapHub,
  readTestCloudRuntimeLifecycle,
} from './test-cloud-provider-contract.mjs';
const BOOTSTRAP_HUB_PROPERTY='__APPWRITEWORK_TEST_CLOUD_BOOTSTRAP_HUB_V1__';
const getOwnPropertyDescriptor=Object.getOwnPropertyDescriptor;
const reflectApply=Reflect.apply;
const FIXTURES_BOOTSTRAP_RECEIVER=Object.freeze(Object.create(null));
let fixturesBootstrapState='EMPTY';
const TIMESTAMP_BINDING_ORDINALS=Object.freeze([4,5,8,11,16]);
const FIXTURE_LITERAL_NAMES=Object.freeze([
  'entrypointArtifactName','projectRowName','projectTags','rootArtifactName',
]);
const FIXTURE_LITERAL_VALUES=Object.freeze({
  entrypointArtifactName:'Entrypoint',
  projectRowName:'Hello World',
  projectTags:Object.freeze([]),
  rootArtifactName:'Hello World',
});
const MILLIS_UTC=/^\d{4}-(0[1-9]|1[0-2])-([0-2]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$/u;
const ROUTE_PROJECTION_KEYS=Object.freeze([
  'method','originBinding','pathBinding','queryBinding','bodyBinding',
  'sourceBytesDigest','generatedIdBindings',
]);
const PROVIDER_MUTATION_PROFILE_KEYS=Object.freeze([
  'operation','expectedStateContract','expectedStateContractDigest',
  'fixtureSemanticLiterals','environmentBindings','providerIdentities',
  'ownerUserId','priorExpectedStates','sourceByteSizes','timestampBindings',
]);
const OPERATION_KEYS=Object.freeze([
  'mutationOrdinal','phase','operation','requestTemplate','requestTemplateDigest',
  'expectedStateContract','expectedStateContractDigest',
]);
const SOURCE_SLOT_BY_ORDINAL=Object.freeze({
  0:'rootManifestInitial',1:'entrypointSourceInitial',7:'entrypointSourceSaved',
  10:'rootManifestSaved',14:'visualModelSourceSaved',
});
let consumeExpectedStateResultDispatcher=null;
let bootstrapBridgeReceiver=null;
const frozenExact=(value,keys)=>{try{return plainExact(value,keys)&&Object.isFrozen(value)&&keys.every((key,index)=>Reflect.ownKeys(value)[index]===key);}catch{return false;}};
const denseFrozen=(value)=>Array.isArray(value)&&Object.isFrozen(value)&&Reflect.ownKeys(value).length===value.length+1&&value.every((_item,index)=>Object.hasOwn(value,index));
const nominal=(value)=>{try{return value!==null&&typeof value==='object'&&Object.getPrototypeOf(value)===null&&Object.isFrozen(value)&&Reflect.ownKeys(value).length===0;}catch{return false;}};
const closed=(keys,values)=>{const output=Object.create(null);for(const key of keys)Object.defineProperty(output,key,{value:values[key],enumerable:true});return Object.freeze(output);};
const canonicalDigest=(value)=>sha256Bytes(encoder.encode(canonicalJson(value)));
const safeClone=(value)=>freeze(JSON.parse(canonicalJson(value)));
const validDigest=(value)=>typeof value==='string'&&DIGEST.test(value);
function mapRows(rows,keys,nameKey,expected){
  if(!denseFrozen(rows)||!exactRowNames(rows,nameKey,expected))return null;
  const mapped=new Map();
  for(let index=0;index<rows.length;index+=1){
    const row=rows[index];
    if(!frozenExact(row,keys))return null;
    const name=row[nameKey];
    if((typeof name!=='string'&&!Number.isSafeInteger(name))||mapped.has(name))return null;
    mapped.set(name,row);
  }
  return mapped;
}
function exactRowNames(rows,nameKey,expected){
  return rows.length===expected.length&&rows.every((row,index)=>row[nameKey]===expected[index]);
}
function valueTypeOf(value){
  if(value===null)return'null';
  if(Array.isArray(value))return'array';
  if(typeof value==='object')return'object';
  return typeof value;
}
function validTypedRows(rows){return rows.every((row)=>row.valueType===valueTypeOf(row.value));}
function collectSourceRequirements(contract){
  const required={providerIdentities:[],logicalValueBindings:[],priorExpectedStates:[],sourceByteSizes:[]};
  const add=(name,value)=>{if(!required[name].includes(value))required[name].push(value);};
  if(Object.hasOwn(contract,'baseSourceMutationOrdinal')&&contract.baseSourceMutationOrdinal!==null){
    add('priorExpectedStates',contract.baseSourceMutationOrdinal);
  }
  const visit=(source,depth=0)=>{
    if(depth>8||source===null||typeof source!=='object')throw new TypeError('source depth');
    if(source.kind==='provider-id')add('providerIdentities',source.ownerSlot);
    else if(source.kind==='environment-id')add('providerIdentities',source.bindingName);
    else if(source.kind==='logical-value')add('logicalValueBindings',source.ownerSlot+'.'+source.name);
    else if(source.kind==='expected-state-field')add('priorExpectedStates',source.sourceMutationOrdinal);
    else if(source.kind==='source-bytes-size'){
      const slot=SOURCE_SLOT_BY_ORDINAL[source.sourceMutationOrdinal];
      if(typeof slot!=='string')throw new TypeError('source slot');
      add('sourceByteSizes',slot);
    }else if(source.kind==='derived-string'){
      if(!denseFrozen(source.inputSources))throw new TypeError('derived sources');
      for(const input of source.inputSources)visit(input,depth+1);
    }
  };
  for(const row of contract.valueSources)visit(row.source);
  return Object.freeze({
    providerIdentities:Object.freeze(required.providerIdentities),
    logicalValueBindings:Object.freeze(required.logicalValueBindings),
    priorExpectedStates:Object.freeze(required.priorExpectedStates),
    sourceByteSizes:Object.freeze(required.sourceByteSizes),
  });
}
function validateRouteProjection(routeProjection,operation){
  if(!frozenExact(routeProjection,ROUTE_PROJECTION_KEYS)
    ||!['POST','PATCH'].includes(routeProjection.method)
    ||routeProjection.method!==operation.requestTemplate?.method
    ||!frozenExact(routeProjection.originBinding,['originClass','originDigest'])
    ||routeProjection.originBinding.originClass!=='appwrite-api'
    ||!validDigest(routeProjection.originBinding.originDigest)
    ||!frozenExact(routeProjection.pathBinding,['pathClass','pathDigest'])
    ||!['row-create','row-update','file-create'].includes(routeProjection.pathBinding.pathClass)
    ||routeProjection.pathBinding.pathClass!==operation.requestTemplate?.bodyKind
    ||!validDigest(routeProjection.pathBinding.pathDigest)
    ||!frozenExact(routeProjection.queryBinding,['queryClass','queryDigest'])
    ||routeProjection.queryBinding.queryClass!=='absent'
    ||!validDigest(routeProjection.queryBinding.queryDigest)
    ||!frozenExact(routeProjection.bodyBinding,['semanticBodyDigest','boundValuesDigest','executionEnvelopeDigest'])
    ||!validDigest(routeProjection.bodyBinding.semanticBodyDigest)
    ||!validDigest(routeProjection.bodyBinding.boundValuesDigest)
    ||routeProjection.bodyBinding.executionEnvelopeDigest!==null
    ||!denseFrozen(routeProjection.generatedIdBindings)
    ||routeProjection.generatedIdBindings.some((binding)=>(
      !frozenExact(binding,['bindingName','valueDigest'])
      ||typeof binding.bindingName!=='string'||binding.bindingName.length===0
      ||!validDigest(binding.valueDigest)
    ))
    ||new Set(routeProjection.generatedIdBindings.map((binding)=>binding.bindingName)).size
      !==routeProjection.generatedIdBindings.length
    ||(routeProjection.sourceBytesDigest!==null&&!validDigest(routeProjection.sourceBytesDigest))
    ||(operation.requestTemplate?.bodyKind==='file-create')
      !==(routeProjection.sourceBytesDigest!==null))return false;
  return true;
}
function deriveString(derivation,inputs){
  if(derivation==='stable-default-entrypoint-ref'&&inputs.length===4){
    return JSON.stringify({kind:'artifact-version',ref:{projectId:inputs[0],artifactId:inputs[1],artifactType:'workflow.dag.v1',versionId:inputs[2],stability:'stable'},contentHash:inputs[3]});
  }
  if(derivation==='workflow-save-file-name'&&inputs.length===1)return `${inputs[0]}.workflow.dag.json`;
  if(derivation==='container-manifest-file-name'&&inputs.length===1){
    const component=String(inputs[0]).split(':').at(-1).replace(/[^A-Za-z0-9._-]/gu,'-');
    return `${component.length===0?'container':component}.container.json`;
  }
  if(derivation==='visual-model-artifact-id'&&inputs.length===1)return `visual-model:${inputs[0]}`;
  if(derivation==='visual-model-artifact-name'&&inputs.length===1)return `${inputs[0]} layout`;
  if(derivation==='visual-model-file-name'&&inputs.length===1)return `${String(inputs[0]).replace(/[^A-Za-z0-9._-]/gu,'-')}.json`;
  throw new TypeError('unsupported derived string');
}
function resolveExpectedSource(source,authority,depth=0){
  if(depth>8||source===null||typeof source!=='object'||!Object.isFrozen(source))throw new TypeError('invalid source');
  if(frozenExact(source,['kind','name'])&&source.kind==='contract-literal'){
    const row=authority.fixtureSemanticLiterals.get(source.name);if(!row)throw new TypeError('missing literal');return safeClone(row.value);
  }
  if(frozenExact(source,['kind','value'])&&source.kind==='literal')return safeClone(source.value);
  if(frozenExact(source,['kind'])&&source.kind==='owner-user-id')return authority.ownerUserId;
  if(frozenExact(source,['kind','ownerSlot','name'])&&source.kind==='logical-value'){
    const row=authority.logicalValueBindings.get(`${source.ownerSlot}.${source.name}`);if(!row)throw new TypeError('missing logical value');return safeClone(row.value);
  }
  if(frozenExact(source,['kind','ownerSlot'])&&source.kind==='provider-id'){
    const row=authority.providerIdentities.get(source.ownerSlot);if(!row)throw new TypeError('missing provider identity');return row.value;
  }
  if(frozenExact(source,['kind','bindingName'])&&source.kind==='environment-id'){
    const row=authority.providerIdentities.get(source.bindingName);if(!row)throw new TypeError('missing environment identity');return row.value;
  }
  if(frozenExact(source,['kind','ownerSlot','sourceMutationOrdinal','key'])&&source.kind==='expected-state-field'){
    const row=authority.priorExpectedStates.get(source.sourceMutationOrdinal);
    if(!row||row.expectedState===null||typeof row.expectedState!=='object'||!Object.hasOwn(row.expectedState,source.key))throw new TypeError('missing prior state');
    return safeClone(row.expectedState[source.key]);
  }
  if(frozenExact(source,['kind','sourceMutationOrdinal'])&&source.kind==='source-bytes-size'){
    const slot=SOURCE_SLOT_BY_ORDINAL[source.sourceMutationOrdinal];
    const row=authority.sourceByteSizes.get(slot);if(!row)throw new TypeError('missing source size');return row.sizeBytes;
  }
  if(frozenExact(source,['kind','mutationOrdinal','name'])&&source.kind==='runtime-utc-timestamp'&&source.name==='publishedAt'){
    const row=authority.timestampBindings.get(source.mutationOrdinal);if(!row)throw new TypeError('missing timestamp');return row.timestamp;
  }
  if(frozenExact(source,['kind','derivation','inputSources'])&&source.kind==='derived-string'&&denseFrozen(source.inputSources)){
    return deriveString(source.derivation,source.inputSources.map((item)=>resolveExpectedSource(item,authority,depth+1)));
  }
  throw new TypeError('unsupported source');
}
function constructExpectedMapping(contract,authority){
  let output;
  let keys;
  if(frozenExact(contract,['schemaVersion','baseSourceMutationOrdinal','applicationKeys','valueSources'])
    &&contract.schemaVersion==='verification-row-expected-state-contract.v1'
    &&denseFrozen(contract.applicationKeys)&&denseFrozen(contract.valueSources)){
    keys=[...contract.applicationKeys];
    if(keys.some((key)=>typeof key!=='string'||key.length===0)||new Set(keys).size!==keys.length)throw new TypeError('invalid application keys');
    const base=contract.baseSourceMutationOrdinal===null?{}:authority.priorExpectedStates.get(contract.baseSourceMutationOrdinal)?.expectedState;
    if(base===undefined||base===null||typeof base!=='object'||Array.isArray(base))throw new TypeError('invalid base');
    output={...base};
  }else if(frozenExact(contract,['schemaVersion','metadataKeys','valueSources'])
    &&contract.schemaVersion==='verification-file-expected-state-contract.v1'
    &&denseFrozen(contract.metadataKeys)
    &&canonicalJson(contract.metadataKeys)===canonicalJson(['bucketBinding','fileName','mimeType','sizeBytes'])
    &&denseFrozen(contract.valueSources)){
    keys=[...contract.metadataKeys];output={};
  }else throw new TypeError('invalid expected state contract');
  for(const row of contract.valueSources){
    if(!frozenExact(row,['key','source'])||typeof row.key!=='string'||!keys.includes(row.key))throw new TypeError('invalid value source');
    output[row.key]=resolveExpectedSource(row.source,authority);
  }
  if(Object.keys(output).length!==keys.length||keys.some((key)=>!Object.hasOwn(output,key)))throw new TypeError('incomplete expected mapping');
  const ordered=Object.create(null);
  for(const key of keys)Object.defineProperty(ordered,key,{value:safeClone(output[key]),enumerable:true});
  return freeze(ordered);
}
let timestampTransferRecord=Object.freeze({
  state:'TIMESTAMPS_ACCEPTING',cursor:0,clock:null,bindings:Object.freeze([]),
});
let expectedStateConstructionRecord=Object.freeze({
  state:'OPEN',nextMutationOrdinal:0,constructedCount:0,
});

const encoder=new TextEncoder();
const TYPES=new Set(['primary-project','primary-graph','primary-share','account-session-set','primary-execution']);
const LIFECYCLES=new Set(['fixture','session-aggregate','provider-retained-observation']);
const DIGEST=/^sha256:[0-9a-f]{64}$/u;
const OWNER_MARKER=/^verification-owner\.v1:sha256:[0-9a-f]{64}$/u;
const PROVIDER_ID=/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const pass=(value)=>Object.freeze({status:'PASS',value,diagnostics:Object.freeze([])});
const blocked=(code)=>Object.freeze({status:'BLOCKED',value:null,diagnostics:Object.freeze([Object.freeze({code,safeMessage:'Fixture transition was blocked.',retryable:false})])});
const blockedWithState=(code,lease,capability)=>Object.freeze({status:'BLOCKED',value:freeze({lease,capability}),diagnostics:Object.freeze([Object.freeze({code,safeMessage:'Fixture transition was blocked.',retryable:false})])});
const freeze=(v)=>{if(v&&typeof v==='object'&&!Object.isFrozen(v)){for(const x of Object.values(v))freeze(x);Object.freeze(v);}return v;};
const hash=(text)=>sha256Bytes(encoder.encode(text)).slice(7);
const iso=(clock)=>new Date(clock.nowEpochSeconds()*1000).toISOString();
const plainExact=(value,keys)=>{try{return value&&typeof value==='object'&&!Array.isArray(value)&&Reflect.ownKeys(value).length===keys.length&&keys.every((key)=>{const descriptor=Object.getOwnPropertyDescriptor(value,key);return descriptor?.enumerable===true&&Object.hasOwn(descriptor,'value');});}catch{return false;}};
const DESCRIPTOR_KEYS=['resourceType','resourceId','providerResourceIds','ownerMarker','dependencyOrder','lifecycleClass','retentionExpiresAt'];
function expectedPrimaryExecutionDescriptor(context){
  const parameters={inputProfile:'verification-minimal',logicalWorkflow:'hello-world-no-cost'};
  const operationKey=sha256Bytes(encoder.encode(`${context.runId}|worker.invoke_no_cost|${canonicalJson(parameters)}`));
  const resourceId=`vr-${hash(`${context.environmentDigest}|${context.runId}|primary-execution`).slice(0,32)}`;
  const preimage={environmentDigest:context.environmentDigest,operationKey,resourceId,resourceType:'primary-execution',runId:context.runId,schemaVersion:'verification-owner-marker.v1'};
  return {resourceId,ownerMarker:`verification-owner.v1:${sha256Bytes(encoder.encode(canonicalJson(preimage)))}`};
}
function validDescriptor(d,context=null){
  if(!plainExact(d,DESCRIPTOR_KEYS)||!TYPES.has(d.resourceType)||typeof d.resourceId!=='string'||d.resourceId.length===0||(d.resourceType==='account-session-set'&&!['owner','editor','viewer'].includes(d.resourceId))||!Array.isArray(d.providerResourceIds)||d.providerResourceIds.some((x)=>typeof x!=='string'||x.length===0)||new Set(d.providerResourceIds).size!==d.providerResourceIds.length||typeof d.ownerMarker!=='string'||!Number.isSafeInteger(d.dependencyOrder)||d.dependencyOrder<0||!LIFECYCLES.has(d.lifecycleClass)||(d.retentionExpiresAt!==null&&typeof d.retentionExpiresAt!=='string'))return false;
  if(d.resourceType!=='primary-execution')return d.lifecycleClass!=='provider-retained-observation';
  if(!isAuthenticTestEnvironmentContext(context)||d.lifecycleClass!=='provider-retained-observation'||d.dependencyOrder!==50||d.providerResourceIds.length!==0||d.retentionExpiresAt!==null||!OWNER_MARKER.test(d.ownerMarker))return false;
  const expected=expectedPrimaryExecutionDescriptor(context);
  return d.resourceId===expected.resourceId&&d.ownerMarker===expected.ownerMarker;
}
function snapshot({context,descriptor,state,version,createdAt,updatedAt}){const intentId=hash(`${context.environmentDigest}|${context.runId}|${descriptor.resourceType}|${descriptor.resourceId}`);return freeze({schemaVersion:'verification-intent-snapshot.v1',intentId,runId:context.runId,environmentDigest:context.environmentDigest,resourceType:descriptor.resourceType,resourceId:descriptor.resourceId,providerResourceIds:[...descriptor.providerResourceIds].sort(),ownerMarker:descriptor.ownerMarker,dependencyOrder:descriptor.dependencyOrder,lifecycleClass:descriptor.lifecycleClass,state,intentVersion:version,observationDigest:null,retentionExpiresAt:descriptor.retentionExpiresAt,createdAt,updatedAt});}
function descriptorFrom(i){return{resourceType:i.resourceType,resourceId:i.resourceId,providerResourceIds:i.providerResourceIds,ownerMarker:i.ownerMarker,dependencyOrder:i.dependencyOrder,lifecycleClass:i.lifecycleClass,retentionExpiresAt:i.retentionExpiresAt};}

function activeRuntimeQualification(runtimeQualification){
  if(readTestCloudRuntimeLifecycle()!=='ACTIVE')return false;
  const authenticationArgs=Object.freeze({runtimeQualification});
  return authenticateTestCloudRuntimeActive(authenticationArgs)===true;
}

function blockExpectedStateConstruction(){
  expectedStateConstructionRecord=Object.freeze({
    state:'BLOCKED',
    nextMutationOrdinal:expectedStateConstructionRecord.nextMutationOrdinal,
    constructedCount:expectedStateConstructionRecord.constructedCount,
  });
  return false;
}

function constructExpectedStateForProviderMutation(args){
  try{

    if(
      fixturesBootstrapState!=='REGISTERED'
      ||expectedStateConstructionRecord.state!=='OPEN'
      ||expectedStateConstructionRecord.nextMutationOrdinal!==args.mutationOrdinal
      ||!frozenExact(args,[
        'runtimeQualification','context','sessionIntentQualification','mutationOrdinal',
        'providerMutationProfile','logicalValueBindings','routeProjection',
      ])
      ||!activeRuntimeQualification(args.runtimeQualification)
      ||!isAuthenticTestEnvironmentContext(args.context)
      ||!nominal(args.sessionIntentQualification)
      ||!Number.isSafeInteger(args.mutationOrdinal)||args.mutationOrdinal<0||args.mutationOrdinal>16
      ||!frozenExact(args.providerMutationProfile,PROVIDER_MUTATION_PROFILE_KEYS)
      ||!frozenExact(args.providerMutationProfile.operation,OPERATION_KEYS)
      ||args.providerMutationProfile.operation.mutationOrdinal!==args.mutationOrdinal
      ||args.providerMutationProfile.operation.expectedStateContract!==args.providerMutationProfile.expectedStateContract
      ||args.providerMutationProfile.operation.expectedStateContractDigest!==args.providerMutationProfile.expectedStateContractDigest
      ||!validDigest(args.providerMutationProfile.expectedStateContractDigest)
      ||canonicalDigest(args.providerMutationProfile.expectedStateContract)!==args.providerMutationProfile.expectedStateContractDigest
      ||!validDigest(args.providerMutationProfile.operation.requestTemplateDigest)
      ||canonicalDigest(args.providerMutationProfile.operation.requestTemplate)!==args.providerMutationProfile.operation.requestTemplateDigest
      ||!frozenExact(args.providerMutationProfile.environmentBindings,['environmentDigest','providerContractDigest'])
      ||!validDigest(args.providerMutationProfile.environmentBindings.environmentDigest)
      ||!validDigest(args.providerMutationProfile.environmentBindings.providerContractDigest)
      ||typeof args.providerMutationProfile.ownerUserId!=='string'||args.providerMutationProfile.ownerUserId.length===0
      ||!validateRouteProjection(args.routeProjection,args.providerMutationProfile.operation)
    )return blockExpectedStateConstruction();
    const sourceRequirements=collectSourceRequirements(args.providerMutationProfile.expectedStateContract);
    const fixtureSemanticLiterals=mapRows(args.providerMutationProfile.fixtureSemanticLiterals,['literalName','valueType','value'],'literalName',FIXTURE_LITERAL_NAMES);
    const providerIdentities=mapRows(args.providerMutationProfile.providerIdentities,['bindingName','value'],'bindingName',sourceRequirements.providerIdentities);
    const priorExpectedStates=mapRows(args.providerMutationProfile.priorExpectedStates,['mutationOrdinal','expectedState'],'mutationOrdinal',sourceRequirements.priorExpectedStates);
    const sourceByteSizes=mapRows(args.providerMutationProfile.sourceByteSizes,['bindingName','sizeBytes'],'bindingName',sourceRequirements.sourceByteSizes);
    const timestampRows=args.providerMutationProfile.timestampBindings.length===0
      &&timestampTransferRecord.bindings.length===TIMESTAMP_BINDING_ORDINALS.length
      ?Object.freeze(TIMESTAMP_BINDING_ORDINALS.map((mutationOrdinal,index)=>closed(
        ['mutationOrdinal','timestamp'],
        {mutationOrdinal,timestamp:timestampTransferRecord.bindings[index]},
      )))
      :args.providerMutationProfile.timestampBindings;
    const timestampBindings=mapRows(timestampRows,['mutationOrdinal','timestamp'],'mutationOrdinal',TIMESTAMP_BINDING_ORDINALS);
    const logicalValueBindings=mapRows(args.logicalValueBindings,['bindingName','valueType','value'],'bindingName',sourceRequirements.logicalValueBindings);
    if(!fixtureSemanticLiterals||!providerIdentities||!priorExpectedStates||!sourceByteSizes||!timestampBindings||!logicalValueBindings
      ||args.providerMutationProfile.environmentBindings.environmentDigest!==args.context.environmentDigest
      ||args.providerMutationProfile.environmentBindings.providerContractDigest!==inventory.providerContractDigest
      ||!exactRowNames(timestampRows,'mutationOrdinal',TIMESTAMP_BINDING_ORDINALS)
      ||!exactRowNames(args.providerMutationProfile.priorExpectedStates,'mutationOrdinal',sourceRequirements.priorExpectedStates)
      ||!validTypedRows([...fixtureSemanticLiterals.values()])
      ||!validTypedRows([...logicalValueBindings.values()])
      ||!denseFrozen(fixtureSemanticLiterals.get('projectTags')?.value)
      ||[...fixtureSemanticLiterals.values()].some((row)=>canonicalJson(row.value)!==canonicalJson(FIXTURE_LITERAL_VALUES[row.literalName]))
      ||[...providerIdentities.values()].some((row)=>typeof row.value!=='string'||row.value.length===0)
      ||[...sourceByteSizes.values()].some((row)=>!Number.isSafeInteger(row.sizeBytes)||row.sizeBytes<0)
      ||TIMESTAMP_BINDING_ORDINALS.some((ordinal,index)=>timestampBindings.get(ordinal)?.timestamp!==timestampTransferRecord.bindings[index])
      ||[...timestampBindings.values()].some((row)=>!MILLIS_UTC.test(row.timestamp))){return blockExpectedStateConstruction();}
    if(timestampTransferRecord.state==='TIMESTAMPS_COMPLETE'){
      timestampTransferRecord=Object.freeze({...timestampTransferRecord,state:'TIMESTAMPS_CONSUMED'});
    }else if(timestampTransferRecord.state!=='TIMESTAMPS_CONSUMED')return blockExpectedStateConstruction();
    const expectedResultState=constructExpectedMapping(args.providerMutationProfile.expectedStateContract,{
      fixtureSemanticLiterals,providerIdentities,priorExpectedStates,sourceByteSizes,
      timestampBindings,logicalValueBindings,ownerUserId:args.providerMutationProfile.ownerUserId,
    });
    const requestInstance=closed([
      'schemaVersion','mutationOrdinal','requestTemplateDigest','boundValuesDigest',
      'semanticBodyDigest','sourceBytesDigest','executionEnvelopeDigest',
    ],{
      schemaVersion:'verification-provider-request-instance.v1',
      mutationOrdinal:args.mutationOrdinal,
      requestTemplateDigest:args.providerMutationProfile.operation.requestTemplateDigest,
      boundValuesDigest:args.routeProjection.bodyBinding.boundValuesDigest,
      semanticBodyDigest:args.routeProjection.bodyBinding.semanticBodyDigest,
      sourceBytesDigest:args.routeProjection.sourceBytesDigest,
      executionEnvelopeDigest:null,
    });
    const output=closed(['requestInstanceDigest','expectedResultState','expectedStateContractDigest'],{
      requestInstanceDigest:canonicalDigest(requestInstance),expectedResultState,
      expectedStateContractDigest:args.providerMutationProfile.expectedStateContractDigest,
    });
    const nextMutationOrdinal=args.mutationOrdinal+1;
    expectedStateConstructionRecord=Object.freeze({
      state:nextMutationOrdinal===17?'COMPLETE':'OPEN',
      nextMutationOrdinal,constructedCount:nextMutationOrdinal,
    });
    return output;
  }catch(error){return blockExpectedStateConstruction();}
}

function blockTimestampTransfers(){
  timestampTransferRecord=Object.freeze({
    state:'BLOCKED',
    cursor:timestampTransferRecord.cursor,
    clock:timestampTransferRecord.clock,
    bindings:Object.freeze([...timestampTransferRecord.bindings]),
  });
  return false;
}

function receiveTimestampBindingTransfer(args){
  try{
    const expectedOrdinal=TIMESTAMP_BINDING_ORDINALS[timestampTransferRecord.cursor];
    if(
      fixturesBootstrapState!=='REGISTERED'
      ||timestampTransferRecord.state!=='TIMESTAMPS_ACCEPTING'
      ||consumeExpectedStateResultDispatcher===null
      ||bootstrapBridgeReceiver===null
      ||!plainExact(args,[
        'runtimeQualification','expectedStateResult','clock','mutationOrdinal',
      ])
      ||args.mutationOrdinal!==expectedOrdinal
      ||args.clock===null||typeof args.clock!=='object'
      ||args.expectedStateResult===null||typeof args.expectedStateResult!=='object'
      ||(timestampTransferRecord.clock!==null&&timestampTransferRecord.clock!==args.clock)
      ||!activeRuntimeQualification(args.runtimeQualification)
    )return blockTimestampTransfers();
    const publishedAt=reflectApply(
      consumeExpectedStateResultDispatcher,
      bootstrapBridgeReceiver,
      [args],
    );
    if(typeof publishedAt!=='string'||!MILLIS_UTC.test(publishedAt)){
      return blockTimestampTransfers();
    }
    const bindings=Object.freeze([...timestampTransferRecord.bindings,publishedAt]);
    const cursor=timestampTransferRecord.cursor+1;
    timestampTransferRecord=Object.freeze({
      state:cursor===TIMESTAMP_BINDING_ORDINALS.length
        ?'TIMESTAMPS_COMPLETE':'TIMESTAMPS_ACCEPTING',
      cursor,
      clock:args.clock,
      bindings,
    });
    return true;
  }catch{return blockTimestampTransfers();}
}

function blockFixturesBootstrap(){
  fixturesBootstrapState='BLOCKED';
  isAuthenticTestCloudBootstrapHub(undefined);
  return false;
}

function registrationEnvelope(implementation){
  return Object.freeze(Object.assign(Object.create(null),{
    receiver:FIXTURES_BOOTSTRAP_RECEIVER,
    implementation,
    moduleUrl:import.meta.url,
  }));
}

function currentAuthenticBootstrapHub(){
  const descriptor=reflectApply(
    getOwnPropertyDescriptor,
    Object,
    [globalThis,BOOTSTRAP_HUB_PROPERTY],
  );
  if(
    descriptor===undefined
    ||descriptor.configurable!==true
    ||descriptor.enumerable!==false
    ||descriptor.writable!==false
    ||!Object.hasOwn(descriptor,'value')
    ||!isAuthenticTestCloudBootstrapHub(descriptor.value)
  )return null;
  return descriptor.value;
}

export function registerTestCloudFixturesBootstrap(){
  if(
    arguments.length!==0
    ||fixturesBootstrapState!=='EMPTY'
    ||readTestCloudRuntimeLifecycle()!=='BOOTSTRAPPING'
  )return blockFixturesBootstrap();
  const hub=currentAuthenticBootstrapHub();
  if(hub===null)return blockFixturesBootstrap();
  fixturesBootstrapState='REGISTERING';
  try{
    if(
      typeof hub.consumeExpectedStateResult!=='function'
      ||hub.consumeExpectedStateResult.length!==1
    )return blockFixturesBootstrap();
    consumeExpectedStateResultDispatcher=hub.consumeExpectedStateResult;
    bootstrapBridgeReceiver=hub.bridgeReceiver;
    const registrations=[
      [hub.registerExpectedStateConstructor,registrationEnvelope(constructExpectedStateForProviderMutation)],
      [hub.registerTimestampBindingTransferReceiver,registrationEnvelope(receiveTimestampBindingTransfer)],
    ];
    for(const [registrar,envelope] of registrations){
      if(typeof registrar!=='function'||registrar.length!==1
        ||reflectApply(registrar,hub.bridgeReceiver,[envelope])!==true)
        return blockFixturesBootstrap();
    }
    fixturesBootstrapState='REGISTERED';
    return true;
  }catch{return blockFixturesBootstrap();}
}

export async function planCreate({context,store,lease,capability,descriptor,clock}){try{if(!isAuthenticTestEnvironmentContext(context)||!validDescriptor(descriptor,context)||lease.ownerRunId!==context.runId)return blocked('INTENT_WRITE_BLOCKED');const intentId=hash(`${context.environmentDigest}|${context.runId}|${descriptor.resourceType}|${descriptor.resourceId}`);const existing=await store.getIntentProjection(intentId);if(existing){if(canonicalJson(descriptorFrom(existing))!==canonicalJson(descriptor))return blocked('INTENT_INVALID_TRANSITION');return pass(freeze({intent:existing,lease,capability}));}const at=iso(clock),intent=snapshot({context,descriptor,state:'planned',version:1,createdAt:at,updatedAt:at});const r=await commitIntentSnapshot({context,store,lease,capability,clock,snapshot:intent});return r.status==='PASS'?pass(freeze({intent,lease:r.value.lease,capability:r.value.capability})):r;}catch{return blocked('INTENT_WRITE_BLOCKED');}}

export async function markCreated({context,store,lease,capability,intent,providerReadback,clock}){try{if(!isAuthenticTestEnvironmentContext(context)||intent?.state!=='planned'||intent.runId!==context.runId||intent.resourceType==='primary-execution')return blocked('INTENT_INVALID_TRANSITION');if(!plainExact(providerReadback,['resourceId','ownerMarker','environmentDigest'])||providerReadback.resourceId!==intent.resourceId||providerReadback.ownerMarker!==intent.ownerMarker||providerReadback.environmentDigest!==context.environmentDigest)return blocked('OWNERSHIP_MISMATCH');const next=snapshot({context,descriptor:descriptorFrom(intent),state:'created',version:intent.intentVersion+1,createdAt:intent.createdAt,updatedAt:iso(clock)});const r=await commitIntentSnapshot({context,store,lease,capability,clock,snapshot:next});return r.status==='PASS'?pass(freeze({intent:next,lease:r.value.lease,capability:r.value.capability})):r;}catch{return blocked('INTENT_WRITE_BLOCKED');}}

function extractProviderExecutionId(value){
  try{
    if(utilTypes.isProxy(value)||value===null||typeof value!=='object'||Array.isArray(value))return null;
    const descriptor=Object.getOwnPropertyDescriptor(value,'executionId');
    return descriptor?.enumerable===true&&Object.hasOwn(descriptor,'value')&&typeof descriptor.value==='string'&&PROVIDER_ID.test(descriptor.value)?descriptor.value:null;
  }catch{return null;}
}
function expectedWorkerOutputDigest(context,intent){
  const record={environmentDigest:context.environmentDigest,inputProfile:'verification-minimal',logicalWorkflow:'hello-world-no-cost',outcome:'completed-no-cost',ownerMarker:intent.ownerMarker,runId:context.runId,schemaVersion:'verification-worker-output.v1'};
  return sha256Bytes(encoder.encode(canonicalJson(record)));
}
export async function markPrimaryExecutionObserved({context,store,lease,capability,intent,observation,clock}){
  try{
    const expectedDescriptor=expectedPrimaryExecutionDescriptor(context);
    if(!isAuthenticTestEnvironmentContext(context)||intent?.resourceType!=='primary-execution'||intent.lifecycleClass!=='provider-retained-observation'||intent.state!=='planned'||intent.intentVersion!==1||intent.runId!==context.runId||intent.environmentDigest!==context.environmentDigest||intent.resourceId!==expectedDescriptor.resourceId||intent.ownerMarker!==expectedDescriptor.ownerMarker||intent.observationDigest!==null||intent.retentionExpiresAt!==null||!Array.isArray(intent.providerResourceIds)||intent.providerResourceIds.length!==0)return blocked('INTENT_INVALID_TRANSITION');
    const reconciled=await reconcilePrimaryExecutionRunnerObservation({context,store,lease,capability,intent,clock});
    if(reconciled.status!=='PASS')return reconciled;
    const inner=reconciled.value.intent;
    const executionId=extractProviderExecutionId(observation);
    if(executionId===null||inner.providerResourceIds.includes(executionId))return blockedWithState('INTENT_INVALID_TRANSITION',reconciled.value.lease,reconciled.value.capability);
    const next=freeze({...inner,providerResourceIds:[...inner.providerResourceIds,executionId].sort(),intentVersion:inner.intentVersion+1,updatedAt:iso(clock)});
    const committed=await commitIntentSnapshot({context,store,lease:reconciled.value.lease,capability:reconciled.value.capability,clock,snapshot:next});
    if(committed.status!=='PASS')return committed;
    const exactObservation=plainExact(observation,['executionId','transportStatus','status','responseStatusCode','outputDigest']);
    if(!exactObservation||observation.transportStatus!==201||observation.status!=='completed'||observation.responseStatusCode!==200||typeof observation.outputDigest!=='string'||!DIGEST.test(observation.outputDigest)||observation.outputDigest!==expectedWorkerOutputDigest(context,intent))return blockedWithState('INTENT_INVALID_TRANSITION',committed.value.lease,committed.value.capability);
    return pass(freeze({intent:next,lease:committed.value.lease,capability:committed.value.capability,stateDigest:sha256Bytes(encoder.encode(canonicalJson(next)))}));
  }catch{return blocked('INTENT_WRITE_BLOCKED');}
}

async function markAbsent({context,store,lease,capability,intent,clock}){const next=snapshot({context,descriptor:descriptorFrom(intent),state:'absent',version:intent.intentVersion+1,createdAt:intent.createdAt,updatedAt:iso(clock)});const r=await commitIntentSnapshot({context,store,lease,capability,clock,snapshot:next});return r.status==='PASS'?pass(freeze({intent:next,lease:r.value.lease,capability:r.value.capability})):r;}

export async function cleanupRun({context,store,provider,lease,capability,intents,clock}) {
  if (!isAuthenticTestEnvironmentContext(context) || !Array.isArray(intents)
      || capability === null
      || typeof provider?.readExact !== 'function' || typeof provider?.deleteExact !== 'function') return blocked('CLEANUP_AMBIGUOUS');
  let currentLease=lease,currentCap=capability; const result=[...intents];
  const persistDebt=async(code)=>{const debt=await markCleanupDebt({context,store,lease:currentLease,capability:currentCap,clock});return debt.status==='PASS'?blocked(code):debt;};
  try {
    const ordered=result.map((intent,index)=>({intent,index}))
      .filter(({intent})=>intent.lifecycleClass!=='provider-retained-observation'&&intent.state!=='absent')
      .sort((a,b)=>b.intent.dependencyOrder-a.intent.dependencyOrder||(a.intent.intentId<b.intent.intentId?-1:a.intent.intentId>b.intent.intentId?1:0));
    for (const {intent,index} of ordered) {
      const read=await provider.readExact(intent);
      if (read?.status!==404) {
        if (read?.status!==200||read.ownerMarker!==intent.ownerMarker||read.environmentDigest!==context.environmentDigest)
          return persistDebt(read?.status===200?'OWNERSHIP_MISMATCH':'CLEANUP_AMBIGUOUS');
        const deleted=await provider.deleteExact(intent);
        if (deleted?.status!==204&&deleted?.status!==404) return persistDebt('CLEANUP_AMBIGUOUS');
        if ((await provider.readExact(intent))?.status!==404) return persistDebt('CLEANUP_AMBIGUOUS');
      }
      const absent=await markAbsent({context,store,lease:currentLease,capability:currentCap,intent,clock});
      if (absent.status!=='PASS') return persistDebt('CLEANUP_AMBIGUOUS');
      result[index]=absent.value.intent;currentLease=absent.value.lease;currentCap=absent.value.capability;
    }
    return pass(freeze({intents:result,lease:currentLease,capability:currentCap}));
  } catch { return persistDebt('CLEANUP_AMBIGUOUS'); }
}

export async function verifyRunAbsent({context,provider,intents}){try{if(!isAuthenticTestEnvironmentContext(context)||!Array.isArray(intents))return blocked('CLEANUP_AMBIGUOUS');for(const intent of intents){if(intent.lifecycleClass==='provider-retained-observation')continue;if(intent.state!=='absent')return blocked('CLEANUP_AMBIGUOUS');if(typeof provider?.readExact==='function'){const r=await provider.readExact(intent);if(r?.status!==404)return blocked('CLEANUP_AMBIGUOUS');}}return pass(freeze({absenceProven:true}));}catch{return blocked('CLEANUP_AMBIGUOUS');}}
