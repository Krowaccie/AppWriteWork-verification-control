import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { readFile as READ_FILE } from 'node:fs/promises';
import { URL as NodeURL, fileURLToPath } from 'node:url';
import { env as PROCESS_ENV } from 'node:process';
import { TextDecoder } from 'node:util';
import {
  isAsyncFunction,
  isGeneratorFunction,
  isPromise,
  isProxy,
} from 'node:util/types';
import { runInNewContext } from 'node:vm';

const CLEAN_PRIMORDIALS = runInNewContext(`
(() => {
  const record = Object.create(null);
  Object.defineProperties(record, {
    arrayIsArray: { value: Array.isArray, enumerable: true },
    functionToString: { value: Function.prototype.toString, enumerable: true },
    jsonParse: { value: JSON.parse, enumerable: true },
    jsonStringify: { value: JSON.stringify, enumerable: true },
    numberIsSafeInteger: { value: Number.isSafeInteger, enumerable: true },
    objectCreate: { value: Object.create, enumerable: true },
    objectDefineProperty: { value: Object.defineProperty, enumerable: true },
    objectDefineProperties: { value: Object.defineProperties, enumerable: true },
    objectFreeze: { value: Object.freeze, enumerable: true },
    objectGetOwnPropertyDescriptor: {
      value: Object.getOwnPropertyDescriptor,
      enumerable: true,
    },
    objectGetPrototypeOf: { value: Object.getPrototypeOf, enumerable: true },
    objectHasOwn: { value: Object.hasOwn, enumerable: true },
    objectIs: { value: Object.is, enumerable: true },
    objectIsFrozen: { value: Object.isFrozen, enumerable: true },
    objectKeys: { value: Object.keys, enumerable: true },
    reflectApply: { value: Reflect.apply, enumerable: true },
    reflectDeleteProperty: { value: Reflect.deleteProperty, enumerable: true },
    reflectHas: { value: Reflect.has, enumerable: true },
    reflectOwnKeys: { value: Reflect.ownKeys, enumerable: true },
    stringIndexOf: { value: String.prototype.indexOf, enumerable: true },
    typedArrayByteLength: {
      value: Object.getOwnPropertyDescriptor(
        Object.getPrototypeOf(Uint8Array.prototype),
        'byteLength',
      ).get,
      enumerable: true,
    },
    uint8Array: { value: Uint8Array, enumerable: true },
    uint8ArrayIncludes: {
      value: Uint8Array.prototype.includes,
      enumerable: true,
    },
    uint8ArraySet: { value: Uint8Array.prototype.set, enumerable: true },
    uint8ArraySubarray: {
      value: Uint8Array.prototype.subarray,
      enumerable: true,
    },
    weakMap: { value: WeakMap, enumerable: true },
    weakMapSet: { value: WeakMap.prototype.set, enumerable: true },
  });
  return Object.freeze(record);
})()
`);

const ARRAY_IS_ARRAY = CLEAN_PRIMORDIALS.arrayIsArray;
const FUNCTION_TO_STRING = CLEAN_PRIMORDIALS.functionToString;
const JSON_PARSE = CLEAN_PRIMORDIALS.jsonParse;
const JSON_STRINGIFY = CLEAN_PRIMORDIALS.jsonStringify;
const NUMBER_IS_SAFE_INTEGER = CLEAN_PRIMORDIALS.numberIsSafeInteger;
const OBJECT_CREATE = CLEAN_PRIMORDIALS.objectCreate;
const OBJECT_DEFINE_PROPERTY = CLEAN_PRIMORDIALS.objectDefineProperty;
const OBJECT_DEFINE_PROPERTIES = CLEAN_PRIMORDIALS.objectDefineProperties;
const OBJECT_FREEZE = CLEAN_PRIMORDIALS.objectFreeze;
const OBJECT_GET_OWN_PROPERTY_DESCRIPTOR =
  CLEAN_PRIMORDIALS.objectGetOwnPropertyDescriptor;
const OBJECT_GET_PROTOTYPE_OF = CLEAN_PRIMORDIALS.objectGetPrototypeOf;
const OBJECT_HAS_OWN = CLEAN_PRIMORDIALS.objectHasOwn;
const OBJECT_IS = CLEAN_PRIMORDIALS.objectIs;
const OBJECT_IS_FROZEN = CLEAN_PRIMORDIALS.objectIsFrozen;
const OBJECT_KEYS = CLEAN_PRIMORDIALS.objectKeys;
const REFLECT_APPLY = CLEAN_PRIMORDIALS.reflectApply;
const REFLECT_DELETE_PROPERTY = CLEAN_PRIMORDIALS.reflectDeleteProperty;
const REFLECT_HAS = CLEAN_PRIMORDIALS.reflectHas;
const REFLECT_OWN_KEYS = CLEAN_PRIMORDIALS.reflectOwnKeys;
const STRING_INDEX_OF = CLEAN_PRIMORDIALS.stringIndexOf;
const TYPED_ARRAY_BYTE_LENGTH = CLEAN_PRIMORDIALS.typedArrayByteLength;
const UINT8_ARRAY = CLEAN_PRIMORDIALS.uint8Array;
const UINT8_ARRAY_INCLUDES = CLEAN_PRIMORDIALS.uint8ArrayIncludes;
const UINT8_ARRAY_SET = CLEAN_PRIMORDIALS.uint8ArraySet;
const UINT8_ARRAY_SUBARRAY = CLEAN_PRIMORDIALS.uint8ArraySubarray;
const WEAK_MAP = CLEAN_PRIMORDIALS.weakMap;
const WEAK_MAP_SET = CLEAN_PRIMORDIALS.weakMapSet;

function exactIntrinsicFunctionDescriptor(descriptor, expectedValue) {
  return descriptor !== undefined
    && REFLECT_HAS(descriptor, 'value') === true
    && descriptor.value === expectedValue
    && descriptor.enumerable === false
    && descriptor.configurable === true
    && descriptor.writable === false;
}

function captureDataIntrinsic(
  owner,
  key,
  expectedEnumerable,
  expectedName,
  expectedLength,
) {
  const descriptor = REFLECT_APPLY(
    OBJECT_GET_OWN_PROPERTY_DESCRIPTOR,
    undefined,
    [owner, key],
  );
  if (
    descriptor === undefined
    || REFLECT_HAS(descriptor, 'value') !== true
    || typeof descriptor.value !== 'function'
    || isProxy(descriptor.value)
    || descriptor.enumerable !== expectedEnumerable
    || descriptor.configurable !== true
    || descriptor.writable !== true
  ) throw new TypeError(`trusted intrinsic capture failed: ${key}`);
  const nameDescriptor = REFLECT_APPLY(
    OBJECT_GET_OWN_PROPERTY_DESCRIPTOR,
    undefined,
    [descriptor.value, 'name'],
  );
  const lengthDescriptor = REFLECT_APPLY(
    OBJECT_GET_OWN_PROPERTY_DESCRIPTOR,
    undefined,
    [descriptor.value, 'length'],
  );
  if (
    !exactIntrinsicFunctionDescriptor(nameDescriptor, expectedName)
    || !exactIntrinsicFunctionDescriptor(lengthDescriptor, expectedLength)
  ) throw new TypeError(`trusted intrinsic capture failed: ${key}`);
  return descriptor.value;
}

const LOCAL_OBJECT = captureDataIntrinsic(globalThis, 'Object', false, 'Object', 1);
const localObjectPrototypeDescriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
  LOCAL_OBJECT,
  'prototype',
);
if (
  localObjectPrototypeDescriptor === undefined
  || REFLECT_HAS(localObjectPrototypeDescriptor, 'value') !== true
  || localObjectPrototypeDescriptor.enumerable !== false
  || localObjectPrototypeDescriptor.configurable !== false
  || localObjectPrototypeDescriptor.writable !== false
  || localObjectPrototypeDescriptor.value === null
  || typeof localObjectPrototypeDescriptor.value !== 'object'
  || OBJECT_GET_PROTOTYPE_OF(localObjectPrototypeDescriptor.value) !== null
) throw new TypeError('trusted intrinsic capture failed: Object.prototype');
const OBJECT_PROTOTYPE = localObjectPrototypeDescriptor.value;

const LOCAL_PROMISE = captureDataIntrinsic(globalThis, 'Promise', false, 'Promise', 1);
const localPromisePrototypeDescriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
  LOCAL_PROMISE,
  'prototype',
);
if (
  localPromisePrototypeDescriptor === undefined
  || REFLECT_HAS(localPromisePrototypeDescriptor, 'value') !== true
  || localPromisePrototypeDescriptor.enumerable !== false
  || localPromisePrototypeDescriptor.configurable !== false
  || localPromisePrototypeDescriptor.writable !== false
  || localPromisePrototypeDescriptor.value === null
  || typeof localPromisePrototypeDescriptor.value !== 'object'
) throw new TypeError('trusted intrinsic capture failed: Promise.prototype');
const PROMISE_PROTOTYPE = localPromisePrototypeDescriptor.value;

function exactLocalPromise(value) {
  try {
    return isPromise(value)
      && !isProxy(value)
      && OBJECT_IS(OBJECT_GET_PROTOTYPE_OF(value), PROMISE_PROTOTYPE);
  } catch {
    return false;
  }
}

const BUFFER_FROM_INTRINSIC = captureDataIntrinsic(Buffer, 'from', true, 'from', 3);
const BUFFER_FROM = (...args) => REFLECT_APPLY(BUFFER_FROM_INTRINSIC, Buffer, args);
const BUFFER_TO_STRING = captureDataIntrinsic(
  Buffer.prototype,
  'toString',
  true,
  'toString',
  3,
);
const TEXT_DECODER_DECODE = captureDataIntrinsic(
  TextDecoder.prototype,
  'decode',
  true,
  'decode',
  0,
);

{
  const sentinel = OBJECT_CREATE(null);
  const frozen = REFLECT_APPLY(OBJECT_FREEZE, undefined, [sentinel]);
  if (!OBJECT_IS(frozen, sentinel) || OBJECT_IS_FROZEN(sentinel) !== true) {
    throw new TypeError('trusted immutable reflection root failed');
  }
}


export const TEST_CLOUD_PROVIDER_CONTRACT_VERSION =
  'test-cloud.provider-contract.v1';
const BOOTSTRAP_HUB_PROPERTY = '__APPWRITEWORK_TEST_CLOUD_BOOTSTRAP_HUB_V1__';
const TEST_CLOUD_PROVIDER_CONTRACT_URL = import.meta.url;
const TEST_CLOUD_PROVIDER_CONTRACT_DATA_URL = import.meta.resolve('../../src/functions/verification-runner-py/provider-contract/test-cloud.provider-contract.v1.json');
const TEST_CLOUD_PROVIDER_CONTRACT_DATA_PATH = fileURLToPath(TEST_CLOUD_PROVIDER_CONTRACT_DATA_URL);

const TEST_CLOUD_ENVIRONMENT_URL = import.meta.resolve('./test-cloud-environment.mjs');

function hasModuleUrlDelimiter(value) {
  return typeof value !== 'string'
    || REFLECT_APPLY(STRING_INDEX_OF, value, ['?']) !== -1
    || REFLECT_APPLY(STRING_INDEX_OF, value, ['#']) !== -1;
}

function assertFixedModuleUrl(value) {
  if (hasModuleUrlDelimiter(value)) {
    throw new TypeError('noncanonical fixed provider module URL');
  }
}

if (hasModuleUrlDelimiter(TEST_CLOUD_PROVIDER_CONTRACT_URL)) {
  throw new TypeError('noncanonical provider-contract module URL');
}

function resolveProviderSiblingModuleUrl(specifier) {
  return new NodeURL(specifier, TEST_CLOUD_PROVIDER_CONTRACT_URL).href;
}

const TEST_CLOUD_PROVIDER_CONTROL_IMPLEMENTATION_URL =
  import.meta.resolve('./test-cloud-provider-control-store.mjs');
const TEST_CLOUD_PROVIDER_CONTROL_URL =
  resolveProviderSiblingModuleUrl('./test-cloud-provider-control-runtime.mjs');
const TEST_CLOUD_CONTROL_STORE_URL =
  resolveProviderSiblingModuleUrl('./test-cloud-control-runtime.mjs');
const TEST_CLOUD_FIXTURES_URL =
  import.meta.resolve('./test-cloud-fixtures.mjs');
const TEST_CLOUD_BROWSER_ROUTE_ADAPTER_URL = import.meta.resolve('../../packages/verification-controller/src/test-cloud-browser-route-adapter.mjs');
const TEST_CLOUD_BROWSER_ARTIFACT_SET_URL = import.meta.resolve('../../packages/verification-controller/src/test-cloud-browser-artifact-set.mjs');
const TEST_CLOUD_FIXTURE_CLOCK_URL = import.meta.resolve('../../packages/verification-controller/src/test-cloud-fixture-clock.mjs');
const TEST_CLOUD_IDENTITY_BINDINGS_URL =
  import.meta.resolve('./test-cloud-identity-bindings.mjs');
const TEST_CLOUD_APPWRITE_URL =
  resolveProviderSiblingModuleUrl('./test-cloud-appwrite-runtime.mjs');

assertFixedModuleUrl(TEST_CLOUD_PROVIDER_CONTROL_IMPLEMENTATION_URL);
assertFixedModuleUrl(TEST_CLOUD_PROVIDER_CONTROL_URL);
assertFixedModuleUrl(TEST_CLOUD_CONTROL_STORE_URL);
assertFixedModuleUrl(TEST_CLOUD_FIXTURES_URL);
assertFixedModuleUrl(TEST_CLOUD_BROWSER_ROUTE_ADAPTER_URL);
assertFixedModuleUrl(TEST_CLOUD_BROWSER_ARTIFACT_SET_URL);
assertFixedModuleUrl(TEST_CLOUD_FIXTURE_CLOCK_URL);
assertFixedModuleUrl(TEST_CLOUD_IDENTITY_BINDINGS_URL);
assertFixedModuleUrl(TEST_CLOUD_APPWRITE_URL);
let browserRouteAdapterNamespacePromise;
let browserArtifactSetNamespacePromise;
let identityBindingsNamespacePromise;
let appwriteNamespacePromise;
let providerControlNamespacePromise;
let controlStoreNamespacePromise;
let fixturesNamespacePromise;
let fixtureClockNamespacePromise;
let canonicalIdentityBindingsNamespace;
let canonicalAppwriteNamespace;
let armedIdentityRegistrarCall;
let runnerVariableAuthorityRegistered = false;

function loadTestCloudBrowserRouteAdapterNamespace() {
  if (browserRouteAdapterNamespacePromise === undefined) {
    browserRouteAdapterNamespacePromise = importValidatedNamespace(
      TEST_CLOUD_BROWSER_ROUTE_ADAPTER_URL,
      (namespace) => validateExactModuleNamespace(
        namespace,
        BROWSER_ROUTE_NAMESPACE_EXPORTS,
        BROWSER_ROUTE_NAMESPACE_FUNCTIONS,
      ),
    );
  }
  return browserRouteAdapterNamespacePromise;
}

function loadTestCloudBrowserArtifactSetNamespace() {
  if (browserArtifactSetNamespacePromise === undefined) {
    browserArtifactSetNamespacePromise = importValidatedNamespace(
      TEST_CLOUD_BROWSER_ARTIFACT_SET_URL,
      (namespace) => validateExactModuleNamespace(
        namespace,
        BROWSER_ARTIFACT_NAMESPACE_EXPORTS,
        BROWSER_ARTIFACT_NAMESPACE_FUNCTIONS,
      ),
    );
  }
  return browserArtifactSetNamespacePromise;
}

const FUTURE_HUB_KEYS = OBJECT_FREEZE([
  'bridgeReceiver',
  'registerProviderControlImplementation',
  'registerIdentityAuthorityBridge',
  'registerInitialProviderPrefixAuthenticator',
  'registerSessionLineageAuthenticator',
  'registerMutationReconciliationAuthenticator',
  'registerExpectedStateConstructor',
  'registerProviderMutationRouteProducer',
  'registerTimestampBindingTransferReceiver',
  'registerBrowserRouteAdapterImplementation',
  'registerBrowserScenarioAutosaveCompletionReceiver',
  'registerBrowserArtifactSetSetupBridge',
  'registerExpectedStateResultConsumer',
  'registerClockReconciliationAggregateReceiver',
  'deliverTimestampBindingResult',
  'deliverMutationReconciliationQualification',
  'deliverBrowserScenarioAutosaveCompletion',
  'authenticateProviderQualification',
  'authenticateBrowserScenarioQualification',
  'readFixtureClockPolicy',
  'readBrowserRequestPolicy',
  'prepareShareValuesTransition',
  'abortShareValuesTransition',
  'commitShareValuesTransition',
  'finalizeShareValuesTransition',
  'readAuthenticatedShareBindingDigests',
  'readAuthenticatedBrowserIdentityEmail',
  'authenticateInitialProviderPrefix',
  'ownerAuthenticator',
  'authenticateShareIdentityFinalState',
  'authenticateSessionLineage',
  'authenticateMutationReconciliation',
  'constructExpectedStateForProviderMutation',
  'captureProviderMutationRoute',
  'consumeExpectedStateResult',
  'browserFacade',
  'browserScenarioQualification',
]);
const FUTURE_REGISTRATION_SLOT_NAMES = OBJECT_FREEZE([
  'registerProviderControlImplementation',
  'registerIdentityAuthorityBridge',
  'registerInitialProviderPrefixAuthenticator',
  'registerSessionLineageAuthenticator',
  'registerMutationReconciliationAuthenticator',
  'registerExpectedStateConstructor',
  'registerProviderMutationRouteProducer',
  'registerTimestampBindingTransferReceiver',
  'registerBrowserRouteAdapterImplementation',
  'registerBrowserScenarioAutosaveCompletionReceiver',
  'registerBrowserArtifactSetSetupBridge',
  'registerExpectedStateResultConsumer',
  'registerClockReconciliationAggregateReceiver',
]);
const ENVELOPE_KEYS = OBJECT_FREEZE(['receiver', 'implementation', 'moduleUrl']);
const PROVIDER_CONTROL_IMPLEMENTATION_KEYS = OBJECT_FREEZE([
  'receiver',
  'installProviderControlStore',
  'prepareShareValuesTransition',
  'abortShareValuesTransition',
  'commitShareValuesTransition',
  'finalizeShareValuesTransition',
  'issueProviderMutation',
  'reconcileProviderMutation',
  'createShareBaselineProof',
  'issueShareCreate',
  'reconcileShareCreate',
]);
const IDENTITY_AUTHORITY_BRIDGE_KEYS = OBJECT_FREEZE([
  'receiver',
  'ownerAuthenticator',
  'authenticateShareIdentityFinalState',
  'readAuthenticatedShareBindingDigests',
  'readAuthenticatedBrowserIdentityEmail',
  'authenticateBrowserArtifactIdentityQualification',
]);
const BROWSER_ROUTE_IMPLEMENTATION_KEYS = OBJECT_FREEZE([
  'receiver',
  'implementation',
  'moduleUrl',
  'artifactMemberReader',
]);
const BROWSER_ROUTE_METHOD_KEYS = OBJECT_FREEZE([
  'receiver',
  'performOwnerLogin',
  'performProjectCreateAndGraphEditPrefix',
  'performEditorShare',
  'performViewerShare',
]);
const BROWSER_ARTIFACT_SETUP_KEYS = OBJECT_FREEZE([
  'receiver',
  'beginBrowserArtifactSetSetupBinding',
  'commitBrowserArtifactSetSetupBinding',
  'abortBrowserArtifactSetSetupBinding',
]);
const IDENTITY_NAMESPACE_EXPORTS = OBJECT_FREEZE([
  'bindQualifiedShareIdentityValues',
  'createShareIdentityBindingHandoff',
  'isQualifiedTestCloudIdentityBindings',
  'loadQualifiedTestCloudIdentityBindings',
  'readAuthenticatedShareBindingDigests',
  'registerTestCloudIdentityBootstrap',
  'validateTestCloudIdentityBindings',
]);
const APPWRITE_NAMESPACE_EXPORTS = OBJECT_FREEZE([
  'createTestCloudClients',
  'createTestCloudRunnerVariableReadbackOperator',
  'isAuthenticTestCloudControlClient',
  'isAuthenticTestCloudOperatorClient',
  'isAuthenticTestCloudRunnerVariableReadbackResult',
  'qualifyTestCloudRunnerVariableReadbackRequest',
  'validateTestCloudRunnerVariableObservation',
]);
const APPWRITE_NAMESPACE_FUNCTIONS = OBJECT_FREEZE([
  OBJECT_FREEZE([1, 'sync']),
  OBJECT_FREEZE([1, 'sync']),
  OBJECT_FREEZE([2, 'sync']),
  OBJECT_FREEZE([2, 'sync']),
  OBJECT_FREEZE([2, 'sync']),
  OBJECT_FREEZE([1, 'sync']),
  OBJECT_FREEZE([1, 'sync']),
]);
const APPWRITE_RUNNER_VARIABLE_REGISTRAR_PROPERTY =
  '__registerTestCloudRunnerVariableAuthorityV1__';
const APPWRITE_RUNNER_VARIABLE_REGISTRATION_KEYS = OBJECT_FREEZE([
  'receiver',
  'authenticateRunnerVariableReadbackRequestEvidence',
  'moduleUrl',
]);
const PROVIDER_CONTROL_NAMESPACE_EXPORTS = OBJECT_FREEZE([
  'createProviderControlStore',
  'registerTestCloudProviderControlBootstrap',
]);
const CONTROL_STORE_NAMESPACE_EXPORTS = OBJECT_FREEZE([
  'GENESIS_LEDGER_DIGEST',
  'PRIMARY_EXECUTION_RETENTION_MAX_SECONDS',
  'acquireLease',
  'closeLease',
  'commitIntentSnapshot',
  'consumeRunnerRequest',
  'createInMemoryControlStore',
  'createRunnerRequest',
  'createTestCloudPreflightHandoff',
  'markCleanupDebt',
  'reconcilePrimaryExecutionRunnerObservation',
  'reconstructAuthoritativeIntents',
  'renewLease',
]);
const FIXTURES_NAMESPACE_EXPORTS = OBJECT_FREEZE([
  'cleanupRun',
  'markCreated',
  'markPrimaryExecutionObserved',
  'planCreate',
  'registerTestCloudFixturesBootstrap',
  'verifyRunAbsent',
]);
const BROWSER_ROUTE_NAMESPACE_EXPORTS = OBJECT_FREEZE([
  'createTestCloudBrowserFacade',
  'registerTestCloudBrowserRouteAdapterBootstrap',
]);
const BROWSER_ARTIFACT_NAMESPACE_EXPORTS = OBJECT_FREEZE([
  'armQualifiedTestCloudBrowserArtifactMembers',
  'closeQualifiedTestCloudBrowserArtifactMembers',
  'consumeQualifiedTestCloudBrowserArtifactSet',
  'projectTestCloudBrowserArtifactPolicyRows',
  'qualifyTestCloudBrowserArtifactSet',
  'readQualifiedTestCloudBrowserArtifactMember',
  'registerTestCloudBrowserArtifactSetBootstrap',
]);
const FIXTURE_CLOCK_NAMESPACE_EXPORTS = OBJECT_FREEZE([
  'advanceTestCloudFixtureClock',
  'authenticateTestCloudFixtureClock',
  'installTestCloudFixtureClock',
  'prepareTestCloudFixtureClock',
  'readTestCloudFixtureExpectedState',
  'registerTestCloudFixtureClockBootstrap',
  'sealTestCloudFixtureClock',
]);
const PROVIDER_CONTROL_NAMESPACE_FUNCTIONS = OBJECT_FREEZE([
  OBJECT_FREEZE([0, 'sync']),
  OBJECT_FREEZE([0, 'sync']),
]);
const FIXTURES_NAMESPACE_FUNCTIONS = OBJECT_FREEZE([
  OBJECT_FREEZE([1, 'async']),
  OBJECT_FREEZE([1, 'async']),
  OBJECT_FREEZE([1, 'async']),
  OBJECT_FREEZE([1, 'async']),
  OBJECT_FREEZE([0, 'sync']),
  OBJECT_FREEZE([1, 'async']),
]);
const BROWSER_ROUTE_NAMESPACE_FUNCTIONS = OBJECT_FREEZE([
  OBJECT_FREEZE([0, 'async']),
  OBJECT_FREEZE([0, 'sync']),
]);
const BROWSER_ARTIFACT_NAMESPACE_FUNCTIONS = OBJECT_FREEZE([
  OBJECT_FREEZE([1, 'sync']),
  OBJECT_FREEZE([1, 'async']),
  OBJECT_FREEZE([1, 'sync']),
  OBJECT_FREEZE([1, 'async']),
  OBJECT_FREEZE([1, 'async']),
  OBJECT_FREEZE([1, 'sync']),
  OBJECT_FREEZE([0, 'sync']),
]);
const FIXTURE_CLOCK_NAMESPACE_FUNCTIONS = OBJECT_FREEZE([
  OBJECT_FREEZE([1, 'async']),
  OBJECT_FREEZE([1, 'async']),
  OBJECT_FREEZE([1, 'async']),
  OBJECT_FREEZE([1, 'sync']),
  OBJECT_FREEZE([1, 'sync']),
  OBJECT_FREEZE([0, 'sync']),
  OBJECT_FREEZE([1, 'async']),
]);
const FACTORY_READY_KEYS = OBJECT_FREEZE([
  'browserFacade',
  'browserScenarioQualification',
  'finalizeBootstrap',
]);
const BROWSER_FACADE_KEYS = OBJECT_FREEZE([
  'installPausedBeforeNavigation',
  'proveOwnerUiReady',
  'readOwnerAccount',
  'runForExactly800Milliseconds',
  'sealClock',
]);
const CLOCK_OPERATIONS_KEYS = OBJECT_FREEZE([
  'receiver',
  'installTestCloudFixtureClock',
  'authenticateTestCloudFixtureClock',
  'advanceTestCloudFixtureClock',
  'sealTestCloudFixtureClock',
]);
const RUNTIME_PASS_VALUE_KEYS = OBJECT_FREEZE([
  'runtimeQualification',
  'browserScenarioQualification',
]);
const AUTHENTICATE_RUNTIME_ARGUMENT_KEYS = OBJECT_FREEZE([
  'runtimeQualification',
]);
const INSTALL_PROVIDER_CONTROL_STORE_ARGUMENT_KEYS = OBJECT_FREEZE([
  'runtimeQualification',
  'context',
  'providerContractQualification',
  'providerControlStore',
]);
const CAPTURE_PROVIDER_MUTATION_ROUTE_ARGUMENT_KEYS = OBJECT_FREEZE([
  'runtimeQualification',
  'context',
  'sessionIntentQualification',
  'mutationOrdinal',
]);
const CAPTURE_PROVIDER_MUTATION_ROUTE_INTERNAL_KEYS = OBJECT_FREEZE([
  'runtimeQualification',
  'context',
  'sessionIntentQualification',
  'mutationOrdinal',
  'requestAuthority',
]);
const RECONCILE_PROVIDER_MUTATION_ARGUMENT_KEYS = OBJECT_FREEZE([
  'runtimeQualification',
  'providerMutationIssue',
]);
const CREATE_SHARE_BASELINE_ARGUMENT_KEYS = OBJECT_FREEZE([
  'runtimeQualification',
  'context',
  'sessionIntentQualification',
  'providerQualification',
  'ownerSlot',
]);
const ISSUE_SHARE_CREATE_ARGUMENT_KEYS = OBJECT_FREEZE([
  'runtimeQualification',
  'context',
  'sessionIntentQualification',
  'providerQualification',
  'baselineProof',
  'requestTuple',
]);
const RECONCILE_SHARE_CREATE_ARGUMENT_KEYS = OBJECT_FREEZE([
  'runtimeQualification',
  'shareIssue',
]);
const PERFORM_OWNER_LOGIN_ARGUMENT_KEYS = OBJECT_FREEZE([
  'runtimeQualification',
  'context',
  'browserScenarioQualification',
  'clock',
  'ownerLoginInput',
  'providerContractQualification',
  'identityBindingsQualification',
  'providerSetupReadbackQualification',
  'sessionIntentQualification',
]);
const PERFORM_PROJECT_PREFIX_ARGUMENT_KEYS = OBJECT_FREEZE([
  'runtimeQualification',
  'context',
  'browserScenarioQualification',
  'clock',
  'providerContractQualification',
  'sessionIntentQualification',
]);
const PERFORM_SHARE_ARGUMENT_KEYS = OBJECT_FREEZE([
  'runtimeQualification',
  'context',
  'browserScenarioQualification',
  'clock',
  'providerContractQualification',
  'identityBindingsQualification',
  'sessionIntentQualification',
]);
const OWNER_LOGIN_INPUT_KEYS = OBJECT_FREEZE(['password']);
const REQUEST_AUTHORITY_KEYS = OBJECT_FREEZE([
  'operationQualification',
  'requestTemplate',
  'requestTemplateDigest',
  'exactDeploymentOrigin',
  'logicalValueBindings',
]);
const REQUEST_TEMPLATE_KEYS = OBJECT_FREEZE([
  'schemaVersion',
  'mutationOrdinal',
  'method',
  'routeId',
  'pathTemplate',
  'pathBindings',
  'query',
  'bodyKind',
  'bodyTemplate',
  'bindingNames',
  'executionEnvelopeTemplate',
]);
const QUALIFIED_PROVIDER_REGISTRY_KEYS = OBJECT_FREEZE([
  'state',
  'runtimeQualification',
  'context',
  'sessionIntentQualification',
  'exactDeploymentOrigin',
  'operationProfiles',
  'logicalValueBindingGroups',
]);
const ROUTE_PROJECTION_KEYS = OBJECT_FREEZE([
  'method',
  'originBinding',
  'pathBinding',
  'queryBinding',
  'bodyBinding',
  'sourceBytesDigest',
  'generatedIdBindings',
]);
const ROUTE_CAPTURE_RESULT_KEYS = OBJECT_FREEZE([
  'observationQualification',
  'routeProjection',
]);
const EXPECTED_STATE_CONSTRUCTOR_ARGUMENT_KEYS = OBJECT_FREEZE([
  'runtimeQualification',
  'context',
  'sessionIntentQualification',
  'mutationOrdinal',
  'providerMutationProfile',
  'logicalValueBindings',
  'routeProjection',
]);
const EXPECTED_STATE_MAPPING_KEYS = OBJECT_FREEZE([
  'requestInstanceDigest',
  'expectedResultState',
  'expectedStateContractDigest',
]);
const ORIGIN_BINDING_KEYS = OBJECT_FREEZE(['originClass', 'originDigest']);
const PATH_BINDING_KEYS = OBJECT_FREEZE(['pathClass', 'pathDigest']);
const QUERY_BINDING_KEYS = OBJECT_FREEZE(['queryClass', 'queryDigest']);
const BODY_BINDING_KEYS = OBJECT_FREEZE([
  'semanticBodyDigest',
  'boundValuesDigest',
  'executionEnvelopeDigest',
]);
const GENERATED_ID_BINDING_KEYS = OBJECT_FREEZE(['bindingName', 'valueDigest']);
const PROVIDER_MUTATION_PROFILE_KEYS = OBJECT_FREEZE([
  'operation',
  'expectedStateContract',
  'expectedStateContractDigest',
  'fixtureSemanticLiterals',
  'environmentBindings',
  'providerIdentities',
  'ownerUserId',
  'priorExpectedStates',
  'sourceByteSizes',
  'timestampBindings',
]);
const CANONICAL_OPERATION_PROFILE_KEYS = OBJECT_FREEZE([
  'mutationOrdinal',
  'phase',
  'operation',
  'requestTemplate',
  'requestTemplateDigest',
  'expectedStateContract',
  'expectedStateContractDigest',
]);
const FIXTURE_SEMANTIC_LITERAL_KEYS = OBJECT_FREEZE([
  'literalName',
  'valueType',
  'value',
]);
const ENVIRONMENT_BINDING_KEYS = OBJECT_FREEZE([
  'environmentDigest',
  'providerContractDigest',
]);
const PROVIDER_IDENTITY_KEYS = OBJECT_FREEZE(['bindingName', 'value']);
const PRIOR_EXPECTED_STATE_KEYS = OBJECT_FREEZE([
  'mutationOrdinal',
  'expectedState',
]);
const SOURCE_BYTE_SIZE_KEYS = OBJECT_FREEZE(['bindingName', 'sizeBytes']);
const TIMESTAMP_BINDING_KEYS = OBJECT_FREEZE(['mutationOrdinal', 'timestamp']);
const LOGICAL_VALUE_BINDING_KEYS = OBJECT_FREEZE([
  'bindingName',
  'valueType',
  'value',
]);
const GENERIC_ISSUE_INTERNAL_ARGUMENT_KEYS = OBJECT_FREEZE([
  'runtimeQualification',
  'context',
  'sessionIntentQualification',
  'mutationOrdinal',
  'observationQualification',
  'routeProjection',
  'expectedStateMapping',
]);
const GENERIC_RECONCILE_INTERNAL_ARGUMENT_KEYS = OBJECT_FREEZE([
  'runtimeQualification',
  'providerMutationIssue',
  'observationQualification',
  'releaseDisposition',
]);
const SHARE_ISSUE_INTERNAL_ARGUMENT_KEYS = OBJECT_FREEZE([
  'runtimeQualification',
  'context',
  'sessionIntentQualification',
  'providerQualification',
  'baselineProof',
  'requestTuple',
  'observationQualification',
  'routeProjection',
]);
const SHARE_RECONCILE_INTERNAL_ARGUMENT_KEYS = OBJECT_FREEZE([
  'runtimeQualification',
  'shareIssue',
  'observationQualification',
  'releaseDisposition',
]);
const ROUTE_BIND_PROVIDER_ISSUE_ARGUMENT_KEYS = OBJECT_FREEZE([
  'operation',
  'runtimeQualification',
  'observationQualification',
  'providerMutationIssue',
]);
const ROUTE_CONSUME_PROVIDER_RELEASE_ARGUMENT_KEYS = OBJECT_FREEZE([
  'operation',
  'runtimeQualification',
  'providerMutationIssue',
]);
const ROUTE_BIND_SHARE_ISSUE_ARGUMENT_KEYS = OBJECT_FREEZE([
  'operation',
  'runtimeQualification',
  'observationQualification',
  'shareIssue',
]);
const ROUTE_CONSUME_SHARE_RELEASE_ARGUMENT_KEYS = OBJECT_FREEZE([
  'operation',
  'runtimeQualification',
  'shareIssue',
]);
const ROUTE_RELEASE_RESULT_KEYS = OBJECT_FREEZE([
  'observationQualification',
  'releaseDisposition',
]);
const ASYNC_FUNCTION_PROTOTYPE = OBJECT_GET_PROTOTYPE_OF(
  async function trustedAsyncFunction(_args) {},
);
const PROVIDER_CONTROL_METHOD_KINDS = OBJECT_FREEZE([
  'sync', 'async', 'sync', 'async', 'sync',
  'async', 'async', 'async', 'async', 'async',
]);
const IDENTITY_AUTHORITY_METHOD_KINDS = OBJECT_FREEZE([
  'sync',
  'sync',
  'sync',
  'sync',
  'sync',
]);
const BROWSER_ROUTE_METHOD_KINDS = OBJECT_FREEZE([
  'async',
  'async',
  'async',
  'async',
]);
const BROWSER_ARTIFACT_METHOD_KINDS = OBJECT_FREEZE([
  'sync',
  'sync',
  'sync',
]);


function createSlotProfile(kind, moduleUrl, receiverGroup) {
  return OBJECT_FREEZE({ kind, moduleUrl, receiverGroup });
}

const futureSlotProfiles = OBJECT_CREATE(null);
futureSlotProfiles.registerProviderControlImplementation = createSlotProfile(
  'provider-control-implementation',
  TEST_CLOUD_PROVIDER_CONTROL_IMPLEMENTATION_URL,
  'provider-control',
);
futureSlotProfiles.registerIdentityAuthorityBridge = createSlotProfile(
  'identity-authority',
  TEST_CLOUD_IDENTITY_BINDINGS_URL,
  'identity',
);
futureSlotProfiles.registerInitialProviderPrefixAuthenticator = createSlotProfile(
  'envelope',
  TEST_CLOUD_PROVIDER_CONTROL_IMPLEMENTATION_URL,
  'provider-control',
);
futureSlotProfiles.registerSessionLineageAuthenticator = createSlotProfile(
  'envelope',
  TEST_CLOUD_PROVIDER_CONTRACT_URL,
  'provider-bootstrap',
);
futureSlotProfiles.registerMutationReconciliationAuthenticator = createSlotProfile(
  'envelope',
  TEST_CLOUD_PROVIDER_CONTROL_IMPLEMENTATION_URL,
  'provider-control',
);
futureSlotProfiles.registerExpectedStateConstructor = createSlotProfile(
  'envelope',
  TEST_CLOUD_FIXTURES_URL,
  'fixtures',
);
futureSlotProfiles.registerProviderMutationRouteProducer = createSlotProfile(
  'envelope',
  TEST_CLOUD_BROWSER_ROUTE_ADAPTER_URL,
  'browser-route',
);
futureSlotProfiles.registerTimestampBindingTransferReceiver = createSlotProfile(
  'envelope',
  TEST_CLOUD_FIXTURES_URL,
  'fixtures',
);
futureSlotProfiles.registerBrowserRouteAdapterImplementation = createSlotProfile(
  'browser-route-implementation',
  TEST_CLOUD_BROWSER_ROUTE_ADAPTER_URL,
  'browser-route',
);
futureSlotProfiles.registerBrowserScenarioAutosaveCompletionReceiver = createSlotProfile(
  'envelope',
  TEST_CLOUD_BROWSER_ROUTE_ADAPTER_URL,
  'browser-route',
);
futureSlotProfiles.registerBrowserArtifactSetSetupBridge = createSlotProfile(
  'browser-artifact-setup',
  TEST_CLOUD_BROWSER_ARTIFACT_SET_URL,
  'browser-artifact',
);
futureSlotProfiles.registerExpectedStateResultConsumer = createSlotProfile(
  'envelope',
  TEST_CLOUD_FIXTURE_CLOCK_URL,
  'fixture-clock',
);
futureSlotProfiles.registerClockReconciliationAggregateReceiver = createSlotProfile(
  'envelope',
  TEST_CLOUD_FIXTURE_CLOCK_URL,
  'fixture-clock',
);
OBJECT_FREEZE(futureSlotProfiles);

function createRuntimeRecord(state, version, substep = undefined) {
  const record = OBJECT_CREATE(null);
  const descriptors = OBJECT_CREATE(null);
  descriptors.version = {
    value: version,
    enumerable: true,
    configurable: false,
    writable: false,
  };
  descriptors.state = {
    value: state,
    enumerable: true,
    configurable: false,
    writable: false,
  };
  if (substep !== undefined) {
    descriptors.substep = {
      value: substep,
      enumerable: true,
      configurable: false,
      writable: false,
    };
  }
  OBJECT_DEFINE_PROPERTIES(record, descriptors);
  return OBJECT_FREEZE(record);
}

let runtimeRecord = createRuntimeRecord('EMPTY', 0);
let activationState = 'NONE';
let activeRuntimeQualification;
let providerLoadRecord = OBJECT_FREEZE({ state: 'EMPTY', version: 0 });
let setupLoadRecord = OBJECT_FREEZE({ state: 'EMPTY', version: 0 });
const PROVIDER_QUALIFICATIONS = new WEAK_MAP();
const SETUP_QUALIFICATIONS = new WEAK_MAP();
const PROVIDER_TUPLES = new WEAK_MAP();
const SETUP_TUPLES = new WEAK_MAP();
let futureBootstrapHub;
let canonicalProviderControlNamespace;
let canonicalControlStoreNamespace;
let canonicalControlStoreExports;
let canonicalFixturesNamespace;
let canonicalBrowserRouteAdapterNamespace;
let canonicalBrowserArtifactSetNamespace;
let canonicalFixtureClockNamespace;
let futureBrowserArtifactMemberReader;
let currentQualifiedProviderRegistry;
const providerMutationCaptureEntries = [];
const OPERATION_QUALIFICATIONS = new WEAK_MAP();
const futureBridgeReceiver = OBJECT_FREEZE(OBJECT_CREATE(null));
const futureSessionLineageReceiver = OBJECT_FREEZE(OBJECT_CREATE(null));
const runnerVariableAuthorityReceiver = OBJECT_FREEZE(OBJECT_CREATE(null));
const futureRegistrationStates = OBJECT_CREATE(null);
const futureRegistrationValues = OBJECT_CREATE(null);
const futureReceiverGroups = OBJECT_CREATE(null);
const futureRegistrars = OBJECT_CREATE(null);
let futureIdentityAuthorityBridge;

function terminallyBlockRuntime() {
  const observed = runtimeRecord;
  if (observed.state === 'BLOCKED') return false;
  const successor = createRuntimeRecord('BLOCKED', observed.version + 1);
  if (OBJECT_IS(runtimeRecord, observed)) {
    activationState = 'BLOCKED';
    activeRuntimeQualification = undefined;
    activeBrowserScenarioQualification = undefined;
    currentQualifiedProviderRegistry = undefined;
    futureBrowserArtifactMemberReader = undefined;
    runtimeRecord = successor;
  }
  return false;
}

function advanceBootstrapSubstep(expectedRecord, expectedSubstep, nextSubstep) {
  if (
    !OBJECT_IS(runtimeRecord, expectedRecord)
    || expectedRecord.state !== 'BOOTSTRAPPING'
    || expectedRecord.substep !== expectedSubstep
  ) return false;
  const successor = createRuntimeRecord(
    'BOOTSTRAPPING',
    expectedRecord.version + 1,
    nextSubstep,
  );
  runtimeRecord = successor;
  return OBJECT_IS(runtimeRecord, successor) ? successor : false;
}

function exactOrderedDataRecord(value, expectedKeys) {
  if (
    value === null
    || typeof value !== 'object'
    || isProxy(value)
    || OBJECT_GET_PROTOTYPE_OF(value) !== null
    || OBJECT_IS_FROZEN(value) !== true
  ) return false;
  const ownKeys = REFLECT_OWN_KEYS(value);
  if (ownKeys.length !== expectedKeys.length) return false;
  for (let index = 0; index < expectedKeys.length; index += 1) {
    if (ownKeys[index] !== expectedKeys[index]) return false;
    const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(value, expectedKeys[index]);
    if (
      descriptor === undefined
      || REFLECT_HAS(descriptor, 'value') !== true
      || descriptor.enumerable !== true
      || descriptor.configurable !== false
      || descriptor.writable !== false
    ) return false;
  }
  return true;
}

function exactOrderedPublicDataRecord(value, expectedKeys) {
  if (
    value === null
    || typeof value !== 'object'
    || isProxy(value)
    || OBJECT_GET_PROTOTYPE_OF(value) !== OBJECT_PROTOTYPE
    || OBJECT_IS_FROZEN(value) !== true
  ) return false;
  const ownKeys = REFLECT_OWN_KEYS(value);
  if (ownKeys.length !== expectedKeys.length) return false;
  for (let index = 0; index < expectedKeys.length; index += 1) {
    if (ownKeys[index] !== expectedKeys[index]) return false;
    const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(value, expectedKeys[index]);
    if (
      descriptor === undefined
      || REFLECT_HAS(descriptor, 'value') !== true
      || descriptor.enumerable !== true
      || descriptor.configurable !== false
      || descriptor.writable !== false
    ) return false;
  }
  return true;
}

function exactDenseFrozenArray(value) {
  if (!ARRAY_IS_ARRAY(value) || isProxy(value) || OBJECT_IS_FROZEN(value) !== true) {
    return false;
  }
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(value, `${index}`);
    if (
      descriptor === undefined
      || REFLECT_HAS(descriptor, 'value') !== true
      || descriptor.enumerable !== true
      || descriptor.configurable !== false
      || descriptor.writable !== false
    ) return false;
  }
  return REFLECT_OWN_KEYS(value).length === value.length + 1;
}

function exactEmptyReceiver(value) {
  return value !== null
    && typeof value === 'object'
    && !isProxy(value)
    && OBJECT_GET_PROTOTYPE_OF(value) === null
    && OBJECT_IS_FROZEN(value) === true
    && REFLECT_OWN_KEYS(value).length === 0;
}

function exactFunction(value, expectedLength, expectedKind, expectedName) {
  if (
    typeof value !== 'function'
    || isProxy(value)
    || isGeneratorFunction(value)
  ) return false;
  const asyncFunction = isAsyncFunction(value);
  if (
    (expectedKind === 'async' && asyncFunction !== true)
    || (expectedKind === 'sync' && asyncFunction !== false)
  ) return false;
  let functionSource;
  try {
    functionSource = REFLECT_APPLY(FUNCTION_TO_STRING, value, []);
  } catch {
    return false;
  }
  if (
    typeof functionSource !== 'string'
    || (
      functionSource[0] === 'c'
      && functionSource[1] === 'l'
      && functionSource[2] === 'a'
      && functionSource[3] === 's'
      && functionSource[4] === 's'
    )
  ) return false;

  const lengthDescriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(value, 'length');
  const nameDescriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(value, 'name');
  if (
    lengthDescriptor === undefined
    || nameDescriptor === undefined
    || REFLECT_HAS(lengthDescriptor, 'value') !== true
    || REFLECT_HAS(nameDescriptor, 'value') !== true
    || lengthDescriptor.value !== expectedLength
    || typeof nameDescriptor.value !== 'string'
    || nameDescriptor.value.length === 0
    || lengthDescriptor.enumerable !== false
    || lengthDescriptor.configurable !== true
    || lengthDescriptor.writable !== false
    || nameDescriptor.enumerable !== false
    || nameDescriptor.configurable !== true
    || nameDescriptor.writable !== false
  ) return false;
  if (expectedName !== undefined && nameDescriptor.value !== expectedName) return false;
  if (
    nameDescriptor.value[0] === 'b'
    && nameDescriptor.value[1] === 'o'
    && nameDescriptor.value[2] === 'u'
    && nameDescriptor.value[3] === 'n'
    && nameDescriptor.value[4] === 'd'
    && nameDescriptor.value[5] === ' '
  ) return false;
  const prototypeDescriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(value, 'prototype');
  if (expectedKind === 'async') {
    return prototypeDescriptor === undefined
      && OBJECT_IS(OBJECT_GET_PROTOTYPE_OF(value), ASYNC_FUNCTION_PROTOTYPE);
  }
  return prototypeDescriptor !== undefined
    && REFLECT_HAS(prototypeDescriptor, 'value') === true
    && prototypeDescriptor.value !== null
    && typeof prototypeDescriptor.value === 'object'
    && prototypeDescriptor.enumerable === false
    && prototypeDescriptor.configurable === false
    && prototypeDescriptor.writable === true;
}


function exactMethodsRecord(value, expectedKeys, expectedKinds) {
  if (!exactOrderedDataRecord(value, expectedKeys)) return false;
  const receiver = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(value, 'receiver').value;
  if (!exactEmptyReceiver(receiver)) return false;
  for (let index = 1; index < expectedKeys.length; index += 1) {
    const key = expectedKeys[index];
    const method = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(value, key).value;
    if (!exactFunction(method, 1, expectedKinds[index - 1])) return false;
  }
  return true;
}

function exactEnvelope(registration, profile) {
  if (!exactOrderedDataRecord(registration, ENVELOPE_KEYS)) return false;
  const receiver = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(registration, 'receiver').value;
  const implementation = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
    registration,
    'implementation',
  ).value;
  const moduleUrl = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(registration, 'moduleUrl').value;
  return exactEmptyReceiver(receiver)
    && exactFunction(implementation, 1, 'sync')
    && typeof moduleUrl === 'string'
    && moduleUrl === profile.moduleUrl;
}

function exactProviderControlRegistration(registration, profile) {
  if (!exactOrderedDataRecord(registration, ENVELOPE_KEYS)) return false;
  const receiver = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(registration, 'receiver').value;
  const implementation = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
    registration,
    'implementation',
  ).value;
  const moduleUrl = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(registration, 'moduleUrl').value;
  if (
    !exactEmptyReceiver(receiver)
    || typeof moduleUrl !== 'string'
    || moduleUrl !== profile.moduleUrl
    || !exactMethodsRecord(
      implementation,
      PROVIDER_CONTROL_IMPLEMENTATION_KEYS,
      PROVIDER_CONTROL_METHOD_KINDS,
    )
  ) return false;
  return OBJECT_IS(
    receiver,
    OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(implementation, 'receiver').value,
  );
}

function exactBrowserRouteProducerRegistration(registration, profile) {
  if (!exactOrderedDataRecord(registration, BROWSER_ROUTE_IMPLEMENTATION_KEYS)) {
    return false;
  }
  const receiver = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(registration, 'receiver').value;
  const implementation = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
    registration,
    'implementation',
  ).value;
  const moduleUrl = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(registration, 'moduleUrl').value;
  const artifactMemberReader = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
    registration,
    'artifactMemberReader',
  ).value;
  return exactEmptyReceiver(receiver)
    && exactFunction(implementation, 1, 'sync')
    && typeof moduleUrl === 'string'
    && moduleUrl === profile.moduleUrl
    && exactFunction(
      artifactMemberReader,
      1,
      'sync',
      'readQualifiedTestCloudBrowserArtifactMember',
    )
    && !OBJECT_IS(artifactMemberReader, implementation);
}

function isExactIdentityAuthorityBridge(value) {
  return exactMethodsRecord(
    value,
    IDENTITY_AUTHORITY_BRIDGE_KEYS,
    IDENTITY_AUTHORITY_METHOD_KINDS,
  );
}

function isExactRegistrationForSlot(slotName, registration) {
  try {
    if (
      typeof slotName !== 'string'
      || !OBJECT_HAS_OWN(futureSlotProfiles, slotName)
    ) return false;
    const profile = futureSlotProfiles[slotName];
    if (slotName === 'registerProviderMutationRouteProducer') {
      return exactBrowserRouteProducerRegistration(registration, profile);
    }
    if (profile.kind === 'envelope') return exactEnvelope(registration, profile);
    if (profile.kind === 'provider-control-implementation') {
      return exactProviderControlRegistration(registration, profile);
    }
    if (profile.kind === 'identity-authority') {
      return isExactIdentityAuthorityBridge(registration);
    }
    if (profile.kind === 'browser-route-implementation') {
      return exactMethodsRecord(
        registration,
        BROWSER_ROUTE_METHOD_KEYS,
        BROWSER_ROUTE_METHOD_KINDS,
      );
    }
    if (profile.kind === 'browser-artifact-setup') {
      return exactMethodsRecord(
        registration,
        BROWSER_ARTIFACT_SETUP_KEYS,
        BROWSER_ARTIFACT_METHOD_KINDS,
      );
    }
    return false;
  } catch {
    return false;
  }
}

function registrationReceiver(registration) {
  return OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(registration, 'receiver').value;
}

function validateExactModuleNamespace(namespace, expectedExports, functionProfiles) {
  if (
    namespace === null
    || typeof namespace !== 'object'
    || isProxy(namespace)
    || OBJECT_GET_PROTOTYPE_OF(namespace) !== null
  ) return false;
  const ownKeys = REFLECT_OWN_KEYS(namespace);
  if (
    ownKeys.length !== expectedExports.length + 1
    || ownKeys[expectedExports.length] !== Symbol.toStringTag
  ) return false;
  for (let index = 0; index < expectedExports.length; index += 1) {
    const key = expectedExports[index];
    if (ownKeys[index] !== key) return false;
    const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(namespace, key);
    if (
      descriptor === undefined
      || REFLECT_HAS(descriptor, 'value') !== true
      || descriptor.enumerable !== true
      || descriptor.configurable !== false
      || descriptor.writable !== true
    ) return false;
    if (functionProfiles !== undefined) {
      const profile = functionProfiles[index];
      if (!exactFunction(descriptor.value, profile[0], profile[1], key)) return false;
    }
  }
  const tagDescriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(namespace, Symbol.toStringTag);
  return tagDescriptor !== undefined
    && REFLECT_HAS(tagDescriptor, 'value') === true
    && tagDescriptor.value === 'Module'
    && tagDescriptor.enumerable === false
    && tagDescriptor.configurable === false
    && tagDescriptor.writable === false;
}

function validateControlStoreNamespace(namespace) {
  if (!validateExactModuleNamespace(
    namespace,
    CONTROL_STORE_NAMESPACE_EXPORTS,
    undefined,
  )) return false;
  for (let index = 0; index < CONTROL_STORE_NAMESPACE_EXPORTS.length; index += 1) {
    const key = CONTROL_STORE_NAMESPACE_EXPORTS[index];
    const value = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(namespace, key).value;
    if (key === 'GENESIS_LEDGER_DIGEST') {
      if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(value)) return false;
    } else if (key === 'PRIMARY_EXECUTION_RETENTION_MAX_SECONDS') {
      if (!NUMBER_IS_SAFE_INTEGER(value) || value <= 0) return false;
    } else if (
      typeof value !== 'function'
      || isProxy(value)
      || isGeneratorFunction(value)
    ) return false;
  }
  return true;
}

function importValidatedNamespace(moduleUrl, validator) {
  const imported = import(moduleUrl);
  if (!exactLocalPromise(imported)) {
    terminallyBlockRuntime();
    throw new TypeError('invalid canonical namespace Promise');
  }
  return (async () => {
    const namespace = await imported;
    if (!validator(namespace)) {
      terminallyBlockRuntime();
      throw new TypeError('invalid canonical module namespace');
    }
    return namespace;
  })();
}

function loadTestCloudProviderControlNamespace() {
  if (providerControlNamespacePromise === undefined) {
    providerControlNamespacePromise = importValidatedNamespace(
      TEST_CLOUD_PROVIDER_CONTROL_URL,
      (namespace) => validateExactModuleNamespace(
        namespace,
        PROVIDER_CONTROL_NAMESPACE_EXPORTS,
        PROVIDER_CONTROL_NAMESPACE_FUNCTIONS,
      ),
    );
  }
  return providerControlNamespacePromise;
}

function loadTestCloudControlStoreNamespace() {
  if (controlStoreNamespacePromise === undefined) {
    controlStoreNamespacePromise = importValidatedNamespace(
      TEST_CLOUD_CONTROL_STORE_URL,
      validateControlStoreNamespace,
    );
  }
  return controlStoreNamespacePromise;
}

function loadTestCloudFixturesNamespace() {
  if (fixturesNamespacePromise === undefined) {
    fixturesNamespacePromise = importValidatedNamespace(
      TEST_CLOUD_FIXTURES_URL,
      (namespace) => validateExactModuleNamespace(
        namespace,
        FIXTURES_NAMESPACE_EXPORTS,
        FIXTURES_NAMESPACE_FUNCTIONS,
      ),
    );
  }
  return fixturesNamespacePromise;
}

function loadTestCloudFixtureClockNamespace() {
  if (fixtureClockNamespacePromise === undefined) {
    fixtureClockNamespacePromise = importValidatedNamespace(
      TEST_CLOUD_FIXTURE_CLOCK_URL,
      (namespace) => validateExactModuleNamespace(
        namespace,
        FIXTURE_CLOCK_NAMESPACE_EXPORTS,
        FIXTURE_CLOCK_NAMESPACE_FUNCTIONS,
      ),
    );
  }
  return fixtureClockNamespacePromise;
}

function validateIdentityBindingsNamespace(namespace) {
  if (
    namespace === null
    || typeof namespace !== 'object'
    || isProxy(namespace)
    || OBJECT_GET_PROTOTYPE_OF(namespace) !== null
  ) return false;
  const ownKeys = REFLECT_OWN_KEYS(namespace);
  if (
    ownKeys.length !== IDENTITY_NAMESPACE_EXPORTS.length + 1
    || ownKeys[IDENTITY_NAMESPACE_EXPORTS.length] !== Symbol.toStringTag
  ) return false;
  for (let index = 0; index < IDENTITY_NAMESPACE_EXPORTS.length; index += 1) {
    const key = IDENTITY_NAMESPACE_EXPORTS[index];
    if (ownKeys[index] !== key) return false;
    const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(namespace, key);
    const expectedAsync = key === 'bindQualifiedShareIdentityValues'
      || key === 'createShareIdentityBindingHandoff'
      || key === 'loadQualifiedTestCloudIdentityBindings';
    const expectedLength = key === 'registerTestCloudIdentityBootstrap' ? 0 : 1;
    if (
      descriptor === undefined
      || REFLECT_HAS(descriptor, 'value') !== true
      || descriptor.enumerable !== true
      || descriptor.configurable !== false
      || descriptor.writable !== true
      || !exactFunction(
        descriptor.value,
        expectedLength,
        expectedAsync ? 'async' : 'sync',
        key,
      )
    ) return false;
  }
  const tagDescriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(namespace, Symbol.toStringTag);
  return tagDescriptor !== undefined
    && REFLECT_HAS(tagDescriptor, 'value') === true
    && tagDescriptor.value === 'Module'
    && tagDescriptor.enumerable === false
    && tagDescriptor.configurable === false
    && tagDescriptor.writable === false;
}

function loadTestCloudIdentityBindingsNamespace() {
  if (identityBindingsNamespacePromise === undefined) {
    identityBindingsNamespacePromise = (async () => {
      try {
        const imported = importValidatedNamespace(
          TEST_CLOUD_IDENTITY_BINDINGS_URL,
          validateIdentityBindingsNamespace,
        );
        if (!exactLocalPromise(imported)) {
          throw new TypeError('invalid canonical identity namespace Promise');
        }
        const namespace = await imported;
        canonicalIdentityBindingsNamespace = namespace;
        if (!OBJECT_IS(canonicalIdentityBindingsNamespace, namespace)) {
          throw new TypeError('identity namespace readback failed');
        }
        return namespace;
      } catch (error) {
        terminallyBlockRuntime();
        throw error;
      }
    })();
  }
  return identityBindingsNamespacePromise;
}

function loadTestCloudAppwriteNamespace() {
  if (appwriteNamespacePromise === undefined) {
    appwriteNamespacePromise = importValidatedNamespace(
      TEST_CLOUD_APPWRITE_URL,
      (namespace) => validateExactModuleNamespace(
        namespace,
        APPWRITE_NAMESPACE_EXPORTS,
        APPWRITE_NAMESPACE_FUNCTIONS,
      ),
    );
  }
  return appwriteNamespacePromise;
}

async function invokeCanonicalIdentityRegistrar() {
  if (runtimeRecord.state !== 'BOOTSTRAPPING') return terminallyBlockRuntime();
  const namespace = await loadTestCloudIdentityBindingsNamespace();
  if (
    runtimeRecord.state !== 'BOOTSTRAPPING'
    || !OBJECT_IS(namespace, canonicalIdentityBindingsNamespace)
  ) return terminallyBlockRuntime();
  const registrar = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
    namespace,
    'registerTestCloudIdentityBootstrap',
  ).value;
  const authority = OBJECT_FREEZE({ namespace, registrar });
  if (armedIdentityRegistrarCall !== undefined) return terminallyBlockRuntime();
  armedIdentityRegistrarCall = authority;
  if (!OBJECT_IS(armedIdentityRegistrarCall, authority)) return terminallyBlockRuntime();
  try {
    const result = REFLECT_APPLY(registrar, namespace, []);
    if (result !== true || runtimeRecord.state !== 'BOOTSTRAPPING') {
      return terminallyBlockRuntime();
    }
    return true;
  } catch {
    return terminallyBlockRuntime();
  } finally {
    if (OBJECT_IS(armedIdentityRegistrarCall, authority)) {
      armedIdentityRegistrarCall = undefined;
    } else {
      terminallyBlockRuntime();
    }
  }
}

function registerFutureSlot(slotName, invocationReceiver, registration, argumentLength) {
  const identityAuthorityValid = slotName !== 'registerIdentityAuthorityBridge'
    || (
      armedIdentityRegistrarCall !== undefined
      && OBJECT_IS(
        armedIdentityRegistrarCall.namespace,
        canonicalIdentityBindingsNamespace,
      )
      && OBJECT_IS(
        armedIdentityRegistrarCall.registrar,
        OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
          canonicalIdentityBindingsNamespace,
          'registerTestCloudIdentityBootstrap',
        ).value,
      )
    );
  if (
    argumentLength !== 1
    || runtimeRecord.state !== 'BOOTSTRAPPING'
    || !OBJECT_IS(invocationReceiver, futureBridgeReceiver)
    || !OBJECT_HAS_OWN(futureRegistrationStates, slotName)
    || futureRegistrationStates[slotName] !== 'EMPTY'
    || identityAuthorityValid !== true
    || !isExactRegistrationForSlot(slotName, registration)
  ) return terminallyBlockRuntime();

  futureRegistrationStates[slotName] = 'REGISTERING';
  const profile = futureSlotProfiles[slotName];
  const receiver = registrationReceiver(registration);
  const recordedReceiver = futureReceiverGroups[profile.receiverGroup];
  if (recordedReceiver === undefined) {
    for (const group of OBJECT_KEYS(futureReceiverGroups)) {
      if (OBJECT_IS(futureReceiverGroups[group], receiver)) {
        return terminallyBlockRuntime();
      }
    }
    futureReceiverGroups[profile.receiverGroup] = receiver;
    if (!OBJECT_IS(futureReceiverGroups[profile.receiverGroup], receiver)) {
      return terminallyBlockRuntime();
    }
  } else if (!OBJECT_IS(recordedReceiver, receiver)) {
    return terminallyBlockRuntime();
  }

  futureRegistrationValues[slotName] = registration;
  if (
    !OBJECT_IS(futureRegistrationValues[slotName], registration)
    || !isExactRegistrationForSlot(slotName, futureRegistrationValues[slotName])
    || !OBJECT_IS(
      registrationReceiver(futureRegistrationValues[slotName]),
      futureReceiverGroups[profile.receiverGroup],
    )
  ) return terminallyBlockRuntime();

  if (slotName === 'registerIdentityAuthorityBridge') {
    futureIdentityAuthorityBridge = registration;
    if (!OBJECT_IS(futureIdentityAuthorityBridge, registration)) {
      return terminallyBlockRuntime();
    }
  }
  if (slotName === 'registerProviderMutationRouteProducer') {
    futureBrowserArtifactMemberReader = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
      registration,
      'artifactMemberReader',
    ).value;
    if (!OBJECT_IS(
      futureBrowserArtifactMemberReader,
      OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
        futureRegistrationValues[slotName],
        'artifactMemberReader',
      ).value,
    )) return terminallyBlockRuntime();
  }
  futureRegistrationStates[slotName] = 'REGISTERED';
  if (futureRegistrationStates[slotName] !== 'REGISTERED') {
    return terminallyBlockRuntime();
  }
  return true;
}


function makeFutureRegistrar(slotName) {
  const registrar = function futureRegistrar(registration) {
    return registerFutureSlot(slotName, this, registration, arguments.length);
  };
  OBJECT_DEFINE_PROPERTIES(registrar, {
    name: {
      value: slotName,
      configurable: true,
    },
  });
  return OBJECT_FREEZE(registrar);
}

for (const slotName of FUTURE_REGISTRATION_SLOT_NAMES) {
  futureRegistrationStates[slotName] = 'EMPTY';
  futureRegistrars[slotName] = makeFutureRegistrar(slotName);
}
OBJECT_FREEZE(futureRegistrars);

function inertFutureDispatcher(_args) {
  return terminallyBlockRuntime();
}

function createClosedNullRecord(keys, values) {
  const value = OBJECT_CREATE(null);
  const descriptors = OBJECT_CREATE(null);
  for (const key of keys) {
    descriptors[key] = {
      value: values[key],
      enumerable: true,
      configurable: false,
      writable: false,
    };
  }
  OBJECT_DEFINE_PROPERTIES(value, descriptors);
  return OBJECT_FREEZE(value);
}

function createClosedOrdinaryRecord(keys, values) {
  const value = OBJECT_CREATE(OBJECT_PROTOTYPE);
  const descriptors = OBJECT_CREATE(null);
  for (const key of keys) {
    descriptors[key] = {
      value: values[key],
      enumerable: true,
      configurable: false,
      writable: false,
    };
  }
  OBJECT_DEFINE_PROPERTIES(value, descriptors);
  return OBJECT_FREEZE(value);
}

function safeSetupLoadDiagnosticCode(code) {
  switch (code) {
    case 'TEST_CLOUD_SETUP_REQUEST_INVALID':
    case 'TEST_CLOUD_SETUP_PROVIDER_BINDING_INVALID':
    case 'TEST_CLOUD_SETUP_RUNTIME_STATE_INVALID':
    case 'TEST_CLOUD_SETUP_IDENTITY_QUALIFICATION_INVALID':
    case 'TEST_CLOUD_SETUP_ENVIRONMENT_BINDING_INVALID':
    case 'TEST_CLOUD_SETUP_PAYLOAD_INVALID':
    case 'TEST_CLOUD_SETUP_IDENTITY_DIGEST_MISMATCH':
    case 'TEST_CLOUD_SETUP_FINALIZATION_INVALID':
      return code;
    default:
      return undefined;
  }
}

function runtimeBlockedResult(code) {
  const safeCode = safeSetupLoadDiagnosticCode(code);
  const diagnostics = safeCode === undefined
    ? OBJECT_FREEZE([])
    : OBJECT_FREEZE([createClosedNullRecord(
      ['code', 'retryable', 'safeMessage'],
      {
        code: safeCode,
        retryable: false,
        safeMessage: 'Protected test-cloud setup readback could not be qualified.',
      },
    )]);
  return createClosedNullRecord(
    ['status', 'value', 'diagnostics'],
    {
      status: 'BLOCKED',
      value: null,
      diagnostics,
    },
  );
}

function runtimePassResult(runtimeQualification, browserScenarioQualification) {
  const value = createClosedNullRecord(RUNTIME_PASS_VALUE_KEYS, {
    runtimeQualification,
    browserScenarioQualification,
  });
  return createClosedNullRecord(
    ['status', 'value', 'diagnostics'],
    {
      status: 'PASS',
      value,
      diagnostics: OBJECT_FREEZE([]),
    },
  );
}

function runtimeOperationPassResult(keys, values) {
  return createClosedNullRecord(
    ['status', 'value', 'diagnostics'],
    {
      status: 'PASS',
      value: createClosedNullRecord(keys, values),
      diagnostics: OBJECT_FREEZE([]),
    },
  );
}

function currentPublicOperationAuthorized(args, expectedKeys) {
  if (
    runtimeRecord.state !== 'ACTIVE'
    || activationState !== 'COMMITTED'
    || !exactOrderedPublicDataRecord(args, expectedKeys)
    || futureBootstrapHub !== undefined
    || OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
      globalThis,
      BOOTSTRAP_HUB_PROPERTY,
    ) !== undefined
  ) return false;
  const runtimeDescriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
    args,
    'runtimeQualification',
  );
  return runtimeDescriptor !== undefined
    && REFLECT_HAS(runtimeDescriptor, 'value') === true
    && OBJECT_IS(runtimeDescriptor.value, activeRuntimeQualification);
}

function blockPublicOperation() {
  terminallyBlockRuntime();
  return runtimeBlockedResult();
}

function exactDigestString(value) {
  return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value);
}

function exactLogicalValueBindings(value) {
  if (!exactDenseFrozenArray(value)) return false;
  for (let index = 0; index < value.length; index += 1) {
    const binding = value[index];
    if (!exactOrderedDataRecord(binding, LOGICAL_VALUE_BINDING_KEYS)) return false;
    const name = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(binding, 'bindingName').value;
    const valueType = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(binding, 'valueType').value;
    if (
      typeof name !== 'string'
      || name.length === 0
      || typeof valueType !== 'string'
      || valueType.length === 0
    ) return false;
  }
  return true;
}

function exactQualifiedProviderRegistryFor(args) {
  const registry = currentQualifiedProviderRegistry;
  if (!exactOrderedDataRecord(registry, QUALIFIED_PROVIDER_REGISTRY_KEYS)) return false;
  const values = OBJECT_CREATE(null);
  for (const key of QUALIFIED_PROVIDER_REGISTRY_KEYS) {
    values[key] = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(registry, key).value;
  }
  if (
    values.state !== 'QUALIFIED'
    || !OBJECT_IS(values.runtimeQualification, activeRuntimeQualification)
    || !OBJECT_IS(values.runtimeQualification, args.runtimeQualification)
    || !OBJECT_IS(values.context, args.context)
    || !OBJECT_IS(
      values.sessionIntentQualification,
      args.sessionIntentQualification,
    )
    || typeof values.exactDeploymentOrigin !== 'string'
    || values.exactDeploymentOrigin.length === 0
    || values.exactDeploymentOrigin.length > 2048
    || !exactDenseFrozenArray(values.operationProfiles)
    || !exactDenseFrozenArray(values.logicalValueBindingGroups)
    || values.operationProfiles.length !== values.logicalValueBindingGroups.length
    || !NUMBER_IS_SAFE_INTEGER(args.mutationOrdinal)
    || args.mutationOrdinal < 0
    || args.mutationOrdinal >= values.operationProfiles.length
  ) return false;
  const operationProfile = values.operationProfiles[args.mutationOrdinal];
  const logicalValueBindings = values.logicalValueBindingGroups[args.mutationOrdinal];
  if (
    !exactOrderedDataRecord(operationProfile, CANONICAL_OPERATION_PROFILE_KEYS)
    || operationProfile.mutationOrdinal !== args.mutationOrdinal
    || !exactOrderedDataRecord(operationProfile.requestTemplate, REQUEST_TEMPLATE_KEYS)
    || operationProfile.requestTemplate.mutationOrdinal !== args.mutationOrdinal
    || !exactDigestString(operationProfile.requestTemplateDigest)
    || operationProfile.requestTemplateDigest !== sha256(BUFFER_FROM(
      canonicalJson(operationProfile.requestTemplate),
      'utf8',
    ))
    || !exactLogicalValueBindings(logicalValueBindings)
  ) return false;
  return createClosedNullRecord(
    ['registry', 'operationProfile', 'logicalValueBindings'],
    { registry, operationProfile, logicalValueBindings },
  );
}

function mutationOrdinalAlreadyCaptured(registry, mutationOrdinal) {
  for (const entry of providerMutationCaptureEntries) {
    if (
      OBJECT_IS(entry.registry, registry)
      && entry.mutationOrdinal === mutationOrdinal
    ) return true;
  }
  return false;
}

function createMutationRequestAuthority(args) {
  const qualified = exactQualifiedProviderRegistryFor(args);
  if (
    qualified === false
    || mutationOrdinalAlreadyCaptured(qualified.registry, args.mutationOrdinal)
  ) return false;
  const operationQualification = OBJECT_FREEZE(OBJECT_CREATE(null));
  const operationRecord = createClosedNullRecord(
    [
      'operationQualification',
      'registry',
      'runtimeQualification',
      'context',
      'sessionIntentQualification',
      'mutationOrdinal',
      'operationProfile',
    ],
    {
      operationQualification,
      registry: qualified.registry,
      runtimeQualification: args.runtimeQualification,
      context: args.context,
      sessionIntentQualification: args.sessionIntentQualification,
      mutationOrdinal: args.mutationOrdinal,
      operationProfile: qualified.operationProfile,
    },
  );
  REFLECT_APPLY(
    WEAK_MAP_SET,
    OPERATION_QUALIFICATIONS,
    [operationQualification, operationRecord],
  );
  const requestAuthority = createClosedNullRecord(REQUEST_AUTHORITY_KEYS, {
    operationQualification,
    requestTemplate: qualified.operationProfile.requestTemplate,
    requestTemplateDigest: qualified.operationProfile.requestTemplateDigest,
    exactDeploymentOrigin: qualified.registry.exactDeploymentOrigin,
    logicalValueBindings: qualified.logicalValueBindings,
  });
  return createClosedNullRecord(
    ['registry', 'operationQualification', 'requestAuthority'],
    { registry: qualified.registry, operationQualification, requestAuthority },
  );
}

function exactRouteProjection(value) {
  if (!exactOrderedDataRecord(value, ROUTE_PROJECTION_KEYS)) return false;
  if (
    typeof value.method !== 'string'
    || value.method.length === 0
    || !exactOrderedDataRecord(value.originBinding, ORIGIN_BINDING_KEYS)
    || !exactOrderedDataRecord(value.pathBinding, PATH_BINDING_KEYS)
    || !exactOrderedDataRecord(value.queryBinding, QUERY_BINDING_KEYS)
    || !exactOrderedDataRecord(value.bodyBinding, BODY_BINDING_KEYS)
    || !exactDigestString(value.originBinding.originDigest)
    || !exactDigestString(value.pathBinding.pathDigest)
    || !exactDigestString(value.queryBinding.queryDigest)
    || !exactDigestString(value.bodyBinding.semanticBodyDigest)
    || !exactDigestString(value.bodyBinding.boundValuesDigest)
    || !exactDigestString(value.bodyBinding.executionEnvelopeDigest)
    || !exactDigestString(value.sourceBytesDigest)
    || !exactDenseFrozenArray(value.generatedIdBindings)
  ) return false;
  for (const binding of value.generatedIdBindings) {
    if (
      !exactOrderedDataRecord(binding, GENERATED_ID_BINDING_KEYS)
      || typeof binding.bindingName !== 'string'
      || binding.bindingName.length === 0
      || !exactDigestString(binding.valueDigest)
    ) return false;
  }
  return true;
}

function exactRouteCaptureResult(value) {
  return exactOrderedDataRecord(value, ROUTE_CAPTURE_RESULT_KEYS)
    && exactEmptyReceiver(value.observationQualification)
    && exactRouteProjection(value.routeProjection);
}

function createCurrentClockOperations() {
  if (
    runtimeRecord.state !== 'ACTIVE'
    || activationState !== 'COMMITTED'
    || canonicalFixtureClockNamespace === undefined
    || futureReceiverGroups['fixture-clock'] === undefined
  ) return false;
  const values = OBJECT_CREATE(null);
  values.receiver = futureReceiverGroups['fixture-clock'];
  for (let index = 1; index < CLOCK_OPERATIONS_KEYS.length; index += 1) {
    const key = CLOCK_OPERATIONS_KEYS[index];
    const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
      canonicalFixtureClockNamespace,
      key,
    );
    if (
      descriptor === undefined
      || REFLECT_HAS(descriptor, 'value') !== true
      || !exactFunction(descriptor.value, 1, 'async', key)
    ) return false;
    values[key] = descriptor.value;
  }
  return createClosedNullRecord(CLOCK_OPERATIONS_KEYS, values);
}

function registeredEnvelopeImplementation(slotName) {
  if (
    futureRegistrationStates[slotName] !== 'REGISTERED'
    || !OBJECT_HAS_OWN(futureRegistrationValues, slotName)
  ) return undefined;
  const registration = futureRegistrationValues[slotName];
  if (!isExactRegistrationForSlot(slotName, registration)) return undefined;
  return registration;
}

function invokeEnvelopeSlot(slotName, args) {
  const registration = registeredEnvelopeImplementation(slotName);
  if (registration === undefined) return terminallyBlockRuntime();
  const implementation = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
    registration,
    'implementation',
  ).value;
  const receiver = registrationReceiver(registration);
  try {
    return REFLECT_APPLY(implementation, receiver, [args]);
  } catch {
    return terminallyBlockRuntime();
  }
}

function invokeProviderControlMethod(methodName, args) {
  const registration = registeredEnvelopeImplementation(
    'registerProviderControlImplementation',
  );
  if (registration === undefined) return terminallyBlockRuntime();
  const implementation = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
    registration,
    'implementation',
  ).value;
  const receiver = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(implementation, 'receiver').value;
  const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(implementation, methodName);
  if (
    descriptor === undefined
    || REFLECT_HAS(descriptor, 'value') !== true
    || typeof descriptor.value !== 'function'
  ) return terminallyBlockRuntime();
  try {
    return REFLECT_APPLY(descriptor.value, receiver, [args]);
  } catch {
    return terminallyBlockRuntime();
  }
}

function invokeIdentityMethod(methodName, args) {
  if (
    futureRegistrationStates.registerIdentityAuthorityBridge !== 'REGISTERED'
    || !OBJECT_IS(
      futureIdentityAuthorityBridge,
      futureRegistrationValues.registerIdentityAuthorityBridge,
    )
  ) return terminallyBlockRuntime();
  const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
    futureIdentityAuthorityBridge,
    methodName,
  );
  const receiver = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
    futureIdentityAuthorityBridge,
    'receiver',
  ).value;
  if (
    descriptor === undefined
    || REFLECT_HAS(descriptor, 'value') !== true
    || typeof descriptor.value !== 'function'
  ) return terminallyBlockRuntime();
  try {
    return REFLECT_APPLY(descriptor.value, receiver, [args]);
  } catch {
    return terminallyBlockRuntime();
  }
}

function deliverTimestampBindingResult(args) {
  return invokeEnvelopeSlot('registerTimestampBindingTransferReceiver', args);
}

function deliverMutationReconciliationQualification(args) {
  return invokeEnvelopeSlot('registerClockReconciliationAggregateReceiver', args);
}

function deliverBrowserScenarioAutosaveCompletion(args) {
  return invokeEnvelopeSlot(
    'registerBrowserScenarioAutosaveCompletionReceiver',
    args,
  );
}

function authenticateProviderQualification(args) {
  return authenticateProviderQualificationRecord(args) === true
    ? true : terminallyBlockRuntime();
}

function authenticateBrowserScenarioQualification(args) {
  try {
    if (
      runtimeRecord.state !== 'ACTIVE'
      || activationState !== 'COMMITTED'
      || args === null
      || typeof args !== 'object'
      || isProxy(args)
    ) return terminallyBlockRuntime();
    const runtimeDescriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
      args,
      'runtimeQualification',
    );
    const scenarioDescriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
      args,
      'browserScenarioQualification',
    );
    return runtimeDescriptor !== undefined
      && scenarioDescriptor !== undefined
      && REFLECT_HAS(runtimeDescriptor, 'value') === true
      && REFLECT_HAS(scenarioDescriptor, 'value') === true
      && OBJECT_IS(runtimeDescriptor.value, activeRuntimeQualification)
      && futureBootstrapHub === undefined
      && OBJECT_IS(
        scenarioDescriptor.value,
        activeBrowserScenarioQualification,
      )
      ? true
      : terminallyBlockRuntime();
  } catch {
    return terminallyBlockRuntime();
  }
}

function readFixtureClockPolicy(_args) {
  return terminallyBlockRuntime();
}

function readBrowserRequestPolicy(_args) {
  return terminallyBlockRuntime();
}

async function prepareShareValuesTransition(args) {
  const result = invokeProviderControlMethod('prepareShareValuesTransition', args);
  if (!exactLocalPromise(result)) return terminallyBlockRuntime();
  return await result;
}

function abortShareValuesTransition(args) {
  return invokeProviderControlMethod('abortShareValuesTransition', args);
}

async function commitShareValuesTransition(args) {
  const result = invokeProviderControlMethod('commitShareValuesTransition', args);
  if (!exactLocalPromise(result)) return terminallyBlockRuntime();
  return await result;
}

function finalizeShareValuesTransition(args) {
  return invokeProviderControlMethod('finalizeShareValuesTransition', args);
}

function readAuthenticatedShareBindingDigests(args) {
  return invokeIdentityMethod('readAuthenticatedShareBindingDigests', args);
}

function readAuthenticatedBrowserIdentityEmail(args) {
  return invokeIdentityMethod('readAuthenticatedBrowserIdentityEmail', args);
}

function authenticateInitialProviderPrefix(args) {
  return invokeEnvelopeSlot('registerInitialProviderPrefixAuthenticator', args);
}

function ownerAuthenticator(args) {
  return invokeIdentityMethod('ownerAuthenticator', args);
}

function authenticateShareIdentityFinalState(args) {
  return invokeIdentityMethod('authenticateShareIdentityFinalState', args);
}

function authenticateSessionLineage(args) {
  return invokeEnvelopeSlot('registerSessionLineageAuthenticator', args);
}

function authenticateMutationReconciliation(args) {
  return invokeEnvelopeSlot('registerMutationReconciliationAuthenticator', args);
}

function constructExpectedStateForProviderMutation(args) {
  return invokeEnvelopeSlot('registerExpectedStateConstructor', args);
}

function captureProviderMutationRoute(args) {
  return invokeEnvelopeSlot('registerProviderMutationRouteProducer', args);
}

function consumeExpectedStateResult(args) {
  return invokeEnvelopeSlot('registerExpectedStateResultConsumer', args);
}

const futureHubDispatchers = OBJECT_FREEZE({
  deliverTimestampBindingResult,
  deliverMutationReconciliationQualification,
  deliverBrowserScenarioAutosaveCompletion,
  authenticateProviderQualification,
  authenticateBrowserScenarioQualification,
  readFixtureClockPolicy,
  readBrowserRequestPolicy,
  prepareShareValuesTransition,
  abortShareValuesTransition,
  commitShareValuesTransition,
  finalizeShareValuesTransition,
  readAuthenticatedShareBindingDigests,
  readAuthenticatedBrowserIdentityEmail,
  authenticateInitialProviderPrefix,
  ownerAuthenticator,
  authenticateShareIdentityFinalState,
  authenticateSessionLineage,
  authenticateMutationReconciliation,
  constructExpectedStateForProviderMutation,
  captureProviderMutationRoute,
  consumeExpectedStateResult,
});

let activeBrowserScenarioQualification;

function createFutureBootstrapHub(browserFacade, browserScenarioQualification) {
  const hub = OBJECT_CREATE(null);
  const descriptors = OBJECT_CREATE(null);
  for (const key of FUTURE_HUB_KEYS) {
    let value = inertFutureDispatcher;
    if (key === 'bridgeReceiver') value = futureBridgeReceiver;
    else if (OBJECT_HAS_OWN(futureRegistrars, key)) value = futureRegistrars[key];
    else if (OBJECT_HAS_OWN(futureHubDispatchers, key)) value = futureHubDispatchers[key];
    else if (key === 'browserFacade') value = browserFacade;
    else if (key === 'browserScenarioQualification') {
      value = browserScenarioQualification;
    }
    descriptors[key] = {
      value,
      enumerable: true,
      configurable: false,
      writable: false,
    };
  }
  OBJECT_DEFINE_PROPERTIES(hub, descriptors);
  if (
    OBJECT_GET_PROTOTYPE_OF(hub) !== null
    || OBJECT_KEYS(hub).some((key, index) => key !== FUTURE_HUB_KEYS[index])
  ) throw new TypeError('invalid private bootstrap hub shape');
  return OBJECT_FREEZE(hub);
}

function validateFactoryReady(value) {
  if (!exactOrderedDataRecord(value, FACTORY_READY_KEYS)) return false;
  const browserFacade = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
    value,
    'browserFacade',
  ).value;
  const browserScenarioQualification = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
    value,
    'browserScenarioQualification',
  ).value;
  const finalizeBootstrap = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
    value,
    'finalizeBootstrap',
  ).value;
  if (!exactOrderedDataRecord(browserFacade, BROWSER_FACADE_KEYS)) return false;
  for (const key of BROWSER_FACADE_KEYS) {
    if (!exactFunction(
      OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(browserFacade, key).value,
      1,
      'async',
      key,
    )) return false;
  }
  return exactEmptyReceiver(browserScenarioQualification)
    && !OBJECT_IS(browserFacade, browserScenarioQualification)
    && exactFunction(finalizeBootstrap, 1, 'async');
}

function defineBootstrapHub(hub) {
  if (OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(globalThis, BOOTSTRAP_HUB_PROPERTY) !== undefined) {
    return false;
  }
  OBJECT_DEFINE_PROPERTY(globalThis, BOOTSTRAP_HUB_PROPERTY, {
    value: hub,
    enumerable: false,
    configurable: true,
    writable: false,
  });
  const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
    globalThis,
    BOOTSTRAP_HUB_PROPERTY,
  );
  return descriptor !== undefined
    && REFLECT_HAS(descriptor, 'value') === true
    && descriptor.enumerable === false
    && descriptor.configurable === true
    && descriptor.writable === false
    && OBJECT_IS(descriptor.value, hub);
}

function deleteBootstrapHubAndProveAbsent() {
  const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
    globalThis,
    BOOTSTRAP_HUB_PROPERTY,
  );
  if (descriptor !== undefined && !REFLECT_DELETE_PROPERTY(globalThis, BOOTSTRAP_HUB_PROPERTY)) {
    return false;
  }
  return OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
    globalThis,
    BOOTSTRAP_HUB_PROPERTY,
  ) === undefined;
}

function invokeCanonicalRegistrar(namespace, registrarName, expectedSlots) {
  if (
    runtimeRecord.state !== 'BOOTSTRAPPING'
    || runtimeRecord.substep !== 'REGISTRARS_RUNNING'
  ) return terminallyBlockRuntime();
  const registrar = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(namespace, registrarName).value;
  try {
    const result = REFLECT_APPLY(registrar, namespace, []);
    if (result !== true) return terminallyBlockRuntime();
  } catch {
    return terminallyBlockRuntime();
  }
  for (const slotName of expectedSlots) {
    if (
      futureRegistrationStates[slotName] !== 'REGISTERED'
      || !OBJECT_HAS_OWN(futureRegistrationValues, slotName)
      || !isExactRegistrationForSlot(slotName, futureRegistrationValues[slotName])
    ) return terminallyBlockRuntime();
  }
  return true;
}

function sessionLineageImplementation(_args) {
  if (
    canonicalControlStoreNamespace === undefined
    || canonicalControlStoreExports === undefined
  ) return terminallyBlockRuntime();
  for (const key of CONTROL_STORE_NAMESPACE_EXPORTS) {
    if (!OBJECT_IS(
      OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(canonicalControlStoreNamespace, key).value,
      OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(canonicalControlStoreExports, key).value,
    )) return terminallyBlockRuntime();
  }
  return false;
}

function captureControlStoreExports(namespace) {
  const values = OBJECT_CREATE(null);
  for (const key of CONTROL_STORE_NAMESPACE_EXPORTS) {
    values[key] = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(namespace, key).value;
  }
  const captured = createClosedNullRecord(CONTROL_STORE_NAMESPACE_EXPORTS, values);
  for (const key of CONTROL_STORE_NAMESPACE_EXPORTS) {
    if (!OBJECT_IS(
      OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(captured, key).value,
      OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(namespace, key).value,
    )) return false;
  }
  return captured;
}

function registerSessionLineageClosure() {
  const registration = createClosedNullRecord(ENVELOPE_KEYS, {
    receiver: futureSessionLineageReceiver,
    implementation: sessionLineageImplementation,
    moduleUrl: TEST_CLOUD_PROVIDER_CONTRACT_URL,
  });
  return REFLECT_APPLY(
    futureRegistrars.registerSessionLineageAuthenticator,
    futureBridgeReceiver,
    [registration],
  ) === true
    && futureRegistrationStates.registerSessionLineageAuthenticator === 'REGISTERED'
    && OBJECT_IS(
      futureRegistrationValues.registerSessionLineageAuthenticator,
      registration,
    );
}

function registerRunnerVariableAuthority(namespace) {
  if (
    runtimeRecord.state !== 'BOOTSTRAPPING'
    || runtimeRecord.substep !== 'REGISTRARS_RUNNING'
    || !OBJECT_IS(namespace, canonicalAppwriteNamespace)
    || runnerVariableAuthorityRegistered !== false
  ) return terminallyBlockRuntime();
  const qualifierDescriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
    namespace,
    'qualifyTestCloudRunnerVariableReadbackRequest',
  );
  if (
    qualifierDescriptor === undefined
    || REFLECT_HAS(qualifierDescriptor, 'value') !== true
    || !exactFunction(
      qualifierDescriptor.value,
      1,
      'sync',
      'qualifyTestCloudRunnerVariableReadbackRequest',
    )
  ) return terminallyBlockRuntime();
  const qualifier = qualifierDescriptor.value;
  const registrarDescriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
    qualifier,
    APPWRITE_RUNNER_VARIABLE_REGISTRAR_PROPERTY,
  );
  if (
    registrarDescriptor === undefined
    || REFLECT_HAS(registrarDescriptor, 'value') !== true
    || registrarDescriptor.enumerable !== false
    || registrarDescriptor.configurable !== true
    || registrarDescriptor.writable !== false
    || !exactFunction(
      registrarDescriptor.value,
      1,
      'sync',
      'registerTestCloudRunnerVariableAuthority',
    )
  ) return terminallyBlockRuntime();
  const registration = createClosedOrdinaryRecord(
    APPWRITE_RUNNER_VARIABLE_REGISTRATION_KEYS,
    {
      receiver: runnerVariableAuthorityReceiver,
      authenticateRunnerVariableReadbackRequestEvidence,
      moduleUrl: TEST_CLOUD_PROVIDER_CONTRACT_URL,
    },
  );
  try {
    if (
      REFLECT_APPLY(registrarDescriptor.value, qualifier, [registration]) !== true
      || runtimeRecord.state !== 'BOOTSTRAPPING'
      || runtimeRecord.substep !== 'REGISTRARS_RUNNING'
      || !OBJECT_IS(canonicalAppwriteNamespace, namespace)
      || runnerVariableAuthorityRegistered !== false
      || OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
        qualifier,
        APPWRITE_RUNNER_VARIABLE_REGISTRAR_PROPERTY,
      ) !== undefined
    ) return terminallyBlockRuntime();
  } catch {
    return terminallyBlockRuntime();
  }
  runnerVariableAuthorityRegistered = true;
  return runnerVariableAuthorityRegistered === true;
}

function allRegistrationsComplete() {
  if (runnerVariableAuthorityRegistered !== true) return false;
  for (const slotName of FUTURE_REGISTRATION_SLOT_NAMES) {
    if (
      futureRegistrationStates[slotName] !== 'REGISTERED'
      || !OBJECT_HAS_OWN(futureRegistrationValues, slotName)
      || !isExactRegistrationForSlot(slotName, futureRegistrationValues[slotName])
    ) return false;
  }
  return true;
}

export async function bootstrapRuntime() {
  let factoryReady = false;
  let finalizerInvoked = false;
  let commitAttempted = false;
  let finalizeBootstrap;
  let browserScenarioQualification;
  let bootstrapHubInstalled = false;
  try {
    if (arguments.length !== 0 || runtimeRecord.state !== 'EMPTY') {
      terminallyBlockRuntime();
      return runtimeBlockedResult();
    }
    const pending = createRuntimeRecord(
      'BOOTSTRAPPING',
      runtimeRecord.version + 1,
      'FACTORY_CALL_PENDING',
    );
    runtimeRecord = pending;
    if (!OBJECT_IS(runtimeRecord, pending)) throw new TypeError('bootstrap reservation failed');

    const routeNamespacePromise = loadTestCloudBrowserRouteAdapterNamespace();
    if (!exactLocalPromise(routeNamespacePromise)) {
      throw new TypeError('invalid route namespace Promise');
    }
    const routeNamespace = await routeNamespacePromise;
    canonicalBrowserRouteAdapterNamespace = routeNamespace;
    if (!OBJECT_IS(canonicalBrowserRouteAdapterNamespace, routeNamespace)) {
      throw new TypeError('route namespace readback failed');
    }
    const createFacade = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
      routeNamespace,
      'createTestCloudBrowserFacade',
    ).value;
    const factoryPromise = REFLECT_APPLY(createFacade, routeNamespace, []);
    if (
      !exactLocalPromise(factoryPromise)
      || runtimeRecord.state !== 'BOOTSTRAPPING'
      || runtimeRecord.substep !== 'FACTORY_CALL_CONSUMED'
    ) throw new TypeError('browser factory authorization failed');
    const ready = await factoryPromise;
    if (!validateFactoryReady(ready)) throw new TypeError('invalid browser factory READY');
    factoryReady = true;
    const browserFacade = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(ready, 'browserFacade').value;
    browserScenarioQualification = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
      ready,
      'browserScenarioQualification',
    ).value;
    finalizeBootstrap = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
      ready,
      'finalizeBootstrap',
    ).value;

    let retained = runtimeRecord;
    retained = advanceBootstrapSubstep(
      retained,
      'FACTORY_CALL_CONSUMED',
      'HUB_INSTALLING',
    );
    if (retained === false) throw new TypeError('factory successor mismatch');
    futureBootstrapHub = createFutureBootstrapHub(
      browserFacade,
      browserScenarioQualification,
    );
    if (!defineBootstrapHub(futureBootstrapHub)) {
      throw new TypeError('bootstrap hub installation failed');
    }
    bootstrapHubInstalled = true;
    retained = advanceBootstrapSubstep(retained, 'HUB_INSTALLING', 'REGISTRARS_RUNNING');
    if (retained === false) throw new TypeError('registrar successor mismatch');

    const providerControlPromise = loadTestCloudProviderControlNamespace();
    if (!exactLocalPromise(providerControlPromise)) throw new TypeError('provider control Promise');
    canonicalProviderControlNamespace = await providerControlPromise;
    if (!invokeCanonicalRegistrar(
      canonicalProviderControlNamespace,
      'registerTestCloudProviderControlBootstrap',
      [
        'registerProviderControlImplementation',
        'registerInitialProviderPrefixAuthenticator',
        'registerMutationReconciliationAuthenticator',
      ],
    )) throw new TypeError('provider control registrar failed');

    const controlStorePromise = loadTestCloudControlStoreNamespace();
    if (!exactLocalPromise(controlStorePromise)) throw new TypeError('control store Promise');
    canonicalControlStoreNamespace = await controlStorePromise;
    canonicalControlStoreExports = captureControlStoreExports(
      canonicalControlStoreNamespace,
    );
    if (canonicalControlStoreExports === false) {
      throw new TypeError('control store capture failed');
    }
    if (!registerSessionLineageClosure()) throw new TypeError('session closure failed');

    const identityRegistrarPromise = invokeCanonicalIdentityRegistrar();
    if (!exactLocalPromise(identityRegistrarPromise)) throw new TypeError('identity registrar Promise');
    if (await identityRegistrarPromise !== true) throw new TypeError('identity registrar failed');

    const appwritePromise = loadTestCloudAppwriteNamespace();
    if (!exactLocalPromise(appwritePromise)) {
      throw new TypeError('invalid Appwrite namespace Promise');
    }
    canonicalAppwriteNamespace = await appwritePromise;
    if (!registerRunnerVariableAuthority(canonicalAppwriteNamespace)) {
      throw new TypeError('runner-variable authority registrar failed');
    }

    const fixturesPromise = loadTestCloudFixturesNamespace();
    if (!exactLocalPromise(fixturesPromise)) throw new TypeError('fixtures Promise');
    canonicalFixturesNamespace = await fixturesPromise;
    if (!invokeCanonicalRegistrar(
      canonicalFixturesNamespace,
      'registerTestCloudFixturesBootstrap',
      [
        'registerExpectedStateConstructor',
        'registerTimestampBindingTransferReceiver',
      ],
    )) throw new TypeError('fixtures registrar failed');

    if (!OBJECT_IS(routeNamespace, canonicalBrowserRouteAdapterNamespace)) {
      throw new TypeError('route namespace cache mismatch');
    }
    if (!invokeCanonicalRegistrar(
      routeNamespace,
      'registerTestCloudBrowserRouteAdapterBootstrap',
      [
        'registerProviderMutationRouteProducer',
        'registerBrowserRouteAdapterImplementation',
        'registerBrowserScenarioAutosaveCompletionReceiver',
      ],
    )) throw new TypeError('route registrar failed');

    const artifactPromise = loadTestCloudBrowserArtifactSetNamespace();
    if (!exactLocalPromise(artifactPromise)) throw new TypeError('artifact Promise');
    canonicalBrowserArtifactSetNamespace = await artifactPromise;
    const canonicalBrowserArtifactMemberReader =
      OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
        canonicalBrowserArtifactSetNamespace,
        'readQualifiedTestCloudBrowserArtifactMember',
      ).value;
    if (
      futureBrowserArtifactMemberReader === undefined
      || !OBJECT_IS(
        canonicalBrowserArtifactMemberReader,
        futureBrowserArtifactMemberReader,
      )
    ) throw new TypeError('artifact reader identity readback failed');
    if (!invokeCanonicalRegistrar(
      canonicalBrowserArtifactSetNamespace,
      'registerTestCloudBrowserArtifactSetBootstrap',
      ['registerBrowserArtifactSetSetupBridge'],
    )) throw new TypeError('artifact registrar failed');

    const clockPromise = loadTestCloudFixtureClockNamespace();
    if (!exactLocalPromise(clockPromise)) throw new TypeError('clock Promise');
    canonicalFixtureClockNamespace = await clockPromise;
    if (!invokeCanonicalRegistrar(
      canonicalFixtureClockNamespace,
      'registerTestCloudFixtureClockBootstrap',
      [
        'registerExpectedStateResultConsumer',
        'registerClockReconciliationAggregateReceiver',
      ],
    )) throw new TypeError('clock registrar failed');

    if (!allRegistrationsComplete()) throw new TypeError('registrar readback failed');
    retained = advanceBootstrapSubstep(
      runtimeRecord,
      'REGISTRARS_RUNNING',
      'REGISTRARS_COMPLETE',
    );
    if (retained === false) throw new TypeError('registrar completion failed');
    if (!deleteBootstrapHubAndProveAbsent()) throw new TypeError('hub cleanup failed');
    bootstrapHubInstalled = false;
    futureBootstrapHub = undefined;

    const runtimeQualification = OBJECT_FREEZE(OBJECT_CREATE(null));
    const active = createRuntimeRecord('ACTIVE', retained.version + 1);
    activeRuntimeQualification = runtimeQualification;
    activeBrowserScenarioQualification = browserScenarioQualification;
    activationState = 'PROVISIONAL';
    runtimeRecord = active;
    if (!OBJECT_IS(runtimeRecord, active)) throw new TypeError('provisional activation failed');
    const withheldResult = runtimePassResult(
      runtimeQualification,
      browserScenarioQualification,
    );
    const commitArgs = createClosedNullRecord(['outcome'], { outcome: 'commit' });
    finalizerInvoked = true;
    commitAttempted = true;
    const commitPromise = REFLECT_APPLY(finalizeBootstrap, undefined, [commitArgs]);
    if (!exactLocalPromise(commitPromise) || await commitPromise !== true) {
      throw new TypeError('browser bootstrap commit failed');
    }
    if (
      !OBJECT_IS(runtimeRecord, active)
      || runtimeRecord.state !== 'ACTIVE'
      || runtimeRecord.version !== retained.version + 1
      || activationState !== 'PROVISIONAL'
      || !OBJECT_IS(activeRuntimeQualification, runtimeQualification)
      || !OBJECT_IS(
        activeBrowserScenarioQualification,
        browserScenarioQualification,
      )
      || !exactEmptyReceiver(runtimeQualification)
      || !exactEmptyReceiver(browserScenarioQualification)
      || futureBootstrapHub !== undefined
      || OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
        globalThis,
        BOOTSTRAP_HUB_PROPERTY,
      ) !== undefined
    ) throw new TypeError('provisional activation changed during commit');
    activationState = 'COMMITTED';
    if (
      !OBJECT_IS(runtimeRecord, active)
      || runtimeRecord.state !== 'ACTIVE'
      || activationState !== 'COMMITTED'
      || !OBJECT_IS(activeRuntimeQualification, runtimeQualification)
      || !OBJECT_IS(
        activeBrowserScenarioQualification,
        browserScenarioQualification,
      )
    ) throw new TypeError('committed activation readback failed');
    return withheldResult;
  } catch {
    if (factoryReady && !finalizerInvoked && !commitAttempted) {
      finalizerInvoked = true;
      try {
        const abortArgs = createClosedNullRecord(['outcome'], { outcome: 'abort' });
        const abortPromise = REFLECT_APPLY(finalizeBootstrap, undefined, [abortArgs]);
        if (exactLocalPromise(abortPromise)) await abortPromise;
      } catch {
        // Sanitized terminal failure is retained below.
      }
    }
    if (bootstrapHubInstalled || futureBootstrapHub !== undefined) {
      try {
        deleteBootstrapHubAndProveAbsent();
      } catch {
        // Runtime invalidation below is unconditional.
      }
    }
    futureBootstrapHub = undefined;
    activeBrowserScenarioQualification = undefined;
    terminallyBlockRuntime();
    return runtimeBlockedResult();
  } finally {
    finalizeBootstrap = undefined;
    browserScenarioQualification = undefined;
  }
}

export function readTestCloudRuntimeLifecycle() {
  if (arguments.length !== 0) terminallyBlockRuntime();
  return runtimeRecord.state === 'ACTIVE' && activationState !== 'COMMITTED'
    ? 'BOOTSTRAPPING'
    : runtimeRecord.state;
}

export function isAuthenticTestCloudBootstrapHub(hub) {
  if (
    arguments.length === 1
    && runtimeRecord.state === 'BOOTSTRAPPING'
    && runtimeRecord.substep === 'REGISTRARS_RUNNING'
    && OBJECT_IS(hub, futureBootstrapHub)
  ) {
    const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(globalThis, BOOTSTRAP_HUB_PROPERTY);
    if (
      descriptor !== undefined
      && REFLECT_HAS(descriptor, 'value')
      && descriptor.enumerable === false
      && descriptor.configurable === true
      && descriptor.writable === false
      && OBJECT_IS(descriptor.value, futureBootstrapHub)
    ) return true;
  }
  return terminallyBlockRuntime();
}

export function authenticateTestCloudRuntimeActive(args) {
  try {
    if (
      arguments.length === 1
      && runtimeRecord.state === 'ACTIVE'
      && activationState === 'COMMITTED'
      && exactOrderedPublicDataRecord(
        args,
        AUTHENTICATE_RUNTIME_ARGUMENT_KEYS,
      )
    ) {
      const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
        args,
        'runtimeQualification',
      );
      if (
        descriptor !== undefined
        && REFLECT_HAS(descriptor, 'value') === true
        && descriptor.enumerable === true
        && descriptor.configurable === false
        && descriptor.writable === false
        && OBJECT_IS(descriptor.value, activeRuntimeQualification)
      ) return true;
    }
  } catch {
    // Fall through to terminal invalidation.
  }
  return terminallyBlockRuntime();
}

export function consumeTestCloudBrowserFactoryAuthorization() {
  if (
    this === undefined
    &&
    arguments.length === 0
    && runtimeRecord.state === 'BOOTSTRAPPING'
    && runtimeRecord.substep === 'FACTORY_CALL_PENDING'
  ) {
    const consumed = advanceBootstrapSubstep(
      runtimeRecord,
      'FACTORY_CALL_PENDING',
      'FACTORY_CALL_CONSUMED',
    );
    if (consumed !== false) return true;
  }
  return terminallyBlockRuntime();
}

export function installProviderControlStore(args) {
  if (
    arguments.length !== 1
    || !currentPublicOperationAuthorized(
      args,
      INSTALL_PROVIDER_CONTROL_STORE_ARGUMENT_KEYS,
    )
    || currentQualifiedProviderRegistry === undefined
  ) return blockPublicOperation();
  return blockPublicOperation();
}

export function captureTestCloudProviderMutationRoute(args) {
  if (
    arguments.length !== 1
    || !currentPublicOperationAuthorized(
      args,
      CAPTURE_PROVIDER_MUTATION_ROUTE_ARGUMENT_KEYS,
    )
  ) return blockPublicOperation();
  const authority = createMutationRequestAuthority(args);
  if (authority === false) return blockPublicOperation();
  const captureEntry = {
    registry: authority.registry,
    mutationOrdinal: args.mutationOrdinal,
    state: 'PENDING',
    retainedResult: undefined,
  };
  providerMutationCaptureEntries.push(captureEntry);
  const internalArgs = createClosedNullRecord(
    CAPTURE_PROVIDER_MUTATION_ROUTE_INTERNAL_KEYS,
    {
      runtimeQualification: args.runtimeQualification,
      context: args.context,
      sessionIntentQualification: args.sessionIntentQualification,
      mutationOrdinal: args.mutationOrdinal,
      requestAuthority: authority.requestAuthority,
    },
  );
  const result = captureProviderMutationRoute(internalArgs);
  if (
    !exactRouteCaptureResult(result)
    || captureEntry.state !== 'PENDING'
    || runtimeRecord.state !== 'ACTIVE'
    || activationState !== 'COMMITTED'
    || !OBJECT_IS(activeRuntimeQualification, args.runtimeQualification)
    || !OBJECT_IS(currentQualifiedProviderRegistry, authority.registry)
  ) {
    captureEntry.state = 'BLOCKED';
    return blockPublicOperation();
  }
  captureEntry.retainedResult = createClosedNullRecord(
    ROUTE_CAPTURE_RESULT_KEYS,
    {
      observationQualification: result.observationQualification,
      routeProjection: result.routeProjection,
    },
  );
  captureEntry.state = 'CAPTURED';
  return runtimeOperationPassResult(['captured'], { captured: true });
}

function validMutationOrdinal(args) {
  return NUMBER_IS_SAFE_INTEGER(args.mutationOrdinal)
    && args.mutationOrdinal >= 0;
}

async function inertProviderOperation(args, expectedKeys, validate = undefined) {
  if (
    !currentPublicOperationAuthorized(args, expectedKeys)
    || (validate !== undefined && validate(args) !== true)
    || currentQualifiedProviderRegistry === undefined
  ) return blockPublicOperation();
  return blockPublicOperation();
}

export async function issueProviderMutation(args) {
  if (arguments.length !== 1) return blockPublicOperation();
  return inertProviderOperation(
    args,
    CAPTURE_PROVIDER_MUTATION_ROUTE_ARGUMENT_KEYS,
    validMutationOrdinal,
  );
}

export async function reconcileProviderMutation(args) {
  if (arguments.length !== 1) return blockPublicOperation();
  return inertProviderOperation(args, RECONCILE_PROVIDER_MUTATION_ARGUMENT_KEYS);
}

export async function createShareBaselineProof(args) {
  if (arguments.length !== 1) return blockPublicOperation();
  return inertProviderOperation(args, CREATE_SHARE_BASELINE_ARGUMENT_KEYS);
}

export async function issueShareCreate(args) {
  if (arguments.length !== 1) return blockPublicOperation();
  return inertProviderOperation(args, ISSUE_SHARE_CREATE_ARGUMENT_KEYS);
}

export async function reconcileShareCreate(args) {
  if (arguments.length !== 1) return blockPublicOperation();
  return inertProviderOperation(args, RECONCILE_SHARE_CREATE_ARGUMENT_KEYS);
}

function exactCurrentBrowserOperation(args, expectedKeys) {
  if (
    !currentPublicOperationAuthorized(args, expectedKeys)
    || !OBJECT_IS(
      args.browserScenarioQualification,
      activeBrowserScenarioQualification,
    )
    || !exactEmptyReceiver(args.clock)
  ) return false;
  return true;
}

async function inertBrowserOperation(args, expectedKeys, validate = undefined) {
  if (
    !exactCurrentBrowserOperation(args, expectedKeys)
    || (validate !== undefined && validate(args) !== true)
    || currentQualifiedProviderRegistry === undefined
  ) return blockPublicOperation();
  const clockOperations = createCurrentClockOperations();
  if (clockOperations === false) return blockPublicOperation();
  return blockPublicOperation();
}

function exactOwnerLoginInput(args) {
  if (!exactOrderedPublicDataRecord(args.ownerLoginInput, OWNER_LOGIN_INPUT_KEYS)) {
    return false;
  }
  const password = args.ownerLoginInput.password;
  return typeof password === 'string'
    && password.length > 0
    && password.length <= 4096
    && !/[\u0000-\u001f\u007f]/u.test(password);
}

export async function performOwnerLogin(args) {
  if (arguments.length !== 1) return blockPublicOperation();
  return inertBrowserOperation(
    args,
    PERFORM_OWNER_LOGIN_ARGUMENT_KEYS,
    exactOwnerLoginInput,
  );
}

export async function performProjectCreateAndGraphEditPrefix(args) {
  if (arguments.length !== 1) return blockPublicOperation();
  return inertBrowserOperation(args, PERFORM_PROJECT_PREFIX_ARGUMENT_KEYS);
}

export async function performEditorShare(args) {
  if (arguments.length !== 1) return blockPublicOperation();
  return inertBrowserOperation(args, PERFORM_SHARE_ARGUMENT_KEYS);
}

export async function performViewerShare(args) {
  if (arguments.length !== 1) return blockPublicOperation();
  return inertBrowserOperation(args, PERFORM_SHARE_ARGUMENT_KEYS);
}

const MAX_CONTRACT_BYTES = 262_144;
const APPROVED_CONTRACT_DIGEST =
  'sha256:eaa6c314b13daa4c56a75bfc29eb8b3c66b7315ad6f114475db4d5f9aee75cd8';
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const ROOT_KEYS = Object.freeze([
  'aggregateContracts',
  'controlProvider',
  'coreProvider',
  'environmentClass',
  'failurePolicy',
  'fixedQueryContracts',
  'fixtureClockPolicy',
  'fixtureGraphProfile',
  'fixtureSemanticLiterals',
  'responseFormats',
  'runnerFunction',
  'runnerVariables',
  'schemaVersion',
]);
const ARG_KEYS = Object.freeze([
  'bytes',
  'expectedDigest',
  'expectedEnvironmentDigest',
]);

const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

class ContractValidationError extends Error {}

function invalid() {
  throw new ContractValidationError();
}

function blocked() {
  const diagnostic = OBJECT_FREEZE({
    code: 'TEST_PROVIDER_CONTRACT_INVALID',
    retryable: false,
    safeMessage: 'Test-cloud provider contract data could not be validated.',
  });
  const diagnostics = OBJECT_FREEZE([diagnostic]);
  return OBJECT_FREEZE({
    status: 'BLOCKED',
    value: null,
    diagnostics,
  });
}

function pass(outputDigest) {
  return OBJECT_FREEZE({
    status: 'PASS',
    value: OBJECT_FREEZE({ outputDigest }),
    diagnostics: OBJECT_FREEZE([]),
  });
}

function exactDataRecord(value, expectedKeys) {
  if (
    value === null
    || typeof value !== 'object'
    || isProxy(value)
    || OBJECT_GET_PROTOTYPE_OF(value) !== OBJECT_PROTOTYPE
  ) {
    invalid();
  }

  const ownKeys = REFLECT_OWN_KEYS(value);
  if (ownKeys.some((key) => typeof key !== 'string')) invalid();
  const keys = ownKeys.sort(compareOrdinal);
  const expected = [...expectedKeys].sort(compareOrdinal);
  if (
    keys.length !== expected.length
    || keys.some((key, index) => key !== expected[index])
  ) {
    invalid();
  }

  const snapshot = OBJECT_CREATE(null);
  for (const key of expectedKeys) {
    const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(value, key);
    if (
      descriptor === undefined
      || !REFLECT_HAS(descriptor, 'value')
      || descriptor.enumerable !== true
    ) {
      invalid();
    }
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function compareOrdinal(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function assertScalarString(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) invalid();
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      invalid();
    }
  }
}

function parseClosedJson(text) {
  let cursor = 0;
  let depth = 0;

  function enterContainer() {
    depth += 1;
    if (depth > 256) invalid();
  }

  function leaveContainer() {
    depth -= 1;
  }

  function parseString() {
    const start = cursor;
    if (text[cursor] !== '"') invalid();
    cursor += 1;

    while (cursor < text.length) {
      const code = text.charCodeAt(cursor);
      if (code === 0x22) {
        cursor += 1;
        let value;
        try {
          value = JSON_PARSE(text.slice(start, cursor));
        } catch {
          invalid();
        }
        assertScalarString(value);
        return value;
      }
      if (code < 0x20) invalid();
      if (code === 0x5c) {
        cursor += 1;
        const escaped = text[cursor];
        if (escaped === 'u') {
          const hex = text.slice(cursor + 1, cursor + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) invalid();
          cursor += 5;
          continue;
        }
        if (!'"\\/bfnrt'.includes(escaped)) invalid();
      }
      cursor += 1;
    }
    invalid();
  }

  function parseNumber() {
    const start = cursor;
    if (text[cursor] === '-') cursor += 1;
    if (text[cursor] === '0') {
      cursor += 1;
      if (/[0-9]/.test(text[cursor] ?? '')) invalid();
    } else {
      if (!/[1-9]/.test(text[cursor] ?? '')) invalid();
      while (/[0-9]/.test(text[cursor] ?? '')) cursor += 1;
    }
    const token = text.slice(start, cursor);
    const value = Number(token);
    if (!NUMBER_IS_SAFE_INTEGER(value) || OBJECT_IS(value, -0)) invalid();
    return value;
  }

  function parseArray() {
    enterContainer();
    cursor += 1;
    const result = [];
    if (text[cursor] === ']') {
      cursor += 1;
      leaveContainer();
      return result;
    }
    while (true) {
      result.push(parseValue());
      if (text[cursor] === ']') {
        cursor += 1;
        leaveContainer();
        return result;
      }
      if (text[cursor] !== ',') invalid();
      cursor += 1;
    }
  }

  function parseObject() {
    enterContainer();
    cursor += 1;
    const result = OBJECT_CREATE(null);
    const keys = new Set();
    if (text[cursor] === '}') {
      cursor += 1;
      leaveContainer();
      return result;
    }
    while (true) {
      const key = parseString();
      if (keys.has(key)) invalid();
      keys.add(key);
      if (text[cursor] !== ':') invalid();
      cursor += 1;
      result[key] = parseValue();
      if (text[cursor] === '}') {
        cursor += 1;
        leaveContainer();
        return result;
      }
      if (text[cursor] !== ',') invalid();
      cursor += 1;
    }
  }

  function parseValue() {
    const token = text[cursor];
    if (token === '"') return parseString();
    if (token === '{') return parseObject();
    if (token === '[') return parseArray();
    if (token === '-' || /[0-9]/.test(token ?? '')) return parseNumber();
    if (text.startsWith('true', cursor)) {
      cursor += 4;
      return true;
    }
    if (text.startsWith('false', cursor)) {
      cursor += 5;
      return false;
    }
    if (text.startsWith('null', cursor)) {
      cursor += 4;
      return null;
    }
    invalid();
  }

  const value = parseValue();
  if (cursor !== text.length) invalid();
  return value;
}

function canonicalJson(value) {
  if (value === null) return 'null';
  if (typeof value === 'string') {
    assertScalarString(value);
    return JSON_STRINGIFY(value);
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!NUMBER_IS_SAFE_INTEGER(value) || OBJECT_IS(value, -0)) invalid();
    return String(value);
  }
  if (ARRAY_IS_ARRAY(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  }
  if (value !== null && typeof value === 'object') {
    return `{${OBJECT_KEYS(value)
      .sort(compareOrdinal)
      .map((key) => `${JSON_STRINGIFY(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  invalid();
}

function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function typedArrayByteLength(value) {
  try {
    return REFLECT_APPLY(TYPED_ARRAY_BYTE_LENGTH, value, []);
  } catch {
    invalid();
  }
}

function copyTypedArray(value, byteLength) {
  try {
    const copy = new UINT8_ARRAY(byteLength);
    REFLECT_APPLY(UINT8_ARRAY_SET, copy, [value]);
    return copy;
  } catch {
    invalid();
  }
}

function deepFreezeJson(value) {
  const pending = [value];
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === null || typeof current !== 'object') continue;
    for (const key of OBJECT_KEYS(current)) pending.push(current[key]);
    OBJECT_FREEZE(current);
  }
  return value;
}

function exactParsedRecord(value, expectedKeys) {
  if (
    value === null
    || typeof value !== 'object'
    || ARRAY_IS_ARRAY(value)
    || OBJECT_GET_PROTOTYPE_OF(value) !== null
  ) invalid();
  const keys = OBJECT_KEYS(value).sort(compareOrdinal);
  const expected = [...expectedKeys].sort(compareOrdinal);
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    invalid();
  }
  return value;
}

function assertDigest(value) {
  if (typeof value !== 'string' || !DIGEST_PATTERN.test(value)) invalid();
}

function authenticateContractBytes({ bytes, expectedDigest, expectedEnvironmentDigest }) {
  if (
    bytes === null
    || typeof bytes !== 'object'
    || isProxy(bytes)
  ) invalid();
  assertDigest(expectedDigest);
  assertDigest(expectedEnvironmentDigest);

  const byteLength = typedArrayByteLength(bytes);
  if (byteLength < 1 || byteLength > MAX_CONTRACT_BYTES) invalid();
  const stableBytes = copyTypedArray(bytes, byteLength);
  if (
    stableBytes[0] === 0xef
    && stableBytes[1] === 0xbb
    && stableBytes[2] === 0xbf
  ) invalid();
  if (
    stableBytes[stableBytes.length - 1] !== 0x0a
    || stableBytes[stableBytes.length - 2] === 0x0a
    || REFLECT_APPLY(UINT8_ARRAY_INCLUDES, stableBytes, [0x0d])
  ) invalid();

  const actualDigest = sha256(stableBytes);
  if (actualDigest !== expectedDigest || actualDigest !== APPROVED_CONTRACT_DIGEST) invalid();

  let text;
  try {
    text = REFLECT_APPLY(TEXT_DECODER_DECODE, UTF8_DECODER, [
      REFLECT_APPLY(UINT8_ARRAY_SUBARRAY, stableBytes, [0, stableBytes.length - 1]),
    ]);
  } catch {
    invalid();
  }
  const providerContract = parseClosedJson(text);
  if (canonicalJson(providerContract) !== text) invalid();
  exactParsedRecord(providerContract, ROOT_KEYS);
  if (
    providerContract.schemaVersion !== TEST_CLOUD_PROVIDER_CONTRACT_VERSION
    || providerContract.environmentClass !== 'appwrite-cloud-test'
  ) invalid();
  deepFreezeJson(providerContract);
  return { providerContract, expectedEnvironmentDigest };
}

function parityDigest(operation, value) {
  return sha256(BUFFER_FROM(canonicalJson({
    schemaVersion: 'verification-parity-output.v1',
    operation,
    value,
  }), 'utf8'));
}

function validate(args) {
  const values = exactDataRecord(args, ARG_KEYS);
  const authenticated = authenticateContractBytes(values);
  return parityDigest('validate-contract-bytes', {
    expectedEnvironmentDigest: authenticated.expectedEnvironmentDigest,
    providerContract: authenticated.providerContract,
  });
}

const INTENT_ARG_KEYS = Object.freeze([
  'contractBytes',
  'expectedContractDigest',
  'expectedEnvironmentDigest',
  'logicalResource',
  'value',
]);
const INTENT_VALUE_KEYS = Object.freeze(['expectedRowId', 'expectedRunId', 'rawRow']);
const RAW_INTENT_KEYS = Object.freeze([
  '$createdAt',
  '$databaseId',
  '$id',
  '$permissions',
  '$sequence',
  '$tableId',
  '$updatedAt',
  'createdAt',
  'dependencyOrder',
  'environmentDigest',
  'intentId',
  'intentVersion',
  'lifecycleClass',
  'observationDigest',
  'ownerMarker',
  'providerAggregateDigest',
  'providerAggregateJson',
  'providerResourceIds',
  'resourceId',
  'resourceType',
  'retentionExpiresAt',
  'runId',
  'schemaVersion',
  'state',
  'updatedAt',
]);
const INTENT_V1_KEYS = Object.freeze([
  'schemaVersion', 'intentId', 'runId', 'environmentDigest', 'resourceType',
  'resourceId', 'providerResourceIds', 'ownerMarker', 'dependencyOrder',
  'lifecycleClass', 'state', 'intentVersion', 'observationDigest',
  'retentionExpiresAt', 'createdAt', 'updatedAt',
]);
const INTENT_V2_KEYS = Object.freeze([
  'schemaVersion', 'intentId', 'runId', 'environmentDigest', 'resourceType',
  'resourceId', 'providerAggregateJson', 'providerAggregateDigest', 'ownerMarker',
  'dependencyOrder', 'lifecycleClass', 'state', 'intentVersion',
  'observationDigest', 'retentionExpiresAt', 'createdAt', 'updatedAt',
]);
const V1_RESOURCES = Object.freeze(['account-session-set', 'primary-execution']);
const V2_RESOURCES = Object.freeze(['primary-project', 'primary-graph', 'primary-share']);
const RFC3339_MILLISECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

function exactOrdinaryArray(value) {
  if (!ARRAY_IS_ARRAY(value)) invalid();
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.hasOwn(value, index)) invalid();
  }
  return value;
}

function copyIntentProjection(fields, keys) {
  const projection = {};
  for (const key of keys) projection[key] = fields[key];
  deepFreezeJson(projection);
  return projection;
}

function validateIntentCommon(fields, expected) {
  if (
    fields.$id !== expected.expectedRowId
    || fields.$databaseId !== 'verification_control'
    || fields.$tableId !== 'verification_intents'
    || !ARRAY_IS_ARRAY(fields.$permissions)
    || fields.$permissions.length !== 0
    || !NUMBER_IS_SAFE_INTEGER(fields.$sequence)
    || fields.$sequence < 0
    || fields.runId !== expected.expectedRunId
    || fields.environmentDigest !== expected.expectedEnvironmentDigest
    || fields.resourceType !== expected.logicalResource
    || typeof fields.resourceId !== 'string'
    || fields.resourceId.length < 1
    || typeof fields.intentId !== 'string'
    || !/^[0-9a-f]{64}$/.test(fields.intentId)
    || typeof fields.ownerMarker !== 'string'
    || !/^verification-owner\.v1:sha256:[0-9a-f]{64}$/.test(fields.ownerMarker)
    || !NUMBER_IS_SAFE_INTEGER(fields.dependencyOrder)
    || fields.dependencyOrder < 0
    || !NUMBER_IS_SAFE_INTEGER(fields.intentVersion)
    || fields.intentVersion < 1
    || !['planned', 'created', 'absent'].includes(fields.state)
    || (fields.observationDigest !== null && !DIGEST_PATTERN.test(fields.observationDigest))
    || (fields.retentionExpiresAt !== null && typeof fields.retentionExpiresAt !== 'string')
    || typeof fields.createdAt !== 'string'
    || typeof fields.updatedAt !== 'string'
    || typeof fields.$createdAt !== 'string'
    || typeof fields.$updatedAt !== 'string'
  ) invalid();
}

const LOGICAL_VALUE_KEYS = Object.freeze([
  'name', 'sourceMutationOrdinal', 'state', 'value', 'valueDigest', 'valueKind',
]);
const OPERATION_STATE_KEYS = Object.freeze([
  'baselineDigest', 'discoveryProofDigest', 'expectedResultState', 'mutationOrdinal',
  'requestInstanceDigest', 'resultStateDigest', 'state',
]);

function findResourceContract(providerContract, resourceType) {
  const resources = exactOrdinaryArray(providerContract.aggregateContracts.resources);
  const matches = resources.filter((resource) => resource.resourceType === resourceType);
  if (matches.length !== 1) invalid();
  return matches[0];
}

function deriveV2Identity(expected, resourceType) {
  const operationScenario = 'sharing-permissions';
  const parameters = {};
  const operationKey = sha256(BUFFER_FROM(
    `${expected.expectedRunId}|${operationScenario}|${canonicalJson(parameters)}`,
    'utf8',
  ));
  const resourceHash = sha256(BUFFER_FROM(
    `${expected.expectedEnvironmentDigest}|${expected.expectedRunId}|${resourceType}`,
    'utf8',
  ));
  const resourceId = `vr-${resourceHash.slice('sha256:'.length, 'sha256:'.length + 32)}`;
  const ownerMarker = `verification-owner.v1:${sha256(BUFFER_FROM(canonicalJson({
    environmentDigest: expected.expectedEnvironmentDigest,
    operationKey,
    resourceId,
    resourceType,
    runId: expected.expectedRunId,
    schemaVersion: 'verification-owner-marker.v1',
  }), 'utf8'))}`;
  const intentId = sha256(BUFFER_FROM(
    `${expected.expectedEnvironmentDigest}|${expected.expectedRunId}|${resourceType}|${resourceId}`,
    'utf8',
  )).slice('sha256:'.length);
  const encodedIntentId = REFLECT_APPLY(
    BUFFER_TO_STRING,
    BUFFER_FROM(intentId, 'hex'),
    ['base64url'],
  );
  return {
    intentId,
    intentRowId: `h${encodedIntentId.slice(0, 35)}`,
    operationKey,
    operationScenario,
    ownerMarker,
    parameters,
    resourceId,
    resourceType,
  };
}

function expectedAggregateBinding(expected, identity) {
  return {
    schemaVersion: 'verification-provider-aggregate-binding.v1',
    environmentDigest: expected.expectedEnvironmentDigest,
    providerContractDigest: APPROVED_CONTRACT_DIGEST,
    runId: expected.expectedRunId,
    resourceType: identity.resourceType,
    resourceId: identity.resourceId,
    operationScenario: identity.operationScenario,
    parameters: identity.parameters,
    operationKey: identity.operationKey,
    ownerMarker: identity.ownerMarker,
    intentId: identity.intentId,
  };
}

function validateLogicalValueBindings(member, template) {
  const rows = exactOrdinaryArray(member.logicalValueBindings);
  const contracts = exactOrdinaryArray(template.logicalValueBindingContracts);
  if (rows.length !== contracts.length) invalid();
  for (let index = 0; index < contracts.length; index += 1) {
    const row = exactParsedRecord(rows[index], LOGICAL_VALUE_KEYS);
    const contract = contracts[index];
    if (
      row.name !== contract.name
      || row.valueKind !== contract.valueKind
      || row.sourceMutationOrdinal !== contract.sourceMutationOrdinal
      || !['unbound', 'bound'].includes(row.state)
    ) invalid();
    if (row.state === 'unbound') {
      if (row.value !== null || row.valueDigest !== null) invalid();
    } else if (
      typeof row.value !== 'string'
      || row.value.length < 1
      || row.valueDigest !== sha256(BUFFER_FROM(row.value, 'utf8'))
    ) invalid();
  }
}

function validateOperationStates(member, template, isShare) {
  const rows = exactOrdinaryArray(member.operationStates);
  const contracts = exactOrdinaryArray(template.operations);
  if (rows.length !== contracts.length) invalid();
  for (let index = 0; index < contracts.length; index += 1) {
    const row = exactParsedRecord(rows[index], OPERATION_STATE_KEYS);
    const contract = contracts[index];
    if (
      row.mutationOrdinal !== contract.mutationOrdinal
      || (!isShare && contract.expectedStateContractDigest !== sha256(BUFFER_FROM(
        canonicalJson(contract.expectedStateContract),
        'utf8',
      )))
      || contract.requestTemplateDigest !== sha256(BUFFER_FROM(
        canonicalJson(contract.requestTemplate),
        'utf8',
      ))
      || contract.requestTemplate.mutationOrdinal !== contract.mutationOrdinal
      || !['pending', 'issued', 'reconciled'].includes(row.state)
    ) invalid();
    const evidence = [
      row.requestInstanceDigest, row.expectedResultState, row.resultStateDigest,
      row.baselineDigest, row.discoveryProofDigest,
    ];
    if (row.state === 'pending') {
      if (evidence.some((value) => value !== null)) invalid();
      continue;
    }
    assertDigest(row.requestInstanceDigest);
    if (isShare) {
      if (row.expectedResultState !== null) invalid();
      assertDigest(row.baselineDigest);
      if (row.state === 'issued') {
        if (row.resultStateDigest !== null || row.discoveryProofDigest !== null) invalid();
      } else {
        assertDigest(row.resultStateDigest);
        assertDigest(row.discoveryProofDigest);
      }
      continue;
    }

    const expectedStateContract = contract.expectedStateContract;
    const expectedKeys = template.providerKind === 'storage-file'
      ? exactOrdinaryArray(expectedStateContract.metadataKeys)
      : exactOrdinaryArray(expectedStateContract.applicationKeys);
    const bodyTemplate = contract.requestTemplate.bodyTemplate;
    if (
      bodyTemplate === null
      || bodyTemplate.expectedStateContractDigest !== contract.expectedStateContractDigest
      || row.expectedResultState === null
      || row.baselineDigest !== null
      || row.discoveryProofDigest !== null
    ) invalid();
    const expectedResultState = exactParsedRecord(row.expectedResultState, expectedKeys);
    const expectedResultStateDigest = sha256(BUFFER_FROM(
      canonicalJson(expectedResultState),
      'utf8',
    ));
    if (row.state === 'issued') {
      if (row.resultStateDigest !== null) invalid();
    } else if (row.resultStateDigest !== expectedResultStateDigest) {
      invalid();
    }
  }
}

function validateMemberState(member, template, phase, fields, isShare) {
  const isFile = template.providerKind === 'storage-file';
  const state = exactParsedRecord(member.memberState, isFile
    ? ['metadataDigest', 'permissionsDigest', 'presence', 'schemaVersion']
    : ['dataDigest', 'permissionsDigest', 'presence', 'schemaVersion']);
  const contentDigest = isFile ? state.metadataDigest : state.dataDigest;
  if (
    state.schemaVersion !== (isFile
      ? 'storage-file-metadata-state.v1'
      : 'tablesdb-row-state.v1')
    || !['unknown', 'absent', 'present'].includes(state.presence)
  ) invalid();
  if (state.presence === 'present') {
    assertDigest(contentDigest);
    assertDigest(state.permissionsDigest);
  } else if (contentDigest !== null || state.permissionsDigest !== null) {
    invalid();
  }

  const planningOnly = fields.state === 'planned'
    && phase === 'owner-baseline'
    && !isShare;
  if (planningOnly) {
    if (
      member.bindingState !== 'unbound'
      || state.presence !== 'unknown'
      || member.operationStates.some(({ state: operationState }) => operationState !== 'pending')
      || member.logicalValueBindings.some(({ state: bindingState }) => bindingState !== 'unbound')
    ) invalid();
    return;
  }
  if (!isShare && fields.state === 'planned') invalid();

  const expectedStates = exactOrdinaryArray(template.memberStateContract.expectedStatesByPhase);
  const expectedStatesForPhase = expectedStates.filter((entry) => entry.phase === phase);
  if (expectedStatesForPhase.length !== 1) {
    if (!['editor-issued', 'viewer-issued'].includes(phase)) invalid();
    return;
  }
  const expectedState = exactParsedRecord(expectedStatesForPhase[0], [
    'dataSourceMutationOrdinal', 'permissionsProfile', 'phase', 'presence',
  ]);
  if (state.presence !== expectedState.presence) invalid();

  if (isShare && expectedState.presence === 'present') {
    // This pure projection does not carry the authenticated tuple/discovery
    // proof required to qualify S0/S1, so a stable share row cannot prove
    // its own observed data or permissions digests.
    invalid();
  }

  if (!isShare && expectedState.presence === 'present') {
    if (
      fields.state !== 'created'
      || member.bindingState !== 'bound'
      || member.logicalValueBindings.some(({ state: bindingState }) => bindingState !== 'bound')
      || member.operationStates.some(({ state: operationState }) => operationState !== 'reconciled')
      || !['owner-only', 'shared-members'].includes(expectedState.permissionsProfile)
    ) invalid();
    const sourceIndexes = [];
    for (let index = 0; index < template.operations.length; index += 1) {
      if (template.operations[index].mutationOrdinal === expectedState.dataSourceMutationOrdinal) {
        sourceIndexes.push(index);
      }
    }
    if (sourceIndexes.length !== 1) invalid();
    const sourceState = member.operationStates[sourceIndexes[0]];
    if (
      sourceState.mutationOrdinal !== expectedState.dataSourceMutationOrdinal
      || sourceState.state !== 'reconciled'
    ) invalid();
    const expectedDigest = sha256(BUFFER_FROM(
      canonicalJson(sourceState.expectedResultState),
      'utf8',
    ));
    if (
      sourceState.resultStateDigest !== expectedDigest
      || contentDigest !== expectedDigest
    ) invalid();

    // This projection has neither the authenticated request-instance preimage nor
    // raw identity values required to derive the exact permissions profile. The
    // candidate digests cannot authenticate themselves, so stable present state
    // remains fail-closed until the trusted runtime facade supplies that context.
    invalid();
  }
}

function validateOwnedMember(member, template, bindingDigest, fields, aggregate) {
  exactParsedRecord(member, [
    'bindingState', 'logicalValueBindings', 'memberBinding', 'memberBindingDigest',
    'memberState', 'operationStates', 'providerId', 'providerIdentity', 'schemaVersion',
  ]);
  if (member.schemaVersion !== 'verification-provider-member.v1') invalid();
  const memberBinding = exactParsedRecord(member.memberBinding, [
    'aggregateBindingDigest', 'memberTemplateDigest', 'ownerOrdinal',
    'ownerResourceId', 'ownerResourceType', 'schemaVersion', 'slot',
  ]);
  if (
    memberBinding.schemaVersion !== 'verification-provider-member-binding.v1'
    || memberBinding.aggregateBindingDigest !== bindingDigest
    || memberBinding.ownerResourceType !== fields.resourceType
    || memberBinding.ownerResourceId !== fields.resourceId
    || memberBinding.slot !== template.slot
    || memberBinding.ownerOrdinal !== template.ownerOrdinal
    || memberBinding.memberTemplateDigest !== template.memberTemplateDigest
    || member.memberBindingDigest !== sha256(BUFFER_FROM(canonicalJson(memberBinding), 'utf8'))
  ) invalid();

  const isShare = fields.resourceType === 'primary-share';
  const allowedBindingStates = isShare
    ? ['unissued', 'issued', 'bound']
    : ['unbound', 'bound'];
  if (!allowedBindingStates.includes(member.bindingState)) invalid();
  if (member.bindingState === 'bound') {
    const identity = exactParsedRecord(member.providerIdentity, [
      'bindingName', 'providerId', 'providerKind',
    ]);
    if (
      typeof member.providerId !== 'string'
      || member.providerId.length < 1
      || identity.providerId !== member.providerId
      || identity.providerKind !== template.providerKind
      || identity.bindingName !== template.bindingName
    ) invalid();
  } else if (member.providerId !== null || member.providerIdentity !== null) {
    invalid();
  }
  validateLogicalValueBindings(member, template);
  validateOperationStates(member, template, isShare);
  validateMemberState(member, template, aggregate.phase, fields, isShare);
}

function parseProviderAggregate(fields, expected, providerContract) {
  if (
    typeof fields.providerAggregateJson !== 'string'
    || BUFFER_FROM(fields.providerAggregateJson, 'utf8').length < 1
    || BUFFER_FROM(fields.providerAggregateJson, 'utf8').length > 32_768
  ) invalid();
  const aggregate = parseClosedJson(fields.providerAggregateJson);
  if (canonicalJson(aggregate) !== fields.providerAggregateJson) invalid();
  if (sha256(BUFFER_FROM(fields.providerAggregateJson, 'utf8')) !== fields.providerAggregateDigest) {
    invalid();
  }
  exactParsedRecord(aggregate, [
    'aggregateBinding', 'aggregateBindingDigest', 'ownedMembers', 'phase',
    'referencedMembers', 'schemaVersion',
  ]);
  if (aggregate.schemaVersion !== 'verification-provider-aggregate.v1') invalid();

  const identity = deriveV2Identity(expected, fields.resourceType);
  const expectedBinding = expectedAggregateBinding(expected, identity);
  const binding = exactParsedRecord(aggregate.aggregateBinding, [
    'environmentDigest', 'intentId', 'operationKey', 'operationScenario',
    'ownerMarker', 'parameters', 'providerContractDigest', 'resourceId',
    'resourceType', 'runId', 'schemaVersion',
  ]);
  if (canonicalJson(binding) !== canonicalJson(expectedBinding)) invalid();
  const bindingDigest = sha256(BUFFER_FROM(canonicalJson(binding), 'utf8'));
  if (aggregate.aggregateBindingDigest !== bindingDigest) invalid();

  const resourceContract = findResourceContract(providerContract, fields.resourceType);
  if (
    fields.dependencyOrder !== resourceContract.dependencyOrder
    || fields.lifecycleClass !== resourceContract.lifecycleClass
    || !providerContract.aggregateContracts.phaseOrder.includes(aggregate.phase)
  ) invalid();

  const members = exactOrdinaryArray(aggregate.ownedMembers);
  const templates = exactOrdinaryArray(resourceContract.memberTemplates);
  const ownedSlots = exactOrdinaryArray(resourceContract.ownedSlots);
  if (members.length !== templates.length || members.length !== ownedSlots.length) invalid();
  const identities = new Set();
  for (let index = 0; index < templates.length; index += 1) {
    if (templates[index].slot !== ownedSlots[index]) invalid();
    validateOwnedMember(members[index], templates[index], bindingDigest, fields, aggregate);
    if (members[index].providerIdentity !== null) {
      const key = canonicalJson(members[index].providerIdentity);
      if (identities.has(key)) invalid();
      identities.add(key);
    }
  }

  const references = exactOrdinaryArray(aggregate.referencedMembers);
  const referenceContracts = exactOrdinaryArray(resourceContract.referencedSlots);
  if (references.length !== referenceContracts.length) invalid();
  for (let index = 0; index < referenceContracts.length; index += 1) {
    const reference = exactParsedRecord(references[index], [
      'memberBinding', 'memberBindingDigest', 'schemaVersion',
    ]);
    if (reference.schemaVersion !== 'verification-provider-member-reference.v1') invalid();
    const memberBinding = exactParsedRecord(reference.memberBinding, [
      'aggregateBindingDigest', 'memberTemplateDigest', 'ownerOrdinal',
      'ownerResourceId', 'ownerResourceType', 'schemaVersion', 'slot',
    ]);
    const referenceContract = referenceContracts[index];
    const ownerContract = findResourceContract(providerContract, referenceContract.ownerResourceType);
    const ownerTemplates = exactOrdinaryArray(ownerContract.memberTemplates);
    const ownerTemplate = ownerTemplates[referenceContract.ownerOrdinal];
    const ownerIdentity = deriveV2Identity(expected, referenceContract.ownerResourceType);
    const ownerBindingDigest = sha256(BUFFER_FROM(
      canonicalJson(expectedAggregateBinding(expected, ownerIdentity)),
      'utf8',
    ));
    if (
      ownerTemplate === undefined
      || ownerTemplate.slot !== referenceContract.ownerSlot
      || memberBinding.schemaVersion !== 'verification-provider-member-binding.v1'
      || memberBinding.aggregateBindingDigest !== ownerBindingDigest
      || memberBinding.ownerResourceType !== referenceContract.ownerResourceType
      || memberBinding.ownerResourceId !== ownerIdentity.resourceId
      || memberBinding.slot !== referenceContract.ownerSlot
      || memberBinding.ownerOrdinal !== referenceContract.ownerOrdinal
      || memberBinding.memberTemplateDigest !== ownerTemplate.memberTemplateDigest
      || reference.memberBindingDigest !== sha256(BUFFER_FROM(canonicalJson(memberBinding), 'utf8'))
    ) invalid();
  }
  deepFreezeJson(aggregate);
  return aggregate;
}

function readIntent(args) {
  const values = exactDataRecord(args, INTENT_ARG_KEYS);
  const authenticated = authenticateContractBytes({
    bytes: values.contractBytes,
    expectedDigest: values.expectedContractDigest,
    expectedEnvironmentDigest: values.expectedEnvironmentDigest,
  });
  if (
    typeof values.logicalResource !== 'string'
    || ![...V1_RESOURCES, ...V2_RESOURCES].includes(values.logicalResource)
  ) invalid();
  const envelope = exactDataRecord(values.value, INTENT_VALUE_KEYS);
  if (
    typeof envelope.expectedRowId !== 'string'
    || envelope.expectedRowId.length < 1
    || typeof envelope.expectedRunId !== 'string'
    || envelope.expectedRunId.length < 1
  ) invalid();
  const fields = exactDataRecord(envelope.rawRow, RAW_INTENT_KEYS);
  const expected = {
    expectedEnvironmentDigest: values.expectedEnvironmentDigest,
    expectedRowId: envelope.expectedRowId,
    expectedRunId: envelope.expectedRunId,
    logicalResource: values.logicalResource,
  };
  validateIntentCommon(fields, expected);

  let intent;
  let providerProjection = null;
  if (fields.schemaVersion === 'verification-intent-snapshot.v1') {
    if (
      !V1_RESOURCES.includes(values.logicalResource)
      || fields.providerAggregateJson !== null
      || fields.providerAggregateDigest !== null
    ) invalid();
    const providerIds = exactOrdinaryArray(fields.providerResourceIds);
    if (providerIds.some((value) => typeof value !== 'string')) invalid();
    intent = copyIntentProjection(fields, INTENT_V1_KEYS);
  } else if (fields.schemaVersion === 'verification-intent-snapshot.v2') {
    if (
      !V2_RESOURCES.includes(values.logicalResource)
      || fields.providerResourceIds !== null
      || fields.lifecycleClass !== 'fixture'
    ) invalid();
    const identity = deriveV2Identity(expected, values.logicalResource);
    const resourceContract = findResourceContract(authenticated.providerContract, values.logicalResource);
    if (
      fields.resourceId !== identity.resourceId
      || fields.ownerMarker !== identity.ownerMarker
      || fields.intentId !== identity.intentId
      || fields.$id !== identity.intentRowId
      || envelope.expectedRowId !== identity.intentRowId
      || fields.dependencyOrder !== resourceContract.dependencyOrder
    ) invalid();
    assertDigest(fields.providerAggregateDigest);
    providerProjection = parseProviderAggregate(fields, expected, authenticated.providerContract);
    intent = copyIntentProjection(fields, INTENT_V2_KEYS);
  } else {
    invalid();
  }
  return { expected, intent, providerProjection };
}

function validateIntent(args) {
  const parsed = readIntent(args);
  return parityDigest('validate-intent-row', {
    expectedEnvironmentDigest: parsed.expected.expectedEnvironmentDigest,
    logicalResource: parsed.expected.logicalResource,
    expectedRowId: parsed.expected.expectedRowId,
    expectedRunId: parsed.expected.expectedRunId,
    intent: parsed.intent,
  });
}

function validateProjection(args) {
  const parsed = readIntent(args);
  if (parsed.providerProjection === null) invalid();
  return parityDigest('validate-provider-projection', {
    expectedEnvironmentDigest: parsed.expected.expectedEnvironmentDigest,
    logicalResource: parsed.expected.logicalResource,
    expectedRowId: parsed.expected.expectedRowId,
    expectedRunId: parsed.expected.expectedRunId,
    providerProjection: parsed.providerProjection,
  });
}

const CLOCK_ARG_KEYS = Object.freeze([
  'contractBytes', 'expectedContractDigest', 'expectedEnvironmentDigest', 'value',
]);
const CLOCK_KEYS = Object.freeze([
  'baseUtc', 'environmentDigest', 'providerContractDigest', 'publishedAtByMutation',
  'runId', 'schemaVersion',
]);

function validateClock(args) {
  const values = exactDataRecord(args, CLOCK_ARG_KEYS);
  const authenticated = authenticateContractBytes({
    bytes: values.contractBytes,
    expectedDigest: values.expectedContractDigest,
    expectedEnvironmentDigest: values.expectedEnvironmentDigest,
  });
  const schedule = exactDataRecord(values.value, CLOCK_KEYS);
  if (
    schedule.schemaVersion !== 'verification-dashboard-clock-schedule.v1'
    || typeof schedule.runId !== 'string'
    || schedule.runId.length < 1
    || schedule.environmentDigest !== values.expectedEnvironmentDigest
    || schedule.providerContractDigest !== APPROVED_CONTRACT_DIGEST
    || typeof schedule.baseUtc !== 'string'
    || !RFC3339_MILLISECONDS.test(schedule.baseUtc)
  ) invalid();
  const baseTime = Date.parse(schedule.baseUtc);
  if (!Number.isFinite(baseTime) || new Date(baseTime).toISOString() !== schedule.baseUtc) invalid();
  const rows = exactOrdinaryArray(schedule.publishedAtByMutation);
  const offsets = authenticated.providerContract.fixtureClockPolicy.publishedAtOffsets;
  if (rows.length !== offsets.length) invalid();
  const copiedRows = [];
  for (let index = 0; index < offsets.length; index += 1) {
    const row = exactDataRecord(rows[index], ['mutationOrdinal', 'value']);
    const offset = offsets[index];
    const expectedValue = new Date(baseTime + offset.offsetMilliseconds).toISOString();
    if (row.mutationOrdinal !== offset.mutationOrdinal || row.value !== expectedValue) invalid();
    copiedRows.push({ mutationOrdinal: row.mutationOrdinal, value: row.value });
  }
  const fixtureClockSchedule = {
    schemaVersion: schedule.schemaVersion,
    runId: schedule.runId,
    environmentDigest: schedule.environmentDigest,
    providerContractDigest: schedule.providerContractDigest,
    baseUtc: schedule.baseUtc,
    publishedAtByMutation: copiedRows,
  };
  deepFreezeJson(fixtureClockSchedule);
  return parityDigest('validate-clock-schedule', {
    expectedEnvironmentDigest: values.expectedEnvironmentDigest,
    fixtureClockSchedule,
  });
}

const SETUP_ARG_KEYS = Object.freeze([
  'bytes', 'expectedDigest', 'expectedEnvironmentDigest', 'expectedProviderContractDigest',
]);
const SETUP_KEYS = Object.freeze([
  'browserRequestPolicy', 'controlDatabase', 'coreBindings', 'environmentDigest',
  'expectedRunnerVariables', 'genesis', 'identityBindings', 'nodeResponseFormat',
  'providerContractDigest', 'pythonRuntimeResponseFormat', 'schemaVersion',
]);
const BROWSER_ROW_KEYS = Object.freeze([
  'credentialCarrier', 'exactCount', 'expectedResponseStatus', 'finalUrl',
  'lifecyclePhase', 'method', 'ordinal', 'profileId', 'requestClass',
  'requestHeaderBindings', 'requestOpaqueHeaderRules', 'resourceType',
  'responseBodyDigest', 'responseByteLength', 'responseHeaderBindings',
  'responseMimeEssence', 'responseOpaqueHeaderRules',
]);
const PROFILE_BY_ORDINAL = Object.freeze([
  ...Array(25).fill('synthetic-immutable-asset'),
  'cors-preflight-owner-session-post',
  'owner-session-create',
  'cors-preflight-appwrite-prefs-get',
  'authenticated-appwrite-read',
  'cors-preflight-appwrite-multipart-post',
  'cors-preflight-appwrite-json-post',
  'cors-preflight-appwrite-json-post',
  'cors-preflight-appwrite-json-post',
  'cors-preflight-appwrite-json-patch',
  'cors-preflight-appwrite-json-patch',
  'cors-preflight-appwrite-json-patch',
  'cors-preflight-appwrite-function-json-post',
  'authenticated-appwrite-multipart-mutation',
  'authenticated-appwrite-multipart-mutation',
  'authenticated-appwrite-json-mutation',
  'authenticated-appwrite-json-mutation',
  'authenticated-appwrite-json-mutation',
  'authenticated-appwrite-json-mutation',
  'authenticated-appwrite-json-mutation',
  'authenticated-appwrite-multipart-mutation',
  'authenticated-appwrite-json-mutation',
  'authenticated-appwrite-json-mutation',
  'authenticated-appwrite-multipart-mutation',
  'authenticated-appwrite-json-mutation',
  'authenticated-appwrite-json-mutation',
  'authenticated-appwrite-json-mutation',
  'authenticated-appwrite-multipart-mutation',
  'authenticated-appwrite-json-mutation',
  'authenticated-appwrite-json-mutation',
  'authenticated-appwrite-function-json-mutation',
  'authenticated-appwrite-function-json-mutation',
]);

function validateBrowserProfile(row, index) {
  const profileId = PROFILE_BY_ORDINAL[index];
  if (profileId === undefined || row.profileId !== profileId) invalid();
  if (index <= 24) {
    if (
      row.requestClass !== (index === 0 ? 'main-document' : 'build-asset')
      || row.credentialCarrier !== 'none'
      || row.method !== 'GET'
      || row.lifecyclePhase !== (index <= 12
        ? 'APPLICATION_NAVIGATION'
        : index <= 21 ? 'OWNER_LOGIN' : 'APPLICATION_READ')
      || (index === 0 && row.resourceType !== 'document')
      || (index >= 22 && row.resourceType !== 'fetch')
      || (index > 0 && index < 22 && !['script', 'stylesheet', 'image'].includes(row.resourceType))
    ) invalid();
    return;
  }
  if ([25, 27, 29, 30, 31, 32, 33, 34, 35, 36].includes(index)) {
    if (
      row.requestClass !== 'cors-preflight'
      || row.credentialCarrier !== 'none'
      || row.method !== 'OPTIONS'
      || row.resourceType !== 'other'
      || row.lifecyclePhase !== (index <= 27 ? 'OWNER_LOGIN' : 'APPLICATION_MUTATION')
    ) invalid();
    return;
  }
  if (index === 26) {
    if (
      row.requestClass !== 'owner-session-create'
      || row.credentialCarrier !== 'raw-playwright-request-body-only'
      || row.method !== 'POST'
      || row.resourceType !== 'fetch'
      || row.lifecyclePhase !== 'OWNER_LOGIN'
    ) invalid();
    return;
  }
  if (index === 28) {
    if (
      row.requestClass !== 'appwrite-read'
      || row.credentialCarrier !== 'browser-cookie-jar-only'
      || row.method !== 'GET'
      || row.resourceType !== 'fetch'
      || row.lifecyclePhase !== 'OWNER_LOGIN'
    ) invalid();
    return;
  }
  const multipart = [37, 38, 44, 47, 51].includes(index);
  const patch = [46, 49, 50].includes(index);
  if (
    row.requestClass !== (multipart ? 'appwrite-multipart-mutation' : 'appwrite-json-mutation')
    || row.credentialCarrier !== 'browser-cookie-jar-only'
    || row.method !== (patch ? 'PATCH' : 'POST')
    || row.resourceType !== 'fetch'
    || row.lifecyclePhase !== 'APPLICATION_MUTATION'
  ) invalid();
}

function validateHeaderRows(rows, keys) {
  exactOrdinaryArray(rows);
  for (const row of rows) exactParsedRecord(row, keys);
}

function validateSetupProjection(setup, expectedEnvironmentDigest, expectedProviderContractDigest) {
  exactParsedRecord(setup, SETUP_KEYS);
  if (
    setup.schemaVersion !== 'test-cloud.setup-readback.v1'
    || setup.nodeResponseFormat !== '1.9.5'
    || setup.pythonRuntimeResponseFormat !== '1.8.0'
    || setup.environmentDigest !== expectedEnvironmentDigest
    || setup.providerContractDigest !== expectedProviderContractDigest
    || expectedProviderContractDigest !== APPROVED_CONTRACT_DIGEST
  ) invalid();

  const identity = exactParsedRecord(setup.identityBindings, [
    'identityBindingsDigest', 'sessionCounts',
  ]);
  assertDigest(identity.identityBindingsDigest);
  const sessionCounts = exactOrdinaryArray(identity.sessionCounts);
  if (sessionCounts.length !== 3) invalid();
  for (const [index, role] of ['editor', 'owner', 'viewer'].entries()) {
    const row = exactParsedRecord(sessionCounts[index], ['role', 'total']);
    if (row.role !== role || row.total !== 0) invalid();
  }

  const control = exactParsedRecord(setup.controlDatabase, [
    'enabled', 'id', 'permissions', 'tables',
  ]);
  if (control.id !== 'verification_control' || control.enabled !== true) invalid();
  if (exactOrdinaryArray(control.permissions).length !== 0) invalid();
  const tables = exactOrdinaryArray(control.tables);
  if (tables.length !== 3) invalid();
  for (const table of tables) {
    const record = exactParsedRecord(table, [
      'columns', 'enabled', 'id', 'indexes', 'permissions', 'rowSecurity',
    ]);
    if (typeof record.id !== 'string' || record.enabled !== true) invalid();
    exactOrdinaryArray(record.permissions);
    for (const column of exactOrdinaryArray(record.columns)) {
      exactParsedRecord(column, [
        'array', 'default', 'elements', 'encrypt', 'key', 'max', 'min',
        'required', 'size', 'type',
      ]);
    }
    for (const index of exactOrdinaryArray(record.indexes)) {
      exactParsedRecord(index, ['columns', 'key', 'orders', 'type']);
    }
  }

  const core = exactParsedRecord(setup.coreBindings, [
    'primaryDatabaseIdDigest', 'projectFilesBucket', 'tables',
  ]);
  assertDigest(core.primaryDatabaseIdDigest);
  const coreTables = exactOrdinaryArray(core.tables);
  const roles = [
    ['projects', 'projects'],
    ['project-shares', 'project_shares'],
    ['project-snapshots', 'project_snapshots'],
    ['project-artifacts', 'project_artifacts'],
    ['project-artifact-versions', 'project_artifact_versions'],
    ['project-artifact-references', 'project_artifact_references'],
  ];
  if (coreTables.length !== roles.length) invalid();
  for (let index = 0; index < roles.length; index += 1) {
    const row = exactParsedRecord(coreTables[index], [
      'enabled', 'idDigest', 'role', 'tableBinding',
    ]);
    if (row.role !== roles[index][0] || row.tableBinding !== roles[index][1] || row.enabled !== true) {
      invalid();
    }
    assertDigest(row.idDigest);
  }
  const bucket = exactParsedRecord(core.projectFilesBucket, [
    'allowedFileExtensions', 'antivirus', 'compression', 'enabled', 'encryption',
    'fileSecurity', 'idDigest', 'maximumFileSize', 'name', 'permissionsDigest',
    'transformations',
  ]);
  if (
    bucket.name !== 'project-files'
    || bucket.fileSecurity !== true
    || bucket.enabled !== true
    || bucket.maximumFileSize !== 52_428_800
    || exactOrdinaryArray(bucket.allowedFileExtensions).length !== 0
    || bucket.compression !== 'none'
    || bucket.encryption !== true
    || bucket.antivirus !== true
    || bucket.transformations !== true
  ) invalid();
  assertDigest(bucket.idDigest);
  assertDigest(bucket.permissionsDigest);

  const policy = exactParsedRecord(setup.browserRequestPolicy, [
    'digest', 'rows', 'schemaVersion', 'timeoutMilliseconds',
  ]);
  if (
    policy.schemaVersion !== 'test-cloud.browser-request-policy.v1'
    || policy.timeoutMilliseconds !== 5000
  ) invalid();
  const policyRows = exactOrdinaryArray(policy.rows);
  if (policyRows.length !== PROFILE_BY_ORDINAL.length) invalid();
  for (let index = 0; index < policyRows.length; index += 1) {
    const row = exactParsedRecord(policyRows[index], BROWSER_ROW_KEYS);
    if (
      row.ordinal !== index
      || !NUMBER_IS_SAFE_INTEGER(row.exactCount)
      || row.exactCount < 1
      || row.exactCount > 256
    ) invalid();
    validateBrowserProfile(row, index);
    validateHeaderRows(row.requestHeaderBindings, ['name', 'valueDigest']);
    validateHeaderRows(row.responseHeaderBindings, ['name', 'valueDigest']);
    validateHeaderRows(row.requestOpaqueHeaderRules, [
      'kind', 'maximumCount', 'minimumCount', 'name',
    ]);
    validateHeaderRows(row.responseOpaqueHeaderRules, [
      'kind', 'maximumCount', 'minimumCount', 'name',
    ]);
  }
  assertDigest(policy.digest);
  if (policy.digest !== sha256(BUFFER_FROM(canonicalJson({
    schemaVersion: policy.schemaVersion,
    timeoutMilliseconds: policy.timeoutMilliseconds,
    rows: policy.rows,
  }), 'utf8'))) invalid();

  const variables = exactParsedRecord(setup.expectedRunnerVariables, [
    'identityQualifiedKey', 'staticTotal', 'total', 'variables',
  ]);
  if (
    variables.total !== 16
    || variables.staticTotal !== 15
    || variables.identityQualifiedKey !== 'VERIFICATION_IDENTITY_BINDINGS_DIGEST'
  ) invalid();
  const variableRows = exactOrdinaryArray(variables.variables);
  if (variableRows.length !== 16) invalid();
  let previousKey = null;
  for (const row of variableRows) {
    exactParsedRecord(row, ['key', 'valueDigest']);
    if (
      typeof row.key !== 'string'
      || row.key.length < 1
      || (previousKey !== null && compareOrdinal(previousKey, row.key) >= 0)
    ) invalid();
    assertDigest(row.valueDigest);
    previousKey = row.key;
  }
  if (!variableRows.some(({ key }) => key === variables.identityQualifiedKey)) invalid();

  const genesis = exactParsedRecord(setup.genesis, [
    'dataDigest', 'permissions', 'rowId', 'tableId',
  ]);
  if (
    genesis.tableId !== 'verification_leases'
    || genesis.rowId !== 'appwrite_test_verification'
    || exactOrdinaryArray(genesis.permissions).length !== 0
  ) invalid();
  assertDigest(genesis.dataDigest);
  deepFreezeJson(setup);
  return setup;
}

function readValidatedSetup(args) {
  const values = exactDataRecord(args, SETUP_ARG_KEYS);
  assertDigest(values.expectedDigest);
  assertDigest(values.expectedEnvironmentDigest);
  assertDigest(values.expectedProviderContractDigest);
  if (values.bytes === null || typeof values.bytes !== 'object' || isProxy(values.bytes)) invalid();
  const byteLength = typedArrayByteLength(values.bytes);
  if (byteLength < 1 || byteLength > 1_048_576) invalid();
  const stableBytes = copyTypedArray(values.bytes, byteLength);
  if (
    (stableBytes[0] === 0xef && stableBytes[1] === 0xbb && stableBytes[2] === 0xbf)
    || REFLECT_APPLY(UINT8_ARRAY_INCLUDES, stableBytes, [0x0d])
  ) invalid();
  const actualDigest = sha256(stableBytes);
  if (actualDigest !== values.expectedDigest) invalid();
  let text;
  try {
    text = REFLECT_APPLY(TEXT_DECODER_DECODE, UTF8_DECODER, [stableBytes]);
  } catch {
    invalid();
  }
  const setup = parseClosedJson(text);
  if (canonicalJson(setup) !== text) invalid();
  validateSetupProjection(
    setup,
    values.expectedEnvironmentDigest,
    values.expectedProviderContractDigest,
  );
  return {
    outputDigest: parityDigest('validate-setup-readback-bytes', {
      expectedEnvironmentDigest: values.expectedEnvironmentDigest,
      providerSetupReadback: setup,
    }),
    providerSetupReadback: setup,
  };
}

function safePureValidator(validateOperation, args) {
  try {
    return pass(validateOperation(args));
  } catch (error) {
    if (error instanceof ContractValidationError) return blocked();
    throw error;
  }
}

const PROVIDER_LOAD_KEYS = OBJECT_FREEZE(['runtimeQualification', 'context']);
const SETUP_LOAD_KEYS = OBJECT_FREEZE(['runtimeQualification', 'context', 'providerContract', 'identityBindings']);
const PROVIDER_EXPECTED_KEYS = OBJECT_FREEZE(['runtimeQualification', 'expectedDigest', 'expectedEnvironmentDigest']);
const SETUP_EXPECTED_KEYS = OBJECT_FREEZE(['runtimeQualification', 'expectedContractDigest', 'expectedDigest', 'expectedEnvironmentDigest', 'expectedIdentityBindingsDigest', 'expectedRunnerVariableExpectationDigest']);
const PROVIDER_AUTH_KEYS = OBJECT_FREEZE(['runtimeQualification', 'context', 'providerContractQualification', 'expectedEnvironmentDigest', 'expectedProviderContractDigest']);
const RUNNER_VARIABLE_EVIDENCE_KEYS = OBJECT_FREEZE([
  'runtimeQualification',
  'context',
  'providerContract',
  'identityBindings',
  'providerSetupReadback',
]);
function activeQualificationIs(value) { return runtimeRecord.state === 'ACTIVE' && activationState === 'COMMITTED' && futureBootstrapHub === undefined && OBJECT_IS(value, activeRuntimeQualification); }
function loadBlocked(kind, code) {
  const provider = kind === 'provider';
  const current = provider ? providerLoadRecord : setupLoadRecord;
  if (current.state !== 'BLOCKED') {
    if (current.qualification !== undefined) (provider ? PROVIDER_QUALIFICATIONS : SETUP_QUALIFICATIONS).delete(current.qualification);
    const next = OBJECT_FREEZE({ state: 'BLOCKED', version: current.version + 1 });
    if (provider) providerLoadRecord = next; else setupLoadRecord = next;
  }
  terminallyBlockRuntime();
  return runtimeBlockedResult(provider ? undefined : code);
}
function exactResultRecord(value, keys) {
  if (value === null || typeof value !== 'object' || isProxy(value) || OBJECT_IS_FROZEN(value) !== true) return null;
  const prototype = OBJECT_GET_PROTOTYPE_OF(value);
  if (prototype !== OBJECT_PROTOTYPE && prototype !== null) return null;
  const ownKeys = REFLECT_OWN_KEYS(value);
  if (ownKeys.length !== keys.length) return null;
  const output = OBJECT_CREATE(null);
  for (const key of keys) {
    const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(value, key);
    if (descriptor === undefined || REFLECT_HAS(descriptor, 'value') !== true || descriptor.enumerable !== true) return null;
    output[key] = descriptor.value;
  }
  return output;
}
function readClosedPass(resultValue, valueKeys) {
  const result = exactResultRecord(resultValue, ['status', 'value', 'diagnostics']);
  if (result === null || result.status !== 'PASS' || !exactDenseFrozenArray(result.diagnostics) || result.diagnostics.length !== 0) return null;
  const value = exactResultRecord(result.value, valueKeys);
  return value === null ? null : { result: resultValue, value };
}
function providerRecordFor(qualification) {
  try {
    const record = PROVIDER_QUALIFICATIONS.get(qualification);
    return record !== undefined && record.state === 'QUALIFIED' && OBJECT_IS(record, providerLoadRecord) && OBJECT_IS(record.qualification, qualification) && OBJECT_IS(PROVIDER_TUPLES.get(record.context), record) ? record : undefined;
  } catch { return undefined; }
}
function setupRecordFor(qualification) {
  try {
    const record = SETUP_QUALIFICATIONS.get(qualification);
    return record !== undefined && record.state === 'QUALIFIED' && OBJECT_IS(record, setupLoadRecord) && OBJECT_IS(record.qualification, qualification) && OBJECT_IS(SETUP_TUPLES.get(record.context), record) ? record : undefined;
  } catch { return undefined; }
}
function providerExpectedSnapshot(expected) {
  const fields = exactDataRecord(expected, PROVIDER_EXPECTED_KEYS);
  if (!exactDigestString(fields.expectedDigest) || !exactDigestString(fields.expectedEnvironmentDigest)) invalid();
  return fields;
}
function setupExpectedSnapshot(expected) {
  const fields = exactDataRecord(expected, SETUP_EXPECTED_KEYS);
  for (const key of SETUP_EXPECTED_KEYS.slice(1)) if (!exactDigestString(fields[key])) invalid();
  return fields;
}
function providerQualificationMatches(qualification, expected) {
  const fields = providerExpectedSnapshot(expected);
  if (!activeQualificationIs(fields.runtimeQualification)) return false;
  const record = providerRecordFor(qualification);
  return record !== undefined && OBJECT_IS(record.runtimeQualification, fields.runtimeQualification) && record.providerContractDigest === fields.expectedDigest && record.environmentDigest === fields.expectedEnvironmentDigest;
}
function setupQualificationMatches(qualification, expected) {
  const fields = setupExpectedSnapshot(expected);
  if (!activeQualificationIs(fields.runtimeQualification)) return false;
  const record = setupRecordFor(qualification);
  return record !== undefined && OBJECT_IS(record.runtimeQualification, fields.runtimeQualification) && record.providerContractDigest === fields.expectedContractDigest && record.providerSetupReadbackDigest === fields.expectedDigest && record.environmentDigest === fields.expectedEnvironmentDigest && record.identityBindingsDigest === fields.expectedIdentityBindingsDigest && record.runnerVariableExpectationDigest === fields.expectedRunnerVariableExpectationDigest;
}
function authenticateProviderQualificationRecord(args) {
  try {
    const fields = exactDataRecord(args, PROVIDER_AUTH_KEYS);
    if (!activeQualificationIs(fields.runtimeQualification) || !exactDigestString(fields.expectedEnvironmentDigest) || !exactDigestString(fields.expectedProviderContractDigest)) return false;
    const record = providerRecordFor(fields.providerContractQualification);
    return record !== undefined && OBJECT_IS(record.runtimeQualification, fields.runtimeQualification) && OBJECT_IS(record.context, fields.context) && record.environmentDigest === fields.expectedEnvironmentDigest && record.providerContractDigest === fields.expectedProviderContractDigest;
  } catch { return false; }
}
async function authenticEnvironmentContext(context) {
  const namespace = await import(TEST_CLOUD_ENVIRONMENT_URL);
  const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(namespace, 'isAuthenticTestEnvironmentContext');
  return descriptor !== undefined && REFLECT_HAS(descriptor, 'value') === true && typeof descriptor.value === 'function' && REFLECT_APPLY(descriptor.value, namespace, [context]) === true;
}
function identityQualificationMatches(args) {
  try {
    if (canonicalIdentityBindingsNamespace === undefined) return false;
    const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(canonicalIdentityBindingsNamespace, 'isQualifiedTestCloudIdentityBindings');
    return descriptor !== undefined && REFLECT_HAS(descriptor, 'value') === true && typeof descriptor.value === 'function' && REFLECT_APPLY(descriptor.value, canonicalIdentityBindingsNamespace, [args]) === true;
  } catch { return false; }
}
function readProtectedSetupValue(name) {
  const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(PROCESS_ENV, name);
  if (descriptor === undefined || REFLECT_HAS(descriptor, 'value') !== true || typeof descriptor.value !== 'string') invalid();
  assertScalarString(descriptor.value);
  return descriptor.value;
}
export async function loadQualifiedTestCloudProviderContract(args) {
  if (providerLoadRecord.state !== 'EMPTY') return loadBlocked('provider');
  try {
    if (arguments.length !== 1 || !currentPublicOperationAuthorized(args, PROVIDER_LOAD_KEYS)) return loadBlocked('provider');
    const context = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(args, 'context').value;
    const runtimeQualification = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(args, 'runtimeQualification').value;
    if (context === null || typeof context !== 'object' || isProxy(context) || PROVIDER_TUPLES.get(context) !== undefined) return loadBlocked('provider');
    const reservation = OBJECT_FREEZE({ state: 'RESERVING', version: 1, runtimeQualification, context });
    providerLoadRecord = reservation; PROVIDER_TUPLES.set(context, reservation);
    if (!OBJECT_IS(providerLoadRecord, reservation) || !OBJECT_IS(PROVIDER_TUPLES.get(context), reservation)) return loadBlocked('provider');
    if (!await authenticEnvironmentContext(context) || !OBJECT_IS(providerLoadRecord, reservation) || !activeQualificationIs(runtimeQualification) || !exactDigestString(context.environmentDigest)) return loadBlocked('provider');
    const reading = OBJECT_FREEZE({ state: 'READING', version: 2, runtimeQualification, context });
    providerLoadRecord = reading; PROVIDER_TUPLES.set(context, reading);
    const bytes = await READ_FILE(TEST_CLOUD_PROVIDER_CONTRACT_DATA_PATH);
    if (!OBJECT_IS(providerLoadRecord, reading) || !activeQualificationIs(runtimeQualification)) return loadBlocked('provider');
    const authenticated = authenticateContractBytes({ bytes, expectedDigest: APPROVED_CONTRACT_DIGEST, expectedEnvironmentDigest: context.environmentDigest });
    const qualification = OBJECT_FREEZE(OBJECT_CREATE(null));
    const passResult = runtimeOperationPassResult(['qualification', 'providerContractDigest'], { qualification, providerContractDigest: APPROVED_CONTRACT_DIGEST });
    const qualified = OBJECT_FREEZE({ state: 'QUALIFIED', version: 3, runtimeQualification, context, environmentDigest: context.environmentDigest, providerContractDigest: APPROVED_CONTRACT_DIGEST, providerContract: authenticated.providerContract, qualification, passResult });
    providerLoadRecord = qualified; PROVIDER_TUPLES.set(context, qualified); PROVIDER_QUALIFICATIONS.set(qualification, qualified);
    if (!OBJECT_IS(providerLoadRecord, qualified) || !OBJECT_IS(PROVIDER_TUPLES.get(context), qualified) || !OBJECT_IS(PROVIDER_QUALIFICATIONS.get(qualification), qualified)) return loadBlocked('provider');
    return passResult;
  } catch { return loadBlocked('provider'); }
}
export function loadQualifiedTestCloudSetupReadback(args) {
  let failureCode = 'TEST_CLOUD_SETUP_REQUEST_INVALID';
  if (setupLoadRecord.state !== 'EMPTY') {
    return loadBlocked('setup', 'TEST_CLOUD_SETUP_REQUEST_INVALID');
  }
  try {
    if (arguments.length !== 1 || !currentPublicOperationAuthorized(args, SETUP_LOAD_KEYS)) {
      return loadBlocked('setup', 'TEST_CLOUD_SETUP_REQUEST_INVALID');
    }
    const runtimeQualification = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(args, 'runtimeQualification').value;
    const context = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(args, 'context').value;
    const providerPass = readClosedPass(OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(args, 'providerContract').value, ['qualification', 'providerContractDigest']);
    const identityPass = readClosedPass(OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(args, 'identityBindings').value, ['qualification', 'identityBindingsDigest']);
    if (providerPass === null || identityPass === null || !exactDigestString(providerPass.value.providerContractDigest) || !exactDigestString(identityPass.value.identityBindingsDigest) || SETUP_TUPLES.get(context) !== undefined) {
      return loadBlocked('setup', 'TEST_CLOUD_SETUP_REQUEST_INVALID');
    }
    failureCode = 'TEST_CLOUD_SETUP_PROVIDER_BINDING_INVALID';
    const providerRecord = providerRecordFor(providerPass.value.qualification);
    if (providerRecord === undefined || !OBJECT_IS(providerRecord.passResult, providerPass.result) || !OBJECT_IS(providerRecord.context, context) || !OBJECT_IS(providerRecord.runtimeQualification, runtimeQualification)) {
      return loadBlocked('setup', 'TEST_CLOUD_SETUP_PROVIDER_BINDING_INVALID');
    }
    failureCode = 'TEST_CLOUD_SETUP_RUNTIME_STATE_INVALID';
    const reservation = OBJECT_FREEZE({ state: 'RESERVING', version: 1, runtimeQualification, context });
    setupLoadRecord = reservation; SETUP_TUPLES.set(context, reservation);
    if (!OBJECT_IS(setupLoadRecord, reservation) || !OBJECT_IS(SETUP_TUPLES.get(context), reservation) || !activeQualificationIs(runtimeQualification)) {
      return loadBlocked('setup', 'TEST_CLOUD_SETUP_RUNTIME_STATE_INVALID');
    }
    failureCode = 'TEST_CLOUD_SETUP_IDENTITY_QUALIFICATION_INVALID';
    if (!identityQualificationMatches({ runtimeQualification, qualification: identityPass.value.qualification, context, providerContractQualification: providerPass.value.qualification, expectedEnvironmentDigest: providerRecord.environmentDigest, expectedProviderContractDigest: providerRecord.providerContractDigest, expectedIdentityBindingsDigest: identityPass.value.identityBindingsDigest })) {
      return loadBlocked('setup', 'TEST_CLOUD_SETUP_IDENTITY_QUALIFICATION_INVALID');
    }
    if (!OBJECT_IS(setupLoadRecord, reservation) || !OBJECT_IS(SETUP_TUPLES.get(context), reservation) || !activeQualificationIs(runtimeQualification)) {
      return loadBlocked('setup', 'TEST_CLOUD_SETUP_RUNTIME_STATE_INVALID');
    }
    failureCode = 'TEST_CLOUD_SETUP_ENVIRONMENT_BINDING_INVALID';
    const reading = OBJECT_FREEZE({ state: 'READING', version: 2, runtimeQualification, context });
    setupLoadRecord = reading; SETUP_TUPLES.set(context, reading);
    if (!OBJECT_IS(setupLoadRecord, reading) || !OBJECT_IS(SETUP_TUPLES.get(context), reading) || !activeQualificationIs(runtimeQualification)) {
      return loadBlocked('setup', 'TEST_CLOUD_SETUP_RUNTIME_STATE_INVALID');
    }
    const setupJson = readProtectedSetupValue('TEST_CLOUD_SETUP_READBACK_JSON');
    const expectedDigest = readProtectedSetupValue('TEST_CLOUD_SETUP_READBACK_DIGEST');
    if (!exactDigestString(expectedDigest)) {
      return loadBlocked('setup', 'TEST_CLOUD_SETUP_ENVIRONMENT_BINDING_INVALID');
    }
    if (!OBJECT_IS(setupLoadRecord, reading) || !activeQualificationIs(runtimeQualification)) {
      return loadBlocked('setup', 'TEST_CLOUD_SETUP_RUNTIME_STATE_INVALID');
    }
    failureCode = 'TEST_CLOUD_SETUP_PAYLOAD_INVALID';
    const bytes = BUFFER_FROM(setupJson, 'utf8');
    if (bytes.length < 1 || bytes.length > 1_048_576 || REFLECT_APPLY(BUFFER_TO_STRING, bytes, ['utf8']) !== setupJson) {
      return loadBlocked('setup', 'TEST_CLOUD_SETUP_PAYLOAD_INVALID');
    }
    const validated = readValidatedSetup({ bytes, expectedDigest, expectedEnvironmentDigest: providerRecord.environmentDigest, expectedProviderContractDigest: providerRecord.providerContractDigest });
    const setup = validated.providerSetupReadback;
    failureCode = 'TEST_CLOUD_SETUP_IDENTITY_DIGEST_MISMATCH';
    if (setup.identityBindings.identityBindingsDigest !== identityPass.value.identityBindingsDigest) {
      return loadBlocked('setup', 'TEST_CLOUD_SETUP_IDENTITY_DIGEST_MISMATCH');
    }
    failureCode = 'TEST_CLOUD_SETUP_FINALIZATION_INVALID';
    const runnerVariableExpectationDigest = sha256(BUFFER_FROM(canonicalJson(setup.expectedRunnerVariables), 'utf8'));
    const qualification = OBJECT_FREEZE(OBJECT_CREATE(null));
    const passResult = runtimeOperationPassResult(['qualification', 'identityBindingsDigest', 'providerSetupReadbackDigest', 'runnerVariableExpectationDigest'], { qualification, identityBindingsDigest: identityPass.value.identityBindingsDigest, providerSetupReadbackDigest: expectedDigest, runnerVariableExpectationDigest });
    const qualified = OBJECT_FREEZE({ state: 'QUALIFIED', version: 3, runtimeQualification, context, providerQualification: providerPass.value.qualification, identityQualification: identityPass.value.qualification, identityPassResult: identityPass.result, environmentDigest: providerRecord.environmentDigest, providerContractDigest: providerRecord.providerContractDigest, identityBindingsDigest: identityPass.value.identityBindingsDigest, providerSetupReadbackDigest: expectedDigest, runnerVariableExpectationDigest, qualification, passResult });
    setupLoadRecord = qualified; SETUP_TUPLES.set(context, qualified); SETUP_QUALIFICATIONS.set(qualification, qualified);
    if (!OBJECT_IS(setupLoadRecord, qualified) || !OBJECT_IS(SETUP_TUPLES.get(context), qualified) || !OBJECT_IS(SETUP_QUALIFICATIONS.get(qualification), qualified)) {
      return loadBlocked('setup', 'TEST_CLOUD_SETUP_FINALIZATION_INVALID');
    }
    return passResult;
  } catch { return loadBlocked('setup', failureCode); }
}
function authenticateRunnerVariableReadbackRequestEvidence(args) {
  try {
    if (
      arguments.length !== 1
      || !OBJECT_IS(this, runnerVariableAuthorityReceiver)
      || !currentPublicOperationAuthorized(args, RUNNER_VARIABLE_EVIDENCE_KEYS)
    ) return false;
    const runtimeQualification = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
      args,
      'runtimeQualification',
    ).value;
    const context = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(args, 'context').value;
    const providerPass = readClosedPass(
      OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(args, 'providerContract').value,
      ['qualification', 'providerContractDigest'],
    );
    const identityPass = readClosedPass(
      OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(args, 'identityBindings').value,
      ['qualification', 'identityBindingsDigest'],
    );
    const setupPass = readClosedPass(
      OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(args, 'providerSetupReadback').value,
      [
        'qualification',
        'identityBindingsDigest',
        'providerSetupReadbackDigest',
        'runnerVariableExpectationDigest',
      ],
    );
    if (providerPass === null || identityPass === null || setupPass === null) return false;
    const providerRecord = providerRecordFor(providerPass.value.qualification);
    const setupRecord = setupRecordFor(setupPass.value.qualification);
    if (
      providerRecord === undefined
      || setupRecord === undefined
      || !OBJECT_IS(providerRecord.passResult, providerPass.result)
      || !OBJECT_IS(setupRecord.passResult, setupPass.result)
      || !OBJECT_IS(setupRecord.identityPassResult, identityPass.result)
      || !OBJECT_IS(providerRecord.runtimeQualification, runtimeQualification)
      || !OBJECT_IS(setupRecord.runtimeQualification, runtimeQualification)
      || !OBJECT_IS(providerRecord.context, context)
      || !OBJECT_IS(setupRecord.context, context)
      || !OBJECT_IS(
        setupRecord.providerQualification,
        providerPass.value.qualification,
      )
      || !OBJECT_IS(
        setupRecord.identityQualification,
        identityPass.value.qualification,
      )
      || providerRecord.environmentDigest !== setupRecord.environmentDigest
      || providerRecord.providerContractDigest !== setupRecord.providerContractDigest
      || providerPass.value.providerContractDigest !== providerRecord.providerContractDigest
      || identityPass.value.identityBindingsDigest !== setupRecord.identityBindingsDigest
      || setupPass.value.identityBindingsDigest !== setupRecord.identityBindingsDigest
      || setupPass.value.providerSetupReadbackDigest
        !== setupRecord.providerSetupReadbackDigest
      || setupPass.value.runnerVariableExpectationDigest
        !== setupRecord.runnerVariableExpectationDigest
    ) return false;
    const identityMatches = identityQualificationMatches(createClosedOrdinaryRecord([
      'runtimeQualification',
      'qualification',
      'context',
      'providerContractQualification',
      'expectedEnvironmentDigest',
      'expectedProviderContractDigest',
      'expectedIdentityBindingsDigest',
    ], {
      runtimeQualification,
      qualification: identityPass.value.qualification,
      context,
      providerContractQualification: providerPass.value.qualification,
      expectedEnvironmentDigest: providerRecord.environmentDigest,
      expectedProviderContractDigest: providerRecord.providerContractDigest,
      expectedIdentityBindingsDigest: setupRecord.identityBindingsDigest,
    }));
    if (identityMatches !== true) return false;
    const currentProviderRecord = providerRecordFor(providerPass.value.qualification);
    const currentSetupRecord = setupRecordFor(setupPass.value.qualification);
    return activeQualificationIs(runtimeQualification)
      && OBJECT_IS(currentProviderRecord, providerRecord)
      && OBJECT_IS(currentSetupRecord, setupRecord)
      && OBJECT_IS(currentProviderRecord.passResult, providerPass.result)
      && OBJECT_IS(currentSetupRecord.passResult, setupPass.result)
      && OBJECT_IS(currentSetupRecord.identityPassResult, identityPass.result);
  } catch {
    return false;
  }
}
export function isQualifiedTestCloudProviderContract(qualification, expected) {
  try { return arguments.length === 2 && providerQualificationMatches(qualification, expected); } catch { return false; }
}
export function isQualifiedTestCloudSetupReadback(qualification, expected) {
  try { return arguments.length === 2 && setupQualificationMatches(qualification, expected); } catch { return false; }
}
export function validateTestCloudIntentRow(args) {
  return safePureValidator(validateIntent, args);
}

export function validateTestCloudProviderProjection(args) {
  return safePureValidator(validateProjection, args);
}

export function validateTestCloudFixtureClockSchedule(args) {
  return safePureValidator(validateClock, args);
}

export function validateTestCloudSetupReadbackBytes(args) {
  return safePureValidator((value) => readValidatedSetup(value).outputDigest, args);
}
export function validateTestCloudProviderContractBytes(args) {
  try {
    return pass(validate(args));
  } catch (error) {
    if (error instanceof ContractValidationError) return blocked();
    throw error;
  }
}
