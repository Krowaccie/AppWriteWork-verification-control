import { types as utilTypes } from 'node:util';

const authorityStates = new WeakMap();
const leaseStates = new WeakMap();
const NativeArray = Array;
const arrayIsArray = Array.isArray;
const arrayPush = Array.prototype.push;
const arraySome = Array.prototype.some;
const isProxy = utilTypes.isProxy;
const objectCreate = Object.create;
const objectEntries = Object.entries;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const ARTIFACT_NAME = /^verification-artifacts-[0-9a-f]{40}$/u;
const MEMBER_IDS = objectFreeze([
  'site:web',
  'function:api-keys-py',
  'function:api-router-py',
  'function:billing-cron-py',
  'function:billing-py',
  'function:billing-webhook-py',
  'function:branch-py',
  'function:cache-cleanup-cron-py',
  'function:catalog-py',
  'function:chat-py',
  'function:cleanup-cron-py',
  'function:connections-py',
  'function:finance-sync-sec-py',
  'function:finance-sync-wb-py',
  'function:flowise-runner-py',
  'function:mcp-cleanup-cron-py',
  'function:mcp-gateway-py',
  'function:project-public-links-py',
  'function:project-public-read-py',
  'function:project-snapshots-py',
  'function:runs-cancel-py',
  'function:runs-clear-py',
  'function:runs-create-py',
  'function:runs-detail-py',
  'function:runs-list-py',
  'function:runs-status-py',
  'function:runs-steps-py',
  'function:sec-cache-builder-py',
  'function:sharing-py',
  'function:smtp-diagnostic-py',
  'function:telemetry-py',
  'function:usage-cron-py',
  'function:usage-py',
  'function:validate-py',
  'function:verification-email-py',
  'function:worker-cron-py',
  'function:verification-runner-py',
  'metadata:artifact-manifest',
  'metadata:artifact-handoff',
]);

function nullRecord(fields = {}) {
  const result = objectCreate(null);
  const entries = objectEntries(fields);
  for (let index = 0; index < entries.length; index += 1) {
    result[entries[index][0]] = entries[index][1];
  }
  return objectFreeze(result);
}

function exactFrozenObject(value, keys) {
  try {
    if (isProxy(value) || value === null || typeof value !== 'object' || !objectIsFrozen(value)) return null;
    const actual = reflectOwnKeys(value);
    if (
      actual.length !== keys.length
      || reflectApply(arraySome, actual, [(key) => typeof key !== 'string'])
      || reflectApply(arraySome, keys, [(key) => !objectHasOwn(value, key)])
    ) return null;
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      const descriptor = objectGetOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !objectHasOwn(descriptor, 'value') || !descriptor.enumerable) return null;
    }
    return value;
  } catch {
    return null;
  }
}

function memberPath(memberId) {
  if (memberId === 'site:web') return 'site/site.tar.gz';
  if (memberId === 'metadata:artifact-manifest') return 'artifact-manifest.v1.json';
  if (memberId === 'metadata:artifact-handoff') return 'artifact-handoff.v1.json';
  return `functions/${memberId.slice('function:'.length)}.tar.gz`;
}

function snapshotMembers(value) {
  try {
    if (isProxy(value) || !arrayIsArray(value) || !objectIsFrozen(value)) return null;
    const ownKeys = reflectOwnKeys(value);
    const length = objectGetOwnPropertyDescriptor(value, 'length');
    if (
      ownKeys.length !== MEMBER_IDS.length + 1
      || length === undefined
      || !objectHasOwn(length, 'value')
      || length.value !== MEMBER_IDS.length
    ) return null;
    const members = new NativeArray();
    for (let index = 0; index < MEMBER_IDS.length; index += 1) {
      const member = objectGetOwnPropertyDescriptor(value, String(index));
      if (
        member === undefined
        || !objectHasOwn(member, 'value')
        || !member.enumerable
      ) return null;
      const input = exactFrozenObject(member.value, [
        'memberId', 'relativePath', 'sizeBytes', 'transportDigest',
      ]);
      if (
        input === null
        || input.memberId !== MEMBER_IDS[index]
        || input.relativePath !== memberPath(input.memberId)
        || !Number.isSafeInteger(input.sizeBytes)
        || input.sizeBytes < 1
        || typeof input.transportDigest !== 'string'
        || !DIGEST.test(input.transportDigest)
      ) return null;
      reflectApply(arrayPush, members, [nullRecord({
        memberId: input.memberId,
        relativePath: input.relativePath,
        sizeBytes: input.sizeBytes,
        transportDigest: input.transportDigest,
      })]);
    }
    return objectFreeze(members);
  } catch {
    return null;
  }
}

function retainedOutputCapability(value) {
  try {
    if (
      isProxy(value)
      || value === null
      || typeof value !== 'object'
      || !objectIsFrozen(value)
    ) return null;
    const readMember = objectGetOwnPropertyDescriptor(value, 'readMember');
    const revalidate = objectGetOwnPropertyDescriptor(value, 'revalidate');
    if (
      readMember === undefined
      || revalidate === undefined
      || !objectHasOwn(readMember, 'value')
      || !objectHasOwn(revalidate, 'value')
      || typeof readMember.value !== 'function'
      || typeof revalidate.value !== 'function'
      || isProxy(readMember.value)
      || isProxy(revalidate.value)
    ) return null;
    return nullRecord({
      readMember: readMember.value,
      receiver: value,
      revalidate: revalidate.value,
    });
  } catch {
    return null;
  }
}

function authorityState(capability, role) {
  if (capability === null || (typeof capability !== 'object' && typeof capability !== 'function')) return null;
  const binding = authorityStates.get(capability);
  return binding !== undefined && binding.role === role ? binding.state : null;
}

export function createPublicationLeaseAuthority() {
  const launcherAuthority = nullRecord();
  const publisherAuthority = nullRecord();
  const state = { launcher: null, publisher: null };
  authorityStates.set(launcherAuthority, { role: 'launcher', state });
  authorityStates.set(publisherAuthority, { role: 'publisher', state });
  return nullRecord({ launcherAuthority, publisherAuthority });
}

export function isPublicationLeaseLauncherAuthority(value) {
  return authorityState(value, 'launcher') !== null;
}

export function isPublicationLeasePublisherAuthority(value) {
  return authorityState(value, 'publisher') !== null;
}

export function registerPublicationPublisher(publisherAuthority, publisher) {
  const state = authorityState(publisherAuthority, 'publisher');
  if (
    state === null
    || publisher === null
    || (typeof publisher !== 'object' && typeof publisher !== 'function')
    || isProxy(publisher)
    || (state.publisher !== null && state.publisher !== publisher)
  ) return false;
  state.publisher = publisher;
  return true;
}

export function registerPublicationLauncher(launcherAuthority, launcher) {
  const state = authorityState(launcherAuthority, 'launcher');
  if (
    state === null
    || launcher === null
    || (typeof launcher !== 'object' && typeof launcher !== 'function')
    || isProxy(launcher)
    || (state.launcher !== null && state.launcher !== launcher)
  ) return false;
  state.launcher = launcher;
  return true;
}

export function issuePublicationLease(
  launcherAuthority,
  launcher,
  publisher,
  input,
) {
  const authority = authorityState(launcherAuthority, 'launcher');
  if (
    authority === null
    || authority.launcher !== launcher
    || authority.publisher !== publisher
  ) return null;
  const value = exactFrozenObject(input, [
    'artifactManifestDigest', 'artifactName', 'members', 'publisher', 'retainedOutput', 'session', 'workspaceOutput',
  ]);
  const members = value === null ? null : snapshotMembers(value.members);
  const retainedOutput = value === null ? null : retainedOutputCapability(value.retainedOutput);
  if (
    value === null
    || value.publisher !== publisher
    || members === null
    || retainedOutput === null
    || launcher === null
    || (typeof launcher !== 'object' && typeof launcher !== 'function')
    || isProxy(launcher)
    || value.session === null
    || typeof value.session !== 'object'
    || isProxy(value.session)
    || value.workspaceOutput === null
    || typeof value.workspaceOutput !== 'object'
    || isProxy(value.workspaceOutput)
    || typeof value.artifactName !== 'string'
    || !ARTIFACT_NAME.test(value.artifactName)
    || typeof value.artifactManifestDigest !== 'string'
    || !DIGEST.test(value.artifactManifestDigest)
  ) return null;
  const lease = nullRecord();
  leaseStates.set(lease, {
    artifactManifestDigest: value.artifactManifestDigest,
    artifactName: value.artifactName,
    authority,
    completed: false,
    consumed: false,
    launcher,
    members,
    publisher,
    retainedOutput,
    session: value.session,
    workspaceOutput: value.workspaceOutput,
  });
  return lease;
}

export function consumePublicationLease(publisherAuthority, lease, publisher) {
  const authority = authorityState(publisherAuthority, 'publisher');
  if (authority === null || lease === null || (typeof lease !== 'object' && typeof lease !== 'function')) return null;
  const state = leaseStates.get(lease);
  if (
    state === undefined
    || state.authority !== authority
    || state.publisher !== publisher
    || authority.publisher !== publisher
    || state.consumed
  ) return null;
  state.consumed = true;
  return nullRecord({
    artifactManifestDigest: state.artifactManifestDigest,
    artifactName: state.artifactName,
    members: state.members,
    retainedOutput: state.retainedOutput,
  });
}

export function completePublicationLease(publisherAuthority, lease, publisher) {
  const authority = authorityState(publisherAuthority, 'publisher');
  const state = lease !== null && (typeof lease === 'object' || typeof lease === 'function')
    ? leaseStates.get(lease)
    : undefined;
  if (
    authority === null
    || state === undefined
    || state.authority !== authority
    || state.publisher !== publisher
    || !state.consumed
    || state.completed
  ) return false;
  state.completed = true;
  return true;
}

export function verifyPublicationLeaseCompletion(
  launcherAuthority,
  lease,
  launcher,
  publisher,
) {
  const authority = authorityState(launcherAuthority, 'launcher');
  const state = lease !== null && (typeof lease === 'object' || typeof lease === 'function')
    ? leaseStates.get(lease)
    : undefined;
  return authority !== null
    && state !== undefined
    && state.authority === authority
    && state.launcher === launcher
    && state.publisher === publisher
    && state.consumed
    && state.completed;
}
