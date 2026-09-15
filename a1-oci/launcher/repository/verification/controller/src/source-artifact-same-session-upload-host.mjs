import {
  isPublicationLeasePublisherAuthority,
  registerPublicationPublisher,
} from './source-artifact-publication-lease-authority.mjs';

const hostStates = new WeakMap();
const sessionStates = new WeakMap();
const NativePromise = Promise;

function settled(value) {
  return new NativePromise((resolve) => resolve(value));
}

function isPass(value) {
  return value !== null && typeof value === 'object' && value.status === 'PASS';
}

function exactSession(value) {
  if (value === null || typeof value !== 'object' || !Object.isFrozen(value)) return null;
  const keys = Object.keys(value).sort();
  if (
    keys.length !== 3
    || keys[0] !== 'abortAndJoin'
    || keys[1] !== 'complete'
    || keys[2] !== 'writeMemberChunk'
    || typeof value.abortAndJoin !== 'function'
    || typeof value.complete !== 'function'
    || typeof value.writeMemberChunk !== 'function'
  ) return null;
  return value;
}

function terminalPromise(state, kind) {
  const ownKey = kind === 'complete' ? 'completePromise' : 'abortPromise';
  if (state[ownKey] !== null) return state[ownKey];
  if (kind === 'complete' && state.abortPromise !== null) return settled(false);
  if (kind === 'abort' && state.completed) return settled(false);
  let settle;
  const promise = new NativePromise((resolve) => { settle = resolve; });
  state[ownKey] = promise;
  void (async () => {
    if (kind === 'abort' && state.completePromise !== null) {
      const completed = await state.completePromise;
      if (completed) {
        settle(false);
        return;
      }
    }
    let accepted = false;
    try {
      accepted = isPass(await state.raw[kind === 'complete' ? 'complete' : 'abortAndJoin']());
    } catch {
      accepted = false;
    }
    if (kind === 'complete' && accepted) state.completed = true;
    settle(accepted);
  })();
  return promise;
}

export function claimSameSessionSourceArtifactUploadHost(host, publisher) {
  const state = hostStates.get(host);
  if (
    state === undefined
    || state.publisher !== null
    || !registerPublicationPublisher(state.publicationPublisherAuthority, publisher)
  ) return null;
  state.publisher = publisher;
  return state.publicationPublisherAuthority;
}

export function createSameSessionSourceArtifactUploadHost({
  artifactUploadClient,
  publicationPublisherAuthority,
} = {}) {
  if (
    artifactUploadClient === null
    || typeof artifactUploadClient !== 'object'
    || !Object.isFrozen(artifactUploadClient)
    || Object.keys(artifactUploadClient).length !== 1
    || typeof artifactUploadClient.openArtifact !== 'function'
    || !isPublicationLeasePublisherAuthority(publicationPublisherAuthority)
  ) throw new TypeError('Same-session upload host requires a controller-owned client and publication authority.');

  let host;
  async function openArtifact(details) {
    const hostState = hostStates.get(host);
    if (hostState === undefined || hostState.publisher === null) return null;
    try {
      const session = exactSession(await artifactUploadClient.openArtifact(details));
      if (session === null) return null;
      const token = Object.freeze(Object.create(null));
      sessionStates.set(token, {
        abortPromise: null,
        completePromise: null,
        completed: false,
        host,
        raw: session,
      });
      return token;
    } catch {
      return null;
    }
  }

  async function writeMemberChunk(token, chunk) {
    const state = sessionStates.get(token);
    if (
      state === undefined
      || state.host !== host
      || state.completed
      || state.completePromise !== null
      || state.abortPromise !== null
    ) return false;
    try {
      return isPass(await state.raw.writeMemberChunk(chunk));
    } catch {
      return false;
    }
  }

  function complete(token) {
    const state = sessionStates.get(token);
    return state === undefined || state.host !== host
      ? settled(false)
      : terminalPromise(state, 'complete');
  }

  function abortAndJoin(token) {
    const state = sessionStates.get(token);
    return state === undefined || state.host !== host
      ? settled(false)
      : terminalPromise(state, 'abort');
  }

  host = Object.freeze({ abortAndJoin, complete, openArtifact, writeMemberChunk });
  hostStates.set(host, {
    publicationPublisherAuthority,
    publisher: null,
  });
  return host;
}
