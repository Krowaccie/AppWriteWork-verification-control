import { Buffer } from 'node:buffer';

import { canonicalJson, sha256Bytes } from './canonical-json.mjs';

const CONTENT_DIGEST = /^sha256:([0-9a-f]{64})$/u;
const INTENT_ID = /^([0-9a-f]{64})$/u;
const PROVIDER_ROW_ID = /^h[A-Za-z0-9_-]{35}$/u;
const encoder = new TextEncoder();

function mapHexDigest(hex) {
  return `h${Buffer.from(hex, 'hex').toString('base64url').slice(0, 35)}`;
}

export function contentDigestToRowId(value) {
  const match = typeof value === 'string' ? CONTENT_DIGEST.exec(value) : null;
  if (match === null) throw new TypeError('content digest');
  return mapHexDigest(match[1]);
}

export function intentIdToRowId(value) {
  const match = typeof value === 'string' ? INTENT_ID.exec(value) : null;
  if (match === null) throw new TypeError('intent id');
  return mapHexDigest(match[1]);
}

export function isProviderSafeControlRowId(value) {
  return typeof value === 'string'
    && value.length === 36
    && PROVIDER_ROW_ID.test(value);
}

export function contentAddressedRowMatches({ rowId, contentDigest, data }) {
  try {
    return contentDigestToRowId(contentDigest) === rowId
      && sha256Bytes(encoder.encode(canonicalJson(data))) === contentDigest;
  } catch {
    return false;
  }
}

export function intentProjectionRowMatches({ rowId, data }) {
  try {
    const preimage = `${data.environmentDigest}|${data.runId}|${data.resourceType}|${data.resourceId}`;
    const computedIntentId = sha256Bytes(encoder.encode(preimage)).slice(7);
    return data.intentId === computedIntentId
      && intentIdToRowId(data.intentId) === rowId;
  } catch {
    return false;
  }
}
