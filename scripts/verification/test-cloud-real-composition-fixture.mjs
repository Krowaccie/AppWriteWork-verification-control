import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';

import { canonicalJson } from './canonical-json.mjs';
import inventory from '../../dev/verification/environments/test-cloud.inventory.v1.json' with { type: 'json' };
import providerContract from '../../src/functions/verification-runner-py/provider-contract/test-cloud.provider-contract.v1.json' with { type: 'json' };

const {
  auditTableId: AUDIT_TABLE_ID,
  databaseId: DATABASE_ID,
  intentTableId: INTENT_TABLE_ID,
  leaseRowId: LEASE_ROW_ID,
  leaseTableId: LEASE_TABLE_ID,
} = inventory.control;

const sha = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const digest = (value) => sha(Buffer.from(canonicalJson(value), 'utf8'));
const textDigest = (value) => sha(Buffer.from(value, 'utf8'));
const rowKey = (tableId, rowId) => `${tableId}\u0000${rowId}`;

const GENESIS_LEDGER_DIGEST = digest({
  leaseRowId: LEASE_ROW_ID,
  schemaVersion: 'verification-audit-genesis.v1',
});

function writeString(target, offset, length, value) {
  Buffer.from(value, 'ascii').copy(target, offset, 0, length);
}

function writeOctal(target, offset, length, value) {
  writeString(target, offset, length, `${value.toString(8).padStart(length - 1, '0')}\0`);
}

function tarEntry(name, bytes) {
  const header = Buffer.alloc(512);
  writeString(header, 0, 100, name);
  writeOctal(header, 100, 8, 0o644);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, bytes.length);
  writeOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = 0x30;
  writeString(header, 257, 6, 'ustar\0');
  writeString(header, 263, 2, '00');
  writeOctal(header, 148, 8, [...header].reduce((sum, byte) => sum + byte, 0));
  return Buffer.concat([
    header,
    bytes,
    Buffer.alloc((512 - (bytes.length % 512)) % 512),
  ]);
}

function hostedPayloadDigest(members) {
  const records = [...members.entries()]
    .filter(([memberPath]) => memberPath !== 'build-identity.json')
    .map(([memberPath, bytes]) => ({
      path: memberPath,
      mode: '100644',
      contentDigest: sha(bytes),
    }))
    .sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  return digest(records);
}

export function createReleaseEligibleSourceArtifactSet() {
  const manifest = {
    'index.html': {
      file: 'assets/index.js', name: 'index', src: 'index.html', isEntry: true,
      imports: ['terminal', 'xyflow'], dynamicImports: ['App'], css: ['assets/index.css'],
    },
    App: {
      file: 'assets/App.js', name: 'App', isDynamicEntry: true,
      imports: ['appwrite-runtime', 'Callout', 'useTheme'],
      dynamicImports: ['Dashboard'], css: ['assets/App.css'],
    },
    Dashboard: {
      file: 'assets/Dashboard.js', name: 'Dashboard', isDynamicEntry: true,
      imports: ['apiClient', 'external-link', 'mcpConnect', 'play', 'publicProjectLinks', 'refresh'],
      css: ['assets/Dashboard.css'],
    },
    apiClient: { file: 'assets/apiClient.js', name: 'apiClient' },
    'appwrite-runtime': {
      file: 'assets/appwrite-runtime.js', name: 'appwrite', isDynamicEntry: true,
      imports: ['appwrite-vendor'],
    },
    'appwrite-vendor': { file: 'assets/appwrite-vendor.js', name: 'appwrite' },
    Callout: { file: 'assets/Callout.js', name: 'Callout', css: ['assets/Callout.css'] },
    'external-link': { file: 'assets/external-link.js', name: 'external-link' },
    mcpConnect: { file: 'assets/mcpConnect.js', name: 'mcpConnect' },
    play: { file: 'assets/play.js', name: 'play' },
    publicProjectLinks: { file: 'assets/publicProjectLinks.js', name: 'publicProjectLinks' },
    refresh: { file: 'assets/refresh.js', name: 'refresh-cw' },
    terminal: { file: 'assets/terminal.js', name: 'terminal' },
    useTheme: { file: 'assets/useTheme.js', name: 'useTheme' },
    xyflow: { file: 'assets/xyflow.js', name: 'xyflow' },
  };
  const members = new Map();
  const payload = (name) => Buffer.from(`immutable:${name}`);
  for (const entry of Object.values(manifest)) {
    members.set(entry.file, payload(entry.file));
    for (const css of entry.css ?? []) members.set(css, payload(css));
  }
  for (const name of [
    'index.html', 'theme-init.js', 'salmora-mark.svg',
    'catalog/catalog-bundle.json', 'templates/registry.json',
    'templates/entitlements.json',
  ]) members.set(name, payload(name));
  members.set('.vite/manifest.json', Buffer.from(JSON.stringify(manifest)));
  members.set('build-identity.json', Buffer.from(JSON.stringify({
    schemaVersion: 'hosted-site-build-identity.v1',
    nonce: 'real-composition',
  })));
  const canonicalContentDigest = hostedPayloadDigest(members);
  const entries = [...members.entries()].sort(([left], [right]) => left.localeCompare(right));
  const tar = Buffer.concat([
    ...entries.map(([name, bytes]) => tarEntry(name, bytes)),
    Buffer.alloc(1024),
  ]);
  const siteBytes = gzipSync(tar, { level: 9, mtime: 0 });
  return Object.freeze({
    releaseEligibleArtifacts: Object.freeze([Object.freeze({
      bytes: Uint8Array.from(siteBytes),
      canonicalContentDigest,
      kind: 'site',
      logicalTarget: 'web',
      relativePath: 'site/site.tar.gz',
      sizeBytes: siteBytes.length,
      transportDigest: sha(siteBytes),
    })]),
  });
}

export function createIdleLease() {
  return {
    leaseRowId: LEASE_ROW_ID,
    leaseVersion: 0,
    state: 'idle',
    ownerRunId: null,
    ownerWorkflowRunId: null,
    environmentDigest: null,
    acquiredAt: null,
    renewedAt: null,
    expiresAt: null,
    ledgerDigest: GENESIS_LEDGER_DIGEST,
    leaseTokenDigest: null,
    cleanupDebt: false,
  };
}

export function providerRowData(tableId, data) {
  const clone = structuredClone(data);
  if (tableId !== INTENT_TABLE_ID
    || !Object.hasOwn(clone, 'cleanupRunnerExecutionRetentionExpiresAt')) return clone;
  clone.cleanupRunnerExecutionRetentionAt = clone.cleanupRunnerExecutionRetentionExpiresAt;
  delete clone.cleanupRunnerExecutionRetentionExpiresAt;
  return clone;
}

function json(url, value, status = 200) {
  return new Response(JSON.stringify(value), {
    url,
    status,
    headers: { 'content-type': 'application/json' },
  });
}

export function createInMemoryAppwriteTransport(initialRows = []) {
  const rows = new Map(initialRows.map((record) => [
    rowKey(record.tableId, record.rowId),
    providerRowData(record.tableId, record.data),
  ]));
  if (!rows.has(rowKey(LEASE_TABLE_ID, LEASE_ROW_ID))) {
    rows.set(rowKey(LEASE_TABLE_ID, LEASE_ROW_ID), createIdleLease());
  }
  const transactions = new Map();
  const calls = [];
  let nextTransaction = 1;

  const apply = (operations) => {
    const staged = new Map([...rows].map(([key, value]) => [key, structuredClone(value)]));
    for (const operation of operations) {
      const key = rowKey(operation.tableId, operation.rowId);
      if (operation.action === 'create') {
        if (staged.has(key)) return false;
        staged.set(key, structuredClone(operation.data));
      } else if (operation.action === 'update') {
        if (!staged.has(key)) return false;
        staged.set(key, { ...staged.get(key), ...structuredClone(operation.data) });
      } else if (operation.action === 'increment') {
        if (!staged.has(key)) return false;
        const prior = staged.get(key);
        const next = prior[operation.data.column] + operation.data.value;
        if (!Number.isSafeInteger(next) || next > operation.data.max) return false;
        staged.set(key, { ...prior, [operation.data.column]: next });
      } else return false;
    }
    rows.clear();
    for (const [key, value] of staged) rows.set(key, value);
    return true;
  };

  const fetch = async (url, options) => {
    const requestPath = new URL(url).pathname.replace(/^\/v1/u, '');
    calls.push({ method: options.method, path: requestPath, body: options.body });
    const rowMatch = /^\/tablesdb\/([^/]+)\/tables\/([^/]+)\/rows\/([^/]+)$/u.exec(requestPath);
    if (options.method === 'GET' && rowMatch !== null) {
      if (rowMatch[1] !== DATABASE_ID) throw new Error('wrong control database');
      const tableId = rowMatch[2];
      const rowId = decodeURIComponent(rowMatch[3]);
      const data = rows.get(rowKey(tableId, rowId));
      return data === undefined
        ? json(url, {}, 404)
        : json(url, { $id: rowId, ...structuredClone(data) });
    }
    if (options.method === 'POST' && requestPath === '/tablesdb/transactions') {
      const transactionId = `transaction-${nextTransaction}`;
      nextTransaction += 1;
      transactions.set(transactionId, { operations: [], status: 'pending' });
      return json(url, { $id: transactionId, status: 'pending' }, 201);
    }
    const transactionMatch = /^\/tablesdb\/transactions\/([^/]+)$/u.exec(requestPath);
    const operationMatch = /^\/tablesdb\/transactions\/([^/]+)\/operations$/u.exec(requestPath);
    if (options.method === 'POST' && operationMatch !== null) {
      const transaction = transactions.get(decodeURIComponent(operationMatch[1]));
      if (transaction === undefined) throw new Error('unknown transaction');
      transaction.operations = JSON.parse(options.body).operations;
      return json(url, { $id: decodeURIComponent(operationMatch[1]), status: 'pending' }, 201);
    }
    if (options.method === 'PATCH' && transactionMatch !== null) {
      const transactionId = decodeURIComponent(transactionMatch[1]);
      const transaction = transactions.get(transactionId);
      if (transaction === undefined || JSON.parse(options.body).commit !== true) {
        throw new Error('invalid commit');
      }
      if (!apply(transaction.operations)) return json(url, { message: 'conflict' }, 409);
      transaction.status = 'committed';
      return json(url, { $id: transactionId, status: 'committed' });
    }
    if (options.method === 'GET' && transactionMatch !== null) {
      const transactionId = decodeURIComponent(transactionMatch[1]);
      return json(url, {
        $id: transactionId,
        status: transactions.get(transactionId)?.status ?? 'unknown',
      });
    }
    throw new Error(`unexpected control request ${options.method} ${requestPath}`);
  };
  Object.defineProperties(fetch, {
    calls: { value: calls },
    rows: { value: rows },
  });
  return fetch;
}

export function setTransportRow(fetch, tableId, rowId, data) {
  fetch.rows.set(rowKey(tableId, rowId), providerRowData(tableId, data));
}

export function providerPlannedIntent(context, resourceType) {
  const corpus = JSON.parse(readFileSync(
    new URL('../../dev/verification/fixtures/test-cloud-provider-contract.v1.corpus.json', import.meta.url),
    'utf8',
  ));
  const vectorId = {
    'primary-project': '09.intent.pass.primary-project-v2',
    'primary-graph': '10.intent.pass.primary-graph-v2',
    'primary-share': '11.intent.pass.primary-share-v2',
  }[resourceType];
  const vector = corpus.vectors.find(({ id }) => id === vectorId);
  const raw = JSON.parse(Buffer.from(vector.input.valueBase64, 'base64').toString('utf8')).rawRow;
  const identity = (type) => {
    const resourceId = `vr-${textDigest(`${context.environmentDigest}|${context.runId}|${type}`).slice(7, 39)}`;
    const operationKey = textDigest(`${context.runId}|sharing-permissions|{}`);
    const ownerMarker = `verification-owner.v1:${digest({
      schemaVersion: 'verification-owner-marker.v1',
      environmentDigest: context.environmentDigest,
      operationKey,
      resourceId,
      resourceType: type,
      runId: context.runId,
    })}`;
    return {
      resourceId,
      operationKey,
      ownerMarker,
      intentId: textDigest(`${context.environmentDigest}|${context.runId}|${type}|${resourceId}`).slice(7),
    };
  };
  const bindingFor = (type) => {
    const value = identity(type);
    return {
      schemaVersion: 'verification-provider-aggregate-binding.v1',
      environmentDigest: context.environmentDigest,
      providerContractDigest: sha(Buffer.from(`${canonicalJson(providerContract)}\n`, 'utf8')),
      runId: context.runId,
      resourceType: type,
      resourceId: value.resourceId,
      operationScenario: 'sharing-permissions',
      parameters: {},
      operationKey: value.operationKey,
      ownerMarker: value.ownerMarker,
      intentId: value.intentId,
    };
  };
  const current = identity(resourceType);
  const aggregate = JSON.parse(raw.providerAggregateJson);
  const binding = bindingFor(resourceType);
  aggregate.aggregateBinding = binding;
  aggregate.aggregateBindingDigest = digest(binding);
  for (const member of aggregate.ownedMembers) {
    member.memberBinding.aggregateBindingDigest = aggregate.aggregateBindingDigest;
    member.memberBinding.ownerResourceId = current.resourceId;
    member.memberBindingDigest = digest(member.memberBinding);
  }
  for (const reference of aggregate.referencedMembers) {
    const ownerBinding = bindingFor(reference.memberBinding.ownerResourceType);
    reference.memberBinding.aggregateBindingDigest = digest(ownerBinding);
    reference.memberBinding.ownerResourceId = identity(reference.memberBinding.ownerResourceType).resourceId;
    reference.memberBindingDigest = digest(reference.memberBinding);
  }
  const {
    $createdAt, $databaseId, $id, $permissions, $sequence, $tableId, $updatedAt,
    providerResourceIds, recoveryCheckpointDigest, cleanupRunnerExecutionRetentionAt,
    ...projection
  } = raw;
  return {
    ...projection,
    intentId: current.intentId,
    runId: context.runId,
    environmentDigest: context.environmentDigest,
    resourceId: current.resourceId,
    ownerMarker: current.ownerMarker,
    providerAggregateJson: canonicalJson(aggregate),
    providerAggregateDigest: digest(aggregate),
    cleanupRunnerExecutionRetentionExpiresAt: cleanupRunnerExecutionRetentionAt,
  };
}

export const controlIds = Object.freeze({
  auditTableId: AUDIT_TABLE_ID,
  databaseId: DATABASE_ID,
  intentTableId: INTENT_TABLE_ID,
  leaseRowId: LEASE_ROW_ID,
  leaseTableId: LEASE_TABLE_ID,
});
