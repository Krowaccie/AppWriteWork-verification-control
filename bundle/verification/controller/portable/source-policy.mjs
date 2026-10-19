import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { loadPortableRegistry, selectPortableChecks } from '../../core/portable-registry.mjs';
import { snapshotSource } from '../../portable/source.mjs';
import { canonical, digest } from './bundle.mjs';

const POLICY = 'pinned-source-policy.v1';
const LOCKED = ['command', 'collection', 'capabilities', 'profiles', 'consumers', 'paths', 'expectedSkips'];
function under(root, filename) {
  const relative = path.relative(root, filename);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}
function safeFailureReason(error) {
  // JSON.parse can include candidate-authored plaintext in its native message.
  if (error instanceof SyntaxError) return 'CANDIDATE_POLICY_JSON_INVALID';
  const code = String(error?.message ?? '').split(':', 1)[0];
  return /^[A-Z][A-Z0-9_]{1,100}$/u.test(code) ? code : 'SOURCE_POLICY_OPERATOR_FAILED';
}
function boundedPolicyBytes(candidate, entry) {
  let filename = candidate;
  for (const segment of entry.path.split('/')) {
    filename = path.join(filename, segment);
    if (lstatSync(filename).isSymbolicLink() || !under(candidate, realpathSync(filename))) throw new Error('SOURCE_PATH_ESCAPE');
  }
  const before = lstatSync(filename), maximum = 4 * 1024 * 1024;
  if (!before.isFile() || before.size > maximum) throw new Error('CANDIDATE_POLICY_SIZE_LIMIT');
  const fd = openSync(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(fd);
    if (opened.ino !== before.ino || opened.dev !== before.dev || opened.size !== before.size) throw new Error('SOURCE_READ_IDENTITY_MISMATCH');
    const bytes = Buffer.alloc(before.size + 1); let length = 0;
    while (length < bytes.length) { const count = readSync(fd, bytes, length, bytes.length - length, null); if (!count) break; length += count; }
    const after = fstatSync(fd);
    if (length !== before.size || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) throw new Error('SOURCE_READ_IDENTITY_MISMATCH');
    return bytes.subarray(0, length);
  } finally { closeSync(fd); }
}
export function runSourcePolicyAudit({ candidateRoot, verifierRoot, snapshot = snapshotSource }) {
  const candidate = realpathSync(candidateRoot);
  const registry = loadPortableRegistry({ root: verifierRoot });
  const errors = [];
  const checks = [];
  let before;
  try {
    before = snapshot(candidate);
    const seen = new Set();
    for (const entry of before.files) {
      if (entry.kind === 'deleted') continue;
      if (entry.kind !== 'file' || seen.has(entry.path.toLowerCase())) { errors.push({ code: 'SOURCE_FILE_KIND_OR_CASE_COLLISION', path: entry.path }); continue; }
      seen.add(entry.path.toLowerCase());
      // The trusted snapshot already checks every ancestor and bounds fd reads.
      // Re-reading all files here adds no policy assertion and would create an
      // unbounded race after that guarded read. Final snapshot equality binds it.
      if (/(?:^|\/)\.env(?:\.[^/]*)?$/u.test(entry.path) && !entry.path.endsWith('.example')) errors.push({ code: 'PRIVATE_ENV_FILE_IN_SOURCE', path: entry.path });
    }
    checks.push({ id: 'source-file-boundary', status: errors.length ? 'FAIL' : 'PASS', files: seen.size });
    const candidatePolicyPath = 'verification/core/verification-manifest.v2.json';
    const policyEntry = before.files.find((entry) => entry.path === candidatePolicyPath && entry.kind === 'file');
    if (!policyEntry) errors.push({ code: 'CANDIDATE_POLICY_MISSING' });
    else {
      const data = boundedPolicyBytes(candidate, policyEntry);
      if (digest(data) !== policyEntry.digest) throw new Error('CANDIDATE_POLICY_SOURCE_CHANGED');
      const proposed = JSON.parse(data);
      if (proposed.schemaVersion !== 2 || !Array.isArray(proposed.suites)) errors.push({ code: 'CANDIDATE_POLICY_INVALID' });
      else {
        const proposedSuites = new Map();
        for (const suite of proposed.suites) {
          if (proposedSuites.has(suite.id)) errors.push({ code: 'CANDIDATE_POLICY_DUPLICATE_SUITE', suiteId: suite.id });
          proposedSuites.set(suite.id, suite);
        }
        for (const expected of registry.suites) {
          const actual = proposedSuites.get(expected.id);
          if (!actual) { errors.push({ code: 'PINNED_OBLIGATION_REMOVED', suiteId: expected.id }); continue; }
          for (const field of LOCKED) if (canonical(actual[field] ?? null) !== canonical(expected[field] ?? null)) errors.push({ code: 'PINNED_OBLIGATION_CHANGED', suiteId: expected.id, field });
        }
      }
    }
    checks.push({ id: 'pinned-registry-obligations', status: errors.some((entry) => /POLICY|OBLIGATION/u.test(entry.code)) ? 'FAIL' : 'PASS', requiredSuites: registry.suites.map((suite) => suite.id) });
    const taxonomy = selectPortableChecks({ registry, profile: 'repository', changedPaths: before.files.filter((entry) => entry.kind !== 'deleted').map((entry) => entry.path) });
    for (const error of taxonomy.errors) errors.push({ ...error, code: `SOURCE_${error.code}` });
    checks.push({ id: 'maintained-source-ownership', status: taxonomy.errors.length ? 'BLOCKED' : 'PASS', unknownPaths: taxonomy.unknownPaths });
    if (snapshot(candidate).digest !== before.digest) errors.push({ code: 'CANDIDATE_SOURCE_CHANGED' });
  } catch (error) { errors.push({ code: 'SOURCE_POLICY_INPUT_UNAVAILABLE', reason: safeFailureReason(error) }); }
  const failed = errors.some((entry) => !entry.code.startsWith('SOURCE_COVERAGE_') && entry.code !== 'SOURCE_POLICY_INPUT_UNAVAILABLE');
  return { schemaVersion: 'portable-source-policy-result.v1', policy: POLICY, scope: 'source-policy',
    status: failed ? 'FAIL' : errors.length ? 'BLOCKED' : 'PASS', independent: true,
    independentProductAcceptance: false, independentRuntimeAcceptance: false, candidateSourceDigest: before?.digest ?? null,
    registryDigest: registry.registryDigest, checks, errors, pendingCapabilities: errors.filter((entry) => entry.code.startsWith('SOURCE_COVERAGE_')).map((entry) => ({ capability: 'maintained-source-ownership', path: entry.path })),
    releaseEligible: false };
}

export function controllerVerdict({ scope, sourcePolicy, selectedSuites = [], result }) {
  const pending = [];
  if (scope !== 'source-policy' && selectedSuites.length === 0) pending.push({ capability: 'required-runtime-suite-selection', reason: 'NO_SELECTED_RUNTIME_OBLIGATIONS' });
  if (scope !== 'source-policy') for (const suite of selectedSuites) {
    const privileged = suite.capabilities.filter((capability) => /docker|windows|postgres|temporal|browser|tls/iu.test(capability));
    for (const capability of privileged) pending.push({ suiteId: suite.id, capability, reason: /windows/iu.test(capability) ? 'RESTRICTED_NATIVE_IDENTITY_NOT_QUALIFIED' : 'TRUSTED_PRIVILEGED_OPERATOR_NOT_QUALIFIED' });
    pending.push({ suiteId: suite.id, capability: `trusted-runtime-assertions:${suite.id}`, reason: 'CANDIDATE_TEST_OUTPUT_IS_ANCILLARY' });
  }
  pending.push(...(sourcePolicy.pendingCapabilities ?? []));
  const status = sourcePolicy.status === 'FAIL' || result?.status === 'FAIL' ? 'FAIL'
    : sourcePolicy.status !== 'PASS' || pending.length || (scope !== 'source-policy' && result?.status !== 'PASS') ? 'BLOCKED' : 'PASS';
  return { status, independent: status === 'PASS', independentProductAcceptance: false, independentRuntimeAcceptance: false,
    scope, policy: sourcePolicy.policy, pendingCapabilities: pending,
    errors: sourcePolicy.errors, sourcePolicy, selectedResultStatus: result?.status ?? 'NOT_REQUESTED', releaseEligible: false };
}
