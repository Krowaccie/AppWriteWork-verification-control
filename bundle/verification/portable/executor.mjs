import { createHash, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { loadPortableRegistry, selectPortableChecks } from '../core/portable-registry.mjs';
import { snapshotSource, validatePaths } from './source.mjs';
import { collectTests, executeCommand, prepareCommand, redact } from './process.mjs';

export function explainPortableVerification({ root, profile, changedPaths = [], group, registry, expectedRegistryDigest } = {}) {
  const loaded = registry ?? loadPortableRegistry({ root });
  const selection = selectPortableChecks({ registry: loaded, profile, changedPaths: validatePaths(changedPaths) });
  if (group && !['web', 'python', 'mcp', 'quick', 'portable', 'windows'].includes(group)) throw new Error('UNKNOWN_GROUP');
  const suites = selection.suites.filter((suite) => !group || suite.group === group);
  const errors = [...(selection.errors ?? [])];
  if (expectedRegistryDigest && expectedRegistryDigest !== selection.registryDigest) errors.push({ code: 'REGISTRY_DIGEST_MISMATCH', message: 'Selection registry differs from selected CI policy' });
  return { ...selection, suites, suiteIds: suites.map((suite) => suite.id), group: group ?? null, errors, scope: group ? 'capability-shard' : profile === 'repository' ? 'repository-baseline' : 'changed-components', trust: { mode: 'development', independent: false, containment: 'same-user-processes' } };
}

function verifierDigest(root) {
  const files = ['scripts/verify.mjs', 'verification/core/portable-registry.mjs', 'verification/core/verification-manifest.v2.json'];
  const directory = path.join(root, 'verification/portable');
  if (existsSync(directory)) files.push(...readdirSync(directory).filter((name) => /\.(?:mjs|py)$/u.test(name) && !name.endsWith('.test.mjs') && !name.startsWith('test_')).map((name) => `verification/portable/${name}`));
  const hash = createHash('sha256');
  for (const filename of files.sort()) {
    if (existsSync(path.join(root, filename))) hash.update(filename).update('\0').update(readFileSync(path.join(root, filename))).update('\0');
  }
  return `sha256:${hash.digest('hex')}`;
}

export function evaluateSuite(suite, observation, output) {
  const base = { id: suite.id, group: suite.group, durationMs: observation.durationMs ?? 0, ...(observation.processCleanup ? { processCleanup: observation.processCleanup } : {}), ...(observation.terminationErrors?.length ? { terminationErrors: observation.terminationErrors } : {}) };
  if (observation.spawnError) return { ...base, status: 'BLOCKED', reason: `PREREQUISITE_UNAVAILABLE:${observation.spawnError}` };
  if (observation.timedOut) return { ...base, status: 'FAIL', reason: 'TIMEOUT' };
  if (observation.interrupted) return { ...base, status: 'NOT_RUN', reason: 'INTERRUPTED' };
  if (observation.processCleanup && observation.processCleanup.status !== 'PASS') return { ...base, status: 'BLOCKED', reason: 'OWNED_PROCESS_CLEANUP_INCOMPLETE' };
  if (observation.exitCode !== 0) {
    // Preserve the first process failure while retaining actual assertion
    // counts from a complete failed report when one was produced.
    let collection;
    try { collection = collectTests(suite, observation, output, { allowFailedOperatorReport: true }); }
    catch { collection = { error: 'FAILED_REPORT_UNAVAILABLE' }; }
    return { ...base, status: observation.exitCode === 2 ? 'BLOCKED' : 'FAIL', reason: `PROCESS_EXIT:${observation.exitCode}`, ...(collection.error ? { collectionError: collection.error } : { tests: collection }) };
  }
  const tests = collectTests(suite, observation, output);
  if (tests.error) return { ...base, status: 'BLOCKED', reason: tests.error };
  if ((tests.failed ?? 0) > 0) return { ...base, status: 'FAIL', reason: 'REPORTED_TEST_FAILURE', tests };
  if ((tests.cancelled ?? 0) > 0) return { ...base, status: 'BLOCKED', reason: 'REQUIRED_TEST_CANCELLED', tests };
  if ((tests.todo ?? 0) > 0) return { ...base, status: 'BLOCKED', reason: 'REQUIRED_TEST_TODO', tests };
  if ((suite.collection?.minimumTests ?? 0) > (tests.executed ?? 0)) return { ...base, status: 'BLOCKED', reason: 'EMPTY_OR_INCOMPLETE_COLLECTION', tests };
  const unexpected = tests.skipped.filter((skip) => {
    const allowed = (suite.expectedSkips ?? []).find((rule) => {
      if (typeof rule.reason !== 'string' || !rule.reason.trim() || typeof rule.pattern !== 'string' || !rule.pattern.trim()) return false;
      try {
        const pattern = new RegExp(rule.pattern, 'u');
        return (typeof skip.reason === 'string' && skip.reason !== 'unspecified' && pattern.test(skip.reason))
          || (typeof skip.title === 'string' && Boolean(skip.title) && pattern.test(skip.title));
      } catch { return false; }
    });
    if (!allowed) return true;
    skip.expected = { pattern: allowed.pattern, explanation: allowed.reason };
    return false;
  });
  if (unexpected.length) return { ...base, status: 'BLOCKED', reason: 'UNEXPECTED_REQUIRED_SKIP', tests };
  return { ...base, status: 'PASS', tests };
}

export async function runPortableVerification({ root, candidateRoot = root, profile, changedPaths = [], group, outputRoot, registry, expectedRegistryDigest, runner = executeCommand, cleanup = async () => ({ status: 'PASS', detail: 'No outer fixture resources created; suite adapters own fixture cleanup' }), snapshot = snapshotSource, signal, requireIndependent = false, env = process.env } = {}) {
  const started = new Date().toISOString();
  const candidate = path.resolve(candidateRoot);
  const verifierRoot = path.resolve(root);
  const output = path.resolve(outputRoot ?? path.join(candidate, '.local/verification', randomUUID()));
  if (existsSync(output) && readdirSync(output).length) throw new Error('OUTPUT_NOT_EMPTY: use a new owned run directory');
  // Evidence may be inside ignored .local only; other in-candidate paths alter source.
  const relativeOutput = path.relative(candidate, output);
  if (relativeOutput && !relativeOutput.startsWith(`..${path.sep}`) && !path.isAbsolute(relativeOutput) && !relativeOutput.startsWith(`.local${path.sep}`)) throw new Error('OUTPUT_INSIDE_SOURCE');
  const executionRegistry = registry ?? loadPortableRegistry({ root: verifierRoot });
  const explanation = explainPortableVerification({ root: verifierRoot, profile, changedPaths, group, registry: executionRegistry, expectedRegistryDigest });
  mkdirSync(output, { recursive: true });
  const result = { schemaVersion: 'portable-verification-result.v1', runId: randomUUID(), status: 'NOT_RUN', finalized: false, startedAt: started, completedAt: null, profile, scope: explanation.scope, group: group ?? null, registryDigest: explanation.registryDigest, verifier: { digest: verifierDigest(verifierRoot), root: verifierRoot }, trust: explanation.trust, runtime: { node: process.versions.node, platform: process.platform, architecture: process.arch }, candidate: null, selectedSuiteIds: explanation.suiteIds, suites: [], errors: [...explanation.errors], cleanup: { status: 'NOT_RUN' } };
  const checkpoint = () => writeFileSync(path.join(output, 'result.json'), `${JSON.stringify(result, null, 2)}\n`);
  checkpoint();
  let before;
  try {
    before = snapshot(candidate);
    result.candidate = { root: candidate, head: before.head, dirty: before.dirty, digest: before.digest, fileCount: before.files.length, exclusions: before.exclusions };
    if (profile === 'repository') {
      const coverage = selectPortableChecks({ registry: executionRegistry, profile, changedPaths: validatePaths(before.files.filter((entry) => entry.kind !== 'deleted').map((entry) => entry.path)) });
      result.errors.push(...coverage.errors);
      result.coverage = { checkedFiles: before.files.length, unknownPaths: coverage.unknownPaths };
    }
    if (requireIndependent) result.errors.push({ code: 'INDEPENDENT_CONTAINMENT_UNAVAILABLE', message: 'This executor supplies same-user development evidence; a pinned verifier alone is not enforced isolation' });
    if (profile === 'repository' && explanation.suites.length === 0) result.errors.push({ code: 'REPOSITORY_BASELINE_EMPTY' });
    if (result.errors.length === 0) {
      for (const suite of explanation.suites) {
        if (signal?.aborted) { result.suites.push({ id: suite.id, group: suite.group, status: 'NOT_RUN', reason: 'INTERRUPTED' }); continue; }
        const suiteOutput = path.join(output, 'suites', suite.id);
        if (!/^[a-z0-9][a-z0-9-]*$/u.test(suite.id)) throw new Error('UNSAFE_SUITE_ID');
        mkdirSync(suiteOutput, { recursive: true });
        let observation;
        try {
          const command = prepareCommand(suite, { root: candidate, output: suiteOutput, env });
          observation = await runner(command, { timeoutMs: suite.timeoutMs, signal, suite, output: suiteOutput });
        } catch (error) { observation = { spawnError: error.code ?? error.message ?? 'EXECUTOR_ERROR' }; }
        if (!observation || typeof observation !== 'object') observation = { spawnError: 'MISSING_PROCESS_RESULT' };
        const evaluated = evaluateSuite(suite, observation, suiteOutput);
        result.suites.push(evaluated);
        writeFileSync(path.join(suiteOutput, 'log.txt'), redact(`${observation.stdout ?? ''}\n${observation.stderr ?? ''}`, env));
        checkpoint();
      }
    }
    const after = snapshot(candidate);
    result.candidate.afterDigest = after.digest;
    if (before.digest !== after.digest) result.errors.push({ code: 'CANDIDATE_SOURCE_CHANGED', message: 'Candidate contents changed during verification' });
    if (result.verifier.digest !== verifierDigest(verifierRoot)) result.errors.push({ code: 'VERIFIER_SOURCE_CHANGED' });
  } catch (error) { result.errors.push({ code: 'EXECUTOR_ERROR', message: redact(error.message, env) }); }
  finally {
    try {
      result.cleanup = await cleanup({ candidateRoot: candidate, outputRoot: output, signal });
      if (result.cleanup?.status !== 'PASS') result.errors.push({ code: 'CLEANUP_INCOMPLETE' });
    } catch (error) { result.cleanup = { status: 'FAIL', reason: redact(error.message, env) }; result.errors.push({ code: 'CLEANUP_FAILED' }); }
  }
  const unconfirmedProcesses = result.suites.filter((suite) => suite.processCleanup && suite.processCleanup.status !== 'PASS');
  if (unconfirmedProcesses.length) {
    result.cleanup = { ...result.cleanup, status: 'BLOCKED', processes: unconfirmedProcesses.map((suite) => ({ suiteId: suite.id, ...suite.processCleanup })) };
    result.errors.push({ code: 'OWNED_PROCESS_CLEANUP_INCOMPLETE' });
  }
  if (before) {
    try {
      const finalSnapshot = snapshot(candidate);
      result.candidate.afterDigest = finalSnapshot.digest;
      if (before.digest !== finalSnapshot.digest && !result.errors.some((error) => error.code === 'CANDIDATE_SOURCE_CHANGED')) result.errors.push({ code: 'CANDIDATE_SOURCE_CHANGED', message: 'Candidate contents changed before final cleanup readback' });
      if (result.verifier.digest !== verifierDigest(verifierRoot) && !result.errors.some((error) => error.code === 'VERIFIER_SOURCE_CHANGED')) result.errors.push({ code: 'VERIFIER_SOURCE_CHANGED' });
    } catch (error) { result.errors.push({ code: 'FINAL_SOURCE_READBACK_FAILED', message: redact(error.message, env) }); }
  }
  const missing = explanation.suiteIds.filter((id) => !result.suites.some((suite) => suite.id === id));
  if (missing.length) result.errors.push({ code: 'SELECTED_RESULTS_MISSING', suiteIds: missing });
  result.status = result.suites.some((suite) => suite.status === 'FAIL') ? 'FAIL'
    : result.errors.length || result.suites.some((suite) => suite.status !== 'PASS') ? 'BLOCKED'
      : result.suites.length ? 'PASS' : 'NOT_APPLICABLE';
  result.firstFailure = result.errors[0]?.code ?? result.suites.find((suite) => suite.status !== 'PASS')?.reason ?? null;
  result.completedAt = new Date().toISOString(); result.finalized = true;
  checkpoint();
  writeFileSync(path.join(output, 'report.md'), `# Portable verification\n\nStatus: **${result.status}**\n\nProfile: ${profile}; scope: ${result.scope}.\n\nCandidate: ${result.candidate?.head ?? 'unavailable'}; snapshot: ${result.candidate?.digest ?? 'unavailable'}.\n\nRegistry: ${result.registryDigest}.\n\nEvidence: same-user development execution; independent: false.\n\n${result.suites.map((suite) => `- ${suite.id}: ${suite.status}${suite.reason ? ` (${suite.reason})` : ''}`).join('\n')}\n\nCleanup: ${result.cleanup?.status ?? 'UNKNOWN'}.\n\nFirst failure: ${result.firstFailure ?? 'none'}.\n`);
  return result;
}
