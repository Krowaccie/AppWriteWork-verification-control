import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const PORTABLE_GROUPS = Object.freeze(['web', 'python', 'mcp', 'quick', 'portable', 'windows']);
const defaultRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const arrayOfStrings = value => Array.isArray(value) && value.every(item => typeof item === 'string' && item.length > 0);
const fail = message => { throw new Error(`PORTABLE_REGISTRY_INVALID: ${message}`); };

function validate(registry) {
  if (registry?.schemaVersion !== 2 || registry.kind !== 'portable-verification-registry') fail('unsupported version');
  if (JSON.stringify(registry.groups) !== JSON.stringify(PORTABLE_GROUPS)) fail('groups');
  for (const key of ['globalPaths', 'prosePatterns', 'ignoredPaths', 'alwaysSuiteIds']) if (!arrayOfStrings(registry[key])) fail(key);
  if (!Array.isArray(registry.exclusions) || registry.exclusions.some(entry => !entry.pattern || !entry.reason)) fail('exclusions');
  if (!Array.isArray(registry.suites) || !registry.suites.length) fail('empty suites');
  const ids = new Set();
  for (const suite of registry.suites) {
    if (!/^[a-z][a-z0-9-]*$/.test(suite.id) || ids.has(suite.id)) fail('duplicate/invalid suite ID');
    ids.add(suite.id);
    if (!PORTABLE_GROUPS.includes(suite.group)) fail(`${suite.id}: group`);
    for (const key of ['paths', 'consumers', 'capabilities', 'profiles']) if (!arrayOfStrings(suite[key])) fail(`${suite.id}: ${key}`);
    if (!suite.paths.length || !suite.capabilities.length || !suite.owner || !suite.reason) fail(`${suite.id}: ownership`);
    if (!suite.profiles.length || suite.profiles.some(profile => !['changes', 'repository'].includes(profile))) fail(`${suite.id}: profiles`);
    if (typeof suite.ci !== 'boolean' || !Number.isSafeInteger(suite.timeoutMs) || suite.timeoutMs <= 0) fail(`${suite.id}: execution limits`);
    if (!suite.command || typeof suite.command.executable !== 'string' || !arrayOfStrings(suite.command.args)) fail(`${suite.id}: command`);
    if (!['{node}', '{python}'].includes(suite.command.executable) || suite.command.args.some(argument => argument.includes('\0'))) fail(`${suite.id}: executable/argv`);
    if (suite.command.env && (typeof suite.command.env !== 'object' || Object.values(suite.command.env).some(v => typeof v !== 'string'))) fail(`${suite.id}: env`);
    if (!['node-tap', 'pytest-junit', 'operator-json', 'exit-code'].includes(suite.collection?.format)
      || !Number.isSafeInteger(suite.collection.minimumTests) || suite.collection.minimumTests < 0 || suite.collection.required !== true) fail(`${suite.id}: collection`);
    if (suite.collection.minimumTests === 0 && suite.collection.format !== 'exit-code') fail(`${suite.id}: empty test collection`);
    if (!Array.isArray(suite.expectedSkips) || suite.expectedSkips.some(skip => !skip.reason || !skip.pattern)) fail(`${suite.id}: skip contract`);
    for (const key of ['nativeTargets', 'nativeExclude']) if (suite[key] && !arrayOfStrings(suite[key])) fail(`${suite.id}: ${key}`);
  }
  for (const suite of registry.suites) for (const id of suite.consumers) if (!ids.has(id)) fail(`${suite.id}: dangling consumer ${id}`);
  for (const id of registry.alwaysSuiteIds) if (!ids.has(id)) fail(`dangling always suite ${id}`);
  const sql = registry.sqlInventory;
  if (!sql || !arrayOfStrings(sql.files) || !sql.files.length || new Set(sql.files).size !== sql.files.length
    || !arrayOfStrings(sql.offlineFiles) || !ids.has(sql.nativeDefaultSuite)) fail('SQL inventory');
  for (const file of sql.offlineFiles) if (!sql.files.includes(file)) fail(`unknown SQL file ${file}`);
  for (const [id, targets] of Object.entries(sql.exceptionTargets ?? {})) {
    if (!ids.has(id) || !arrayOfStrings(targets)) fail(`SQL exception suite ${id}`);
    for (const target of targets) if (!sql.files.includes(target.split('::')[0])) fail(`unknown SQL target ${target}`);
  }
  const native = registry.suites.find(suite => suite.id === sql.nativeDefaultSuite);
  if (!native.nativeTargets?.length || !Array.isArray(native.nativeExclude)) fail('native SQL collection');
  const coveredFiles = new Set(registry.suites.flatMap(suite => suite.nativeTargets ?? []).map(target => target.split('::')[0]));
  for (const file of sql.files) if (!coveredFiles.has(`${sql.root}/${file}`)) fail(`SQL file has no native capability route: ${file}`);
  for (const [id, targets] of Object.entries(sql.exceptionTargets)) {
    const suite = registry.suites.find(candidate => candidate.id === id);
    for (const target of targets) {
      const path = `${sql.root}/${target}`;
      if (!suite.nativeTargets?.includes(path)) fail(`SQL exception lost its route: ${target}`);
      if (target.includes('::') && !native.nativeExclude.includes(path)) fail(`SQL exception not excluded from baseline: ${target}`);
    }
  }
  return registry;
}

/** Load the registry owned by the caller's verifier root, never a candidate override. */
export function loadPortableRegistry({ root = defaultRoot } = {}) {
  const bytes = readFileSync(resolve(root, 'verification/core/verification-manifest.v2.json'));
  const registry = validate(JSON.parse(bytes.toString('utf8')));
  return { ...registry, registryDigest: `sha256:${createHash('sha256').update(bytes).digest('hex')}` };
}

function matches(path, pattern) {
  // Deliberately small portable glob grammar: ** crosses separators, * does not.
  let expression = '^';
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index];
    if (character === '*' && pattern[index + 1] === '*') {
      index += 1;
      if (pattern[index + 1] === '/') { index += 1; expression += '(?:.*/)?'; }
      else expression += '.*';
    } else if (character === '*') expression += '[^/]*';
    else expression += character.replace(/[\\^$+?.()|{}\[\]]/g, '\\$&');
  }
  return new RegExp(`${expression}$`).test(path);
}

/** Deterministic selection used by CLI, CI and advisory impact analysis. */
export function selectPortableChecks({ registry = loadPortableRegistry(), profile = 'changes', changedPaths = [] } = {}) {
  validate(registry);
  if (!['changes', 'repository'].includes(profile)) throw new Error('PORTABLE_PROFILE_INVALID');
  if (!Array.isArray(changedPaths) || changedPaths.some(path => typeof path !== 'string')) throw new Error('PORTABLE_CHANGED_PATHS_INVALID');
  const selected = new Set();
  const reasons = new Map();
  const unknownPaths = [];
  const excludedPaths = [];
  const errors = [];
  const include = (suite, reason) => {
    selected.add(suite.id);
    if (!reasons.has(suite.id)) reasons.set(suite.id, new Set());
    reasons.get(suite.id).add(reason);
  };
  if (profile === 'repository') for (const suite of registry.suites) if (suite.profiles.includes(profile)) include(suite, 'whole-repository baseline');
  for (const original of [...new Set(changedPaths)].sort()) {
    const path = original.replaceAll('\\', '/');
    if (!path || path.startsWith('/') || /^[a-z]:/i.test(path) || path.split('/').some(part => part === '..' || part === '.' || !part) || /[\x00-\x1f]/.test(path)) {
      errors.push({ code: 'COVERAGE_PATH_INVALID', path: original, message: 'Expected a relative repository path' });
      continue;
    }
    if (registry.globalPaths.some(pattern => matches(path, pattern))) {
      for (const suite of registry.suites) if (suite.profiles.includes(profile)) include(suite, `global policy/configuration: ${path}`);
      continue;
    }
    if (registry.prosePatterns.some(pattern => matches(path, pattern)) || registry.ignoredPaths.some(pattern => matches(path, pattern))) continue;
    const exclusion = registry.exclusions.find(entry => matches(path, entry.pattern));
    if (exclusion) { excludedPaths.push({ path, reason: exclusion.reason }); continue; }
    const owners = registry.suites.filter(suite => suite.paths.some(pattern => matches(path, pattern)));
    if (!owners.length) {
      unknownPaths.push(path);
      errors.push({ code: 'COVERAGE_PATH_UNMAPPED', path, message: 'Runtime-affecting input has no maintained suite owner' });
    }
    const applicable = owners.filter(suite => suite.profiles.includes(profile));
    if (owners.length && !applicable.length) errors.push({ code: 'COVERAGE_PROFILE_UNSUPPORTED', path, message: 'Owned runtime input has no maintained check in the selected profile' });
    for (const suite of applicable) include(suite, `changed path: ${path}`);
  }
  if (selected.size) for (const id of registry.alwaysSuiteIds) {
    const suite = registry.suites.find(candidate => candidate.id === id);
    if (suite.profiles.includes(profile)) include(suite, 'retained cheap repository integrity check');
  }
  // Consumer edges are transitive. Cycles are safe and do not duplicate checks.
  for (let previous = -1; previous !== selected.size;) {
    previous = selected.size;
    for (const suite of registry.suites) if (selected.has(suite.id)) for (const id of suite.consumers) {
      const consumer = registry.suites.find(candidate => candidate.id === id);
      if (consumer.profiles.includes(profile)) include(consumer, `consumer of ${suite.id}`);
    }
  }
  const suites = registry.suites.filter(suite => selected.has(suite.id)).map(suite => ({ ...suite, selectionReasons: [...reasons.get(suite.id)].sort() }));
  return { profile, suiteIds: suites.map(suite => suite.id), suites,
    groups: Object.fromEntries(PORTABLE_GROUPS.map(group => [group, suites.filter(suite => suite.group === group).map(suite => suite.id)])),
    unknownPaths: [...new Set(unknownPaths)], excludedPaths, errors, registryDigest: registry.registryDigest ?? null };
}
