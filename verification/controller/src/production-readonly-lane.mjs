const SHA = /^[0-9a-f]{40}$/;

function deepFreeze(value, seen = new WeakSet()) {
  if (value === null || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function blocked() {
  return deepFreeze({
    status: 'BLOCKED',
    diagnostics: [{
      code: 'CANDIDATE_REVISION_INVALID',
      safeMessage: 'Candidate revision must be one full lowercase Git SHA.',
      retryable: false,
    }],
  });
}

export async function runProductionReadonlyLane({ adapter, candidateRevision = null, artifactId } = {}) {
  if (candidateRevision !== null && !SHA.test(candidateRevision)) return blocked();
  if (typeof adapter?.execute !== 'function') {
    return deepFreeze({
      status: 'BLOCKED',
      diagnostics: [{ code: 'PRODUCTION_READONLY_ADAPTER_INVALID', safeMessage: 'Production adapter is unavailable.', retryable: false }],
    });
  }
  const result = await adapter.execute({ candidateRevision, artifactId });
  return deepFreeze(structuredClone(result));
}
