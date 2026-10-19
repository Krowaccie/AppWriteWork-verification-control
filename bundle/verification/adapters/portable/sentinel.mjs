import {randomBytes,createHash} from 'node:crypto';

export const SENTINEL_IMAGE = 'node:24.11.1-bookworm@sha256:9a2ed90cd91b1f3412affe080b62e69b057ba8661d9844e143a6bbd76a23260f';
export const SENTINEL_OWNER = 'io.appwritework.verification-sentinel';
const fail = code => { throw new Error(code); };
const requireThat = (value, code) => { if (!value) fail(code); };
const parse = (raw, code) => { try { return JSON.parse(raw); } catch { return fail(code); } };
const canonical=value=>Array.isArray(value)?value.map(canonical):value&&typeof value==='object'
  ?Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonical(value[key])])):value;
const configurationDigest=row=>createHash('sha256').update(JSON.stringify(canonical({Config:row.Config,HostConfig:row.HostConfig}))).digest('hex');

export async function minimalContainerInventory(docker) {
  // Expanding {{json .}} also requests Size and can fail while an unrelated
  // ephemeral container's layer disappears. These fields need no layer stats.
  const format = '{"ID":{{json .ID}},"Names":{{json .Names}},"Labels":{{json .Labels}}}';
  const raw = await docker(['ps', '-a', '--no-trunc', '--format', format]);
  const rows = raw.trim().split(/\r?\n/).filter(Boolean).map(line => parse(line, 'SENTINEL_INVENTORY_INVALID'));
  requireThat(rows.every(row => row && typeof row === 'object' && /^[a-f0-9]{64}$/.test(row.ID) && typeof row.Names === 'string' && row.Names.length > 0
    && typeof row.Labels === 'string') && new Set(rows.map(row => row.ID)).size === rows.length, 'SENTINEL_INVENTORY_INVALID');
  return rows;
}

export function observeForeignDrift(before, after, excludedIds = []) {
  const excluded = new Set(excludedIds), remaining = new Set(after.map(row => row.ID));
  return {scope: 'observed foreign inventory only; no pristine-environment claim',
    beforeCount: before.filter(row => !excluded.has(row.ID)).length,
    missing: before.filter(row => !excluded.has(row.ID) && !remaining.has(row.ID)).map(row => ({id: row.ID, name: row.Names})),
    addedCount: after.filter(row => !excluded.has(row.ID) && !before.some(old => old.ID === row.ID)).length};
}

export function assertOwnedRemovalTarget(id, ownedIds, sentinelId) {
  requireThat(/^[a-f0-9]{64}$/.test(id) && id !== sentinelId && new Set(ownedIds).has(id), 'SENTINEL_OUTSIDE_OWNED_REMOVAL_SET');
}

// Callers supply a cohort whose ownership was already positively validated.
// Failed Docker operations alone never establish absence.
export async function exactContainerAbsent({docker,id,ownedIds,sentinelId}) {
  assertOwnedRemovalTarget(id,ownedIds,sentinelId);
  let raw;
  try{raw=await docker(['ps','-aq','--no-trunc','--filter','id='+id]);}
  catch{fail('OWNED_CONTAINER_ABSENCE_UNCONFIRMED');}
  requireThat(typeof raw==='string','OWNED_CONTAINER_ABSENCE_UNCONFIRMED');
  const rows=raw.trim().split(/\s+/).filter(Boolean);
  requireThat(rows.length===0||(rows.length===1&&rows[0]===id),'OWNED_CONTAINER_ABSENCE_UNCONFIRMED');
  return rows.length===0;
}

function validateSentinelRows(rows,record,{initial=false}={}) {
  requireThat(record && /^[a-f0-9]{64}$/.test(record.id) && /^sha256:[a-f0-9]{64}$/.test(record.imageId)
    && record.image === SENTINEL_IMAGE && /^verify-sentinel-[a-f0-9]{16}$/.test(record.name)
    && /^[a-zA-Z0-9_-]{6,100}$/.test(record.runId), 'SENTINEL_RECORD_INVALID');
  const row = rows?.[0], labels = row?.Config?.Labels || {};
  requireThat(Array.isArray(rows) && rows.length === 1 && row && typeof row === 'object' && row.Id === record.id && row.Name === '/' + record.name
    && row.Image === record.imageId && row.Config.Image === record.image
    && labels[SENTINEL_OWNER] === record.runId && labels['io.appwritework.verification-role'] === 'cleanup-sentinel'
    && !labels['io.appwritework.portable'] && !labels['com.docker.compose.project']
    && row.State?.Running === false && row.State?.Status === 'created' && row.Mounts?.length === 0
    && row.HostConfig?.NetworkMode === 'none' && row.HostConfig.ReadonlyRootfs === true
    && row.HostConfig.Privileged === false && row.Config.User === '65534:65534'
    && JSON.stringify(row.Config.Entrypoint)===JSON.stringify(['/bin/true'])
    && row.HostConfig.CapDrop?.includes('ALL') && row.HostConfig.SecurityOpt?.some(value => /^no-new-privileges(?::true)?$/.test(value)),
  'SENTINEL_IDENTITY_CHANGED');
  requireThat(initial||(/^[a-f0-9]{64}$/.test(record.configurationDigest)&&record.configurationDigest===configurationDigest(row)),
    'SENTINEL_CONFIGURATION_CHANGED');
  return row;
}

export async function assertSentinel({docker, record}) {
  requireThat(record&&/^[a-f0-9]{64}$/.test(record.id),'SENTINEL_RECORD_INVALID');
  let rows;
  try { rows = parse(await docker(['inspect', record.id]), 'SENTINEL_INSPECTION_INVALID'); }
  catch { fail('SENTINEL_SURVIVAL_UNCONFIRMED'); }
  validateSentinelRows(rows,record);
  return {status: 'PASS', id: record.id, name: record.name, imageId: record.imageId, survivedCleanup: true};
}

export async function createSentinel({docker, runId, image = SENTINEL_IMAGE, onCreated = async () => {}}) {
  requireThat(/^[a-zA-Z0-9_-]{6,100}$/.test(runId) && image === SENTINEL_IMAGE, 'SENTINEL_CREATE_SCOPE_INVALID');
  const imageRows = parse(await docker(['image', 'inspect', image]), 'SENTINEL_IMAGE_INVALID');
  requireThat(Array.isArray(imageRows) && imageRows.length === 1 && imageRows[0]
    && /^sha256:[a-f0-9]{64}$/.test(imageRows[0].Id), 'SENTINEL_IMAGE_INVALID');
  const name = 'verify-sentinel-' + randomBytes(8).toString('hex');
  const id = (await docker(['create', '--name', name, '--network', 'none', '--read-only', '--user', '65534:65534',
    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--label', SENTINEL_OWNER + '=' + runId,
    '--label', 'io.appwritework.verification-role=cleanup-sentinel', '--entrypoint', '/bin/true', image])).trim();
  requireThat(/^[a-f0-9]{64}$/.test(id), 'SENTINEL_CREATE_ID_INVALID');
  const confirmed = Object.freeze({id, name, runId, image, imageId: imageRows[0].Id});
  // Persist a confirmed creation before the first fallible inspection. A lost
  // or invalid create reply has no confirmed ID and must remain non-PASS.
  await onCreated(confirmed);
  let rows;
  try { rows=parse(await docker(['inspect',id]),'SENTINEL_INSPECTION_INVALID'); }
  catch { fail('SENTINEL_SURVIVAL_UNCONFIRMED'); }
  const row=validateSentinelRows(rows,confirmed,{initial:true});
  const record=Object.freeze({...confirmed,configurationDigest:configurationDigest(row)});
  await onCreated(record);
  await assertSentinel({docker, record});
  return record;
}

export async function releaseSentinel({docker, record}) {
  const survival = await assertSentinel({docker, record});
  await docker(['rm', record.id]); // Never available to product cleanup itself.
  const remaining = (await docker(['ps', '-aq', '--no-trunc', '--filter', 'id=' + record.id])).trim();
  requireThat(remaining === '', 'SENTINEL_REMOVAL_UNCONFIRMED');
  return {...survival, parentRemoved: true, remainingOwnedSentinels: 0};
}
