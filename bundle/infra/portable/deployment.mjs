// One topology for operator, maintenance and recovery; the private default stays private.
import {compose, OWNER, VOLUMES} from './compose.mjs';
import {publicCompose, validate} from './public-edge.mjs';
import {holdCompose} from './upgrade-contract.mjs';

export function edgeProfile(s) {
  const e = s.publicEdge;
  if (e === undefined) return null;
  if (!e || e.version !== 1 || !['enabled','held'].includes(e.state) ||
      (e.state === 'held' && !['configured','restore','maintenance','operator'].includes(e.reason)))
    throw new Error('PUBLIC_LIFECYCLE_INVALID');
  validate(e.config);
  for (const value of Object.values(e.ports ?? {}))
    if (!Number.isInteger(value) || value < 0 || value > 65535) throw new Error('PUBLIC_PORT_INVALID');
  return e;
}
export const edgeEnabled = s => edgeProfile(s)?.state === 'enabled';
export const volumeNames = s => [...VOLUMES, ...(edgeProfile(s) ? ['public-tls'] : [])];
export const backupEdge = s => edgeProfile(s) ? {publicEdge: structuredClone(s.publicEdge)} : {};
export function recoveryEdge(s) {
  const e = edgeProfile(s);
  return e ? {publicEdge: {...e, state:'held', reason:'restore', ports:{}}} : {};
}
export function deployment(s, pins) {
  const e = edgeProfile(s);
  const c = edgeEnabled(s) ? publicCompose(s, pins, e.config) : compose(s, pins);
  // Retain ownership even while ingress is held (maintenance or restored clone).
  if (e) c.volumes['public-tls'] = {name:s.project+'-public-tls',labels:{[OWNER]:s.project}};
  // Explicit local private subnets are optional; useful on a crowded Docker Desktop.
  if(new Set(Object.values(s.networkSubnets??{})).size!==Object.keys(s.networkSubnets??{}).length)throw new Error('PORTABLE_SUBNET_DUPLICATE');
  for (const [name,subnet] of Object.entries(s.networkSubnets ?? {})) {
    if (!['lab','private','ingress','public-ingress','mail-egress'].includes(name) ||
        !/^10\.(?:\d{1,3})\.(?:\d{1,3})\.0\/24$/.test(subnet) ||
        subnet.split(/[./]/).slice(0,4).some(n=>Number(n)>255)) throw new Error('PORTABLE_SUBNET_INVALID');
    if (c.networks[name]) c.networks[name].ipam = {config:[{subnet}]};
  }
  return holdCompose(c,s);
}
