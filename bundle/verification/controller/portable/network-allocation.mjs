import { canonical, digest } from './bundle.mjs';
import { isIP } from 'node:net';

function requireThat(value, code) { if (!value) throw new Error(code); }
function range(cidr) {
  requireThat(typeof cidr === 'string', 'INDEPENDENT_NETWORK_SUBNET_INVALID');
  if (cidr.includes(':')) {
    const ipv6 = /^(.+)\/(\d{1,3})$/u.exec(cidr);
    requireThat(ipv6 && isIP(ipv6[1]) === 6 && Number(ipv6[2]) <= 128, 'INDEPENDENT_NETWORK_SUBNET_INVALID');
    return null; // A valid IPv6 subnet cannot overlap an IPv4 subnet.
  }
  const match = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d|[12]\d|3[0-2])$/u.exec(cidr);
  requireThat(match, 'INDEPENDENT_NETWORK_SUBNET_INVALID');
  const octets = match[1].split('.').map(Number), prefix = Number(match[2]);
  requireThat(octets.every(value => value <= 255) && octets.join('.') === match[1], 'INDEPENDENT_NETWORK_SUBNET_INVALID');
  const ip = octets.reduce((value, byte) => value * 256 + byte, 0);
  const size = 2 ** (32 - prefix), first = Math.floor(ip / size) * size;
  requireThat(first === ip, 'INDEPENDENT_NETWORK_SUBNET_INVALID');
  return [first, first + size - 1];
}

export function choosePrivateSubnets(existing, seed) {
  requireThat(Array.isArray(existing) && existing.length <= 4096 && /^[a-z0-9-]{6,100}$/u.test(seed), 'INDEPENDENT_NETWORK_SELECTION_INVALID');
  const occupied = existing.map(range).filter(Boolean);
  const start = Number.parseInt(digest(seed).slice(7, 15), 16) % 85;
  // Only explicit task-owned /24s in RFC1918 space are considered. We never
  // modify daemon address pools, remove foreign networks or silently reuse one.
  for (const second of [231, 232, 233]) for (let offset = 0; offset < 85; offset++) {
    const third = ((start + offset) % 85) * 3;
    const result = Object.fromEntries(['lab', 'private', 'ingress'].map((name, index) => [name, `10.${second}.${third + index}.0/24`]));
    const free = Object.values(result).every(cidr => {
      const [first, last] = range(cidr);
      return occupied.every(([begin, end]) => last < begin || first > end);
    });
    if (free) return result;
  }
  throw new Error('INDEPENDENT_NETWORK_FREE_SUBNETS_UNAVAILABLE');
}

export async function allocateFixtureNetworks({ docker, seed }) {
  const ids = (await docker(['network', 'ls', '--quiet', '--no-trunc'])).trim().split(/\s+/u).filter(Boolean);
  requireThat(ids.length <= 4096 && ids.every(id => /^[a-f0-9]{64}$/u.test(id)) && new Set(ids).size === ids.length, 'INDEPENDENT_NETWORK_INVENTORY_INVALID');
  const rows = ids.length ? JSON.parse(await docker(['network', 'inspect', ...ids])) : [];
  requireThat(Array.isArray(rows) && rows.length === ids.length && rows.every(row => row && ids.includes(row.Id))
    && new Set(rows.map(row => row.Id)).size === ids.length, 'INDEPENDENT_NETWORK_INVENTORY_INVALID');
  const subnets = rows.flatMap(row => row.IPAM?.Config ?? []).map(config => config.Subnet);
  return { strategy: 'collision-checked-task-private-ipv4.v1', networkSubnets: choosePrivateSubnets(subnets, seed),
    observedSubnetInventoryDigest: digest(canonical([...subnets].sort())) };
}
