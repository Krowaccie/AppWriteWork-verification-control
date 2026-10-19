import test from 'node:test';
import assert from 'node:assert/strict';
import { allocateFixtureNetworks, choosePrivateSubnets } from './network-allocation.mjs';

test('crowded default pools do not prevent distinct explicit task-private subnets', () => {
  const existing = ['172.16.0.0/12', '192.168.0.0/16', '10.231.0.0/16', 'fd00::/64'];
  const selected = choosePrivateSubnets(existing, 'sm9-owned-network-fixture');
  assert.deepEqual(Object.keys(selected), ['lab', 'private', 'ingress']);
  assert.equal(new Set(Object.values(selected)).size, 3);
  assert.ok(Object.values(selected).every(value => /^10\.232\.\d+\.0\/24$/u.test(value)));
  assert.deepEqual(choosePrivateSubnets([...existing].reverse(), 'sm9-owned-network-fixture'), selected);
});

test('selection cannot overlap broad foreign routes or silently accept malformed IPv4 evidence', () => {
  assert.throws(() => choosePrivateSubnets(['10.0.0.0/8'], 'sm9-owned-network-fixture'), /FREE_SUBNETS_UNAVAILABLE/);
  assert.throws(() => choosePrivateSubnets(['0.0.0.0/0'], 'sm9-owned-network-fixture'), /FREE_SUBNETS_UNAVAILABLE/);
  for (const subnet of ['10.231.0.1/24', '10.231.999.0/24', '10.0231.0.0/24', 'not-a-subnet', 'invalid:ipv6/64', 'fd00::/129', undefined]) {
    assert.throws(() => choosePrivateSubnets([subnet], 'sm9-owned-network-fixture'), /SUBNET_INVALID/);
  }
});

test('live allocator uses read-only exact network inventory and rejects a substituted response', async () => {
  const id = 'a'.repeat(64), calls = [];
  const result = await allocateFixtureNetworks({ seed: 'sm9-owned-network-fixture', docker: async args => {
    calls.push(args); return args[1] === 'ls' ? id : JSON.stringify([{ Id: id, IPAM: { Config: [{ Subnet: '10.231.0.0/16' }] } }]);
  } });
  assert.ok(result.networkSubnets.lab.startsWith('10.232.'));
  assert.deepEqual(calls, [['network', 'ls', '--quiet', '--no-trunc'], ['network', 'inspect', id]]);
  await assert.rejects(allocateFixtureNetworks({ seed: 'sm9-owned-network-fixture', docker: async args => args[1] === 'ls' ? id : JSON.stringify([{ Id: 'b'.repeat(64) }]) }), /INVENTORY_INVALID/);
});
