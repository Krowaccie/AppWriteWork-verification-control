import assert from 'node:assert/strict';
import test from 'node:test';
import {SENTINEL_IMAGE, SENTINEL_OWNER, createSentinel, assertSentinel, releaseSentinel,
  minimalContainerInventory, observeForeignDrift, assertOwnedRemovalTarget,exactContainerAbsent} from './sentinel.mjs';

const id = 'a'.repeat(64), imageId = 'sha256:' + 'b'.repeat(64);
function fixture() {
  const calls = [];
  let row, persisted, removed = false;
  const docker = async args => {
    calls.push(args);
    if (args[0] === 'image') return JSON.stringify([{Id: imageId}]);
    if (args[0] === 'create') {
      const value = flag => args[args.indexOf(flag) + 1];
      row = {Id: id, Name: '/' + value('--name'), Image: imageId,
        Config: {Image: SENTINEL_IMAGE, User: '65534:65534', Entrypoint:['/bin/true'], Labels: {[SENTINEL_OWNER]: 'audit-task-123',
          'io.appwritework.verification-role': 'cleanup-sentinel'}},
        State: {Running: false, Status: 'created'}, Mounts: [],
        HostConfig: {NetworkMode: 'none', ReadonlyRootfs: true, Privileged: false,
          CapDrop: ['ALL'], SecurityOpt: ['no-new-privileges']}};
      return id;
    }
    if (args[0] === 'inspect') {
      if (removed) throw new Error('PRIVATE_CAUSE');
      return JSON.stringify([row]);
    }
    if (args[0] === 'rm') { removed = true; return id; }
    if (args[0] === 'ps') return removed ? '' : id;
    throw new Error('UNEXPECTED_TEST_DOCKER_COMMAND');
  };
  return {calls, docker, get row() { return row; }, get persisted() { return persisted; },
    create: () => createSentinel({docker, runId: 'audit-task-123', onCreated: async record => { persisted = record; }})};
}

test('separate stopped sentinel is persisted, survives product cleanup, and parent releases exact ID', async () => {
  const f = fixture(), record = await f.create();
  assert.equal(f.persisted, record);
  assert.ok(Object.isFrozen(record));
  const create = f.calls.find(args => args[0] === 'create');
  assert.ok(create.includes('--read-only'));
  assert.ok(!create.some(arg => arg.includes('io.appwritework.portable')));
  assert.equal((await assertSentinel({docker: f.docker, record})).survivedCleanup, true);
  assert.equal(f.calls.filter(args => args[0] === 'rm').length, 0);
  const released = await releaseSentinel({docker: f.docker, record});
  assert.equal(released.parentRemoved, true);
  assert.deepEqual(f.calls.filter(args => args[0] === 'rm'), [['rm', id]]);
  assert.equal(released.remainingOwnedSentinels, 0);
});

test('missing or changed sentinel never authorizes removal', async () => {
  for (const change of [row => {row.Id = 'c'.repeat(64);}, row => {row.Image = 'sha256:' + 'c'.repeat(64);},
    row => {row.Config.Labels[SENTINEL_OWNER] = 'foreign';}, row => {row.Mounts = [{Type: 'bind'}];},
    row => {row.State.Running = true;}, row => {row.HostConfig.NetworkMode = 'host';},
    row => {row.Config.Labels['io.appwritework.portable'] = 'product';}]) {
    const f = fixture(), record = await f.create(); change(f.row);
    await assert.rejects(releaseSentinel({docker: f.docker, record}), /SENTINEL_IDENTITY_CHANGED/);
    assert.equal(f.calls.filter(args => args[0] === 'rm').length, 0);
  }
  const f = fixture(), record = await f.create();
  await assert.rejects(releaseSentinel({docker: async () => {throw new Error('PRIVATE_SECRET');}, record}), /SENTINEL_SURVIVAL_UNCONFIRMED/);
});

test('unconfirmed sentinel removal remains a failure', async () => {
  const f = fixture(), record = await f.create();
  const docker = args => args[0] === 'ps' ? id : f.docker(args);
  await assert.rejects(releaseSentinel({docker, record}), /SENTINEL_REMOVAL_UNCONFIRMED/);
});

test('later Docker configuration changes and incomplete initial records cannot prove survival',async()=>{
  for(const change of [row=>{row.HostConfig.RestartPolicy={Name:'always'};},
    row=>{row.HostConfig.Memory=1048576;},row=>{row.Config.Env=['ALTERED=value'];},
    row=>{row.Config.Entrypoint=['/bin/sh'];}]){
    const f=fixture(),record=await f.create();change(f.row);
    await assert.rejects(releaseSentinel({docker:f.docker,record}),/SENTINEL_(CONFIGURATION|IDENTITY)_CHANGED/);
    assert.equal(f.calls.some(args=>args[0]==='rm'),false);
  }
  const f=fixture(),record=await f.create();const incomplete={...record};delete incomplete.configurationDigest;
  await assert.rejects(assertSentinel({docker:f.docker,record:incomplete}),/SENTINEL_CONFIGURATION_CHANGED/);
});

test('lost or invalid creation reply cannot fabricate a confirmed sentinel identity',async()=>{
  for(const response of ['invalid',null]){
    let persisted=false;
    await assert.rejects(createSentinel({runId:'audit-task-123',onCreated:async()=>{persisted=true;},
      docker:async args=>{
        if(args[0]==='image')return JSON.stringify([{Id:imageId}]);
        if(response===null)throw Error('PRIVATE_LOST_CREATE_REPLY');
        return response;
      }}));
    assert.equal(persisted,false);
  }
});

test('confirmed creation survives a subsequent inspection failure in the private record',async()=>{
  const f=fixture();let persisted;
  await assert.rejects(createSentinel({runId:'audit-task-123',
    docker:args=>args[0]==='inspect'?Promise.reject(Error('PRIVATE_INSPECTION_FAILED')):f.docker(args),
    onCreated:async record=>{persisted=record;}}),/SENTINEL_SURVIVAL_UNCONFIRMED/);
  assert.equal(persisted.id,id);assert.equal(f.calls.some(args=>args[0]==='rm'),false);
});

test('foreign and sentinel IDs cannot enter the owned removal set', () => {
  assertOwnedRemovalTarget(id, [id], 'd'.repeat(64));
  for (const target of ['c'.repeat(64), '--force', id]) {
    assert.throws(() => assertOwnedRemovalTarget(target, [], id), /OUTSIDE_OWNED_REMOVAL_SET/);
  }
  assert.throws(() => assertOwnedRemovalTarget(id, [id], id), /OUTSIDE_OWNED_REMOVAL_SET/);
});

test('absence needs a successful exact-ID probe within the previously validated cohort',async()=>{
  let argv;
  assert.equal(await exactContainerAbsent({id,ownedIds:[id],docker:async args=>{argv=args;return ''}}),true);
  assert.deepEqual(argv,['ps','-aq','--no-trunc','--filter','id='+id]);
  assert.equal(await exactContainerAbsent({id,ownedIds:[id],docker:async()=>id+'\n'}),false);
  for(const raw of ['c'.repeat(64),id+'\n'+id,'PRIVATE_MALFORMED'])
    await assert.rejects(exactContainerAbsent({id,ownedIds:[id],docker:async()=>raw}),/OWNED_CONTAINER_ABSENCE_UNCONFIRMED/);
  await assert.rejects(exactContainerAbsent({id,ownedIds:[id],docker:async()=>{throw Error('PRIVATE_TRANSPORT_ERROR')}}),/OWNED_CONTAINER_ABSENCE_UNCONFIRMED/);
  let called=false;
  for(const options of [{id:'short',ownedIds:[id]},{id,ownedIds:[]},{id,ownedIds:[id],sentinelId:id}])
    await assert.rejects(exactContainerAbsent({...options,docker:async()=>{called=true;return ''}}),/OUTSIDE_OWNED_REMOVAL_SET/);
  assert.equal(called,false);
});

test('minimal inventory never expands whole Docker context or layer size and rejects malformed data', async () => {
  let command;
  const rows = await minimalContainerInventory(async args => {command = args; return JSON.stringify({ID: id, Names: 'foreign', Labels: ''});});
  assert.equal(rows.length, 1);
  assert.ok(!command.includes('{{json .}}') && !command.at(-1).includes('Size'));
  for (const raw of ['PRIVATE_SECRET', '{"ID":"short","Names":"foreign","Labels":""}',
    JSON.stringify({ID: id, Names: 'a', Labels: ''}) + '\n' + JSON.stringify({ID: id, Names: 'b', Labels: ''})]) {
    await assert.rejects(minimalContainerInventory(async () => raw), /SENTINEL_INVENTORY_INVALID/);
  }
});

test('foreign disappearance is recorded separately and never represented as pristine evidence', () => {
  const drift = observeForeignDrift([{ID: id, Names: 'external', Labels: 'SECRET_PRIVATE_LABEL'},
    {ID: 'b'.repeat(64), Names: 'sentinel'}], [], ['b'.repeat(64)]);
  assert.deepEqual(drift.missing, [{id, name: 'external'}]);
  assert.equal(drift.beforeCount, 1);
  assert.ok(!JSON.stringify(drift).includes('SECRET_PRIVATE_LABEL'));
  assert.match(drift.scope, /no pristine/);
});
