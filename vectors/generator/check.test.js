'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const SOURCE = path.resolve(__dirname, '..');
const REFERENCE = process.env.FREEDOM_BROWSER_CHECKOUT || '/root/herdr/freedom-browser';
const FILES = ['keys.json', 'mnemonic-validation.json', 'identity-formats.json', 'signing.json', 'naming.json', 'naming-replay.json',
  'fixtures/vaults.json', 'fixtures/bee-keystores.json', 'fixtures/radicle-openssh.json',
  'generator/generate.js', 'generator/signing.js', 'generator/naming.js', 'generator/naming-replay.js'];

function corruptedCheck(filename, corrupt) {
  const copy = fs.mkdtempSync(path.join(os.tmpdir(), 'freedom-core-vectors-'));
  for (const file of FILES) {
    const destination = path.join(copy, file);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(path.join(SOURCE, file), destination);
  }
  const destination = path.join(copy, filename);
  const contents = JSON.parse(fs.readFileSync(destination, 'utf8'));
  corrupt(contents);
  fs.writeFileSync(destination, JSON.stringify(contents, null, 2) + '\n');
  const result = spawnSync(process.execPath, [path.join(copy, 'generator/generate.js'),
    'check', '--freedom-browser', REFERENCE], { encoding: 'utf8', timeout: 60000 });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  return result.stderr;
}

test('check rejects a changed deterministic private key', () => {
  const stderr = corruptedCheck('keys.json', (contents) => {
    contents.vectors[0].userWallets[0].privateKey = '0x' + '00'.repeat(32);
  });
  assert.match(stderr, /Byte mismatch: keys.json/);
});

test('check rejects a changed signature', () => {
  const stderr = corruptedCheck('signing.json', (contents) => {
    const entry = contents.typedData.find((item) => item.result.status === 'success');
    entry.result.signature = entry.result.signature.slice(0, -2) + '1b';
  });
  assert.match(stderr, /Byte mismatch: signing.json/);
});

test('check rejects a changed naming result', () => {
  const stderr = corruptedCheck('naming.json', (contents) => {
    contents.contenthash[0].js.decoded = 'Qm' + 'x'.repeat(44);
  });
  assert.match(stderr, /Byte mismatch: naming.json/);
});

test('check decrypts vault fixtures and rejects a damaged authentication tag', () => {
  const stderr = corruptedCheck('fixtures/vaults.json', (contents) => {
    const vault = JSON.parse(contents.fixtures[0].fileContents);
    const encrypted = JSON.parse(vault.encrypted);
    const data = Buffer.from(encrypted.data, 'base64');
    data[data.length - 1] ^= 1;
    encrypted.data = data.toString('base64');
    vault.encrypted = JSON.stringify(encrypted);
    contents.fixtures[0].fileContents = JSON.stringify(vault, null, 2);
  });
  assert.match(stderr, /Incorrect password/);
});

test('check decrypts Bee fixtures and rejects a damaged ciphertext', () => {
  const stderr = corruptedCheck('fixtures/bee-keystores.json', (contents) => {
    const keystore = JSON.parse(contents.fixtures[0].keystore);
    const data = Buffer.from(keystore.Crypto.ciphertext, 'hex');
    data[0] ^= 1;
    keystore.Crypto.ciphertext = data.toString('hex');
    contents.fixtures[0].keystore = JSON.stringify(keystore);
  });
  assert.match(stderr, /incorrect password/i);
});

test('check requires the positive legacy fallback fixture', () => {
  const stderr = corruptedCheck('fixtures/vaults.json', (contents) => {
    delete contents.legacyFixtures;
  });
  assert.match(stderr, /Missing positive legacy vault fixture/);
});

test('check decrypts the positive legacy fallback fixture', () => {
  const stderr = corruptedCheck('fixtures/vaults.json', (contents) => {
    const vault = JSON.parse(contents.legacyFixtures[0].fileContents);
    const payload = JSON.parse(vault.encrypted);
    const data = Buffer.from(payload.data, 'base64');
    data[data.length - 1] ^= 1;
    payload.data = data.toString('base64');
    vault.encrypted = JSON.stringify(payload);
    contents.legacyFixtures[0].fileContents = JSON.stringify(vault, null, 2);
  });
  assert.match(stderr, /Incorrect password/);
});

test('check parses OpenSSH and rejects unequal check integers', () => {
  const stderr = corruptedCheck('fixtures/radicle-openssh.json', (contents) => {
    const identity = contents.fixtures[0].identity;
    const lines = identity.privateKeyFile.trimEnd().split('\n');
    const data = Buffer.from(lines.slice(1, -1).join(''), 'base64');
    let offset = 15;
    // cipher, KDF name, KDF options
    for (let field = 0; field < 3; field += 1) offset += 4 + data.readUInt32BE(offset);
    offset += 4; // key count
    offset += 4 + data.readUInt32BE(offset); // public key blob
    offset += 4; // private section length
    data[offset] ^= 1;
    const base64 = data.toString('base64');
    identity.privateKeyFile = lines[0] + '\n' + base64.match(/.{1,70}/g).join('\n') + '\n' + lines.at(-1) + '\n';
  });
  assert.match(stderr, /AssertionError/);
  assert.match(stderr, /parseOpenSSH/);
});

test('check rejects a changed replay request', () => {
  const stderr = corruptedCheck('naming-replay.json', (contents) => {
    contents.scenarios[0].io[0].params = ['0x1'];
  });
  assert.match(stderr, /Byte mismatch: naming-replay.json/);
});

// The replay runs in this process: it must not see or leave global state.
const replay = require('./naming-replay');

function referenceEthers() {
  return require('node:module').createRequire(path.join(REFERENCE, 'package.json'))('ethers').ethers;
}

function globalsSnapshot(ethers) {
  return {
    random: Math.random,
    date: Date,
    setTimeout,
    load: require('node:module')._load,
    getUrl: new ethers.FetchRequest('https://snapshot.invalid').getUrlFunc,
    env: { ETH_RPC: process.env.ETH_RPC, TEZOS_RPC: process.env.TEZOS_RPC },
  };
}

function definition(ethers, id) {
  return replay.scenarioDefinitions(ethers).find((scenario) => scenario.id === id);
}

test('replay ignores the ambient resolver environment', async () => {
  const ethers = referenceEthers();
  const FakeTimers = replay.loadFakeTimers(REFERENCE);
  const clean = await replay.runScenario(REFERENCE, ethers, FakeTimers, definition(ethers, 'quorum-agree'));
  process.env.ETH_RPC = 'https://ambient.rpc.example';
  process.env.TEZOS_RPC = 'https://ambient.tez.example';
  try {
    assert.deepEqual(await replay.runScenario(REFERENCE, ethers, FakeTimers, definition(ethers, 'quorum-agree')), clean);
    assert.equal(process.env.ETH_RPC, 'https://ambient.rpc.example');
    assert.equal(process.env.TEZOS_RPC, 'https://ambient.tez.example');
  } finally {
    delete process.env.ETH_RPC;
    delete process.env.TEZOS_RPC;
  }
});

test('replay leaves its input unchanged and repeats exactly', async () => {
  const ethers = referenceEthers();
  const FakeTimers = replay.loadFakeTimers(REFERENCE);
  const scenario = definition(ethers, 'ccip-slow-gateway-then-another-name');
  const before = structuredClone(scenario);
  const first = await replay.runScenario(REFERENCE, ethers, FakeTimers, scenario);
  assert.deepEqual(scenario, before);
  assert.deepEqual(await replay.runScenario(REFERENCE, ethers, FakeTimers, scenario), first);
});

test('replay restores every global, also when setup fails', async () => {
  const ethers = referenceEthers();
  const FakeTimers = replay.loadFakeTimers(REFERENCE);
  const before = globalsSnapshot(ethers);
  await replay.runScenario(REFERENCE, ethers, FakeTimers, definition(ethers, 'quorum-agree'));
  assert.deepEqual(globalsSnapshot(ethers), before);
  await assert.rejects(replay.runScenario(path.join(os.tmpdir(), 'no-such-checkout'), ethers, FakeTimers, definition(ethers, 'quorum-agree')), /ENOENT/);
  assert.deepEqual(globalsSnapshot(ethers), before);
});

test('replay patches the reference per scenario, and loudly', async () => {
  const ethers = referenceEthers();
  const FakeTimers = replay.loadFakeTimers(REFERENCE);
  const scenario = definition(ethers, 'deviation-ccip-urls');
  const patched = await replay.runScenario(REFERENCE, ethers, FakeTimers, scenario);
  assert.deepEqual(patched.patches.map((patch) => patch.id), ['ccip-urls']);
  // A patched module never outlives its scenario.
  const plain = await replay.runScenario(REFERENCE, ethers, FakeTimers, { ...scenario, deviation: undefined, patches: [] });
  assert.notDeepEqual(plain.steps, patched.steps);
  assert.deepEqual(await replay.runScenario(REFERENCE, ethers, FakeTimers, scenario), patched);
  await assert.rejects(replay.runScenario(REFERENCE, ethers, FakeTimers, { ...scenario, patches: ['no-such-patch'] }), /unknown patch no-such-patch/);
  // An edit whose text isn't there exactly once fails the run.
  replay.PATCHES.stale = () => ({ text: 'stale', source: { 'ens-resolver.js': { edits: [['no such text', '']], append: [] } } });
  try {
    await assert.rejects(replay.runScenario(REFERENCE, ethers, FakeTimers, { ...scenario, patches: ['stale'] }), /patch for ens-resolver\.js: 0 matches/);
  } finally {
    delete replay.PATCHES.stale;
  }
});

test('replay fails loudly on unscripted I/O', async () => {
  const ethers = referenceEthers();
  const FakeTimers = replay.loadFakeTimers(REFERENCE);
  const unscriptedCall = structuredClone(definition(ethers, 'quorum-agree'));
  delete unscriptedCall.world.calls.resolve;
  await assert.rejects(replay.runScenario(REFERENCE, ethers, FakeTimers, unscriptedCall), /unscripted I\/O: resolve:contenthash call to/);
  const undeclaredGateway = structuredClone(definition(ethers, 'ccip-fast-gateway'));
  delete undeclaredGateway.world.gateways;
  await assert.rejects(replay.runScenario(REFERENCE, ethers, FakeTimers, undeclaredGateway), /undeclared gateway gw\.example/);
});

test('replay transport keeps ethers\' cancel and timeout semantics', async () => {
  const ethers = referenceEthers();
  const FakeTimers = replay.loadFakeTimers(REFERENCE);
  const probe = (options, hosts = {}) => replay.runScenario(REFERENCE, ethers, FakeTimers, {
    id: 'transport-probe',
    world: { endpoints: ['https://a.rpc.example'], hosts: { 'a.rpc.example': { delay: 10, ...hosts } } },
    steps: [{ call: { fn: '$fetch', args: ['https://a.rpc.example', options] } }],
  });
  const outcome = async (options, hosts) => {
    const run = await probe(options, hosts);
    const [result] = run.steps[0].results;
    return { thrown: result.thrown ?? null, settled: result.settled, io: run.io[0] };
  };
  // A cancel at the reply's own instant wins, as checkSignal() does natively.
  const sameInstant = await outcome({ cancelAt: 10 });
  assert.match(sameInstant.thrown, /cancelled/);
  assert.equal(sameInstant.io.outcome, 'answered');
  assert.equal(sameInstant.io.rejected.code, 'CANCELLED');
  // The inactivity timeout, either side of a 10 ms reply.
  assert.match((await outcome({ timeout: 9 })).thrown, /request timeout/);
  // Zero turns the timer off.
  assert.equal((await outcome({ timeout: 0 })).thrown, null);
  const inTime = await outcome({ timeout: 11 });
  assert.equal(inTime.thrown, null);
  assert.equal(inTime.io.rejected, undefined);
  // A hang rejects at ethers' default 300 s and the exchange stays open.
  const hang = await outcome({}, { hang: true });
  assert.match(hang.thrown, /request timeout/);
  assert.equal(hang.settled, 300_000);
  assert.equal(hang.io.outcome, 'open');
});

test('replay attributes every verifier raw call to its operation', () => {
  const vectors = JSON.parse(fs.readFileSync(path.join(SOURCE, 'naming-replay.json'), 'utf8'));
  for (const scenario of vectors.scenarios) {
    const ops = new Map(scenario.io.filter((e) => e.kind === 'verified-op').map((e) => [e.id, e]));
    for (const entry of scenario.io) {
      if (entry.kind !== 'verified' && entry.within === undefined) continue;
      const op = ops.get(entry.within);
      assert.ok(op, `${scenario.id}: exchange ${entry.id} has no operation`);
      assert.ok(entry.t >= op.t && (op.end === null || entry.t <= op.end), `${scenario.id}: exchange ${entry.id} outside operation ${op.id}`);
      if (entry.kind === 'verified') assert.equal(entry.host, op.host, `${scenario.id}: exchange ${entry.id} attributed to another verifier`);
    }
  }
  const concurrent = vectors.scenarios.find((s) => s.id === 'colibri-concurrent');
  const owners = concurrent.io.filter((e) => e.kind === 'verified').map((e) => e.within);
  assert.equal(new Set(owners).size, 2, 'each concurrent operation owns its raw call');
});
