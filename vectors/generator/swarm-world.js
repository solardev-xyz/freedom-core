'use strict';

// The swarm reference's main-process modules, loaded whole from the
// checkout for each run, unpatched, over a scripted world (design 0015,
// SWM-1). Everything under src/ is loaded fresh, so each run starts with the
// modules' own state empty (read budgets, tag owners, the GSOC cache, the
// feed store's cache). The packages (bee-js, core-sdk, ethers,
// better-sqlite3) are the checkout's install, loaded once.
//
// Stubbed, as the world a run scripts:
// - Electron and electron-log, main's logger: inert;
// - the service registry: the fake node's URL (`getAntApiUrl`);
// - the publish setup service: the run's readiness (`getPublishReadiness`);
// - the vault timer: each reset noted;
// - the identity manager: the vault's addresses for the test keys of
//   keys.json (`abandon-12`'s Bee wallet and publisher keys), or the locked
//   vault's answers;
// - the identity core (`core/vault-backend.js`): `sign.soc` signs with
//   core-sdk's own makeContentAddressedChunk(…).toSingleOwnerChunk(…) under
//   the key the reference names, each call noted;
// - the core's grant mirror (`core/grants.js`): the run's Swarm grants;
// - the Freedom data directory: a fresh directory per run, where the feed
//   store, the manifest store and the publish history keep their files.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');
const { createRequire } = Module;

const SILENT = { info() {}, warn() {}, error() {}, debug() {}, log() {}, verbose() {} };
const ELECTRON = (dir) => ({
  ipcMain: { handle() {}, on() {}, removeHandler() {} },
  app: { getPath: () => dir, isPackaged: false },
  dialog: {},
  BrowserWindow: { getAllWindows: () => [] },
  session: { defaultSession: {} },
});

/** The test keys the signer uses: keys.json's `abandon-12`. */
function testKeys(keysJson) {
  const vector = keysJson.vectors.find((v) => v.id === 'abandon-12');
  assert.ok(vector, 'keys.json lacks abandon-12');
  const publishers = new Map(vector.publisherKeys.map((k) => [k.originIndex, k]));
  return { bee: vector.beeWallet, publishers };
}

/**
 * Loads the reference fresh and returns its modules and the run's state.
 * `world`: { nodeUrl, readiness, unlocked, grants, keys, core, dir, clock }.
 */
function loadReference(checkout, world) {
  const src = path.join(checkout, 'src') + path.sep;
  for (const key of Object.keys(require.cache)) {
    if (key.startsWith(src)) delete require.cache[key];
  }
  const events = world.events;
  const { core, keys } = world;
  const signSoc = (key, { identifier, payload, span }, options = {}) => {
    const record = {
      key,
      identifier: Buffer.from(identifier).toString('hex'),
      payload: Buffer.from(payload).toString('hex'),
      ...(span !== undefined && span !== null ? { span: String(span) } : {}),
      ...(options.authorization ? { authorization: options.authorization } : {}),
      page: options.page !== undefined && options.page !== null,
    };
    events.push({ sign_soc: record });
    if (!world.unlocked) return Promise.reject(Object.assign(new Error('Vault is locked'), { code: 'vault_locked' }));
    let privateKey;
    if (key.kind === 'bee_wallet') privateKey = keys.bee.privateKey;
    else if (key.kind === 'publisher') privateKey = keys.publishers.get(key.origin_index)?.privateKey;
    assert.ok(privateKey, `no test key for ${JSON.stringify(key)}`);
    const cac = core.makeContentAddressedChunk(payload, span === undefined || span === null ? undefined : BigInt(span));
    const soc = cac.toSingleOwnerChunk(new core.Identifier(identifier), privateKey.replace(/^0x/, ''));
    return Promise.resolve({
      signature: '0x' + soc.signature.toHex(),
      owner: soc.owner.toChecksum(),
      chunk_address: '0x' + cac.address.toHex(),
      soc_address: '0x' + soc.address.toHex(),
      span: cac.span.toBigInt().toString(),
    });
  };
  const grantStore = () => ({
    get: (key) => (world.grants[key] ? structuredClone(world.grants[key]) : null),
    all: () => Object.values(world.grants).map((g) => structuredClone(g)),
    whenLoaded: async () => true,
    grant: async (change, caller) => {
      const key = change.key ?? caller?.origin;
      events.push({ grant: { change, caller: caller === null ? 'shell' : (typeof caller === 'string' ? caller : 'page') } });
      const record = world.grants[key] || { origin: key, connectedAt: world.clock.now, lastUsed: world.clock.now,
        autoApprove: { publish: false, feeds: false, signing: false, messaging: false } };
      if (change.op === 'connect') world.grants[key] = record;
      else if (change.op === 'flag') world.grants[key] = { ...record, autoApprove: { ...record.autoApprove, [change.flag]: true } };
      else if (change.op === 'messaging') world.grants[key] = { ...record, messaging: true };
    },
    revoke: async (key, what, caller) => {
      events.push({ revoke: { key, what, caller: caller === null ? 'shell' : (typeof caller === 'string' ? caller : 'page') } });
      const record = world.grants[key];
      if (!record) return;
      if (what === 'grant') delete world.grants[key];
      else if (what === 'messaging') world.grants[key] = { ...record, messaging: false };
      else if (what?.flag) world.grants[key] = { ...record, autoApprove: { ...record.autoApprove, [what.flag]: false } };
    },
    touch: async () => {},
  });
  const stubs = {
    'src/main/service-registry.js': { getAntApiUrl: () => world.nodeUrl },
    'src/main/swarm/publish-setup-service.js': {
      getPublishReadiness: async () => {
        events.push({ readiness: 'publish', after_requests: world.requestCount ? world.requestCount() : 0 });
        if (world.readiness === 'throws') throw new Error('readiness failed');
        return world.readiness;
      },
    },
    'src/main/vault-timer.js': { resetVaultAutoLockTimer: () => events.push({ vault_timer_reset: true }) },
    'src/main/identity-manager.js': {
      getBeeWalletAddress: async () => (world.unlocked ? keys.bee.address : null),
      getPublisherAddress: async (index) => {
        // identity-manager.js's own answers (getPublisherAddress, :311-320).
        if (typeof index !== 'number' || index < 0 || !Number.isInteger(index)) {
          throw new Error('Origin index must be a non-negative integer');
        }
        if (!world.unlocked) throw new Error('Vault must be unlocked to derive publisher keys');
        const key = keys.publishers.get(index);
        assert.ok(key, `keys.json has no publisher key at index ${index}`);
        return key.address;
      },
      getDerivedWallets: async () => [],
    },
    'src/main/core/vault-backend.js': { vaultBackend: { sign: { soc: signSoc }, touch: () => {} } },
    'src/main/core/grants.js': { grantStore },
    'src/main/freedom-root.js': { getFreedomDataPath: (name) => path.join(world.dir, name) },
    'src/main/logger.js': SILENT,
    'src/main/private/private-windows.js': { isPrivateWebContents: () => false },
    'src/main/swarm/bzz-protocol.js': { handleBzzRequest: async () => { throw new Error('no bzz: in the harness'); } },
  };
  const electron = ELECTRON(world.dir);
  const originalLoad = Module._load;
  Module._load = function load(request, parent, isMain) {
    if (parent?.filename?.startsWith(src)) {
      if (request === 'electron') return electron;
      if (request === 'electron-log') return SILENT;
      // Subscription ids: deterministic, from the world's counter.
      if (request === 'crypto' && world.crypto && parent.filename.endsWith(`${path.sep}subscription-registry.js`)) return world.crypto;
      if (request.startsWith('.')) {
        const resolved = Module._resolveFilename(request, parent, isMain);
        const rel = path.relative(checkout, resolved).split(path.sep).join('/');
        if (Object.hasOwn(stubs, rel)) return stubs[rel];
      }
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  const requireRef = createRequire(path.join(checkout, 'src', 'main', 'swarm', 'index.js'));
  try {
    return {
      provider: requireRef('./swarm-provider-ipc.js'),
      feedStore: requireRef('./feed-store.js'),
      feedService: requireRef('./feed-service.js'),
      chunkService: requireRef('./chunk-service.js'),
      swarmService: requireRef('./swarm-service.js'),
      publishService: requireRef('./publish-service.js'),
      messagingService: requireRef('./messaging-service.js'),
      history: requireRef('./publish-history.js'),
      manifests: requireRef('./permission-manifests.js'),
      permissions: requireRef('./swarm-permissions.js'),
      registry: requireRef('./subscription-registry.js'),
      miner: requireRef('./gsoc-miner.js'),
      antApi: requireRef('./ant-storage-api.js'),
      batchErrors: requireRef('./batch-errors.js'),
      load: (rel) => requireRef(rel),
      restore: () => { Module._load = originalLoad; },
    };
  } catch (err) {
    Module._load = originalLoad;
    throw err;
  }
}

function scratchDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'freedom-core-swarm-vectors-'));
}

module.exports = { loadReference, testKeys, scratchDir, SILENT };
