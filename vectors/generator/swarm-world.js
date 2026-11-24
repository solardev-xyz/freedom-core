'use strict';

// The swarm reference's main-process modules, loaded whole from the
// checkout for each run, unpatched, over a scripted world (design 0015,
// SWM-1). Everything under src/ is loaded fresh, so each run starts with the
// modules' own state empty (read budgets, tag owners, the GSOC cache, the
// feed store's cache, the dispatcher's manifest checks). The packages
// (bee-js, core-sdk, ethers, better-sqlite3) are the checkout's install,
// loaded once.
//
// Stubbed, as the world a run scripts:
// - Electron and electron-log, main's logger: inert; a guest's webContents
//   is the run's live guest, on the default session;
// - the service registry: the fake node's URL (`getAntApiUrl`);
// - the publish setup service: the run's readiness (`getPublishReadiness`);
// - the vault timer: each reset noted;
// - the identity core (`core/vault-backend.js`): the vault's status, its
//   addresses for the test keys of keys.json (`abandon-12`'s Bee wallet and
//   publisher keys) or the locked vault's refusal, and `sign.soc`, which
//   signs with core-sdk's own makeContentAddressedChunk(…).toSingleOwnerChunk(…)
//   under the key the reference names, each call noted;
// - identity-manager.js's own lower modules (its profile paths, the node
//   identity guard, the Radicle gate, private files, the fs offload), for
//   its requires only, as stores.js loads it: the module itself is the
//   reference's, so every text it answers is its own;
// - the core's grant mirror (`core/grants.js`): the run's Swarm grants,
//   each write noted;
// - the Freedom data directory: a fresh directory per run, where the feed
//   store, the manifest store, the publish history and settings.json keep
//   their files.

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
  BrowserWindow: { getAllWindows: () => [], fromId: () => null },
  session: { defaultSession: {} },
  webContents: { fromId: () => null, getAllWebContents: () => [] },
  nativeTheme: {},
});
const inert = () => {};

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
  // A world the case didn't script (a key keys.json lacks): the run fails
  // after its step (world.fatal), whatever the reference made of the throw.
  const fatal = (message) => {
    world.fatal ??= new Error(message);
    return world.fatal;
  };
  const signSoc = (key, { identifier, payload, span }, options = {}) => {
    const record = {
      key,
      identifier: Buffer.from(identifier).toString('hex'),
      payload: Buffer.from(payload).toString('hex'),
      ...(span !== undefined && span !== null ? { span: String(span) } : {}),
      ...(options.authorization ? { authorization: options.authorization } : {}),
      page: options.page ?? null,
    };
    events.push({ sign_soc: record });
    if (!world.unlocked) return Promise.reject(Object.assign(new Error('Vault is locked'), { code: 'vault_locked' }));
    let privateKey;
    if (key.kind === 'bee_wallet') privateKey = keys.bee.privateKey;
    else if (key.kind === 'publisher') privateKey = keys.publishers.get(key.origin_index)?.privateKey;
    if (!privateKey) return Promise.reject(fatal(`no test key for ${JSON.stringify(key)}`));
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
    whenLoaded: async () => world.grantsLoaded !== false,
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
    // `approval.touch`: a page's last use, under `page`.
    touch: async (page) => {
      events.push({ touch: page?.origin === undefined ? 'shell' : 'page' });
      if (world.grants[page?.origin]) world.grants[page.origin] = { ...world.grants[page.origin], lastUsed: world.clock.now };
    },
  });
  // The identity core's vault (core/vault-backend.js), as identity-manager.js
  // and the signer call it: its status, the addresses of keys.json's test
  // keys while it is unlocked, the core's refusal while it is locked.
  const lockedError = () => Object.assign(new Error('Vault is locked'), { code: 'vault_locked' });
  const vaultBackend = {
    status: async () => ({ exists: true, unlocked: world.unlocked }),
    addresses: async ({ accounts = [], publishers = [] } = {}) => {
      if (!world.unlocked) throw lockedError();
      if (accounts.length) throw fatal('the swarm vectors derive no user wallet');
      return {
        user_wallets: [],
        bee_wallet: keys.bee.address,
        publishers: publishers.map((index) => {
          const key = keys.publishers.get(index);
          if (!key) throw fatal(`keys.json has no publisher key at index ${index}`);
          return { origin_index: index, address: key.address };
        }),
        radicle: null,
      };
    },
    accounts: { list: async () => [] },
    sign: { soc: signSoc },
    touch: inert,
  };
  // identity-manager.js's own lower modules, for its requires only (as
  // stores.js loads it): profile paths in the run's directory, the node,
  // Radicle and file wiring inert.
  const identityStubs = {
    'src/main/fs-offload.js': {},
    'src/main/profile-paths.js': {
      getIdentityDataDir: () => path.join(world.dir, 'identity'),
      getAntDataDir: () => path.join(world.dir, 'ant'),
      getIpfsDataDir: () => path.join(world.dir, 'ipfs'),
      getRadicleDataDir: () => path.join(world.dir, 'radicle'),
      prepareRadicleDataDir: async () => {},
    },
    'src/main/profile-resolver.js': { getActiveProfile: () => ({ id: 'default' }) },
    'src/main/windows/request-window.js': { forSenderWindow: (fn) => fn },
    'src/main/core/node-identity-guard.js': { blockNode: inert, unblockNode: inert, nodeWriteStatus: () => null, restoreNodeWrite: inert },
    'src/main/radicle/radicled-gate.js': { withRadicleGate: (fn) => fn() },
    'src/main/radicle/radicle-backend-kind.js': { radicleBackendKind: () => 'service' },
    'src/main/private-files.js': { withPrivateDir: inert },
    'src/main/swarm/ant-keystore-password.js': {},
  };
  const identityManager = path.join(checkout, 'src', 'main', 'identity-manager.js');
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
    'src/main/core/vault-backend.js': { vaultBackend },
    'src/main/core/grants.js': { grantStore },
    'src/main/freedom-root.js': { getFreedomDataPath: (name) => path.join(world.dir, name) },
    'src/main/logger.js': SILENT,
    'src/main/private/private-windows.js': { isPrivateWebContents: () => false, getPartitionForWebContents: () => null },
    // The bzz: handler, as the manifest check fetches a document's
    // freedom-manifest.json on its guest's session: the world's manifest, or
    // the node's 404.
    'src/main/swarm/bzz-protocol.js': {
      handleBzzRequest: async (request) => {
        if (!/^bzz:\/\/[^/]+\/freedom-manifest\.json$/.test(request.url)) throw new Error(`no bzz: ${request.url} in the harness`);
        events.push({ manifest_fetch: request.url });
        if (world.manifest === undefined) return new Response('Not Found', { status: 404 });
        return new Response(JSON.stringify(world.manifest), { status: 200, headers: { 'content-type': 'application/json' } });
      },
    },
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
        if (parent.filename === identityManager && Object.hasOwn(identityStubs, rel)) return identityStubs[rel];
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
      identityManager: requireRef('../identity-manager.js'),
      pageSwarm: requireRef('../page/page-swarm.js'),
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
