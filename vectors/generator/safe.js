'use strict';

// vectors/safe.json (design 0016, SAFE-1): what fc-safe computes, as the
// safe reference's Safe modules compute it. The browser's own
// src/main/wallet/safe/ modules run whole and unpatched (safe-executor.js,
// safe-service.js, safe-transactions.js, safe-messages.js and
// signature-collection.js, with pending-store.js, safe-approvals.js and
// message-sessions.js beneath them), over the checkout's installed
// @safe-global/protocol-kit 8.0.11, @safe-global/safe-deployments 1.37.66
// and ethers 6.17.0, refusing any other version. They are loaded fresh for
// each section, and for each case whose modules keep state (a send, a
// message session). The provider is the browser's own test chain
// (__tests__/helpers/stub-chain.js). No reference code is copied, and
// nothing the vectors pin is computed here.
//
// Stubbed, as the world a case scripts:
// - the owners' signers (`wallet/signers.js`): keys.json's test accounts,
//   each signing the typed data it is given with ethers' Wallet, as the
//   browser's test signer does (test-owners.js), or the case's scripted
//   answer in its place;
// - the wallet records (`identity-manager.js`): the owners and the Safes a
//   case sets up, the vault unlocked; a Safe it creates is captured;
// - the executor's send (`transaction-service.js` and `tx-recorder.js`):
//   captured, with a fixed quote, never signed or sent; the fee check
//   (`fee-check.js`) allows it, and the confirmations module
//   (`signing-confirmation.js`) runs the send as it is;
// - the identity core (`core/vault-backend.js`): the typed-data hash (the
//   core's: ethers' TypedDataEncoder.hash, which fc-evm reproduces for every
//   input here, as signing.json pins), the Safe approvals' end, and the
//   pending SafeTx store, in memory;
// - the chain reads outside protocol-kit (`provider-manager.js` and
//   `networks/chain-data.js`): the same test chain, its answers verified;
// - safe-service.js's randomness, for the drawn salts: fixed bytes, which
//   each case records.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const { createRequire } = Module;

// Node's loader as it was when this file was loaded, before the other
// generators' hooks: each of those wraps the one before for good, and a run
// this late, through protocol-kit's deep require graph, would overflow the
// stack through all of them. None of them applies to this checkout's files.
const NODE_LOAD = Module._load;

const PACKAGES = {
  '@safe-global/protocol-kit': '8.0.11',
  '@safe-global/safe-deployments': '1.37.66',
  ethers: '6.17.0',
};
const CHAIN_ID = 100;
const SAFE = 'src/main/wallet/safe';
// The modules the Safe stack may load from the checkout, unstubbed.
const REAL = new Set([
  `${SAFE}/safe-executor.js`, `${SAFE}/safe-service.js`, `${SAFE}/safe-transactions.js`,
  `${SAFE}/safe-messages.js`, `${SAFE}/signature-collection.js`, `${SAFE}/pending-store.js`,
  `${SAFE}/safe-approvals.js`, `${SAFE}/message-sessions.js`, `${SAFE}/errors.js`,
  `${SAFE}/__tests__/helpers/stub-chain.js`, `${SAFE}/__tests__/helpers/proxy-factory-code.js`,
  'src/main/wallet/signing-utils.js',
]);
// identity-manager.js's wallet kinds, which its records carry; each is
// checked against the module's own text (walletTypes).
const WALLET_TYPES = { MNEMONIC: 'mnemonic', LEDGER: 'ledger', REMOTE: 'remote', SAFE: 'safe' };
const MAX_UINT256 = (2n ** 256n - 1n).toString();
// The Safe approval a spent `safe-send` or `safe-message` token gives
// (safe-approvals.js `isApproval`): the wallet's, so `page` is null.
const APPROVAL = { id: '5afe'.repeat(8), page: null };
// The executor's quote, as the stubbed transaction service answers it.
const QUOTE = { gasLimit: '210000', maxFeePerGas: '2000000000', maxPriorityFeePerGas: '1000000000' };
const SENT_HASH = '0x' + 'e1'.repeat(32);
const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

const plain = (value) => JSON.parse(JSON.stringify(value));
const errorOf = (err) => ({ ...(err?.code ? { code: err.code } : {}), message: String(err?.message ?? err) });

function packageDir(name, from) {
  let dir = path.dirname(require.resolve(name, { paths: [from] }));
  for (;;) {
    const manifest = path.join(dir, 'package.json');
    if (fs.existsSync(manifest) && JSON.parse(fs.readFileSync(manifest, 'utf8')).name === name) return dir;
    const up = path.dirname(dir);
    assert.notEqual(up, dir, `no package.json for ${name}`);
    dir = up;
  }
}

/**
 * The checkout's protocol-kit, safe-deployments and ethers, refused unless
 * exactly the versions design 0016 names, and the versions of the two
 * packages protocol-kit itself loads.
 */
function loadPackages(checkout) {
  const version = (dir) => JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')).version;
  const dirs = Object.fromEntries(Object.keys(PACKAGES).map((name) => [name, packageDir(name, checkout)]));
  const packages = Object.fromEntries(Object.entries(dirs).map(([name, dir]) => [name, version(dir)]));
  const wrong = Object.keys(PACKAGES).filter((name) => packages[name] !== PACKAGES[name]);
  if (wrong.length) {
    throw new Error(`The Safe vectors are ${Object.entries(PACKAGES).map(([n, v]) => `${n} ${v}`).join(', ')}'s; `
      + `${checkout} has ${wrong.map((name) => `${name} ${packages[name]}`).join(', ')}`);
  }
  const kitDir = dirs['@safe-global/protocol-kit'];
  for (const name of ['@safe-global/types-kit', 'viem']) packages[name] = version(packageDir(name, kitDir));
  const ref = createRequire(path.join(checkout, 'package.json'));
  const previousLoad = Module._load;
  Module._load = NODE_LOAD;
  try {
    return { packages, ethers: ref('ethers'), kit: ref('@safe-global/protocol-kit'), deploymentsDir: dirs['@safe-global/safe-deployments'] };
  } finally {
    Module._load = previousLoad;
  }
}

/**
 * keys.json's test accounts, as the vectors name them: abandon-12's
 * accounts 0, 1 and 2 (A, B, C) and legal-12's accounts 0 and 1 (D, E).
 */
function testKeys(keysJson) {
  const account = (id, index) => {
    const vector = keysJson.vectors.find((v) => v.id === id);
    assert.ok(vector, `keys.json lacks ${id}`);
    const wallet = vector.userWallets.find((w) => w.accountIndex === index);
    assert.ok(wallet, `keys.json lacks ${id}'s account ${index}`);
    return { mnemonicId: id, accountIndex: index, address: wallet.address, privateKey: wallet.privateKey };
  };
  return {
    A: account('abandon-12', 0), B: account('abandon-12', 1), C: account('abandon-12', 2),
    D: account('legal-12', 0), E: account('legal-12', 1),
  };
}

/** The wallet kinds, each checked against identity-manager.js's own text. */
function walletTypes(checkout) {
  const text = fs.readFileSync(path.join(checkout, 'src', 'main', 'identity-manager.js'), 'utf8');
  for (const [name, value] of Object.entries(WALLET_TYPES)) {
    assert.match(text, new RegExp(`\\n  ${name}: '${value}',`), `identity-manager.js's WALLET_TYPES.${name} moved`);
  }
  return WALLET_TYPES;
}

// The wallet: test accounts at fixed indexes, of the kinds a Safe's owners
// take (two devices, which sign only when their row is chosen).
const OWNER_RECORDS = [
  { index: 0, key: 'A', type: WALLET_TYPES.MNEMONIC },
  { index: 1, key: 'B', type: WALLET_TYPES.MNEMONIC },
  { index: 2, key: 'C', type: WALLET_TYPES.MNEMONIC },
  { index: 3, key: 'D', type: WALLET_TYPES.LEDGER },
  { index: 4, key: 'E', type: WALLET_TYPES.REMOTE },
];
const indexOf = (key) => OWNER_RECORDS.find((r) => r.key === key).index;

/** A world: the wallet records, the chain, and what the run captured. */
function newWorld(env, { safes = [], deployedSafes = {}, proxyCreationCode = null, draws = [] } = {}) {
  const records = new Map();
  for (const { index, key, type } of OWNER_RECORDS) {
    records.set(index, { index, name: `Owner ${key}`, address: env.keys[key].address, type });
  }
  for (const safe of safes) {
    records.set(safe.index, {
      index: safe.index, name: `Safe ${safe.index}`, address: safe.address, type: WALLET_TYPES.SAFE,
      owners: safe.owners.map(indexOf), threshold: safe.threshold, saltNonce: safe.saltNonce,
      deployed: safe.deployed === false ? {} : { [CHAIN_ID]: true },
    });
  }
  return {
    records, deployedSafes, proxyCreationCode, draws: [...draws],
    answers: new Map(), signed: [], sent: [], created: [], pending: new Map(), chain: null,
  };
}

/** Each address's test key, by address (lower case). */
function keyByAddress(env) {
  return new Map(Object.values(env.keys).map((k) => [k.address.toLowerCase(), k]));
}

/** The stubbed modules of a world, by path in the checkout. */
function stubs(env, world, refs) {
  const { ethers } = env;
  const keys = keyByAddress(env);
  const getWalletRecord = (index) => (world.records.has(index) ? structuredClone(world.records.get(index)) : null);
  const getSigner = (index, options = {}) => {
    const record = world.records.get(index);
    assert.ok(record, `no wallet record ${index} in the Safe vectors`);
    const key = keys.get(record.address.toLowerCase());
    return {
      getAddress: async () => record.address,
      signTypedData: async ({ domain, types, message }) => {
        if (options.beforeSign) await options.beforeSign();
        const honest = await new ethers.Wallet(key.privateKey).signTypedData(domain, refs.withoutDomainType(types), message);
        const answer = world.answers.get(index);
        const answered = answer ? await answer(honest, { domain, types, message }, refs) : honest;
        world.signed.push(answered);
        return answered;
      },
    };
  };
  const send = (via) => async (params, signer, ...rest) => {
    // tx-recorder's signAndRecord(params, signer, record, options),
    // transaction-service's signAndSendTransaction(params, signer, options).
    const options = (via === 'tx-recorder' ? rest[1] : rest[0]) ?? {};
    world.sent.push({
      via,
      executor: await signer.getAddress(),
      to: params.to, value: params.value, data: params.data, chainId: params.chainId,
      intentKey: options.intentKey,
    });
    return { hash: SENT_HASH, explorerUrl: `https://gnosisscan.io/tx/${SENT_HASH}` };
  };
  const chainRequest = (args) => world.chain.request(args);
  return {
    'src/main/identity-manager.js': {
      WALLET_TYPES: walletTypes(env.checkout),
      getWalletRecord,
      isVaultUnlocked: async () => true,
      addSafeWallet: async (name, params) => {
        world.created.push({ name, ...params });
        return { index: 10 + world.created.length, name, type: WALLET_TYPES.SAFE, ...params };
      },
      markSafeDeployed: async () => {},
    },
    'src/main/wallet/signers.js': { getSigner },
    'src/main/wallet/transaction-service.js': {
      estimateGas: async () => ({ gasLimit: QUOTE.gasLimit }),
      getGasPrices: async () => ({ maxFeePerGas: QUOTE.maxFeePerGas, maxPriorityFeePerGas: QUOTE.maxPriorityFeePerGas }),
      toFeeFields: (prices) => ({ maxFeePerGas: prices.maxFeePerGas, maxPriorityFeePerGas: prices.maxPriorityFeePerGas }),
      namesOwnFees: () => true,
      heldIntentFor: async () => null,
      signAndSendTransaction: send('transaction-service'),
      waitForTransaction: async () => ({ status: 'confirmed', verified: true }),
    },
    'src/main/wallet/tx-recorder.js': { KINDS: { SAFE_SEND: 'safe-send', SAFE_DEPLOY: 'safe-deploy' }, signAndRecord: send('tx-recorder') },
    'src/main/wallet/auto-approve-pause.js': { takeSiteTurn: async () => () => {} },
    'src/main/wallet/fee-check.js': {
      FEE_CHECK_NEEDS_CONFIRMATION: 'FEE_CHECK_NEEDS_CONFIRMATION',
      checkAtApproval: async () => ({ autoApprove: true }),
      feeCheckError: (code) => Object.assign(new Error(code), { code }),
      feeNotShownError: () => new Error('The fee was not shown'),
    },
    'src/main/wallet/signing-confirmation.js': {
      KINDS: { EXECUTOR_SEND: 'executor-send' },
      NOT_CONFIRMED: 'SIGNING_NOT_CONFIRMED',
      confirmationFor: () => { throw new Error('the Safe vectors confirm no fee'); },
      withConfirmation: async (_confirmation, run) => run(),
    },
    'src/main/wallet/provider-manager.js': { getEip1193Provider: () => ({ request: chainRequest }) },
    'src/main/networks/chain-data.js': {
      request: async (_chainId, method, params) => ({ result: await chainRequest({ method, params }), verified: true }),
    },
    'src/main/core/vault-backend.js': {
      vaultBackend: {
        typedDataHash: async ({ domain, types, message }) => ethers.TypedDataEncoder.hash(domain, types, message),
        coreProcess: () => 'core',
        coreProcessEnded: () => false,
        approval: { end: async () => ({}) },
        safePending: {
          list: async () => [...world.pending.keys()].sort((a, b) => a - b),
          get: async (index) => (world.pending.has(index) ? JSON.parse(world.pending.get(index)) : null),
          set: async (index, entry) => {
            world.pending.set(index, JSON.stringify(entry));
            return { durable: true };
          },
          clear: async (index) => {
            world.pending.delete(index);
            return { durable: true };
          },
        },
      },
    },
  };
}

/**
 * The reference's Safe modules, loaded fresh over `world`, with Node's
 * loader hooked until `restore()`: the modules require some of their
 * dependencies lazily (the identity core, Electron).
 */
function loadReference(env, world) {
  const { checkout } = env;
  const src = path.join(checkout, 'src') + path.sep;
  for (const key of Object.keys(require.cache)) {
    if (key.startsWith(src)) delete require.cache[key];
  }
  const refs = {};
  const stubbed = stubs(env, world, refs);
  const service = path.join(checkout, SAFE, 'safe-service.js');
  // safe-service.js's salt: the world's next fixed 16 bytes.
  const salts = {
    randomBytes: (size) => {
      assert.equal(size, 16, 'a Safe salt is 16 bytes');
      assert.ok(world.draws.length, 'the case drew more salts than it fixed');
      return Buffer.from(world.draws.shift(), 'hex');
    },
  };
  const electron = { webContents: { fromId: () => null } };
  const previousLoad = Module._load;
  Module._load = function load(request, parent, isMain) {
    if (parent?.filename?.startsWith(src)) {
      if (request === 'electron') return electron;
      if (request === 'crypto' && parent.filename === service) return salts;
      if (request.startsWith('.')) {
        const resolved = Module._resolveFilename(request, parent, isMain);
        const rel = path.relative(checkout, resolved).split(path.sep).join('/');
        if (Object.hasOwn(stubbed, rel)) return stubbed[rel];
        assert.ok(REAL.has(rel), `the Safe modules load ${rel}, which the vectors neither stub nor run`);
      }
    }
    return NODE_LOAD.call(this, request, parent, isMain);
  };
  const restore = () => { Module._load = previousLoad; };
  try {
    const at = (rel) => require(path.join(checkout, rel));
    Object.assign(refs, at('src/main/wallet/signing-utils.js'));
    const stubChain = at(`${SAFE}/__tests__/helpers/stub-chain.js`);
    world.chain = stubChain.createStubChain({
      chainId: CHAIN_ID, deployedSafes: world.deployedSafes, proxyCreationCode: world.proxyCreationCode,
    });
    return {
      executor: at(`${SAFE}/safe-executor.js`),
      service: at(`${SAFE}/safe-service.js`),
      transactions: at(`${SAFE}/safe-transactions.js`),
      messages: at(`${SAFE}/safe-messages.js`),
      collection: at(`${SAFE}/signature-collection.js`),
      sessions: at(`${SAFE}/message-sessions.js`),
      stubChain,
      factoryCode: at(`${SAFE}/__tests__/helpers/proxy-factory-code.js`),
      restore,
    };
  } catch (err) {
    restore();
    throw err;
  }
}

/** `fn(reference)` over a fresh load of `world`, Node's loader and console restored after. */
async function within(env, world, fn) {
  const { warn, error } = console;
  console.warn = () => {};
  console.error = () => {};
  const reference = loadReference(env, world);
  try {
    return await fn(reference);
  } finally {
    reference.restore();
    console.warn = warn;
    console.error = error;
  }
}

/** `{ value }`, or the error the reference threw. */
async function outcome(fn) {
  try {
    return { value: await fn() };
  } catch (err) {
    return { error: errorOf(err) };
  }
}

function permutations(items) {
  if (items.length <= 1) return [items];
  return items.flatMap((item, i) => permutations([...items.slice(0, i), ...items.slice(i + 1)]).map((rest) => [item, ...rest]));
}

// ---------------------------------------------------------------------------
// The pinned constants.

/**
 * The deployment the reference pins (`pinnedSafeDeployment`), checked
 * against safe-deployments' own files for 1.4.1, the factory's recorded
 * runtime code (proxy-factory-code.js, whose keccak256 is the codeHash
 * safe-deployments lists, and which embeds the proxy code once) and the
 * recorded `proxyCreationCode()` answer (stub-chain.js).
 */
async function buildConstants(env) {
  const { ethers } = env;
  return within(env, newWorld(env), async ({ executor, stubChain, factoryCode }) => {
    const pinned = executor.pinnedSafeDeployment(CHAIN_ID);
    const assets = path.join(env.deploymentsDir, 'dist', 'assets', `v${executor.SAFE_VERSION}`);
    const files = {};
    const listed = {};
    for (const [name, file] of [['singleton', 'safe_l2.json'], ['factory', 'safe_proxy_factory.json'],
      ['fallbackHandler', 'compatibility_fallback_handler.json']]) {
      const text = fs.readFileSync(path.join(assets, file));
      files[`dist/assets/v${executor.SAFE_VERSION}/${file}`] = crypto.createHash('sha256').update(text).digest('hex');
      const asset = JSON.parse(text);
      assert.equal(asset.version, executor.SAFE_VERSION);
      assert.equal(asset.networkAddresses[String(CHAIN_ID)], 'canonical', `${file}: Gnosis's deployment is the canonical one`);
      listed[name] = { contractName: asset.contractName, ...asset.deployments.canonical };
      assert.equal(pinned[name], asset.deployments.canonical.address, `the pinned ${name} is safe-deployments' canonical ${file}`);
    }
    const runtime = factoryCode.PROXY_FACTORY_1_4_1_RUNTIME;
    assert.equal(ethers.keccak256(runtime), listed.factory.codeHash, 'the recorded factory code is the one safe-deployments lists');
    assert.equal(runtime.split(pinned.proxyCreationCode.slice(2)).length, 2, 'the factory embeds the pinned proxy code once');
    const [answered] = ethers.AbiCoder.defaultAbiCoder().decode(['bytes'], stubChain.PROXY_CREATION_CODE_RESPONSE);
    assert.equal(answered, pinned.proxyCreationCode, "the recorded proxyCreationCode() answer is the pinned code");
    assert.equal(ethers.keccak256(pinned.proxyCreationCode), pinned.proxyCreationCodeHash);
    assert.equal(ethers.dataLength(pinned.proxyCreationCode), 486);
    // protocol-kit's own prediction over the honest chain is the pinned one:
    // the L2 singleton and the canonical handler on Gnosis.
    const owners = [env.keys.A.address, env.keys.B.address];
    const kit = await env.kit.default.init({
      provider: stubChain.createStubChain({ chainId: CHAIN_ID }),
      predictedSafe: { safeAccountConfig: { owners, threshold: 1 }, safeDeploymentConfig: { saltNonce: '0', safeVersion: executor.SAFE_VERSION } },
    });
    assert.equal(await kit.getAddress(), await executor.predictSafeAddress({ owners, threshold: 1, saltNonce: '0', chainId: CHAIN_ID }));
    return {
      version: executor.SAFE_VERSION,
      chainId: CHAIN_ID,
      singleton: pinned.singleton,
      factory: pinned.factory,
      fallbackHandler: pinned.fallbackHandler,
      proxyCreationCode: pinned.proxyCreationCode,
      proxyCreationCodeHash: pinned.proxyCreationCodeHash,
      safeDeployments: { files, listed },
      factoryRuntimeCode: runtime,
      proxyCreationCodeAnswer: stubChain.PROXY_CREATION_CODE_RESPONSE,
    };
  });
}

// ---------------------------------------------------------------------------
// Addresses and deployments.

const SALTS = [['0', '0'], ['1', '1'], ['2^128-1', (2n ** 128n - 1n).toString()]];

/** The fixed bytes a drawn salt takes, the `n`th. */
const drawn = (n) => crypto.createHash('sha256').update(`safe.json drawn salt ${n}`).digest().subarray(0, 16).toString('hex');

async function buildAddresses(env) {
  const { keys } = env;
  const cases = [];
  for (const ids of [...permutations(['A', 'B']), ...permutations(['A', 'B', 'C'])]) {
    for (const [label, saltNonce] of SALTS) {
      cases.push({ id: `${ids.join('')}-salt-${label}`, owners: ids, threshold: ids.length - 1, saltNonce });
    }
  }
  cases.push(
    { id: 'AB-salt-2^256-1', owners: ['A', 'B'], threshold: 1, saltNonce: MAX_UINT256 },
    { id: 'ABC-salt-leading-zeros', owners: ['A', 'B', 'C'], threshold: 2, saltNonce: '007' },
    { id: 'DAE-salt-1', owners: ['D', 'A', 'E'], threshold: 2, saltNonce: '1' },
  );
  const refused = [
    { id: 'no-owners', owners: [], threshold: 1, saltNonce: '0', core: 'unsupported' },
    { id: 'threshold-0', owners: ['A', 'B'], threshold: 0, saltNonce: '0', core: 'unsupported' },
    { id: 'threshold-past-the-owners', owners: ['A', 'B'], threshold: 3, saltNonce: '0', core: 'unsupported' },
    { id: 'salt-negative', owners: ['A', 'B'], threshold: 1, saltNonce: '-1', core: 'salt' },
    { id: 'salt-hex', owners: ['A', 'B'], threshold: 1, saltNonce: '0x10', core: 'salt' },
    { id: 'salt-empty', owners: ['A', 'B'], threshold: 1, saltNonce: '', core: 'salt' },
    { id: 'salt-fraction', owners: ['A', 'B'], threshold: 1, saltNonce: '1.5', core: 'salt' },
    { id: 'salt-2^256', owners: ['A', 'B'], threshold: 1, saltNonce: (2n ** 256n).toString(), core: 'salt' },
    { id: 'chain-1', owners: ['A', 'B'], threshold: 1, saltNonce: '0', chainId: 1, core: 'unsupported' },
  ];
  return within(env, newWorld(env), async ({ executor }) => {
    const out = [];
    for (const c of [...cases, ...refused]) {
      const params = {
        owners: c.owners.map((id) => keys[id].address), threshold: c.threshold, saltNonce: c.saltNonce, chainId: c.chainId ?? CHAIN_ID,
      };
      const address = await outcome(() => executor.predictSafeAddress(params));
      const deployment = await outcome(() => executor.buildDeploymentTransaction(params));
      const entry = { id: c.id, owners: c.owners, threshold: c.threshold, saltNonce: c.saltNonce, chainId: params.chainId };
      if (c.core) {
        assert.ok(address.error && deployment.error, `${c.id}: the reference refuses it`);
        assert.deepEqual(address.error, deployment.error);
        out.push({ ...entry, error: address.error, core: { refused: c.core } });
      } else {
        assert.equal(deployment.value.safeAddress, address.value, `${c.id}: the deployment lands on the address`);
        out.push({ ...entry, address: address.value, deployment: { to: deployment.value.to, value: deployment.value.value, data: deployment.value.data } });
      }
    }
    return out;
  });
}

/** Safes created as the wallet creates them (`createSafeAccount`), each salt drawn. */
async function buildCreated(env) {
  const out = [];
  let n = 0;
  for (const [id, owners, threshold] of [['AB', ['A', 'B'], 1], ['BA', ['B', 'A'], 1], ['ABC', ['A', 'B', 'C'], 2], ['CAD', ['C', 'A', 'D'], 2]]) {
    for (let k = 0; k < 2; k++) {
      const draw = drawn(n++);
      const world = newWorld(env, { draws: [draw] });
      out.push(await within(env, world, async ({ service, executor }) => {
        await service.createSafeAccount({ name: `Safe ${id}`, ownerIndexes: owners.map(indexOf), threshold });
        assert.equal(world.created.length, 1);
        const [created] = world.created;
        const deployment = await executor.buildDeploymentTransaction({
          owners: owners.map((o) => env.keys[o].address), threshold, saltNonce: created.saltNonce, chainId: CHAIN_ID,
        });
        assert.equal(deployment.safeAddress, created.address);
        return {
          id: `${id}-drawn-${k}`, owners, threshold, drawnBytes: draw, saltNonce: created.saltNonce, address: created.address,
          record: { owners: created.owners, threshold: created.threshold, saltNonce: created.saltNonce },
          deployment: { to: deployment.to, value: deployment.value, data: deployment.data },
        };
      }));
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// SafeTxs.

/** The Safes the SafeTx, execution and message cases use. */
async function safesOf(env) {
  const defs = {
    S2: { owners: ['A', 'B'], threshold: 1, saltNonce: '0', index: 20 },
    S3: { owners: ['A', 'B', 'C'], threshold: 2, saltNonce: '1', index: 21 },
    S4: { owners: ['D', 'A', 'E'], threshold: 2, saltNonce: '1', index: 22 },
  };
  return within(env, newWorld(env), async ({ executor }) => {
    const out = {};
    for (const [name, def] of Object.entries(defs)) {
      const address = await executor.predictSafeAddress({
        owners: def.owners.map((id) => env.keys[id].address), threshold: def.threshold, saltNonce: def.saltNonce, chainId: CHAIN_ID,
      });
      out[name] = { name, ...def, address };
    }
    return out;
  });
}

const safeView = (safe) => ({ name: safe.name, owners: safe.owners, threshold: safe.threshold, saltNonce: safe.saltNonce, address: safe.address });

function erc20Transfer(ethers, to, amount) {
  return new ethers.Interface(['function transfer(address to, uint256 amount) returns (bool)']).encodeFunctionData('transfer', [to, amount]);
}

/** Every 1,000 bytes counting up from 0, as data no encoder pads or trims. */
const LONG_DATA = '0x' + Buffer.from(Array.from({ length: 1000 }, (_, i) => i % 256)).toString('hex');

function safeTxCases(env, safes) {
  const { keys, ethers } = env;
  const D = keys.D.address;
  const tx = (extra = {}) => ({ to: D, value: '0', data: '0x', ...extra });
  return [
    { id: 'zero', safe: 'S2', nonce: 0, tx: tx() },
    { id: 'value-1', safe: 'S2', nonce: 1, tx: tx({ value: '1' }) },
    { id: 'value-max', safe: 'S2', nonce: 2, tx: tx({ value: MAX_UINT256 }) },
    { id: 'erc20-transfer', safe: 'S2', nonce: 3, tx: tx({ to: keys.E.address, data: erc20Transfer(ethers, D, 10n ** 18n) }) },
    { id: 'data-1000', safe: 'S2', nonce: 4, tx: tx({ value: '12345', data: LONG_DATA }) },
    { id: 'nonce-255', safe: 'S2', nonce: 255, tx: tx({ value: '1' }) },
    { id: 'nonce-256', safe: 'S2', nonce: 256, tx: tx({ value: '1' }) },
    { id: 'nonce-2^32', safe: 'S2', nonce: 2 ** 32, tx: tx({ value: '1' }) },
    { id: 'nonce-2^53-1', safe: 'S2', nonce: 2 ** 53 - 1, tx: tx({ value: '1' }) },
    { id: 'nonce-2^53', safe: 'S2', nonce: 2n ** 53n, tx: tx({ value: '1' }), core: 'nonce' },
    { id: 'nonce-2^64', safe: 'S2', nonce: 2n ** 64n, tx: tx({ value: '1' }), core: 'nonce' },
    { id: 'to-lower-case', safe: 'S2', nonce: 5, tx: tx({ to: D.toLowerCase(), value: '7' }) },
    { id: 'value-and-data-omitted', safe: 'S2', nonce: 6, tx: { to: D } },
    { id: 'two-of-three', safe: 'S3', nonce: 9, tx: tx({ value: '1000000000000000000' }) },
    { id: 'counterfactual', safe: 'S3', nonce: null, tx: tx({ value: '1' }) },
    // A lying endpoint's proxyCreationCode() moves neither the address nor
    // the hash (#1066).
    { id: 'lying-proxy-code', safe: 'S3', nonce: 9, tx: tx({ value: '1000000000000000000' }), lying: true },
    { id: 'record-address-mismatch', safe: 'S2', nonce: 0, tx: tx(), recordAddress: safes.S3.address, core: 'address_mismatch' },
    { id: 'chain-1', safe: 'S2', nonce: 0, tx: tx(), chainId: 1, core: 'unsupported' },
  ];
}

const LYING_PROXY_CODE = () => '0x' + 'fe'.repeat(486);

async function buildSafeTxs(env, safes) {
  const out = [];
  for (const c of safeTxCases(env, safes)) {
    const safe = safes[c.safe];
    const deployedSafes = c.nonce === null ? {} : { [safe.address]: { nonce: c.nonce, threshold: safe.threshold } };
    const world = newWorld(env, { deployedSafes, proxyCreationCode: c.lying ? LYING_PROXY_CODE() : null });
    out.push(await within(env, world, async ({ executor }) => {
      const record = {
        owners: safe.owners.map((id) => env.keys[id].address), threshold: safe.threshold, saltNonce: safe.saltNonce,
        address: c.recordAddress ?? safe.address,
      };
      const built = await outcome(() => executor.buildSafeTransaction({ chainId: c.chainId ?? CHAIN_ID, safe: record, tx: c.tx }));
      const entry = {
        id: c.id, safe: safeView(safe), ...(c.recordAddress ? { recordAddress: c.recordAddress } : {}),
        chainId: c.chainId ?? CHAIN_ID, chainNonce: c.nonce === null ? null : c.nonce.toString(), tx: c.tx,
        ...(c.lying ? { proxyCreationCodeAnswer: 'a lying endpoint: 486 bytes of 0xfe' } : {}),
      };
      if (c.core) {
        assert.ok(built.error, `${c.id}: the reference refuses it`);
        return { ...entry, error: built.error, core: { refused: c.core } };
      }
      const { safeAddress, deployed, safeTxData, safeTxHash, typedData } = built.value;
      assert.equal(safeAddress, safe.address);
      return { ...entry, deployed, safeAddress, safeTxData, typedData, safeTxHash };
    }));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Owner signatures and execTransaction.

/**
 * The owners' signatures over one SafeTx, as `collectOwnerSignature` keeps
 * them (each recovered against its owner), and the SafeTx.
 */
async function signedSafeTx(env, safe, nonce, tx) {
  const world = newWorld(env, { deployedSafes: { [safe.address]: { nonce, threshold: safe.threshold } } });
  return within(env, world, async ({ executor }) => {
    const built = await executor.buildSafeTransaction({
      chainId: CHAIN_ID,
      safe: { owners: safe.owners.map((id) => env.keys[id].address), threshold: safe.threshold, saltNonce: safe.saltNonce, address: safe.address },
      tx,
    });
    const signatures = {};
    for (const id of safe.owners) {
      signatures[id] = await executor.collectOwnerSignature({ typedData: built.typedData, ownerIndex: indexOf(id), approval: APPROVAL });
    }
    return { built, signatures };
  });
}

/** `execTransaction` with the signatures in the order given, its send captured. */
async function executed(env, safe, built, signatures) {
  const world = newWorld(env);
  return within(env, world, async ({ executor }) => {
    const result = await outcome(() => executor.execTransaction({
      chainId: CHAIN_ID, safeAddress: built.safeAddress, safeTxData: built.safeTxData, signatures,
      executorIndex: indexOf(safe.owners[0]), approval: APPROVAL,
    }));
    return { result, sent: world.sent };
  });
}

async function buildExecutions(env, safes) {
  const out = [];
  const D = env.keys.D.address;
  const runs = [
    { id: 'S3', safe: safes.S3, nonce: 5, tx: { to: D, value: '1000000000000000000', data: '0x' },
      orders: [...['A', 'B', 'C'].map((id) => [id]), ...permutations(['A', 'B']), ...permutations(['A', 'C']), ...permutations(['B', 'C']),
        ...permutations(['A', 'B', 'C']), ['A', 'A'], ['B', 'A', 'B']] },
    { id: 'S2-data', safe: safes.S2, nonce: 0, tx: { to: env.keys.E.address, value: MAX_UINT256, data: LONG_DATA }, orders: [['A'], ['B'], ['B', 'A']] },
  ];
  for (const run of runs) {
    const { built, signatures } = await signedSafeTx(env, run.safe, run.nonce, run.tx);
    for (const order of run.orders) {
      const given = order.map((id) => signatures[id]);
      const { result, sent } = await executed(env, run.safe, built, given);
      assert.ok(!result.error, `${run.id} ${order.join('')}: ${result.error?.message}`);
      assert.equal(sent.length, 1);
      out.push({
        id: `${run.id}-${order.join('')}`, safe: safeView(run.safe), safeAddress: built.safeAddress,
        safeTxData: built.safeTxData, safeTxHash: built.safeTxHash, signatures: given, send: sent[0],
      });
    }
  }
  return out;
}

/** A signature's `v` replaced (its last byte). */
const withV = (signature, v) => signature.slice(0, -2) + v.toString(16).padStart(2, '0');

/** The same signature with `s` as n − s and the parity flipped: what ecrecover also takes. */
function highS(signature) {
  const s = BigInt('0x' + signature.slice(66, 130));
  const v = parseInt(signature.slice(-2), 16);
  return signature.slice(0, 66) + (SECP256K1_N - s).toString(16).padStart(64, '0') + (v === 27 ? '1c' : '1b');
}

/** EIP-2098's 64-byte form: `r ‖ yParityAndS`. */
function compact(signature) {
  const s = BigInt('0x' + signature.slice(66, 130));
  const parity = parseInt(signature.slice(-2), 16) - 27;
  return signature.slice(0, 66) + ((BigInt(parity) << 255n) | s).toString(16).padStart(64, '0');
}

/**
 * One owner's signature as signature-collection.js takes it: the signer's
 * answer, scripted, through `signEntryOwner` with an in-memory store as its
 * adapter, so the reference's own checks decide (`collectOwnerSignature`'s
 * recovery, the membership and once-each checks).
 */
async function buildOwnerSignatures(env, safes) {
  const { ethers, keys } = env;
  const safe = safes.S4;
  const tx = { to: keys.B.address, value: '5', data: '0x' };
  const v = (sig) => parseInt(sig.slice(-2), 16);
  const by = (key) => (_honest, typed, refs) =>
    new ethers.Wallet(keys[key].privateKey).signTypedData(typed.domain, refs.withoutDomainType(typed.types), typed.message);
  const otherSafeTx = await signedSafeTx(env, safe, 11, { ...tx, value: '6' });
  const cases = [
    { id: 'honest', owner: 'D' },
    { id: 'v-0', owner: 'D', parity: 0, answer: (sig) => withV(sig, v(sig) - 27), deviation: 'owner-signatures', core: 'v' },
    { id: 'v-1', owner: 'D', parity: 1, answer: (sig) => withV(sig, v(sig) - 27), deviation: 'owner-signatures', core: 'v' },
    { id: 'v-eip-155-37', owner: 'D', parity: 0, answer: (sig) => withV(sig, 37), deviation: 'owner-signatures', core: 'v' },
    { id: 'v-eip-155-38', owner: 'D', parity: 1, answer: (sig) => withV(sig, 38), deviation: 'owner-signatures', core: 'v' },
    { id: 'eip-2098-64-bytes', owner: 'D', answer: compact, deviation: 'owner-signatures', core: 'length' },
    { id: 'v-29', owner: 'D', answer: (sig) => withV(sig, 29), core: 'v' },
    { id: 'high-s', owner: 'D', answer: highS, core: 'recovery' },
    { id: '66-bytes', owner: 'D', answer: (sig) => sig + '00', core: 'length' },
    { id: 'another-key', owner: 'D', answer: by('C'), core: 'mismatch' },
    { id: 'another-owners-key', owner: 'D', answer: by('A'), core: 'mismatch' },
    { id: 'another-safe-tx', owner: 'D', answer: () => otherSafeTx.signatures.D.data, core: 'mismatch' },
    { id: 'not-an-owner', owner: 'B', core: 'not_owner' },
    { id: 'second-from-one-owner', owner: 'D', twice: true },
  ];
  // A case that names a parity runs at a nonce where the owner's honest
  // signature has it.
  const nonces = {};
  for (let nonce = 11; nonces[0] === undefined || nonces[1] === undefined; nonce++) {
    const { signatures } = await signedSafeTx(env, safe, nonce, tx);
    nonces[v(signatures.D.data) - 27] ??= nonce;
  }
  const out = [];
  for (const c of cases) {
    const nonce = nonces[c.parity ?? 0];
    const world = newWorld(env, { safes: [safe], deployedSafes: { [safe.address]: { nonce, threshold: safe.threshold } } });
    if (c.answer) world.answers.set(indexOf(c.owner), c.answer);
    out.push(await within(env, world, async ({ executor, collection }) => {
      const built = await executor.buildSafeTransaction({
        chainId: CHAIN_ID,
        safe: { owners: safe.owners.map((id) => keys[id].address), threshold: safe.threshold, saltNonce: safe.saltNonce, address: safe.address },
        tx,
      });
      let entry = { typedData: built.typedData, threshold: safe.threshold, signatures: [] };
      const store = {
        get: () => entry,
        set: async (_index, next) => { entry = next; },
        idOf: () => built.safeTxHash,
        approvalOf: () => APPROVAL,
        forgetApproval: () => {},
      };
      const sign = () => collection.signEntryOwner({
        store, safeIndex: safe.index, ownerIndex: indexOf(c.owner), ownerIndexes: safe.owners.map(indexOf), expectedId: built.safeTxHash,
      });
      const first = await outcome(sign);
      const answers = world.signed.length;
      const second = c.twice ? await outcome(sign) : null;
      const result = {
        id: c.id, safe: safeView(safe), owner: c.owner, safeAddress: built.safeAddress, safeTxHash: built.safeTxHash,
        answered: world.signed[0] ?? null,
        reference: first.error ? { error: first.error } : { kept: plain(entry.signatures) },
        core: c.core ? { refused: c.core } : { kept: plain(entry.signatures) },
      };
      if (c.twice) {
        assert.ok(!second.error && entry.signatures.length === 1 && world.signed.length === answers,
          'the owner signed already: nothing is asked or kept');
        result.again = { asked: false, kept: entry.signatures.length };
      }
      if (c.deviation) {
        assert.ok(!first.error && entry.signatures.length === 1, `${c.id}: the reference keeps it`);
        result.deviation = c.deviation;
      } else if (c.core) {
        assert.ok(first.error, `${c.id}: the reference refuses it`);
      }
      return result;
    }));
  }
  return out;
}

// ---------------------------------------------------------------------------
// A SafeTx's whole course, through safe-transactions.js.

const DISPLAY = (tx) => ({ toAddress: tx.to, asset: null, amount: tx.value ?? '0', symbol: 'xDAI', decimals: 18 });

/** The board's state, without its clock reading. */
function boardState(state) {
  if (!state) return state;
  const { createdAt: _createdAt, display: _display, ...rest } = state;
  return plain(rest);
}

/** The pending entry the core holds for a Safe, without its clock reading, or null. */
function pendingEntry(world, index) {
  if (!world.pending.has(index)) return null;
  const { createdAt: _createdAt, ...entry } = JSON.parse(world.pending.get(index));
  return entry;
}

async function buildFlows(env, safes) {
  const { keys } = env;
  const tx = { to: keys.D.address, value: '250000000000000000', data: '0x' };
  const flows = [
    { id: 'one-of-two', safe: 'S2', nonce: 3, steps: [['start'], ['execute']] },
    { id: 'two-of-three-vault-owners', safe: 'S3', nonce: 4, steps: [['start'], ['execute']] },
    { id: 'two-of-three-device-owner', safe: 'S4', nonce: 2, steps: [['start'], ['execute'], ['sign', 'D'], ['execute']] },
    { id: 'three-signatures', safe: 'S3', nonce: 4, steps: [['start'], ['sign', 'C'], ['execute']] },
    { id: 'superseded', safe: 'S2', nonce: 3, steps: [['start'], ['chainNonce', 4], ['execute']] },
    { id: 'nonce-behind', safe: 'S2', nonce: 3, steps: [['start'], ['chainNonce', 2], ['execute']],
      deviation: 'nonce-behind', core: { refused: 'nonce_behind' } },
    { id: 'not-an-owner', safe: 'S2', nonce: 3, steps: [['start'], ['sign', 'C']] },
    { id: 'another-chain', safe: 'S2', nonce: 3, chainId: 1, steps: [['start']], core: { refused: 'unsupported' } },
  ];
  const out = [];
  for (const flow of flows) {
    const safe = safes[flow.safe];
    const chainSafe = { nonce: flow.nonce, threshold: safe.threshold };
    const world = newWorld(env, { safes: [safe], deployedSafes: { [safe.address]: chainSafe } });
    out.push(await within(env, world, async ({ transactions }) => {
      const steps = [];
      for (const [step, arg] of flow.steps) {
        if (step === 'chainNonce') {
          chainSafe.nonce = arg;
          steps.push({ step, nonce: arg });
          continue;
        }
        const sentBefore = world.sent.length;
        const result = await outcome(async () => {
          if (step === 'start') {
            const reservation = transactions.reserveSafeSend(safe.index);
            try {
              return await transactions.startSafeSend({
                safeIndex: safe.index, tx, display: DISPLAY(tx), chainId: flow.chainId ?? CHAIN_ID, approval: APPROVAL, reservation,
              });
            } finally {
              reservation.release();
            }
          }
          if (step === 'sign') return transactions.signSafePending(safe.index, indexOf(arg));
          return transactions.executeSafePending(safe.index);
        });
        steps.push({
          step, ...(arg ? { owner: arg } : {}),
          ...(result.error ? { error: result.error } : { state: boardState(result.value) }),
          sent: world.sent.slice(sentBefore),
          pending: pendingEntry(world, safe.index),
        });
      }
      const entry = {
        id: flow.id, safe: safeView(safe), chainId: flow.chainId ?? CHAIN_ID, chainNonce: flow.nonce, tx, steps,
      };
      if (flow.deviation) entry.deviation = flow.deviation;
      if (flow.core) entry.core = flow.core;
      return entry;
    }));
  }
  return out;
}

// ---------------------------------------------------------------------------
// SafeMessages (EIP-1271), through safe-messages.js.

const SITE = 'https://app.example';

function mail(verifyingContract) {
  return {
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' }, { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' },
      ],
      Person: [{ name: 'name', type: 'string' }, { name: 'wallet', type: 'address' }],
      Mail: [{ name: 'from', type: 'Person' }, { name: 'to', type: 'Person' }, { name: 'contents', type: 'string' }],
    },
    primaryType: 'Mail',
    domain: { name: 'Ether Mail', version: '1', chainId: CHAIN_ID, verifyingContract },
    message: {
      from: { name: 'Cow', wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826' },
      to: { name: 'Bob', wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB' },
      contents: 'Hello, Bob!',
    },
  };
}

function permit(owner, spender) {
  return {
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' }, { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' },
      ],
      Permit: [
        { name: 'owner', type: 'address' }, { name: 'spender', type: 'address' }, { name: 'value', type: 'uint256' },
        { name: 'nonce', type: 'uint256' }, { name: 'deadline', type: 'uint256' },
      ],
    },
    primaryType: 'Permit',
    domain: { name: 'USD Coin', version: '2', chainId: CHAIN_ID, verifyingContract: '0xDDAfbb505ad214D7b80b1f830fcCc89B60fb7A83' },
    message: { owner, spender, value: MAX_UINT256, nonce: '0', deadline: '1893456000' },
  };
}

async function buildMessages(env, safes) {
  const { keys } = env;
  const requests = (safe) => [
    ['personal-hex', 'personal_sign', ['0x48656c6c6f2c2053616665', safe.address]],
    ['personal-hex-upper-case', 'personal_sign', ['0xDEADBEEF', safe.address]],
    ['personal-text', 'personal_sign', ['Hello, Safe', safe.address]],
    ['personal-unicode', 'personal_sign', ['Gr\u00fc\u00dfe \u2713 \ud83d\ude00', safe.address]],
    ['personal-empty-hex', 'personal_sign', ['0x', safe.address]],
    ['personal-empty-text', 'personal_sign', ['', safe.address]],
    ['typed-mail', 'eth_signTypedData_v4', [safe.address, mail(keys.E.address)]],
    ['typed-mail-json', 'eth_signTypedData_v4', [safe.address, JSON.stringify(mail(keys.E.address))]],
    ['typed-permit', 'eth_signTypedData_v4', [safe.address, permit(safe.address, keys.D.address)]],
  ];
  const runs = [];
  for (const name of ['S2', 'S3']) {
    for (const [id, method, params] of requests(safes[name])) runs.push({ id: `${name}-${id}`, safe: name, method, params });
  }
  runs.push(
    { id: 'S4-device-owner', safe: 'S4', method: 'personal_sign', params: ['From a Ledger', safes.S4.address], sign: ['D'] },
    { id: 'S4-below-the-threshold', safe: 'S4', method: 'personal_sign', params: ['One of two', safes.S4.address], core: { refused: 'threshold' } },
  );
  const out = [];
  for (const run of runs) {
    const safe = safes[run.safe];
    const world = newWorld(env, { safes: [safe] });
    out.push(await within(env, world, async ({ messages, sessions }) => {
      const request = { method: run.method, params: run.params };
      const started = await messages.startSafeMessage({
        safeIndex: safe.index, request, display: { site: SITE, method: run.method },
        requester: { origin: SITE, webContentsId: null }, approval: APPROVAL,
      });
      for (const owner of run.sign ?? []) await messages.signSafeMessage(safe.index, indexOf(owner), started.token);
      const session = sessions.getSession(safe.index);
      const complete = await outcome(() => messages.completeSafeMessage(safe.index, started.token));
      const entry = {
        id: run.id, safe: safeView(safe), request,
        digest: session.typedData.message.message, typedData: plain(session.typedData), hash: session.hash,
        signatures: plain(session.signatures),
        ...(complete.error ? { error: complete.error } : { signature: complete.value.signature }),
      };
      if (run.core) entry.core = run.core;
      assert.equal(Boolean(complete.error), Boolean(run.core), `${run.id}: ${complete.error?.message}`);
      return entry;
    }));
  }
  return out;
}

/** safe.json, whole. */
async function buildSafe(checkout, keysJson, meta) {
  const loaded = loadPackages(checkout);
  const env = { checkout, keys: testKeys(keysJson), ...loaded };
  const safes = await safesOf(env);
  return {
    meta: { ...meta, packages: loaded.packages },
    encodings: {
      address: 'EIP-55 checksummed hex with 0x, as the reference answers',
      bytes: 'lowercase hex with 0x, as the reference answers; a case input as the case gives it',
      owners: "keys.json's test accounts: A, B and C are abandon-12's accounts 0 to 2, D and E legal-12's accounts 0 and 1",
      saltNonce: 'decimal text, as a Safe record stores it',
      safeTxData: "protocol-kit's SafeTx fields, in the reference's property order, as safe-pending.json keeps them",
      typedData: 'the EIP-712 payload the owners sign, EIP712Domain included, in the reference\'s property order',
      core: "the core's answer where it isn't the reference's: `refused` names fc-safe's error kind",
    },
    owners: Object.fromEntries(Object.entries(env.keys).map(([id, k]) => [id, {
      keys: { mnemonicId: k.mnemonicId, accountIndex: k.accountIndex }, address: k.address,
      wallet: OWNER_RECORDS.find((r) => r.key === id),
    }])),
    constants: await buildConstants(env),
    addresses: await buildAddresses(env),
    created: await buildCreated(env),
    safes: Object.fromEntries(Object.entries(safes).map(([name, safe]) => [name, safeView(safe)])),
    safeTxs: await buildSafeTxs(env, safes),
    executions: await buildExecutions(env, safes),
    ownerSignatures: await buildOwnerSignatures(env, safes),
    flows: await buildFlows(env, safes),
    messages: await buildMessages(env, safes),
  };
}

module.exports = { buildSafe, loadPackages, testKeys, PACKAGES };
