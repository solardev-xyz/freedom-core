'use strict';

// Design 0012's fc-eip1193 (step APR-5a): what 0011's Ethereum dispatcher
// does with a page's request, recorded from the approvals reference's own
// src/main/page/page-ethereum.js, with its page-signing.js and page-sends.js
// (`createEthereumDispatchers`), driven through the dependencies and the
// request context it takes for its tests, as page-requests.js gives them:
// - the site's grant: the reference's own dapp-permissions.js over an
//   in-memory file (approval-stores.js's harness), with `Date.now` fixed;
// - the prepared send: the reference's own transaction-service.js
//   `estimateGas` (its 20% buffer) and `getGasPrices`, over the chain reads
//   they make (`eth_estimateGas`, the fee quote);
// - #88 and #89: signing-utils.js (ethers from the main reference's install,
//   the same 6.17.0 by the same integrity in both lockfiles), and
//   wallet-ipc.js's `messageViewFor` and `typedDataViewFor`, copied, as
//   wallet-ipc.js needs Electron and the vault (`checkSource` holds each copy
//   to the reference's text);
// - the tokens: page-requests.js's `confirm` and `spend`, over the
//   reference's own signing-confirmation.js (`issuePageConfirmation`,
//   `consumePageConfirmation`), its random tokens named in the order minted;
// - signatures: the first three test wallets of `abandon … about`, by ethers
//   (EIP-191 over the message's bytes, EIP-712 over the typed data), standing
//   for the vault and the devices.
// Everything else the dispatcher asks of main is scripted per scenario: the
// chain reads' answers, the name's resolution, the prompts' decisions, Agent
// custody, the fee check's verdicts, D12's pause and the broadcast's hash.
//
// Each request records every effect, in order, with its arguments and its
// answer (or what it threw), the dispatcher's own result, the answer main
// delivers (page-requests.js's `answer`: a name-revalidated read registered
// its keyless answer, and a document that has gone gets nothing), and the
// events main sends after it. Grant reads are not effects: `grants` holds the
// store's file before and after, and each write is an effect.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const { loadWithInternals } = require('./naming');
const { USER_DATA, FILES, memoryFs, loadStore } = require('./approval-stores');

const FILE = `${USER_DATA}/${FILES.dapp}`;
// The wall clock for every run: the grant store's timestamps.
const T = 1_763_000_000_000;
const MNEMONIC = [...Array(11).fill('abandon'), 'about'].join(' ');
const GWEI = 1_000_000_000n;
const SITE = 'https://app.example';
const NAME = 'docs.example.org';
const IPNS_KEY = 'k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8';
// In lowercase: the send prompt shows it checksummed.
const ROUTER = '0x' + 'ab'.repeat(20);
const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const RECIPIENT = '0x' + '55'.repeat(20);
const APPROVE = '0x095ea7b3';
const TRANSFER = '0xa9059cbb';
const BLOCK = '0x' + 'b1'.repeat(32);
const HASH = '0x' + '5e'.repeat(32);
const HELLO = '0x68656c6c6f';
const RAW32 = '0x' + '42'.repeat(32);

// The network registry's chains: Sepolia is known but has no RPC provider.
const NETWORKS = Object.freeze({
  1: Object.freeze({ name: 'Ethereum', nativeSymbol: 'ETH' }),
  100: Object.freeze({ name: 'Gnosis', nativeSymbol: 'xDAI' }),
  8453: Object.freeze({ name: 'Base', nativeSymbol: 'ETH' }),
  11155111: Object.freeze({ name: 'Sepolia', nativeSymbol: 'ETH' }),
});
const AVAILABLE = Object.freeze([1, 100, 8453]);

// page-requests.js's answer while the document has another wallet prompt
// open, and its handle's close reasons (`checkSource`).
const PROMPT_PENDING_LINE = "const PROMPT_PENDING = { code: -32002, message: 'Another wallet request is already pending' };";
const PROMPT_PENDING = Object.freeze({ code: -32002, message: 'Another wallet request is already pending' });

const word = (hex) => hex.replace(/^0x/, '').toLowerCase().padStart(64, '0');
const approveData = (amount) => `${APPROVE}${word(RECIPIENT)}${word(BigInt(amount).toString(16))}`;
const transferData = (amount) => `${TRANSFER}${word(RECIPIENT)}${word(BigInt(amount).toString(16))}`;

// ---------------------------------------------------------------------------
// The reference's modules.

/** wallet-ipc.js's `messageViewFor` and `typedDataViewFor`, as copied below. */
const WALLET_IPC_SOURCE = [
  `async function typedDataViewFor(typedData, chainId) {
  const normalized = normalizeTypedData(typedData);
  if (!normalized || typeof normalized !== 'object') {
    throw new Error('Typed data is required');
  }
  const { hash, view } = await vaultBackend.typedDataView(
    toCoreTypedData(normalized),
    typedDataViewOptions(normalized, chainId)
  );
  return { hash, view, warnings: typedDataWarnings(view) };
}`,
  `function messageViewFor(message) {
  if (typeof message !== 'string') {
    throw new Error('The message to sign must be text or 0x-prefixed hex');
  }
  const bytes = messageToBytes(normalizeMessage(message));
  return { hex: '0x' + bytes.toString('hex'), rawHash: signsRawHash(message) };
}`,
];

function checkSource(checkout, rel, snippet) {
  const text = fs.readFileSync(path.join(checkout, rel), 'utf8');
  assert.ok(text.includes(snippet), `STOP: ${rel} no longer holds the text the generator copies`);
}

function loadReference(checkout, mainCheckout) {
  checkSource(checkout, 'src/main/page/page-requests.js', PROMPT_PENDING_LINE);
  for (const snippet of WALLET_IPC_SOURCE) checkSource(checkout, 'src/main/wallet/wallet-ipc.js', snippet);
  const ethers = createRequire(path.join(mainCheckout, 'package.json'))('ethers');
  assert.equal(ethers.version, '6.17.0', 'STOP: the main reference installs another ethers');
  const own = createRequire(path.join(checkout, 'package.json'));
  // The chain reads transaction-service.js makes, routed to the scenario.
  const chainData = {
    request: (...args) => chainData.current.request(...args),
    getFeeQuote: (...args) => chainData.current.getFeeQuote(...args),
    current: null,
  };
  const signing = loadWithInternals(checkout, 'src/main/page/page-signing.js', [], {});
  // A failure's text goes through rpc-errors' redaction, which needs packages
  // this checkout doesn't install; no text here holds a URL or a key.
  const sends = loadWithInternals(checkout, 'src/main/page/page-sends.js', [], {
    '../wallet/rpc-errors': { redactRpcText: (text) => text },
    ethers,
  });
  return {
    checkout,
    ethers,
    methods: own('./src/main/page/page-methods.js'),
    confirmations: own('./src/main/wallet/signing-confirmation.js'),
    utils: loadWithInternals(checkout, 'src/main/wallet/signing-utils.js', [], { ethers }),
    ethereum: loadWithInternals(checkout, 'src/main/page/page-ethereum.js', [], {
      './page-signing': signing,
      './page-sends': sends,
    }),
    transactions: loadWithInternals(checkout, 'src/main/wallet/transaction-service.js', [], {
      ethers,
      '../networks/chain-data': chainData,
      './chains': {},
      './remote/errors': {},
      './intent-store': {},
      './phone-payments': {},
      './nonce-reservations': {},
    }),
    chainData,
  };
}

/** The test wallets: index 0 the vault's, 1 a Ledger's, 2 a phone's, and two Safes. */
function walletsOf(ethers) {
  const keys = [0, 1, 2].map((index) => ethers.HDNodeWallet.fromPhrase(MNEMONIC, undefined, `m/44'/60'/0'/0/${index}`));
  assert.equal(keys[0].address, '0x9858EfFD232B4033E47d90003D41EC34EcaEda94', 'STOP: wallet sanity check failed');
  const wallets = [
    { index: 0, name: 'Main Wallet', address: keys[0].address, type: 'mnemonic' },
    { index: 1, name: 'Ledger', address: keys[1].address, type: 'ledger' },
    { index: 2, name: 'Phone', address: keys[2].address, type: 'remote' },
    { index: 1000, name: 'Team Safe', address: ethers.getAddress('0x' + '44'.repeat(20)), type: 'safe', deployed: { 100: true } },
    { index: 1001, name: 'New Safe', address: ethers.getAddress('0x' + '66'.repeat(20)), type: 'safe', deployed: {} },
  ];
  return { keys, wallets };
}

// ---------------------------------------------------------------------------
// Recording.

/** A value as JSON carries it: undefined properties dropped, and nothing JSON can't hold. */
function jsonOf(value, where = 'value') {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    assert.ok(Number.isFinite(value), `${where}: a number JSON can't hold`);
    return value;
  }
  if (Array.isArray(value)) return value.map((item, index) => (item === undefined ? null : jsonOf(item, `${where}[${index}]`)));
  const proto = typeof value === 'object' ? Object.getPrototypeOf(value) : undefined;
  assert.ok(proto === Object.prototype || proto === null, `${where}: not plain JSON (${typeof value})`);
  const out = {};
  for (const [key, item] of Object.entries(value)) if (item !== undefined) out[key] = jsonOf(item, `${where}.${key}`);
  return out;
}

/** What a dependency threw, as the dispatcher reads it. */
function thrown(err) {
  return jsonOf({
    ...(err?.code !== undefined ? { code: err.code } : {}),
    message: String(err?.message ?? err),
    ...(err?.data !== undefined ? { data: err.data } : {}),
  });
}

/** A scripted failure. */
function failing({ code, message, data }) {
  return Object.assign(new Error(message), code !== undefined ? { code } : {}, data !== undefined ? { data } : {});
}

/** A scripted answer: its value, or the failure it scripts. */
function scripted(answer) {
  if (answer && typeof answer === 'object' && answer.throws) throw failing(answer.throws);
  return answer;
}

function effectSync(w, effect, args, compute) {
  const entry = { effect, args: jsonOf(args, effect) };
  w.log.push(entry);
  try {
    const value = compute();
    if (value !== undefined) entry.answer = jsonOf(value, effect);
    return value;
  } catch (err) {
    entry.throws = thrown(err);
    throw err;
  }
}

async function effect(w, name, args, compute) {
  const entry = { effect: name, args: jsonOf(args, name) };
  w.log.push(entry);
  try {
    const value = await compute();
    if (value !== undefined) entry.answer = jsonOf(value, name);
    return value;
  } catch (err) {
    entry.throws = thrown(err);
    throw err;
  }
}

// ---------------------------------------------------------------------------
// The scenario's world.

const CHAIN_ANSWERS = Object.freeze({
  eth_blockNumber: '0x1406f40',
  eth_getBalance: '0xde0b6b3a7640000',
  eth_getCode: '0x6080604052',
  eth_getStorageAt: '0x' + '00'.repeat(31) + '01',
  eth_getTransactionCount: '0x5',
  eth_getBlockByNumber: { number: '0x1406f40', hash: BLOCK, timestamp: '0x6912a000', baseFeePerGas: '0x2540be400', transactions: [] },
  eth_getBlockByHash: { number: '0x1406f40', hash: BLOCK, timestamp: '0x6912a000', baseFeePerGas: '0x2540be400', transactions: [] },
  eth_getTransactionByHash: null,
  eth_getTransactionReceipt: null,
  eth_call: '0x' + word('de0b6b3a7640000'),
  eth_estimateGas: '0xc350',
  eth_gasPrice: '0x4e3b29200',
  eth_feeHistory: {
    oldestBlock: '0x1406f3d',
    baseFeePerGas: ['0x2540be400', '0x2540be400', '0x2540be400', '0x2540be400', '0x2540be400'],
    gasUsedRatio: [0.5, 0.42, 0.61, 0.48],
    reward: [['0x3b9aca00', '0x77359400'], ['0x3b9aca00', '0x77359400'], ['0x3b9aca00', '0x77359400'], ['0x3b9aca00', '0x77359400']],
  },
  eth_maxPriorityFeePerGas: '0x3b9aca00',
  eth_getLogs: [],
  eth_getFilterChanges: [],
  eth_getFilterLogs: [],
  eth_newFilter: '0x1',
  eth_newBlockFilter: '0x2',
  eth_newPendingTransactionFilter: '0x3',
  eth_uninstallFilter: true,
  web3_clientVersion: 'Geth/v1.16.5-stable',
  // keccak256("hello")
  web3_sha3: '0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8',
});

const QUOTE_1559 = Object.freeze({ source: 'direct', type: 'eip1559', maxFeePerGas: String(30n * GWEI), maxPriorityFeePerGas: String(2n * GWEI), answered: 3 });
const QUOTE_LEGACY = Object.freeze({ source: 'direct', type: 'legacy', gasPrice: String(20n * GWEI), answered: 3 });

/** The fee check's verdict for a prepared send, as fee-check.js's `judgeFees` shapes it. */
function verdictFor(tx, { above = false, oneEndpoint = false } = {}) {
  const perGas = BigInt(tx.maxFeePerGas ?? tx.gasPrice);
  return {
    maxCost: (perGas * BigInt(tx.gasLimit)).toString(),
    comparable: true,
    ratio: above ? '4.76' : '1.43',
    above,
    oneEndpoint,
    basis: 'header',
    autoApprove: !above && !oneEndpoint,
  };
}

function worldOf(ref, fixtures, spec) {
  const docs = (spec.docs ?? [page()]).map((doc) => ({ ...doc, current: true, holds: true }));
  const fsMem = memoryFs();
  const store = loadStore(ref.checkout, 'dapp', fsMem);
  for (const grant of spec.grants ?? []) {
    store.grantPermission(grant.key, grant.walletIndex, grant.chainId);
    if (grant.signing) store.setSigningAutoApprove(grant.key, true);
    for (const rule of grant.rules ?? []) store.addTransactionAutoApprove(grant.key, rule.to, rule.selector, rule.chainId, rule.value);
  }
  const file = () => (fsMem.files.has(FILE) ? JSON.parse(fsMem.files.get(FILE)) : null);
  const w = {
    id: spec.id,
    store,
    file,
    before: file(),
    docs,
    requester: docs[0],
    windows: { ...(spec.windows ?? { 1: null }) },
    enabled: spec.enabled ?? true,
    vault: spec.vault ?? true,
    custody: [].concat(spec.custody ?? false),
    active: spec.active ?? 0,
    wallets: (spec.wallets ?? fixtures.wallets).map((wallet) => ({ ...wallet })),
    names: [...(spec.names ?? [])],
    prompts: [...(spec.prompts ?? [])],
    chain: spec.chain ?? ((method) => ({ result: CHAIN_ANSWERS[method] })),
    quotes: [].concat(spec.quote ?? QUOTE_1559),
    verdicts: [...(spec.verdicts ?? [])],
    atApproval: [...(spec.atApproval ?? [])],
    signFails: spec.signFails ?? null,
    sendFails: spec.sendFails ?? null,
    turnBusy: spec.turnBusy ?? false,
    waiting: spec.waiting ?? false,
    failGrant: spec.failGrant ?? false,
    view: spec.view ?? null,
    handles: 0,
    tokens: new Map(),
    log: null,
  };
  return w;
}

/** Custody as the scenario sets it: one answer per read, the last one kept. */
const custodyNow = (w) => (w.custody.length > 1 ? w.custody.shift() : w.custody[0]);

/** A change to the world while a prompt is open, recorded where it happens. */
function applyChange(w, change) {
  w.log.push({ effect: 'world', change });
  const [what, arg] = change.split(':');
  if (what === 'navigated') w.requester.current = false;
  else if (what === 'grant-revoked') w.store.revokePermission(w.requester.key);
  else if (what === 'signing-rule-off') w.store.setSigningAutoApprove(w.requester.key, false);
  else if (what === 'wallet-removed') w.wallets = w.wallets.filter((wallet) => wallet.index !== Number(arg));
  else if (what === 'vault-unlocked') w.vault = true;
  else if (what === 'custody-entered') w.custody = [true];
  else assert.fail(`${w.id}: unknown change ${change}`);
}

function dependenciesOf(ref, fixtures, w) {
  const { utils, ethers, transactions } = ref;
  const write = (op, args, fn) => effectSync(w, 'grant.write', { op, ...args }, () => {
    if (w.failGrant && op === 'grantPermission') throw new Error('EACCES: permission denied');
    fn();
  });
  const custody = (guest) => effectSync(w, 'custody', { guest }, () => custodyNow(w));
  const keyOf = (index) => fixtures.keys[index] ?? assert.fail(`${w.id}: no key for account ${index}`);
  const signFailure = () => {
    if (w.signFails) throw failing(w.signFails);
  };
  const coreTypedDataView = (typedData, options, normalized) =>
    effect(w, 'core.typed_data_view', { typedData, options }, () => ({
      hash: ethers.TypedDataEncoder.hash(normalized.domain, utils.withoutDomainType(normalized.types), normalized.message),
      view: { named_type: 'match', chain: 'match', ...(w.view ?? {}) },
    }));
  ref.chainData.current = {
    request: (chainId, method, params, options) =>
      effect(w, 'chain.request', { chainId, method, params, origin: options?.routingContext?.origin }, () => scripted(w.chain(method, params, chainId))),
    getFeeQuote: (chainId) => effect(w, 'chain.fee_quote', { chainId }, () => scripted(w.quotes.length > 1 ? w.quotes.shift() : w.quotes[0])),
  };
  return {
    identityWalletEnabled: () => w.enabled,
    selectedChainOf: (windowId) => w.windows[windowId] ?? null,
    getPermission: (key) => w.store.getPermission(key),
    getDerivedWallets: async () => w.wallets.map((wallet) => ({ ...wallet })),
    chainRequest: (chainId, method, params, options) => ref.chainData.current.request(chainId, method, params, options),
    isChainAvailable: (chainId) => AVAILABLE.includes(Number(chainId)),
    chainName: (chainId) => NETWORKS[chainId]?.name,
    networks: () => NETWORKS,
    getActiveWalletIndex: () => w.active,
    grantPermission: (key, walletIndex, chainId) =>
      write('grantPermission', { key, walletIndex, chainId }, () => w.store.grantPermission(key, walletIndex, chainId)),
    updateLastUsed: (key, chainId) => write('updateLastUsed', { key, chainId }, () => w.store.updateLastUsed(key, chainId)),
    selectChainForPage: (windowId, chainId) => effectSync(w, 'chain.select', { window: windowId, chainId }, () => {
      w.windows[windowId] = chainId;
    }),
    agentWalletRequest: (guest, request) => effect(w, 'agent.request', { guest, request }, () => ({ handled: false })),
    signing: {
      inCustody: custody,
      isVaultUnlocked: async () => w.vault,
      messageView(message) {
        if (typeof message !== 'string') {
          throw new Error('The message to sign must be text or 0x-prefixed hex');
        }
        const bytes = utils.messageToBytes(utils.normalizeMessage(message));
        return { hex: '0x' + bytes.toString('hex'), rawHash: utils.signsRawHash(message) };
      },
      async typedDataView(typedData, chainId) {
        const normalized = utils.normalizeTypedData(typedData);
        if (!normalized || typeof normalized !== 'object') {
          throw new Error('Typed data is required');
        }
        const { hash, view } = await coreTypedDataView(
          utils.toCoreTypedData(normalized),
          utils.typedDataViewOptions(normalized, chainId),
          normalized
        );
        return { hash, view, warnings: utils.typedDataWarnings(view) };
      },
      signsRawHash: (message) => utils.signsRawHash(message),
      getSigner: (walletIndex) => ({
        signMessage: (payload) => effect(w, 'sign.message', { account: walletIndex, message: payload }, () => {
          signFailure();
          return keyOf(walletIndex).signMessage(utils.messageToBytes(utils.normalizeMessage(payload)));
        }),
        signTypedData: (payload, { expectedHash } = {}) =>
          effect(w, 'sign.typed_data', { account: walletIndex, typedData: payload, expectedHash }, () => {
            signFailure();
            const normalized = utils.normalizeTypedData(payload);
            const types = utils.withoutDomainType(normalized.types);
            assert.equal(ethers.TypedDataEncoder.hash(normalized.domain, types, normalized.message), expectedHash);
            return keyOf(walletIndex).signTypedData(normalized.domain, types, normalized.message);
          }),
      }),
      setSigningAutoApprove: (key, enabled) =>
        write('setSigningAutoApprove', { key, enabled }, () => w.store.setSigningAutoApprove(key, enabled)),
      startSafeMessage: () => assert.fail(`${w.id}: a Safe's message is not scripted`),
      completeSafeMessage: () => assert.fail(`${w.id}: a Safe's message is not scripted`),
      cancelSafeMessage: () => assert.fail(`${w.id}: a Safe's message is not scripted`),
    },
    sends: {
      inCustody: custody,
      isVaultUnlocked: async () => w.vault,
      ruleMatches: (key, to, selector, chainId, value) => w.store.isTransactionAutoApproved(key, to, selector, chainId, value),
      rulePaused: (key) => effect(w, 'send.paused', { key }, () => false),
      addTransactionAutoApprove: (key, to, selector, chainId, value) =>
        write('addTransactionAutoApprove', { key, to, selector, chainId, value },
          () => w.store.addTransactionAutoApprove(key, to, selector, chainId, value)),
      estimateGas: (request) => transactions.estimateGas(request),
      getGasPrices: (chainId) => transactions.getGasPrices(chainId),
      checkFees: (tx) => effect(w, 'fees.check', { tx }, () => (w.verdicts.length ? w.verdicts.shift() : verdictFor)(tx)),
      checkAtApproval: (tx, { acknowledged = false } = {}) => effect(w, 'fees.at_approval', { tx, acknowledged }, () => {
        const verdict = (w.atApproval.length ? w.atApproval.shift() : verdictFor)(tx);
        return { ...verdict, askAgain: verdict.above && acknowledged !== true };
      }),
      takeSiteTurn: async (site, { wait }) => {
        await effect(w, 'send.turn', { site, wait }, () => {
          if (w.turnBusy) throw failing({ code: 'SITE_TURN_BUSY', message: 'Another payment of this site is in progress' });
          return 'taken';
        });
        return () => {};
      },
      sitePaymentWaiting: (site) => effect(w, 'send.waiting', { site }, () => w.waiting),
      getSigner: (walletIndex) => ({ walletIndex }),
      // tx-recorder.js's order: the signature, main's check after it
      // (`guardCommit`), then the journal and the broadcast.
      async signAndRecord(tx, signer, context, { walletIndex, onCommitted, guardCommit } = {}) {
        await effect(w, 'send.sign', { tx, account: signer.walletIndex, walletIndex, context }, () => {
          if (w.sendFails) throw failing(w.sendFails);
          return 'signed';
        });
        if (guardCommit) await guardCommit(async () => {});
        const hash = await effect(w, 'send.broadcast', {}, () => w.hash ?? HASH);
        onCommitted?.();
        return { hash };
      },
      startSafeSend: () => assert.fail(`${w.id}: a Safe's send is not scripted`),
      onSafeSendSettled: () => assert.fail(`${w.id}: a Safe's send is not scripted`),
      guardSiteSafeSend: () => assert.fail(`${w.id}: a Safe's send is not scripted`),
      siteWithdrawn: () => assert.fail(`${w.id}: a Safe's send is not scripted`),
    },
  };
}

/** page-requests.js's context for one record, over the scenario's world. */
async function runRequest(ref, w, dispatchers, request) {
  const { confirmations } = ref;
  const doc = w.requester;
  const requester = Object.freeze({
    key: doc.key, chain: doc.chain, window: doc.window, guest: doc.guest, navigation: doc.navigation, transportKey: doc.transportKey,
  });
  const record = { keyless: undefined, answered: false, approved: null, tokenHandle: null };
  const holdsKey = () => doc.current && doc.holds;
  const queued = [];
  let outcome = null;
  const labelOf = (target) => w.docs.find((d) => d.guest === target.guest && d.navigation === target.navigation)?.id
    ?? assert.fail(`${w.id}: an event to an unknown document`);
  const notConfirmed = (reason) => Object.assign(new Error(`Signing was not confirmed: ${reason}`), { code: confirmations.NOT_CONFIRMED });
  w.log = [];
  const log = w.log;
  const context = {
    id: 1,
    requester,
    provider: 'ethereum',
    method: request.method,
    params: request.params,
    isCurrent: () => doc.current,
    nameHolds: async ({ keyless } = {}) => {
      if (keyless !== undefined && record.keyless === undefined) record.keyless = keyless;
      // Only a DNS name over IPNS whose binding stands resolves anything
      // (`recheckName`: once `endNameBinding` has cleared the document's
      // key, nothing is resolved); a name that no longer answers its IPNS
      // key ends the binding.
      if (doc.transportKey && doc.current && doc.holds) {
        const holds = await effect(w, 'name.check', { name: doc.key, transportKey: doc.transportKey },
          () => (w.names.length ? w.names.shift() : true));
        if (!holds) doc.holds = false;
      }
      return holdsKey();
    },
    holdsKey,
    async prompt({ kind, view = {}, choices } = {}) {
      if (record.answered) return { closed: 'cancelled' };
      const entry = { effect: 'prompt', args: jsonOf({ kind, view }, 'prompt') };
      w.log.push(entry);
      const refused = [];
      let decision;
      let raw;
      for (;;) {
        assert.ok(w.prompts.length > 0, `${w.id}: prompt ${kind} has no scripted decision`);
        raw = w.prompts.shift();
        if (raw.busy) decision = { error: { ...PROMPT_PENDING } };
        else if (raw.closed) decision = { closed: raw.closed };
        else if (raw.approve !== true) decision = { approve: false, choices: {} };
        else {
          let checked;
          try {
            checked = choices(raw.choices ?? {});
          } catch {
            checked = null;
          }
          // page-prompts.js's `decide`: a pick the prompt didn't offer is
          // refused, and the prompt stays open.
          if (!checked) {
            refused.push(raw.choices);
            continue;
          }
          decision = { approve: true, choices: checked };
        }
        break;
      }
      if (refused.length > 0) entry.refused = jsonOf(refused, 'refused');
      entry.answer = jsonOf(decision, 'decision');
      // Main's handle: 32 random bytes in hex (page-requests.js's
      // `openHandle`), here the prompt's count.
      if (decision.approve === true) record.approved = (++w.handles).toString(16).padStart(64, '0');
      for (const change of raw.then ?? []) applyChange(w, change);
      return decision;
    },
    confirm(kind, accountIndex, payload, bound) {
      return effectSync(w, 'token.issue', { kind, account: accountIndex, payload, bound }, () => {
        const handle = record.approved;
        if (record.answered || !handle || !doc.current || !requester.key) throw notConfirmed('no live request approved by the user');
        const { token } = confirmations.issuePageConfirmation(kind, accountIndex, payload, { handle, key: requester.key }, bound);
        const label = `token-${w.tokens.size + 1}`;
        w.tokens.set(label, token);
        record.approved = null;
        record.tokenHandle = handle;
        return label;
      });
    },
    spend(label, kind, accountIndex, payload) {
      return effectSync(w, 'token.spend', { token: label, kind, account: accountIndex, payload }, () => {
        const token = w.tokens.get(label);
        if (record.answered || !doc.current || !holdsKey()) {
          confirmations.discardConfirmation(token);
          throw notConfirmed('the document that asked has gone');
        }
        const handle = record.tokenHandle;
        record.tokenHandle = null;
        return confirmations.consumePageConfirmation(token, kind, accountIndex, payload, { handle, key: requester.key });
      });
    },
    walletOperation: async (run) => ({ done: await run({ signal: new AbortController().signal, open: () => !record.answered }) }),
    leaveWalletSlot: () => {},
    signal: new AbortController().signal,
    afterAnswer: () => {},
    whenAnswered: async () => outcome,
    liveDocuments: () => w.docs.filter((d) => d.current)
      .map((d) => ({ key: d.key, chain: d.chain, window: d.window, guest: d.guest, navigation: d.navigation })),
    sendEvent: async (target, event, data) => {
      w.log.push(jsonOf({ effect: 'event', args: { to: labelOf(target), event, data } }, 'event'));
    },
    onDocumentEnded: () => () => {},
    inGrantOrder: (_key, job) => queued.push(job),
    inChainOrder: async (_windowId, job) => job(),
    copied: () => {},
  };
  const dispatch = dispatchers[`ethereum:${request.method}`];
  assert.ok(dispatch, `${w.id}: no dispatcher for ${request.method}`);
  const result = jsonOf(await dispatch(context), `${w.id} result`);
  record.answered = true;
  // page-requests.js's `answer`.
  const current = doc.current;
  let value = result;
  if (current && record.keyless !== undefined && value && !value.error && !holdsKey()) value = jsonOf(record.keyless);
  outcome = { delivered: current, ok: Boolean(current && value && !value.error) };
  // The grant's events, queued at its write, go out once main has answered.
  w.log = [];
  const after = w.log;
  for (const job of queued) await job();
  w.log = null;
  return {
    method: request.method,
    ...(request.params !== undefined ? { params: jsonOf(request.params, 'params') } : {}),
    effects: log,
    result,
    ...(record.keyless !== undefined ? { keyless: jsonOf(record.keyless) } : {}),
    answer: current ? value : { gone: true },
    ...(after.length > 0 ? { after } : {}),
  };
}

async function runScenario(ref, fixtures, spec) {
  const w = worldOf(ref, fixtures, spec);
  const dispatchers = ref.ethereum.createEthereumDispatchers(dependenciesOf(ref, fixtures, w));
  const world = jsonOf({
    documents: w.docs.map(({ current: _c, holds: _h, ...doc }) => doc),
    windows: w.windows,
    enabled: w.enabled,
    vault: w.vault,
    custody: w.custody[0],
    active: w.active,
    ...(spec.wallets ? { wallets: spec.wallets } : {}),
  }, `${spec.id} world`);
  const requests = [];
  for (const request of spec.requests) requests.push(await runRequest(ref, w, dispatchers, request));
  assert.equal(w.prompts.length, 0, `${spec.id}: a scripted decision was never asked for`);
  assert.equal(w.names.length, 0, `${spec.id}: a scripted name check never ran`);
  assert.equal(w.verdicts.length + w.atApproval.length, 0, `${spec.id}: a scripted verdict was never asked for`);
  return {
    id: spec.id,
    from: spec.from,
    step: spec.step,
    world,
    grants: { before: w.before, after: w.file() },
    requests,
  };
}

// ---------------------------------------------------------------------------
// The scenarios. `from` is the reference test each mirrors
// (src/main/page/<file>:<line>, checked to start a test), or the design.

const page = (fields = {}) => ({ id: 'page', key: SITE, chain: null, window: 1, guest: 11, navigation: 1, transportKey: null, ...fields });
const named = (fields = {}) => page({ key: NAME, transportKey: `ipns://${IPNS_KEY}`, ...fields });
const req = (method, params) => ({ method, ...(params !== undefined ? { params } : {}) });
const grant = (walletIndex = 0, chainId = 1, fields = {}) => ({ key: SITE, walletIndex, chainId, ...fields });
const approve = (choices, then) => ({ approve: true, ...(choices !== undefined ? { choices } : {}), ...(then ? { then } : {}) });
const reject = (then) => ({ approve: false, ...(then ? { then } : {}) });
const typed = (fields = {}) => ({
  types: {
    EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'chainId', type: 'uint256' }],
    Order: [{ name: 'amount', type: 'uint256' }, { name: 'to', type: 'address' }],
  },
  domain: { name: 'Example', chainId: 1 },
  primaryType: 'Order',
  message: { amount: '1000', to: RECIPIENT },
  ...fields,
});
const contractCall = (fields = {}) => ({ to: ROUTER, value: '0x0', data: approveData(1000), ...fields });
const RULE = Object.freeze({ to: ROUTER, selector: APPROVE, chainId: 1, value: '0' });

function readScenarios(ethereumRpcReads, account) {
  const params = {
    eth_blockNumber: [],
    eth_getBalance: [account, 'latest'],
    eth_getCode: [ROUTER, 'latest'],
    eth_getStorageAt: [ROUTER, '0x0', 'latest'],
    eth_getTransactionCount: [account, 'pending'],
    eth_getBlockByNumber: ['latest', false],
    eth_getBlockByHash: [BLOCK, false],
    eth_getTransactionByHash: [HASH],
    eth_getTransactionReceipt: [HASH],
    eth_call: [{ to: USDC, data: '0x70a08231' + word(account) }, 'latest'],
    eth_estimateGas: [{ from: account, to: ROUTER, data: approveData(1) }],
    eth_gasPrice: [],
    eth_feeHistory: ['0x4', 'latest', [25, 75]],
    eth_maxPriorityFeePerGas: [],
    eth_getLogs: [{ address: USDC, fromBlock: '0x1406f00', toBlock: 'latest' }],
    eth_getFilterChanges: ['0x1'],
    eth_getFilterLogs: ['0x1'],
    eth_newFilter: [{ address: USDC, fromBlock: 'latest' }],
    eth_newBlockFilter: [],
    eth_newPendingTransactionFilter: [],
    eth_uninstallFilter: ['0x1'],
    web3_clientVersion: [],
    web3_sha3: [HELLO],
  };
  assert.deepEqual(Object.keys(params), [...ethereumRpcReads], 'STOP: the reference reads other methods');
  const rpcRevert = { throws: { code: 3, message: 'execution reverted: ERC20: insufficient allowance', data: '0x08c379a0' + word('20') + word('1d') } };
  return [
    { id: 'read-chain-default', from: 'page-ethereum.test.js:203', step: 'APR-5b',
      requests: [req('eth_chainId', []), req('net_version', [])] },
    { id: 'read-chain-selected', from: 'page-ethereum.test.js:203', step: 'APR-5b', windows: { 1: 1 },
      requests: [req('eth_chainId', []), req('net_version', [])] },
    { id: 'read-chain-onchain-app', from: 'page-ethereum.test.js:225', step: 'APR-5b', windows: { 1: 1 },
      docs: [page({ key: 'web3://0x' + 'cd'.repeat(20) + ':8453', chain: 8453 })],
      requests: [req('eth_chainId', []), req('net_version', []), req('eth_blockNumber', [])] },
    { id: 'read-accounts-granted', from: 'page-ethereum.test.js:243', step: 'APR-5b', grants: [grant(0, 1)],
      requests: [req('eth_accounts', [])] },
    { id: 'read-accounts-no-grant', from: 'page-ethereum.test.js:243', step: 'APR-5b',
      requests: [req('eth_accounts', [])] },
    { id: 'read-accounts-wallet-gone', from: 'page-ethereum.test.js:243', step: 'APR-5b', grants: [grant(7, 1)],
      requests: [req('eth_accounts', [])] },
    { id: 'read-keyless', from: 'page-ethereum.test.js:276', step: 'APR-5b', docs: [page({ key: null })],
      requests: [req('eth_accounts', []), req('eth_chainId', []), req('eth_blockNumber', [])] },
    { id: 'read-rpc-every-method', from: 'page-ethereum.test.js:294', step: 'APR-5b', windows: { 1: 8453 },
      requests: Object.entries(params).map(([method, p]) => req(method, p)) },
    { id: 'read-rpc-no-params', from: 'page-ethereum.test.js:294', step: 'APR-5b',
      requests: [req('eth_blockNumber')] },
    { id: 'read-rpc-error-code-data', from: 'page-ethereum.test.js:313', step: 'APR-5b',
      chain: () => rpcRevert,
      requests: [req('eth_call', [{ to: USDC, data: approveData(1) }, 'latest'])] },
    { id: 'read-rpc-error-plain', from: 'page-ethereum.test.js:313', step: 'APR-5b',
      chain: () => ({ throws: { message: 'All chain sources failed for chain 100' } }),
      requests: [req('eth_blockNumber', [])] },
    { id: 'read-rpc-error-empty', from: 'page-ethereum.test.js:313', step: 'APR-5b',
      chain: () => ({ throws: { code: 0, message: '' } }),
      requests: [req('eth_gasPrice', [])] },
    { id: 'read-rpc-no-provider', from: 'page-ethereum.test.js:313', step: 'APR-5b', windows: { 1: 11155111 },
      chain: () => ({ throws: { code: -32603, message: 'No endpoints for chain 11155111' } }),
      requests: [req('eth_blockNumber', [])] },
    { id: 'read-rpc-no-provider-unknown-chain', from: 'page-ethereum.test.js:313', step: 'APR-5b', windows: { 1: 424242 },
      chain: () => ({ throws: { code: -32603, message: 'No endpoints for chain 424242' } }),
      requests: [req('eth_chainId', []), req('eth_blockNumber', [])] },
    { id: 'read-switch-off', from: 'page-ethereum.test.js:363', step: 'APR-5b', enabled: false, grants: [grant(0, 1)],
      requests: [
        req('eth_chainId', []), req('eth_accounts', []), req('eth_call', [{ to: USDC, data: '0x' }, 'latest']),
        req('eth_requestAccounts', []), req('wallet_switchEthereumChain', [{ chainId: '0x1' }]),
        req('personal_sign', [HELLO, account]), req('eth_sendTransaction', [contractCall()]),
      ] },
  ];
}

function nameScenarios() {
  const grants = [{ key: NAME, walletIndex: 0, chainId: 100 }, { key: `ipns://${IPNS_KEY}`, walletIndex: 1, chainId: 100 }];
  return [
    { id: 'name-accounts-honest', from: 'page-ethereum.test.js:400', step: 'APR-5f', docs: [named()], grants,
      requests: [req('eth_accounts', [])] },
    { id: 'name-accounts-moved', from: 'page-ethereum.test.js:409', step: 'APR-5f', docs: [named()], grants, names: [false],
      requests: [req('eth_accounts', []), req('eth_blockNumber', []), req('eth_accounts', [])] },
    { id: 'name-accounts-moved-during-wallets', from: 'page-ethereum.test.js:447', step: 'APR-5f', docs: [named()], grants,
      names: [true, false],
      requests: [req('eth_accounts', [])] },
    { id: 'name-connect-honest', from: 'page-connect.test.js:818', step: 'APR-5f', docs: [named()],
      prompts: [approve({ walletIndex: 0 })],
      requests: [req('eth_requestAccounts', [])] },
    { id: 'name-connect-moved-during-prompt', from: 'page-connect.test.js:886', step: 'APR-5f', docs: [named()],
      names: [true, true, false], prompts: [approve({ walletIndex: 0 })],
      requests: [req('eth_requestAccounts', [])] },
    { id: 'name-switch-moved', from: 'page-connect.test.js:1022', step: 'APR-5f', docs: [named()], grants, names: [false],
      requests: [req('wallet_switchEthereumChain', [{ chainId: '0x1' }])] },
    { id: 'name-sign-moved-during-prompt', from: 'page-signing.test.js:937', step: 'APR-5f', docs: [named()], grants,
      names: [true, true, true, false], prompts: [approve({})],
      requests: [req('personal_sign', [HELLO])] },
    { id: 'name-send-moved-during-prompt', from: 'page-sends.test.js:1076', step: 'APR-5f', docs: [named()],
      grants: [{ key: NAME, walletIndex: 0, chainId: 1 }], windows: { 1: 1 },
      names: [true, true, true, false], prompts: [approve({})],
      requests: [req('eth_sendTransaction', [contractCall()])] },
  ];
}

function connectScenarios() {
  const other = { id: 'other-tab', key: SITE, chain: null, window: 2, guest: 12, navigation: 1, transportKey: null };
  const elsewhere = { id: 'other-site', key: 'https://other.example', chain: null, window: 1, guest: 13, navigation: 1, transportKey: null };
  return [
    { id: 'connect-connected', from: 'page-connect.test.js:210', step: 'APR-5c', grants: [grant(0, 100)],
      requests: [req('eth_requestAccounts', [])] },
    { id: 'connect-approved', from: 'page-connect.test.js:220', step: 'APR-5c', windows: { 1: 1 },
      prompts: [approve({ walletIndex: 0 })],
      requests: [req('eth_requestAccounts', []), req('eth_accounts', [])] },
    { id: 'connect-approved-events', from: 'page-connect.test.js:254', step: 'APR-5c',
      docs: [page(), other, elsewhere], windows: { 1: 100, 2: 100 }, prompts: [approve({ walletIndex: 1 })],
      requests: [req('eth_requestAccounts', [])] },
    { id: 'connect-rejected', from: 'page-connect.test.js:270', step: 'APR-5c', prompts: [reject()],
      requests: [req('eth_requestAccounts', [])] },
    { id: 'connect-pick-not-offered', from: 'page-connect.test.js:281', step: 'APR-5c',
      prompts: [approve({ walletIndex: 1001 }), approve({ walletIndex: 0, extra: true }), approve({ walletIndex: 2 })],
      requests: [req('eth_requestAccounts', [])] },
    { id: 'connect-default-first-offered', from: 'page-connect.test.js:296', step: 'APR-5c', active: 1001,
      prompts: [approve({ walletIndex: 1000 })],
      requests: [req('eth_requestAccounts', [])] },
    { id: 'connect-onchain-app-chain', from: 'page-connect.test.js:310', step: 'APR-5c', windows: { 1: 1 },
      docs: [page({ key: 'web3://0x' + 'cd'.repeat(20) + ':8453', chain: 8453 })], prompts: [approve({ walletIndex: 0 })],
      requests: [req('eth_requestAccounts', [])] },
    { id: 'connect-keyless', from: 'page-connect.test.js:326', step: 'APR-5c', docs: [page({ key: null })],
      requests: [req('eth_requestAccounts', [])] },
    { id: 'connect-navigated', from: 'page-connect.test.js:338', step: 'APR-5c',
      prompts: [{ closed: 'navigated', then: ['navigated'] }],
      requests: [req('eth_requestAccounts', [])] },
    { id: 'connect-closed', from: 'design 0012', step: 'APR-5c', prompts: [{ closed: 'closed' }],
      requests: [req('eth_requestAccounts', [])] },
    { id: 'connect-busy', from: 'page-signing.test.js:484', step: 'APR-5c', prompts: [{ busy: true }],
      requests: [req('eth_requestAccounts', [])] },
    { id: 'connect-account-gone', from: 'page-connect.test.js:350', step: 'APR-5c',
      prompts: [approve({ walletIndex: 1 }, ['wallet-removed:1'])],
      requests: [req('eth_requestAccounts', [])] },
    { id: 'connect-grant-fails', from: 'page-connect.test.js:361', step: 'APR-5c', failGrant: true,
      prompts: [approve({ walletIndex: 0 })],
      requests: [req('eth_requestAccounts', [])] },
    { id: 'switch-known-chain', from: 'page-connect.test.js:958', step: 'APR-5c', grants: [grant(0, 100)],
      docs: [page(), { ...other, window: 1, guest: 12 }, { ...other, id: 'onchain-app', window: 1, guest: 14, key: 'web3://0x' + 'cd'.repeat(20) + ':8453', chain: 8453 }, { ...other, id: 'other-window' }],
      windows: { 1: 100, 2: 100 },
      requests: [req('wallet_switchEthereumChain', [{ chainId: '0x1' }]), req('eth_chainId', [])] },
    { id: 'switch-no-grant', from: 'page-connect.test.js:982', step: 'APR-5c', windows: { 1: 100 },
      requests: [req('wallet_switchEthereumChain', [{ chainId: '0x2105' }])] },
    { id: 'switch-same-chain', from: 'page-connect.test.js:958', step: 'APR-5c', grants: [grant(0, 100)],
      docs: [page(), { ...other, window: 1, guest: 12 }], windows: { 1: 100 },
      requests: [req('wallet_switchEthereumChain', [{ chainId: '0x64' }])] },
    // `parseInt(raw, 16)` reads a number's decimal digits as hex: 100 is 0x100.
    { id: 'switch-number-read-as-hex', from: 'page-connect.test.js:991', step: 'APR-5c', grants: [grant(0, 100)], windows: { 1: 100 },
      requests: [req('wallet_switchEthereumChain', [{ chainId: 100 }]), req('wallet_switchEthereumChain', [{ chainId: 1 }])] },
    { id: 'switch-refusals', from: 'page-connect.test.js:991', step: 'APR-5c', grants: [grant(0, 100)], windows: { 1: 100 },
      requests: [
        req('wallet_switchEthereumChain', []), req('wallet_switchEthereumChain'), req('wallet_switchEthereumChain', [{}]),
        req('wallet_switchEthereumChain', [{ chainId: '' }]), req('wallet_switchEthereumChain', [{ chainId: { id: 1 } }]),
        req('wallet_switchEthereumChain', [{ chainId: '0x539' }]), req('wallet_switchEthereumChain', [{ chainId: '0xaa36a7' }]),
        req('eth_chainId', []),
      ] },
    { id: 'switch-keyless', from: 'page-connect.test.js:991', step: 'APR-5c', docs: [page({ key: null })],
      requests: [req('wallet_switchEthereumChain', [{ chainId: '0x1' }])] },
    { id: 'switch-onchain-app', from: 'page-connect.test.js:1008', step: 'APR-5c', windows: { 1: 100 },
      docs: [page({ key: 'web3://0x' + 'cd'.repeat(20) + ':8453', chain: 8453 }), { ...other, window: 1, guest: 12 }],
      requests: [req('wallet_switchEthereumChain', [{ chainId: '0x1' }]), req('wallet_switchEthereumChain', [{ chainId: '0x2105' }])] },
  ];
}

function signingScenarios(account) {
  const ruled = grant(0, 1, { signing: true });
  return [
    { id: 'sign-message-approved', from: 'page-signing.test.js:329', step: 'APR-5d', grants: [grant(0, 1)], windows: { 1: 1 },
      prompts: [approve({})],
      requests: [req('personal_sign', [HELLO, account])] },
    { id: 'sign-message-text', from: 'page-signing.test.js:329', step: 'APR-5d', grants: [grant(0, 100)],
      prompts: [approve()],
      requests: [req('personal_sign', ['Sign in to app.example', account])] },
    { id: 'sign-typed-approved', from: 'page-signing.test.js:361', step: 'APR-5d', grants: [grant(0, 1)], windows: { 1: 1 },
      prompts: [approve({ alwaysAllow: false })],
      requests: [req('eth_signTypedData_v4', [account, JSON.stringify(typed())])] },
    { id: 'sign-typed-object', from: 'page-signing.test.js:361', step: 'APR-5d', grants: [grant(0, 1)], windows: { 1: 1 },
      prompts: [approve({})],
      requests: [req('eth_signTypedData_v4', [account, typed()])] },
    { id: 'sign-typed-chain-mismatch', from: 'page-signing.test.js:382', step: 'APR-5d', grants: [grant(0, 100)],
      view: { chain: 'mismatch' }, prompts: [reject()],
      requests: [req('eth_signTypedData_v4', [account, JSON.stringify(typed())])] },
    { id: 'sign-rejected', from: 'page-signing.test.js:397', step: 'APR-5d', grants: [grant(0, 1)], prompts: [reject()],
      requests: [req('personal_sign', [HELLO, account])] },
    { id: 'sign-not-connected', from: 'page-signing.test.js:409', step: 'APR-5d',
      requests: [req('personal_sign', [HELLO, account]), req('eth_signTypedData_v4', [account, JSON.stringify(typed())])] },
    { id: 'sign-keyless', from: 'page-signing.test.js:409', step: 'APR-5d', docs: [page({ key: null })],
      requests: [req('personal_sign', [HELLO, account])] },
    { id: 'sign-unshowable', from: 'page-signing.test.js:419', step: 'APR-5d', grants: [grant(0, 1)],
      requests: [req('personal_sign', [42, account]), req('personal_sign', []), req('eth_signTypedData_v4', [account, null]),
        req('eth_signTypedData_v4', [account, '{not json'])] },
    { id: 'sign-account-gone', from: 'design 0012', step: 'APR-5d', grants: [grant(7, 1)],
      requests: [req('personal_sign', [HELLO, account])] },
    { id: 'sign-safe-off-gnosis', from: 'page-signing.test.js:432', step: 'APR-5d', grants: [grant(1000, 1)], windows: { 1: 1 },
      requests: [req('personal_sign', [HELLO])] },
    { id: 'sign-always-allow', from: 'page-signing.test.js:443', step: 'APR-5d', grants: [grant(0, 1)],
      prompts: [approve({ alwaysAllow: true })],
      requests: [req('personal_sign', [HELLO, account])] },
    { id: 'sign-always-allow-fails', from: 'page-signing.test.js:460', step: 'APR-5d', grants: [grant(0, 1)],
      signFails: { message: 'The vault is locked' }, prompts: [approve({ alwaysAllow: true })],
      requests: [req('personal_sign', [HELLO, account])] },
    { id: 'sign-ledger-approved', from: 'page-signing.test.js:472', step: 'APR-5d', grants: [grant(1, 1)],
      prompts: [approve({})],
      requests: [req('personal_sign', [HELLO])] },
    { id: 'sign-ledger-declined', from: 'page-signing.test.js:472', step: 'APR-5d', grants: [grant(1, 1)],
      signFails: { code: 'LEDGER_USER_REJECTED', message: 'Rejected on the device' }, prompts: [approve({})],
      requests: [req('personal_sign', [HELLO])] },
    { id: 'sign-busy', from: 'page-signing.test.js:484', step: 'APR-5d', grants: [grant(0, 1)], prompts: [{ busy: true }],
      requests: [req('personal_sign', [HELLO, account])] },
    { id: 'sign-navigated', from: 'page-signing.test.js:538', step: 'APR-5d', grants: [grant(0, 1)],
      prompts: [{ closed: 'navigated', then: ['navigated'] }],
      requests: [req('personal_sign', [HELLO, account])] },
    { id: 'sign-revoked-during-prompt', from: 'page-signing.test.js:552', step: 'APR-5d', grants: [grant(0, 1)],
      prompts: [approve({}, ['grant-revoked'])],
      requests: [req('personal_sign', [HELLO, account])] },
    { id: 'sign-rule-answers', from: 'page-signing.test.js:700', step: 'APR-5d', grants: [ruled],
      requests: [req('personal_sign', [HELLO, account]), req('eth_signTypedData_v4', [account, JSON.stringify(typed())])] },
    { id: 'sign-rule-warned-prompts', from: 'page-signing.test.js:714', step: 'APR-5d', grants: [ruled], view: { chain: 'mismatch' },
      prompts: [approve({}), reject()],
      requests: [req('personal_sign', [RAW32, account]), req('eth_signTypedData_v4', [account, JSON.stringify(typed())])] },
    { id: 'sign-rule-locked-vault', from: 'page-signing.test.js:755', step: 'APR-5d', grants: [ruled], vault: false,
      prompts: [approve({}, ['vault-unlocked'])],
      requests: [req('personal_sign', [HELLO, account])] },
    { id: 'sign-rule-unlock-cancelled', from: 'page-signing.test.js:772', step: 'APR-5d', grants: [ruled], vault: false,
      prompts: [reject()],
      requests: [req('personal_sign', [HELLO, account])] },
    { id: 'sign-rule-off-during-unlock', from: 'page-signing.test.js:784', step: 'APR-5d', grants: [ruled], vault: false,
      prompts: [approve({}, ['vault-unlocked', 'signing-rule-off'])],
      requests: [req('personal_sign', [HELLO, account])] },
    { id: 'sign-rule-custody-during-unlock', from: 'page-signing.test.js:801', step: 'APR-5d', grants: [ruled], vault: false,
      prompts: [approve({}, ['vault-unlocked', 'custody-entered'])],
      requests: [req('personal_sign', [HELLO, account])] },
  ];
}

function sendScenarios() {
  const at1 = { windows: { 1: 1 } };
  const ruled = grant(0, 1, { rules: [RULE] });
  return [
    { id: 'send-approved', from: 'page-sends.test.js:393', step: 'APR-5e', ...at1, grants: [grant(0, 1)],
      prompts: [approve({})],
      requests: [req('eth_sendTransaction', [contractCall()])] },
    { id: 'send-plain-transfer-legacy', from: 'page-sends.test.js:452', step: 'APR-5e', grants: [grant(0, 100)], quote: QUOTE_LEGACY,
      chain: () => ({ result: '0x5208' }), prompts: [approve({ alwaysAllow: true })],
      requests: [req('eth_sendTransaction', [{ to: RECIPIENT, value: '0xde0b6b3a7640000' }])] },
    { id: 'send-erc20-transfer', from: 'page-sends.test.js:452', step: 'APR-5e', ...at1, grants: [grant(0, 1)],
      chain: () => ({ result: '0xfde8' }), prompts: [approve({})],
      requests: [req('eth_sendTransaction', [{ to: USDC, data: transferData(2500000) }])] },
    { id: 'send-effective-gas-price', from: 'page-sends.test.js:393', step: 'APR-5e', ...at1, grants: [grant(0, 1)],
      quote: { ...QUOTE_1559, effectiveGasPrice: String(12n * GWEI) }, prompts: [reject()],
      requests: [req('eth_sendTransaction', [contractCall()])] },
    { id: 'send-rejected', from: 'page-sends.test.js:479', step: 'APR-5e', ...at1, grants: [grant(0, 1)], prompts: [reject()],
      requests: [req('eth_sendTransaction', [contractCall()])] },
    { id: 'send-refusals', from: 'page-sends.test.js:491', step: 'APR-5e', ...at1, grants: [grant(0, 1)],
      requests: [
        req('eth_sendTransaction', []), req('eth_sendTransaction'), req('eth_sendTransaction', [[contractCall()]]),
        req('eth_sendTransaction', [{ value: '0x1' }]), req('eth_sendTransaction', [{ to: '0x1234' }]),
        req('eth_sendTransaction', [contractCall({ data: '0x123' })]), req('eth_sendTransaction', [contractCall({ value: '-1' })]),
        req('eth_sendTransaction', [contractCall({ value: 1.5 })]), req('eth_sendTransaction', [contractCall({ gas: 'lots' })]),
      ] },
    { id: 'send-not-connected', from: 'page-sends.test.js:491', step: 'APR-5e', ...at1,
      requests: [req('eth_sendTransaction', [contractCall()])] },
    { id: 'send-keyless', from: 'page-sends.test.js:491', step: 'APR-5e', docs: [page({ key: null })],
      requests: [req('eth_sendTransaction', [contractCall()])] },
    { id: 'send-page-fields-ignored', from: 'page-sends.test.js:516', step: 'APR-5e', ...at1, grants: [grant(0, 1)],
      prompts: [approve({})],
      requests: [req('eth_sendTransaction', [contractCall({
        from: '0x' + '99'.repeat(20), chainId: '0x64', nonce: '0x7', gasPrice: '0x1', maxFeePerGas: '0x1', type: '0x0', value: '1000', gas: 90000,
      })])] },
    { id: 'send-estimate-fails-page-gas', from: 'page-sends.test.js:607', step: 'APR-5e', ...at1, grants: [grant(0, 1)],
      chain: () => ({ throws: { code: 3, message: 'execution reverted' } }), prompts: [reject()],
      requests: [req('eth_sendTransaction', [contractCall({ gas: '0x15f90' })])] },
    { id: 'send-safe-off-gnosis', from: 'page-sends.test.js:535', step: 'APR-5e', ...at1, grants: [grant(1000, 1)],
      requests: [req('eth_sendTransaction', [contractCall()])] },
    { id: 'send-account-gone', from: 'design 0012', step: 'APR-5e', ...at1, grants: [grant(7, 1)],
      requests: [req('eth_sendTransaction', [contractCall()])] },
    { id: 'send-always-allow', from: 'page-sends.test.js:549', step: 'APR-5e', ...at1, grants: [grant(0, 1)],
      prompts: [approve({ alwaysAllow: true })],
      requests: [req('eth_sendTransaction', [contractCall({ value: '0x2386f26fc10000' })])] },
    { id: 'send-fee-asked-again', from: 'page-sends.test.js:582', step: 'APR-5e', ...at1, grants: [grant(0, 1)],
      atApproval: [(tx) => verdictFor(tx, { above: true }), (tx) => verdictFor(tx, { above: true })],
      prompts: [approve({}), approve({ feeAcknowledged: true })],
      requests: [req('eth_sendTransaction', [contractCall()])] },
    { id: 'send-quote-failed', from: 'page-sends.test.js:607', step: 'APR-5e', ...at1, grants: [grant(0, 1)],
      quote: [{ throws: { message: 'No fee quote for chain 1' } }, QUOTE_1559], prompts: [approve({}), approve({})],
      requests: [req('eth_sendTransaction', [contractCall()])] },
    { id: 'send-ledger-declined', from: 'page-sends.test.js:625', step: 'APR-5e', ...at1, grants: [grant(1, 1)],
      sendFails: { code: 'LEDGER_USER_REJECTED', message: 'Rejected on the device' }, prompts: [approve({})],
      requests: [req('eth_sendTransaction', [contractCall()])] },
    { id: 'send-phone-outcome-unknown', from: 'page-sends.test.js:641', step: 'APR-5e', ...at1, grants: [grant(2, 1)],
      sendFails: { code: 'REMOTE_OUTCOME_UNKNOWN', message: 'The phone did not answer' }, prompts: [approve({})],
      requests: [req('eth_sendTransaction', [contractCall()])] },
    { id: 'send-failed', from: 'page-sends.test.js:566', step: 'APR-5e', ...at1, grants: [grant(0, 1)],
      sendFails: { message: 'insufficient funds for gas * price + value' }, prompts: [approve({ alwaysAllow: true })],
      requests: [req('eth_sendTransaction', [contractCall()])] },
    { id: 'send-busy', from: 'page-sends.test.js:671', step: 'APR-5e', ...at1, grants: [grant(0, 1)], prompts: [{ busy: true }],
      requests: [req('eth_sendTransaction', [contractCall()])] },
    { id: 'send-navigated', from: 'page-sends.test.js:709', step: 'APR-5e', ...at1, grants: [grant(0, 1)],
      prompts: [{ closed: 'navigated', then: ['navigated'] }],
      requests: [req('eth_sendTransaction', [contractCall()])] },
    { id: 'send-revoked-during-prompt', from: 'page-sends.test.js:723', step: 'APR-5e', ...at1, grants: [grant(0, 1)],
      prompts: [approve({}, ['grant-revoked'])],
      requests: [req('eth_sendTransaction', [contractCall()])] },
    { id: 'send-rule-answers', from: 'page-sends.test.js:797', step: 'APR-5e', ...at1, grants: [ruled],
      requests: [req('eth_sendTransaction', [contractCall()])] },
    { id: 'send-rule-not-for-more-value', from: 'page-sends.test.js:811', step: 'APR-5e', ...at1, grants: [ruled],
      prompts: [reject()],
      requests: [req('eth_sendTransaction', [contractCall({ value: '0x1' })])] },
    { id: 'send-rule-turn-busy', from: 'page-sends.test.js:853', step: 'APR-5e', ...at1, grants: [ruled], turnBusy: true,
      requests: [req('eth_sendTransaction', [contractCall()])] },
    { id: 'send-rule-payment-waiting', from: 'page-sends.test.js:853', step: 'APR-5e', ...at1, grants: [ruled], waiting: true,
      requests: [req('eth_sendTransaction', [contractCall()])] },
    { id: 'send-rule-fee-needs-user', from: 'page-sends.test.js:872', step: 'APR-5e', ...at1, grants: [ruled],
      verdicts: [(tx) => verdictFor(tx, { oneEndpoint: true })], prompts: [reject()],
      requests: [req('eth_sendTransaction', [contractCall()])] },
    { id: 'send-rule-estimate-fails', from: 'design 0012', step: 'APR-5e', ...at1, grants: [ruled],
      chain: () => ({ throws: { code: 3, message: 'execution reverted' } }),
      requests: [req('eth_sendTransaction', [contractCall()])] },
    { id: 'send-rule-locked-vault', from: 'page-sends.test.js:901', step: 'APR-5e', ...at1, grants: [ruled], vault: false,
      prompts: [approve({}, ['vault-unlocked'])],
      requests: [req('eth_sendTransaction', [contractCall()])] },
    { id: 'send-rule-custody-during-unlock', from: 'page-sends.test.js:973', step: 'APR-5e', ...at1, grants: [ruled], vault: false,
      prompts: [approve({}, ['vault-unlocked', 'custody-entered'])],
      requests: [req('eth_sendTransaction', [contractCall()])] },
  ];
}

/** Each scenario's `from`: a design, or a line of the reference's tests that starts a test. */
function checkFrom(checkout, scenario) {
  if (/^design 00\d\d$/.test(scenario.from)) return;
  const match = /^(page-[a-z-]+\.test\.js):(\d+)$/.exec(scenario.from);
  assert.ok(match, `${scenario.id}: from ${scenario.from}`);
  const lines = fs.readFileSync(path.join(checkout, 'src/main/page', match[1]), 'utf8').split('\n');
  assert.match(lines[Number(match[2]) - 1] ?? '', /^\s*test\(/, `${scenario.id}: ${scenario.from} starts no test`);
}

const FORMAT = Object.freeze({
  scenario: '`id`; `from`, the reference test it mirrors (src/main/page/<file>:<line>) or the design; `step`, the APR-5 PR that replays it; `world`, the documents (the requester first), each window\'s selected chain (null: none, so Gnosis), the Identity & Wallet switch (`enabled`), the vault\'s lock, Agent custody at the first read, the active account, and `wallets` where the scenario changes the top-level list; `grants`, dapp-permissions.json before the first request and after the last, as the reference store wrote it; then `requests`, run in order on the same world.',
  request: '`method`, `params` (absent: none given), `effects` in order, `result` (the dispatcher\'s), `keyless` (what a name-revalidated method registered to answer once the name no longer holds), `answer` (what main delivers: `{ gone: true }` when the document has gone), and `after`, the events main sends once it has answered.',
  effect: '`effect`, `args`, and `answer` (absent for none) or `throws` (`code`, `message`, `data`). `chain.request`: a read through the core, with `origin` the routing hint (absent for transaction-service.js\'s estimate); `chain.fee_quote`; `name.check`: a DNS name over IPNS resolved again, true while it answers the document\'s IPNS key (false ends the binding); `prompt`: `{ kind, view }`, with `refused`, the picks the prompt refused while it stayed open, and the decision (`{ approve, choices }`, `{ closed }`, or `{ error }` for a busy window); `token.issue` and `token.spend` (tokens named in the order minted); `custody`; `core.typed_data_view` (the core\'s view, scripted as approvals.json\'s rules script it; the hash is EIP-712\'s); `sign.message` and `sign.typed_data` (the signature of the account\'s test key, or the device\'s failure); `fees.check` and `fees.at_approval` (scripted verdicts); `send.paused`, `send.turn`, `send.waiting` (D12); `send.sign` (the prepared transaction, without a nonce), `send.broadcast` (its hash); `grant.write`; `chain.select`; `agent.request`; `event` (`to` a document\'s id); and `world`, a change the scenario makes while a prompt is open (`navigated`, `grant-revoked`, `signing-rule-off`, `wallet-removed:<index>`, `vault-unlocked`, `custody-entered`).',
});

async function buildEip1193(checkout, mainCheckout, meta) {
  const ref = loadReference(checkout, mainCheckout);
  const fixtures = walletsOf(ref.ethers);
  const account = fixtures.wallets[0].address;
  const { ETHEREUM_PAGE_METHODS, ETHEREUM_RPC_READS = ref.methods.ETHEREUM_RPC_READS } = ref.ethereum;
  const methods = [...ref.methods.METHODS.values()]
    .filter((row) => row.provider === 'ethereum')
    .map((row) => ({
      method: row.method,
      class: row.class,
      timeoutMs: row.timeoutMs,
      error: row.error,
      dispatched: ETHEREUM_PAGE_METHODS.includes(row.method),
    }));
  assert.deepEqual(methods.filter((row) => row.dispatched).map((row) => row.method).sort(), [...ETHEREUM_PAGE_METHODS].sort(),
    'STOP: a dispatched method has no row');
  const specs = [
    ...readScenarios(ETHEREUM_RPC_READS, account),
    ...connectScenarios(),
    ...signingScenarios(account),
    ...sendScenarios(),
    ...nameScenarios(),
  ];
  const ids = new Set();
  const scenarios = [];
  const realNow = Date.now;
  const consoleWas = { ...console };
  Date.now = () => T;
  for (const name of ['log', 'info', 'warn', 'error', 'debug']) console[name] = () => {};
  try {
    for (const spec of specs) {
      assert.ok(!ids.has(spec.id), `duplicate scenario ${spec.id}`);
      ids.add(spec.id);
      checkFrom(checkout, spec);
      scenarios.push(await runScenario(ref, fixtures, spec));
    }
  } finally {
    Date.now = realNow;
    Object.assign(console, consoleWas);
    ref.chainData.current = null;
  }
  return {
    meta,
    format: FORMAT,
    now: T,
    wallets: fixtures.wallets,
    networks: NETWORKS,
    available: AVAILABLE,
    methods,
    scenarios,
  };
}

module.exports = { buildEip1193 };
