'use strict';

// Design 0012's tokens (step APR-1), and its grant files (APR-2, in
// approval-stores.js), from the approvals reference's own
// src/main/wallet/signing-confirmation.js: freedom-browser's
// integration/rust-core at APPROVALS_REFERENCE_COMMIT (generate.js), which
// has SEC-1's eleventh kind (#1016) and 0011's page tokens (PRQ-5a). The
// module requires only Node's crypto and src/shared/origin-utils.js, which
// requires nothing, so no package of the reference's is read and nothing is
// stubbed.
//
// What the reference decides, and the generator records:
// - `bindings`: for each case, `bindingFor`'s facts, or its error;
// - `pairs`: whether a token minted for one request spends for another
//   (`alike`) or is refused (`apart`), asked of the reference itself: a
//   fresh module, `issueConfirmation` (or main's page issuer,
//   `issuePageConfirmation`, for a case with a page) for the first, then
//   `consumeConfirmation` (or `consumePageConfirmation`) for the second, and
//   the same the other way round;
// - `runs`: issue, consume, discard and count, in order, under `_setNow`,
//   with each outcome.
//
// What the design adds, and the generator writes beside each case:
// - `core`: the request as the core takes it (fc-approval's `Request`:
//   0012, "Tokens": "its own parse of the sign.* parameters"), from the
//   case's own payload by `coreForm` below: names as the core spells them,
//   a JS safe integer quantity as its decimal string, a message's text as
//   its UTF-8 bytes in hex (as main normalizes it), a typed-data text as the
//   text the core parses, a Safe's address beside its index (and a Safe
//   message's chain, which main reads from the Safe's record), and everything
//   else as the payload has it, so a value the core's parse refuses stays
//   refused.
//   `null` where the reference's input has no form in the core's (a dApp
//   send's site is its page there, not a payload field).
// - `deviation`, on a case or a pair, and the core's expected answer
//   (`expect` on a case, `core` on a pair or a run's step), from 0012's
//   Deviations table: `token-strict` (the reference binds what the core's
//   parse refuses), `token-clock`, `token-page` (the core binds a page's
//   frame and navigation, which the reference doesn't), `token-typed-parse`
//   (typed data bound parsed, with its view) and `token-message-bytes` (a
//   message bound as its bytes: `hello` and its hex in either case share a
//   token, as they share the signature; the reference binds each text).

const assert = require('node:assert/strict');
const path = require('node:path');
const { buildStores, STORES_FORMAT, buildRollback, ROLLBACK_FORMAT } = require('./approval-stores');
const { createRequire } = require('node:module');

const BACKSLASH = String.fromCharCode(92);
// The clock every pair runs at, and most runs start from.
const T0 = 1_000_000;
const SITE = 'https://app.example';
const OTHER_SITE = 'https://other.example';
const HANDLE = 'a1'.repeat(32);
const OTHER_HANDLE = 'b2'.repeat(32);
// The EIP-712 hash main hands the reference's issuer for typed data. The
// reference binds the payload, not this hash; the core computes its own.
const TYPED_HASH = '0x' + 'ab'.repeat(32);
// The Safe's address the core binds beside its index (0012: "the Safe and
// its address"); the reference binds the index alone.
const SAFE_ADDRESSES = { 7: '0x' + '5a'.repeat(19) + '07', 8: '0x' + '5a'.repeat(19) + '08' };
// A Safe message's chain, which the core binds beside the Safe's index
// (0012: "the Safe's index, address and chain"); the reference reads it
// from the Safe's record.
const SAFE_CHAIN = '100';

const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const OTHER_TO = '0x' + '33'.repeat(20);
// USDC with its checksum broken: one letter's case flipped.
const BAD_CHECKSUM = '0x833589fcD6eDb6E08f4c7C32D4f71b54bdA02913';

const TX = Object.freeze({
  chainId: 100,
  to: USDC,
  value: '1000000000000000',
  data: '0x095ea7b3' + '00'.repeat(64),
  gasLimit: '21000',
  maxFeePerGas: '2000000000',
  maxPriorityFeePerGas: '1000000000',
});

const MAIL = Object.freeze({
  domain: { name: 'Ether Mail', version: '1', chainId: 1, verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC' },
  types: {
    Person: [{ name: 'name', type: 'string' }, { name: 'wallet', type: 'address' }],
    Mail: [{ name: 'from', type: 'Person' }, { name: 'to', type: 'Person' }, { name: 'contents', type: 'string' }],
  },
  message: {
    from: { name: 'Cow', wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826' },
    to: { name: 'Bob', wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB' },
    contents: 'Hello, Bob!',
  },
});

const ACCEPT = Object.freeze({
  scheme: 'exact',
  network: 'eip155:8453',
  amount: '10000',
  asset: USDC,
  payTo: '0x209693Bc6afc0C5328bA36FaF03C514EF312287C',
  maxTimeoutSeconds: 60,
  extra: { name: 'USD Coin', version: '2' },
});
const PAYMENT = Object.freeze({
  webContentsId: 42,
  detectionId: 'req-9100',
  url: 'https://api.example/article',
  acceptIndex: 0,
  accept: ACCEPT,
  grant: null,
});

const INTENT = '7b0c6c1e-0c62-4a6e-9a49-0d6a3f6d1a07';
const SENDER = '0x' + 'AB'.repeat(20);
const HASH_A = '0x' + 'A1'.repeat(32);
const HASH_B = '0x' + 'b2'.repeat(32);

const clone = (value) => JSON.parse(JSON.stringify(value));

/** Every object's keys in reverse order, but `types`' own (its type names'
 * order is the one thing the view keeps). */
function reversedKeys(value, keepOrder = false) {
  if (Array.isArray(value)) return value.map((item) => reversedKeys(item));
  if (value === null || typeof value !== 'object') return value;
  const keys = Object.keys(value);
  const out = {};
  for (const key of keepOrder ? keys : keys.reverse()) out[key] = reversedKeys(value[key], key === 'types');
  return out;
}

function withTypesReordered(typed) {
  return { ...clone(typed), types: { Mail: clone(typed.types.Mail), Person: clone(typed.types.Person) } };
}

// ---- the core's form of a case (fc-approval's `Request`) ---------------

const TX_NAMES = [
  ['chainId', 'chain_id'], ['nonce', 'nonce'], ['gasLimit', 'gas_limit'], ['to', 'to'], ['value', 'value'],
  ['data', 'data'], ['gasPrice', 'gas_price'], ['maxFeePerGas', 'max_fee_per_gas'],
  ['maxPriorityFeePerGas', 'max_priority_fee_per_gas'],
];

/** A quantity as main writes one: a JS safe integer as its decimal string,
 * anything else as it is. */
function quantity(value) {
  return typeof value === 'number' && Number.isSafeInteger(value) ? String(value) : value;
}

/** `sign.transaction`'s `tx` for a reference payload: its type from the
 * fee fields it names (2 with EIP-1559 fees, 0 with a gas price), each
 * field renamed, quantities as main writes them. `bound` keeps the nonce. */
function coreTx(tx, bound) {
  const out = {};
  if (tx.maxFeePerGas !== undefined || tx.maxPriorityFeePerGas !== undefined) out.type = 2;
  else if (tx.gasPrice !== undefined) out.type = 0;
  for (const [from, to] of TX_NAMES) {
    if (from === 'nonce' && !bound) continue;
    if (tx[from] === undefined) continue;
    out[to] = ['to', 'data'].includes(from) ? tx[from] : quantity(tx[from]);
  }
  return out;
}

function corePage(c) {
  if (!c.page) return null;
  return { origin: c.page.key, frame: c.frame ?? 1, navigation: c.navigation ?? 1, handle: c.page.handle };
}

/** A message's bytes as main normalizes them (signing-utils.js,
 * `normalizeMessage` and `messageToBytes`): `0x` hex as it is, any other
 * non-empty text as its UTF-8. */
function coreMessage(message) {
  // An empty text is no message (the reference's "Message is required"),
  // not an empty one: it stays empty, and the core's parse refuses it.
  if (typeof message !== 'string' || message === '') return message;
  return message.startsWith('0x') ? message : '0x' + Buffer.from(message, 'utf8').toString('hex');
}

function coreForm(c) {
  if (c.core !== undefined) return c.core;
  const p = c.payload;
  const account = ['intent-resend', 'intent-replace', 'intent-close'].includes(c.kind) ? null : c.account;
  const page = corePage(c);
  const form = (payload) => ({ account, payload, page });
  if (p === null || p === undefined) return form({});
  switch (c.kind) {
    case 'wallet-send':
    case 'executor-send':
    case 'dapp-send':
      return form({ tx: coreTx(p, false) });
    case 'sign-message':
      return form({ message: coreMessage(p) });
    case 'sign-typed-data': {
      if (typeof p === 'string') {
        // Parsed by the core from its own text.
        try {
          JSON.parse(p);
        } catch {
          return form({ typed_data: p });
        }
        return { account, payload_text: `{"typed_data":${p}}`, page };
      }
      const payload = { typed_data: { domain: p.domain, types: p.types, message: p.message } };
      if (Object.prototype.hasOwnProperty.call(p, 'primaryType')) payload.primary_type = p.primaryType;
      return form(payload);
    }
    case 'safe-send':
      return form({
        safe: SAFE_ADDRESSES[c.account],
        chain_id: quantity(p.chainId),
        tx: p.tx && typeof p.tx === 'object' ? { to: p.tx.to, value: quantity(p.tx.value), data: p.tx.data } : p.tx,
      });
    case 'safe-message':
      return form({ safe: SAFE_ADDRESSES[c.account], chain_id: SAFE_CHAIN, method: p.method, params: p.params });
    case 'intent-resend':
      return form({ intent_id: p.intentId, chain_id: quantity(p.chainId), sender: p.sender, nonce: quantity(p.nonce), hash: p.hash });
    case 'intent-replace':
      return form({ intent_id: p.intentId, sender: p.sender, tx: coreTx(p, true) });
    case 'intent-close':
      return form({ intent_id: p.intentId, chain_id: quantity(p.chainId), sender: p.sender, nonce: quantity(p.nonce), hashes: p.hashes });
    case 'x402-payment': {
      const grant = p.grant && typeof p.grant === 'object' && !Array.isArray(p.grant)
        ? { cap_amount: p.grant.capAmount, window_seconds: p.grant.windowSeconds }
        : p.grant;
      return form({
        detection: { tab: p.webContentsId, id: p.detectionId, url: p.url },
        accept_index: p.acceptIndex,
        accept: p.accept,
        ...(grant === undefined ? {} : { grant }),
      });
    }
    default:
      throw new Error(`no core form for ${c.kind}`);
  }
}

// ---- the cases ------------------------------------------------------------

const cases = [];
const pairs = [];

function addCase(c) {
  assert.ok(!cases.some((other) => other.id === c.id), c.id);
  cases.push(c);
  return c;
}

/** A case and its pair with `base`. `deviation` is the pair's. */
function variant(base, suffix, changes, pairDeviation) {
  const c = addCase({ ...base, deviation: undefined, ...changes, id: `${base.id.split('/')[0]}/${suffix}` });
  pairs.push({ a: base.id, b: c.id, deviation: pairDeviation });
  return c;
}

const PAGE = { handle: HANDLE, key: SITE };

/** The page variants of a page case: another handle and another site,
 * which the reference binds (0011), and another frame and navigation,
 * which only the core does (`token-page`). */
function pageVariants(base, siteInPayload) {
  variant(base, 'handle', { page: { handle: OTHER_HANDLE, key: SITE } });
  variant(base, 'site', {
    page: { handle: HANDLE, key: OTHER_SITE },
    ...(siteInPayload ? { payload: { ...base.payload, origin: OTHER_SITE } } : {}),
  });
  variant(base, 'frame', { frame: 2 }, 'token-page');
  variant(base, 'navigation', { navigation: 2 }, 'token-page');
}

/** A transaction kind's cases: every fact the reference binds changed in
 * turn, its equivalent spellings, what only the core refuses, and what both
 * refuse. */
function txCases(kind, account, extra = {}) {
  const page = extra.page;
  const tx = { ...TX, ...(extra.payload || {}) };
  const base = addCase({ id: `${kind}/base`, kind, account, payload: tx, page });
  const p = (changes) => ({ payload: { ...tx, ...changes } });
  // Spelled another way: the reference binds them alike, and so does the
  // core's parse.
  variant(base, 'to-lowercase', p({ to: TX.to.toLowerCase() }));
  variant(base, 'to-uppercase', p({ to: '0x' + TX.to.slice(2).toUpperCase() }));
  variant(base, 'value-hex', p({ value: '0x' + BigInt(TX.value).toString(16) }));
  variant(base, 'data-uppercase', p({ data: '0x' + TX.data.slice(2).toUpperCase() }));
  variant(base, 'gas-limit-number', p({ gasLimit: 21000 }));
  variant(base, 'chain-string', p({ chainId: '100' }));
  variant(base, 'chain-hex', p({ chainId: '0x64' }));
  // Each fact changed.
  variant(base, 'account', { account: account + 1 });
  variant(base, 'chain', p({ chainId: 1 }));
  variant(base, 'to', p({ to: OTHER_TO }));
  variant(base, 'creation', p({ to: null }));
  variant(base, 'value', p({ value: '1000000000000001' }));
  variant(base, 'data', p({ data: '0x01' }));
  variant(base, 'gas-limit', p({ gasLimit: '21001' }));
  variant(base, 'max-fee', p({ maxFeePerGas: '2000000001' }));
  variant(base, 'priority-fee', p({ maxPriorityFeePerGas: '1000000001' }));
  const legacy = { ...tx };
  delete legacy.maxFeePerGas;
  delete legacy.maxPriorityFeePerGas;
  variant(base, 'legacy', { payload: { ...legacy, gasPrice: '2000000000' } });
  // The reference binds them; the core's parse refuses them (token-strict).
  const strict = (suffix, payload) => addCase({ ...base, id: `${kind}/${suffix}`, payload, deviation: 'token-strict' });
  strict('chain-true', { ...tx, chainId: true });
  strict('chain-space', { ...tx, chainId: ' 100' });
  strict('value-space', { ...tx, value: ' 1000000000000000' });
  strict('value-octal', { ...tx, value: '0o7' });
  strict('to-bad-checksum', { ...tx, to: BAD_CHECKSUM });
  strict('to-short', { ...tx, to: '0x1234' });
  strict('data-odd', { ...tx, data: '0x123' });
  const noGas = { ...tx };
  delete noGas.gasLimit;
  strict('no-gas-limit', noGas);
  const noFees = { ...legacy };
  strict('no-fees', noFees);
  // Both refuse.
  const refused = (suffix, changes) => addCase({ ...base, id: `${kind}/${suffix}`, ...changes });
  refused('chain-zero', p({ chainId: 0 }));
  refused('chain-negative', p({ chainId: -1 }));
  refused('chain-unsafe', p({ chainId: 2 ** 53 }));
  refused('value-negative', p({ value: '-1' }));
  refused('value-fraction', p({ value: 1.5 }));
  refused('data-not-hex', p({ data: '0xzz' }));
  refused('to-number', p({ to: 123 }));
  refused('account-negative', { account: -1 });
  refused('account-fraction', { account: 1.5 });
  refused('no-transaction', { payload: null });
  return base;
}

// wallet-send and executor-send: the account and the transaction.
const walletSend = txCases('wallet-send', 0);
const executorSend = txCases('executor-send', 2);
pairs.push({ a: walletSend.id, b: addCase({ ...walletSend, id: 'executor-send/as-wallet-send-account', kind: 'executor-send' }).id });

// dapp-send: the site's transaction, for its page and handle.
const dappSend = txCases('dapp-send', 3, { page: PAGE, payload: { origin: SITE } });
pageVariants(dappSend, true);
// The reference refuses a dApp send with no site in its payload; the core's
// site is the page, so the payload has no such field.
addCase({ ...dappSend, id: 'dapp-send/no-site', payload: { ...TX }, core: null });
pairs.push({ a: walletSend.id, b: addCase({ ...walletSend, id: 'wallet-send/as-dapp-send', kind: 'dapp-send', account: 3, payload: { ...TX, origin: SITE }, page: PAGE }).id });

// sign-message: the account and the bytes, for its page and handle.
const message = addCase({ id: 'sign-message/base', kind: 'sign-message', account: 0, payload: '0x68656c6c6f', page: PAGE });
variant(message, 'text', { payload: 'hello' }, 'token-message-bytes');
variant(message, 'hex-uppercase', { payload: '0x68656C6C6F' }, 'token-message-bytes');
variant(message, 'other', { payload: '0x68656c6c70' });
variant(message, 'account', { account: 1 });
pageVariants(message, false);
addCase({ ...message, id: 'sign-message/empty-bytes', payload: '0x' });
addCase({ ...message, id: 'sign-message/raw-hash', payload: '0x' + '42'.repeat(32) });
addCase({ ...message, id: 'sign-message/hex-odd', payload: '0x6', deviation: 'token-strict' });
addCase({ ...message, id: 'sign-message/object', payload: { message: 'hello' }, deviation: 'token-strict' });
addCase({ ...message, id: 'sign-message/empty', payload: '' });
addCase({ ...message, id: 'sign-message/null', payload: null });

// sign-typed-data: the account, the hash, the request and its view.
const typed = addCase({ id: 'sign-typed-data/base', kind: 'sign-typed-data', account: 0, payload: { ...clone(MAIL), primaryType: 'Mail' }, page: PAGE });
variant(typed, 'key-order', { payload: reversedKeys({ ...clone(MAIL), primaryType: 'Mail' }) });
variant(typed, 'contents', { payload: { ...clone(MAIL), primaryType: 'Mail', message: { ...clone(MAIL.message), contents: 'Hello, Alice!' } } });
variant(typed, 'domain-chain', { payload: { ...clone(MAIL), primaryType: 'Mail', domain: { ...MAIL.domain, chainId: 100 } } });
variant(typed, 'primary-type', { payload: { ...clone(MAIL), primaryType: 'Person' } });
variant(typed, 'no-primary-type', { payload: clone(MAIL) });
// The same EIP-712 hash: a field the types don't declare, at the top of
// the message (its view lists it) and in a nested struct (its view doesn't).
variant(typed, 'ignored-top', { payload: { ...clone(MAIL), primaryType: 'Mail', message: { ...clone(MAIL.message), note: 'unsigned' } }, sameHash: true });
variant(typed, 'ignored-nested', {
  payload: { ...clone(MAIL), primaryType: 'Mail', message: { ...clone(MAIL.message), from: { ...MAIL.message.from, note: 'unsigned' } } },
  sameHash: true,
});
variant(typed, 'account', { account: 1 });
pageVariants(typed, false);
// One request in other texts (token-typed-parse), each parsed by the core
// from its own text. The reference binds each text apart.
const TEXT = JSON.stringify(MAIL);
const text = addCase({ ...typed, id: 'sign-typed-data/text', payload: TEXT });
variant(text, 'text-spacing', { payload: JSON.stringify(MAIL, null, 2).replace(/\n {2}"message"/, '\n\t"message"') }, 'token-typed-parse');
variant(text, 'text-key-order', { payload: JSON.stringify(reversedKeys(clone(MAIL))) }, 'token-typed-parse');
const ESCAPED = TEXT.replace('"Bob"', `"${BACKSLASH}u0042ob"`).replace('"Hello, Bob!"', `"Hello,${BACKSLASH}u0020Bob${BACKSLASH}u0021"`);
assert.notEqual(ESCAPED, TEXT);
assert.deepEqual(JSON.parse(ESCAPED), JSON.parse(TEXT));
variant(text, 'text-escapes', { payload: ESCAPED }, 'token-typed-parse');
// The type names in another order: the same hash, another view.
variant(text, 'text-type-order', { payload: JSON.stringify(withTypesReordered(MAIL)), sameHash: true });
// The text and the object it parses to: one request to the core.
const object = variant(text, 'object', { payload: clone(MAIL) }, 'token-typed-parse');
// The same two as objects: alike to the reference, which sorts keys, two
// views to the core.
variant(object, 'object-type-order', { payload: withTypesReordered(MAIL), sameHash: true }, 'token-typed-parse');
addCase({ ...typed, id: 'sign-typed-data/not-json', payload: 'hello', deviation: 'token-strict' });
addCase({ ...typed, id: 'sign-typed-data/not-typed-data', payload: { hello: 'world' }, deviation: 'token-strict' });
addCase({ ...typed, id: 'sign-typed-data/empty', payload: '' });
addCase({ ...typed, id: 'sign-typed-data/null', payload: null });
pairs.push({ a: message.id, b: addCase({ ...message, id: 'sign-message/as-typed-data', kind: 'sign-typed-data', payload: TEXT }).id });

// safe-send: a wallet's (no site) and a site's (its page and handle).
const SAFE_TX = { tx: { to: USDC, value: '5', data: '0x' }, chainId: 100 };
const safeWallet = addCase({ id: 'safe-send/wallet', kind: 'safe-send', account: 7, payload: SAFE_TX });
const safeSite = addCase({ id: 'safe-send/site', kind: 'safe-send', account: 7, payload: { ...SAFE_TX, origin: SITE }, page: PAGE });
pairs.push({ a: safeWallet.id, b: safeSite.id });
for (const base of [safeWallet, safeSite]) {
  const s = base.id.split('/')[1];
  const tx = (changes) => ({ payload: { ...base.payload, tx: { ...SAFE_TX.tx, ...changes } } });
  const one = (suffix, changes, deviation) => {
    const c = addCase({ ...base, ...changes, id: `safe-send/${s}-${suffix}` });
    pairs.push({ a: base.id, b: c.id, deviation });
    return c;
  };
  one('to-lowercase', tx({ to: USDC.toLowerCase() }));
  one('value-hex', tx({ value: '0x5' }));
  one('account', { account: 8 });
  one('chain', { payload: { ...base.payload, chainId: 1 } });
  one('to', tx({ to: OTHER_TO }));
  one('value', tx({ value: '6' }));
  one('data', tx({ data: '0x01' }));
  addCase({ ...base, id: `safe-send/${s}-no-value`, ...tx({ value: undefined }), deviation: 'token-strict' });
  addCase({ ...base, id: `safe-send/${s}-no-to`, ...tx({ to: undefined }), deviation: 'token-strict' });
  addCase({ ...base, id: `safe-send/${s}-chain-zero`, payload: { ...base.payload, chainId: 0 } });
  addCase({ ...base, id: `safe-send/${s}-no-transaction`, payload: { chainId: 100, origin: base.payload.origin } });
}
for (const [suffix, changes, deviation] of [
  ['site-handle', { page: { handle: OTHER_HANDLE, key: SITE } }],
  ['site-site', { page: { handle: HANDLE, key: OTHER_SITE }, payload: { ...SAFE_TX, origin: OTHER_SITE } }],
  ['site-frame', { frame: 2 }, 'token-page'],
  ['site-navigation', { navigation: 2 }, 'token-page'],
]) {
  pairs.push({ a: safeSite.id, b: addCase({ ...safeSite, ...changes, id: `safe-send/${suffix}` }).id, deviation });
}

// safe-message: the Safe, the method and its params, for a page.
const safeMessage = addCase({ id: 'safe-message/base', kind: 'safe-message', account: 7, payload: { method: 'personal_sign', params: ['0xdead', SAFE_ADDRESSES[7]] }, page: PAGE });
variant(safeMessage, 'params', { payload: { method: 'personal_sign', params: ['0xbeef', SAFE_ADDRESSES[7]] } });
variant(safeMessage, 'method', { payload: { method: 'eth_sign', params: ['0xdead', SAFE_ADDRESSES[7]] } });
variant(safeMessage, 'account', { account: 8 });
pageVariants(safeMessage, false);
const safeTyped = addCase({ ...safeMessage, id: 'safe-message/typed-data', payload: { method: 'eth_signTypedData_v4', params: [SAFE_ADDRESSES[7], { ...clone(MAIL), primaryType: 'Mail' }] } });
variant(safeTyped, 'typed-data-key-order', { payload: { method: 'eth_signTypedData_v4', params: [SAFE_ADDRESSES[7], reversedKeys({ ...clone(MAIL), primaryType: 'Mail' })] } });
addCase({ ...safeMessage, id: 'safe-message/method-not-text', payload: { method: 5, params: [] } });
addCase({ ...safeMessage, id: 'safe-message/params-not-list', payload: { method: 'personal_sign', params: '0xdead' } });

// intent-resend, intent-replace, intent-close: from main's record.
const RESEND = { intentId: INTENT, chainId: 100, sender: SENDER, nonce: 7, hash: HASH_A };
const resend = addCase({ id: 'intent-resend/base', kind: 'intent-resend', account: null, payload: RESEND });
for (const [suffix, changes] of [
  ['sender-lowercase', { sender: SENDER.toLowerCase() }],
  ['hash-lowercase', { hash: HASH_A.toLowerCase() }],
  ['chain-string', { chainId: '100' }],
  ['intent', { intentId: INTENT.replace(/7$/, '8') }],
  ['chain', { chainId: 1 }],
  ['sender', { sender: '0x' + 'cd'.repeat(20) }],
  ['nonce', { nonce: 8 }],
  ['hash', { hash: HASH_B }],
]) variant(resend, suffix, { payload: { ...RESEND, ...changes } });
addCase({ ...resend, id: 'intent-resend/sender-not-address', payload: { ...RESEND, sender: 'not-an-address' }, deviation: 'token-strict' });
for (const [suffix, changes] of [
  ['intent-short', { intentId: 'short' }],
  ['intent-characters', { intentId: 'not an intent id' }],
  ['nonce-negative', { nonce: -1 }],
  ['nonce-fraction', { nonce: 1.5 }],
  ['hash-short', { hash: '0x12' }],
  ['chain-zero', { chainId: 0 }],
  ['no-sender', { sender: undefined }],
]) addCase({ ...resend, id: `intent-resend/${suffix}`, payload: { ...RESEND, ...changes } });

const REPLACE = { intentId: INTENT, sender: SENDER, nonce: 7, ...TX };
const replace = addCase({ id: 'intent-replace/base', kind: 'intent-replace', account: null, payload: REPLACE });
for (const [suffix, changes] of [
  ['sender-lowercase', { sender: SENDER.toLowerCase() }],
  ['intent', { intentId: INTENT.replace(/7$/, '8') }],
  ['sender', { sender: '0x' + 'cd'.repeat(20) }],
  ['nonce', { nonce: 8 }],
  ['chain', { chainId: 1 }],
  ['to', { to: OTHER_TO }],
  ['value', { value: '1000000000000001' }],
  ['data', { data: '0x01' }],
  ['gas-limit', { gasLimit: '21001' }],
  ['max-fee', { maxFeePerGas: '2000000001' }],
  ['priority-fee', { maxPriorityFeePerGas: '1000000001' }],
]) variant(replace, suffix, { payload: { ...REPLACE, ...changes } });
const replaceLegacy = { ...REPLACE, gasPrice: '2000000000' };
delete replaceLegacy.maxFeePerGas;
delete replaceLegacy.maxPriorityFeePerGas;
variant(replace, 'legacy', { payload: replaceLegacy });
addCase({ ...replace, id: 'intent-replace/nonce-negative', payload: { ...REPLACE, nonce: -1 } });
addCase({ ...replace, id: 'intent-replace/intent-short', payload: { ...REPLACE, intentId: 'short' } });

const CLOSE = { intentId: INTENT, chainId: 100, sender: SENDER, nonce: 7, hashes: [HASH_A, HASH_B] };
const close = addCase({ id: 'intent-close/base', kind: 'intent-close', account: null, payload: CLOSE });
variant(close, 'lowercase', { payload: { ...CLOSE, sender: SENDER.toLowerCase(), hashes: CLOSE.hashes.map((h) => h.toLowerCase()) } });
for (const [suffix, changes] of [
  ['one-hash', { hashes: [HASH_A] }],
  ['hashes-reversed', { hashes: [HASH_B, HASH_A] }],
  ['hash-added', { hashes: [HASH_A, HASH_B, '0x' + 'c3'.repeat(32)] }],
  ['nonce', { nonce: 8 }],
  ['chain', { chainId: 1 }],
  ['intent', { intentId: INTENT.replace(/7$/, '8') }],
  ['sender', { sender: '0x' + 'cd'.repeat(20) }],
]) variant(close, suffix, { payload: { ...CLOSE, ...changes } });
addCase({ ...close, id: 'intent-close/most-hashes', payload: { ...CLOSE, hashes: Array(64).fill(HASH_A) } });
for (const [suffix, hashes] of [
  ['no-hashes', []],
  ['hashes-missing', undefined],
  ['hash-short', ['0x12']],
  ['too-many-hashes', Array(65).fill(HASH_A)],
]) addCase({ ...close, id: `intent-close/${suffix}`, payload: { ...CLOSE, hashes } });
pairs.push({ a: addCase({ ...resend, id: 'intent-resend/close-intent', payload: { ...CLOSE, hash: HASH_B } }).id, b: close.id });

// x402-payment: the account, the detection, the entry and the grant.
const payment = addCase({ id: 'x402-payment/base', kind: 'x402-payment', account: 0, payload: PAYMENT });
const pay = (changes) => ({ payload: { ...PAYMENT, ...changes } });
const entry = (changes) => pay({ accept: { ...ACCEPT, ...changes } });
const GRANT = { capAmount: '100000', windowSeconds: 3600 };
variant(payment, 'entry-key-order', pay({ accept: reversedKeys(ACCEPT) }));
variant(payment, 'account', { account: 1 });
variant(payment, 'tab', pay({ webContentsId: 43 }));
variant(payment, 'detection', pay({ detectionId: 'req-9101' }));
variant(payment, 'url', pay({ url: 'https://api.example/other' }));
variant(payment, 'entry-index', pay({ acceptIndex: 1 }));
variant(payment, 'scheme', entry({ scheme: 'upto' }));
variant(payment, 'network', entry({ network: 'eip155:1' }));
variant(payment, 'asset-case', entry({ asset: USDC.toLowerCase() }));
variant(payment, 'amount', entry({ amount: '10001' }));
variant(payment, 'amount-hex', entry({ amount: '0x2710' }));
variant(payment, 'pay-to', entry({ payTo: OTHER_TO }));
variant(payment, 'extra', entry({ extra: { name: 'USD Coin', version: '1' } }));
variant(payment, 'timeout', entry({ maxTimeoutSeconds: 61 }));
const granted = variant(payment, 'grant', pay({ grant: GRANT }));
variant(granted, 'grant-cap', pay({ grant: { ...GRANT, capAmount: '100001' } }));
variant(granted, 'grant-window', pay({ grant: { ...GRANT, windowSeconds: 3601 } }));
const v1 = { ...ACCEPT, maxAmountRequired: ACCEPT.amount };
delete v1.amount;
variant(payment, 'v1-entry', pay({ accept: v1 }));
addCase({ ...payment, id: 'x402-payment/grant-cap-number', ...pay({ grant: { ...GRANT, capAmount: 100000 } }), deviation: 'token-strict' });
addCase({ ...payment, id: 'x402-payment/grant-empty', ...pay({ grant: {} }), deviation: 'token-strict' });
addCase({ ...payment, id: 'x402-payment/amount-space', ...entry({ amount: ' 10000' }), deviation: 'token-strict' });
for (const [suffix, changes] of [
  ['no-entry', pay({ accept: undefined })],
  ['no-amount', entry({ amount: undefined })],
  ['amount-negative', entry({ amount: '-1' })],
  ['detection-characters', pay({ detectionId: 'req 9100' })],
  ['url-empty', pay({ url: '' })],
  ['tab-negative', pay({ webContentsId: -1 })],
  ['grant-not-object', pay({ grant: 'always' })],
  ['scheme-empty', entry({ scheme: '' })],
  ['account-negative', { account: -1 }],
]) addCase({ ...payment, id: `x402-payment/${suffix}`, ...changes });
// Not a payment's token, nor a payment's a send's.
pairs.push({ a: walletSend.id, b: payment.id });

// ---- the reference's decisions ---------------------------------------------

function loadReference(checkout) {
  const referenceRequire = createRequire(path.join(checkout, 'package.json'));
  return referenceRequire('./src/main/wallet/signing-confirmation.js');
}

function bound(kind) {
  return kind === 'sign-typed-data' ? { hash: TYPED_HASH } : undefined;
}

function issueFor(sc, c) {
  return c.page
    ? sc.issuePageConfirmation(c.kind, c.account, c.payload, c.page, bound(c.kind))
    : sc.issueConfirmation(c.kind, c.account, c.payload, bound(c.kind));
}

function consumeFor(sc, token, c, route = c.page ? 'page' : 'wallet') {
  return route === 'page'
    ? sc.consumePageConfirmation(token, c.kind, c.account, c.payload, c.page)
    : sc.consumeConfirmation(token, c.kind, c.account, c.payload);
}

/** Whether a token minted for `a` spends for `b`, in a fresh store. */
function decide(sc, a, b) {
  sc._reset();
  sc._setNow(() => T0);
  const { token } = issueFor(sc, a);
  try {
    consumeFor(sc, token, b);
    return 'alike';
  } catch (error) {
    assert.equal(error.code, sc.NOT_CONFIRMED, `${a.id} -> ${b.id}: ${error.message}`);
    return 'apart';
  } finally {
    sc._reset();
  }
}

const jsError = (error) => ({ error: error.message });

function bindingOf(sc, c) {
  try {
    const facts = sc.bindingFor(c.kind, c.account, c.payload);
    // A page case also mints through main's issuer: its kind is a page
    // kind, and its page is well formed.
    if (c.page) {
      sc._reset();
      issueFor(sc, c);
      sc._reset();
    }
    return { facts };
  } catch (error) {
    return jsError(error);
  }
}

/** The keys in which two cases' reference bindings differ. */
function changed(a, b, ja, jb) {
  const keys = [];
  if (a.kind !== b.kind) keys.push('kind');
  for (const key of new Set([...Object.keys(ja.facts), ...Object.keys(jb.facts)])) {
    if (JSON.stringify(ja.facts[key]) !== JSON.stringify(jb.facts[key])) keys.push(key);
  }
  if (!!a.page !== !!b.page) keys.push('page');
  else if (a.page) {
    if (a.page.handle !== b.page.handle) keys.push('page.handle');
    if (a.page.key !== b.page.key) keys.push('page.key');
  }
  return keys;
}

/** The core's answer for a pair, from 0012's Deviations table. */
function coreAnswer(js, deviation) {
  switch (deviation) {
    case undefined:
      return js;
    case 'token-page':
      assert.equal(js, 'alike');
      return 'apart';
    case 'token-typed-parse':
    case 'token-message-bytes':
      return js === 'alike' ? 'apart' : 'alike';
    default:
      throw new Error(`unknown pair deviation ${deviation}`);
  }
}

// ---- the runs -----------------------------------------------------------------

const MINUTE = 60_000;
const RUNS = [
  {
    id: 'valid-just-before-two-minutes',
    ops: [
      { op: 'issue', at: T0, case: 'wallet-send/base', token: 'a' },
      { op: 'consume', at: T0 + 2 * MINUTE - 1, case: 'wallet-send/base', token: 'a' },
    ],
  },
  {
    id: 'expired-at-two-minutes-and-burnt',
    ops: [
      { op: 'issue', at: T0, case: 'wallet-send/base', token: 'a' },
      { op: 'consume', at: T0 + 2 * MINUTE, case: 'wallet-send/base', token: 'a' },
      { op: 'consume', at: T0, case: 'wallet-send/base', token: 'a' },
    ],
  },
  {
    id: 'spent-once',
    ops: [
      { op: 'issue', at: T0, case: 'dapp-send/base', token: 'a' },
      { op: 'consume', at: T0, case: 'dapp-send/base', token: 'a' },
      { op: 'consume', at: T0, case: 'dapp-send/base', token: 'a' },
    ],
  },
  {
    id: 'burnt-on-mismatch',
    ops: [
      { op: 'issue', at: T0, case: 'wallet-send/base', token: 'a' },
      { op: 'consume', at: T0, case: 'wallet-send/value', token: 'a' },
      { op: 'consume', at: T0, case: 'wallet-send/base', token: 'a' },
    ],
  },
  {
    id: 'burnt-on-wrong-kind',
    ops: [
      { op: 'issue', at: T0, case: 'wallet-send/base', token: 'a' },
      { op: 'consume', at: T0, case: 'executor-send/as-wallet-send-account', token: 'a' },
      { op: 'consume', at: T0, case: 'wallet-send/base', token: 'a' },
    ],
  },
  {
    id: 'burnt-on-a-malformed-request',
    ops: [
      { op: 'issue', at: T0, case: 'wallet-send/base', token: 'a' },
      { op: 'consume', at: T0, case: 'wallet-send/chain-zero', token: 'a' },
      { op: 'consume', at: T0, case: 'wallet-send/base', token: 'a' },
    ],
  },
  {
    id: 'page-token-burnt-for-another-handle',
    ops: [
      { op: 'issue', at: T0, case: 'sign-typed-data/base', token: 'a' },
      { op: 'consume', at: T0, case: 'sign-typed-data/handle', token: 'a' },
      { op: 'consume', at: T0, case: 'sign-typed-data/base', token: 'a' },
    ],
  },
  {
    id: 'page-token-refused-without-its-page',
    ops: [
      { op: 'issue', at: T0, case: 'dapp-send/base', token: 'a' },
      { op: 'consume', at: T0, case: 'dapp-send/base', route: 'wallet', token: 'a' },
      { op: 'consume', at: T0, case: 'dapp-send/base', token: 'a' },
    ],
  },
  {
    id: 'site-safe-send-refused-as-a-wallet-one',
    ops: [
      { op: 'issue', at: T0, case: 'safe-send/site', token: 'a' },
      { op: 'consume', at: T0, case: 'safe-send/site', route: 'wallet', token: 'a' },
    ],
  },
  {
    id: 'wallet-safe-send-refused-as-a-site-one',
    ops: [
      { op: 'issue', at: T0, case: 'safe-send/wallet', token: 'a' },
      { op: 'consume', at: T0, case: 'safe-send/site', token: 'a' },
    ],
  },
  {
    id: 'no-token',
    ops: [{ op: 'consume', at: T0, case: 'wallet-send/base', literal: '' }],
  },
  {
    id: 'unknown-token',
    ops: [
      { op: 'issue', at: T0, case: 'wallet-send/base', token: 'a' },
      { op: 'consume', at: T0, case: 'wallet-send/base', literal: 'f'.repeat(64) },
      { op: 'consume', at: T0, case: 'wallet-send/base', token: 'a' },
    ],
  },
  {
    id: 'discarded',
    ops: [
      { op: 'issue', at: T0, case: 'x402-payment/base', token: 'a' },
      { op: 'discard', token: 'a' },
      { op: 'consume', at: T0, case: 'x402-payment/base', token: 'a' },
    ],
  },
  {
    id: 'thirty-third-drops-the-oldest',
    ops: [
      ...Array.from({ length: 33 }, (_, i) => ({ op: 'issue', at: T0 + i, case: 'wallet-send/base', token: `t${i + 1}` })),
      { op: 'count' },
      { op: 'consume', at: T0 + 33, case: 'wallet-send/base', token: 't1' },
      ...Array.from({ length: 32 }, (_, i) => ({ op: 'consume', at: T0 + 33, case: 'wallet-send/base', token: `t${i + 2}` })),
      { op: 'count' },
    ],
  },
  {
    id: 'expired-pruned-before-the-oldest-is-dropped',
    ops: [
      ...Array.from({ length: 32 }, (_, i) => ({ op: 'issue', at: T0, case: 'wallet-send/base', token: `t${i + 1}` })),
      { op: 'issue', at: T0 + 2 * MINUTE - 1, case: 'wallet-send/base', token: 'live' },
      { op: 'count' },
      { op: 'issue', at: T0 + 2 * MINUTE, case: 'wallet-send/base', token: 'next' },
      { op: 'count' },
      { op: 'consume', at: T0 + 2 * MINUTE, case: 'wallet-send/base', token: 'live' },
      { op: 'consume', at: T0 + 2 * MINUTE, case: 'wallet-send/base', token: 'next' },
    ],
  },
  {
    // The wall clock set back an hour, a minute after the token was minted,
    // then two more minutes: today's token is still valid. The vault's
    // clock counts the three minutes (`vaultAt`), and the core's expires.
    id: 'wall-clock-set-back',
    deviation: 'token-clock',
    ops: [
      { op: 'issue', at: 10 * T0, vaultAt: 10 * T0, case: 'wallet-send/base', token: 'a' },
      { op: 'consume', at: 10 * T0 + MINUTE - 60 * MINUTE + 2 * MINUTE, vaultAt: 10 * T0 + 3 * MINUTE, case: 'wallet-send/base', token: 'a', core: { error: 'Signing was not confirmed: confirmation expired' } },
    ],
  },
];

function runAll(sc, byId) {
  return RUNS.map((run) => {
    sc._reset();
    let clock = T0;
    sc._setNow(() => clock);
    const tokens = new Map();
    const steps = run.ops.map((op) => {
      if (op.at !== undefined) clock = op.at;
      const c = op.case ? byId.get(op.case) : null;
      const step = { ...op };
      try {
        if (op.op === 'issue') {
          tokens.set(op.token, issueFor(sc, c).token);
          step.outcome = { ok: true };
        } else if (op.op === 'consume') {
          const token = op.literal !== undefined ? op.literal : tokens.get(op.token);
          const spent = consumeFor(sc, token, c, op.route);
          step.outcome = { ok: true, bound: spent };
        } else if (op.op === 'discard') {
          sc.discardConfirmation(tokens.get(op.token));
          step.outcome = { ok: true };
        } else if (op.op === 'count') {
          step.outcome = { count: sc._outstandingCount() };
        } else {
          throw new Error(`unknown op ${op.op}`);
        }
      } catch (error) {
        assert.equal(error.code, sc.NOT_CONFIRMED, `${run.id}: ${error.message}`);
        step.outcome = jsError(error);
      }
      return step;
    });
    sc._reset();
    return { ...run, ops: steps };
  });
}

// ---- the vector -----------------------------------------------------------------

async function buildApprovals(checkout, meta) {
  const sc = loadReference(checkout);
  assert.equal(sc.CONFIRMATION_TTL_MS, 2 * MINUTE);
  assert.equal(sc.MAX_OUTSTANDING, 32);
  const byId = new Map(cases.map((c) => [c.id, c]));
  const built = cases.map((c) => {
    const js = bindingOf(sc, c);
    const out = {
      id: c.id,
      kind: c.kind,
      account: c.account === undefined ? null : c.account,
      payload: c.payload === undefined ? null : c.payload,
      page: c.page ?? null,
      js,
      core: coreForm(c),
    };
    if (c.deviation) {
      assert.equal(c.deviation, 'token-strict', c.id);
      assert.ok(js.facts, `${c.id}: the reference must bind a token-strict case`);
      out.deviation = c.deviation;
    }
    if (c.sameHash) out.sameHash = true;
    // The core issues a token for what the reference binds, but for the
    // token-strict cases; and none for what it refuses.
    out.expect = js.facts && !c.deviation ? 'issued' : 'refused';
    if (out.core === null) delete out.expect;
    return out;
  });
  const builtById = new Map(built.map((c) => [c.id, c]));
  const builtPairs = pairs.map(({ a, b, deviation }) => {
    const [ca, cb] = [byId.get(a), byId.get(b)];
    const [ja, jb] = [builtById.get(a).js, builtById.get(b).js];
    assert.ok(ja.facts && jb.facts, `${a} / ${b}: a pair is of two requests the reference binds`);
    assert.ok(builtById.get(a).expect === 'issued' && builtById.get(b).expect === 'issued', `${a} / ${b}`);
    const js = decide(sc, ca, cb);
    assert.equal(decide(sc, cb, ca), js, `${a} / ${b}: the same both ways`);
    const keys = changed(ca, cb, ja, jb);
    // The reference tells two requests apart exactly when their facts,
    // kinds or pages differ.
    assert.equal(js === 'apart', keys.length > 0, `${a} / ${b}: ${keys}`);
    const pair = { a, b, js, changed: keys, core: coreAnswer(js, deviation) };
    if (deviation) pair.deviation = deviation;
    return pair;
  });
  // Every fact each kind's reference binding holds is changed alone, or with
  // its page, by an apart pair of that kind.
  const bases = built.filter((c) => c.id.endsWith('/base') || c.id === 'safe-send/wallet' || c.id === 'safe-send/site');
  assert.equal(bases.length, 11 + 1);
  for (const base of bases) {
    const keys = [...Object.keys(base.js.facts), ...(base.page ? ['page.handle', 'page.key'] : [])];
    for (const key of keys) {
      assert.ok(
        builtPairs.some((p) => p.a === base.id && p.js === 'apart' && p.changed.includes(key)),
        `${base.id}: no pair changes ${key}`
      );
    }
  }
  const runs = runAll(sc, byId);
  const kinds = Object.values(sc.KINDS).map((name) => ({
    name,
    page: sc.PAGE_KINDS.includes(name) ? 'always' : name === sc.KINDS.SAFE_SEND ? 'with-site' : 'never',
    design: name !== sc.KINDS.X402_CAP_UPDATE,
  }));
  assert.equal(kinds.filter((k) => k.design).length, 11);
  return {
    meta,
    formats: {
      constants: 'The reference\'s `CONFIRMATION_TTL_MS` and `MAX_OUTSTANDING`.',
      kinds: 'The reference\'s `KINDS`: whether each is a page kind (`always`, `with-site` for a Safe send that names a site, `never`), and whether design 0012 takes it (`design`; the cap edit, #1023, is not one of its eleven).',
      rules: require('./approval-rules').RULES_FORMAT,
      bindings: 'One request each: `kind`, `account`, `payload` and `page` (`{ handle, key }`, for main\'s page issuer) as the reference takes them; `js`, `bindingFor`\'s facts or its error message; `core`, the request in fc-approval\'s form (`account`, `payload` or `payload_text`, the payload\'s JSON text the core parses itself, and `page`: `{ origin, frame, navigation, handle }`), or null where the reference\'s input has none; `expect`, whether the core issues a token for it (`issued`) or refuses it (`refused`), from 0012 (`deviation: token-strict` where the reference binds what the core refuses); `sameHash`, set where the case was built to share the EIP-712 hash of the case it is paired with.',
      pairs: 'Two requests the reference binds: `js`, whether a token minted for either spends for the other (`alike`) or is refused (`apart`), asked of the reference both ways; `changed`, the facts (and `kind`, `page`, `page.handle`, `page.key`) in which the reference\'s bindings differ; `core`, the core\'s answer, from 0012\'s Deviations table where `deviation` is set.',
      stores: STORES_FORMAT,
      rollback: ROLLBACK_FORMAT,
      runs: 'Steps in order under `_setNow`, on a fresh store: `issue` (a case\'s request, minted as `token`), `consume` (a case\'s request, presented with `token`, or with `literal` text; `route: wallet` presents it without its page), `discard` and `count` (the outstanding tokens); `at` is the reference\'s clock, and `vaultAt` the vault\'s where they differ (`token-clock`); each step\'s `outcome` (`ok`, with what the token bound; `error`, the reference\'s message; or `count`), and `core` where the core\'s differs.',
    },
    constants: { ttlMs: sc.CONFIRMATION_TTL_MS, maxOutstanding: sc.MAX_OUTSTANDING },
    kinds,
    // Design 0012's R-6 limiter and fee check (APR-2).
    rules: await require('./approval-rules').buildRules(checkout),
    bindings: built,
    pairs: builtPairs,
    runs,
    // Design 0012's grant files (APR-2), from the reference's four stores.
    stores: buildStores(checkout),
    // Q9's legacy transition: the design's texts, read by the reference.
    rollback: buildRollback(checkout),
  };
}

module.exports = { buildApprovals };
