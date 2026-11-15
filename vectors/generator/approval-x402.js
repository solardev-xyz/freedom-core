'use strict';

// Design 0012's x402 (step X402-1), from the approvals reference's own
// src/main/x402/ code over the main reference's installed @x402/core and
// @x402/evm 2.28.0 (the pinned SDK the design names): nothing of x402 is
// reimplemented here.
//
// - `defaultAssets`: @x402/evm's DEFAULT_ASSETS, which @x402/core's client
//   spend controls allow with no configuration (client.js configures
//   none). The table isn't exported: its entries are read from the
//   module's own source text, and each is confirmed through the scheme's
//   own `findDefaultAsset`.
// - `keys`: intercept.js' `originKeyForUrl`, the cap key of a paid URL.
// - `tuples`: payment-utils.js' `tupleFromAccept`.
// - `covering`: payment-utils.js' `findCoveringPermission` over the real
//   permissions.js (in memory, `Date.now` fixed), and whether its `charge`
//   then takes the covering entry's amount.
// - `payloads`: sign-flow.js' `signAndQueueRetry` for one entry, through
//   the reference's client.js and the SDK, with `Date.now` and
//   `crypto.getRandomValues` fixed and a signer over a public test key:
//   the header's JSON (what sign-flow.js base64-encodes), or the error.
//   Requirements go through @x402/core's own schema first, as intercept.js
//   parses a 402: `requirements` is the schema's output, what main holds.
// - `devices`: the same payloads for a Ledger or phone account (core #392):
//   the typed data @x402/evm hands the signer's `signTypedData`, its EIP-712
//   hash (ethers' `TypedDataEncoder.hash`), the signature text the device
//   returns, the header's JSON with that text in it, and whether ethers'
//   `recoverAddress` (main's device check today) recovers the account.
//
// `core` is the core's answer (`payload` or `refused`); `inferred` marks
// where it differs from the reference's, a narrowing design 0012's X402-1
// notes list.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const { loadWithInternals } = require('./naming');
const { memoryFs, loadStore, at, plain } = require('./approval-stores');

const SILENT_LOG = { info() {}, warn() {}, error() {}, debug() {}, log() {} };
const T = 1_762_000_000_000;
const S = Math.floor(T / 1000);
const SITE = 'https://paid.example';
const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const MAINNET_USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const CELO_USDT = '0x48065fbBE25f71C9282ddf5e1cD6D6A887483D5e';
const MEGA_USDM = '0xFAfDdbb3FC7688494971a79cc65DCa3EF82079E7';
const PAY_TO = '0x209693bc6afc0c5328ba36faf03c514ef312287c';
// keys.json's abandon-12, account 0: a public test key. Never fund it.
const SIGNER = Object.freeze({
  privateKey: '0x1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727',
  address: '0x9858EfFD232B4033E47d90003D41EC34EcaEda94',
});
// keys.json's abandon-12, account 1: a device that signs with another key.
const OTHER_KEY = Object.freeze({
  privateKey: '0x318470c858f622e48a80120a1fc3c8460d67a7bf31b3273a6d27d4c013f2f8d3',
  address: '0x78839F6054d7ed13918bAe0473BA31b1Ca9D7265',
});
const NONCE = Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 37 + 11) & 0xff));

const FORMAT = 'Design 0012\'s x402 (X402-1), from the approvals reference\'s src/main/x402/ over the main reference\'s @x402/core and @x402/evm (`meta.packages`). `defaultAssets`: the SDK\'s DEFAULT_ASSETS, which its client\'s default spend controls allow (`chainId`, `asset`, `decimals`), each confirmed by the scheme\'s `findDefaultAsset`. `keys`: `originKeyForUrl(url)` (`js`, null where the reference has none) and the core\'s (`core`, null where it refuses: x402 pays only an http or https resource). `tuples`: `tupleFromAccept(accept)`. `covering`: from a cap file (`start`) at `at` (wall-clock ms), `findCoveringPermission(origin, accepts)`\'s entry index (`js`, null for none, or `error`), whether `charge` then took its amount (`charged`), and the core\'s entry (`core`), with `deviation` where 0012 says it differs. `payloads`: `signAndQueueRetry` for `requirements.accepts[accept_index]` at `now` (wall-clock seconds) with `nonce` (the 32 bytes `getRandomValues` gave) and `signer`: `js.payload`, the JSON text sign-flow.js base64-encodes into the header, or `js.error`; `core`, `payload` (the same text) or `refused`; `inferred` where the core refuses what the reference signs. `devices`: the payloads of `payloads` that the core signs, for a device account (core #392) whose address is `address`: `typedData`, the JSON text of what @x402/evm hands the signer\'s `signTypedData` (`{ domain, types, primaryType, message }`, its BigInts as decimal strings); `hash`, its EIP-712 hash (ethers\' `TypedDataEncoder.hash`); `signature`, the text the device returns (`variant`: `ethers`, as ethers\' `Wallet.signTypedData` returns it; `upper`, its hex digits in upper case; `v-parity`, its last byte 0 or 1; `v-eip155`, its last byte 37 or 38; `high-s`, `s` replaced by the order minus `s` and the parity flipped; `other-key`, another account\'s signature); `js.payload`, the header\'s JSON with that text in it, as sign-flow.js base64-encodes it; `recovers`, what ethers\' `recoverAddress(hash, signature)` gives (main\'s device check today), or null where it throws; `core`, `payload` (the same text) or `{ refused }` with `wrong_account` or `bad_response`, the reason the core gives; `inferred` where the core refuses a signature ethers recovers to the account.';

/** The main reference's SDK and ethers, and the approvals reference's x402 modules over them. */
function load(checkout, mainCheckout) {
  const ref = createRequire(path.join(mainCheckout, 'package.json'));
  const sdk = {
    client: ref('@x402/core/client'),
    schemas: ref('@x402/core/schemas'),
    evm: ref('@x402/evm/exact/client'),
    evmV1: ref('@x402/evm/exact/v1/client'),
    evmPath: ref.resolve('@x402/evm/exact/client'),
  };
  const ethers = ref('ethers');
  const wallet = new ethers.Wallet(SIGNER.privateKey);
  assert.equal(wallet.address, SIGNER.address);
  // client.js' signer: `getSigner(index)` with `getAddress` and the
  // viem-style `signTypedData({ domain, types, primaryType, message })`.
  // A device account's signer, when `device.sign` is set: what the scheme
  // hands `signTypedData` is kept, and the device's text returned.
  const device = { sign: null, asked: [] };
  const signer = {
    getAddress: async () => wallet.address,
    signTypedData: async (typedData) => {
      if (device.sign) {
        device.asked.push(typedData);
        return device.sign(typedData);
      }
      const { domain, types, message } = typedData;
      return wallet.signTypedData(domain, types, message);
    },
  };
  const client = loadWithInternals(checkout, 'src/main/x402/client.js', [], {
    '@x402/core/client': sdk.client,
    '@x402/evm/exact/client': sdk.evm,
    '@x402/evm/exact/v1/client': sdk.evmV1,
    '../wallet/signers': { getSigner: () => signer },
  });
  const pending = { value: null };
  const signFlow = loadWithInternals(checkout, 'src/main/x402/sign-flow.js', [], {
    electron: { webContents: { fromId: () => null } },
    '../logger': SILENT_LOG,
    './client': client,
    '../identity-manager': { getActiveWalletIndex: () => 0 },
    './intercept': {
      X402_HEADERS: {},
      AUTHORIZED_BY: { CAP: 'cap', MANUAL: 'manual' },
      outgoingHeaderForVersion: (version) => (version === 1 ? 'X-PAYMENT' : 'PAYMENT-SIGNATURE'),
      getDetectedPayment: () => null,
      clearDetectedPayment() {},
      setPendingPayment: (_id, _url, payment) => { pending.value = payment; },
      sendToHost() {},
    },
    './permissions': { grant() {}, charge: () => null, refund: () => false },
    '../wallet/agent-tab-custody': { isUserPageId: () => true },
  });
  const intercept = loadWithInternals(checkout, 'src/main/x402/intercept.js', ['originKeyForUrl'], {
    electron: { webContents: { fromId: () => null } },
    '../logger': SILENT_LOG,
    '@x402/core/schemas': sdk.schemas,
    '../webrequest-dispatcher': { registerWebRequestHandler() {} },
    '../ipfs/gateway-transport': { isGatewayTransportRequest: () => false },
    '../payment-history': {},
    './payment-utils': { findCoveringPermission: () => null },
    './permissions': {},
    '../wallet/vault-errors': { isVaultLockedError: () => false },
    '../wallet/agent-tab-custody': { isUserPageId: () => true },
  });
  return { sdk, ethers, signer, device, signFlow, pending, originKeyForUrl: intercept.__internals.originKeyForUrl };
}

// ---------------------------------------------------------------------------

function defaultAssets({ sdk, signer }) {
  const source = fs.readFileSync(sdk.evmPath, 'utf8');
  const start = source.indexOf('var DEFAULT_ASSETS = {');
  assert.ok(start >= 0, 'DEFAULT_ASSETS not found');
  const block = source.slice(start, source.indexOf('\n};', start));
  const entries = [];
  for (const network of block.split(/\n {2}"(eip155:\d+)": \[/).reduce((acc, part, i, all) => {
    if (i % 2 === 1) acc.push([part, all[i + 1]]);
    return acc;
  }, [])) {
    const [name, body] = network;
    for (const match of body.matchAll(/asset: "(0x[0-9a-fA-F]{40})",[\s\S]*?decimals: (\d+)/g)) {
      entries.push({ network: name, asset: match[1], decimals: Number(match[2]) });
    }
  }
  const scheme = new sdk.evm.ExactEvmScheme({ address: SIGNER.address, signTypedData: signer.signTypedData });
  for (const entry of entries) {
    const found = scheme.findDefaultAsset(entry.asset.toLowerCase(), entry.network);
    assert.equal(found?.decimals, entry.decimals, `${entry.network} ${entry.asset}`);
  }
  assert.equal(scheme.findDefaultAsset(USDC, 'eip155:10'), undefined);
  assert.equal(scheme.findDefaultAsset(USDC, 'base')?.decimals, 6);
  assert.equal(entries.length, 31);
  return entries.map(({ network, asset, decimals }) => ({ chainId: Number(network.slice(7)), asset, decimals }));
}

const KEY_URLS = [
  'https://paid.example/article?id=1#top',
  'https://Paid.Example:443/a',
  'http://paid.example:8080/a',
  'https://user:pw@paid.example/a',
  'https://bücher.example/a',
  'https://[::1]:8443/a',
  'https://192.168.000.001/a',
  '  https://paid.example/a  ',
  'bzz://' + 'ab'.repeat(32) + '/a',
  'ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi/a',
  'file:///etc/passwd',
  'not a url',
];

function keys(ref) {
  return KEY_URLS.map((url) => {
    const js = ref.originKeyForUrl(url);
    const scheme = (() => { try { return new URL(url).protocol; } catch { return null; } })();
    const core = scheme === 'http:' || scheme === 'https:' ? js : null;
    return { url, js, core };
  });
}

const accept = (over = {}) => ({
  scheme: 'exact', network: 'eip155:8453', amount: '10000', asset: USDC, payTo: PAY_TO,
  maxTimeoutSeconds: 60, extra: { name: 'USD Coin', version: '2' }, ...over,
});
const v1Accept = (over = {}) => ({
  scheme: 'exact', network: 'base', maxAmountRequired: '10000', resource: `${SITE}/v1`,
  description: '', payTo: PAY_TO, maxTimeoutSeconds: 60, asset: USDC,
  extra: { name: 'USD Coin', version: '2' }, ...over,
});

const TUPLE_ACCEPTS = [
  accept(),
  accept({ asset: USDC.toLowerCase() }),
  accept({ network: 'eip155:0x10' }),
  accept({ network: 'eip155: 8453' }),
  accept({ network: 'eip155:8453.5' }),
  accept({ network: 'eip155:' }),
  accept({ network: 'eip155:abc' }),
  accept({ network: 'EIP155:8453' }),
  accept({ amount: 10000 }),
  accept({ asset: 7 }),
  v1Accept(),
  null,
];

function tuples(paymentUtils) {
  return TUPLE_ACCEPTS.map((a) => ({ accept: a, js: plain(paymentUtils.tupleFromAccept(a)) }));
}

const capFile = (caps) => JSON.stringify({ [SITE]: caps }, null, 2);
const cap = (capAmount, spentAmount, createdAt = S - 100, expiresAt = S + 3600) => ({ capAmount, spentAmount, createdAt, expiresAt });
const KEY_BASE = `8453:${USDC.toLowerCase()}`;
const KEY_MAINNET = `1:${MAINNET_USDC.toLowerCase()}`;
const COVERING = [
  { id: 'first-covered', start: capFile({ [KEY_BASE]: cap('20000', '0') }), accepts: [accept(), accept({ amount: '1' })] },
  { id: 'seller-order', start: capFile({ [KEY_BASE]: cap('20000', '0'), [KEY_MAINNET]: cap('20000', '0') }), accepts: [accept({ network: 'eip155:1', asset: MAINNET_USDC }), accept()] },
  { id: 'over-cap-skipped', start: capFile({ [KEY_BASE]: cap('20000', '15000'), [KEY_MAINNET]: cap('20000', '0') }), accepts: [accept(), accept({ network: 'eip155:1', asset: MAINNET_USDC })] },
  { id: 'exactly-left', start: capFile({ [KEY_BASE]: cap('20000', '10000') }), accepts: [accept()] },
  { id: 'one-over', start: capFile({ [KEY_BASE]: cap('20000', '10001') }), accepts: [accept()] },
  { id: 'none', start: capFile({ [KEY_MAINNET]: cap('20000', '0') }), accepts: [accept()] },
  { id: 'no-file', start: null, accepts: [accept()] },
  { id: 'other-origin', start: JSON.stringify({ 'https://other.example': { [KEY_BASE]: cap('20000', '0') } }), accepts: [accept()] },
  { id: 'expired-at-boundary', start: capFile({ [KEY_BASE]: cap('20000', '0', S - 100, S) }), accepts: [accept()] },
  { id: 'live-one-second-before', start: capFile({ [KEY_BASE]: cap('20000', '0', S - 100, S + 1) }), accepts: [accept()] },
  // A cap created after now: the reference's covers; the core's is expired.
  { id: 'clock-set-back', start: capFile({ [KEY_BASE]: cap('20000', '0', S + 100, S + 3600) }), accepts: [accept()], deviation: 'x402-clock-back' },
  { id: 'asset-mixed-in-entry', start: capFile({ [KEY_BASE]: cap('20000', '0') }), accepts: [accept({ asset: USDC })] },
  // A key written in mixed case (never by tupleFromAccept): found by neither.
  { id: 'asset-mixed-in-key', start: capFile({ [`8453:${USDC}`]: cap('20000', '0') }), accepts: [accept()] },
  { id: 'v1-entry', start: capFile({ [KEY_BASE]: cap('20000', '0') }), accepts: [v1Accept(), accept()] },
  // An amount BigInt reads but charge's /^\d+$/ refuses, and one BigInt throws on.
  { id: 'hex-amount', start: capFile({ [KEY_BASE]: cap('20000', '0') }), accepts: [accept({ amount: '0x10' }), accept()] },
  { id: 'amount-not-a-number', start: capFile({ [KEY_BASE]: cap('20000', '0') }), accepts: [accept({ amount: 'abc' }), accept()] },
  { id: 'leading-zeros', start: capFile({ [KEY_BASE]: cap('20000', '0') }), accepts: [accept({ amount: '0010000' })] },
];

function covering(checkout) {
  return COVERING.map((c) => {
    const memory = memoryFs();
    if (c.start !== null) memory.files.set('/user-data/x402-permissions.json', c.start);
    const permissions = loadStore(checkout, 'x402', memory);
    const utils = loadWithInternals(checkout, 'src/main/x402/payment-utils.js', [], { './permissions': permissions });
    const out = { id: c.id, start: c.start, at: T, origin: SITE, accepts: c.accepts };
    let index = null;
    let error;
    let charged = false;
    at(T, () => {
      try {
        const found = utils.findCoveringPermission(SITE, c.accepts);
        index = found ? c.accepts.indexOf(found.accept) : null;
        if (found) {
          charged = permissions.charge(SITE, found.tuple.chainId, found.tuple.asset, found.tuple.amount) !== null;
        }
      } catch (e) {
        error = String(e?.message ?? e);
      }
    });
    if (error !== undefined) out.error = error;
    else out.js = index;
    out.charged = charged;
    out.core = charged && !c.deviation ? index : null;
    if (c.deviation) out.deviation = c.deviation;
    return out;
  });
}

// The payloads: [id, raw requirements, index, extra].
const v2 = (accepts, over = {}) => ({
  x402Version: 2,
  resource: { url: `${SITE}/article`, description: 'An article', mimeType: 'text/html' },
  accepts,
  ...over,
});
const v1 = (accepts) => ({ x402Version: 1, accepts });
const PAYLOADS = [
  ['v2-eip3009', v2([accept()]), 0],
  ['v2-second-entry', v2([accept({ network: 'eip155:1', asset: MAINNET_USDC, extra: { name: 'USD Coin', version: '2' } }), accept()]), 1],
  ['v2-permit2', v2([accept({ extra: { assetTransferMethod: 'permit2' } })]), 0],
  ['v2-permit2-short-window', v2([accept({ maxTimeoutSeconds: 5, extra: { assetTransferMethod: 'permit2' } })]), 0],
  ['v2-other-method-is-eip3009', v2([accept({ extra: { name: 'USD Coin', version: '2', assetTransferMethod: 'eip2612' } })]), 0],
  ['v2-extensions', v2([accept()], { extensions: { bazaar: { info: { n: 1.5, s: 'x' } } } }), 0],
  ['v2-extensions-null', v2([accept()], { extensions: null }), 0],
  ['v2-resource-text', v2([accept()], { resource: { url: `${SITE}/é?q="1"`, description: 'line sep\u0001 "quoted" \\ é', serviceName: 'Paid', tags: ['a', 'b'] } }), 0],
  ['v2-unknown-fields-stripped', v2([{ ...accept(), note: 'dropped' }], { note: 'dropped' }), 0],
  ['v2-amount-leading-zeros', v2([accept({ amount: '0010000' })]), 0],
  ['v2-amount-at-limit', v2([accept({ amount: '1000000' })]), 0],
  ['v2-amount-over-limit', v2([accept({ amount: '1000001' })]), 0],
  ['v2-amount-hex', v2([accept({ amount: '0x10' })]), 0],
  ['v2-amount-decimal', v2([accept({ amount: '0.5' })]), 0],
  ['v2-amount-negative', v2([accept({ amount: '-1' })]), 0],
  ['v2-asset-lowercase', v2([accept({ asset: USDC.toLowerCase() })]), 0],
  ['v2-asset-upper-x', v2([accept({ asset: '0X' + USDC.slice(2) })]), 0],
  ['v2-asset-not-default', v2([accept({ asset: '0x' + '11'.repeat(20) })]), 0],
  ['v2-network-not-default', v2([accept({ network: 'eip155:10' })]), 0],
  ['v2-network-padded', v2([accept({ network: 'eip155:08453' })]), 0],
  ['v2-network-solana', v2([accept({ network: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp' })]), 0],
  ['v2-scheme-other', v2([accept({ scheme: 'upto' })]), 0],
  ['v2-flow-escrow', v2([accept({ extra: { name: 'USD Coin', version: '2', paymentFlow: 'escrow' } })]), 0],
  ['v2-flow-unknown', v2([accept({ extra: { name: 'USD Coin', version: '2', paymentFlow: 'stream' } })]), 0],
  ['v2-no-version', v2([accept({ extra: { name: 'USD Coin' } })]), 0],
  ['v2-extra-null', v2([accept({ extra: null })]), 0],
  ['v2-name-not-string', v2([accept({ extra: { name: 5, version: '2' } })]), 0],
  ['v2-version-not-string', v2([accept({ extra: { name: 'USD Coin', version: 2 } })]), 0],
  ['v2-runway-19', v2([accept({ maxTimeoutSeconds: 19 })]), 0],
  ['v2-runway-20', v2([accept({ maxTimeoutSeconds: 20 })]), 0],
  ['v2-timeout-fraction', v2([accept({ maxTimeoutSeconds: 60.5 })]), 0],
  ['v2-pay-to-invalid', v2([accept({ payTo: '0x1234' })]), 0],
  ['v2-celo-second-asset', v2([accept({ network: 'eip155:42220', asset: CELO_USDT, extra: { name: 'Tether USD', version: '1' } })]), 0],
  ['v2-18-decimals', v2([accept({ network: 'eip155:4326', asset: MEGA_USDM, amount: '1000000000000000000', extra: { name: 'MegaUSD', version: '1' } })]), 0],
  ['v1-base', v1([v1Accept()]), 0],
  ['v1-ethereum', v1([v1Accept({ network: 'ethereum', asset: MAINNET_USDC })]), 0],
  ['v1-polygon', v1([v1Accept({ network: 'polygon' })]), 0],
  ['v1-permit2-ignored', v1([v1Accept({ extra: { name: 'USD Coin', version: '2', assetTransferMethod: 'permit2' } })]), 0],
  ['v1-runway-19', v1([v1Accept({ maxTimeoutSeconds: 19 })]), 0],
];

async function payload(ref, raw, index) {
  const parsed = ref.sdk.schemas.parsePaymentRequired(raw);
  assert.ok(parsed.success, JSON.stringify(parsed.error));
  const requirements = parsed.data;
  ref.pending.value = null;
  const realNow = Date.now;
  const crypto = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  Date.now = () => T;
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: { getRandomValues: (array) => { array.set(NONCE.subarray(0, array.length)); return array; } },
  });
  try {
    await ref.signFlow.signAndQueueRetry(1, {
      detection: { url: `${SITE}/article`, requirements, resourceType: 'xhr' },
      selectedAccept: requirements.accepts[index],
      authorizedBy: 'manual',
      walletIndex: 0,
    });
    const value = ref.pending.value.value;
    return { requirements: plain(requirements), js: { payload: Buffer.from(value, 'base64').toString('utf8') } };
  } catch (error) {
    return { requirements: plain(requirements), js: { error: String(error?.message ?? error) } };
  } finally {
    Date.now = realNow;
    Object.defineProperty(globalThis, 'crypto', crypto);
  }
}

async function payloads(ref) {
  const out = [];
  for (const [id, raw, index, extra = {}] of PAYLOADS) {
    const { requirements, js } = await payload(ref, raw, index);
    const signed = js.payload !== undefined;
    if (extra.inferred) assert.ok(signed, `${id}: an inferred refusal is of a payload the reference signs`);
    const c = {
      id, requirements, accept_index: index, now: S, nonce: '0x' + NONCE.toString('hex'), signer: SIGNER, js,
      core: signed && !extra.inferred ? 'payload' : 'refused',
    };
    if (extra.inferred) c.inferred = true;
    out.push(c);
  }
  // Every kind of payload is signed at least once.
  for (const kind of ['"authorization"', '"permit2Authorization"', '"x402Version":1']) {
    assert.ok(out.some((c) => c.js.payload?.includes(kind)), kind);
  }
  return out;
}

// The device payloads (core #392): each payload the core signs, for a
// device account whose address is the test key's, with the device's
// signature text in each variant.
const ORDER = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
const ALL_VARIANTS = ['ethers', 'upper', 'v-parity', 'v-eip155', 'high-s', 'other-key'];
const DEVICE_VARIANTS = {
  'v2-eip3009': ALL_VARIANTS,
  'v2-permit2': ['ethers', 'v-parity', 'other-key'],
  'v1-base': ['ethers', 'upper', 'other-key'],
};

/** The text a device returns for `typedData`, in `variant`. */
async function deviceSignature(ethers, variant, typedData) {
  const { domain, types, message } = typedData;
  const key = variant === 'other-key' ? OTHER_KEY.privateKey : SIGNER.privateKey;
  const text = await new ethers.Wallet(key).signTypedData(domain, types, message);
  const signature = ethers.Signature.from(text);
  const parity = signature.v - 27;
  const body = text.slice(0, 130);
  switch (variant) {
    case 'ethers':
    case 'other-key':
      return text;
    case 'upper':
      return '0x' + text.slice(2).toUpperCase();
    case 'v-parity':
      return body + (parity ? '01' : '00');
    case 'v-eip155':
      return body + (parity ? '26' : '25');
    case 'high-s':
      return signature.r + (ORDER - BigInt(signature.s)).toString(16).padStart(64, '0') + (parity ? '1b' : '1c');
    default:
      throw new Error(`unknown variant ${variant}`);
  }
}

const bigintsAsText = (_key, value) => (typeof value === 'bigint' ? value.toString() : value);

async function devices(ref, signed) {
  const out = [];
  for (const [id, raw, index] of PAYLOADS) {
    const vault = signed.find((c) => c.id === id);
    if (!vault || vault.core !== 'payload') continue;
    for (const variant of DEVICE_VARIANTS[id] ?? ['ethers']) {
      ref.device.asked = [];
      let text = null;
      ref.device.sign = async (typedData) => {
        text = await deviceSignature(ref.ethers, variant, typedData);
        return text;
      };
      let result;
      try {
        result = await payload(ref, raw, index);
      } finally {
        ref.device.sign = null;
      }
      assert.equal(ref.device.asked.length, 1, `${id}/${variant}: one signature asked`);
      const asked = ref.device.asked[0];
      const payloadText = result.js.payload;
      assert.ok(payloadText !== undefined, `${id}/${variant}: ${result.js.error}`);
      // The device's text goes into the header as it came.
      assert.ok(payloadText.includes(JSON.stringify(text)), `${id}/${variant}`);
      if (variant === 'ethers') assert.equal(payloadText, vault.js.payload, `${id}: the vault's payload`);
      const hash = ref.ethers.TypedDataEncoder.hash(asked.domain, asked.types, asked.message);
      let recovers = null;
      try {
        recovers = ref.ethers.recoverAddress(hash, text);
      } catch {
        recovers = null;
      }
      // The core's check is PHN-1's: 0x and 130 hex digits, a last byte of
      // 0, 1, 27 or 28, a low s, and the account recovered.
      const last = parseInt(text.slice(130), 16);
      const core = recovers === null || ![0, 1, 27, 28].includes(last)
        ? { refused: 'bad_response' }
        : recovers === SIGNER.address ? 'payload' : { refused: 'wrong_account' };
      const c = {
        id: `${id}/${variant}`, payload: id, variant, requirements: result.requirements, accept_index: index,
        now: S, nonce: '0x' + NONCE.toString('hex'), address: SIGNER.address,
        typedData: JSON.stringify(asked, bigintsAsText), hash, signature: text,
        js: { payload: payloadText }, recovers, core,
      };
      if (recovers === SIGNER.address && core !== 'payload') c.inferred = true;
      out.push(c);
    }
  }
  // Each kind of payload, a refusal of each reason, and an inferred one.
  for (const kind of ['"authorization"', '"permit2Authorization"', '"x402Version":1']) {
    assert.ok(out.some((c) => c.core === 'payload' && c.js.payload.includes(kind)), kind);
  }
  for (const reason of ['wrong_account', 'bad_response']) {
    assert.ok(out.some((c) => c.core.refused === reason), reason);
  }
  assert.ok(out.some((c) => c.inferred), 'an inferred refusal');
  return out;
}

async function buildX402(checkout, mainCheckout) {
  const ref = load(checkout, mainCheckout);
  const paymentUtils = loadWithInternals(checkout, 'src/main/x402/payment-utils.js', [], { './permissions': {} });
  const signed = await payloads(ref);
  return {
    defaultAssets: defaultAssets(ref),
    keys: keys(ref),
    tuples: tuples(paymentUtils),
    covering: covering(checkout),
    payloads: signed,
    devices: await devices(ref, signed),
  };
}

function x402Packages(mainCheckout, packageVersion) {
  const ref = createRequire(path.join(mainCheckout, 'package.json'));
  return Object.fromEntries(['@x402/core', '@x402/evm', 'ethers'].map((name) => [name, packageVersion(ref, name)]));
}

module.exports = { buildX402, X402_FORMAT: FORMAT, x402Packages };
