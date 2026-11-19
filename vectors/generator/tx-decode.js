'use strict';

const assert = require('node:assert/strict');

// Signed transactions read back (design 0013, PRF-5e-1), as freedom-browser's
// intent store checks the bytes it keeps: `verifySigned` and `signerOf` in
// src/main/wallet/intent-store.js (integration/rust-core at 9d4ea625,
// lines 326-353) run ethers' `Transaction.from(raw)`, require a signature and
// type 0 or 2, compare `tx.serialized` with `raw` and recover `tx.from`.
// `verdict` makes the same calls in the same order on the main reference's
// ethers, which is the same version. Every input is built here from
// transactions the test keys sign, changed through ethers' own RLP coder or
// the few header forms `encodeItem` writes; none is written out by hand.

const N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
const HALF = N / 2n;
const TOKEN = '0xddafbb505ad214d7b80b1f830fccc89b60fb7a83';
const ADDRESS = '0x8ba1f109551bD432803012645Ac136ddd64DBA72';
const SLOT = (byte) => '0x' + byte.repeat(32);
const TRANSFER = '0xa9059cbb0000000000000000000000008ba1f109551bd432803012645ac136ddd64dba7200000000000000000000000000000000000000000000000000000000000f4240';
// The types ethers reads and the store refuses. The core refuses them by
// their first byte alone (deviation `tx-other-types`).
const OTHER_TYPES = [1, 3, 4];

const short = (error) => error.shortMessage || error.message;

/** The intent store's checks, in its order, then its `signerOf`. */
function verdict(ethers, raw) {
  let tx;
  try {
    tx = ethers.Transaction.from(raw);
  } catch (error) {
    return { verdict: 'undecodable', message: short(error) };
  }
  if (!tx.signature) return { verdict: 'unsigned' };
  if (tx.type !== 0 && tx.type !== 2) return { verdict: 'unsupported_type', type: tx.type };
  let serialized;
  try {
    serialized = tx.serialized;
  } catch (error) {
    return { verdict: 'unserializable', message: short(error) };
  }
  if (serialized !== raw) return { verdict: 'not_canonical' };
  let signer;
  try {
    signer = ethers.Transaction.from(raw).from.toLowerCase();
  } catch {
    signer = null;
  }
  return { verdict: 'accepted', tx: fieldsOf(tx), digest: tx.unsignedHash, hash: ethers.keccak256(raw), signer };
}

/** What ethers decoded, field by field. */
function fieldsOf(tx) {
  const legacy = tx.type === 0;
  const { signature } = tx;
  return {
    type: tx.type,
    chain_id: tx.chainId.toString(),
    nonce: tx.nonce,
    gas_limit: tx.gasLimit.toString(),
    to: tx.to ? tx.to.toLowerCase() : null,
    value: tx.value.toString(),
    data: tx.data,
    gas_price: legacy ? tx.gasPrice.toString() : null,
    max_fee_per_gas: legacy ? null : tx.maxFeePerGas.toString(),
    max_priority_fee_per_gas: legacy ? null : tx.maxPriorityFeePerGas.toString(),
    access_list: legacy ? null : tx.accessList.map(({ address, storageKeys }) => ({
      address: address.toLowerCase(), storage_keys: storageKeys,
    })),
    // A legacy transaction's v as it carries it: EIP-155's, or 27 or 28.
    v: legacy ? (signature.networkV ?? BigInt(signature.v)).toString() : null,
    y_parity: signature.yParity,
    r: signature.r,
    s: signature._s,
  };
}

function coder(ethers) {
  const { decodeRlp, encodeRlp, toBeArray, toBeHex, hexlify } = ethers;
  const bare = (hex) => hex.slice(2);
  const uint = (value) => (value === 0n ? '0x' : toBeHex(value));
  const word = (value) => toBeHex(value, 32);

  /** A transaction's type prefix (`0x` for legacy) and its fields. */
  function split(raw) {
    const typed = parseInt(raw.slice(2, 4), 16) < 0x7f;
    return typed
      ? { prefix: raw.slice(0, 4), fields: decodeRlp('0x' + raw.slice(4)) }
      : { prefix: '0x', fields: decodeRlp(raw) };
  }
  const join = (prefix, fields) => prefix + bare(encodeRlp(fields));

  /** `raw` with field `index` replaced (or removed with `undefined`). */
  function withField(raw, index, value) {
    const { prefix, fields } = split(raw);
    if (value === undefined) fields.splice(index, 1);
    else fields[index] = value;
    return join(prefix, fields);
  }
  function withFields(raw, fields) {
    return join(split(raw).prefix, fields);
  }

  /** An RLP header: the shortest form, the long form whatever the length,
   * or the long form with a zero byte before the length. */
  function header(offset, length, form) {
    if (form === 'shortest' && length < 56) return hexlify(new Uint8Array([offset + length]));
    const digits = length === 0 ? [] : Array.from(toBeArray(length));
    const body = form === 'padded' || digits.length === 0 ? [0, ...digits] : digits;
    return hexlify(new Uint8Array([offset + 55 + body.length, ...body]));
  }

  /** One item in `form` (its children in the shortest): `wrapped` is a
   * single byte below 0x80 behind a one-byte header, which the shortest
   * form leaves bare. */
  function encodeItem(value, form) {
    if (form === 'shortest') return encodeRlp(value);
    if (Array.isArray(value)) {
      const payload = value.map((child) => bare(encodeRlp(child))).join('');
      return header(0xc0, payload.length / 2, form) + payload;
    }
    const length = bare(value).length / 2;
    if (form === 'wrapped') {
      assert.ok(length === 1 && parseInt(bare(value), 16) < 0x80, 'wrapped needs a byte below 0x80');
      return header(0x80, 1, 'shortest') + bare(value);
    }
    return header(0x80, length, form) + bare(value);
  }

  /** `raw` with field `index` written in `form`. */
  function fieldForm(raw, index, form) {
    const { prefix, fields } = split(raw);
    const payload = fields.map((field, i) => bare(i === index ? encodeItem(field, form) : encodeRlp(field))).join('');
    return prefix + bare(header(0xc0, payload.length / 2, 'shortest')) + payload;
  }

  /** `raw` with its outer list's header in `form`. */
  function listForm(raw, form) {
    const { prefix, fields } = split(raw);
    const payload = fields.map((field) => bare(encodeRlp(field))).join('');
    return prefix + bare(header(0xc0, payload.length / 2, form)) + payload;
  }

  return { split, join, withField, withFields, fieldForm, listForm, uint, word, bare, header };
}

/** Lists nested `depth` deep around an empty string. */
function nested(depth) {
  let value = '0x';
  for (let i = 0; i < depth; i += 1) value = [value];
  return value;
}

async function buildTransactionDecoding(ethers, wallet, signed) {
  const c = coder(ethers);
  const { uint, word, withField, withFields, fieldForm, listForm, split } = c;
  const sign = (tx) => wallet.signTransaction(tx);
  /** A transaction of a type the store refuses, signed through ethers'
   * Transaction object, which Wallet.signTransaction also uses. */
  const signOther = (tx) => {
    const btx = ethers.Transaction.from(tx);
    btx.signature = wallet.signingKey.sign(btx.unsignedHash);
    return btx.serialized;
  };

  const legacy = await sign({ type: 0, chainId: 1, nonce: 5, gasLimit: 21000, to: ADDRESS, value: 10n ** 18n, data: '0x', gasPrice: 20000000000n });
  const pre155 = await sign({ type: 0, chainId: 0, nonce: 5, gasLimit: 21000, to: ADDRESS, value: 10n ** 18n, data: '0x', gasPrice: 20000000000n });
  const legacyCreate = await sign({ type: 0, chainId: 11155111, nonce: 0, gasLimit: 53000, to: null, value: 0, data: '0x00', gasPrice: 1000000000n });
  const accessList = [{ address: TOKEN, storageKeys: [SLOT('01'), SLOT('ab')] }, { address: ADDRESS, storageKeys: [] }];
  const eip1559 = await sign({
    type: 2, chainId: 1, nonce: 7, gasLimit: 100000, to: TOKEN, value: 0, data: TRANSFER,
    maxFeePerGas: 30000000000n, maxPriorityFeePerGas: 1500000000n, accessList,
  });
  const eip1559Create = await sign({ type: 2, chainId: 100, nonce: 0, gasLimit: 100000, to: null, value: 0, data: '0x6080', maxFeePerGas: 2, maxPriorityFeePerGas: 0 });
  const longData = await sign({ type: 2, chainId: 1, nonce: 1, gasLimit: 50000, to: ADDRESS, value: 0, data: '0x' + 'ab'.repeat(100), maxFeePerGas: 2, maxPriorityFeePerGas: 1 });
  const eip2930 = signOther({ type: 1, chainId: 1, nonce: 1, gasLimit: 30000, to: ADDRESS, value: 0, data: '0x', gasPrice: 1, accessList });
  const eip4844 = signOther({
    type: 3, chainId: 1, nonce: 1, gasLimit: 30000, to: ADDRESS, value: 0, data: '0x', maxFeePerGas: 2, maxPriorityFeePerGas: 1,
    maxFeePerBlobGas: 1, blobVersionedHashes: ['0x01' + '11'.repeat(31)],
  });
  const eip7702 = signOther({
    type: 4, chainId: 1, nonce: 1, gasLimit: 60000, to: ADDRESS, value: 0, data: '0x', maxFeePerGas: 2, maxPriorityFeePerGas: 1,
    authorizationList: [wallet.authorizeSync({ address: TOKEN, nonce: 2, chainId: 1 })],
  });

  const L = split(legacy).fields;
  const E = split(eip1559).fields;
  const legacyS = BigInt(L[8]);
  const eipS = BigInt(E[11]);
  // A high s of the same signature: n - s with the other parity.
  assert.ok(N - eipS >= 2n ** 255n, 'the EIP-1559 base needs an s whose high form is 2^255 or more');
  const flippedV = BigInt(L[6]) === 37n ? 38n : 37n;
  // The smallest r that is no point's x-coordinate: ethers' recovery
  // throws for it.
  let offCurve = 1n;
  for (;; offCurve += 1n) {
    try {
      ethers.SigningKey.recoverPublicKey(ethers.keccak256('0x'), { r: word(offCurve), s: word(1n), v: 27 });
    } catch {
      break;
    }
  }
  const sigWith = (base, r, s) => withFields(base, [...split(base).fields.slice(0, -2), r, s]);

  const cases = [
    // What signing makes, every case of `transactions` ethers signed.
    ...signed.map(({ id, raw }) => [`signed/${id}`, raw]),

    // Bases.
    ['legacy-eip155', legacy],
    ['legacy-pre-eip155', pre155],
    ['legacy-create', legacyCreate],
    ['eip1559-access-list', eip1559],
    ['eip1559-create', eip1559Create],
    ['eip1559-long-data', longData],

    // The first byte.
    ['empty', '0x'],
    ['type-2-alone', '0x02'],
    ['type-0', '0x00' + c.bare(eip1559).slice(2)],
    ['type-5', '0x05' + c.bare(eip1559).slice(2)],
    ['type-7e', '0x7e' + c.bare(eip1559).slice(2)],
    ['byte-7f', '0x7f'],
    ['legacy-byte-string', ethers.encodeRlp('0x' + 'aa'.repeat(10))],
    ['eip1559-byte-string', '0x02' + c.bare(ethers.encodeRlp('0x' + 'aa'.repeat(10)))],
    ['eip2930-signed', eip2930],
    ['eip2930-unsigned', withFields(eip2930, split(eip2930).fields.slice(0, 8))],
    ['eip2930-empty-list', '0x01c0'],
    ['eip2930-alone', '0x01'],
    ['eip4844-signed', eip4844],
    ['eip4844-alone', '0x03'],
    ['eip7702-signed', eip7702],
    ['eip7702-alone', '0x04'],

    // Whole-input structure.
    ['legacy-trailing-byte', legacy + '00'],
    ['eip1559-trailing-byte', eip1559 + '00'],
    ['legacy-truncated', legacy.slice(0, -2)],
    ['eip1559-truncated', eip1559.slice(0, -2)],
    ['legacy-list-length-padded', listForm(legacy, 'padded')],
    ['eip1559-list-length-padded', listForm(eip1559, 'padded')],
    // At 56 bytes or more, the long form is the shortest.
    ['eip1559-create-list-long-form', listForm(eip1559Create, 'long')],
    // The outer list one byte short: its last child runs past it.
    ['legacy-child-past-list', (() => {
      const { fields } = split(legacy);
      const payload = fields.map((field) => c.bare(ethers.encodeRlp(field))).join('');
      return c.header(0xc0, payload.length / 2 - 1, 'shortest') + payload;
    })()],

    // Field counts.
    ['legacy-6-fields', withFields(legacy, L.slice(0, 6))],
    ['legacy-7-fields', withFields(legacy, L.slice(0, 7))],
    ['legacy-8-fields', withFields(legacy, L.slice(0, 8))],
    ['legacy-10-fields', withFields(legacy, [...L, '0x'])],
    ['legacy-r-s-zero', sigWith(legacy, '0x', '0x')],
    ['legacy-r-s-zero-padded', sigWith(legacy, word(0n), word(0n) + '00')],
    // With r and s zero, ethers reads v as the chain id and checks nothing.
    ['legacy-r-s-zero-v-0', withFields(legacy, [...L.slice(0, 6), '0x', '0x', '0x'])],
    ['legacy-6-fields-bad-to', withFields(legacy, [...L.slice(0, 3), '0x' + '11'.repeat(19), ...L.slice(4, 6)])],
    ['eip1559-9-fields', withFields(eip1559, E.slice(0, 9))],
    ['eip1559-10-fields', withFields(eip1559, E.slice(0, 10))],
    ['eip1559-11-fields', withFields(eip1559, E.slice(0, 11))],
    ['eip1559-13-fields', withFields(eip1559, [...E, '0x'])],
    ['eip1559-9-fields-bad-access-list', withFields(eip1559, [...E.slice(0, 8), '0x'])],

    // Byte-string forms (the shortest form re-serializes differently).
    ['legacy-nonce-wrapped', fieldForm(legacy, 0, 'wrapped')],
    ['legacy-nonce-long-form', fieldForm(legacy, 0, 'long')],
    ['legacy-value-long-form', fieldForm(legacy, 4, 'long')],
    // 68 bytes: the long form is the shortest.
    ['eip1559-data-long-form', fieldForm(eip1559, 7, 'long')],
    ['legacy-create-data-long-form', fieldForm(legacyCreate, 5, 'long')],
    ['legacy-create-data-wrapped', fieldForm(legacyCreate, 5, 'wrapped')],
    ['eip1559-create-access-list-long-form', fieldForm(eip1559Create, 8, 'long')],
    ['eip1559-access-list-padded', fieldForm(eip1559, 8, 'padded')],
    ['eip1559-to-long-form', fieldForm(eip1559, 5, 'long')],
    ['eip1559-y-parity-long-form', fieldForm(eip1559, 9, 'long')],
    ['eip1559-long-data-length-padded', fieldForm(longData, 7, 'padded')],
    ['eip1559-nonce-zero-long-form', fieldForm(eip1559Create, 1, 'long')],

    // Integers.
    ['legacy-nonce-leading-zero', withField(legacy, 0, '0x0005')],
    ['legacy-nonce-zero-byte', withField(legacy, 0, '0x00')],
    ['legacy-gas-price-leading-zero', withField(legacy, 1, '0x00' + c.bare(L[1]))],
    ['eip1559-chain-leading-zero', withField(eip1559, 0, '0x0001')],
    ['eip1559-gas-limit-leading-zero', withField(eip1559, 4, '0x00' + c.bare(E[4]))],
    ['eip1559-value-33-bytes-leading-zero', withField(eip1559, 6, '0x00' + 'ff'.repeat(32))],
    ['eip1559-value-33-bytes', withField(eip1559, 6, '0x01' + '00'.repeat(32))],
    ['eip1559-value-max', withField(eip1559, 6, uint(2n ** 256n - 1n))],
    ['eip1559-nonce-max-safe', withField(eip1559, 1, uint(2n ** 53n - 1n))],
    ['eip1559-nonce-2-53', withField(eip1559, 1, uint(2n ** 53n))],
    ['legacy-nonce-2-53', withField(legacy, 0, uint(2n ** 53n))],
    ['eip1559-chain-zero', withField(eip1559, 0, '0x')],
    ['eip1559-chain-max', withField(eip1559, 0, uint(2n ** 256n - 1n))],
    ['eip1559-chain-2-256', withField(eip1559, 0, uint(2n ** 256n))],
    ['eip1559-gas-limit-list', withField(eip1559, 4, [])],

    // Legacy v.
    ...[0n, 1n, 26n, 27n, 28n, 29n, 34n, 35n, 36n, 37n, 38n, 2n ** 256n - 1n, 2n ** 256n].map((v) =>
      [`legacy-v-${v < 1000n ? v : (v === 2n ** 256n ? '2-256' : 'max')}`, withField(legacy, 6, uint(v))]),
    ['legacy-v-leading-zero', withField(legacy, 6, '0x00' + c.bare(L[6]))],
    ['legacy-v-list', withField(legacy, 6, [])],
    ['pre155-v-flipped', withField(pre155, 6, uint(BigInt(split(pre155).fields[6]) === 27n ? 28n : 27n))],

    // EIP-1559 y parity.
    ['eip1559-y-parity-2', withField(eip1559, 9, uint(2n))],
    ['eip1559-y-parity-zero-byte', withField(eip1559, 9, '0x00')],
    ['eip1559-y-parity-leading-zero', withField(eip1559, 9, '0x0001')],
    ['eip1559-y-parity-list', withField(eip1559, 9, [])],
    ['eip1559-y-parity-flipped', withField(eip1559, 9, BigInt(E[9]) === 0n ? '0x01' : '0x')],

    // r and s: forms.
    ['legacy-r-33-bytes', withField(legacy, 7, '0x00' + c.bare(L[7]))],
    ['legacy-r-padded-32', withField(legacy, 7, word(BigInt(L[7]) >> 8n))],
    ['eip1559-r-33-bytes', withField(eip1559, 10, '0x00' + c.bare(E[10]))],
    ['eip1559-r-padded-32', withField(eip1559, 10, word(BigInt(E[10]) >> 8n))],
    ['eip1559-s-padded-32', withField(eip1559, 11, word(eipS >> 8n))],
    ['legacy-r-list', withField(legacy, 7, [])],
    ['eip1559-s-list', withField(eip1559, 11, [])],

    // r and s: values. A high s keeps its signer; values with no signer
    // still pass the store's verifySigned.
    ['legacy-high-s', withFields(legacy, [...L.slice(0, 6), uint(flippedV), L[7], uint(N - legacyS)])],
    ['pre155-high-s', (() => {
      const P = split(pre155).fields;
      return withFields(pre155, [...P.slice(0, 6), uint(BigInt(P[6]) === 27n ? 28n : 27n), P[7], uint(N - BigInt(P[8]))]);
    })()],
    ['eip1559-high-s', withFields(eip1559, [...E.slice(0, 9), BigInt(E[9]) === 0n ? '0x01' : '0x', E[10], uint(N - eipS)])],
    ...[
      ['half', HALF], ['half-plus-1', HALF + 1n], ['2-255-minus-1', 2n ** 255n - 1n], ['2-255', 2n ** 255n],
      ['n-minus-1', N - 1n], ['n', N], ['max', 2n ** 256n - 1n], ['zero', 0n], ['one', 1n],
    ].flatMap(([name, s]) => [
      [`legacy-s-${name}`, sigWith(legacy, L[7], uint(s))],
      [`eip1559-s-${name}`, sigWith(eip1559, E[10], uint(s))],
    ]),
    ...[
      ['zero', 0n], ['one', 1n], ['n', N], ['max', 2n ** 256n - 1n], ['off-curve', offCurve],
    ].flatMap(([name, r]) => [
      [`legacy-r-${name}`, sigWith(legacy, uint(r), L[8])],
      [`eip1559-r-${name}`, sigWith(eip1559, uint(r), E[11])],
    ]),
    ['eip1559-r-s-zero', sigWith(eip1559, '0x', '0x')],

    // Addresses.
    ['legacy-to-empty', withField(legacy, 3, '0x')],
    ['legacy-to-19-bytes', withField(legacy, 3, '0x' + '11'.repeat(19))],
    ['legacy-to-21-bytes', withField(legacy, 3, '0x' + '11'.repeat(21))],
    ['eip1559-to-empty', withField(eip1559, 5, '0x')],
    ['eip1559-to-list', withField(eip1559, 5, [])],

    // Data.
    ['legacy-data-list', withField(legacy, 5, [])],
    ['eip1559-data-nested-64', withField(eip1559, 7, nested(64))],

    // The access list.
    ['eip1559-access-list-empty', withField(eip1559, 8, [])],
    ['eip1559-access-list-bytes', withField(eip1559, 8, '0x')],
    ['eip1559-access-entry-bytes', withField(eip1559, 8, [TOKEN])],
    ['eip1559-access-entry-1-item', withField(eip1559, 8, [[TOKEN]])],
    ['eip1559-access-entry-3-items', withField(eip1559, 8, [[TOKEN, [], []]])],
    ['eip1559-access-address-19-bytes', withField(eip1559, 8, [['0x' + '11'.repeat(19), []]])],
    ['eip1559-access-address-empty', withField(eip1559, 8, [['0x', []]])],
    ['eip1559-access-address-list', withField(eip1559, 8, [[[], []]])],
    ['eip1559-access-keys-bytes', withField(eip1559, 8, [[TOKEN, SLOT('01')]])],
    ['eip1559-access-key-31-bytes', withField(eip1559, 8, [[TOKEN, ['0x' + '01'.repeat(31)]]])],
    ['eip1559-access-key-33-bytes', withField(eip1559, 8, [[TOKEN, ['0x' + '01'.repeat(33)]]])],
    ['eip1559-access-key-empty', withField(eip1559, 8, [[TOKEN, ['0x']]])],
    ['eip1559-access-key-list', withField(eip1559, 8, [[TOKEN, [[]]]])],
    ['eip1559-access-many', withField(eip1559, 8, Array.from({ length: 5 }, (_, i) => [TOKEN, Array.from({ length: i }, (_, j) => SLOT((16 * i + j).toString(16).padStart(2, '0')))]))],

    // Fees.
    ['eip1559-priority-above-max', withField(eip1559, 2, uint(BigInt(E[3]) + 1n))],
    ['eip1559-priority-equal-max', withField(eip1559, 2, E[3])],
    ['eip1559-priority-above-max-unsigned', withFields(eip1559, [...E.slice(0, 2), uint(BigInt(E[3]) + 1n), ...E.slice(3, 9)])],
  ];

  const ids = new Set();
  return cases.map(([id, raw]) => {
    assert.ok(!ids.has(id), `duplicate case ${id}`);
    ids.add(id);
    assert.match(raw, /^0x(?:[0-9a-f]{2})*$/, `${id}: the store's HEX_PATTERN`);
    const result = verdict(ethers, raw);
    const first = raw.length >= 4 ? parseInt(raw.slice(2, 4), 16) : null;
    const deviation = OTHER_TYPES.includes(first) && result.verdict !== 'unsupported_type';
    return {
      id, raw, result,
      ...(deviation ? { deviation: 'tx-other-types', core: { verdict: 'unsupported_type', type: first } } : {}),
    };
  });
}

module.exports = { buildTransactionDecoding };
