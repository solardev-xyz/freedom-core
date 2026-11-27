'use strict';

// Design 0016's APDU grammar ("The APDU grammar", "Bounds"), written from the
// design: the encoder every operation's honest stream comes from, the rows as
// data, and the check every APDU ledger.json records passes. The encoder is
// the design's, not hw-app-eth's: it cuts every value in pieces of 255, counts
// a name's length in bytes, and refuses what a Ledger can't carry. Its
// `reference` mode applies exactly the faults design 0016's F-2 names, so a
// recorded stream that differs from the honest one is explained by the
// case's deviation, byte for byte, or the run fails.

const assert = require('node:assert/strict');

const HARD = 0x80000000;
const MAX_INDEX = 2 ** 31 - 1;
const MAX_APDUS = 2048;
const MAX_CHECKS = 20;
const MAX_VALUE = 65535;
const NAME = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

class Refused extends Error {
  constructor(deviation, reason) {
    super(reason);
    this.deviation = deviation;
  }
}

/**
 * A path in one of the two schemes' forms: `44'/60'/i'/0/0` (live) or
 * `44'/60'/0'/i` (legacy), i from 0 to 2^31 − 1, as data (`n`, then each
 * element big-endian, 0x80000000 set when hardened). Anything else is
 * refused (deviation path-strict).
 */
function schemePath(path) {
  const live = /^44'\/60'\/(0|[1-9][0-9]*)'\/0\/0$/.exec(path);
  const legacy = /^44'\/60'\/0'\/(0|[1-9][0-9]*)$/.exec(path);
  const i = live ? Number(live[1]) : legacy ? Number(legacy[1]) : NaN;
  if (!(i >= 0 && i <= MAX_INDEX)) throw new Refused('path-strict', `not a scheme's path: ${path}`);
  const elements = live ? [44 + HARD, 60 + HARD, i + HARD, 0, 0] : [44 + HARD, 60 + HARD, HARD, i];
  const out = Buffer.alloc(1 + 4 * elements.length);
  out[0] = elements.length;
  elements.forEach((e, k) => out.writeUInt32BE(e, 1 + 4 * k));
  return out;
}

const SCHEMES = {
  live: (i) => `44'/60'/${i}'/0/0`,
  legacy: (i) => `44'/60'/0'/${i}`,
};

function apdu(cla, ins, p1, p2, data = Buffer.alloc(0)) {
  if (data.length > 255) throw new Refused('device-bounds', `an APDU's data of ${data.length} bytes`);
  return Buffer.concat([Buffer.from([cla, ins, p1, p2, data.length]), data]);
}

const bounded = (apdus) => {
  if (apdus.length > MAX_APDUS) throw new Refused('device-bounds', `${apdus.length} APDUs`);
  return apdus;
};

/** `ledger.accounts`: c × `E0 02 00 00 P(path_k)`. */
function accountsStream({ scheme, start, count }) {
  const build = SCHEMES[scheme];
  assert.ok(build && count >= 1 && count <= 20);
  return Array.from({ length: count }, (_, k) => apdu(0xe0, 0x02, 0x00, 0x00, schemePath(build(start + k))));
}

/**
 * `ledger.accounts`' check of the Ledger records no device has matched
 * (D1): `E0 02 00 00 P(path_j)` at each record's path, in the wallet list's
 * order, display off. Only a scheme's path is read (path-strict), and at
 * most 20 (check-bound): `skipped` names the deviations that left a record
 * unread.
 */
function checkStream(paths) {
  const apdus = [];
  const skipped = new Set();
  for (const p of paths) {
    let bytes;
    try {
      bytes = schemePath(p);
    } catch (err) {
      if (!(err instanceof Refused)) throw err;
      skipped.add(err.deviation);
      continue;
    }
    if (apdus.length === MAX_CHECKS) {
      skipped.add('check-bound');
      continue;
    }
    apdus.push(apdu(0xe0, 0x02, 0x00, 0x00, bytes));
  }
  return { apdus, skipped };
}

/** The paths account-checks.js reads: each listed record's with a path and an address, both strings. */
const checkedPaths = (records = []) => records
  .filter((r) => typeof r.path === 'string' && r.path && typeof r.address === 'string')
  .map((r) => r.path);

/** `ledger.add`: `E0 02 01 00 P`, the display on (question 3). */
const addStream = (path) => [apdu(0xe0, 0x02, 0x01, 0x00, schemePath(path))];

/** Every signature's first two: the address check, then the app's name and version. */
const signatureHead = (path) => [apdu(0xe0, 0x02, 0x00, 0x00, schemePath(path)), apdu(0xb0, 0x01, 0x00, 0x00)];

/**
 * The piece size of `P ‖ T`: 255, but for a legacy transaction the size
 * hw-app-eth's safeChunkTransaction picks so that no piece ends where a
 * legacy transaction could (the design's row).
 */
function pieceSize(ethers, payloadLength, t, type) {
  if (payloadLength <= 255 || type !== 0) return 255;
  const fields = ethers.decodeRlp(t);
  const vrs = Buffer.from(ethers.getBytes(ethers.encodeRlp(fields.slice(-3)))).subarray(1).length;
  const fine = (size) => payloadLength % size === 0 || payloadLength % size > vrs;
  for (let size = 255; size > 0; size--) if (fine(size)) return size;
  throw new Error('no piece size');
}

/** `sign.transaction`'s pieces of `P ‖ T`, T the unsigned serialization. */
function transactionStream(ethers, path, unsignedHex, type) {
  const t = Buffer.from(unsignedHex.slice(2), 'hex');
  const payload = Buffer.concat([schemePath(path), t]);
  const size = pieceSize(ethers, payload.length, t, type);
  const out = [];
  for (let at = 0; at < payload.length; at += size) {
    out.push(apdu(0xe0, 0x04, at === 0 ? 0x00 : 0x80, 0x00, payload.subarray(at, at + size)));
  }
  return bounded(out);
}

/** `sign.message`: `P ‖ len(m) ‖` the first 150 − 5 − 4n bytes, then 150 at a time. */
function messageStream(path, m) {
  if (m.length === 0) throw new Refused('empty-message', 'an empty message');
  const p = schemePath(path);
  const first = 150 - 1 - 4 * p[0] - 4;
  const length = Buffer.alloc(4);
  length.writeUInt32BE(m.length);
  const out = [apdu(0xe0, 0x08, 0x00, 0x00, Buffer.concat([p, length, m.subarray(0, first)]))];
  for (let at = first; at < m.length; at += 150) out.push(apdu(0xe0, 0x08, 0x80, 0x00, m.subarray(at, at + 150)));
  return bounded(out);
}

// hw-app-eth's EIP712_TYPE_PROPERTIES keys (EIP712/utils.js:28–56).
const KEYS = { custom: 0, int: 1, uint: 2, address: 3, bool: 4, string: 5, bytesN: 6, bytes: 7 };

/** A type string as `{ base, kind, bits|size, dims: [null | n, …] }`. */
function parseType(type, types) {
  const m = /^([^[\]]+)((?:\[\d*\])*)$/.exec(type);
  assert.ok(m, `a type: ${type}`);
  const dims = [...m[2].matchAll(/\[(\d*)\]/g)].map(([, n]) => (n === '' ? null : Number(n)));
  const base = m[1];
  let kind;
  let size = null;
  let r;
  if (Object.hasOwn(types, base)) kind = 'custom';
  else if ((r = /^(u?)int(\d+)$/.exec(base))) [kind, size] = [r[1] ? 'uint' : 'int', Number(r[2]) / 8];
  else if ((r = /^bytes(\d+)$/.exec(base))) [kind, size] = ['bytesN', Number(r[1])];
  else if (['address', 'bool', 'string', 'bytes'].includes(base)) kind = base;
  else throw new Error(`a type the encoder doesn't know: ${type}`);
  return { base, kind, size, dims };
}

/**
 * A one-byte length, as the design writes it, or as hw-app-eth's
 * `intAsHexBytes(n, 1)` does in reference mode (F-2: its hex cut to one
 * byte, the odd digit dropped).
 */
function lengthByte(n, mode, what) {
  if (mode === 'reference') return Buffer.from(n.toString(16).padStart(2, '0'), 'hex');
  if (n > 255) throw new Refused('device-bounds', `${what} of ${n}`);
  return Buffer.from([n]);
}

/** A name's length byte: its bytes (names are ASCII), or its UTF-16 units in reference mode (F-2). */
function nameLength(name, mode) {
  if (mode === 'reference') return lengthByte(name.length, mode);
  return lengthByte(Buffer.byteLength(name, 'utf8'), mode, 'a name');
}

/** A field's descriptor: type byte, a custom type's name, the size, the dimensions, the name. */
function descriptor({ name, type }, types, mode) {
  const t = parseType(type, types);
  const hasSize = t.size !== null;
  const parts = [Buffer.from([(t.dims.length ? 0x80 : 0) | (hasSize ? 0x40 : 0) | KEYS[t.kind]])];
  if (t.kind === 'custom') parts.push(nameLength(t.base, mode), Buffer.from(t.base, 'utf8'));
  if (hasSize) parts.push(lengthByte(t.size, mode, 'a size'));
  if (t.dims.length) {
    parts.push(lengthByte(t.dims.length, mode, 'a number of dimensions'));
    for (const d of t.dims) parts.push(d === null ? Buffer.from([0]) : Buffer.concat([Buffer.from([1]), lengthByte(d, mode, 'a fixed size')]));
  }
  parts.push(nameLength(name, mode), Buffer.from(name, 'utf8'));
  return Buffer.concat(parts);
}

const minimalBytes = (n) => {
  const hex = n.toString(16);
  return Buffer.from(hex.length % 2 ? '0' + hex : hex, 'hex');
};
const hexBytes = (text) => {
  const hex = String(text).replace(/^0x/, '');
  return Buffer.from(hex.length % 2 ? '0' + hex : hex, 'hex');
};

/** A value as hw-app-eth's EIP712_TYPE_ENCODERS encode it (EIP712/utils.js:62–102). */
function encodeValue(t, value) {
  switch (t.kind) {
    case 'int': case 'uint': {
      let n = BigInt(value);
      if (n < 0n) n += 1n << BigInt(8 * t.size);
      return minimalBytes(n);
    }
    case 'bool': return minimalBytes(BigInt(typeof value === 'boolean' ? Number(value) : value));
    case 'address': return hexBytes(value).subarray(0, 20);
    case 'string': return Buffer.from(value, 'utf8');
    case 'bytesN': return hexBytes(value).subarray(0, t.size);
    case 'bytes': return hexBytes(value);
    default: throw new Error(`no encoder for ${t.kind}`);
  }
}

/**
 * A value's APDUs: its encoding (2-byte length ‖ value) in pieces of 255,
 * `E0 1C 01 FF` for each but the last and `E0 1C 00 FF` for the last; in
 * reference mode cut as hw-app-eth cuts it, ceil(length / 256) pieces of 255
 * (F-2: a value of 255·n + 1 to 256·n bytes loses its last bytes).
 */
function valueApdus(bytes, mode) {
  if (mode !== 'reference' && bytes.length > MAX_VALUE) throw new Refused('device-bounds', `a value of ${bytes.length} bytes`);
  const length = mode === 'reference'
    ? Buffer.concat([lengthByte(Math.floor(bytes.length / 256), mode), lengthByte(bytes.length % 256, mode)])
    : Buffer.from([bytes.length >> 8, bytes.length & 0xff]);
  const data = Buffer.concat([length, bytes]);
  const count = mode === 'reference' ? Math.ceil(data.length / 256) : Math.ceil(data.length / 255);
  return Array.from({ length: count }, (_, i) => apdu(0xe0, 0x1c, i < count - 1 ? 0x01 : 0x00, 0xff, data.subarray(i * 255, (i + 1) * 255)));
}

/**
 * `sign.typed_data`'s stream, from ethers' `getPayload` of the bound typed
 * data (the design's parse; equal to the core's for every case 0002
 * accepts): the definitions, the values depth first, and `E0 0C 00 01 P`.
 * `mode`: 'design' (the core's) or 'reference' (hw-app-eth's, F-2's faults).
 */
function typedDataStream(ethers, path, typedData, mode = 'design') {
  const { payload } = typedPayload(ethers, typedData);
  const types = payload.types;
  if (mode === 'design') {
    for (const [name, fields] of Object.entries(types)) {
      for (const n of [name, ...fields.map((f) => f.name)]) {
        if (!NAME.test(n)) throw new Refused('name-ascii', `a name outside 0002's identifiers: ${JSON.stringify(n)}`);
        if (n.length > 255) throw new Refused('device-bounds', `a name of ${n.length} characters`);
      }
    }
  }
  const out = [];
  // Ascending by name, as evm-tools' sortObjectAlphabetically sorts them.
  const definitions = () => {
    for (const name of Object.keys(types).sort()) {
      out.push(apdu(0xe0, 0x1a, 0x00, 0x00, Buffer.from(name, 'utf8')));
      for (const field of types[name]) out.push(apdu(0xe0, 0x1a, 0x00, 0xff, descriptor(field, types, mode)));
    }
  };
  const walk = (type, value) => {
    const t = parseType(type, types);
    if (t.dims.length) {
      const inner = type.slice(0, type.lastIndexOf('['));
      assert.ok(Array.isArray(value));
      out.push(apdu(0xe0, 0x1c, 0x00, 0x0f, lengthByte(value.length, mode, 'an array of length')));
      for (const entry of value) walk(inner, entry);
    } else if (t.kind === 'custom') {
      for (const field of types[t.base]) walk(field.type, value[field.name]);
    } else {
      out.push(...valueApdus(encodeValue(t, value), mode));
    }
  };
  const values = () => {
    out.push(apdu(0xe0, 0x1c, 0x00, 0x00, Buffer.from('EIP712Domain', 'utf8')));
    for (const field of types.EIP712Domain) walk(field.type, payload.domain[field.name]);
    out.push(apdu(0xe0, 0x1c, 0x00, 0x00, Buffer.from(payload.primaryType, 'utf8')));
    // hw-app-eth walks an array's entries by the value (data.length at each
    // level), as this walk does, peeling the last dimension.
    for (const field of types[payload.primaryType]) walk(field.type, payload.message[field.name]);
    out.push(apdu(0xe0, 0x0c, 0x00, 0x01, schemePath(path)));
  };
  if (mode === 'design') {
    definitions();
    values();
    return bounded(out);
  }
  // hw-transport refuses an APDU whose data is 256 bytes or more
  // (DataLengthTooBig) before it reaches the device: the stream ends there.
  try {
    definitions();
    values();
  } catch (err) {
    if (!(err instanceof Refused)) throw err;
    out.tooBig = err.message;
  }
  return out;
}

/** The typed data's payload (`getPayload`), its hash and its two hash-only hashes. */
function typedPayload(ethers, typedData) {
  const { TypedDataEncoder } = ethers;
  const types = { ...typedData.types };
  delete types.EIP712Domain;
  const domain = typedData.domain || {};
  const payload = TypedDataEncoder.getPayload(domain, types, typedData.message);
  return {
    payload,
    hash: TypedDataEncoder.hash(domain, types, typedData.message),
    domainSeparator: TypedDataEncoder.hashDomain(payload.domain),
    structHash: TypedDataEncoder.from(types).hash(typedData.message),
  };
}

/** The hash-only form (Q23): `E0 0C 00 00 P ‖ domainSeparator ‖ hashStruct(message)`. */
function hashOnlyApdu(ethers, path, typedData) {
  const { domainSeparator, structHash } = typedPayload(ethers, typedData);
  return apdu(0xe0, 0x0c, 0x00, 0x00, Buffer.concat([schemePath(path), hexBytes(domainSeparator), hexBytes(structHash)]));
}

const header = (a) => a.subarray(0, 4).toString('hex');

module.exports = {
  Refused, schemePath, SCHEMES, apdu, accountsStream, checkStream, checkedPaths, addStream, signatureHead, transactionStream, messageStream,
  typedDataStream, typedPayload, hashOnlyApdu, parseType, descriptor, header, NAME, MAX_APDUS, MAX_VALUE, MAX_CHECKS,
};
