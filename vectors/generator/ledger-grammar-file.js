'use strict';

// vectors/ledger-grammar.json (design 0016, "The APDU grammar"): the rows as
// data, the check every APDU ledger.json records passes, each case's honest
// stream (the core's), and the forbidden APDUs main's relay must refuse.

const assert = require('node:assert/strict');
const g = require('./ledger-grammar');

const hexOf = (b) => Buffer.from(b).toString('hex');
const headerOf = (h) => h.slice(0, 8);

// The rows, as the design's table has them.
const ROWS = [
  { row: 'ledger.accounts', apdus: [{ header: 'e0020000', data: 'P(path_k)', times: 'c, 1 to 20' }, { header: 'e0020000', data: 'P(path_j)', times: 'r, 0 to 20' }],
    from: "the scheme's paths for start … start + c − 1; then the path of each Ledger record no device has matched (unchecked or mismatched), in the wallet list's order, at most 20 (D1)", waits: false },
  { row: 'ledger.add', apdus: [{ header: 'e0020100', data: 'P', times: 1 }], from: 'the path asked (question 3)', waits: true },
  { row: 'signature.first', apdus: [{ header: 'e0020000', data: 'P', times: 1 }], from: "the record's path", waits: false },
  { row: 'signature.second', apdus: [{ header: 'b0010000', data: '', times: 1 }], from: '—', waits: false },
  { row: 'sign.transaction', apdus: [{ header: 'e0040000', data: 'the first piece of P ‖ T', times: 1 }, { header: 'e0048000', data: 'each other piece', times: 'the rest' }],
    from: 'the bound transaction (its nonce main chose); pieces of 255, for type 0 the size hw-app-eth\'s safeChunkTransaction picks', waits: 'the last piece' },
  { row: 'sign.message', apdus: [{ header: 'e0080000', data: 'P ‖ len(m) (4 bytes) ‖ the first 150 − 5 − 4n bytes', times: 1 }, { header: 'e0088000', data: 'each next 150 bytes', times: 'the rest' }],
    from: 'the bound bytes m, at least 1', waits: 'the last' },
  { row: 'sign.typed_data.definitions', apdus: [{ header: 'e01a0000', data: "a type's name", times: 'each type, ascending' }, { header: 'e01a00ff', data: "a field's descriptor", times: 'each field in order' }],
    from: "the bound typed data's types, EIP712Domain from the domain's keys as getPayload builds it", waits: false },
  { row: 'sign.typed_data.values', apdus: [{ header: 'e01c0000', data: '"EIP712Domain", then the primary type\'s name', times: 2 }, { header: 'e01c000f', data: "an array's length", times: 'each array' },
    { header: 'e01c01ff', data: "a value's piece but the last", times: 'each but the last' }, { header: 'e01c00ff', data: "a value's last piece", times: 'each value' }],
    from: "the core's parse of the bound values, encoded as EIP712_TYPE_ENCODERS encode them, in pieces of 255", waits: false },
  { row: 'sign.typed_data.sign', apdus: [{ header: 'e00c0001', data: 'P', times: 1 }], from: "the record's path", waits: true },
  { row: 'hash-only', apdus: [{ header: 'e00c0000', data: 'P ‖ domainSeparator ‖ hashStruct(message)', times: 1 }],
    from: "fc-evm's hashes of the bound typed data; only after 6D00 answered the operation's first E0 1A and main answered hash_only: \"shown\"", waits: true },
  { row: 'x402.settle', apdus: 'as sign.typed_data, over the reserved authorization', from: 'main\'s own rebuild of it, which it sent as typed_data (x402.settle { reservation, typed_data }, a Ledger account, D2)', waits: true },
  { row: 'safe.sign_owner', apdus: 'as sign.typed_data, over the core\'s SafeTx', from: 'the approved SafeTx, which main derives from its own record', waits: true },
  { row: 'safe.message_sign', apdus: 'as sign.typed_data, over the core\'s SafeMessage', from: 'the session\'s SafeMessage, which main derives from the page\'s request it holds', waits: true },
];

const RULES = {
  parent: 'the APDU names a parent that is not live, not one of the rows\' operations, or not for a Ledger account',
  order: 'an APDU of the row out of its place: swapped, skipped, or the hash-only APDU without its 6D00 or before main\'s hash_only answer',
  header: 'CLA INS P1 P2 that the row doesn\'t have at that point (E0 02 01 00 outside ledger.add among them), or an Lc that isn\'t the data\'s length',
  count: 'an APDU the row sends once (the address check, B0 01, E0 0C), sent again',
  path: 'another path where the row has P',
  payload: 'the right header with other data: main\'s own stream, built from what it holds, has other bytes there',
  ended: 'any APDU after the operation\'s last',
};

/** Which row an APDU of an operation is in. */
function rowOf(operation, header, index) {
  if (operation === 'ledger.accounts') return 'ledger.accounts';
  if (operation === 'ledger.add') return 'ledger.add';
  if (index === 0 && header === 'e0020000') return 'signature.first';
  if (header === 'b0010000') return 'signature.second';
  if (header.startsWith('e004')) return 'sign.transaction';
  if (header.startsWith('e008')) return 'sign.message';
  if (header.startsWith('e01a')) return 'sign.typed_data.definitions';
  if (header.startsWith('e01c')) return 'sign.typed_data.values';
  if (header === 'e00c0001') return 'sign.typed_data.sign';
  if (header === 'e00c0000') return 'hash-only';
  return null;
}

/**
 * A case's streams: `honest`, the design's (null with `refused` when the core
 * refuses it before the first APDU), and `reference`, what the design says
 * the reference sends (its deviations applied), before any scripted fault.
 * `needs`: the deviations that make the two differ.
 */
function streams(env, c, recorded) {
  const { ethers } = env;
  const needs = new Set();
  let honest = null;
  let refused = null;
  const design = (fn) => {
    try {
      honest = fn();
    } catch (err) {
      if (!(err instanceof g.Refused)) throw err;
      refused = { deviation: err.deviation, reason: err.message };
      needs.add(err.deviation);
    }
  };
  let reference;
  const refPath = (p) => referencePath(p);
  const fault = c.device?.fault;
  switch (c.operation) {
    case 'ledger.accounts': {
      const { scheme, start, count } = c.request;
      // Then the check (D1): the records' paths, as the core reads them and
      // as account-checks.js does, every one in a second session.
      const paths = g.checkedPaths(recorded.records);
      const check = g.checkStream(paths);
      design(() => [...g.accountsStream(c.request), ...check.apdus]);
      for (const deviation of check.skipped) needs.add(deviation);
      reference = [];
      for (let k = 0; k < count; k++) {
        const p = refPath(g.SCHEMES[scheme](start + k));
        if (!p) break;
        reference.push(g.apdu(0xe0, 0x02, 0x00, 0x00, p));
      }
      if (reference.length === count) for (const p of paths) reference.push(g.apdu(0xe0, 0x02, 0x00, 0x00, refPath(p)));
      break;
    }
    case 'ledger.add': {
      design(() => g.addStream(c.request.path));
      needs.add('address-from-device');
      reference = [g.apdu(0xe0, 0x02, 0x00, 0x00, refPath(c.request.path))];
      break;
    }
    case 'sign.transaction': {
      const tx = c.request.tx;
      const unsigned = ethers.Transaction.from(env.toEthersTx(tx)).unsignedSerialized;
      design(() => [...g.signatureHead(c.record.path), ...g.transactionStream(ethers, c.record.path, unsigned, tx.type)]);
      needs.add('app-check');
      const pieces = g.transactionStream(ethers, c.record.path, unsigned, tx.type);
      const wide = BigInt(tx.chain_id) >= 2n ** 53n;
      if (wide) needs.add('chain-id-width');
      // hw-app-eth parses the transaction with ethers v5, whose toNumber
      // overflows: a type 2 fails before its first piece.
      reference = [g.signatureHead(c.record.path)[0], ...(wide && tx.type === 2 ? [] : pieces)];
      break;
    }
    case 'sign.message': {
      const m = Buffer.from(c.request.message.slice(2), 'hex');
      design(() => [...g.signatureHead(c.record.path), ...g.messageStream(c.record.path, m)]);
      needs.add('app-check');
      reference = [g.signatureHead(c.record.path)[0], ...(m.length ? g.messageStream(c.record.path, m) : [])];
      break;
    }
    case 'sign.typed_data': {
      const td = typedDataOf(c, recorded);
      design(() => [...g.signatureHead(c.record.path), ...g.typedDataStream(ethers, c.record.path, td)]);
      const ref = g.typedDataStream(ethers, c.record.path, td, 'reference');
      const full = [...g.signatureHead(c.record.path), ...ref];
      if (honest && !sameStreams(honest, full)) needs.add('field-pieces');
      // A 6D00 to an APDU of signEIP712Message: the reference sends the
      // hash-only form next. Only the first E0 1A's is the design's.
      const firstTypeName = 2;
      const fallbackAt = c.device?.fields === false ? firstTypeName
        : fault?.status === 0x6d00 && fault.at >= 1 && fault.at < full.length ? fault.at : null;
      if (fallbackAt !== null) {
        reference = [...full.slice(0, fallbackAt + 1), g.hashOnlyApdu(ethers, c.record.path, td)];
        if (fallbackAt !== firstTypeName) needs.add('blind-typed-data');
        if (honest) honest = [...honest.slice(0, firstTypeName + 1), g.hashOnlyApdu(ethers, c.record.path, td)];
      } else {
        reference = full;
        if (ref.tooBig) reference.tooBig = ref.tooBig;
      }
      break;
    }
    default: throw new Error(`no streams for ${c.operation}`);
  }
  // What the core refuses before its first APDU differs by that refusal alone.
  return { honest, refused, reference, needs: refused ? new Set([refused.deviation]) : needs };
}

/** hw-app-eth's splitPath (utils.js:52–67): a path's bytes as it sends them, or null where writeUInt32BE throws. */
function referencePath(p) {
  const elements = [];
  for (const part of p.split('/')) {
    let value = parseInt(part, 10);
    if (Number.isNaN(value)) continue;
    if (part.length > 1 && part[part.length - 1] === "'") value += 0x80000000;
    elements.push(value);
  }
  if (elements.some((e) => e > 0xffffffff)) return null;
  const out = Buffer.alloc(1 + 4 * elements.length);
  out[0] = elements.length;
  elements.forEach((e, k) => out.writeUInt32BE(e, 1 + 4 * k));
  return out;
}

const sameStreams = (a, b) => a.length === b.length && a.every((x, i) => x.equals(b[i]));

/** The typed data a case signs: its request's, or for x402 what @x402/evm handed the signer. */
function typedDataOf(c, recorded) {
  if (!c.x402) return c.request.typed_data;
  const asked = recorded.events.find((e) => e.typed_data);
  assert.ok(asked, `${c.id}: no typed data reached the signer`);
  return asked.typed_data;
}

/**
 * Check one recorded case against the grammar: its APDUs are the reference
 * stream the design predicts, up to where the case stopped, and every
 * deviation that makes them differ from the honest stream is marked.
 */
function checkCase(env, c, recorded) {
  const { honest, refused, reference, needs } = streams(env, c, recorded);
  const got = recorded.exchanges.map((e) => e.apdu);
  const want = reference.map(hexOf);
  const fault = c.device?.fault;
  let limit = want.length;
  if (fault && !(fault.status === 0x6d00 && c.operation === 'sign.typed_data' && fault.at >= 1)) limit = Math.min(limit, fault.at + 1);
  assert.ok(got.length <= limit, `${c.id}: ${got.length} APDUs where the grammar has at most ${limit}`);
  got.forEach((apdu, i) => assert.equal(apdu, want[i], `${c.id}: APDU ${i} isn't the grammar's (${rowOf(c.operation, headerOf(apdu), i)})`));
  // A fault in discovery's check ends the check, not discovery (D1).
  const checkFault = fault && c.operation === 'ledger.accounts' && fault.at >= c.request.count;
  if (recorded.result.status === 'success' && !checkFault) {
    assert.equal(got.length, want.length, `${c.id}: it signed before the grammar's last APDU`);
  } else if (!fault && got.length < want.length) {
    // An operation that stopped early: on a fault in an answer, a too-long
    // APDU, an input the reference refuses before its device, or a device
    // the run scripts as missing.
    assert.ok(c.device?.answerFault || reference.tooBig || needs.has('chain-id-width') || needs.has('path-strict')
      || needs.has('empty-message') || c.device?.open || recorded.result.code, `${c.id}: stopped at ${got.length} of ${want.length} with no cause`);
  }
  // A difference the run never reached isn't the case's: an app check
  // missing at APDU 1, the add's display at APDU 0, a value's cut where it
  // lies.
  if (got.length < 2) needs.delete('app-check');
  if (got.length < 1) needs.delete('address-from-device');
  if (needs.has('field-pieces')) {
    const at = firstDifference(honest, reference).at;
    if (got.length <= at) needs.delete('field-pieces');
  }
  // A record the core doesn't read, which the reference reads where the
  // run stopped before it.
  if (c.operation === 'ledger.accounts' && honest && (needs.has('check-bound') || needs.has('path-strict'))) {
    const diff = firstDifference(honest, reference);
    if (!diff || got.length <= diff.at) {
      needs.delete('check-bound');
      needs.delete('path-strict');
    }
  }
  const marks = new Set([c.deviation, ...(c.also || [])].filter(Boolean));
  if (!c.markless) for (const need of needs) assert.ok(marks.has(need), `${c.id}: differs from the honest stream by ${need}, which it doesn't mark`);
  return { honest, refused, needs, rows: got.map((h, i) => rowOf(c.operation, headerOf(h), i)) };
}

/** The deviations a case's recorded stream shows, which checkCase then requires it to mark. */
function streamDeviations(env, c, recorded) {
  return [...checkCase(env, { ...c, deviation: undefined, also: undefined, markless: true }, recorded).needs];
}

/** A name like `name`, of the same length, with each letter and digit moved one on. */
function rotate(name) {
  return [...name].map((ch) => {
    if (/[a-yA-Y0-8]/.test(ch)) return String.fromCharCode(ch.charCodeAt(0) + 1);
    if (ch === 'z') return 'a';
    if (ch === 'Z') return 'A';
    if (ch === '9') return '0';
    return ch;
  }).join('');
}

/** Another value of the same type whose encoding has the same length. */
function otherValue(type, value, types) {
  const t = g.parseType(type, types);
  if (t.dims.length) return value.map((v) => otherValue(type.slice(0, type.lastIndexOf('[')), v, types));
  if (t.kind === 'custom') return value;
  switch (t.kind) {
    case 'int': case 'uint': return (BigInt(value) ^ 1n).toString();
    case 'bool': return !(value === true || value === 'true');
    case 'address': return flipHex(value);
    case 'string': return rotate(String(value));
    case 'bytesN': case 'bytes': return String(value).length > 2 ? flipHex(value) : value;
    default: return value;
  }
}
const flipHex = (h) => {
  const b = Buffer.from(String(h).slice(2), 'hex');
  b[b.length - 1] ^= 1;
  return '0x' + b.toString('hex');
};

/**
 * Typed data of the same shape: every type and field name moved one letter
 * on (EIP712Domain's fixed), every value another of the same encoded length.
 */
function sameShape(ethers, typedData) {
  const { payload } = g.typedPayload(ethers, typedData);
  const rename = (n) => (n === 'EIP712Domain' ? n : rotate(n));
  const types = {};
  for (const [name, fields] of Object.entries(payload.types)) {
    if (name === 'EIP712Domain') continue;
    types[rename(name)] = fields.map((f) => {
      const t = g.parseType(f.type, payload.types);
      return { name: rename(f.name), type: t.kind === 'custom' ? rename(t.base) + f.type.slice(t.base.length) : f.type };
    });
  }
  const walk = (type, value) => {
    const t = g.parseType(type, payload.types);
    if (t.dims.length) return value.map((v) => walk(type.slice(0, type.lastIndexOf('[')), v));
    if (t.kind === 'custom') return Object.fromEntries(payload.types[t.base].map((f) => [rename(f.name), walk(f.type, value[f.name])]));
    return otherValue(type, value, payload.types);
  };
  const domain = {};
  for (const f of payload.types.EIP712Domain) {
    const v = payload.domain[f.name];
    domain[f.name] = f.name === 'chainId' ? (BigInt(v) ^ 1n).toString() : otherValue(f.type, v, payload.types);
  }
  const message = walk(payload.primaryType, payload.message);
  return { domain, types, primaryType: rename(payload.primaryType), message };
}

/** The first APDU where `b` leaves `a`: { at, apdu }. */
function firstDifference(a, b) {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (!a[i] || !b[i] || !a[i].equals(b[i])) return b[i] ? { at: i, apdu: hexOf(b[i]) } : { at: i, apdu: null };
  }
  return null;
}

/** Typed data with one thing changed, as a set of named changes. */
function boundChanges(typedData, changes) {
  return changes.map(([change, edit]) => {
    const td = structuredClone(typedData);
    edit(td);
    return { change, typed_data: td };
  });
}

function safeChanges(caseId, td) {
  const out = [];
  if (caseId === 'typed-safe-tx') {
    for (const field of ['to', 'value', 'data', 'operation', 'safeTxGas', 'baseGas', 'gasPrice', 'gasToken', 'refundReceiver', 'nonce']) {
      out.push([`message.${field}`, (t) => {
        const type = t.types.SafeTx.find((f) => f.name === field).type;
        t.message[field] = field === 'data' && t.message.data === '0x' ? '0x01' : otherValue(type, t.message[field], t.types);
      }]);
    }
  } else {
    out.push(['message.message (the digest)', (t) => { t.message.message = flipHex(t.message.message); }]);
  }
  out.push(['domain.verifyingContract (the Safe)', (t) => { t.domain.verifyingContract = flipHex(t.domain.verifyingContract); }]);
  out.push(['domain.chainId', (t) => { t.domain.chainId = 101; }]);
  return boundChanges(td, out);
}

/** x402's changes: what main's rebuild catches, the APDUs made to match. */
function x402Changes(form, td, otherForm) {
  const out = [];
  for (const key of Object.keys(td.domain)) {
    out.push([`domain.${key}`, (t) => {
      const v = t.domain[key];
      t.domain[key] = key === 'chainId' ? Number(v) + 1 : /^0x[0-9a-fA-F]{40}$/.test(v) ? flipHex(v) : rotate(String(v));
    }]);
  }
  out.push(['primaryType', (t) => {
    const renamed = rotate(t.primaryType);
    t.types[renamed] = t.types[t.primaryType];
    delete t.types[t.primaryType];
    t.primaryType = renamed;
  }]);
  const instances = (t, typeName) => {
    // Every message object of type typeName.
    const found = [];
    const visit = (type, value) => {
      if (type === typeName) found.push(value);
      for (const f of t.types[type] || []) if (t.types[f.type]) visit(f.type, value[f.name]);
    };
    visit(t.primaryType, t.message);
    return found;
  };
  for (const [typeName, fields] of Object.entries(td.types)) {
    fields.forEach((field, k) => {
      out.push([`types.${typeName}.${field.name}: renamed`, (t) => {
        const f = t.types[typeName][k];
        const renamed = rotate(f.name);
        for (const v of instances(t, typeName)) { v[renamed] = v[f.name]; delete v[f.name]; }
        f.name = renamed;
      }]);
      if (!td.types[field.type]) {
        out.push([`types.${typeName}.${field.name}: retyped`, (t) => {
          const f = t.types[typeName][k];
          for (const v of instances(t, typeName)) v[f.name] = retypedValue(f.type, v[f.name]);
          f.type = retypedType(f.type, instances(t, typeName)[0][f.name]);
        }]);
      }
    });
    out.push([`types.${typeName}: reordered`, (t) => { t.types[typeName].reverse(); }]);
    out.push([`types.${typeName}: a field added`, (t) => {
      t.types[typeName].push({ name: 'extra', type: 'uint256' });
      for (const v of instances(t, typeName)) v.extra = '0';
    }]);
    // The last field of a basic type, so that no type goes unused.
    out.push([`types.${typeName}: a field dropped`, (t) => {
      const fields = t.types[typeName];
      const k = fields.map((f) => !t.types[f.type]).lastIndexOf(true);
      const [f] = fields.splice(k, 1);
      for (const v of instances(t, typeName)) delete v[f.name];
    }]);
  }
  const values = (t, typeName, value, prefix) => {
    for (const f of t.types[typeName]) {
      if (t.types[f.type]) values(t, f.type, value[f.name], `${prefix}${f.name}.`);
      else out.push([`message.${prefix}${f.name}`, (u) => {
        const holder = prefix ? prefix.split('.').filter(Boolean).reduce((o, k) => o[k], u.message) : u.message;
        holder[f.name] = otherValue(f.type, holder[f.name], u.types);
      }]);
    }
  };
  values(td, td.primaryType, td.message, '');
  const times = form === 'permit2-v2' ? [['deadline'], ['witness', 'validAfter']] : [['validAfter'], ['validBefore']];
  for (const at of times) {
    out.push([`message.${at.join('.')}: one second later`, (t) => {
      const holder = at.slice(0, -1).reduce((o, k) => o[k], t.message);
      holder[at.at(-1)] = (BigInt(holder[at.at(-1)]) + 1n).toString();
    }]);
  }
  if (form === 'permit2-v2') {
    out.push(['the Permit2 address (domain.verifyingContract)', (t) => { t.domain.verifyingContract = flipHex(t.domain.verifyingContract); }]);
    out.push(['the Permit2 proxy (message.spender)', (t) => { t.message.spender = flipHex(t.message.spender); }]);
  }
  const changed = boundChanges(td, out);
  changed.push({ change: "the other form's schema for the same accept entry", typed_data: otherForm });
  return changed;
}

function retypedType(type, value) {
  if (type === 'address') return 'bytes20';
  if (type === 'bytes32') return 'uint256';
  if (/^uint\d+$/.test(type)) return BigInt(value) < 2n ** 128n ? 'uint128' : 'bytes32';
  return 'string';
}
function retypedValue(type, value) {
  if (type === 'address') return String(value).toLowerCase();
  if (type === 'bytes32') return BigInt(value).toString();
  if (/^uint\d+$/.test(type)) return BigInt(value) < 2n ** 128n ? String(value) : '0x' + BigInt(value).toString(16).padStart(64, '0');
  return String(value);
}

/**
 * The grammar file. `ledger`: the built ledger.json; `recorded`: each case
 * and its run; `x402Other(form)`: the other form's typed data for that
 * form's accept entry, as @x402/evm builds it.
 */
function buildGrammarFile(env, meta, recorded, x402Other) {
  const honest = [];
  const refused = [];
  const reached = Object.fromEntries(ROWS.map((r) => [r.row, 0]));
  let apdus = 0;
  const complete = new Set(['discovery', 'add', 'transaction', 'transaction-pieces', 'message', 'typed-data', 'hash-only', 'value-length', 'array-length', 'name-length', 'x402', 'app']);
  const byId = new Map();
  for (const { c, run } of recorded) {
    const checked = checkCase(env, c, run);
    apdus += run.exchanges.length;
    byId.set(c.id, { c, run, checked });
    // Another app's name ends the core's operation at B0 01 (app-check): no complete stream.
    if (!complete.has(c.family) || (c.family === 'app' && c.device.app.name !== 'Ethereum')) continue;
    if (checked.refused) {
      refused.push({ case: c.id, operation: c.operation, deviation: checked.refused.deviation, reason: checked.refused.reason });
      continue;
    }
    const stream = checked.honest.map(hexOf);
    stream.forEach((h, i) => {
      const row = rowOf(c.operation, headerOf(h), i);
      assert.ok(row, `${c.id}: APDU ${i} in no row`);
      reached[row] += 1;
      if (c.id === 'typed-safe-tx') reached['safe.sign_owner'] += 1;
      if (c.id === 'typed-safe-message') reached['safe.message_sign'] += 1;
      if (c.family === 'x402') reached['x402.settle'] += 1;
    });
    honest.push({ case: c.id, operation: c.operation, apdus: stream });
  }
  for (const [row, n] of Object.entries(reached)) assert.ok(n > 0, `no case reaches the row ${row}`);

  const forbidden = [];
  const honestOf = (id) => honest.find((h) => h.case === id).apdus.map((h) => Buffer.from(h, 'hex'));
  const push = (entry) => forbidden.push(entry);
  const changeByte = (b, at) => { const out = Buffer.from(b); out[at] ^= 0x01; return out; };
  // Headers, Lc, order, counts, paths and the end, on one case of each operation.
  for (const id of ['discovery-live-0-2', 'add-live-0', 'tx-steps', 'msg-steps', 'typed-steps']) {
    const stream = honestOf(id);
    const { c } = byId.get(id);
    const seen = new Set();
    stream.forEach((a, i) => {
      const h = headerOf(hexOf(a));
      if (seen.has(h)) return;
      seen.add(h);
      for (const [k, what] of [[0, 'CLA'], [1, 'INS'], [2, 'P1'], [3, 'P2']]) {
        push({ case: id, rule: 'header', at: i, apdu: hexOf(changeByte(a, k)), what: `${what} changed` });
      }
      const lc = Buffer.from(a);
      lc[4] = (lc[4] + 1) & 0xff;
      push({ case: id, rule: 'header', at: i, apdu: hexOf(lc), what: 'Lc one more than the data' });
    });
    if (stream.length > 2) {
      push({ case: id, rule: 'order', at: 1, apdu: hexOf(stream[2]), what: 'the third APDU in the second\'s place' });
    }
    push({ case: id, rule: 'ended', at: stream.length, apdu: hexOf(stream[stream.length - 1]), what: 'the last APDU again, after the operation\'s end' });
    if (c.operation.startsWith('sign.')) {
      push({ case: id, rule: 'count', at: 2, apdu: hexOf(stream[0]), what: 'the address check again' });
      push({ case: id, rule: 'count', at: 2, apdu: hexOf(stream[1]), what: 'B0 01 again' });
      push({ case: id, rule: 'order', at: 0, apdu: hexOf(stream[1]), what: 'B0 01 before the address check' });
      push({ case: id, rule: 'header', at: 0, apdu: hexOf(g.apdu(0xe0, 0x02, 0x01, 0x00, g.schemePath(c.record.path))), what: 'E0 02 01 00 outside ledger.add' });
    }
    const p = c.record?.path ?? (c.request.path || g.SCHEMES[c.request.scheme](c.request.start));
    const others = [["44'/60'/1'/0/0", 'another index'], ["44'/60'/0'/0", 'the other scheme\'s form'], ["44'/60'/0/0/0", 'an account element not hardened'],
      ["44'/60'/0'", 'three elements'], ["44'/60'/0'/0/0/0", 'six elements']];
    for (const [other, what] of others) {
      if (other === p) continue;
      const bytes = referencePath(other);
      const header = c.operation === 'ledger.add' ? [0xe0, 0x02, 0x01, 0x00] : [0xe0, 0x02, 0x00, 0x00];
      push({ case: id, rule: 'path', at: 0, apdu: hexOf(Buffer.concat([Buffer.from(header), Buffer.from([bytes.length]), bytes])), what });
    }
  }
  // Discovery's check (D1): at the first check's place, the path of a record
  // a device matched (which the check doesn't read), the display on, and the
  // second record's check; one after the last record's, and a 21st.
  {
    const id = 'discovery-records-mixed';
    const stream = honestOf(id);
    const { c } = byId.get(id);
    const at = c.request.count;
    const read = (p) => hexOf(g.apdu(0xe0, 0x02, 0x00, 0x00, g.schemePath(p)));
    const matched = c.meta.derivedWallets.find((w) => w.type === 'ledger' && w.addressCheck === 'matched').path;
    push({ case: id, rule: 'path', at, apdu: read(matched), what: 'the path of a record a device matched, which the check doesn\'t read' });
    push({ case: id, rule: 'header', at, apdu: hexOf(Buffer.concat([Buffer.from([0xe0, 0x02, 0x01, 0x00]), stream[at].subarray(4)])), what: 'the first record\'s check with the display on' });
    push({ case: id, rule: 'order', at, apdu: hexOf(stream[at + 1]), what: 'the second record\'s check in the first\'s place' });
    push({ case: id, rule: 'ended', at: stream.length, apdu: read(matched), what: 'a check after the last record\'s' });
    const { c: many, run } = byId.get('discovery-records-25');
    const past = g.checkedPaths(run.records)[g.MAX_CHECKS];
    push({ case: many.id, rule: 'ended', at: honestOf(many.id).length, apdu: read(past), what: 'a 21st record\'s check (check-bound)' });
  }
  // A parent that isn't a Ledger operation: the right APDU for a vault account's signature.
  push({ case: 'msg-steps', rule: 'parent', parent: { method: 'sign.message', key: { kind: 'account', index: 0 } }, at: 0, apdu: honestOf('msg-steps').map(hexOf)[0],
    what: 'a vault account\'s sign.message' });
  // The hash-only APDU without its 6D00, and after it before main's answer.
  const typed = honestOf('typed-steps');
  const { c: stepsCase } = byId.get('typed-steps');
  const hashOnly = hexOf(g.hashOnlyApdu(env.ethers, stepsCase.record.path, stepsCase.request.typed_data));
  push({ case: 'typed-steps', rule: 'order', at: typed.length - 1, apdu: hashOnly, what: 'E0 0C 00 00 with no 6D00 before it' });
  push({ case: 'typed-hash-only-mail', rule: 'order', at: 3, apdu: honestOf('typed-hash-only-mail').map(hexOf)[3],
    what: 'E0 0C 00 00 after the 6D00, before main answered hash_only: "shown"', state: '6D00 answered; main held its answer' });
  // A byte of a transaction's or a message's piece.
  for (const id of ['tx-steps', 'msg-steps']) {
    const stream = honestOf(id);
    const last = stream.length - 1;
    push({ case: id, rule: 'payload', at: last, apdu: hexOf(changeByte(stream[last], 5)), what: 'one byte of the last piece changed' });
    push({ case: id, rule: 'path', at: 2, apdu: hexOf(changeByte(stream[2], 5 + 4)), what: 'a byte of the first piece\'s path changed' });
  }

  // Each typed-data case's schema and message of the same shape.
  const typedCases = recorded.filter(({ c }) => c.operation === 'sign.typed_data' && ['typed-data', 'value-length', 'array-length', 'name-length'].includes(c.family) && !byId.get(c.id).checked.refused);
  const sameShapes = typedCases.map(({ c }) => {
    const td = sameShape(env.ethers, c.request.typed_data);
    const stream = [...g.signatureHead(c.record.path), ...g.typedDataStream(env.ethers, c.record.path, td)];
    const mine = honestOf(c.id);
    assert.equal(stream.length, mine.length, `${c.id}: the same shape has the same count`);
    stream.forEach((a, i) => assert.equal(headerOf(hexOf(a)), headerOf(hexOf(mine[i])), `${c.id}: the same shape keeps the headers`));
    return { case: c.id, rule: 'payload', typed_data: td, apdus: stream.map(hexOf) };
  });

  // The name-ascii cases: the reference's definitions, which count in UTF-16 units.
  const nameAscii = recorded.filter(({ c }) => byId.get(c.id).checked.refused?.deviation === 'name-ascii').map(({ c, run }) => ({
    case: c.id, rule: 'payload', apdus: run.exchanges.map((e) => e.apdu).filter((h) => h.startsWith('e01a')),
  }));

  // SafeTx and SafeMessage: each field, the Safe's address, the chain, the digest.
  const safe = [];
  for (const id of ['typed-safe-tx', 'typed-safe-message']) {
    const { c } = byId.get(id);
    const mine = honestOf(id);
    for (const { change, typed_data } of safeChanges(id, c.request.typed_data)) {
      const stream = [...g.signatureHead(c.record.path), ...g.typedDataStream(env.ethers, c.record.path, typed_data)];
      const diff = firstDifference(mine, stream);
      assert.ok(diff, `${id}: ${change} changes no APDU`);
      safe.push({ case: id, change, rule: 'payload', typed_data, first_difference: diff });
    }
  }

  // x402: the core's authorization with one thing changed, its APDUs made to match.
  const x402 = [];
  for (const { c, run } of recorded.filter(({ c }) => c.family === 'x402')) {
    const form = c.id.replace(/^x402-/, '');
    const td = typedDataOf(c, run);
    const mine = honestOf(c.id);
    for (const { change, typed_data } of x402Changes(form, td, x402Other(form))) {
      const { hash } = g.typedPayload(env.ethers, typed_data);
      const stream = [...g.signatureHead(c.record.path), ...g.typedDataStream(env.ethers, c.record.path, typed_data)];
      assert.ok(firstDifference(mine, stream), `${c.id}: ${change} changes no APDU`);
      x402.push({ case: c.id, change, refused_by: "main's rebuild, before the first APDU", typed_data, hash, apdus: stream.map(hexOf) });
    }
  }

  // The per-byte families, as rules over the honest streams above.
  const count = (pred, dataFrom) => honest.reduce((n, h) => n + h.apdus.reduce((m, a) => m + (pred(h, a) ? (a.length / 2 - 5) - dataFrom(a) : 0), 0), 0);
  const typedApdu = (h, a) => h.operation === 'sign.typed_data' && (a.startsWith('e01a') || a.startsWith('e01c'));
  const pieceApdu = (h, a) => (h.operation === 'sign.transaction' && a.startsWith('e004')) || (h.operation === 'sign.message' && a.startsWith('e008'));
  const families = [
    { family: 'typed-data-byte', rule: 'payload', applies_to: 'every honest sign.typed_data stream: each E0 1A and E0 1C APDU',
      change: 'each byte of its data in turn XOR 0x01, header, order and counts kept', count: count(typedApdu, () => 0) },
    { family: 'piece-byte', rule: 'payload', applies_to: 'every honest sign.transaction and sign.message stream: each E0 04 and E0 08 APDU',
      change: 'each byte of its data past the path (the first piece\'s P) in turn XOR 0x01; a byte of P so changed is rule path', count: count(pieceApdu, (a) => (a.slice(4, 8) === '0000' ? 1 + 4 * parseInt(a.slice(10, 12), 16) : 0)) },
  ];

  return {
    meta,
    formats: GRAMMAR_FORMATS,
    rows: ROWS,
    rules: RULES,
    bounds: { apdu_data_bytes: 255, apdus_per_operation: g.MAX_APDUS, value_encoding_bytes: g.MAX_VALUE, array_entries: 255, fixed_size: 255, dimensions: 255, name_bytes: 255 },
    checked: { cases: recorded.length, apdus, reached },
    honest,
    refused,
    forbidden,
    same_shape: sameShapes,
    name_ascii: nameAscii,
    safe_changes: safe,
    x402_changes: x402,
    byte_families: families,
  };
}

const GRAMMAR_FORMATS = {
  apdu: 'lowercase hex, CLA INS P1 P2 Lc data; Lc is the data\'s length, at most 255 (ledger.json\'s APDUs are hw-transport\'s framing of hw-app-eth\'s sends).',
  rows: 'design 0016\'s rows in order: each APDU\'s header, its data, how many, where its bytes come from, and whether it waits for the user.',
  checked: 'every APDU ledger.json records was checked against its row: the stream the design predicts for the case (honest, with the case\'s deviations applied as the design describes the reference: no B0 01 for a transaction or a message, app-check; E0 02 00 00 for ledger.add, address-from-device; hw-app-eth\'s cut, count and UTF-16 name lengths, field-pieces, device-bounds and name-ascii; the hash-only APDU after any 6D00 of signEIP712Message, blind-typed-data; nothing past the address check for a type 2 at a chain ID of 2^53 or more, chain-id-width; hw-app-eth\'s splitPath, path-strict; every listed record\'s path read after discovery, where the core reads a scheme\'s path only, path-strict, and at most 20, check-bound), up to where the case stopped (a fault in discovery\'s check ends the check, not discovery), and every deviation that makes it differ is marked on the case. `reached`: the honest APDUs of each row.',
  honest: 'each complete operation\'s stream as the core sends it (ledger.json\'s case `case`), which main\'s relay admits; for a hash-only case, through the 6D00 and the hash-only APDU; for discovery, its paths and then its check of the case\'s `records` (each one\'s path, a scheme\'s only, at most 20: D1).',
  refused: 'the cases the core refuses before the first APDU, by deviation.',
  forbidden: 'single APDUs main refuses with `rule`, each at position `at` of the case\'s honest stream (the APDUs before it as honest): `what` says what changed; `parent` the parent it names; `state` what main holds then.',
  same_shape: 'for each typed-data case the core sends, another schema and message of the same shape (every type and field name moved one letter on, EIP712Domain kept, every value another of the same encoded length) and its whole stream: the same headers and counts, other bytes, refused payload.',
  name_ascii: 'for each name-ascii case, the reference\'s definition APDUs (a name\'s length byte in UTF-16 units), which the core never sends: refused payload.',
  safe_changes: 'the SafeTx and SafeMessage of 0002\'s cases with one thing changed (each of the ten fields, the Safe\'s address, the chain, the digest): the typed data and the first APDU where its stream leaves the honest one, refused payload.',
  x402_changes: 'for each x402 form, the authorization with one thing changed (each domain member, the primary type, each type\'s fields renamed, retyped, reordered, added and dropped, each message value, each time field one second later, the Permit2 address and proxy, the other form\'s schema) and its stream as the core would send it: consistent with the changed typed data, so only main\'s rebuild, before the first APDU, refuses it.',
  byte_families: 'families too large to list, as rules over `honest`: the APDUs they change, how, and how many APDUs they make.',
};

module.exports = { buildGrammarFile, checkCase, streamDeviations, streams, ROWS, RULES, rowOf };
