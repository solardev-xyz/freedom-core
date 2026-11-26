'use strict';

// The scripted Ledger and the recording transport of vectors/ledger.json
// (design 0016, LDG-1). The reference's transport.js opens a transport with
// `TransportNodeHid.open('')`; the run hands it a RecordingTransport, a
// subclass of the very Transport class hw-transport-node-hid's transport
// extends (hw-transport 6.35.5, the copy -noevents pins), so `send`'s framing
// into one APDU, its 255-byte data limit and its status check are the
// package's own. Its `exchange` goes through the package's
// `exchangeAtomicImpl`, as node-hid's does, and asks the scripted device.
//
// The device is the world, not the oracle: it answers `E0 02` with the key
// of keys.json's test mnemonic at the path it was sent, `B0 01` with the
// case's app, and signs a transaction or a message the way the Ethereum app
// does, over the hash of the pieces it was sent. It can't hash typed data
// field by field, so it signs `E0 0C 00 01` over the case's EIP-712 hash, and
// `E0 0C 00 00` over the two hashes it was sent. A case scripts a status
// word or a disconnect at one APDU, or a fault in its answer.

const assert = require('node:assert/strict');

// The order of secp256k1.
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const STATUS_OK = Buffer.from([0x90, 0x00]);

/** A path's elements from its encoding (`n`, then n big-endian u32s), or null. */
function decodePath(data) {
  const n = data[0];
  if (n === undefined || data.length < 1 + 4 * n) return null;
  const elements = [];
  for (let i = 0; i < n; i++) elements.push(data.readUInt32BE(1 + 4 * i));
  return { elements, length: 1 + 4 * n };
}

const pathText = (elements) => 'm/' + elements
  .map((e) => (e >= 0x80000000 ? `${e - 0x80000000}'` : String(e))).join('/');

/** The total length of the RLP item at the head of `bytes`, or null while its header is short. */
function rlpLength(bytes) {
  if (bytes.length === 0) return null;
  const b = bytes[0];
  if (b < 0xc0) throw new Error('the scripted device reads a list');
  if (b <= 0xf7) return 1 + (b - 0xc0);
  const width = b - 0xf7;
  if (bytes.length < 1 + width) return null;
  return 1 + width + Number(BigInt('0x' + bytes.subarray(1, 1 + width).toString('hex')));
}

/** The chain ID's first four bytes, as the Ethereum app keeps it for a legacy `v`. */
function chainIdPrime(chainIdBytes) {
  const head = chainIdBytes.subarray(0, Math.min(4, chainIdBytes.length));
  return head.length ? Number(BigInt('0x' + head.toString('hex'))) : 0;
}

class ScriptedDevice {
  /**
   * `env`: { ethers, mnemonic, otherKey }; `script`: { app: { name, version },
   * fields (false: a Nano S, `6D00` to E0 1A and E0 1C), typedDigest (the
   * case's EIP-712 hash), fault: { at, status } | { at, disconnect },
   * answerFault: { at, kind } for one answer's bytes }.
   */
  constructor(env, script) {
    this.env = env;
    this.script = script;
    this.count = 0;
    this.keys = new Map();
    this.tx = null;
    this.msg = null;
  }

  keyAt(elements) {
    const text = pathText(elements);
    if (!this.keys.has(text)) {
      const node = this.env.ethers.HDNodeWallet.fromPhrase(this.env.mnemonic, '', text);
      this.keys.set(text, node.signingKey);
    }
    return this.keys.get(text);
  }

  /** The device's answer to one APDU, or a throw for a disconnect. */
  answer(apdu) {
    const at = this.count++;
    const fault = this.script.fault;
    if (fault && fault.at === at) {
      if (fault.disconnect) {
        const { DisconnectedDeviceDuringOperation } = this.env.errors;
        // node-hid's read failure, as hw-transport-node-hid-noevents maps it.
        throw new DisconnectedDeviceDuringOperation('could not read from HID device');
      }
      return Buffer.from(fault.status.toString(16).padStart(4, '0'), 'hex');
    }
    const [cla, ins, p1, p2, lc] = apdu;
    const data = apdu.subarray(5);
    assert.equal(lc, data.length, 'the transport frames Lc as the data length');
    const app = this.script.app;
    if (cla === 0xb0 && ins === 0x01) {
      const name = Buffer.from(app.name, 'ascii');
      const version = Buffer.from(app.version, 'ascii');
      return Buffer.concat([Buffer.from([0x01, name.length]), name, Buffer.from([version.length]), version,
        Buffer.from([0x01, 0x00]), STATUS_OK]);
    }
    assert.equal(cla, 0xe0, `the scripted device answers CLA E0 and B0, not ${cla.toString(16)}`);
    if (this.script.fields === false && (ins === 0x1a || ins === 0x1c)) return Buffer.from([0x6d, 0x00]);
    switch (ins) {
      case 0x02: return this.address(data, at);
      case 0x04: return this.transaction(p1, data, at);
      case 0x08: return this.message(p1, data, at);
      case 0x1a: case 0x1c: return STATUS_OK;
      case 0x0c: return this.typedData(p2, data, at);
      default: throw new Error(`the scripted device has no INS ${ins.toString(16)}`);
    }
  }

  address(data, at) {
    const decoded = decodePath(data);
    assert.ok(decoded && decoded.length === data.length, 'E0 02 carries one path');
    let key = this.keyAt(decoded.elements);
    let text = this.env.ethers.computeAddress(key.publicKey);
    const kind = this.answerFault(at);
    // Another address: another seed holds this path.
    if (kind === 'other-address') {
      key = this.env.otherKey;
      text = this.env.ethers.computeAddress(key.publicKey);
    }
    // The address text of this path, with another key beside it.
    if (kind === 'key-not-address') key = this.env.otherKey;
    const pub = Buffer.from(key.publicKey.slice(2), 'hex');
    const ascii = Buffer.from(text.slice(2), 'ascii');
    return Buffer.concat([Buffer.from([pub.length]), pub, Buffer.from([ascii.length]), ascii, STATUS_OK]);
  }

  transaction(p1, data, at) {
    if (p1 === 0x00) {
      const decoded = decodePath(data);
      assert.ok(decoded, 'E0 04 00 00 starts with a path');
      this.tx = { elements: decoded.elements, bytes: data.subarray(decoded.length) };
    } else {
      assert.ok(this.tx && p1 === 0x80, 'E0 04 80 00 continues a transaction');
      this.tx.bytes = Buffer.concat([this.tx.bytes, data]);
    }
    const t = this.tx.bytes;
    const typed = t[0] < 0x80;
    const body = typed ? t.subarray(1) : t;
    const total = rlpLength(body);
    if (total === null || body.length < total) return STATUS_OK;
    assert.equal(body.length, total, 'no byte past the transaction');
    const fields = this.env.ethers.decodeRlp(body);
    const digest = this.env.ethers.keccak256(t);
    const sig = this.sign(this.tx.elements, digest, at);
    this.tx = null;
    if (typed) return this.signatureAnswer((parity) => parity, sig, at);
    const prime = chainIdPrime(Buffer.from(this.env.ethers.getBytes(fields[6])));
    return this.signatureAnswer((parity) => (prime * 2 + 35 + parity) & 0xff, sig, at);
  }

  message(p1, data, at) {
    if (p1 === 0x00) {
      const decoded = decodePath(data);
      assert.ok(decoded, 'E0 08 00 00 starts with a path');
      const length = data.readUInt32BE(decoded.length);
      this.msg = { elements: decoded.elements, length, bytes: data.subarray(decoded.length + 4) };
    } else {
      assert.ok(this.msg && p1 === 0x80, 'E0 08 80 00 continues a message');
      this.msg.bytes = Buffer.concat([this.msg.bytes, data]);
    }
    if (this.msg.bytes.length < this.msg.length) return STATUS_OK;
    assert.equal(this.msg.bytes.length, this.msg.length, 'no byte past the message');
    const digest = this.env.ethers.hashMessage(this.msg.bytes);
    const sig = this.sign(this.msg.elements, digest, at);
    this.msg = null;
    return this.signatureAnswer((parity) => 27 + parity, sig, at);
  }

  typedData(p2, data, at) {
    const decoded = decodePath(data);
    assert.ok(decoded, 'E0 0C starts with a path');
    let digest;
    if (p2 === 0x01) {
      assert.equal(decoded.length, data.length, 'E0 0C 00 01 carries the path only');
      assert.ok(this.script.typedDigest, 'the case gives the device its EIP-712 hash');
      digest = this.script.typedDigest;
    } else {
      assert.equal(p2, 0x00);
      const rest = data.subarray(decoded.length);
      assert.equal(rest.length, 64, 'E0 0C 00 00 carries two hashes');
      digest = this.env.ethers.keccak256(Buffer.concat([Buffer.from([0x19, 0x01]), rest]));
    }
    const sig = this.sign(decoded.elements, digest, at);
    return this.signatureAnswer((parity) => 27 + parity, sig, at);
  }

  answerFault(at) {
    const f = this.script.answerFault;
    return f && (f.at === at || f.at === 'signature') ? f.kind : null;
  }

  sign(elements, digest, at) {
    const kind = this.answerFault(at);
    const key = kind === 'other-key' ? this.env.otherKey : this.keyAt(elements);
    // Another digest: the hash of the one it was asked, as a confused device might sign.
    const signed = kind === 'other-digest' ? this.env.ethers.keccak256(digest) : digest;
    const s = key.sign(signed);
    return { r: Buffer.from(s.r.slice(2), 'hex'), s: BigInt(s.s), parity: s.yParity };
  }

  /** `v ‖ r ‖ s ‖ 9000`, `vOf(parity)` the operation's v byte. */
  signatureAnswer(vOf, sig, at) {
    const kind = this.answerFault(at);
    let { s, parity } = sig;
    // The same signature with s in the high half: n − s, the parity flipped.
    if (kind === 'high-s') [s, parity] = [N - s, 1 - parity];
    if (kind === 'flip-v') parity = 1 - parity;
    // A legacy transaction's v as a message's: 27 or 28, not the chain's.
    const v = kind === 'v-27' ? 27 + parity : vOf(parity);
    let body = Buffer.concat([Buffer.from([v & 0xff]), sig.r, Buffer.from(s.toString(16).padStart(64, '0'), 'hex')]);
    if (kind === 'long') body = Buffer.concat([body, Buffer.from([0x00])]);
    if (kind === 'short') body = body.subarray(0, 64);
    return Buffer.concat([body, STATUS_OK]);
  }
}

/**
 * The recording transport class over `Transport` (the class TransportNodeHid
 * extends): every exchange recorded as `{ apdu, answer }` or `{ apdu, thrown }`
 * in `log.exchanges`, each open and close counted.
 */
function recordingTransport(Transport) {
  return class RecordingTransport extends Transport {
    constructor(device, log) {
      super();
      this.device = device;
      this.log = log;
      log.opened += 1;
    }

    async exchange(apdu) {
      return this.exchangeAtomicImpl(async () => {
        await null;
        const entry = { apdu: Buffer.from(apdu).toString('hex') };
        this.log.exchanges.push(entry);
        try {
          const answer = this.device.answer(Buffer.from(apdu));
          entry.answer = answer.toString('hex');
          return answer;
        } catch (err) {
          entry.thrown = { name: err.name, message: err.message };
          throw err;
        }
      });
    }

    setScrambleKey() {}

    async close() {
      await this.exchangeBusyPromise;
      this.log.closed += 1;
    }
  };
}

module.exports = { ScriptedDevice, recordingTransport, decodePath, pathText, N };
