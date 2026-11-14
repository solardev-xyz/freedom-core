'use strict';

// HPKE (RFC 9180) base mode, single-shot, composed from node:crypto's
// primitives: X25519 Diffie-Hellman, HMAC-SHA256 and the AEAD cipher. No
// package is read. It implements no primitive of its own: only RFC 9180's
// composition of them (LabeledExtract and LabeledExpand over HKDF, DHKEM's
// DeriveKeyPair, Encap and ExtractAndExpand, the key schedule and the
// nonce), step by step as the RFC writes it.
//
// check.test.js pins it to the RFC's own test vectors, embedded there as
// data: Appendix A.1.1 (the printed base-mode vector, AES-128-GCM) and the
// base-mode entry of the exact suite the key store uses, AES-256-GCM, from
// the JSON file Appendix A cites as [TestVectors]. The Rust replay of
// keystore.json then opens every seal made here with the `hpke` crate.
//
// The suites: DHKEM(X25519, HKDF-SHA256) and HKDF-SHA256, with AES-128-GCM
// (for Appendix A.1) or AES-256-GCM (the key store's).

const crypto = require('node:crypto');

const KEM_ID = 0x0020;
const KDF_ID = 0x0001;
const AEADS = {
  'aes-128-gcm': { id: 0x0001, nk: 16 },
  'aes-256-gcm': { id: 0x0002, nk: 32 },
};
const NN = 12; // the AEADs' nonce length
const NT = 16; // and tag length
const NH = 32; // HKDF-SHA256's output length
const NSECRET = 32; // DHKEM(X25519)'s shared secret
const NSK = 32; // an X25519 private key
const MODE_BASE = 0x00;

// I2OSP for a non-negative safe integer, big-endian in `length` bytes.
const i2osp = (n, length) => {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error('I2OSP: not a non-negative safe integer');
  const out = Buffer.alloc(length);
  let rest = BigInt(n);
  for (let i = length - 1; i >= 0 && rest > 0n; i -= 1) {
    out[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  if (rest > 0n) throw new Error('I2OSP: integer too large');
  return out;
};
const ascii = (text) => Buffer.from(text, 'ascii');

// HKDF (RFC 5869) over HMAC-SHA256: Extract with an empty salt is HMAC
// under a zero-length key, which HMAC pads with zeros as it would a
// string of HashLen zeros.
const hmac = (key, data) => crypto.createHmac('sha256', key).update(data).digest();
const extract = (salt, ikm) => hmac(salt, ikm);
function expand(prk, info, length) {
  if (length > 255 * NH) throw new Error('HKDF-Expand: length too large');
  const blocks = [];
  let previous = Buffer.alloc(0);
  for (let i = 1; Buffer.concat(blocks).length < length; i += 1) {
    previous = hmac(prk, Buffer.concat([previous, info, Buffer.from([i])]));
    blocks.push(previous);
  }
  return Buffer.concat(blocks).subarray(0, length);
}

// RFC 9180 §4: the labeled forms, under a suite_id.
const labeledExtract = (suiteId, salt, label, ikm) =>
  extract(salt, Buffer.concat([ascii('HPKE-v1'), suiteId, ascii(label), ikm]));
const labeledExpand = (suiteId, prk, label, info, length) =>
  expand(prk, Buffer.concat([i2osp(length, 2), ascii('HPKE-v1'), suiteId, ascii(label), info]), length);

// RFC 9180 §4.1: the KEM's suite_id.
const KEM_SUITE = Buffer.concat([ascii('KEM'), i2osp(KEM_ID, 2)]);

// X25519 keys as node:crypto takes them: the RFC 8410 DER forms around the
// 32 raw bytes.
const PKCS8_X25519 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const SPKI_X25519 = Buffer.from('302a300506032b656e032100', 'hex');
const privateKey = (sk) => crypto.createPrivateKey({ key: Buffer.concat([PKCS8_X25519, sk]), format: 'der', type: 'pkcs8' });
const publicKey = (pk) => crypto.createPublicKey({ key: Buffer.concat([SPKI_X25519, pk]), format: 'der', type: 'spki' });
const publicOf = (sk) => {
  const der = crypto.createPublicKey(privateKey(sk)).export({ format: 'der', type: 'spki' });
  if (der.length !== SPKI_X25519.length + 32 || !der.subarray(0, SPKI_X25519.length).equals(SPKI_X25519)) {
    throw new Error('unexpected X25519 public key encoding');
  }
  return Buffer.from(der.subarray(SPKI_X25519.length));
};
function dh(sk, pk) {
  const shared = crypto.diffieHellman({ privateKey: privateKey(sk), publicKey: publicKey(pk) });
  // RFC 9180 §7.1.4: an all-zero shared secret is refused.
  if (shared.every((b) => b === 0)) throw new Error('DH: all-zero shared secret');
  return shared;
}

// RFC 9180 §7.1.3: DeriveKeyPair for X25519; SerializePrivateKey and
// SerializePublicKey are the raw 32 bytes.
function deriveKeyPair(ikm) {
  if (ikm.length < NSK) throw new Error('DeriveKeyPair: ikm too short');
  const dkpPrk = labeledExtract(KEM_SUITE, Buffer.alloc(0), 'dkp_prk', ikm);
  const sk = labeledExpand(KEM_SUITE, dkpPrk, 'sk', Buffer.alloc(0), NSK);
  return { sk, pk: publicOf(sk) };
}

// RFC 9180 §4.1: Encap, with the ephemeral key pair from ikmE.
function encap(pkR, ikmE) {
  const { sk: skE, pk: pkE } = deriveKeyPair(ikmE);
  const dhOut = dh(skE, pkR);
  const enc = pkE;
  const kemContext = Buffer.concat([enc, pkR]);
  const eaePrk = labeledExtract(KEM_SUITE, Buffer.alloc(0), 'eae_prk', dhOut);
  const sharedSecret = labeledExpand(KEM_SUITE, eaePrk, 'shared_secret', kemContext, NSECRET);
  return { sharedSecret, enc, skE, pkE };
}

// RFC 9180 §4.1: Decap.
function decap(enc, skR) {
  const dhOut = dh(skR, enc);
  const kemContext = Buffer.concat([enc, publicOf(skR)]);
  const eaePrk = labeledExtract(KEM_SUITE, Buffer.alloc(0), 'eae_prk', dhOut);
  return labeledExpand(KEM_SUITE, eaePrk, 'shared_secret', kemContext, NSECRET);
}

function suite(aead) {
  const params = AEADS[aead];
  if (!params) throw new Error(`unknown AEAD ${aead}`);
  return { ...params, id: Buffer.concat([ascii('HPKE'), i2osp(KEM_ID, 2), i2osp(KDF_ID, 2), i2osp(params.id, 2)]) };
}

// RFC 9180 §5.1: the key schedule, base mode (no PSK).
function keySchedule(aead, sharedSecret, info) {
  const { id, nk } = suite(aead);
  const pskIdHash = labeledExtract(id, Buffer.alloc(0), 'psk_id_hash', Buffer.alloc(0));
  const infoHash = labeledExtract(id, Buffer.alloc(0), 'info_hash', info);
  const keyScheduleContext = Buffer.concat([Buffer.from([MODE_BASE]), pskIdHash, infoHash]);
  const secret = labeledExtract(id, sharedSecret, 'secret', Buffer.alloc(0));
  return {
    keyScheduleContext,
    secret,
    key: labeledExpand(id, secret, 'key', keyScheduleContext, nk),
    baseNonce: labeledExpand(id, secret, 'base_nonce', keyScheduleContext, NN),
    exporterSecret: labeledExpand(id, secret, 'exp', keyScheduleContext, NH),
  };
}

// RFC 9180 §5.2: the nonce for sequence number `seq`.
function nonce(baseNonce, seq) {
  const out = Buffer.from(baseNonce);
  const counter = i2osp(seq, NN);
  for (let i = 0; i < NN; i += 1) out[i] ^= counter[i];
  return out;
}

function aeadSeal(aead, key, iv, aad, pt) {
  const cipher = crypto.createCipheriv(aead, key, iv, { authTagLength: NT });
  cipher.setAAD(aad);
  return Buffer.concat([cipher.update(pt), cipher.final(), cipher.getAuthTag()]);
}

function aeadOpen(aead, key, iv, aad, ct) {
  if (ct.length < NT) throw new Error('AEAD: ciphertext too short');
  const decipher = crypto.createDecipheriv(aead, key, iv, { authTagLength: NT });
  decipher.setAAD(aad);
  decipher.setAuthTag(ct.subarray(ct.length - NT));
  return Buffer.concat([decipher.update(ct.subarray(0, ct.length - NT)), decipher.final()]);
}

// Every intermediate value of a base-mode setup and its encryption at
// `seq`, as RFC 9180's Appendix A lists them.
function trace({ aead, ikmR, ikmE, info, aad, pt, seq = 0 }) {
  const { sk: skR, pk: pkR } = deriveKeyPair(ikmR);
  const { sharedSecret, enc, skE, pkE } = encap(pkR, ikmE);
  const schedule = keySchedule(aead, sharedSecret, info);
  const iv = nonce(schedule.baseNonce, seq);
  return { skR, pkR, skE, pkE, enc, sharedSecret, ...schedule, nonce: iv, ct: aeadSeal(aead, schedule.key, iv, aad, pt) };
}

// RFC 9180 §6.1: SealBase, single-shot (sequence number 0), with the
// ephemeral key pair from ikmE.
function sealBase({ aead, pkR, ikmE, info, aad, pt }) {
  const { sharedSecret, enc } = encap(pkR, ikmE);
  const { key, baseNonce } = keySchedule(aead, sharedSecret, info);
  return { enc, ct: aeadSeal(aead, key, nonce(baseNonce, 0), aad, pt) };
}

// RFC 9180 §6.1: OpenBase, single-shot.
function openBase({ aead, enc, skR, info, aad, ct }) {
  const sharedSecret = decap(enc, skR);
  const { key, baseNonce } = keySchedule(aead, sharedSecret, info);
  return aeadOpen(aead, key, nonce(baseNonce, 0), aad, ct);
}

module.exports = { KEM_ID, KDF_ID, AEADS, deriveKeyPair, trace, sealBase, openBase };
