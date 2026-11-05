#!/usr/bin/env python3
"""Writes the fuzz targets' starting inputs into fuzz/seeds/<target>/.

Run from the repository root: python3 fuzz/seeds/generate.py
The vault seeds need the `cryptography` package for AES-GCM, and the seal
seeds for X25519 and AES-GCM.

The inputs only give the fuzzer a start; nothing checks them against a
reference. Each one is small, so libFuzzer's input-size limit stays small.
"""

import base64
import hashlib
import hmac
import json
import os
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)))
BS = chr(92)  # a backslash, so no escape in this file is decoded by a tool
PHRASE = ' '.join(['abandon'] * 11 + ['about'])


def write(target, name, data):
    directory = os.path.join(ROOT, target)
    os.makedirs(directory, exist_ok=True)
    if isinstance(data, str):
        data = data.encode('utf-8')
    with open(os.path.join(directory, name), 'wb') as f:
        f.write(data)


def frame(kind, payload):
    if isinstance(payload, str):
        payload = payload.encode('utf-8')
    return struct.pack('>IB', len(payload) + 1, kind) + payload


def stream_id(n):
    return struct.pack('>Q', n)


def json_seeds():
    write('json_parse', 'object', '{"a":[1,2.5e3,-0,true,false,null,"x"],"b":{"c":""}}')
    write('json_parse', 'escapes', '["' + BS + 'u00e9' + BS + 'n' + BS + '"' + BS + 'ud83d' + BS + 'ude00"]')
    write('json_parse', 'lone-surrogates', '{"' + BS + 'ud800":1,"' + BS + 'udfff":2,"' + BS + 'ufffd":3}')
    # Keys that U+FFFD makes equal, merged before and after it (review of #122).
    write('json_parse', 'lone-surrogate-keys', '{"' + BS + 'ud800":1,"b":2,"' + BS + 'udfff":3,"' + BS + 'ud800":4}')
    write('json_parse', 'property-order', '{"b":1,"2":2,"a":3,"1":4,"b":5,"4294967295":6}')
    write('json_parse', 'numbers', '[1e400,-1e-400,9007199254740993,0.1,1E+2,-0.0]')
    write('json_parse', 'deep', '[' * 600 + ']' * 600)


def message(kind, **fields):
    return json.dumps(dict(type=kind, **fields), separators=(',', ':'))


def protocol_seeds():
    secret = base64.b64encode(b'correct horse battery staple').decode()
    request = message('request', id=7, method='vault.unlock',
                      params={'password_b64': secret}, context={'caller': 'chrome'})
    error = message('response', id=7, error={'code': 'incorrect_password', 'message': 'Incorrect password'})
    event = message('event', event='vault.locked', data={'reason': 'auto', 'epoch': 12})
    write('protocol_message', 'request', request)
    write('protocol_message', 'error', error)
    write('protocol_message', 'event', event)
    write('protocol_message', 'cancel', message('cancel', id=7))
    write('protocol_message', 'secret-token', '"' + secret + '"')

    # protocol_frames: the first byte picks the connection (% 4) and the
    # read size (/ 4 % 64 + 1): 0 is a core connection read a byte at a time.
    body = message('response', id=1, result={'ok': True}).encode()
    begin = json.dumps({'id': 1, 'bytes': len(body)}).encode()
    core = (frame(0x01, request) + frame(0x12, begin) + frame(0x10, body[:10])
            + frame(0x11, body[10:]) + frame(0x13, b''))
    write('protocol_frames', 'core', bytes([0]) + core)
    write('protocol_frames', 'core-64-byte-reads', bytes([4 * 63]) + core)
    head = message('response', id=1, result={'status': 200, 'headers': [], 'body': True})
    abort = json.dumps({'code': 'internal', 'message': 'freedom-ipfs native gateway error'})
    main = (frame(0x01, head) + frame(0x02, stream_id(1) + b'hello') + frame(0x03, stream_id(1))
            + frame(0x02, stream_id(2) + b'x' * 300) + frame(0x04, stream_id(2) + abort.encode()))
    write('protocol_frames', 'main', bytes([1]) + main)
    write('protocol_frames', 'main-small-reads', bytes([4 * 4 + 1]) + main)
    service = b''.join(frame(0x05, stream_id(n) + struct.pack('>I', 4096)) for n in (1, 2, 3, 4))
    write('protocol_frames', 'service', bytes([2]) + service + frame(0x01, message('cancel', id=3)))
    # The core at protocol 2 (design 0009): credit for the bodies it sends,
    # and the bodies main sends for the core's own requests, under the same
    # IDs, with whole messages and fragments between.
    both = (service + frame(0x02, stream_id(1) + b'hello') + frame(0x03, stream_id(1))
            + frame(0x02, stream_id(2) + b'x' * 300) + frame(0x04, stream_id(2) + abort.encode())
            + frame(0x01, request) + frame(0x12, begin) + frame(0x10, body[:10]) + frame(0x11, body[10:]))
    write('protocol_frames', 'core-streams', bytes([3]) + both)
    write('protocol_frames', 'core-streams-small-reads', bytes([4 * 6 + 3]) + both)


def vault_file(plaintext, password, iterations, key_metadata=True):
    salt = bytes(range(32))
    iv = bytes(range(16, 32))
    key = hashlib.pbkdf2_hmac('sha256', password, salt, iterations, 32)
    data = AESGCM(key).encrypt(iv, plaintext, b'')
    payload = {'data': base64.b64encode(data).decode(), 'iv': base64.b64encode(iv).decode()}
    if key_metadata:
        payload['keyMetadata'] = {'algorithm': 'PBKDF2', 'params': {'iterations': iterations}}
    payload['salt'] = base64.b64encode(salt).decode()
    envelope = {'version': 1, 'encrypted': json.dumps(payload, separators=(',', ':')),
                'createdAt': '2026-10-19T00:00:00.000Z'}
    return json.dumps(envelope, indent=2)


def vault_seeds():
    # Mode 0 (even first byte): a whole file, under the target's password.
    password = b'fuzzing password'
    plain = json.dumps({'mnemonic': PHRASE}, separators=(',', ':')).encode()
    write('vault_open', 'file-one-round', bytes([0]) + vault_file(plain, password, 1).encode())
    write('vault_open', 'file-string-rounds',
          bytes([0]) + vault_file(plain, password, 1).replace('"iterations' + BS + '":1', '"iterations' + BS + '":' + BS + '"1' + BS + '"').encode())
    write('vault_open', 'file-legacy', bytes([0]) + vault_file(plain, password, 10000, key_metadata=False).encode())
    # Mode 1 (odd first byte): the decrypted plaintext.
    write('vault_open', 'plaintext', bytes([1]) + plain)
    escaped = '{"mnemonic":"' + PHRASE.replace(' ', BS + 'u0020', 1) + '","other":1}'
    write('vault_open', 'plaintext-escapes', bytes([1]) + escaped.encode())


def openssh_seeds():
    # The JS vector's files (vectors/fixtures/radicle-openssh.json).
    fixtures = os.path.join(ROOT, '..', '..', 'vectors', 'fixtures', 'radicle-openssh.json')
    with open(fixtures) as f:
        identity = json.load(f)['fixtures'][0]['identity']
    private = identity['privateKeyFile'].encode()
    public = identity['publicKeyFile'].encode()
    # Top bit clear: a file or a line, fed 1, 7 or 64 bytes at a time.
    write('openssh_public', 'file-bytewise', bytes([0]) + private)
    write('openssh_public', 'file-7-byte-pieces', bytes([6]) + private)
    write('openssh_public', 'file-64-byte-pieces', bytes([63]) + private)
    write('openssh_public', 'line', bytes([5]) + public)
    # Top bit set: key 1, a check integer, and a comment to write.
    write('openssh_public', 'written', bytes([0x80 | 3, 1]) + bytes.fromhex('d3890d10') + b'FreedomBrowser')


# fc-seal's HPKE (RFC 9180): DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
# AES-256-GCM, base mode, fc-seal's INFO and an empty aad.
SEAL_KEM = b'KEM' + struct.pack('>H', 0x0020)
SEAL_SUITE = b'HPKE' + struct.pack('>HHH', 0x0020, 0x0001, 0x0002)
SEAL_INFO = b'freedom-radicle-node-key/1'


def hkdf_extract(salt, ikm):
    return hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length):
    out, block, counter = b'', b'', 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def labeled_extract(suite, salt, label, ikm):
    return hkdf_extract(salt, b'HPKE-v1' + suite + label + ikm)


def labeled_expand(suite, prk, label, info, length):
    return hkdf_expand(prk, struct.pack('>H', length) + b'HPKE-v1' + suite + label + info, length)


def derive_keypair(ikm):
    """DeriveKeyPair: what `RecipientKey::generate` and a seal's ephemeral
    key make of 32 bytes."""
    prk = labeled_extract(SEAL_KEM, b'', b'dkp_prk', ikm)
    secret = X25519PrivateKey.from_private_bytes(labeled_expand(SEAL_KEM, prk, b'sk', b'', 32))
    return secret, secret.public_key().public_bytes_raw()


def hpke_seal(recipient, key, ikm):
    """`fc_seal::seal(recipient, key)` with `ikm` as its 32 random bytes:
    enc and ciphertext."""
    ephemeral, enc = derive_keypair(ikm)
    dh = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient))
    prk = labeled_extract(SEAL_KEM, b'', b'eae_prk', dh)
    shared = labeled_expand(SEAL_KEM, prk, b'shared_secret', enc + recipient, 32)
    context = (bytes([0]) + labeled_extract(SEAL_SUITE, b'', b'psk_id_hash', b'')
               + labeled_extract(SEAL_SUITE, b'', b'info_hash', SEAL_INFO))
    secret = labeled_extract(SEAL_SUITE, shared, b'secret', b'')
    aead_key = labeled_expand(SEAL_SUITE, secret, b'key', context, 32)
    nonce = labeled_expand(SEAL_SUITE, secret, b'base_nonce', context, 12)
    return enc, AESGCM(aead_key).encrypt(nonce, key, b'')


def seal_seeds():
    # Even: a recipient's seed, then a relayed enc and ciphertext, cut at 32.
    write('seal_open', 'relayed', bytes([64]) + bytes(range(32)) + bytes(range(32, 112)))
    # The same, relaying a genuine seal of 0x52 * 32 to that recipient
    # (review of #199): it opens, so the target checks what a seal implies.
    _, recipient = derive_keypair(bytes([0x31] * 32))
    enc, ciphertext = hpke_seal(recipient, bytes([0x52] * 32), bytes([0x73] * 32))
    write('seal_open', 'relayed-genuine', bytes([64]) + bytes([0x31] * 32) + enc + ciphertext)
    # Odd: a recipient's public key, a key, a seed.
    write('seal_open', 'sealed', bytes([1]) + bytes(range(1, 97)))
    # A low-order point as the recipient: seal must refuse it.
    write('seal_open', 'low-order', bytes([1]) + bytes(32) + bytes(range(64)))


def chain_seeds():
    ok = struct.pack('>H', 200)
    write('chain_answer', 'result', ok + b'{"jsonrpc":"2.0","id":1,"result":"0x10"}')
    write('chain_answer', 'node-error', ok + b'{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"nonce too low","data":"0x"}}')
    write('chain_answer', 'invalid-utf8', ok + b'{"result":"' + bytes([0xff, 0xfe]) + b'"}')
    write('chain_answer', 'status', struct.pack('>H', 503) + b'busy')


def word(n):
    return n.to_bytes(32, 'big')


def abi_bytes(data):
    return word(len(data)) + data + bytes(-len(data) % 32)


def naming_seeds():
    digest = hashlib.sha256(b'freedom').digest()
    write('naming_answer', 'contenthash-ipfs', bytes([0]) + bytes([0xe3, 0x01, 0x01, 0x70, 0x12, 0x20]) + digest)
    write('naming_answer', 'contenthash-swarm', bytes([0]) + bytes([0xe4, 0x01, 0x01, 0xfa, 0x01, 0x1b, 0x20]) + digest)
    write('naming_answer', 'cid', bytes([1]) + bytes([0x01, 0x70, 0x12, 0x20]) + digest)
    write('naming_answer', 'gateway', bytes([2]) + b'{"data":"0x' + digest.hex().encode() + b'"}')
    # Mode 3 + 4 * shape, the output bound (two bytes), then ABI data: for
    # [bytes], and for OffchainLookup.
    unbounded = struct.pack('>H', 0xffff)
    one_bytes = word(32) + abi_bytes(digest)
    write('naming_answer', 'abi-bytes', bytes([3]) + unbounded + one_bytes)
    # Its 32 bytes exactly at the bound, and one byte over it.
    write('naming_answer', 'abi-bytes-at-bound', bytes([3]) + struct.pack('>H', 32) + one_bytes)
    write('naming_answer', 'abi-bytes-over-bound', bytes([3]) + struct.pack('>H', 31) + one_bytes)
    url = b'https://gateway.example/{sender}/{data}.json'
    lookup = offchain_lookup(word(1) + word(32) + abi_bytes(url))
    write('naming_answer', 'abi-offchain-lookup', bytes([3 + 4 * 5]) + unbounded + lookup)
    # Its output (the URL, callData and extraData) at the bound, and over it.
    output = len(url) + 2
    write('naming_answer', 'abi-offchain-lookup-at-bound',
          bytes([3 + 4 * 5]) + struct.pack('>H', output) + lookup)
    write('naming_answer', 'abi-offchain-lookup-over-bound',
          bytes([3 + 4 * 5]) + struct.pack('>H', output - 1) + lookup)
    # A urls string[] that fails after reading its first URL (the second
    # offset is above 2^53 - 1): the URL counts against the bound but isn't
    # in the answer, so a bound of what the answer holds (callData's 2
    # bytes) refuses it, and so does one of the URL's length, which
    # callData then passes (review of #199).
    failing = offchain_lookup(word(2) + word(64) + word(2 ** 64) + abi_bytes(url))
    write('naming_answer', 'abi-offchain-lookup-failed-urls',
          bytes([3 + 4 * 5]) + struct.pack('>H', 2) + failing)
    write('naming_answer', 'abi-offchain-lookup-failed-urls-at-url',
          bytes([3 + 4 * 5]) + struct.pack('>H', len(url)) + failing)
    # A [string[]] whose first item offset is above 2^53 - 1: the field
    # fails before any string is made, so it decodes within a bound of 0
    # (review of #199).
    write('naming_answer', 'abi-string-array-failed-offset',
          bytes([3 + 4 * 4]) + struct.pack('>H', 0) + word(32) + word(1) + word(2 ** 64))


def offchain_lookup(urls):
    """An OffchainLookup revert's ABI data around `urls` (string[])."""
    sender = bytes(12) + bytes(range(20))
    call = abi_bytes(b'\x12\x34')
    extra = abi_bytes(b'')
    head_len = 5 * 32
    urls_at = head_len
    call_at = urls_at + len(urls)
    extra_at = call_at + len(call)
    return (word(int.from_bytes(sender, 'big')) + word(urls_at) + word(call_at)
            + bytes([0xde, 0xad, 0xbe, 0xef]) + bytes(28) + word(extra_at) + urls + call + extra)

if __name__ == '__main__':
    json_seeds()
    protocol_seeds()
    vault_seeds()
    openssh_seeds()
    seal_seeds()
    chain_seeds()
    naming_seeds()
