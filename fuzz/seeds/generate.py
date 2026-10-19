#!/usr/bin/env python3
"""Writes the fuzz targets' starting inputs into fuzz/seeds/<target>/.

Run from the repository root: python3 fuzz/seeds/generate.py
The vault seeds need the `cryptography` package for AES-GCM.

The inputs only give the fuzzer a start; nothing checks them against a
reference. Each one is small, so libFuzzer's input-size limit stays small.
"""

import base64
import hashlib
import json
import os
import struct

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

    # protocol_frames: the first byte picks the connection (% 3) and the
    # read size (/ 3 % 64 + 1): 0 is a core connection read a byte at a time.
    body = message('response', id=1, result={'ok': True}).encode()
    begin = json.dumps({'id': 1, 'bytes': len(body)}).encode()
    core = (frame(0x01, request) + frame(0x12, begin) + frame(0x10, body[:10])
            + frame(0x11, body[10:]) + frame(0x13, b''))
    write('protocol_frames', 'core', bytes([0]) + core)
    write('protocol_frames', 'core-64-byte-reads', bytes([3 * 63]) + core)
    head = message('response', id=1, result={'status': 200, 'headers': [], 'body': True})
    abort = json.dumps({'code': 'internal', 'message': 'freedom-ipfs native gateway error'})
    main = (frame(0x01, head) + frame(0x02, stream_id(1) + b'hello') + frame(0x03, stream_id(1))
            + frame(0x02, stream_id(2) + b'x' * 300) + frame(0x04, stream_id(2) + abort.encode()))
    write('protocol_frames', 'main', bytes([1]) + main)
    write('protocol_frames', 'main-small-reads', bytes([3 * 4 + 1]) + main)
    service = b''.join(frame(0x05, stream_id(n) + struct.pack('>I', 4096)) for n in (1, 2, 3, 4))
    write('protocol_frames', 'service', bytes([2]) + service + frame(0x01, message('cancel', id=3)))


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


if __name__ == '__main__':
    json_seeds()
    protocol_seeds()
    vault_seeds()
