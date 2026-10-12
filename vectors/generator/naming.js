'use strict';

// Naming vectors (design 0003): the reference's own resolver code produces
// every expected output. Its internal functions are reached through a
// harness that appends test-only exports to the original source and stubs
// the Electron environment, so no reference code is copied here.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const Module = require('node:module');
const path = require('node:path');

const SILENT_LOG = { info() {}, warn() {}, error() {}, debug() {}, log() {} };

/**
 * Loads `rel` from the checkout with `internals` appended to its exports
 * as `__internals`, and `stubs` (by request string) for its own requires.
 */
function loadWithInternals(checkout, rel, internals, stubs) {
  const filename = path.join(checkout, rel);
  const source = fs.readFileSync(filename, 'utf8');
  const exposed = `\n;module.exports.__internals = { ${internals.join(', ')} };\n`;
  const originalLoad = Module._load;
  Module._load = function load(request, parent, isMain) {
    if (parent && parent.filename === filename && Object.hasOwn(stubs, request)) return stubs[request];
    // Lazy `require('electron')` anywhere in the checkout (the gateway transport).
    if (request === 'electron' && parent?.filename?.startsWith(checkout)) return stubs.electron;
    return originalLoad.call(this, request, parent, isMain);
  };
  const mod = new Module(filename, null);
  mod.filename = filename;
  mod.paths = Module._nodeModulePaths(path.dirname(filename));
  mod._compile(source + exposed, filename);
  return mod.exports;
}

const ELECTRON = {
  ipcMain: { handle() {}, on() {}, removeHandler() {} },
  net: {},
  session: { defaultSession: { resolveProxy: async () => 'DIRECT' } },
  app: { getPath: () => '/nonexistent' },
  BrowserWindow: { getAllWindows: () => [] },
};

function loadEnsResolver(checkout) {
  return loadWithInternals(checkout, 'src/main/ens-resolver.js', [
    'fastNormalize', 'parseContentHashBytes', 'ensCoinType', 'nodeFromResolverCallData',
    'nameSystemForName', 'encodeReverseOutcome', 'decodeReverseMismatchClaimedName',
    'isReverseAddressMismatchError', 'UR_ABI', 'NAME_NFT_ABI',
  ], {
    electron: ELECTRON,
    './logger': SILENT_LOG,
    './networks/network-registry': { getEndpoints: () => [], getNetwork: () => ({}), getEndpointSources: () => [], getEndpointSourceList: () => [] },
    './ens-prefetch': { prefetchGatewayUrl: () => ({ abort() {} }), NOOP_HANDLE: { abort() {} } },
    './myotis/myotis-manager': { onAvailabilityTransition() {}, getStatus: () => ({}) },
    './private/private-log-context': { runWithPrivateLogContext: (_p, fn) => fn(), redactForLog: (v) => v, isPrivateLogContext: () => false },
    './private/private-windows': { isPrivateWebContents: () => false },
  });
}

function loadTezos(checkout) {
  return loadWithInternals(checkout, 'src/main/tezos-domains-resolver.js', [
    'mapEntries', 'decodeJsonBytes', 'storageTypeFromScript', 'bytesFromHex',
  ], {
    electron: ELECTRON,
    './logger': SILENT_LOG,
    './private/private-log-context': { runWithPrivateLogContext: (_p, fn) => fn(), redactForLog: (v) => v },
  });
}

const errorOf = (error) => ({ error: String(error?.message ?? error) });

function attempt(fn) {
  try {
    return { value: fn() };
  } catch (error) {
    return errorOf(error);
  }
}

// ---------------------------------------------------------------------------
// Names

const NAMES = [
  'vitalik.eth', '  Vitalik.ETH  ', 'nick.eth', 'eth', 'a.b.c.d.eth', 'xn--x.eth', 'ab--cd.eth', 'foo..eth', '.eth', 'eth.',
  'a_b.eth', '\uFF21\uFF22\uFF23.eth', '\u216B.eth', '\u212Aelvin.eth', 'İstanbul.eth', '💩.eth', '🏳️\u200D🌈.eth', 'ß.eth', 'Ω.eth',
  'café.eth', 'cafe\u0301.eth', '\uFEFFa.eth', '\u0085a.eth', 'a\u200Db.eth', '\u3000a.eth\u3000', ' ', '', 'a.wei', 'b.GWEI',
  'test.offchaindemo.eth', '1inch.eth', 'a'.repeat(63) + '.eth', 'a'.repeat(255) + '.eth', 'a'.repeat(256) + '.eth',
  // Around the core's 1,024-byte limit (design 0003): the JS has none.
  'a'.repeat(200) + '.' + 'b'.repeat(200) + '.' + 'c'.repeat(200) + '.' + 'd'.repeat(200) + '.' + 'e'.repeat(216) + '.eth',
  'a'.repeat(200) + '.' + 'b'.repeat(200) + '.' + 'c'.repeat(200) + '.' + 'd'.repeat(200) + '.' + 'e'.repeat(217) + '.eth',
];

function buildNames({ ensResolver, ethers }) {
  const { fastNormalize, nameSystemForName } = ensResolver.__internals;
  return NAMES.map((input) => {
    // resolveWithCache: trim, refuse empty, fastNormalize; ethers then hashes.
    const trimmed = input.trim();
    if (!trimmed) return { input, js: { stage: 'empty', error: 'ENS name is empty' } };
    const normalized = attempt(() => fastNormalize(trimmed));
    if (normalized.error) return { input, js: { stage: 'normalize', ...normalized } };
    const node = attempt(() => ethers.namehash(normalized.value));
    const dns = attempt(() => ethers.dnsEncode(normalized.value, 255));
    if (node.error) return { input, js: { stage: 'namehash', error: node.error, normalized: normalized.value } };
    return {
      input,
      // Longer than 1,024 bytes: the core refuses it (design 0003).
      ...(Buffer.byteLength(trimmed) > 1024 ? { deviation: 'name-length' } : {}),
      js: {
        normalized: normalized.value,
        namehash: node.value,
        dns_encoded: dns.value ?? null,
        dns_error: dns.error ?? null,
        system: nameSystemForName(normalized.value).id,
      },
    };
  });
}

const CHAIN_IDS = [1, 10, 100, 8453, 0x7fffffff, 0, -1, 0x80000000, 1.5, 2 ** 53];

function buildCoinTypes({ ensResolver }) {
  const { ensCoinType } = ensResolver.__internals;
  return CHAIN_IDS.map((chainId) => {
    const result = attempt(() => ensCoinType(chainId));
    return { chain_id: chainId, ...(result.error ? result : { value: result.value.toString() }) };
  });
}

// ---------------------------------------------------------------------------
// contenthash

function contenthashInputs({ ethers }) {
  const v0 = '0x' + ethers.toBeHex(ethers.decodeBase58('QmW81r84Aihiqqi2Jw6nM1LnpeMfRCenRxtjwHNkXVkZYa')).slice(2);
  const peer = '0x00' + ethers.toBeHex(ethers.decodeBase58('12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA')).slice(2);
  return [
    '0xe3010170' + v0.slice(2),
    '0xe30101700003616263',
    '0xe30101551220178009fb926120f294c60ebc3ae54de9dccaace22db785445f6f54a807b322fd',
    '0xe30101a9021220' + '07'.repeat(32),
    '0xe3010170128100aa',
    '0xe3010170' + '12ffffffff0f',
    '0xe3010155128180808010ab',
    '0xe301017012' ,
    '0xe5010172' + peer.slice(2),
    '0xe50101720024' + '08',
    '0xe40101fa011b20' + 'ab'.repeat(32),
    '0xe40101fa011b20' + 'ab'.repeat(33),
    '0x90b2c60f0000',
    '0xbc037a6a76',
    '0x1220' + 'aa'.repeat(32),
    '0xe301',
    '0xe30101',
    '0xe3010170',
    '0xe301010170',
  ];
}

function buildContenthash(reference) {
  const { parseContentHashBytes } = reference.ensResolver.__internals;
  return contenthashInputs(reference).map((input) => ({ input, js: parseContentHashBytes(input) }));
}

// ---------------------------------------------------------------------------
// ABI: ethers v6's strict decoder, field by field.

function describeField(type, read) {
  try {
    const value = read();
    if (type === 'string[]') return { value: [...Array(value.length).keys()].map((i) => describeField('string', () => value[i])) };
    if (typeof value === 'bigint') return { value: value.toString() };
    return { value };
  } catch (error) {
    return { error: error.code || error.message };
  }
}

/** One string of `length` bytes, aliased by every item of a string[]. */
function aliasedStrings(count, length) {
  const word = (n) => n.toString(16).padStart(64, '0');
  const head = word(32) + word(count) + word(32 * count).repeat(count); // item offsets are relative to the items
  return '0x' + head + word(length) + '7a'.repeat(length);
}

function abiCases({ ethers }) {
  const coder = ethers.AbiCoder.defaultAbiCoder();
  const enc = (types, values) => coder.encode(types, values);
  const good = enc(['bytes', 'address'], ['0x68656c6c6f', '0x' + '07'.repeat(20)]);
  const word = (hex) => hex.padStart(64, '0');
  const flip = (hex, byteIndex, value) => hex.slice(0, 2 + 2 * byteIndex) + value + hex.slice(4 + 2 * byteIndex);
  return [
    { types: ['bytes', 'address'], data: good },
    { types: ['bytes', 'address'], data: good.slice(0, -2) },
    { types: ['bytes', 'address'], data: flip(good, 32, '01') },
    { types: ['bytes', 'address'], data: flip(good, 31, 'ff') },
    { types: ['bytes', 'address'], data: flip(good, 0, '01') },
    { types: ['bytes', 'address'], data: flip(good, 64, '01') },
    { types: ['string', 'uint256'], data: enc(['bytes', 'uint256'], ['0xc080', 7]) },
    { types: ['string', 'uint256'], data: enc(['string', 'uint256'], ['héllo', 7]) },
    { types: ['string', 'address', 'address'], data: enc(['string', 'address', 'address'], ['vitalik.eth', '0x' + '11'.repeat(20), '0x' + '22'.repeat(20)]) },
    { types: ['address', 'string[]', 'bytes', 'bytes4', 'bytes'], data: enc(['address', 'string[]', 'bytes', 'bytes4', 'bytes'], ['0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe', ['https://a.example/{data}', 'https://b.example'], '0x0102', '0xdeadbeef', '0x09']) },
    // A string[] count that claims more items than the data could hold.
    { types: ['string[]'], data: '0x' + word('20') + word('ffff') },
    // Two offsets to the same string (aliased tails are legal).
    { types: ['string', 'string'], data: (() => { const one = enc(['string'], ['shared']); return '0x' + word('40') + word('40') + one.slice(2 + 64); })() },
    // The 1,024x read cap: a string[] whose items all alias one 64 KiB
    // string. ethers counts 64 + count * (64 + 65,536) bytes read against
    // 1,024 x the data length, so 2,047 items fit and 2,048 don't. Stored as
    // a recipe (aliasedStrings) that the replay rebuilds.
    ...[2047, 2048].map((count) => ({ types: ['string[]'], recipe: { aliased_strings: count, string_length: 65536 } })),
    { types: ['bytes'], data: '0x' },
    { types: ['address'], data: '0x' + word('ff'.repeat(20)) },
  ].map(({ types, data: given, recipe }) => {
    const data = recipe ? aliasedStrings(recipe.aliased_strings, recipe.string_length) : given;
    let result;
    const tag = recipe ? { recipe } : { data };
    try {
      result = coder.decode(types, data);
    } catch (error) {
      return { types, ...tag, js: { error: error.code || error.message } };
    }
    // Arrays of thousands of strings are summarized by count and first item.
    const fields = types.map((type, i) => describeField(type, () => result[i]));
    if (recipe) {
      for (const f of fields) {
        if (Array.isArray(f.value)) f.value = { count: f.value.length, first_length: f.value[0]?.value?.length ?? null };
      }
    }
    return { types, ...tag, js: { fields } };
  });
}

// ---------------------------------------------------------------------------
// The Universal Resolver and NameNFT

function offchainLayouts({ ethers }) {
  const coder = ethers.AbiCoder.defaultAbiCoder();
  const canonical = coder.encode(['address', 'string[]', 'bytes', 'bytes4', 'bytes'], [
    '0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe', ['https://gw.example/{data}'], '0x0102', '0xdeadbeef', '0x09',
  ]);
  const at = (hex, byte, value) => hex.slice(0, 2 + 2 * byte) + value + hex.slice(2 + 2 * byte + value.length);
  return [
    ['canonical', canonical],
    // Nonzero bytes after the callback selector (word 3).
    ['callback-padding', at(canonical, 3 * 32 + 4, 'ff')],
    ['trailing-bytes', canonical + 'ab'.repeat(32)],
    ['sender-high-bits', at(canonical, 0, '01')],
    ['urls-offset-out-of-range', at(canonical, 32 + 30, 'ffff')],
    ['short', canonical.slice(0, 2 + 2 * 100)],
    ['two-urls', coder.encode(['address', 'string[]', 'bytes', 'bytes4', 'bytes'], ['0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe', ['https://a.example', 'https://b.example/{data}'], '0x', '0x00000000', '0x'])],
  ];
}

function describeLookup(decode) {
  try {
    const r = decode();
    return { value: { sender: r.sender.toLowerCase(), urls: [...r.urls], call_data: r.calldata, callback: r.selector, extra_data: r.extraData } };
  } catch (error) {
    return { error: error.code || error.message };
  }
}

function buildOffchain(reference, checkout) {
  const { ethers } = reference;
  const coder = ethers.AbiCoder.defaultAbiCoder();
  const builtin = loadWithInternals(checkout, 'node_modules/ethers/lib.commonjs/providers/abstract-provider.js', ['parseOffchainLookup'], {});
  return offchainLayouts(reference).map(([id, data]) => ({
    id,
    data: '0x556f1830' + data.slice(2),
    // The pinned RPC path: AbiCoder.decode, all five fields destructured.
    strict: describeLookup(() => {
      const [sender, urls, calldata, selector, extraData] = coder.decode(['address', 'string[]', 'bytes', 'bytes4', 'bytes'], data);
      return { sender, urls, calldata, selector, extraData };
    }),
    // ethers' built-in parser, used on the Myotis and Colibri paths.
    builtin: describeLookup(() => builtin.__internals.parseOffchainLookup(data)),
  }));
}

function buildUr({ ensResolver, ethers }) {
  const ui = ensResolver.__internals;
  const ur = new ethers.Interface(ui.UR_ABI);
  const coder = ethers.AbiCoder.defaultAbiCoder();
  const revert = (signature, types, values) => ethers.id(signature).slice(0, 10) + coder.encode(types, values).slice(2);
  const resolveResult = (hex) => {
    try {
      const result = ur.decodeFunctionResult('resolve', hex);
      return { fields: [describeField('bytes', () => result[0]), describeField('address', () => result[1])] };
    } catch (error) {
      return { error: error.code || error.message };
    }
  };
  const results = [
    coder.encode(['bytes', 'address'], ['0x1234', '0x' + '33'.repeat(20)]),
    coder.encode(['bytes', 'address'], ['0x1234', '0x' + '33'.repeat(20)]).slice(0, -2),
    coder.encode(['bytes', 'address'], ['0x1234', '0x' + '33'.repeat(20)]) + '00'.repeat(32),
    '0x',
  ].map((data) => ({ data, js: resolveResult(data) }));
  const reverts = [
    revert('ResolverNotFound(bytes)', ['bytes'], ['0x0376697461']),
    revert('ResolverNotContract(bytes,address)', ['bytes', 'address'], ['0x00', '0x' + '44'.repeat(20)]),
    revert('ReverseAddressMismatch(string,bytes)', ['string', 'bytes'], ['vitalik.eth', '0x']),
    revert('ReverseAddressMismatch(string,bytes)', ['string', 'bytes'], ['', '0x']),
    revert('ReverseAddressMismatch(string,bytes)', ['string', 'bytes'], ['vitalik.eth', '0x']).slice(0, -64),
    revert('ResolverError(bytes)', ['bytes'], ['0x']),
    '0x77209FE8',
    '0x1234',
  ].map((data) => ({
    data,
    js: {
      selector: data.length >= 10 ? data.slice(0, 10).toLowerCase() : null,
      mismatch: ui.isReverseAddressMismatchError({ data }),
      claimed_name: ui.decodeReverseMismatchClaimedName({ data }),
    },
  }));
  const node = ethers.namehash('vitalik.eth');
  const calls = {
    resolve: ur.encodeFunctionData('resolve', [ethers.dnsEncode('vitalik.eth', 255), '0xbc1c58d1' + node.slice(2)]),
    reverse: ur.encodeFunctionData('reverse', [ethers.getBytes('0x' + 'ab'.repeat(20)), 60n]),
    addr_multicoin: '0xf1cb7e06' + coder.encode(['bytes32', 'uint256'], [node, 2147492101n]).slice(2),
    reverse_resolve: new ethers.Interface(ui.NAME_NFT_ABI).encodeFunctionData('reverseResolve', ['0x' + 'ab'.repeat(20)]),
  };
  const reverseOutcomes = [[0, ''], [1, 'vitalik.eth'], [2, 'claimed.eth'], [3, 'error detail']].map(([status, detail]) => ({
    status, detail, encoded: ui.encodeReverseOutcome(status, detail),
  }));
  const nodes = ['0x' + 'bc1c58d1' + node.slice(2), '0x3b3b57de' + node.slice(2) + '00', '0x3b3b57de' + node.slice(2, 60), 'nope']
    .map((input) => ({ input, js: attempt(() => ui.nodeFromResolverCallData(input)) }));
  const lookup = coder.encode(['address', 'string[]', 'bytes', 'bytes4', 'bytes'], [
    '0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe', ['https://gw.example/{sender}/{data}.json', 'https://gw2.example'], '0x0102', '0xdeadbeef', '0x09',
  ]);
  const callback = { selector: '0xdeadbeef', response: '0xcafe', extra: '0x09', encoded: '0xdeadbeef' + coder.encode(['bytes', 'bytes'], ['0xcafe', '0x09']).slice(2) };
  return { results, reverts, calls, reverse_outcomes: reverseOutcomes, nodes, offchain_lookup: '0x556f1830' + lookup.slice(2), callback };
}

// ---------------------------------------------------------------------------
// CCIP gateways, through the reference's own ccipReadFetch.

function fakeRequest(record, respond) {
  const { FakeClientRequest, emitResponse } = record.helpers;
  return (options) => {
    const request = new FakeClientRequest(options);
    request.end = () => {
      record.requests.push({ url: options.url, method: options.method, body: Buffer.concat(request.written).toString('utf8') || null });
      setImmediate(() => respond(request, emitResponse));
    };
    return request;
  };
}

async function buildCcip(checkout) {
  const { ccipReadFetch } = loadWithInternals(checkout, 'src/main/ens/ccip-fetch.js', [], { electron: ELECTRON });
  const helpers = require(path.join(checkout, 'test/helpers/fake-electron-net.js'));
  const sender = '0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe';
  const run = async (templates, data, body, status = 200) => {
    const record = { requests: [], helpers };
    const requestImpl = fakeRequest(record, (request, emit) => emit(request, { status, chunks: [body] }));
    try {
      const result = await ccipReadFetch({ to: sender }, data, templates, undefined, { requestImpl, resolveProxy: async () => 'DIRECT' });
      return { requests: record.requests, result };
    } catch (error) {
      return { requests: record.requests, error: error.code || error.message };
    }
  };
  const templates = [
    'https://gw.example/{sender}/{data}.json', 'https://gw.example/lookup', 'https://GW.Example./x/{data}',
    'file:///etc/passwd', 'http://127.0.0.1:1633/stamps/1/17', 'http://gateway.example/query', 'https://127.0.0.1/query',
    'https://2130706433/query', 'https://[::1]/query', 'https://[::ffff:127.0.0.1]/query', 'https://localhost./query',
    'https://node.localhost/query', 'https://node.local/query', 'https://node.internal/query', 'https://node/query',
    'https://user:password@gateway.example/query', 'https://user@gateway.example/query', 'https://0x7f.1/q', 'https://127.1/q',
    'https://0300.0250.0.1/q', 'not a url', 'https://xn--nxasmq6b.example/{data}', 'https://bücher.example/{data}',
  ];
  const policy = [];
  for (const template of templates) policy.push({ template, data: '0x0102', ...(await run([template], '0x0102', JSON.stringify({ data: '0x00' }))) });
  const bodies = [
    '{"data":"0x00ff"}', '{"data":"0x"}', '{"data":"0x0"}', '{"data":"00ff"}', '{"data":"0X00"}', '{"data":"0xzz"}',
    '{"data":1}', '[1]', '\uFEFF{"data":"0x"}', 'nope', '{"data":"0x01","data":"0x02"}', '{"x":"\uFFFD","data":"0x01"}',
    // JSON as V8 reads it: huge numbers, escaped lone surrogates, deep
    // nesting, and a repeated key whose last value isn't a string.
    '{"data":"0x01","ignored":1e400}', '{"x":"\\ud800","data":"0x01"}',
    '{"data":"0x01","deep":' + '['.repeat(130) + ']'.repeat(130) + '}', '{"data":"0x01","data":5}', '{"data":"0x01"} ',
    '{"data":"0x01",}', '{"data":"\\u0030x01"}',
  ];
  const answers = [];
  for (const body of bodies) answers.push({ body, ...(await run(['https://gw.example/{data}'], '0x01', body)) });
  // Invalid UTF-8 outside `data`, and a non-2xx status.
  answers.push({ body_hex: Buffer.from('{"x":"\xff","data":"0x01"}', 'latin1').toString('hex'), ...(await run(['https://gw.example/{data}'], '0x01', Buffer.from('{"x":"\xff","data":"0x01"}', 'latin1'))) });
  answers.push({ body: '{"data":"0x01"}', status: 404, ...(await run(['https://gw.example/{data}'], '0x01', '{"data":"0x01"}', 404)) });
  return { sender, policy, answers };
}

// ---------------------------------------------------------------------------
// Tezos Domains

function buildTezos({ tezos }) {
  const ti = tezos.__internals;
  const keys = ['awesome-tezos.tez', 'a.tez', '', 'ünïcödé.tez', 'x'.repeat(300)];
  const scriptExpr = keys.map((key) => ({ key, js: tezos.scriptExprHash(new TextEncoder().encode(key)) }));
  const names = ['Awesome-Tezos.TEZ', 'a.eth', '.tez', 'a..tez', 'a b.tez', 'a/b.tez', 'a\u0001.tez', 'a?.tez', 'a#.tez',
    'a'.repeat(251) + '.tez', 'a'.repeat(252) + '.tez', 'ΟΔΟΣ.tez', '\u2028a.tez'].map((name) => ({ name, js: tezos.isTezosDomainName(name) }));
  const uris = [
    ['https://Example.org/a', true], ['http://example.org', false], ['ipfs://x', true], ['ipfs://bafyCID/a/b/', false],
    ['ipns://k51key/', false], ['ipfs://self.tez/', false], ['ipns://self.tez./', false], ['ipns://self%2Etez/', false],
    ['ipns://%zz%2Etez/', false], ['ipfs://cid:8080/', false], ['ipfs://user@cid/', false], ['https://user@example.org/', false],
    ['ftp://example.org/', false], ['not a url', false], [42, false], [null, false], ['https://' + 'a'.repeat(8200), false],
    ['ipfs://bafy/', false], ['ipfs://BAFY/x', false], ['https:///nohost', false], ['ipns://name.eth/', false],
  ].map(([raw, redirect]) => ({ raw, redirect, js: tezos.parsePublishedUri(raw, { redirect }) }));
  const contentUrl = Buffer.from('"https://example.org"').toString('hex');
  const maps = [
    [{ prim: 'Elt', args: [{ string: 'web:content_url' }, { bytes: '00' }] }, { prim: 'Elt', args: [{ string: 'web:content_url' }, { bytes: contentUrl }] }, { prim: 'Elt', args: [{ int: '1' }, { bytes: '00' }] }],
    [{ prim: 'Elt', args: [{ string: 'td:ttl' }] }],
    'not an array',
  ].map((value) => ({ value, js: [...ti.mapEntries(value)].map(([key, bytes]) => [key, bytes ?? null]) }));
  const hexOf = (text) => Buffer.from(text).toString('hex');
  const metadata = [
    contentUrl, '7b', '0', 'zz', hexOf('3600'), hexOf('{"a":1}'), Buffer.from('\xff"x"', 'latin1').toString('hex'),
    hexOf('9007199254740993'), hexOf('1e400'), hexOf('-0'), hexOf('"\\ud800"'), hexOf('{"b":1,"2":0,"a":3,"1":4,"01":5,"a":6}'),
    hexOf('[' .repeat(200) + ']'.repeat(200)), hexOf('1.5e-7'), hexOf('123456789012345680000'),
  ].map((hex) => {
    const result = attempt(() => ti.decodeJsonBytes(hex));
    // A lone surrogate survives in a JS string; a Rust string holds U+FFFD
    // (design 0003, jsjson).
    const loneSurrogate = typeof result.value === 'string' && /[\uD800-\uDFFF]/.test(result.value.replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]/g, ''));
    // Recorded as JSON.stringify, so non-JSON doubles (Infinity) survive.
    return {
      hex,
      ...(loneSurrogate ? { deviation: 'lone-surrogate' } : {}),
      js: result.error ? result : { stringified: JSON.stringify(result.value) },
    };
  });
  const ty = { prim: 'pair', args: [{ prim: 'address', annots: ['%contract'] }, { prim: 'PAIR', args: [{ prim: 'nat', annots: ['%x'] }, { prim: 'big_map', annots: ['%records'] }] }] };
  const value = { prim: 'Pair', args: [{ string: 'KT1x' }, { prim: 'Pair', args: [{ int: '1' }, { int: '42' }] }] };
  const annotated = ['%contract', '%records', '%x', '%missing'].map((annotation) => ({ annotation, js: tezos._test.findAnnotatedValue(ty, value, annotation) }));
  // Edge cases: nesting past 64, a prim that is an array, and args or code
  // without flatMap/find (TypeErrors in the JS).
  let deepType = { annots: ['%records'] };
  let deepValue = { int: '7' };
  for (let i = 0; i < 65; i += 1) {
    deepType = { prim: 'pair', args: [deepType] };
    deepValue = { prim: 'Pair', args: [deepValue] };
  }
  const walk = (type, val, annotation) => {
    try {
      return { value: tezos._test.findAnnotatedValue(type, val, annotation) };
    } catch (error) {
      return { error: error.name };
    }
  };
  const micheline = [
    { type: deepType, value: deepValue, annotation: '%records' },
    { type: { prim: ['PAIR'], args: [{ annots: ['%a'] }, { annots: ['%b'] }] }, value: { prim: 'Pair', args: [1, 2] }, annotation: '%b' },
    { type: { prim: 'pair', args: 'x' }, value: 1, annotation: '%a' },
    { type: { prim: 'pair', args: [{ annots: ['%a'] }] }, value: { prim: 'Pair', args: 'xy' }, annotation: '%a' },
    { type: 0, value: 1, annotation: '%a' },
    { type: { annots: ['%a'] }, value: null, annotation: '%a' },
  ].map((c) => ({ ...c, js: walk(c.type, c.value, c.annotation) }));
  const scripts = [
    { code: [{ prim: 'parameter' }, { prim: 'storage', args: [{ prim: 'nat' }] }] },
    { code: 'x' },
    { code: null },
    {},
    { code: [{ prim: 'storage', args: 'abc' }] },
    { code: [{ prim: 'storage', args: [] }] },
  ].map((script) => {
    try {
      return { script, js: { value: ti.storageTypeFromScript(script) } };
    } catch (error) {
      return { script, js: { error: error.name } };
    }
  });
  return { script_expr: scriptExpr, names, uris, maps, metadata, annotated: { type: ty, value, cases: annotated }, micheline, scripts };
}

async function buildNaming(checkout, ethers, meta) {
  const reference = { ensResolver: loadEnsResolver(checkout), tezos: loadTezos(checkout), ethers };
  assert.equal(reference.ethers.namehash('vitalik.eth'), '0xee6c4522aab0003e8d14cd40a6af439055fd2577951148c14b6cea9a53475835', 'STOP: namehash sanity check failed');
  return {
    meta,
    names: buildNames(reference),
    coin_types: buildCoinTypes(reference),
    contenthash: buildContenthash(reference),
    abi: abiCases(reference),
    ur: buildUr(reference),
    ccip: await buildCcip(checkout),
    offchain_lookup: buildOffchain(reference, checkout),
    tezos: buildTezos(reference),
  };
}

module.exports = { buildNaming };
