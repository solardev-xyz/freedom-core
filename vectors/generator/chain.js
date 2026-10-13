'use strict';

// Chain-data codec vectors (design 0005, step 1): the reference's own
// chain-data-router.js, blockscout-logs.js and the Ant bridge
// (swarm/ant-chain-bridge.js) produce every expected output, except the
// broadcast refusals, which are the design's own (see there). Their internal
// functions are reached through naming.js's harness, which appends
// test-only exports to the original source and stubs the router's modules,
// so no reference code is copied here. The observers appended below only
// record, in order, the errors the sources throw on the way to the router's
// aggregate texts; they change nothing the router does.
//
// JavaScript strings that may hold lone surrogates (messages, texts) are
// recorded as their JSON.stringify text (`*_json`), which is always
// well-formed, so the file stays valid UTF-8 for any JSON reader.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { loadWithInternals } = require('./naming');

const SILENT_LOG = { verbose() {}, info() {}, warn() {}, error() {}, debug() {}, log() {} };
const ELECTRON = {
  ipcMain: { handle() {}, on() {}, removeHandler() {} },
  net: {},
  session: { defaultSession: { resolveProxy: async () => 'DIRECT' } },
  app: { getPath: () => '/nonexistent' },
  BrowserWindow: { getAllWindows: () => [] },
};
// The deepest nesting the core accepts (design 0005, deviation json-depth).
const MAX_DEPTH = 512;
// Decimal conversions the core makes stop below 2^4096 (deviation
// bigint-width, reported with this step).
const BIGINT_BITS = 4096;

// Wraps the named internal functions to record each error they throw, and
// bypasses the adaptive routing reports. Returns a function that restores
// the originals.
const OBSERVER = `
module.exports.__observe = function observe(events, names) {
  const originals = { requestSource, requestDirect, requestDirectFeeQuote, adaptiveSourceUnavailable };
  const record = (name, sourceOf) => async function observed(...args) {
    try {
      return await originals[name].apply(this, args);
    } catch (error) {
      events.push({ source: sourceOf(args), error });
      throw error;
    }
  };
  for (const name of names) {
    if (name === 'requestSource') requestSource = record(name, (args) => args[0]);
    else if (name === 'requestDirect') requestDirect = record(name, () => 'direct');
    else if (name === 'requestDirectFeeQuote') requestDirectFeeQuote = record(name, () => 'direct');
    else if (name === 'adaptiveSourceUnavailable') {
      adaptiveSourceUnavailable = function observed(routeKey, ...rest) {
        const bypassed = originals.adaptiveSourceUnavailable(routeKey, ...rest);
        if (bypassed) events.push({ source: JSON.parse(routeKey)[0], bypassed: true });
        return bypassed;
      };
    } else throw new Error('Unknown observer ' + name);
  }
  return () => {
    requestSource = originals.requestSource;
    requestDirect = originals.requestDirect;
    requestDirectFeeQuote = originals.requestDirectFeeQuote;
    adaptiveSourceUnavailable = originals.adaptiveSourceUnavailable;
  };
};
`;

/** The world the router's stubbed modules read; each scenario sets it. */
function createWorld() {
  const world = {
    router: null,
    network: {},
    endpoints: {},
    myotisReady: false,
    // Errors the Myotis and Colibri stubs throw, by source, as
    // SourceUnavailableErrors with exactly these messages.
    messages: {},
    // When set, the Myotis stubs record their own errors: the fee quote and
    // the broadcast call them directly, where no wrapper sees them. (Colibri
    // is always reached through requestSource, which the observer wraps.)
    events: null,
    fail(source) {
      const error = new world.router.SourceUnavailableError(world.messages[source]);
      if (world.events && source === 'myotis') world.events.push({ source, error });
      throw error;
    },
    // Each Myotis read operation (getAccount, ethCallTx, ...) by name, with
    // its arguments; the Myotis payload scenarios answer it.
    myotisOperation: () => world.fail('myotis'),
    myotisStatus: () => ({}),
  };
  return world;
}

function loadRouter(checkout, world) {
  const registry = {
    getNetwork: () => world.network,
    getEndpoints: (_chainId, kind) => world.endpoints[kind] || [],
  };
  const operation = (name) => async (...args) => world.myotisOperation(name, args);
  const myotis = {
    NETWORKS: new Set([1]),
    isReady: () => world.myotisReady,
    getStatus: (...args) => world.myotisStatus(...args),
    getAccount: operation('getAccount'),
    getCode: operation('getCode'),
    getStorageAt: operation('getStorageAt'),
    ethCallTx: operation('ethCallTx'),
    estimateGas: operation('estimateGas'),
    feeEstimate: operation('feeEstimate'),
    sendRawTransaction: async () => world.fail('myotis'),
  };
  const colibri = { requestViaColibri: async () => world.fail('colibri') };
  const router = loadWithInternals(checkout, 'src/main/networks/chain-data-router.js',
    ['normalizeParams', 'stableValue', 'safeErrorMessage', 'feeQuote',
      'requestMyotis', 'requestViaMyotis', 'MYOTIS_CAPABILITY_REFUSAL', 'MAX_MYOTIS_REFUSAL_MESSAGE',
      'MYOTIS_BLOB_FIELDS', 'READ_METHODS', 'SINGLE_NODE_METHODS', 'logRangeRefusal',
      'LOG_SCAN_QUORUM_ROUNDS', 'LOG_INDEX_ABORT_COOLDOWN_MS'], {
      electron: ELECTRON,
      '../logger': SILENT_LOG,
      './network-registry': registry,
      '../myotis/myotis-manager': myotis,
      '../ens/colibri-resolver': colibri,
    }, OBSERVER);
  world.router = router;
  return router;
}

const jsonText = (value) => JSON.stringify(value);

function describeError(error) {
  const described = { name: error.name, message_json: jsonText(error.message) };
  // The router sets `code` and `data` on a node error even when the answer
  // has none (undefined, recorded as null).
  for (const key of ['code', 'data']) {
    if (Object.hasOwn(error, key)) described[`${key}_json`] = error[key] === undefined ? null : jsonText(error[key]);
  }
  return described;
}

// ---------------------------------------------------------------------------
// normalizeParams

function normalizationInputs() {
  const call = (fields) => jsonText([{ to: '0x' + '11'.repeat(20), ...fields }]);
  const value = (v) => call({ value: v });
  const cases = [
    // Params that aren't a call: returned as they are.
    ['not-call-method', 'eth_getBalance', jsonText(['0x' + '11'.repeat(20), 'latest'])],
    ['not-call-method-with-value', 'eth_sendTransaction', value('10')],
    ['params-object', 'eth_call', '{"value":"10"}'],
    ['params-null', 'eth_call', 'null'],
    ['params-string', 'eth_call', '"0x10"'],
    ['params-empty', 'eth_call', '[]'],
    ['call-null', 'eth_call', '[null,"latest"]'],
    ['call-string', 'eth_call', '["0x10"]'],
    ['call-array', 'eth_call', '[["0x10"]]'],
    ['call-number', 'eth_call', '[10]'],
    ['call-empty', 'eth_call', '[{}]'],
    // BigInt(string), quirks included.
    ['decimal', 'eth_call', value('1000')],
    ['decimal-estimate', 'eth_estimateGas', value('1000')],
    ['decimal-spaces', 'eth_call', value(' 12 ')],
    ['decimal-tabs-newlines', 'eth_call', value('\t12\n\r')],
    ['decimal-unicode-spaces', 'eth_call', value('   7 　﻿')],
    ['decimal-vt-ff', 'eth_call', value('\u000b7\u000c')],
    ['decimal-nel-not-space', 'eth_call', value('\u00857')],
    ['decimal-mongolian-not-space', 'eth_call', value('᠎7')],
    ['decimal-leading-zeros', 'eth_call', value('00012')],
    ['decimal-plus', 'eth_call', value('+5')],
    ['decimal-negative', 'eth_call', value('-1')],
    ['decimal-negative-large', 'eth_call', value('-1000000000000000000000')],
    ['decimal-negative-zero', 'eth_call', value('-0')],
    ['decimal-only-spaces', 'eth_call', value('   ')],
    ['decimal-exponent', 'eth_call', value('1e3')],
    ['decimal-fraction', 'eth_call', value('1.5')],
    ['decimal-separator', 'eth_call', value('1_000')],
    ['decimal-arabic-digits', 'eth_call', value('١٢')],
    ['decimal-fullwidth-digits', 'eth_call', value('１２')],
    ['decimal-double-sign', 'eth_call', value('--1')],
    ['decimal-sign-space', 'eth_call', value('- 1')],
    ['decimal-lone-sign', 'eth_call', value('-')],
    ['decimal-infinity', 'eth_call', value('Infinity')],
    ['decimal-inner-space', 'eth_call', value('1 2')],
    ['decimal-nul', 'eth_call', value('\u00001')],
    ['decimal-2-256', 'eth_call', value((2n ** 256n).toString())],
    ['decimal-uint256-max', 'eth_call', value((2n ** 256n - 1n).toString())],
    ['hex-canonical', 'eth_call', value('0x1a')],
    ['hex-upper-digits', 'eth_call', value('0x1A')],
    ['hex-upper-prefix', 'eth_call', value('0X10')],
    ['hex-zero-padded', 'eth_call', value('0x0010')],
    ['hex-zero', 'eth_call', value('0x0')],
    ['hex-zeros', 'eth_call', value('0x00')],
    ['hex-empty', 'eth_call', value('0x')],
    ['hex-bad-digit', 'eth_call', value('0xg')],
    ['hex-negative', 'eth_call', value('-0x5')],
    ['hex-plus', 'eth_call', value('+0x5')],
    ['hex-spaces', 'eth_call', value(' 0x10 ')],
    ['hex-trailing-newline', 'eth_call', value('0x1\n')],
    ['hex-inner-space', 'eth_call', value('0x 1')],
    ['hex-double-prefix', 'eth_call', value('0x0x1')],
    ['hex-zero-prefix', 'eth_call', value('00x1')],
    ['hex-separator', 'eth_call', value('0x1_0')],
    ['hex-wide', 'eth_call', value('0x' + '0'.repeat(300) + 'f'.repeat(1500))],
    ['binary', 'eth_call', value('0b101')],
    ['binary-upper', 'eth_call', value('0B101')],
    ['binary-empty', 'eth_call', value('0b')],
    ['binary-bad-digit', 'eth_call', value('0b102')],
    ['binary-wide', 'eth_call', value('0b' + '1'.repeat(5000))],
    ['octal', 'eth_call', value('0o17')],
    ['octal-upper', 'eth_call', value('0O17')],
    ['octal-bad-digit', 'eth_call', value('0o8')],
    ['octal-wide', 'eth_call', value('0o' + '7'.repeat(2000) + '1')],
    ['octal-padded', 'eth_call', value('0o0001234567')],
    ['lone-surrogate', 'eth_call', '[{"value":"\\ud800"}]'],
    // BigInt(number): integers only; `value || 0` makes -0 zero.
    ['number', 'eth_call', '[{"gas":21000}]'],
    ['number-zero', 'eth_call', '[{"value":0}]'],
    ['number-negative-zero', 'eth_call', '[{"value":-0}]'],
    ['number-negative', 'eth_call', '[{"value":-5}]'],
    ['number-fraction', 'eth_call', '[{"value":1.5}]'],
    ['number-exponent', 'eth_call', '[{"value":1e2}]'],
    ['number-1e21', 'eth_call', '[{"value":1e21}]'],
    ['number-2-53-plus-1', 'eth_call', '[{"value":9007199254740993}]'],
    ['number-max', 'eth_call', '[{"value":1.7976931348623157e308}]'],
    ['number-min-subnormal', 'eth_call', '[{"value":5e-324}]'],
    ['number-infinite', 'eth_call', '[{"value":1e400}]'],
    ['number-underflow', 'eth_call', '[{"value":1e-400}]'],
    // Skipped values.
    ['null-value', 'eth_call', '[{"value":null}]'],
    ['empty-string', 'eth_call', '[{"value":""}]'],
    ['boolean', 'eth_call', '[{"value":true}]'],
    ['object-value', 'eth_call', '[{"value":{"x":1}}]'],
    ['array-value', 'eth_call', '[{"value":["1"]}]'],
    // Every quantity field, in their own positions, and the others untouched.
    ['all-fields', 'eth_call', jsonText([{
      from: '0x' + '22'.repeat(20), to: '0x' + '11'.repeat(20), gas: 21000, gasPrice: '1000000000',
      maxFeePerGas: '0x0Af', maxPriorityFeePerGas: '0x1', value: ' 1 ', nonce: 7, chainId: 1, type: 2,
      accessList: [], blobVersionedHashes: ['0x01'], data: '0xabcd',
    }, 'latest'])],
    ['other-fields-untouched', 'eth_call', jsonText([{ input2: '10', Value: '10', VALUE: '10', gas_price: '10' }])],
    ['estimate-with-tag-and-overrides', 'eth_estimateGas', jsonText([{ value: '16' }, '0x10', { ['0x' + '11'.repeat(20)]: { balance: '0x1' } }])],
    // The input alias and the appended data key.
    ['input-only', 'eth_call', jsonText([{ to: '0x' + '11'.repeat(20), input: '0xabcd', value: '1' }])],
    ['input-and-data', 'eth_call', jsonText([{ input: '0xabcd', data: '0x1234' }])],
    ['input-and-empty-data', 'eth_call', jsonText([{ data: '0x', to: '0x' + '11'.repeat(20), input: '0xabcd' }])],
    ['input-and-blank-data', 'eth_call', jsonText([{ data: '', input: '0xabcd' }])],
    ['input-and-spaced-upper-data', 'eth_call', jsonText([{ data: '  0X  ', input: '0xabcd' }])],
    ['input-and-number-data', 'eth_call', jsonText([{ data: 5, input: '0xabcd' }])],
    ['input-and-null-data', 'eth_call', jsonText([{ data: null, input: '0xabcd' }])],
    ['input-empty', 'eth_call', jsonText([{ input: '0x' }])],
    ['input-upper-prefix-empty', 'eth_call', jsonText([{ input: ' 0X ' }])],
    ['input-blank', 'eth_call', jsonText([{ input: '   ' }])],
    ['input-number', 'eth_call', jsonText([{ input: 5 }])],
    ['input-kept-as-sent', 'eth_call', jsonText([{ input: ' 0XAB ' }])],
    ['input-not-hex', 'eth_call', jsonText([{ input: 'hello' }])],
    ['input-with-index-keys', 'eth_call', '[{"1":"b","input":"0xab","0":"a"}]'],
    ['input-lone-surrogate', 'eth_call', '[{"input":"\\udc00"}]'],
    // JSON.parse's objects: duplicates, property order, __proto__.
    ['duplicate-value', 'eth_call', '[{"value":"1","to":"0x","value":"2"}]'],
    ['duplicate-value-null-last', 'eth_call', '[{"value":"1","value":null}]'],
    ['duplicate-data', 'eth_call', '[{"data":"0x","input":"0xab","data":""}]'],
    ['duplicate-input', 'eth_call', '[{"input":"0xab","input":"0x"}]'],
    ['escaped-key', 'eth_call', '[{"\\u0076alue":"10"}]'],
    ['index-keys-first', 'eth_call', '[{"value":"10","2":"x","1":"y","01":"z"}]'],
    ['proto-key', 'eth_call', '[{"__proto__":{"value":"10","input":"0xab"},"gas":"5"}]'],
    ['proto-only', 'eth_call', '[{"__proto__":{"value":"10"}}]'],
    // The rest is written as JSON.stringify writes it.
    ['canonical-output', 'eth_call', '[ { "value" : "10" , "x" : 1.0E2 , "y" : [ -0, 1e400, "\\u0041\\/" ] } , "latest" ]'],
    ['canonical-unchanged', 'eth_call', '[ { "value" : "0x10" , "x" : 1.0E2 } ]'],
    ['lone-surrogates-kept', 'eth_call', '[{"to":"\\ud800","value":"1","\\udfff":"\\ud83d\\ude00\\ud83d"}]'],
    ['controls-escaped', 'eth_call', '[{"to":"\\u0001\\u001f\\b\\f\\n\\r\\t\\"\\\\\\u007f\\u2028","value":"1"}]'],
    ['nested-depth-512', 'eth_call', '[{"value":"1","x":' + '['.repeat(MAX_DEPTH - 2) + ']'.repeat(MAX_DEPTH - 2) + '}]'],
    ['nested-depth-513', 'eth_call', '[{"value":"1","x":' + '['.repeat(MAX_DEPTH - 1) + ']'.repeat(MAX_DEPTH - 1) + '}]', 'json-depth'],
    // Decimal conversion stops at 2^4096: the core leaves wider decimals for
    // the node to refuse, as it refuses JS's equally wide hex.
    ['decimal-width-max', 'eth_call', value((2n ** BigInt(BIGINT_BITS) - 1n).toString())],
    ['decimal-width-max-negative', 'eth_call', value('-' + (2n ** BigInt(BIGINT_BITS) - 1n).toString())],
    ['decimal-width-max-zero-padded', 'eth_call', value('0'.repeat(3000) + (2n ** BigInt(BIGINT_BITS) - 1n).toString())],
    ['decimal-width-over', 'eth_call', value((2n ** BigInt(BIGINT_BITS)).toString()), 'bigint-width'],
    ['decimal-width-far-over', 'eth_call', value('9'.repeat(5000)), 'bigint-width'],
    ['decimal-width-far-over-invalid', 'eth_call', value('9'.repeat(5000) + 'x')],
  ];
  return cases;
}

function buildNormalization(router) {
  const { normalizeParams } = router.__internals;
  const cases = normalizationInputs().map(([id, method, params, deviation]) => {
    const parsed = JSON.parse(params);
    const normalized = normalizeParams(method, parsed);
    return {
      id, method, params,
      ...(deviation ? { deviation } : {}),
      js: { params: jsonText(normalized), changed: normalized !== parsed },
    };
  });
  // Which UTF-16 units BigInt(string) trims, through the real normalizeParams.
  const whitespace = [];
  for (let unit = 0; unit < 0x10000; unit += 1) {
    const c = String.fromCharCode(unit);
    if (normalizeParams('eth_call', [{ value: `${c}1${c}` }])[0].value === '0x1') whitespace.push(unit);
  }
  return { cases, bigint_whitespace: whitespace };
}

// ---------------------------------------------------------------------------
// stableValue

const BLOCK = jsonText({
  number: '0x10', hash: '0x' + 'ab'.repeat(32), parentHash: '0x' + 'cd'.repeat(32), nonce: '0x0000000000000000',
  transactions: [
    { hash: '0x' + '01'.repeat(32), input: '0x', value: '0x0', accessList: [], v: '0x1', yParity: '0x1' },
    { hash: '0x' + '02'.repeat(32), input: '0xabcdef', value: '0xde0b6b3a7640000', to: null, chainId: '0x1' },
  ],
  withdrawals: [], uncles: [], baseFeePerGas: '0x7', size: '0x220', logsBloom: '0x' + '00'.repeat(256),
});

function stableInputs() {
  const nest = (n) => '['.repeat(n) + ']'.repeat(n);
  return [
    ['null', 'null'], ['true', 'true'], ['false', 'false'],
    ['zero', '0'], ['negative-zero', '-0'], ['negative-zero-fraction', '-0.0'], ['zero-exponent', '0e5'],
    ['hundred', '100'], ['hundred-exponent', '1e2'], ['hundred-upper-exponent', '1E+2'], ['hundred-fraction', '100.0'],
    ['hundred-split', '10e1'], ['hundred-negative-exponent', '1000e-1'],
    ['two-53', '9007199254740992'], ['two-53-plus-one', '9007199254740993'],
    ['large-integer', '123456789012345678901234567890'], ['large-integer-printed', '1.2345678901234568e+29'],
    ['e21', '1e21'], ['e20', '100000000000000000000'], ['small', '1.5e-7'], ['millionth', '0.000001'],
    ['point-three', '0.30000000000000004'], ['min-subnormal', '5e-324'], ['max', '1.7976931348623157e308'],
    ['overflow', '1e400'], ['negative-overflow', '-1e400'], ['underflow', '1e-400'], ['negative-underflow', '-1e-400'],
    ['string', '"0x1"'], ['string-escapes', '"\\u0041\\/\\"\\\\\\b\\f\\n\\r\\t"'],
    ['string-controls', '"\\u0000\\u0001\\u001f\\u007f\\u0080\\u2028\\u2029"'],
    ['string-lone-high', '"\\ud800"'], ['string-lone-high-upper', '"\\uD800"'], ['string-lone-low', '"\\udc00x"'],
    ['string-replacement', '"\\ufffd"'], ['string-pair-escaped', '"\\ud83d\\ude00"'], ['string-pair-raw', '"😀"'],
    ['string-reversed-pair', '"\\ude00\\ud83d"'], ['string-non-ascii', '"café é"'],
    ['array', '[1,"a",null,true,{}]'], ['array-spaced', ' [ 1 , "a" , null , true , { } ] '],
    ['array-reversed', '[{},true,null,"a",1]'],
    ['object', '{"a":1,"b":2}'], ['object-reversed', '{"b":2,"a":1}'], ['object-spaced', '\n{ "b" : 2 ,\t"a" : 1 }\r'],
    ['object-duplicate', '{"a":1,"b":2,"a":3}'], ['object-duplicate-first', '{"a":3,"b":2}'],
    ['object-duplicate-escaped', '{"a":1,"\\u0061":3,"b":2}'],
    ['object-index-keys', '{"b":1,"10":2,"9":3,"a":4,"01":5}'],
    ['object-utf16-order', '{"\\uffff":1,"\\ud83d\\ude00":2,"a":3,"\\u00e9":4,"":5,"\\ud800":6,"\\udc00":7,"\\ufffd":8}'],
    ['object-proto', '{"__proto__":{"a":1},"b":2}'], ['object-proto-null', '{"__proto__":null}'],
    ['object-proto-duplicate', '{"__proto__":1,"__proto__":2}'], ['object-empty', '{}'],
    ['object-lone-key', '{"\\ud800":1}'], ['object-replacement-key', '{"\\ufffd":1}'],
    ['nested', '{"z":{"y":[{"b":1,"a":[2,{"d":null,"c":-0}]}]},"a":"\\ud800"}'],
    ['block', BLOCK],
    ['depth-512', nest(MAX_DEPTH)],
    ['depth-512-objects', '{"a":'.repeat(MAX_DEPTH - 1) + '[]' + '}'.repeat(MAX_DEPTH - 1)],
    ['depth-513', nest(MAX_DEPTH + 1), 'json-depth'],
    ['depth-513-objects', '{"a":'.repeat(MAX_DEPTH) + '[]' + '}'.repeat(MAX_DEPTH), 'json-depth'],
  ];
}

// Pairs whose stableValue must, or must not, be equal. null is `undefined`,
// a missing result.
const EQUIVALENCE = [
  ['{"a":1,"a":2}', '{"a":2}'], ['{"a":1,"a":2}', '{"a":1}'], ['{"a":1,"\\u0061":2}', '{"a":2}'],
  ['{"b":1,"a":2}', '{"a":2,"b":1}'], ['{"1":1,"a":2}', '{"a":2,"1":1}'],
  ['1e2', '100'], ['100.0', '100'], ['1E+2', '100'], ['-0', '0'], ['-0.0', '0'], ['0e10', '0'],
  ['9007199254740993', '9007199254740992'], ['9007199254740993', '9007199254740994'],
  ['123456789012345678901234567890', '123456789012345680000000000000'], ['1e400', 'null'], ['-1e400', 'null'],
  ['1e-400', '0'], ['0.1', '0.10000000000000001'], ['1', '"1"'], ['true', '1'], ['null', '"null"'],
  ['{"__proto__":1}', '{}'], ['{"__proto__":{"a":1}}', '{"a":1}'], ['{"__proto__":1}', '{"__proto__":1}'],
  ['"\\ud800"', '"\\uD800"'], ['"\\ud800"', '"\\ufffd"'], ['{"\\ud800":1}', '{"\\ufffd":1}'],
  ['"\\ud83d\\ude00"', '"😀"'], ['"\\u0041\\/"', '"A/"'],
  ['["a","b"]', '["b","a"]'], ['[1,[2]]', '[1, [ 2 ] ]'], ['[]', '{}'], ['""', 'null'],
  [null, 'null'], [null, '""'], [null, '[]'], [null, null],
];

function buildStable(router) {
  const { stableValue } = router.__internals;
  const stable = (text) => (text === null ? undefined : stableValue(JSON.parse(text)));
  const cases = stableInputs().map(([id, text, deviation]) => {
    const value = stable(text);
    return {
      id, text, ...(deviation ? { deviation } : {}),
      js: { stable: value, sha256: crypto.createHash('sha256').update(value, 'utf8').digest('hex') },
    };
  });
  cases.push({ id: 'undefined', text: null, js: { stable: null, sha256: null } });
  assert.equal(stable(null), undefined);
  const equivalence = EQUIVALENCE.map(([a, b]) => ({ a, b, equal: stable(a) === stable(b) }));
  return { cases, equivalence };
}

// ---------------------------------------------------------------------------
// Answers, through the real requestRpcUrl and undici's Response

function answerInputs() {
  const utf8 = (text) => Buffer.from(text, 'utf8');
  const bytes = (...parts) => Buffer.concat(parts.map((part) => (typeof part === 'string' ? utf8(part) : Buffer.from(part))));
  const BOM = [0xef, 0xbb, 0xbf];
  const ok = '{"jsonrpc":"2.0","id":1,"result":"0x1"}';
  const nested = (n) => '{"jsonrpc":"2.0","id":1,"result":' + '['.repeat(n) + ']'.repeat(n) + '}';
  const error = (value) => `{"jsonrpc":"2.0","id":1,"error":${value}}`;
  const message = (value) => error(`{"code":-32000,"message":${value}}`);
  return [
    ['result', 200, ok],
    ['result-key-order', 200, '{"result":{"b":1,"a":2,"1":3},"id":1}'],
    ['result-duplicate', 200, '{"result":1,"id":1,"result":2}'],
    ['result-duplicate-object-then-array', 200, '{"result":{"a":1},"id":1,"result":[1, 2]}'],
    ['result-missing', 200, '{"jsonrpc":"2.0","id":1}'],
    ['result-null', 200, '{"jsonrpc":"2.0","id":1,"result":null}'],
    ['result-false', 200, '{"result":false}'],
    ['result-numbers', 200, '{"result":[1e400,-0,1E2,9007199254740993]}'],
    ['result-spaced', 200, ' \n\t{ "result" : [ 1 , { "a" : "b" } ] }\r\n '],
    ['result-escapes', 200, '{"result":"\\u0041\\ud800\\/"}'],
    ['result-block', 200, `{"jsonrpc":"2.0","id":7,"result":${BLOCK}}`],
    ['result-long-string', 200, `{"jsonrpc":"2.0","id":1,"result":"0x${'ab'.repeat(2048)}"}`],
    ['result-empty-object-body', 200, '{}'],
    ['result-proto', 200, '{"__proto__":{"result":5}}'],
    ['result-proto-error', 200, '{"__proto__":{"error":{"message":"x"}},"result":1}'],
    ['result-escaped-key', 200, '{"\\u0072esult":"0x2"}'],
    ['result-key-case', 200, '{"Result":"0x2"}'],
    // `data.error` is checked for truthiness first.
    ['error', 200, error('{"code":-32000,"message":"nonce too low"}')],
    ['error-with-data', 200, error('{"code":3,"message":"execution reverted","data":"0x08c379a0"}')],
    ['error-and-result', 200, '{"result":"0x1","error":{"code":1,"message":"m"}}'],
    ['error-null-and-result', 200, '{"error":null,"result":"0x2"}'],
    ['error-false', 200, '{"error":false,"result":"0x2"}'],
    ['error-zero', 200, '{"error":0,"result":"0x2"}'],
    ['error-negative-zero', 200, '{"error":-0.0,"result":"0x2"}'],
    ['error-underflow', 200, '{"error":1e-400,"result":"0x2"}'],
    ['error-empty-string', 200, '{"error":"","result":"0x2"}'],
    ['error-true', 200, error('true')],
    ['error-number', 200, error('1')],
    ['error-overflow', 200, error('1e400')],
    ['error-string', 200, error('"boom"')],
    ['error-empty-array', 200, error('[]')],
    ['error-array', 200, error('[{"message":"x"}]')],
    ['error-empty-object', 200, error('{}')],
    ['error-duplicate', 200, '{"error":{"code":1,"message":"a"},"error":null,"result":5}'],
    ['error-duplicate-message', 200, error('{"message":"a","code":2,"message":"b","code":3}')],
    ['error-proto', 200, error('{"__proto__":{"message":"x","code":1}}')],
    ['error-code-types', 200, error('{"code":"x","message":"m","data":{"b":[1,{"a":null}]}}')],
    ['error-code-null', 200, error('{"code":null,"message":"m","data":null}')],
    ['error-code-object', 200, error('{"code":{"a":1},"message":"m","data":[1e400,-0]}')],
    ['message-empty', 200, message('""')],
    ['message-zero', 200, message('0')],
    ['message-null', 200, message('null')],
    ['message-false', 200, message('false')],
    ['message-number', 200, message('5')],
    ['message-number-exponent', 200, message('1e21')],
    ['message-fraction', 200, message('1.5')],
    ['message-true', 200, message('true')],
    ['message-object', 200, message('{}')],
    ['message-object-value-of', 200, message('{"valueOf":1}')],
    ['message-object-to-string', 200, message('{"toString":1}')],
    ['message-array', 200, message('[1,[2,[3,null]],{"a":1},"x",true,-0,1e21]')],
    ['message-empty-array', 200, message('[]')],
    ['message-array-to-string', 200, message('[[{"toString":"x"}]]')],
    ['message-lone-surrogate', 200, message('"\\ud800 bad"')],
    ['message-escapes', 200, message('"line\\nbreak \\u0000 \\"q\\""')],
    ['message-long', 200, message(jsonText('x'.repeat(5000)))],
    // Bodies that aren't objects: `data.error` and `data.result` are undefined,
    // except for null.
    ['body-null', 200, 'null'],
    ['body-number', 200, '5'],
    ['body-zero', 200, '0'],
    ['body-string', 200, '"x"'],
    ['body-true', 200, 'true'],
    ['body-false', 200, 'false'],
    ['body-array', 200, '[{"result":1}]'],
    ['body-empty-array', 200, '[]'],
    // response.json(): UTF-8 with replacement, BOMs, V8's grammar.
    ['bom', 200, bytes(BOM, ok)],
    ['bom-twice', 200, bytes(BOM, BOM, ok)],
    ['bom-three-times', 200, bytes(BOM, BOM, BOM, ok), 'json-parse-text'],
    ['bom-after-space', 200, bytes(' ', BOM, ok), 'json-parse-text'],
    ['bom-partial', 200, bytes([0xef, 0xbb], ok), 'json-parse-text'],
    ['bom-in-result', 200, bytes('{"result":"', BOM, BOM, '"}')],
    ['utf16-bom', 200, bytes([0xfe, 0xff, 0x00, 0x7b, 0x00, 0x7d]), 'json-parse-text'],
    ['invalid-utf8-in-string', 200, bytes('{"result":"', [0x80, 0x41, 0xc3, 0x42, 0xc0, 0x80, 0xe0, 0x80, 0x80, 0xed, 0xa0, 0x80, 0xf4, 0x90, 0x80, 0x80, 0xf0, 0x9f, 0x98, 0x43, 0xe2, 0x82, 0xf5, 0xff, 0xfe], '"}')],
    ['invalid-utf8-truncated', 200, bytes('{"result":"', [0xf0, 0x9f, 0x98, 0x80, 0xf0, 0x9f], '"}')],
    ['invalid-utf8-more', 200, bytes('{"result":"', [0xe0, 0xa0, 0x41, 0xf0, 0x90, 0x42, 0xf0, 0x80, 0x80, 0x80, 0xc1, 0xbf, 0xed, 0x9f, 0xbf, 0xee, 0x80, 0x80, 0xc2], '"}')],
    ['invalid-utf8-in-key', 200, bytes('{"res', [0xff], 'ult":1,"result":2}')],
    ['invalid-utf8-outside-string', 200, bytes('{"result":1}', [0xff]), 'json-parse-text'],
    ['valid-utf8-4-byte', 200, bytes('{"result":"', [0xf0, 0x9f, 0x98, 0x80, 0xf4, 0x8f, 0xbf, 0xbf], '"}')],
    ['empty', 200, '', 'json-parse-text'],
    ['spaces', 200, ' \n', 'json-parse-text'],
    ['unterminated', 200, '{"result":1', 'json-parse-text'],
    ['trailing-garbage', 200, '{"result":1} x', 'json-parse-text'],
    ['two-values', 200, '{"result":1}{"result":2}', 'json-parse-text'],
    ['trailing-comma', 200, '{"result":[1,],}', 'json-parse-text'],
    ['single-quotes', 200, "{'result':1}", 'json-parse-text'],
    ['nan', 200, '{"result":NaN}', 'json-parse-text'],
    ['leading-zero', 200, '{"result":01}', 'json-parse-text'],
    ['raw-control', 200, '{"result":"a\u0001b"}', 'json-parse-text'],
    ['raw-tab-in-string', 200, '{"result":"a\tb"}', 'json-parse-text'],
    ['bad-escape', 200, '{"result":"\\x41"}', 'json-parse-text'],
    ['short-escape', 200, '{"result":"\\u12"}', 'json-parse-text'],
    ['vertical-tab', 200, '\u000b{"result":1}', 'json-parse-text'],
    ['nbsp', 200, ' {"result":1}', 'json-parse-text'],
    ['form-feed', 200, '\u000c{"result":1}', 'json-parse-text'],
    // Status before body.
    ['status-299', 299, ok],
    ['status-300', 300, ok],
    ['status-404', 404, ok],
    ['status-429', 429, error('{"code":-32005,"message":"rate limited"}')],
    ['status-500', 500, 'not json'],
    ['status-204', 204, null, 'json-parse-text'],
    // Nesting: 512 levels in all (the body is one), and one more.
    ['depth-512', 200, nested(MAX_DEPTH - 1)],
    ['depth-513', 200, nested(MAX_DEPTH), 'json-depth'],
    ['depth-513-unread', 200, '{"result":1,"x":' + '['.repeat(MAX_DEPTH) + ']'.repeat(MAX_DEPTH) + '}', 'json-depth'],
  ];
}

async function buildAnswers(router) {
  const { stableValue } = router.__internals;
  const original = globalThis.fetch;
  const answers = [];
  try {
    for (const [id, status, body, deviation] of answerInputs()) {
      const payload = body === null ? null : Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8');
      globalThis.fetch = async () => new Response(payload, { status });
      let js;
      try {
        const result = await router.requestRpcUrl('https://rpc.invalid', 'eth_call', [], 60000);
        js = result === undefined ? { undefined: true } : { result_json: jsonText(result), stable: stableValue(result) };
      } catch (error) {
        js = { error: describeError(error) };
      }
      answers.push({
        id, status, body_hex: payload === null ? '' : payload.toString('hex'),
        ...(deviation ? { deviation } : {}), js,
      });
    }
  } finally {
    globalThis.fetch = original;
  }
  return answers;
}

// ---------------------------------------------------------------------------
// feeQuote

function feeInputs() {
  const big = (n) => jsonText('0x' + n.toString(16));
  const max = 2n ** BigInt(BIGINT_BITS) - 1n;
  return [
    ['eip1559', 'quorum', '"0x3b9aca00"', '"0x5f5e100"'],
    ['eip1559-myotis-decimal', 'myotis', '"30000000000"', '"1000000000"'],
    ['eip1559-colibri', 'colibri', '"0x10"', '"0x1"'],
    ['eip1559-direct', 'direct', '"0x10"', '"0x1"'],
    ['eip1559-other-source', 'blockscout', '"0x10"', '"0x1"'],
    ['priority-equal', 'quorum', '"0x10"', '"0x10"'],
    ['priority-over', 'quorum', '"0x10"', '"0x11"'],
    ['priority-zero', 'quorum', '"0x10"', '"0x0"'],
    ['priority-negative', 'quorum', '"0x10"', '"-1"'],
    ['priority-negative-number', 'quorum', '"0x10"', '-1'],
    ['priority-undefined', 'quorum', '"0x10"', null],
    ['priority-null', 'quorum', '"0x10"', 'null'],
    ['priority-false', 'quorum', '"0x10"', 'false'],
    ['priority-true', 'quorum', '"0x10"', 'true'],
    ['priority-number', 'myotis', '30000000000', '1000000000'],
    ['priority-invalid', 'quorum', '"0x10"', '"xyz"'],
    ['priority-empty-string', 'quorum', '"0x10"', '""'],
    ['priority-fraction', 'quorum', '"0x10"', '1.5'],
    ['priority-object', 'quorum', '"0x10"', '{}'],
    ['priority-array', 'quorum', '"0x10"', '["0x2"]'],
    ['priority-huge', 'quorum', '"0x10"', jsonText('9'.repeat(5000))],
    ['priority-huge-negative', 'quorum', '"0x10"', jsonText('-' + '9'.repeat(5000))],
    ['priority-huge-hex', 'quorum', '"0x10"', jsonText('0x' + 'f'.repeat(5000))],
    ['gas-price-zero', 'quorum', '"0x0"', '"0x0"'],
    ['gas-price-negative', 'direct', '"-5"', null],
    ['gas-price-number-zero', 'myotis', '0', null],
    ['gas-price-undefined', 'quorum', null, '"0x1"'],
    ['gas-price-null', 'quorum', 'null', null],
    ['gas-price-invalid', 'quorum', '"abc"', null],
    ['gas-price-hex-empty', 'quorum', '"0x"', null],
    ['gas-price-fraction', 'myotis', '1.5', null],
    ['gas-price-overflow', 'myotis', '1e400', null],
    ['gas-price-exponent', 'myotis', '1e21', null],
    ['gas-price-negative-zero', 'myotis', '-0', null],
    ['gas-price-true', 'quorum', 'true', null],
    ['gas-price-false', 'quorum', 'false', null],
    ['gas-price-empty-array', 'quorum', '[]', null],
    ['gas-price-array', 'quorum', '["0x10"]', null],
    ['gas-price-nested-array', 'quorum', '[[" 16 "]]', null],
    ['gas-price-array-two', 'quorum', '[1,2]', null],
    ['gas-price-array-null', 'quorum', '[null]', null],
    ['gas-price-array-number', 'quorum', '[1e21]', null],
    ['gas-price-object', 'quorum', '{"a":1}', null],
    ['gas-price-object-to-string', 'quorum', '{"toString":1}', null],
    ['gas-price-array-object-to-string', 'quorum', '[{"toString":1}]', null],
    ['gas-price-spaces', 'quorum', '" 12 "', null],
    ['gas-price-binary', 'quorum', '"0b101"', '"0o1"'],
    ['gas-price-upper-hex', 'quorum', '"0X1F"', '"0x1"'],
    ['gas-price-lone-surrogate', 'quorum', '"\\ud800"', null],
    ['gas-price-long-invalid', 'quorum', jsonText('z'.repeat(1500)), null],
    ['gas-price-1000-invalid', 'quorum', jsonText('z'.repeat(1000)), null],
    ['gas-price-1001-invalid', 'quorum', jsonText('z'.repeat(1001)), null],
    ['gas-price-invalid-pair-cut', 'quorum', jsonText('z'.repeat(999) + '😀' + 'z'), null],
    ['gas-price-long-array', 'quorum', jsonText(Array(600).fill('ab')), null],
    ['gas-price-uint256', 'quorum', big(2n ** 256n - 1n), big(2n ** 255n)],
    ['gas-price-width-max', 'quorum', big(max), big(max - 1n)],
    ['gas-price-width-max-decimal', 'myotis', jsonText(max.toString()), jsonText('1')],
    ['gas-price-width-over', 'quorum', big(max + 1n), null, 'bigint-width'],
    ['gas-price-width-over-decimal', 'quorum', jsonText((max + 1n).toString()), null, 'bigint-width'],
    ['gas-price-width-far-over-negative', 'quorum', jsonText('-' + '9'.repeat(5000)), null],
    ['gas-price-width-far-over-invalid', 'quorum', jsonText('9'.repeat(5000) + '.'), null],
  ];
}

function buildFeeQuotes(router) {
  const { feeQuote } = router.__internals;
  const parse = (text) => (text === null ? undefined : JSON.parse(text));
  return feeInputs().map(([id, source, gasPrice, priority, deviation]) => {
    let js;
    try {
      js = { quote_json: jsonText(feeQuote(source, parse(gasPrice), parse(priority))) };
    } catch (error) {
      js = { error: describeError(error) };
    }
    return { id, source, gas_price: gasPrice, priority, ...(deviation ? { deviation } : {}), js };
  });
}

// ---------------------------------------------------------------------------
// safeErrorMessage and the aggregate texts

function safeErrorInputs() {
  const hex = (n, digit = 'a') => digit.repeat(n);
  const pair = '😀';
  return [
    ['Error', 'short'],
    ['Error', ''],
    ['SourceUnavailableError', ''],
    ['TypeError', ''],
    ['Error', `data 0x${hex(127)} end`],
    ['Error', `data 0x${hex(128)} end`],
    ['Error', `data 0x${hex(129)} end`],
    ['Error', `0x${hex(130, 'F')}`],
    ['Error', `0X${hex(200)}`],
    ['Error', `0x${hex(64, 'aB')}`],
    ['Error', `0x${hex(130)}0x${hex(130, 'b')}`],
    ['Error', `00x${hex(200)}`],
    ['Error', `x0x${hex(200)}g0x${hex(10)}`],
    ['Error', `0x${hex(20000)}`],
    ['Error', `0x${hex(129)} and\t\t0x${hex(128)}`],
    ['Error', 'a \t\n\r\u000b\u000c b'],
    ['Error', 'a        　﻿b'],
    ['Error', 'a\u0085᠎​b'],
    ['Error', '   '],
    ['Error', ` lead and trail \n`],
    ['Error', 'x'.repeat(600)],
    ['Error', 'x'.repeat(499) + pair + 'y'],
    ['Error', 'x'.repeat(498) + pair + 'y'],
    ['Error', 'x'.repeat(499) + '\ud800'],
    ['Error', 'a\ud800 \udc00b'],
    ['Error', ' '.repeat(1000) + 'x'],
    ['Error', 'é'.repeat(700)],
  ];
}

function buildSafeErrorMessages(router) {
  const { safeErrorMessage } = router.__internals;
  const cases = safeErrorInputs().map(([name, message]) => {
    const error = new Error(message);
    if (name !== 'Error') Object.defineProperty(error, 'name', { value: name });
    return { name, message_json: jsonText(message), js: { text_json: jsonText(safeErrorMessage(error)) } };
  });
  const whitespace = [];
  for (let unit = 0; unit < 0x10000; unit += 1) {
    if (safeErrorMessage(new Error(`a${String.fromCharCode(unit)}b`)) === 'a b') whitespace.push(unit);
  }
  return { cases, whitespace };
}

const LONG_HEX_SOURCE = '0x' + 'ab'.repeat(80);

function requestScenarios() {
  const all = ['myotis', 'colibri', 'quorum', 'direct'];
  return [
    { id: 'default-order', method: 'eth_call', readOrder: all, messages: { myotis: 'Myotis native read unavailable', colibri: 'Colibri prover timed out' } },
    { id: 'not-ready', method: 'eth_call', readOrder: all, myotisReady: false, messages: { colibri: 'x' } },
    { id: 'excluded-by-caller', method: 'eth_call', readOrder: all, excludeSources: ['quorum', 'myotis'], messages: { myotis: 'a', colibri: 'b' } },
    { id: 'excluded-by-capability', method: 'eth_getLogs', readOrder: all, excludeSources: ['myotis'], messages: { colibri: 'b' } },
    { id: 'excluded-twice', method: 'eth_getLogs', readOrder: ['colibri', 'direct', 'colibri'], messages: {} },
    { id: 'single-node-method', method: 'web3_clientVersion', readOrder: all, messages: {} },
    { id: 'unknown-sources', method: 'eth_blockNumber', readOrder: [LONG_HEX_SOURCE, 'tab\tand  space', 'pair😀'], messages: {} },
    { id: 'empty-message', method: 'eth_call', readOrder: ['myotis', 'colibri'], messages: { myotis: '', colibri: '' } },
    { id: 'long-messages', method: 'eth_call', readOrder: ['myotis', 'colibri'], messages: { myotis: `revert 0x${'ab'.repeat(100)}\n\tdata`, colibri: 'x'.repeat(499) + '😀' + 'tail' } },
    { id: 'lone-surrogates', method: 'eth_call', readOrder: ['myotis', 'colibri'], messages: { myotis: '\ud800', colibri: 'a\udc00b' } },
    // A capacity failure blocks Myotis for this app's route; the second
    // request reports it bypassed.
    {
      id: 'bypassed', method: 'eth_call', readOrder: ['myotis', 'colibri'], routingContext: { origin: 'https://app.example' },
      messages: { myotis: 'out of gas', colibri: 'c' }, repeat: true,
    },
  ];
}

async function buildRequestTexts(router, world) {
  const out = [];
  for (const scenario of requestScenarios()) {
    router.clearAdaptiveRoutingForTest();
    Object.assign(world, {
      network: { access: { readOrder: scenario.readOrder } },
      endpoints: { prover: ['https://prover.invalid'] },
      myotisReady: scenario.myotisReady ?? true,
      messages: scenario.messages,
      events: null,
    });
    const run = async () => {
      const events = [];
      const restore = router.__observe(events, ['requestSource', 'adaptiveSourceUnavailable']);
      try {
        await router.request(1, scenario.method, [{ to: '0x' + '11'.repeat(20) }], {
          excludeSources: scenario.excludeSources || [], routingContext: scenario.routingContext || null,
        });
        throw new Error(`${scenario.id}: the request unexpectedly succeeded`);
      } catch (error) {
        return { events, error };
      } finally {
        restore();
      }
    };
    let outcome = await run();
    if (scenario.repeat) outcome = await run();
    const { events, error } = outcome;
    assert.equal(error.name, 'Error', `${scenario.id}: ${error.stack}`);
    // The sources the router left out are the read order's entries it never
    // tried (each tried source either failed or was bypassed).
    const tried = new Set(events.map((event) => event.source));
    out.push({
      id: scenario.id,
      method: scenario.method,
      failures: events.map((event) => (event.bypassed
        ? { source: event.source, bypassed: true }
        : { source: event.source, name: event.error.name, message_json: jsonText(event.error.message) })),
      excluded: scenario.readOrder.filter((source) => !tried.has(source)),
      js: { text_json: jsonText(error.message) },
    });
  }
  router.clearAdaptiveRoutingForTest();
  return out;
}

async function buildFeeQuoteTexts(router, world) {
  const scenarios = [
    { id: 'default-order', readOrder: ['myotis', 'colibri', 'quorum', 'direct'], messages: { myotis: 'Myotis native read unavailable', colibri: 'Colibri prover timed out' } },
    // Fee-quote failures keep the raw message: no shortening.
    { id: 'raw-messages', readOrder: ['myotis', 'colibri'], messages: { myotis: `0x${'ab'.repeat(100)}\n\t${'x'.repeat(600)}`, colibri: '' } },
    { id: 'lone-surrogate', readOrder: ['myotis', 'quorum'], messages: { myotis: 'a\ud800' } },
  ];
  const out = [];
  for (const scenario of scenarios) {
    router.clearAdaptiveRoutingForTest();
    const events = [];
    Object.assign(world, {
      network: { access: { readOrder: scenario.readOrder } },
      endpoints: { prover: ['https://prover.invalid'] },
      myotisReady: true, messages: scenario.messages, events,
    });
    const restore = router.__observe(events, ['requestSource', 'requestDirectFeeQuote']);
    let error;
    try {
      await router.getFeeQuote(1);
    } catch (caught) {
      error = caught;
    } finally {
      restore();
      world.events = null;
    }
    assert.ok(error, `${scenario.id}: the fee quote unexpectedly succeeded`);
    assert.equal(events.length, scenario.readOrder.length, scenario.id);
    out.push({
      id: scenario.id,
      failures: events.map((event) => ({ source: event.source, message_json: jsonText(event.error.message) })),
      js: { text_json: jsonText(error.message) },
    });
  }
  return out;
}

async function buildBroadcastTexts(router, world) {
  const scenarios = [
    { id: 'default-order', broadcastOrder: ['myotis', 'direct'], messages: { myotis: 'Myotis is not running' } },
    { id: 'raw-messages', broadcastOrder: ['direct', 'myotis'], messages: { myotis: `  0x${'cd'.repeat(70)}  ` } },
  ];
  const out = [];
  for (const scenario of scenarios) {
    const events = [];
    Object.assign(world, {
      network: { access: { broadcastOrder: scenario.broadcastOrder } },
      endpoints: {}, myotisReady: true, messages: scenario.messages, events,
    });
    const restore = router.__observe(events, ['requestDirect']);
    let error;
    try {
      await router.broadcastRawTransaction(1, '0x02');
    } catch (caught) {
      error = caught;
    } finally {
      restore();
      world.events = null;
    }
    assert.ok(error, `${scenario.id}: the broadcast unexpectedly succeeded`);
    assert.equal(events.length, scenario.broadcastOrder.length, scenario.id);
    out.push({
      id: scenario.id,
      failures: events.map((event) => ({ source: event.source, message_json: jsonText(event.error.message) })),
      js: { text_json: jsonText(error.message) },
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Transaction hashes: ethers' keccak256 of the signed bytes

async function buildTransactionHashes(ethers, privateKey) {
  const wallet = new ethers.Wallet(privateKey);
  const to = '0x' + '11'.repeat(20);
  const signed = [
    await wallet.signTransaction({ type: 0, chainId: 1, nonce: 0, gasLimit: 21000n, gasPrice: 1n, to, value: 1n }),
    await wallet.signTransaction({ type: 2, chainId: 100, nonce: 7, gasLimit: 50000n, maxFeePerGas: 2n, maxPriorityFeePerGas: 1n, to, data: '0x1234' }),
    await wallet.signTransaction({ type: 1, chainId: 1, nonce: 1, gasLimit: 30000n, gasPrice: 3n, to, accessList: [{ address: to, storageKeys: ['0x' + '00'.repeat(32)] }] }),
  ];
  for (const raw of signed) assert.equal(ethers.keccak256(raw), ethers.Transaction.from(raw).hash);
  const inputs = [
    ...signed,
    '0X' + signed[1].slice(2).toUpperCase(),
    '0x' + signed[1].slice(2).toUpperCase(),
    '0x',
    signed[0].slice(2),
    signed[0] + '0',
    signed[0].slice(0, -1) + 'g',
    ' ' + signed[0],
    signed[0] + '\n',
    '',
  ];
  return inputs.map((raw) => {
    try {
      return { raw, js: { hash: ethers.keccak256(raw) } };
    } catch {
      return { raw, js: { invalid: true } };
    }
  });
}

// ---------------------------------------------------------------------------
// Read methods and the source order

// isReadMethod is Set membership: exact names only.
const METHOD_PROBES = [
  'eth_sendRawTransaction', 'eth_sendTransaction', 'eth_chainId', 'net_version', 'eth_getProof',
  'eth_createAccessList', 'eth_getBlockReceipts', 'eth_blobBaseFee', 'eth_syncing', 'eth_subscribe',
  'ETH_CALL', 'eth_Call', ' eth_call', 'eth_call ', 'eth_call\u0000', 'web3_clientversion', '',
  '__proto__', 'constructor', 'toString', 'hasOwnProperty', 'valueOf',
];

async function buildMethods(router) {
  const { READ_METHODS, SINGLE_NODE_METHODS } = router.__internals;
  const capabilities = Object.entries(router.SOURCE_CAPABILITIES).map(([source, capability]) => ({
    source, unsupported: [...capability.unsupported], opt_in: capability.optIn === true,
  }));
  const probes = [...READ_METHODS, ...SINGLE_NODE_METHODS, ...METHOD_PROBES];
  const unsupported = [];
  for (const method of ['eth_sendRawTransaction', 'eth_chainId', '', 'eth call', 'méthode 😀', 'x'.repeat(600)]) {
    try {
      await router.request(1, method, []);
      throw new Error(`${method}: the request unexpectedly succeeded`);
    } catch (error) {
      assert.equal(error.name, 'Error');
      unsupported.push({ method, js: { text_json: jsonText(error.message) } });
    }
  }
  return {
    read_methods: [...READ_METHODS],
    single_node_methods: [...SINGLE_NODE_METHODS],
    source_capabilities: capabilities,
    is_read_method: probes.map((method) => ({ method, js: router.isReadMethod(method) })),
    unsupported,
  };
}

const ADDRESS = '0x' + '11'.repeat(20);
const WALLET = '0x' + 'ab'.repeat(20);
const COUNTERPARTY = '0x' + 'cd'.repeat(20);
const addressTopic = (address) => '0x' + '0'.repeat(24) + address.slice(2);

// Requests whose sources all fail without I/O (no endpoints, no prover,
// Myotis not ready), or that have no source left at all.
function sourceOrderScenarios(blockscout) {
  const token = blockscout.LOG_INDEX_TOKENS[100];
  const transfer = blockscout.ERC20_TRANSFER_TOPIC;
  const scan = (fields) => jsonText([{ address: token, topics: [transfer, addressTopic(WALLET)], fromBlock: '0x1', toBlock: '0x186a0', ...fields }]);
  const call = jsonText([{ to: ADDRESS }]);
  const all = ['myotis', 'colibri', 'quorum', 'direct'];
  return [
    { id: 'all-tried', method: 'eth_call', params: call, readOrder: all },
    { id: 'single-node-method', method: 'web3_clientVersion', params: '[]', readOrder: all },
    { id: 'single-node-method-no-direct', method: 'eth_newBlockFilter', params: '[]', readOrder: ['myotis', 'colibri', 'quorum'] },
    { id: 'all-excluded', method: 'eth_call', params: call, readOrder: ['quorum'], exclude: ['quorum'] },
    { id: 'empty-read-order', method: 'eth_call', params: call, readOrder: [] },
    { id: 'duplicates', method: 'eth_call', params: call, readOrder: ['direct', 'quorum', 'direct'], exclude: ['direct', 'quorum'] },
    { id: 'unknown-excluded', method: 'eth_call', params: call, readOrder: ['foo', 'colibri'], exclude: ['foo', 'colibri'] },
    { id: 'logs-without-colibri', method: 'eth_getLogs', params: scan({}), readOrder: ['colibri', 'myotis'], exclude: ['myotis'] },
    { id: 'chain-100', chainId: 100, method: 'eth_getLogs', params: scan({}), readOrder: ['colibri'] },
    { id: 'blockscout-in-read-order', method: 'eth_blockNumber', params: '[]', readOrder: ['blockscout', 'quorum'], exclude: ['quorum'] },
    // The Ant profile: Blockscout joins before the quorum, only for an
    // eth_getLogs xBZZ Transfer scan over a numeric range on chain 100.
    { id: 'ant-scan', chainId: 100, method: 'eth_getLogs', params: scan({}), readOrder: all, profile: 'ant' },
    { id: 'ant-scan-all-excluded', chainId: 100, method: 'eth_getLogs', params: scan({}), readOrder: all, profile: 'ant', exclude: ['quorum', 'blockscout'] },
    { id: 'ant-scan-quorum-twice', chainId: 100, method: 'eth_getLogs', params: scan({}), readOrder: ['quorum', 'quorum'], profile: 'ant', exclude: ['quorum', 'blockscout'] },
    { id: 'ant-scan-no-quorum', chainId: 100, method: 'eth_getLogs', params: scan({}), readOrder: ['myotis', 'direct'], profile: 'ant' },
    { id: 'ant-scan-include-twice', chainId: 100, method: 'eth_getLogs', params: scan({}), readOrder: ['quorum'], profile: 'ant', include: ['blockscout', 'direct', 'blockscout'], exclude: ['quorum', 'blockscout'] },
    { id: 'ant-scan-blockscout-in-order', chainId: 100, method: 'eth_getLogs', params: scan({}), readOrder: ['blockscout', 'quorum'], profile: 'ant', exclude: ['quorum', 'blockscout'] },
    { id: 'ant-scan-latest', chainId: 100, method: 'eth_getLogs', params: scan({ toBlock: 'latest' }), readOrder: all, profile: 'ant', exclude: ['quorum'] },
    { id: 'ant-scan-other-address', chainId: 100, method: 'eth_getLogs', params: scan({ address: ADDRESS }), readOrder: all, profile: 'ant', exclude: ['quorum'] },
    { id: 'ant-scan-chain-1', chainId: 1, method: 'eth_getLogs', params: scan({}), readOrder: all, profile: 'ant', exclude: ['quorum'] },
    { id: 'ant-other-method', chainId: 100, method: 'eth_blockNumber', params: '[]', readOrder: all, profile: 'ant', exclude: ['quorum'] },
    { id: 'default-profile-include', chainId: 100, method: 'eth_getLogs', params: scan({}), readOrder: all, include: ['blockscout'], exclude: ['myotis', 'colibri', 'quorum', 'direct'] },
  ];
}

async function buildSourceOrders(router, world, bridge, blockscout) {
  const out = [];
  for (const scenario of sourceOrderScenarios(blockscout)) {
    router.clearAdaptiveRoutingForTest();
    Object.assign(world, {
      network: { access: { readOrder: scenario.readOrder } },
      endpoints: {}, myotisReady: false, messages: {}, events: null,
    });
    const profile = scenario.profile || 'default';
    const options = {
      ...(profile === 'ant' ? bridge.LOG_SCAN_ROUTER_OPTIONS : {}),
      ...(scenario.include ? { includeSources: scenario.include } : {}),
    };
    const exclude = [...(options.excludeSources || []), ...(scenario.exclude || [])];
    const events = [];
    const restore = router.__observe(events, ['requestSource']);
    let error;
    try {
      await router.request(scenario.chainId || 1, scenario.method, JSON.parse(scenario.params), { ...options, excludeSources: exclude });
    } catch (caught) {
      error = caught;
    } finally {
      restore();
    }
    assert.ok(error, `${scenario.id}: the request unexpectedly succeeded`);
    assert.equal(error.name, 'Error', `${scenario.id}: ${error.stack}`);
    out.push({
      id: scenario.id,
      chain_id: scenario.chainId || 1,
      method: scenario.method,
      params: scenario.params,
      read_order: scenario.readOrder,
      exclude_sources: exclude,
      include_sources: options.includeSources || [],
      profile,
      js: {
        tried: events.map((event) => ({ source: event.source, name: event.error.name, message_json: jsonText(event.error.message) })),
        text_json: jsonText(error.message),
      },
    });
  }
  router.clearAdaptiveRoutingForTest();
  return out;
}

// ---------------------------------------------------------------------------
// Myotis: the read gates, the payload classification and the trust block

// A payload as main sends it (design 0005, Myotis read outcomes): the
// adapter's JSON with its keys in snake_case.
function wirePayload(payload) {
  if (payload === undefined) return null;
  const value = JSON.parse(payload);
  if (!value || typeof value !== 'object' || Array.isArray(value)) return jsonText(value);
  return jsonText(Object.fromEntries(Object.entries(value)
    .map(([key, item]) => [key.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`), item])));
}

// [id, method, params, payload (JSON, or undefined for none), deviation]
function myotisInputs() {
  const call = { to: ADDRESS, data: '0x1234' };
  const p = (...items) => jsonText(items);
  const answer = (fields) => jsonText({ status: 'ok', ...fields });
  const account = (fields) => jsonText({ verifyMethod: 'proof', exists: true, ...fields });
  const long = 'x'.repeat(299) + '😀' + 'tail';
  return [
    // assertMyotisAnswer, through eth_call (its answer is passed on as it is).
    ['revert', 'eth_call', p(call), jsonText({ status: 'revert', dataHex: '0x08c379a0' + '00'.repeat(4) })],
    ['revert-no-data', 'eth_call', p(call), jsonText({ status: 'revert' })],
    ['revert-data-number', 'eth_call', p(call), jsonText({ status: 'revert', dataHex: 5 })],
    ['revert-data-empty', 'eth_call', p(call), jsonText({ status: 'revert', dataHex: '' })],
    ['revert-data-not-hex', 'eth_call', p(call), jsonText({ status: 'revert', dataHex: 'not hex \ud800' })],
    ['revert-before-error', 'eth_call', p(call), jsonText({ status: 'revert', error: 'x', code: -32602, dataHex: '0x01' })],
    ['revert-upper-status', 'eth_call', p(call), jsonText({ status: 'REVERT', resultHex: '0x01' })],
    ['invalid-params', 'eth_call', p(call), jsonText({ error: 'chainId 5 does not match 1', code: -32602 })],
    ['invalid-params-spaces', 'eth_call', p(call), jsonText({ error: '  bad\n\t field   x  ', code: -32602 })],
    ['invalid-params-long', 'eth_call', p(call), jsonText({ error: long, code: -32602 })],
    ['invalid-params-cut-pair', 'eth_call', p(call), jsonText({ error: 'y'.repeat(299) + '😀', code: -32602 })],
    ['invalid-params-true', 'eth_call', p(call), jsonText({ error: true, code: -32602 })],
    ['invalid-params-object', 'eth_call', p(call), jsonText({ error: { message: 'x' }, code: -32602 })],
    ['invalid-params-blank', 'eth_call', p(call), jsonText({ error: ' \n ', code: -32602 })],
    ['invalid-params-code-fraction', 'eth_call', p(call), '{"error":"x","code":-32602.0}'],
    ['invalid-params-code-string', 'eth_call', p(call), jsonText({ error: 'x', code: '-32602' })],
    ['invalid-params-before-infeasible', 'eth_call', p(call), jsonText({ status: 'infeasible', error: 'x', code: -32602, reason: 'r' })],
    ['capability-eip-7843', 'eth_call', p(call), jsonText({ error: 'EIP-7843 slot number unavailable', code: -32602 })],
    ['capability-fork-table', 'eth_call', p(call), jsonText({ error: 'executor FORK TABLE disagrees', code: -32602 })],
    ['capability-gas-budget', 'eth_call', p(call), jsonText({ error: "call exceeds this node's 50000000-gas call budget", code: -32602 })],
    ['capability-not-supported', 'eth_call', p(call), jsonText({ error: 'blob transactions are Not Supported By This Node', code: -32602 })],
    ['capability-spaces-collapsed', 'eth_call', p(call), jsonText({ error: 'fork\n table', code: -32602 })],
    ['capability-kelvin-sign', 'eth_call', p(call), jsonText({ error: 'forK table', code: -32602 })],
    ['capability-arabic-digits', 'eth_call', p(call), jsonText({ error: "node's ١٢-gas call budget", code: -32602 })],
    ['capability-curly-apostrophe', 'eth_call', p(call), jsonText({ error: 'node’s 5-gas call budget', code: -32602 })],
    ['capability-long', 'eth_call', p(call), jsonText({ error: 'z'.repeat(290) + ' fork table', code: -32602 })],
    ['infeasible', 'eth_estimateGas', p(call), jsonText({ status: 'infeasible', reason: 'insufficient funds for gas * price + value' })],
    ['infeasible-no-reason', 'eth_call', p(call), jsonText({ status: 'infeasible' })],
    ['infeasible-reason-number', 'eth_call', p(call), jsonText({ status: 'infeasible', reason: 7 })],
    ['infeasible-reason-long', 'eth_call', p(call), jsonText({ status: 'infeasible', reason: long })],
    ['error-without-code', 'eth_call', p(call), jsonText({ error: 'boom' })],
    ['error-other-code', 'eth_call', p(call), jsonText({ error: 'boom', code: -32000 })],
    ['status-error', 'eth_call', p(call), jsonText({ status: 'error', resultHex: '0x01' })],
    ['status-unavailable', 'eth_call', p(call), jsonText({ status: 'unavailable' })],
    ['payload-undefined', 'eth_call', p(call), undefined],
    ['payload-null', 'eth_call', p(call), 'null'],
    ['payload-false', 'eth_call', p(call), 'false'],
    ['payload-zero', 'eth_call', p(call), '0'],
    ['payload-empty-string', 'eth_call', p(call), '""'],
    ['payload-string', 'eth_call', p(call), '"0x01"'],
    ['payload-array', 'eth_call', p(call), '[{"resultHex":"0x01"}]'],
    ['payload-empty-object', 'eth_call', p(call), '{}'],
    ['result-hex', 'eth_call', p(call), answer({ resultHex: '0xabcdef' })],
    ['result-fallback', 'eth_call', p(call), answer({ resultHex: null, result: '0x02' })],
    ['result-object', 'eth_call', p(call), answer({ result: { b: 1, a: [true, null] } })],
    ['result-number', 'eth_call', p(call), answer({ result: 1e21 })],
    ['result-falsy-error', 'eth_call', p(call), jsonText({ error: '', code: -32602, resultHex: '0x' })],
    ['result-zero-error', 'eth_call', p(call), jsonText({ error: 0, resultHex: '0x03' })],
    // Call gates: the block tag, state overrides and blob fields.
    ['call-latest', 'eth_call', p(call, 'latest'), answer({ resultHex: '0x' })],
    ['call-null-tag', 'eth_call', p(call, null), answer({ resultHex: '0x' })],
    ['call-pending', 'eth_call', p(call, 'pending'), answer({ resultHex: '0x' })],
    ['call-tag-case', 'eth_call', p(call, 'Latest'), answer({ resultHex: '0x' })],
    ['call-tag-number', 'eth_call', p(call, 5), answer({ resultHex: '0x' })],
    ['call-tag-object', 'eth_call', p(call, { blockHash: '0x' + '22'.repeat(32) }), answer({ resultHex: '0x' })],
    ['call-tag-array', 'eth_call', p(call, ['a', ['b', null]]), answer({ resultHex: '0x' })],
    ['call-tag-to-string', 'eth_call', p(call, { toString: 1 }), answer({ resultHex: '0x' })],
    ['call-tag-lone-surrogate', 'eth_call', p(call, '\udc00'), answer({ resultHex: '0x' })],
    ['call-overrides', 'eth_call', p(call, 'latest', { [ADDRESS]: { balance: '0x1' } }), answer({ resultHex: '0x' })],
    ['call-overrides-empty', 'eth_call', p(call, 'latest', {}), answer({ resultHex: '0x' })],
    ['call-overrides-null', 'eth_call', p(call, 'latest', null), answer({ resultHex: '0x' })],
    ['call-overrides-false', 'eth_call', p(call, null, false), answer({ resultHex: '0x' })],
    ['call-blob-hashes', 'eth_call', p({ ...call, blobVersionedHashes: ['0x01'] }), answer({ resultHex: '0x' })],
    ['call-blob-hashes-empty', 'eth_call', p({ ...call, blobVersionedHashes: [] }), answer({ resultHex: '0x' })],
    ['call-blob-hashes-null', 'eth_call', p({ ...call, blobVersionedHashes: null }), answer({ resultHex: '0x' })],
    ['call-blob-hashes-string', 'eth_call', p({ ...call, blobVersionedHashes: '' }), answer({ resultHex: '0x' })],
    ['call-blob-fee', 'eth_estimateGas', p({ ...call, maxFeePerBlobGas: '0x1' }), jsonText({ gas: 21000 })],
    ['call-blob-fee-zero', 'eth_call', p({ ...call, maxFeePerBlobGas: 0 }), answer({ resultHex: '0x' })],
    ['call-blobs', 'eth_call', p({ ...call, blobs: [] , commitments: ['0x'] }), answer({ resultHex: '0x' })],
    ['call-proofs', 'eth_call', p({ ...call, proofs: false }), answer({ resultHex: '0x' })],
    ['call-sidecar', 'eth_call', p({ ...call, sidecar: {} }), answer({ resultHex: '0x' })],
    ['call-blob-field-order', 'eth_call', p({ sidecar: {}, ...call, blobVersionedHashes: ['0x01'] }), answer({ resultHex: '0x' })],
    ['call-blob-case', 'eth_call', p({ ...call, BlobVersionedHashes: ['0x01'] }), answer({ resultHex: '0x' })],
    ['call-not-object', 'eth_call', p('0x1234'), answer({ resultHex: '0x' })],
    ['call-array', 'eth_call', p([{ blobs: ['x'] }]), answer({ resultHex: '0x' })],
    ['call-missing', 'eth_call', '[]', answer({ resultHex: '0x' })],
    ['call-null', 'eth_call', '[null]', answer({ resultHex: '0x' })],
    ['call-zero', 'eth_call', '[0]', answer({ resultHex: '0x' })],
    ['params-object', 'eth_call', jsonText({ 0: call, 1: 'latest' }), answer({ resultHex: '0x' })],
    ['params-object-tag', 'eth_call', jsonText({ 0: call, 1: 'safe' }), answer({ resultHex: '0x' })],
    ['params-string', 'eth_call', '"abc"', answer({ resultHex: '0x' })],
    ['params-short-string', 'eth_call', '"a"', answer({ resultHex: '0x' })],
    ['params-pair-string', 'eth_call', '"😀"', answer({ resultHex: '0x' })],
    ['params-number', 'eth_estimateGas', '5', jsonText({ gas: 1 })],
    ['params-true', 'eth_call', 'true', answer({ resultHex: '0x' })],
    ['params-null', 'eth_call', 'null', answer({ resultHex: '0x' })],
    // Estimates must be safe non-negative integers.
    ['estimate', 'eth_estimateGas', p(call), jsonText({ gas: 21000 })],
    ['estimate-zero', 'eth_estimateGas', p(call), jsonText({ gas: 0 })],
    ['estimate-negative-zero', 'eth_estimateGas', p(call), '{"gas":-0}'],
    ['estimate-exponent', 'eth_estimateGas', p(call), '{"gas":1e3}'],
    ['estimate-max-safe', 'eth_estimateGas', p(call), jsonText({ gas: Number.MAX_SAFE_INTEGER })],
    ['estimate-unsafe', 'eth_estimateGas', p(call), '{"gas":9007199254740992}'],
    ['estimate-fraction', 'eth_estimateGas', p(call), jsonText({ gas: 1.5 })],
    ['estimate-negative', 'eth_estimateGas', p(call), jsonText({ gas: -1 })],
    ['estimate-string', 'eth_estimateGas', p(call), jsonText({ gas: '21000' })],
    ['estimate-hex-string', 'eth_estimateGas', p(call), jsonText({ gas: '0x5208' })],
    ['estimate-null', 'eth_estimateGas', p(call), jsonText({ gas: null })],
    ['estimate-missing', 'eth_estimateGas', p(call), jsonText({ status: 'ok' })],
    ['estimate-revert', 'eth_estimateGas', p(call), jsonText({ status: 'revert', dataHex: '0xdead' })],
    ['estimate-pending', 'eth_estimateGas', p(call, 'pending'), jsonText({ gas: 1 })],
    // Account reads: a verdict, then the balance or nonce as a quantity.
    ['balance', 'eth_getBalance', p(ADDRESS, 'latest'), account({ balanceWei: '1000000000000000000' })],
    ['balance-no-tag', 'eth_getBalance', p(ADDRESS), account({ balanceWei: '0x0010' })],
    ['balance-fallback', 'eth_getBalance', p(ADDRESS), account({ balanceWei: null, balance: '0x10' })],
    ['balance-number', 'eth_getBalance', p(ADDRESS), account({ balanceWei: 1000 })],
    ['balance-fraction', 'eth_getBalance', p(ADDRESS), account({ balanceWei: 1.5 })],
    ['balance-not-number', 'eth_getBalance', p(ADDRESS), account({ balanceWei: 'abc' })],
    ['balance-empty', 'eth_getBalance', p(ADDRESS), account({ balanceWei: '' })],
    ['balance-true', 'eth_getBalance', p(ADDRESS), account({ balanceWei: true })],
    ['balance-false', 'eth_getBalance', p(ADDRESS), account({ balanceWei: false })],
    ['balance-object', 'eth_getBalance', p(ADDRESS), account({ balanceWei: {} })],
    ['balance-object-to-string', 'eth_getBalance', p(ADDRESS), account({ balanceWei: { toString: 1 } })],
    ['balance-empty-array', 'eth_getBalance', p(ADDRESS), account({ balanceWei: [] })],
    ['balance-array', 'eth_getBalance', p(ADDRESS), account({ balanceWei: [' 5 '] })],
    ['balance-negative', 'eth_getBalance', p(ADDRESS), account({ balanceWei: '-1' })],
    ['balance-spaces', 'eth_getBalance', p(ADDRESS), account({ balanceWei: ' 12 ' })],
    ['balance-binary', 'eth_getBalance', p(ADDRESS), account({ balanceWei: '0b101' })],
    ['balance-upper-hex', 'eth_getBalance', p(ADDRESS), account({ balanceWei: '0XFF' })],
    ['balance-wide-hex', 'eth_getBalance', p(ADDRESS), account({ balanceWei: '0x' + 'f'.repeat(1200) })],
    ['balance-width-max', 'eth_getBalance', p(ADDRESS), account({ balanceWei: (2n ** BigInt(BIGINT_BITS) - 1n).toString() })],
    ['balance-width-over', 'eth_getBalance', p(ADDRESS), account({ balanceWei: (2n ** BigInt(BIGINT_BITS)).toString() }), 'bigint-width'],
    ['balance-missing', 'eth_getBalance', p(ADDRESS), account({})],
    ['balance-absent-account', 'eth_getBalance', p(ADDRESS), account({ exists: false, balanceWei: null, nonce: -1 })],
    ['balance-exists-string', 'eth_getBalance', p(ADDRESS), account({ exists: 'false', balanceWei: '7' })],
    ['balance-no-verdict', 'eth_getBalance', p(ADDRESS), jsonText({ exists: true, balanceWei: '1' })],
    ['balance-empty-verdict', 'eth_getBalance', p(ADDRESS), account({ verifyMethod: '', balanceWei: '1' })],
    ['balance-number-verdict', 'eth_getBalance', p(ADDRESS), account({ verifyMethod: 1, balanceWei: '1' })],
    ['balance-blank-verdict', 'eth_getBalance', p(ADDRESS), account({ verifyMethod: ' ', balanceWei: '1' })],
    ['balance-fail-reason', 'eth_getBalance', p(ADDRESS), jsonText({ failReason: ' head not\n finalized ', balanceWei: '1' })],
    ['balance-fail-reason-long', 'eth_getBalance', p(ADDRESS), jsonText({ failReason: long })],
    ['balance-fail-reason-number', 'eth_getBalance', p(ADDRESS), jsonText({ failReason: 5 })],
    ['balance-unverified-revert', 'eth_getBalance', p(ADDRESS), jsonText({ status: 'revert' })],
    ['balance-unavailable', 'eth_getBalance', p(ADDRESS), account({ status: 'unavailable', balanceWei: '1' })],
    ['balance-pending', 'eth_getBalance', p(ADDRESS, 'pending'), account({ balanceWei: '1' })],
    ['balance-finalized', 'eth_getBalance', p(ADDRESS, 'finalized'), account({ balanceWei: '1' })],
    ['balance-no-params', 'eth_getBalance', '[]', account({ balanceWei: '1' })],
    ['nonce', 'eth_getTransactionCount', p(ADDRESS, 'latest'), account({ nonce: 5 })],
    ['nonce-negative', 'eth_getTransactionCount', p(ADDRESS), account({ nonce: -1 })],
    ['nonce-absent-account', 'eth_getTransactionCount', p(ADDRESS), account({ exists: false, nonce: -1 })],
    ['nonce-missing', 'eth_getTransactionCount', p(ADDRESS), account({ balanceWei: '5' })],
    ['nonce-pending', 'eth_getTransactionCount', p(ADDRESS, 'pending'), account({ nonce: 5 })],
    // Code and storage.
    ['code', 'eth_getCode', p(ADDRESS, 'latest'), account({ codeHex: '0x6080ABCD' })],
    ['code-upper-prefix', 'eth_getCode', p(ADDRESS), account({ codeHex: '0X60' })],
    ['code-empty', 'eth_getCode', p(ADDRESS), account({ codeHex: '0x' })],
    ['code-odd', 'eth_getCode', p(ADDRESS), account({ codeHex: '0xabc' })],
    ['code-no-prefix', 'eth_getCode', p(ADDRESS), account({ codeHex: 'abcd' })],
    ['code-number', 'eth_getCode', p(ADDRESS), account({ codeHex: 5 })],
    ['code-null', 'eth_getCode', p(ADDRESS), account({ codeHex: null })],
    ['code-no-verdict', 'eth_getCode', p(ADDRESS), jsonText({ codeHex: '0x' })],
    ['code-pending', 'eth_getCode', p(ADDRESS, 'pending'), account({ codeHex: '0x' })],
    ['storage', 'eth_getStorageAt', p(ADDRESS, '0x0', 'latest'), account({ valueHex: '0x1' })],
    ['storage-upper', 'eth_getStorageAt', p(ADDRESS, '0x0'), account({ valueHex: '0XAB' })],
    ['storage-empty-slot', 'eth_getStorageAt', p(ADDRESS, '0x0'), account({ valueHex: null })],
    ['storage-missing', 'eth_getStorageAt', p(ADDRESS, '0x0'), account({})],
    ['storage-bare-prefix', 'eth_getStorageAt', p(ADDRESS, '0x0'), account({ valueHex: '0x' })],
    ['storage-full', 'eth_getStorageAt', p(ADDRESS, '0x0'), account({ valueHex: '0x' + 'f'.repeat(64) })],
    ['storage-too-long', 'eth_getStorageAt', p(ADDRESS, '0x0'), account({ valueHex: '0x' + '0'.repeat(65) })],
    ['storage-number', 'eth_getStorageAt', p(ADDRESS, '0x0'), account({ valueHex: 5 })],
    ['storage-no-prefix', 'eth_getStorageAt', p(ADDRESS, '0x0'), account({ valueHex: '01' })],
    ['storage-pending', 'eth_getStorageAt', p(ADDRESS, '0x0', 'pending'), account({ valueHex: '0x1' })],
    ['storage-tag-in-slot-position', 'eth_getStorageAt', p(ADDRESS, 'pending'), account({ valueHex: '0x1' })],
    // Fees.
    ['gas-price', 'eth_gasPrice', '[]', jsonText({ gasPriceWei: '30000000000', maxPriorityFeePerGasWei: '1' })],
    ['gas-price-fallback', 'eth_gasPrice', '[]', jsonText({ gasPrice: 7 })],
    ['gas-price-missing', 'eth_gasPrice', '[]', jsonText({ maxPriorityFeePerGasWei: '1' })],
    ['gas-price-tag-ignored', 'eth_gasPrice', p('pending'), jsonText({ gasPriceWei: '0x1' })],
    ['priority-fee', 'eth_maxPriorityFeePerGas', '[]', jsonText({ gasPriceWei: '3', maxPriorityFeePerGasWei: '1000000000' })],
    ['priority-fee-fallback', 'eth_maxPriorityFeePerGas', '[]', jsonText({ maxPriorityFeePerGas: '0x2' })],
    ['priority-fee-revert', 'eth_maxPriorityFeePerGas', '[]', jsonText({ status: 'revert' })],
    // Methods Myotis doesn't serve.
    ['block-number', 'eth_blockNumber', '[]', answer({ result: '0x1' })],
    ['logs', 'eth_getLogs', p({}), answer({ result: [] })],
    ['fee-history', 'eth_feeHistory', p('0x1', 'latest', []), answer({})],
  ];
}

function describeMyotisError(router, error) {
  const described = describeError(error);
  if (error.myotisRefusal !== undefined) described.myotis_refusal = error.myotisRefusal;
  // How the read loop treats it: final (served), and whether it may become
  // the last error (anything but a SourceUnavailableError).
  described.final = error.code === 3 || Boolean(error.myotisRefusal);
  described.unavailable = error instanceof router.SourceUnavailableError;
  return described;
}

// The operation main runs for the core (design 0005, Verified operations),
// from the arguments the router passed to the manager.
function describeOperation(calls) {
  if (calls.length === 0) return null;
  assert.equal(calls.length, 1);
  const [{ name, args }] = calls;
  const json = (value) => (value === undefined ? null : jsonText(value));
  if (name === 'getAccount' || name === 'getCode') {
    assert.equal(args[1], 1);
    return { kind: name === 'getAccount' ? 'account' : 'code', address_json: json(args[0]) };
  }
  if (name === 'getStorageAt') {
    assert.equal(args[2], 1);
    return { kind: 'storage', address_json: json(args[0]), slot_json: json(args[1]) };
  }
  if (name === 'ethCallTx' || name === 'estimateGas') {
    assert.deepEqual(Object.keys(args[0]), ['chainId', 'tx', 'block']);
    assert.equal(args[0].chainId, 1);
    assert.equal(args[0].block, 'latest');
    return { kind: name === 'ethCallTx' ? 'call_tx' : 'estimate_tx', tx_json: jsonText(args[0].tx) };
  }
  assert.equal(name, 'feeEstimate');
  assert.equal(args[0], 1);
  return { kind: 'fee' };
}

// getStatus() before and after a read, as JSON (undefined: it returned
// nothing).
const TRUST_STATUSES = [
  ['{"optimisticBlockNumber":5}', '{"optimisticBlockNumber":5}'],
  ['{"optimisticBlockNumber":5}', '{"optimisticBlockNumber":6}'],
  ['{"optimisticBlockNumber":0}', '{"optimisticBlockNumber":0}'],
  ['{"optimisticBlockNumber":-0}', '{"optimisticBlockNumber":0}'],
  ['{"optimisticBlockNumber":0}', '{"optimisticBlockNumber":-0}'],
  ['{"optimisticBlockNumber":5.0}', '{"optimisticBlockNumber":5}'],
  ['{"optimisticBlockNumber":9007199254740993}', '{"optimisticBlockNumber":9007199254740992}'],
  ['{"optimisticBlockNumber":1e21}', '{"optimisticBlockNumber":1e21}'],
  ['{"optimisticBlockNumber":"5"}', '{"optimisticBlockNumber":"5"}'],
  ['{"optimisticBlockNumber":"5"}', '{"optimisticBlockNumber":5}'],
  ['{"optimisticBlockNumber":"\\ud800"}', '{"optimisticBlockNumber":"\\ud800"}'],
  ['{"optimisticBlockNumber":true}', '{"optimisticBlockNumber":true}'],
  ['{"optimisticBlockNumber":false}', '{"optimisticBlockNumber":false}'],
  ['{"optimisticBlockNumber":{}}', '{"optimisticBlockNumber":{}}'],
  ['{"optimisticBlockNumber":[]}', '{"optimisticBlockNumber":[]}'],
  ['{"optimisticBlockNumber":null}', '{"optimisticBlockNumber":null}'],
  ['{}', '{"optimisticBlockNumber":5}'],
  ['{"optimisticBlockNumber":5}', '{}'],
  ['{}', '{}'],
  ['null', 'null'],
  [undefined, '{"optimisticBlockNumber":5}'],
  ['{"optimisticBlockNumber":5,"head":7}', '{"head":7,"optimisticBlockNumber":5}'],
];

async function buildMyotis(router, world) {
  const { requestMyotis, requestViaMyotis } = router.__internals;
  const reads = [];
  router.clearAdaptiveRoutingForTest();
  try {
    world.myotisReady = true;
    for (const [id, method, params, payload, deviation] of myotisInputs()) {
      const calls = [];
      world.myotisOperation = (name, args) => {
        calls.push({ name, args });
        return payload === undefined ? undefined : JSON.parse(payload);
      };
      let js;
      try {
        js = { result_json: jsonText(await requestMyotis(1, method, JSON.parse(params))) };
      } catch (error) {
        js = { error: describeMyotisError(router, error) };
      }
      reads.push({
        id, method, params, payload_json: payload === undefined ? null : payload, wire_json: wirePayload(payload),
        ...(deviation ? { deviation } : {}), js: { operation: describeOperation(calls), ...js },
      });
    }
    // Readiness is checked first.
    world.myotisReady = false;
    let notReady;
    try {
      await requestMyotis(1, 'eth_call', [{ to: ADDRESS }]);
    } catch (error) {
      notReady = describeMyotisError(router, error);
    }
    world.myotisReady = true;
    // The trust block: recorded only when the head was the same before and
    // after the read.
    const trust = [];
    for (const [before, after] of TRUST_STATUSES) {
      const statuses = [before, after];
      world.myotisStatus = () => {
        const status = statuses.shift();
        return status === undefined ? undefined : JSON.parse(status);
      };
      world.myotisOperation = () => ({ resultHex: '0x01' });
      const { result, trust: label } = await requestViaMyotis(1, 'eth_call', [{ to: ADDRESS }], { includeTrust: true });
      assert.equal(result, '0x01');
      assert.equal(statuses.length, 0);
      // What main sends: getStatus()'s optimistic block number (design
      // 0005), absent when there is none.
      const block = (status) => {
        const value = status === undefined ? undefined : JSON.parse(status)?.optimisticBlockNumber;
        return value === undefined ? null : jsonText(value);
      };
      trust.push({
        status_before: before === undefined ? null : before,
        status_after: after,
        block_before_json: block(before),
        block_after_json: block(after),
        js: { trust_json: jsonText(label) },
      });
    }
    return {
      capability_refusal: describePattern(router.__internals.MYOTIS_CAPABILITY_REFUSAL),
      max_refusal_message: router.__internals.MAX_MYOTIS_REFUSAL_MESSAGE,
      blob_fields: router.__internals.MYOTIS_BLOB_FIELDS,
      not_ready: notReady,
      reads,
      trust,
    };
  } finally {
    world.myotisOperation = () => world.fail('myotis');
    world.myotisStatus = () => ({});
    world.myotisReady = false;
    router.clearAdaptiveRoutingForTest();
  }
}

const describePattern = (pattern) => ({ source: pattern.source, flags: pattern.flags });

// ---------------------------------------------------------------------------
// The Ant profile: rankLogScanError, logScanRangeCap, and the range text

function loadBridge(checkout) {
  return loadWithInternals(checkout, 'src/main/swarm/ant-chain-bridge.js', [
    'TIMEOUT_TEXT', 'RANGE_SIZE_TEXT', 'REQUEST_LIMIT_TEXT', 'ENDPOINT_LIMIT_TEXT', 'ENDPOINT_STATE_TEXT',
    'BLOCK_RANGE_CAP_TEXT', 'RESULT_SIZE_TEXT', 'LOG_SCAN_QUORUM_TIMEOUT_MS',
  ], {});
}

// Error messages Ant's log scans meet: the wordings the bridge and the
// router quote (measured by freedom-browser), the router's own errors, and
// boundaries of each pattern. Each is ranked with code -32005 and without
// a code.
const LOG_SCAN_MESSAGES = [
  // Range caps, as the bridge quotes them.
  'Block range 50000 exceeds the maximum of 10000 blocks per logs request',
  'exceed maximum block range: 50000',
  'ranges over 10000 blocks are not supported',
  'You can make eth_getLogs requests with up to a 10000 block range.',
  'Log response size exceeded. You can make eth_getLogs requests with up to a 2K block range and no limit on the response size',
  'eth_getLogs is limited to a 10,000 blocks range',
  'query exceeds max block range 50000',
  'Block range 32059916 exceeds the maximum of 10000 blocks',
  // Result-count and size limits.
  'query returned more than 10000 results',
  'Query returned more than 10,000 results. Try with this block range [0x1, 0x2].',
  'query exceeds limit of 10000 logs',
  'response size exceeded',
  'logs matched by query exceeds limit of 10000',
  'too many blocks',
  'result set too large',
  'maximum number of logs',
  // Throttles and lagging endpoints.
  'limit exceeded',
  'project ID request rate exceeded',
  'rate limit: 10 block-range requests per second',
  'Too Many Requests',
  'HTTP 429',
  'daily request count exceeded, request rate limited',
  'credits exhausted for the max block range',
  'service over capacity, block range too large',
  'Throttled: requests per second limit',
  'block range extends beyond current head block',
  'requested block range [1, 2] is beyond latest executed block 5 (node is still syncing)',
  'node not synced; block range limited',
  // Timeouts.
  'RPC query timeout after 5000ms',
  'Query timeout exceeded. Consider reducing your block range.',
  'request timed out',
  'Time-out',
  'TIMEDOUT',
  'time  out',
  'time\tout',
  'time out',
  'time﻿out',
  'time\u0085out',
  'time᠎out',
  // Ant's needles alone.
  '10000',
  'more than',
  'exceed',
  'range',
  'limit',
  'too large',
  'up to a',
  // Other patterns' boundaries.
  'Maximum allowed block range is: 2,000k',
  'max block range is 5000',
  'maximum block range: 1,000 exceeded',
  'max allowed block range 100k',
  'limited to an 5000 block range',
  'up to a 10,000-block range',
  'up to a 10000 blocks range',
  'ranges above 5000 blocks',
  'ranges wider than 1,000 blocks',
  'range greater than 2000 blocks',
  'Maximum Of 10000 Blocks',
  'maximum of 0 blocks',
  'maximum of ,,, blocks',
  'maximum of 99999999999999999999 blocks',
  'maximum of 9007199254740991 blocks',
  'maximum of 9007199254741k blocks',
  'maximum of 10000blocks in a block range',
  'maximum of 10000 blocksx in a block range',
  'max block range 5000kb',
  'block range is too wide',
  'range of 5000 is too big',
  'block range limit exceeded',
  'permitted range 5',
  'exceeds the block range',
  'accurate block range check failed',
  'x429 block range exceeded',
  'credit block range',
  'creditsx block range exceeded',
  'the limit is ١٢ blocks range',
  // Unicode the patterns and toLowerCase treat differently.
  'max blocK range',
  'BLOCK RANGE',
  'exceedſ the block range',
  'QUERY LİMİT',
  'max block range',
  'block range\ud800 is too large',
  '\udc00',
  '',
];

// [message, code (JSON, or undefined), name, failureKind]
const LOG_SCAN_ERRORS = [
  ...LOG_SCAN_MESSAGES.flatMap((message) => [[message, '-32005'], [message, undefined]]),
  ['query exceeds max block range 50000', '-32000'],
  ['query exceeds max block range 50000', '3'],
  ['query exceeds max block range 50000', '"-32005"'],
  ['query exceeds max block range 50000', '-32005.5'],
  ['query exceeds max block range 50000', '9007199254740992'],
  ['query exceeds max block range 50000', '9007199254740991'],
  ['query exceeds max block range 50000', '-0'],
  ['query exceeds max block range 50000', '1e3'],
  ['query exceeds max block range 50000', 'null'],
  ['query exceeds max block range 50000', 'true'],
  ['ranges over 10000 blocks are not supported', '[1]'],
  ['some failure', '-32005', 'Error', 'timeout'],
  ['some failure', '-32005', 'Error', 'capacity'],
  ['some failure', '-32005', 'AbortError'],
  ['This operation was aborted', '20', 'AbortError'],
  ['The operation was aborted due to timeout', '23', 'TimeoutError'],
  ['RPC quorum did not reach 2 matching responses', undefined, 'SourceUnavailableError', 'timeout'],
  ['fetch failed', undefined, 'TypeError'],
  ['query matched too many logs: the RPC returned only the 474 logs in the last 474 blocks of the 50000-block range asked, and earlier blocks match more; narrow the block range', '-32005', 'TruncatedLogsError'],
];

const CAP_SPANS = [null, 1, 2, 50000, 2 ** 53 - 1, 2 ** 53];

function buildAntProfile(bridge, router) {
  const internals = bridge.__internals;
  const patterns = {};
  for (const name of ['TIMEOUT_TEXT', 'RANGE_SIZE_TEXT', 'REQUEST_LIMIT_TEXT', 'ENDPOINT_LIMIT_TEXT',
    'ENDPOINT_STATE_TEXT', 'RESULT_SIZE_TEXT']) {
    patterns[name] = describePattern(internals[name]);
  }
  patterns.BLOCK_RANGE_CAP_TEXT = internals.BLOCK_RANGE_CAP_TEXT.map(describePattern);
  assert.deepEqual(bridge.LOG_SCAN_ERROR_RANK, { ...router.ERROR_RANK });
  const errors = LOG_SCAN_ERRORS.map(([message, code, name, failureKind]) => {
    const error = new Error(message);
    if (name) Object.defineProperty(error, 'name', { value: name });
    if (code !== undefined) error.code = JSON.parse(code);
    if (failureKind) error.failureKind = failureKind;
    return {
      name: error.name,
      message_json: jsonText(message),
      code_json: code === undefined ? null : code,
      failure_kind: failureKind || null,
      js: {
        rank: bridge.rankLogScanError(error),
        shrinks: bridge.antShrinksLogScanOn(message),
        caps: CAP_SPANS.map((span) => bridge.logScanRangeCap(error, span)),
      },
    };
  });
  const { logRangeRefusal } = router.__internals;
  return {
    rank: bridge.LOG_SCAN_ERROR_RANK,
    needles: bridge.ANT_LOG_SCAN_SHRINK_NEEDLES,
    patterns,
    router_options: {
      exclude_sources: bridge.LOG_SCAN_ROUTER_OPTIONS.excludeSources,
      include_sources: bridge.LOG_SCAN_ROUTER_OPTIONS.includeSources,
      quorum_timeout_ms: bridge.LOG_SCAN_ROUTER_OPTIONS.quorumTimeoutMs,
    },
    cap_spans: CAP_SPANS,
    errors,
    range_refusals: [1, 2, 9999, 50000, 2 ** 53 - 1].map((span) => ({ span, js: describeError(logRangeRefusal(span)) })),
    log_constants: {
      LOG_RANGE_CAP_TTL_MS: router.LOG_RANGE_CAP_TTL_MS,
      LOG_SCAN_COOLDOWN_MS: router.LOG_SCAN_COOLDOWN_MS,
      LOG_SCAN_QUORUM_ROUNDS: router.__internals.LOG_SCAN_QUORUM_ROUNDS,
      LOG_TRUNCATION_TAIL_BLOCKS: router.LOG_TRUNCATION_TAIL_BLOCKS,
      LOG_TRUNCATION_MIN_SPAN: router.LOG_TRUNCATION_MIN_SPAN,
    },
  };
}

// ---------------------------------------------------------------------------
// Blockscout: blockscout-logs.js's filter, mappers, agreement, cooldowns and
// paging, without its network policy (redirects and DNS stay in main)

function loadBlockscout(checkout) {
  return loadWithInternals(checkout, 'src/main/networks/blockscout-logs.js', [
    'rpcTransferLogWellFormed', 'cooldownFrom', 'pageUrl', 'RATE_LIMIT_COOLDOWN_MS', 'MIN_COOLDOWN_MS',
    'MAX_COOLDOWN_MS', 'MAX_RESPONSE_BYTES',
  ], {});
}

const hash = (byte) => '0x' + byte.repeat(32);
const word = (value) => '0x' + BigInt(value).toString(16).padStart(64, '0');

/** One RPC eth_getLogs entry of an xBZZ Transfer, as nodes write it. */
function rpcLog(blockscout, { block, index, from = WALLET, to = COUNTERPARTY, value = 1000, ...fields }) {
  return {
    address: blockscout.LOG_INDEX_TOKENS[100],
    topics: [blockscout.ERC20_TRANSFER_TOPIC, addressTopic(from), addressTopic(to)],
    data: word(value),
    blockNumber: '0x' + block.toString(16),
    blockHash: hash((block % 256).toString(16).padStart(2, '0')),
    transactionHash: hash(((block + index) % 256).toString(16).padStart(2, '0')),
    transactionIndex: '0x0',
    logIndex: '0x' + index.toString(16),
    removed: false,
    ...fields,
  };
}

/** The same transfer as an item of Blockscout's token-transfer list. */
function blockscoutItem(blockscout, { block, index, from = WALLET, to = COUNTERPARTY, value = 1000, ...fields }) {
  return {
    block_number: block,
    log_index: index,
    block_hash: hash((block % 256).toString(16).padStart(2, '0')),
    transaction_hash: hash(((block + index) % 256).toString(16).padStart(2, '0')),
    token_type: 'ERC-20',
    token: { address_hash: blockscout.LOG_INDEX_TOKENS[100].toUpperCase().replace('0X', '0x'), symbol: 'xBZZ', decimals: '16' },
    from: { hash: from.toUpperCase().replace('0X', '0x') },
    to: { hash: to },
    total: { value: String(value), decimals: '16' },
    type: 'token_transfer',
    method: 'transfer',
    timestamp: '2026-10-07T00:00:00.000000Z',
    ...fields,
  };
}

function filterInputs(blockscout) {
  const token = blockscout.LOG_INDEX_TOKENS[100];
  const transfer = blockscout.ERC20_TRANSFER_TOPIC;
  const sender = addressTopic(WALLET);
  const recipient = addressTopic(COUNTERPARTY);
  const filter = (fields) => [{ address: token, topics: [transfer, sender], fromBlock: '0x1', toBlock: '0x186a0', ...fields }];
  const without = (key) => {
    const [value] = filter({});
    delete value[key];
    return [value];
  };
  return [
    ['sender', 100, filter({})],
    ['recipient', 100, filter({ topics: [transfer, null, recipient] })],
    ['both', 100, filter({ topics: [transfer, sender, recipient] })],
    ['sender-null-recipient', 100, filter({ topics: [transfer, sender, null] })],
    ['neither', 100, filter({ topics: [transfer, null, null] })],
    ['neither-short', 100, filter({ topics: [transfer, null] })],
    ['upper-case', 100, filter({ address: token.toUpperCase().replace('0X', '0x'), topics: [transfer.toUpperCase(), sender.toUpperCase()] })],
    ['upper-prefix', 100, filter({ topics: [transfer, sender.replace('0x', '0X')] })],
    ['chain-1', 1, filter({})],
    ['other-token', 100, filter({ address: ADDRESS })],
    ['address-array', 100, filter({ address: [token] })],
    ['other-topic', 100, filter({ topics: [hash('11'), sender] })],
    ['one-topic', 100, filter({ topics: [transfer] })],
    ['four-topics', 100, filter({ topics: [transfer, sender, recipient, null] })],
    ['topic-array', 100, filter({ topics: [transfer, [sender]] })],
    ['topic-not-address', 100, filter({ topics: [transfer, hash('ff')] })],
    ['topic-short', 100, filter({ topics: [transfer, sender.slice(0, -2)] })],
    ['extra-key', 100, filter({ blockHash: hash('00') })],
    ['proto-key', 100, JSON.parse(`[{"address":"${token}","topics":["${transfer}","${sender}"],"fromBlock":"0x1","toBlock":"0x2","__proto__":{}}]`)],
    ['no-from-block', 100, without('fromBlock')],
    ['tag-to-block', 100, filter({ toBlock: 'latest' })],
    ['reversed-range', 100, filter({ fromBlock: '0x10', toBlock: '0xf' })],
    ['one-block', 100, filter({ fromBlock: '0x10', toBlock: '0x10' })],
    ['zero-padded', 100, filter({ fromBlock: '0x0001', toBlock: '0X00ff' })],
    ['unsafe-to-block', 100, filter({ toBlock: '0x20000000000000' })],
    ['max-safe-to-block', 100, filter({ toBlock: '0x1fffffffffffff' })],
    ['number-blocks', 100, filter({ fromBlock: 1, toBlock: 2 })],
    ['two-params', 100, [...filter({}), 'latest']],
    ['params-object', 100, { 0: filter({})[0] }],
    ['filter-array', 100, [[filter({})[0]]]],
    ['filter-null', 100, [null]],
  ];
}

function canonicalInputs(blockscout) {
  const entry = rpcLog(blockscout, { block: 100, index: 1 });
  return [
    ['transfer', entry],
    ['upper-case', { ...entry, address: entry.address.toUpperCase().replace('0X', '0x'), data: entry.data.toUpperCase().replace('0X', '0x'), transactionHash: entry.transactionHash.replace('0x', '0X') }],
    ['padded-quantities', { ...entry, blockNumber: '0x00064', logIndex: '0x0001', transactionIndex: '0x00' }],
    ['wide-quantity', { ...entry, blockNumber: '0x' + '0'.repeat(10) + 'f'.repeat(80) }],
    ['trailing-null-topics', { ...entry, topics: [...entry.topics, null, null] }],
    ['inner-null-topic', { ...entry, topics: [entry.topics[0], null, entry.topics[2]] }],
    ['no-topics', { ...entry, topics: [] }],
    ['two-topics', { ...entry, topics: entry.topics.slice(0, 2) }],
    ['other-event', { ...entry, topics: [hash('11'), ...entry.topics.slice(1)] }],
    ['topics-object', { ...entry, topics: { 0: entry.topics[0] } }],
    ['removed', { ...entry, removed: true }],
    ['removed-string', { ...entry, removed: 'true' }],
    ['removed-missing', (({ removed, ...rest }) => rest)(entry)],
    ['no-block-hash', (({ blockHash, ...rest }) => rest)(entry)],
    ['bad-block-hash', { ...entry, blockHash: '0x12' }],
    ['empty-data', { ...entry, data: '0x' }],
    ['odd-data', { ...entry, data: '0x123' }],
    ['long-data', { ...entry, data: entry.data + '00' }],
    ['number-block', { ...entry, blockNumber: 100 }],
    ['empty-quantity', { ...entry, logIndex: '0x' }],
    ['no-transaction-index', (({ transactionIndex, ...rest }) => rest)(entry)],
    ['bad-address', { ...entry, address: '0x1234' }],
    ['short-address-topic', { ...entry, topics: [entry.topics[0], '0x' + '00'.repeat(11) + 'ab'.repeat(21), entry.topics[2]] }],
    ['dirty-address-topic', { ...entry, topics: [entry.topics[0], '0x01' + entry.topics[1].slice(4), entry.topics[2]] }],
    ['unsafe-block', { ...entry, blockNumber: '0x20000000000000' }],
    ['unsafe-log-index', { ...entry, logIndex: '0x' + 'f'.repeat(16) }],
    ['max-value', { ...entry, data: '0x' + 'f'.repeat(64) }],
    ['null', null],
    ['string', 'x'],
    ['array', [entry]],
  ];
}

function itemInputs(blockscout) {
  const item = blockscoutItem(blockscout, { block: 100, index: 1 });
  return [
    ['transfer', item],
    ['zero-padded-value', { ...item, total: { value: '000123' } }],
    ['value-78-digits', { ...item, total: { value: (2n ** 256n - 1n).toString().padStart(78, '0') } }],
    ['value-max', { ...item, total: { value: (2n ** 256n - 1n).toString() } }],
    ['value-over', { ...item, total: { value: (2n ** 256n).toString() } }],
    ['value-79-digits', { ...item, total: { value: '0'.repeat(78) + '1' } }],
    ['value-empty', { ...item, total: { value: '' } }],
    ['value-number', { ...item, total: { value: 1000 } }],
    ['value-negative', { ...item, total: { value: '-1' } }],
    ['value-arabic-digits', { ...item, total: { value: '١' } }],
    ['no-total', { ...item, total: null }],
    ['other-type', { ...item, token_type: 'ERC-721' }],
    ['no-type', (({ token_type, ...rest }) => rest)(item)],
    ['block-negative-zero', jsonText(item).replace('"block_number":100', '"block_number":-0')],
    ['block-zero', { ...item, block_number: 0 }],
    ['block-string', { ...item, block_number: '100' }],
    ['block-fraction', { ...item, block_number: 1.5 }],
    ['block-negative', { ...item, block_number: -1 }],
    ['block-unsafe', jsonText(item).replace('"block_number":100', '"block_number":9007199254740992')],
    ['log-index-null', { ...item, log_index: null }],
    ['bad-hash', { ...item, transaction_hash: '0x12' }],
    ['upper-hashes', { ...item, block_hash: item.block_hash.toUpperCase().replace('0X', '0x'), transaction_hash: item.transaction_hash.replace('0x', '0X') }],
    ['token-string', { ...item, token: blockscout.LOG_INDEX_TOKENS[100] }],
    ['from-string', { ...item, from: WALLET }],
    ['from-bad', { ...item, from: { hash: '0x12' } }],
    ['null', null],
    ['array', [item]],
  ];
}

function cooldownInputs() {
  // Header values as main reads them (Headers#get); undefined: absent.
  return [
    [undefined, undefined], ['120000', undefined], ['30000', undefined], ['60000', undefined], ['59999', undefined],
    ['900000', undefined], ['900001', undefined], ['1e9', undefined], ['60000.5', undefined], ['0', '30'],
    ['-5', '120'], ['abc', '120'], ['', '90'], [' 70000 ', undefined], ['0x1d4c0', undefined], ['0b1', '61'],
    ['Infinity', '90'], ['1e400', '90'], ['NaN', '90'], ['1_000', '90'], [undefined, '30'], [undefined, '61.5'],
    [undefined, '0'], [undefined, '-1'], [undefined, '1e3'], [undefined, '9999'], [undefined, 'Wed, 21 Oct 2026 07:28:00 GMT'],
    ['5, 10', undefined], [undefined, '+90'], [undefined, '.5e3'], [undefined, '90.'], [undefined, '0o77'],
    [undefined, '00090'], [undefined, ' 90'], [undefined, '0X5A'], [undefined, '-0x5A'], [undefined, '9'.repeat(400)],
  ];
}

function buildCooldowns(blockscout) {
  const { cooldownFrom } = blockscout.__internals;
  return cooldownInputs().map(([reset, retryAfter]) => {
    const headers = new Headers();
    if (reset !== undefined) headers.append('x-ratelimit-reset', reset);
    if (retryAfter !== undefined) headers.append('retry-after', retryAfter);
    return {
      x_ratelimit_reset: headers.get('x-ratelimit-reset'),
      retry_after: headers.get('retry-after'),
      js: { cool_ms: cooldownFrom(headers) },
    };
  });
}

// A page of Blockscout's list: its items newest first and the next
// page's position (null on the last page).
const page = (items, next = null) => ({ status: 200, body: jsonText({ items, next_page_params: next }) });
const NEXT = { block_number: 1, index: 0, items_count: 50 };

function scanScenarios(blockscout) {
  const item = (block, index, fields = {}) => blockscoutItem(blockscout, { block, index, ...fields });
  const sender = addressTopic(WALLET);
  const recipient = addressTopic(COUNTERPARTY);
  const token = blockscout.LOG_INDEX_TOKENS[100];
  const transfer = blockscout.ERC20_TRANSFER_TOPIC;
  const params = (topics, fromBlock = '0x64', toBlock = '0xc8') => jsonText([{ address: token, topics: [transfer, ...topics], fromBlock, toBlock }]);
  const bySender = params([sender]);
  const pages = (count, last) => Array.from({ length: count }, (_, i) => page([item(190 - i, 0)], i === count - 1 ? last : NEXT));
  return [
    { id: 'one-page', params: bySender, toBlock: 200, pages: [page([item(150, 3), item(150, 1), item(120, 0)])] },
    { id: 'empty', params: bySender, toBlock: 200, pages: [page([])] },
    { id: 'pair-to-below-to-block', params: bySender, toBlock: 160, pages: [page([item(150, 3)])] },
    { id: 'two-pages', params: bySender, toBlock: 200, pages: [page([item(190, 2), item(180, 0)], NEXT), page([item(170, 5), item(99, 0), item(98, 0)])] },
    { id: 'stops-at-from-block', params: bySender, toBlock: 200, pages: [page([item(101, 0), item(100, 0), item(99, 0)], NEXT)] },
    { id: 'recipient', params: params([null, recipient]), toBlock: 200, pages: [page([item(150, 0)])] },
    { id: 'sender-and-recipient', params: params([sender, recipient]), toBlock: 200, pages: [page([item(150, 2), item(150, 1, { to: ADDRESS }), item(140, 0)])] },
    { id: 'other-token', params: bySender, toBlock: 200, pages: [page([item(150, 0, { token: { address_hash: ADDRESS } })])] },
    { id: 'other-sender', params: bySender, toBlock: 200, pages: [page([item(150, 0, { from: ADDRESS })])] },
    { id: 'malformed-item', params: bySender, toBlock: 200, pages: [page([item(150, 0, { token_type: 'ERC-721' })])] },
    { id: 'out-of-order', params: bySender, toBlock: 200, pages: [page([item(150, 0), item(151, 0)])] },
    { id: 'same-position', params: bySender, toBlock: 200, pages: [page([item(150, 1), item(150, 1)])] },
    { id: 'at-cursor', params: bySender, toBlock: 200, pages: [page([item(201, 0)])] },
    { id: 'before-cursor', params: bySender, toBlock: 200, pages: [page([item(200, 9)])] },
    { id: 'empty-page-not-last', params: bySender, toBlock: 200, pages: [page([], NEXT)] },
    { id: 'next-page-ignored', params: bySender, toBlock: 200, pages: [page([item(150, 0)], { block_number: 300, index: 0 }), page([item(140, 0)])] },
    { id: 'forty-pages', params: bySender, toBlock: 200, pages: pages(40, null) },
    { id: 'over-forty-pages', params: bySender, toBlock: 200, pages: pages(40, NEXT) },
    { id: 'items-missing', params: bySender, toBlock: 200, pages: [{ status: 200, body: jsonText({ next_page_params: null }) }] },
    { id: 'items-object', params: bySender, toBlock: 200, pages: [{ status: 200, body: jsonText({ items: {}, next_page_params: null }) }] },
    { id: 'next-missing', params: bySender, toBlock: 200, pages: [{ status: 200, body: jsonText({ items: [] }) }] },
    { id: 'next-array', params: bySender, toBlock: 200, pages: [{ status: 200, body: jsonText({ items: [], next_page_params: [] }) }] },
    { id: 'next-string', params: bySender, toBlock: 200, pages: [{ status: 200, body: jsonText({ items: [], next_page_params: 'x' }) }] },
    { id: 'message-throttled', params: bySender, toBlock: 200, pages: [{ status: 200, body: jsonText({ message: 'Too Many Requests' }) }] },
    { id: 'message-rate-limit', params: bySender, toBlock: 200, pages: [{ status: 200, body: jsonText({ message: 'API RATE LIMIT reached', items: [] }) }] },
    { id: 'message-rate-limit-spaced', params: bySender, toBlock: 200, pages: [{ status: 200, body: jsonText({ message: 'rate limit' }) }] },
    { id: 'message-other', params: bySender, toBlock: 200, pages: [{ status: 200, body: jsonText({ message: 'Not found' }) }] },
    { id: 'message-number', params: bySender, toBlock: 200, pages: [{ status: 200, body: jsonText({ message: 5 }) }] },
    { id: 'body-null', params: bySender, toBlock: 200, pages: [{ status: 200, body: 'null' }] },
    { id: 'body-array', params: bySender, toBlock: 200, pages: [{ status: 200, body: '[]' }] },
    { id: 'body-string', params: bySender, toBlock: 200, pages: [{ status: 200, body: '"rate limit"' }] },
    { id: 'not-json', params: bySender, toBlock: 200, pages: [{ status: 200, body: '<html>' }] },
    { id: 'empty-body', params: bySender, toBlock: 200, pages: [{ status: 200, body: '' }] },
    { id: 'bom', params: bySender, toBlock: 200, pages: [{ status: 200, body_hex: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf]), Buffer.from(page([]).body)]).toString('hex') }] },
    { id: 'status-299', params: bySender, toBlock: 200, pages: [{ ...page([]), status: 299 }] },
    { id: 'status-300', params: bySender, toBlock: 200, pages: [{ ...page([]), status: 300 }] },
    { id: 'status-404', params: bySender, toBlock: 200, pages: [{ ...page([]), status: 404 }] },
    { id: 'status-500', params: bySender, toBlock: 200, pages: [{ status: 500, body: 'oops' }] },
    { id: 'throttled-reset', params: bySender, toBlock: 200, pages: [{ status: 429, body: '', headers: { 'x-ratelimit-reset': '120000' } }] },
    { id: 'throttled-retry-after', params: bySender, toBlock: 200, pages: [{ status: 429, body: '', headers: { 'retry-after': '600' } }] },
    { id: 'throttled-unnamed', params: bySender, toBlock: 200, pages: [{ status: 429, body: '' }] },
    { id: 'throttled-later-page', params: bySender, toBlock: 200, pages: [page([item(150, 0)], NEXT), { status: 429, body: '', headers: { 'x-ratelimit-reset': '1' } }] },
    { id: 'content-length-over', params: bySender, toBlock: 200, pages: [{ ...page([]), headers: { 'content-length': '8388609' } }] },
    { id: 'content-length-at-cap', params: bySender, toBlock: 200, pages: [{ ...page([]), headers: { 'content-length': '8388608' } }] },
    { id: 'content-length-not-number', params: bySender, toBlock: 200, pages: [{ ...page([]), headers: { 'content-length': 'abc' } }] },
    { id: 'content-length-hex', params: bySender, toBlock: 200, pages: [{ ...page([]), headers: { 'content-length': '0x800001' } }] },
    // Text length is counted in UTF-16 code units, after decoding.
    { id: 'text-at-cap', params: bySender, toBlock: 200, pages: [{ status: 200, body_repeat: { prefix: '"', unit: 'a', count: 8388606, suffix: '"' } }] },
    { id: 'text-over-cap', params: bySender, toBlock: 200, pages: [{ status: 200, body_repeat: { prefix: '"', unit: 'a', count: 8388607, suffix: '"' } }] },
    { id: 'text-multibyte-under-cap', params: bySender, toBlock: 200, deviation: 'blockscout-page-bytes', pages: [{ status: 200, body_repeat: { prefix: '"', unit: 'é', count: 4194304, suffix: '"' } }] },
    // A valid page under 8 Mi UTF-16 units but over 8 MiB of bytes: the
    // reference reads it; the core refuses it (deviation blockscout-page-bytes).
    { id: 'page-multibyte-over-byte-cap', params: bySender, toBlock: 200, deviation: 'blockscout-page-bytes', pages: [{ status: 200, body_repeat: { prefix: '{"items":[],"next_page_params":null,"pad":"', unit: 'é', count: 4194304, suffix: '"}' } }] },
    { id: 'no-log-index', filter: { chainId: 1, token, sender, recipient: null, fromBlock: 100, toBlock: 200 }, toBlock: 200, pages: [] },
  ];
}

function pageBody(entry) {
  if (entry.body_hex !== undefined) return Buffer.from(entry.body_hex, 'hex');
  if (entry.body_repeat) {
    const { prefix, unit, count, suffix } = entry.body_repeat;
    return Buffer.from(prefix + unit.repeat(count) + suffix, 'utf8');
  }
  return Buffer.from(entry.body, 'utf8');
}

async function buildScans(blockscout) {
  const out = [];
  for (const scenario of scanScenarios(blockscout)) {
    const filter = scenario.filter || blockscout.logIndexFilter(100, JSON.parse(scenario.params));
    assert.ok(filter, scenario.id);
    const pages = [...scenario.pages];
    const urls = [];
    const fetchImpl = async (url) => {
      urls.push(url);
      const entry = pages.shift();
      assert.ok(entry, `${scenario.id}: more pages read than scripted`);
      return new Response(entry.status === 204 ? null : pageBody(entry), { status: entry.status, headers: entry.headers || {} });
    };
    const lookup = async () => assert.fail(`${scenario.id}: no DNS lookup expected`);
    let js;
    try {
      const transfers = await blockscout.fetchBlockscoutTransferLogs(filter, scenario.toBlock, { fetchImpl, lookup, timeoutMs: 60000 });
      js = { transfers_json: jsonText(transfers) };
    } catch (error) {
      assert.equal(error.name, 'BlockscoutError', `${scenario.id}: ${error.stack}`);
      js = { error: { message: error.message, cool_ms: error.coolMs } };
    }
    assert.equal(pages.length, 0, `${scenario.id}: pages left unread`);
    out.push({
      id: scenario.id,
      ...(scenario.deviation ? { deviation: scenario.deviation } : {}),
      ...(scenario.params ? { params: scenario.params } : { filter_json: jsonText(filter) }),
      to_block: scenario.toBlock,
      pages: scenario.pages.map((entry, index) => {
        const response = new Response(null, { headers: entry.headers || {} });
        return {
          url: urls[index],
          status: entry.status,
          content_length: response.headers.get('content-length'),
          x_ratelimit_reset: response.headers.get('x-ratelimit-reset'),
          retry_after: response.headers.get('retry-after'),
          ...(entry.body_repeat ? { body_repeat: entry.body_repeat } : { body_hex: pageBody(entry).toString('hex') }),
        };
      }),
      js,
    });
  }
  return out;
}

function buildBlockscout(blockscout, router) {
  const internals = blockscout.__internals;
  const filters = filterInputs(blockscout).map(([id, chainId, params]) => {
    const filter = blockscout.logIndexFilter(chainId, params);
    return { id, chain_id: Number(chainId), params: jsonText(params), js: { filter_json: filter === null ? null : jsonText(filter) } };
  });
  const logs = canonicalInputs(blockscout).map(([id, entry]) => ({
    id,
    entry_json: jsonText(entry),
    js: {
      canonical_json: jsonText(blockscout.canonicalLog(entry)),
      well_formed: internals.rpcTransferLogWellFormed(entry),
      transfer_json: jsonText(blockscout.rpcTransfer(entry)),
    },
  }));
  // An item given as text keeps its spelling (-0).
  const items = itemInputs(blockscout).map(([id, input]) => {
    const text = typeof input === 'string' ? input : jsonText(input);
    return { id, item_json: text, js: { transfer_json: jsonText(blockscout.blockscoutTransfer(JSON.parse(text))) } };
  });
  // Pairs: Blockscout's items and an RPC's answer for the same span.
  const log = (block, index, fields) => rpcLog(blockscout, { block, index, ...fields });
  const item = (block, index, fields) => blockscoutItem(blockscout, { block, index, ...fields });
  const pairs = [
    ['agree', [item(150, 1), item(120, 0)], [log(120, 0), log(150, 1)]],
    ['agree-empty', [], []],
    ['agree-spelling', [item(150, 1)], [log(150, 1, { blockNumber: '0x0096', logIndex: '0x01', address: blockscout.LOG_INDEX_TOKENS[100].toUpperCase().replace('0X', '0x'), transactionIndex: '0x7', extra: 'x' })]],
    ['agree-upper-hashes', [item(150, 1)], [log(150, 1, { blockHash: hash('96').toUpperCase().replace('0X', '0x') })]],
    ['length', [item(150, 1)], []],
    ['missing', [item(150, 1), item(120, 0)], [log(150, 1), log(121, 0)]],
    ['value', [item(150, 1)], [log(150, 1, { value: 1001 })]],
    ['recipient', [item(150, 1)], [log(150, 1, { to: ADDRESS })]],
    ['block-hash', [item(150, 1)], [log(150, 1, { blockHash: hash('00') })]],
    ['transaction-hash', [item(150, 1)], [log(150, 1, { transactionHash: hash('00') })]],
    ['duplicate-indexed', [item(150, 1), item(150, 1)], [log(150, 1), log(150, 1)]],
    ['duplicate-rpc', [item(150, 1), item(120, 0)], [log(150, 1), log(150, 1)]],
    ['rpc-removed', [item(150, 1)], [log(150, 1, { removed: true })]],
    ['rpc-null-topic', [item(150, 1)], [log(150, 1, { topics: [blockscout.ERC20_TRANSFER_TOPIC, addressTopic(WALLET), addressTopic(COUNTERPARTY), null] })]],
    ['rpc-other-event', [item(150, 1)], [log(150, 1, { topics: [hash('11'), addressTopic(WALLET), addressTopic(COUNTERPARTY)] })]],
    ['rpc-two-topics', [item(150, 1)], [log(150, 1, { topics: [blockscout.ERC20_TRANSFER_TOPIC, addressTopic(WALLET)] })]],
    ['rpc-unsafe-block', [item(150, 1)], [log(150, 1, { blockNumber: '0x20000000000000' })]],
    ['rpc-not-array', [item(150, 1)], { 0: log(150, 1) }],
  ].map(([id, indexed, rpc]) => {
    const transfers = indexed.map((entry) => blockscout.blockscoutTransfer(entry));
    assert.ok(transfers.every(Boolean), id);
    const agree = blockscout.logsAgree(transfers, rpc);
    return {
      id, items_json: jsonText(indexed), rpc_json: jsonText(rpc),
      js: { agree, ...(agree ? { agreed_json: jsonText(blockscout.agreedRpcLogs(rpc)) } : {}) },
    };
  });
  return {
    constants: {
      log_index_url: blockscout.LOG_INDEX_URLS[100],
      log_index_token: blockscout.LOG_INDEX_TOKENS[100],
      log_index_chains: Object.keys(blockscout.LOG_INDEX_TOKENS).map(Number),
      erc20_transfer_topic: blockscout.ERC20_TRANSFER_TOPIC,
      max_pages: blockscout.BLOCKSCOUT_MAX_PAGES,
      max_response_bytes: internals.MAX_RESPONSE_BYTES,
      rate_limit_cooldown_ms: internals.RATE_LIMIT_COOLDOWN_MS,
      min_cooldown_ms: internals.MIN_COOLDOWN_MS,
      max_cooldown_ms: internals.MAX_COOLDOWN_MS,
      tail_blocks: router.LOG_INDEX_TAIL_BLOCKS,
      disagreement_cooldown_ms: router.LOG_INDEX_DISAGREEMENT_COOLDOWN_MS,
      abort_cooldown_ms: router.__internals.LOG_INDEX_ABORT_COOLDOWN_MS,
      pair_malformed_cooldown_ms: router.LOG_INDEX_PAIR_MALFORMED_COOLDOWN_MS,
    },
    filters,
    logs,
    items,
    pairs,
    cooldowns: buildCooldowns(blockscout),
  };
}

// ---------------------------------------------------------------------------
// Broadcast refusals: design 0005's own (deviation broadcast-outcome)
//
// The reference has no refusal classifier: its broadcast re-sends to every
// endpoint on any error and reports the last one. The design classifies
// each attempt instead, and only an exact refusal (a code and a fixed
// message prefix) is `refused`. These cases are the design's: client
// wordings from each client's source, at the release cited. Each answer
// body still goes through the reference's requestRpcUrl, so the error the
// classifier reads is the one the router builds today.
//
// Sources (fetched 2026-10-12):
// - geth v1.17.8: core/txpool/errors.go, core/error.go,
//   core/txpool/validation.go (the wrapping, e.g. "nonce too low: next
//   nonce 5, tx nonce 3"), core/types/transaction_signing.go
//   (ErrInvalidChainId), rpc/errors.go (errcodeDefault = -32000).
// - Nethermind 2.1.0: Nethermind.TxPool/AcceptTxResult.cs (ToString is
//   "code, message"), Nethermind.TxPool/TxPoolErrorMessages.cs,
//   Nethermind.Core/Messages/TxErrorMessages.cs, TxPool/Filters/*.cs,
//   JsonRpc/ErrorCodes.cs (TransactionRejected = -32000 since 1.37.0).
// - Nethermind 1.39.3 and 1.36.0: AcceptTxResult.cs with nameof() codes
//   ("InsufficientFunds", "FeeTooLow", "ReplacementNotAllowed", ...);
//   ErrorCodes.cs TransactionRejected = -32010 up to 1.36.x.
// - Erigon v3.7.1: rpc/jsonrpc/send_transaction.go ("%s: %s" of the import
//   result and the discard reason; "invalid chain id, expected: %d got:
//   %d"), txnprovider/txpool/txpoolcfg/txpoolcfg.go (DiscardReason
//   strings), txnprovider/txpool/txpool_grpc_server.go (reason to import
//   result), rpc/errors.go (ErrCodeDefault = -32000).
// - Besu 26.9.0: ethereum/api/.../JsonRpcErrorConverter.java and
//   RpcErrorType.java (codes and fixed messages, no details).
// - reth v2.7.0: crates/rpc/rpc-eth-types/src/error/mod.rs (RpcPoolError,
//   RpcInvalidTransactionError and their codes), with alloy v2.5.0's
//   EthRpcErrorCode (InvalidInput -32000, TransactionRejected -32003).
// - Providers: Base's eth_sendRawTransaction reference
//   (docs.base.org/base-chain/api-reference/ethereum-json-rpc-api/
//   eth_sendRawTransaction.md) lists geth's wording with -32000; Alchemy's
//   error reference (alchemy.com/docs/reference/error-reference) quotes
//   "already known", "transaction underpriced" and the eth_call form
//   "err: intrinsic gas too low (supplied gas 50000000)".

// [client, code, message, reason (null: ambiguous)]
const BROADCAST_ERRORS = [
  // geth
  ['geth', -32000, 'insufficient funds for gas * price + value: balance 0, tx cost 21000000000000, overshot 21000000000000', 'insufficient_funds'],
  ['geth', -32000, 'insufficient funds for gas * price + value', 'insufficient_funds'],
  ['geth', -32000, 'nonce too low: next nonce 5, tx nonce 3', 'nonce_too_low'],
  ['geth', -32000, 'replacement transaction underpriced', 'replacement_underpriced'],
  ['geth', -32000, 'transaction underpriced', 'underpriced'],
  ['geth', -32000, 'intrinsic gas too low: gas 0, minimum needed 21000', 'intrinsic_gas_too_low'],
  ['geth', -32000, 'exceeds block gas limit', 'exceeds_block_gas_limit'],
  ['geth', -32000, 'max fee per gas less than block base fee: address 0x1111111111111111111111111111111111111111, maxFeePerGas: 1, baseFee: 7', 'fee_cap_below_base_fee'],
  ['geth', -32000, 'max priority fee per gas higher than max fee per gas', 'tip_above_fee_cap'],
  ['geth', -32000, 'invalid sender: invalid chain id for signer: have 1 want 100', 'invalid_sender'],
  ['geth', -32000, 'oversized data: transaction size 131200, limit 131072', 'oversized_data'],
  ['geth', -32000, 'transaction type not supported: tx type 3 not supported by this pool', 'transaction_type_not_supported'],
  ['geth', -32000, 'already known', null],
  ['geth', -32000, 'nonce too high: tx nonce 9, gapped nonce 5', null],
  ['geth', -32000, 'transaction gas price below minimum: gas tip cap 0, minimum needed 1000000', null],
  ['geth', -32000, 'txpool is full', null],
  ['geth', -32000, 'account limit exceeded: pooled 16 txs', null],
  ['geth', -32000, 'only replay-protected (EIP-155) transactions allowed over RPC', null],
  ['geth', -32000, 'tx fee (1.10 ether) exceeds the configured cap (1.00 ether)', null],
  ['geth', -32000, 'negative value', null],
  // Nethermind 2.x (geth's phrases, then ", " and details)
  ['nethermind-2', -32000, 'nonce too low', 'nonce_too_low'],
  ['nethermind-2', -32000, 'insufficient funds for gas * price + value, Account balance: 0, cumulative cost: 21000', 'insufficient_funds'],
  ['nethermind-2', -32000, 'transaction underpriced', 'underpriced'],
  ['nethermind-2', -32000, 'replacement transaction underpriced', 'replacement_underpriced'],
  ['nethermind-2', -32000, 'gas limit reached, Gas limit: 17000000, gas limit of rejected tx: 30000000', 'exceeds_block_gas_limit'],
  ['nethermind-2', -32000, 'transaction too large', 'oversized_data'],
  ['nethermind-2', -32000, 'unsupported transaction type', 'transaction_type_not_supported'],
  ['nethermind-2', -32000, 'failed to recover sender', 'invalid_sender'],
  ['nethermind-2', -32000, 'transaction invalid, InvalidTxChainId: Expected 100, got 1.', 'invalid_chain_id'],
  ['nethermind-2', -32000, 'transaction invalid, intrinsic gas too low', 'intrinsic_gas_too_low'],
  ['nethermind-2', -32000, 'transaction invalid, InvalidTxSignature: Signature is invalid.', 'invalid_sender'],
  ['nethermind-2', -32000, 'already known', null],
  ['nethermind-2', -32000, 'nonce too high', null],
  ['nethermind-2', -32000, 'nonce too far in future', null],
  ['nethermind-2', -32000, 'node is syncing', null],
  ['nethermind-2', -32000, 'transaction cost overflow', null],
  // Nethermind 1.37 to 1.39 (-32000) and up to 1.36 (-32010)
  ['nethermind-1.39', -32000, 'InsufficientFunds, Balance is zero, cannot pay gas', 'insufficient_funds'],
  ['nethermind-1.39', -32000, 'nonce too low', 'nonce_too_low'],
  ['nethermind-1.39', -32000, 'FeeTooLow', 'underpriced'],
  ['nethermind-1.39', -32000, 'FeeTooLowToCompete', 'underpriced'],
  ['nethermind-1.39', -32000, 'ReplacementNotAllowed', 'replacement_underpriced'],
  ['nethermind-1.39', -32000, 'gas limit reached, Gas limit: 17000000, gas limit of rejected tx: 30000000', 'exceeds_block_gas_limit'],
  ['nethermind-1.39', -32000, 'MaxTxSizeExceeded', 'oversized_data'],
  ['nethermind-1.39', -32000, 'NotSupportedTxType', 'transaction_type_not_supported'],
  ['nethermind-1.39', -32000, 'FailedToResolveSender', 'invalid_sender'],
  ['nethermind-1.39', -32000, 'Invalid, InvalidTxChainId: Expected 100, got 1.', 'invalid_chain_id'],
  ['nethermind-1.39', -32000, 'Invalid, intrinsic gas too low', 'intrinsic_gas_too_low'],
  ['nethermind-1.39', -32000, 'Invalid, InvalidTxSignature: Signature is invalid.', 'invalid_sender'],
  ['nethermind-1.39', -32000, 'Invalid, InvalidTxType: Transaction type in Custom is not supported.', null],
  ['nethermind-1.39', -32000, 'AlreadyKnown', null],
  ['nethermind-1.39', -32000, 'NonceTooFarInFuture', null],
  ['nethermind-1.39', -32000, 'Syncing', null],
  ['nethermind-1.36', -32010, 'nonce too low', 'nonce_too_low'],
  ['nethermind-1.36', -32010, 'InsufficientFunds, Account balance: 0, cumulative cost: 21000', 'insufficient_funds'],
  ['nethermind-1.36', -32010, 'ReplacementNotAllowed', 'replacement_underpriced'],
  ['nethermind-1.36', -32010, 'AlreadyKnown', null],
  // Erigon 3: "<import result>: <discard reason>"
  ['erigon', -32000, 'INTERNAL_ERROR: nonce too low', 'nonce_too_low'],
  ['erigon', -32000, 'INTERNAL_ERROR: insufficient funds', 'insufficient_funds'],
  ['erigon', -32000, 'FEE_TOO_LOW: underpriced', 'underpriced'],
  ['erigon', -32000, 'FEE_TOO_LOW: replacement transaction underpriced', 'replacement_underpriced'],
  ['erigon', -32000, 'INTERNAL_ERROR: IntrinsicGas', 'intrinsic_gas_too_low'],
  ['erigon', -32000, 'INTERNAL_ERROR: gas limit is too high', 'exceeds_block_gas_limit'],
  ['erigon', -32000, 'INVALID: max priority fee per gas higher than max fee per gas', 'tip_above_fee_cap'],
  ['erigon', -32000, 'INVALID: invalid sender', 'invalid_sender'],
  ['erigon', -32000, 'invalid chain id, expected: 100 got: 1', 'invalid_chain_id'],
  ['erigon', -32000, 'INVALID: oversized data', 'oversized_data'],
  ['erigon', -32000, 'INVALID: fork supporting this transaction type is not activated yet', 'transaction_type_not_supported'],
  ['erigon', -32000, 'ALREADY_EXISTS: already known', null],
  ['erigon', -32000, 'FEE_TOO_LOW: fee too low', null],
  ['erigon', -32000, 'INTERNAL_ERROR: nonce gap too large: transaction nonce is too far ahead of sender\'s on-chain nonce', null],
  ['erigon', -32000, 'INTERNAL_ERROR: could not replace existing tx', null],
  // Besu: fixed messages, each with its own code
  ['besu', -32001, 'Nonce too low', 'nonce_too_low'],
  ['besu', -32004, 'Upfront gas cost exceeds account balance', 'insufficient_funds'],
  ['besu', -32004, 'Insufficient funds for transfer', 'insufficient_funds'],
  ['besu', -32003, 'Intrinsic gas exceeds gas limit', 'intrinsic_gas_too_low'],
  ['besu', -32005, 'Transaction gas limit exceeds block gas limit', 'exceeds_block_gas_limit'],
  ['besu', -32009, 'Gas price below configured minimum gas price', 'underpriced'],
  ['besu', -32009, 'Gas price below current base fee', 'fee_cap_below_base_fee'],
  ['besu', -32000, 'Replacement transaction underpriced', 'replacement_underpriced'],
  ['besu', -32000, 'Max priority fee per gas exceeds max fee per gas', 'tip_above_fee_cap'],
  ['besu', -32002, 'Invalid signature', 'invalid_sender'],
  ['besu', -32000, 'Wrong chainId', 'invalid_chain_id'],
  ['besu', -32000, 'Transaction size exceeds the maximum allowed size', 'oversized_data'],
  ['besu', -32602, 'Invalid transaction type', 'transaction_type_not_supported'],
  ['besu', -32000, 'Known transaction', null],
  ['besu', -32006, 'Nonce too high', null],
  ['besu', -32000, 'Transaction fee cap exceeded', null],
  ['besu', -32008, 'Initial sync is still in progress', null],
  // reth: pool errors at -32000, some invalid-transaction errors at -32003
  ['reth', -32000, 'nonce too low: next nonce 5, tx nonce 3', 'nonce_too_low'],
  ['reth', -32003, 'insufficient funds for gas * price + value: have 0 want 21000', 'insufficient_funds'],
  ['reth', -32000, 'transaction underpriced', 'underpriced'],
  ['reth', -32000, 'replacement transaction underpriced', 'replacement_underpriced'],
  ['reth', -32000, 'intrinsic gas too low', 'intrinsic_gas_too_low'],
  ['reth', -32000, 'exceeds block gas limit', 'exceeds_block_gas_limit'],
  ['reth', -32000, 'max fee per gas less than block base fee', 'fee_cap_below_base_fee'],
  ['reth', -32003, 'max priority fee per gas higher than max fee per gas', 'tip_above_fee_cap'],
  ['reth', -32000, 'invalid sender', 'invalid_sender'],
  ['reth', -32000, 'invalid chain ID', 'invalid_chain_id'],
  ['reth', -32000, 'oversized data: transaction size 131200, limit 131072', 'oversized_data'],
  ['reth', -32003, 'transaction type not supported', 'transaction_type_not_supported'],
  ['reth', -32000, 'already known', null],
  ['reth', -32003, 'txpool is full', null],
  ['reth', -32000, 'exceeds max transaction gas limit', null],
  // Providers
  ['base', -32000, 'nonce too low', 'nonce_too_low'],
  ['base', -32000, 'insufficient funds for gas * price + value', 'insufficient_funds'],
  ['base', -32000, 'already known', null],
  ['base', -32000, 'replacement transaction underpriced', 'replacement_underpriced'],
  ['alchemy', -32000, 'already known', null],
  ['alchemy', -32000, 'transaction underpriced', 'underpriced'],
  ['alchemy', -32000, 'err: intrinsic gas too low (supplied gas 50000000)', null],
  // Exactness: the code, the prefix, its case and position.
  ['boundary', -32000, 'Nonce too low', null],
  ['boundary', -32001, 'nonce too low', null],
  ['boundary', -32602, 'nonce too low', null],
  ['boundary', -32003, 'Nonce too low', null],
  // A known wording with a code no client documents for it.
  ['boundary', -32003, 'nonce too low', null],
  ['boundary', -32010, 'transaction too large', null],
  ['boundary', -32010, 'transaction underpriced', null],
  ['boundary', -32003, 'oversized data', null],
  ['boundary', -32010, 'FeeTooLow', null],
  ['boundary', -32000, ' nonce too low', null],
  ['boundary', -32000, 'error: nonce too low', null],
  ['boundary', -32000, 'nonce too lo', null],
  ['boundary', -32000, 'nonce too low\u0000', 'nonce_too_low'],
  ['boundary', -32000, 'NONCE TOO LOW', null],
  ['boundary', -32000, 'already known: nonce too low', null],
  ['boundary', -32000, 'Known transaction', null],
  ['boundary', -32000, 'AlreadyKnown, nonce too low', null],
  ['boundary', -32000, 'invalid chain id', 'invalid_chain_id'],
  ['boundary', -32000, 'invalid chain Id', null],
  ['boundary', -32000, 'transaction underpriced', 'underpriced'],
  ['boundary', -32000, 'underpriced', null],
  ['boundary', -32000, 'FeeTooLowX', 'underpriced'],
  ['boundary', -32000, '', null],
  ['boundary', '"-32000"', 'nonce too low', null],
  ['boundary', '-32000.0', 'nonce too low', 'nonce_too_low'],
  ['boundary', '-3.2e4', 'nonce too low', 'nonce_too_low'],
  ['boundary', null, 'nonce too low', null],
  ['boundary', undefined, 'nonce too low', null],
  ['boundary', 'missing', 'nonce too low', null],
  ['boundary', -32000, null, null],
  ['boundary', -32000, ['nonce too low'], 'nonce_too_low'],
  ['boundary', -32000, 'nonce too low\ud800', 'nonce_too_low'],
];

async function buildBroadcastRefusals(router, signed) {
  const original = globalThis.fetch;
  try {
    const cases = [];
    const send = async (status, body) => {
      globalThis.fetch = async () => new Response(Buffer.from(body, 'utf8'), { status });
      try {
        const result = await router.requestRpcUrl('https://rpc.invalid', 'eth_sendRawTransaction', [signed.raw], 60000);
        return result === undefined ? { undefined: true } : { result_json: jsonText(result) };
      } catch (error) {
        return { error: describeError(error) };
      }
    };
    for (const [client, code, message, reason] of BROADCAST_ERRORS) {
      const error = {};
      if (code !== 'missing') error.code = typeof code === 'string' ? '\u0000' : code;
      error.message = message;
      // Codes given as JSON text keep their spelling.
      let body = jsonText({ jsonrpc: '2.0', id: 1, error });
      if (typeof code === 'string' && code !== 'missing') body = body.replace('"\\u0000"', code);
      cases.push({
        client, status: 200, body,
        js: await send(200, body),
        design: reason === null ? { class: 'ambiguous' } : { class: 'refused', reason },
      });
    }
    // Answers that aren't node errors: accepted only with the transaction's
    // own hash.
    const answers = [
      ['accepted', 200, jsonText({ jsonrpc: '2.0', id: 1, result: signed.hash }), 'accepted'],
      ['accepted-upper', 200, jsonText({ result: '0x' + signed.hash.slice(2).toUpperCase() }), 'accepted'],
      ['accepted-upper-prefix', 200, jsonText({ result: '0X' + signed.hash.slice(2) }), 'accepted'],
      ['accepted-escaped', 200, `{"result":"${signed.hash.replace('0x', '0\\u0078')}"}`, 'accepted'],
      ['other-hash', 200, jsonText({ result: hash('00') }), 'ambiguous'],
      ['short-hash', 200, jsonText({ result: signed.hash.slice(0, -2) }), 'ambiguous'],
      ['no-prefix', 200, jsonText({ result: signed.hash.slice(2) }), 'ambiguous'],
      ['hash-with-space', 200, jsonText({ result: signed.hash + ' ' }), 'ambiguous'],
      ['result-null', 200, jsonText({ result: null }), 'ambiguous'],
      ['result-missing', 200, jsonText({ jsonrpc: '2.0', id: 1 }), 'ambiguous'],
      ['result-object', 200, jsonText({ result: { hash: signed.hash } }), 'ambiguous'],
      ['result-true', 200, jsonText({ result: true }), 'ambiguous'],
      ['status-500', 500, jsonText({ error: { code: -32000, message: 'nonce too low' } }), 'ambiguous'],
      ['status-429', 429, jsonText({ result: signed.hash }), 'ambiguous'],
      ['not-json', 200, '<html>', 'ambiguous'],
      ['body-null', 200, 'null', 'ambiguous'],
      ['error-and-result', 200, jsonText({ result: signed.hash, error: { code: -32000, message: 'nonce too low' } }), 'refused', 'nonce_too_low'],
      ['error-falsy', 200, jsonText({ result: signed.hash, error: null }), 'accepted'],
      ['error-string', 200, jsonText({ error: 'nonce too low' }), 'ambiguous'],
    ];
    const attempts = [];
    for (const [id, status, body, kind, reason] of answers) {
      attempts.push({ id, status, body, js: await send(status, body), design: { class: kind, ...(reason ? { reason } : {}) } });
    }
    return { deviation: 'broadcast-outcome', raw: signed.raw, hash: signed.hash, errors: cases, attempts };
  } finally {
    globalThis.fetch = original;
  }
}

// ---------------------------------------------------------------------------

function assertWellFormed(value, where = '') {
  if (typeof value === 'string') assert.ok(value.isWellFormed(), `Lone surrogate in ${where}`);
  else if (Array.isArray(value)) value.forEach((item, index) => assertWellFormed(item, `${where}[${index}]`));
  else if (value && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      assertWellFormed(key, where);
      assertWellFormed(item, `${where}.${key}`);
    }
  }
}

async function buildChain(checkout, ethers, privateKey, meta) {
  const world = createWorld();
  const router = loadRouter(checkout, world);
  assert.equal(router.__internals.stableValue({ b: 1, a: [2] }), '{"a":[2],"b":1}', 'STOP: stableValue sanity check failed');
  const normalization = buildNormalization(router);
  const stable = buildStable(router);
  const safe = buildSafeErrorMessages(router);
  const chain = {
    meta,
    normalization: normalization.cases,
    bigint_whitespace: normalization.bigint_whitespace,
    stable: stable.cases,
    equivalence: stable.equivalence,
    answers: await buildAnswers(router),
    fee_quotes: buildFeeQuotes(router),
    safe_error_message: safe.cases,
    safe_error_whitespace: safe.whitespace,
    failure_texts: {
      request: await buildRequestTexts(router, world),
      fee_quote: await buildFeeQuoteTexts(router, world),
      broadcast: await buildBroadcastTexts(router, world),
    },
    transaction_hashes: await buildTransactionHashes(ethers, privateKey),
  };
  const bridge = loadBridge(checkout);
  const blockscout = loadBlockscout(checkout);
  Object.assign(chain, {
    methods: await buildMethods(router),
    source_orders: await buildSourceOrders(router, world, bridge, blockscout),
    myotis: await buildMyotis(router, world),
    ant_profile: buildAntProfile(bridge, router),
    blockscout: { ...buildBlockscout(blockscout, router), scans: await buildScans(blockscout) },
    broadcast_refusals: await buildBroadcastRefusals(router, {
      raw: chain.transaction_hashes[0].raw, hash: chain.transaction_hashes[0].js.hash,
    }),
  });
  assertWellFormed(chain);
  return chain;
}

module.exports = { buildChain };
