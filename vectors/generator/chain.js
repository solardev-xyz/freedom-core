'use strict';

// Chain-data codec vectors (design 0005, step 1): the reference's own
// chain-data-router.js produces every expected output. Its internal
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
  };
  return world;
}

function loadRouter(checkout, world) {
  const registry = {
    getNetwork: () => world.network,
    getEndpoints: (_chainId, kind) => world.endpoints[kind] || [],
  };
  const myotis = {
    NETWORKS: new Set([1]),
    isReady: () => world.myotisReady,
    getStatus: () => ({}),
    ethCallTx: async () => world.fail('myotis'),
    estimateGas: async () => world.fail('myotis'),
    feeEstimate: async () => world.fail('myotis'),
    sendRawTransaction: async () => world.fail('myotis'),
  };
  const colibri = { requestViaColibri: async () => world.fail('colibri') };
  const router = loadWithInternals(checkout, 'src/main/networks/chain-data-router.js',
    ['normalizeParams', 'stableValue', 'safeErrorMessage', 'feeQuote'], {
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
  assertWellFormed(chain);
  return chain;
}

module.exports = { buildChain };
