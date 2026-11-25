'use strict';

// stamps-reference.json: `/stamps` replies past the vectors' shapes, read by
// the swarm reference's own bee-js 13.2.0 as `stamp.getAll` reads them
// (`Response.text()`, `JSON.parse`, `GetAllPostageBatchesResponse.parse`,
// `mapPostageBatch`). tests/replies.rs checks the crate against each.
//
//   node stamps-reference.js <swarm reference checkout> > stamps-reference.json
//
// It loads bee-js from the checkout's installed node_modules and refuses any
// version but 13.2.0. Numbers are written as String(n), so NaN and Infinity
// survive JSON; labels as their JSON text, so lone surrogates do.

const path = require('path');

const checkout = process.argv[2];
if (!checkout) throw new Error('usage: node stamps-reference.js <swarm reference checkout>');
const nm = path.join(checkout, 'node_modules/@ethersphere/bee-js/dist/cjs');
const { GetAllPostageBatchesResponse } = require(path.join(nm, 'types/schema/stamps'));
const { mapPostageBatch } = require(path.join(nm, 'utils/stamps'));
const pkg = require(path.join(nm, '../../package.json'));
if (pkg.version !== '13.2.0') throw new Error(pkg.version);

const A = 'a1'.repeat(32);
const base = `"batchID":"${A}","utilization":0,"usable":true,"label":"freedom","depth":22,"amount":"100000000000","bucketDepth":16,"blockNumber":1000,"immutableFlag":true,"batchTTL":864000`;
const cases = {
  empty_object_batch: '{"stamps":[{}]}',
  non_objects: '{"stamps":[1,"x",null,[],true,{' + base + '}]}',
  stamps_object: '{"stamps":{}}',
  no_stamps: '{}',
  root_array: '[]',
  root_null: 'null',
  root_string: '"str"',
  stamps_repeated: '{"stamps":[{' + base + '}],"stamps":5}',
  wrong_types: '{"stamps":[{"batchID":7,"utilization":"0","utilizationRatio":null,"usable":"yes","label":{},"depth":1e400,"amount":5,"bucketDepth":-1e400,"blockNumber":[],"immutableFlag":0,"batchTTL":true}]}',
  escapes: '{"stamps":[{' + base.replace('"label":"freedom"', '"label":"\\ud800x\\u00e9"').replace('"amount":"100000000000"', '"amount":"\\u0031\\u0032"') + '}]}',
  upper_0x: '{"stamps":[{' + base.replace(A, '0X' + 'AB'.repeat(32)) + '}]}',
  empty_id: '{"stamps":[{' + base.replace(A, '') + '}]}',
  short_id: '{"stamps":[{' + base.replace(A, 'ab'.repeat(31)) + '}]}',
  odd_id: '{"stamps":[{' + base.replace(A, 'a'.repeat(63)) + '}]}',
  bad_amount: '{"stamps":[{' + base.replace('"100000000000"', '"1.5"') + '}]}',
  overfull: '{"stamps":[{' + base.replace('"utilization":0', '"utilization":100').replace('"depth":22', '"depth":17') + '}]}',
  deep_40: '{"stamps":[{' + base.replace('"depth":22', '"depth":40') + '}]}',
  depth_huge: '{"stamps":[{' + base.replace('"depth":22', '"depth":2000').replace('"bucketDepth":16', '"bucketDepth":0').replace('"utilization":0', '"utilization":1') + '}]}',
  usage_nan: '{"stamps":[{' + base.replace('"depth":22', '"depth":0').replace('"bucketDepth":16', '"bucketDepth":2000') + '}]}',
  ttl_capped: '{"stamps":[{' + base.replace('864000', '3155695201') + '}]}',
  ttl_negative: '{"stamps":[{' + base.replace('864000', '-5') + '}]}',
  ratio_third: '{"stamps":[{' + base + ',"utilizationRatio":0.3333333333333333}]}',
  ratio_tiny_negative: '{"stamps":[{' + base + ',"utilizationRatio":-0.0000001}]}',
  bad_utf8_label: '',
  bom: '\ufeff{"stamps":[]}',
  empty_reply: '',
  bom_only: '\ufeff',
};
const out = {};
for (const [id, text] of Object.entries(cases)) {
  let t = text;
  let bytes = Buffer.from(text ?? '', 'utf8');
  if (id === 'bad_utf8_label') {
    // The label's bytes: a, 0xff, b, 0xe2 0x82 (cut short).
    const [before, after] = base.split('"label":"freedom"');
    bytes = Buffer.concat([Buffer.from(`{"stamps":[{${before}"label":"a`), Buffer.from([0xff]), Buffer.from('b'),
      Buffer.from([0xe2, 0x82]), Buffer.from(`"${after}}]}`)]);
  }
  // As bee-js's http reads a reply: Response.text() drops a byte-order mark.
  t = new TextDecoder().decode(bytes);
  const reply = bytes.toString('hex');
  try {
    const data = t ? JSON.parse(t) : null;
    const batches = GetAllPostageBatchesResponse.parse(data).stamps.map((x) => mapPostageBatch(x));
    out[id] = { reply, mapped: batches.map((b) => ({
      batchID: b.batchID.toHex(), label: JSON.stringify(b.label), amount: b.amount, usage: String(b.usage), usageText: b.usageText,
      size: String(b.size.toBytes()), remainingSize: String(b.remainingSize.toBytes()), theoreticalSize: String(b.theoreticalSize.toBytes()), duration: b.duration.toSeconds(),
    })) };
  } catch (err) {
    out[id] = { reply, error: { name: err.name, message: err.message } };
  }
}
console.log(JSON.stringify(out, null, 1));
