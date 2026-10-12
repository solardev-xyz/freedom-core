'use strict';

// Signing vectors (design 0002): the reference's own ethers and bee-js produce
// every expected output from keys the reference's derivation produces. Inputs
// are written in the core's wire form; `toEthersTx` is the only translation.

const KEY_CASES = [
  { id: 'account-0', mnemonicId: 'abandon-12', key: { kind: 'account', index: 0 } },
  { id: 'account-max', mnemonicId: 'abandon-12', key: { kind: 'account', index: 2147483647 } },
  { id: 'legal-account-1', mnemonicId: 'legal-12', key: { kind: 'account', index: 1 } },
  { id: 'bee-wallet', mnemonicId: 'abandon-12', key: { kind: 'bee_wallet' } },
  { id: 'publisher-0', mnemonicId: 'abandon-12', key: { kind: 'publisher', origin_index: 0 } },
  { id: 'publisher-7', mnemonicId: 'legal-12', key: { kind: 'publisher', origin_index: 7 } },
];

const MAX_U256 = (2n ** 256n - 1n).toString();
const ADDRESS = '0x8ba1f109551bD432803012645Ac136ddd64DBA72';

const TRANSACTIONS = [
  { id: 'eip1559-transfer', tx: { type: 2, chain_id: '1', nonce: '0', gas_limit: '21000', to: ADDRESS, value: '1000000000000000000', data: '0x', max_fee_per_gas: '30000000000', max_priority_fee_per_gas: '1500000000' } },
  { id: 'eip1559-gnosis-erc20', tx: { type: 2, chain_id: '100', nonce: '42', gas_limit: '65000', to: '0xddafbb505ad214d7b80b1f830fccc89b60fb7a83', value: '0', data: '0xa9059cbb0000000000000000000000008ba1f109551bd432803012645ac136ddd64dba7200000000000000000000000000000000000000000000000000000000000f4240', max_fee_per_gas: '0x77359400', max_priority_fee_per_gas: '0x3b9aca00' } },
  { id: 'eip1559-sepolia-equal-fees', tx: { type: 2, chain_id: '11155111', nonce: '7', gas_limit: '21000', to: ADDRESS, value: '1', data: '0x', max_fee_per_gas: '1', max_priority_fee_per_gas: '1' } },
  { id: 'eip1559-big-chain-max-values', tx: { type: 2, chain_id: '4294967296', nonce: '9007199254740991', gas_limit: MAX_U256, to: ADDRESS, value: MAX_U256, data: '0x00', max_fee_per_gas: MAX_U256, max_priority_fee_per_gas: MAX_U256 } },
  { id: 'eip1559-create', tx: { type: 2, chain_id: '1', nonce: '3', gas_limit: '100000', to: null, value: '0', data: '0x6080604052348015600f57600080fd5b50603f80601d6000396000f3fe6080604052600080fdfea164736f6c6343000818000a', max_fee_per_gas: '2', max_priority_fee_per_gas: '0' } },
  { id: 'eip1559-long-data', tx: { type: 2, chain_id: '1', nonce: '1', gas_limit: '500000', to: ADDRESS, value: '0', data: '0x' + 'ab'.repeat(1000), max_fee_per_gas: '100', max_priority_fee_per_gas: '50' } },
  { id: 'legacy-mainnet', tx: { type: 0, chain_id: '1', nonce: '0', gas_limit: '21000', to: ADDRESS, value: '1000000000000000000', data: '0x', gas_price: '20000000000' } },
  { id: 'legacy-gnosis', tx: { type: 0, chain_id: '100', nonce: '255', gas_limit: '30000', to: ADDRESS, value: '0', data: '0x1234', gas_price: '1' } },
  { id: 'legacy-big-chain', tx: { type: 0, chain_id: '4294967296', nonce: '256', gas_limit: '21000', to: ADDRESS, value: '0', data: '0x', gas_price: '0' } },
  { id: 'legacy-create', tx: { type: 0, chain_id: '11155111', nonce: '0', gas_limit: '53000', to: null, value: '0', data: '0x00', gas_price: '1000000000' } },
  // ethers rejects these; so does the core.
  { id: 'error-priority-above-max', tx: { type: 2, chain_id: '1', nonce: '0', gas_limit: '21000', to: ADDRESS, value: '0', data: '0x', max_fee_per_gas: '1', max_priority_fee_per_gas: '2' } },
  { id: 'error-unsafe-nonce', tx: { type: 2, chain_id: '1', nonce: '9007199254740992', gas_limit: '21000', to: ADDRESS, value: '0', data: '0x', max_fee_per_gas: '2', max_priority_fee_per_gas: '1' } },
];

const MESSAGES = [
  { id: 'empty', message: '' },
  { id: 'ascii', message: Buffer.from('Hello, Freedom!').toString('hex') },
  { id: 'utf8-multibyte', message: Buffer.from('Grüße 🔐 自由').toString('hex') },
  { id: 'binary-32', message: 'ff00'.repeat(16) },
  { id: 'siwe', message: Buffer.from('example.org wants you to sign in with your Ethereum account:\n0x9858EfFD232B4033E47d90003D41EC34EcaEda94\n\nURI: https://example.org\nVersion: 1\nChain ID: 1\nNonce: 32891756\nIssued At: 2026-01-01T00:00:00.000Z').toString('hex') },
  { id: 'long-1000', message: '61'.repeat(1000) },
];

const MAIL_TYPES = {
  Person: [{ name: 'name', type: 'string' }, { name: 'wallet', type: 'address' }],
  Mail: [{ name: 'from', type: 'Person' }, { name: 'to', type: 'Person' }, { name: 'contents', type: 'string' }],
};
const MAIL_DOMAIN = { name: 'Ether Mail', version: '1', chainId: 1, verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC' };
const MAIL_MESSAGE = {
  from: { name: 'Cow', wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826' },
  to: { name: 'Bob', wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB' },
  contents: 'Hello, Bob!',
};
const ONE = (type) => ({ M: [{ name: 'v', type }] });
const SAFE_TX_TYPES = {
  SafeTx: [
    { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'data', type: 'bytes' },
    { name: 'operation', type: 'uint8' }, { name: 'safeTxGas', type: 'uint256' }, { name: 'baseGas', type: 'uint256' },
    { name: 'gasPrice', type: 'uint256' }, { name: 'gasToken', type: 'address' }, { name: 'refundReceiver', type: 'address' },
    { name: 'nonce', type: 'uint256' },
  ],
};
const SAFE = '0x1234567890AbcdEF1234567890aBcdef12345678';

const TYPED_DATA = [
  { id: 'mail', typed_data: { domain: MAIL_DOMAIN, types: MAIL_TYPES, message: MAIL_MESSAGE } },
  { id: 'mail-extra-field-ignored', typed_data: { domain: MAIL_DOMAIN, types: MAIL_TYPES, message: { ...MAIL_MESSAGE, unused: 'x' } } },
  { id: 'domain-chain-only', typed_data: { domain: { chainId: 100 }, types: ONE('uint256'), message: { v: '1' } } },
  { id: 'domain-hex-chain-and-salt', typed_data: { domain: { name: 'S', chainId: '0x64', salt: '0x' + '11'.repeat(32) }, types: ONE('uint8'), message: { v: 5 } } },
  { id: 'domain-empty', typed_data: { domain: {}, types: ONE('bool'), message: { v: false } } },
  { id: 'uint-boundaries', typed_data: { domain: { name: 'U' }, types: { M: [{ name: 'a', type: 'uint8' }, { name: 'b', type: 'uint256' }, { name: 'c', type: 'uint64' }, { name: 'd', type: 'uint16' }] }, message: { a: 255, b: MAX_U256, c: '0xffffffffffffffff', d: '0' } } },
  { id: 'int-boundaries', typed_data: { domain: { name: 'I' }, types: { M: [{ name: 'a', type: 'int8' }, { name: 'b', type: 'int8' }, { name: 'c', type: 'int256' }, { name: 'd', type: 'int256' }] }, message: { a: -128, b: 127, c: '-' + (2n ** 255n).toString(), d: ((2n ** 255n) - 1n).toString() } } },
  { id: 'safe-integer-numbers', typed_data: { domain: { name: 'N' }, types: { M: [{ name: 'a', type: 'uint256' }, { name: 'b', type: 'int64' }] }, message: { a: 9007199254740991, b: -9007199254740991 } } },
  { id: 'bytes-kinds', typed_data: { domain: { name: 'B' }, types: { M: [{ name: 'a', type: 'bytes' }, { name: 'b', type: 'bytes1' }, { name: 'c', type: 'bytes32' }, { name: 'd', type: 'bytes' }] }, message: { a: '0xdeadbeef', b: '0x01', c: '0x' + 'ab'.repeat(32), d: '0x' } } },
  { id: 'addresses-lower-and-checksum', typed_data: { domain: { name: 'A' }, types: { M: [{ name: 'a', type: 'address' }, { name: 'b', type: 'address' }] }, message: { a: ADDRESS.toLowerCase(), b: ADDRESS } } },
  { id: 'strings-unicode', typed_data: { domain: { name: 'Grüße 🔐' }, types: ONE('string'), message: { v: 'zwölf Boxkämpfer 自由 🔐' } } },
  { id: 'arrays', typed_data: { domain: { name: 'Arr' }, types: { Item: [{ name: 'id', type: 'uint32' }, { name: 'tags', type: 'string[]' }], M: [{ name: 'items', type: 'Item[]' }, { name: 'fixed', type: 'uint8[3]' }, { name: 'nested', type: 'uint256[][]' }, { name: 'none', type: 'address[]' }] }, message: { items: [{ id: 1, tags: ['a', 'b'] }, { id: 2, tags: [] }], fixed: [1, 2, 3], nested: [['1'], [], ['2', '3']], none: [] } } },
  { id: 'bool-values', typed_data: { domain: { name: 'Bool' }, types: { M: [{ name: 'a', type: 'bool' }, { name: 'b', type: 'bool' }] }, message: { a: true, b: false } } },
  { id: 'safe-tx', typed_data: { domain: { chainId: 100, verifyingContract: SAFE }, types: SAFE_TX_TYPES, message: { to: ADDRESS, value: '1234567890123456789', data: '0x', operation: 0, safeTxGas: '0', baseGas: '0', gasPrice: '0', gasToken: '0x0000000000000000000000000000000000000000', refundReceiver: '0x0000000000000000000000000000000000000000', nonce: '3' } } },
  { id: 'safe-message', typed_data: { domain: { chainId: 100, verifyingContract: SAFE }, types: { SafeMessage: [{ name: 'message', type: 'bytes' }] }, message: { message: '0x' + '5e'.repeat(32) } } },
  { id: 'eip3009-transfer-with-authorization', typed_data: { domain: { name: 'USD Coin', version: '2', chainId: 8453, verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' }, types: { TransferWithAuthorization: [{ name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' }, { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' }] }, message: { from: '0x9858EfFD232B4033E47d90003D41EC34EcaEda94', to: ADDRESS, value: '10000', validAfter: '1767225000', validBefore: '1767225600', nonce: '0x' + '42'.repeat(32) } } },
  { id: 'permit2-witness-transfer', typed_data: { domain: { name: 'Permit2', chainId: 8453, verifyingContract: '0x000000000022D473030F116dDEE9F6B43aC78BA3' }, types: { PermitWitnessTransferFrom: [{ name: 'permitted', type: 'TokenPermissions' }, { name: 'spender', type: 'address' }, { name: 'nonce', type: 'uint256' }, { name: 'deadline', type: 'uint256' }, { name: 'witness', type: 'Witness' }], TokenPermissions: [{ name: 'token', type: 'address' }, { name: 'amount', type: 'uint256' }], Witness: [{ name: 'to', type: 'address' }, { name: 'validAfter', type: 'uint256' }] }, message: { permitted: { token: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', amount: '10000' }, spender: '0x4020615294c913F045dc10f0a5cdEbd86c280001', nonce: '123456789012345678901234567890', deadline: '1767225600', witness: { to: ADDRESS, validAfter: '1767225000' } } } },
  // ethers rejects these; so does the core.
  { id: 'error-ambiguous-root', typed_data: { domain: { name: 'E' }, types: { A: [{ name: 'a', type: 'uint8' }], B: [{ name: 'b', type: 'uint8' }] }, message: { a: 1 } } },
  { id: 'error-unused-type', typed_data: { domain: { name: 'E' }, types: { M: [{ name: 'a', type: 'uint8' }], U: [{ name: 'x', type: 'uint8' }] }, message: { a: 1 } } },
  { id: 'error-cycle', typed_data: { domain: { name: 'E' }, types: { M: [{ name: 'm', type: 'M' }] }, message: { m: {} } } },
  { id: 'error-unknown-type', typed_data: { domain: { name: 'E' }, types: { M: [{ name: 'a', type: 'Missing' }] }, message: { a: {} } } },
  { id: 'error-domain-key', typed_data: { domain: { foo: 1 }, types: ONE('uint8'), message: { v: 1 } } },
  { id: 'error-domain-type-in-types', typed_data: { domain: { name: 'E' }, types: { ...ONE('uint8'), EIP712Domain: [{ name: 'name', type: 'string' }] }, message: { v: 1 } } },
  { id: 'error-uint8-overflow', typed_data: { domain: { name: 'E' }, types: ONE('uint8'), message: { v: 256 } } },
  { id: 'error-uint-negative', typed_data: { domain: { name: 'E' }, types: ONE('uint256'), message: { v: '-1' } } },
  { id: 'error-int8-underflow', typed_data: { domain: { name: 'E' }, types: ONE('int8'), message: { v: -129 } } },
  { id: 'error-float', typed_data: { domain: { name: 'E' }, types: ONE('uint256'), message: { v: 1.5 } } },
  { id: 'error-unsafe-number', typed_data: { domain: { name: 'E' }, types: ONE('uint256'), message: { v: 9007199254740992 } } },
  { id: 'error-bytes32-short', typed_data: { domain: { name: 'E' }, types: ONE('bytes32'), message: { v: '0x01' } } },
  { id: 'error-bytes-not-hex', typed_data: { domain: { name: 'E' }, types: ONE('bytes'), message: { v: 'hello' } } },
  { id: 'error-bad-checksum', typed_data: { domain: { name: 'E' }, types: ONE('address'), message: { v: '0x8Ba1f109551bD432803012645Ac136ddd64DBA72' } } },
  { id: 'error-missing-field', typed_data: { domain: { name: 'E' }, types: ONE('uint8'), message: {} } },
  { id: 'error-string-not-string', typed_data: { domain: { name: 'E' }, types: ONE('string'), message: { v: 5 } } },
  { id: 'error-fixed-array-length', typed_data: { domain: { name: 'E' }, types: ONE('uint8[2]'), message: { v: [1, 2, 3] } } },
  // ethers signs these; the core rejects them (design 0002: bool is strict).
  { id: 'deviation-bool-string-false', deviation: 'bool-strict', typed_data: { domain: { name: 'D' }, types: ONE('bool'), message: { v: 'false' } } },
  { id: 'deviation-bool-number', deviation: 'bool-strict', typed_data: { domain: { name: 'D' }, types: ONE('bool'), message: { v: 1 } } },
];

const SOCS = [
  { id: 'one-byte', identifier: '00'.repeat(32), payload: '01' },
  { id: 'thirty-two', identifier: '11'.repeat(32), payload: 'ab'.repeat(32) },
  { id: 'thirty-three', identifier: '22'.repeat(32), payload: 'cd'.repeat(33) },
  { id: 'full-4096', identifier: '33'.repeat(32), payload: Buffer.alloc(4096, 7).toString('hex') },
  { id: 'span-above-payload', identifier: '44'.repeat(32), payload: 'ef'.repeat(64), span: '1000000' },
  { id: 'span-below-payload', identifier: '55'.repeat(32), payload: 'ef'.repeat(64), span: '1' },
];

function keyFor(reference, mnemonicFor, { mnemonicId, key }) {
  const mnemonic = mnemonicFor(mnemonicId);
  const d = reference.derivation;
  if (key.kind === 'account') return d.deriveUserWallet(mnemonic, key.index);
  if (key.kind === 'bee_wallet') return d.deriveAllKeys(mnemonic).beeWallet;
  return d.derivePublisherKey(mnemonic, key.origin_index);
}

function toEthersTx(tx) {
  const ethersTx = {
    type: tx.type, chainId: BigInt(tx.chain_id), nonce: Number(tx.nonce), gasLimit: BigInt(tx.gas_limit),
    to: tx.to, value: BigInt(tx.value), data: tx.data,
  };
  if (BigInt(tx.nonce) > BigInt(Number.MAX_SAFE_INTEGER)) ethersTx.nonce = BigInt(tx.nonce);
  if (tx.type === 0) ethersTx.gasPrice = BigInt(tx.gas_price);
  else {
    ethersTx.maxFeePerGas = BigInt(tx.max_fee_per_gas);
    ethersTx.maxPriorityFeePerGas = BigInt(tx.max_priority_fee_per_gas);
  }
  return ethersTx;
}

async function settle(fn) {
  try {
    return { status: 'success', ...(await fn()) };
  } catch (error) {
    return { status: 'error', message: error.shortMessage || error.message };
  }
}

async function buildSigning(reference, mnemonicFor, meta) {
  const { ethers, beeJs } = reference;
  const keys = KEY_CASES.map((entry) => {
    const derived = keyFor(reference, mnemonicFor, entry);
    return { ...entry, address: derived.address, wallet: new ethers.Wallet(derived.privateKey) };
  });
  const byId = Object.fromEntries(keys.map((entry) => [entry.id, entry]));
  const accounts = keys.filter((entry) => entry.key.kind === 'account');

  const transactions = [];
  for (const { id, tx } of TRANSACTIONS) {
    for (const signer of accounts) {
      transactions.push({
        id: `${id}/${signer.id}`, keyId: signer.id, tx,
        result: await settle(async () => {
          const raw = await signer.wallet.signTransaction(toEthersTx(tx));
          return { raw, hash: ethers.keccak256(raw) };
        }),
      });
    }
  }

  const messages = [];
  for (const { id, message } of MESSAGES) {
    for (const signer of accounts) {
      messages.push({
        id: `${id}/${signer.id}`, keyId: signer.id, message: '0x' + message,
        result: await settle(async () => ({
          signature: await signer.wallet.signMessage(Buffer.from(message, 'hex')),
        })),
      });
    }
  }

  const typedData = [];
  for (const { id, typed_data: data, deviation } of TYPED_DATA) {
    for (const signer of accounts) {
      typedData.push({
        id: `${id}/${signer.id}`, keyId: signer.id, typed_data: data,
        ...(deviation ? { deviation } : {}),
        result: await settle(async () => ({
          signature: await signer.wallet.signTypedData(data.domain, data.types, data.message),
          hash: ethers.TypedDataEncoder.hash(data.domain, data.types, data.message),
        })),
      });
    }
  }

  const bee = new beeJs.Bee('http://127.0.0.1:1633');
  const socs = [];
  for (const { id, identifier, payload, span } of SOCS) {
    for (const signer of keys) {
      const derived = keyFor(reference, mnemonicFor, signer);
      socs.push({
        id: `${id}/${signer.id}`, keyId: signer.id, identifier: '0x' + identifier, payload: '0x' + payload,
        ...(span ? { span } : {}),
        result: await settle(async () => {
          const cac = bee.makeContentAddressedChunk(
            Buffer.from(payload, 'hex'), span ? BigInt(span) : undefined
          );
          const soc = cac.toSingleOwnerChunk(
            new beeJs.Identifier(identifier), new beeJs.PrivateKey(derived.privateKey.slice(2))
          );
          return {
            span: soc.span.toBigInt().toString(),
            chunkAddress: '0x' + cac.address.toHex(),
            signature: '0x' + soc.signature.toHex(),
            owner: soc.owner.toChecksum(),
            socAddress: '0x' + soc.address.toHex(),
          };
        }),
      });
    }
  }

  return {
    meta,
    encodings: {
      quantities: 'decimal or 0x-hex strings, as on the core wire',
      bytes: '0x-prefixed lowercase hex',
      signature: '65 bytes r || s || v with v in {27, 28}, 0x hex',
      deviation: 'ethers signs these; the core must reject them (design 0002)',
    },
    keys: keys.map(({ id, mnemonicId, key, address }) => ({ id, mnemonicId, key, address })),
    transactions, messages, typedData, socs,
  };
}

module.exports = { buildSigning };
