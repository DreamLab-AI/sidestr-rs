// The fixture generator for sidestr-evm's JSON-RPC: siding's Ethereum JSON-RPC (sidestr/spec at fa86dac,
// siding/lib/evmrpc.mjs, AGPL-3.0, Melvin Carvalho) over the `evm` rule (siding/lib/overlays/evm.mjs), both
// the reference modules themselves, on ethereumjs 10.1.3, driven by a scripted host. Every request and the
// exact text `JSON.stringify` makes of its answer are written to `rpc.json` for the Rust port to reproduce
// byte for byte.
//
// The host plays `lib/chain.mjs` and `bin/siding.mjs`: the genesis's EVM record, a mempool whose carriers pass
// `evm.checkTx` at the next height, blocks sequenced as `sequencedEvm` does (begin, checkTx with keep, end)
// with the withdrawals and the `evmroot:` record in the coinbase, then `evm.prepare`; the POST /evm handler
// for the HTTP cases. The clock is frozen (`Date.now`), so the answers that read it (a read-only call's
// block.timestamp) are fixed too: nothing is normalised for time.
//
//   mkdir -p $SCRATCH/lib/overlays && cp sidestr-evm/tests/oracle/{rpc-oracle.mjs,package.json,package-lock.json} $SCRATCH
//   cp $SIDESTR_SIDING/lib/evmrpc.mjs $SCRATCH/lib/ && cp $SIDESTR_SIDING/lib/overlays/evm.mjs $SCRATCH/lib/overlays/
//   cd $SCRATCH && npm ci && node rpc-oracle.mjs $REPO/sidestr-evm/tests/fixtures
//
// @noble/curves and @noble/hashes (a signature ethereumjs will not make) are ethereumjs's own dependencies,
// at the versions package-lock.json pins. Error texts from JavaScript itself are V8's: run it on Node 22.
import fs from 'node:fs'; import path from 'node:path'; import crypto from 'node:crypto';
import * as T from '@ethereumjs/tx'; import * as com from '@ethereumjs/common'; import * as util from '@ethereumjs/util'; import { RLP } from '@ethereumjs/rlp';
import { secp256k1 } from '@noble/curves/secp256k1.js'; import { keccak_256 } from '@noble/hashes/sha3.js';

const PINNED = { 'lib/evmrpc.mjs': '40440d6a56fa552f9ca0d0b5dae4f0917bdde23220ec99cbc0c7e6c567c90d32', 'lib/overlays/evm.mjs': '8903eab6c67244ded02edf8122112efb015ee1e3e5d4ca913372e542cc1820cc' };
const out = process.argv[2]; if (!out) { console.error('usage: node rpc-oracle.mjs <fixtures dir>'); process.exit(2); }
const here = path.dirname(new URL(import.meta.url).pathname);
for (const [f, want] of Object.entries(PINNED)) {
  const p = path.join(here, f); if (!fs.existsSync(p)) { console.error(`${f} is missing: copy it from siding at fa86dac`); process.exit(2); }
  const sum = crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex'); if (sum !== want) { console.error(`${f} is not the pinned file (sha256 ${sum})`); process.exit(2); }
}
const { evmOverlay, carrierScript, depositScript, rootScript, GWEI, WITHDRAW } = await import(path.join(here, 'lib/overlays/evm.mjs'));
const { makeEvmRpc } = await import(path.join(here, 'lib/evmrpc.mjs'));

// ---- the frozen clock ------------------------------------------------------------------------------
const GENESIS_TIME = 1790000000, NOW = 1790003600;
Date.now = () => NOW * 1000 + 250;

// ---- the scripted host ---------------------------------------------------------------------------
const sha = (x) => crypto.createHash('sha256').update(x).digest('hex');
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const RESERVE = '5120' + 'aa'.repeat(32);
const chain = { id: 'sidestr:evmrpcoracle', challenge: RESERVE, rules: ['evm'], evm: { chainId: 21474, gasLimit: 30000000 } };
const evm = evmOverlay(chain); await evm.init();
evm.roots.set(0, evm.roots.get(-1)); evm.blocks.set(0, { hashes: [], root: '0x' + evm.roots.get(-1) }); // chain.mjs, the genesis
const codec = { blockHash: (h) => h.hash, txid: (tx) => tx.txid };
const s = { node: { chain: [sha('genesis')], headers: [{ time: GENESIS_TIME }] }, mempool: new Map(), height() { return this.node.chain.length - 1; } };
const steps = []; let carried = 0;
const submit = async (label, outputs) => { // chain.mjs submit: the EVM check at the next height, then the mempool
  const tx = { txid: sha(`submit ${label}`), outputs: outputs.map(([value, scriptPubKey]) => ({ value, scriptPubKey })) };
  const ev = await evm.checkTx(tx, tx.txid, { height: s.height() + 1 }); if (!ev.ok) throw new Error(`${label}: evm: ${ev.error}`);
  s.mempool.set(tx.txid, tx); steps.push({ submit: { label, outputs: tx.outputs.map((o) => ({ value: o.value, script: o.scriptPubKey })) } });
};
const carrier = async (spk) => { // bin/siding.mjs carrier: one output, the producer's coins pay (their outputs do not reach the EVM)
  const tx = { txid: sha(`carrier ${carried++}`), outputs: [{ value: 0, scriptPubKey: spk }] };
  const ev = await evm.checkTx(tx, tx.txid, { height: s.height() + 1 }); if (!ev.ok) throw new Error(`evm: ${ev.error}`);
  s.mempool.set(tx.txid, tx); return { txid: tx.txid };
};
let time = GENESIS_TIME;
const produce = async (label, dt = 60) => { // chain.mjs sequencedEvm + buildNext + the add path's prepare
  const h = s.height() + 1; time += dt; const txs = [...s.mempool.values()];
  await evm.begin(); const withdrawals = [], hashes = [];
  for (const tx of txs) { const r = await evm.checkTx(tx, tx.txid, { height: h, time, keep: true }); if (!r.ok) throw new Error(`${label}: sequencing dropped ${tx.txid}: ${r.error}`); withdrawals.push(...r.withdrawals); hashes.push(...r.hashes); }
  const root = await evm.end(hashes);
  const coinbase = [...withdrawals.map((w) => ({ value: w.sats, scriptPubKey: w.script })), { value: 0, scriptPubKey: rootScript(root) }];
  const block = { header: { hash: sha(`block ${label}`), time }, transactions: [{ txid: sha(`coinbase ${label}`), outputs: coinbase }, ...txs] };
  const v = await evm.prepare(block, h, codec); if (!v.ok) throw new Error(`${label}: ${v.error}`);
  s.node.chain.push(block.header.hash); s.node.headers.push({ time }); s.mempool.clear();
  steps.push({ block: { label, height: h, hash: block.header.hash, time, root, coinbase: coinbase.map((o) => ({ value: o.value, script: o.scriptPubKey })) } });
  console.error(`block ${h} ${label}: ${hashes.length} evm transaction(s), root ${root.slice(0, 18)}…`);
};
const rpc = makeEvmRpc({ s, chain, evm, carrier });
// one request, its answer as the wire carries it. `reason` is the one normalisation: an error message
// compared only as far as this prefix, because what follows is ethereumjs's own text (why a raw
// transaction does not read; why the host's mempool check refused a carrier) and the port's is its own
const call = async (label, request, { reason } = {}) => { const res = await rpc(request); const response = JSON.stringify(res); steps.push({ rpc: { label, request, response, ...(reason ? { normalise: reason } : {}) } }); return res; };
const req = (method, params, id = 1) => ({ jsonrpc: '2.0', id, method, ...(params === undefined ? {} : { params }) });
const result = async (label, method, params) => { const r = await call(label, req(method, params)); if (r.error) throw new Error(`${label}: ${r.error.message}`); return r.result; };
const refused = async (label, method, params, opts) => { const r = await call(label, req(method, params), opts); if (!r.error) throw new Error(`${label}: expected an error, got ${JSON.stringify(r.result)}`); return r.error; };
// bin/siding.mjs's POST /evm body handling, for the cases that start from bytes
const httpCase = async (label, body) => {
  let status, response; let parsed; let bad = false; try { parsed = JSON.parse(body); } catch { bad = true; }
  if (body.length > 1048576) { status = 413; response = JSON.stringify({ error: 'too large' }); }
  else if (bad) { status = 400; response = JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }); }
  else { status = 200; response = JSON.stringify(await rpc(parsed)); }
  steps.push({ http: { label, body, status, response } });
};

// ---- keys, transactions, contracts ----------------------------------------------------------------
const common = evm.common;
const key = (b) => util.hexToBytes('0x' + b.repeat(32));
const alicePriv = key('42'), carolPriv = key('43'), davePriv = key('46'), frankPriv = key('47'), gracePriv = key('48');
const addrOf = (p) => util.createAddressFromPrivateKey(p).toString();
const alice = addrOf(alicePriv), carol = addrOf(carolPriv), dave = addrOf(davePriv), frank = addrOf(frankPriv), grace = addrOf(gracePriv);
const bob = '0x' + '77'.repeat(20), erin = '0x' + 'e7'.repeat(20);
const checksum = (a) => util.toChecksumAddress(a);
const nonces = new Map(); const nonce = (a) => { const n = nonces.get(a) ?? 0; nonces.set(a, n + 1); return n; };
const created = (from, n) => util.createContractAddress(util.createAddressFromString(from), BigInt(n)).toString();
const raw = (etx) => '0x' + hex(etx.serialize());
const legacy = (priv, f) => T.createLegacyTx({ gasPrice: GWEI, gasLimit: 21000, ...f }, { common }).sign(priv);
const eip1559 = (priv, f) => T.createFeeMarket1559Tx({ chainId: 21474n, maxFeePerGas: 3n * GWEI, maxPriorityFeePerGas: 0n, gasLimit: 21000, ...f }, { common }).sign(priv);
const eip2930 = (priv, f) => T.createAccessList2930Tx({ chainId: 21474n, gasPrice: 2n * GWEI, gasLimit: 60000, ...f }, { common }).sign(priv);
const pre155 = com.createCustomCommon({ chainId: 21474 }, com.Mainnet, { hardfork: com.Hardfork.TangerineWhistle });
const mainnet = new com.Common({ chain: com.Mainnet, hardfork: com.Hardfork.Cancun });
const word = (n) => n.toString(16).padStart(64, '0');
const deployer = (runtime) => { const n = runtime.length / 2; return '60' + n.toString(16).padStart(2, '0') + '80600b6000396000f3' + runtime; };
const INIT_42 = '69602a60005260206000f3600052600a6016f3'; // evmrpc-test.mjs: returns 42
const INIT_TIME = '66425f5260205ff35f5260076019f3'; // evmrpc-test.mjs: returns block.timestamp
const INIT_NUMBER = '66435f5260205ff35f5260076019f3'; // returns block.number
const TOPIC = 'ab'.repeat(32);
// slot 0 = the calldata word, slot 1 counts calls, LOG2(word; topics TOPIC, word)
const RUNTIME_LOG = '600035600055' + '600154600101600155' + '600035600052' + '600035' + '7f' + TOPIC + '60206000a2' + '00';
const RUNTIME_REVERT = '63deadbeef600052' + '6004601cfd'; // reverts with 0xdeadbeef
const TARGET = '5120' + 'bb'.repeat(32);

// ---- the steps ---------------------------------------------------------------------------------------
await result('web3_clientVersion', 'web3_clientVersion');
await result('net_version', 'net_version');
await result('eth_chainId', 'eth_chainId', []);
for (const m of ['eth_syncing', 'eth_accounts', 'eth_mining', 'eth_blockNumber', 'eth_gasPrice', 'eth_maxPriorityFeePerGas']) await result(m, m, []);
await result('the genesis block by number', 'eth_getBlockByNumber', ['0x0', false]);
await result('the genesis block, earliest, full', 'eth_getBlockByNumber', ['earliest', true]);
await result('the genesis block by hash', 'eth_getBlockByHash', ['0x' + s.node.chain[0], false]);
await result('a block by hash in upper case', 'eth_getBlockByHash', ['0x' + s.node.chain[0].toUpperCase(), false]);
await result('an unknown block hash', 'eth_getBlockByHash', ['0x' + '00'.repeat(32), false]);
await result('an empty account has no balance', 'eth_getBalance', [alice, 'latest']);
await produce('empty');
await submit('deposits', [[2_000_000, RESERVE], [0, depositScript(alice)], [500_000, RESERVE], [0, depositScript(carol)], [1_000_000, RESERVE], [0, depositScript(dave)]]);
await submit('two more deposits', [[800_000, RESERVE], [0, depositScript(frank)], [900_000, RESERVE], [0, depositScript(grace)]]);
await result('pending counts no deposit', 'eth_getTransactionCount', [alice, 'pending']);
await produce('deposits');

await result('a deposit of 2,000,000 sats is 2,000,000 gwei', 'eth_getBalance', [alice, 'latest']);
await result('a checksummed address', 'eth_getBalance', [checksum(alice)]);
await result('an address with 0X', 'eth_getBalance', ['0X' + alice.slice(2).toUpperCase()]);
await refused('an address too short', 'eth_getBalance', ['0x1234']);
await refused('no params', 'eth_getBalance', []);
await refused('no params member', 'eth_getBalance', undefined);
await refused('params null', 'eth_getBalance', null);
await refused('params an object', 'eth_getBalance', { address: alice });
await refused('params a number', 'eth_getBalance', 5);
await refused('params a string: its first character', 'eth_getBalance', alice);
await refused('an address that is a number', 'eth_getBalance', [5]);
await refused('an address that is an object', 'eth_getBalance', [{}]);
await result('the nonce, latest', 'eth_getTransactionCount', [alice, 'latest']);
await result('the nonce, no tag', 'eth_getTransactionCount', [alice]);
await result('no code at an account', 'eth_getCode', [alice, 'latest']);
await result('no code at a missing account', 'eth_getCode', [erin]);
await result('the balance of a missing account', 'eth_getBalance', [erin]);
await result('eth_feeHistory with percentiles', 'eth_feeHistory', ['0x4', 'latest', [50]]);
await result('eth_feeHistory without percentiles', 'eth_feeHistory', ['0x4', 'latest']);
await result('eth_feeHistory, a number count', 'eth_feeHistory', [2, 'latest', [10, 90]]);
await result('eth_feeHistory, more blocks than there are', 'eth_feeHistory', ['0x9', 'latest', []]);
await result('eth_feeHistory, no blocks', 'eth_feeHistory', ['0x0', 'latest', [25, 75]]);
await result('eth_feeHistory, a decimal string', 'eth_feeHistory', ['3', 'latest']);
await result('eth_feeHistory, an empty string is 0', 'eth_feeHistory', ['']);
await refused('eth_feeHistory, a negative count', 'eth_feeHistory', ['-1', 'latest']);
await refused('eth_feeHistory, a count that is no number', 'eth_feeHistory', ['abc']);
await refused('eth_feeHistory, a fraction', 'eth_feeHistory', [1.5]);
await refused('eth_feeHistory, no count', 'eth_feeHistory', []);
await refused('eth_feeHistory, null count', 'eth_feeHistory', [null]);
await refused('eth_feeHistory, percentiles not a list', 'eth_feeHistory', ['0x2', 'latest', 'x']);
await refused('eth_feeHistory, a count past any array', 'eth_feeHistory', ['0x100000000', 'latest']);
await result('eth_estimateGas: a transfer is 21000', 'eth_estimateGas', [{ from: alice, to: bob, value: '0x1' }]);
await result('eth_estimateGas: from the zero address, no value', 'eth_estimateGas', [{ to: bob }]);
await result('eth_estimateGas: a deployment', 'eth_estimateGas', [{ from: alice, data: '0x' + INIT_42 }]);
await result('eth_estimateGas: calldata with zero bytes to an account', 'eth_estimateGas', [{ from: alice, to: bob, data: '0x00ff0000ff' }]);
await result('eth_estimateGas: to the identity precompile', 'eth_estimateGas', [{ to: '0x0000000000000000000000000000000000000004', data: '0x' + 'ab'.repeat(40) }]);
await refused('eth_estimateGas: value beyond the balance', 'eth_estimateGas', [{ from: erin, to: bob, value: '0x1' }]);
await refused('eth_estimateGas: no call object', 'eth_estimateGas', []);
await refused('eth_estimateGas: a null call object', 'eth_estimateGas', [null]);

const h1 = await result('eth_sendRawTransaction: a legacy transfer', 'eth_sendRawTransaction', [raw(legacy(alicePriv, { nonce: nonce(alice), to: bob, value: 500_000n * GWEI }))]);
await result('pending counts the carrier', 'eth_getTransactionCount', [alice, 'pending']);
await result('latest does not', 'eth_getTransactionCount', [alice, 'latest']);
await result('the receipt is null until a block', 'eth_getTransactionReceipt', [h1]);
await result('the transaction is null until a block', 'eth_getTransactionByHash', [h1]);
const h2 = await result('eth_sendRawTransaction: EIP-1559 with a tip', 'eth_sendRawTransaction', [raw(eip1559(carolPriv, { nonce: nonce(carol), to: bob, value: 1000n * GWEI, maxPriorityFeePerGas: 2n * GWEI }))]);
const h3 = await result('eth_sendRawTransaction: EIP-2930 with an access list', 'eth_sendRawTransaction', [raw(eip2930(davePriv, { nonce: nonce(dave), to: carol, value: 5n * GWEI, accessList: [{ address: bob, storageKeys: ['0x' + word(1), '0x' + word(2)] }] }))]);
await refused('a second carrier from one sender fails the host\'s check against the confirmed state', 'eth_sendRawTransaction', [raw(legacy(alicePriv, { nonce: 1, to: bob, value: 1n }))], { reason: 'evm: carrier at output 0: ' });
await result('pending, a checksummed address', 'eth_getTransactionCount', [checksum(carol), 'pending']);
await refused('eth_sendRawTransaction: not a transaction', 'eth_sendRawTransaction', ['0x1234'], { reason: 'not a transaction: ' });
await refused('eth_sendRawTransaction: empty', 'eth_sendRawTransaction', ['0x'], { reason: 'not a transaction: ' });
await refused('eth_sendRawTransaction: signed for chain 1', 'eth_sendRawTransaction', [raw(T.createLegacyTx({ nonce: 9, gasPrice: GWEI, gasLimit: 21000, to: bob }, { common: mainnet }).sign(alicePriv))], { reason: 'not a transaction: ' });
await refused('eth_sendRawTransaction: EIP-1559 for chain 1', 'eth_sendRawTransaction', [raw(T.createFeeMarket1559Tx({ chainId: 1n, maxFeePerGas: GWEI, gasLimit: 21000, to: bob, nonce: 9 }, { common: mainnet }).sign(alicePriv))], { reason: 'not a transaction: ' });
{ const t = eip1559(alicePriv, { nonce: 9, to: bob }); const r = t.raw(); const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n; r[r.length - 3] = util.bigIntToUnpaddedBytes(t.v ^ 1n); r[r.length - 1] = util.bigIntToUnpaddedBytes(N - t.s);
  await refused('eth_sendRawTransaction: EIP-1559 with a high s', 'eth_sendRawTransaction', ['0x02' + hex(RLP.encode(r))], { reason: 'not a transaction: ' }); }
{ const t = eip1559(alicePriv, { nonce: 9, to: bob }); const r = t.raw(); await refused('eth_sendRawTransaction: EIP-1559 unsigned (nine fields)', 'eth_sendRawTransaction', ['0x02' + hex(RLP.encode(r.slice(0, 9)))]); }
{ const t = eip2930(alicePriv, { nonce: 9, to: bob }); const r = t.raw(); await refused('eth_sendRawTransaction: EIP-2930 unsigned (eight fields)', 'eth_sendRawTransaction', ['0x01' + hex(RLP.encode(r.slice(0, 8)))]); }
{ const t = eip1559(alicePriv, { nonce: 9, to: bob }); const r = t.raw(); r[r.length - 2] = new Uint8Array(); r[r.length - 1] = new Uint8Array();
  await refused('eth_sendRawTransaction: EIP-1559 with r and s empty', 'eth_sendRawTransaction', ['0x02' + hex(RLP.encode(r))]); }
{ const b = legacy(alicePriv, { nonce: 9, to: bob, value: 5n }); await refused('eth_sendRawTransaction: legacy unsigned (six fields)', 'eth_sendRawTransaction', ['0x' + hex(RLP.encode(b.raw().slice(0, 6)))]);
  await refused('eth_sendRawTransaction: legacy, v r s empty', 'eth_sendRawTransaction', [raw(T.createLegacyTx({ nonce: 9, gasPrice: GWEI, gasLimit: 21000, to: bob }, { common }))]);
  const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  await refused('eth_sendRawTransaction: legacy with a high s', 'eth_sendRawTransaction', [raw(T.createLegacyTx({ nonce: 9, gasPrice: GWEI, gasLimit: 21000, to: bob, value: 5n, v: b.v === 21474n * 2n + 35n ? b.v + 1n : b.v - 1n, r: b.r, s: N - b.s }, { common }))]);
  await refused('eth_sendRawTransaction: legacy with r = 0', 'eth_sendRawTransaction', [raw(T.createLegacyTx({ nonce: 9, gasPrice: GWEI, gasLimit: 21000, to: bob, value: 5n, v: b.v, r: 0n, s: b.s }, { common }))]);
  await refused('eth_sendRawTransaction: legacy with trailing bytes', 'eth_sendRawTransaction', [raw(b) + '00'], { reason: 'not a transaction: ' }); }
{ // ethereumjs will not build one, so it is signed by hand
  const f = eip1559(alicePriv, { nonce: 9, to: bob, maxFeePerGas: GWEI }).raw().slice(0, 9); f[2] = util.bigIntToUnpaddedBytes(2n * GWEI);
  const sig = secp256k1.sign(util.hexToBytes('0x' + hex(keccak_256(Uint8Array.from([2, ...RLP.encode(f)])))), alicePriv, { prehash: false, format: 'recovered', lowS: true });
  const signed = [...f, sig[0] ? Uint8Array.from([1]) : new Uint8Array(), util.unpadBytes(sig.slice(1, 33)), util.unpadBytes(sig.slice(33, 65))];
  await refused('eth_sendRawTransaction: EIP-1559 with its tip above its fee cap', 'eth_sendRawTransaction', ['0x02' + hex(RLP.encode(signed))], { reason: 'not a transaction: ' }); }
await refused('eth_sendRawTransaction: no 0x', 'eth_sendRawTransaction', ['1234']);
await refused('eth_sendRawTransaction: not hex', 'eth_sendRawTransaction', ['0xzz']);
await refused('eth_sendRawTransaction: not hex, odd length', 'eth_sendRawTransaction', ['0xzz1']);
await refused('eth_sendRawTransaction: no raw transaction', 'eth_sendRawTransaction', []);
await refused('eth_sendRawTransaction: a number', 'eth_sendRawTransaction', [1234]);
await refused('eth_sendRawTransaction: null', 'eth_sendRawTransaction', [null]);
await produce('three transfers');

for (const [l, h] of [['legacy', h1], ['EIP-1559', h2], ['EIP-2930', h3]]) {
  await result(`receipt: ${l}`, 'eth_getTransactionReceipt', [h]);
  await result(`transaction: ${l}`, 'eth_getTransactionByHash', [h]);
}
await result('a receipt by an upper-case hash', 'eth_getTransactionReceipt', ['0x' + h2.slice(2).toUpperCase()]);
await result('a receipt by an unknown hash', 'eth_getTransactionReceipt', ['0x' + '12'.repeat(32)]);
await result('a transaction by a malformed hash', 'eth_getTransactionByHash', ['0x12']);
await result('a transaction by no hash', 'eth_getTransactionByHash', []);
await result('bob has the 500,000 gwei and more', 'eth_getBalance', [bob]);
await result('the latest block', 'eth_getBlockByNumber', ['latest', false]);
await result('the latest block, full', 'eth_getBlockByNumber', ['latest', true]);
await result('the block by hash, full', 'eth_getBlockByHash', ['0x' + s.node.chain[3], true]);
await result('the block by number, hex', 'eth_getBlockByNumber', ['0x3']);
await result('the block by number, a JSON number', 'eth_getBlockByNumber', [2, false]);
await result('the block by number, true is 1', 'eth_getBlockByNumber', [true, false]);
await result('a "false" string is truthy', 'eth_getBlockByNumber', ['0x3', 'false']);
await result('0 is not', 'eth_getBlockByNumber', ['0x3', 0]);
for (const tag of ['pending', 'safe', 'finalized']) await result(`the block tagged ${tag}`, 'eth_getBlockByNumber', [tag, false]);
await result('no tag is latest', 'eth_getBlockByNumber', []);
await result('an unknown height is null', 'eth_getBlockByNumber', ['0x7fffffff', false]);
await result('a negative height is null', 'eth_getBlockByNumber', ['-1', false]);
await result('a height beyond 256 bits is null', 'eth_getBlockByNumber', ['0x1' + '0'.repeat(80), false]);
await refused('a tag that is no number', 'eth_getBlockByNumber', ['newest', false]);
await refused('a null tag', 'eth_getBlockByNumber', [null, false]);
await result('transaction count, latest', 'eth_getBlockTransactionCountByNumber', ['latest']);
await result('transaction count, an empty block', 'eth_getBlockTransactionCountByNumber', ['0x1']);
await result('transaction count, an unknown block', 'eth_getBlockTransactionCountByNumber', ['0x99']);

const n42 = nonce(alice), c42 = created(alice, n42), nLog = nonce(frank), cLog = created(frank, nLog), nRev = nonce(grace), cRev = created(grace, nRev);
const nTime = nonce(dave), cTime = created(dave, nTime), nNum = nonce(carol), cNum = created(carol, nNum);
const d42 = await result('deploy: returns 42', 'eth_sendRawTransaction', [raw(legacy(alicePriv, { nonce: n42, gasLimit: 100000, data: '0x' + INIT_42 }))]);
const dLog = await result('deploy: stores and logs', 'eth_sendRawTransaction', [raw(legacy(frankPriv, { nonce: nLog, gasLimit: 200000, data: '0x' + deployer(RUNTIME_LOG) }))]);
await result('deploy: reverts with data', 'eth_sendRawTransaction', [raw(eip1559(gracePriv, { nonce: nRev, gasLimit: 100000, data: '0x' + deployer(RUNTIME_REVERT) }))]);
await result('deploy: returns block.timestamp', 'eth_sendRawTransaction', [raw(legacy(davePriv, { nonce: nTime, gasLimit: 100000, data: '0x' + INIT_TIME }))]);
await result('deploy: returns block.number', 'eth_sendRawTransaction', [raw(legacy(carolPriv, { nonce: nNum, gasLimit: 100000, data: '0x' + INIT_NUMBER }))]);
await produce('five deployments');

await result('a deployment receipt names the contract', 'eth_getTransactionReceipt', [d42]);
await result('a deployment transaction has no to', 'eth_getTransactionByHash', [dLog]);
await result('eth_getCode returns the runtime', 'eth_getCode', [c42, 'latest']);
await result('eth_getCode, the log contract', 'eth_getCode', [cLog]);
await result('eth_call returns 42', 'eth_call', [{ to: c42, from: alice }, 'latest']);
await result('eth_call sees the next block\'s timestamp', 'eth_call', [{ to: cTime }, 'latest']);
await result('eth_call sees the next block\'s number', 'eth_call', [{ to: cNum }]);
await result('eth_estimateGas for a call', 'eth_estimateGas', [{ from: alice, to: c42 }]);
await result('eth_estimateGas for a call with value', 'eth_estimateGas', [{ from: alice, to: c42, value: '0x10' }]);
await result('eth_estimateGas for storage and a log (first touch)', 'eth_estimateGas', [{ from: alice, to: cLog, data: '0x' + word(7) }]);
await refused('eth_call reverting with data', 'eth_call', [{ to: cRev }]);
await refused('eth_estimateGas reverting with data', 'eth_estimateGas', [{ to: cRev, from: carol }]);
await result('eth_call to an account with data: nothing runs', 'eth_call', [{ to: alice, data: '0x' + 'ff'.repeat(4) }]);
await refused('eth_call out of gas', 'eth_call', [{ to: c42, gas: '0x5' }]);
await result('eth_call with a gas number', 'eth_call', [{ to: c42, gas: 100000 }]);
await result('eth_call with input', 'eth_call', [{ to: c42, input: '0x01' }]);
await result('eth_call data wins over input', 'eth_call', [{ to: alice, data: '0x', input: 'nonsense' }]);
await result('eth_call without to runs the code as a creation', 'eth_call', [{ from: alice, data: '0x' + INIT_42 }]);
await result('eth_call, an empty to is a creation', 'eth_call', [{ to: '', data: '0x' + INIT_42 }]);
await result('eth_call, a call object that is a string', 'eth_call', ['latest']);
await refused('eth_call with value the caller lacks', 'eth_call', [{ from: erin, to: c42, value: '0x1' }]);
await result('eth_call with value from the zero-address coinbase, which holds the tips', 'eth_call', [{ to: c42, value: '0x1' }]);
await refused('eth_call with a value beyond 256 bits', 'eth_call', [{ from: alice, to: bob, value: '0x1' + '0'.repeat(70) }]);
await refused('eth_call, data without 0x', 'eth_call', [{ to: c42, data: 'ff' }]);
await refused('eth_call, data not hex', 'eth_call', [{ to: c42, data: '0xgg' }]);
await refused('eth_call, data a number', 'eth_call', [{ to: c42, data: 5 }]);
await refused('eth_call, a bad to', 'eth_call', [{ to: '0x12' }]);
await refused('eth_call, a bad from', 'eth_call', [{ to: c42, from: 7 }]);
await refused('eth_call, a fractional value', 'eth_call', [{ to: c42, value: 1.5 }]);
await refused('eth_call, a gas that is no number', 'eth_call', [{ to: c42, gas: 'lots' }]);
await result('the state has not moved', 'eth_getTransactionCount', [alice, 'latest']);

const w1 = await result('store 42', 'eth_sendRawTransaction', [raw(legacy(alicePriv, { nonce: nonce(alice), to: cLog, gasLimit: 100000, data: '0x' + word(42) }))]);
const w2 = await result('store 0x1234, EIP-1559', 'eth_sendRawTransaction', [raw(eip1559(carolPriv, { nonce: nonce(carol), to: cLog, gasLimit: 100000, data: '0x' + word(0x1234), maxPriorityFeePerGas: GWEI }))]);
const w3 = await result('a call that reverts is carried and applied', 'eth_sendRawTransaction', [raw(legacy(gracePriv, { nonce: nonce(grace), to: cRev, gasLimit: 50000 }))]);
const w5 = await result('eth_sendRawTransaction: pre-EIP-155 legacy', 'eth_sendRawTransaction', ['0x' + hex(T.createLegacyTx({ nonce: nonce(frank), gasPrice: GWEI, gasLimit: 21000, to: bob, value: 3n }, { common: pre155 }).sign(frankPriv).serialize())]);
const w4 = await result('store 0x77, EIP-2930', 'eth_sendRawTransaction', [raw(eip2930(davePriv, { nonce: nonce(dave), to: cLog, gasLimit: 100000, data: '0x' + word(0x77), accessList: [{ address: cLog, storageKeys: ['0x' + word(0), '0x' + word(1)] }] }))]);
await produce('writes and logs');

for (const [l, h] of [['store 42', w1], ['store 0x1234', w2], ['reverted', w3], ['store 0x77', w4], ['pre-EIP-155', w5]]) await result(`receipt: ${l}`, 'eth_getTransactionReceipt', [h]);
await result('transaction: pre-EIP-155', 'eth_getTransactionByHash', [w5]);
await result('transaction: EIP-2930 with its access list', 'eth_getTransactionByHash', [w4]);
await result('storage: slot 0', 'eth_getStorageAt', [cLog, '0x0', 'latest']);
await result('storage: slot 1', 'eth_getStorageAt', [cLog, '0x1']);
await result('storage: slot 1, padded', 'eth_getStorageAt', [cLog, '0x' + word(1)]);
await result('storage: slot 1, odd length', 'eth_getStorageAt', [cLog, '0x001']);
await result('storage: an unwritten slot', 'eth_getStorageAt', [cLog, '0x5']);
await result('storage: an account without code', 'eth_getStorageAt', [alice, '0x0']);
await result('storage: a missing account', 'eth_getStorageAt', [erin, '0x0']);
await result('storage: an empty position', 'eth_getStorageAt', [cLog, '0x']);
await refused('storage: a position of 33 bytes', 'eth_getStorageAt', [cLog, '0x01' + word(1)]);
await refused('storage: a position without 0x', 'eth_getStorageAt', [cLog, '1']);
await refused('storage: no position', 'eth_getStorageAt', [cLog]);
await refused('storage: a bad address comes first', 'eth_getStorageAt', ['0x12', 'nonsense']);
await result('logs: the latest block', 'eth_getLogs', [{}]);
await result('logs: every block', 'eth_getLogs', [{ fromBlock: '0x0', toBlock: 'latest' }]);
await result('logs: a block with none', 'eth_getLogs', [{ fromBlock: '0x4', toBlock: '0x4' }]);
await result('logs: a JSON-number range', 'eth_getLogs', [{ fromBlock: 5, toBlock: 5 }]);
await result('logs: null bounds are latest', 'eth_getLogs', [{ fromBlock: null, toBlock: null }]);
await result('logs: by address', 'eth_getLogs', [{ fromBlock: 'earliest', address: cLog }]);
await result('logs: by a list of addresses', 'eth_getLogs', [{ fromBlock: 'earliest', address: [c42, checksum(cLog)] }]);
await result('logs: by another address', 'eth_getLogs', [{ fromBlock: 'earliest', address: c42 }]);
await result('logs: an empty address is no filter', 'eth_getLogs', [{ address: '' }]);
await result('logs: by the first topic', 'eth_getLogs', [{ topics: ['0x' + TOPIC] }]);
await result('logs: by the second topic', 'eth_getLogs', [{ topics: [null, '0x' + word(42)] }]);
await result('logs: either of two', 'eth_getLogs', [{ topics: [null, ['0x' + word(42), '0x' + word(0x77)]] }]);
await result('logs: topics compare as written', 'eth_getLogs', [{ topics: ['0x' + TOPIC.toUpperCase()] }]);
await result('logs: an empty alternative matches nothing', 'eth_getLogs', [{ topics: [[]] }]);
await result('logs: an empty string is a wildcard', 'eth_getLogs', [{ topics: ['', '0x' + word(0x1234)] }]);
await result('logs: a third topic no log has', 'eth_getLogs', [{ topics: ['0x' + TOPIC, null, '0x' + word(1)] }]);
await result('logs: an empty topic list', 'eth_getLogs', [{ topics: [] }]);
await result('logs: a filter that is a string', 'eth_getLogs', ['latest']);
await refused('logs: an address that is a number', 'eth_getLogs', [{ address: 5 }]);
await refused('logs: topics that are a string', 'eth_getLogs', [{ topics: 'ab' }]);
await result('logs: topics that are a string, no log in range', 'eth_getLogs', [{ fromBlock: '0x1', toBlock: '0x1', topics: 'ab' }]);
await refused('logs: no filter', 'eth_getLogs', []);
await refused('logs: a bound that is no number', 'eth_getLogs', [{ fromBlock: 'soon' }]);
await result('the block with the writes, full', 'eth_getBlockByNumber', ['latest', true]);
await result('eth_feeHistory after five blocks', 'eth_feeHistory', ['0x4', 'latest', [50]]);

const wd = await result('a withdrawal', 'eth_sendRawTransaction', [raw(legacy(alicePriv, { nonce: nonce(alice), to: WITHDRAW, gasLimit: 30000, value: 100_000n * GWEI, data: '0x' + TARGET }))]);
await submit('an ordinary payment', [[10_000, TARGET]]);
await result('pending ignores what is not a carrier', 'eth_getTransactionCount', [alice, 'pending']);
await produce('a withdrawal');
await result('receipt: the withdrawal', 'eth_getTransactionReceipt', [wd]);
await result('the WITHDRAW account is empty', 'eth_getBalance', [WITHDRAW]);
await result('alice after the withdrawal', 'eth_getBalance', [alice]);

// batches, ids and methods
const batch = async (label, body) => { const res = await rpc(body); steps.push({ rpc: { label, request: body, response: JSON.stringify(res) } }); };
await batch('a batch answers each, unknown methods with -32601', [{ jsonrpc: '2.0', id: 'a', method: 'eth_chainId' }, { jsonrpc: '2.0', id: 'b', method: 'nope' }]);
await batch('an empty batch', []);
await batch('a batch of oddities', [5, null, 'x', [1], {}, { id: 0, method: 'eth_blockNumber' }]);
await batch('a nested batch', [[{ id: 1, method: 'eth_chainId' }]]);
await batch('no id is null', { method: 'eth_chainId' });
await batch('an id that is an object', { id: { n: [1, 'two'] }, method: 'eth_chainId' });
await batch('an explicit null id', { id: null, method: 'eth_chainId' });
await batch('params ignored where none are read', { id: 7, method: 'eth_blockNumber', params: { a: 1 } });
await batch('params null where none are read', { id: 7, method: 'net_version', params: null });
await batch('a method in a list', { id: 8, method: ['eth_chainId'] });
await batch('a method that is a number', { id: 9, method: 5 });
await batch('a method that is an object', { id: 10, method: { a: 1 } });
await batch('a method list with null and nesting', { id: 11, method: [null, ['a', 1.5], true] });
await batch('no method', { id: 12 });
await batch('a body that is a number', 5);
await batch('a body that is null', null);
await batch('a body that is a string', 'eth_chainId');
await httpCase('an ordinary body', '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}');
await httpCase('a body that is not JSON', '{"jsonrpc":');
await httpCase('an empty body', '');
await httpCase('a large integer id', '{"id":12345678901234567890,"method":"eth_chainId"}');
await httpCase('ids as JavaScript numbers', '[{"id":1e21,"method":"eth_chainId"},{"id":-0,"method":"eth_chainId"},{"id":1.0,"method":"eth_chainId"},{"id":1e-7,"method":"eth_chainId"},{"id":0.1,"method":"eth_chainId"},{"id":123.456e5,"method":"eth_chainId"}]');
await httpCase('object keys in JavaScript order', '{"id":{"b":1,"2":2,"1":3,"01":4,"a":5,"4294967295":6,"4294967294":7},"method":"eth_chainId"}');
await httpCase('a duplicate key keeps its first place', '{"method":"nope","id":1,"method":"eth_chainId"}');
await httpCase('escapes', '{"id":"tab\\t nl\\n quote\\" bs\\\\ nul\\u0000 del\\u007f e\\u00e9 ls\\u2028","method":"eth_chainId"}');
await httpCase('an unsupported method named with escapes', '{"id":1,"method":"x\\u0001y"}');
await httpCase('whitespace around the body', ' \n\t{"id":1,"method":"eth_chainId"}\r\n ');

// last: ethereumjs throws out of runCall here and leaves a checkpoint open, so nothing may follow it
await refused('eth_call to the KZG precompile, which ethereumjs lacks', 'eth_call', [{ to: '0x000000000000000000000000000000000000000a', data: '0x' + '00'.repeat(192) }]);

fs.mkdirSync(out, { recursive: true });
const meta = { reference: `sidestr/spec fa86dac83d47b8f70195132e91e9dc083e1d9228 siding/lib/evmrpc.mjs (sha256 ${PINNED['lib/evmrpc.mjs']}) over siding/lib/overlays/evm.mjs (sha256 ${PINNED['lib/overlays/evm.mjs']})`, ethereumjs: '10.1.3', node: process.version };
fs.writeFileSync(path.join(out, 'rpc.json'), JSON.stringify({ ...meta, chain, genesis: { hash: s.node.chain[0], time: GENESIS_TIME }, now: NOW, steps }, null, 1) + '\n');
const count = (k) => steps.filter((x) => x[k]).length;
console.error(`${count('rpc')} requests, ${count('http')} bodies, ${count('block')} blocks, ${count('submit')} submissions`);
