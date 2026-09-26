// The fixture generator for sidestr-evm: the `evm` rule of siding (sidestr/spec at fa86dac,
// siding/lib/overlays/evm.mjs, AGPL-3.0, Melvin Carvalho) run on ethereumjs 10.1.3 over a scripted
// chain, every verdict and state root written as JSON for the Rust port to reproduce byte for byte.
//
// Two engines run side by side:
//   - `Driver` below drives ethereumjs exactly as evm.mjs's applyTx and prepare do (createCustomCommon
//     with the chain id over Mainnet at Cancun, createVM, deposits through putAccount, runTx with
//     skipBlockGasLimitValidation, the WITHDRAW account zeroed after a withdrawal, a checkpoint per
//     block reverted on failure);
//   - when `evm.reference.mjs` sits beside this file (a copy of the pinned evm.mjs, checked by its
//     SHA-256), the reference module itself runs every block too, and the generator stops on the first
//     verdict, root, withdrawal list or receipt on which the two differ.
// The fixtures record the reference's verdicts.
//
//   mkdir -p $SCRATCH && cp sidestr-evm/tests/oracle/{oracle.mjs,package.json,package-lock.json} $SCRATCH
//   cp $SIDESTR_SIDING/lib/overlays/evm.mjs $SCRATCH/evm.reference.mjs
//   cd $SCRATCH && npm ci && node oracle.mjs $REPO/sidestr-evm/tests/fixtures
import fs from 'node:fs'; import path from 'node:path'; import crypto from 'node:crypto';
import * as vmm from '@ethereumjs/vm'; import * as T from '@ethereumjs/tx'; import * as blk from '@ethereumjs/block';
import * as com from '@ethereumjs/common'; import * as util from '@ethereumjs/util'; import { RLP } from '@ethereumjs/rlp';

const REFERENCE_SHA256 = '8903eab6c67244ded02edf8122112efb015ee1e3e5d4ca913372e542cc1820cc'; // siding/lib/overlays/evm.mjs at fa86dac
const out = process.argv[2]; if (!out) { console.error('usage: node oracle.mjs <fixtures dir>'); process.exit(2); }
const here = path.dirname(new URL(import.meta.url).pathname);
let Ref = null; const refPath = path.join(here, 'evm.reference.mjs');
if (fs.existsSync(refPath)) {
  const sum = crypto.createHash('sha256').update(fs.readFileSync(refPath)).digest('hex');
  if (sum !== REFERENCE_SHA256) { console.error(`evm.reference.mjs is not the pinned evm.mjs (sha256 ${sum})`); process.exit(2); }
  Ref = await import(refPath);
}
console.error(Ref ? 'cross-checking against the reference evm.mjs' : 'no evm.reference.mjs: the driver alone');

// ---- the record codecs, as evm.mjs writes them ---------------------------------------------------
export const WITHDRAW = '0x00000000000000000000000000000000000501de';
export const GWEI = 1000000000n;
const enc = new TextEncoder();
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (h) => Uint8Array.from((h.startsWith('0x') ? h.slice(2) : h).match(/../g) ?? [], (x) => parseInt(x, 16));
const pushData = (bytes) => { const n = bytes.length; const op = n <= 75 ? [n] : n <= 255 ? [0x4c, n] : [0x4d, n & 255, n >> 8]; return '6a' + hex(Uint8Array.from(op)) + hex(bytes); };
const opReturnBytes = (spk) => { const m = /^6a(?:4c([0-9a-f]{2})|4d([0-9a-f]{4})|([0-9a-f]{2}))([0-9a-f]*)$/i.exec(spk); if (!m) return null; const n = m[1] ? parseInt(m[1], 16) : m[2] ? parseInt(m[2].slice(2) + m[2].slice(0, 2), 16) : parseInt(m[3], 16); const b = unhex(m[4]); return b.length === n ? b : null; };
const withPrefix = (b, p) => { const h = enc.encode(p); if (!b || b.length <= h.length) return null; for (let i = 0; i < h.length; i++) if (b[i] !== h[i]) return null; return b.subarray(h.length); };
const carrierScript = (rlp) => pushData(new Uint8Array([...enc.encode('evm:'), ...rlp]));
const depositScript = (address) => pushData(new Uint8Array([...enc.encode('evmin:'), ...unhex(address)]));
const rootScript = (root) => pushData(new Uint8Array([...enc.encode('evmroot:'), ...unhex(root)]));
const parseCarrier = (spk) => withPrefix(opReturnBytes(spk), 'evm:');
const parseDeposit = (spk) => { const b = withPrefix(opReturnBytes(spk), 'evmin:'); return b && b.length === 20 ? '0x' + hex(b) : null; };
const parseRoot = (spk) => { const b = withPrefix(opReturnBytes(spk), 'evmroot:'); return b && b.length === 32 ? '0x' + hex(b) : null; };
const sameCodecs = (a, b, what) => { if (Ref && a !== b) throw new Error(`${what}: the driver writes ${a}, the reference ${b}`); return a; };

// ---- the driver: evm.mjs's applyTx and prepare, on ethereumjs directly ---------------------------
class Driver {
  constructor(chain) { const cfg = chain.evm ?? {}; this.chainId = Number(cfg.chainId ?? 21474); this.gasLimit = BigInt(cfg.gasLimit ?? 30000000); this.reserve = (cfg.reserve ?? chain.challenge).toLowerCase(); this.chain = chain; this.roots = new Map(); this.receipts = new Map(); }
  async init() {
    this.common = com.createCustomCommon({ chainId: this.chainId, name: this.chain.id }, com.Mainnet, { hardfork: com.Hardfork.Cancun });
    this.vm = await vmm.createVM({ common: this.common });
    this.roots.set(-1, hex(await this.vm.stateManager.getStateRoot())); this.roots.set(0, this.roots.get(-1)); return this;
  }
  async rootHex() { return '0x' + hex(await this.vm.stateManager.getStateRoot()); }
  async applyTx(tx, txid, { height, time }) {
    const { vm, common } = this; const res = { ok: true, hashes: [], withdrawals: [] };
    const block = blk.createBlock({ header: { number: BigInt(height), timestamp: BigInt(time), gasLimit: this.gasLimit, coinbase: util.createZeroAddress(), baseFeePerGas: GWEI } }, { common });
    for (let i = 0; i < tx.outputs.length; i++) {
      const o = tx.outputs[i]; const dep = parseDeposit(o.scriptPubKey);
      if (dep) { const prev = tx.outputs[i - 1]; if (!prev || prev.scriptPubKey.toLowerCase() !== this.reserve || !(prev.value >= 1)) return { ...res, ok: false, error: `evmin at output ${i} has no reserve payment before it` };
        const addr = util.createAddressFromString(dep); const acct = (await vm.stateManager.getAccount(addr)) ?? new util.Account(); acct.balance += BigInt(prev.value) * GWEI; await vm.stateManager.putAccount(addr, acct); continue; }
      const rlp = parseCarrier(o.scriptPubKey); if (!rlp) continue;
      let etx; try { etx = T.createTxFromRLP(rlp, { common }); } catch (e) { return { ...res, ok: false, error: `carrier at output ${i}: not an Ethereum transaction (${e.message.slice(0, 60)})` }; }
      if (!etx.isSigned() || !etx.verifySignature()) return { ...res, ok: false, error: `carrier at output ${i}: unsigned or bad signature` };
      let r; try { r = await vmm.runTx(vm, { tx: etx, block, skipBlockGasLimitValidation: true }); } catch (e) { return { ...res, ok: false, error: `carrier at output ${i}: ${e.message.slice(0, 120)}` }; }
      const h = '0x' + hex(etx.hash()); res.hashes.push(h);
      this.receipts.set(h, { hash: h, status: r.receipt.status !== undefined ? Number(r.receipt.status) : 1, gasUsed: r.totalGasSpent.toString(), contractAddress: r.createdAddress ? r.createdAddress.toString() : null, logs: (r.execResult.logs ?? []).length, sidechainTxid: txid, from: etx.getSenderAddress().toString() });
      if (etx.to && etx.to.toString().toLowerCase() === WITHDRAW && etx.value > 0n && etx.data.length === 34 && (r.receipt.status === undefined || Number(r.receipt.status) === 1)) {
        const script = hex(etx.data); const sats = Number(etx.value / GWEI); const w = util.createAddressFromString(WITHDRAW); const acct = await vm.stateManager.getAccount(w); if (acct) { acct.balance = 0n; await vm.stateManager.putAccount(w, acct); }
        if (sats >= 1) res.withdrawals.push({ script, sats, hash: h });
      }
    }
    return res;
  }
  async prepare(block, height) {
    const { vm } = this; const prevRoot = this.roots.get(height - 1); if (prevRoot === undefined) return { ok: false, error: `no state for height ${height - 1}` };
    await vm.stateManager.setStateRoot(unhex(prevRoot)); await vm.stateManager.checkpoint();
    const hashes = [], withdrawals = []; let error = null;
    for (let i = 1; i < block.transactions.length && !error; i++) { const tx = block.transactions[i]; const r = await this.applyTx(tx, tx.txid, { height, time: block.header.time }); if (!r.ok) error = `tx ${i}: ${r.error}`; else { hashes.push(...r.hashes); withdrawals.push(...r.withdrawals); } }
    const root = await this.rootHex(); const cb = block.transactions[0]; const committed = cb.outputs.map((o) => parseRoot(o.scriptPubKey)).find(Boolean) ?? null;
    if (!error && committed !== root) error = `coinbase commits ${committed ? committed.slice(0, 14) : 'no'} state root, the block's execution gives ${root.slice(0, 14)}`;
    if (!error) for (const w of withdrawals) { if (!cb.outputs.some((o) => o.scriptPubKey === w.script && o.value === w.sats)) { error = `withdrawal of ${w.sats} sats to ${w.script.slice(0, 12)}… is not paid by the coinbase`; break; } }
    if (error) { await vm.stateManager.revert(); for (const h of hashes) this.receipts.delete(h); return { ok: false, error, root, withdrawals }; }
    await vm.stateManager.commit(); this.roots.set(height, root.slice(2)); return { ok: true, root, withdrawals, hashes };
  }
  // the producer's sequencing (chain.mjs sequencedEvm: begin, checkTx with keep, end): the root and the
  // withdrawals a block of these transactions leaves, the state reverted after
  async sequence(txs, height, time) {
    const { vm } = this; await vm.stateManager.setStateRoot(unhex(this.roots.get(height - 1))); await vm.stateManager.checkpoint();
    const withdrawals = [], hashes = [];
    for (const tx of txs) { const r = await this.applyTx(tx, tx.txid, { height, time }); if (!r.ok) throw new Error(`sequencing: ${r.error}`); withdrawals.push(...r.withdrawals); hashes.push(...r.hashes); }
    const root = await this.rootHex(); await vm.stateManager.revert(); for (const h of hashes) this.receipts.delete(h); return { root, withdrawals };
  }
}

// ---- the chain -------------------------------------------------------------------------------
const RESERVE = '5120' + 'aa'.repeat(32);
const chain = { id: 'sidestr:evmoracle', challenge: RESERVE, rules: ['evm'], evm: { chainId: 21474, gasLimit: 30000000 } };
const driver = await new Driver(chain).init(); const common = driver.common;
let ref = null; if (Ref) { ref = Ref.evmOverlay(chain); await ref.init(); ref.roots.set(0, ref.roots.get(-1)); ref.blocks.set(0, { hashes: [], root: '0x' + ref.roots.get(-1) }); }
const codec = { blockHash: (h) => h.hash, txid: (tx) => tx.txid };
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const key = (b) => util.hexToBytes('0x' + b.repeat(32));
const alicePriv = key('42'), bobPriv = key('45'), carolPriv = key('43'), davePriv = key('46');
const addr = (p) => util.createAddressFromPrivateKey(p).toString();
const alice = addr(alicePriv), bob = addr(bobPriv), carol = addr(carolPriv), dave = addr(davePriv);
const TARGET1 = '5120' + 'bb'.repeat(32), TARGET2 = '5120' + 'cc'.repeat(32), TARGET3 = '5120' + 'dd'.repeat(32);
const out_ = (value, script) => ({ value, scriptPubKey: script });
const deposit = (value, to) => [out_(value, RESERVE), out_(0, sameCodecs(depositScript(to), Ref?.depositScript(to) ?? depositScript(to), 'depositScript'))];
const carry = (etx) => { const b = etx.serialize(); return out_(0, sameCodecs(carrierScript(b), Ref?.carrierScript(b) ?? carrierScript(b), 'carrierScript')); };
const legacy = (priv, f) => T.createLegacyTx({ gasPrice: GWEI, gasLimit: 21000, ...f }, { common }).sign(priv);
const eip1559 = (priv, f) => T.createFeeMarket1559Tx({ chainId: 21474n, maxFeePerGas: 3n * GWEI, maxPriorityFeePerGas: 0n, gasLimit: 21000, ...f }, { common }).sign(priv);
const eip2930 = (priv, f) => T.createAccessList2930Tx({ chainId: 21474n, gasPrice: 2n * GWEI, gasLimit: 60000, ...f }, { common }).sign(priv);
const nonces = new Map(); const nonce = (a) => { const n = nonces.get(a) ?? 0; nonces.set(a, n + 1); return n; };
const created = (from, n) => util.createContractAddress(util.createAddressFromString(from), BigInt(n)).toString();

// contracts: the evm-test.mjs one (returns 42), a store (slot 0 = calldata word, slot 1 counts calls, LOG0 of the word),
// one that reverts, and one that writes the block environment into its storage
const RUNTIME_42 = '602a60005260206000f3', INIT_42 = '69' + RUNTIME_42 + '600052600a6016f3';
const deployer = (runtime) => { const n = runtime.length / 2; return '60' + n.toString(16).padStart(2, '0') + '80600b6000396000f3' + runtime; };
const RUNTIME_STORE = '600035600055' + '600154600101600155' + '600035600052' + '60206000a0' + '00';
const RUNTIME_REVERT = '60006000fd';
const RUNTIME_ENV = '43600055' + '42600155' + '48600255' + '46600355' + '45600455' + '44600555' + '4a600655' + '6001430340600755' + '4131600855' + '00';
const RUNTIME_KZG = '600060006000600060006000600a5af1' + '600055' + '00'; // CALL(gas, 0x0a, 0, 0, 0, 0, 0), result into slot 0
const word = (n) => n.toString(16).padStart(64, '0');

const blocks = []; const dumped = [];
let height = 0, time = 1790000000;
async function submitBlock(label, txs, { coinbase = null, rootOverride, omitRoot = false, skipPayments = false, payExtra = [], expectOk = true, time: t, advance = true } = {}) {
  const h = height + 1; const bt = t ?? time + 10; const txObjs = txs.map((outputs, i) => ({ txid: sha(`${label} tx ${i}`), outputs }));
  let seq = { root: '0x' + '00'.repeat(32), withdrawals: [] };
  try { seq = await driver.sequence(txObjs, h, bt); } catch { if (expectOk) throw new Error(`${label}: sequencing failed on a block meant to pass`); }
  const cbOuts = coinbase ?? [
    ...(skipPayments ? [] : seq.withdrawals.map((w) => out_(w.sats, w.script))), ...payExtra,
    ...(omitRoot ? [] : [out_(0, sameCodecs(rootScript(rootOverride ?? seq.root), Ref?.rootScript(rootOverride ?? seq.root) ?? rootScript(rootOverride ?? seq.root), 'rootScript'))])];
  const block = { header: { hash: sha(`block ${label}`), time: bt }, transactions: [{ txid: sha(`${label} coinbase`), outputs: cbOuts }, ...txObjs] };
  const v = await driver.prepare(block, h);
  if (ref) {
    const r = await ref.prepare(block, h, codec); const norm = (x) => JSON.stringify({ ok: x.ok, root: x.root ?? null, withdrawals: x.withdrawals ?? [], hashes: x.hashes ?? [], error: x.error ?? null });
    if (norm(r) !== norm(v)) throw new Error(`${label}: the driver says ${norm(v)}, the reference ${norm(r)}`);
    for (const hsh of v.hashes ?? []) { const a = driver.receipts.get(hsh), b = ref.receipts.get(hsh); if (!b || a.status !== b.status || a.gasUsed !== b.gasUsed.toString() || a.contractAddress !== b.contractAddress || a.logs !== b.logs.length) throw new Error(`${label}: receipt ${hsh} differs`); }
    if (v.ok && (await ref.rootHex()) !== v.root) throw new Error(`${label}: the reference's state is not at the verdict's root`);
  }
  if (v.ok !== expectOk) throw new Error(`${label}: expected ${expectOk ? 'acceptance' : 'refusal'}, got ${JSON.stringify(v)}`);
  const receipts = (v.hashes ?? []).map((x) => driver.receipts.get(x)).map(({ sidechainTxid, from, ...r }) => ({ ...r, from }));
  blocks.push({ label, height: h, time: bt, hash: block.header.hash, coinbase: cbOuts.map((o) => ({ value: o.value, script: o.scriptPubKey })),
    txs: txObjs.map((tx) => ({ txid: tx.txid, outputs: tx.outputs.map((o) => ({ value: o.value, script: o.scriptPubKey })) })),
    verdict: { ok: v.ok, root: v.root ?? null, error: v.error ?? null, withdrawals: v.withdrawals ?? [], hashes: v.hashes ?? [] }, receipts });
  console.error(`${v.ok ? 'accepted' : 'refused '} h=${h} ${label}${v.ok ? ' ' + v.root : ': ' + v.error}`);
  if (v.ok && advance) { height = h; time = bt; }
  return v;
}
// a refused block leaves nothing behind in the driver's nonce bookkeeping either
const attempt = async (label, txs, opts = {}) => { const saved = new Map(nonces); const v = await submitBlock(label, txs, { ...opts, expectOk: false }); nonces.clear(); for (const [k, n] of saved) nonces.set(k, n); return v; };

// ---- the scripted chain ------------------------------------------------------------------------
await submitBlock('empty block 1', []);
await submitBlock('deposits', [[...deposit(100_000_000, alice), ...deposit(500_000, carol)], [...deposit(2_000_000, bob)], [out_(7, RESERVE), out_(0, depositScript(dave))]]);
await attempt('a deposit without the reserve payment before it', [[out_(0, depositScript(bob))]]);
await attempt('a deposit whose reserve payment carries nothing', [[out_(0, RESERVE), out_(0, depositScript(bob))]]);
await attempt('a deposit after a payment to another script', [[out_(5000, TARGET1), out_(0, depositScript(bob))]]);
await submitBlock('transfers: legacy, EIP-1559 with a tip to the zero-address coinbase, EIP-2930', [
  [carry(legacy(alicePriv, { nonce: nonce(alice), to: bob, value: 250_000n * GWEI }))],
  [carry(eip1559(carolPriv, { nonce: nonce(carol), to: bob, value: 1000n * GWEI, maxPriorityFeePerGas: 2n * GWEI }))],
  [carry(eip2930(alicePriv, { nonce: nonce(alice), to: carol, value: 5n * GWEI, accessList: [{ address: bob, storageKeys: ['0x' + word(1)] }] }))]]);
const deployNonce = nonce(alice); const c42 = created(alice, deployNonce);
const storeNonce = nonce(alice); const cStore = created(alice, storeNonce);
const revertNonce = nonce(alice); const cRevert = created(alice, revertNonce);
await submitBlock('three deployments, one of them long enough for OP_PUSHDATA2', [
  [carry(T.createLegacyTx({ nonce: deployNonce, gasPrice: GWEI, gasLimit: 100000, data: '0x' + INIT_42 }, { common }).sign(alicePriv))],
  [carry(T.createLegacyTx({ nonce: storeNonce, gasPrice: GWEI, gasLimit: 200000, data: '0x' + deployer(RUNTIME_STORE) + '00'.repeat(300) }, { common }).sign(alicePriv))],
  [carry(eip1559(alicePriv, { nonce: revertNonce, gasLimit: 100000, data: '0x' + deployer(RUNTIME_REVERT) }))]]);
await submitBlock('storage: two writes, a revert that is still applied, a write of zero', [
  [carry(legacy(alicePriv, { nonce: nonce(alice), to: cStore, gasLimit: 100000, data: '0x' + word(42) }))],
  [carry(legacy(bobPriv, { nonce: nonce(bob), to: cStore, gasLimit: 100000, data: '0x' + word(0x1234) }))],
  [carry(eip1559(carolPriv, { nonce: nonce(carol), to: cRevert, gasLimit: 50000 }))],
  [carry(eip1559(bobPriv, { nonce: nonce(bob), to: cStore, gasLimit: 100000, data: '0x' + word(0), maxPriorityFeePerGas: GWEI }))]]);
const envNonce = nonce(bob); const cEnv = created(bob, envNonce);
await submitBlock('a contract that stores the block environment, deployed', [[carry(legacy(bobPriv, { nonce: envNonce, gasLimit: 200000, data: '0x' + deployer(RUNTIME_ENV) }))]], { time: time + 600 });
await submitBlock('the block environment read at a later height and time', [[carry(eip1559(bobPriv, { nonce: nonce(bob), to: cEnv, gasLimit: 200000, maxPriorityFeePerGas: 3n * GWEI, maxFeePerGas: 5n * GWEI }))]], { time: time + 3600 });
await submitBlock('withdrawals: one of 100,000 sats, one of 1.5 gwei paid as 1 sat', [
  [carry(legacy(alicePriv, { nonce: nonce(alice), to: WITHDRAW, gasLimit: 30000, value: 100_000n * GWEI, data: '0x' + TARGET1 }))],
  [carry(eip1559(carolPriv, { nonce: nonce(carol), to: WITHDRAW, gasLimit: 30000, value: 1_500_000_000n, data: '0x' + TARGET2 }))]]);
await submitBlock('a zero-value call touches the emptied WITHDRAW account', [[carry(legacy(bobPriv, { nonce: nonce(bob), to: WITHDRAW, gasLimit: 30000 }))]]);
await submitBlock('a withdrawal under a gwei: burned, nothing to pay', [[carry(legacy(bobPriv, { nonce: nonce(bob), to: WITHDRAW, gasLimit: 30000, value: 999_999_999n, data: '0x' + TARGET3 }))]]);
await submitBlock('value to WITHDRAW without a script is kept there, then burned by the next withdrawal', [
  [carry(legacy(bobPriv, { nonce: nonce(bob), to: WITHDRAW, gasLimit: 30000, value: 3n * GWEI }))]]);
await submitBlock('the next withdrawal burns all of it', [[carry(legacy(bobPriv, { nonce: nonce(bob), to: WITHDRAW, gasLimit: 30000, value: 2n * GWEI, data: '0x' + TARGET3 }))]]);
{ const n = nonce(alice); const wd = legacy(alicePriv, { nonce: n, to: WITHDRAW, gasLimit: 30000, value: 7_000n * GWEI, data: '0x' + TARGET1 });
  await attempt('a withdrawal the coinbase does not pay', [[carry(wd)]], { skipPayments: true });
  await attempt('a withdrawal paid one sat short', [[carry(wd)]], { skipPayments: true, payExtra: [out_(6_999, TARGET1)] });
  nonces.set(alice, n); }
await attempt('a block committing a wrong state root', [], { rootOverride: '0x' + '11'.repeat(32) });
await attempt('a block committing no state root', [], { omitRoot: true });
await attempt('a carrier with the wrong nonce', [[carry(legacy(alicePriv, { nonce: 0, to: bob, value: 1n }))]]);
await attempt('a carrier spending more than the sender holds', [[carry(legacy(davePriv, { nonce: 0, to: bob, value: 1n }))]]);
await attempt('a carrier that is not an Ethereum transaction', [[out_(0, carrierScript(Uint8Array.from([1, 2, 3, 4])))]]);
{ const good = legacy(alicePriv, { nonce: nonces.get(alice), to: bob, value: 1n }); const bytes = good.serialize(); bytes[bytes.length - 1] ^= 1;
  await attempt('a carrier whose signature was altered', [[out_(0, carrierScript(bytes))]]); }
await attempt('a carrier calling the KZG point-evaluation precompile (ethereumjs has no KZG)', [
  [carry(legacy(alicePriv, { nonce: nonces.get(alice), to: '0x000000000000000000000000000000000000000a', gasLimit: 100000, data: '0x' + '00'.repeat(192) }))]]);
await submitBlock('after the KZG refusal the chain goes on', [[carry(legacy(alicePriv, { nonce: nonce(alice), to: bob, value: 1n }))]]);
await attempt('a carrier after a good one, with a bad nonce: the whole block is refused', [
  [carry(legacy(alicePriv, { nonce: nonces.get(alice), to: bob, value: 1n })), carry(legacy(alicePriv, { nonce: nonces.get(alice) + 5, to: bob, value: 1n }))]]);
{ const kzgNonce = nonce(alice); const cKzg = created(alice, kzgNonce);
  await submitBlock('a contract that would call the KZG precompile, deployed', [[carry(legacy(alicePriv, { nonce: kzgNonce, gasLimit: 200000, data: '0x' + deployer(RUNTIME_KZG) }))]]);
  await attempt('an inner CALL reaching the KZG precompile', [[carry(legacy(alicePriv, { nonce: nonces.get(alice), to: cKzg, gasLimit: 200000 }))]]);
  await submitBlock('an inner CALL too poor to reach the precompile is an ordinary out-of-gas', [[carry(legacy(alicePriv, { nonce: nonce(alice), to: cKzg, gasLimit: 21_000 + 30 }))]]); }
await submitBlock('a pre-EIP-155 legacy transaction (v = 27/28) is carried', [[carry(T.createLegacyTx({ nonce: nonce(carol), gasPrice: GWEI, gasLimit: 21000, to: bob, value: 3n }, { common: com.createCustomCommon({ chainId: 21474 }, com.Mainnet, { hardfork: com.Hardfork.TangerineWhistle }) }).sign(carolPriv))]]);
await submitBlock('a gas limit above the block gas limit (validation skipped)', [[carry(legacy(alicePriv, { nonce: nonce(alice), to: bob, value: 1n, gasLimit: 40_000_000 }))]]);
await submitBlock('a deposit and a carrier in one transaction: the deposit first, in output order', [[...deposit(100_000, dave), carry(legacy(davePriv, { nonce: nonce(dave), to: carol, value: 9_000n * GWEI }))]]);
await attempt('a carrier before the deposit that funds it', [[carry(legacy(davePriv, { nonce: nonces.get(dave), to: carol, value: 900_000n * GWEI })), ...deposit(1_000_000, dave)]]);
await submitBlock('the coinbase carries a deposit and a carrier: ignored (transactions from index 1)', [], { coinbase: null, payExtra: [out_(5, RESERVE), out_(0, depositScript(dave)), carry(legacy(alicePriv, { nonce: 999, to: bob, value: 1n }))] });
await submitBlock('empty block', [], { time: time + 7 });

// ---- the final state, for debugging a mismatch --------------------------------------------------
for (const [name, a] of Object.entries({ alice, bob, carol, dave, zero: '0x' + '00'.repeat(20), withdraw: WITHDRAW, c42, cStore, cRevert, cEnv })) {
  const acct = await driver.vm.stateManager.getAccount(util.createAddressFromString(a));
  dumped.push({ name, address: a, exists: !!acct, nonce: acct ? acct.nonce.toString() : null, balance: acct ? acct.balance.toString() : null,
    codeHash: acct ? '0x' + hex(acct.codeHash) : null, storageRoot: acct ? '0x' + hex(acct.storageRoot) : null });
}

// ---- carrier decoding at the edges ---------------------------------------------------------------
const decode = [];
const decodeCase = (label, bytes) => {
  let ok = false, sender = null, hash = null, type = null, error = null;
  try { const etx = T.createTxFromRLP(bytes, { common }); type = etx.type; if (!etx.isSigned() || !etx.verifySignature()) error = 'unsigned or bad signature'; else { ok = true; sender = etx.getSenderAddress().toString(); hash = '0x' + hex(etx.hash()); } }
  catch (e) { error = e.message.slice(0, 100); }
  decode.push({ label, rlp: hex(bytes), ok, sender, hash, type, error });
};
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const pre155 = com.createCustomCommon({ chainId: 21474 }, com.Mainnet, { hardfork: com.Hardfork.TangerineWhistle });
const mainnet = new com.Common({ chain: com.Mainnet, hardfork: com.Hardfork.Cancun });
const prague = com.createCustomCommon({ chainId: 21474 }, com.Mainnet, { hardfork: com.Hardfork.Prague });
const base = legacy(alicePriv, { nonce: 3, to: bob, value: 5n });
decodeCase('legacy, EIP-155', base.serialize());
decodeCase('legacy, v = 27/28', T.createLegacyTx({ nonce: 3, gasPrice: GWEI, gasLimit: 21000, to: bob, value: 5n }, { common: pre155 }).sign(alicePriv).serialize());
decodeCase('legacy, EIP-155 for chain 1', T.createLegacyTx({ nonce: 3, gasPrice: GWEI, gasLimit: 21000, to: bob, value: 5n }, { common: mainnet }).sign(alicePriv).serialize());
decodeCase('legacy, contract creation', T.createLegacyTx({ nonce: 3, gasPrice: GWEI, gasLimit: 100000, data: '0x' + INIT_42 }, { common }).sign(alicePriv).serialize());
decodeCase('EIP-2930 with an access list', eip2930(alicePriv, { nonce: 1, to: bob, accessList: [{ address: carol, storageKeys: ['0x' + word(7), '0x' + word(8)] }] }).serialize());
decodeCase('EIP-1559', eip1559(alicePriv, { nonce: 1, to: bob, value: 9n }).serialize());
decodeCase('EIP-1559, contract creation', eip1559(alicePriv, { nonce: 1, gasLimit: 100000, data: '0x' + INIT_42 }).serialize());
decodeCase('EIP-1559 for chain 1', T.createFeeMarket1559Tx({ chainId: 1n, maxFeePerGas: 3n * GWEI, maxPriorityFeePerGas: 0n, gasLimit: 21000, to: bob, nonce: 1 }, { common: mainnet }).sign(alicePriv).serialize());
decodeCase('EIP-2930 for chain 1', T.createAccessList2930Tx({ chainId: 1n, gasPrice: GWEI, gasLimit: 21000, to: bob, nonce: 1 }, { common: mainnet }).sign(alicePriv).serialize());
decodeCase('legacy with a high s', T.createLegacyTx({ nonce: 3, gasPrice: GWEI, gasLimit: 21000, to: bob, value: 5n, v: base.v === 21474n * 2n + 35n ? base.v + 1n : base.v - 1n, r: base.r, s: N - base.s }, { common }).serialize());
{ const t = eip1559(alicePriv, { nonce: 1, to: bob, value: 9n }); const raw = t.raw(); raw[raw.length - 3] = util.bigIntToUnpaddedBytes(t.v ^ 1n); raw[raw.length - 1] = util.bigIntToUnpaddedBytes(N - t.s);
  decodeCase('EIP-1559 with a high s', Uint8Array.from([2, ...RLP.encode(raw)])); } // the typed constructors refuse a high s themselves: built by hand
decodeCase('legacy with trailing bytes', Uint8Array.from([...base.serialize(), 0]));
decodeCase('EIP-1559 with trailing bytes', Uint8Array.from([...eip1559(alicePriv, { nonce: 1, to: bob }).serialize(), 0]));
decodeCase('legacy with r = 0', T.createLegacyTx({ nonce: 3, gasPrice: GWEI, gasLimit: 21000, to: bob, value: 5n, v: base.v, r: 0n, s: base.s }, { common }).serialize());
decodeCase('legacy, unsigned (six fields)', RLP.encode(base.raw().slice(0, 6)));
decodeCase('legacy, v r s empty', T.createLegacyTx({ nonce: 3, gasPrice: GWEI, gasLimit: 21000, to: bob, value: 5n }, { common }).serialize());
{ const raw = base.raw(); raw[0] = Uint8Array.from([0, 3]); decodeCase('legacy with a leading zero in the nonce', RLP.encode(raw)); }
{ const raw = base.raw(); raw[3] = raw[3].subarray(1); decodeCase('legacy with a 19-byte to', RLP.encode(raw)); }
{ const raw = base.raw(); raw[6] = util.bigIntToUnpaddedBytes(29n); decodeCase('legacy with v = 29', RLP.encode(raw)); }
decodeCase('legacy with a list for data', RLP.encode([...base.raw().slice(0, 5), [Uint8Array.from([1])], ...base.raw().slice(6)]));
decodeCase('an unknown type byte', Uint8Array.from([0x05, ...RLP.encode([])]));
decodeCase('a bare RLP string', RLP.encode(Uint8Array.from([1, 2, 3])));
decodeCase('garbage', Uint8Array.from([1, 2, 3, 4]));
{ // a blob transaction needs KZG in the common even to be read (4844/tx.js), so it is refused before its
  // signature is looked at: built by hand, with a placeholder signature
  const fields = [util.bigIntToUnpaddedBytes(21474n), Uint8Array.from([1]), new Uint8Array(), util.bigIntToUnpaddedBytes(3n * GWEI), util.bigIntToUnpaddedBytes(50000n), util.hexToBytes(bob), new Uint8Array(), new Uint8Array(), [], util.bigIntToUnpaddedBytes(10n), [util.hexToBytes('0x01' + '00'.repeat(31))]];
  decodeCase('EIP-4844 blob transaction', Uint8Array.from([3, ...RLP.encode([...fields, Uint8Array.from([1]), Uint8Array.from([1]), Uint8Array.from([1])])])); }
decodeCase('EIP-7702 (Prague) transaction', T.createEOACode7702Tx({ chainId: 21474n, nonce: 1, maxFeePerGas: 3n * GWEI, maxPriorityFeePerGas: 0n, gasLimit: 60000, to: bob, authorizationList: [{ chainId: '0x53e2', address: carol, nonce: '0x0', yParity: '0x0', r: '0x01', s: '0x01' }] }, { common: prague }).sign(alicePriv).serialize());

// ---- the record codecs at the edges ---------------------------------------------------------------
const records = [];
const rec = (label, script) => records.push({ label, script, carrier: parseCarrier(script) ? hex(parseCarrier(script)) : null, deposit: parseDeposit(script), root: parseRoot(script) });
rec('carrier, direct push', carrierScript(Uint8Array.from([0xc0, 1, 2])));
rec('carrier, OP_PUSHDATA1', carrierScript(new Uint8Array(100).fill(7)));
rec('carrier, OP_PUSHDATA2', carrierScript(new Uint8Array(400).fill(9)));
rec('carrier, empty payload', pushData(enc.encode('evm:')));
rec('carrier, push length one short', '6a05' + hex(enc.encode('evm:')));
rec('carrier, OP_PUSHDATA1 used for a short push', '6a4c05' + hex(enc.encode('evm:x')));
rec('carrier, upper-case hex', carrierScript(Uint8Array.from([0xab, 0xcd])).toUpperCase());
rec('deposit', depositScript(alice));
rec('deposit, 19 bytes', pushData(new Uint8Array([...enc.encode('evmin:'), ...new Uint8Array(19).fill(1)])));
rec('deposit, 21 bytes', pushData(new Uint8Array([...enc.encode('evmin:'), ...new Uint8Array(21).fill(1)])));
rec('root', rootScript('0x' + '5a'.repeat(32)));
rec('root, 31 bytes', pushData(new Uint8Array([...enc.encode('evmroot:'), ...new Uint8Array(31).fill(1)])));
rec('not OP_RETURN', '51' + carrierScript(Uint8Array.from([1])).slice(2));
rec('OP_RETURN with a second push', carrierScript(Uint8Array.from([1])) + '01ff');
rec('OP_PUSHDATA4', '6a4e05000000' + hex(enc.encode('evm:x')));
rec('evmroot: read as a carrier prefix', rootScript('0x' + '00'.repeat(32)));

fs.mkdirSync(out, { recursive: true });
const meta = { reference: 'sidestr/spec fa86dac83d47b8f70195132e91e9dc083e1d9228 siding/lib/overlays/evm.mjs (sha256 ' + REFERENCE_SHA256 + ')', ethereumjs: '10.1.3', crossChecked: !!Ref };
fs.writeFileSync(path.join(out, 'chain.json'), JSON.stringify({ ...meta, chain, emptyRoot: '0x' + driver.roots.get(-1), accounts: { alice, bob, carol, dave }, blocks, final: dumped }, null, 1) + '\n');
fs.writeFileSync(path.join(out, 'decode.json'), JSON.stringify({ ...meta, chainId: 21474, cases: decode }, null, 1) + '\n');
fs.writeFileSync(path.join(out, 'records.json'), JSON.stringify({ ...meta, cases: records }, null, 1) + '\n');
console.error(`${blocks.length} blocks (${blocks.filter((b) => b.verdict.ok).length} accepted), ${decode.length} decode cases, ${records.length} record cases`);
