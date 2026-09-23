// The reference engine (siding, Melvin Carvalho, AGPL-3.0) driven as the
// oracle for the wallet: `setup` opens a chain directory, seals its genesis
// from the document and produces N blocks so the genesis pegs mature;
// `submit` replays that directory and hands a transaction hex to
// `Siding.submit()` — the same mempool policy and signature check a
// producer applies to a `POST /tx` — then seals a block holding it.
//   SIDESTR_SIDING=<siding dir> SCHEMA=<schema-kernel> BLAKETESTNODE=<blaketestnode> \
//     node xcheck-wallet.mjs setup  <chain.json> <dir> <key file> <blocks>
//     node xcheck-wallet.mjs submit <chain.json> <dir> <key file> <tx hex>
//     node xcheck-wallet.mjs txsign <chain.json> <tx hex> <prevouts json> <key hex>
// `txsign` (SPEC 3, 0.0.3; lib/txsign.mjs): judges a transaction signed by the Rust wallet under
// the chain's own family rule and the other family's, and signs the same unsigned transaction
// with the reference's keyPathSighash and zero auxiliary randomness, so the witnesses compare
// byte for byte; and once more with siding's own signKeyPath (fresh randomness) for Rust to verify.
import { readFile, mkdir } from 'node:fs/promises';
const siding = process.env.SIDESTR_SIDING;
const { loadEngine } = await import(`${siding}/lib/engine.mjs`);
const { makeSigner, loadKey } = await import(`${siding}/lib/sign.mjs`);
const { Siding } = await import(`${siding}/lib/chain.mjs`);
const [cmd, chainFile, dir, keyFile, arg] = process.argv.slice(2);
const chain = JSON.parse(await readFile(chainFile, 'utf8'));
const engine = await loadEngine(chain); const signer = makeSigner(engine);
if (cmd === 'txsign') {
  const { keyPathSighash, signKeyPath, verifyKeyPath, usesUnifiedSighash } = await import(`${siding}/lib/txsign.mjs`);
  const [hex, prevoutsJson, keyHex] = [dir, keyFile, arg]; const prevouts = JSON.parse(prevoutsJson);
  const { k, hash, secp } = engine; const tx = k.codec.decode('Transaction', hex); const pub = signer.pubkeyOf(keyHex);
  const unified = usesUnifiedSighash(k);
  const own = tx.inputs.every((_, i) => k.interpreter.verifyInput(tx, i, prevouts[i], prevouts, null, { unifiedSighash: unified }).ok === true);
  const other = tx.inputs.every((_, i) => k.interpreter.verifyInput(tx, i, prevouts[i], prevouts, null, { unifiedSighash: !unified }).ok === true);
  const bare = { ...tx, witness: [] };
  const zero = new Uint8Array(32);
  const resigned = { ...bare, witness: tx.inputs.map((_, i) => { const { m, ht } = keyPathSighash({ k, hash }, bare, i, prevouts); return [hash.bytesToHex(signer.schnorrSign(m, keyHex, zero)) + ht.toString(16).padStart(2, '0')]; }) };
  const fresh = signKeyPath({ k, hash, signer }, { ...bare, witness: [] }, prevouts, keyHex);
  console.log(JSON.stringify({ unified, hashTypes: tx.witness.map((w) => w[0].slice(128)), verifyKeyPath: verifyKeyPath({ k, hash, secp }, tx, prevouts, pub), ownRule: own, otherRule: other,
    resigned: k.codec.encodeHex('Transaction', resigned), fresh: k.codec.encodeHex('Transaction', fresh), txid: k.codec.txid(tx) }));
  process.exit(0);
}
await mkdir(dir, { recursive: true });
const key = await loadKey(keyFile, { signer });
const s = await new Siding({ engine, chain, dir, signer }).open(key);
if (cmd === 'setup') {
  let last = null; for (let i = 0; i < Number(arg); i++) last = await s.produce(key);
  console.log(JSON.stringify({ genesisHash: s.genesisHash, height: s.height(), tip: s.tip().hash, coins: s.utxo.size, last: last?.hash ?? null }));
} else if (cmd === 'submit') {
  try {
    const r = await s.submit(arg);
    const b = await s.produce(key);
    console.log(JSON.stringify({ ok: true, txid: r.txid, fee: r.fee, vsize: r.vsize, dup: !!r.dup, height: b.height, txs: b.txs, coins: s.utxo.size }));
  } catch (e) { console.log(JSON.stringify({ ok: false, error: e.message })); }
} else { console.error('setup|submit'); process.exit(2); }
