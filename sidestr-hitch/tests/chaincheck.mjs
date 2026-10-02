// The reference engine (siding, Melvin Carvalho, AGPL-3.0) as the second
// judge of a chain whose transactions are Hitch channel spends
// (tests/chain_consensus.rs). Three commands:
//
//   replay  <chain.json> <dir>                 open the directory, validate every block, report the tip
//   judge   <chain.json> <dir> <cases.json>    offer each block [{name, hex}] to a fresh copy of the
//                                              chain at its tip; report each verdict, keep none
//   mempool <chain.json> <dir> <key> <tx hex>  on a copy: Siding.submit the transaction, then produce
//                                              once; report both outcomes (the BIP 68 admission probe)
//
//   SIDESTR_SIDING=<siding dir> SCHEMA=<schema-kernel> BLAKETESTNODE=<blaketestnode> node chaincheck.mjs …
import { readFile, rm, cp } from 'node:fs/promises';
const siding = process.env.SIDESTR_SIDING;
const { loadEngine } = await import(`${siding}/lib/engine.mjs`);
const { makeSigner, loadKey } = await import(`${siding}/lib/sign.mjs`);
const { Siding } = await import(`${siding}/lib/chain.mjs`);
const [cmd, chainFile, dir, extra, extra2] = process.argv.slice(2);
const chain = JSON.parse(await readFile(chainFile, 'utf8'));
const open = async (at, key = null) => {
  const engine = await loadEngine(chain);
  return new Siding({ engine, chain, dir: at, signer: makeSigner(engine), log: () => {} }).open(key);
};
const copyOf = async (name) => {
  const at = `${dir}-${name}`;
  await rm(at, { recursive: true, force: true });
  await cp(dir, at, { recursive: true });
  return at;
};
const message = (e) => String(e?.message ?? e);

if (cmd === 'replay') {
  const s = await open(dir);
  console.log(JSON.stringify({ height: s.height(), tip: s.tip().hash, coins: s.utxo.size }));
} else if (cmd === 'judge') {
  const cases = JSON.parse(await readFile(extra, 'utf8'));
  const out = [];
  for (const x of cases) {
    const at = await copyOf(x.name);
    const s = await open(at);
    let error = null;
    try { await s.addBlock(x.hex); } catch (e) { error = message(e); }
    out.push({ name: x.name, ok: error === null, error });
    await rm(at, { recursive: true, force: true });
  }
  console.log(JSON.stringify(out));
} else if (cmd === 'mempool') {
  const at = await copyOf('mempool');
  const engine = await loadEngine(chain);
  const signer = makeSigner(engine);
  const key = await loadKey(extra, { signer });
  const s = await new Siding({ engine, chain, dir: at, signer, log: () => {} }).open(key);
  const hex = (await readFile(extra2, 'utf8')).trim();
  const before = s.height();
  let submit = null, produce = null, produced = null;
  try { submit = await s.submit(hex); } catch (e) { submit = { error: message(e) }; }
  try { const r = await s.produce(key); produced = { height: r.height, txs: r.txs, evicted: r.evicted ?? null }; } catch (e) { produce = message(e); }
  console.log(JSON.stringify({ before, submit, produced, produceError: produce, after: s.height(), mempool: s.mempool.size }));
  await rm(at, { recursive: true, force: true });
} else {
  throw new Error(`unknown command ${cmd}`);
}
