// The teller itself (solidpayorg/teller lib/teller.mjs at 7c00cea, Melvin Carvalho, AGPL-3.0-or-later)
// as the oracle for webledgers-teller, with the engine and the sidestr library it loads (the kernel for
// btc:testnet4-blake2b, keys.mjs, txsign.mjs, address.mjs, relay.mjs signEvent). Reads one JSON object of
// cases on stdin and writes, section by section, what the teller makes of each: {"ok": …} or
// {"error": <the teller's message>}.
//   TELLER=<teller> SCHEMA=<schema> BLAKETESTNODE=<blaketestnode> SIDESTR_LIB=<siding/lib> node xcheck-teller.mjs < cases.json
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
const imp = (p) => import(pathToFileURL(p).href);
const { TELLER, SCHEMA, BLAKETESTNODE: BTN, SIDESTR_LIB: LIB } = process.env;
const [{ loadEngine }, hash, secp, { makeSigner }, { makeKeys }, txsign, address, { makeEvents }, T, { verifyNostrEvent }] = await Promise.all([
  imp(join(BTN, 'lib/engine.mjs')), imp(join(SCHEMA, 'codec/hash.js')), imp(join(SCHEMA, 'codec/secp256k1.js')), imp(join(LIB, 'schnorr.mjs')), imp(join(LIB, 'keys.mjs')),
  imp(join(LIB, 'txsign.mjs')), imp(join(LIB, 'address.mjs')), imp(join(LIB, 'relay.mjs')), imp(join(TELLER, 'lib/teller.mjs')), imp(join(SCHEMA, 'codec/nostr.js'))]);
const k = await loadEngine('btc:testnet4-blake2b');
const signer = makeSigner({ hash, secp }), keys = makeKeys({ hash, secp }), events = makeEvents({ signer, hash });
const deps = { hash, secp, keys, address, signer, events, txsign, k };
const run = (f) => { try { return { ok: f() }; } catch (e) { return { error: e.message }; } };
const planView = (p) => ({ picked: p.picked.map((c) => `${c.txid}:${c.vout}`), outputs: p.outputs, fee: p.fee, change: p.change, rate: p.rate });

let input = '';
for await (const chunk of process.stdin) input += chunk;
const c = JSON.parse(input);
const out = {
  jcs: c.jcs.map((v) => T.jcs(v)),
  accounts: c.accounts.map((a) => run(() => T.accountOf(a))),
  sats: c.sats.map((s) => run(() => T.sats(s))),
  ledgers: c.ledgers.map((p) => run(() => T.newLedger(deps, p))),
  ledgerScripts: c.ledgerScripts.map(({ ledger, ops }) => {
    const L = T.newLedger(deps, ledger);
    const results = ops.map(({ fn, arg, now }) => run(() => T[fn](L, arg, now)));
    return { results, ledger: L, total: T.total(L), balances: L.entries.map((e) => T.balance(L, e.url)) };
  }),
  deposits: c.deposits.map((d) => run(() => T.depositAddress(deps, d))),
  secrets: c.secrets.map(({ operatorSecret, tweak }) => run(() => T.depositSecret(deps, operatorSecret, tweak))),
  watch: c.watch.map(({ ledger, operatorPoint, extra }) => run(() => T.watchList(deps, ledger, operatorPoint, extra).map((d) => d.address))),
  plans: c.plans.map((p) => run(() => { const plan = T.planPayout(p); const tx = T.unsignedTx(plan); return { plan: planView(plan), unsignedHex: k.codec.encodeHex('Transaction', tx), txid: k.codec.txid(tx) }; })),
  jsPayouts: c.jsPayouts.map(({ plan, operatorSecret }) => run(() => { const p = T.planPayout(plan); const s = T.signPayout(deps, p, operatorSecret); return { plan: planView(p), hex: s.hex, txid: s.txid, vsize: s.vsize }; })),
  rustPayouts: c.rustPayouts.map(({ hex, prevouts }) => run(() => {
    const tx = k.codec.decode('Transaction', hex);
    const checks = tx.inputs.map((_, i) => { const v = k.interpreter.verifyInput(tx, i, prevouts[i], prevouts, null, { unifiedSighash: txsign.usesUnifiedSighash(k) }); return v.ok === true ? 'ok' : (v.error ?? v.reason ?? '?'); });
    return { checks, vsize: T.vsizeOf(k, tx), txid: k.codec.txid(tx), hex: k.codec.encodeHex('Transaction', tx) };
  })),
  requestTags: c.requestTags.map((r) => run(() => T.requestTags(r))),
  rustRequests: c.rustRequests.map(({ event, ledgerHash }) => run(() => { const r = T.parseRequest(event, { verify: verifyNostrEvent, ledgerHash }); delete r.event; return r; })),
  jsRequests: c.jsRequests.map(({ key, req }) => run(() => T.requestEvent(deps, key, req))),
};
process.stdout.write(JSON.stringify(out));
