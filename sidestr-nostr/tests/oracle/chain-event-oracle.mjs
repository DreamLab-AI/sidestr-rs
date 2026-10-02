// The fixture generator for sidestr-nostr's chain events (SPEC 3, 0.0.5): siding's own
// `chainEvent`, `parseChainEvent`, `tipEvent` and `parseTip` (lib/announce.mjs at sidestr/spec
// e8deb63) over the schema kernel's hash and secp256k1, for the disposable keys sidestr-core
// carries in fixtures/trial and fixtures/fedtest, with zero BIP-340 auxiliary randomness so the
// signatures are reproducible. Writes the fixture JSON to stdout:
//
//   SIDESTR_SIDING=<sidestr/spec>/siding SCHEMA=<bitcoin-desktop/schema> BLAKETESTNODE=<bitcoin-blake/blaketestnode> \
//     node sidestr-nostr/tests/oracle/chain-event-oracle.mjs > sidestr-nostr/fixtures/chain-event-vectors.json
//
// tests/chain_event.rs runs it again when those variables are set and requires the committed
// fixture to be exactly what it prints.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

for (const n of ['SIDESTR_SIDING', 'SCHEMA', 'BLAKETESTNODE']) if (!process.env[n]) throw new Error(`${n} is required`);
const at = (p) => pathToFileURL(`${process.env.SIDESTR_SIDING}/${p}`).href;
const [{ loadEngine }, { makeSigner }, { makeEvents }, A] = await Promise.all([
  import(at('lib/engine.mjs')), import(at('lib/sign.mjs')), import(at('lib/relay.mjs')), import(at('lib/announce.mjs')),
]);
const fixtures = new URL('../../../sidestr-core/fixtures/', import.meta.url);
const text = (p) => readFileSync(new URL(p, fixtures), 'utf8');
const AT = 1790100000;

const trialText = text('trial/chain.json'); const trial = JSON.parse(trialText);
const e = await loadEngine(trial); const base = makeSigner(e);
const signer = { ...base, schnorrSign: (m, k) => base.schnorrSign(m, k, new Uint8Array(32)) };
const events = makeEvents({ signer, hash: e.hash }); const verify = e.nostr.verifyNostrEvent;
const trialKey = text('trial/trial.key').trim();
const fedText = text('fedtest/chain.json'); const fedKey = text('fedtest/signer2.key').trim();

// a document whose JSON exercises what JSON.parse then JSON.stringify do to a text: integer-like
// keys move to the front in ascending order, a repeated key keeps its first place and its last
// value, numbers print as JavaScript prints them, strings escape as JSON.stringify escapes them
const awkwardText = '{"id":"sidestr:awkward","name":"awkward","10":"ten","parent":"tbtc4","2":"two",'
  + '"signer":"' + base.pubkeyOf(trialKey) + '","f":1.0,"g":1e21,"h":0.000001,"i":1e-7,"j":123.456,"k":-0.0,'
  + '"l":1.5e300,"m":-2.5e-9,"big":9007199254740993,"neg":-12,"s":"\\u00e9 \\u2028 \\"q\\" \\u0001 \\/ \\t","nested":{"b":1,"0":[1.10,{"z":null,"a":true}]},'
  + '"name":"awkward-again"}';

const docs = { trial: [trialText, trialKey], fed: [fedText, fedKey], awkward: [awkwardText, trialKey] };
const out = { reference: 'sidestr/spec e8deb63161c7459ed39c01d2ca9fda3d860b65b6 siding/lib/announce.mjs chainEvent, parseChainEvent, tipEvent, parseTip', created_at: AT, documents: {}, events: {}, upstream: {} };
for (const [name, [src, key]] of Object.entries(docs)) {
  out.documents[name] = src;
  const ev = A.chainEvent({ events, key, chain: JSON.parse(src), created_at: AT });
  if (!verify(ev)) throw new Error(`${name}: the kernel does not verify siding's own event`);
  out.events[name] = { id: ev.id, pubkey: ev.pubkey, created_at: ev.created_at, kind: ev.kind, tags: ev.tags, content: ev.content, sig: ev.sig };
  const d = A.parseChainEvent(ev, { verify });
  out.upstream[`parseChainEvent_${name}`] = { hash: d.hash, alias: d.alias, pubkey: d.pubkey, chain: JSON.stringify(d.chain) };
}
// tipEvent takes no created_at: its events are pinned to the same instant here
const pinned = { ...events, signEvent: (k, t) => events.signEvent(k, { ...t, created_at: t.created_at ?? AT }) };
const S = (i) => i.toString(16).padStart(2, '0').repeat(80);
const tip = A.tipEvent({ events: pinned, key: trialKey, chainId: trial.id, headersHex: [S(1), S(2), S(3)], tip: 12, mirrors: ['https://a.example/siding/'], pegScript: '5120' + 'AB'.repeat(32), chainHash: out.events.trial.id.toUpperCase() });
out.events.tipChainHash = { id: tip.id, pubkey: tip.pubkey, created_at: tip.created_at, kind: tip.kind, tags: tip.tags, content: tip.content, sig: tip.sig };
const p = A.parseTip(tip); out.upstream.parseTip_chainHash = p.chainHash;
const bare = A.tipEvent({ events: pinned, key: trialKey, chainId: trial.id, headersHex: [S(1)], tip: 0, mirrors: [], chainHash: out.events.trial.id });
out.events.tipChainHashOnly = { id: bare.id, pubkey: bare.pubkey, created_at: bare.created_at, kind: bare.kind, tags: bare.tags, content: bare.content, sig: bare.sig };
let refused = null; try { A.tipEvent({ events: pinned, key: trialKey, chainId: trial.id, headersHex: [S(1)], tip: 0, chainHash: 'ab' }); } catch (x) { refused = x.message; }
out.upstream.tipEvent_badChainHash = refused;
out.note = 'Built by siding chainEvent/tipEvent with the schema kernel hash and secp256k1 at sidestr/spec e8deb63 for the disposable keys in sidestr-core/fixtures/trial (trial.key) and fixtures/fedtest (signer2.key); BIP-340 aux randomness zero. documents.* are the source texts as given to JSON.parse; upstream.* records what parseChainEvent and parseTip returned.';
process.stdout.write(JSON.stringify(out, null, 1) + '\n');
