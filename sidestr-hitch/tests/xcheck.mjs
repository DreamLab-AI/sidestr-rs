// Check Rust-built Hitch transactions with the exact JavaScript reference
// module and the schema kernel's interpreter. Rust sends fixed-vector
// transactions and signatures on stdin; this script derives the same channel
// independently and returns one JSON verdict.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const need = ['HITCH', 'SCHEMA', 'BLAKETESTNODE', 'SIDESTR_SIDING'];
for (const name of need) if (!process.env[name]) throw new Error(`${name} is required`);
const at = (root, path) => pathToFileURL(`${root}/${path}`).href;
const [{ makeChannels }, { loadEngine }, hash, secp, { makeSigner }] = await Promise.all([
  import(at(process.env.HITCH, 'lib/channel.mjs')),
  import(at(process.env.BLAKETESTNODE, 'lib/engine.mjs')),
  import(at(process.env.SCHEMA, 'codec/hash.js')),
  import(at(process.env.SCHEMA, 'codec/secp256k1.js')),
  import(at(process.env.SIDESTR_SIDING, 'lib/schnorr.mjs')),
]);
const k = await loadEngine('btc:testnet4-blake2b');
const signer = makeSigner({ hash, secp });
const C = makeChannels({ k, hash, secp, signer });
const x = JSON.parse(readFileSync(0, 'utf8'));
const keyA = '11'.repeat(32), keyB = '22'.repeat(32);
const a = signer.pubkeyOf(keyA), b = signer.pubkeyOf(keyB);
const f = C.fundingScript(a, b);
const ch = {
  keys: { a, b },
  funding: { txid: 'ab'.repeat(32), vout: 1, value: 100000, ...f },
  fee: 300,
  delay: 6,
};
const preimage = '55'.repeat(32);
const paymentHash = hash.bytesToHex(hash.sha256(hash.hexToBytes(preimage)));
const state = {
  balA: 40000,
  balB: 40000,
  rev: { a: signer.pubkeyOf('33'.repeat(32)), b: signer.pubkeyOf('44'.repeat(32)) },
  htlcs: [{ id: 1, from: 'a', amount: 20000, hash: paymentHash, expiry: 152200 }],
};
const commitA = C.commitmentTx(ch, 2, { ...state, owner: 'a' });
const commitB = C.commitmentTx(ch, 2, { ...state, owner: 'b' });
const failures = [];
const check = (name, condition) => { if (!condition) failures.push(name); };
check('commitment A bytes', C.encode(commitA.tx) === x.commitAUnsigned);
check('commitment B bytes', C.encode(commitB.tx) === x.commitBUnsigned);
check('A funding signature', C.verifyFunding(ch, commitA.tx, a, x.sigA));
check('B funding signature', C.verifyFunding(ch, commitA.tx, b, x.sigB));
const signedA = C.decode(x.commitASigned);
check('signed commitment interpreter', C.verifyTx(signedA, [C.fundingPrevout(ch)]).ok === true);
check('signed commitment txid', C.txid(signedA) === C.txid(commitA.tx));

const toLocalPrev = [{ value: commitA.local, scriptPubKey: commitA.toLocal.spk }];
check('delayed sweep interpreter', C.verifyTx(C.decode(x.sweep), toLocalPrev).ok === true);
check('penalty interpreter', C.verifyTx(C.decode(x.penalty), toLocalPrev).ok === true);
const htlcPrev = [{ value: 20000, scriptPubKey: commitA.htlcs[0].scripts.spk }];
check('HTLC success interpreter', C.verifyTx(C.decode(x.success), htlcPrev).ok === true);
check('HTLC timeout interpreter', C.verifyTx(C.decode(x.timeout), htlcPrev).ok === true);
check('HTLC penalty interpreter', C.verifyTx(C.decode(x.htlcPenalty), htlcPrev).ok === true);
const remotePrev = [{ value: commitA.remote, scriptPubKey: C.toRemoteScript(b) }];
check('to_remote key path interpreter', C.verifyTx(C.decode(x.keyPath), remotePrev).ok === true);

const closeState = { balA: 60000, balB: 40000, rev: state.rev };
const close = C.closingTx(ch, closeState);
check('cooperative close bytes', C.encode(close) === x.closeUnsigned);
check('close A signature', C.verifyFunding(ch, close, a, x.closeSigA));
check('close B signature', C.verifyFunding(ch, close, b, x.closeSigB));
check('signed close interpreter', C.verifyTx(C.decode(x.closeSigned), [C.fundingPrevout(ch)]).ok === true);

process.stdout.write(JSON.stringify({ ok: failures.length === 0, failures }));
