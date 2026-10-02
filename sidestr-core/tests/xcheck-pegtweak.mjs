// The reference keys and peg-in tweak modules (siding/lib/keys.mjs at sidestr/spec bd1d692,
// siding/lib/pegtweak.mjs at 4c4915f; Melvin Carvalho, AGPL-3.0) as the oracle for
// sidestr-core's `keys` and `pegtweak`: reads a JSON array of cases on stdin and writes one
// answer per case, so the Rust side compares field for field.
//   SIDESTR_SIDING=<siding dir> SCHEMA=<bitcoin-desktop/schema> node xcheck-pegtweak.mjs keys < cases.json
//   SIDESTR_SIDING=<siding dir> SCHEMA=<bitcoin-desktop/schema> node xcheck-pegtweak.mjs pegtweak < reveals.json
// keys:     {secret, tweaks, tag, data} -> the key functions over them
// pegtweak: {internal, refundKey, refundBlocks, chainHash, script, extraLeaves, hrp, holder?}
//           -> pegOutput's object, pegMatches on its own script, and pegSpendSecret(holder) when given
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
const siding = process.env.SIDESTR_SIDING, schema = process.env.SCHEMA;
const url = (dir, file) => pathToFileURL(join(dir, file)).href;
const [hash, secp] = await Promise.all([import(url(schema, 'codec/hash.js')), import(url(schema, 'codec/secp256k1.js'))]);
const { makeKeys } = await import(url(siding, 'lib/keys.mjs'));
const K = makeKeys({ hash, secp });
let input = '';
for await (const chunk of process.stdin) input += chunk;
const cases = JSON.parse(input);
const mode = process.argv[2];
let out;
if (mode === 'keys') {
  out = cases.map(({ secret, tweaks, tag, data }) => {
    const P = K.publicKey(secret), n = K.normalize(secret);
    return {
      publicKey: P,
      normalize: n,
      signingKey: K.signingKey(secret),
      did: K.did(P),
      multikey: K.multikey(P),
      negate: K.negate(P),
      basePointMultikey: K.basePoint(K.multikey(P)),
      chainSecrets: K.chainSecrets(n, tweaks),
      chainPoints: K.chainPoints(K.basePoint(K.did(P)), tweaks),
      chainFromOwnPoint: K.chainPoints(P, tweaks),
      taggedScalar: K.taggedScalar(tag, data),
      tapTweak: K.tapTweak(P, data),
      tapTweakNone: K.tapTweak(P),
    };
  });
} else if (mode === 'pegtweak') {
  const { pegOutput, pegMatches, pegSpendSecret } = await import(url(siding, 'lib/pegtweak.mjs'));
  const deps = { keys: K, hash, secp };
  out = cases.map(({ holder, ...c }) => {
    try {
      const o = pegOutput(deps, c);
      return { ok: o, matches: pegMatches(deps, o.reveal, o.scriptPubKey), spend: holder ? pegSpendSecret(deps, holder, o) : null };
    } catch (e) {
      return { error: e.message };
    }
  });
} else {
  throw new Error(`unknown mode ${mode}: keys or pegtweak`);
}
process.stdout.write(JSON.stringify(out));
