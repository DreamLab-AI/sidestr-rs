// Reef's own BIP 21 parser (bitcoin-blake/reef lib/wallet.mjs parsePaymentUri, Melvin Carvalho,
// AGPL-3.0) as the oracle for sidestr-wallet's `bip21` module: reads a JSON array of strings on
// stdin and writes, for each, {"ok": <the request or null>} or {"error": <Reef's message>}.
//   REEF=<reef checkout> node xcheck-bip21.mjs < uris.json
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
const { parsePaymentUri } = await import(pathToFileURL(join(process.env.REEF, 'lib/wallet.mjs')).href);
let input = '';
for await (const chunk of process.stdin) input += chunk;
const out = JSON.parse(input).map((uri) => {
  try {
    return { ok: parsePaymentUri(uri) };
  } catch (e) {
    return { error: e.message };
  }
});
process.stdout.write(JSON.stringify(out));
