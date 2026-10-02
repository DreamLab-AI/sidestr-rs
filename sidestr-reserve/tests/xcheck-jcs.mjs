// The teller's JCS (solidpayorg/teller lib/teller.mjs `jcs` at 7c00cea, Melvin Carvalho) as the
// oracle for sidestr-reserve's canonical bytes: reads a JSON array of JSON documents (each a
// string) on stdin and writes the array of their JCS serialisations.
//   TELLER=<teller checkout> node xcheck-jcs.mjs < documents.json
// The function is held to the SHA-256 of its source text, so a teller whose `jcs` changed is
// reported as such instead of silently becoming a different oracle.
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
const JCS_SHA256 = '471016ed043c05d107b62f1a342089b701c2b6e593f02ea4cfc14f3b4d8de7c4';
const { jcs } = await import(pathToFileURL(join(process.env.TELLER, 'lib/teller.mjs')).href);
const got = createHash('sha256').update(jcs.toString()).digest('hex');
if (got !== JCS_SHA256) {
  process.stderr.write(`teller's jcs is not 7c00cea's: source sha256 ${got}\n`);
  process.exit(2);
}
let input = '';
for await (const chunk of process.stdin) input += chunk;
process.stdout.write(JSON.stringify(JSON.parse(input).map((doc) => jcs(JSON.parse(doc)))));
