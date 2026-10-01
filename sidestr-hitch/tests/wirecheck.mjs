// Feed Rust-serialised channel messages through the exact validator exported
// by the pinned Hitch peer state machine.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

if (!process.env.HITCH) throw new Error('HITCH is required');
const { makePeer } = await import(pathToFileURL(`${process.env.HITCH}/lib/peer.mjs`).href);
const peer = makePeer({
  C: {},
  signer: {},
  hash: {},
  pub: '11'.repeat(32),
  key: '11'.repeat(32),
  channels: [],
  io: { save() {}, log() {}, height() { return 0; } },
});
const { messages } = JSON.parse(readFileSync(0, 'utf8'));
const failures = messages
  .map((message, index) => ({ index, type: message.t, error: peer.wellFormed(message) }))
  .filter(({ error }) => error != null);
process.stdout.write(JSON.stringify({ ok: failures.length === 0, checked: messages.length, failures }));
