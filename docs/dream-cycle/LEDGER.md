# Dream-cycle ledger

One row per night the dream engine runs on this repository (nominated 2026-10-24).

| date | slot | verdict | finding |
|---|---|---|---|
| 2026-10-25 | nostr-plane | pledge_event took a d-tag reward the tx never spends; now a Disagree refusal | NONE | https://github.com/DreamLab-AI/sidestr-rs/pull/2 | yes | ACCEPT |  | 6b42dabf2a8f |  |  |  |
| 2026-10-26 | rounds-and-channels | VETOED: split_combined_journal now witnessed: burns copy once, block journal… | NONE | VETOED | yes | REJECT |  | dbb419ac9088 |  |  |  |
| 2026-10-28 | consensus-core | peg_matches accepts output-script hex in either case; the reveal is normalised | NONE | https://github.com/DreamLab-AI/sidestr-rs/pull/3 | yes | ACCEPT |  | d531fb35ba8c |  |  |  |
| 2026-10-29 | headers-and-pow | check_pow enforces the compact-truncated powLimit (7fffff00..00), inclusive | NONE | https://github.com/DreamLab-AI/sidestr-rs/pull/4 | yes | ACCEPT |  | 530d7b63408d |  |  |  |
| 2026-10-30 | wallet-and-signing | VETOED: change at 330 keeps an output; 329 joins the fee, which still clears… | NONE | VETOED | yes | REJECT |  | e84ef14ef9b1 |  |  |  |
| 2026-10-31 | nostr-plane | VETOED: parse_record refuses a pledge d tag naming an outpoint its tx never… | NONE | VETOED | yes | REJECT |  | adf6997d34e4 |  |  |  |
| 2026-11-01 | headers-and-pow | VETOED: check_pow edge pinned: hash == truncated limit passes; +1 is… | NONE | VETOED | yes | REJECT |  | ca63b7d1f007 |  |  |  |
| 2026-11-02 | wallet-and-signing | VETOED: build_outputs reselects for the sized fee: records outrun the 200-vB… | NONE | VETOED | yes | REJECT |  | f6f3955a900e |  |  |  |
| 2026-11-03 | nostr-plane | sign_pledge refuses a marker one byte off the 34-byte payee boundary (pinned) | NONE | https://github.com/DreamLab-AI/sidestr-rs/pull/5 | yes | ACCEPT |  | c1e3198fd77f |  |  |  |
| 2026-11-04 | rounds-and-channels | round.rs:1-369 & tests/round.rs not supplied: cannot build a Round to pin | NONE | NONE | yes | INCONCLUSIVE |  | 4bf95c2223fa |  |  |  |
| 2026-11-05 | agent-evm-reserve | reserve bounds pinned from the accepting side: 128-byte ids, 256-byte source ok | NONE | https://github.com/DreamLab-AI/sidestr-rs/pull/6 | yes | ACCEPT |  | 44b1c68370ef |  |  |  |
