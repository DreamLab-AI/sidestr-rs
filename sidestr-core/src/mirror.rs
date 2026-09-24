//! A mirror's block file read from memory: what a client holds after one
//! `GET <mirror>/blocks.dat` (SPEC 11), replayed into a validated
//! [`StateOf`] without a file system. The framing is the block file's,
//! `[u32le height][u32le size][block bytes]` repeated
//! (`bitcoin-blake/blaketestnode` `lib/blockfile.mjs`); `blockfile` (feature
//! `std`) writes and reads the same records on disk.
//!
//! Nothing here trusts the mirror. The genesis is judged against the chain
//! document and held to its `genesisHash`, and every later block passes the
//! same rules as [`StateOf::apply`], so a mirror can serve a short chain or
//! none at all, but never a block the signer did not seal. A client that
//! wants to know how far behind the mirror is compares the replayed tip with
//! the signer's own kind-33333 announcement.
//!
//! ```
//! use bitcoin::secp256k1::SecretKey;
//! use sidestr_core::block::{challenge_for, pubkey_of, SidestrBlock};
//! use sidestr_core::document::ChainDocument;
//! use sidestr_core::mirror::{encode_record, records};
//! use sidestr_core::state::{NextBlock, State};
//!
//! let key = SecretKey::from_slice(&[7u8; 32]).unwrap();
//! let json = format!(r#"{{"id":"sidestr:example","name":"example","parent":"tbtc4","challenge":"{}",
//!   "powLimit":"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","addressPrefix":"ex",
//!   "genesisTime":1790000000,"signer":"{}","pegs":[]}}"#, challenge_for(&pubkey_of(&key)).to_hex_string(), pubkey_of(&key));
//! let doc = ChainDocument::from_json(&json).unwrap();
//!
//! // a producer makes three blocks and a mirror serves them as a block file
//! let genesis = State::genesis_block_for(&doc, &key).unwrap();
//! let mut dat = encode_record(0, &genesis.encode());
//! let mut chain = State::from_genesis(doc.clone(), &genesis, None).unwrap();
//! for i in 1..=3 {
//!     let (_, block) = chain.produce(&key, &NextBlock { time: 1790000000 + i, claims: vec![] }, None).unwrap();
//!     dat.extend(encode_record(i, &block.encode()));
//! }
//! assert_eq!(records(&dat).unwrap().len(), 4);
//!
//! // a client replays the bytes against the document it already trusts
//! let replayed = State::replay(doc, &dat, None).unwrap();
//! assert_eq!(replayed.tip(), chain.tip());
//! ```

use crate::block::{HeaderFamily, SidestrBlock};
use crate::document::ChainDocument;
use crate::error::{Error, Result};
use crate::state::StateOf;

/// The per-record prefix: height and size, both `u32le`.
pub const RECORD_HEADER: usize = 8;

/// One record of a block file: its height and the block bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record<'a> {
    /// The height the record claims. [`StateOf::replay`] holds it to the
    /// height the chain reaches by applying the block.
    pub height: u32,
    /// The block's consensus bytes.
    pub bytes: &'a [u8],
}

/// Split a block file into its records. A trailing record that is cut short
/// (a mirror caught mid-write, a truncated download) is
/// [`Error::BlockFile`], named with its offset; a client retries rather than
/// replaying a chain it half holds.
pub fn records(dat: &[u8]) -> Result<Vec<Record<'_>>> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < dat.len() {
        let head = dat.get(at..at + RECORD_HEADER).ok_or_else(|| {
            Error::BlockFile(format!(
                "a record at byte {at} is cut short: {} bytes left, the prefix is 8",
                dat.len() - at
            ))
        })?;
        let height = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
        let size = u32::from_le_bytes([head[4], head[5], head[6], head[7]]) as usize;
        let start = at + RECORD_HEADER;
        let end = start.checked_add(size).filter(|e| *e <= dat.len()).ok_or_else(|| {
            Error::BlockFile(format!(
                "the record for height {height} at byte {at} runs past the file: size {size}, {} bytes left",
                dat.len() - start
            ))
        })?;
        out.push(Record {
            height,
            bytes: &dat[start..end],
        });
        at = end;
    }
    Ok(out)
}

/// One record's bytes, `[u32le height][u32le size][block]`: what
/// `blockfile::append_block` writes, for a test or a tool that assembles a
/// block file in memory.
pub fn encode_record(height: u32, block: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(RECORD_HEADER + block.len());
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(&(block.len() as u32).to_le_bytes());
    out.extend_from_slice(block);
    out
}

impl<F: HeaderFamily> StateOf<F> {
    /// Replay a mirror's block file held in memory into a validated state.
    /// The first record must be height 0 and is judged as the genesis
    /// ([`StateOf::from_genesis`], held to the document's `genesisHash`);
    /// every later record must be the next height and passes
    /// [`StateOf::apply`]. `now` is the clock for the future-time rule
    /// (`None` skips it). An empty file is [`Error::BlockFile`]: a chain
    /// always has its genesis.
    pub fn replay(doc: ChainDocument, dat: &[u8], now: Option<u32>) -> Result<Self> {
        Self::replay_with(doc, dat, now, |_, _, _| {})
    }

    /// [`StateOf::replay`], calling `on_block(before, height, block)` for
    /// each block ahead of applying it: `before` is the state at the previous
    /// height (`None` for the genesis). A wallet uses it to read its own
    /// history, since which coins a block spends is known only before the
    /// block is applied. A block the rules refuse stops the replay with the
    /// error; `on_block` has then seen it, so a caller keeps nothing from a
    /// call that returned an error.
    pub fn replay_with(
        doc: ChainDocument,
        dat: &[u8],
        now: Option<u32>,
        mut on_block: impl FnMut(Option<&Self>, u32, &F::Block),
    ) -> Result<Self> {
        let recs = records(dat)?;
        let (first, rest) = recs
            .split_first()
            .ok_or_else(|| Error::BlockFile("the block file is empty: no genesis".into()))?;
        if first.height != 0 {
            return Err(Error::BlockFile(format!(
                "the block file starts at height {}, not the genesis",
                first.height
            )));
        }
        let genesis = F::Block::decode(first.bytes)?;
        on_block(None, 0, &genesis);
        let mut state = Self::from_genesis(doc, &genesis, None)?;
        for rec in rest {
            let block = F::Block::decode(rec.bytes)?;
            on_block(Some(&state), rec.height, &block);
            state.apply(rec.height, &block, None, now)?;
        }
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{challenge_for, pubkey_of};
    use crate::state::{NextBlock, State};
    use bitcoin::secp256k1::SecretKey;

    fn doc_and_key() -> (ChainDocument, SecretKey) {
        let key = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let json = format!(
            r#"{{"id":"sidestr:example","name":"example","parent":"tbtc4","challenge":"{}",
            "powLimit":"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","addressPrefix":"ex",
            "genesisTime":1790000000,"signer":"{}","pegs":[]}}"#,
            challenge_for(&pubkey_of(&key)).to_hex_string(),
            pubkey_of(&key)
        );
        (ChainDocument::from_json(&json).unwrap(), key)
    }

    /// A producer's chain of `n` blocks after the genesis, as a mirror serves it.
    fn mirror_of(n: u32) -> (ChainDocument, Vec<u8>, State) {
        let (doc, key) = doc_and_key();
        let genesis = State::genesis_block_for(&doc, &key).unwrap();
        let mut dat = encode_record(0, &genesis.encode());
        let mut chain = State::from_genesis(doc.clone(), &genesis, None).unwrap();
        for i in 1..=n {
            let (_, block) = chain
                .produce(
                    &key,
                    &NextBlock {
                        time: 1_790_000_000 + i,
                        claims: vec![],
                    },
                    None,
                )
                .unwrap();
            dat.extend(encode_record(i, &block.encode()));
        }
        (doc, dat, chain)
    }

    #[test]
    fn replays_to_the_producers_tip() {
        let (doc, dat, chain) = mirror_of(5);
        let replayed = State::replay(doc, &dat, None).unwrap();
        assert_eq!(replayed.height(), 5);
        assert_eq!(replayed.tip(), chain.tip());
    }

    #[test]
    fn the_callback_sees_every_block_with_the_state_before_it() {
        let (doc, dat, _) = mirror_of(3);
        let mut seen = Vec::new();
        State::replay_with(doc, &dat, None, |before, h, _| {
            seen.push((h, before.map(|s| s.height())));
        })
        .unwrap();
        assert_eq!(
            seen,
            vec![(0, None), (1, Some(0)), (2, Some(1)), (3, Some(2))]
        );
    }

    #[test]
    fn a_truncated_tail_is_refused_not_half_replayed() {
        let (doc, dat, _) = mirror_of(2);
        let cut = &dat[..dat.len() - 3];
        assert!(matches!(
            State::replay(doc, cut, None),
            Err(Error::BlockFile(_))
        ));
    }

    #[test]
    fn a_file_that_does_not_start_at_the_genesis_is_refused() {
        let (doc, dat, _) = mirror_of(2);
        let first = records(&dat).unwrap()[0].bytes.len() + RECORD_HEADER;
        assert!(matches!(
            State::replay(doc, &dat[first..], None),
            Err(Error::BlockFile(_))
        ));
    }

    #[test]
    fn a_skipped_height_is_refused() {
        let (doc, dat, _) = mirror_of(3);
        let recs = records(&dat).unwrap();
        let mut gap = encode_record(0, recs[0].bytes);
        gap.extend(encode_record(2, recs[2].bytes));
        assert!(State::replay(doc, &gap, None).is_err());
    }

    #[test]
    fn a_block_the_signer_did_not_seal_is_refused() {
        let (doc, dat, _) = mirror_of(1);
        // block 1 as the signer sealed it, then its time moved by a second:
        // the seal no longer commits to the header the mirror serves
        let recs = records(&dat).unwrap();
        let mut forged =
            <crate::block::Stock as HeaderFamily>::Block::decode(recs[1].bytes).unwrap();
        forged.header.time += 1;
        let mut dat = encode_record(0, recs[0].bytes);
        dat.extend(encode_record(1, &forged.encode()));
        assert!(State::replay(doc, &dat, None).is_err());
    }

    #[test]
    fn an_empty_file_has_no_genesis() {
        let (doc, _) = doc_and_key();
        assert!(matches!(
            State::replay(doc, &[], None),
            Err(Error::BlockFile(_))
        ));
    }
}
