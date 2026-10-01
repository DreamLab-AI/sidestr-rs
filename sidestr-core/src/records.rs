//! Records (SPEC 12.1): `OP_RETURN` outputs whose data is UTF-8 text of at
//! most 255 bytes in a single minimal push. Asset, pool and prediction-market
//! records are parsed here; their rules decide what they mean. A port of
//! `siding/lib/records.mjs` (AGPL-3.0, Melvin Carvalho).
//!
//! | record | meaning |
//! |---|---|
//! | `issue:<TICKER>:<decimals>` | this transaction issues an asset whose id is its txid |
//! | `tally:<asset>:<vout>=<amount>[,…]` | those outputs carry those amounts of the asset (`self` in the issuing transaction) |
//! | `pool:<pool>:<vout>` | the named output is that pool's coin |
//! | `market:self:<vout>:<resolver>:<expiry>:<grace>` | open a binary market |
//! | `split\|merge\|redeem:<market>:<vout>` | move the market collateral |
//! | `resolve:<market>:yes\|no` | the resolver answers |
//! | `question:<text>` | the market's question (at most 200 UTF-8 bytes) |
//!
//! Any other text in an `OP_RETURN` is a record too; it is simply not one of
//! these three, and [`classify`] leaves it alone, so an application may carry
//! its own (`tip:nostr:<event id>`, say) beside a tally.
//!
//! ```
//! use sidestr_core::records::{parse_issue, parse_tally, record_script, record_text, Issue, Tally, AssetRef};
//!
//! let s = record_script("issue:DREAM:0").unwrap();
//! assert_eq!(record_text(&s).as_deref(), Some("issue:DREAM:0"));
//! assert_eq!(parse_issue("issue:DREAM:0"), Some(Issue { ticker: "DREAM".into(), decimals: 0 }));
//! let t = parse_tally("tally:self:0=1000000").unwrap();
//! assert_eq!(t.asset, AssetRef::SelfTx);
//! assert_eq!(t.assigns, vec![(0, 1_000_000)]);
//! ```

use bitcoin::script::PushBytesBuf;
use bitcoin::{Script, ScriptBuf, Transaction, Txid};

use crate::error::{Error, Result};

/// The largest amount a tally may assign, `2^53 - 1` (a JavaScript safe
/// integer, so the reference and this port agree on every sum).
pub const MAX_AMOUNT: u64 = (1 << 53) - 1;

/// The longest record, in bytes.
pub const MAX_RECORD: usize = 255;

/// The text of an `OP_RETURN` output, or `None` when it is not exactly
/// `OP_RETURN` followed by one minimal push of at most 255 bytes of UTF-8
/// (`recordText`).
pub fn record_text(script: &Script) -> Option<String> {
    let bytes = script.as_bytes();
    if bytes.first() != Some(&0x6a) {
        return None;
    }
    // the reference accepts a direct push (1..=75) or OP_PUSHDATA1 (76..=255), minimal only
    let (len, start) = match bytes.get(1)? {
        n @ 1..=75 => (*n as usize, 2),
        0x4c => {
            let n = *bytes.get(2)? as usize;
            if n <= 75 {
                return None;
            }
            (n, 3)
        }
        _ => return None,
    };
    if bytes.len() != start + len || len > MAX_RECORD {
        return None;
    }
    String::from_utf8(bytes[start..].to_vec()).ok()
}

/// The `OP_RETURN` script carrying `text` (`recordScript`): a direct push up
/// to 75 bytes, `OP_PUSHDATA1` above. More than 255 bytes, or no bytes, is
/// [`Error::Encoding`].
pub fn record_script(text: &str) -> Result<ScriptBuf> {
    let b = text.as_bytes();
    if b.is_empty() || b.len() > MAX_RECORD {
        return Err(Error::Encoding(format!(
            "a record is 1 to {MAX_RECORD} bytes, this one is {}",
            b.len()
        )));
    }
    let push = PushBytesBuf::try_from(b.to_vec())
        .map_err(|_| Error::Encoding("a record does not fit one push".into()))?;
    Ok(ScriptBuf::new_op_return(push))
}

/// Every record of a transaction: `(vout, text)` in output order (`recordsOf`).
pub fn records_of(tx: &Transaction) -> Vec<(u32, String)> {
    tx.output
        .iter()
        .enumerate()
        .filter_map(|(v, o)| record_text(&o.script_pubkey).map(|t| (v as u32, t)))
        .collect()
}

/// `issue:<TICKER>:<decimals>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    /// 1 to 8 of `A-Z0-9`.
    pub ticker: String,
    /// 0 to 8; display only.
    pub decimals: u8,
}

/// Which asset a tally names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetRef {
    /// `self`: the asset this transaction issues (or the pool it opens).
    SelfTx,
    /// An asset id: the txid that issued it, display order.
    Id(Txid),
}

/// `tally:<asset>:<vout>=<amount>[,…]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tally {
    /// The asset.
    pub asset: AssetRef,
    /// `(vout, amount)` in the order written; no vout twice.
    pub assigns: Vec<(u32, u64)>,
}

/// `pool:<pool>:<vout>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pool {
    /// The pool: `self` when this transaction opens it.
    pub pool: AssetRef,
    /// The pool coin's output.
    pub vout: u32,
}

/// The answer recorded by a market resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarketOutcome {
    /// The YES asset wins.
    Yes,
    /// The NO asset wins.
    No,
}

/// A `market:`, `split:`, `merge:`, `redeem:` or `resolve:` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarketRecord {
    /// `market:self:<vout>:<resolver>:<expiry>:<grace>`.
    Open {
        /// The new market coin's output.
        vout: u32,
        /// The resolver's lower-case x-only public key.
        resolver: String,
        /// Last height at which the market remains open before its grace
        /// interval.
        expiry: u32,
        /// Blocks after expiry during which the resolver may still answer.
        grace: u32,
    },
    /// `split:<market>:<vout>`: add collateral and mint a YES/NO pair.
    Split {
        /// The market id (its opening transaction id).
        market: Txid,
        /// The replacement market coin's output.
        vout: u32,
    },
    /// `merge:<market>:<vout>`: burn a pair and release collateral.
    Merge {
        /// The market id.
        market: Txid,
        /// The replacement market coin's output.
        vout: u32,
    },
    /// `redeem:<market>:<vout>`: redeem the winner or refund after grace.
    Redeem {
        /// The market id.
        market: Txid,
        /// The replacement market coin's output.
        vout: u32,
    },
    /// `resolve:<market>:yes|no`.
    Resolve {
        /// The market id.
        market: Txid,
        /// The resolver's answer.
        outcome: MarketOutcome,
    },
}

impl MarketRecord {
    /// The action name used by the reference's diagnostics.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Open { .. } => "open",
            Self::Split { .. } => "split",
            Self::Merge { .. } => "merge",
            Self::Redeem { .. } => "redeem",
            Self::Resolve { .. } => "resolve",
        }
    }

    /// The existing market named by an action, or `None` for an opening.
    pub fn market(&self) -> Option<Txid> {
        match self {
            Self::Open { .. } => None,
            Self::Split { market, .. }
            | Self::Merge { market, .. }
            | Self::Redeem { market, .. }
            | Self::Resolve { market, .. } => Some(*market),
        }
    }
}

/// A `question:<text>` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// The non-empty question, at most 200 UTF-8 bytes.
    pub text: String,
}

fn amount(s: &str) -> Option<u64> {
    // `^[1-9]\d{0,15}$`, at most MAX_AMOUNT
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 16 || b[0] == b'0' || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    s.parse::<u64>().ok().filter(|n| *n <= MAX_AMOUNT)
}

fn asset_ref(s: &str) -> Option<AssetRef> {
    if s == "self" {
        return Some(AssetRef::SelfTx);
    }
    // 64 lower hex only, as the reference's `[0-9a-f]{64}`
    if s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return s.parse().ok().map(AssetRef::Id);
    }
    None
}

fn vout(s: &str) -> Option<u32> {
    // `\d{1,5}`
    if !(1..=5).contains(&s.len()) || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn height(s: &str) -> Option<u32> {
    if !(1..=9).contains(&s.len()) || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn txid(s: &str) -> Option<Txid> {
    match asset_ref(s)? {
        AssetRef::Id(id) => Some(id),
        AssetRef::SelfTx => None,
    }
}

/// `issue:<TICKER>:<decimals>` (`parseIssue`).
pub fn parse_issue(text: &str) -> Option<Issue> {
    let rest = text.strip_prefix("issue:")?;
    let (ticker, dec) = rest.split_once(':')?;
    let ok_ticker = (1..=8).contains(&ticker.len())
        && ticker
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
    let d = dec.as_bytes();
    if !ok_ticker || d.len() != 1 || !(b'0'..=b'8').contains(&d[0]) {
        return None;
    }
    Some(Issue {
        ticker: ticker.to_string(),
        decimals: d[0] - b'0',
    })
}

/// `tally:<asset>:<vout>=<amount>[,…]` (`parseTally`); a repeated vout is malformed.
pub fn parse_tally(text: &str) -> Option<Tally> {
    let rest = text.strip_prefix("tally:")?;
    let (asset, list) = rest.split_once(':')?;
    let asset = asset_ref(asset)?;
    let mut assigns: Vec<(u32, u64)> = Vec::new();
    for part in list.split(',') {
        let (v, a) = part.split_once('=')?;
        let (v, a) = (vout(v)?, amount(a)?);
        if assigns.iter().any(|(seen, _)| *seen == v) {
            return None;
        }
        assigns.push((v, a));
    }
    Some(Tally { asset, assigns })
}

/// `pool:<pool>:<vout>` (`parsePool`).
pub fn parse_pool(text: &str) -> Option<Pool> {
    let rest = text.strip_prefix("pool:")?;
    let (pool, v) = rest.split_once(':')?;
    Some(Pool {
        pool: asset_ref(pool)?,
        vout: vout(v)?,
    })
}

/// Parse a binary-market record (`parseMarket`).
pub fn parse_market(text: &str) -> Option<MarketRecord> {
    let fields: Vec<&str> = text.split(':').collect();
    match fields.as_slice() {
        ["market", "self", output, resolver, expiry, grace]
            if resolver.len() == 64
                && resolver
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) =>
        {
            Some(MarketRecord::Open {
                vout: vout(output)?,
                resolver: (*resolver).to_owned(),
                expiry: height(expiry)?,
                grace: height(grace)?,
            })
        }
        ["split", market, output] => Some(MarketRecord::Split {
            market: txid(market)?,
            vout: vout(output)?,
        }),
        ["merge", market, output] => Some(MarketRecord::Merge {
            market: txid(market)?,
            vout: vout(output)?,
        }),
        ["redeem", market, output] => Some(MarketRecord::Redeem {
            market: txid(market)?,
            vout: vout(output)?,
        }),
        ["resolve", market, "yes"] => Some(MarketRecord::Resolve {
            market: txid(market)?,
            outcome: MarketOutcome::Yes,
        }),
        ["resolve", market, "no"] => Some(MarketRecord::Resolve {
            market: txid(market)?,
            outcome: MarketOutcome::No,
        }),
        _ => None,
    }
}

/// Parse `question:<text>` (`parseQuestion`).
pub fn parse_question(text: &str) -> Option<Question> {
    let question = text.strip_prefix("question:")?;
    if question.is_empty() || question.len() > 200 {
        return None;
    }
    Some(Question {
        text: question.to_owned(),
    })
}

/// A transaction's records, classified (`classify`): each list keeps the
/// record's `vout`. `bad` holds text that starts like one of the recognised
/// forms but does not parse, which the assets rule refuses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Classified {
    /// `issue:` records.
    pub issues: Vec<(u32, Issue)>,
    /// `tally:` records.
    pub tallies: Vec<(u32, Tally)>,
    /// `pool:` records.
    pub pools: Vec<(u32, Pool)>,
    /// Market action records.
    pub markets: Vec<(u32, MarketRecord)>,
    /// `question:` records.
    pub questions: Vec<(u32, Question)>,
    /// Malformed recognised text.
    pub bad: Vec<String>,
}

/// Classify every record of `tx`.
pub fn classify(tx: &Transaction) -> Classified {
    let mut out = Classified::default();
    for (v, text) in records_of(tx) {
        if text.starts_with("issue:") {
            match parse_issue(&text) {
                Some(r) => out.issues.push((v, r)),
                None => out.bad.push(text),
            }
        } else if text.starts_with("tally:") {
            match parse_tally(&text) {
                Some(r) => out.tallies.push((v, r)),
                None => out.bad.push(text),
            }
        } else if text.starts_with("pool:") {
            match parse_pool(&text) {
                Some(r) => out.pools.push((v, r)),
                None => out.bad.push(text),
            }
        } else if ["market:", "split:", "merge:", "redeem:", "resolve:"]
            .iter()
            .any(|prefix| text.starts_with(prefix))
        {
            match parse_market(&text) {
                Some(r) => out.markets.push((v, r)),
                None => out.bad.push(text),
            }
        } else if text.starts_with("question:") {
            match parse_question(&text) {
                Some(r) => out.questions.push((v, r)),
                None => out.bad.push(text),
            }
        }
    }
    out
}

/// The `tally:` text for `asset` (`None` = `self`) assigning `assigns`.
/// Amounts of zero are left out; an empty result is [`Error::Encoding`].
pub fn tally_text(asset: Option<&Txid>, assigns: &[(u32, u64)]) -> Result<String> {
    let parts: Vec<String> = assigns
        .iter()
        .filter(|(_, a)| *a > 0)
        .map(|(v, a)| format!("{v}={a}"))
        .collect();
    if parts.is_empty() {
        return Err(Error::Encoding(
            "a tally assigns at least one output".into(),
        ));
    }
    if let Some((_, a)) = assigns.iter().find(|(_, a)| *a > MAX_AMOUNT) {
        return Err(Error::Encoding(format!("{a} is above the largest amount")));
    }
    let id = asset.map_or_else(|| "self".to_string(), |t| t.to_string());
    Ok(format!("tally:{id}:{}", parts.join(",")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_scripts_round_trip_and_are_minimal() {
        let short = record_script("tip:nostr:ab").unwrap();
        assert_eq!(&short.as_bytes()[..2], &[0x6a, 12]);
        let long = "x".repeat(200);
        let s = record_script(&long).unwrap();
        assert_eq!(&s.as_bytes()[..3], &[0x6a, 0x4c, 200]);
        assert_eq!(record_text(&s).unwrap(), long);
        assert!(record_script(&"x".repeat(256)).is_err());
        assert!(record_script("").is_err());
        // a non-minimal PUSHDATA1 of 3 bytes is not a record
        let nm = ScriptBuf::from_bytes(vec![0x6a, 0x4c, 3, b'a', b'b', b'c']);
        assert_eq!(record_text(&nm), None);
        // not UTF-8
        let bin = ScriptBuf::from_bytes(vec![0x6a, 2, 0xff, 0xfe]);
        assert_eq!(record_text(&bin), None);
        // trailing bytes after the push
        let trail = ScriptBuf::from_bytes(vec![0x6a, 1, b'a', 0x51]);
        assert_eq!(record_text(&trail), None);
    }

    #[test]
    fn issue_grammar() {
        assert!(parse_issue("issue:A:8").is_some());
        assert!(parse_issue("issue:ABCDEFGH:0").is_some());
        assert!(parse_issue("issue:ABCDEFGHI:0").is_none());
        assert!(parse_issue("issue:dream:0").is_none());
        assert!(parse_issue("issue:DREAM:9").is_none());
        assert!(parse_issue("issue::0").is_none());
    }

    #[test]
    fn tally_grammar() {
        let id = "ab".repeat(32);
        let t = parse_tally(&format!("tally:{id}:0=5,2=7")).unwrap();
        assert_eq!(t.assigns, vec![(0, 5), (2, 7)]);
        assert!(parse_tally(&format!("tally:{id}:0=5,0=7")).is_none());
        assert!(parse_tally(&format!("tally:{id}:0=0")).is_none());
        assert!(parse_tally(&format!("tally:{id}:0=05")).is_none());
        assert!(parse_tally(&format!("tally:{id}:123456=5")).is_none());
        assert!(parse_tally(&format!("tally:{}:0=5", "AB".repeat(32))).is_none());
        assert!(parse_tally(&format!("tally:{id}:0={}", MAX_AMOUNT + 1)).is_none());
        assert!(parse_tally(&format!("tally:{id}:0={MAX_AMOUNT}")).is_some());
    }

    #[test]
    fn tally_text_writes_what_parse_reads() {
        let id: Txid = "cd".repeat(32).parse().unwrap();
        let t = tally_text(Some(&id), &[(0, 10), (1, 0), (2, 3)]).unwrap();
        assert_eq!(t, format!("tally:{id}:0=10,2=3"));
        assert_eq!(parse_tally(&t).unwrap().asset, AssetRef::Id(id));
        assert_eq!(tally_text(None, &[(0, 1)]).unwrap(), "tally:self:0=1");
        assert!(tally_text(None, &[(0, 0)]).is_err());
    }

    #[test]
    fn market_and_question_grammar() {
        let id = "ab".repeat(32);
        let resolver = "cd".repeat(32);
        assert_eq!(
            parse_market(&format!("market:self:12:{resolver}:150000:20")),
            Some(MarketRecord::Open {
                vout: 12,
                resolver,
                expiry: 150_000,
                grace: 20,
            })
        );
        assert!(matches!(
            parse_market(&format!("split:{id}:0")),
            Some(MarketRecord::Split { vout: 0, .. })
        ));
        assert!(matches!(
            parse_market(&format!("resolve:{id}:no")),
            Some(MarketRecord::Resolve {
                outcome: MarketOutcome::No,
                ..
            })
        ));
        assert!(parse_market(&format!("market:self:0:{}:1:1", "CD".repeat(32))).is_none());
        assert!(parse_market(&format!("split:{}:0", "AB".repeat(32))).is_none());
        assert!(parse_market(&format!("resolve:{id}:maybe")).is_none());
        assert_eq!(
            parse_question("question:Will it rain?"),
            Some(Question {
                text: "Will it rain?".into()
            })
        );
        assert!(parse_question("question:").is_none());
        assert!(parse_question(&format!("question:{}", "é".repeat(101))).is_none());
    }
}
