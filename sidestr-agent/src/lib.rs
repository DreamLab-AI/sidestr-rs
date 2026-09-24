//! `sidestr-agent`: an agent wallet for sidestr sidechains, where **a
//! did:nostr key is the wallet**.
//!
//! A Nostr identity is a secp256k1 key whose x-only public key is the
//! `did:nostr:<hex>` identifier and the `npub`. On a sidestr chain that same
//! 32-byte x-only key is a taproot output key: its coins pay `OP_1
//! <pubkey>` (`5120‖pubkey`, the key used untweaked, as siding's wallet does),
//! and its address is that script in bech32m under the chain's
//! `addressPrefix`. So an agent needs no second key. It reads its balance
//! from a producer, pays another agent by `npub`, and signs the spend with
//! the key its identity already holds. The kind-23500 event that carries the
//! transaction to the producer's relays is signed with the same key, so the
//! event names the agent that paid.
//!
//! This crate is the library behind the `sidestr-agent` binary. The binary is
//! a generalisation of the tool that ran the first live loop on
//! `sidestr:dreamlab`, beside Bitcoin testnet4. That loop was a peg-in, three
//! trades between two agents as kind-23500 events each signed by its agent's
//! own Nostr key, and a peg-out. Everything here is for **testnet4 and
//! experimental sidechains**: coins on `sidestr:dreamlab` have no value.
//!
//! | item | what |
//! |---|---|
//! | [`AgentKey`] | the secret: a key file as 64 hex characters or an `nsec` (NIP-19) |
//! | [`parse_pubkey`], [`npub`], [`Identity`] | `npub` / hex / `did:nostr:` ↔ x-only key ↔ script ↔ chain address |
//! | [`destination`], [`refuse_secret`] | a pay-to: an `npub`, a `did:nostr:`, a chain address or a script hex; never secret-shaped text |
//! | [`prepare`] | a spend or peg-out burn, signed by the key, and its kind-23500 event, signed by the same key |
//! | [`ChainView`] | a mirror's block file replayed, with the SPEC 12 assets view: coins, plain coins, asset balances |
//! | [`prepare_transfer`], [`prepare_issue`] | move or issue an asset (with memo records such as `tip:nostr:<event id>`), and the event |
//! | [`pegin_plan`] | what a parent wallet pays to peg in: the peg address (and its refund descriptor), the marker |
//!
//! It is a port in the AGPL sense: it builds on `sidestr-core`,
//! `sidestr-wallet` and `sidestr-nostr`, which port **siding**, the
//! reference implementation by Melvin Carvalho
//! (<https://github.com/sidestr/spec>). It carries the same licence,
//! AGPL-3.0-only.
//!
//! # An agent pays another agent by npub
//!
//! ```
//! use bitcoin::secp256k1::SecretKey;
//! use sidestr_agent::{destination, identity, prepare, AgentKey, Payment};
//! use sidestr_core::block::{challenge_for, pubkey_of};
//! use sidestr_core::document::{ChainDocument, Peg};
//! use sidestr_core::state::{NextBlock, State};
//! use sidestr_wallet::coins::from_state;
//!
//! // two agents: the key file text is what an agent keeps (hex, or an nsec)
//! let alice = AgentKey::parse(&"11".repeat(32)).unwrap();
//! let bob = AgentKey::parse(&"22".repeat(32)).unwrap();
//!
//! // a throwaway chain whose genesis pegs alice's script; the producer's key seals blocks
//! let producer = SecretKey::from_slice(&[7u8; 32]).unwrap();
//! let json = format!(r#"{{"id":"sidestr:example","name":"example","parent":"tbtc4","challenge":"{}",
//!   "powLimit":"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","addressPrefix":"ex",
//!   "genesisTime":1790000000,"signer":"{}","pegs":[]}}"#, challenge_for(&pubkey_of(&producer)).to_hex_string(), pubkey_of(&producer));
//! let mut doc = ChainDocument::from_json(&json).unwrap();
//! doc.pegs.push(Peg { txid: "a".repeat(64), vout: 0, amount: 100_000, script: alice.script().to_hex_string(), extra: Default::default() });
//! let mut chain = State::with_key(doc.clone(), &producer).unwrap();
//! for i in 1..=100 { chain.produce(&producer, &NextBlock { time: 1790000000 + i, claims: vec![] }, None).unwrap(); }
//!
//! // alice's did:nostr key is her wallet: the same x-only key, the same script
//! let me = identity(&alice.pubkey(), "ex").unwrap();
//! assert_eq!(me.did, format!("did:nostr:{}", alice.pubkey()));
//! assert_eq!(me.script, format!("5120{}", alice.pubkey()));
//!
//! // pay bob by his npub; the event carrying the transaction is signed by alice's key too
//! let to = destination(&identity(&bob.pubkey(), "ex").unwrap().npub).unwrap();
//! let coins = from_state(&chain, &alice.script());
//! let p = prepare(&alice, &doc, &coins, chain.height(), Payment::Send, &to, 30_000, None, 1_790_000_200).unwrap();
//! assert!(p.event.verify().is_ok() && p.event.pubkey == alice.pubkey().to_string());
//! assert_eq!(p.event.kind, 23500);
//! chain.submit(p.spend.tx.clone()).unwrap(); // the producer's mempool check
//! ```

#![forbid(unsafe_code)]
#![deny(
    missing_docs,
    missing_debug_implementations,
    rustdoc::broken_intra_doc_links
)]

use std::str::FromStr;

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32, Hrp};
use bitcoin::key::XOnlyPublicKey;
use bitcoin::secp256k1::SecretKey;
use bitcoin::Txid;
use bitcoin::{Address, ScriptBuf};
use serde::Serialize;
use sidestr_core::address::script_to_address;
use sidestr_core::assets::{AssetView, Issued};
use sidestr_core::block::{key_from_hex, pubkey_of};
use sidestr_core::document::ChainDocument;
use sidestr_core::federation::Federation;
use sidestr_core::parent::parent_network;
use sidestr_core::state::State;
use sidestr_nostr::event::{Event, SecretKeySigner};
use sidestr_nostr::tx::sign_transaction_event;
use sidestr_wallet::asset::{
    balance_of, build_issue, build_transfer, plain_coins, IssueRequest, TransferRequest,
};
use sidestr_wallet::burn::{build_burn, BurnRequest};
use sidestr_wallet::coins::from_state;
use sidestr_wallet::coins::Coin;
use sidestr_wallet::key::{script_for, PlainKey};
use sidestr_wallet::pegin::build_pegin;
use sidestr_wallet::spend::{build_spend, Spend, SpendRequest};
use sidestr_wallet::Permissive;

/// What can go wrong.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A key file or key argument that is neither 64 hex characters, an
    /// `nsec`, an `npub` nor a `did:nostr:` identifier. The text is never
    /// echoed: it may be a secret.
    #[error("not a key: {0}")]
    Key(&'static str),
    /// A destination that is none of the accepted forms.
    #[error("not a destination: {0}")]
    Destination(String),
    /// The peg-in plan cannot be made as asked.
    #[error("peg-in plan: {0}")]
    Plan(String),
    /// A consensus or document error.
    #[error(transparent)]
    Core(#[from] sidestr_core::Error),
    /// The wallet refused to build.
    #[error(transparent)]
    Wallet(#[from] sidestr_wallet::Error),
    /// The event could not be made.
    #[error(transparent)]
    Nostr(#[from] sidestr_nostr::Error),
    /// Reading a key file.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// This crate's result.
pub type Result<T> = core::result::Result<T, Error>;

const NSEC: Hrp = Hrp::parse_unchecked("nsec");
const NPUB: Hrp = Hrp::parse_unchecked("npub");

/// A NIP-19 string's payload: Bech32 (not Bech32m, which NIP-19 does not
/// use), under exactly `hrp`. The error is static: the text may be a secret.
fn nip19(text: &str, hrp: Hrp, what: &'static str) -> Result<Vec<u8>> {
    let c = CheckedHrpstring::new::<Bech32>(text).map_err(|_| Error::Key(what))?;
    if c.hrp() != hrp {
        return Err(Error::Key(what));
    }
    Ok(c.byte_iter().collect())
}

/// Whether `text` has the shape of a secret key: an `nsec`, or 32 bytes of
/// bare hex (a key file's form). Such text is never a destination here; it
/// is refused before it can reach an error message, a log, or an output
/// script on the chain.
fn looks_secret(text: &str) -> bool {
    let t = text.trim();
    t.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("nsec1"))
        || (t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Refuse secret-shaped text where a destination or an address is expected
/// (see [`destination`]); the error names what to use and never echoes it.
pub fn refuse_secret(text: &str) -> Result<&str> {
    if looks_secret(text) {
        return Err(Error::Destination(
            "that looks like a secret key (an nsec, or 64 hex characters), which is never a \
             destination: use an npub1…, a did:nostr:<hex>, an address, or a full script hex \
             such as 5120…"
                .into(),
        ));
    }
    Ok(text)
}

/// An agent's secret key: its Nostr identity, and so its wallet. `Debug`
/// prints the public key only.
#[derive(Clone)]
pub struct AgentKey {
    secret: SecretKey,
}

impl core::fmt::Debug for AgentKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AgentKey")
            .field("pubkey", &self.pubkey())
            .finish_non_exhaustive()
    }
}

impl AgentKey {
    /// From a key file's text: 64 hex characters (siding's
    /// `~/.sidestr/<name>.key`) or a NIP-19 `nsec1…`. Surrounding whitespace
    /// is ignored.
    ///
    /// ```
    /// use sidestr_agent::AgentKey;
    /// // NIP-19's published vector: this nsec is this hex secret
    /// let a = AgentKey::parse("nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5").unwrap();
    /// let b = AgentKey::parse("67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa\n").unwrap();
    /// assert_eq!(a.pubkey(), b.pubkey());
    /// assert!(AgentKey::parse("npub1…").is_err());
    /// ```
    pub fn parse(text: &str) -> Result<Self> {
        let t = text.trim();
        let secret = if t.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("nsec1")) {
            let bytes = nip19(t, NSEC, "not a Bech32 nsec (NIP-19)")?;
            SecretKey::from_slice(&bytes).map_err(|_| Error::Key("an nsec of the wrong length"))?
        } else {
            key_from_hex(t).map_err(|_| Error::Key("want 64 hex characters or an nsec1…"))?
        };
        Ok(Self { secret })
    }

    /// From the 32 secret bytes held in memory (a browser session's key).
    /// The error does not echo the bytes.
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let secret =
            SecretKey::from_slice(bytes).map_err(|_| Error::Key("not a secp256k1 secret key"))?;
        Ok(Self { secret })
    }

    /// Read and parse a key file.
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self> {
        Self::parse(&std::fs::read_to_string(path)?)
    }

    /// The x-only public key: the `did:nostr` identifier, the `npub`, and
    /// the taproot output key its coins pay.
    pub fn pubkey(&self) -> XOnlyPublicKey {
        pubkey_of(&self.secret)
    }

    /// The script the agent's coins pay: `OP_1 <pubkey>`.
    pub fn script(&self) -> ScriptBuf {
        script_for(&self.pubkey())
    }

    /// The key as the wallet's spend signer.
    pub fn spend_signer(&self) -> PlainKey {
        PlainKey::new(self.secret)
    }

    /// The key as a Nostr event signer.
    pub fn event_signer(&self) -> SecretKeySigner {
        SecretKeySigner::from_bytes(&self.secret.secret_bytes())
            .expect("a valid secret key is a valid signer")
    }
}

/// An x-only key from `npub1…`, `did:nostr:<hex>` or 64 hex characters.
///
/// ```
/// use sidestr_agent::parse_pubkey;
/// // NIP-19's published vector
/// let k = parse_pubkey("npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg").unwrap();
/// assert_eq!(k.to_string(), "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e");
/// assert_eq!(parse_pubkey(&format!("did:nostr:{k}")).unwrap(), k);
/// ```
pub fn parse_pubkey(text: &str) -> Result<XOnlyPublicKey> {
    let t = text.trim();
    let bytes = if t.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("npub1")) {
        nip19(t, NPUB, "not a Bech32 npub (NIP-19)")?
    } else {
        let h = t.strip_prefix("did:nostr:").unwrap_or(t);
        if h.len() != 64 {
            return Err(Error::Key(
                "want an npub1…, did:nostr:<hex> or 64 hex characters",
            ));
        }
        hex::decode(h).map_err(|_| Error::Key("not hex"))?
    };
    XOnlyPublicKey::from_slice(&bytes).map_err(|_| Error::Key("not a point on secp256k1"))
}

/// The NIP-19 `npub` of a key.
pub fn npub(key: &XOnlyPublicKey) -> String {
    bech32::encode::<Bech32>(NPUB, &key.serialize()).expect("32 bytes fit an npub")
}

/// One key, every name it goes by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Identity {
    /// NIP-19.
    pub npub: String,
    /// The x-only key, hex.
    pub pubkey: String,
    /// `did:nostr:<hex>`.
    pub did: String,
    /// The script its coins pay, hex: `5120‖pubkey`.
    pub script: String,
    /// That script as an address under the chain's prefix.
    pub address: String,
}

/// Every name of `key` on a chain whose `addressPrefix` is `prefix`; `None`
/// for a prefix bech32 cannot carry.
pub fn identity(key: &XOnlyPublicKey, prefix: &str) -> Option<Identity> {
    let script = script_for(key);
    Some(Identity {
        npub: npub(key),
        pubkey: key.to_string(),
        did: format!("did:nostr:{key}"),
        address: script_to_address(&script, prefix)?,
        script: script.to_hex_string(),
    })
}

/// A destination in the form the wallet takes (a script hex or an address
/// under any prefix): an `npub` or a `did:nostr:` becomes its key's `5120`
/// script; anything else passes through for the wallet to judge — except
/// secret-shaped text ([`refuse_secret`]). A bare 64-hex string is refused
/// too: it may be a key file's secret, and the wallet would otherwise read
/// it as a 32-byte script and publish it in an output. A key is named as an
/// `npub` or a `did:nostr:`, a script by its full hex.
///
/// ```
/// use sidestr_agent::destination;
/// assert!(destination("nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5").is_err());
/// assert!(destination(&"ab".repeat(32)).is_err());
/// assert_eq!(destination(&format!("did:nostr:{}", "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e")).unwrap(),
///            "51207e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e");
/// ```
pub fn destination(to: &str) -> Result<String> {
    let t = refuse_secret(to)?.trim();
    if t.is_empty() {
        return Err(Error::Destination("empty".into()));
    }
    let lower = t.to_ascii_lowercase();
    if lower.starts_with("npub1") || lower.starts_with("did:nostr:") {
        return Ok(script_for(&parse_pubkey(t)?).to_hex_string());
    }
    Ok(t.to_string())
}

/// What a payment is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Payment {
    /// A spend to a sidechain destination.
    Send,
    /// A peg-out: a burn owed to a parent address (SPEC 7).
    Burn,
}

/// A signed transaction and the signed event that carries it.
#[derive(Debug, Clone)]
pub struct Prepared {
    /// The wallet's spend or burn.
    pub spend: Spend,
    /// Kind 23500, tagged with the chain, content the transaction hex,
    /// signed by the agent's key.
    pub event: Event,
}

/// Build and sign a payment with the agent's key, and the kind-23500 event
/// that carries it, signed with the same key (pure: no network). `to` is a
/// sidechain destination for [`Payment::Send`] (see [`destination`]) and a
/// parent address or script for [`Payment::Burn`]; `created_at` is the
/// event's time.
///
/// `coins` are spent as sats. On a chain where issued assets ride on coins,
/// pass [`ChainView::plain_coins`], never every coin the key holds: a coin
/// spent here carries nothing onward, so an asset on it would be destroyed.
#[allow(clippy::too_many_arguments)]
pub fn prepare(
    key: &AgentKey,
    chain: &ChainDocument,
    coins: &[Coin],
    tip_height: u32,
    what: Payment,
    to: &str,
    amount: u64,
    fee: Option<u64>,
    created_at: u64,
) -> Result<Prepared> {
    let signer = key.spend_signer();
    let spend = match what {
        Payment::Send => build_spend(
            &SpendRequest {
                chain,
                coins,
                tip_height,
                to,
                amount,
                fee,
            },
            &signer,
            &Permissive,
        )?,
        Payment::Burn => build_burn(
            &BurnRequest {
                chain,
                coins,
                tip_height,
                to,
                amount,
                fee,
            },
            &signer,
            &Permissive,
        )?,
    };
    let event = sign_transaction_event(&key.event_signer(), &chain.id, &spend.hex, created_at)?;
    Ok(Prepared { spend, event })
}

/// A chain replayed from a block file and read under the `assets` rule:
/// the UTXO set and what each unspent output carries (SPEC 12). What an
/// agent needs before it moves an issued asset or pays plain sats beside
/// coins that carry one.
#[derive(Debug)]
pub struct ChainView {
    /// The validated chain at the file's last block.
    pub state: State,
    /// What each unspent output carries.
    pub assets: AssetView,
}

impl ChainView {
    /// Replay a block file's bytes (`GET <mirror>/blocks.dat`) against the
    /// chain document the caller trusts. `now` is the clock for the
    /// future-time rule, `None` to skip it. Stock-header chains.
    pub fn replay(doc: ChainDocument, dat: &[u8], now: Option<u32>) -> Result<Self> {
        let mut assets = AssetView::new();
        let state = State::replay_with(doc, dat, now, |_, h, block| {
            assets.apply_transactions(&block.txdata, h);
        })?;
        Ok(Self { state, assets })
    }

    /// The coins a script holds at the tip.
    pub fn coins(&self, script: &bitcoin::Script) -> Vec<Coin> {
        from_state(&self.state, script)
    }

    /// The coins a script holds that carry nothing: what a plain payment
    /// may spend without destroying an asset.
    pub fn plain_coins(&self, script: &bitcoin::Script) -> Vec<Coin> {
        plain_coins(&self.coins(script), &self.assets)
    }

    /// How much of `asset` a script holds.
    pub fn asset_balance(&self, script: &bitcoin::Script, asset: &Txid) -> u64 {
        balance_of(&self.coins(script), &self.assets, asset)
    }

    /// An asset by id, or by ticker (the earliest issued under it).
    pub fn find_asset(&self, text: &str) -> Option<(Txid, Issued)> {
        if let Ok(id) = text.parse::<Txid>() {
            return self.assets.issued().get(&id).map(|i| (id, i.clone()));
        }
        self.assets.by_ticker(text).map(|(id, i)| (*id, i.clone()))
    }
}

/// An asset transfer signed with the agent's key, and the kind-23500 event
/// that carries it: `amount` units of `asset` to `to` (a
/// [`destination`]), with `memos` as records beside the tally. Plain coins
/// pay the fee; no other asset is touched.
#[allow(clippy::too_many_arguments)]
pub fn prepare_transfer(
    key: &AgentKey,
    view: &ChainView,
    asset: Txid,
    to: &str,
    amount: u64,
    memos: &[String],
    fee: Option<u64>,
    created_at: u64,
) -> Result<Prepared> {
    let chain = view.state.document();
    let coins = view.coins(&key.script());
    let t = build_transfer(
        &TransferRequest {
            chain,
            coins: &coins,
            view: &view.assets,
            tip_height: view.state.height(),
            asset,
            to,
            amount,
            memos,
            fee,
        },
        &key.spend_signer(),
        &Permissive,
    )?;
    let event = sign_transaction_event(&key.event_signer(), &chain.id, &t.spend.hex, created_at)?;
    Ok(Prepared {
        spend: t.spend,
        event,
    })
}

/// Issue an asset from the agent's plain coins, its whole supply on one
/// carrier to `to` (the agent itself when `None`), and the kind-23500
/// event. The asset's id is the spend's txid.
#[allow(clippy::too_many_arguments)]
pub fn prepare_issue(
    key: &AgentKey,
    view: &ChainView,
    ticker: &str,
    decimals: u8,
    supply: u64,
    to: Option<&str>,
    fee: Option<u64>,
    created_at: u64,
) -> Result<Prepared> {
    let chain = view.state.document();
    let coins = view.coins(&key.script());
    let spend = build_issue(
        &IssueRequest {
            chain,
            coins: &coins,
            view: &view.assets,
            tip_height: view.state.height(),
            ticker,
            decimals,
            supply,
            to,
            fee,
        },
        &key.spend_signer(),
        &Permissive,
    )?;
    let event = sign_transaction_event(&key.event_signer(), &chain.id, &spend.hex, created_at)?;
    Ok(Prepared { spend, event })
}

/// Whose output the peg is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PegTarget {
    /// A taproot output with this key path and the refund leaf
    /// `and_v(v:pk(refund), older(refundBlocks))` (SPEC 6, item 1). The peg
    /// holders import the descriptor so their wallet owns the output.
    Key(XOnlyPublicKey),
    /// An address the peg holders' wallet already owns (level 1:
    /// `getnewaddress` on the producer's peg wallet), paid as it is.
    Address(String),
}

/// What a parent wallet pays to peg in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeginPlan {
    /// The chain the coins appear on.
    pub chain: String,
    /// Its parent's alias.
    pub parent: String,
    /// Sats to peg.
    pub amount: u64,
    /// The peg output's address on the parent.
    pub peg_address: String,
    /// The output descriptor, with checksum, when the plan made the address:
    /// what the peg holders import (`importdescriptors`) so that their
    /// wallet owns it (SPEC 6, 0.0.3).
    pub descriptor: Option<String>,
    /// Blocks after which the refund key may sweep an unclaimed peg.
    pub refund_blocks: u32,
    /// The sidechain script the marker names, hex.
    pub side_script: String,
    /// The `OP_RETURN` payload, hex: `pegin:<chain id>:<script bytes>`.
    pub marker: String,
    /// Bitcoin Core's `send` outputs: `[{"<peg address>": "<btc>"}, {"data": "<marker>"}]`.
    pub core_send: serde_json::Value,
    /// What the plan means.
    pub note: String,
}

/// The signing key a level-1 document names: its `signer`, else the key of a
/// `5120‖key` challenge. `None` for a level-2 document. This is what
/// [`PegTarget::Key`] takes when the peg holders choose to import a
/// descriptor; [`pegin_plan`] never uses it on its own, because at level 1
/// the peg is whatever the producer's parent wallet owns.
pub fn level1_peg_key(chain: &ChainDocument) -> Result<Option<XOnlyPublicKey>> {
    if Federation::for_document(chain)?.is_some() {
        return Ok(None);
    }
    if let Some(s) = &chain.signer {
        return Ok(Some(parse_pubkey(s)?));
    }
    let c = chain.challenge_script()?;
    if c.is_p2tr() {
        return Ok(Some(
            XOnlyPublicKey::from_slice(&c.as_bytes()[2..34])
                .map_err(|_| Error::Key("the challenge's key is not a point"))?,
        ));
    }
    Ok(None)
}

/// Plan a peg-in (SPEC 6) for a parent wallet to pay: `amount` sats to the
/// peg output and `OP_RETURN pegin:<chain id>:<side script>`, in one parent
/// transaction, outputs in any order. Since 0.0.3 the producer takes the peg
/// to be the output its peg wallet owns, wherever it sits.
///
/// Who owns the peg decides what to pay (SPEC 6):
///
/// - **Level 1:** the producer's parent wallet owns the peg output. Pass
///   [`PegTarget::Address`] with an address that wallet gave
///   (`getnewaddress`); it is paid as it is. With no target, a level-1 plan
///   is refused rather than guessed.
/// - **Level 2:** the peg is the chain's challenge script, which the
///   federation's peg wallet owns. With no target, its address is paid.
/// - [`PegTarget::Key`] is the explicit alternative at either level: the
///   peg address is `tr(<key>, and_v(v:pk(<refund>), older(<refundBlocks>)))`,
///   and the descriptor comes back. It is a peg-in only once the peg holders
///   have imported it (watch-only is enough), so their wallet owns it. Then
///   `refund` may sweep a peg left unclaimed for `refundBlocks`.
///
/// ```
/// use sidestr_agent::{pegin_plan, parse_pubkey, PegTarget};
/// use sidestr_core::document::ChainDocument;
/// use sidestr_core::parent::find_pegin;
///
/// let doc = ChainDocument::from_json(r#"{"id":"sidestr:example","name":"example","parent":"tbtc4",
///   "challenge":"5120c95b519579bda3b5e29f5dca4a0b8f9f1d04d1979d2e4c3a33483a6b34b61d88",
///   "powLimit":"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","addressPrefix":"ex",
///   "genesisTime":1790000000,"refundBlocks":10000,"pegs":[]}"#).unwrap();
/// let refund = parse_pubkey("npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg").unwrap();
/// let side = format!("5120{}", "ab".repeat(32));
/// // level 1: the producer's peg wallet gave this address; it is paid as it is
/// let peg = "tb1palk8spjn20q8fa3gu8p30tx4xl0mqyk7t3497540zjkmt4zdvesq07eq2k";
/// let plan = pegin_plan(&doc, 50_000, &refund, &side, Some(PegTarget::Address(peg.into()))).unwrap();
/// assert_eq!(plan.peg_address, peg);
/// assert!(plan.descriptor.is_none());
/// // with no target, a level-1 plan is refused rather than guessed
/// assert!(pegin_plan(&doc, 50_000, &refund, &side, None).is_err());
/// // the explicit descriptor alternative, for peg holders who import it
/// let key = parse_pubkey("c95b519579bda3b5e29f5dca4a0b8f9f1d04d1979d2e4c3a33483a6b34b61d88").unwrap();
/// let plan = pegin_plan(&doc, 50_000, &refund, &side, Some(PegTarget::Key(key))).unwrap();
/// assert!(plan.descriptor.as_deref().unwrap().starts_with("tr(c95b5195"));
/// assert!(plan.descriptor.as_deref().unwrap().contains("older(10000)"));
/// assert_eq!(plan.core_send[1]["data"], plan.marker);
/// ```
pub fn pegin_plan(
    chain: &ChainDocument,
    amount: u64,
    refund: &XOnlyPublicKey,
    side: &str,
    target: Option<PegTarget>,
) -> Result<PeginPlan> {
    // secret-shaped text is refused before anything else is judged, so no
    // other error can come first and nothing can repeat it
    refuse_secret(side)?;
    if let Some(PegTarget::Address(a)) = &target {
        refuse_secret(a)?;
    }
    let parent = chain.parent()?;
    let network = parent_network(parent).ok_or(sidestr_core::Error::ReservedParent {
        alias: parent.alias,
        label: parent.label,
    })?;
    let side_script = destination(side)?;
    if target.is_none() && Federation::for_document(chain)?.is_none() {
        return Err(Error::Plan(
            "level 1: the peg output is the one the producer's parent wallet owns (SPEC 6): \
             pay an address that wallet gave (--peg-address), or pass --peg-key for a \
             descriptor the peg holders import"
                .into(),
        ));
    }
    let (address, descriptor, note) = match target {
        Some(PegTarget::Key(k)) => {
            let text = format!(
                "tr({k},and_v(v:pk({refund}),older({})))",
                chain.refund_blocks
            );
            let d = miniscript::Descriptor::<XOnlyPublicKey>::from_str(&text)
                .map_err(|e| Error::Plan(format!("descriptor {text}: {e}")))?;
            d.sanity_check()
                .map_err(|e| Error::Plan(format!("descriptor {text}: {e}")))?;
            let a = d
                .address(network)
                .map_err(|e| Error::Plan(format!("descriptor {text}: {e}")))?;
            (
                a.to_string(),
                Some(d.to_string()),
                format!(
                    "the peg holders import the descriptor (importdescriptors, watch-only is enough) so their wallet owns the peg (SPEC 6, 0.0.3); {refund} may sweep it after {} parent blocks unclaimed",
                    chain.refund_blocks
                ),
            )
        }
        Some(PegTarget::Address(a)) => (
            refuse_secret(&a)?.to_string(),
            None,
            "paid to an address the peg holders' wallet owns; the refund is theirs to honour"
                .into(),
        ),
        None => {
            let c = chain.challenge_script()?;
            let a = Address::from_script(&c, network)
                .map_err(|_| Error::Plan("the challenge has no parent address".into()))?;
            (
                a.to_string(),
                None,
                "level 2: the peg is the chain's challenge, which the federation's peg wallet owns (SPEC 6)".into(),
            )
        }
    };
    let p = build_pegin(chain, &address, amount, &side_script)?;
    let core_send = p.core_send_outputs();
    let marker = core_send[1]["data"]
        .as_str()
        .expect("core_send_outputs carries the marker")
        .to_string();
    Ok(PeginPlan {
        chain: chain.id.clone(),
        parent: parent.alias.to_string(),
        amount,
        peg_address: p.peg_address.to_string(),
        descriptor,
        refund_blocks: chain.refund_blocks,
        side_script: p.side_script.to_hex_string(),
        marker,
        core_send,
        note,
    })
}
