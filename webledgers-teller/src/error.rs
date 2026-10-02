//! The one error type every fallible function in this crate returns.
//!
//! The teller throws with a sentence a person reads (`'a withdrawal is at
//! least 546 sat'`) and its tests match on those words. Every refusal here is
//! a named variant whose `Display` is the teller's sentence, word for word,
//! so a page can show it and a test can match either the variant or the
//! text. The variants this port adds (the ledger event, which the teller's
//! page reads, and the boundaries Rust types make explicit) say so.

/// Everything the teller refuses, in its own words.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// `accountOf`: not `did:nostr:<x>`, a bare x or a did:nostr Multikey.
    #[error("an account is a did:nostr identifier (did:nostr:<64 hex>)")]
    Account,
    /// `sats`: not a whole number of satoshis between 0 and 21 million coins.
    #[error("an amount is a whole number of satoshis")]
    Amount,
    /// `newLedger`: the name is empty or longer than 80 characters.
    #[error("a ledger has a name of up to 80 characters")]
    Name,
    /// `checkLedger`: not a `WebLedger`, or no genesis.
    #[error("not a Web Ledger with a genesis")]
    NotALedger,
    /// `checkLedger`: the stored hash is not the hash of the genesis.
    #[error("the ledger's hash is not the hash of its genesis")]
    HashMismatch,
    /// `credit`: the outpoint is not `<64 lowercase hex>:<vout>`.
    #[error("a deposit is an outpoint txid:vout")]
    Outpoint,
    /// `transfer`: an amount of zero.
    #[error("a transfer moves at least one satoshi")]
    ZeroTransfer,
    /// `transfer`, `debit`: the account holds less than the amount.
    #[error("{account}… has {has} sat, not {wanted}")]
    Insufficient {
        /// The first 20 characters of the account's did (`did:nostr:` and
        /// ten hex digits), as the teller writes it.
        account: String,
        /// The balance the account holds.
        has: u64,
        /// The amount asked for.
        wanted: u64,
    },
    /// `debit`: below [`crate::MIN_PAY`].
    #[error("a withdrawal is at least 546 sat")]
    WithdrawalTooSmall,
    /// `depositAddress`: the ledger hash is not 64 lowercase hex.
    #[error("ledgerHash is the ledger's 32-byte hash")]
    DepositLedgerHash,
    /// `requestTags`: the ledger hash is not 64 lowercase hex.
    #[error("ledgerHash is the ledger's hash")]
    RequestLedgerHash,
    /// `requestTags`: an op other than join, withdraw or transfer.
    #[error("op is join, withdraw or transfer")]
    Op,
    /// `requestTags`, `parseRequest`: a withdrawal or transfer with no `to`.
    #[error("a withdrawal or transfer names where to")]
    NoDestination,
    /// `parseRequest`: not kind 3700.
    #[error("not a request (kind 3700)")]
    NotARequest,
    /// `parseRequest`: the id or the signature does not verify.
    #[error("the request does not verify")]
    Unverified,
    /// `parseRequest`: the `ledger` tag names another ledger.
    #[error("a request for another ledger")]
    OtherLedger,
    /// `parseRequest`: no valid op, or no id of 8 to 64 lowercase hex.
    #[error("a request has an op and an id")]
    OpAndId,
    /// `planPayout`: below [`crate::MIN_PAY`].
    #[error("a payout is at least 546 sat")]
    PayoutTooSmall,
    /// `planPayout`: a fee rate outside 1 to 1000 sat/vB.
    #[error("rate 1 to 1000 sat/vB")]
    Rate,
    /// `planPayout`: every coin together cannot pay the amount and the fee.
    #[error("the deposits held ({held} sat) do not cover {amount} sat and the fee")]
    NotCovered {
        /// The sum of every coin offered.
        held: u64,
        /// The amount to pay.
        amount: u64,
    },
    /// `signPayout`: an input failed the chain's script check.
    #[error("input {input} did not pass the script check ({reason}); nothing was paid")]
    ScriptCheck {
        /// The input's index.
        input: usize,
        /// The verifier's reason.
        reason: String,
    },
    /// `signPayout`: the signed transaction is bigger than the fee pays for.
    #[error("the signed payout is {vsize} vB, so its fee of {fee} sat is below {rate} sat/vB; nothing was paid")]
    FeeBelowRate {
        /// The signed transaction's virtual size.
        vsize: u64,
        /// The plan's fee.
        fee: u64,
        /// The plan's rate.
        rate: u64,
    },
    /// A key, point, tweak or scalar refused by the key rule
    /// (`sidestr/spec siding/lib/keys.mjs`), in its words.
    #[error("{0}")]
    Key(&'static str),
    /// Not a segwit script under that prefix (`address.mjs scriptToAddress`
    /// returns `null`; this port refuses).
    #[error("no address for that script under prefix {0:?}")]
    Address(String),
    /// A script or txid that is not hex of the right shape (this port: the
    /// teller writes whatever it is given and the kernel's codec refuses it).
    #[error("{what}: {reason}")]
    Encoding {
        /// Which field.
        what: &'static str,
        /// Why it was refused.
        reason: String,
    },
    /// The chain's signature hash could not be computed for an input.
    #[error("input {input}: {reason}")]
    Sighash {
        /// The input's index.
        input: usize,
        /// The reason the sighash refused.
        reason: &'static str,
    },
    /// A Nostr event could not be built or signed (`sidestr-nostr`'s reason).
    #[error("event: {0}")]
    Event(String),
    /// This port's reading of a ledger event (kind 30333), which the teller's
    /// page does inline: not kind 30333.
    #[error("not a ledger (kind 30333)")]
    NotALedgerEvent,
    /// This port: the ledger event's content is not a ledger document.
    #[error("the ledger event's content is not a ledger: {0}")]
    LedgerContent(String),
    /// This port: a ledger event not signed by the ledger's operator, or for
    /// another ledger (the page drops both: "the operator's own word only").
    #[error("a ledger event that is not the operator's own copy of this ledger")]
    NotTheOperators,
}

/// `Result` with this crate's [`Error`].
pub type Result<T> = core::result::Result<T, Error>;
