//! The chain document's `evm` section (proposals/evm.md): the chain id, the
//! block gas limit the EVM sees and the reserve script deposits pay, each
//! with the reference's default (`evm.mjs evmOverlay`).

use bitcoin::ScriptBuf;
use serde_json::Value;
use sidestr_core::ChainDocument;

use crate::error::{Error, Result};

/// The chain id when the document names none (`evm.mjs`: 21474).
pub const DEFAULT_CHAIN_ID: u64 = 21_474;
/// The block gas limit when the document names none (`evm.mjs`: 30,000,000).
pub const DEFAULT_GAS_LIMIT: u64 = 30_000_000;

/// The rule's parameters for one chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmConfig {
    /// The EIP-155 chain id: `CHAINID`, and what every carried transaction
    /// must be signed for.
    pub chain_id: u64,
    /// The block gas limit the EVM sees (`GASLIMIT`). A transaction may ask
    /// for more: the reference runs each with `skipBlockGasLimitValidation`,
    /// and there is no per-block total either.
    pub gas_limit: u64,
    /// The script a deposit's payment goes to: `evm.reserve`, or the chain's
    /// challenge.
    pub reserve: ScriptBuf,
}

/// A JSON number, or a decimal string, as a `u64` (`Number(…)` and
/// `BigInt(…)` in the reference accept both).
fn integer(v: &Value, what: &str) -> Result<u64> {
    let bad = || Error::Config(format!("evm.{what} must be a whole number, not {v}"));
    match v {
        Value::Number(n) => n.as_u64().ok_or_else(bad),
        Value::String(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
            s.parse().map_err(|_| bad())
        }
        _ => Err(bad()),
    }
}

impl EvmConfig {
    /// The parameters a document gives, with the defaults for what it leaves
    /// out: `{"evm": {"chainId": 21474, "gasLimit": 30000000, "reserve": "<script hex>"}}`.
    ///
    /// ```
    /// use sidestr_core::ChainDocument;
    /// use sidestr_evm::EvmConfig;
    ///
    /// let mut doc: serde_json::Value = serde_json::from_str(include_str!("../../sidestr-core/fixtures/trial/chain.json")).unwrap();
    /// doc["evm"] = serde_json::json!({ "chainId": 777 });
    /// let doc: ChainDocument = serde_json::from_value(doc).unwrap();
    /// let cfg = EvmConfig::from_document(&doc).unwrap();
    /// assert_eq!((cfg.chain_id, cfg.gas_limit), (777, 30_000_000));
    /// assert_eq!(cfg.reserve, doc.challenge_script().unwrap());
    /// ```
    pub fn from_document(doc: &ChainDocument) -> Result<Self> {
        let cfg = match doc.extra.get("evm") {
            None | Some(Value::Null) => serde_json::Map::new(),
            Some(Value::Object(m)) => m.clone(),
            Some(v) => return Err(Error::Config(format!("evm must be an object, not {v}"))),
        };
        let field = |k: &str| cfg.get(k).filter(|v| !v.is_null());
        let chain_id = field("chainId")
            .map(|v| integer(v, "chainId"))
            .transpose()?
            .unwrap_or(DEFAULT_CHAIN_ID);
        let gas_limit = field("gasLimit")
            .map(|v| integer(v, "gasLimit"))
            .transpose()?
            .unwrap_or(DEFAULT_GAS_LIMIT);
        let reserve = match field("reserve") {
            None => doc.challenge_script()?,
            Some(Value::String(h)) => ScriptBuf::from_bytes(
                hex::decode(h)
                    .map_err(|e| Error::Config(format!("evm.reserve is not a hex script: {e}")))?,
            ),
            Some(v) => {
                return Err(Error::Config(format!(
                    "evm.reserve must be a hex script, not {v}"
                )))
            }
        };
        Ok(Self {
            chain_id,
            gas_limit,
            reserve,
        })
    }
}
