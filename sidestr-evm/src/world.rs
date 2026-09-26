//! The account state the rule keeps beside the UTXO set, and its state root:
//! the Merkle-Patricia root of Ethereum's state trie over it (alloy-trie),
//! which is what ethereumjs's `stateManager.getStateRoot()` answers.
//!
//! The world is a plain map. Accounts are written three ways, and each keeps
//! the reference's notion of which accounts exist, which is what the root
//! commits to:
//!
//! - an executed transaction's changes (`commit`), with EIP-161's
//!   rule that an account the transaction touched and left empty is removed
//!   (ethereumjs's journal `cleanup()`);
//! - a deposit (`credit`), which creates the account if need be;
//! - a withdrawal's burn (`zero_balance`), which sets the WITHDRAW
//!   account's balance to zero and *keeps* the account, empty, as
//!   `stateManager.putAccount` does outside any transaction, until a later
//!   transaction touches it.

use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_trie::{root, TrieAccount, EMPTY_ROOT_HASH, KECCAK_EMPTY};
use revm::bytecode::Bytecode;
use revm::state::{AccountInfo, EvmState};
use revm::Database;

/// One account. The default is a new, empty account: no nonce, no
/// balance, the empty code's hash, no storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// The nonce.
    pub nonce: u64,
    /// The balance, in wei.
    pub balance: U256,
    /// The code's keccak-256; that of empty code for an externally owned account.
    pub code_hash: B256,
    /// Storage, without zero values.
    pub storage: BTreeMap<U256, U256>,
}

impl Default for Account {
    fn default() -> Self {
        Self {
            nonce: 0,
            balance: U256::ZERO,
            code_hash: KECCAK_EMPTY,
            storage: BTreeMap::new(),
        }
    }
}

impl Account {
    /// Whether EIP-161 counts it empty: no nonce, no balance, no code.
    pub fn is_empty(&self) -> bool {
        self.nonce == 0 && self.balance.is_zero() && self.code_hash == KECCAK_EMPTY
    }

    /// The root of its storage trie.
    pub fn storage_root(&self) -> B256 {
        if self.storage.is_empty() {
            return EMPTY_ROOT_HASH;
        }
        root::storage_root_unhashed(self.storage.iter().map(|(k, v)| (B256::from(*k), *v)))
    }
}

/// The accounts and the code they hold.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct World {
    accounts: BTreeMap<Address, Account>,
    code: HashMap<B256, Bytes>,
}

impl World {
    /// No accounts: the state before the first block.
    pub fn new() -> Self {
        Self::default()
    }

    /// An account, if it exists.
    pub fn account(&self, address: &Address) -> Option<&Account> {
        self.accounts.get(address)
    }

    /// Every account, by address.
    pub fn accounts(&self) -> impl Iterator<Item = (&Address, &Account)> {
        self.accounts.iter()
    }

    /// An account's code; empty for none.
    pub fn code(&self, address: &Address) -> Bytes {
        self.accounts
            .get(address)
            .and_then(|a| self.code.get(&a.code_hash))
            .cloned()
            .unwrap_or_default()
    }

    /// A storage slot's value; zero for none.
    pub fn storage(&self, address: &Address, slot: U256) -> U256 {
        self.accounts
            .get(address)
            .and_then(|a| a.storage.get(&slot))
            .copied()
            .unwrap_or_default()
    }

    /// The state root: `keccak256(RLP(""))` for no accounts.
    pub fn root(&self) -> B256 {
        root::state_root_unhashed(self.accounts.iter().map(|(a, acct)| {
            (
                *a,
                TrieAccount {
                    nonce: acct.nonce,
                    balance: acct.balance,
                    storage_root: acct.storage_root(),
                    code_hash: acct.code_hash,
                },
            )
        }))
    }

    /// Add `wei` to an account, creating it (`evm.mjs`: a deposit's
    /// `getAccount(addr) ?? new Account()`, then `putAccount`).
    pub(crate) fn credit(&mut self, address: Address, wei: U256) {
        let a = self.accounts.entry(address).or_default();
        a.balance = a.balance.saturating_add(wei);
    }

    /// Set an existing account's balance to zero, keeping the account
    /// (`evm.mjs`: the WITHDRAW account after a withdrawal).
    pub(crate) fn zero_balance(&mut self, address: &Address) {
        if let Some(a) = self.accounts.get_mut(address) {
            a.balance = U256::ZERO;
        }
    }

    /// Fold one transaction's changes in. An account the transaction did not
    /// touch is as it was; one it destroyed is gone; one it touched and left
    /// empty is gone (EIP-161); a new contract starts with empty storage.
    pub(crate) fn commit(&mut self, changes: EvmState) {
        for (address, account) in changes {
            if !account.is_touched() {
                continue;
            }
            if account.is_selfdestructed() || account.is_empty() {
                self.accounts.remove(&address);
                continue;
            }
            let entry = self.accounts.entry(address).or_default();
            if account.is_created() {
                entry.storage.clear();
            }
            entry.nonce = account.info.nonce;
            entry.balance = account.info.balance;
            entry.code_hash = account.info.code_hash;
            if let Some(code) = &account.info.code {
                if account.info.code_hash != KECCAK_EMPTY {
                    self.code
                        .entry(account.info.code_hash)
                        .or_insert_with(|| code.original_bytes());
                }
            }
            for (slot, value) in account.storage {
                let v = value.present_value();
                if v.is_zero() {
                    entry.storage.remove(&slot);
                } else {
                    entry.storage.insert(slot, v);
                }
            }
        }
    }
}

/// The world as revm reads it. `BLOCKHASH` answers zero for every height,
/// as ethereumjs's mock blockchain does under `createVM` without one.
pub(crate) struct Db<'a>(pub(crate) &'a World);

impl Database for Db<'_> {
    type Error = Infallible;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Infallible> {
        Ok(self.0.accounts.get(&address).map(|a| {
            let code = self
                .0
                .code
                .get(&a.code_hash)
                .map(|b| Bytecode::new_raw(b.clone()))
                .unwrap_or_default();
            AccountInfo::new(a.balance, a.nonce, a.code_hash, code)
        }))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Infallible> {
        Ok(self
            .0
            .code
            .get(&code_hash)
            .map(|b| Bytecode::new_raw(b.clone()))
            .unwrap_or_default())
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Infallible> {
        Ok(self.0.storage(&address, index))
    }

    fn block_hash(&mut self, _number: u64) -> Result<B256, Infallible> {
        Ok(B256::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;

    #[test]
    fn roots() {
        // keccak256(RLP("")): ethereumjs's empty state root
        assert_eq!(
            World::new().root(),
            "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
                .parse::<B256>()
                .unwrap()
        );
        assert_eq!(World::new().root(), keccak256([0x80]));
        let mut w = World::new();
        w.credit(Address::repeat_byte(1), U256::from(5));
        assert_ne!(w.root(), EMPTY_ROOT_HASH);
        // an emptied account stays in the trie: the root differs from no account at all
        w.zero_balance(&Address::repeat_byte(1));
        assert!(w.account(&Address::repeat_byte(1)).unwrap().is_empty());
        assert_ne!(w.root(), EMPTY_ROOT_HASH);
    }
}
