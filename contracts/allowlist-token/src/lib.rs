// Copyright (c) 2026 Stellar Compliance Kit contributors
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! `allowlist-token` is a `#![no_std]` Soroban contract that wraps an existing
//! SEP-41 token and only permits `transfer` calls between two addresses that
//! are both present on an on-chain allowlist.
//!
//! **Purpose**: give issuers of permissioned tokens (e.g. RWA or regulated
//! stablecoins) a drop-in gate that blocks transfers to or from addresses
//! that haven't cleared KYC/onboarding, without modifying the underlying
//! token contract's own logic.
//!
//! **Composition**: deploy this contract in front of an issuer's real token
//! and point clients at it instead of the underlying token — cleared
//! transfers are forwarded on via a cross-contract call.
#![no_std]

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, token, Address, BytesN,
    Env, String,
};

/// Extend a persistent allowlist entry when its remaining TTL drops below
/// this many ledgers (~7 days at ~5s/ledger on mainnet).
pub(crate) const ALLOWED_TTL_THRESHOLD: u32 = 120_960; // ~7 days

/// Target remaining TTL after extension (~90 days at ~5s/ledger).
pub(crate) const ALLOWED_TTL_EXTEND_TO: u32 = 1_555_200; // ~90 days

#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// The admin address, set once in `initialize`. Instance storage.
    Admin,
    Token,
    Allowed(Address),
    Paused,
    PendingAdmin,
    PendingUpgrade,
}

/// Delayed contract-upgrade proposal state used by `propose_upgrade` and
/// `commit_upgrade`.
#[contracttype]
#[derive(Clone)]
pub struct UpgradeState {
    pub new_wasm: BytesN<32>,
    pub activated_at: u64,
}

/// Schema version tracked by this contract instance for migration/audit tooling.
pub const SCHEMA_VERSION: u32 = 1;

/// Value stored under `DataKey::Allowed(address)`.
///
/// `expiration_ledger` is the last ledger sequence (inclusive) at which the
/// address is still treated as allowlisted. `None` means the entry never
/// expires and stays valid until an explicit `remove_from_allowlist`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowlistEntry {
    pub expiration_ledger: Option<u32>,
}

#[contractevent]
pub struct AllowAdd {
    #[topic]
    pub address: Address,
}

#[contractevent]
pub struct AllowRemove {
    #[topic]
    pub address: Address,
}

#[contractevent]
pub struct Blocked {
    #[topic]
    pub from: Address,
    #[topic]
    pub to: Address,
    pub amount: i128,
}

#[contractevent]
pub struct AdminTransferred {
    #[topic]
    pub old_admin: Address,
    #[topic]
    pub new_admin: Address,
}

#[contractevent]
pub struct Paused {
    #[topic]
    pub admin: Address,
}

#[contractevent]
pub struct Unpaused {
    #[topic]
    pub admin: Address,
}

#[contracttype]
#[derive(Clone)]
pub struct Metadata {
    pub version: String,
    pub admin: Address,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    NotAuthorized = 3,
    /// Caller supplied an argument that is structurally invalid — e.g. a
    /// negative token amount.
    InvalidInput = 4,
    ContractPaused = 5,
    NoPendingAdmin = 6,
    PendingAdminMismatch = 7,
    UpgradeNotReady = 8,
}

#[contract]
pub struct AllowlistToken;

#[contractimpl]
impl AllowlistToken {
    /// One-time setup. `admin` may manage the allowlist; `token` is the
    /// address of the underlying SEP-41 token contract that real transfers
    /// are forwarded to once both parties clear the allowlist check.
    pub fn initialize(env: Env, admin: Address, token: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Token, &token);
        Ok(())
    }

    /// Returns metadata about this contract instance.
    pub fn metadata(env: Env) -> Result<Metadata, Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        Ok(Metadata {
            version: String::from_str(&env, env!("CARGO_PKG_VERSION")),
            admin,
        })
    }

    /// Add `address` to the allowlist. Admin-only.
    ///
    /// `expiration_ledger` optionally bounds how long the entry stays valid:
    ///
    /// - `None` — the address stays allowlisted until `remove_from_allowlist`.
    /// - `Some(n)` — the address is allowlisted while the current ledger
    ///   sequence is `<= n` and automatically treated as not allowlisted from
    ///   ledger `n + 1` onward, with no explicit removal required.
    ///
    /// Re-adding an address overwrites its previous expiry. Returns
    /// `Error::InvalidInput` if `expiration_ledger` is already in the past.
    pub fn add_to_allowlist(
        env: Env,
        admin: Address,
        address: Address,
        expiration_ledger: Option<u32>,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if let Some(exp) = expiration_ledger {
            if exp < env.ledger().sequence() {
                return Err(Error::InvalidInput);
            }
        }
        let key = DataKey::Allowed(address.clone());
        env.storage()
            .persistent()
            .set(&key, &AllowlistEntry { expiration_ledger });
        env.storage().persistent().extend_ttl(
            &key,
            ALLOWED_TTL_THRESHOLD,
            ALLOWED_TTL_EXTEND_TO,
        );
        AllowAdd { address }.publish(&env);
        Ok(())
    }

    /// Remove `address` from the allowlist. Admin-only.
    pub fn remove_from_allowlist(env: Env, admin: Address, address: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage()
            .persistent()
            .remove(&DataKey::Allowed(address.clone()));
        AllowRemove { address }.publish(&env);
        Ok(())
    }

    /// Propose a new admin. The current admin remains active until the
    /// proposed admin calls `accept_admin`.
    pub fn propose_admin(
        env: Env,
        current_admin: Address,
        new_admin: Address,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &current_admin)?;
        env.storage()
            .instance()
            .set(&DataKey::PendingAdmin, &new_admin);
        Ok(())
    }

    /// Accept a pending admin transfer. Must be called by the proposed admin.
    pub fn accept_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        new_admin.require_auth();

        let pending_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::PendingAdmin)
            .ok_or(Error::NoPendingAdmin)?;
        if pending_admin != new_admin {
            return Err(Error::PendingAdminMismatch);
        }

        let old_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.storage().instance().remove(&DataKey::PendingAdmin);
        AdminTransferred { old_admin, new_admin }.publish(&env);
        Ok(())
    }

    /// Propose a two-step upgrade to `new_wasm` (the replacement contract Wasm).
    ///
    /// Admin-only. The upgrade does **not** take effect immediately: it becomes
    /// committable only once the ledger sequence reaches `activated_at`, which
    /// `propose_upgrade` sets to `current_ledger + delay_ledgers`. This gives the
    /// admin, the compliance officer, and any external watchguard a
    /// `delay_ledgers`-long window to review the proposed Wasm and call
    /// `cancel_upgrade` before it can be installed — the safe "migration path"
    /// required by issue #113, in contrast to `jurisdiction-flag::upgrade`, which
    /// is single-step and issuer-only (see threat model J6).
    pub fn propose_upgrade(
        env: Env,
        admin: Address,
        new_wasm: BytesN<32>,
        delay_ledgers: u32,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let state = UpgradeState {
            new_wasm,
            activated_at: u64::from(env.ledger().sequence())
                .saturating_add(delay_ledgers as u64),
        };
        env.storage().instance().set(&DataKey::PendingUpgrade, &state);
        env.events()
            .publish((soroban_sdk::symbol_short!("upgprop"),), (admin, delay_ledgers));
        Ok(())
    }

    /// Commit a previously proposed upgrade, installing `new_wasm`.
    ///
    /// Admin-only. Errors with `UpgradeNotReady` if no upgrade is pending or if
    /// the current ledger has not yet reached `activated_at`.
    pub fn commit_upgrade(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let state: UpgradeState = env
            .storage()
            .instance()
            .get(&DataKey::PendingUpgrade)
            .ok_or(Error::UpgradeNotReady)?;
        if u64::from(env.ledger().sequence()) < state.activated_at {
            return Err(Error::UpgradeNotReady);
        }
        env.deployer().update_current_contract_wasm(state.new_wasm);
        env.storage().instance().remove(&DataKey::PendingUpgrade);
        env.events()
            .publish((soroban_sdk::symbol_short!("upgcommit"),), (admin,));
        Ok(())
    }

    /// Cancel a pending upgrade. Admin-only.
    pub fn cancel_upgrade(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().remove(&DataKey::PendingUpgrade);
        Ok(())
    }

    /// Current on-chain schema version (see [`SCHEMA_VERSION`]).
    pub fn schema_version(env: Env) -> u32 {
        SCHEMA_VERSION
    }

    /// Returns true if `address` is currently allowlisted.
    ///
    /// An entry whose `expiration_ledger` has passed (current ledger sequence
    /// is greater than it) is treated as not allowlisted, even though it has
    /// not been explicitly removed.
    ///
    /// Not affected by pause state — reads always succeed.
    pub fn is_allowed(env: Env, address: Address) -> bool {
        let entry: Option<AllowlistEntry> =
            env.storage().persistent().get(&DataKey::Allowed(address));
        match entry {
            None => false,
            Some(AllowlistEntry {
                expiration_ledger: None,
            }) => true,
            Some(AllowlistEntry {
                expiration_ledger: Some(exp),
            }) => env.ledger().sequence() <= exp,
        }
    }

    /// Returns the raw allowlist entry stored for `address`, if any.
    ///
    /// An already-expired entry is still returned here (it is only ignored,
    /// not deleted) — use `is_allowed` for the effective status.
    pub fn get_allowlist_entry(env: Env, address: Address) -> Option<AllowlistEntry> {
        env.storage().persistent().get(&DataKey::Allowed(address))
    }

    /// Pause all mutating operations. Admin-only.
    pub fn pause(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Paused, &true);
        Paused {
            admin: admin.clone(),
        }
        .publish(&env);
        Ok(())
    }

    /// Unpause. Admin-only.
    pub fn unpause(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Paused, &false);
        Unpaused {
            admin: admin.clone(),
        }
        .publish(&env);
        Ok(())
    }

    /// Returns true if the contract is currently paused.
    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    /// Transfer `amount` of the underlying token from `from` to `to`.
    ///
    /// Returns `Ok(false)` without forwarding if either party is not
    /// allowlisted, emitting a `Blocked` event for auditability.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) -> Result<bool, Error> {
        if amount < 0 {
            return Err(Error::InvalidInput);
        }

        if Self::is_paused(env.clone()) {
            return Err(Error::ContractPaused);
        }

        from.require_auth();

        if !Self::is_allowed(env.clone(), from.clone())
            || !Self::is_allowed(env.clone(), to.clone())
        {
            Blocked { from, to, amount }.publish(&env);
            return Ok(false);
        }

        let token_address: Address = env
            .storage()
            .instance()
            .get(&DataKey::Token)
            .ok_or(Error::NotInitialized)?;
        let token_client = token::Client::new(&env, &token_address);
        token_client.transfer(&from, &to, &amount);
        Ok(true)
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn require_admin(env: &Env, admin: &Address) -> Result<(), Error> {
        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        if stored_admin != *admin {
            return Err(Error::NotAuthorized);
        }
        Ok(())
    }
}

#[cfg(test)]
mod test;

#[cfg(test)]
mod fuzz;
