// Copyright (c) 2026 Stellar Compliance Kit contributors
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! `denylist-gate` is a `#![no_std]` Soroban contract that maintains a
//! standalone on-chain denylist.
//!
//! **Purpose**: give issuers a shared, independently auditable place to
//! record addresses that must never transact (sanctions hits, fraud, court
//! orders, etc.), decoupled from any single token contract's own storage.
//!
//! **Callers**: an `admin` address manages the denylist through
//! `add_to_denylist`/`remove_from_denylist`. Other contracts — typically a
//! token's `transfer` function — call the read-only `check(address)` via a
//! cross-contract call before moving funds, so the denylist can be updated
//! without redeploying or touching the token contract itself.
//!
//! **Composition**: this contract is meant to be called into, not deployed
//! as a token itself. See `/examples/denylist-gate-consumer` for a worked
//! example of a token contract wiring `check()` into its `transfer` path.
//!
//! # Authorization model
//!
//! The contract starts in single-admin mode: `admin` (set in `initialize`)
//! authorizes every denylist mutation via `require_auth()`.
//!
//! `initialize_multisig` (admin-only, callable once) additionally installs an
//! M-of-N signer set. From then on the signer set is governed as follows:
//!
//! - `add_signer` and `remove_signer` take the calling `caller` explicitly.
//!   Each call runs `caller.require_auth()` and then requires `caller` to be in
//!   the *current* signer set; any other address is rejected with
//!   `NotAuthorized`.
//! - A change does not take effect on a single signer's say-so. Each call
//!   records one approval from `caller` for that exact action (add X / remove
//!   X). Approvals are per action and de-duplicated per signer, so one signer
//!   calling twice still counts once. The change is applied, and its pending
//!   approvals cleared, only once `threshold` distinct current signers have
//!   approved it.
//! - Removals are validated before an approval is recorded: the set can never
//!   shrink to empty, nor below the threshold (`InvalidSignerSet` /
//!   `InvalidThreshold`).
#![no_std]

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, Address, BytesN, Env, Vec,
};

/// On-chain schema version reported by `schema_version`.
pub const SCHEMA_VERSION: u32 = 1;

/// Batch operations are capped to reduce the chance of a single invocation
/// exceeding Soroban instruction/resource limits.
const MAX_BATCH_SIZE: u32 = 100;

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// The admin address, set once in `initialize`. Instance storage.
    Admin,
    Paused,
    Denied(Address),
    /// A proposed two-step upgrade awaiting `commit_upgrade`.
    PendingUpgrade,
    /// The M-of-N signer set, present once `initialize_multisig` has run.
    SignerSet,
    /// Approvals collected so far for one pending signer-set change.
    PendingSignerAction(SignerAction),
}

/// A proposed upgrade: the new Wasm hash and the ledger it becomes committable.
#[contracttype]
#[derive(Clone)]
pub struct UpgradeState {
    pub new_wasm: BytesN<32>,
    pub activated_at: u32,
}

/// The M-of-N signer set.
#[contracttype]
#[derive(Clone)]
pub struct SignerSet {
    pub signers: Vec<Address>,
    pub threshold: u32,
}

/// A signer-set change that needs `threshold` distinct approvals to apply.
#[contracttype]
#[derive(Clone)]
pub enum SignerAction {
    Add(Address),
    Remove(Address),
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[contractevent]
pub struct DenyAdd {
    #[topic]
    pub address: Address,
}

#[contractevent]
pub struct DenyRemove {
    #[topic]
    pub address: Address,
}

#[contractevent]
pub struct MultisigInitialized {
    pub threshold: u32,
    pub signer_count: u32,
}

#[contractevent]
pub struct SignerApproved {
    #[topic]
    pub signer: Address,
}

#[contractevent]
pub struct SignerAdded {
    #[topic]
    pub signer: Address,
}

#[contractevent]
pub struct SignerRemoved {
    #[topic]
    pub signer: Address,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    NotAuthorized = 3,
    ContractPaused = 4,
    BatchTooLarge = 5,
    UpgradeNotReady = 6,
    InvalidThreshold = 7,
    InvalidSignerSet = 8,
    SignerNotInSet = 9,
    SignerAlreadyExists = 10,
    MultisigNotEnabled = 11,
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct DenylistGate;

#[contractimpl]
impl DenylistGate {
    /// One-time setup. Stores `admin` as the only address allowed to update
    /// the denylist afterward.
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
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
    /// required by issue #114, in contrast to `jurisdiction-flag::upgrade`, which
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
            activated_at: env.ledger().sequence().saturating_add(delay_ledgers),
        };
        env.storage().instance().set(&DataKey::PendingUpgrade, &state);
        env.events().publish((soroban_sdk::symbol_short!("upg_prop"),), (admin, delay_ledgers));
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
        if env.ledger().sequence() < state.activated_at {
            return Err(Error::UpgradeNotReady);
        }
        env.deployer().update_current_contract_wasm(state.new_wasm);
        env.storage().instance().remove(&DataKey::PendingUpgrade);
        env.events().publish((soroban_sdk::symbol_short!("upg_cmt"),), (admin,));
        Ok(())
    }

    /// Cancel a pending upgrade. Admin-only.
    pub fn cancel_upgrade(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().remove(&DataKey::PendingUpgrade);
        Ok(())
    }

    /// Current on-chain schema version (see [`SCHEMA_VERSION`]).
    pub fn schema_version(_env: Env) -> u32 {
        SCHEMA_VERSION
    }

    /// Pause admin mutations (`add_to_denylist` / `remove_from_denylist`).
    /// `check()` continues to work while paused. Admin-only.
    pub fn pause(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Paused, &true);
        Ok(())
    }

    /// Resume admin mutations after a `pause`. Admin-only.
    pub fn unpause(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Paused, &false);
        Ok(())
    }

    /// Add `address` to the denylist. Admin-only.
    ///
    /// Uses persistent storage with a long TTL to avoid fail-open archival.
    pub fn add_to_denylist(env: Env, admin: Address, address: Address) -> Result<(), Error> {
        Self::reject_if_paused(&env)?;
        Self::require_admin(&env, &admin)?;

        const MAX_TTL: u32 = 6_311_520;
        const THRESHOLD: u32 = MAX_TTL / 2;

        let key = DataKey::Denied(address.clone());
        env.storage().persistent().set(&key, &true);
        env.storage()
            .persistent()
            .extend_ttl(&key, THRESHOLD, MAX_TTL);

        DenyAdd { address }.publish(&env);
        Ok(())
    }

    /// Remove `address` from the denylist. Admin-only.
    pub fn remove_from_denylist(env: Env, admin: Address, address: Address) -> Result<(), Error> {
        Self::reject_if_paused(&env)?;
        Self::require_admin(&env, &admin)?;
        env.storage()
            .persistent()
            .remove(&DataKey::Denied(address.clone()));
        DenyRemove {
            address: address.clone(),
        }
        .publish(&env);
        Ok(())
    }

    /// Remove every address in `addresses` from the denylist. Admin-only.
    pub fn remove_multiple_from_denylist(
        env: Env,
        admin: Address,
        addresses: Vec<Address>,
    ) -> Result<(), Error> {
        Self::reject_if_paused(&env)?;
        Self::require_admin(&env, &admin)?;
        if addresses.len() > MAX_BATCH_SIZE {
            return Err(Error::BatchTooLarge);
        }

        for address in addresses.iter() {
            env.storage()
                .persistent()
                .remove(&DataKey::Denied(address.clone()));
            DenyRemove { address }.publish(&env);
        }
        Ok(())
    }

    /// Returns `true` if `address` is clear to transact, i.e. it is NOT on
    /// the denylist. This is the function other contracts should call via
    /// cross-contract invocation before proceeding with a transfer.
    ///
    /// **Not** affected by pause state — reads always succeed.
    pub fn check(env: Env, address: Address) -> bool {
        !env.storage()
            .persistent()
            .get(&DataKey::Denied(address))
            .unwrap_or(false)
    }

    /// Returns `true` if `address` is on the denylist. Inverse of `check`.
    pub fn is_denylisted(env: Env, address: Address) -> bool {
        !Self::check(env, address)
    }

    /// Install an M-of-N signer set. Admin-only; callable once.
    ///
    /// `signers` must be non-empty and free of duplicates, and `threshold`
    /// must be between 1 and `signers.len()`.
    pub fn initialize_multisig(
        env: Env,
        admin: Address,
        signers: Vec<Address>,
        threshold: u32,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if env.storage().instance().has(&DataKey::SignerSet) {
            return Err(Error::AlreadyInitialized);
        }
        if signers.is_empty() {
            return Err(Error::InvalidSignerSet);
        }
        if threshold == 0 || threshold > signers.len() {
            return Err(Error::InvalidThreshold);
        }
        for (i, signer) in signers.iter().enumerate() {
            for other in signers.iter().skip(i + 1) {
                if signer == other {
                    return Err(Error::InvalidSignerSet);
                }
            }
        }

        let signer_count = signers.len();
        env.storage()
            .instance()
            .set(&DataKey::SignerSet, &SignerSet { signers, threshold });
        MultisigInitialized {
            threshold,
            signer_count,
        }
        .publish(&env);
        Ok(())
    }

    /// Approve adding `new_signer` to the signer set. `caller` must authorize
    /// the call and be in the current signer set. The signer is added once
    /// `threshold` distinct signers have approved this exact action.
    pub fn add_signer(env: Env, caller: Address, new_signer: Address) -> Result<(), Error> {
        let signer_set = Self::require_signer(&env, &caller)?;
        if Self::contains(&signer_set.signers, &new_signer) {
            return Err(Error::SignerAlreadyExists);
        }
        Self::approve(&env, caller, SignerAction::Add(new_signer), signer_set)
    }

    /// Approve removing `signer_to_remove` from the signer set. `caller` must
    /// authorize the call and be in the current signer set. The signer is
    /// removed once `threshold` distinct signers have approved this exact
    /// action. The set may never become empty or smaller than the threshold.
    pub fn remove_signer(
        env: Env,
        caller: Address,
        signer_to_remove: Address,
    ) -> Result<(), Error> {
        let signer_set = Self::require_signer(&env, &caller)?;
        if !Self::contains(&signer_set.signers, &signer_to_remove) {
            return Err(Error::SignerNotInSet);
        }
        if signer_set.signers.len() <= 1 {
            return Err(Error::InvalidSignerSet);
        }
        if signer_set.threshold > signer_set.signers.len() - 1 {
            return Err(Error::InvalidThreshold);
        }
        Self::approve(&env, caller, SignerAction::Remove(signer_to_remove), signer_set)
    }

    /// The current signer set, or empty when multisig is not enabled.
    pub fn signers(env: Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get::<_, SignerSet>(&DataKey::SignerSet)
            .map(|set| set.signers)
            .unwrap_or_else(|| Vec::new(&env))
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn contains(signers: &Vec<Address>, address: &Address) -> bool {
        signers.iter().any(|s| s == *address)
    }

    /// Requires `caller`'s authorization and membership in the current signer
    /// set; returns that set.
    fn require_signer(env: &Env, caller: &Address) -> Result<SignerSet, Error> {
        caller.require_auth();
        let signer_set: SignerSet = env
            .storage()
            .instance()
            .get(&DataKey::SignerSet)
            .ok_or(Error::MultisigNotEnabled)?;
        if !Self::contains(&signer_set.signers, caller) {
            return Err(Error::NotAuthorized);
        }
        Ok(signer_set)
    }

    /// Records `caller`'s approval of `action` and applies it once `threshold`
    /// distinct signers have approved.
    fn approve(
        env: &Env,
        caller: Address,
        action: SignerAction,
        mut signer_set: SignerSet,
    ) -> Result<(), Error> {
        let key = DataKey::PendingSignerAction(action.clone());
        let mut approvals: Vec<Address> = env
            .storage()
            .instance()
            .get(&key)
            .unwrap_or_else(|| Vec::new(env));
        if !Self::contains(&approvals, &caller) {
            approvals.push_back(caller.clone());
        }
        SignerApproved { signer: caller }.publish(env);

        // Only approvals from signers still in the set count towards the threshold.
        let mut valid = 0u32;
        for approver in approvals.iter() {
            if Self::contains(&signer_set.signers, &approver) {
                valid += 1;
            }
        }
        if valid < signer_set.threshold {
            env.storage().instance().set(&key, &approvals);
            return Ok(());
        }

        env.storage().instance().remove(&key);
        match action {
            SignerAction::Add(new_signer) => {
                signer_set.signers.push_back(new_signer.clone());
                env.storage().instance().set(&DataKey::SignerSet, &signer_set);
                SignerAdded { signer: new_signer }.publish(env);
            }
            SignerAction::Remove(removed) => {
                let mut remaining = Vec::new(env);
                for signer in signer_set.signers.iter() {
                    if signer != removed {
                        remaining.push_back(signer);
                    }
                }
                signer_set.signers = remaining;
                env.storage().instance().set(&DataKey::SignerSet, &signer_set);
                SignerRemoved { signer: removed }.publish(env);
            }
        }
        Ok(())
    }

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

    fn reject_if_paused(env: &Env) -> Result<(), Error> {
        if env
            .storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
        {
            return Err(Error::ContractPaused);
        }
        Ok(())
    }
}

#[cfg(test)]
mod test;

#[cfg(test)]
mod fuzz_test;
