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
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype, Address,
    BytesN, Env, String, Symbol, Vec,
};

/// Batch operations are capped to reduce the chance of a single invocation
/// exceeding Soroban instruction/resource limits. Set to 45 to fit comfortably
/// within Soroban's default per-invocation write-entry budget of ~50.
const MAX_BATCH_SIZE: u32 = 45;

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// The admin address, set once in `initialize`. Instance storage.
    Admin,
    Paused,
    ComplianceOfficer,
    AuditLog,
    SignerSet,
    Denied(Address),
    PendingUpgrade,
    /// Approvals collected so far for one pending signer-set change.
    PendingSignerAction(SignerAction),
}

/// Delayed upgrade proposal state.
#[contracttype]
#[derive(Clone)]
pub struct UpgradeState {
    pub new_wasm: BytesN<32>,
    pub activated_at: u64,
}

/// Current on-chain schema version for this contract instance.
pub const SCHEMA_VERSION: u32 = 1;

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

#[contractclient(name = "AuditLogClient")]
pub trait AuditLogInterface {
    fn record(env: Env, source: Address, kind: Symbol, subject: Address, detail: String);
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

#[contractevent]
pub struct AdminTransferred {
    #[topic]
    pub old_admin: Address,
    #[topic]
    pub new_admin: Address,
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
    ThresholdNotMet = 6,
    InvalidThreshold = 7,
    InvalidSignerSet = 8,
    SignerNotInSet = 9,
    UpgradeNotReady = 10,
    SignerAlreadyExists = 11,
    MultisigNotEnabled = 12,
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
        env.storage().instance().set(&DataKey::Paused, &false);
        Ok(())
    }

    /// Assign the compliance-officer role. Admin-only.
    pub fn set_compliance_officer(
        env: Env,
        admin: Address,
        officer: Address,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::ComplianceOfficer, &officer);
        Ok(())
    }

    /// Revoke the compliance-officer role. Admin-only.
    pub fn revoke_compliance_officer(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().remove(&DataKey::ComplianceOfficer);
        Ok(())
    }

    /// Return the currently assigned compliance officer, if any.
    pub fn get_compliance_officer(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::ComplianceOfficer)
    }

    /// Configure the optional append-only audit log. Admin-only.
    pub fn set_audit_log(env: Env, admin: Address, audit_log: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::AuditLog, &audit_log);
        Ok(())
    }

    /// Reassign the admin role to `new_admin`. Requires auth from
    /// `current_admin`, which must be the stored admin.
    ///
    /// Takes effect immediately: the old admin loses all privileges as soon
    /// as this call succeeds. Deliberately *not* blocked by `pause`, so a
    /// compromised or rotated admin key can always be replaced.
    ///
    /// Emits `AdminTransferred { old_admin, new_admin }`.
    pub fn transfer_admin(
        env: Env,
        current_admin: Address,
        new_admin: Address,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &current_admin)?;
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        AdminTransferred {
            old_admin: current_admin,
            new_admin,
        }
        .publish(&env);
        Ok(())
    }

    /// Propose a two-step upgrade to `new_wasm_hash` (the hash of the
    /// already-uploaded replacement contract Wasm).
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
            activated_at: u64::from(env.ledger().sequence())
                .saturating_add(delay_ledgers as u64),
        };
        env.storage().instance().set(&DataKey::PendingUpgrade, &state);
        env.events()
            .publish((soroban_sdk::symbol_short!("upgprop"),), (admin, delay_ledgers));
        Ok(())
    }

    /// Commit a previously proposed upgrade, installing `new_wasm_hash`.
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

    /// Add `address` to the denylist. Admin or compliance-officer.
    ///
    /// Uses persistent storage with a long TTL to avoid fail-open archival.
    ///
    /// Persistent denylist entries receive an explicit long TTL because their
    /// reads can happen independently of instance-storage activity. Instance
    /// configuration keys do not need the same treatment: Soroban bumps the
    /// instance entry TTL when this contract is invoked.
    pub fn add_to_denylist(env: Env, admin: Address, address: Address) -> Result<(), Error> {
        Self::reject_if_paused(&env)?;
        Self::require_compliance_authority(&env, &admin)?;

        const MAX_TTL: u32 = 6_311_520;
        const THRESHOLD: u32 = MAX_TTL / 2;

        let key = DataKey::Denied(address.clone());
        env.storage().persistent().set(&key, &true);
        env.storage()
            .persistent()
            .extend_ttl(&key, THRESHOLD, MAX_TTL);

        DenyAdd {
            address: address.clone(),
        }
        .publish(&env);
        Self::record_audit(&env, Symbol::new(&env, "deny_add"), &address, "address added to denylist");
        Ok(())
    }

    /// Remove `address` from the denylist. Admin or compliance-officer.
    pub fn remove_from_denylist(env: Env, admin: Address, address: Address) -> Result<(), Error> {
        Self::reject_if_paused(&env)?;
        Self::require_compliance_authority(&env, &admin)?;
        env.storage()
            .persistent()
            .remove(&DataKey::Denied(address.clone()));
        DenyRemove {
            address: address.clone(),
        }
        .publish(&env);
        Self::record_audit(&env, Symbol::new(&env, "deny_remove"), &address, "address removed from denylist");
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

    /// Unified compliance check — returns `true` if `address` is NOT on the
    /// denylist, identical to calling [`check`].
    ///
    /// This entry point implements the shared `ComplianceCheck` interface
    /// (`is_compliant(address) -> bool`) so external contracts can call any
    /// of the three compliance primitives through the same pattern.
    ///
    /// **Not** affected by pause state — reads always succeed.
    pub fn is_compliant(env: Env, address: Address) -> bool {
        Self::check(env, address)
    }

    /// Return whether `address` is currently stored on the denylist.
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

    fn require_compliance_authority(env: &Env, caller: &Address) -> Result<(), Error> {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        if admin == *caller {
            return Ok(());
        }
        if env.storage().instance().get::<DataKey, Address>(&DataKey::ComplianceOfficer)
            == Some(caller.clone())
        {
            return Ok(());
        }
        Err(Error::NotAuthorized)
    }

    fn record_audit(env: &Env, kind: Symbol, subject: &Address, detail: &str) {
        if let Some(audit_log) = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::AuditLog)
        {
            AuditLogClient::new(env, &audit_log).record(
                &env.current_contract_address(),
                &kind,
                subject,
                &String::from_str(env, detail),
            );
        }
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
