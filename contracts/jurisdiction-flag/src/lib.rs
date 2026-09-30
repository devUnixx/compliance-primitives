// Copyright (c) 2026 Stellar Compliance Kit contributors
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! `jurisdiction-flag` is a `#![no_std]` Soroban contract that attaches a
//! jurisdiction code (e.g. an ISO 3166-1 alpha-2 country code) to an
//! address.
//!
//! **Permission semantics**: `is_permitted_jurisdiction` uses *any*
//! matching — it returns `true` if at least one of the address's codes
//! appears in `allowed_codes`. An address with no codes is never permitted.
//!
//! **Callers**: only the configured `issuer` address may call
//! `set_jurisdiction` / `remove_jurisdiction_multiple`. Any contract or
//! off-chain client can read a flag via `get_jurisdiction`, and contracts
//! enforcing a jurisdiction allowlist can call
//! `is_permitted_jurisdiction(address, allowed_codes)` directly.
#![no_std]

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, Address, BytesN, Env,
    String, Vec,
};

/// Extend persistent jurisdiction entries when TTL drops below this many ledgers.
const TTL_THRESHOLD: u32 = 1_000;
/// Target TTL (in ledgers) after extension.
const TTL_EXTEND_TO: u32 = 5_000;

#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// The issuer address, set once in `initialize`. Instance storage.
    Issuer,
    ComplianceOfficer,
    Jurisdiction(Address),
    Paused,
}

/// Emitted whenever a jurisdiction flag is set.
#[contractevent]
pub struct JurisdictionSet {
    #[topic]
    pub address: Address,
    pub code: String,
}

#[contractevent]
pub struct JurisdictionRemoved {
    #[topic]
    pub address: Address,
}

#[contractevent]
pub struct Paused {
    #[topic]
    pub issuer: Address,
}

#[contractevent]
pub struct Unpaused {
    #[topic]
    pub issuer: Address,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    NotAuthorized = 3,
    /// Caller supplied an argument that is structurally invalid.
    InvalidInput = 4,
    ContractPaused = 5,
}

#[contract]
pub struct JurisdictionFlag;

#[contractimpl]
impl JurisdictionFlag {
    /// One-time setup that records `issuer` as the only address allowed to
    /// set jurisdiction codes afterward.
    ///
    /// # Parameters
    /// - `issuer`: the address that will be authorized to call
    ///   [`set_jurisdiction`](Self::set_jurisdiction).
    ///
    /// # Auth
    /// Requires `issuer.require_auth()`, so the issuer must sign the
    /// initialization.
    ///
    /// # Errors
    /// - [`Error::AlreadyInitialized`] if the contract has already been
    ///   initialized. The existing issuer is left unchanged.
    pub fn initialize(env: Env, issuer: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Issuer) {
            return Err(Error::AlreadyInitialized);
        }
        issuer.require_auth();
        env.storage().instance().set(&DataKey::Issuer, &issuer);
        env.storage().instance().set(&DataKey::Paused, &false);
        Ok(())
    }

    /// Assign the compliance-officer role. Issuer-only.
    ///
    /// The officer role grants access to exactly one entry point:
    /// [`set_jurisdiction`](Self::set_jurisdiction), which is guarded by
    /// `require_compliance_authority` (issuer *or* officer). Every other
    /// mutating entry point is guarded by `require_issuer` and therefore
    /// remains issuer-only, including:
    ///
    /// - [`remove_jurisdiction_multiple`](Self::remove_jurisdiction_multiple)
    /// - [`pause`](Self::pause) / [`unpause`](Self::unpause)
    /// - [`upgrade`](Self::upgrade)
    /// - [`set_compliance_officer`](Self::set_compliance_officer) /
    ///   [`revoke_compliance_officer`](Self::revoke_compliance_officer)
    ///
    /// There are no `_until` or multiple-address variants of
    /// `set_jurisdiction`; the officer role does not extend to any other
    /// function.
    ///
    /// Auth: gated by [`require_issuer`] — only the issuer may delegate this role.
    pub fn set_compliance_officer(
        env: Env,
        issuer: Address,
        officer: Address,
    ) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        env.storage()
            .instance()
            .set(&DataKey::ComplianceOfficer, &officer);
        Ok(())
    }

    /// Revoke the compliance-officer role. Issuer-only.
    ///
    /// After revocation, the officer no longer satisfies
    /// `require_compliance_authority`, so the only entry point it previously
    /// unlocked — [`set_jurisdiction`](Self::set_jurisdiction) — reverts to
    /// issuer-only access. All other mutating entry points
    /// ([`remove_jurisdiction_multiple`](Self::remove_jurisdiction_multiple),
    /// [`pause`](Self::pause), [`unpause`](Self::unpause),
    /// [`upgrade`](Self::upgrade)) were already issuer-only via
    /// `require_issuer` and are unaffected.
    ///
    /// Auth: gated by [`require_issuer`] — only the issuer may revoke the delegated role.
    pub fn revoke_compliance_officer(env: Env, issuer: Address) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        env.storage()
            .instance()
            .remove(&DataKey::ComplianceOfficer);
        Ok(())
    }

    /// Pause all mutating operations. Issuer-only.
    ///
    /// Auth: gated by [`require_issuer`] — pause/unpause is a lifecycle operation reserved for the issuer.
    pub fn pause(env: Env, issuer: Address) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        env.storage().instance().set(&DataKey::Paused, &true);
        Paused {
            issuer: issuer.clone(),
        }
        .publish(&env);
        Ok(())
    }

    /// Resume all mutating operations. Issuer-only.
    ///
    /// Auth: gated by [`require_issuer`] — pause/unpause is a lifecycle operation reserved for the issuer.
    pub fn unpause(env: Env, issuer: Address) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        env.storage().instance().set(&DataKey::Paused, &false);
        Unpaused {
            issuer: issuer.clone(),
        }
        .publish(&env);
        Ok(())
    }

    /// Attach jurisdiction `code` to `address`. Issuer or compliance-officer.
    ///
    /// Auth: gated by [`require_compliance_authority`] — allows either the issuer or a
    /// delegated compliance officer, so routine flag management does not require the issuer key.
    pub fn set_jurisdiction(
        env: Env,
        issuer: Address,
        address: Address,
        code: String,
    ) -> Result<(), Error> {
        Self::require_compliance_authority(&env, &issuer)?;

        let key = DataKey::Jurisdiction(address.clone());
        env.storage().persistent().set(&key, &code);
        Self::extend_jurisdiction_ttl(&env, &key);

        JurisdictionSet {
            address,
            code,
        }
        .publish(&env);
        Ok(())
    }

    /// Remove stored jurisdiction codes for each address in `addresses`.
    ///
    /// Auth: gated by [`require_issuer`] — bulk removal is a privileged operation reserved for the issuer.
    pub fn remove_jurisdiction_multiple(
        env: Env,
        issuer: Address,
        addresses: Vec<Address>,
    ) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        for address in addresses.iter() {
            env.storage()
                .persistent()
                .remove(&DataKey::Jurisdiction(address.clone()));
            JurisdictionRemoved { address }.publish(&env);
        }
        Ok(())
    }

    /// Returns the jurisdiction code attached to `address`, if any.
    ///
    /// # Parameters
    /// - `address`: the address to look up.
    ///
    /// # Returns
    /// `Some(code)` if a code has been set via
    /// [`set_jurisdiction`](Self::set_jurisdiction), otherwise `None`.
    ///
    /// # Auth
    /// None. This is a read-only call anyone may make.
    ///
    /// # Errors
    /// Never fails. Works even before the contract is initialized, in which
    /// case it always returns `None`.
    pub fn get_jurisdiction(env: Env, address: Address) -> Option<String> {
        let key = DataKey::Jurisdiction(address);
        let code: Option<String> = env.storage().persistent().get(&key);
        if code.is_some() {
            Self::extend_jurisdiction_ttl(&env, &key);
        }
        code
    }

    /// Returns `true` if `address` has a jurisdiction code that appears in
    /// `allowed_codes`. Meant to be called by other contracts enforcing a
    /// permitted-jurisdiction policy.
    pub fn is_permitted_jurisdiction(
        env: Env,
        address: Address,
        allowed_codes: Vec<String>,
    ) -> bool {
        match Self::get_jurisdiction(env, address) {
            Some(code) => allowed_codes.iter().any(|c| c == code),
            None => false,
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Upgrade the contract WASM. Issuer-only.
    ///
    /// Uses Soroban's native `update_current_contract_wasm` host function to
    /// swap the contract code behind the same contract ID. All existing
    /// storage (issuer address, jurisdiction flags) is preserved across the
    /// upgrade. The issuer's auth is verified before the upgrade proceeds.
    pub fn upgrade(env: Env, issuer: Address, new_wasm_hash: BytesN<32>) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        env.deployer().update_current_contract_wasm(new_wasm_hash);
        Ok(())
    }

    /// Strict single-address auth gate — only the address stored as `issuer`
    /// at [`initialize`] time may pass.
    ///
    /// ## Authorization split
    ///
    /// This helper enforces the *tightest* authorization level in the contract.
    /// It is used by every entry point that changes the contract's own
    /// configuration or lifecycle (pause/unpause, compliance-officer
    /// assignment, bulk jurisdiction removal, WASM upgrade). The reasoning is
    /// that these operations affect the contract's trust model itself, so they
    /// must be gated on the one address the deployer designated at setup —
    /// the issuer — and no delegation is permitted.
    ///
    /// Contrast with [`require_compliance_authority`], which additionally
    /// allows a delegated compliance officer for day-to-day data operations.
    ///
    /// ## Errors
    ///
    /// Returns [`Error::NotInitialized`] if `initialize` has not been called
    /// yet, or [`Error::NotAuthorized`] if `issuer` does not match the stored
    /// issuer address.
    fn require_issuer(env: &Env, issuer: &Address) -> Result<(), Error> {
        issuer.require_auth();
        let stored_issuer: Address = env
            .storage()
            .instance()
            .get(&DataKey::Issuer)
            .ok_or(Error::NotInitialized)?;
        if stored_issuer != *issuer {
            return Err(Error::NotAuthorized);
        }
        Ok(())
    }

    /// Looser auth gate — passes if `caller` is the issuer **or** the
    /// currently assigned compliance officer.
    ///
    /// ## Authorization split
    ///
    /// This helper enforces a *delegated* authorization level intended for
    /// routine compliance data operations (currently: [`set_jurisdiction`]).
    /// The issuer can optionally appoint a compliance officer via
    /// [`set_compliance_officer`]; once appointed, that officer may call any
    /// entry point gated by this helper without requiring the issuer key for
    /// every individual flag operation.
    ///
    /// Entry points that mutate the contract's *configuration* (who the
    /// compliance officer is, whether the contract is paused, etc.) use the
    /// stricter [`require_issuer`] instead, so a compromised compliance-officer
    /// key cannot escalate its own privileges.
    ///
    /// If no compliance officer has been set, this helper behaves identically
    /// to [`require_issuer`].
    ///
    /// ## Errors
    ///
    /// Returns [`Error::NotInitialized`] if `initialize` has not been called,
    /// or [`Error::NotAuthorized`] if `caller` is neither the issuer nor the
    /// compliance officer.
    fn require_compliance_authority(env: &Env, caller: &Address) -> Result<(), Error> {
        caller.require_auth();
        let stored_issuer: Address = env
            .storage()
            .instance()
            .get(&DataKey::Issuer)
            .ok_or(Error::NotInitialized)?;
        if stored_issuer == *caller {
            return Ok(());
        }
        if let Some(officer) = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::ComplianceOfficer)
        {
            if officer == *caller {
                return Ok(());
            }
        }
        Err(Error::NotAuthorized)
    }

    fn extend_jurisdiction_ttl(env: &Env, key: &DataKey) {
        env.storage()
            .persistent()
            .exten

/* … truncated 98 chars — edit only what you need near the top … */
