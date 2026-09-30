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
//! **Callers**: the configured issuer or compliance officer may call
//! `set_jurisdiction` and `add_jurisdiction`; only the issuer may call
//! `remove_jurisdiction`, `remove_jurisdiction_multiple`, or `upgrade`.
//! `set_jurisdiction` / `get_jurisdiction` remain single-code conveniences.
//! Use `add_jurisdiction`, `remove_jurisdiction`, and `list_jurisdictions`
//! for the multi-code model. Any contract or off-chain client can read codes
//! and call `is_permitted_jurisdiction(address, allowed_codes)` directly.
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
    Jurisdictions(Address),
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

        let mut codes = Vec::new(&env);
        codes.push_back(code.clone());
        Self::store_jurisdictions(&env, &address, &codes);

        JurisdictionSet {
            address,
            code,
        }
        .publish(&env);
        Ok(())
    }

    /// Add `code` to `address`'s jurisdiction codes if it is not already present.
    /// Issuer or compliance-officer only.
    pub fn add_jurisdiction(
        env: Env,
        issuer: Address,
        address: Address,
        code: String,
    ) -> Result<(), Error> {
        Self::require_compliance_authority(&env, &issuer)?;

        let mut codes = Self::load_jurisdictions(&env, &address);
        if !codes.iter().any(|existing| existing == code) {
            codes.push_back(code.clone());
            Self::store_jurisdictions(&env, &address, &codes);
        }

        JurisdictionSet { address, code }.publish(&env);
        Ok(())
    }

    /// Remove `code` from `address`'s jurisdiction codes. Issuer-only.
    pub fn remove_jurisdiction(
        env: Env,
        issuer: Address,
        address: Address,
        code: String,
    ) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;

        let mut remaining = Vec::new(&env);
        for existing in Self::load_jurisdictions(&env, &address).iter() {
            if existing != code {
                remaining.push_back(existing);
            }
        }
        Self::store_jurisdictions(&env, &address, &remaining);
        JurisdictionRemoved { address }.publish(&env);
        Ok(())
    }

    /// Return all jurisdiction codes attached to `address`.
    pub fn list_jurisdictions(env: Env, address: Address) -> Vec<String> {
        Self::load_jurisdictions(&env, &address)
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
            Self::store_jurisdictions(&env, &address, &Vec::new(&env));
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
        Self::load_jurisdictions(&env, &address).iter().next()
    }

    /// Returns `true` if `address` has a jurisdiction code that appears in
    /// `allowed_codes`. Meant to be called by other contracts enforcing a
    /// permitted-jurisdiction policy.
    pub fn is_permitted_jurisdiction(
        env: Env,
        address: Address,
        allowed_codes: Vec<String>,
    ) -> bool {
        let codes = Self::load_jurisdictions(&env, &address);
        allowed_codes
            .iter()
            .any(|allowed| codes.iter().any(|code| code == allowed))
    }

    /// Unified compliance check — returns `true` if `address` has **any**
    /// jurisdiction code set, i.e. it has been through an onboarding/KYC
    /// process that assigned it a jurisdiction.
    ///
    /// This entry point implements the shared `ComplianceCheck` interface
    /// (`is_compliant(address) -> bool`).  Unlike [`is_permitted_jurisdiction`],
    /// it does not validate the code against a permitted-jurisdictions list
    /// because the `ComplianceCheck` interface carries only `address`.
    ///
    /// Use [`is_permitted_jurisdiction`] when you need to enforce a specific
    /// set of allowed codes.  Use `is_compliant` for the lighter check of
    /// "has this address been assigned a jurisdiction at all".
    ///
    /// Not affected by pause state — reads always succeed.
    pub fn is_compliant(env: Env, address: Address) -> bool {
        Self::get_jurisdiction(env, address).is_some()
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
            .extend_ttl(key, TTL_THRESHOLD, TTL_EXTEND_TO);
    }

    fn load_jurisdictions(env: &Env, address: &Address) -> Vec<String> {
        let list_key = DataKey::Jurisdictions(address.clone());
        if let Some(codes) = env.storage().persistent().get::<_, Vec<String>>(&list_key) {
            Self::extend_jurisdiction_ttl(env, &list_key);
            return codes;
        }

        let legacy_key = DataKey::Jurisdiction(address.clone());
        match env.storage().persistent().get::<_, String>(&legacy_key) {
            Some(code) => {
                Self::extend_jurisdiction_ttl(env, &legacy_key);
                Vec::from_array(env, [code])
            }
            None => Vec::new(env),
        }
    }

    fn store_jurisdictions(env: &Env, address: &Address, codes: &Vec<String>) {
        let list_key = DataKey::Jurisdictions(address.clone());
        let legacy_key = DataKey::Jurisdiction(address.clone());
        if let Some(first_code) = codes.iter().next() {
            env.storage().persistent().set(&list_key, codes);
            Self::extend_jurisdiction_ttl(env, &list_key);
            env.storage().persistent().set(&legacy_key, &first_code);
            Self::extend_jurisdiction_ttl(env, &legacy_key);
        } else {
            env.storage().persistent().remove(&list_key);
            env.storage().persistent().remove(&legacy_key);
        }
    }
}

#[cfg(test)]
mod test;

#[cfg(test)]
mod fuzz;
