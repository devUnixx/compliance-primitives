//! `policy-engine` is a `#![no_std]` Soroban contract that composes multiple
//! compliance checks into a single policy evaluation call.
//!
//! ## AND / OR design choice
//!
//! Compliance use cases almost always reduce to one of two logical shapes:
//! every check must pass (AND — "this address must be allowlisted **and** in
//! a permitted jurisdiction") or at least one must pass (OR — "this address
//! either cleared KYC with provider A **or** provider B"). A two-variant
//! `CombineOp` enum (`All` / `Any`) covers both without the overhead of an
//! AST, which would be over-engineered for this domain and would add
//! significant complexity to the storage, serialization, and auditing story.
//!
//! ## Check failure surfacing
//!
//! `evaluate` returns `Ok(bool)` rather than panicking or returning an
//! opaque error on a failed policy: a Soroban invocation that returns a
//! contract error rolls back all state changes including emitted events, so
//! any failure audit trail would be silently discarded. By returning
//! `Ok(false)` and emitting a `PolicyResult` event the caller gets a
//! machine-readable result and the chain preserves an auditable record of
//! the decision, consistent with the pattern used in `allowlist-token`.
//!
//! ## Registration design
//!
//! Checks are stored as an admin-managed, mutable `Vec<CheckKind>` in
//! persistent storage. This lets the issuer add, reorder, or remove checks
//! as compliance requirements evolve — without redeploying or upgrading the
//! contract binary. An authorized admin is required for all mutations,
//! keeping the policy immutable to unprivileged callers.
//!
//! ## Upgradeability
//!
//! `upgrade(admin, new_wasm_hash)` lets the configured admin move the
//! contract's code to a new WASM hash via
//! `env.deployer().update_current_contract_wasm`, following the same
//! admin-gated pattern used elsewhere in the repo (see `jurisdiction-flag`).
//! Storage (the admin key, `CombineOp`, and the registered `Checks` vec) is
//! untouched by the WASM swap, so all state is preserved and the contract
//! remains fully callable immediately after the upgrade. Only the admin can
//! call `upgrade`; any other caller is rejected with `Error::NotAuthorized`.
#![no_std]

use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype,
    Address, BytesN, Env, String, Symbol, Vec,
};

// ---------------------------------------------------------------------------
// Cross-contract client interfaces
// ---------------------------------------------------------------------------

/// Describes the `denylist-gate` contract interface used for cross-contract
/// calls. The generated `DenylistCheckClient` is used in `evaluate` to call
/// `check()` on a deployed denylist-gate instance. We do not take a direct
/// crate dependency on `denylist-gate` to avoid colliding wasm exports.
#[contractclient(name = "DenylistCheckClient")]
pub trait DenylistCheckInterface {
    fn check(env: Env, address: Address) -> bool;
}

/// Describes the `jurisdiction-flag` contract interface used for
/// cross-contract calls. The generated `JurisdictionCheckClient` is used in
/// `evaluate`. Same reason as above for avoiding a direct crate dep.
#[contractclient(name = "JurisdictionCheckClient")]
pub trait JurisdictionCheckInterface {
    fn is_permitted_jurisdiction(env: Env, address: Address, allowed_codes: Vec<String>) -> bool;
}

/// Describes the `circuit-breaker` contract interface used for cross-contract
/// calls. Same reason as above for avoiding a direct crate dep.
#[contractclient(name = "CircuitBreakerClient")]
pub trait CircuitBreakerInterface {
    fn is_frozen(env: Env) -> bool;
}

// ---------------------------------------------------------------------------
// Storage types
// ---------------------------------------------------------------------------

/// Parameters for a denylist-gate check.
#[contracttype]
#[derive(Clone)]
pub struct DenylistCheck {
    /// Address of the deployed `denylist-gate` contract to call.
    pub contract: Address,
}

/// Parameters for a jurisdiction-flag check.
#[contracttype]
#[derive(Clone)]
pub struct JurisdictionCheck {
    /// Address of the deployed `jurisdiction-flag` contract to call.
    pub contract: Address,
    /// The set of jurisdiction codes that are permitted.
    pub allowed_codes: Vec<String>,
}

/// Parameters for an allowlist-token check.
#[contracttype]
#[derive(Clone)]
pub struct AllowlistCheck {
    /// Address of the deployed `allowlist-token` contract to call.
    pub contract: Address,
}

/// Describes a single compliance check the engine should perform.
///
/// Each variant carries the address of the external contract that implements
/// the check plus any parameters that check needs.
///
/// Note: `#[contracttype]` only supports tuple variants (not named struct
/// variants). Each variant wraps a dedicated parameter struct.
#[contracttype]
#[derive(Clone)]
pub enum CheckKind {
    /// Call `denylist-gate.check(address)`. The address must **not** be on
    /// the denylist for this check to pass.
    Denylist(DenylistCheck),
    /// Call `jurisdiction-flag.is_permitted_jurisdiction(address,
    /// allowed_codes)`. The address must have a jurisdiction code in
    /// `allowed_codes` for this check to pass.
    Jurisdiction(JurisdictionCheck),
    /// Call `allowlist-token.is_allowed(address)`. The address must be
    /// present on the allowlist for this check to pass.
    Allowlist(AllowlistCheck),
}

/// How the engine combines the results of multiple checks.
#[contracttype]
#[derive(Clone, PartialEq)]
pub enum CombineOp {
    /// AND — every check must pass. Used when an address must satisfy all
    /// compliance requirements simultaneously.
    All,
    /// OR — at least one check must pass. Used when multiple equivalent
    /// compliance paths exist (e.g. two KYC providers).
    Any,
}

/// Describes a pair of addresses (e.g. sender and recipient) for evaluating
/// compliance policies on transfers in batches.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressPair {
    pub from: Address,
    pub to: Address,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Checks,
    CombineOp,
    /// Address of the `circuit-breaker` contract to consult, if any. When
    /// set and frozen, `evaluate` short-circuits to deny.
    CircuitBreaker,
}

// ---------------------------------------------------------------------------
// Errors and events
// ---------------------------------------------------------------------------

/// Maximum number of addresses accepted by `batch_evaluate` in a single call.
///
/// Soroban imposes a per-transaction CPU-instruction and memory budget. Each
/// address in the batch requires one or more cross-contract calls (one per
/// registered check), so an unbounded list would allow a caller to exhaust
/// the budget and brick the transaction. 20 was chosen to mirror the limit
/// used in the `compliance-aggregator` batch family and to keep the worst-case
/// instruction cost within the conservative end of the Soroban default budget.
pub const MAX_BATCH_SIZE: u32 = 20;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    NotAuthorized = 3,
    PolicyViolation = 4,
    /// Returned by `add_check` when the number of registered checks would
    /// exceed `MAX_CHECKS`. Keeps per-evaluation resource cost bounded and
    /// prevents unbounded storage growth.
    MaxDepthExceeded = 5,
}

/// Maximum number of checks that can be registered in a single policy
/// engine instance.  Chosen to keep per-`evaluate` cross-contract call
/// overhead well within Soroban's instruction limits while still supporting
/// all realistic compliance stack sizes.
pub const MAX_CHECKS: u32 = 16;

/// Emitted by `evaluate` regardless of the pass/fail outcome so that
/// off-chain compliance tooling can build a full audit trail even when the
/// policy passes (which wouldn't produce an error event).
#[contractevent]
pub struct PolicyResult {
    #[topic]
    pub passed: bool,
    pub from: Address,
    pub to: Address,
}

/// Emitted whenever the contract is upgraded to a new WASM implementation,
/// for on-chain auditability of the upgrade path.
#[contractevent]
pub struct UpgradePerformed {
    #[topic]
    pub admin: Address,
}

/// Carries information about which check in the list failed and what kind it
/// was. Serializable on-chain; can be embedded in future error events or
/// returned from an extended evaluate variant.
#[contracttype]
#[derive(Clone)]
#[allow(dead_code)]
pub struct CheckFailure {
    pub check_index: u32,
    pub kind: Symbol,
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct PolicyEngine;

#[contractimpl]
impl PolicyEngine {
    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /// One-time initializer. Sets `admin` as the authorized manager and
    /// `op` as the combination operator for all future evaluations.
    /// Initializes the check list to empty.
    pub fn initialize(
        env: Env,
        admin: Address,
        op: CombineOp,
        circuit_breaker: Option<Address>,
    ) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::CombineOp, &op);
        let empty: Vec<CheckKind> = Vec::new(&env);
        env.storage().instance().set(&DataKey::Checks, &empty);
        if let Some(breaker) = circuit_breaker {
            env.storage()
                .instance()
                .set(&DataKey::CircuitBreaker, &breaker);
        }
        Ok(())
    }

    /// Register or replace the `circuit-breaker` contract address.
    /// Admin-only. Pass this to enable emergency-freeze short-circuiting.
    pub fn set_circuit_breaker(env: Env, admin: Address, breaker: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage()
            .instance()
            .set(&DataKey::CircuitBreaker, &breaker);
        Ok(())
    }

    /// Returns the currently registered `circuit-breaker` address, if any.
    pub fn circuit_breaker(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::CircuitBreaker)
    }

    // -----------------------------------------------------------------------
    // Admin mutations
    // -----------------------------------------------------------------------

    /// Append a new `check` to the end of the policy list. Admin-only.
    ///
    /// Returns `Err(Error::MaxDepthExceeded)` if the list already contains
    /// `MAX_CHECKS` entries. This keeps the number of cross-contract calls
    /// issued by `evaluate` bounded and prevents storage bloat.
    pub fn add_check(env: Env, admin: Address, check: CheckKind) -> Result<(), Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        Self::require_admin(&env, &admin)?;
        let mut checks: Vec<CheckKind> = env
            .storage()
            .instance()
            .get(&DataKey::Checks)
            .ok_or(Error::NotInitialized)?;
        if checks.len() >= MAX_CHECKS {
            return Err(Error::MaxDepthExceeded);
        }
        checks.push_back(check);
        env.storage().instance().set(&DataKey::Checks, &checks);
        Ok(())
    }

    /// Remove the check at position `index` from the policy list.
    /// Admin-only. Indices shift down after removal (Vec::remove semantics).
    pub fn remove_check(env: Env, admin: Address, index: u32) -> Result<(), Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        Self::require_admin(&env, &admin)?;
        let mut checks: Vec<CheckKind> = env
            .storage()
            .instance()
            .get(&DataKey::Checks)
            .ok_or(Error::NotInitialized)?;
        checks.remove(index);
        env.storage().instance().set(&DataKey::Checks, &checks);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Evaluation
    // -----------------------------------------------------------------------

    /// Evaluate the current policy for a proposed transfer from `from` to
    /// `to`. Runs every registered check against both addresses using the
    /// configured `CombineOp`.
    ///
    /// Returns `Ok(true)` if the policy passes, `Ok(false)` if it fails.
    /// A `PolicyResult` event is always emitted so the outcome is auditable
    /// on-chain regardless of the result. `Err` is returned only for
    /// configuration failures (e.g. the contract was never initialized).
    pub fn evaluate(env: Env, from: Address, to: Address) -> Result<bool, Error> {
        // Emergency freeze short-circuit: if a configured circuit-breaker is
        // frozen, deny outright without evaluating any registered checks.
        let breaker_addr: Option<Address> = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::CircuitBreaker);
        if let Some(addr) = breaker_addr {
            if CircuitBreakerClient::new(&env, &addr).is_frozen() {
                PolicyResult {
                    passed: false,
                    from: from.clone(),
                    to: to.clone(),
                }
                .publish(&env);
                return Ok(false);
            }
        }

        let checks: Vec<CheckKind> = env
            .storage()
            .instance()
            .get(&DataKey::Checks)
            .ok_or(Error::NotInitialized)?;
        let op: CombineOp = env
            .storage()
            .instance()
            .get(&DataKey::CombineOp)
            .ok_or(Error::NotInitialized)?;

        let passed = match op {
            CombineOp::All => {
                // All checks must pass for both from and to.
                let mut all_pass = true;
                for i in 0..checks.len() {
                    let check = checks.get(i).unwrap();
                    if !Self::run_check(&env, &check, &from)
                        || !Self::run_check(&env, &check, &to)
                    {
                        all_pass = false;
                        break;
                    }
                }
                all_pass
            }
            CombineOp::Any => {
                // At least one check must pass for both from and to.
                if checks.is_empty() {
                    false
                } else {
                    let mut any_pass = false;
                    for i in 0..checks.len() {
                        let check = checks.get(i).unwrap();
                        if Self::run_check(&env, &check, &from)
                            && Self::run_check(&env, &check, &to)
                        {
                            any_pass = true;
                            break;
                        }
                    }
                    any_pass
                }
            }
        };

        PolicyResult {
            passed,
            from: from.clone(),
            to: to.clone(),
        }
        .publish(&env);

        Ok(passed)
    }

    /// Evaluate the current policy for multiple address pairs (transfers) in a single call.
    ///
    /// Returns a `Vec<bool>` containing the pass/fail status for each pair in the same order.
    pub fn batch_evaluate(env: Env, pairs: Vec<AddressPair>) -> Result<Vec<bool>, Error> {
        let mut results = Vec::new(&env);
        for pair in pairs.iter() {
            let res = Self::evaluate(env.clone(), pair.from, pair.to)?;
            results.push_back(res);
        }
        Ok(results)
    }

    // -----------------------------------------------------------------------
    // Read-only accessors
    // -----------------------------------------------------------------------

    /// Returns the current list of registered checks.
    pub fn get_checks(env: Env) -> Vec<CheckKind> {
        env.storage()
            .instance()
            .get(&DataKey::Checks)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Returns the current combination operator.
    pub fn get_op(env: Env) -> Result<CombineOp, Error> {
        env.storage()
            .instance()
            .get(&DataKey::CombineOp)
            .ok_or(Error::NotInitialized)
    }

    /// Returns the full configured policy tree as a [`PolicyNode`].
    ///
    /// Off-chain tooling and auditors can call this single view to read back
    /// everything needed to understand and reproduce the policy that a
    /// deployed instance will evaluate, without having to reconstruct it from
    /// deployment transaction history.
    ///
    /// Returns `Err(Error::NotInitialized)` if the contract has not yet been
    /// initialized.
    pub fn get_policy(env: Env) -> Result<PolicyNode, Error> {
        let op: CombineOp = env
            .storage()
            .instance()
            .get(&DataKey::CombineOp)
            .ok_or(Error::NotInitialized)?;
        let checks: Vec<CheckKind> = env
            .storage()
            .instance()
            .get(&DataKey::Checks)
            .ok_or(Error::NotInitialized)?;
        Ok(PolicyNode { op, checks })
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn run_check(env: &Env, check: &CheckKind, address: &Address) -> bool {
        match check {
            CheckKind::Denylist(params) => {
                let client = DenylistCheckClient::new(env, &params.contract);
                client.check(address)
            }
            CheckKind::Jurisdiction(params) => {
                let client = JurisdictionCheckClient::new(env, &params.contract);
                client.is_permitted_jurisdiction(address, &params.allowed_codes)
            }
            CheckKind::Allowlist(params) => {
                let client = AllowlistCheckClient::new(env, &params.contract);
                client.is_allowed(address)
            }
        }
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
}

#[cfg(test)]
mod test_utils;

#[cfg(test)]
mod test;

#[cfg(test)]
mod fuzz;

#[cfg(test)]
mod bench;

