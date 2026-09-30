//! `pausable` is a `#![no_std]` shared crate that provides a minimal pause
//! mechanism for Soroban contracts.
//!
//! **Purpose**: let any Soroban contract add an emergency-stop capability
//! without reimplementing the same storage key and guard logic. A consuming
//! contract stores a single boolean under a well-known key and calls these
//! helpers to manage it.
//!
//! **Usage**: import this crate as a regular dependency and call the free
//! functions directly, passing your contract's `Env`. No contract struct is
//! defined here — these are pure utility functions, not an entry-point
//! contract.
//!
//! ## Which contracts use this crate vs. a local pause implementation
//!
//! Not every contract in the workspace delegates pause state to this crate.
//! A reader of this file would otherwise need to grep the workspace to find
//! out who depends on it — the table below captures that for each primitive.
//!
//! | Contract | Pause mechanism | Notes |
//! |---|---|---|
//! | `multisig-admin` | **this crate** (`compliance_pausable::*`) | Added when the crate was introduced |
//! | `compliance-aggregator` | **this crate** (`compliance_pausable::*`) | Added when the crate was introduced |
//! | `audit-log` | **this crate** (`compliance_pausable::*`) | Added when the crate was introduced |
//! | `policy-engine` | **this crate** (`compliance_pausable::*`) | Added when the crate was introduced |
//! | `allowlist-token` | **local** `DataKey::Paused` (inline) | Predates the shared crate; not yet migrated |
//! | `denylist-gate` | **local** `DataKey::Paused` (inline) | Predates the shared crate; not yet migrated |
//! | `jurisdiction-flag` | **local** `DataKey::Paused` (inline) | Predates the shared crate; not yet migrated |
//! | `circuit-breaker` | **not applicable** — uses `DataKey::Frozen` | Freeze semantics differ from pause: `Frozen` is a cross-contract gate, not an admin stop |
//!
//! ### Why the three original primitives use local pause state
//!
//! `allowlist-token`, `denylist-gate`, and `jurisdiction-flag` were written
//! before `compliance-pausable` existed. Each inlines its own
//! `env.storage().instance().set(&DataKey::Paused, &true/false)` logic —
//! functionally identical to what this crate does, but not going through it.
//! Migrating them is safe (the storage key and semantics are the same) but
//! requires a coordinated change across three contracts plus their test
//! suites; it has been left for a dedicated refactor rather than mixed into
//! unrelated PRs.
//!
//! ### Why `circuit-breaker` is different
//!
//! `circuit-breaker` uses `DataKey::Frozen` rather than `DataKey::Paused`
//! and exposes `freeze`/`unfreeze`/`is_frozen` rather than
//! `pause`/`unpause`/`is_paused`. This is intentional: freeze is a
//! *cross-contract emergency gate* that other contracts poll before allowing
//! a transfer — it is not the same concept as an admin pause on the
//! circuit-breaker contract itself. The two mechanisms are kept separate to
//! avoid conflating operational pause (admin maintenance window) with
//! emergency freeze (halt-all-transfers signal).
#![no_std]

use soroban_sdk::{contracttype, Env};

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Paused,
}

/// Returns `true` if the contract is currently paused.
///
/// Defaults to `false` when no pause flag has been stored yet, so a freshly
/// initialized contract starts in the active (unpaused) state.
pub fn is_paused(env: &Env) -> bool {
    env.storage()
        .instance()
        .get(&DataKey::Paused)
        .unwrap_or(false)
}

/// Set the paused flag to `true`.
///
/// Calling this when already paused is a no-op — the flag remains set.
pub fn pause(env: &Env) {
    env.storage().instance().set(&DataKey::Paused, &true);
}

/// Clear the paused flag, returning the contract to the active state.
///
/// Calling this when not paused is a no-op — the flag remains cleared.
pub fn unpause(env: &Env) {
    env.storage().instance().set(&DataKey::Paused, &false);
}

/// Panic with a descriptive message if the contract is currently paused.
///
/// Consuming contracts should call this at the top of any state-mutating
/// entry point that must be blocked while paused, e.g.:
///
/// ```ignore
/// pub fn transfer(env: Env, ...) -> Result<(), Error> {
///     pausable::require_not_paused(&env);
///     // ...
/// }
/// ```
pub fn require_not_paused(env: &Env) {
    if is_paused(env) {
        panic!("contract is paused");
    }
}

/// Returns `Err(err)` if the contract is currently paused, `Ok(())` otherwise.
///
/// Use this instead of [`require_not_paused`] in entry points that surface
/// pause state as a typed contract error (via `?`) rather than panicking,
/// e.g.:
///
/// ```ignore
/// pub fn transfer(env: Env, ...) -> Result<(), Error> {
///     pausable::require_not_paused_or(&env, Error::ContractPaused)?;
///     // ...
/// }
/// ```
pub fn require_not_paused_or<E>(env: &Env, err: E) -> Result<(), E> {
    if is_paused(env) {
        Err(err)
    } else {
        Ok(())
    }
}

/// Panic with a descriptive message if the contract is **not** currently paused.
///
/// This is the inverse of [`require_not_paused`] and is intended for
/// emergency-only recovery functions that should only be callable *while the
/// contract is paused* — for example, an admin drain or state-reset that must
/// be guarded against accidental invocation during normal operation.
///
/// # Example
///
/// ```ignore
/// /// Emergency drain — only callable while the contract is paused.
/// pub fn emergency_recover(env: Env, admin: Address) -> Result<(), Error> {
///     pausable::require_paused(&env);
///     // ... recovery logic ...
/// }
/// ```
pub fn require_paused(env: &Env) {
    if !is_paused(env) {
        panic!("contract is not paused");
    }
}

/// Returns `Err(err)` if the contract is **not** currently paused, `Ok(())`
/// otherwise.
///
/// Use this in entry points that expose the "not paused" condition as a typed
/// contract error rather than panicking:
///
/// ```ignore
/// pub fn emergency_recover(env: Env) -> Result<(), Error> {
///     pausable::require_paused_or(&env, Error::NotPaused)?;
///     // ...
/// }
/// ```
pub fn require_paused_or<E>(env: &Env, err: E) -> Result<(), E> {
    if !is_paused(env) {
        Err(err)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod test;
