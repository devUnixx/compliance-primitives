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
//! ## Pause timestamp and reason (issue #411)
//!
//! In addition to the simple pause flag, this crate optionally tracks **when**
//! a pause happened (via [`env.ledger().timestamp()`]) and an optional
//! **reason string** supplied by the caller.  Both are stored in instance
//! storage under their own [`DataKey`] variants and are readable at any time
//! via [`paused_since`] and [`pause_reason`].
//!
//! Consuming contracts that only need the basic boolean gate do not have to
//! call the new helpers at all — [`pause`] continues to work without a reason,
//! and the old helpers remain unchanged.  Contracts that want the richer
//! audit trail can call [`pause_with_reason`] instead.
//!
//! ### Storage layout
//!
//! | Key             | Type         | Storage  | Lifecycle                              |
//! |-----------------|--------------|----------|----------------------------------------|
//! | `Paused`        | `bool`       | instance | set by [`pause`] / [`unpause`]         |
//! | `PausedSince`   | `u64`        | instance | set by [`pause`] / cleared by [`unpause`] |
//! | `PauseReason`   | `String`     | instance | set by [`pause_with_reason`] / cleared by [`unpause`] |
#![no_std]

use soroban_sdk::{contracttype, Env, String};

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Paused,
    /// Ledger timestamp (seconds since Unix epoch) recorded when the contract
    /// was last paused.  Absent when the contract is not paused.
    PausedSince,
    /// Optional human-readable reason string recorded when the contract was
    /// last paused via [`pause_with_reason`].  Absent when no reason was
    /// supplied or the contract is not paused.
    PauseReason,
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

/// Set the paused flag to `true` and record the current ledger timestamp.
///
/// Calling this when already paused is a no-op — the flag and timestamp remain
/// set to their existing values.
///
/// To also record a reason string, call [`pause_with_reason`] instead.
pub fn pause(env: &Env) {
    if !is_paused(env) {
        env.storage().instance().set(&DataKey::Paused, &true);
        env.storage()
            .instance()
            .set(&DataKey::PausedSince, &env.ledger().timestamp());
    }
}

/// Set the paused flag to `true`, record the current ledger timestamp, and
/// store an optional `reason` string for auditability.
///
/// Calling this when already paused is a no-op — the existing pause state,
/// timestamp, and reason are preserved.
///
/// If `reason` is `None`, any previously stored reason is left untouched (or
/// absent).
pub fn pause_with_reason(env: &Env, reason: Option<String>) {
    if !is_paused(env) {
        env.storage().instance().set(&DataKey::Paused, &true);
        env.storage()
            .instance()
            .set(&DataKey::PausedSince, &env.ledger().timestamp());
        if let Some(r) = reason {
            env.storage().instance().set(&DataKey::PauseReason, &r);
        }
    }
}

/// Clear the paused flag, returning the contract to the active state.
///
/// Also clears the stored pause timestamp and reason so they do not linger
/// after the contract resumes.
///
/// Calling this when not paused is a no-op — the flag remains cleared.
pub fn unpause(env: &Env) {
    env.storage().instance().set(&DataKey::Paused, &false);
    env.storage().instance().remove(&DataKey::PausedSince);
    env.storage().instance().remove(&DataKey::PauseReason);
}

/// Returns the ledger timestamp (seconds since Unix epoch) at which the
/// contract was last paused, or `None` if the contract is not currently
/// paused or has never been paused.
///
/// This value is cleared automatically when [`unpause`] is called, so it
/// is only present while the contract is in the paused state.
///
/// # Example
///
/// ```ignore
/// if let Some(since) = pausable::paused_since(&env) {
///     // contract has been paused since ledger timestamp `since`
/// }
/// ```
pub fn paused_since(env: &Env) -> Option<u64> {
    env.storage().instance().get(&DataKey::PausedSince)
}

/// Returns the reason string recorded when the contract was last paused via
/// [`pause_with_reason`], or `None` if no reason was provided or the contract
/// is not currently paused.
///
/// This value is cleared automatically when [`unpause`] is called.
pub fn pause_reason(env: &Env) -> Option<String> {
    env.storage().instance().get(&DataKey::PauseReason)
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
/// Use this at the top of emergency-only recovery functions that should be
/// callable **only while the contract is paused** — the inverse of
/// [`require_not_paused`].
///
/// # Example
///
/// ```ignore
/// /// Emergency drain, only callable while the contract is paused.
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
/// Use this in entry points that surface the "not paused" condition as a
/// typed contract error rather than panicking:
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
