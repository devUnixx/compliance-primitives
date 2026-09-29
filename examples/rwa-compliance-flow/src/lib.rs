//! # RWA Compliance Flow Integration
//!
//! An integration example demonstrating how the three compliance primitives
//! compose to form a comprehensive compliance framework for RWA tokens and stablecoins.
//!
//! ## Pattern: Policy Composition via Trait-Based Clients
//!
//! This example shows a **lightweight integration layer** that does not implement
//! a token itself. Instead, it defines trait-based clients for the three primitives
//! and demonstrates the canonical composition pattern:
//!
//! 1. Each primitive (allowlist, denylist, jurisdiction) is wired independently
//! 2. Calls are made in series (AND logic); all must pass for a transfer to succeed
//! 3. Specific error types are returned to identify which check failed
//!
//! ## Compliance Layers Demonstrated
//!
//! - **Allowlist**: Only allowlisted addresses can transact
//! - **Denylist**: Sanctioned, defrauded, or court-ordered addresses are blocked
//! - **Jurisdiction**: Restricts activity to permitted jurisdictions (e.g., regulatory
//!   requirements)
//!
//! ## Differences from other examples
//!
//! - **vs. `/examples/rwa-token`**: That crate implements a complete token contract with
//!   balance tracking and integration of all three gates. This module shows only the
//!   compliance composition pattern without the token implementation.
//! - **vs. `/examples/denylist-gate-sep41`**: That crate is a SEP-41 token gated by
//!   denylist-gate alone. This demonstrates composition of all three gates.
//!
//! ## Test Coverage
//!
//! The module includes comprehensive tests verifying:
//! 1. A successful transfer when all three compliance checks pass
//! 2. Blocked transfers when each compliance check independently fails

#![no_std]

use soroban_sdk::{Address, Env, String};

// Contract clients generated from trait definitions
// These allow us to call the three compliance contracts without linking their full implementations
use soroban_sdk::contractclient;

/// Shared compliance check interface - unified way to call any compliance contract.
/// All three primitives implement `is_compliant(address) -> bool`; it is declared
/// only here so `client.is_compliant(...)` resolves to a single trait method.
/// The interface traits below cover the primitive-specific methods only.
#[contractclient(name = "ComplianceCheckClient")]
pub trait ComplianceCheckInterface {
    fn is_compliant(env: Env, address: Address) -> bool;
}

#[contractclient(name = "AllowlistTokenClient")]
pub trait AllowlistTokenInterface {
    fn initialize(env: Env, admin: Address, token: Address);
    fn add_to_allowlist(env: Env, admin: Address, address: Address);
    fn remove_from_allowlist(env: Env, admin: Address, address: Address);
    fn is_allowed(env: Env, address: Address) -> bool;
}

#[contractclient(name = "DenylistGateClient")]
pub trait DenylistGateInterface {
    fn initialize(env: Env, admin: Address);
    fn add_to_denylist(env: Env, admin: Address, address: Address);
    fn remove_from_denylist(env: Env, admin: Address, address: Address);
    fn check(env: Env, address: Address) -> bool;
}

#[contractclient(name = "JurisdictionFlagClient")]
pub trait JurisdictionFlagInterface {
    fn initialize(env: Env, issuer: Address);
    fn set_jurisdiction(env: Env, issuer: Address, address: Address, code: String);
    fn get_jurisdiction(env: Env, address: Address) -> Option<String>;
    fn is_permitted_jurisdiction(env: Env, address: Address, allowed_codes: soroban_sdk::Vec<String>) -> bool;
}

#[cfg(test)]
mod test;

#[cfg(test)]
mod policy_engine_test;
