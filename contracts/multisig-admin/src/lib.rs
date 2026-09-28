//! `multisig-admin` is a `#![no_std]` Soroban contract that implements
//! **M-of-N multisig authorization** using Soroban's custom-account
//! (`CustomAccountInterface`) pattern.
//!
//! ## Purpose
//!
//! Single-admin control is a known operational and security liability. This
//! contract can be set as the `admin` (or `issuer`) address of any of the
//! three compliance primitives — `allowlist-token`, `denylist-gate`,
//! `jurisdiction-flag` — because those contracts accept any `Address` as
//! their admin, and Soroban's auth model satisfies `require_auth()` for a
//! contract address by invoking `__check_auth` on that contract. No changes
//! to the primitives are needed.
//!
//! ## Tradeoff vs. #26 (built-in multisig)
//!
//! | Aspect | This contract (standalone) | #26 (built-in) |
//! |---|---|---|
//! | Primitive changes needed | None | Each primitive modified |
//! | Reusability | Shared across all three primitives | Per-primitive |
//! | Deployment | Extra contract to deploy | None |
//! | Upgrade path | Swap admin address | Redeploy primitive |
//! | Auth overhead | One cross-contract call per admin op | Inline |
//!
//! **When to use this contract**: you want a single multisig policy to govern
//! multiple deployed primitives, or you don't control the primitive's source
//! and cannot add built-in multisig. **When to use #26's approach**: you want
//! the tightest possible integration with a single primitive and don't mind
//! modifying it; one fewer deployment step.
//!
//! ## How `__check_auth` is invoked
//!
//! When any primitive calls `admin.require_auth()` and `admin` is the address
//! of this contract, the Soroban host calls
//! `MultisigAdmin::__check_auth(env, payload, signatures, context)`. The
//! `signatures` value is the `Vec<Address>` of approving signers provided by
//! the invoker. If at least `threshold` of those addresses are in the stored
//! signer set, authorization succeeds; otherwise it is rejected.
//!
//! ## Signer-set management
//!
//! `add_signer`, `remove_signer`, and `update_threshold` themselves go
//! through the multisig: they call `env.current_contract_address().require_auth()`
//! which re-enters `__check_auth`, ensuring no single signer can unilaterally
//! change the policy.
//!
//! ## Who calls this contract
//!
//! There are three distinct kinds of caller, and each touches a different
//! part of the surface:
//!
//! - **The deployer / issuer operations team** calls [`MultisigAdmin::initialize`]
//!   exactly once with the initial signer set and threshold. After that the
//!   deployer has no special privileges — every later change goes through
//!   the multisig itself.
//! - **The Soroban host** calls `__check_auth` on behalf of any contract
//!   that runs `admin.require_auth()` where `admin` is this contract's
//!   address. Signers never call `__check_auth` directly; they sign the
//!   authorization entry for the outer operation (e.g. `denylist-gate.add_to_denylist`)
//!   and the submitter attaches the list of approving signer addresses as the
//!   `signatures` value.
//! - **Individual signers** call `propose`, `approve`, and `execute` to
//!   coordinate an off-chain-visible approval trail before submitting the
//!   final transaction, and collectively (via `__check_auth`) call
//!   `add_signer`, `remove_signer`, `update_threshold`, `pause`, and
//!   `unpause` to govern this contract's own configuration.
//!
//! Read-only accessors (`get_signers`, `get_threshold`, `get_proposal`,
//! `is_paused`) may be called by anyone, including off-chain tooling such as
//! `tools/indexer` and other contracts deciding whether to trust this
//! contract as an admin.
//!
//! ## Composition with the other contracts in this repo
//!
//! This contract never calls the other contracts itself — composition is
//! entirely by *address*: you pass this contract's ID wherever another
//! contract asks for an admin/issuer `Address`, and Soroban's auth framework
//! routes the `require_auth()` back here.
//!
//! | Contract | Role this contract plays | Operations it gates |
//! |---|---|---|
//! | `allowlist-token` | `admin` | allowlist add/remove, timelocked upgrade |
//! | `denylist-gate` | `admin` | denylist add/remove, timelocked upgrade |
//! | `jurisdiction-flag` | `issuer` | setting/clearing jurisdiction flags, upgrade |
//! | `policy-engine` | `admin` | registering/removing checks, combine op |
//! | `compliance-aggregator` | `admin` | wiring gate/flag/breaker addresses, pause |
//! | `circuit-breaker` | `admin` | `freeze` / `unfreeze` (emergency stop) |
//! | `audit-log` | `admin` | audit-log administration |
//! | `pausable` (shared crate) | — | used *internally* here to back `pause`/`unpause` |
//!
//! Typical deployment: deploy `multisig-admin` first, initialize it with the
//! operations team's signer keys, then initialize each primitive with the
//! multisig's contract ID as its admin. One multisig can govern every
//! primitive in a deployment, giving a single auditable M-of-N policy. A
//! common pattern is to pair it with `audit-log` (record proposal creation,
//! approvals, and execution — see the `multisig-audit-trail` example) and to
//! make it the admin of `circuit-breaker` so that an emergency freeze still
//! requires quorum.
//!
//! ## Storage and TTL policy
//!
//! All state (signer set, threshold, pending proposals, next proposal ID,
//! pause flag) lives in **instance storage**, which shares a single TTL with
//! the contract instance entry. Every write path calls
//! `extend_instance_ttl`, which extends that TTL to
//! [`INSTANCE_TTL_EXTEND_TO`] ledgers (~30 days at ~5s/ledger) whenever the
//! remaining TTL has fallen below [`INSTANCE_TTL_THRESHOLD`] ledgers
//! (~1 day). A multisig that is written to at least once a month therefore
//! never becomes archived; one that sits idle longer must be restored (e.g.
//! `stellar contract restore`) before its admin powers can be exercised,
//! otherwise every governed primitive's `require_auth()` would fail.
#![no_std]

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractevent, contractimpl, contracttype,
    crypto::Hash,
    Address, Env, Vec,
};

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

mod events {
    use soroban_sdk::{symbol_short, Address, Env};

    /// Emitted when a new signer is added to the set.
    ///
    /// topics : [Symbol("SignerAdded"), Address(signer)]
    /// data   : Void
    pub fn signer_added(env: &Env, signer: &Address) {
        env.events()
            .publish((symbol_short!("SignerAdd"), signer.clone()), ());
    }

    /// Emitted when a signer is removed from the set.
    ///
    /// topics : [Symbol("SignerRemoved"), Address(signer)]
    /// data   : Void
    pub fn signer_removed(env: &Env, signer: &Address) {
        env.events()
            .publish((symbol_short!("SignerRm"), signer.clone()), ());
    }

    /// Emitted when the signing threshold is updated.
    ///
    /// topics : [Symbol("ThresholdSet")]
    /// data   : u32 (new threshold)
    pub fn threshold_updated(env: &Env, threshold: u32) {
        env.events()
            .publish((symbol_short!("ThreshSet"),), threshold);
    }

    /// Emitted on every successful `__check_auth` call.
    ///
    /// topics : [Symbol("AuthOk")]
    /// data   : (u32 valid_count, u32 threshold)  — encoded as a two-element
    ///          Vec so both values travel in a single ScVal.
    pub fn auth_approved(env: &Env, valid_count: u32, threshold: u32) {
        env.events()
            .publish((symbol_short!("AuthOk"),), (valid_count, threshold));
    }
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

/// Extend the instance TTL when it drops below this many ledgers
/// (~1 day at ~5s/ledger).
pub const INSTANCE_TTL_THRESHOLD: u32 = 17_280;

/// Target remaining instance TTL after extension (~30 days at ~5s/ledger).
pub const INSTANCE_TTL_EXTEND_TO: u32 = 518_400;

/// Refresh the TTL of the contract instance (and therefore of every
/// instance-storage entry: signers, threshold, proposals, pause flag).
/// Called on every write path so live state survives Soroban archival.
fn extend_instance_ttl(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);
}

#[contracttype]
#[derive(Clone)]
struct Proposal {
    /// The payload to execute (opaque bytes).
    pub payload: soroban_sdk::Bytes,
    /// Ledger sequence at which this proposal expires.
    pub expiry: u32,
    /// Addresses that have approved this proposal.
    pub approvals: Vec<Address>,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// `Vec<Address>` — the current signer set.
    Signers,
    /// `u32` — minimum number of signers required to authorize.
    Threshold,
    /// `Proposal` — a pending proposal keyed by its ID.
    Proposal(u64),
    /// `u64` — the next proposal ID to assign.
    NextProposalId,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// Contract has not been initialized yet.
    NotInitialized = 1,
    /// `initialize` was called more than once.
    AlreadyInitialized = 2,
    /// The number of valid signatures in the provided set is below threshold.
    ThresholdNotMet = 3,
    /// Threshold value is invalid (zero, or greater than signer count).
    InvalidThreshold = 4,
    /// The address to remove is not currently in the signer set.
    SignerNotFound = 5,
    /// The address to add is already in the signer set.
    AlreadySigner = 6,
    /// The same signer address appears more than once in the provided
    /// signature set for a single `__check_auth` call.
    DuplicateSignature = 7,
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct MultisigAdmin;

#[contractimpl]
impl MultisigAdmin {
    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /// One-time setup. `signers` is the initial signer set; `threshold` is
    /// the minimum number of valid signatures required (`1 <= threshold <=
    /// signers.len()`).
    pub fn initialize(
        env: Env,
        signers: Vec<Address>,
        threshold: u32,
    ) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Threshold) {
            return Err(Error::AlreadyInitialized);
        }
        if threshold == 0 || threshold as usize > signers.len() as usize {
            return Err(Error::InvalidThreshold);
        }
        env.storage().instance().set(&DataKey::Signers, &signers);
        env.storage()
            .instance()
            .set(&DataKey::Threshold, &threshold);
        extend_instance_ttl(&env);
        Ok(())
    }

    /// Pause the contract to prevent new proposals/approvals. Requires multisig threshold.
    pub fn pause(env: Env) -> Result<(), Error> {
        env.current_contract_address().require_auth();
        compliance_pausable::pause(&env);
        extend_instance_ttl(&env);
        env.events().publish((), soroban_sdk::symbol_short!("Paused"));
        Ok(())
    }

    /// Resume operations after a pause. Requires multisig threshold.
    pub fn unpause(env: Env) -> Result<(), Error> {
        env.current_contract_address().require_auth();
        compliance_pausable::unpause(&env);
        extend_instance_ttl(&env);
        env.events().publish((), soroban_sdk::symbol_short!("Unpaused"));
        Ok(())
    }

    /// Check if the contract is currently paused.
    pub fn is_paused(env: Env) -> bool {
        compliance_pausable::is_paused(&env)
    }

    // -----------------------------------------------------------------------
    // Signer-set management (all require the current multisig threshold)
    // -----------------------------------------------------------------------

    /// Add `new_signer` to the signer set. Requires the current M-of-N
    /// threshold to be met (the call goes through `__check_auth`).
    pub fn add_signer(env: Env, new_signer: Address) -> Result<(), Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        // Require auth from this contract itself — satisfied by __check_auth.
        env.current_contract_address().require_auth();

        let mut signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .ok_or(Error::NotInitialized)?;

        // Reject duplicates.
        for i in 0..signers.len() {
            if signers.get(i).unwrap() == new_signer {
                return Err(Error::AlreadySigner);
            }
        }

        signers.push_back(new_signer.clone());
        env.storage().instance().set(&DataKey::Signers, &signers);
        extend_instance_ttl(&env);
        events::signer_added(&env, &new_signer);
        Ok(())
    }

    /// Remove `signer` from the signer set. Requires the current M-of-N
    /// threshold. The resulting signer count must still be >= threshold.
    pub fn remove_signer(env: Env, signer: Address) -> Result<(), Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        env.current_contract_address().require_auth();

        let mut signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .ok_or(Error::NotInitialized)?;
        let threshold: u32 = env
            .storage()
            .instance()
            .get(&DataKey::Threshold)
            .ok_or(Error::NotInitialized)?;

        // Find the index of the signer to remove.
        let mut found_index: Option<u32> = None;
        for i in 0..signers.len() {
            if signers.get(i).unwrap() == signer {
                found_index = Some(i);
                break;
            }
        }
        let index = found_index.ok_or(Error::SignerNotFound)?;

        signers.remove(index);

        // Guard: resulting count must still satisfy the threshold.
        if (signers.len() as u32) < threshold {
            return Err(Error::InvalidThreshold);
        }

        env.storage().instance().set(&DataKey::Signers, &signers);
        extend_instance_ttl(&env);
        events::signer_removed(&env, &signer);
        Ok(())
    }

    /// Update the signing threshold. Requires the current M-of-N threshold.
    pub fn update_threshold(env: Env, threshold: u32) -> Result<(), Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        env.current_contract_address().require_auth();

        let signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .ok_or(Error::NotInitialized)?;

        if threshold == 0 || threshold as usize > signers.len() as usize {
            return Err(Error::InvalidThreshold);
        }

        env.storage()
            .instance()
            .set(&DataKey::Threshold, &threshold);
        extend_instance_ttl(&env);
        events::threshold_updated(&env, threshold);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Read-only accessors
    // -----------------------------------------------------------------------

    /// Returns the currently configured signer set together with the
    /// signing threshold, as `(signers, threshold)`. Used by off-chain
    /// tooling (e.g. the indexer) and by other contracts deciding whether to
    /// trust this contract as an admin.
    pub fn get_signers(env: Env) -> (Vec<Address>, u32) {
        let signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .unwrap_or_else(|| Vec::new(&env));
        let threshold: u32 = env
            .storage()
            .instance()
            .get(&DataKey::Threshold)
            .unwrap_or(0);
        (signers, threshold)
    }

    pub fn get_threshold(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::Threshold)
            .unwrap_or(0)
    }

    // -----------------------------------------------------------------------
    // Proposal workflow
    // -----------------------------------------------------------------------

    /// Create a new proposal with the given payload. Returns the proposal ID.
    /// The proposal expires at `expiry_ledger`.
    pub fn propose(
        env: Env,
        payload: soroban_sdk::Bytes,
        expiry_ledger: u32,
    ) -> Result<u64, Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        let current_ledger = env.ledger().sequence();
        if expiry_ledger <= current_ledger {
            return Err(Error::ExpiredProposal);
        }

        let proposal_id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextProposalId)
            .unwrap_or(0);

        let signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .ok_or(Error::NotInitialized)?;

        let proposal = Proposal {
            payload,
            expiry: expiry_ledger,
            approvals: Vec::new(&env),
        };

        env.storage()
            .instance()
            .set(&DataKey::Proposal(proposal_id), &proposal);
        env.storage()
            .instance()
            .set(&DataKey::NextProposalId, &(proposal_id + 1));
        extend_instance_ttl(&env);

        Ok(proposal_id)
    }

    /// Approve a proposal. The approver must be a valid signer. A signer can
    /// only approve once. Returns true if the proposal now has enough approvals
    /// to execute.
    pub fn approve(env: Env, proposal_id: u64, approver: Address) -> Result<bool, Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        let current_ledger = env.ledger().sequence();

        let mut proposal: Proposal = env
            .storage()
            .instance()
            .get(&DataKey::Proposal(proposal_id))
            .ok_or(Error::ProposalNotFound)?;

        if current_ledger >= proposal.expiry {
            return Err(Error::ExpiredProposal);
        }

        let signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .ok_or(Error::NotInitialized)?;

        // Verify approver is in the signer set.
        let mut is_valid_signer = false;
        for i in 0..signers.len() {
            if signers.get(i).unwrap() == approver {
                is_valid_signer = true;
                break;
            }
        }
        if !is_valid_signer {
            return Err(Error::ThresholdNotMet);
        }

        // Check if already approved.
        for i in 0..proposal.approvals.len() {
            if proposal.approvals.get(i).unwrap() == approver {
                return Ok(false);
            }
        }

        proposal.approvals.push_back(approver);
        env.storage()
            .instance()
            .set(&DataKey::Proposal(proposal_id), &proposal);
        extend_instance_ttl(&env);

        let threshold: u32 = env
            .storage()
            .instance()
            .get(&DataKey::Threshold)
            .ok_or(Error::NotInitialized)?;

        Ok(proposal.approvals.len() as u32 >= threshold)
    }

    /// Execute a proposal. Requires that it has at least `threshold` approvals
    /// and has not expired. After execution, the proposal is deleted.
    pub fn execute(env: Env, proposal_id: u64) -> Result<(), Error> {
        let current_ledger = env.ledger().sequence();

        let proposal: Proposal = env
            .storage()
            .instance()
            .get(&DataKey::Proposal(proposal_id))
            .ok_or(Error::ProposalNotFound)?;

        if current_ledger >= proposal.expiry {
            return Err(Error::ExpiredProposal);
        }

        let threshold: u32 = env
            .storage()
            .instance()
            .get(&DataKey::Threshold)
            .ok_or(Error::NotInitialized)?;

        if (proposal.approvals.len() as u32) < threshold {
            return Err(Error::ThresholdNotMet);
        }

        env.storage()
            .instance()
            .remove(&DataKey::Proposal(proposal_id));
        extend_instance_ttl(&env);

        Ok(())
    }

    /// Get the details of a proposal (payload, expiry, current approvals).
    pub fn get_proposal(
        env: Env,
        proposal_id: u64,
    ) -> Result<(soroban_sdk::Bytes, u32, Vec<Address>), Error> {
        let proposal: Proposal = env
            .storage()
            .instance()
            .get(&DataKey::Proposal(proposal_id))
            .ok_or(Error::ProposalNotFound)?;
        Ok((proposal.payload, proposal.expiry, proposal.approvals))
    }
}

// ---------------------------------------------------------------------------
// Custom account interface — the heart of the multisig pattern
// ---------------------------------------------------------------------------

impl CustomAccountInterface for MultisigAdmin {
    /// The signature type is a `Vec<Address>` — the list of approving signer
    /// addresses. The invoker must provide at least `threshold` addresses that
    /// are all present in the stored signer set. Each address in the list must
    /// also call `require_auth()` within the same transaction (Soroban's auth
    /// framework verifies this automatically when the transaction is submitted).
    type Signature = Vec<Address>;
    type Error = Error;

    /// Called by the Soroban host whenever something requires auth from this
    /// contract's address. Counts how many entries in `signatures` appear in
    /// the stored signer set; if the count meets the threshold, authorization
    /// succeeds.
    ///
    /// `signature_payload` and `auth_context` are provided by the host for
    /// advanced use-cases (replay prevention, context-specific auth) but are
    /// not required for this reference implementation.
    #[allow(unused_variables)]
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signatures: Vec<Address>,
        auth_context: Vec<Context>,
    ) -> Result<(), Error> {
        let signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .ok_or(Error::NotInitialized)?;
        let threshold: u32 = env
            .storage()
            .instance()
            .get(&DataKey::Threshold)
            .ok_or(Error::NotInitialized)?;

        // Reject if the same signer address appears more than once in the
        // provided signature set — otherwise a single signer's approval
        // could be duplicated to satisfy the threshold on its own.
        for i in 0..signatures.len() {
            let addr_i = signatures.get(i).unwrap();
            for j in (i + 1)..signatures.len() {
                if signatures.get(j).unwrap() == addr_i {
                    return Err(Error::DuplicateSignature);
                }
            }
        }

        let mut valid_count: u32 = 0;

        for i in 0..signatures.len() {
            let sig_addr = signatures.get(i).unwrap();
            // Each approving address must prove it authorized this call.
            sig_addr.require_auth();

            // Check whether this signer is in the authorized set.
            for j in 0..signers.len() {
                if signers.get(j).unwrap() == sig_addr {
                    valid_count += 1;
                    break;
                }
            }
        }

        if valid_count >= threshold {
            events::auth_approved(&env, valid_count, threshold);
            Ok(())
        } else {
            Err(Error::ThresholdNotMet)
        }
    }
}

#[cfg(test)]
mod test;
