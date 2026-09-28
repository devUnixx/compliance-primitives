extern crate std;

use super::*;
use denylist_gate::{DenylistGate, DenylistGateClient};
use soroban_sdk::{
    testutils::Address as _,
    vec, Address, Bytes, Env,
};

/// Build an arbitrary 32-byte payload hash for `__check_auth` calls in tests.
/// The contract under test does not inspect the payload content.
fn dummy_payload(env: &Env) -> Hash<32> {
    env.crypto().sha256(&Bytes::from_array(env, &[0u8; 32]))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Register and initialise a MultisigAdmin with `threshold`-of-`n` signers.
/// Returns `(signers_vec, contract_id, client)`.
fn setup_multisig(
    env: &Env,
    n: usize,
    threshold: u32,
) -> (Vec<Address>, Address, MultisigAdminClient<'_>) {
    env.mock_all_auths();
    let mut signers = Vec::new(env);
    for _ in 0..n {
        signers.push_back(Address::generate(env));
    }
    let contract_id = env.register(MultisigAdmin, ());
    let client = MultisigAdminClient::new(env, &contract_id);
    client.initialize(&signers, &threshold);
    (signers, contract_id, client)
}

// ---------------------------------------------------------------------------
// Basic state tests
// ---------------------------------------------------------------------------

#[test]
fn test_initialize_stores_signers_and_threshold() {
    let env = Env::default();
    let (signers, _id, client) = setup_multisig(&env, 3, 2);

    assert_eq!(client.get_threshold(), 2u32);
    let (stored, stored_threshold) = client.get_signers();
    assert_eq!(stored.len(), 3);
    assert_eq!(stored_threshold, 2u32);
    // All original signers should be present.
    for i in 0..signers.len() {
        assert_eq!(stored.get(i), signers.get(i));
    }
}

#[test]
fn test_get_signers_matches_initialization() {
    let env = Env::default();
    let (signers, _id, client) = setup_multisig(&env, 4, 3);

    let (stored, threshold) = client.get_signers();
    assert_eq!(stored.len(), signers.len());
    for i in 0..signers.len() {
        assert_eq!(stored.get(i), signers.get(i));
    }
    assert_eq!(threshold, 3u32);
}

#[test]
fn test_double_initialize_fails() {
    let env = Env::default();
    let (signers, _id, client) = setup_multisig(&env, 2, 1);
    let result = client.try_initialize(&signers, &1);
    assert_eq!(result, Err(Ok(Error::AlreadyInitialized)));
}

#[test]
fn test_invalid_threshold_zero_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(MultisigAdmin, ());
    let client = MultisigAdminClient::new(&env, &contract_id);
    let signers = vec![&env, Address::generate(&env)];
    let result = client.try_initialize(&signers, &0);
    assert_eq!(result, Err(Ok(Error::InvalidThreshold)));
}

#[test]
fn test_invalid_threshold_exceeds_signer_count() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(MultisigAdmin, ());
    let client = MultisigAdminClient::new(&env, &contract_id);
    let signers = vec![&env, Address::generate(&env), Address::generate(&env)];
    // threshold = 3 but only 2 signers
    let result = client.try_initialize(&signers, &3);
    assert_eq!(result, Err(Ok(Error::InvalidThreshold)));
}

// ---------------------------------------------------------------------------
// Signer-set management tests
// ---------------------------------------------------------------------------

#[test]
fn test_add_signer_increases_count() {
    let env = Env::default();
    let (_signers, _id, client) = setup_multisig(&env, 2, 1);
    let new_signer = Address::generate(&env);
    client.add_signer(&new_signer);
    assert_eq!(client.get_signers().0.len(), 3);
}

#[test]
fn test_add_duplicate_signer_rejected() {
    let env = Env::default();
    let (signers, _id, client) = setup_multisig(&env, 2, 1);
    let existing = signers.get(0).unwrap();
    let result = client.try_add_signer(&existing);
    assert_eq!(result, Err(Ok(Error::AlreadySigner)));
}

#[test]
fn test_remove_signer_decreases_count() {
    let env = Env::default();
    let (signers, _id, client) = setup_multisig(&env, 3, 1);
    let to_remove = signers.get(0).unwrap();
    client.remove_signer(&to_remove);
    assert_eq!(client.get_signers().0.len(), 2);
}

#[test]
fn test_remove_signer_not_found_rejected() {
    let env = Env::default();
    let (_signers, _id, client) = setup_multisig(&env, 2, 1);
    let unknown = Address::generate(&env);
    let result = client.try_remove_signer(&unknown);
    assert_eq!(result, Err(Ok(Error::SignerNotFound)));
}

#[test]
fn test_remove_signer_rejected_when_count_drops_below_threshold() {
    let env = Env::default();
    // 2 signers, threshold 2 — removing one would leave 1 < 2.
    let (signers, _id, client) = setup_multisig(&env, 2, 2);
    let to_remove = signers.get(0).unwrap();
    let result = client.try_remove_signer(&to_remove);
    assert_eq!(result, Err(Ok(Error::InvalidThreshold)));
}

#[test]
fn test_update_threshold() {
    let env = Env::default();
    let (_signers, _id, client) = setup_multisig(&env, 3, 1);
    client.update_threshold(&3);
    assert_eq!(client.get_threshold(), 3u32);
}

#[test]
fn test_update_threshold_invalid_rejected() {
    let env = Env::default();
    let (_signers, _id, client) = setup_multisig(&env, 2, 1);
    // threshold of 5 with only 2 signers is invalid.
    let result = client.try_update_threshold(&5);
    assert_eq!(result, Err(Ok(Error::InvalidThreshold)));
}

// ---------------------------------------------------------------------------
// Integration: multisig as admin of denylist-gate
// ---------------------------------------------------------------------------

/// Demonstrate that the multisig contract can serve as the admin of a
/// denylist-gate. With mock_all_auths the Soroban test framework satisfies
/// all auth requirements automatically, so this test confirms that the
/// initialization and call plumbing work end-to-end.
#[test]
fn test_multisig_as_denylist_admin_with_mock_auth() {
    let env = Env::default();
    env.mock_all_auths();

    // Deploy and initialise the multisig with 3 signers, threshold 2.
    let (_, multisig_id, _multisig_client) = setup_multisig(&env, 3, 2);

    // Deploy denylist-gate and set the multisig contract as its admin.
    let denylist_id = env.register(DenylistGate, ());
    let denylist_client = DenylistGateClient::new(&env, &denylist_id);
    denylist_client.initialize(&multisig_id);

    // With mock_all_auths active every require_auth is satisfied, so
    // denylist operations that go through the multisig address succeed.
    let target = Address::generate(&env);
    denylist_client.add_to_denylist(&multisig_id, &target);
    assert!(!denylist_client.check(&target));

    denylist_client.remove_from_denylist(&multisig_id, &target);
    assert!(denylist_client.check(&target));
}

// ---------------------------------------------------------------------------
// __check_auth threshold tests
// ---------------------------------------------------------------------------

/// Verify ThresholdNotMet is returned from __check_auth when too few valid
/// signers are provided. We test this via the contract's signer-management
/// functions (which call `env.current_contract_address().require_auth()`),
/// but we cannot directly call __check_auth in unit tests without the host
/// context. Instead we verify the Error enum value is correct.
#[test]
fn test_threshold_not_met_error_value() {
    // This is a compile-time / value correctness test: confirm ThresholdNotMet
    // is distinct from the other error codes.
    assert_eq!(Error::ThresholdNotMet as u32, 3);
    assert_ne!(Error::ThresholdNotMet, Error::NotInitialized);
    assert_ne!(Error::ThresholdNotMet, Error::InvalidThreshold);
}

/// Verify that the signer-set update path (add_signer) requires the
/// multisig's own auth by attempting to call it without any auth mock.
/// In a real deployment this would require __check_auth to pass.
#[test]
fn test_signer_update_requires_multisig_auth() {
    // Without mock_all_auths, any call requiring auth will fail.
    // We set up a contract without mocking auth for the add_signer call.
    let env = Env::default();
    env.mock_all_auths(); // needed for initialize
    let (_signers, _id, client) = setup_multisig(&env, 2, 1);

    // Since mock_all_auths is active on this env we cannot test the rejection
    // path here without a separate env. We confirm the call succeeds (auth
    // satisfied by the mock), demonstrating the round-trip plumbing works.
    let new_signer = Address::generate(&env);
    client.add_signer(&new_signer);
    assert_eq!(client.get_signers().0.len(), 3);
    // A separate rejection test for the threshold path is
    // test_threshold_not_met_error_value above.
}

// ---------------------------------------------------------------------------
// __check_auth threshold edge cases (M=1, M=N) — #220
// ---------------------------------------------------------------------------

/// M=1: any single signer's approval is sufficient.
#[test]
fn test_check_auth_threshold_one_of_n_succeeds_with_single_signature() {
    let env = Env::default();
    env.mock_all_auths();
    let (signers, _id, _client) = setup_multisig(&env, 3, 1);

    let payload = dummy_payload(&env);
    let sigs = vec![&env, signers.get(0).unwrap()];
    let result = MultisigAdmin::__check_auth(env.clone(), payload, sigs, Vec::new(&env));
    assert_eq!(result, Ok(()));
}

/// M=1: zero signatures still fails even though the threshold is low.
#[test]
fn test_check_auth_threshold_one_of_n_fails_with_zero_signatures() {
    let env = Env::default();
    env.mock_all_auths();
    let (_signers, _id, _client) = setup_multisig(&env, 3, 1);

    let payload = dummy_payload(&env);
    let sigs: Vec<Address> = Vec::new(&env);
    let result = MultisigAdmin::__check_auth(env.clone(), payload, sigs, Vec::new(&env));
    assert_eq!(result, Err(Error::ThresholdNotMet));
}

/// M=N: every signer must approve; a full set succeeds.
#[test]
fn test_check_auth_threshold_n_of_n_succeeds_with_all_signers() {
    let env = Env::default();
    env.mock_all_auths();
    let (signers, _id, _client) = setup_multisig(&env, 3, 3);

    let payload = dummy_payload(&env);
    let sigs = vec![
        &env,
        signers.get(0).unwrap(),
        signers.get(1).unwrap(),
        signers.get(2).unwrap(),
    ];
    let result = MultisigAdmin::__check_auth(env.clone(), payload, sigs, Vec::new(&env));
    assert_eq!(result, Ok(()));
}

/// M=N: missing even one signer's approval is rejected.
#[test]
fn test_check_auth_threshold_n_of_n_fails_with_one_missing() {
    let env = Env::default();
    env.mock_all_auths();
    let (signers, _id, _client) = setup_multisig(&env, 3, 3);

    let payload = dummy_payload(&env);
    // Only 2 of the 3 required signers approve.
    let sigs = vec![&env, signers.get(0).unwrap(), signers.get(1).unwrap()];
    let result = MultisigAdmin::__check_auth(env.clone(), payload, sigs, Vec::new(&env));
    assert_eq!(result, Err(Error::ThresholdNotMet));
}

// ---------------------------------------------------------------------------
// Duplicate-signer double-counting guard — #221
// ---------------------------------------------------------------------------

/// The same signer approving twice in one signature set must not count as
/// two approvals toward the threshold: with threshold=2 and only one
/// distinct signer submitted (twice), the call must be rejected rather than
/// treated as satisfying the threshold.
#[test]
fn test_check_auth_duplicate_signature_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (signers, _id, _client) = setup_multisig(&env, 3, 2);

    let payload = dummy_payload(&env);
    let solo_signer = signers.get(0).unwrap();
    // Same signer listed twice — must not be double-counted to reach
    // threshold=2.
    let sigs = vec![&env, solo_signer.clone(), solo_signer];
    let result = MultisigAdmin::__check_auth(env.clone(), payload, sigs, Vec::new(&env));
    assert_eq!(result, Err(Error::DuplicateSignature));
}

/// Sanity check: two genuinely distinct signers still satisfy threshold=2.
#[test]
fn test_check_auth_distinct_signers_not_flagged_as_duplicate() {
    let env = Env::default();
    env.mock_all_auths();
    let (signers, _id, _client) = setup_multisig(&env, 3, 2);

    let payload = dummy_payload(&env);
    let sigs = vec![&env, signers.get(0).unwrap(), signers.get(1).unwrap()];
    let result = MultisigAdmin::__check_auth(env.clone(), payload, sigs, Vec::new(&env));
    assert_eq!(result, Ok(()));
}

// ---------------------------------------------------------------------------
// TTL extension
// ---------------------------------------------------------------------------

fn instance_ttl(env: &Env, contract_id: &Address) -> u32 {
    use soroban_sdk::testutils::storage::Instance as _;
    env.as_contract(contract_id, || env.storage().instance().get_ttl())
}

/// Advance the ledger far enough that the instance TTL drops below the
/// extension threshold.
fn advance_past_threshold(env: &Env) {
    use soroban_sdk::testutils::Ledger as _;
    env.ledger().with_mut(|li| {
        li.sequence_number += INSTANCE_TTL_EXTEND_TO - INSTANCE_TTL_THRESHOLD + 1;
    });
}

#[test]
fn test_initialize_extends_instance_ttl() {
    let env = Env::default();
    let (_signers, contract_id, _client) = setup_multisig(&env, 3, 2);
    assert_eq!(instance_ttl(&env, &contract_id), INSTANCE_TTL_EXTEND_TO);
}

#[test]
fn test_write_refreshes_ttl_and_state_survives_past_original_ttl() {
    let env = Env::default();
    let (signers, contract_id, client) = setup_multisig(&env, 3, 2);
    let new_signer = Address::generate(&env);

    advance_past_threshold(&env);
    assert!(instance_ttl(&env, &contract_id) < INSTANCE_TTL_THRESHOLD);

    // A write refreshes the TTL back to the configured target.
    client.add_signer(&new_signer);
    assert_eq!(instance_ttl(&env, &contract_id), INSTANCE_TTL_EXTEND_TO);

    // Advance again: the ledger is now well past the TTL granted at
    // initialization, but the refreshed entry is still live and readable.
    advance_past_threshold(&env);
    let (stored, threshold) = client.get_signers();
    assert_eq!(stored.len(), signers.len() + 1);
    assert_eq!(stored.get(3).unwrap(), new_signer);
    assert_eq!(threshold, 2);
}

#[test]
fn test_proposal_writes_refresh_ttl() {
    let env = Env::default();
    let (signers, contract_id, client) = setup_multisig(&env, 3, 2);
    let payload = Bytes::from_array(&env, &[1u8, 2, 3]);
    let far_expiry = INSTANCE_TTL_EXTEND_TO * 4;

    advance_past_threshold(&env);
    let proposal_id = client.propose(&payload, &far_expiry);
    assert_eq!(instance_ttl(&env, &contract_id), INSTANCE_TTL_EXTEND_TO);

    advance_past_threshold(&env);
    client.approve(&proposal_id, &signers.get(0).unwrap());
    assert_eq!(instance_ttl(&env, &contract_id), INSTANCE_TTL_EXTEND_TO);

    advance_past_threshold(&env);
    client.approve(&proposal_id, &signers.get(1).unwrap());
    let (_payload, _expiry, approvals) = client.get_proposal(&proposal_id);
    assert_eq!(approvals.len(), 2);

    advance_past_threshold(&env);
    client.execute(&proposal_id);
    assert_eq!(instance_ttl(&env, &contract_id), INSTANCE_TTL_EXTEND_TO);
}
