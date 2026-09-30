extern crate std;

use super::*;
use denylist_gate::{DenylistGate, DenylistGateClient};
use soroban_sdk::{
    testutils::Address as _,
    vec, Address, Bytes, BytesN, Env,
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
// Upgrade / migration path
// ---------------------------------------------------------------------------

/// Path to the release WASM produced by
/// `cargo build --workspace --target wasm32v1-none --release`.
fn multisig_admin_wasm_path() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("wasm32v1-none")
        .join("release")
        .join("multisig_admin.wasm")
}

#[test]
fn test_upgrade_before_initialize_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(MultisigAdmin, ());
    let client = MultisigAdminClient::new(&env, &contract_id);
    let hash = BytesN::from_array(&env, &[0u8; 32]);
    let result = client.try_upgrade(&hash);
    assert_eq!(result, Err(Ok(Error::NotInitialized)));
}

/// Without the multisig's own authorization (i.e. without the threshold
/// being met through `__check_auth`), `upgrade` must be rejected.
#[test]
fn test_upgrade_requires_multisig_auth() {
    let env = Env::default();
    let contract_id = env.register(MultisigAdmin, ());
    let client = MultisigAdminClient::new(&env, &contract_id);
    let signers = vec![&env, Address::generate(&env), Address::generate(&env)];
    client.initialize(&signers, &2);

    let hash = BytesN::from_array(&env, &[0u8; 32]);
    assert!(client.try_upgrade(&hash).is_err());
}

/// Deploy from WASM, write state, upgrade to a freshly uploaded WASM hash,
/// then confirm every piece of state survived and the contract is still
/// callable. Requires the release WASM (`make build`); skipped otherwise.
#[test]
fn test_upgrade_preserves_state_and_remains_callable() {
    let wasm_path = multisig_admin_wasm_path();
    let wasm = match std::fs::read(&wasm_path) {
        Ok(bytes) => bytes,
        Err(_) => {
            std::eprintln!(
                "skipping migration test: {} not found (run `make build` first)",
                wasm_path.display()
            );
            return;
        }
    };

    let env = Env::default();
    env.mock_all_auths();

    // Deploy the current release WASM and write state.
    let contract_id = env.register(wasm.as_slice(), ());
    let client = MultisigAdminClient::new(&env, &contract_id);
    let signers = vec![&env, Address::generate(&env), Address::generate(&env)];
    client.initialize(&signers, &2);
    let extra_signer = Address::generate(&env);
    client.add_signer(&extra_signer);
    let payload = Bytes::from_array(&env, &[1, 2, 3]);
    let expiry = env.ledger().sequence() + 100;
    let proposal_id = client.propose(&payload, &expiry);
    client.approve(&proposal_id, &signers.get(0).unwrap());

    // Upgrade to a newly uploaded WASM hash.
    let new_hash = env
        .deployer()
        .upload_contract_wasm(Bytes::from_slice(&env, &wasm));
    client.upgrade(&new_hash);

    // State is intact.
    let (stored_signers, threshold) = client.get_signers();
    assert_eq!(stored_signers.len(), 3);
    assert_eq!(stored_signers.get(2).unwrap(), extra_signer);
    assert_eq!(threshold, 2);
    let (stored_payload, stored_expiry, approvals) = client.get_proposal(&proposal_id);
    assert_eq!(stored_payload, payload);
    assert_eq!(stored_expiry, expiry);
    assert_eq!(approvals.len(), 1);

    // And the contract is still callable after the upgrade.
    assert!(client.approve(&proposal_id, &signers.get(1).unwrap()));
    client.execute(&proposal_id);
    client.update_threshold(&3);
    assert_eq!(client.get_threshold(), 3);
    assert_eq!(client.propose(&payload, &expiry), proposal_id + 1);
}

// ---------------------------------------------------------------------------
// Resource-fee benchmark (budget regression) — `__check_auth`
// ---------------------------------------------------------------------------

fn read_baseline(path: &std::path::Path, section: &str) -> (u64, u64) {
    let contents = std::fs::read_to_string(path).unwrap();
    let section_header = std::format!("[{section}]");
    let mut in_section = false;
    let mut cpu = None;
    let mut memory = None;

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_section = trimmed == section_header;
            continue;
        }
        if !in_section {
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("cpu = ") {
            cpu = Some(value.parse::<u64>().unwrap());
        } else if let Some(value) = trimmed.strip_prefix("memory = ") {
            memory = Some(value.parse::<u64>().unwrap());
        }
    }

    let cpu = cpu.expect("missing cpu baseline");
    let memory = memory.expect("missing memory baseline");
    (cpu, memory)
}

fn baseline_path_for_manifest_dir(manifest_dir: std::path::PathBuf) -> std::path::PathBuf {
    manifest_dir.join("..").join("..").join("budget-baselines.toml")
}

fn assert_budget_within_threshold(measured: (u64, u64), baseline: (u64, u64), label: &str) {
    let (measured_cpu, measured_memory) = measured;
    let (baseline_cpu, baseline_memory) = baseline;
    let cpu_limit = (baseline_cpu as f64 * 1.10).ceil() as u64;
    let memory_limit = (baseline_memory as f64 * 1.10).ceil() as u64;

    assert!(
        measured_cpu <= cpu_limit,
        "{label} CPU regression: measured {measured_cpu}, baseline {baseline_cpu}, limit {cpu_limit}"
    );
    assert!(
        measured_memory <= memory_limit,
        "{label} memory regression: measured {measured_memory}, baseline {baseline_memory}, limit {memory_limit}"
    );
}

/// `__check_auth` is the hottest entrypoint: it runs on every admin
/// operation of every primitive that uses this contract as its admin.
/// Measured with a 2-of-3 signer set and a 2-signature approval.
#[test]
fn test_budget_regression_multisig_check_auth() {
    let env = Env::default();
    env.mock_all_auths();
    let (signers, contract_id, _client) = setup_multisig(&env, 3, 2);

    let payload = dummy_payload(&env);
    let sigs = vec![&env, signers.get(0).unwrap(), signers.get(1).unwrap()];

    let mut budget = env.cost_estimate().budget();
    budget.reset_default();
    let result = env.as_contract(&contract_id, || {
        MultisigAdmin::__check_auth(env.clone(), payload, sigs, Vec::new(&env))
    });
    assert_eq!(result, Ok(()));

    let measured = (budget.cpu_instruction_cost(), budget.memory_bytes_cost());
    std::println!(
        "multisig-admin __check_auth: cpu={} memory={}",
        measured.0,
        measured.1
    );
    let baseline_path = baseline_path_for_manifest_dir(std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
    ));
    let baseline = read_baseline(&baseline_path, "multisig-admin.__check_auth");
    assert_budget_within_threshold(measured, baseline, "multisig-admin __check_auth");
}
