use super::*;
use soroban_sdk::testutils::storage::Persistent as _;
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::{vec, Env, IntoVal, Map, Symbol, Val};
use std::path::{Path, PathBuf};

fn setup(env: &Env) -> (Address, Address, DenylistGateClient<'_>) {
    env.mock_all_auths();
    let admin = Address::generate(env);
    let contract_id = env.register(DenylistGate, ());
    let client = DenylistGateClient::new(env, &contract_id);
    client.initialize(&admin);
    (admin, contract_id, client)
}

fn read_baseline(path: &Path, section: &str) -> (u64, u64) {
    let contents = std::fs::read_to_string(path).unwrap();
    let section_header = format!("[{section}]");
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

fn baseline_path_for_manifest_dir(manifest_dir: PathBuf) -> PathBuf {
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

#[test]
fn test_check_defaults_to_clear() {
    let env = Env::default();
    let (_admin, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    assert!(client.check(&alice));
}

#[test]
fn test_compliance_officer_view_tracks_assignment_and_revocation() {
    let env = Env::default();
    let (admin, _contract_id, client) = setup(&env);
    let officer = Address::generate(&env);

    assert_eq!(client.get_compliance_officer(), None);
    client.set_compliance_officer(&admin, &officer);
    assert_eq!(client.get_compliance_officer(), Some(officer));
    client.revoke_compliance_officer(&admin);
    assert_eq!(client.get_compliance_officer(), None);
}

#[test]
fn bench_add_to_denylist_with_and_without_audit_log() {
    let env = Env::default();
    let (admin, _gate_id, client) = setup(&env);
    let without_audit = Address::generate(&env);
    env.cost_estimate().budget().reset_default();
    client.add_to_denylist(&admin, &without_audit);
    let without_cpu = env.cost_estimate().budget().cpu_instruction_cost();
    let without_memory = env.cost_estimate().budget().memory_bytes_cost();

    let audit_admin = Address::generate(&env);
    let audit_id = env.register(audit_log::AuditLog, ());
    audit_log::AuditLogClient::new(&env, &audit_id).initialize(&audit_admin);
    client.set_audit_log(&admin, &audit_id);
    let with_audit = Address::generate(&env);
    env.cost_estimate().budget().reset_default();
    client.add_to_denylist(&admin, &with_audit);
    let with_cpu = env.cost_estimate().budget().cpu_instruction_cost();
    let with_memory = env.cost_estimate().budget().memory_bytes_cost();

    std::println!("denylist add without audit: cpu={without_cpu} memory={without_memory}; with audit: cpu={with_cpu} memory={with_memory}");
}

#[test]
fn test_budget_regression_denylist_check() {
    let env = Env::default();
    let (_admin, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    let mut budget = env.cost_estimate().budget();
    budget.reset_default();
    let is_clear = client.check(&alice);
    assert!(is_clear);

    let measured = (budget.cpu_instruction_cost(), budget.memory_bytes_cost());
    let baseline_path = baseline_path_for_manifest_dir(PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()));
    let baseline = read_baseline(&baseline_path, "denylist-gate.check");
    assert_budget_within_threshold(measured, baseline, "denylist-gate check");
}

#[test]
fn test_add_and_remove_from_denylist() {
    let env = Env::default();
    let (admin, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    client.add_to_denylist(&admin, &alice);
    assert!(!client.check(&alice));

    client.remove_from_denylist(&admin, &alice);
    assert!(client.check(&alice));
}

#[test]
fn test_is_denylisted_is_inverse_of_check() {
    let env = Env::default();
    let (admin, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    assert_eq!(client.is_denylisted(&alice), !client.check(&alice));

    client.add_to_denylist(&admin, &alice);
    assert_eq!(client.is_denylisted(&alice), !client.check(&alice));

    client.remove_from_denylist(&admin, &alice);
    assert_eq!(client.is_denylisted(&alice), !client.check(&alice));
}

#[test]
fn test_add_to_denylist_rejects_non_admin() {
    let env = Env::default();
    let (_admin, _contract_id, client) = setup(&env);
    let impostor = Address::generate(&env);
    let alice = Address::generate(&env);

    let result = client.try_add_to_denylist(&impostor, &alice);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
    assert!(client.check(&alice));
}

/// Soroban's `Address` type has no literal "empty" or "invalid" value the
/// way a raw string (`""`) would: every `Address` is either a well-formed
/// account or contract identifier, and the host rejects malformed ones
/// before they can ever reach contract code. So there is no empty-address
/// input to test directly.
///
/// What this test guards instead is the default-value invariant for a
/// storage key that has never been written: `check` reads
/// `DataKey::Denied(address)` and falls back via `unwrap_or(false)`, so an
/// untouched address must read as "clear" (`true`) rather than panicking
/// or defaulting to denied.
#[test]
fn test_empty_address_key_is_well_defined() {
    let env = Env::default();
    let (_admin, _contract_id, client) = setup(&env);
    let never_seen = Address::generate(&env);
    assert!(client.check(&never_seen));
}

#[test]
fn test_check_fresh_address_never_referenced_is_clear() {
    let env = Env::default();
    let (admin, _contract_id, client) = setup(&env);

    // Touch the denylist with other addresses so storage is not pristine.
    let bob = Address::generate(&env);
    let carol = Address::generate(&env);
    client.add_to_denylist(&admin, &bob);
    client.add_to_denylist(&admin, &carol);
    client.remove_from_denylist(&admin, &carol);

    // A freshly generated address the contract has never seen in any call.
    let fresh = Address::generate(&env);
    assert!(client.check(&fresh));
    assert!(!client.check(&bob));
}

#[test]
fn test_add_then_remove_returns_to_default_clear_state() {
    let env = Env::default();
    let (admin, contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    client.add_to_denylist(&admin, &alice);
    assert!(!client.check(&alice));

    client.remove_from_denylist(&admin, &alice);
    assert!(client.check(&alice));

    // The storage entry itself must be gone, not left behind as a stale
    // `false` or `true` value.
    env.as_contract(&contract_id, || {
        assert!(!env
            .storage()
            .persistent()
            .has(&DataKey::Denied(alice.clone())));
    });
}

#[test]
fn test_remove_from_denylist_never_added_is_noop() {
    let env = Env::default();
    let (admin, contract_id, client) = setup(&env);
    let never_added = Address::generate(&env);

    assert!(client.check(&never_added));

    client.remove_from_denylist(&admin, &never_added);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                contract_id.clone(),
                (Symbol::new(&env, "deny_remove"), never_added.clone()).into_val(&env),
                Map::<Symbol, Val>::new(&env).into_val(&env),
            ),
        ]
    );
    assert!(client.check(&never_added));
}

#[test]
fn test_remove_multiple_from_denylist_removes_all_and_emits_events() {
    let env = Env::default();
    let (admin, contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    env.storage()
        .persistent()
        .set(&DataKey::Denied(alice.clone()), &true);
    env.storage()
        .persistent()
        .set(&DataKey::Denied(bob.clone()), &true);

    client.remove_multiple_from_denylist(&admin, &vec![&env, alice.clone(), bob.clone()]);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                contract_id.clone(),
                (Symbol::new(&env, "deny_remove"), alice.clone()).into_val(&env),
                Map::<Symbol, Val>::new(&env).into_val(&env),
            ),
            (
                contract_id.clone(),
                (Symbol::new(&env, "deny_remove"), bob.clone()).into_val(&env),
                Map::<Symbol, Val>::new(&env).into_val(&env),
            ),
        ]
    );
    assert!(client.check(&alice));
    assert!(client.check(&bob));
}

#[test]
fn test_remove_multiple_from_denylist_rejects_non_admin() {
    let env = Env::default();
    let (_admin, _contract_id, client) = setup(&env);
    let impostor = Address::generate(&env);
    let alice = Address::generate(&env);

    let result = client.try_remove_multiple_from_denylist(&impostor, &vec![&env, alice.clone()]);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
    assert!(client.check(&alice));
}

#[test]
fn test_remove_multiple_from_denylist_empty_vec_is_noop() {
    let env = Env::default();
    let (admin, _contract_id, client) = setup(&env);

    client.remove_multiple_from_denylist(&admin, &vec![&env]);

    assert_eq!(env.events().all(), vec![&env]);
}

#[test]
fn test_remove_multiple_from_denylist_batch_limit_succeeds() {
    let env = Env::default();
    let (admin, _contract_id, client) = setup(&env);
    let mut addresses: Vec<Address> = Vec::new(&env);

    for _ in 0..MAX_BATCH_SIZE {
        let address = Address::generate(&env);
        env.storage()
            .persistent()
            .set(&DataKey::Denied(address.clone()), &true);
        addresses.push_back(address);
    }

    client.remove_multiple_from_denylist(&admin, &addresses);

    for address in addresses.iter() {
        assert!(client.check(&address));
    }
}

#[test]
fn test_remove_multiple_from_denylist_over_batch_limit_rejected() {
    let env = Env::default();
    let (admin, _contract_id, client) = setup(&env);
    let mut addresses: Vec<Address> = Vec::new(&env);

    for _ in 0..(MAX_BATCH_SIZE + 1) {
        let address = Address::generate(&env);
        env.storage()
            .persistent()
            .set(&DataKey::Denied(address.clone()), &true);
        addresses.push_back(address);
    }

    let first = addresses.get_unchecked(0);
    let result = client.try_remove_multiple_from_denylist(&admin, &addresses);
    assert_eq!(result, Err(Ok(Error::BatchTooLarge)));
    assert!(!client.check(&first));
}

#[test]
fn test_double_initialize_fails() {
    let env = Env::default();
    let (admin, _contract_id, client) = setup(&env);
    let result = client.try_initialize(&admin);
    assert_eq!(result, Err(Ok(Error::AlreadyInitialized)));
}

#[test]
fn test_multisig_initialize() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let signer1 = Address::generate(&env);
    let signer2 = Address::generate(&env);
    let signer3 = Address::generate(&env);

    let contract_id = env.register(DenylistGate, ());
    let client = DenylistGateClient::new(&env, &contract_id);

    // Initialize single-admin first
    client.initialize(&admin);

    // Then convert to multisig (2-of-3)
    let signers = vec![&env, admin.clone(), signer1.clone(), signer2.clone()];
    let result = client.try_initialize_multisig(&admin, &signers, &3);
    assert!(result.is_ok());
}

#[test]
fn test_multisig_invalid_threshold() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let signer1 = Address::generate(&env);

    let contract_id = env.register(DenylistGate, ());
    let client = DenylistGateClient::new(&env, &contract_id);

    client.initialize(&admin);

    // Try to set threshold higher than signer count
    let signers = vec![&env, admin.clone(), signer1.clone()];
    let result = client.try_initialize_multisig(&admin, &signers, &5);
    assert_eq!(result, Err(Ok(Error::InvalidThreshold)));
}

#[test]
fn test_multisig_empty_signers_fails() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register(DenylistGate, ());
    let client = DenylistGateClient::new(&env, &contract_id);

    client.initialize(&admin);

    // Try to initialize with empty signer set
    let signers = vec![&env];
    let result = client.try_initialize_multisig(&admin, &signers, &1);
    assert_eq!(result, Err(Ok(Error::InvalidSignerSet)));
}

#[test]
fn test_multisig_add_signer() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let signer1 = Address::generate(&env);
    let signer2 = Address::generate(&env);
    let new_signer = Address::generate(&env);

    let contract_id = env.register(DenylistGate, ());
    let client = DenylistGateClient::new(&env, &contract_id);

    client.initialize(&admin);

    // Initialize 2-of-2 multisig
    let signers = vec![&env, admin.clone(), signer1.clone()];
    client.initialize_multisig(&admin, &signers, &2);

    // Add a new signer
    let result = client.try_add_signer(&new_signer);
    assert!(result.is_ok());
}

#[test]
fn test_multisig_remove_signer() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let signer1 = Address::generate(&env);
    let signer2 = Address::generate(&env);

    let contract_id = env.register(DenylistGate, ());
    let client = DenylistGateClient::new(&env, &contract_id);

    client.initialize(&admin);

    // Initialize 2-of-3 multisig
    let signers = vec![&env, admin.clone(), signer1.clone(), signer2.clone()];
    client.initialize_multisig(&admin, &signers, &2);

    // Remove one signer (should still have 2)
    let result = client.try_remove_signer(&signer2);
    assert!(result.is_ok());
}

#[test]
fn test_multisig_remove_signer_fails_if_only_one() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);

    let contract_id = env.register(DenylistGate, ());
    let client = DenylistGateClient::new(&env, &contract_id);

    client.initialize(&admin);

    // Initialize 1-of-1 multisig
    let signers = vec![&env, admin.clone()];
    client.initialize_multisig(&admin, &signers, &1);

    // Try to remove the only signer (should fail)
    let result = client.try_remove_signer(&admin);
    assert_eq!(result, Err(Ok(Error::InvalidSignerSet)));
}

#[test]
fn test_add_and_remove_without_audit_log_is_unchanged() {
    let env = Env::default();
    let (admin, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    assert!(client.check(&alice));

    client.add_to_denylist(&admin, &alice);
    assert!(!client.check(&alice));

    client.remove_from_denylist(&admin, &alice);
    assert!(client.check(&alice));
}

#[test]
fn test_remove_multiple_from_denylist_removes_all_without_audit_log_noise() {
    let env = Env::default();
    let (admin, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    client.add_to_denylist(&admin, &alice);
    client.add_to_denylist(&admin, &bob);

    client.remove_multiple_from_denylist(&admin, &vec![&env, alice.clone(), bob.clone()]);

    assert!(client.check(&alice));
    assert!(client.check(&bob));
}
