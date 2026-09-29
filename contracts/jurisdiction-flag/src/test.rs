use super::*;
use soroban_sdk::testutils::{storage::Persistent as _, Address as _, Events as _, Ledger as _};
use soroban_sdk::{vec, Env};
use std::path::{Path, PathBuf};

fn setup(env: &Env) -> (Address, Address, JurisdictionFlagClient<'_>) {
    env.mock_all_auths();
    let issuer = Address::generate(env);
    let contract_id = env.register(JurisdictionFlag, ());
    let client = JurisdictionFlagClient::new(env, &contract_id);
    client.initialize(&issuer);
    (issuer, contract_id, client)
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
fn test_set_and_get_jurisdiction() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    assert_eq!(client.get_jurisdiction(&alice), None);

    let code = String::from_str(&env, "US");
    client.set_jurisdiction(&issuer, &alice, &code);
    assert_eq!(client.get_jurisdiction(&alice), Some(code));
}

#[test]
fn test_budget_regression_is_permitted_jurisdiction() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let code = String::from_str(&env, "US");
    client.set_jurisdiction(&issuer, &alice, &code);

    let allowed = vec![
        &env,
        String::from_str(&env, "CA"),
        String::from_str(&env, "US"),
    ];

    let mut budget = env.cost_estimate().budget();
    budget.reset_default();
    let is_permitted = client.is_permitted_jurisdiction(&alice, &allowed);
    assert!(is_permitted);

    let measured = (budget.cpu_instruction_cost(), budget.memory_bytes_cost());
    let baseline_path = baseline_path_for_manifest_dir(PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()));
    let baseline = read_baseline(&baseline_path, "jurisdiction-flag.is_permitted_jurisdiction");
    assert_budget_within_threshold(measured, baseline, "jurisdiction-flag jurisdiction check");
}

#[test]
fn test_set_jurisdiction_rejects_non_issuer() {
    let env = Env::default();
    let (_issuer, _contract_id, client) = setup(&env);
    let impostor = Address::generate(&env);
    let alice = Address::generate(&env);
    let code = String::from_str(&env, "US");

    let result = client.try_set_jurisdiction(&impostor, &alice, &code);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
    assert_eq!(client.get_jurisdiction(&alice), None);
}

#[test]
fn test_remove_jurisdiction_multiple_clears_mixed_addresses() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let never_set = Address::generate(&env);

    client.set_jurisdiction(&issuer, &alice, &String::from_str(&env, "US"));
    client.set_jurisdiction(&issuer, &bob, &String::from_str(&env, "CA"));
    assert_eq!(
        client.get_jurisdiction(&alice),
        Some(String::from_str(&env, "US"))
    );
    assert_eq!(
        client.get_jurisdiction(&bob),
        Some(String::from_str(&env, "CA"))
    );
    assert_eq!(client.get_jurisdiction(&never_set), None);

    let addresses = vec![&env, alice.clone(), bob.clone(), never_set.clone()];
    client.remove_jurisdiction_multiple(&issuer, &addresses);

    assert_eq!(client.get_jurisdiction(&alice), None);
    assert_eq!(client.get_jurisdiction(&bob), None);
    assert_eq!(client.get_jurisdiction(&never_set), None);
}

#[test]
fn test_remove_jurisdiction_multiple_rejects_non_issuer() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let impostor = Address::generate(&env);
    let alice = Address::generate(&env);

    client.set_jurisdiction(&issuer, &alice, &String::from_str(&env, "US"));

    let addresses = vec![&env, alice.clone()];
    let result = client.try_remove_jurisdiction_multiple(&impostor, &addresses);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
    assert_eq!(
        client.get_jurisdiction(&alice),
        Some(String::from_str(&env, "US"))
    );
}

#[test]
fn test_remove_jurisdiction_multiple_empty_vec_is_noop() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    client.set_jurisdiction(&issuer, &alice, &String::from_str(&env, "US"));

    let empty: Vec<Address> = vec![&env];
    client.remove_jurisdiction_multiple(&issuer, &empty);

    assert_eq!(
        client.get_jurisdiction(&alice),
        Some(String::from_str(&env, "US"))
    );
}

#[test]
fn test_is_permitted_jurisdiction_true_when_code_in_list() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let code = String::from_str(&env, "US");
    client.set_jurisdiction(&issuer, &alice, &code);

    let allowed = vec![
        &env,
        String::from_str(&env, "CA"),
        String::from_str(&env, "US"),
    ];
    assert_eq!(client.is_permitted_jurisdiction(&alice, &allowed), true);
}

#[test]
fn test_is_permitted_jurisdiction_false_when_no_jurisdiction_set() {
    let env = Env::default();
    let (_issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let allowed = vec![&env, String::from_str(&env, "US")];
    assert_eq!(client.is_permitted_jurisdiction(&alice, &allowed), false);
}

#[test]
fn test_is_permitted_jurisdiction_errors_with_empty_allowed_list() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let code = String::from_str(&env, "US");
    client.set_jurisdiction(&issuer, &alice, &code);

    let allowed: Vec<String> = vec![&env];
    let result = client.try_is_permitted_jurisdiction(&alice, &allowed);
    assert_eq!(result, Err(Ok(Error::EmptyAllowedCodes)));
}

#[test]
fn test_is_permitted_jurisdiction_errors_when_no_jurisdiction_and_empty_allowed_list() {
    let env = Env::default();
    let (_issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    let allowed: Vec<String> = vec![&env];
    let result = client.try_is_permitted_jurisdiction(&alice, &allowed);
    assert_eq!(result, Err(Ok(Error::EmptyAllowedCodes)));
}

#[test]
fn test_set_jurisdiction_fails_before_initialize() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(JurisdictionFlag, ());
    let client = JurisdictionFlagClient::new(&env, &contract_id);
    let issuer = Address::generate(&env);
    let alice = Address::generate(&env);
    let code = String::from_str(&env, "US");

    let result = client.try_set_jurisdiction(&issuer, &alice, &code);
    assert_eq!(result, Err(Ok(Error::NotInitialized)));
    assert_eq!(env.events().all(), vec![&env]);
}

#[test]
fn test_set_jurisdiction_emits_jurisdiction_set_event() {
    let env = Env::default();
    let (issuer, contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let code = String::from_str(&env, "US");

    client.set_jurisdiction(&issuer, &alice, &code);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                contract_id.clone(),
                (Symbol::new(&env, "jurisdiction_set"), alice.clone()).into_val(&env),
                Map::<Symbol, Val>::from_array(
                    &env,
                    [(Symbol::new(&env, "code"), code.clone().into_val(&env))]
                )
                .into_val(&env),
            ),
        ]
    );
}

#[test]
fn test_double_initialize_fails() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let result = client.try_initialize(&issuer);
    assert_eq!(result, Err(Ok(Error::AlreadyInitialized)));
}

#[test]
fn test_set_jurisdiction_extends_persistent_ttl() {
    let env = Env::default();
    let (issuer, contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let code = String::from_str(&env, "US");

    client.set_jurisdiction(&issuer, &alice, &code);

    let key = DataKey::Jurisdiction(alice.clone());

    // Advance the ledger until the entry TTL drops below the extension threshold.
    env.ledger().with_mut(|li| {
        li.sequence_number += super::TTL_EXTEND_TO - super::TTL_THRESHOLD + 1;
    });

    let ttl_before_read = env.as_contract(&contract_id, || {
        env.storage().persistent().get_ttl(&key)
    });
    assert!(ttl_before_read < super::TTL_THRESHOLD);

    assert_eq!(client.get_jurisdiction(&alice), Some(code));

    let ttl_after_read = env.as_contract(&contract_id, || {
        env.storage().persistent().get_ttl(&key)
    });
    assert_eq!(ttl_after_read, super::TTL_EXTEND_TO);

    env.ledger().with_mut(|li| {
        li.sequence_number += super::TTL_EXTEND_TO - super::TTL_THRESHOLD + 1;
    });

    let ttl_before_rewrite = env.as_contract(&contract_id, || {
        env.storage().persistent().get_ttl(&key)
    });
    assert!(ttl_before_rewrite < super::TTL_THRESHOLD);

    let updated = String::from_str(&env, "CA");
    client.set_jurisdiction(&issuer, &alice, &updated);

    let ttl_after_write = env.as_contract(&contract_id, || {
        env.storage().persistent().get_ttl(&key)
    });
    assert_eq!(ttl_after_write, super::TTL_EXTEND_TO);
}

#[test]
fn test_no_expiry_never_expires() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let code = String::from_str(&env, "US");
    client.set_jurisdiction(&issuer, &alice, &code);

    env.ledger().with_mut(|li| li.sequence_number += 1_000_000);
    assert_eq!(client.get_jurisdiction(&alice), Some(code));
}

#[test]
fn test_jurisdiction_expires_after_valid_until() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let code = String::from_str(&env, "US");
    let valid_until = env.ledger().sequence() + 10;
    client.set_jurisdiction_until(&issuer, &alice, &code, &valid_until);

    env.ledger().with_mut(|li| li.sequence_number = valid_until);
    assert_eq!(client.get_jurisdiction(&alice), Some(code));

    env.ledger().with_mut(|li| li.sequence_number = valid_until + 1);
    assert_eq!(client.get_jurisdiction(&alice), None);
    let allowed = vec![&env, String::from_str(&env, "US")];
    assert_eq!(client.is_permitted_jurisdiction(&alice, &allowed), false);
}
