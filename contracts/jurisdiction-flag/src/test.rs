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

/// Default per-invocation write-entry budget used by the Soroban host.
///
/// `remove_jurisdiction_multiple` has no `MAX_BATCH_SIZE` guard yet (deferred to
/// a future shared-cap issue), so this benchmark measures where its resource
/// cost crosses the default budget at increasing batch sizes. The recorded
/// crossing point is the measurement that should inform the batch-size cap when
/// the shared-cap issue is picked up.
const DEFAULT_WRITE_ENTRY_BUDGET: u64 = 100;

/// Batch sizes exercised by the benchmark, from a realistic single call up to
/// well past the point where the default write-entry budget is exhausted.
const BENCHMARK_BATCH_SIZES: [u32; 6] = [1, 5, 10, 25, 50, 100];

#[test]
fn test_remove_jurisdiction_multiple_resource_fee_benchmark() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);

    let mut crossing_point: Option<u32> = None;

    for &batch_size in BENCHMARK_BATCH_SIZES.iter() {
        let mut addresses = Vec::new(&env);
        for _ in 0..batch_size {
            let addr = Address::generate(&env);
            client.set_jurisdiction(&issuer, &addr, &String::from_str(&env, "US"));
            addresses.push_back(addr);
        }

        let mut budget = env.cost_estimate().budget();
        budget.reset_default();
        client.remove_jurisdiction_multiple(&issuer, &addresses);

        let cpu = budget.cpu_instruction_cost();
        let memory = budget.memory_bytes_cost();

        // Each cleared address consumes one write entry; record the first batch
        // size whose write-entry cost exceeds the default per-invocation budget.
        let write_entries = batch_size as u64;
        if write_entries > DEFAULT_WRITE_ENTRY_BUDGET && crossing_point.is_none() {
            crossing_point = Some(batch_size);
        }

        std::println!(
            "remove_jurisdiction_multiple batch_size={batch_size} cpu={cpu} memory={memory} write_entries={write_entries}"
        );
    }

    // The benchmark must actually observe the crossing point so the recorded
    // measurement can inform the future shared batch-size cap.
    assert!(
        crossing_point.is_some(),
        "benchmark did not reach the default write-entry budget ({DEFAULT_WRITE_ENTRY_BUDGET}) within {BENCHMARK_BATCH_SIZES:?}"
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
fn test_get_jurisdiction_emits_expired_event_for_expired_flag() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let code = String::from_str(&env, "US");

    client.set_jurisdiction(&issuer, &alice, &code);

    // Advance the ledger past the flag's expiry so the read enforces expiry.
    let expiry = client.get_jurisdiction_expiry(&alice).unwrap();
    env.ledger().set_timestamp(expiry + 1);

    assert_eq!(client.get_jurisdiction(&alice), None);

    let events = env.events().all();
    let expired = events.iter().any(|(_, topics, _)| {
        topics
            .iter()
            .any(|topic| topic == &Symbol::new(&env, "JurisdictionExpired").into())
    });
    assert!(expired, "JurisdictionExpired event was not published");
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

/* … truncated 1219 chars — edit only what you need near the top … */
