use super::*;
use crate::test_utils::{
    MockCircuitBreaker, MockCircuitBreakerClient, MockDenylist, MockDenylistClient,
    MockJurisdiction, MockJurisdictionClient,
};
use circuit_breaker::{CircuitBreaker, CircuitBreakerClient as CbClient};
use denylist_gate::{DenylistGate, DenylistGateClient};
use jurisdiction_flag::{JurisdictionFlag, JurisdictionFlagClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{vec, Env, String};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Registers a mock denylist contract, returns its address.
fn setup_denylist(env: &Env) -> Address {
    env.register(MockDenylist, ())
}

/// Registers a mock jurisdiction contract, returns its address.
fn setup_jurisdiction(env: &Env) -> Address {
    env.register(MockJurisdiction, ())
}

/// Registers and initialises a policy-engine contract with `All` semantics,
/// returns `(admin, contract_id, client)`.
fn setup_engine_all(env: &Env) -> (Address, Address, PolicyEngineClient<'_>) {
    let admin = Address::generate(env);
    let id = env.register(PolicyEngine, ());
    let client = PolicyEngineClient::new(env, &id);
    client.initialize(&admin, &CombineOp::All, &None);
    (admin, id, client)
}

/// Same as above but with `Any` semantics.
fn setup_engine_any(env: &Env) -> (Address, Address, PolicyEngineClient<'_>) {
    let admin = Address::generate(env);
    let id = env.register(PolicyEngine, ());
    let client = PolicyEngineClient::new(env, &id);
    client.initialize(&admin, &CombineOp::Any, &None);
    (admin, id, client)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// With All semantics: a denylist check (addresses clear) and a jurisdiction
/// check (addresses in permitted list) both pass → evaluate returns true.
#[test]
fn test_all_checks_pass() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Set permitted jurisdictions for both addresses.
    let code_us = String::from_str(&env, "US");
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&from, &code_us);
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&to, &code_us);

    let (admin, _engine_id, client) = setup_engine_all(&env);

    client.add_check(
        &admin,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );

    let result = client.evaluate(&from, &to);
    assert!(result);
}

/// With All semantics: one of two checks fails (sender is on the denylist)
/// → evaluate returns false.
#[test]
fn test_one_check_fails_and_semantics() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Both addresses have valid jurisdiction codes.
    let code_us = String::from_str(&env, "US");
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&from, &code_us);
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&to, &code_us);

    // But `from` is denied.
    MockDenylistClient::new(&env, &deny_id).add_to_denylist(&from);

    let (admin, _engine_id, client) = setup_engine_all(&env);

    client.add_check(
        &admin,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );

    let result = client.evaluate(&from, &to);
    assert!(!result);
}

/// With Any semantics: the denylist check fails (both addresses denied) but
/// the jurisdiction check passes → evaluate returns true because at least
/// one check passes for both parties.
#[test]
fn test_one_check_passes_or_semantics() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Both addresses are on the denylist (denylist check will fail).
    MockDenylistClient::new(&env, &deny_id).add_to_denylist(&from);
    MockDenylistClient::new(&env, &deny_id).add_to_denylist(&to);

    // But both have valid jurisdiction codes (jurisdiction check will pass).
    let code_us = String::from_str(&env, "US");
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&from, &code_us);
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&to, &code_us);

    let (admin, _engine_id, client) = setup_engine_any(&env);

    client.add_check(
        &admin,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );

    // With Any: the jurisdiction check passes for both → result is true.
    let result = client.evaluate(&from, &to);
    assert!(result);
}

/// Verify that add_check and remove_check correctly mutate the checks list.
#[test]
fn test_add_and_remove_check() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);

    let (admin, _engine_id, client) = setup_engine_all(&env);

    // Initially empty.
    assert_eq!(client.get_checks().len(), 0);

    // Add one check.
    client.add_check(
        &admin,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    assert_eq!(client.get_checks().len(), 1);

    // Add a second check.
    let juri_id = setup_jurisdiction(&env);
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );
    assert_eq!(client.get_checks().len(), 2);

    // Remove the first check (index 0); list should shrink to 1.
    client.remove_check(&admin, &0);
    assert_eq!(client.get_checks().len(), 1);
}

#[test]
fn test_clear_checks_resets_policy_to_empty() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);

    let (admin, _engine_id, client) = setup_engine_all(&env);
    client.add_check(
        &admin,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );

    assert_eq!(client.get_checks().len(), 2);
    client.clear_checks(&admin);
    assert_eq!(client.get_checks().len(), 0);
}

/// `swap_checks` exchanges the positions of two checks so that `evaluate`
/// follows the new order, including short-circuit behaviour under `CombineOp::All`.
#[test]
fn test_swap_checks_reorders_and_short_circuits() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // `from` is on the denylist — under CombineOp::All this check will fail.
    MockDenylistClient::new(&env, &deny_id).add_to_denylist(&from);

    // Both addresses have valid jurisdiction codes so the jurisdiction check passes.
    let code_us = String::from_str(&env, "US");
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&from, &code_us);
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&to, &code_us);

    let (admin, _engine_id, client) = setup_engine_all(&env);

    // Add jurisdiction check first (index 0), then denylist check (index 1).
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );
    client.add_check(
        &admin,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );

    // Before swap: jurisdiction (passes) then denylist (fails) → false.
    assert!(!client.evaluate(&from, &to));

    // Swap positions 0 and 1: denylist is now index 0, jurisdiction is index 1.
    client.swap_checks(&admin, &0, &1);
    let checks = client.get_checks();
    assert_eq!(checks.len(), 2);
    // The first check must now be the denylist check.
    match checks.get(0).unwrap() {
        CheckKind::Denylist(_) => {}
        _ => panic!("expected Denylist at index 0 after swap"),
    }
    match checks.get(1).unwrap() {
        CheckKind::Jurisdiction(_) => {}
        _ => panic!("expected Jurisdiction at index 1 after swap"),
    }

    // After swap the denylist short-circuits first — result is still false,
    // but the cheaper check now fires before the jurisdiction check.
    assert!(!client.evaluate(&from, &to));
}

/// `swap_checks` with equal indices is a no-op — the list is unchanged.
#[test]
fn test_swap_checks_same_index_is_noop() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let (admin, _engine_id, client) = setup_engine_all(&env);

    client.add_check(
        &admin,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    assert_eq!(client.get_checks().len(), 1);

    // Swapping index 0 with itself must not panic and must leave the list intact.
    client.swap_checks(&admin, &0, &0);
    assert_eq!(client.get_checks().len(), 1);
}

/// `swap_checks` with an out-of-range index panics (the generated client
/// surfaces the contract error as a panic in test environments).
#[test]
#[should_panic]
fn test_swap_checks_out_of_bounds() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let (admin, _engine_id, client) = setup_engine_all(&env);

    client.add_check(
        &admin,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );

    // Only one check at index 0; index 1 is out of range.
    client.swap_checks(&admin, &0, &1);
}

/// `get_policy` returns a `PolicyNode` whose `op` and `checks` fields exactly
/// match what was configured via `initialize` / `add_check`.
#[test]
fn test_get_policy_matches_configuration() {
    let env = Env::default();
    env.mock_all_auths();

    // Set up two external contracts to use as checks.
    let deny_admin = Address::generate(&env);
    let juri_issuer = Address::generate(&env);
    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);

    // Initialise with `Any` semantics and add two checks.
    let (admin, _engine_id, client) = setup_engine_any(&env);

    let allowed_codes = vec![&env, String::from_str(&env, "US"), String::from_str(&env, "GB")];

    client.add_check(
        &admin,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: allowed_codes.clone(),
        }),
    );

    // Fetch the full policy tree.
    let policy = client.get_policy();

    // The combine operator must match what was passed to `initialize`.
    assert_eq!(policy.op, CombineOp::Any);

    // There must be exactly two checks, in insertion order.
    assert_eq!(policy.checks.len(), 2);

    // First check must be the denylist check with the correct contract address.
    match policy.checks.get(0).unwrap() {
        CheckKind::Denylist(inner) => assert_eq!(inner.contract, deny_id),
        _ => panic!("expected Denylist check at index 0"),
    }

    // Second check must be the jurisdiction check with correct contract and codes.
    match policy.checks.get(1).unwrap() {
        CheckKind::Jurisdiction(inner) => {
            assert_eq!(inner.contract, juri_id);
            assert_eq!(inner.allowed_codes, allowed_codes);
        }
        _ => panic!("expected Jurisdiction check at index 1"),
    }
}

// ---------------------------------------------------------------------------
// TTL extension
// ---------------------------------------------------------------------------

fn instance_ttl(env: &Env, contract_id: &Address) -> u32 {
    use soroban_sdk::testutils::storage::Instance as _;
    env.as_contract(contract_id, || env.storage().instance().get_ttl())
}

/// A write refreshes the instance TTL, so the policy stays readable after the
/// ledger advances past the TTL the entries were originally given.
#[test]
fn test_write_extends_instance_ttl_past_original_expiry() {
    use soroban_sdk::testutils::Ledger as _;

    let env = Env::default();
    env.mock_all_auths();
    let (admin, contract_id, client) = setup_engine_all(&env);
    let deny_id = setup_denylist(&env);

    // `initialize` is a write path and must extend the TTL.
    assert_eq!(instance_ttl(&env, &contract_id), INSTANCE_TTL_EXTEND_TO);

    // Advance until the remaining TTL drops below the extension threshold.
    env.ledger().with_mut(|li| {
        li.sequence_number += INSTANCE_TTL_EXTEND_TO - INSTANCE_TTL_THRESHOLD + 1;
    });
    assert!(instance_ttl(&env, &contract_id) < INSTANCE_TTL_THRESHOLD);

    // A write refreshes the TTL back to the target.
    client.add_check(
        &admin,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    assert_eq!(instance_ttl(&env, &contract_id), INSTANCE_TTL_EXTEND_TO);

    // Advance past the ledger at which the original TTL would have expired.
    env.ledger().with_mut(|li| {
        li.sequence_number += INSTANCE_TTL_THRESHOLD + 1;
    });

    // State written before and after the refresh is still readable.
    assert_eq!(client.get_checks().len(), 1);
    assert!(client.get_op() == CombineOp::All);

    // Remaining write paths also refresh the TTL. Remaining TTL is currently
    // EXTEND_TO - THRESHOLD - 1; drop it just below the threshold.
    env.ledger().with_mut(|li| {
        li.sequence_number += INSTANCE_TTL_EXTEND_TO - 2 * INSTANCE_TTL_THRESHOLD;
    });
    assert!(instance_ttl(&env, &contract_id) < INSTANCE_TTL_THRESHOLD);
    client.remove_check(&admin, &0);
    assert_eq!(instance_ttl(&env, &contract_id), INSTANCE_TTL_EXTEND_TO);

    env.ledger().with_mut(|li| {
        li.sequence_number += INSTANCE_TTL_EXTEND_TO - INSTANCE_TTL_THRESHOLD + 1;
    });
    let breaker = Address::generate(&env);
    client.set_circuit_breaker(&admin, &breaker);
    assert_eq!(instance_ttl(&env, &contract_id), INSTANCE_TTL_EXTEND_TO);
    assert_eq!(client.circuit_breaker(), Some(breaker));
}

// ---------------------------------------------------------------------------
// Tests for issue #403: CircuitBreaker check kind
// ---------------------------------------------------------------------------

/// Registers a mock circuit-breaker contract, returns its address.
fn setup_circuit_breaker(env: &Env) -> Address {
    env.register(MockCircuitBreaker, ())
}

/// Policy with all three check kinds under `CombineOp::All`: denylist passes,
/// jurisdiction passes, circuit-breaker is not frozen → `evaluate` returns true.
#[test]
fn test_all_three_check_kinds_all_pass() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);
    let cb_id = setup_circuit_breaker(&env);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Both addresses have valid jurisdiction codes; circuit-breaker is not frozen.
    let code_us = String::from_str(&env, "US");
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&from, &code_us);
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&to, &code_us);
    // MockCircuitBreaker starts unfrozen by default.

    let (admin, _engine_id, client) = setup_engine_all(&env);

    client.add_check(
        &admin,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );
    client.add_check(
        &admin,
        &CheckKind::CircuitBreaker(CircuitBreakerCheck {
            contract: cb_id.clone(),
        }),
    );

    let result = client.evaluate(&from, &to);
    assert!(result, "expected all-pass with three check kinds (All)");
}

/// Policy with all three check kinds under `CombineOp::All`: circuit-breaker
/// is frozen → the circuit-breaker check fails → `evaluate` returns false.
#[test]
fn test_circuit_breaker_check_kind_frozen_fails_all() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);
    let cb_id = setup_circuit_breaker(&env);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Both addresses clear denylist and jurisdiction.
    let code_us = String::from_str(&env, "US");
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&from, &code_us);
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&to, &code_us);

    // Freeze the circuit-breaker — this check should fail.
    MockCircuitBreakerClient::new(&env, &cb_id).freeze();

    let (admin, _engine_id, client) = setup_engine_all(&env);

    client.add_check(
        &admin,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );
    client.add_check(
        &admin,
        &CheckKind::CircuitBreaker(CircuitBreakerCheck {
            contract: cb_id.clone(),
        }),
    );

    let result = client.evaluate(&from, &to);
    assert!(!result, "expected false when circuit-breaker is frozen (All)");
}

/// Policy with all three check kinds under `CombineOp::Any`: denylist and
/// jurisdiction both fail but circuit-breaker is not frozen → circuit-breaker
/// check passes for both parties → `evaluate` returns true.
#[test]
fn test_circuit_breaker_check_kind_passes_any_semantics() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);
    let cb_id = setup_circuit_breaker(&env);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Both addresses are denied (denylist check fails).
    MockDenylistClient::new(&env, &deny_id).add_to_denylist(&from);
    MockDenylistClient::new(&env, &deny_id).add_to_denylist(&to);
    // No jurisdiction codes set (jurisdiction check fails).
    // Circuit-breaker is not frozen (circuit-breaker check passes).

    let (admin, _engine_id, client) = setup_engine_any(&env);

    client.add_check(
        &admin,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );
    client.add_check(
        &admin,
        &CheckKind::CircuitBreaker(CircuitBreakerCheck {
            contract: cb_id.clone(),
        }),
    );

    // With Any: circuit-breaker passes for both → result is true.
    let result = client.evaluate(&from, &to);
    assert!(result, "expected true: circuit-breaker passes under Any semantics");
}

/// Policy with all three check kinds under `CombineOp::Any`: all three checks
/// fail → `evaluate` returns false.
#[test]
fn test_all_three_check_kinds_all_fail_any() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);
    let cb_id = setup_circuit_breaker(&env);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Denylist check fails: both denied.
    MockDenylistClient::new(&env, &deny_id).add_to_denylist(&from);
    MockDenylistClient::new(&env, &deny_id).add_to_denylist(&to);
    // Jurisdiction check fails: no codes set.
    // Circuit-breaker check fails: frozen.
    MockCircuitBreakerClient::new(&env, &cb_id).freeze();

    let (admin, _engine_id, client) = setup_engine_any(&env);

    client.add_check(
        &admin,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );
    client.add_check(
        &admin,
        &CheckKind::CircuitBreaker(CircuitBreakerCheck {
            contract: cb_id.clone(),
        }),
    );

    let result = client.evaluate(&from, &to);
    assert!(!result, "expected false when all three checks fail under Any");
}

// ---------------------------------------------------------------------------
// Tests for issue #404: get_admin view function
// ---------------------------------------------------------------------------

/// `get_admin` returns the address that was passed to `initialize`.
#[test]
fn test_get_admin_returns_initialized_admin() {
    let env = Env::default();
    env.mock_all_auths();

    let (admin, _engine_id, client) = setup_engine_all(&env);

    let returned_admin = client.get_admin();
    assert_eq!(returned_admin, admin, "get_admin should return the initialized admin address");
}

/// `get_admin` returns `Err(NotInitialized)` when called before `initialize`.
#[test]
fn test_get_admin_not_initialized_returns_error() {
    let env = Env::default();
    env.mock_all_auths();

    // Register the contract but do NOT call initialize.
    let id = env.register(PolicyEngine, ());
    let client = PolicyEngineClient::new(&env, &id);

    let result = client.try_get_admin();
    assert!(
        result.is_err(),
        "get_admin should return an error before initialization"
    );
}
