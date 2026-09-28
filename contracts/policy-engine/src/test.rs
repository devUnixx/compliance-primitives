use super::*;
use super::test_utils::*;
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

/// `get_policy` returns a `PolicyNode` whose `op` and `checks` fields exactly
/// match what was configured via `initialize` / `add_check`.
#[test]
fn test_get_policy_matches_configuration() {
    let env = Env::default();
    env.mock_all_auths();

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
        CheckKind::Denylist(params) => assert_eq!(params.contract, deny_id),
        _ => panic!("expected Denylist check at index 0"),
    }

    // Second check must be the jurisdiction check with correct contract and codes.
    match policy.checks.get(1).unwrap() {
        CheckKind::Jurisdiction(params) => {
            assert_eq!(params.contract, juri_id);
            assert_eq!(params.allowed_codes, allowed_codes);
        }
        _ => panic!("expected Jurisdiction check at index 1"),
    }
}

// ---------------------------------------------------------------------------
// Tests for issue #405: evaluate_verbose surfaces CheckFailure
// ---------------------------------------------------------------------------

/// `evaluate_verbose` returns `(true, None)` when all checks pass (All op).
#[test]
fn test_evaluate_verbose_passes_returns_none_failure() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

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

    let (passed, failure) = client.evaluate_verbose(&from, &to);
    assert!(passed, "expected policy to pass");
    assert!(failure.is_none(), "expected no CheckFailure when policy passes");
}

/// `evaluate_verbose` returns `(false, Some(CheckFailure))` with the correct
/// index and kind when the denylist check fails under All semantics.
#[test]
fn test_evaluate_verbose_fails_surfaces_check_failure() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Both addresses have valid jurisdiction codes but `from` is denied.
    let code_us = String::from_str(&env, "US");
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&from, &code_us);
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&to, &code_us);
    MockDenylistClient::new(&env, &deny_id).add_to_denylist(&from);

    let (admin, _engine_id, client) = setup_engine_all(&env);

    // Register Denylist at index 0, Jurisdiction at index 1.
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

    let (passed, failure) = client.evaluate_verbose(&from, &to);
    assert!(!passed, "expected policy to fail");

    let f = failure.expect("expected Some(CheckFailure) when policy fails");
    assert_eq!(f.check_index, 0, "denylist is at index 0");
    assert_eq!(
        f.kind,
        soroban_sdk::Symbol::new(&env, "Denylist"),
        "kind should be 'Denylist'"
    );
}

// ---------------------------------------------------------------------------
// Tests for issue #405: evaluate_verbose surfaces CheckFailure
// ---------------------------------------------------------------------------

/// `evaluate_verbose` returns `(true, None)` when all checks pass.
#[test]
fn test_evaluate_verbose_passes_returns_none_failure() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    let code_us = String::from_str(&env, "US");
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&from, &code_us);
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&to, &code_us);

    let (admin, _engine_id, client) = setup_engine_all(&env);
    client.add_check(
        &admin,
        &CheckKind::Denylist(DenylistCheck { contract: deny_id.clone() }),
    );
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );

    let (passed, failure) = client.evaluate_verbose(&from, &to);
    assert!(passed, "expected policy to pass");
    assert!(failure.is_none(), "expected no CheckFailure when policy passes");
}

/// `evaluate_verbose` returns `(false, Some(CheckFailure { check_index: 0, kind: "Denylist" }))`
/// when the denylist check at index 0 fails under All semantics.
#[test]
fn test_evaluate_verbose_fails_surfaces_check_failure() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Both addresses have valid jurisdiction codes but `from` is denied.
    let code_us = String::from_str(&env, "US");
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&from, &code_us);
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&to, &code_us);
    MockDenylistClient::new(&env, &deny_id).add_to_denylist(&from);

    let (admin, _engine_id, client) = setup_engine_all(&env);
    // Denylist at index 0, Jurisdiction at index 1.
    client.add_check(
        &admin,
        &CheckKind::Denylist(DenylistCheck { contract: deny_id.clone() }),
    );
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );

    let (passed, failure) = client.evaluate_verbose(&from, &to);
    assert!(!passed, "expected policy to fail");

    let f = failure.expect("expected Some(CheckFailure) when policy fails");
    assert_eq!(f.check_index, 0, "denylist is registered at index 0");
    assert_eq!(
        f.kind,
        soroban_sdk::Symbol::new(&env, "Denylist"),
        "kind should be 'Denylist'"
    );
}
