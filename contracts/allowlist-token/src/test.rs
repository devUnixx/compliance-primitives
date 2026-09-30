use super::*;
use ed25519_dalek::SigningKey;
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::testutils::ed25519::Sign;
use soroban_sdk::{contract, contractimpl, symbol_short, vec, Bytes, BytesN, Env, IntoVal, Map, Symbol, Val};
use std::path::{Path, PathBuf};

// ─── MockToken ───────────────────────────────────────────────────────────────

/// A minimal token double used only by these tests, so `allowlist-token`'s
/// unit tests don't depend on any particular real SEP-41 implementation.
#[contract]
struct MockToken;

#[contractimpl]
impl MockToken {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        env.storage().instance().set(&Symbol::new(&env, "last"), &(from, to, amount));
    }

    pub fn last_transfer(env: Env) -> Option<(Address, Address, i128)> {
        env.storage().instance().get(&Symbol::new(&env, "last"))
    }
}

// ─── Setup helper ────────────────────────────────────────────────────────────

fn setup(env: &Env) -> (Address, Address, Address, AllowlistTokenClient<'_>) {
    env.mock_all_auths();
    let admin = Address::generate(env);
    let token_id = env.register(MockToken, ());
    let contract_id = env.register(AllowlistToken, ());
    let client = AllowlistTokenClient::new(env, &contract_id);
    client.initialize(&admin, &token_id);
    (admin, token_id, contract_id, client)
}

// ─── Existing unit tests ──────────────────────────────────────────────────────

#[test]
fn test_initialize_and_allowlist_roundtrip() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    assert!(!client.is_allowed(&alice));
    client.add_to_allowlist(&admin, &alice, &None);
    assert!(client.is_allowed(&alice));
    client.remove_from_allowlist(&admin, &alice);
    assert!(!client.is_allowed(&alice));
}

#[test]
fn test_transfer_forwards_to_underlying_token_when_both_allowlisted() {
    let env = Env::default();
    let (admin, token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice, &None);
    client.add_to_allowlist(&admin, &bob, &None);

    let ok = client.transfer(&alice, &bob, &500);
    assert!(ok);

    let token_client = MockTokenClient::new(&env, &token_id);
    let last = token_client.last_transfer().unwrap();
    assert_eq!(last, (alice, bob, 500));
}

#[test]
fn test_budget_regression_allowlist_transfer() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice, &None);
    client.add_to_allowlist(&admin, &bob, &None);

    let mut budget = env.cost_estimate().budget();
    budget.reset_default();
    let ok = client.transfer(&alice, &bob, &500);
    assert!(ok);

    let measured = (budget.cpu_instruction_cost(), budget.memory_bytes_cost());
    let baseline_path = baseline_path_for_manifest_dir(PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()));
    let baseline = read_baseline(&baseline_path, "allowlist-token.transfer");
    assert_budget_within_threshold(measured, baseline, "allowlist-token transfer");
}

#[test]
fn test_transfer_blocked_when_recipient_not_allowlisted() {
    let env = Env::default();
    let (admin, _token_id, contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice, &None);

    let ok = client.transfer(&alice, &bob, &500);
    assert!(!ok);

    // `assert_events_eq` pretty-prints both the actual and expected events on
    // mismatch instead of a single-line raw XDR dump.
    compliance_test_trace::assert_events_eq(
        &env,
        &env.events().all(),
        &vec![
            &env,
            (
                contract_id.clone(),
                (Symbol::new(&env, "allow_add"), alice.clone()).into_val(&env),
                Map::<Symbol, Val>::new(&env).into_val(&env),
            ),
            (
                contract_id.clone(),
                (symbol_short!("blocked"), alice.clone(), bob.clone()).into_val(&env),
                Map::<Symbol, Val>::from_array(&env, [(symbol_short!("amount"), 500i128.into_val(&env))])
                    .into_val(&env),
            ),
        ],
    );
}

#[test]
fn test_add_to_allowlist_rejects_non_admin() {
    let env = Env::default();
    let (_admin, _token_id, _contract_id, client) = setup(&env);
    let impostor = Address::generate(&env);
    let alice = Address::generate(&env);

    let result = client.try_add_to_allowlist(&impostor, &alice, &None);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
    assert!(!client.is_allowed(&alice));
}

#[test]
fn test_non_admin_allowlist_mutations_rejected_end_to_end() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let impostor = Address::generate(&env);
    let alice = Address::generate(&env);

    let add_result = client.try_add_to_allowlist(&impostor, &alice, &None);
    assert_eq!(add_result, Err(Ok(Error::NotAuthorized)));
    assert!(!client.is_allowed(&alice));

    client.add_to_allowlist(&admin, &alice, &None);
    assert!(client.is_allowed(&alice));

    let remove_result = client.try_remove_from_allowlist(&impostor, &alice);
    assert_eq!(remove_result, Err(Ok(Error::NotAuthorized)));
    assert!(client.is_allowed(&alice));
}

#[test]
fn test_delegated_add_to_allowlist_succeeds() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let signing_key = SigningKey::from_bytes(&[
        0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, 26, 27, 28, 29, 30, 31,
    ]);
    let pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());

    client.set_delegated_admin_key(&admin, &pubkey);

    let expiry = env.ledger().timestamp() + 60;
    let signature = sign_delegated_action(&env, &signing_key, &alice, 1, expiry);

    client.add_to_allowlist_delegated(&admin, &alice, &1u64, &expiry, &signature);
    assert!(client.is_allowed(&alice));
}

#[test]
fn test_delegated_add_to_allowlist_rejects_replay() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let signing_key = SigningKey::from_bytes(&[
        0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, 26, 27, 28, 29, 30, 31,
    ]);
    let pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());

    client.set_delegated_admin_key(&admin, &pubkey);

    let expiry = env.ledger().timestamp() + 60;
    let signature = sign_delegated_action(&env, &signing_key, &alice, 1, expiry);

    client.add_to_allowlist_delegated(&admin, &alice, &1u64, &expiry, &signature);
    let replay = client.try_add_to_allowlist_delegated(&admin, &alice, &1u64, &expiry, &signature);
    assert_eq!(replay, Err(Ok(Error::InvalidNonce)));
    assert!(client.is_allowed(&alice));
}

#[test]
fn test_delegated_add_to_allowlist_rejects_expired_signature() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let signing_key = SigningKey::from_bytes(&[
        0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, 26, 27, 28, 29, 30, 31,
    ]);
    let pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());

    client.set_delegated_admin_key(&admin, &pubkey);

    env.ledger().set_timestamp(100);
    let expiry = 99u64;
    let signature = sign_delegated_action(&env, &signing_key, &alice, 1, expiry);

    let result = client.try_add_to_allowlist_delegated(&admin, &alice, &1u64, &expiry, &signature);
    assert_eq!(result, Err(Ok(Error::ExpiredSignature)));
    assert!(!client.is_allowed(&alice));
}

#[test]
fn test_delegated_add_to_allowlist_rejects_non_admin_key() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let signing_key = SigningKey::from_bytes(&[
        0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, 26, 27, 28, 29, 30, 31,
    ]);
    let attacker_key = SigningKey::from_bytes(&[
        32u8, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
        54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    ]);
    let pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());

    client.set_delegated_admin_key(&admin, &pubkey);

    let expiry = env.ledger().timestamp() + 60;
    let signature = sign_delegated_action(&env, &attacker_key, &alice, 1, expiry);

    let result = client.try_add_to_allowlist_delegated(&admin, &alice, &1u64, &expiry, &signature);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
    assert!(!client.is_allowed(&alice));
}

#[test]
fn test_remove_from_allowlist_never_added_is_noop() {
    let env = Env::default();
    let (admin, _token_id, contract_id, client) = setup(&env);
    let never_added = Address::generate(&env);

    assert!(!client.is_allowed(&never_added));

    client.remove_from_allowlist(&admin, &never_added);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                contract_id.clone(),
                (Symbol::new(&env, "allow_remove"), never_added.clone()).into_val(&env),
                Map::<Symbol, Val>::new(&env).into_val(&env),
            ),
        ]
    );
    assert!(!client.is_allowed(&never_added));
}

#[test]
fn test_is_allowed_false_before_initialize() {
    let env = Env::default();
    let contract_id = env.register(AllowlistToken, ());
    let client = AllowlistTokenClient::new(&env, &contract_id);
    let alice = Address::generate(&env);

    assert!(!client.is_allowed(&alice));
}

#[test]
fn test_get_admin_returns_initialized_admin() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);

    assert_eq!(client.get_admin(), admin);
}

#[test]
fn test_get_admin_fails_before_initialize() {
    let env = Env::default();
    let contract_id = env.register(AllowlistToken, ());
    let client = AllowlistTokenClient::new(&env, &contract_id);

    let result = client.try_get_admin();
    assert_eq!(result, Err(Ok(Error::NotInitialized)));
}

#[test]
fn test_double_initialize_fails() {
    let env = Env::default();
    let (admin, token_id, _contract_id, client) = setup(&env);
    let result = client.try_initialize(&admin, &token_id);
    assert_eq!(result, Err(Ok(Error::AlreadyInitialized)));
}

#[test]
fn test_add_to_allowlist_emits_allow_add_event() {
    let env = Env::default();
    let (admin, _token_id, contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice, &None);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                contract_id.clone(),
                (Symbol::new(&env, "allow_add"), alice.clone()).into_val(&env),
                Map::<Symbol, Val>::new(&env).into_val(&env),
            ),
        ]
    );
}

#[test]
fn test_remove_from_allowlist_emits_allow_remove_event() {
    let env = Env::default();
    let (admin, _token_id, contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    client.add_to_allowlist(&admin, &alice, &None);

    client.remove_from_allowlist(&admin, &alice);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                contract_id.clone(),
                (Symbol::new(&env, "allow_add"), alice.clone()).into_val(&env),
                Map::<Symbol, Val>::new(&env).into_val(&env),
            ),
            (
                contract_id.clone(),
                (Symbol::new(&env, "allow_remove"), alice.clone()).into_val(&env),
                Map::<Symbol, Val>::new(&env).into_val(&env),
            ),
        ]
    );
}

#[test]
fn test_add_to_allowlist_extends_persistent_ttl() {
    use soroban_sdk::testutils::storage::Persistent as _;
    use soroban_sdk::testutils::Ledger;

    let env = Env::default();
    env.ledger().with_mut(|li| {
        li.sequence_number = 100_000;
        li.min_persistent_entry_ttl = 500;
        li.max_entry_ttl = 6_311_520;
    });

    let (admin, _token_id, contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice, &None);

    env.as_contract(&contract_id, || {
        let ttl = env
            .storage()
            .persistent()
            .get_ttl(&DataKey::Allowed(alice.clone()));
        assert_eq!(
            ttl, ALLOWED_TTL_EXTEND_TO,
            "fresh allowlist write should bump TTL to ALLOWED_TTL_EXTEND_TO"
        );
    });

    // Advance far enough that remaining TTL falls below the threshold, then
    // re-add and confirm extension runs again.
    env.ledger().with_mut(|li| {
        li.sequence_number += ALLOWED_TTL_EXTEND_TO - ALLOWED_TTL_THRESHOLD + 1;
    });
    env.as_contract(&contract_id, || {
        let ttl = env
            .storage()
            .persistent()
            .get_ttl(&DataKey::Allowed(alice.clone()));
        assert!(
            ttl < ALLOWED_TTL_THRESHOLD,
            "TTL should be below threshold after ledger bump, got {ttl}"
        );
    });

    client.add_to_allowlist(&admin, &alice, &None);
    env.as_contract(&contract_id, || {
        let ttl = env
            .storage()
            .persistent()
            .get_ttl(&DataKey::Allowed(alice.clone()));
        assert_eq!(ttl, ALLOWED_TTL_EXTEND_TO);
    });
}

/// Property: after any sequence of add/remove on a fixed address pool,
/// `is_allowed(addr)` matches whether the last op touching `addr` was an add.
#[test]
fn prop_allowlist_add_remove_last_write_wins() {
    use proptest::prelude::*;
    use proptest::test_runner::{Config, TestRunner};

    #[derive(Clone, Debug)]
    enum Op {
        Add(usize),
        Remove(usize),
    }

    let mut runner = TestRunner::new(Config {
        cases: 64,
        max_shrink_iters: 100,
        ..Config::default()
    });

    runner
        .run(
            &(1usize..32).prop_flat_map(|len| {
                proptest::collection::vec(
                    (0usize..4).prop_flat_map(|addr_i| {
                        proptest::bool::ANY.prop_map(move |is_add| {
                            if is_add {
                                Op::Add(addr_i)
                            } else {
                                Op::Remove(addr_i)
                            }
                        })
                    }),
                    len,
                )
            }),
            |ops| {
                let env = Env::default();
                let (admin, _token_id, _contract_id, client) = setup(&env);
                let addresses: [Address; 4] = [
                    Address::generate(&env),
                    Address::generate(&env),
                    Address::generate(&env),
                    Address::generate(&env),
                ];
                let mut model = [false; 4];

                for op in &ops {
                    match *op {
                        Op::Add(i) => {
                            client.add_to_allowlist(&admin, &addresses[i], &None);
                            model[i] = true;
                        }
                        Op::Remove(i) => {
                            client.remove_from_allowlist(&admin, &addresses[i]);
                            model[i] = false;
                        }
                    }
                }

                for (i, address) in addresses.iter().enumerate() {
                    prop_assert_eq!(
                        client.is_allowed(address),
                        model[i],
                        "addr {} mismatch after {:?}",
                        i,
                        ops
                    );
                }
                Ok(())
            },
        )
        .unwrap();
}

// ─── Allowlist expiry (#21) ──────────────────────────────────────────────────

/// Pin the ledger to a known sequence with TTLs generous enough that neither
/// the contract instance nor allowlist entries get archived while the tests
/// move the ledger forward.
fn set_ledger(env: &Env, sequence: u32) {
    env.ledger().with_mut(|li| {
        li.sequence_number = sequence;
        li.min_persistent_entry_ttl = 1_000_000;
        li.max_entry_ttl = 6_311_520;
    });
}

#[test]
fn test_allowlist_entry_without_expiry_never_expires() {
    let env = Env::default();
    set_ledger(&env, 100);
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice, &None);
    assert!(client.is_allowed(&alice));
    assert_eq!(
        client.get_allowlist_entry(&alice),
        Some(AllowlistEntry { expiration_ledger: None })
    );

    set_ledger(&env, 500_000);
    assert!(client.is_allowed(&alice));
}

#[test]
fn test_allowlist_entry_valid_at_expiration_ledger_and_expired_one_after() {
    let env = Env::default();
    set_ledger(&env, 100);
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice, &Some(150));
    assert!(client.is_allowed(&alice));

    // Exactly at the expiration ledger: still allowed (inclusive bound).
    set_ledger(&env, 150);
    assert!(client.is_allowed(&alice));

    // One past the expiration ledger: treated as not allowlisted, without any
    // explicit remove_from_allowlist call.
    set_ledger(&env, 151);
    assert!(!client.is_allowed(&alice));
    // The raw entry is still in storage; it is just ignored.
    assert_eq!(
        client.get_allowlist_entry(&alice),
        Some(AllowlistEntry { expiration_ledger: Some(150) })
    );
}

#[test]
fn test_transfer_blocked_after_allowlist_entry_expires() {
    let env = Env::default();
    set_ledger(&env, 100);
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice, &None);
    client.add_to_allowlist(&admin, &bob, &Some(200));

    set_ledger(&env, 200);
    assert!(client.transfer(&alice, &bob, &10));

    set_ledger(&env, 201);
    assert!(!client.transfer(&alice, &bob, &10));
}

#[test]
fn test_add_to_allowlist_rejects_expiration_in_the_past() {
    let env = Env::default();
    set_ledger(&env, 100);
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    let result = client.try_add_to_allowlist(&admin, &alice, &Some(99));
    assert_eq!(result, Err(Ok(Error::InvalidInput)));
    assert!(!client.is_allowed(&alice));

    // The current ledger itself is a valid (single-ledger) expiry.
    client.add_to_allowlist(&admin, &alice, &Some(100));
    assert!(client.is_allowed(&alice));
}

#[test]
fn test_re_adding_expired_entry_restores_allowlist_status() {
    let env = Env::default();
    set_ledger(&env, 100);
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice, &Some(110));
    set_ledger(&env, 111);
    assert!(!client.is_allowed(&alice));

    client.add_to_allowlist(&admin, &alice, &None);
    assert!(client.is_allowed(&alice));
    set_ledger(&env, 10_000);
    assert!(client.is_allowed(&alice));
}
