# Fuzz harnesses

This repo uses **lightweight seeded-PRNG sequence fuzzers** inside each
contract's `#[cfg(test)]` tree rather than a separate `cargo-fuzz` workspace.

## Why not cargo-fuzz / libFuzzer?

Soroban contract tests need a host `Env`, `mock_all_auths`, and `Address`
generation from `soroban-sdk` testutils. Wiring that through libFuzzer's
byte-buffer `fuzz_target!` is possible but heavy for `#![no_std]` crates and
duplicates most of the unit-test setup. A plain `#[test]` loop with a tiny
xorshift PRNG covers the same last-write-wins invariants with zero extra
toolchain deps, and the same scaffolding can be copied for denylist-gate
(#86) and jurisdiction-flag (#87).

## jurisdiction-flag (`#87`)

Harness: `contracts/jurisdiction-flag/src/fuzz.rs`

Invariants checked after every random `set_jurisdiction` sequence:

1. **Last write wins** — `get_jurisdiction(addr)` equals the most recently
   set code for that address (or `None` if never set).
2. **Permission consistency** — `is_permitted_jurisdiction(addr, allowed)`
   matches `get_jurisdiction(addr)` membership in the fuzzer's fixed
   `allowed_codes` list.

### Short run (default, also in `cargo test`)

```sh
cargo test -p jurisdiction-flag fuzz_jurisdiction_set_get_sequences -- --nocapture
```

Defaults: `FUZZ_ITERATIONS=128`, `FUZZ_OPS=24`.

### Periodic longer campaign (not in CI)

```sh
FUZZ_ITERATIONS=2000 FUZZ_OPS=64 \
  cargo test -p jurisdiction-flag fuzz_jurisdiction_set_get_sequences -- --nocapture
```

Run this after non-trivial changes to `set_jurisdiction` /
`get_jurisdiction` / `is_permitted_jurisdiction`, or as part of a release
checklist. Failures print the failing `seed` so the sequence is reproducible.

Multi-code add/remove operations are also fuzzed against a fixed code-pool
set model:

```sh
cargo test -p jurisdiction-flag fuzz_jurisdiction_multicode_add_remove_sequences -- --nocapture
```

This target uses the same `FUZZ_ITERATIONS` and `FUZZ_OPS` controls and checks
that each operation leaves `list_jurisdictions` equal to the modeled set.

## circuit-breaker × denylist-gate-consumer (`#465`)

Harness: `examples/denylist-gate-consumer/src/fuzz_test.rs`

Fuzzes the **composition** of `circuit-breaker` and `denylist-gate` inside a
consumer token's transfer path — the integration-level scenario that
single-contract harnesses cannot cover.  Random `freeze`/`unfreeze`,
`add_to_denylist`/`remove_from_denylist`, and `transfer` calls are interleaved
in arbitrary order.

Invariants checked after every `transfer` attempt:

1. **Frozen gate always blocks** — while `is_frozen()` is `true`, every
   `transfer` must return `Err(FrozenByBreaker)`.
2. **Unfrozen + denied still blocks** — `Err(DeniedByGate)` only fires when
   unfrozen and at least one party is denied.
3. **Unfrozen + both clear allows** — a `transfer` that returns `Ok(())` must
   only occur when unfrozen and neither party is denied.
4. **Balances never mutate through a blocked transfer** — any rejected transfer
   leaves sender and recipient balances unchanged.
5. **No panic** — no op sequence causes a host panic.

### Short run (default, also in `cargo test`)

```sh
cargo test -p denylist-gate-consumer fuzz_circuit_breaker_consumer_composition
```

Defaults: `FUZZ_ITERATIONS=500`, `FUZZ_OPS=32`.

### Periodic longer campaign (not in CI)

```sh
FUZZ_ITERATIONS=2000 FUZZ_OPS=64 \
  cargo test -p denylist-gate-consumer fuzz_circuit_breaker_consumer_composition -- --nocapture
```

Run this after non-trivial changes to `circuit-breaker`, `denylist-gate`, or
the consumer transfer path.  Failures print the failing `seed` for
reproducibility.

## policy-engine (`#234`)

Harness: `contracts/policy-engine/src/fuzz.rs`

Randomly builds combinator trees (up to `MAX_CHECKS=16` entries) using a
mix of `AddDenylist`, `AddJurisdiction`, and `RemoveCheck` mutations, arms
addresses on the denylist or with jurisdiction codes, then calls `evaluate`
for a random `(from, to)` pair.

Invariants checked after every random sequence:

1. **No panic** — `add_check`, `remove_check`, and `evaluate` must never
   panic regardless of the input sequence.
2. **MaxDepthExceeded is returned** — `add_check` returns
   `Err(Error::MaxDepthExceeded)` when the list is at capacity; it does not
   panic and does not silently truncate.
3. **All semantics oracle** — with `CombineOp::All`, `evaluate` returns
   `true` iff every registered check passes for both `from` and `to`.
4. **Any semantics oracle** — with `CombineOp::Any`, `evaluate` returns
   `true` iff at least one registered check passes for both `from` and `to`.

### Short run (default, also in `cargo test`)

```sh
cargo test -p policy-engine fuzz_policy_engine_tree -- --nocapture
```

Defaults: `FUZZ_ITERATIONS=128`, `FUZZ_OPS=24`.

### Periodic longer campaign (not in CI)

```sh
FUZZ_ITERATIONS=2000 FUZZ_OPS=64 \
  cargo test -p policy-engine fuzz_policy_engine_tree -- --nocapture
```

Run this after non-trivial changes to `add_check` / `remove_check` /
`evaluate`, or as part of a release checklist. Failures print the failing
`seed` so the exact failing sequence is fully reproducible.

## allowlist-token (`#22`)

Harness: `contracts/allowlist-token/src/fuzz.rs`

**Why a seeded-PRNG loop instead of `cargo-fuzz` or `proptest`:** it matches
the other harnesses in this repo, runs on the stable toolchain as part of
`cargo test` with no extra dependencies, and prints the failing `seed` so any
counterexample replays exactly. `cargo-fuzz` would need nightly plus a
separate workspace that re-creates the Soroban test `Env` from raw bytes.

Each iteration puts the contract in front of a `CountingToken` double (it
counts how many transfers reach it) and applies a random sequence of
`add_to_allowlist` (with and without an `expiration_ledger`),
`remove_from_allowlist`, ledger advances (so expiries actually lapse),
`pause`/`unpause`, and `transfer` calls with random parties and amounts
(including negative and `i128` extremes).

Invariants checked after every step:

1. **Forward only when both parties are allowlisted** — `transfer` reaches
   the underlying token (and returns `Ok(true)`) only when the contract is
   unpaused, `amount >= 0`, and both `from` and `to` are allowlisted *at call
   time* (entry present and not past its `expiration_ledger`). In every other
   case the underlying token's call counter must not change.
2. **Error mapping** — negative amount → `InvalidInput`, paused →
   `ContractPaused`, a non-allowlisted party → `Ok(false)`.
3. **Model agreement** — `is_allowed(addr)` matches the harness's model for
   every address.

### Short run (default, also in `cargo test`)

```sh
cargo test -p allowlist-token fuzz_transfer_only_forwards_when_both_allowlisted -- --nocapture
```

Defaults: `FUZZ_ITERATIONS=128`, `FUZZ_OPS=24`. This bounded run is part of
the regular workspace `cargo test`, so it runs in CI.

### Periodic longer campaign (not in CI)

```sh
FUZZ_ITERATIONS=2000 FUZZ_OPS=64 \
  cargo test -p allowlist-token fuzz_transfer_only_forwards_when_both_allowlisted -- --nocapture
```

Run this after non-trivial changes to `transfer`, `is_allowed`,
`add_to_allowlist`, or `remove_from_allowlist`, or as part of a release
checklist.
