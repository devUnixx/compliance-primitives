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
