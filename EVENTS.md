# Event Schema Reference

This document describes the Soroban contract events emitted by each contract
in this repository, the naming and topic/data-shape conventions they follow,
and any intentional exceptions to those conventions.

## Convention

### Naming

Event struct names use `PascalCase` and describe the action that occurred
(e.g. `DenyAdd`, `AllowRemove`, `JurisdictionSet`). The Soroban SDK derives a
`snake_case` topic name from the struct name (e.g. `DenyAdd` → `"deny_add"`).
This becomes the first element of the topic vector on-chain, so event
indexers can filter by contract address + first topic to distinguish event
types.

### Topic/data split

The convention across this repo is:

| Field role | Placement | Rationale |
|---|---|---|
| The **primary key** (the address being added/removed/flagged) | `#[topic]` | Enables log bloom / topic-indexed filtering by address |
| A second address that is also a natural filter key | `#[topic]` | Same reason — see `Blocked` below |
| **Payload** values (amounts, codes, etc.) | data map | Not filter keys; kept off the topic vector to keep topics lean |

All `#[topic]` fields appear **before** non-topic fields in the struct.

### Shape summary

Every event body is either:
- **Empty data map** — for single-topic events where no extra payload is
  needed (`AllowAdd`, `AllowRemove`, `DenyAdd`, `DenyRemove`).
- **Non-empty data map** — for events that carry additional payload
  (`JurisdictionSet`, `Blocked`).

---

## Events by contract

### `allowlist-token`

#### `AllowAdd`

Emitted when an address is added to the allowlist.

```
topics : ["allow_add", <address: Address>]
data   : {}
```

| Field | Type | Placement | Description |
|---|---|---|---|
| `address` | `Address` | topic | Address added to the allowlist |

#### `AllowRemove`

Emitted when an address is removed from the allowlist. Also emitted when
`remove_from_allowlist` is called for an address that was never added — the
removal is a no-op but the event is still emitted for auditability.

```
topics : ["allow_remove", <address: Address>]
data   : {}
```

| Field | Type | Placement | Description |
|---|---|---|---|
| `address` | `Address` | topic | Address removed from the allowlist |

#### `Blocked`

Emitted when a `transfer` call is rejected because at least one party is
not on the allowlist. The transaction still succeeds (returns `Ok(false)`)
so that this audit event is persisted.

```
topics : ["blocked", <from: Address>, <to: Address>]
data   : { "amount": <i128> }
```

| Field | Type | Placement | Description |
|---|---|---|---|
| `from` | `Address` | topic | Sender of the attempted transfer |
| `to` | `Address` | topic | Intended recipient |
| `amount` | `i128` | data | Token amount that was blocked |

> **Note — two-topic exception**: `Blocked` carries two `#[topic]` address
> fields (`from` and `to`) rather than the single-topic pattern used by the
> add/remove events. Both parties are natural filter keys for off-chain
> indexers ("show me all blocked attempts involving address X"), so placing
> both in topics is intentional and consistent with the spirit of the
> convention.

#### `AdminTransferred`

Emitted when the admin role changes hands — either immediately via
`transfer_admin(current_admin, new_admin)`, or when a proposed admin
completes the two-step `propose_admin` / `accept_admin` flow.

```
topics : ["admin_transferred", <old_admin: Address>, <new_admin: Address>]
data   : {}
```

| Field | Type | Placement | Description |
|---|---|---|---|
| `old_admin` | `Address` | topic | Admin before the transfer (loses all privileges immediately) |
| `new_admin` | `Address` | topic | Admin after the transfer |

---

### `denylist-gate`

#### `DenyAdd`

Emitted when an address is added to the denylist. Also emitted for each
address in a batch `add_multiple_to_denylist` call.

```
topics : ["deny_add", <address: Address>]
data   : {}
```

| Field | Type | Placement | Description |
|---|---|---|---|
| `address` | `Address` | topic | Address added to the denylist |

#### `DenyRemove`

Emitted when an address is removed from the denylist. Also emitted when
`remove_from_denylist` is called for an address that was never added — the
removal is a no-op but the event is still emitted for auditability.

```
topics : ["deny_remove", <address: Address>]
data   : {}
```

| Field | Type | Placement | Description |
|---|---|---|---|
| `address` | `Address` | topic | Address removed from the denylist |

#### `AdminTransferred`

Emitted when `transfer_admin(current_admin, new_admin)` reassigns the admin
role. Takes effect immediately and is not blocked by `pause`.

```
topics : ["admin_transferred", <old_admin: Address>, <new_admin: Address>]
data   : {}
```

| Field | Type | Placement | Description |
|---|---|---|---|
| `old_admin` | `Address` | topic | Admin before the transfer (loses all privileges immediately) |
| `new_admin` | `Address` | topic | Admin after the transfer |

---

### `jurisdiction-flag`

#### `JurisdictionSet`

Emitted when a jurisdiction code is attached to an address (or updated if
one was already set).

```
topics : ["jurisdiction_set", <address: Address>]
data   : { "code": <String> }
```

| Field | Type | Placement | Description |
|---|---|---|---|
| `address` | `Address` | topic | Address whose jurisdiction was set |
| `code` | `String` | data | ISO 3166-1 alpha-2 (or similar) jurisdiction code |

> **Note — payload in data**: unlike `DenyAdd`/`AllowAdd` where the topic
> address is the entire meaningful payload, `JurisdictionSet` carries a
> `code` value that is not a natural filter key (you'd filter by address,
> then read the code from the data map). Placing `code` in the data map
> rather than as a topic is therefore intentional and consistent with the
> topic/data split convention above.

#### `IssuerTransferred`

Emitted when `transfer_issuer(current_issuer, new_issuer)` reassigns the
issuer role. Takes effect immediately, is not blocked by `pause`, and leaves
any compliance-officer assignment unchanged.

```
topics : ["issuer_transferred", <old_issuer: Address>, <new_issuer: Address>]
data   : {}
```

| Field | Type | Placement | Description |
|---|---|---|---|
| `old_issuer` | `Address` | topic | Issuer before the transfer (loses all privileges immediately) |
| `new_issuer` | `Address` | topic | Issuer after the transfer |

---

### `circuit-breaker`

#### `Frozen`

Emitted when the admin freezes the circuit breaker.

```
topics : ["frozen", <admin: Address>]
data   : {}
```

| Field | Type | Placement | Description |
|---|---|---|---|
| `admin` | `Address` | topic | Admin address that froze the contract |

#### `Unfrozen`

Emitted when the admin unfreezes the circuit breaker.

```
topics : ["unfrozen", <admin: Address>]
data   : {}
```

| Field | Type | Placement | Description |
|---|---|---|---|
| `admin` | `Address` | topic | Admin address that unfroze the contract |

---

## Cross-contract event ordering guarantees

There are none. Each contract emits events only for its own state changes.
If a caller invokes both `denylist-gate` and `jurisdiction-flag` in the same
transaction, events from both contracts will appear in that transaction's
event list in invocation order, but each contract's events are independent.

---

## For indexer authors

To subscribe to all compliance events in this repo, index by:

1. **Contract address** — each deployed instance has a fixed address.
2. **First topic (event name symbol)** — use the table above; all event
   names are stable across versions of these contracts.
3. **Second topic (address)** — available on every event; lets you filter
   to all events touching a given user address across event types.

For `Blocked` events, a third topic (`to` address) is also available.
