# Signed Operator Policy Distribution Rail, Slice 1

Date: 2026-06-27

This slice adds the first custody-safe rail for distributing operator policy state across the v1 federation log. It distributes only a verified policy marker: version, SHA-256 hash, hash algorithm, signing time, and issuing-principal signature. It does not distribute raw policy contents, approval-channel secrets, policy-derived secrets, or private keys.

This is custody-state distribution, not portable audit evidence. It must not be described as parity with Pipelock audit evidence.

## Event

New operator-authority event kind:

```text
operator_policy_bundle
```

Authority origin:

```text
operator:<fortress_id>
```

Payload fields:

```text
event_version: sanctuary.v1.operator-policy-bundle
fortress_id
policy_version
policy_hash
policy_hash_algorithm: sha256-base64url
signed_at
operator_principal_id
operator_signature
```

Signature domain:

```text
sanctuary.v1.federation-policy-bundle
```

The signature is Ed25519 over the canonical payload without `operator_signature`, using the existing federation issuing-principal private key. Receivers verify the issuing-principal certificate against the pinned fortress master, verify the principal id, then verify the payload signature. A bad chain, wrong principal, malformed payload, replayed version, wrong authority origin, or bad signature rejects the event.

## Sync Path

No `/v1` route was added or changed. The bundle rides the existing hash-chained federation event log and the existing `/v1/federation/sync` envelope.

The reserved operator-authority event gate now recognizes `node_eviction` and `operator_policy_bundle`. If the verification callback is unavailable, reserved events are rejected rather than appended.

## Applied State

The durable `FederationSyncStateSnapshot` now carries:

```text
operatorPolicy: FederationAppliedPolicyVersion | null
appliedPolicyVersions: Map<node_id, FederationAppliedPolicyVersion>
```

Each marker stores:

```text
version
hash
hash_algorithm
applied_at
source_event_id
```

The dashboard projects an accepted bundle onto the local node as its applied marker only after verification succeeds. Missing policy fields from older in-memory callers normalize to empty state; malformed present fields in the encrypted record still fail closed.

## CLI

New command:

```bash
sanctuary federation policy-push --fortress-url <url> [--policy-path <path>] [--idempotency-key <s>]
```

The command:

1. Unlocks the local operator identity through the existing headless custody path.
2. Loads the local federation trust root to sign the event with the issuing principal.
3. Reads the current local Principal Policy only to parse its version and compute a SHA-256 base64url hash.
4. Opens a `/v1` session with the existing operator attestation ceremony.
5. Uses `/v1/federation/sync` first to fetch the operator-authority cursor, then to append the signed bundle event.
6. Prints only safe marker fields: pushed flag, version, hash, hash algorithm, and event id.

The command does not print or send raw policy contents.

## Fleet Console

The loopback fleet presenter now shows signed policy state:

```text
operator policy version/hash
per-node applied version/hash
per-node drift: in_sync, drifted, unknown
summary counts: in_sync, drifted, unknown
```

Unknown is never green. If no operator policy marker is known, every node remains unknown even if it has an applied marker. A node is in sync only when version, hash, and hash algorithm match the current operator marker.

## Follow-ups

This slice deliberately stays small. Remaining work for later PRs:

1. Run Erik's two-machine drill and ratify the design before merge.
2. Add explicit remote applied-policy acknowledgments if the live sync drill shows that passive propagation is not enough for operator UX.
3. Decide whether a separate operator-approved raw policy transfer channel is needed. If built, it must preserve the no-agent-read and no-raw-policy-in-event invariants.
4. Add richer console drill-down once the 2-machine behavior is ratified.
