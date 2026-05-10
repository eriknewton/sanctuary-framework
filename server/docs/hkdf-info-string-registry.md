# HKDF info-string registry

> **Status:** Created per full-sweep #83. This file is the centralized index of every HKDF info string Sanctuary emits, with the module that owns each string and the upstream secret it derives from.

## Why this registry exists

Sanctuary's cryptographic agility depends on **non-colliding HKDF info strings**. Every encrypted-at-rest store, every per-purpose subkey, every federation-protocol context derives its key material from the fortress master secret via HKDF-SHA256, parameterized by an info string that acts as the domain separator. Two stores that accidentally use the same info string would derive the same key, breaking the principle that compromise of one purpose does not expose another.

Until this registry existed, info strings were scattered across modules with no single index. That made three things hard:

1. **Auditing for collisions.** A new module adding an info string could not easily check that the string was unique.
2. **Reasoning about the v1.x Crypto Agility Sprint.** The post-quantum migration must rotate every derived key in lockstep; without a registry, there was no canonical list of what needed to rotate.
3. **Documenting the recovery cascade.** When the fortress master secret rotates, every derived key changes deterministically, but the audit-chain replay requires knowing what was derived from the old master. Knowing **which info strings exist** is a prerequisite to knowing which historical-master pubkeys / subkeys must be preserved for verification.

This registry pins the v1.0 surface so any future addition is a documented amendment.

## Conventions

- **Salt** is either the fortress master secret salt (set at master-key creation, fixed string `sanctuary-namespace-v1` or `sanctuary-purpose-v1` for the high-level helpers in `server/src/core/key-derivation.ts`) or, for federation-context derivations, the fortress `fortress_id` (a 128-bit ULID). The salt is documented per-row.
- **Info** is the domain-separation string. By convention, info strings either:
  - Use the high-level `derivePurposeKey(masterKey, purpose)` helper, in which case the on-the-wire info is `purpose` and the salt is `sanctuary-purpose-v1`.
  - Use the high-level `deriveNamespaceKey(masterKey, namespace)` helper, in which case the on-the-wire info is `namespace` and the salt is `sanctuary-namespace-v1`.
  - Call `hkdf()` directly, in which case the row documents both the explicit salt and the explicit info.
- **Output length** is 32 bytes (256 bits) unless noted.
- **Owner module** is the file that owns the constant or hard-codes the literal. New constants MUST be exported from a module with `*Constants*` in its filename or local to a single subsystem; do not scatter literals.

## Registry

### A. High-level helpers (server/src/core/key-derivation.ts)

The two high-level helpers fix the salt and use the caller-supplied string as info. The salt itself is part of the contract:

| Helper | Salt | Source |
|---|---|---|
| `deriveNamespaceKey(masterKey, namespace)` | `sanctuary-namespace-v1` | `core/key-derivation.ts:105` |
| `derivePurposeKey(masterKey, purpose)` | `sanctuary-purpose-v1` | `core/key-derivation.ts:130` |

Every entry in §B and §C below routes through one of these two helpers OR calls `hkdf()` directly with its own salt.

### B. Purpose strings (info to derivePurposeKey, salt = sanctuary-purpose-v1)

| Info string | Owner module | Constant name (if any) | Purpose |
|---|---|---|---|
| `identity-encryption` | `server/src/l1-cognitive/tools.ts:82`, `server/src/l4-reputation/tools.ts:35`, `server/src/handshake/protocol.ts:96`, `server/src/exit/bundle.ts:524` | (literal) | Wraps Ed25519 identity private keys at rest. |
| `audit-log` | `server/src/l2-operational/audit-log.ts:68` | (literal) | Encrypts the L2 audit log. |
| `principal-baseline` | `server/src/principal-policy/baseline.ts:40` | (literal) | Encrypts the L2 baseline-tracker store. |
| `l2-privacy-policies-v1` | `server/src/l2-operational/privacy-core.ts:157` | (literal) | Encrypts L2 privacy policy state. |
| `sanctuary-v1.1-privacy-content-hmac` | `server/src/l2-operational/privacy-core.ts:225` | (literal) | HMAC key for privacy-content fingerprints. |
| `l2-privacy-placeholders` | `server/src/l2-operational/privacy-filter.ts:241` | (literal) | Encrypts L2 placeholder store. |
| `l2-privacy-placeholder-lookup` | `server/src/l2-operational/privacy-filter.ts:242` | (literal) | Lookup-key derivation for placeholder reverse index. |
| `l2-context-gate` | `server/src/l2-operational/context-gate.ts:320` | (literal) | Encrypts the context-gate policy store. |
| `l3-policies` | `server/src/l3-disclosure/policies.ts:140` | (literal) | Encrypts L3 disclosure policy store. |
| `l3-commitments` | `server/src/l3-disclosure/commitments.ts:108` | (literal) | Encrypts L3 commitment store. |
| `bridge-commitments` | `server/src/bridge/tools.ts:44` | (literal) | Encrypts Concordia-bridge commitment store. |
| `l4-reputation` | `server/src/l4-reputation/reputation-store.ts:202` | (literal) | Encrypts L4 reputation store. |
| `sovereignty-profile` | `server/src/sovereignty-profile.ts:79` | `HKDF_DOMAIN` | Encrypts the sovereignty profile store. |
| `intelligence-substrate-config` | `server/src/intelligence/policy-store.ts:39` | `HKDF_INFO` | Encrypts the intelligence-substrate policy store. |
| `operator-chat-store-v1` | `server/src/chat/operator-chat-store.ts:40` | `HKDF_INFO` | Encrypts the operator-chat (concierge) store. |
| `sanctuary-v1.1-coordination-handoffs` | `server/src/coordination/handoff-store.ts:27` | `HANDOFF_PURPOSE_KEY` | Encrypts the v1.1 coordination handoff store. |

### C. Namespace strings (info to deriveNamespaceKey, salt = sanctuary-namespace-v1)

| Info string | Owner module | Constant name (if any) | Purpose |
|---|---|---|---|
| `sanctuary-fortress-mode-v1` | `server/src/fortress/config.ts:44` (constant defined at `fortress/constants.ts:156`) | `HKDF_FORTRESS_MODE_INFO` | Encrypts the fortress-mode config store. |
| `sanctuary-composition-v1` | `server/src/composition/constants.ts:149` | `HKDF_COMPOSITION_INFO` | Encrypts composition config and per-composition state. |
| `<arbitrary state-namespace name>` | `server/src/l1-cognitive/state-store.ts:171` | (caller-supplied) | Per-namespace L1 state encryption. The namespace name is the agent's namespace identifier. Underscore-prefixed namespaces (e.g. `_meta`, `_context_gate_policies`) are reserved for internal use. |

### D. Direct hkdf() callers (explicit salt + info)

These derivations bypass the high-level helpers because they need a salt other than `sanctuary-purpose-v1` / `sanctuary-namespace-v1`. Most use `fortress_id` as the salt so the derivation is bound to a specific fortress.

| Salt | Info | Owner module | Purpose |
|---|---|---|---|
| undefined (passphrase context) | `sanctuary-passphrase-v1` | `server/src/cocoon/passphrase.ts:581` | Final master-key derivation step in the passphrase flow. The Argon2id output is fed to HKDF with this info string to produce the 32-byte master key. |
| `fortress_id` | `sanctuary-fed-v0.1-transport` `\|\| node_id \|\| node_mode` | `server/src/mesh/trust-root.ts:362` | Per-node transport subkey for federation v0.1. |
| `fortress_id` | `sanctuary-fed-v0.1-audit-chain` `\|\| node_id` | `server/src/mesh/trust-root.ts:388` | Per-node audit-chain subkey for federation v0.1. |
| `fortress_id` | `sanctuary-fed-v0.1-lifecycle-agent-state-transfer` | `server/src/mesh/lifecycle/sync.ts:122` | Sync-envelope encryption for agent-state transfer between mesh nodes. |
| `fortress_id` | `sanctuary-fed-v0.1-lifecycle-node-key-wrap` | `server/src/mesh/lifecycle/cocoon-binding.ts:56` | AES-256-GCM wrap of per-node Ed25519 keys (cocoon-binding). |
| `fortress_id` | `sanctuary-agent-contract-v0.1` `\|\| <agent_subkey_id>` | `server/src/agent-contract/identity-bind.ts:55,79` | Per-agent identity-binding subkeys. |
| `fortress_id` | `sanctuary-composition-v1.0-sidecar-signing-key` | `server/src/composition/sidecar-signing-key.ts:77` | Composition sidecar's Ed25519 signing keypair. See `composition/constants.ts:HKDF_COMPOSITION_SIDECAR_SIGNING_INFO`. |
| `fortress_id` | `sanctuary-recovery-flows-v0.1-master-rotation-bundle` `\|\| <bundle_id>` | `server/src/mesh/recovery-flows/secret-bundle.ts:78` | Recovery-flow master-rotation bundle wrap. |

### E. Domain-separation strings used elsewhere (not strictly HKDF info, but co-located by convention)

These strings serve the same domain-separation purpose as HKDF info but appear in non-HKDF contexts (Fiat-Shamir transcript labels, signature challenge tags). Listed here so a future audit pass can see the full domain-separation surface:

| String | Use site | Purpose |
|---|---|---|
| `sanctuary-pedersen-generator-H-v1-a` / `sanctuary-pedersen-generator-H-v1-b` | `server/src/l3-disclosure/zk-proofs.ts:42-43` | Hash-to-curve seed strings for the Pedersen second generator. |
| `sanctuary-zk-pok-v1` | `server/src/l3-disclosure/zk-proofs.ts:247,277` | Fiat-Shamir transcript label for proof-of-knowledge. |
| `sanctuary-zk-range-sum-v1` | `server/src/l3-disclosure/zk-proofs.ts:361,418` | Fiat-Shamir transcript label for range-sum proof. |
| `sanctuary-zk-bit-v1` | `server/src/l3-disclosure/zk-proofs.ts:462,492,529` | Fiat-Shamir transcript label for bit-decomposition proof. |
| `sanctuary-sign-challenge-v1` | `server/src/sanctuary-tools.ts:563` | Domain-separation prefix for signed challenges. |

## Adding a new info string

1. Pick a name that is **collision-free against this registry**. Convention: `<purpose-or-area>-v<spec-version>` (e.g. `l5-foo-v1`, `sanctuary-feature-v2`).
2. Define the constant in the owning module's `constants.ts`. Avoid bare literals at use-sites; use the constant.
3. Add a row to the appropriate section above (B for purpose, C for namespace, D for direct `hkdf()`, E for non-HKDF domain separation).
4. If the new string lives in a federation-protocol context, also update the federation spec §10 reservations as needed.

## Crypto-agility migration note

The v1.5+ Crypto Agility Sprint will replace HKDF-SHA256 with a post-quantum-aware KDF (likely HKDF-SHA3-256 or KMAC-256, pending CFRG guidance at that time). When that sprint runs, **every info string in this registry MUST be rotated to a v2 variant** (`sanctuary-fed-v0.2-transport`, `sanctuary-composition-v2-sidecar-signing-key`, etc.) so the v1.x derivations remain reproducible from preserved historical-master pubkeys and the v2 derivations live in a non-overlapping domain. Audit-chain continuity (federation spec §9.5) requires that v1.x verification still works post-migration; isolating the namespaces is how that works.
