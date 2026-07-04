# HKDF info-string registry

> **Status:** Created per full-sweep #83. **Reconciled against a full code scan 2026-06-16** (Phase-0 rename safety net): a mechanical scan of every `derivePurposeKey` / `deriveNamespaceKey` / direct `hkdf()` constant arg + the master-rotation purpose registry found 35 in-code labels absent from this doc. They are added below, each tagged `(scan-reconciled 2026-06-16)`. The authoritative source is the **code scan**, not this doc; the machine-readable classification lives at `server/test/fixtures/at-rest/hkdf-label-classification.json` and is guarded by `server/test/structure/hkdf-registry-reconciliation.test.ts`, which re-runs the scan and fails if a new in-code label is added without a registry row. This file is the centralized index of every HKDF info string Sanctuary emits, with the module that owns each string and the upstream secret it derives from.

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
| `identity-encryption` | `server/src/cognitive/tools.ts:82`, `server/src/reputation/tools.ts:35`, `server/src/handshake/protocol.ts:96`, `server/src/exit/bundle.ts:524` | (literal) | Wraps Ed25519 identity private keys at rest. |
| `audit-log` | `server/src/operational/audit-log.ts:68` | (literal) | Encrypts the Operational audit log. |
| `principal-baseline` | `server/src/principal-policy/baseline.ts:40` | (literal) | Encrypts the Operational baseline-tracker store. |
| `l2-privacy-policies-v1` | `server/src/operational/privacy-core.ts:157` | (literal) | Encrypts Operational privacy policy state. |
| `sanctuary-v1.1-privacy-content-hmac` | `server/src/operational/privacy-core.ts:225` | (literal) | HMAC key for privacy-content fingerprints. |
| `l2-privacy-placeholders` | `server/src/operational/privacy-filter.ts:241` | (literal) | Encrypts Operational placeholder store. |
| `l2-privacy-placeholder-lookup` | `server/src/operational/privacy-filter.ts:242` | (literal) | Lookup-key derivation for placeholder reverse index. |
| `l2-context-gate` | `server/src/operational/context-gate.ts:320` | (literal) | Encrypts the context-gate policy store. |
| `l3-policies` | `server/src/disclosure/policies.ts:140` | (literal) | Encrypts Selective Disclosure policy store. |
| `l3-commitments` | `server/src/disclosure/commitments.ts:108` | (literal) | Encrypts Selective Disclosure commitment store. |
| `bridge-commitments` | `server/src/bridge/tools.ts:44` | (literal) | Encrypts Concordia-bridge commitment store. |
| `federation-trust-root` | `server/src/mesh/federation-trust-root-store.ts:38` | `FEDERATION_TRUST_ROOT_HKDF_INFO` | Encrypts the `_federation/trust-root-v1` mesh federation trust-root record. **(scan-reconciled 2026-06-23; decryptable store; frozen at-rest contract.)** |
| `federation-joiner-trust-root` | `server/src/mesh/federation-joiner-trust-root-store.ts:43` | `FEDERATION_JOINER_TRUST_ROOT_HKDF_INFO` | Encrypts the `_federation/joiner-trust-root-v1` NON-ISSUER joiner trust-root record (Federation Slice 3a). **(scan-reconciled 2026-06-24; decryptable store; frozen at-rest contract.)** |
| `federation-bootstrap-nonce-spent-set` | `server/src/mesh/lifecycle/standalone-join-approver.ts` (`BOOTSTRAP_NONCE_STORE_HKDF_INFO`, via `durable-spent-set-store.ts`) | `BOOTSTRAP_NONCE_STORE_HKDF_INFO` | Encrypts the `_federation/spent-bootstrap-nonces-v1` durable single-use nonce set so a spent local-join nonce survives a daemon restart (replay denied across restart; fail-closed on a corrupt record). **(scan-reconciled 2026-06-24; decryptable store; frozen at-rest contract.)** |
| `federation-operator-cloud-provision-claim-set` | `server/src/mesh/lifecycle/operator-cloud-join-approver.ts` (`OPERATOR_CLOUD_CLAIM_STORE_HKDF_INFO`, via `durable-claim-set-store.ts`) | `OPERATOR_CLOUD_CLAIM_STORE_HKDF_INFO` | Encrypts the `_federation/operator-cloud-provision-claims-v1` durable single-use provision-claim set so a consumed claim's single-use state survives a daemon restart (cloud join not replayable across restart; fail-closed on a corrupt record). **(scan-reconciled 2026-06-24; decryptable store; frozen at-rest contract.)** |
| `federation-sync-state` | `server/src/v1/federation-sync-state-store.ts` (`FEDERATION_SYNC_STATE_STORE_HKDF_INFO`) | `FEDERATION_SYNC_STATE_STORE_HKDF_INFO` | Encrypts the `_federation/sync-state-v1` durable peer-sync security state (Federation 3/3b P0): per-sender accepted high-water + outbound high-water + folded node-revocation projection. Makes anti-replay AND revocation survive a daemon restart (captured envelope rejected post-restart; revoked node stays revoked across reboot); fail-closed on a corrupt record. **ALSO** the MAC key for two `_meta` markers (F1 re-gate, §7 reuse: NO new HKDF label): the guardian **established sentinel** (`_meta/federation-guardian-requirement-established-v1`, domain `sanctuary.federation.guardian-requirement.established.v1`, a dataless MAC) and the guardian **anti-rollback anchor** (`_meta/federation-guardian-antirollback-anchor-v1`, domain `sanctuary.federation.guardian-antirollback-anchor.v1\n`, a `{marker,data,mac}` record MAC'd over `canonicalJson(data)`). Domain separation comes from the two distinct MAC-domain strings (see section E), exactly as `custody-rollback-freeze` vs `custody-epoch-witness` are separated. Both are handled under master rotation by the `master-rotation.ts` classes `federation-guardian-established` (inline re-derive of the dataless MAC) and `federation-guardian-antirollback` (`restampMacRecord`). **(scan-reconciled 2026-06-24; amended 2026-07-05 for the F1 re-gate MAC-marker reuse; decryptable store; frozen at-rest contract.)** |
| `federation-reissue-node-cert-challenge-set` | `server/src/v1/federation-reissue-challenge-store.ts` (`FEDERATION_REISSUE_CHALLENGE_STORE_HKDF_INFO`, via `durable-spent-set-store.ts`) | `FEDERATION_REISSUE_CHALLENGE_STORE_HKDF_INFO` | Encrypts the `_federation/reissue-node-cert-challenges-v1` durable single-use server challenge spent-set for node-cert reissue (Federation 3c-2). Accepted proof challenges survive daemon restart as spent, so a successful reissue proof cannot be replayed after restart; fail-closed on corrupt. **(scan-reconciled 2026-06-26; decryptable store; frozen at-rest contract.)** |
| `federation-rotate-root-journal-mac` | `server/src/mesh/federation-rotate-root.ts` (`FEDERATION_ROTATE_ROOT_JOURNAL_MAC_PURPOSE`) | `FEDERATION_ROTATE_ROOT_JOURNAL_MAC_PURPOSE` | MAC key (derived under the custody master) authenticating the federation rotate-root journal record (`_federation/rotate-root-journal`, Slice 3a issuer-side signing-master rotation). Not a decryptable store; renaming breaks `--resume` of an in-progress rotation. **(scan-reconciled 2026-06-24; crypto-domain label.)** |
| `operator-cloud-joined-node` | `server/src/mesh/operator-cloud-joined-node-store.ts` (`OPERATOR_CLOUD_JOINED_NODE_HKDF_INFO`) | `OPERATOR_CLOUD_JOINED_NODE_HKDF_INFO` | Encrypts the `_federation/operator-cloud-joined-node-v1` NON-ISSUER operator_cloud joined-node record (Operator Cloud Slice 3 boot-wire): pinned master public key, issuing principal cert, this node's operator_cloud node cert, the node private key held wrapped under the per-node unseal key, the scope manifest, and the Option A trust-boundary manifest. Load-only on boot, fail-closed on corrupt. **(scan-reconciled 2026-06-25; decryptable store; frozen at-rest contract.)** |
| `l4-reputation` | `server/src/reputation/reputation-store.ts:202` | (literal) | Encrypts Verifiable Reputation store. |
| `sovereignty-profile` | `server/src/sovereignty-profile.ts:79` | `HKDF_DOMAIN` | Encrypts the sovereignty profile store. |
| `intelligence-substrate-config` | `server/src/intelligence/policy-store.ts:39` | `HKDF_INFO` | Encrypts the intelligence-substrate policy store. |
| `operator-chat-store-v1` | `server/src/chat/operator-chat-store.ts:40` | `HKDF_INFO` | Encrypts the operator-chat (concierge) store. |
| `query-anonymity-reverse-mapping-v1` | `server/src/query-anonymity/reverse-mapping-store.ts:20` | `HKDF_INFO` | Encrypts Rho-3 per-query reverse mappings for smart-mode render-time restoration. |
| `sanctuary-v1.1-coordination-handoffs` | `server/src/coordination/handoff-store.ts:27` | `HANDOFF_PURPOSE_KEY` | Encrypts the v1.1 coordination handoff store. |
| `transparency-counter-floor` | `server/src/transparency/emitter.ts` | (literal) | MAC key for the transparency checkpoint anti-rollback counter floor. (Registered retroactively; shipped with PR #451.) |
| `transparency-anchor-signing-v1` | `server/src/transparency/anchor.ts` | `TRANSPARENCY_ANCHOR_SIGNING_PURPOSE` | Derives the dedicated ECDSA P-256 anchoring key (the per-fortress pseudonym that signs salted commitment preimages for Sigstore Rekor anchors). Retry suffix `/retry-N` reserved for the astronomically rare out-of-range derivation. |
| `transparency-anchor-config-mac-v1` | `server/src/transparency/anchor.ts` | `TRANSPARENCY_ANCHOR_CONFIG_MAC_PURPOSE` | MAC key authenticating the opt-in anchoring config (a tampered config must not silently enable transmission or silently disable anchoring). |
| `l2-honeypot-trap-v1` | `server/src/honeypot/trap-store.ts:48` | `HKDF_INFO` | Encrypts the honeypot trap store. **(scan-reconciled 2026-06-16; decryptable store.)** |
| `l2-sentinel-finding-v1` | `server/src/sentinel/sentinel-finding-store.ts:39` | `HKDF_INFO` | Encrypts the sentinel-finding store. **(scan-reconciled 2026-06-16; decryptable store.)** |
| `l2-anomaly-classifier-state-v1` | `server/src/anomaly-detection/classifier-state-store.ts:33` | `HKDF_INFO` | Encrypts the anomaly-classifier state store. **(scan-reconciled 2026-06-16; decryptable store.)** |
| `l2-auto-trigger-rules-v1` | `server/src/auto-trigger/threshold-config-store.ts:44` | `HKDF_INFO` | Encrypts the auto-trigger threshold/rules store. **(scan-reconciled 2026-06-16; decryptable store.)** |
| `l2-recognition-hosted-did-web-v1` | `server/src/recognition/did-web-hosted-registry.ts:29` | `HKDF_INFO` | Encrypts the hosted did:web registry store. **(scan-reconciled 2026-06-16; decryptable store.)** |
| `l2-query-anonymity-tier-b-v1` | `server/src/query-anonymity/pii-config-store.ts:47` | `HKDF_INFO` | Encrypts the query-anonymity tier-B PII config store. **(scan-reconciled 2026-06-16; decryptable store.)** |
| `l2-approval-aggregator-v1` | `server/src/principal-policy/approval-aggregator.ts:41` | `APPROVAL_AGGREGATOR_HKDF_INFO` | Encrypts the approval-aggregator's own per-fortress store (DISTINCT from the payload store below). **(scan-reconciled 2026-06-16; decryptable store.)** |
| `l2-approval-aggregator-payload-v1` | `server/src/principal-policy/aggregator-store.ts:47` | `HKDF_INFO` | Encrypts the approval-aggregator payload store. **(scan-reconciled 2026-06-16; decryptable store.)** |
| `l2-english-policy-activation-v1` | `server/src/policy-engine/english-policy-activator.ts:148` | `ACTIVATION_HKDF_INFO` | Encrypts the English-policy activation store. **(scan-reconciled 2026-06-16; decryptable store.)** |
| `principal-policy-unified-inbox-v1` | `server/src/principal-policy/unified-inbox-store.ts:32` | `HKDF_INFO` | Encrypts the unified-inbox store. **(scan-reconciled 2026-06-16; decryptable store.)** |
| `principal-policy-unified-inbox-operator-prefs-v1` | `server/src/principal-policy/unified-inbox-prefs-store.ts:15` | `HKDF_INFO` | Encrypts the unified-inbox operator-prefs store. **(scan-reconciled 2026-06-16; decryptable store.)** |
| `principal-policy-unified-inbox-retention-policy-v1` | `server/src/principal-policy/unified-inbox-retention-policy.ts:39` | `HKDF_INFO` | Encrypts the unified-inbox retention-policy store. **(scan-reconciled 2026-06-16; decryptable store.)** |
| `concierge-memory-store-v1` | `server/src/chat/concierge-memory-store.ts:49` | `HKDF_INFO` | Encrypts the concierge memory store. **(scan-reconciled 2026-06-16; decryptable store.)** |
| `query-anonymity-reverse-mapping-v1` | `server/src/query-anonymity/reverse-mapping-store.ts:21` | `HKDF_INFO` | (Already documented in row above for Rho-3 reverse mappings; constant `HKDF_INFO`.) **(scan note 2026-06-16: confirmed present.)** |
| `distress-inbox` | `server/src/distress/inbox.ts:60` | (literal) | Encrypts the distress inbox store. **(scan-reconciled 2026-06-16; decryptable store.)** |
| `audit-head-anchor` | `server/src/operational/audit-log.ts:387,646` | (literal) | MAC key for the audit-log head anchor (tamper-evident chain head). **(scan-reconciled 2026-06-16; MAC/crypto-domain label, not a decryptable store.)** |
| `audit-rotation-anchor` | `server/src/operational/audit-log.ts:645` | (literal) | MAC key for the audit-log rotation anchor. **(scan-reconciled 2026-06-16; MAC/crypto-domain label.)** |
| `audit-epoch-wrap` | `server/src/operational/audit-log.ts:164` | `AUDIT_EPOCH_WRAP_PURPOSE` | AEAD wrap key for per-epoch audit keys. **(scan-reconciled 2026-06-16; key-wrap/crypto-domain label.)** |
| `audit-epoch-record-mac` | `server/src/operational/audit-log.ts:165` | `AUDIT_EPOCH_MAC_PURPOSE` | MAC key for per-epoch audit records. **(scan-reconciled 2026-06-16; MAC/crypto-domain label.)** |
| `custody-envelope-mac` | `server/src/core/master-custody.ts:577` | (literal) | MAC key for the custody envelope. **(scan-reconciled 2026-06-16; MAC/crypto-domain label.)** |
| `custody-sentinel` | `server/src/core/master-custody.ts:702,823` | (literal) | Custody-sentinel probe key. **(scan-reconciled 2026-06-16; crypto-domain label.)** |
| `custody-rotation-journal-mac` | `server/src/core/master-rotation.ts:147` | `JOURNAL_MAC_PURPOSE` | MAC key for the custody rotation journal. **(scan-reconciled 2026-06-16; MAC/crypto-domain label.)** |
| `custody-rollback-freeze-mac` | `server/src/core/anti-rollback.ts:181`, `core/master-rotation.ts:450` | `FREEZE_MAC_PURPOSE` / `ROLLBACK_FREEZE_MAC_PURPOSE` | MAC key for the rollback-freeze record. **(scan-reconciled 2026-06-16; MAC/crypto-domain label.)** |
| `custody-epoch-witness-mac` | `server/src/core/anti-rollback.ts:177` | `EPOCH_WITNESS_MAC_PURPOSE` | MAC key for the custody epoch-witness record. **(scan-reconciled 2026-06-16; MAC/crypto-domain label.)** |
| `state-meta-mac` | `server/src/cognitive/state-store.ts:467,1773` | (literal) | MAC key for Cognitive state-store metadata. **(scan-reconciled 2026-06-16; MAC/crypto-domain label.)** |
| `config-security-baseline-mac` | `server/src/core/config-baseline.ts` | `CONFIG_BASELINE_MAC_PURPOSE` | MAC key authenticating the config-security-downgrade baseline (the custody-MAC config-downgrade gate; replaces #791's unsigned adjacent baseline). Forging the baseline requires the master key. **(scan-reconciled 2026-06-28; MAC/crypto-domain label.)** |
| `state-export-bundle-mac-v1` | `server/src/cognitive/state-store.ts:77` | (literal) | MAC key binding the portable state-export bundle body + completeness manifest together (anti-lock-in integrity verification). **(scan-reconciled 2026-06-21; MAC/crypto-domain label.)** |
| `sdw-catalog-v1` | `server/src/sdw/records.ts:8` (`SDW_CATALOG_HKDF_INFO`) | `SDW_CATALOG_HKDF_INFO` | Encrypts the SDW catalog store. **(scan-reconciled 2026-06-16; decryptable store.)** |
| `sdw-working-state-v1` | `server/src/sdw/records.ts:9` | `SDW_WORKING_STATE_HKDF_INFO` | Encrypts the SDW working-state store. **(scan-reconciled 2026-06-16; decryptable store.)** |
| `sdw-query-history-v1` | `server/src/sdw/records.ts:10` | `SDW_QUERY_HISTORY_HKDF_INFO` | Encrypts the SDW query-history store. **(scan-reconciled 2026-06-16; decryptable store.)** |
| `sdw-document-corpus-v1` | `server/src/sdw/records.ts:11` | `SDW_DOCUMENT_CORPUS_HKDF_INFO` | Encrypts the SDW document-corpus store. **(scan-reconciled 2026-06-16; decryptable store.)** |
| `sdw-vector-memory-v1` | `server/src/sdw/records.ts:12` | `SDW_VECTOR_MEMORY_HKDF_INFO` | Reserved for the SDW vector-memory store. **(scan-reconciled 2026-06-16; decryptable store / reserved.)** |
| `sdw-replay-anchor-mac` | `server/src/sdw/replay-anchor.ts:17`, `sdw/write-gate.ts:26` | `SDW_REPLAY_MAC_INFO` | MAC key for SDW replay anchors. **(scan-reconciled 2026-06-16; MAC/crypto-domain label.)** |
| `recovery-key-wrap` | `server/src/core/master-custody.ts:370` | (literal) | AEAD key wrapping the master under the recovery key. **(scan-reconciled 2026-06-16; key-wrap; salt = `sanctuary-custody-v1`, see §D.)** |
| `keychain-wrap` | `server/src/core/master-custody.ts:385` | (literal) | AEAD key wrapping the master under the keychain custody key. **(scan-reconciled 2026-06-16; key-wrap; salt = `sanctuary-custody-v1`, see §D.)** |
| `castle-wall-safe-mode-audit-v1` | `server/src/castle-wall/boot/boot-token.ts:68` | `SAFE_MODE_AUDIT_INFO` | Derives the safe-mode audit key from the boot token (salt = undefined; see §D). **(scan-reconciled 2026-06-16; crypto-domain label.)** |

### C. Namespace strings (info to deriveNamespaceKey, salt = sanctuary-namespace-v1)

| Info string | Owner module | Constant name (if any) | Purpose |
|---|---|---|---|
| `sanctuary-fortress-mode-v1` | `server/src/fortress/config.ts:44` (constant defined at `fortress/constants.ts:156`) | `HKDF_FORTRESS_MODE_INFO` | Encrypts the fortress-mode config store. |
| `sanctuary-composition-v1` | `server/src/composition/constants.ts:149` | `HKDF_COMPOSITION_INFO` | Encrypts composition config and per-composition state. |
| `<arbitrary state-namespace name>` | `server/src/cognitive/state-store.ts:171` | (caller-supplied) | Per-namespace Cognitive-layer state encryption. The namespace name is the agent's namespace identifier. Underscore-prefixed namespaces (e.g. `_meta`, `_context_gate_policies`) are reserved for internal use. |

### D. Direct hkdf() callers (explicit salt + info)

These derivations bypass the high-level helpers because they need a salt other than `sanctuary-purpose-v1` / `sanctuary-namespace-v1`. Most use `fortress_id` as the salt so the derivation is bound to a specific fortress.

| Salt | Info | Owner module | Purpose |
|---|---|---|---|
| undefined (passphrase context) | `sanctuary-passphrase-v1` | `server/src/wrap/passphrase.ts:656` | Derives the 32-byte machine-bound key for the no-OS-keyring fallback file from local machine identity material; it does not use Argon2id or passphrase input and is not the passphrase master key. |
| `fortress_id` | `sanctuary-fed-v0.1-transport` `\|\| node_id \|\| node_mode` | `server/src/mesh/trust-root.ts:362` | Per-node transport subkey for federation v0.1. |
| `fortress_id` | `sanctuary-fed-v0.1-audit-chain` `\|\| node_id` | `server/src/mesh/trust-root.ts:388` | Per-node audit-chain subkey for federation v0.1. |
| `fortress_id` | `sanctuary-fed-v0.1-lifecycle-agent-state-transfer` | `server/src/mesh/lifecycle/sync.ts:122` | Sync-envelope encryption for agent-state transfer between mesh nodes. |
| `fortress_id` | `sanctuary-fed-v0.1-lifecycle-node-key-wrap` | `server/src/mesh/lifecycle/node-key-binding.ts:55` | AES-256-GCM wrap of per-node Ed25519 keys (mantle binding). |
| `fortress_id` | `sanctuary-agent-contract-v0.1` `\|\| <agent_subkey_id>` | `server/src/agent-contract/identity-bind.ts:55,79` | Per-agent identity-binding subkeys. |
| `fortress_id` | `sanctuary-composition-v1.0-sidecar-signing-key` | `server/src/composition/sidecar-signing-key.ts:77` | Composition sidecar's Ed25519 signing keypair. See `composition/constants.ts:HKDF_COMPOSITION_SIDECAR_SIGNING_INFO`. |
| `fortress_id` | `sanctuary-recovery-flows-v0.1-master-rotation-bundle` `\|\| <bundle_id>` | `server/src/mesh/recovery-flows/secret-bundle.ts:78` | Recovery-flow master-rotation bundle wrap. |
| `sanctuary-custody-v1` (`CUSTODY_HKDF_SALT`) | `recovery-key-wrap` | `server/src/core/master-custody.ts:166,370` | AEAD key wrapping the master under the recovery key. **(scan-reconciled 2026-06-16.)** |
| `sanctuary-custody-v1` (`CUSTODY_HKDF_SALT`) | `keychain-wrap` | `server/src/core/master-custody.ts:166,385` | AEAD key wrapping the master under the keychain custody key. **(scan-reconciled 2026-06-16.)** |
| undefined (boot-token context) | `castle-wall-safe-mode-audit-v1` | `server/src/castle-wall/boot/boot-token.ts:68,175` | Derives the safe-mode audit key from the boot token (not a fortress-master derivation). **(scan-reconciled 2026-06-16.)** |

### E. Domain-separation strings used elsewhere (not strictly HKDF info, but co-located by convention)

These strings serve the same domain-separation purpose as HKDF info but appear in non-HKDF contexts (Fiat-Shamir transcript labels, signature challenge tags). Listed here so a future audit pass can see the full domain-separation surface:

| String | Use site | Purpose |
|---|---|---|
| `sanctuary-pedersen-generator-H-v1-a` / `sanctuary-pedersen-generator-H-v1-b` | `server/src/disclosure/zk-proofs.ts:42-43` | Hash-to-curve seed strings for the Pedersen second generator. |
| `sanctuary-zk-pok-v1` | `server/src/disclosure/zk-proofs.ts:247,277` | Fiat-Shamir transcript label for proof-of-knowledge. |
| `sanctuary-zk-range-sum-v1` | `server/src/disclosure/zk-proofs.ts:361,418` | Fiat-Shamir transcript label for range-sum proof. |
| `sanctuary-zk-bit-v1` | `server/src/disclosure/zk-proofs.ts:462,492,529` | Fiat-Shamir transcript label for bit-decomposition proof. |
| `sanctuary-sign-challenge-v1` | `server/src/sanctuary-tools.ts:563` | Domain-separation prefix for signed challenges. |
| `key-17:x402-signer:v1` | `server/src/key-17/x402-signer.ts:61` (direct `hkdf()` info) | Derives the x402 payment-signer key. The `key-17` folder token is embedded in the label, so the folder must NEVER be renamed without a crypto migration. **(scan-reconciled 2026-06-16.)** |
| `key-17:erc8004-identity:v1` | `server/src/key-17/erc8004-identity-signer.ts:58` (direct `hkdf()` info) | Derives the ERC-8004 identity-signer key. Folder token embedded. **(scan-reconciled 2026-06-16.)** |
| `key-17:ap2-mandate:v1` | `server/src/key-17/ap2-mandate-signer.ts:62` (direct `hkdf()` info) | Derives the AP2 mandate-signer key. Folder token embedded. **(scan-reconciled 2026-06-16.)** |
| `sanctuary.v1.session-token` | `server/src/v1/session-service.ts:63` (`TOKEN_AAD`) | AES-256-GCM additional authenticated data binding v1 session tokens to their domain (not an HKDF info string; co-located here per convention). **(scan-reconciled 2026-06-16.)** |
| `sanctuary.federation.guardian-requirement.established.v1` | `server/src/v1/federation-sync-state-store.ts` (`FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_MAC_DOMAIN`); re-derived under rotation in `core/master-rotation.ts` | MAC-domain string (NOT an HKDF label) for the guardian **established sentinel** (`_meta/federation-guardian-requirement-established-v1`). The MAC is `HMAC(derivePurposeKey(master, "federation-sync-state"), DOMAIN)` over this fixed string. No new key material; domain-separated from the anchor MAC below. **(F1 re-gate 2026-07-05; MAC-crypto-domain.)** |
| `sanctuary.federation.guardian-antirollback-anchor.v1\n` | `server/src/v1/federation-sync-state-store.ts` (`FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_MAC_DOMAIN`); restamped under rotation in `core/master-rotation.ts` | MAC-domain string (NOT an HKDF label) for the guardian **anti-rollback anchor** (`_meta/federation-guardian-antirollback-anchor-v1`). The MAC is `HMAC(derivePurposeKey(master, "federation-sync-state"), DOMAIN + canonicalJson(data))`, mirroring the `custody-epoch-witness` shape. No new key material; the trailing `\n` matches the epoch-witness/rollback-freeze domain convention. **(F1 re-gate 2026-07-05; MAC-crypto-domain.)** |

## Adding a new info string

1. Pick a name that is **collision-free against this registry**. Convention: `<purpose-or-area>-v<spec-version>` (e.g. `l5-foo-v1`, `sanctuary-feature-v2`).
2. Define the constant in the owning module's `constants.ts`. Avoid bare literals at use-sites; use the constant.
3. Add a row to the appropriate section above (B for purpose, C for namespace, D for direct `hkdf()`, E for non-HKDF domain separation).
4. If the new string lives in a federation-protocol context, also update the federation spec §10 reservations as needed.

## Crypto-agility migration note

The v1.5+ Crypto Agility Sprint will replace HKDF-SHA256 with a post-quantum-aware KDF (likely HKDF-SHA3-256 or KMAC-256, pending CFRG guidance at that time). When that sprint runs, **every info string in this registry MUST be rotated to a v2 variant** (`sanctuary-fed-v0.2-transport`, `sanctuary-composition-v2-sidecar-signing-key`, etc.) so the v1.x derivations remain reproducible from preserved historical-master pubkeys and the v2 derivations live in a non-overlapping domain. Audit-chain continuity (federation spec §9.5) requires that v1.x verification still works post-migration; isolating the namespaces is how that works.
