# SECURITY_AUDIT.md — Sanctuary & Concordia Security Audit

**Audit Date:** 2026-03-28
**Auditor Posture:** Adversarial — assumes motivated attacker with full REVIEW_MAP.md and CLAUDE.md knowledge
**Scope:** Sanctuary v0.3.0 (TypeScript, ~10,400 LoC) + Concordia v0.1.0-draft (Python, ~5,000 LoC)
**Input Documents:** CLAUDE.md, REVIEW_MAP.md, full source code inspection of files listed in APPENDIX B of REVIEW_MAP.md

---

## DOMAIN 1: INJECTION AND INPUT HANDLING

---

### SEC-001 — Secure Deletion Is Tier 3 (Auto-Allow): Agent Can Irreversibly Destroy All User State Without Confirmation

**Severity:** Critical
**File:** `server/src/principal-policy/loader.ts:49`, `server/src/storage/filesystem.ts:69-102`
**Description:** The default Principal Policy places `state_delete` in Tier 3 (auto-allow, line 49 of loader.ts). The `state_delete` tool accepts a `secure_delete: true` parameter that triggers 3-pass random overwrite before unlinking (filesystem.ts:77-87). This is an irreversible operation — overwritten data cannot be recovered. Despite this, it requires zero human approval under the default policy.
**Attack Scenario:** A compromised or prompt-injected agent iterates through `state_list` (also Tier 3) to enumerate all namespaces and keys, then calls `state_delete` with `secure_delete: true` on every entry. The user loses all encrypted state, identities, commitments, reputation, and audit history with no confirmation gate. The Tier 2 frequency spike detector might fire after several calls, but by that time significant data is already destroyed. If the attacker batches deletions within the first session (where Tier 2 only checks operations not in the Tier 3 list), no anomaly is detected at all.
**Sovereignty Violation:** Directly contradicts CLAUDE.md §"WHAT THESE TOOLS MUST NEVER DO" #3: "Never execute an irreversible operation without a confirmation gate." Also contradicts §"SOVEREIGNTY PROPERTIES" #3: "A user can delete any piece of stored state, including secure 3-pass overwrite" — the property assumes user agency, but the default policy allows the agent to do it unilaterally.

---

### SEC-002 — Webhook Auto-Approve on Timeout Is Configurable and Inverts the Security Model

**Severity:** Critical
**File:** `server/src/principal-policy/webhook.ts:176-183`, `server/src/principal-policy/dashboard.ts:181-184`
**Description:** Both the webhook and dashboard approval channels accept an `auto_deny` boolean (default `true`). When set to `false`, any Tier 1 or Tier 2 operation that times out is auto-approved rather than denied. This applies to the most sensitive operations: `state_export`, `state_import`, `identity_rotate`, `reputation_import`. The `auto_deny: false` setting effectively converts the approval gate from a security barrier into an advisory log.
**Attack Scenario:** An attacker who compromises the webhook endpoint (or a misconfigured deployment where `auto_deny: false` is set in the YAML policy) can cause all approval requests to time out by making the webhook/dashboard unreachable (DoS on the callback, network partition). Every Tier 1 operation then auto-approves. The agent can export all state, import forged state bundles, and rotate identity keys without any human ever seeing the request.
**Sovereignty Violation:** Contradicts CLAUDE.md §"WHAT THESE TOOLS MUST NEVER DO" #5: "Never silently degrade to a less-secure behavior on error" and #3: "Never execute an irreversible operation without a confirmation gate." When the approval channel fails with `auto_deny: false`, the system silently upgrades the agent's permissions.

---

### SEC-003 — Canonical JSON Serialization Divergence Between TypeScript and Python

**Severity:** High
**File:** `server/src/bridge/bridge.ts:53-73` (stableStringify), `concordia/signing.py:70-80` (canonical_json)
**Description:** Sanctuary and Concordia independently implement canonical JSON serialization in different languages. The TypeScript version (`stableStringify`) maps `undefined` to `"null"`, uses `JSON.stringify(value)` for numbers and strings (which inherits V8's float-to-string algorithm), and does not call `ensure_ascii`. The Python version uses `json.dumps` with `ensure_ascii=False` and `separators=(",",":")`, rejects `-0.0`, and uses Python's float formatting. These are different implementations of the same semantic contract, but they will diverge on edge cases: floating-point values like `1e20` vs `1e+20` (V8 produces `100000000000000000000`, Python produces `1e+20` for `1e20`; but for `1.0` Python produces `1.0` while JSON.stringify produces `1`). Unicode handling also differs: Python with `ensure_ascii=False` emits raw Unicode codepoints, while V8's `JSON.stringify` escapes some Unicode characters by default.
**Attack Scenario:** An attacker crafts a ConcordiaOutcome with terms containing a floating-point value that serializes differently in Python and TypeScript (e.g., a very large number, or a value where Python uses scientific notation and V8 does not). The Concordia bridge builds a commitment payload with its `canonical_json()`, and the Sanctuary bridge verifies with its `stableStringify()`. The hash mismatches, causing legitimate bridge verifications to fail. More dangerously, if an attacker finds a collision class where two different inputs produce the same hash under one serialization but different hashes under the other, they can forge bridge commitments. This is the highest-risk interop surface as stated in CLAUDE.md §"KNOWN COMPLEXITY AND RISK AREAS" #1.

---

### SEC-004 — Schema Validation Does Not Recurse Into Nested Objects

**Severity:** Medium
**File:** `server/src/router.ts:70-128`
**Description:** The `validateArgs()` function checks types and sizes at the top level only. For `type: "object"` fields, it checks that the value is an object but does not recurse into the object's `properties` schema (lines 156-159 check type but do not validate inner structure). This means the `terms` argument to `bridge_commit` (declared as `type: "object"`) accepts any nested structure without validation — including deeply nested objects, circular-reference-like structures (if JSON parsing creates them), or objects with millions of keys.
**Attack Scenario:** An agent sends a `bridge_commit` call with a `terms` object containing deeply nested structures or an extremely large number of keys. The `stableStringify` function (bridge.ts:53-73) recursively traverses and sorts all keys. A terms object with 100,000 nested keys would cause significant CPU/memory load during canonical serialization, resulting in denial of service. Size caps only apply to string values (MAX_STRING_BYTES), not to object depth or key count.

---

### SEC-005 — Import Does Not Verify Ed25519 Signatures on Imported State Entries

**Severity:** High
**File:** `server/src/l1-cognitive/state-store.ts:518-598`
**Description:** The `import()` method accepts a base64-encoded bundle, parses it, and writes each `StateEntry` directly to storage without verifying the Ed25519 signature (`sig` field) or the identity reference (`kid` field) on each entry. The import skips reserved namespaces (line 541-546, good), but for all user namespaces, it writes whatever is in the bundle. An entry with a forged signature, a non-existent `kid`, or a `sig` that doesn't match the entry content is accepted and stored.
**Attack Scenario:** An attacker creates a crafted export bundle with entries whose `kid` references a legitimate identity but whose `sig` is forged (e.g., signed by a different key). After import (which requires Tier 1 approval — so this requires social engineering the human approver), the attacker's data is indistinguishable from legitimately-created data. Subsequent `state_read` calls return these entries with signatures that will fail verification if checked, but the state store does not enforce signature verification on read.
**Note:** This is partially mitigated by Tier 1 gating on `state_import`, but the CLAUDE.md security invariant states: "Never assume trust across the Sanctuary-Concordia boundary" — the same principle should apply to import bundles. A human approving an import has no way to verify the cryptographic integrity of the bundle's contents.

---

### SEC-006 — bridge_commit Signing Payload Uses Non-Canonical JSON.stringify

**Severity:** Medium
**File:** `server/src/bridge/bridge.ts:131`
**Description:** When creating the bridge commitment, the signing payload is serialized with `JSON.stringify(commitmentPayload)` at line 131 — NOT with `stableStringify()`. The commitment hash itself uses `canonicalize()` → `stableStringify()` over the outcome, but the Ed25519 signature covers a separate `commitmentPayload` object that is serialized with vanilla `JSON.stringify`. While V8's `JSON.stringify` produces deterministic key order for simple objects created with literal syntax, this is not guaranteed by the ECMAScript specification for all engines or cases. The verification side (bridge.ts:189) uses the same `JSON.stringify` pattern, so verification and signing are at least consistent within Sanctuary, but the payload is not canonically serialized.
**Attack Scenario:** If a future JavaScript engine or a port to a different runtime changes property enumeration order, signatures created on one engine will not verify on another. This is a latent portability defect rather than an immediately exploitable vulnerability, but it violates the canonical serialization principle that the bridge architecture is built on.

---

## DOMAIN 2: AUTHENTICATION AND AUTHORIZATION

---

### SEC-007 — Concordia Has Zero Caller Authentication: Any MCP Client Can Impersonate Any Agent

**Severity:** Critical
**File:** `concordia/mcp_server.py` (entire file — 46 tools, none with auth checks)
**Description:** Concordia has no authentication mechanism at any layer. Every MCP tool accepts an `agent_id`, `role`, `initiator_id`, `responder_id`, or `from_agent` parameter as a plain string, and that string is trusted as the caller's identity. There is no token, signature, or challenge-response to verify that the MCP client actually represents the claimed agent. The `role` parameter in negotiation tools (e.g., `concordia_propose` at line ~380) is resolved by string matching ("initiator"/"responder") with no verification that the caller is authorized to act in that role.
**Attack Scenario:** A single MCP client connects to Concordia and: (1) opens a session between two fabricated agent IDs, (2) drives both sides of the negotiation to agreement, (3) generates an attestation, (4) ingests the attestation into the reputation store. The system creates valid Ed25519-signed messages for both sides because it generates key pairs server-side for each session. The result is a legitimate-looking attestation with real cryptographic signatures, manufactured entirely by one attacker. While the Sybil detector catches some patterns (suspiciously fast sessions), it does not reject them — it only flags them with warnings.

---

### SEC-008 — Concordia Agent Deregistration Has No Ownership Verification

**Severity:** High
**File:** `concordia/mcp_server.py:994-1004`, `concordia/registry.py:257-259`
**Description:** The `concordia_deregister_agent` tool accepts an `agent_id` parameter and removes the agent from the discovery registry with no verification that the caller owns or controls that agent_id. The registry's `deregister()` method at registry.py:257-259 simply pops the entry.
**Attack Scenario:** Attacker calls `concordia_deregister_agent` with a competitor's `agent_id`. The competitor is removed from discovery, preventing them from being found via `concordia_search_agents`. Since registration includes capability declarations and the Concordia Preferred badge, deregistration silently removes the competitor's market presence. Re-registration requires knowing the original configuration.

---

### SEC-009 — Concordia Relay: Any Agent Can Read Any Other Agent's Messages

**Severity:** High
**File:** `concordia/mcp_server.py:1572-1587` (tool_relay_receive), `concordia/relay.py:389-399`
**Description:** The `concordia_relay_receive` tool accepts an `agent_id` parameter and returns all queued messages for that agent. There is no verification that the caller is the claimed agent. The relay's `receive_messages` method marks messages as delivered upon retrieval, so the legitimate agent will never see them.
**Attack Scenario:** Attacker polls `concordia_relay_receive` with a target agent's ID. All messages intended for that agent are dequeued and delivered to the attacker. The target agent, polling later, finds an empty mailbox. The attacker can read negotiation offers, counteroffers, signals, and constraints — all the information asymmetry that negotiation protocols are designed to protect. Messages are marked as `DELIVERED` to the attacker, and the legitimate recipient sees nothing.

---

### SEC-010 — Concordia Session State Machine Does Not Verify Message Signatures

**Severity:** High
**File:** `concordia/session.py:115-155`
**Description:** The `apply_message()` method validates the state transition (line 129) and tracks behavioral signals (line 145), but never calls `verify_signature()` from `signing.py`. Message signatures are generated during `build_envelope()` in `message.py:83`, but they are never checked when the message is applied to the session. The `verify_signature()` function exists in `signing.py:95-108` but is not called anywhere in the session lifecycle.
**Attack Scenario:** An attacker who gains access to the MCP transport can inject messages with invalid or absent signatures into active sessions. The session state machine will accept them, advance state, and record them in the transcript. Since the hash chain is computed over the message content (including the signature field), a forged signature becomes part of the permanent transcript hash. The `validate_chain()` function at `message.py:88-105` only checks `prev_hash` chaining, not signature validity.

---

### SEC-011 — Sanctuary Gate Default for Unlisted Operations Is Tier 3 (Allow)

**Severity:** Medium
**File:** `server/src/principal-policy/gate.ts:72-83`, `server/src/principal-policy/loader.ts:35-85`
**Description:** If a new tool is registered that is not listed in `tier1_always_approve` or `tier3_always_allow`, the gate defaults to Tier 3 (allow with audit logging) at gate.ts:72-83. The first-session check (gate.ts:96-104) only triggers for operations not in the `tier3_always_allow` list, which is effectively a whitelist. But new tools added via code changes that are not added to any tier list will auto-allow.
**Attack Scenario:** A developer adds a new sensitive tool (e.g., `identity_delete`) and registers it in the MCP server but forgets to add it to `tier1_always_approve` in the policy. The tool auto-allows without any human approval. This is a defense-in-depth concern: the safe default should be deny, not allow.

---

### SEC-012 — Dashboard Authentication Token Passed in Query String

**Severity:** Medium
**File:** `server/src/principal-policy/dashboard.ts:237-240`
**Description:** The dashboard accepts the auth token via `?token=<TOKEN>` query parameter (line 238-240) in addition to the `Authorization: Bearer` header. Query parameters are logged by web servers, proxies, and browser history. The SSE EventSource API does not support custom headers, which is why the query parameter exists, but this means the auth token appears in URLs.
**Attack Scenario:** A proxy between the user's browser and the dashboard server logs the URL with the token in the query string. An attacker who reads the proxy logs obtains the token and can approve or deny any Tier 1 or Tier 2 operation — including state export, identity rotation, and reputation import. This is the highest-privilege credential in the system (it can approve irreversible operations) and it's exposed in URL logs.

---

### SEC-013 — Webhook Callback Server Has Wildcard CORS

**Severity:** Medium
**File:** `server/src/principal-policy/webhook.ts:251`
**Description:** The webhook callback server sets `Access-Control-Allow-Origin: *` at line 251. While the dashboard server correctly restricts CORS to the self-origin (dashboard.ts:258-259), the webhook callback allows cross-origin requests from any domain.
**Attack Scenario:** If the webhook callback server is bound to a non-localhost address (configurable via `callback_host`), a malicious website can make cross-origin POST requests to the callback endpoint. Combined with knowledge of a pending request ID (which is 8 random hex bytes = 32 bits of entropy), an attacker could brute-force approval of pending Tier 1 operations. The HMAC signature requirement mitigates this significantly, but the CORS misconfiguration widens the attack surface unnecessarily.

---

### SEC-014 — Concordia Attestation Signature Verification Is Optional

**Severity:** High
**File:** `concordia/reputation/store.py:163-175`, `concordia/reputation/store.py:329-356`
**Description:** The `ingest()` method accepts an optional `public_keys` parameter. When `public_keys` is `None` (the default when called from `tool_ingest_attestation` at mcp_server.py:740), signature verification is entirely skipped. The store only emits a warning (store.py:333-338). This means any well-formed attestation with syntactically valid (but cryptographically meaningless) base64 in the `signature` fields will be accepted and scored.
**Attack Scenario:** Attacker crafts attestation dicts with fake signatures for fabricated agents, submits them via `concordia_ingest_attestation`. The attestations pass schema validation (signatures are non-empty strings, which satisfies store.py:318-320), skip cryptographic verification (no `public_keys` provided), and are stored. The attacker can inflate or deflate any agent's reputation at will. The Sybil detector catches some patterns but does not reject, only flags.

---

### SEC-015 — Concordia Want/Have Registry Has No Identity Verification

**Severity:** Medium
**File:** `concordia/want_registry.py:399-433`, `concordia/mcp_server.py:1204-1445`
**Description:** The `post_want` and `post_have` functions accept an `agent_id` parameter without verification. Any caller can post wants and haves claiming to be any agent. There is no signature, token, or authentication binding the caller to the claimed agent_id.
**Attack Scenario:** Attacker floods the want registry with fake wants under a competitor's agent_id, poisoning their market profile. Or the attacker posts haves for capabilities they don't possess under their own agent_id, attracting negotiation partners who will waste time and resources.

---

## DOMAIN 3: DATA HANDLING AND SOVEREIGNTY VIOLATIONS

---

### SEC-016 — Stderr Approval Channel Auto-Resolves After 100ms Without Human Input

**Severity:** High
**File:** `server/src/principal-policy/approval-channel.ts:45-72`
**Description:** The default stderr approval channel displays a prompt and then auto-resolves after 100ms (line 57). With the default `auto_deny: true`, this means Tier 1 operations are auto-denied, which is safe. However, the channel never actually reads human input — it is purely informational. If a user changes `auto_deny: false` thinking they'll get a prompt, every Tier 1 operation silently auto-approves after 100ms. The comments at lines 50-56 acknowledge this is a limitation, but the current behavior means the stderr channel is not actually an interactive approval gate in any configuration.
**Attack Scenario:** User reads the policy YAML comment "How Sanctuary reaches you when approval is needed" and sets `auto_deny: false` expecting interactive prompts. All Tier 1 operations (export, import, rotate) now auto-approve in 100ms. The agent exports all state without human review.

---

### SEC-017 — Bridge Stores Full Concordia Outcome Including Deal Terms

**Severity:** Medium
**File:** `server/src/bridge/tools.ts:47-55`, `server/src/bridge/bridge.ts:92-144`
**Description:** The `bridgeStore.save()` method (tools.ts:48-55) persists both the `BridgeCommitment` and the full `ConcordiaOutcome` — which includes the `terms` object (the actual deal terms). This data is encrypted at rest, but it is stored on the Sanctuary side under the `_bridge` namespace. The CLAUDE.md states that Concordia attestations should "contain behavioral signals only — never raw deal terms" (§"WHAT THESE TOOLS MUST NEVER DO" #8), but the bridge stores the full terms in Sanctuary's encrypted state.
**Attack Scenario:** This is a design tension rather than an exploit. The bridge needs the original terms for verification (`bridge_verify` recomputes the hash from the terms). But it means that a Sanctuary `state_export` (Tier 1 but approvable) would export the full deal terms alongside the bridge commitment, potentially violating the Concordia privacy expectation. The terms are encrypted at rest, but they exist in plaintext in the export bundle.

---

### SEC-018 — Audit Log Entries Contain Operation Arguments Summary

**Severity:** Low
**File:** `server/src/principal-policy/gate.ts:60-63`
**Description:** When a Tier 1 operation triggers approval, the gate calls `summarizeArgs()` which truncates strings to 100 characters but passes through all other argument types (including objects, numbers, arrays) verbatim. These are included in the audit log entry. While the audit log is encrypted at rest, the argument summaries could include sensitive data (namespace names indicating what an agent is storing, counterparty DIDs, etc.).
**Attack Scenario:** An agent deliberately triggers Tier 1 operations with arguments crafted to include sensitive information, which then gets logged in the audit trail. If the audit log is later queried via `monitor_audit_log` (Tier 3, auto-allow), the sensitive data is exposed. Low severity because the audit log is encrypted and only readable through Sanctuary's own tools.

---

### SEC-019 — Config Silently Accepts Unimplemented Security Features

**Severity:** High
**File:** `server/src/config.ts` (see REVIEW_MAP.md §6.2)
**Description:** The configuration schema accepts `proof_system: "groth16" | "plonk"`, `key_protection: "hardware-key"`, and `environment: "tee"` — none of which are implemented. There is no runtime validation, no error, and no warning when these options are selected. The system silently falls back to weaker alternatives (commitment-only proofs, no hardware key, process-level isolation).
**Attack Scenario:** A security-conscious deployer configures `proof_system: "groth16"` and `key_protection: "hardware-key"` believing they are enabling stronger protections. The system starts normally, the SHR (`monitor_health`) shows `proof_system: "groth16"` in the config, and the deployer believes they have SNARK-based ZK proofs and hardware-protected keys. In reality, all proofs use commitment-only schemes and the master key sits in process memory. The system misrepresents its own security posture.
**Sovereignty Violation:** Contradicts CLAUDE.md §"WHAT THESE TOOLS MUST NEVER DO" #5: "Never silently degrade to a less-secure behavior on error." Accepting an unimplemented option and silently using a weaker one is exactly this.

---

### SEC-020 — Recovery Key Path Regenerates Master Key on Every Restart

**Severity:** High
**File:** `server/src/index.ts:98-124`
**Description:** When no passphrase is provided and an existing `recovery-key-hash` exists in `_meta`, the code at line 108 generates a new random master key instead of prompting for the recovery key. The comment at line 107 says "TODO: prompt for recovery key on subsequent runs." This means every restart without a passphrase generates a new master key, rendering all previously encrypted data unreadable. The old data remains on disk but is encrypted with a key that no longer exists.
**Attack Scenario:** A user sets up Sanctuary without a passphrase (using recovery key mode), stores data, then restarts the server. All previously stored state — identities, commitments, reputation, audit logs — is irreversibly lost because the new master key cannot decrypt data encrypted with the old key. The system does not warn the user. The recovery key displayed at first run is the only way to recover the data, but the code doesn't use it on subsequent runs.

---

### SEC-021 — Concordia MCP Server Exposes Private Key Bytes via KeyPair Methods

**Severity:** Medium
**File:** `concordia/signing.py:48-52`
**Description:** The `KeyPair.private_key_bytes()` method returns raw Ed25519 private key bytes. While this method is not directly exposed via an MCP tool, the `SessionContext` dataclass (mcp_server.py:124-134) holds `initiator_key` and `responder_key` as `KeyPair` objects. Any tool handler that serializes a `SessionContext` or its components carelessly could leak private keys. Currently, the tool handlers manually select which fields to return, but there is no defense-in-depth mechanism preventing a future tool from calling `ctx.initiator_key.private_key_bytes()` or `json.dumps(ctx, default=vars)`.
**Attack Scenario:** A developer adds a debug tool or modifies `tool_session_status` to return the full session context. The private keys for both negotiation parties are leaked to the MCP client. This would allow forging signatures for either party.

---

## DOMAIN 4: DEPENDENCY AND SUPPLY CHAIN

---

### SEC-022 — Concordia Has No Lockfile: All Dependencies Are Unpinned

**Severity:** High
**File:** `concordia/pyproject.toml`
**Description:** Concordia declares minimum-version-only constraints (`cryptography>=42.0`, `jsonschema>=4.20`, `mcp>=1.0`) with no lockfile (no `requirements.txt`, `poetry.lock`, or `uv.lock`). This means builds are non-reproducible: `pip install` on different dates or environments may resolve to different versions. The `cryptography` library is the Ed25519 implementation — a version change could alter behavior, and a compromised future version would be automatically installed.
**Attack Scenario:** A supply-chain attacker publishes a malicious version of `cryptography` (e.g., `43.0.0`) that backdoors Ed25519 key generation. Any new installation of Concordia automatically picks up the compromised version because the constraint `>=42.0` accepts it. Unlike Sanctuary (which has a `package-lock.json`), Concordia has no defense against this.

---

### SEC-023 — hash-wasm WASM Binary Is Opaque

**Severity:** Low
**File:** `server/src/core/key-derivation.ts` (imports from hash-wasm)
**Description:** The Argon2id implementation used for master key derivation comes from `hash-wasm`, which includes a pre-compiled WASM binary. The WASM binary cannot be audited from TypeScript source alone — it must be verified against the upstream C source and build reproducibility must be confirmed. The `hash-wasm` package has zero dependencies itself, which is good, but the WASM blob is a trust-on-first-use artifact.
**Attack Scenario:** A compromised `hash-wasm` version could weaken the Argon2id parameters (reducing memory/iteration counts silently), derive a predictable key from the passphrase, or exfiltrate the passphrase. This is a standard supply-chain concern for WASM-based crypto and is listed for completeness. Mitigated by the package-lock.json pinning to version 4.12.0.

---

### SEC-024 — Noble Crypto Libraries Use Caret Ranges

**Severity:** Low
**File:** `server/package.json`
**Description:** The `@noble/ciphers`, `@noble/curves`, and `@noble/hashes` packages use caret ranges (`^2.1.1`, `^1.8.0`, `^1.7.0`). While `package-lock.json` pins exact versions, running `npm update` or deleting the lockfile would pull newer minor/patch versions. The noble libraries are well-audited (by Trail of Bits and others) and have zero transitive dependencies, but caret ranges create a theoretical auto-upgrade vector.
**Attack Scenario:** A compromised npm account pushes a patch version (e.g., `@noble/ciphers@2.1.2`) with a subtle AES-GCM weakness. A developer running `npm update` pulls it in. The lockfile is the primary defense; this finding is defense-in-depth.

---

## SUMMARY: HIGHEST-RISK AREAS

The highest concentration of exploitable vulnerabilities is in **Concordia's complete absence of caller authentication** (SEC-007, SEC-008, SEC-009, SEC-014, SEC-015). Any MCP client can impersonate any agent, read any agent's messages, deregister other agents, and inject fake reputation attestations. These are not theoretical — they require no special access beyond a standard MCP connection. The Sybil detector is the only defense, and it flags rather than blocks.

On the Sanctuary side, the two critical findings are **SEC-001** (secure deletion without confirmation gate) and **SEC-002** (webhook auto-approve inverts the security model). SEC-001 is immediately exploitable by any agent using the default policy. SEC-020 (recovery key path silently regenerates master key) is a data-loss time bomb for any deployment not using passphrases.

The **cross-codebase canonical serialization divergence** (SEC-003) is a correctness landmine that will surface unpredictably when real-world negotiation terms contain floating-point values or non-ASCII characters.

**SEC-019** (silent acceptance of unimplemented features) is particularly insidious because it causes the system to misrepresent its own security posture — a deployer who believes they have hardware key protection and ZK proofs has neither.

For the QA engineer reading this next: focus first on SEC-001 (can be tested with a script that calls state_list then state_delete in a loop), SEC-007 (connect two MCP clients to the same Concordia server and demonstrate cross-agent impersonation), and SEC-020 (start Sanctuary without a passphrase, write data, restart, observe data loss). These three are the highest-severity, lowest-effort-to-verify findings.
