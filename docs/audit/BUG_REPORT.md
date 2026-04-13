# BUG_REPORT.md — Functional Bug Sweep

**Date:** 2026-03-28
**Scope:** Sanctuary v0.3.0 (TypeScript) + Concordia v0.1.0-draft (Python)
**Posture:** QA functional sweep — logic errors, broken features, state corruption, failure modes
**Exclusions:** Security vulnerabilities logged in SECURITY_AUDIT.md (SEC-001 through SEC-024) are not duplicated here

---

## SWEEP 1: CORE USER PATHS

---

### BUG-001 — state_export() Returns Empty Bundle on Fresh Server Session

**Severity:** Blocking
**File:** `server/src/l1-cognitive/state-store.ts:461-470`
**Description:** The `export()` method discovers namespaces by iterating `this.contentHashes.keys()`, which is a lazily-populated in-memory cache. The cache is populated only when `state_read()`, `state_write()`, or `state_list()` operations are performed. On a fresh server session — where the user starts the server, stores data in a previous session, and then calls `state_export` without first touching any state — the cache is empty and the export returns a bundle with zero namespaces. The actual encrypted data remains on disk but is invisible to the export function.

**Reproduction:**
1. Start Sanctuary server with a passphrase, write several state entries across multiple namespaces, stop the server.
2. Restart the server with the same passphrase.
3. Immediately call `state_export` without calling `state_read` or `state_list` first.
4. Receive an export bundle containing zero entries.
5. User believes they have a complete backup, but the bundle is empty.

**Sovereignty violation:** Contradicts Property #2: "A user can retrieve a complete export of all data the system holds about them."

---

### BUG-002 — state_import() Creates Version Cache Staleness Leading to Monotonicity Violation

**Severity:** Major
**File:** `server/src/l1-cognitive/state-store.ts:558-569`
**Description:** When `import()` skips entries due to version conflict (using `conflictResolution="version"`), the in-memory version cache is not updated with the skipped entry's version. Subsequent `state_write()` calls use the stale cache value to determine the next version number, potentially producing a version lower than what exists on disk. This violates the monotonic version invariant that rollback detection depends on.

**Reproduction:**
1. Write entry `ns/key` with version 5 on disk.
2. Import a bundle containing `ns/key` at version 4 with `conflictResolution="version"` — entry is correctly skipped (disk version is higher).
3. The version cache for `ns/key` still holds the pre-import stale value (e.g., version 2 from a previous read).
4. Call `state_write("ns", "key", "new-value")` — the write increments the cache value (2 → 3), producing version 3 on disk.
5. Disk now has version 3 overwriting version 5 — monotonicity violated.

---

## SWEEP 2: BOUNDARY CONDITIONS

---

### BUG-003 — Concordia Session apply_message Crashes on Invalid Message Type

**Severity:** Blocking
**File:** `concordia/session.py:124`
**Description:** The `apply_message()` method converts `message["type"]` directly to a `MessageType` enum via `MessageType(message["type"])` with no prior validation. If the message contains an invalid type string (e.g., `"invalid.type"`), Python raises a raw `ValueError` with no contextual information. The error is not caught and propagates as an unhandled exception, which will crash the MCP tool handler or return an opaque error to the agent.

**Reproduction:**
1. Create an active Concordia session.
2. Call `concordia_send_message` (or directly invoke `apply_message`) with `{"type": "invalid.type", "content": {}}`.
3. Receive: `ValueError: 'invalid.type' is not a valid MessageType`.
4. The error provides no session context, no suggestion, and no recovery path.

**Fix:** Validate before conversion: `if message["type"] not in [mt.value for mt in MessageType]: raise InvalidTransitionError(...)`.

---

### BUG-004 — Relay Capacity Checks Use >= Instead of >, Reducing Effective Capacity by One

**Severity:** Minor
**File:** `concordia/relay.py:349, 378, 240, 499`
**Description:** All capacity limit checks in the relay module use `>=` rather than `>`:
- Line 240: `if len(self._sessions) >= self.MAX_SESSIONS` (max 10,000)
- Line 349: `if len(session.transcript) >= self.MAX_TRANSCRIPT_SIZE` (max 10,000)
- Line 378: `if len(mailbox) >= self.MAX_MAILBOX_SIZE` (max 1,000)
- Line 499: `if len(self._archives) >= self.MAX_ARCHIVES` (max 50,000)

This means the actual capacity is one less than the named constant in each case (e.g., 9,999 transcript messages instead of 10,000). While functional, the constants are misleading, and users relying on the documented capacity will hit the limit one item early.

**Reproduction:**
1. Create a relay session and send exactly 9,999 messages.
2. Send the 10,000th message — rejected with "Transcript full."
3. Expected: 10,000 messages allowed per `MAX_TRANSCRIPT_SIZE = 10_000`.

---

## SWEEP 3: THE OVERLAP SURFACE (BRIDGE)

---

### BUG-005 — Bridge Payload Shape Mismatch: Concordia Produces Generic Proof Payload, Sanctuary Expects ConcordiaOutcome

**Severity:** Blocking
**File:** `concordia/sanctuary_bridge.py:82-127`, `server/src/bridge/tools.ts:115-172`
**Description:** Concordia's `build_commitment_payload()` produces a generic proof commitment payload shaped for Sanctuary's `proof_commitment` tool: `{"tool": "sanctuary/proof_commitment", "arguments": {"value": "..."}}`. However, Sanctuary's `bridge_commit` tool expects a `ConcordiaOutcome`-shaped object with negotiation-specific fields: `session_id`, `terms`, `parties`, `rounds`, `proposer_did`, `acceptor_did`. These are entirely incompatible schemas. The bridge cannot function as designed — forwarding Concordia's output to Sanctuary's `bridge_commit` will fail schema validation.

**Reproduction:**
1. Complete a Concordia negotiation to AGREED state.
2. Call `concordia_sanctuary_bridge_commit` to generate the bridge payload.
3. Forward the returned payload to Sanctuary's `bridge_commit` tool.
4. Sanctuary rejects the payload: missing required fields `proposer_did`, `acceptor_did`, `rounds`, etc.

**Impact:** The bridge integration path is non-functional end-to-end.

---

### BUG-006 — Bridge Requires proposer_did / acceptor_did That Concordia Cannot Provide

**Severity:** Blocking
**File:** `server/src/bridge/tools.ts:126-132`
**Description:** Sanctuary's `bridge_commit` tool schema declares `proposer_did` and `acceptor_did` as required string fields. Concordia's agent model uses opaque `agent_id` strings (e.g., `"agent-alice"`), not DIDs. There is no mapping mechanism, no DID generation in Concordia, and no way for the bridge payload builder to populate these fields. The bridge cannot work without manual DID assignment by the client, which is undocumented.

**Reproduction:** Inspect `bridge/tools.ts` lines 126-132 for required schema fields. Inspect `concordia/sanctuary_bridge.py` — no DID-related fields are generated.

---

### BUG-007 — Unicode Escaping Divergence Between stableStringify (TS) and canonical_json (Python)

**Severity:** Major
**File:** `server/src/bridge/bridge.ts:53-73`, `concordia/signing.py:70-80`
**Description:** TypeScript's `JSON.stringify()` escapes non-ASCII characters as `\uXXXX` sequences by default (e.g., `"café"` → `"caf\u00e9"`). Python's `json.dumps(..., ensure_ascii=False)` preserves UTF-8 codepoints as literal bytes (e.g., `"café"` → `"café"`). When negotiation terms contain any non-ASCII text (agent names like "François", product descriptions in non-Latin scripts, currency symbols like "€"), the two serializers produce different byte strings, producing different SHA-256 hashes. This causes `bridge_verify` to fail with `terms_hash_match: false` on any Unicode-containing outcome.

**Reproduction:**
1. Negotiate terms containing `{"seller": "François"}` in Concordia.
2. Concordia computes `canonical_json(terms)` → `{"seller":"François"}` (UTF-8 bytes).
3. Forward to Sanctuary's `bridge_commit`. Sanctuary computes `stableStringify(terms)` → `{"seller":"Fran\u00e7ois"}`.
4. SHA-256 hashes differ. Bridge verification reports `terms_hash_match: false`.

---

### BUG-008 — Concordia Bridge Reads Wrong Field Name for Transcript Hash

**Severity:** Major
**File:** `concordia/mcp_server.py:1808`
**Description:** The bridge commit function reads `last_msg.get("previous_hash")` to extract the transcript hash, but the message envelope (defined in `message.py:69`) uses the field name `prev_hash`. This causes `transcript_hash` to always be `None` in every bridge commitment payload.

**Reproduction:**
1. Complete a Concordia negotiation to AGREED state.
2. Call `concordia_sanctuary_bridge_commit`.
3. Inspect the returned payload: `transcript_hash` is `None` (or missing).
4. Expected: the SHA-256 hash from the last message's `prev_hash` field.

**Fix:** Change `last_msg.get("previous_hash")` to `last_msg.get("prev_hash")` at line 1808.

---

## SWEEP 4: AGENT BEHAVIOR

---

### BUG-009 — Concordia Closed-Loop Sybil Detection Has Contradictory Condition — Can Never Trigger

**Severity:** Major
**File:** `concordia/reputation/store.py:83-84`
**Description:** The closed-loop Sybil detection check contains logically contradictory conditions:
```python
if (len(a_counterparties) > 2 and a_counterparties == {b}
        and len(b_counterparties) > 2 and b_counterparties == {a}):
    self.closed_loop = True
```
If `a_counterparties == {b}` (a set containing only element `b`), then `len(a_counterparties)` is 1, which is not `> 2`. The `len > 2` and `== {single_element}` conditions are mutually exclusive. The `closed_loop` flag can never be set to `True`, meaning this entire Sybil detection signal is dead code.

**Reproduction:**
1. Create 10 attestations showing agent A and agent B transacting exclusively with each other.
2. Ingest all attestations into the reputation store.
3. Query Sybil signals for any attestation: `closed_loop` is `False`.
4. Expected: `closed_loop` should be `True` for agents that only transact with each other.

**Fix:** Change `len(a_counterparties) > 2` to `len(a_counterparties) <= 1` (or similar logic that correctly detects exclusive trading pairs).

---

### BUG-010 — Audit Log Persistence Failure Silently Swallowed

**Severity:** Major
**File:** `server/src/l2-operational/audit-log.ts:58-61`
**Description:** The `persistEntry()` method's error handler is `.catch(() => {})` — a completely empty catch that swallows all errors silently. If the audit log's encryption or storage write fails (disk full, permission error, encryption failure), the gate still returns its decision, and the audit entry is lost. No warning is emitted, no metric is incremented, and no fallback is attempted. The caller has no indication that audit logging failed.

**Reproduction:**
1. Fill the filesystem hosting `~/.sanctuary/state/_audit/` to capacity.
2. Perform any Sanctuary tool call that triggers an audit log entry.
3. The tool call succeeds, but the audit entry is silently dropped.
4. Call `monitor_audit_log` — the failed entry is absent with no gap indication.

**Sovereignty violation:** Contradicts Property #12: "All gate decisions (approve, deny, auto-allow) are appended to the encrypted audit log." Also violates §"WHAT THESE TOOLS MUST NEVER DO" #5: "Never silently degrade to a less-secure behavior on error."

---

## SWEEP 5: SOVEREIGNTY-SPECIFIC FUNCTIONAL TESTS

---

### BUG-011 — state_export() Does Not Filter Reserved Namespaces

**Severity:** Major
**File:** `server/src/l1-cognitive/state-store.ts:452-513`
**Description:** When `export()` is called without a specific namespace argument, it iterates all namespaces discovered from the `contentHashes` cache. Unlike the tool-level handlers in `tools.ts` (which call `isReservedNamespace()` before operations), the `export()` method in `StateStore` does not filter reserved namespaces like `_identities`, `_audit`, `_commitments`, `_reputation`, `_principal`, etc. If these namespaces have been accessed during the session (populating the cache), they will be included in the export bundle. This means an export can contain encrypted identity keys, audit logs, and internal system state.

**Reproduction:**
1. Start Sanctuary server, create identities (populates `_identities` cache), write state, query audit log (populates `_audit` cache).
2. Call `state_export` without specifying a namespace.
3. Receive an export bundle containing `_identities`, `_audit`, and other reserved namespaces.
4. Expected: export should only include user-created namespaces, matching the namespace filtering applied to other state operations.

**Note:** The exported data is still AES-256-GCM encrypted, so the raw private keys are not exposed in plaintext. But the export bundle structure reveals reserved namespace names and entry counts, and the bundle can be imported into another instance with the same master key.

---

### BUG-012 — Range Proof Accepts Degenerate Range (min == max), Producing Trivially Valid Proof

**Severity:** Major
**File:** `server/src/l3-disclosure/zk-proofs.ts:308-320`
**Description:** The `createRangeProof()` function computes `numBits = Math.ceil(Math.log2(range + 1))` where `range = max - min`. When `min == max`, `range = 0`, `numBits = Math.ceil(Math.log2(1)) = 0`. The bit decomposition loop runs zero times, producing empty `bit_commitments` and `bit_proofs` arrays. The verifier (`verifyRangeProof`) checks that the array lengths match (0 == 0), that the reconstructed sum equals the shift (0 == 0), and returns `valid: true`. The proof proves nothing — it doesn't verify that the prover knows the value or that the value equals `min`.

**Reproduction:**
1. Create a Pedersen commitment to value 50 with a known blinding factor.
2. Call `zk_range_prove` with `value=50, min=50, max=50`.
3. Receive a proof with empty `bit_commitments: []` and `bit_proofs: []`.
4. Call `zk_range_verify` — returns `valid: true`.
5. Now call `zk_range_prove` with `value=99, min=50, max=50` — this should fail (99 is not in [50,50]) but the proof generation step at line 326 computes `shifted = value - min = 49`, then tries to decompose 49 into 0 bits, which silently produces an empty array. Verification still succeeds because both sides agree on 0 bits.

**Impact:** An agent can claim any value is in any single-point range and produce a "valid" proof.

---

### BUG-013 — Handshake Respond Allows Multiple Sessions for Same Challenge

**Severity:** Major
**File:** `server/src/handshake/tools.ts:108-141`
**Description:** The `handshake_respond` tool creates a new session for each invocation without checking whether a session already exists for the given challenge. An agent can call `handshake_respond` multiple times with the same challenge, creating multiple independent sessions with different nonces and session IDs. When the initiator completes the handshake with the first response, the additional sessions remain in an incomplete state indefinitely.

**Reproduction:**
1. Call `handshake_initiate` — receive `challenge` and `session_id_A`.
2. Call `handshake_respond` with `challenge` — receive `session_id_B` with `nonce_B`.
3. Call `handshake_respond` with the same `challenge` again — receive `session_id_C` with `nonce_C`.
4. Complete handshake with `session_id_A` and `nonce_B`.
5. `session_id_C` is now orphaned — incomplete, never cleaned up, consuming state.

**Impact:** Accumulated orphan sessions consume encrypted storage under `_handshake` namespace with no cleanup mechanism.

---

### BUG-014 — proof_reveal Does Not Mark Commitment as Revealed

**Severity:** Minor
**File:** `server/src/l3-disclosure/tools.ts:109-126`
**Description:** The `proof_reveal` tool calls `verifyCommitment()` and returns the result, but never calls the `markRevealed()` method on the commitment store. A commitment can be "revealed" (verified) unlimited times. The `revealed` field in the commitment record permanently remains `false`. There is no way for a verifier to distinguish a commitment that has been revealed from one that has not.

**Reproduction:**
1. Create a commitment via `proof_commitment` — receive `commitment_id`.
2. Reveal via `proof_reveal` with correct value and blinding factor — returns `valid: true`.
3. Query the commitment — `revealed` is still `false`.
4. Reveal again with the same parameters — returns `valid: true` again. No warning or idempotency guard.

---

### BUG-015 — SHR Sovereignty Level Assessment Misclassifies 3-of-4-Layer Active as "Minimal"

**Severity:** Minor
**File:** `server/src/shr/verifier.ts:127-132` (approximate — see SHR assessment logic)
**Description:** The sovereignty level assessment function checks for the "full" case (all 4 layers active), then checks for "degraded" by only examining L4 status. If L1, L2, and L3 are all active but L4 is disabled (e.g., no reputation data yet), the function falls through to return "minimal" instead of "degraded". An agent with 3 of 4 sovereignty layers fully operational is classified at the same level as one with only L1.

**Reproduction:**
1. Initialize Sanctuary with L1 (encryption), L2 (approval gate), L3 (commitments) all active.
2. Do not create any reputation records (L4 inactive/disabled).
3. Generate SHR via `monitor_health`.
4. SHR reports sovereignty level: "minimal".
5. Expected: "degraded" (3 of 4 layers active).

---

### BUG-016 — Attestation Generation Redundant Condition Masks Intent

**Severity:** Minor
**File:** `concordia/attestation.py:60`
**Description:** The guard condition `if not session.is_terminal and session.state != SessionState.EXPIRED` is logically redundant because `EXPIRED` is a terminal state. `is_terminal` returns `True` for AGREED, REJECTED, and EXPIRED. The `and session.state != SessionState.EXPIRED` clause can never contribute to the condition — if `session.state == EXPIRED`, then `session.is_terminal == True`, so `not session.is_terminal` is already `False`. This doesn't cause incorrect behavior, but it obscures the intended logic and could mislead maintainers into thinking EXPIRED sessions are explicitly excluded from attestation generation when they are not.

---

## SUMMARY

### Findings by Severity

| Severity | Count | IDs |
|----------|-------|-----|
| Blocking | 3 | BUG-001, BUG-003, BUG-005/006 |
| Major | 9 | BUG-002, BUG-007, BUG-008, BUG-009, BUG-010, BUG-011, BUG-012, BUG-013 |
| Minor | 4 | BUG-004, BUG-014, BUG-015, BUG-016 |

### Findings by Component

| Component | Count | IDs |
|-----------|-------|-----|
| Sanctuary StateStore (L1) | 3 | BUG-001, BUG-002, BUG-011 |
| Sanctuary Bridge | 2 | BUG-005, BUG-006 |
| Sanctuary L3 Disclosure | 2 | BUG-012, BUG-014 |
| Sanctuary Handshake | 1 | BUG-013 |
| Sanctuary Audit Log | 1 | BUG-010 |
| Sanctuary SHR | 1 | BUG-015 |
| Concordia MCP Server | 2 | BUG-003, BUG-008 |
| Concordia Reputation | 1 | BUG-009 |
| Concordia Relay | 1 | BUG-004 |
| Concordia Attestation | 1 | BUG-016 |
| Cross-Tool Bridge | 1 | BUG-007 |

---

## STRUCTURAL ASSESSMENT

The most structurally concerning pattern across both codebases is **cache-truth divergence**: critical operations depend on in-memory caches that are not guaranteed to reflect the actual state on disk. BUG-001 (export from empty cache) and BUG-002 (stale version cache after import skip) are both symptoms of the same root cause — the StateStore's in-memory maps (`contentHashes`, version cache) are treated as authoritative but are populated lazily and updated inconsistently. Any operation that needs a complete or accurate picture of persisted state (export, import conflict resolution, Merkle integrity) is vulnerable to cache-truth drift. The remediation planner should treat this as a design-level concern, not a collection of individual bugs — the fix is either to make the cache a proper write-through cache that is always consistent, or to have disk-touching operations always read from disk rather than cache.

The second systemic pattern is **bridge protocol incompleteness**. BUG-005, BUG-006, BUG-007, and BUG-008 collectively mean the Sanctuary-Concordia bridge does not function end-to-end. The payload shapes don't match, the required identity fields don't exist, the serialization produces different bytes, and a field name typo causes data loss. These are not edge cases — they prevent the bridge from working at all for any input. This suggests the bridge was designed at the schema level but never integration-tested with actual data flowing from Concordia through to Sanctuary.

The third pattern is **dead verification code** — functions that exist and are correct but are never called. The commitment `markRevealed()` (BUG-014), the Sybil `closed_loop` detector (BUG-009), and the range proof bit decomposition (BUG-012 when range=0) are all verification mechanisms that either cannot trigger or are not wired into the operational path. The system has more verification infrastructure than it actually uses, which creates a false sense of coverage.
