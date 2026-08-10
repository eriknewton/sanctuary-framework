# SANCTUARY_ARCHITECTURE.md - Sanctuary architecture & reference

Load on demand for deep Sanctuary work. The MANDATORY rules (attribution, the commit/test-baseline
gate, the 8 "must never do" security invariants, skill routing) stay in `CLAUDE.md` and fire without
a lookup. This file is the reference detail split out of `CLAUDE.md` on 2026-06-08 to cut per-session
context load.

**Per-module index:** this doc is the *why* (architecture, data flow, trust model); for the *where* -
what each module under `server/src` owns, how they relate, and which names are traps - see the
module map at [`server/src/README.md`](server/src/README.md).

## WHAT THESE TOOLS ARE

**Sanctuary** is a TypeScript MCP server (~202,000 lines, 80+ MCP tools) that gives AI agents four layers of cryptographic sovereignty without requiring changes to the host agent harness. It ships as an npm package (`@sanctuary-framework/mcp-server`), Docker image, and Claude Code plugin. Current release status is tracked in `CHANGELOG.md`.

What it concretely does:

- **Cognitive Sovereignty (Castle Wall).** Encrypts all agent-persistent state at rest using AES-256-GCM. Each namespace derives its own key via HKDF-SHA256 from a master key. The master key is derived from a user passphrase (Argon2id, m=64MB, t=3, p=4) or a one-time recovery key. Ed25519 keypairs provide self-custodied identity; private keys are always encrypted and never appear in MCP responses. State reads return Merkle proofs for integrity verification.
- **Operational Isolation (Sentinels).** A three-tier Principal Policy gate evaluates every tool call before execution. Tier 1 operations (export, import, key rotation) always require human approval through an out-of-band channel (stderr prompt, web dashboard, or signed webhook). Tier 2 operations trigger approval when a behavioral anomaly is detected (new namespace, unfamiliar counterparty, frequency spike). Tier 3 operations auto-allow with audit logging. The policy file is loaded at startup and is immutable to the agent. Denial responses never reveal policy rules.
- **Selective Disclosure (Charter).** SHA-256 commitments with random blinding factors, Pedersen commitments on Ristretto255, Schnorr proofs, and bit-decomposition range proofs, allowing an agent to prove claims about its data without revealing the underlying values.
- **Verifiable Reputation (Heralds).** Signed attestations in EAS-compatible format, stored encrypted under Castle Wall. Sovereignty-gated tiers weight attestations from verified-sovereign agents higher. Escrow mechanism for trust bootstrapping. Reputation bundles are exportable and portable across instances. Current bound: an attestation recorded through `reputation_record` or `bridge_attest` is scored at self-attested or unverified weight; verified-sovereign and verified-degraded are not currently reachable through those recording paths. Handshake-verified peer trust is tracked separately, in the federation layer.

Additional subsystems: Sovereignty Health Report (SHR) generation and verification; sovereignty handshake protocol (nonce challenge-response + SHR exchange between two agents); federation registry for MCP-to-MCP peer discovery; Concordia bridge module; and the sovereignty audit tool (environment fingerprinting, OpenClaw-aware gap analysis, scored posture assessment with prioritized recommendations).

**Concordia** is a Python SDK and MCP server (~5,000 lines, 50+ tools exposed via FastMCP) implementing a structured multi-attribute negotiation protocol for autonomous agents. Version 0.1.0-draft.

What it concretely does:

- Defines a six-state session lifecycle: PROPOSED -> ACTIVE -> AGREED / REJECTED / EXPIRED -> DORMANT. State transitions are enforced by a strict transition table.
- Supports four offer types (Basic, Partial, Conditional, Bundle) and fourteen message types covering negotiation, information exchange, and resolution.
- Every message is Ed25519-signed over canonical JSON (sorted keys, deterministic serialization). Messages form a hash chain, and each message includes the SHA-256 hash of its predecessor, creating a tamper-evident transcript.
- Generates reputation attestations from concluded sessions: behavioral records (offers made, concession magnitude, reasoning rate, responsiveness) without exposing deal terms.
- Includes a Want Registry (demand-side discovery with constraint matching), Agent Registry (capability advertising), message relay service, and graceful degradation for non-Concordia peers.
- All data in the reference implementation is in-memory (Python dicts). No persistent database is included. Production deployment requires swapping storage backends.

**How the two tools interact:**

The connection is the Concordia Bridge, present in both codebases but architecturally optional in each direction.

On the Sanctuary side (`server/src/bridge/`): three MCP tools, `bridge_commit`, `bridge_verify`, `bridge_attest`. When a Concordia negotiation reaches AGREED, the outcome is canonically serialized, committed to Sanctuary's Charter layer (SHA-256 + optional Pedersen commitment), signed by the committer's Ed25519 key, and optionally linked to Heralds reputation via a signed attestation.

On the Concordia side (`concordia/sanctuary_bridge.py`): a payload builder that produces correctly-shaped requests for Sanctuary's `proof_commitment` and `reputation_record` tools. It does NOT directly call Sanctuary; it generates payloads that a client forwards. This keeps Concordia testable without a running Sanctuary server.

The bridge introduces no new cryptographic primitives. Everything delegates to existing Charter/Heralds infrastructure.

---


## ARCHITECTURE IN ONE PAGE

### Entry Points

| Tool | Entry Point | What It Starts |
|------|------------|----------------|
| Sanctuary | `server/src/cli.ts` | Parses flags, calls `createSanctuaryServer()` from `index.ts`, connects via StdioServerTransport |
| Concordia | `concordia/__main__.py` | Parses `--transport`, calls `mcp.run()` from `mcp_server.py` (FastMCP) |

### Core Data Flow

**Sanctuary:**
```
Tool call from agent harness
  -> MCP SDK (router.ts: schema validation, size caps, enum checks)
  -> ApprovalGate (gate.ts: Tier 1/2/3 evaluation)
  -> Tool handler (Castle Wall/Sentinels/Charter/Heralds)
  -> StateStore (state-store.ts: encrypt via AES-256-GCM, sign via Ed25519, compute Merkle root)
  -> StorageBackend (filesystem.ts: write to ~/.sanctuary/state/{namespace}/{key}.enc)
  -> AuditLog (audit-log.ts: append encrypted entry)
```

**Concordia:**
```
Tool call from agent harness
  -> FastMCP dispatcher (mcp_server.py)
  -> Session state machine (session.py: validate transition, append to hash-chain transcript)
  -> Signing (signing.py: Ed25519 sign over canonical JSON)
  -> In-memory stores (SessionStore, AttestationStore, WantRegistry, AgentRegistry)
  -> [Optional] Sanctuary bridge payload generation (sanctuary_bridge.py)
```

### Where the Two Tools Connect

```
Concordia session reaches AGREED
  -> concordia/sanctuary_bridge.py builds commitment payload
  -> Client forwards payload to Sanctuary MCP server
  -> sanctuary/bridge_commit: canonicalize outcome, create Charter commitment, Ed25519 sign
  -> sanctuary/bridge_verify: recompute hash, verify signature (later, on demand)
  -> sanctuary/bridge_attest: create Heralds attestation linking outcome to reputation
```

The bridge is a payload hand-off, not a direct call. The two servers run as separate processes. There is no shared memory, no shared database, no implicit RPC channel between them.

### Auth and Trust Model

**Sanctuary:** Master key (Argon2id from passphrase or random recovery key) -> HKDF per namespace -> AES-256-GCM encryption. Ed25519 for identity, signing, and non-repudiation. Principal Policy for human-in-the-loop approval gating. Sovereignty handshake for mutual agent verification (nonce challenge-response + SHR).

**Concordia:** Ed25519 key pairs per agent. Messages signed over canonical JSON. Hash-chain transcript integrity. Sybil detection on reputation attestations (self-dealing, suspiciously fast sessions, symmetric concessions, closed loops).

**Cross-boundary:** Sanctuary does not trust Concordia's assertions; it verifies cryptographically. Concordia does not call Sanctuary directly; it produces payloads. Trust is established through signature verification and commitment recomputation, not through any shared secret or implicit channel.

### Key Third-Party Dependencies

**Sanctuary (TypeScript):**
- `@noble/ciphers` - AES-256-GCM (audited, zero transitive deps)
- `@noble/curves` - Ed25519, Ristretto255 for Pedersen commitments (audited)
- `@noble/hashes` - SHA-256, HMAC, HKDF (audited)
- `hash-wasm` - Argon2id key derivation (WASM-based)
- `@modelcontextprotocol/sdk` - MCP protocol implementation

**Concordia (Python):**
- `cryptography` (>=42.0) - Ed25519 signing and verification
- `jsonschema` (>=4.20) - Message and attestation schema validation
- `mcp` (>=1.0) - FastMCP server SDK

No blockchain libraries. No external API calls at runtime. No telemetry.

---

## SOVEREIGNTY PROPERTIES THIS SYSTEM IS DESIGNED TO GUARANTEE

These are testable assertions. Each should be verifiable by inspection or automated test.

**Data sovereignty:**

1. "No plaintext user state is ever written to disk." All values in `~/.sanctuary/state/` are AES-256-GCM ciphertext with unique IVs. *(Tested: `test/security/no-plaintext-leak.test.ts`)*
2. "A user can retrieve a complete export of all data the system holds about them" via `state_export` (requires Tier 1 approval). *(Tested: `test/integration/reputation-portability.test.ts`)*
3. "A user can delete any piece of stored state, including secure 3-pass overwrite" via `state_delete` with `secure_delete: true`. *(Tested: unit tests for storage backend)*
4. "Every encryption operation uses a unique, cryptographically random IV (12 bytes)." *(Tested: `test/security/iv-uniqueness.test.ts`)*
5. "File permissions on the storage directory are 0o700 (owner only) and on individual files are 0o600 (owner read/write only)."

**Identity sovereignty:**

6. "Private keys never appear in any MCP tool response." *(Tested: `test/security/key-never-in-response.test.ts`)*
7. "Identity key rotation produces a signed chain proving authorization: the new key is signed by the old key."
8. "A user can export current identity and reputation artifacts through shipped paths." Full exit remains partial: dashboard export omits the state re-key key, import hides skipped-entry counters, and rotated-key imports can lose pre-rotation state. Open defect: **IC-07, IC-08, IC-09**.

**Operational sovereignty:**

9. "Every tool call is evaluated by the ApprovalGate before execution. There is no code path that bypasses the gate." *(Verified by router.ts wrapping all handlers)*
10. "Tier 1 operations (export, import, rotate, delete) require out-of-band human approval. If the approval channel is unreachable, the operation is denied, never auto-approved."
11. "The agent cannot read, modify, or infer the contents of the Principal Policy at runtime. Denial messages are generic."
12. "All gate decisions (approve, deny, auto-allow) are appended to the encrypted audit log."

**Negotiation integrity (Concordia):**

13. "Every Concordia message is Ed25519-signed and hash-chained. Tampering with any message breaks the chain." *(Tested: signing and message hash chain tests)*
14. "Session state transitions are enforced by a strict transition table. Invalid transitions raise `InvalidTransitionError`."
15. "Reputation attestations contain behavioral signals only, never raw deal terms."

**Bridge integrity:**

16. "Bridge commitments use canonical serialization (sorted keys, deterministic JSON) so identical outcomes always produce identical commitment hashes."
17. "Non-finite numbers (NaN, Infinity) in outcome terms are rejected at canonicalization time to prevent commitment ambiguity."
18. "Bridge verification recomputes the commitment from the revealed outcome and compares; it does not trust the stored hash alone."

**Intended but unverified:**

19. "Hardware key protection (FIDO2/WebAuthn) for master key derivation." *(Planned for v0.3.0, config option exists, implementation not yet present.)*
20. "TEE-backed execution environment attestation." *(Config accepts `tee` as environment type, but the code uses self-reported attestation only; no TEE integration exists.)*
21. "Groth16/PLONK zero-knowledge proof systems for Charter (Selective Disclosure)." *(Config accepts these as `proof_system` options, but only `commitment-only` is implemented. ZK proofs use Pedersen/Schnorr, not SNARKs.)*

---

## KNOWN COMPLEXITY AND RISK AREAS

**Slow down and inspect carefully in these areas:**

1. **Canonical serialization (both codebases).** Sanctuary's `stableStringify` in `bridge/bridge.ts` and Concordia's `canonical_json` in `signing.py` must produce byte-identical output for the same input. They are implemented independently in different languages. Any divergence breaks bridge commitment verification. This is the highest-risk interop surface. Edge cases to watch: Unicode normalization, floating-point representation, key ordering in nested objects, handling of `null`/`undefined`/`None`.

2. **Principal Policy baseline tracker.** The `BaselineTracker` in `principal-policy/baseline.ts` builds a behavioral model over time. On first session there is no baseline, so all Tier 2 operations require approval. As the baseline grows, the anomaly detection thresholds shift. The interaction between baseline state, encrypted baseline persistence, and the approval gate evaluation logic is the most stateful part of Sanctuary. Bugs here could either over-permit (missing anomalies) or over-deny (false positives blocking legitimate operations).

3. **Approval channel failure modes.** Three channels exist: stderr (auto-deny on timeout, safe default), dashboard (SSE-based web UI), and webhook (HMAC-signed HTTP POST). The webhook channel introduces an external network dependency. If the webhook endpoint is slow, unreachable, or returns ambiguous responses, the gate must deny; the timeout and retry logic is where subtle bugs live.

4. **Concordia's in-memory state model.** The reference implementation stores everything in Python dicts with size caps (10K sessions, 100K attestations). There is no persistence, no crash recovery, no transaction isolation. Any production deployment must swap these stores, and the swap surface is wide: `SessionStore`, `AttestationStore`, `WantRegistry`, `AgentRegistry`, `NegotiationRelay` all hold independent in-memory state.

5. **Sybil detection heuristics.** Concordia's `SybilSignals` in `reputation/store.py` flags self-dealing, suspiciously fast sessions (<5 seconds), symmetric concessions, and closed-loop trading. These are heuristics, not proofs. A sophisticated attacker can craft sessions that evade all four signals. The scorer applies penalties but does not reject flagged attestations outright; the scoring weights are tunable and their security properties are not formally analyzed.

6. **Merkle tree and version monotonicity in StateStore.** Sanctuary computes Merkle roots over namespace entries and tracks monotonic version numbers to detect rollback. The correctness of rollback detection depends on the version counter never being reset, which depends on the encrypted metadata file not being replaced with a stale copy. An attacker with filesystem access could potentially roll back the version metadata file; the defense relies on the master key protecting integrity, but the threat model for filesystem-level adversaries is not fully specified.

7. **Bridge attestation trust bootstrapping.** When a Concordia outcome is bridged to Sanctuary's Heralds layer, the attestation's weight depends on the counterparty's sovereignty tier (determined by handshake). If the counterparty has not completed a sovereignty handshake, the attestation is tagged `unverified`, and the code still stores it. The boundary between "stored but unverified" and "stored and trusted" attestations could be confusing to consumers of the reputation API.

8. **ZK proof system scope.** The current Charter (Selective Disclosure) implementation provides Pedersen commitments, Schnorr proofs, and bit-decomposition range proofs. These are genuine cryptographic primitives, but they are not SNARKs. The config schema advertises `groth16` and `plonk` as options, which could mislead reviewers into thinking those systems are available. Only `commitment-only` is functional.

---

## REVIEW CONTEXT

The structured security review completed 2026-03-28 with all Critical and High findings resolved. Review artifacts (SECURITY_AUDIT.md, BUG_REPORT.md, REMEDIATION_PLAN.md, SPRINT_CONTRACT.md, SPRINT_RESULT.md, SPRINT_EVAL.md) are in `docs/audit/`.

Post-review work completed 2026-03-29: Sovereignty Audit Tool (`server/src/audit/`), with environment fingerprinting, OpenClaw-specific detection, four-layer gap analysis with deterministic scoring (0-100), and human-readable report generation. Published to npm as v0.3.1 on 2026-03-30.

**Current release status:** see `CHANGELOG.md`. The server currently exposes 80+ MCP tools. Major additions since v0.4.2: Sovereignty Dashboard, `sanctuary wrap` one-command install, EU AI Act compliance generator, context gating, SIEM export, sovereignty profile, governor, and federation tools.

---

## DELTA - 2026-03-31 - Operational (Sentinels) Context Gating

### Subsystem Summary

Context gating is a new Operational Isolation (Sentinels) subsystem that controls what agent context flows to remote providers (LLM inference APIs, tool APIs, logging services, analytics). It enforces "minimum-necessary context" at the execution boundary before any outbound call, where the agent filters its context through a policy that classifies each top-level field as allow, redact, hash, summarize, or deny.

**New source files:**
- `server/src/operational/context-gate.ts` - Core types, `evaluateField()`, `filterContext()`, pattern matching, encrypted policy store (`ContextGatePolicyStore`)
- `server/src/operational/context-gate-tools.ts` - 5 MCP tool definitions
- `server/src/operational/context-gate-templates.ts` - 4 starter templates + template registry
- `server/src/operational/context-gate-recommend.ts` - Heuristic recommendation engine with word-boundary matching

**New test files:**
- `server/test/operational/context-gate.test.ts` - 26 tests for core module
- `server/test/operational/context-gate/context-gate-templates.test.ts` - 47 tests for templates and recommendation engine

**Modified files:**
- `server/src/index.ts` - imports + registration of context gate tools
- `server/src/principal-policy/loader.ts` - 5 context gate operations added to Tier 3
- `server/src/audit/types.ts` - `context_gating: boolean` field added to L2AuditResult
- `server/src/audit/analyzer.ts` - scoring rebalance (Operational now 25 pts with 4 for context gating) + gap analysis for missing context gating

### New Trust Boundaries

| Boundary | Direction | Data | Enforcement |
|----------|-----------|------|-------------|
| Agent input → context_gate_set_policy | Inbound | Policy definitions (rules, patterns, provider categories) | Type casting, no deep validation |
| Agent input → context_gate_filter | Inbound | Arbitrary context objects + policy ID + provider string | Policy lookup, per-field pattern matching |
| Agent input → context_gate_recommend | Inbound | Arbitrary context objects for heuristic analysis | Field name classification, no content inspection |
| Context objects → pattern matcher → filtered output | Internal | Context field names evaluated against allow/redact/hash/summarize lists | Priority: redact > hash > summarize > allow > default |
| Filtered output → audit trail | Internal | SHA-256 hashes of original and filtered content | Hash computed via `hashToString(stringToBytes(JSON.stringify(...)))` |

### New Encrypted Storage

Policy store uses AES-256-GCM with HKDF domain separation key `"l2-context-gate"` derived from the master key. Policies are stored under the `_context_gate_policies` namespace (underscore-prefixed = reserved, protected from Castle Wall tools). Each policy is individually encrypted and addressable by policy ID.

### New Entry Points (5 MCP Tools)

1. `sanctuary/context_gate_set_policy` - Create a context-gating policy with per-provider rules
2. `sanctuary/context_gate_apply_template` - Apply a starter template (inference-minimal, inference-standard, logging-strict, tool-api-scoped)
3. `sanctuary/context_gate_recommend` - Analyze a sample context object and recommend a policy via heuristics
4. `sanctuary/context_gate_filter` - Filter context through a policy before outbound calls
5. `sanctuary/context_gate_list_policies` - List all configured policies

All 5 tools are classified as Tier 3 (auto-allow with audit logging) in the default Principal Policy.

### Threat Model Additions

1. **Malicious field naming to bypass patterns.** The pattern matcher in `matchesPattern()` supports exact match, prefix wildcard (`secret_*`), and suffix wildcard (`*_pii`). An attacker controlling field names could use case variations (e.g., `API_KEY` vs `api_key`), unicode homoglyphs, or nested object structures to evade redaction rules. The enforcement-path pattern matcher must be case-insensitive.

2. **Policy manipulation.** Policies are encrypted at rest but all 5 context gate tools are Tier 3 (auto-allow). A compromised agent can create permissive policies, apply them, and filter context through them to exfiltrate data via allowed fields. The policy store does not enforce identity binding, so any caller can read/use any policy regardless of the `identity_id` field.

3. **Denial of service via large context objects.** The `filter` and `recommend` tools accept arbitrary context objects without size limits. A context with millions of keys would cause O(n×m) pattern matching (n fields × m patterns per rule). No cap on rule array sizes in `set_policy`.

4. **Pattern matching edge cases.** Only top-level keys are evaluated, so nested objects within an allowed field pass through unexamined. Patterns only support prefix and suffix wildcards, not infix. Empty patterns or malformed patterns are not validated.

5. **Template correctness.** The logging-strict template uses `redact: ["*"]` (wildcard redact) which takes absolute priority over its own `allow` list, making the allow list dead code. The template description claims metadata passes through, but in practice everything is redacted.
