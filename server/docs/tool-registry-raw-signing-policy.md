# Tool-Registry Raw Signing Policy

Structural policy for the Identity signing authority surface.
Enforced by `server/test/security/tool-registry-raw-signing-guard.test.ts`.

## Classification Rule

A tool is classified as a "raw signing tool" if its name contains `sign` as
a word-boundary token (regex: `/(?:^|_)sign(?:_|$)/i`). Substring matches
inside non-signing words (assign, design, signal) are excluded.

## Legitimate Paths for Sign-Named Tools

Every tool flagged by the classification rule MUST satisfy one of:

### Path 1: Tier 1 Classification

The tool appears in `tier1_always_approve` in `principal-policy/loader.ts`.
This means every invocation requires explicit human approval via the
out-of-band approval channel. Raw signing tools that accept arbitrary
payloads MUST use this path.

**Current Tier 1 signing tools:**

- `identity_sign` - Signs arbitrary base64url-encoded payloads with a
  managed Ed25519 identity. Operator approval required on every call.

### Path 2: Internal Helper (Not in MCP Registry)

The function is NOT exposed as an MCP tool. It is called only from within
the server codebase. These do not appear in the tool registry enumeration
and therefore do not trigger the guard.

**Current internal signing helpers:**

- `signTypedPayload()` - Internal function in `cognitive/tools.ts`.
  Signs domain-separated payloads for audit events and internal receipts.
- `signPayload()` - HMAC-SHA256 webhook signature in `principal-policy/webhook.ts`.
- `signHmacSha256Hex()` - HMAC helper in `principal-policy/aggregator-push-trigger.ts`.
- `signMasterRotationAsGuardian()` - Guardian roster rotation in `mesh/guardian/guardian-roster.ts`.
- `signApproval()` - Threshold recovery approval in `recovery/threshold-evaluator.ts`.
- `signWithAgentKey()` - Agent contract identity binding in `agent-contract/identity-bind.ts`.
- `signHandoffRecord()` - Coordination handoff in `coordination/signing.ts`.
- `signAuditPayload()` - Coordination audit in `coordination/signing.ts`.

### Path 3: Domain-Separated Allowlist

The tool signs typed payloads under an explicit domain-separation prefix
(not arbitrary bytes). The input schema enforces a domain-binding field.

**Current domain-separated signing tools:**

| Tool | Domain Prefix | Binding Field | Source |
|------|--------------|---------------|--------|
| `sanctuary_sign_challenge` | `sanctuary-sign-challenge-v1` | `purpose` (required) | `sanctuary-tools.ts` |

## Adding a New Entry to the Allowlist

To add a new domain-separated signing tool to the allowlist:

1. Verify the handler constructs a domain-prefixed message before signing
   (the prefix MUST be a constant string that the verifier can reconstruct).
2. Verify the input schema requires at least one field that participates in
   domain separation (preventing cross-purpose replay).
3. Add the tool name and domain prefix to `DOMAIN_SEPARATED_ALLOWLIST` in
   `test/security/tool-registry-raw-signing-guard.test.ts`.
4. Update the table in this document.
5. Get reviewer sign-off on the PR.

## Why This Guard Exists

PR #270 identified that `identity_sign` was not classified as Tier 1,
meaning a compromised agent could sign arbitrary payloads without human
approval. PR #270 fixed this by adding `identity_sign` to
`tier1_always_approve` and extracting typed internal signing helpers from
the MCP surface.

This guard prevents regression: if a future PR adds a new MCP tool with
`sign` in its name, the test fails unless the tool is explicitly
classified via one of the three legitimate paths above. Silent addition of
raw signing capability to the MCP surface is structurally impossible while
this guard is green.
