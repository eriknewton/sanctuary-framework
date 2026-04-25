# Sanctuary Tool Registration Checklist

Every MCP tool registered with the Sanctuary server MUST declare four fields before merge: policy tier, outbound network behavior, audit event shape, and privacy impact. The checklist below is the gate. PR reviewers and CI surface tools that miss any field.

This checklist is part of the v1.1 Local Sovereignty Harness scope lock. v1.1 ships local-only, single-operator scope; the registration declarations below are scoped accordingly. Coordinator review of any new tool requires the four declarations to be filled in below the tool definition (or referenced from a shared registry table where it already exists).

## Why this exists

The v1.0 surface grew to 75 tools without a single source of truth on policy tier, network behavior, audit shape, or privacy impact. v1.1 adds query privacy, internal coordination, and exit bundling as first-class capabilities. Without a registration discipline, every new tool is a quiet hole in the privacy filter, audit chain, or operator approval gate.

## When this applies

- Adding a new MCP tool to the Sanctuary server.
- Renaming an existing tool.
- Changing the underlying behavior of an existing tool such that its policy tier, network behavior, audit shape, or privacy impact changes.
- Promoting an experimental tool to released.

A no-op rename does not require a fresh review, but the checklist entry MUST move with the tool name.

## The four required declarations

### 1. Policy tier

Pick one of:

- `tier1` — Always requires human approval through the Principal Policy gate. Examples: `state_export`, `state_import`, `key_rotate`, `identity_delete`, `reputation_import`, `exit_bundle_export`, `exit_bundle_import`.
- `tier2` — Requires approval when behavioral anomaly detection triggers. Examples: an action against a new namespace, a new counterparty, or an unusual rate.
- `tier3` — Auto-allow with audit logging.

Authority: the canonical tier list lives in `server/src/principal-policy/loader.ts`. Tools MUST be registered there with their tier, not only declared in the tool's own file.

Block conditions: a tool that performs an irreversible operation (export, import, delete, rotate, lockdown, unwrap, re-key) MUST be `tier1`. A tool that mutates the audit chain itself MUST be `tier1`. A tool that reads only its own caller-scoped state MAY be `tier3`.

### 2. Outbound network behavior

Pick one of:

- `none` — Tool reads or writes only local resources. No socket, no spawned subprocess that performs network I/O.
- `model_only` — Tool calls a remote model provider. No other network destination.
- `specific_allowlist` — Tool calls one or more explicitly allowlisted hosts. The allowlist MUST be enumerated in the tool's registration.
- `wildcard_with_policy` — Tool may call any host the operator's egress policy permits. Reserved for proxy and gateway tools that intentionally generalize across destinations. Egress policy is the authoritative gate at runtime.

Block conditions: any tool that egresses to a remote host MUST flow its outbound payload through the privacy filter unless the operator has explicitly disabled the filter through a policy override. A new tool that egresses without a privacy-filter integration is a release blocker for v1.1.

### 3. Audit event shape

Pick one of:

- A reference to an existing audit-event type in `server/src/audit/types.ts` (e.g., "L2 gate decision audit entry").
- A new audit-event type committed in the same PR. New types MUST include: timestamp, identity id, agent id, tool name, tier, outcome, content hashes for any payload material, and `signature_scheme`.

Block conditions:

- The audit event MUST NOT carry raw sensitive content. Hashes only.
- Every signed audit event MUST include `signature_scheme: "ed25519-v1"` per the v1.1 contracts (`server/src/contracts/v1.1/constants.ts`).
- Tools that touch the privacy filter MUST emit a privacy event from `server/src/contracts/v1.1/privacy-events.ts` in addition to the L2 gate audit entry.
- Tools that touch a handoff MUST emit a `LocalHandoffAuditEvent` from `server/src/contracts/v1.1/handoff-records.ts`.

### 4. Privacy impact

Pick one of:

- `no_external_data` — Tool reads or writes only data already inside the fortress. No outbound data of any kind. No prompt-context capture that flows to remote.
- `model_context_only` — Tool sends model-context payloads to a remote model provider. Goes through the privacy filter on every call.
- `external_payload` — Tool sends data to a non-model external endpoint. Goes through the privacy filter and the egress policy on every call.
- `provider_credential_use` — Tool uses a provider credential to act on the operator's behalf. Credential MUST live in the secret broker; the credential value MUST NOT appear in the tool's audit shape, error messages, or response.

Block conditions:

- A tool that emits any of `model_context_only`, `external_payload`, or `provider_credential_use` MUST register with the privacy filter before merge. A registration without filter integration fails CI.
- A tool that handles operator passphrases or recovery seeds MUST be marked `tier1` and MUST never include the value in any response, log, audit field, or error.

## How to fill out the checklist

In the tool's source file, add a TSDoc block above the tool registration (or extend an existing block):

```ts
/**
 * Tool: <name>
 *
 * Registration declarations (v1.1 tool-registration-checklist):
 * - policy_tier: tier1 | tier2 | tier3
 * - outbound_network: none | model_only | specific_allowlist[<hosts>] | wildcard_with_policy
 * - audit_event: <type or ref to types.ts>
 * - privacy_impact: no_external_data | model_context_only | external_payload | provider_credential_use
 *
 * Justification (one line per declaration; concrete enough that a reviewer
 * can challenge it without reading the implementation).
 */
```

The TSDoc block is the canonical source. CI parses the block and cross-checks it against the runtime registration in `server/src/principal-policy/loader.ts` and the audit-event registry. Drift between the TSDoc block and the registration table is a release blocker.

## CI gate

A v1.1 follow-up workstream adds CI coverage that:

1. Requires every tool registered through `addTool` (or whatever the canonical registration helper is at the time the gate lands) to have all four declarations.
2. Cross-checks `policy_tier` against the loader.
3. Cross-checks `outbound_network` against the egress policy registry.
4. Cross-checks `audit_event` against the audit types module.
5. Cross-checks `privacy_impact` against the privacy filter registration.

Until that CI lands, the four declarations are required by reviewer convention. Pull requests that miss declarations are rejected without merge.

## Examples

Each example below is illustrative only; real tool sources are authoritative.

### Example: `state_export` (existing, tier1)

```text
policy_tier: tier1
outbound_network: none
audit_event: L2 gate decision + state-export entry in audit chain
privacy_impact: no_external_data (export bundle stays on the operator's machine)
```

### Example: `inference_call_remote` (illustrative, tier3 with privacy filter)

```text
policy_tier: tier3
outbound_network: model_only
audit_event: privacy-event chain (filtered or denied) + L2 gate decision
privacy_impact: model_context_only (every call flows through the privacy filter)
```

### Example: `local_handoff_create` (illustrative, tier3, internal coordination)

```text
policy_tier: tier3
outbound_network: none
audit_event: LocalHandoffAuditEvent (created)
privacy_impact: no_external_data (handoff is fortress-local)
```

## Authority

This checklist is owned by the coordinator role. Changes to the four-declaration shape land through dated amendments in the v1.1 scope-lock document, not ad-hoc edits to this file.
