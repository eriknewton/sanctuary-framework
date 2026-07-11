# Operator-side enforcement-event exporter

This module turns Castle Wall's already-recorded enforcement evidence into a
**frozen, versioned public event stream** an operator's security console can
consume, and delivers it either locally (default, no network) or, behind an
explicit opt-in + a pinned destination + a Tier-1 approval, as an outbound push
to an HTTP collector (for example a Palo Alto Cortex XSIAM content pack).

The story it enables: **the wall enforces on the host; the console sees every
denial.**

## What LEAVES the host (metadata only, closed schema)

Exactly the fields of `sanctuary.enforcement-event.v1` (see `schema.ts`), and
nothing else. The mapping in `map.ts` constructs every event field-by-field from
an explicit allowlist and **never** spreads or serializes the raw audit
`details` object. Three closed event classes:

1. **`egress_decision`** - a rule-attributed allow/deny:
   `timestamp`, `decision` (coarse `allow`/`deny`), `destination_host`,
   `destination_ip`, `destination_port`, `destination_protocol`, `rule_id`,
   `agent_id` (the operator-facing agent id, e.g. `claude-code-1`),
   `agent_template` (the role), `enforcement_point`.
2. **`policy_change`** - `timestamp`, `change_type`
   (`loaded`/`validation_failed`/`promoted`/`bundle`/`operator_decision`),
   `signer_ref` (a key id, never a private key), `manifest_digest` (a digest,
   never the manifest body), `rule_count` (a count, never the rules),
   `enforcement_point`.
3. **`distress`** - the closed `sanctuary.distress.v1` beacon:
   `event_id`, `actor`, `reason` (closed enum), `severity` (closed enum),
   `detail` (already control-stripped + capped at source, re-bounded here),
   `sequence_in_window`.

## What NEVER leaves the host

- **State content** - namespace payloads, memory, working state, reputation
  bundles. None of it is on any allowlist.
- **Keys / secrets** - Ed25519 private keys, HMAC secrets, bearer tokens.
  Nothing secret is placed in a payload, header, or log line (must-never #6).
- **Policy contents** - the exporter forwards the KIND of a policy change plus a
  signer reference / digest / count, never rule text, allowlist entries, or the
  Principal Policy.
- **Raw `details`** - the free-text `reason` strings that historically carried
  anomaly thresholds (`operational/agent-audit-redaction.ts`) are never
  serialized. The closed schema is emitted instead, so nothing rides along by
  accident.
- **Fine-grained policy-tier signals** - `egress_decision.decision` is a coarse
  `allow`/`deny` derived from the event type, not the fine-grained
  `allow_once`/`deny_always`/`timeout_default_deny` disposition.

## Safe by default; outbound push is Tier-1 gated

- The default sink is **`file`** (NDJSON via an injected writer / stdout). It
  opens **no** network connection (`FileExportSink.touchesNetwork === false`).
- Outbound push (`sink: "http"`) requires **all** of: `enabled: true` (opt-in), a
  well-formed **pinned** `destination_url` (https, or loopback for a local
  collector), and a **Tier-1 operator approval** at enable time (the same gate
  class as `state_export`). Missing any one, or an operator denial, **refuses**
  and arms nothing.
- If an armed push cannot reach the pinned collector, delivery **fails loud**
  (audits a refusal and re-throws). It never falls back to a file and never
  silently drops a batch while reporting success (must-never #5).

## Streaming consumer + durable cursor

`stream.ts` drives the exporter off `AuditLog.streamVerifiedChain` (the
tamper-evident, strict-verified source). It buffers mapped events DURING the
verified pass but delivers them only AFTER the `await` resolves clean, so a
tampered chain rejects before a single event leaves the host, and a torn-read
retry (`reset()`) discards the partial pass.

- **Durable cursor** (`cursor.ts`, `FileExportCursorStore` at
  `<fortress>/state/cortex-export-cursor.json`): a run forwards only entries
  whose chain sequence is STRICTLY ABOVE the persisted cursor. The cursor is
  persisted (atomic temp+rename) only AFTER a batch is confirmed delivered by the
  fail-loud sink, so a crash can only leave it BEHIND the delivered frontier. That
  is the fail-safe direction: re-scan + re-deliver, never skip. The contract is
  at-least-once with **no gap** and **no re-send storm** (a lost cursor write
  re-sends at most the already-delivered tail of one batch; a collector dedupes on
  event identity).
- **Bounded retry, still fail closed**: a transient sink failure is retried up to
  a bounded budget with backoff. The retried payload is the SAME already-mapped
  metadata batch through the SAME sink (no re-mapping, no fallback to a different
  lane). After the budget is exhausted the streamer records `_retry_exhausted` and
  RE-THROWS, leaving the cursor un-advanced so the batch is re-attempted next run.
  It never silently drops and never reports success on failure.

## Operator config file + CLI

- **Config file** (`config-loader.ts`): `<fortress>/policy/egress/cortex-export.json`,
  operator-owned (the agent cannot read or write it). Missing file = the safe
  default (file sink, no network). Present-but-invalid = throws (fail closed).
  Validation reuses the pure `config.ts` (https-only, no userinfo, pinned).
- **CLI** (`cli/cortex-export.ts`, `sanctuary cortex-export run`): reads the
  config, arms the exporter, and runs one streaming pass. The default (file sink)
  needs no approval and touches no network; the outbound push prompts for the
  Tier-1 approval before it arms. `enforcement_export_enabled` is force-pinned
  Tier-1 (`NON_RELAXABLE_ENFORCEMENT_EXPORT_TIER1_OPERATIONS`) so a hand-authored
  policy cannot relax the push out of the approval gate.

## Audit lifecycle (distinct local ops)

`enforcement_export_enabled` / `enforcement_export_emitted` /
`enforcement_export_refused` / `enforcement_export_cursor_advanced` /
`enforcement_export_retry_exhausted` (see `audit-ops.ts`). These are distinct
**local** audit `operation` strings; none widens a shared/global enum.

## Provenance

The events are read from the tamper-evident, hash-chained encrypted audit log,
and Castle Wall events are producer-signed at source
(`sanctuary.castle-wall.audit-producer.v1`). The exported stream is therefore
tamper-evident at the source - a claim a generic log forwarder cannot make.
