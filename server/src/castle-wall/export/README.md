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

## Audit lifecycle (distinct local ops)

`enforcement_export_enabled` / `enforcement_export_emitted` /
`enforcement_export_refused` (see `audit-ops.ts`). These are distinct **local**
audit `operation` strings; none widens a shared/global enum.

## Provenance

The events are read from the tamper-evident, hash-chained encrypted audit log,
and Castle Wall events are producer-signed at source
(`sanctuary.castle-wall.audit-producer.v1`). The exported stream is therefore
tamper-evident at the source - a claim a generic log forwarder cannot make.
