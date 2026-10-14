# Sanctuary SIEM Field Mappings

This directory contains repo-local field mapping files for the redacted
`audit_export_siem` output formats:

- `elastic/`: Elastic Common Schema field mapping for `format: "ecs"`.
- `cortex-xdm/`: raw `sanctuary_*` to XDM field mapping for `format: "xdm"`.

## Mapping

The formatter mapping table is the source of truth and is pinned in
`server/src/audit/siem-formatter.ts`. ECS uses the ECS 8.11.0
categorization pairing `event.category` with `event.type`; the coarse decision
is represented as `event.outcome` plus `sanctuary.audit.decision`, so a denied
decision never reads as allowed.

Each row groups fields built from the same source value. The description adds
"Sanctuary " to the operation; severity is a numeric projection of the coarse
decision. Constant values are marked explicitly.

| Source value | ECS field or fields | XDM raw key and proposed home |
| --- | --- | --- |
| Timestamp | `@timestamp` | raw `sanctuary_time`, home `_time` |
| Operation | `event.action` | raw `sanctuary_event_operation`, home `xdm.event.operation` |
| Operation description | none | raw `sanctuary_event_description`, home `xdm.event.description` |
| Coarse decision from result | `event.severity`, `sanctuary.audit.decision` | raw `sanctuary_event_operation_sub_type`, home `xdm.event.operation_sub_type`; raw `sanctuary_audit_decision`, no standard XDM home |
| Result | `event.outcome`, `sanctuary.audit.result` | raw `sanctuary_event_outcome`, home `xdm.event.outcome`; raw `sanctuary_audit_result`, no standard XDM home |
| constant: 8.11.0 | `ecs.version` | none |
| constant: event | `event.kind` | none |
| constant: configuration category | `event.category` | none |
| constant: info type | `event.type` | none |
| constant: sanctuary | `event.module` | none |
| constant: sanctuary.audit | `event.dataset` | none |
| constant: sanctuary-mcp | `event.provider`, `service.name` | none |
| constant: mcp | `service.type` | none |
| constant: self | `user.id` | raw `sanctuary_source_user_username`, home `xdm.source.user.username` |
| constant: application | none | raw `sanctuary_event_type`, home `xdm.event.type` |
| constant: true | none | raw `sanctuary_event_is_completed`, home `xdm.event.is_completed` |
| constant: Sanctuary Framework | none | raw `sanctuary_observer_product`, home `xdm.observer.product` |
| constant: Erik Newton | none | raw `sanctuary_observer_vendor`, home `xdm.observer.vendor` |

No raw policy tier, rule id, agent DID, session id, raw deal terms, key material,
or free-text policy reason is included. Fields without a standard ECS home use
the `sanctuary.audit.*` namespace. Constant exported fields include
`ecs.version`, `event.kind`, `event.category`, `event.type`, `event.module`,
`event.dataset`, `event.provider`, `service.name`, `service.type`, `user.id`,
`sanctuary_event_type`, `sanctuary_event_is_completed`,
`sanctuary_observer_product`, `sanctuary_observer_vendor`, and
`sanctuary_source_user_username`.

## Suggested Detections

Build these suggested detections after a tenant import drill.

- failures by operation over a time window: `@timestamp`, `event.action`,
  `event.outcome`, `sanctuary.audit.result`, `sanctuary_time`,
  `sanctuary_event_operation`, `sanctuary_event_outcome`, `sanctuary_audit_result`
- total event volume by operation over a time window: `@timestamp`,
  `event.action`, `sanctuary_time`, `sanctuary_event_operation`

The exported coarse decision is deny exactly when the result is failure.
Every caller exports the same "self" sentinel, so separate callers by ingest
source rather than by the constant caller fields.

## Verification Bound

Verified in this repository:

- formatter fixture parity across CEF, OCSF, ECS, and XDM
- safe-decision projection reuse
- no ECS or XDM field outside the mapping table
- JSON field names and XDM raw-to-home pairs match the formatter tables
- README mapping rows name whole field tokens from those tables

Not verified here:

- live Elastic tenant import
- live Cortex XSIAM or Cortex XDR tenant import
- live detections, incidents, or cases

No importable vendor content ships in this directory. These mapping files were
checked by repo tests for field names and raw-to-home pair agreement with the
formatter tables. Null XDM homes keep those values as raw dataset fields. Vendor
modeling and live tenant ingestion remain unverified.
