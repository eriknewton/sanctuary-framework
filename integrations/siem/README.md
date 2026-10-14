# Sanctuary SIEM Content Pack

This directory contains repo-local SIEM integration content for the redacted
`audit_export_siem` output formats:

- `elastic/`: Elastic Common Schema field mapping, ingest pipeline, detection-rule templates, and suggested chart fields for `format: "ecs"`.
- `cortex-xdm/`: Cortex Data Model schema/modeling content and correlation-rule templates for `format: "xdm"`.

## Mapping

The formatter mapping table is the source of truth and is pinned in
`server/src/audit/siem-formatter.ts`. ECS uses the ECS 8.11.0
categorization pairing `event.category` with `event.type`; the coarse decision
is represented as `event.outcome` plus `sanctuary.audit.decision`, so a denied
decision never reads as allowed.

| Source | ECS field | XDM field |
| --- | --- | --- |
| timestamp | `@timestamp` | raw `sanctuary_time`, modeled `_time` |
| event constants | `event.kind`, `event.category`, `event.type` | raw `sanctuary_event_type`, modeled `xdm.event.type` |
| operation | `event.action` | raw `sanctuary_event_operation`, modeled `xdm.event.operation` |
| operation description | `event.action` plus constant `event.provider` | raw `sanctuary_event_description`, modeled `xdm.event.description` |
| coarse allow or deny | `event.severity`, `sanctuary.audit.decision` | raw `sanctuary_event_operation_sub_type` and `sanctuary_audit_decision`, modeled `xdm.event.operation_sub_type` and `sanctuary.audit.decision` |
| result | `event.outcome`, `sanctuary.audit.result` | raw `sanctuary_event_outcome`, `sanctuary_event_is_completed`, `sanctuary_audit_result`; modeled `xdm.event.outcome`, `xdm.event.is_completed`, `sanctuary.audit.result` |
| product identity | `ecs.version`, `event.module`, `event.dataset`, `service.name`, `service.type` | raw `sanctuary_observer_product`, `sanctuary_observer_vendor`; modeled `xdm.observer.product`, `xdm.observer.vendor` |
| caller identity | `user.id` fixed to self | raw `sanctuary_source_user_username`, modeled `xdm.source.user.username` fixed to self |

No raw policy tier, rule id, agent DID, session id, raw deal terms, key material,
or free-text policy reason is included. Fields without a standard home stay in
ECS use the Sanctuary namespace.

## Verification Bound

Verified in this repository:

- formatter fixture parity across CEF, OCSF, ECS, and XDM
- safe-decision projection reuse
- no ECS or XDM field outside the mapping table
- JSON, NDJSON, YAML, and XIF parsing for this pack
- content-pack field references resolve to formatter raw fields or modeled fields

Not verified here:

- live Elastic tenant import
- live Cortex XSIAM or Cortex XDR tenant import
- live dashboards, detections, incidents, or cases

These files follow the vendors' documented content shapes and were checked by
repo tests for shape and field references only. They were not imported into a
live tenant.
