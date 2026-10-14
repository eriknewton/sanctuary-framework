# Sanctuary SIEM Content Pack

This directory contains repo-local SIEM integration content for the redacted
`audit_export_siem` output formats:

- `elastic/`: Elastic Common Schema field mapping, ingest pipeline, saved dashboard objects, and detection-rule templates for `format: "ecs"`.
- `cortex-xdm/`: Cortex Data Model schema/modeling content, dashboards, and correlation-rule templates for `format: "xdm"`.

## Mapping

The formatter mapping table is the source of truth and is pinned in
`server/src/audit/siem-formatter.ts`.

| Source | ECS field | XDM field |
| --- | --- | --- |
| timestamp | `@timestamp` | `_time` |
| operation | `event.action` | `xdm.event.operation` |
| operation description | `event.provider` plus `event.action` | `xdm.event.description` |
| coarse allow or deny | `event.type`, `event.severity`, `sanctuary.audit.decision` | `xdm.event.operation_sub_type`, `sanctuary.audit.decision` |
| result | `event.outcome`, `sanctuary.audit.result` | `xdm.event.outcome`, `xdm.event.is_completed`, `sanctuary.audit.result` |
| product identity | `ecs.version`, `event.module`, `event.dataset`, `service.name`, `service.type` | `xdm.observer.product`, `xdm.observer.vendor` |
| caller identity | `user.id: self` | `xdm.source.identity.username: self` |

No raw policy tier, rule id, agent DID, session id, raw deal terms, key material,
or free-text policy reason is included. Fields without a standard home stay under
`sanctuary.*`.

## Verification Bound

Verified in this repository:

- formatter fixture parity across CEF, OCSF, ECS, and XDM
- safe-decision projection reuse
- no ECS or XDM field outside the mapping table
- JSON and NDJSON parsing for this pack
- content-pack field references resolve to formatter mapping fields

Not verified here:

- live Elastic tenant import
- live Cortex XSIAM or Cortex XDR tenant import
- live dashboards, detections, incidents, or cases

Treat the files as installable starting points for an operator-owned tenant
drill, not as proof that either vendor tenant has accepted them.
