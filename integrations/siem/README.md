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

| ECS field | XDM field |
| --- | --- |
| `@timestamp` | raw `sanctuary_time`, home `_time` |
| `event.kind`, `event.category`, `event.type` | raw `sanctuary_event_type`, home `xdm.event.type` |
| `event.action` | raw `sanctuary_event_operation`, home `xdm.event.operation` |
| `event.provider` | raw `sanctuary_event_description`, home `xdm.event.description` |
| `event.severity`, `sanctuary.audit.decision` | raw `sanctuary_event_operation_sub_type` and `sanctuary_audit_decision`, homes `xdm.event.operation_sub_type` and `sanctuary.audit.decision` |
| `event.outcome`, `sanctuary.audit.result` | raw `sanctuary_event_outcome`, `sanctuary_event_is_completed`, `sanctuary_audit_result`; homes `xdm.event.outcome`, `xdm.event.is_completed`, `sanctuary.audit.result` |
| `ecs.version`, `event.module`, `event.dataset`, `service.name`, `service.type` | raw `sanctuary_observer_product`, `sanctuary_observer_vendor`; homes `xdm.observer.product`, `xdm.observer.vendor` |
| `user.id` | raw `sanctuary_source_user_username`, home `xdm.source.user.username` |

No raw policy tier, rule id, agent DID, session id, raw deal terms, key material,
or free-text policy reason is included. Fields without a standard ECS home use
the `sanctuary.audit.*` namespace. Constant exported fields include
`ecs.version`, `event.kind`, `event.category`, `event.type`, `event.module`,
`event.dataset`, `event.provider`, `service.name`, `service.type`, `user.id`,
`sanctuary_event_type`, `sanctuary_event_is_completed`,
`sanctuary_observer_product`, `sanctuary_observer_vendor`, and
`sanctuary_source_user_username`.

## Suggested Detections

- failures by operation over a time window: `@timestamp`, `event.action`,
  `event.outcome`, `sanctuary.audit.result`, `sanctuary_event_operation`,
  `sanctuary_event_outcome`, `sanctuary_audit_result`
- denied operations by coarse decision: `event.severity`,
  `sanctuary.audit.decision`, `sanctuary_event_operation_sub_type`,
  `sanctuary_audit_decision`
- export volume by caller sentinel: `user.id`,
  `sanctuary_source_user_username`, `service.name`

## Verification Bound

Verified in this repository:

- formatter fixture parity across CEF, OCSF, ECS, and XDM
- safe-decision projection reuse
- no ECS or XDM field outside the mapping table
- JSON mapping files and Markdown references name fields from the formatter tables

Not verified here:

- live Elastic tenant import
- live Cortex XSIAM or Cortex XDR tenant import
- live detections, incidents, or cases

No importable vendor content ships in this directory. These mapping files were
checked by repo tests for field names only. They were not imported into a live
tenant.
