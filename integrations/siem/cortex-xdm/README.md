# Cortex XDM Field Mapping

This pack targets the `audit_export_siem` Cortex raw-event JSON array
(`format: "xdm"`). The export uses raw keys with a sanctuary_ prefix so they do not
collide with the modeled XDM namespace. The mapping file lists where those raw
keys should land in an XDM dataset, including the acting principal sentinel at
`xdm.source.user.username`.

Files:

- `xdm-field-mapping.json`: raw `sanctuary_*` field mapping for an XDM dataset.

Suggested detections to build after a tenant import drill:

- failures by operation over a time window: `sanctuary_time`,
  `sanctuary_event_operation`, `sanctuary_event_outcome`,
  `sanctuary_audit_result`, `_time`, `xdm.event.operation`,
  `xdm.event.outcome`
- denied operations by coarse decision: `sanctuary_event_operation_sub_type`,
  `sanctuary_audit_decision`, `xdm.event.operation_sub_type`,
  `sanctuary.audit.decision`
- export volume by caller sentinel: `sanctuary_source_user_username`,
  `xdm.source.user.username`

Verified in this repository: the JSON mapping file matches the formatter raw
field table, README field references stay inside the raw and destination field
tables, and formatter fixtures produce the raw fields.

Not verified here: importing into a live Cortex tenant or producing live
incidents or cases. No Cortex importable content ships here.
