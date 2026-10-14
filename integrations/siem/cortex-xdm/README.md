# Cortex XDM Field Mapping

This field mapping describes the `audit_export_siem` Cortex raw-event JSON array
(`format: "xdm"`). The export uses raw keys with a sanctuary_ prefix so they do not
collide with the modeled XDM namespace. The mapping file lists proposed XDM
homes, including the acting principal sentinel at `xdm.source.user.username`.
The `sanctuary_audit_decision` and `sanctuary_audit_result` rows have null homes:
keep them as raw dataset fields. The same values have proposed standard homes
through `sanctuary_event_operation_sub_type` and `sanctuary_event_outcome`.
The mapping must match SIEM_XDM_FIELD_HOMES in `server/src/audit/siem-formatter.ts`.

Files:

- `xdm-field-mapping.json`: raw `sanctuary_*` field mapping for an XDM dataset.

Suggested detections to build after a tenant import drill:

- failures by operation over a time window: `sanctuary_time`,
  `sanctuary_event_operation`, `sanctuary_event_outcome`,
  `sanctuary_audit_result`, `_time`, `xdm.event.operation`,
  `xdm.event.outcome`
- total event volume by operation over a time window: `sanctuary_time`,
  `sanctuary_event_operation`, `_time`, `xdm.event.operation`

The exported coarse decision is deny exactly when the result is failure.
Every caller exports the same "self" sentinel, so separate callers by ingest
source rather than by the constant caller field.

Verified in this repository: raw field names and raw-to-home pairs match the
formatter tables, README field references stay inside those tables, and
formatter fixtures produce the raw fields. Null homes mean raw dataset fields.

Not verified here: importing into a live Cortex tenant or producing live
incidents or cases. No Cortex importable content ships here.
