# Elastic Field Mapping

This field mapping describes the `audit_export_siem` ECS JSON array (`format: "ecs"`).

Files:

- `ecs-field-mapping.json`: field mapping for the exported ECS document shape.

Suggested detections to build after a tenant import drill:

- failures by operation over a time window: `@timestamp`, `event.action`,
  `event.outcome`, `sanctuary.audit.result`
- total event volume by operation over a time window: `@timestamp`, `event.action`

The exported coarse decision is deny exactly when the result is failure.
Every caller exports the same "self" sentinel, so separate callers by ingest
source rather than by the constant caller fields.

Verified in this repository: the JSON mapping file matches the formatter mapping
table, README field references stay inside that table, and formatter fixtures
produce the mapped fields.

Not verified here: importing into a live Elastic deployment or running
detections against indexed tenant data. No Elastic importable content ships
here.
