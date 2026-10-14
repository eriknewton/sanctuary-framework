# Elastic Field Mapping

This pack targets the `audit_export_siem` ECS JSON array (`format: "ecs"`).

Files:

- `ecs-field-mapping.json`: field mapping for the exported ECS document shape.

Suggested detections to build after a tenant import drill:

- failures by operation over a time window: `@timestamp`, `event.action`,
  `event.outcome`, `sanctuary.audit.result`
- denied operations by coarse decision: `event.action`, `event.severity`,
  `sanctuary.audit.decision`
- export volume by caller sentinel: `user.id`, `service.name`

Verified in this repository: the JSON mapping file matches the formatter mapping
table, README field references stay inside that table, and formatter fixtures
produce the mapped fields.

Not verified here: importing into a live Elastic deployment or running
detections against indexed tenant data. No Elastic importable content ships
here.
