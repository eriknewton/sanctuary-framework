# Elastic Pack

This pack targets the `audit_export_siem` ECS JSON array (`format: "ecs"`).

Files:

- `ecs-field-mapping.json`: field mapping for the exported ECS document shape.
- `ingest-pipeline.json`: lightweight ingest pipeline metadata and field notes.
- `detection-rules.ndjson`: three Elastic Security rule templates.

Suggested charts to build after a tenant import drill:

- deny count over time: `@timestamp`, `sanctuary.audit.decision`
- operation outcomes: `event.action`, `event.outcome`, `sanctuary.audit.result`
- deny severity by operation: `event.action`, `event.severity`, `sanctuary.audit.decision`

Verified in this repository: the JSON/NDJSON parse, the field references match
the formatter mapping table, and formatter fixtures produce the mapped fields.

Not verified here: importing into a live Elastic deployment, running detections
against indexed tenant data, or loading any dashboard into a tenant.
