# Elastic Pack

This pack targets the `audit_export_siem` ECS JSON array (`format: "ecs"`).

Files:

- `ecs-field-mapping.json`: field mapping for the exported ECS document shape.
- `ingest-pipeline.json`: lightweight ingest pipeline metadata and field notes.
- `dashboards.ndjson`: two Kibana saved-object dashboard templates.
- `detection-rules.ndjson`: three Elastic Security rule templates.

Verified in this repository: the JSON/NDJSON parse, the field references match
the formatter mapping table, and formatter fixtures produce the mapped fields.

Not verified here: importing into a live Elastic deployment or running detections
against indexed tenant data.
