# Cortex XDM Pack

This pack targets the `audit_export_siem` Cortex Data Model shaped JSON array
(`format: "xdm"`).

Files:

- `ModelingRules/SanctuaryAudit_1_0/SanctuaryAudit_1_0.xif`: modeling rule text that maps the raw exported fields to XDM fields.
- `ModelingRules/SanctuaryAudit_1_0/SanctuaryAudit_1_0_schema.json`: raw-field schema used by the modeling rule.
- `Dashboards/*.json`: two dashboard templates over the exported field set.
- `CorrelationRules/*.json`: two correlation-rule templates over the exported field set.

Verified in this repository: the JSON files parse, the field references match
the formatter mapping table, and formatter fixtures produce the mapped fields.

Not verified here: importing into a live Cortex tenant, compiling the `.xif`
inside a tenant repository, or producing live incidents/cases.
