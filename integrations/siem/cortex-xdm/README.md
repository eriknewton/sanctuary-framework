# Cortex XDM Pack

This pack targets the `audit_export_siem` Cortex raw-event JSON array
(`format: "xdm"`). The export uses raw keys with a sanctuary_ prefix so they do not
collide with the modeled XDM namespace; the modeling rule maps those raw
keys into XDM, including the acting principal at `xdm.source.user.username`.

Files:

- `ModelingRules/SanctuaryAudit_1_0/SanctuaryAudit_1_0.xif`: modeling rule text that maps the raw exported fields to XDM fields.
- `ModelingRules/SanctuaryAudit_1_0/SanctuaryAudit_1_0_schema.json`: raw-field schema used by the modeling rule.
- `ModelingRules/SanctuaryAudit_1_0/SanctuaryAudit_1_0.yml`: content-pack modeling rule descriptor.
- `CorrelationRules/*.yml`: two correlation-rule templates over the modeled field set.

Suggested charts to build after a tenant import drill:

- deny count over time: `_time`, `sanctuary.audit.decision`
- operations by outcome: `xdm.event.operation`, `xdm.event.outcome`
- recent denied operations: `_time`, `xdm.event.operation`, `sanctuary.audit.result`

Verified in this repository: the JSON and YAML files parse, the XIF references
match the raw and modeled field tables, and formatter fixtures produce the raw
fields.

Not verified here: importing into a live Cortex tenant, compiling the `.xif`
inside a tenant repository, loading dashboards, or producing live incidents/cases.
