# CLI Audit-Write Completeness Inventory

Generated: 2026-05-21T18:08:29.714Z

## Summary

| Metric | Count |
|--------|-------|
| Total CLI subcommands inventoried | 69 |
| Mutators | 33 |
| Read-only | 36 |
| Pure-UI | 0 |
| **Mutators that do NOT audit (Batch 5b targets)** | **13** |
| Uncertain (operator review needed) | 0 |

## Mutators Missing Audit (Batch 5b Targets)

- `sanctuary agents config` (src/cli/agents/cli.ts:105)
  writes principal-policy.yaml but no audit entry
- `sanctuary anomaly subscribe` (src/cli/anomaly.ts:80)
  writes subscription file but no audit entry
- `sanctuary anomaly unsubscribe` (src/cli/anomaly.ts:82)
  writes subscription file but no audit entry
- `sanctuary auto-trigger recommendations accept` (src/cli/auto-trigger.ts:173)
  applies calibration change but no audit entry
- `sanctuary auto-trigger recommendations reject` (src/cli/auto-trigger.ts:185)
  suppresses recommendation but no audit entry
- `sanctuary auto-trigger rules demote` (src/cli/auto-trigger.ts:224)
  updates ThresholdConfigStore but no audit entry
- `sanctuary auto-trigger rules promote` (src/cli/auto-trigger.ts:222)
  updates ThresholdConfigStore but no audit entry
- `sanctuary auto-trigger rules set-threshold` (src/cli/auto-trigger.ts:226)
  updates ThresholdConfigStore but no audit entry
- `sanctuary did-web issue` (src/cli/did-web.ts:148)
  writes did-web.json but no AuditLog.append in issue handler
- `sanctuary policy drafts activate` (src/cli/policy.ts:238)
  activates policy via HTTP POST but no local audit
- `sanctuary sentinel subscribe` (src/cli/sentinel.ts:62)
  writes subscription file but no audit entry
- `sanctuary sentinel unsubscribe` (src/cli/sentinel.ts:64)
  writes subscription file but no audit entry
- `sanctuary template init` (src/templates/cli.ts:43)
  writes template files but no audit entry

## Full Inventory

| Subcommand | Classification | Audits? | File | Line |
|------------|---------------|---------|------|------|
| `sanctuary agents config` | mutator | **NO** | src/cli/agents/cli.ts | 105 |
| `sanctuary agents list` | read-only | n/a | src/cli/agents/cli.ts | 99 |
| `sanctuary agents show` | read-only | n/a | src/cli/agents/cli.ts | 101 |
| `sanctuary agents status` | read-only | n/a | src/cli/agents/cli.ts | 103 |
| `sanctuary anomaly classifier-state` | read-only | n/a | src/cli/anomaly.ts | 86 |
| `sanctuary anomaly detectors` | read-only | n/a | src/cli/anomaly.ts | 76 |
| `sanctuary anomaly findings` | read-only | n/a | src/cli/anomaly.ts | 84 |
| `sanctuary anomaly list-subscribed` | read-only | n/a | src/cli/anomaly.ts | 78 |
| `sanctuary anomaly subscribe` | mutator | **NO** | src/cli/anomaly.ts | 80 |
| `sanctuary anomaly unsubscribe` | mutator | **NO** | src/cli/anomaly.ts | 82 |
| `sanctuary auto-trigger cancel` | mutator | yes | src/cli/auto-trigger.ts | 82 |
| `sanctuary auto-trigger recommendations accept` | mutator | **NO** | src/cli/auto-trigger.ts | 173 |
| `sanctuary auto-trigger recommendations list` | read-only | n/a | src/cli/auto-trigger.ts | 138 |
| `sanctuary auto-trigger recommendations reject` | mutator | **NO** | src/cli/auto-trigger.ts | 185 |
| `sanctuary auto-trigger recommendations show` | read-only | n/a | src/cli/auto-trigger.ts | 156 |
| `sanctuary auto-trigger rules demote` | mutator | **NO** | src/cli/auto-trigger.ts | 224 |
| `sanctuary auto-trigger rules list` | read-only | n/a | src/cli/auto-trigger.ts | 138 |
| `sanctuary auto-trigger rules promote` | mutator | **NO** | src/cli/auto-trigger.ts | 222 |
| `sanctuary auto-trigger rules set-threshold` | mutator | **NO** | src/cli/auto-trigger.ts | 226 |
| `sanctuary auto-trigger rules show` | read-only | n/a | src/cli/auto-trigger.ts | 156 |
| `sanctuary concierge ask` | read-only | n/a | src/cli/concierge.ts | 54 |
| `sanctuary concierge status` | read-only | n/a | src/cli/concierge.ts | 55 |
| `sanctuary did-web issue` | mutator | **NO** | src/cli/did-web.ts | 148 |
| `sanctuary did-web key-history` | read-only | n/a | src/cli/did-web.ts | 157 |
| `sanctuary did-web register-hosted` | mutator | yes | src/cli/did-web.ts | 160 |
| `sanctuary did-web rotate-key` | mutator | yes | src/cli/did-web.ts | 154 |
| `sanctuary did-web show` | read-only | n/a | src/cli/did-web.ts | 151 |
| `sanctuary exit export` | mutator | yes | src/exit/cli.ts | 267 |
| `sanctuary exit manifest-shape` | read-only | n/a | src/exit/cli.ts | 208 |
| `sanctuary honeypot compile` | read-only | n/a | src/honeypot/cli.ts | 150 |
| `sanctuary honeypot credential-traps` | read-only | n/a | src/honeypot/cli.ts | 286 |
| `sanctuary honeypot deploy` | mutator | yes | src/honeypot/cli.ts | 199 |
| `sanctuary honeypot findings` | read-only | n/a | src/honeypot/cli.ts | 346 |
| `sanctuary honeypot list` | read-only | n/a | src/honeypot/cli.ts | 233 |
| `sanctuary honeypot tool-traps` | read-only | n/a | src/honeypot/cli.ts | 250 |
| `sanctuary honeypot undeploy` | mutator | yes | src/honeypot/cli.ts | 323 |
| `sanctuary identity show` | read-only | n/a | src/cli/identity.ts | 86 |
| `sanctuary inbox approvals approve` | mutator | yes | src/cli/inbox.ts | 195 |
| `sanctuary inbox approvals list` | read-only | n/a | src/cli/inbox.ts | 33 |
| `sanctuary inbox archive` | mutator | yes | src/cli/inbox.ts | 37 |
| `sanctuary inbox dismiss` | mutator | yes | src/cli/inbox.ts | 38 |
| `sanctuary inbox retention set` | mutator | yes | src/cli/inbox.ts | 162 |
| `sanctuary inbox retention show` | read-only | n/a | src/cli/inbox.ts | 35 |
| `sanctuary inbox snooze` | mutator | yes | src/cli/inbox.ts | 40 |
| `sanctuary policy compile` | read-only | n/a | src/cli/policy.ts | 72 |
| `sanctuary policy drafts activate` | mutator | **NO** | src/cli/policy.ts | 238 |
| `sanctuary policy drafts check-conflicts` | read-only | n/a | src/cli/policy.ts | 235 |
| `sanctuary policy drafts list` | read-only | n/a | src/cli/policy.ts | 212 |
| `sanctuary policy drafts show` | read-only | n/a | src/cli/policy.ts | 224 |
| `sanctuary secrets add` | mutator | yes | src/cli/secrets.ts | 61 |
| `sanctuary secrets audit` | read-only | n/a | src/cli/secrets.ts | 73 |
| `sanctuary secrets delete` | mutator | yes | src/cli/secrets.ts | 67 |
| `sanctuary secrets grant` | mutator | yes | src/cli/secrets.ts | 69 |
| `sanctuary secrets list` | read-only | n/a | src/cli/secrets.ts | 63 |
| `sanctuary secrets revoke` | mutator | yes | src/cli/secrets.ts | 71 |
| `sanctuary secrets rotate` | mutator | yes | src/cli/secrets.ts | 65 |
| `sanctuary sentinel findings` | read-only | n/a | src/cli/sentinel.ts | 66 |
| `sanctuary sentinel list` | read-only | n/a | src/cli/sentinel.ts | 58 |
| `sanctuary sentinel list-subscribed` | read-only | n/a | src/cli/sentinel.ts | 60 |
| `sanctuary sentinel subscribe` | mutator | **NO** | src/cli/sentinel.ts | 62 |
| `sanctuary sentinel unsubscribe` | mutator | **NO** | src/cli/sentinel.ts | 64 |
| `sanctuary task assign` | mutator | yes | src/cli/task.ts | 45 |
| `sanctuary task cancel` | mutator | yes | src/cli/task.ts | 47 |
| `sanctuary task create` | mutator | yes | src/cli/task.ts | 37 |
| `sanctuary task list` | read-only | n/a | src/cli/task.ts | 39 |
| `sanctuary task show` | read-only | n/a | src/cli/task.ts | 41 |
| `sanctuary task update` | mutator | yes | src/cli/task.ts | 43 |
| `sanctuary template init` | mutator | **NO** | src/templates/cli.ts | 43 |
| `sanctuary template list` | read-only | n/a | src/templates/cli.ts | 41 |
