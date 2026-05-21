# CLI Audit-Write Completeness Inventory

Generated: 2026-05-21T21:02:10.724Z

## Summary

| Metric | Count |
|--------|-------|
| Total CLI subcommands inventoried | 69 |
| Mutators | 33 |
| Read-only | 36 |
| Pure-UI | 0 |
| **Mutators that do NOT audit (Batch 5b targets)** | **0** |
| Uncertain (operator review needed) | 0 |

## Full Inventory

| Subcommand | Classification | Audits? | File | Line |
|------------|---------------|---------|------|------|
| `sanctuary agents config` | mutator | yes | src/cli/agents/cli.ts | 114 |
| `sanctuary agents list` | read-only | n/a | src/cli/agents/cli.ts | 108 |
| `sanctuary agents show` | read-only | n/a | src/cli/agents/cli.ts | 110 |
| `sanctuary agents status` | read-only | n/a | src/cli/agents/cli.ts | 112 |
| `sanctuary anomaly classifier-state` | read-only | n/a | src/cli/anomaly.ts | 87 |
| `sanctuary anomaly detectors` | read-only | n/a | src/cli/anomaly.ts | 77 |
| `sanctuary anomaly findings` | read-only | n/a | src/cli/anomaly.ts | 85 |
| `sanctuary anomaly list-subscribed` | read-only | n/a | src/cli/anomaly.ts | 79 |
| `sanctuary anomaly subscribe` | mutator | yes | src/cli/anomaly.ts | 81 |
| `sanctuary anomaly unsubscribe` | mutator | yes | src/cli/anomaly.ts | 83 |
| `sanctuary auto-trigger cancel` | mutator | yes | src/cli/auto-trigger.ts | 82 |
| `sanctuary auto-trigger recommendations accept` | mutator | yes | src/cli/auto-trigger.ts | 173 |
| `sanctuary auto-trigger recommendations list` | read-only | n/a | src/cli/auto-trigger.ts | 138 |
| `sanctuary auto-trigger recommendations reject` | mutator | yes | src/cli/auto-trigger.ts | 192 |
| `sanctuary auto-trigger recommendations show` | read-only | n/a | src/cli/auto-trigger.ts | 156 |
| `sanctuary auto-trigger rules demote` | mutator | yes | src/cli/auto-trigger.ts | 236 |
| `sanctuary auto-trigger rules list` | read-only | n/a | src/cli/auto-trigger.ts | 138 |
| `sanctuary auto-trigger rules promote` | mutator | yes | src/cli/auto-trigger.ts | 234 |
| `sanctuary auto-trigger rules set-threshold` | mutator | yes | src/cli/auto-trigger.ts | 238 |
| `sanctuary auto-trigger rules show` | read-only | n/a | src/cli/auto-trigger.ts | 156 |
| `sanctuary concierge ask` | read-only | n/a | src/cli/concierge.ts | 54 |
| `sanctuary concierge status` | read-only | n/a | src/cli/concierge.ts | 55 |
| `sanctuary did-web issue` | mutator | yes | src/cli/did-web.ts | 148 |
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
| `sanctuary policy compile` | read-only | n/a | src/cli/policy.ts | 75 |
| `sanctuary policy drafts activate` | mutator | yes | src/cli/policy.ts | 241 |
| `sanctuary policy drafts check-conflicts` | read-only | n/a | src/cli/policy.ts | 238 |
| `sanctuary policy drafts list` | read-only | n/a | src/cli/policy.ts | 215 |
| `sanctuary policy drafts show` | read-only | n/a | src/cli/policy.ts | 227 |
| `sanctuary secrets add` | mutator | yes | src/cli/secrets.ts | 61 |
| `sanctuary secrets audit` | read-only | n/a | src/cli/secrets.ts | 73 |
| `sanctuary secrets delete` | mutator | yes | src/cli/secrets.ts | 67 |
| `sanctuary secrets grant` | mutator | yes | src/cli/secrets.ts | 69 |
| `sanctuary secrets list` | read-only | n/a | src/cli/secrets.ts | 63 |
| `sanctuary secrets revoke` | mutator | yes | src/cli/secrets.ts | 71 |
| `sanctuary secrets rotate` | mutator | yes | src/cli/secrets.ts | 65 |
| `sanctuary sentinel findings` | read-only | n/a | src/cli/sentinel.ts | 67 |
| `sanctuary sentinel list` | read-only | n/a | src/cli/sentinel.ts | 59 |
| `sanctuary sentinel list-subscribed` | read-only | n/a | src/cli/sentinel.ts | 61 |
| `sanctuary sentinel subscribe` | mutator | yes | src/cli/sentinel.ts | 63 |
| `sanctuary sentinel unsubscribe` | mutator | yes | src/cli/sentinel.ts | 65 |
| `sanctuary task assign` | mutator | yes | src/cli/task.ts | 45 |
| `sanctuary task cancel` | mutator | yes | src/cli/task.ts | 47 |
| `sanctuary task create` | mutator | yes | src/cli/task.ts | 37 |
| `sanctuary task list` | read-only | n/a | src/cli/task.ts | 39 |
| `sanctuary task show` | read-only | n/a | src/cli/task.ts | 41 |
| `sanctuary task update` | mutator | yes | src/cli/task.ts | 43 |
| `sanctuary template init` | mutator | yes | src/templates/cli.ts | 50 |
| `sanctuary template list` | read-only | n/a | src/templates/cli.ts | 48 |
