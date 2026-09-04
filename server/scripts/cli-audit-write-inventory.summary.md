# CLI Audit-Write Completeness Inventory

Generated: 2026-09-03T19:48:36.443Z

## Summary

| Metric | Count |
|--------|-------|
| Total CLI subcommands inventoried | 82 |
| Mutators | 41 |
| Read-only | 41 |
| Pure-UI | 0 |
| **Mutators that do NOT audit (Batch 5b targets)** | **1** |
| Uncertain (operator review needed) | 0 |

## Mutators Missing Audit (Batch 5b Targets)

- `sanctuary identity create` (src/cli/identity.ts:100)
  mints + persists a new Ed25519 identity via IdentityManager.saveNew; no AuditLog call anywhere in that path (gap recorded, not silently classified read-only)

## Full Inventory

| Subcommand | Classification | Audits? | File | Line |
|------------|---------------|---------|------|------|
| `sanctuary agents config` | mutator | yes | src/cli/agents/cli.ts | 139 |
| `sanctuary agents list` | read-only | n/a | src/cli/agents/cli.ts | 129 |
| `sanctuary agents show` | read-only | n/a | src/cli/agents/cli.ts | 135 |
| `sanctuary agents status` | read-only | n/a | src/cli/agents/cli.ts | 137 |
| `sanctuary anomaly classifier-state` | read-only | n/a | src/cli/anomaly.ts | 91 |
| `sanctuary anomaly detectors` | read-only | n/a | src/cli/anomaly.ts | 76 |
| `sanctuary anomaly findings` | read-only | n/a | src/cli/anomaly.ts | 89 |
| `sanctuary anomaly list-subscribed` | read-only | n/a | src/cli/anomaly.ts | 78 |
| `sanctuary anomaly status` | read-only | n/a | src/cli/anomaly.ts | 79 |
| `sanctuary anomaly subscribe` | mutator | yes | src/cli/anomaly.ts | 81 |
| `sanctuary anomaly unsubscribe` | mutator | yes | src/cli/anomaly.ts | 87 |
| `sanctuary auto-trigger cancel` | mutator | yes | src/cli/auto-trigger.ts | 80 |
| `sanctuary auto-trigger recommendations accept` | mutator | yes | src/cli/auto-trigger.ts | 171 |
| `sanctuary auto-trigger recommendations list` | read-only | n/a | src/cli/auto-trigger.ts | 136 |
| `sanctuary auto-trigger recommendations reject` | mutator | yes | src/cli/auto-trigger.ts | 190 |
| `sanctuary auto-trigger recommendations show` | read-only | n/a | src/cli/auto-trigger.ts | 154 |
| `sanctuary auto-trigger rules demote` | mutator | yes | src/cli/auto-trigger.ts | 234 |
| `sanctuary auto-trigger rules list` | read-only | n/a | src/cli/auto-trigger.ts | 136 |
| `sanctuary auto-trigger rules promote` | mutator | yes | src/cli/auto-trigger.ts | 232 |
| `sanctuary auto-trigger rules set-threshold` | mutator | yes | src/cli/auto-trigger.ts | 236 |
| `sanctuary auto-trigger rules show` | read-only | n/a | src/cli/auto-trigger.ts | 154 |
| `sanctuary checkpoint create` | mutator | yes | src/cli/checkpoint.ts | 222 |
| `sanctuary checkpoint list` | read-only | n/a | src/cli/checkpoint.ts | 228 |
| `sanctuary checkpoint prune` | mutator | yes | src/cli/checkpoint.ts | 240 |
| `sanctuary checkpoint restore` | mutator | yes | src/cli/checkpoint.ts | 246 |
| `sanctuary checkpoint show` | read-only | n/a | src/cli/checkpoint.ts | 234 |
| `sanctuary concierge ask` | read-only | n/a | src/cli/concierge.ts | 54 |
| `sanctuary concierge status` | read-only | n/a | src/cli/concierge.ts | 55 |
| `sanctuary did-web issue` | mutator | yes | src/cli/did-web.ts | 146 |
| `sanctuary did-web key-history` | read-only | n/a | src/cli/did-web.ts | 159 |
| `sanctuary did-web register-hosted` | mutator | yes | src/cli/did-web.ts | 162 |
| `sanctuary did-web rotate-key` | mutator | yes | src/cli/did-web.ts | 156 |
| `sanctuary did-web show` | read-only | n/a | src/cli/did-web.ts | 153 |
| `sanctuary erc8004 register` | mutator | yes | src/cli/erc8004.ts | 112 |
| `sanctuary erc8004 status` | read-only | n/a | src/cli/erc8004.ts | 115 |
| `sanctuary exit export` | mutator | yes | src/exit/cli.ts | 859 |
| `sanctuary exit inspect` | read-only | n/a | src/exit/cli.ts | 792 |
| `sanctuary exit manifest-shape` | read-only | n/a | src/exit/cli.ts | 661 |
| `sanctuary file-grant list` | mutator | yes | src/cli/file-grant.ts | 203 |
| `sanctuary file-grant mint` | mutator | yes | src/cli/file-grant.ts | 197 |
| `sanctuary file-grant revoke` | mutator | yes | src/cli/file-grant.ts | 209 |
| `sanctuary honeypot compile` | read-only | n/a | src/honeypot/cli.ts | 138 |
| `sanctuary honeypot credential-traps` | read-only | n/a | src/honeypot/cli.ts | 274 |
| `sanctuary honeypot deploy` | mutator | yes | src/honeypot/cli.ts | 187 |
| `sanctuary honeypot findings` | read-only | n/a | src/honeypot/cli.ts | 334 |
| `sanctuary honeypot list` | read-only | n/a | src/honeypot/cli.ts | 221 |
| `sanctuary honeypot tool-traps` | read-only | n/a | src/honeypot/cli.ts | 238 |
| `sanctuary honeypot undeploy` | mutator | yes | src/honeypot/cli.ts | 311 |
| `sanctuary identity create` | mutator | **NO** | src/cli/identity.ts | 100 |
| `sanctuary identity show` | read-only | n/a | src/cli/identity.ts | 92 |
| `sanctuary inbox approvals approve` | mutator | yes | src/cli/inbox.ts | 195 |
| `sanctuary inbox approvals list` | read-only | n/a | src/cli/inbox.ts | 33 |
| `sanctuary inbox archive` | mutator | yes | src/cli/inbox.ts | 37 |
| `sanctuary inbox dismiss` | mutator | yes | src/cli/inbox.ts | 38 |
| `sanctuary inbox retention set` | mutator | yes | src/cli/inbox.ts | 162 |
| `sanctuary inbox retention show` | read-only | n/a | src/cli/inbox.ts | 35 |
| `sanctuary inbox snooze` | mutator | yes | src/cli/inbox.ts | 40 |
| `sanctuary policy compile` | read-only | n/a | src/cli/policy.ts | 92 |
| `sanctuary policy drafts activate` | mutator | yes | src/cli/policy.ts | 317 |
| `sanctuary policy drafts check-conflicts` | read-only | n/a | src/cli/policy.ts | 314 |
| `sanctuary policy drafts list` | read-only | n/a | src/cli/policy.ts | 291 |
| `sanctuary policy drafts show` | read-only | n/a | src/cli/policy.ts | 303 |
| `sanctuary secrets add` | mutator | yes | src/cli/secrets.ts | 97 |
| `sanctuary secrets audit` | read-only | n/a | src/cli/secrets.ts | 109 |
| `sanctuary secrets delete` | mutator | yes | src/cli/secrets.ts | 103 |
| `sanctuary secrets grant` | mutator | yes | src/cli/secrets.ts | 105 |
| `sanctuary secrets list` | read-only | n/a | src/cli/secrets.ts | 99 |
| `sanctuary secrets revoke` | mutator | yes | src/cli/secrets.ts | 107 |
| `sanctuary secrets rotate` | mutator | yes | src/cli/secrets.ts | 101 |
| `sanctuary sentinel findings` | read-only | n/a | src/cli/sentinel.ts | 66 |
| `sanctuary sentinel list` | read-only | n/a | src/cli/sentinel.ts | 58 |
| `sanctuary sentinel list-subscribed` | read-only | n/a | src/cli/sentinel.ts | 60 |
| `sanctuary sentinel subscribe` | mutator | yes | src/cli/sentinel.ts | 62 |
| `sanctuary sentinel unsubscribe` | mutator | yes | src/cli/sentinel.ts | 64 |
| `sanctuary task assign` | mutator | yes | src/cli/task.ts | 46 |
| `sanctuary task cancel` | mutator | yes | src/cli/task.ts | 48 |
| `sanctuary task create` | mutator | yes | src/cli/task.ts | 38 |
| `sanctuary task list` | read-only | n/a | src/cli/task.ts | 40 |
| `sanctuary task show` | read-only | n/a | src/cli/task.ts | 42 |
| `sanctuary task update` | mutator | yes | src/cli/task.ts | 44 |
| `sanctuary template init` | mutator | yes | src/templates/cli.ts | 56 |
| `sanctuary template list` | read-only | n/a | src/templates/cli.ts | 54 |
