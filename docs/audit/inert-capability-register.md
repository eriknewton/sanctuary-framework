# Inert Capability Register

Status date: 2026-08-07. All 32 entries are **open**.

This is the public register behind every "Open defect: **IC-nn**" marker in the
Sanctuary README, roadmap, changelog, release notes, blog posts, and compliance
pages. It exists so a reader who is told a capability is bounded can look up
exactly which capability, where it stops, and what an operator sees instead.

## What "inert" means here

A capability is inert when a user can reach it, or a public claim depends on it,
and its enforcement or effect has **no consumer in shipping code**. The
definition is deliberately narrow:

- An honestly labelled stub that no user can reach was not counted.
- A capability whose only consumer is a test **was** counted, because a test is
  not a user.

Of the 32 entries, 17 carry HIGH claim risk, meaning a public artifact, a shipped
document, an operator-facing message, or an `ASSURANCE_MATRIX.md` row asserts the
capability. 13 are MEDIUM and 2 are LOW.

The three claims taking the most damage are ours, and all three are named in the
[Assurance Matrix](../../ASSURANCE_MATRIX.md):

- **Linux egress enforcement** was rated `proven`. Four findings (IC-02, IC-03,
  IC-04, IC-19) show the shipping Linux daemon installs no kernel enforcement at
  all. That row now reads `not_implemented`.
- **Tamper-evident audit chain** asserts signed checkpoints. No shipping path
  supplies a checkpoint signer, so every checkpoint on every install is written
  `unsigned: true` (IC-05, IC-06).
- **Export / exit bundle** is undermined three ways: the dashboard export path
  produces permanently unopenable state, the import path silently drops entries,
  and any fortress that has ever rotated its identity key loses all pre-rotation
  state on import (IC-07, IC-08, IC-09).

The macOS Castle Wall row was not changed by this wiring sweep. Its proof
remains the drill evidence named in the Assurance Matrix.

## What the sweep did not examine

This was a wiring sweep: it asked, for each capability, whether a shipping caller
exists. It did not audit cryptographic correctness, concurrency, or crash
consistency.

Bound of this result: the sweep did not identify those defect classes in the
wiring paths it examined. It does not establish implementation soundness, and no
separate cryptographic or security review has been run for this register.

Two findings are inference rather than observation, and are marked as such below:
IC-01 (macOS paused-flow semantics) and IC-03 (systemd `Type=notify` timeout
semantics). No Linux host was used. Settling IC-02 and IC-04 completely means
running the released binary on Linux and checking whether
`nft list table inet sanctuary-castle` shows a table.

## Register

| ID | Subsystem | What is inert | Anchor site | What the operator sees instead | Risk |
|---|---|---|---|---|---|
| IC-01 | castle-wall-macos | `disposition: prompt` rules are admitted by the signed-manifest gate with no resolution path | `castle-wall-macos/Sources/CastleWallFilter/SignedManifestVerification.swift:366` | The flow pauses, the operator answers, the extension discards the answer, and the CLI prints "approved (once)". Paused-flow semantics are an inference from standard macOS filter behavior; the discarded decision is proven either way | HIGH |
| IC-02 | castle-wall-linux | Daemon boot installs no kernel enforcement: no nftables table, no NFQUEUE binding, no cgroup scope | `castle-wall-daemon/src/daemon.rs:414` | A running root daemon that filters nothing, while the CLI prints "listening" and "producer-signed close ACTIVE" | HIGH |
| IC-03 | castle-wall-linux | Shipped systemd unit is `Type=notify`; the daemon never sends `READY=1` | `castle-wall-daemon/systemd/sanctuary-castle-wall.service:9` | The one documented Linux activation path cannot reach `active`. It fails closed. Timeout behavior is standard systemd semantics, inferred | HIGH |
| IC-04 | castle-wall-linux | `evaluate_attempt`, the deny-by-default core, has no caller in the shipping binary | `castle-wall-daemon/src/daemon.rs:139` | Every Linux policy decision is implemented, unit-tested, and never invoked. The write-ahead log carries only `daemon_started` | HIGH |
| IC-05 | audit-chain | Checkpoints are never signed in production; the verifier's signature leg is dead | `server/src/operational/audit-log.ts:5723` | `audit-chain verify` reports PASS and claims it checked Ed25519 signatures that do not exist | HIGH |
| IC-06 | audit-chain | `audit-chain verify --no-strict` returns PASS on a tampered chain (both ternary arms are `"PASS"`) | `server/src/cli/audit-chain-verify.ts:516` | An auditor sees `verdict: PASS` and exit 0 with real hash-mismatch findings sitting in the findings array | HIGH |
| IC-07 | exit-path | Dashboard export omits `mintStateRekeyKey`, so exported state can never be re-keyed | `server/src/dashboard/v1_1/wiring.ts:705` | A signed, verifying bundle whose encrypted state is permanently unopenable elsewhere, while the UI says "Re-key complete." | HIGH |
| IC-08 | exit-path | Import's three skipped-entry counters are never printed in human output, and a non-zero count raises no warning | `server/src/exit/cli.ts:836` | The operator sees PASS and a positive imported count while entries were discarded | HIGH |
| IC-09 | exit-path | `rotation_history` is exported into every bundle and never read at import | `server/src/exit/bundle.ts:1401` | Any fortress that ever rotated its key loses all pre-rotation state on import, with verdict PASS and exit 0 | HIGH |
| IC-10 | federation-mesh | M-of-N guardian sign-off on node revocation has no production setter | `server/src/principal-policy/dashboard.ts:3004` | Guardian quorum before a fleet node is killed cannot be enabled on any fortress; roughly 1900 lines are unreachable | HIGH |
| IC-11 | dashboard-wiring | Fortress lockdown locks nothing, yet reports success | `server/src/dashboard/v1_1/wiring.ts:678` | The operator is told "Lockdown ON", an `engaged` audit entry is written, and `active:true` is persisted, while nothing anywhere gates on lockdown state. There is no lift path | HIGH |
| IC-12 | dashboard-wiring | `inbox` and `agent_status` SSE events have no producer, and there is no periodic refetch | `server/src/principal-policy/dashboard.ts:525` | The dashboard never self-refreshes. Five of six inbox sources and all status changes go stale silently | HIGH |
| IC-13 | policy-gates | `EnglishPolicyActivator` is never constructed in any boot path | `server/src/dashboard/v1_1/wiring.ts:647` | The plain-English policy panel never renders, and "Always allow" always fails with a 503 | HIGH |
| IC-14 | policy-gates | `approval_channel.type`, `webhook_url`, and `webhook_secret` in `principal-policy.yaml` select nothing | `server/src/index.ts:1052` | A regulator-facing EU AI Act statement prints an approval channel the server is not running, and misreports on the default install | HIGH |
| IC-15 | memory-sdw | `createSdwTools` (vault export, import, delete) has zero callers and is tree-shaken out of `dist` | `server/src/sdw/tools.ts:184` | No shipped surface can export the sovereign memory vault. This is the one finding that breaches the repo's own never-persist-what-the-user-cannot-export rule | HIGH |
| IC-16 | memory-sdw | The multi-agent memory isolation guard can never fire, because no shipped path sets `SANCTUARY_AGENT_ID` in the server's own process environment | `server/src/sdw/memory-tools.ts:217` | Two wrapped agents on one host read and write each other's passages | HIGH |
| IC-17 | cli-surface | `dashboard --multi` drops the `--allow-plaintext-remote` guard and the `auto` token mint | `server/src/cli.ts:736` | The documented `--multi --host 0.0.0.0` invocation binds every tenant's metadata in plaintext and unauthenticated | HIGH |
| IC-18 | castle-wall-macos | The `agent_runtime_port_range` read site returns `.agent` on both branches | `castle-wall-macos/Sources/CastleWallFilter/OriginClassifier.swift:244` | A validated, signed, operator-set port range has zero effect, with no warning anywhere | MED |
| IC-19 | castle-wall-linux | The daemon logs and discards `decision_response` and never originates `decision_request` | `castle-wall-daemon/src/ipc/server.rs:658` | There is no operator-approval loop on Linux in either direction, and `sanctuary castle-wall approve` is unguarded by platform | MED |
| IC-20 | audit-chain | `cortex-export run` reads only the operator `_audit` chain | `server/src/cli/cortex-export.ts:369` | On an armed root-daemon host it exports zero enforcement events, reports `ok: true`, and advances its cursor | MED |
| IC-21 | federation-mesh | The Mesh Health panel has no producer; the detector and bridge are never constructed | `server/src/principal-policy/dashboard-html.ts:1723` | The panel shows "Waiting for mesh health data…" forever, so split-brain and audit-loss alerts never reach an operator | MED |
| IC-22 | federation-mesh | Sync transports audit batches; the receiver counts and discards them | `server/src/mesh/lifecycle/sync.ts:225` | A rejoining node never backfills the missed audit range, because `since_audit_seqs` is hardcoded `{}` on send | MED |
| IC-23 | dashboard-wiring | The export result returned by the server is discarded by the client and replaced with a placeholder | `server/src/dashboard/v1_1/client.ts:3487` | The operator sees "Bundle dir: (see activity feed)" and an empty hash, and cannot verify or locate the bundle | MED |
| IC-24 | dashboard-wiring | The Tier-1 fortress-export approval card renders `[unrecognized template: ...]` | `server/src/dashboard/v1_1/client.ts:374` | The operator approves an irreversible full-fortress export from a card that describes nothing | MED |
| IC-25 | policy-gates | The `sanctuary/sign_erc8004_identity` approval resolver has no production caller | `server/src/key-17/erc8004-tools.ts:251` | Every request parks forever, and the CLI points at an inbox card that is never created | MED |
| IC-26 | policy-gates | `agents config` claims changes take effect on the next gate request; policy is frozen at boot | `server/src/cli/agents/cli.ts:521` | Redirect flips and any hand-tightened tier stay inert against the running gate until restart | MED |
| IC-27 | memory-sdw | `sdw_import`'s only transactional backend is never instantiated | `server/src/sdw/import.ts:277` | Import would fail closed with `storage_not_transactional` every time, so the advertised atomicity never runs | MED |
| IC-28 | memory-sdw | `sdw_memory_provenance` is unguarded and, uniquely among reads, unaudited | `server/src/sdw/memory-provenance-tool.ts:108` | A successful vault read leaves no audit record. This one is live on main today | MED |
| IC-29 | cli-surface | `auto-trigger rules set-threshold --warn-sigma/--alert-sigma` persist values no detector reads | `server/src/cli/auto-trigger.ts:403` | The operator retunes detection sensitivity and gets an audit entry saying so, while the sentinels keep their compiled-in sigma | MED |
| IC-30 | cli-surface | `--fortress=<path>` is silently dropped by five verb families, and `federation join --persist` writes to the default fortress | `server/src/cli/federation.ts:261` | A foreign federation trust root lands in `~/.sanctuary` and the verb reports success. The affected verbs are `federation`, `inbox`, `task`, `concierge`, and `agents` | MED |
| IC-31 | castle-wall-macos | The host app parses `--ttl=` and `--no-ttl` and stores them unread | `castle-wall-macos/Sources/CastleWallHostApp/HeadlessFilterCLI.swift:139` | Dead fields only. TTL enforcement genuinely happens in `ArmLease.swift:41`. The parse arms are still required by `sanctuary castle-wall enable`, so removing them would break that verb | LOW |
| IC-32 | audit-chain | The P1 audit-tamper alert file has no reader, and the subscriber hook has no supplier | `server/src/operational/audit-log.ts:5784` | A redundant path only. The condition is already surfaced by the router, the dashboard, and `doctor`. The real cost is unbounded file growth | LOW |

## Two corrections the sweep made to its own findings

Recorded so this register is not trusted more than it should be.

- **IC-31 and IC-32 are cleanup, not capability gaps.** Both were originally
  filed with stronger consequences than the evidence supports. IC-31's TTL is
  enforced elsewhere, and IC-32's operator-notification outcome is delivered by
  three working paths.
- **IC-30's headline was overcounted.** The original claim named seven verbs.
  `audit.ts` handles both flag spellings correctly and `rotate-master.ts` fails
  loudly on the unknown flag, so the real silent-drop set is five.

## One candidate that was refuted

A suspected finding held that `scope.agent_ids` and `scope.template_ids` could
never match a real flow, on the theory that the only `AgentResolver` in the tree
is a placeholder stub. That is false. The matching consumer is real and is fed by
a real producer: `castle-wall-macos/Sources/CastleWallFilter/AllowlistEvaluator.swift:205`,
supplied by `server/src/castle-wall/observe/synthesize.ts:193` via
`server/src/castle-wall/runtime/macos-flow-events.ts:440`. Agent-scoped allowlist
rules do match real flows on macOS.

This matters more than it looks. It is the scoping mechanism underneath the
per-uid allow/deny enforcement demonstration that closed the enforcement thesis
gate on 2026-06-15. Had it been inert, the macOS Castle Wall row in the Assurance
Matrix would have been in question. It is not.

Within this wiring sweep, every candidate resolved to confirmed-inert or
refuted.

## Related

- [`ASSURANCE_MATRIX.md`](../../ASSURANCE_MATRIX.md), the single source of truth
  for what is proven, on which platform, with what bounds.
- [`ROADMAP.md`](../../ROADMAP.md), which carries the per-mechanism status these
  entries bound.
- [`unified-protect-enforcement-status.md`](unified-protect-enforcement-status.md),
  the honesty ledger for the exclusive-egress enforcement core.
