# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## v1.1.2 - Hotfix (2026-04-26)

Hotfix release. Closes the v1.1.1 release-blocker (v1.1 dashboard, hub API, and `/api/identities` alias absent on the dashboard the operator hits during `sanctuary wrap`, Finding V) and persists the operator-supplied fortress path across harness restarts (Finding W). Strict superset of v1.1.1; operators on v1.1.1 should upgrade.

### Fixed

- **v1.1 routes absent on wrap-emitted dashboard (Finding V).** v1.1.1 mounted v1.1 dispatch on `principal-policy/dashboard.ts` (the standalone and MCP-server-boot dashboard) but missed the third dashboard caller. `cocoon/cli.ts:runWrap` starts `dashboard/server.ts` (the legacy operator dashboard the wrap-emitted URL hits). Operators following the documented wrap flow saw `/v1.1`, `/api/hub/*`, and `/api/identities` return 404 against the published binary. The hotfix extracts a shared dispatch helper at `server/src/dashboard/v1_1/dispatch.ts`, plumbs it into both dashboard servers, and wires the v1.1 bindings on the wrap-auto dashboard with a real master-key-derived `AuditLog` so the activity feed reads from the actual audit log, not a stub.

- **`sanctuary wrap --fortress <path>` not persisted to harness config (Finding W).** v1.1.1 honored the flag for the in-process operator dashboard but never wrote `SANCTUARY_FORTRESS_PATH` into the rewritten `~/.claude.json` env block. On harness restart, the spawned MCP server fell back to the default fortress location, silently breaking isolation. The hotfix persists the env var into the rewritten config when `--fortress` is set or `SANCTUARY_FORTRESS_PATH` is in the parent process env. The MCP server boot path also now promotes `SANCTUARY_FORTRESS_PATH` to `SANCTUARY_STORAGE_PATH` early in `cli.ts`, mirroring the existing wrap-time promotion at `cocoon/cli.ts:128-129`, so the persisted env reaches config resolution.

### Added

- **Pre-promote tarball smoke test.** `scripts/published-tarball-smoke-2026-04-26.sh` runs `npm pack` plus install-from-tarball plus curls `/v1.1`, `/api/hub/agents`, `/api/identities` against the actual to-be-published binary, then asserts `SANCTUARY_FORTRESS_PATH` is persisted in a test `.claude.json`. Discipline gap PR #82 demonstrated does not yet exist in CI; for v1.1.2 the operator runs locally pre-promote. Future work: wire into a release-engineering workflow.

- **Wrap-auto dashboard regression smoke suite.** Seven tests at `server/test/wrap/v1_1-routes-smoke.test.ts` boot the actual wrap-auto dashboard (not the standalone path that already had v1.1 routes) and curl every v1.1 endpoint plus the persistence assertion. Locks in the wiring at the entry point operators actually hit.

### Known follow-ups

- Coordination route handler `/api/coordination/*` and `publishV11Event` SSE producer extension remain in v1.1.x housekeeping (carried from v1.1.1 known follow-ups).
- Workflow `version` strict-string-compare (must pass `1.1.0` not `v1.1.0`) is v1.1.x housekeeping; one-line YAML edit in `.github/workflows/publish-on-tag.yml`.
- Node.js 20 actions cohort bump (`actions/checkout@v4`, `actions/setup-node@v4`, `actions/setup-python@v5`) before 2026-09-16 deadline.

## v1.1.1 - Hotfix (2026-04-26)

Hotfix release. Closes the v1.1.0 release-blocker (recovery key truncated on display, Finding U), wires the v1.1 dashboard, hub API, and exit bundle endpoints into the entry-point servers, and lands the fortress isolation flags that v1.1.0 advertised but silently ignored. Strict superset of v1.1.0; operators on v1.1.0 should upgrade.

### Fixed

- **Recovery key disclosure (Finding U).** v1.1.0 printed the recovery key truncated with a literal `...` and never persisted the plaintext anywhere, so any operator following the documented init flow ended up with an unrecoverable fortress on principal loss. The fix prints the full key in a dynamically-sized banner, writes the plaintext to `<fortress>/recovery-key.txt` mode 0600 with explicit "move off-host immediately" instructions (single-issuance, never overwritten on subsequent runs), and adds an interactive confirmation prompt on TTY callers (bypass via `--no-confirm` for CI, launchd, systemd). The MCP server stdio first-run path is non-interactive by definition (the host harness owns stdin) and discloses via banner plus file only.

- **`sanctuary wrap --fortress <path>` ignored (Finding T).** v1.1.0 silently ignored the `--fortress` flag, found the existing harness config, and updated the singleton at `~/.sanctuary` regardless. The flag is now respected end-to-end. Honors the `SANCTUARY_FORTRESS_PATH` env var as a secondary mechanism (lower priority than the flag, higher priority than the legacy `SANCTUARY_STORAGE_PATH`).

- **Re-wrap reports "0 MCP servers" (Finding B).** When the only existing entry was Sanctuary's own canonical wrap, re-wrap reported `MCP servers found: 0` because the canonical entry filters out before counting (so it doesn't get double-wrapped). Operators saw a "0" count next to a clearly-wrapped fortress and concluded wrap had nothing to do. The CLI now reports counts honestly: `MCP servers found: 1 Sanctuary entry (existing), N other servers` with proper pluralization.

- **`dashboard-standalone-v010-4.test.ts` developer-machine flake.** The test now overrides `HOME` during execution so it does not read from the developer's real `~/.sanctuary` directory. CI was unaffected (fresh runners). Developers running `npm test` locally on machines with a real wrapped fortress at `~/.sanctuary/default/` no longer see a spurious test-isolation failure.

### Added

- **`sanctuary init` subcommand.** New lightweight command that creates a fresh fortress at a chosen path without wrapping any agent harness. The drill needed this primitive to satisfy "stand up a side-by-side isolated fortress" guardrails (Finding S); v1.1.0 had no working primitive for that workflow because typing `sanctuary init` fell through to the stdio MCP server boot. Honors `--fortress <path>`, `--force` (overwrite a non-empty directory), `--no-confirm`, `SANCTUARY_FORTRESS_PATH`, and `SANCTUARY_STORAGE_PATH` (precedence: flag, FORTRESS env, STORAGE env, default `~/.sanctuary`). The first-run banner uses the same disclosure surface as `wrap` and the standalone dashboard.

- **v1.1 server route wiring.** v1.1.0 shipped the v1.1 module suite (dashboard, hub API, exit bundle endpoints, coordination endpoints) but no entry-point server imported them, so operators saw only the legacy v1.0 surface after install. The hotfix mounts v1.1 additively at `/v1.1` (legacy stays at `/`) on both `dashboard-standalone.ts` and the embedded `principal-policy/dashboard.ts`. Hub API at `/api/hub/*` (agents, inbox, fortress exit-bundle, policy and budget summaries, activity feed). Activity feed reads from the real audit log; agent registry, inbox sources, and policy / budget summaries start empty and light up as v1.2 wires their data planes. Agent controller surfaces a typed capability error rather than lying about pause / unwrap / lockdown. Default-route flip from `/` to `/v1.1` is deferred to v1.2.

- **`/api/identities` back-compat alias (Finding E).** Returns the same response shape as `/api/hub/agents` so existing operator scripts targeting the pre-v1.1 endpoint name keep working through the upgrade. Preserves query-string filters. Same auth contract as the hub API.

### Known follow-ups

- Coordination route handler `/api/coordination/*` is queued in v1.1.x housekeeping. The `LocalCoordinator` class is fully tested but operator-facing routes are not yet built.
- `publishV11Event` SSE producer extension is queued in v1.1.x housekeeping. Hub events do not yet fan out to `/api/stream` consumers in real time; the dashboard polls instead.
- Pre-existing CLI em-dash sweep in `server/src/cli.ts` continues as v1.0.2 (k); some sites already swept in PR #76 and PR #80, residual sites tracked separately.

## v1.1.0 — Local Sovereignty Harness (2026-04-25)

Sanctuary v1.1 ships the complete Local Sovereignty Harness for running and governing AI agents on operator-owned hardware. v1.1.0 is the first stable release on the 1.x line and the first that pilots can install to `latest` for production use. v1.0.0 GA tag is intentionally skipped (1.0.0-rc.2 was the precursor; 1.1.0 is a strict superset).

The release adds four new pillars on top of v0.10.6 / v1.0.0-rc.2: query privacy enforcement, an operator hub API, internal agent coordination with signed handoffs, and durable portable exit bundles with a standalone verifier. A v1.1 sovereignty dashboard renders the four pillars as a single operator control surface. A harness compatibility matrix locks in v1.0/v1.1 wrap behavior for OpenClaw, Hermes, Claude Code, Cursor, Cline, and generic MCP. An acceptance drill suite covers the four pillars end-to-end against real fortresses. A pre-tag security wave closes three Sanctuary-invariant violations, runtime-validates the Sanctuary-Concordia bridge boundary, and adds a permanent canonical-JSON parity test guarding the bridge contract.

### Added

- **v1.1 contracts** (PR #67): scope-lock contract types under `server/src/contracts/v1.1/` covering privacy events, hub events, local agent records, handoff records, and exit bundle manifest body. Every signed shape pins `signature_scheme: "ed25519-v1"` inside the signed bytes (substitution-resistance invariant). The contracts are the shared spine the rest of v1.1 builds against.

- **Query privacy core** (PR #69): `LocalPrivacyEngine` at `server/src/l2-operational/privacy-core.ts` with `filterOutbound` and `rehydrateResponse`. Recursive bounded sensitive-span detection. Fortress-keyed HMAC content hashes via HKDF info string `sanctuary-v1.1-privacy-content-hmac`. Encrypted placeholder vault. Five destination categories (`inference`, `tool-api`, `logging`, `analytics`, `peer-agent`, `custom`). Five-kind audit-payload union (`allowed`, `filtered`, `denied`, `error`, `rehydrated`). Fail-closed semantics with explicit operator overrides.

- **Remote-bound privacy enforcement** (PR #71): proxy router chokepoint at `server/src/proxy/proxy-router.ts` Step 3.5 routes every outbound proxied tool call through the privacy engine. Activation-gated on hub policy resolver wiring; production behavior unchanged until operator binds a privacy policy. Fourteen magic-string-wire-byte tests confirm the chokepoint runs on the production code path.

- **Operator hub API** (PR #73): eleven routes under `/api/hub/` covering unified inbox (six discriminated-union event kinds: approval-pending, blocked egress, privacy event, budget warning, recovery prompt, agent error), local agent registry (list, get, status snapshot), agent control (pause / resume / restart / unwrap / lockdown / change template / change policy), policy summaries, budget summaries, and the activity feed (read-side projection over the audit chain). Tier 1 control actions (`unwrap`, `lockdown`, `policy_change`) defer to the inbox via `enqueueTier1ControlAction` and only fire the controller call after the operator approves the inbox item (operator-confirms-twice). Defense-in-depth cross-fortress rejection at both router (`rejectCrossFortressParams`) and service (`assertLocalOnlyFilter`) layers.

- **Internal agent coordination** (PR #72): five-state local handoff lifecycle (`created -> accepted -> completed`, with branches `accepted -> denied`, `accepted -> failed`, `created -> denied`) under `server/src/coordination/`. Two-layer signing: Layer 1 handoff record signed by the sender agent's identity key; Layer 2 audit payload signed by the actor (sender / recipient / policy-gate). Every signature uses `Omit<…, "signature">` typing on the input so the signature field is structurally absent during canonicalization. Optional policy gate adapter for capability-based handoff filtering. Non-Concordia-dependency invariant guarded by a structural import-graph test.

- **Exit bundle and verifier** (PR #70): durable signed export of fortress state, identity, audit history, policy set, reputation attestations, and placeholder vault metadata under `server/src/exit/`. Manifest format `SANCTUARY_EXIT_BUNDLE_V1` with eight path-safety rules enforced at write and verify. Standalone verifier CLI (`sanctuary exit verify`) runs out-of-process; the dashboard displays the verifier command, never invokes it in-process (the cross-process trust boundary is part of the sovereignty story). Re-key on import via `sourcePassphrase` flow; default `conflictResolution: "skip"` blocks silent overwrite.

- **Harness compatibility matrix** (PR #74): formal `server/docs/harness-compatibility-matrix.md` plus 21 fixtures and smoke tests covering OpenClaw, Hermes, Claude Code, Cursor, Cline, and generic MCP wrap behavior. Documents the lazy-init pattern: `sanctuary wrap` configures the harness adapter and persists the passphrase but does NOT create the Ed25519 identity or audit-log genesis; those happen on first cocoon-unlock when the master key derives.

- **Sovereignty Dashboard v1.1** (PR #75): server-rendered HTML with embedded ES module client at `server/src/dashboard/v1_1/`. Renders unified inbox (six event kinds with capability-gated actions), local agent registry, activity feed, privacy panel (safe-metadata-only render of `PrivacyAuditPayload`), exit drill wizard (six steps mapping to backend operations, verifier displayed as CLI command not invoked in-process), Tier 1 approval flow rendered honestly (no optimistic flips). SSE-driven live updates via `/api/stream`. Out-of-scope screens hidden from sidebar nav: federation (v1.3), composition (v1.4+ adapter), full recovery management (v1.2+).

- **Fortress-level Tier 1 endpoints** (PR #77): `POST /api/hub/fortress/lockdown` and `POST /api/hub/fortress/exit-bundle/export`. Each creates a single inbox item; on operator approval the handler iterates per-agent (lockdown) or runs `exportExitBundle()` once at fortress scope (export). Routing-layer sentinel alias maps the dashboard's `/api/hub/agents/all/lockdown` and `/api/hub/agents/all/exit-bundle/export` call paths to the canonical `/fortress/*` handlers. Closes Dashboard Backend Binding Addendum §8.1.

- **v1.1 acceptance drill suite** (PR #78): four drills under `server/test/drills/` mirroring the four acceptance pillars:
  - `v1.1-privacy-drill.test.ts`: outbound query containing PII, secrets, project, and client identifiers is filtered, audited safely (no raw spans in the audit payload), and rehydrated only when policy permits. Fail-closed sub-drill verifies missing-policy denial, oversized-payload denial, and operator-override permit-with-audit-trail.
  - `v1.1-coordination-drill.test.ts`: two-agent local handoff completes propose -> accept -> complete with verified Layer 1 record signatures and Layer 2 audit-payload signatures at every stage. Policy-gate sub-drill verifies deny short-circuits handoff creation. Non-Concordia-dependency sub-drill carries the structural import-graph crawl so the invariant cannot regress under acceptance review.
  - `v1.1-hub-drill.test.ts`: pause + resume run synchronously; fortress-wide Tier 1 lockdown via `/api/hub/fortress/lockdown` returns 202 + inbox item, defers controller invocation, and lands the lockdown only after the operator approves via the inbox (operator-confirms-twice). Privacy event surfaces under `category=privacy` in the activity feed; cross-fortress query parameter rejected with `HubLocalOnlyError` 422; unauthenticated request rejected with 401.
  - `v1.1-exit-drill.test.ts`: source fortress with state, reputation, and audit history exports a SANCTUARY_EXIT_BUNDLE_V1 via the Tier 1 hub fortress endpoint; the operator-facing `sanctuary exit verify` CLI passes; tampering one byte fails with a non-zero exit code; injecting `..` in an artifact path fails with `failure_class: "artifact_path_unsafe"`; a fresh destination fortress imports + re-keys; re-import without explicit overwrite refuses to overwrite previously-imported state.

- **Cross-language canonical-JSON parity test** (PR #80, fix #18): new test at `server/test/integration/canonical-json-parity.test.ts` plus `sidecars/concordia/test-canonical-parity.py`. Twenty-four fixtures cover nesting, key ordering, integers, Unicode (Greek, CJK, emoji), escape sequences, null vs absent, signed-event shapes, and sort stability. Asserts byte-identical output between TypeScript `canonicalize()` and Python `canonical_json`. The test is the permanent guard on the Sanctuary-Concordia bridge contract that CLAUDE.md flags as Known Complexity #1 (highest-risk interop surface). All 24 fixtures parity-clean on first execution.

- **Runtime shape validation on Sanctuary-Concordia bridge** (PR #80, fixes #1 + #8): new helper at `server/src/composition/assert-shape.ts` with runtime validators for sidecar JSON-RPC responses (`packConcordiaReceipt`, `verifyConcordiaReceipt`, `verifyMandate`). Malformed `receipt_id` (non-string), `signature` (null), missing fields, and extra fields all throw `SidecarResponseShapeError` before the result reaches L3/L4 commit-and-sign. The seven `agent-contract/schema.ts` validator paths refactored from `as unknown as AgentCardX` casts to explicit object literals; manual field guards above the cast are preserved, but the cast that bypassed tsc narrowing is gone.

### Changed

- **Privacy filter fail-closed default** (PR #80, fix #2). `fail_mode` default changed from `"fallback"` to `"closed"` in BOTH `server/src/config.ts` `defaultConfig()` and `server/src/l2-operational/context-gate-tools.ts:68`. Operators on default config now get fail-closed semantics on OPF subprocess failure; explicit opt-in required for graceful-fallback behavior. **Behavior change.** Operators relying on the previous default need to set `fail_mode: "fallback"` explicitly if they want it. Closes Sanctuary Invariant #5 violation surfaced by the Quality Report.

- **Denial messages redacted at gate boundary** (PR #80, fix #3). `server/src/principal-policy/gate.ts` redaction implemented at the single GateResult return site. Agent-facing denials now read `Tier ${tier} operation requires approval` instead of the previous detailed reasons that included `frequency_spike_multiplier`, `callRate`, `avgRate`, and bulk-read thresholds. The audit log STILL captures detailed reasons for the operator and the approval channel (which the operator authenticates to). Future denial paths inherit redaction automatically. Closes Sanctuary Invariant #7 violation (agent enumeration of policy thresholds).

- **Config structural validation before cast** (PR #80, fix #4). `assertSanctuaryConfigShape()` runs after `deepMerge()` and validates required object keys before the `as unknown as SanctuaryConfig` cast at `server/src/config.ts:407`. A malformed config file with missing required sections or wrong-typed values throws with a helpful error instead of passing silently into runtime.

- **Privacy filter LRU-bounded caches** (PR #80, fix #9). The `cache: Map<string, PlaceholderRecord>` and `pathCache: Map<string, FieldPathRecord>` at `server/src/l2-operational/privacy-filter.ts` now use a bounded LRU (insertion-order Map eviction, 5000 entries each). Long-lived sessions can no longer accumulate unbounded cache entries.

- **Signed-event-stream explicit close and heartbeat reaper** (PR #80, fix #14). `server/src/console/signed-event-stream.ts` adds a `close(clientId)` method that explicitly clears the keepalive interval and removes listeners, plus a heartbeat-timeout reaper that closes clients whose Response object has missed three consecutive keepalives (~75s at the 25s keepalive interval). Network-partitioned clients no longer leak intervals + listeners until garbage collection.

- **10MB cap on OPF subprocess JSON output** (PR #80, fix #6). `server/src/l2-operational/privacy-filter-runner.ts:119` checks `Buffer.byteLength(stdout, "utf8") > OPF_STDOUT_MAX_BYTES` before `JSON.parse`. A misbehaving OPF process can no longer exhaust memory by emitting unbounded JSON before timeout. Mirrors the sidecar JSON-RPC 10MB cap pattern from PR #49.

- **v1.0.2 (j) `export_approval_audit_id` plumbing** (PR #78). `HubServiceDeps.fortressExportBundle` now accepts an optional `approvalAuditId` argument; the hub passes the inbox item id when it invokes the callback after a fortress-scope Tier 1 approval lands. `ExportExitBundleOptions` carries an optional `exportApprovalAuditId` that, when present, becomes the manifest's `export_approval_audit_id` field and the L1 `exit_bundle_export` audit entry's `approval_id`. The manifest now ties one-to-one to the operator's actual Tier 1 inbox approval rather than an internally-generated `exit-export-${Date.now()}` id. Backwards-compatible: existing zero-arg callbacks and existing `exportExitBundle()` callers continue to work.

- **v1.0.2 (l) README identity/audit drift fix** (PR #76). README install verification block split into post-wrap (dashboard responding, passphrase backed up) and post-first-unlock (identities loaded, audit log initialized) phases with an explanatory paragraph. Wrap configures; first-unlock initializes. Operators running the verification immediately after `sanctuary wrap` no longer see false negatives.

- **v1.0.2 (k) CLI em-dash sweep** (PR #76 + PR #80). All user-facing CLI strings in `server/src/cli.ts`, `server/src/cocoon/cli.ts`, `server/src/update-check.ts`, `server/src/index.ts`, and `plugin/README.md` swept of em-dashes per the no-em-dash rule. Replaced with periods, commas, colons, or semicolons per context. New CI-time test gate at `server/test/cli/no-em-dash-in-cli.test.ts` prevents regression.

- **`@noble/ciphers` patch bump** (PR #80, fix #12). 2.1.1 -> 2.2.0. Patch release; no breaking changes. v1 -> v2 migrations for `@noble/curves` and `@noble/hashes` deliberately deferred to the v1.4+ Crypto Agility Sprint.

### Fixed

- **v1.0.2 (a) Reset-history continuity** (PR #68). When a post-reset fortress spins up via `sanctuary wrap`, the lazy-init path on first cocoon-unlock reads the `.reset-history.log` marker written by `sanctuary reset-passphrase --nuke` and emits a signed `recovered-from-reset` audit entry hashing the prior marker into the new chain genesis. Closes the continuity gap between nuked and rebuilt fortress audit chains.

- **Activity-feed categorizer routes `fortress_lockdown_engaged` to `lifecycle`** (PR #79). The categorizer at `server/src/hub/activity-feed.ts` now uses an extracted `LIFECYCLE_VERBS` constant and routes `fortress_*`-prefixed operations through it. `fortress_lockdown_engaged`, `fortress_lockdown_lifted`, and `fortress_unwrap_engaged` all return `category: "lifecycle"` per the dashboard binding addendum §1.2. `fortress_exit_bundle_exported` correctly falls through (it is not a lifecycle event).

- **Per-agent Tier 1 lockdown approve handler emits lifecycle activity** (PR #79). `server/src/hub/hub-service.ts:267-300` now appends `agent_lockdown_engaged` (and `agent_unwrap_engaged` for the parallel path) to the audit log on successful per-agent Tier 1 approval. The per-agent path now mirrors the fortress-scope handler that PR #77 shipped.

- **CHANGELOG.md `v0.9.0-rc.3 (unreleased — in progress)` orphan section** (PR #80, fix #11). Removed; the rc.3 work shipped under `v0.9.0` final and the placeholder no longer represented unfinished work.

- **Stray empty `main` file at repo root** (PR #80, fix #16). Deleted. Predated the v1.1 audit window (introduced at v0.5.6 commit `0daa8eb`).

- **Twenty-eight regex named-group non-null assertions** (PR #80, fix #15). `server/src/policy-engine/compiler-fixture.ts` replaced `m.groups!.X` patterns with safe per-block guards (`const g = m.groups; if (!g) continue;`). No happy-path behavior change; strictly safer if a future regex edit drops a required named group.

### Verified (no fix required, drill confirms property holds)

- **v1.0.2 (i) Import overwrite-refusal.** Default `conflictResolution` is `"skip"`. Re-importing the same bundle on a destination without explicit `conflictResolution: "overwrite"` reports state conflicts and skips the import; previously-imported state is not silently overwritten. Drill at `v1.1-exit-drill.test.ts` verifies via second-import call.

- **v1.0.2 (h) Re-key cleanup.** Re-key occurs in memory inside `rekeyState()`; source-key-encrypted ciphertext is never persisted on the destination fortress. Source-key blobs live only inside the operator-owned bundle directory. Drill verifies by enumerating destination namespaces post-import and asserting none match staged-import or rekey-temp patterns.

- **Sanctuary-Concordia bridge canonical-JSON parity.** Cross-language parity test at `server/test/integration/canonical-json-parity.test.ts` confirms TypeScript `canonicalize()` and Python `canonical_json` produce byte-identical output across 24 fixtures spanning nesting, key ordering, Unicode, integer/float boundaries, null vs absent, and signed-event shapes. The bridge contract holds end-to-end.

### Deferred (out of v1.1 scope)

- **v1.4+ Crypto Agility Sprint** — bundled real RFC 9420 MLS plus ML-DSA / ML-KEM-768 hybrid primitives. The `@noble/curves` and `@noble/hashes` v1 -> v2 majors gate on this sprint.
- **v1.2 Mobile Operator Companion** — phone as approval surface, inbox, and emergency brake. Not a full mobile runtime.
- **v1.3 Public Federation** — cross-operator discovery, messaging, and reputation.
- **v1.4+ Key 17 sovereign-signer adapter** for x402 / Agentic.Market payments. Sanctuary signs Identity + x402 requests + AP2 mandates; Verascore signs Reputation + Validation; x402 wallets stay Coinbase-custodial.
- **v1.4+ EU AI Act compliance generator** (operator-facing tool, not a Sanctuary-binding obligation).
- **v1.4+ MSP / Fleet Operator Console** for service providers running agents on behalf of clients.
- **v1.4+ Agent Vault composition adapter** for external-stack signing.

### Notes

- **v1.0.0 GA tag intentionally skipped.** v1.0.0-rc.2 was the precursor to v1.1.0; the v1.1 wave is a strict superset of the v1.0 functionality. Pilots install over the top via `npm install -g @sanctuary-framework/mcp-server@1.1.0`. Existing fortresses unlock cleanly under the same passphrase; v1.0 -> v1.1 schema migration happens on first dashboard open via the lazy-init pattern.
- **`next` dist-tag removed at release.** v1.0.0-rc.2 stops being installable via `npm install ...@next` at v1.1.0 ship. The `next` label re-spawns when v1.2 pre-release work begins.
- **Backwards compatible with v0.10.6.** Existing wrapped agents continue to function; the v1.1 dashboard renders the same agent registry plus the new privacy / coordination / exit / hub surfaces.
- **Composition with Concordia and Verascore remains default-off and external** per the non-dependency principle. Sanctuary never requires Concordia, and vice versa. Verascore never requires either at runtime.
- **Pilot operators on this version do NOT have remote-bound privacy enforcement active until they bind a privacy policy.** The proxy chokepoint shipped in PR #71; activation gates on the operator's hub policy resolver wiring (which lands at policy-creation time per the operator's choice).
- **Quality Report 2026-04-25** sweep produced 21 fix items; 14 landed in PR #80 pre-tag wave; 7 deferred to v1.1.x backlog.

## v1.0.0-rc.2 (2026-04-23)

Scope-alignment back-out. rc.1 shipped named-agent runtime templates (`x-miner`, `github-miner`) that drifted from Scope Lock §11's channel-orthogonal template archetypes. Sanctuary governs harnesses; operators bring runtimes. See `Wiki/decisions/sanctuary-does-not-ship-sub-agent-runtimes.md` for the rule and rationale.

### Removed

- `server/src/templates/x-miner/` and `server/src/templates/github-miner/` directories, registry entries, and the `x-miner-sla.test.ts` acceptance test that asserted on them.
- Console hardcoded provider mapping for the removed templates (`server/public/console/console.js`).
- README references to the removed templates (archetype table row, narrative copy, CLI scaffold example).

### Changed

- `template init` now rejects orphan `agent_id`. If no wrapped harness exists for the given agent_id, the command exits non-zero with a `sanctuary wrap` pointer. The HTTP dashboard API at `POST /api/templates/:name/init` returns `400 {"error":"orphan_agent_id"}` with the same pointer. Channel-shape governance templates bind to already-wrapped harnesses; authoring a policy artifact for nothing was the runtime-drift surface this rc closed.
- v1.0 acceptance drill Phase 2 rewritten around channel-shape binding to wrapped harnesses (`read-outputs-only` bound to OpenClaw, `bidirectional-sync` bound to Claude Code, plus an orphan-reject demonstration). Observation log rows and post-drill write-up updated to the new roster. Drill script lives in the coordinator workspace at `Review/Sanctuary/V1.0_Acceptance_Drill_Script_2026-04-23.md` (v2.3).
- `server/test/mesh/policy-update-flow.test.ts` renamed its arbitrary `agent_id` string literal from `"x-miner"` to `"governed-harness-a"` so the test name and the naming-discipline gate agree post-back-out. The test itself is unchanged; it never exercised the deleted template.

### Housekeeping

- `.test-baseline` Linux floor adjusted to match the rc.2 test surface (deletion of the x-miner SLA suite plus addition of orphan-handling coverage). The bump lands in a separate scoped commit so the baseline-guard audit trail stays clean.
- `NPM_TOKEN` repo secret required for automated publish on tag push for rc.2 and later. Setup notes in `server/docs/RELEASE.md`.

### Not changed

- rc.1 stays published under npm `next`. rc.2 supersedes cleanly under `next`. Promotion to `latest` gates on the v1.0 acceptance drill clearing on rc.2, not on this PR.

## v1.0.0-rc.1 (2026-04-23)

First release candidate for the v1.0 line. Bundles the v1.0 MVP sprint
(WP-MVP-1 through WP-MVP-11 plus follow-ups, 26 PRs merged between
v0.10.6 and `5a73ba4`) with five intrinsic defects surfaced by the
2026-04-23 acceptance drill on moltbook.

### Fixed (drill blockers)

- **Finding A. Wrap inserts Sanctuary on empty Claude Code config.**
  Pre-v1.0 wrap exited non-zero when `~/.claude/settings.json` existed
  but had no `mcpServers` key (the first-install default), forcing
  operators to seed an unrelated placeholder before wrap would proceed.
  The empty-servers exit gate is gone; `cli.ts` now bootstraps a fresh
  config at the platform's canonical path when none exists for an
  explicitly-hinted platform (`--claude-code`, `--cursor`, `--cline`,
  `--openclaw`, `--hermes`), and re-wrap detection moved off the
  Sanctuary-filtered servers list onto a new `rawConfigContainsSanctuary`
  helper that inspects the raw config directly.
- **Finding B. Exact-match Sanctuary filter (config-reader.ts).**
  `extractServers` used a case-insensitive substring match on
  "sanctuary" to skip the canonical entry that wrap installs, which
  silently dropped operator-installed siblings like `sanctuary-helper`
  or `my-sanctuary-fork` and made every re-wrap of an already-wrapped
  config exit non-zero with "no MCP servers configured". Tightened to
  an exact lowercase match across all four adapter platforms
  (claude-code, cursor, hermes, cline). Stacked-entry prevention is
  preserved; sibling preservation is restored; combined with Finding A,
  re-wrap is now idempotent with an informative
  "Sanctuary already wrapped: updating the existing Sanctuary entry"
  message.
- **Finding C. Probe `~/.claude.json` for Claude Code MCP config.**
  Modern Claude Code writes its MCP config to `~/.claude.json` (the
  file `claude mcp add` updates). Added it as the FIRST entry in
  `getPlatformPaths()["claude-code"]`. Probe order is preference order:
  `~/.claude.json` → `~/.claude/settings.json` (legacy) →
  `~/.config/claude-code/settings.json` (XDG sibling). Bootstrap
  (Finding A) creates one at the canonical path when neither legacy nor
  modern config is present.
- **Finding I. Linkify the L4 claim CTA on the dashboard.** The L4
  panel rendered "Claim your profile at verascore.ai" as plain text;
  operators who treated it as an instruction had to manually retype the
  URL. Wrapped the entire CTA phrase in an anchor pointing at
  `https://www.verascore.ai` (the apex 307-redirects, so the www host
  is canonical) with `target="_blank" rel="noopener noreferrer"`.

### Added (release pipeline)

- **Finding N. `.github/workflows/publish-on-tag.yml`.** Closes the
  release-pipeline gap that let 26 PRs land on main without ever
  tagging or publishing. Fires on any version tag push matching
  `v[0-9]+.[0-9]+.[0-9]+` and pre-release variants. Verifies that the
  tag's version string matches `server/package.json`, runs typecheck +
  tests + build, then publishes to npm under the `next` dist-tag for
  pre-releases (so `npx @sanctuary-framework/mcp-server` keeps
  resolving to stable). The v1.0.0-rc.1 tag itself is published
  manually from MBA; this workflow takes over for rc.2 onward.

### v1.0 MVP sprint (rolled into rc.1)

The eleven work packages of the MVP sprint, in scope-lock order:

- **WP-MVP-1.** Fortress Modes v1.0 (#44): Tier 1 Private / Tier 2
  Federated / Tier 3 Interop hooks. Follow-ups: Hermes wrap adapter
  (#52, Tier B), Cline wrap adapter (#53, Layer 1).
- **WP-MVP-2.** Operator Console v1.0 (#38, #46): browser-primary HTML
  reference surface, six views, persistent attestation header.
- **WP-MVP-3.** Federation Protocol v0.1 foundation (#29):
  trust-root, signed-event envelope, audit-batch, hard-gate
  walkthrough. Follow-ups: lifecycle orchestrator (#30), libp2p wire
  adapter (#34), failure-mode operator surfaces + recovery cascade
  (#36), three-mode acceptance drill §12.1-§12.7 (#35), §12.8 + §12.9
  closeout (#37).
- **WP-MVP-4.** Agent Contract v0.1 implementation (#33).
- **WP-MVP-5.** Policy Engine v0.1 (#31): four canonical slots,
  deterministic compile, signed gates.
- **WP-MVP-6.** Egress Controls + Spend Budgets + Retention Windows
  v1.0 (#39).
- **WP-MVP-7.** Chat v1.0 (#42): libp2p transport with per-epoch
  AES-256-GCM forward-secret encryption.
- **WP-MVP-8.** Recovery Flows v1.0 (#40), Recovery Cascade v1.0 (#45):
  guardian threshold + DMswitch + multi-principal.
- **WP-MVP-9.** Attestation UX v1.0 (#43): three-layer badge surface,
  failure-mode catalog, degrade-not-destroy.
- **WP-MVP-10.** Concordia + Verascore Optional Composition v1.0
  (#47): opt-in, default-off, real Concordia v0.4.0 Python sidecar via
  JSON-RPC 2.0 over stdio. Hardening: composition v1.0 hardening (#49,
  size cap + hash pin + HKDF sidecar key), production-caller surface
  tightening (#50, HKDF default + `emitForCommitment`), commitment-
  boundary → propose → emit production pipeline (#51).
- **WP-MVP-11.** Template Library Starter Set v1.0 (#41), Console
  Scaffolding UI + X-Miner + GitHub-Miner + 10-min SLA (#48).

Other landed work in the rc.1 window: README rewrite against
rearticulation brief (#32, operator-sovereign hero, non-dependency,
dead-claim purge); README rewrite for agent-mediated install (#54).

### Notes

- **Acceptance gate (Scope Lock §6) status:** drill ran against the
  stale v0.10.6 binary and paused mid-Phase 1 once the binary mismatch
  was confirmed. Re-run against the published rc.1 is the next step;
  findings D, E, H, J, K, L, M from the drill are flagged for
  re-verification (they may resolve as stale-binary artifacts or
  persist as separate issues).
- **Out of scope for rc.1 (carried forward):** v1.x crypto agility
  sprint (group-messaging upgrade plus post-quantum hybrid primitives;
  v1.0 chat ships forward-secret per-epoch AES-256-GCM, not the
  upgraded protocol); v1.x MSP / Fleet Operator Console; v1.x native
  mobile interface; v1.x x402 / Agentic.Market sovereign-signer adapter
  (Key 17); v1.x EU AI Act compliance pack.
- The drill script itself has independent drift (findings F, G:
  keychain service-name suffix, audit-log path/format) that the
  coordinator (MBA thread) owns; build-thread scope is the five
  intrinsic code defects only.

## v0.10.6 (2026-04-20)

### Fixed
- **Standalone dashboard reload-loop on a fresh browser tab under loopback auto-auth.** Field signal: moltbook on v0.10.5 confirmed the SSE URL fix (`/api/events` → `/events`) landed cleanly — every documented endpoint returns real data (`/events` streams, `/api/sovereignty-profile` = 200, `/api/proxy/servers` = 200). But the UI still did not render. Mac Mini devtools Network capture (Web Inspector, preserve-log ON) showed the real shape: dozens of identical ~82.91 KB `127.0.0.1` document requests stacked at page-open, zero `fetch(...)` or `EventSource(...)` traffic. A tight client-side reload loop before any data-fetch fires.
- Root cause: `initialize()` in `server/src/principal-policy/dashboard-html.ts` gated on `sessionStorage.authToken` with `if (!AUTH_TOKEN) { redirectToLogin(); return; }` (line 2909). On a fresh tab at `127.0.0.1:PORT/`, `sessionStorage` is always empty, so `AUTH_TOKEN === ''` and `redirectToLogin()` fires, setting `window.location.href = '/'`. The server serves the dashboard HTML (not the login page) because `isAuthenticated()` recognizes loopback callers under `_autoAuthLocalhost` (`dashboard.ts:458`). Same URL, same server, same auto-auth → HTML served again → JS runs again → still empty sessionStorage → redirect again. **Infinite.**
- Server-side loopback auto-auth, no client-side mirror. The fix adds a `loopbackAutoAuth: boolean` option to `generateDashboardHTML`, emits `const LOOPBACK_AUTH = <bool>;` alongside `AUTH_TOKEN` at template boot, and changes the init gate to `if (!AUTH_TOKEN && !LOOPBACK_AUTH)`. `dashboard.setAutoAuthLocalhost()` now regenerates the cached HTML since the flag is decided after construction.

### Added
- Regression test (`test/dashboard-standalone-v010-6.test.ts`, 4 tests) that exercises the browser init path the v0.10.5 test gap missed. Boots a real dashboard against a real seeded tenant, fetches the served HTML, asserts `LOOPBACK_AUTH = true` is embedded, and executes the actual init gate against stubbed browser globals (empty `sessionStorage`, recording `window.location.href` assignments) to prove no redirect fires. Includes the flip-side assertion: with `loopbackAutoAuth=false` and empty sessionStorage, the gate MUST still redirect to the login page (remote-deployment guard).
- All 4 tests fail on v0.10.5 HEAD (`dcfa4c8`) and pass after the patch — both directions verified before merge.

### Notes
- Test-coverage gap, not test-correctness bug: v0.10.5's `dashboard-standalone-v010-5.test.ts` regex-extracted URLs from the served HTML and HTTP-requested each. All routes returned non-4xx — correct. But Node has no `sessionStorage`, so the test never exercised the client-side `initialize()` path where empty sessionStorage triggered the redirect before any fetch fired. v0.10.6 closes this by executing the gate against realistic inputs, not just asserting route mounting.
- Fix shape chosen: server-baked flag mirror, rejecting the alternative "remove the init gate entirely and let per-fetch 401 handlers drive redirects." Gate-removal would create a brief window where several parallel fetches each 401 and each queue a redirect before the first `location.href = '/'` navigation takes effect — noisy in devtools logs and harder to reason about than the explicit flag. The flag shape is also consistent with how the rest of the codebase mirrors server-side decisions (timeout, server version, API base) into inline template constants.
- `.test-baseline` floor raised from 1664 → 1668 (+4 regression tests). Linux-CI-safe floor; macOS reports 1704.

## v0.10.5 (2026-04-19)

### Fixed
- **Standalone dashboard panels stuck on "Loading…" even after v0.10.4 loaded identities.** Field signal: moltbook on v0.10.4 reported `Identities loaded: 8` (the v0.10.4 acceptance) but every panel in the browser stayed empty and the status bar flashed blue in a retry loop. Root cause: the dashboard HTML's SSE setup pointed `EventSource` at `/api/events`, but Stack A's server mounts SSE at `/events` (server/src/principal-policy/dashboard.ts:688). Every dashboard boot from v0.10.0 through v0.10.4 sent EventSource into a 404 retry loop. The same code also passed `{ headers: { Authorization: ... } }` to the EventSource constructor, which the standard browser API silently drops — auth has to travel as a cookie or `?session=` query param for SSE.
- The fix is a minimum-change edit: change the URL from `/api/events` to `/events`, drop the broken headers option. The fortress-view dashboard (server/src/cocoon/fortress-view.ts) already does it this way; this commit brings the standard dashboard into line.

### Added
- Regression test (`test/dashboard-standalone-v010-5.test.ts`, 3 tests) that boots a real dashboard against a real seeded tenant, fetches the served HTML, regex-extracts every fetch + EventSource target, then HTTP-requests each one against the running server. **No route table is mocked.** The test fails on v0.10.4 HEAD with `EventSource -> /api/events returned 404` and passes after the patch. Same anti-pattern guard the v0.10.4 regression test established for identity loading, applied to the data-surface contract.

### Notes
- v0.10.5 closes the route-table mismatch only. The Stack A vs Stack B architectural question (the standalone dashboard mounts the older "Principal Dashboard" stack from `server/src/principal-policy/`, while a newer "Protection Dashboard" stack in `server/src/dashboard/` is documented but not mounted) is **out of scope** here per the spawn prompt's hard-stop rule, and remains an open coordinator-level question.
- Moltbook's three `curl` 404s on `/api/health`, `/api/snapshot`, and `/api/agents` were Stack B routes — correct behaviour for what's actually running, unrelated to the panel-population failure. Documented in the PR audit trail.
- `.test-baseline` floor raised from 1661 → 1664 (+3 regression tests). Linux-CI-safe floor; macOS reports 1700.

## v0.10.4 (2026-04-19)

### Fixed
- **Standalone dashboard could not boot on a real multi-tenant install.** v0.10.2 shipped a fix that passed CI but did not land in the field — moltbook saw `Identities loaded: 0` through v0.10.1 → v0.10.2 → v0.10.3. Root cause: the keychain entry per storage path (sha256-derived suffix) was correct, but the dashboard's default-root boot path could not reach the per-tenant entries, and its regression test mocked a wrong schema (one entry per identity, which is not how Sanctuary stores anything).
- `sanctuary dashboard` against a default root with orphan identity files and no resolvable passphrase now refuses with an actionable error that names the storage path and lists the wrapped tenants discoverable on the host. Pre-fix it threw "Provide SANCTUARY_PASSPHRASE" with no further context.
- `sanctuary dashboard` against a clean default root that has no Sanctuary state but other wrapped tenants now refuses to fresh-install a recovery key over the default root. Pre-fix this obscured the real tenants.
- `Encrypted identities found but NONE loaded` warning banner rewritten: removed the misleading `SANCTUARY_PASSPHRASE=<your-passphrase>` fix-hint, surfaced other discoverable tenants, and pointed at the new keychain-schema doc.

### Added
- `sanctuary dashboard --tenant <name>` flag — resolves a tenant by the human-readable name printed by `sanctuary agents`, sets the per-tenant storage path internally, and looks up the matching Keychain item. The multi-tenant-safe boot path operators need.
- `server/docs/keychain-schema.md` — canonical reference for how Sanctuary stores per-tenant passphrases (macOS Keychain entries, encrypted fallback files), the Argon2id key-derivation flow, the per-purpose HKDF subkeys, the multi-tenant directory layout, and diagnostic recipes.
- Regression test (`test/dashboard-standalone-v010-4.test.ts`) that builds real identity .enc files via the production `IdentityManager` + AES-256-GCM path and persists per-tenant passphrases via `persistUserProvidedPassphrase` exactly the way `sanctuary wrap` does. No keychain shape is mocked. The tests fail without this patch.

### Internal
- `discoverableSubTenants(currentStoragePath)` and `renderTenantDiscoveryHint(tenants)` exported from `dashboard-standalone` so the multi-tenant guidance text is unit-testable and reusable from other boot paths.
- `.test-baseline` floor raised from 1654 → 1661 (+7 regression tests; macOS run reports 1697 passed, but the floor stays Linux-CI-safe per the v0.10.0 rc.2 handoff finding that ~23 darwin-only tests skew MBA-side counts).

## v0.10.3 (2026-04-19)

### Changed
- README hero rewritten for clarity: replaces "Security, privacy, and control for your AI agent." with "Your agent. Your machine. Your keys." and a concrete subhead naming the three things Sanctuary ships (encrypted memory, approval dashboard, portable cryptographic identity).
- New "Why this matters" section earns the "sovereignty" framing after the value prop lands, rather than leading with the abstraction.
- npm package description rewritten to match the new hero — "Your agent, your machine, your keys — an MCP server that adds encrypted state, approval gates, and a portable identity to any AI agent." (previous copy trained readers to mis-file the project as security architecture.)

No code changes. Messaging-clarity patch only.

## v0.9.0-rc.2 (2026-04-17)

### Security
- **SEC-061** — Removed `--passphrase` flag from rewritten agent config (was persisting passphrase as plaintext in argv)
- **SEC-062** — Fallback passphrase file now distinguishes NOT_FOUND vs UNREADABLE; never auto-regenerates on decrypt failure

### Added
- `PassphraseUnreadableError` with remediation steps for failed decryption
- `persistUserProvidedPassphrase()` — one-time passphrase setter that routes to Keychain/fallback

## v0.9.0-rc.1 (2026-04-16)

### Added
- **Sovereignty Dashboard** — unified single-page "you are protected" view with SSE live updates, approval gate integration, and auto-open in browser
- **`sanctuary wrap`** — one-command agent wrapping (replaces the 6-step manual setup)
- macOS Keychain integration for passphrase storage
- Dashboard screenshots in GitHub Release

### Changed
- Dropped "Cocoon" from all user-facing surfaces (deprecated alias retained)
- `sanctuary` CLI bin alias added

## v0.8.0 (2026-04-14)

### Added
- EU AI Act compliance artifact generator (Annex III classifier, delta mode, Verascore publish hook, PDF writer)
- `memory_attest` tool (Ed25519 signed content hash attestation)
- Test baseline hardening (pre-commit hook, CI workflow, branch protection runbook)
- `identity_set_primary` tool with persistent primary identity tracking

### Changed
- SIEM export reclassified to Tier 3

## v0.7.0

- Removed `sanctuary/` prefix from all 67 tool names (fixes OpenClaw double-mangling)
- SIEM CEF/OCSF export (`audit_export_siem` tool)
- Context gate `"*"` wildcard bypass
- Cocoon CLI, config-reader, Fortress View, tier-classifier
- 1071 tests passing

---

## [0.8.0] - unreleased — EU AI Act Compliance Artifact Generator (detailed)

### Added — Phase 2

- **Annex III classification helper (Deliverable 1).** New module
  `server/src/compliance/eu_ai_act/annex_iii.ts` with a structured
  catalog of all 8 Annex III high-risk categories (18 sub-points
  total) under Regulation (EU) 2024/1689. Each category carries
  verbatim regulation text with `[...]` elisions (same citation
  discipline as `coverage_matrix.ts`) and a keyword catalog with
  coarse discrete weights (1.0 / 0.6 / 0.3).

  `classifyAgentDescription(text)` produces zero or more candidate
  categories with a `rule_based_confidence` score (sum of matched
  keyword weights clamped to `[0, 1]`). The confidence field is
  deliberately named `rule_based_confidence` — not `confidence` or
  `probability` — so downstream consumers cannot mistake the
  classifier for a machine-learning model. Classifier is exposed
  as a standalone MCP tool `compliance_eu_ai_act_annex_iii_classify`
  (Tier 3) and also auto-included as bundle document 07
  (`07_annex_iii_classification.md`).

- **Delta mode (Deliverable 2).** Optional
  `delta_from_bundle_path` parameter on
  `compliance_generate_eu_ai_act_bundle`, plus `--delta-from <path>`
  CLI flag. When supplied, the generator loads the prior bundle's
  manifest, compares coverage rows, and emits `08_delta.md` listing
  regulation_version changes, matrix_version changes, rows added,
  rows removed, and rows changed (with explicit `from → to`
  rendering for coverage flag and evidence_emitter changes). Doc 08
  is itself hashed and Ed25519-signed into the final manifest.

  Delta failure never fails bundle generation: unreadable path,
  malformed manifest, missing files, and fetch errors are all
  captured as warnings and the bundle lands locally unchanged.

- **Verascore publish hook (Deliverable 3).** Optional
  `publish_to_verascore: boolean` parameter on the bundle generator,
  plus `--publish-to-verascore` and `--verascore-url` CLI flags.
  When enabled, POSTs the signed manifest (not the document bodies)
  to Verascore after the bundle is fully built. Reuses the exact
  wire format, signing path, and SSRF allow-list of the existing
  `reputation_publish` tool — no second signing pipeline, no new
  cryptography.

  **Non-dependency principle enforced at every layer:** HTTPS
  required, hostname allow-list (verascore.ai, www.verascore.ai,
  api.verascore.ai), validation failures short-circuit before
  fetch, network errors and non-2xx responses captured in a
  `publish_result` field. Sanctuary bundle generation NEVER
  requires Verascore to be online; the publish is a pure side
  effect at the very end of generation.

- **PDF render (Deliverable 4).** Optional `--pdf` CLI flag that
  writes a single `bundle.pdf` alongside the Markdown files using
  a hand-rolled minimal PDF writer at
  `server/src/compliance/eu_ai_act/pdf.ts`. **No new runtime
  dependency.** The writer produces a valid PDF-1.4 byte stream
  with a correct catalog, pages tree, content streams, and xref
  table, using the Courier and Courier-Bold standard PDF Type1
  fonts (no font embedding, no AFM metric tables). Output is clean
  monospace typography with a cover page, per-document page breaks,
  and a footer on every page showing the manifest SHA-256
  identifier prefix and page numbering.

  The PDF is explicitly NOT cryptographically signed — integrity
  verification remains with the Markdown files and the JSON
  manifest. The PDF is a human-readable render of those already-
  signed artifacts. macOS `file(1)` confirms the output is a
  valid "PDF document, version 1.4" and real PDF readers can open
  the example at `examples/eu_ai_act_bundle_example/bundle.pdf`.

### Fixed — Phase 2

- **PDF footer overlay — truncate digest to 16 hex, ASCII separator, width guard.** The Phase 2 Deliverable 4 footer drew the left "Sanctuary EU AI Act Compliance Bundle · Manifest SHA-256: <48 hex>..." string and the right "Page N of M" label at the same Y baseline, overlapping on Letter-sized pages. Fixed by (a) truncating the footer digest prefix from 48 to 16 hex characters (64 bits — still collision-resistant for visual verification), (b) replacing the `·` middle-dot separator with a plain ASCII pipe `|` so the character substitution table doesn't garble it, and (c) adding an `assertFooterFits` width guard + `MIN_FOOTER_GUTTER = 24pt` constant that throws a recognisable error if left-footer width + right-label width + gutter exceeds the available column width. The guard is exported so the regression test can invoke it directly with pathological dimensions. The example HR bundle regenerated under `GENERATE_EXAMPLE=1` remains byte-stable across runs; only `bundle.pdf` changed relative to the pre-fix state (Markdown and JSON files are untouched). +4 tests on the PDF writer.

### Changed — Phase 2

- **Example bundle is now byte-stable across regenerations.** The
  Phase 1 example fixture used real randomness in three places
  (private key generation, encryption IV, timestamps), causing the
  committed example files to drift from regenerated output. Phase 2
  fixes this with a test-file-local `buildDeterministicIdentity()`
  helper that uses a fixed 32-byte private key seed, a fixed IV
  for AES-GCM, and `vi.useFakeTimers` + `vi.setSystemTime` to
  freeze the clock during the example generation. No production
  code changes — the fixture uses `@noble/curves/ed25519` and
  `@noble/ciphers/aes.js` directly (both already dependencies).
  Verified byte-stable across two consecutive `GENERATE_EXAMPLE=1`
  runs.

- **Bundle document count 6 → 7 (+1 optional).** Bundles now always
  include `07_annex_iii_classification.md` as a content document;
  `08_delta.md` is conditional on `delta_from_bundle_path`;
  `bundle.pdf` is conditional on `--pdf`. The Phase 1 test
  assertion "exactly 6 Markdown documents" is updated to "exactly
  7 Markdown documents and a manifest" for the default bundle.

### Added — Phase 1

- **EU AI Act Compliance Artifact Generator.** New Sanctuary subsystem
  under `server/src/compliance/eu_ai_act/` that generates a signed
  bundle of technical compliance documents from a live Sanctuary
  runtime, aligned to Regulation (EU) 2024/1689.
  - Coverage matrix v1 (`coverage_matrix.ts`) — 46 rows mapping
    Sanctuary primitives to Annex IV §1–§9, Article 12, Article 13,
    Article 14, Article 15, Article 19(1), and Article 26. Honest
    coverage distribution: **5 full rows** (11%, machine-verifiable
    with zero enterprise input), **24 partial rows** (52%, structured
    evidence plus enterprise context), and **17 manual-only rows**
    (37%, enterprise-authored). Every "full" row individually verified
    against v0.7.0 source on 2026-04-10; see per-row `review_notes`
    for verification findings and corrections applied.
  - Six Markdown templates covering Annex IV technical documentation
    (per Article 11), Article 26 deployer log, Article 12 automatic
    record-keeping, risk management summary (Article 9), human
    oversight statement (Article 14), and cryptographic attestations.
    Each template uses verbatim regulation quotes with `[...]`
    elisions and emits explicit `[MANUAL INPUT REQUIRED: hint]`
    markers where the enterprise must supply business context.
  - Hand-rolled minimal template engine (`templates/render.ts`, ~60
    lines) with `{{ var }}` and `{{ var | hint }}` grammar. Zero new
    runtime dependencies.
  - Bundle generator (`generator.ts`) that walks the matrix, renders
    each document, computes SHA-256 (lowercase hex for auditor
    compatibility with `sha256sum`), and signs every file with the
    provider's primary Ed25519 identity via the existing
    `core/identity.ts` sign primitive. Canonical JSON signing for
    the manifest.
  - New MCP tool `compliance_generate_eu_ai_act_bundle` registered
    under Tier 3 (auto-allow, read-only) in the default Principal
    Policy.
  - New CLI subcommand `sanctuary-mcp-server compliance eu-ai-act
    <agent-did>` with flags for deployment context, reporting
    period, and output directory.
  - Example bundle under `examples/eu_ai_act_bundle_example/` — a
    fictional Fortune 2000 enterprise deploying a high-risk Annex
    III §4 HR screening agent. Byte-stable across regeneration via
    the new `generated_at_override` input field. Verified end-to-end
    with `shasum -a 256`; every digest matches the manifest exactly.
  - Documentation at `docs/compliance/eu_ai_act_bundle.md` (usage
    guide) and `docs/compliance/eu_ai_act_coverage_matrix_v1.md`
    (auto-generated from the matrix TypeScript data).
  - 81 new tests across render, coverage matrix schema invariants,
    and end-to-end bundle generation (including signature
    verification against the signer's public key).

### Changed

- **`SanctuaryServer` interface extended** with optional-usage
  `identityManager`, `masterKey`, `auditLog`, and `policy` fields so
  embedding callers (notably the compliance CLI subcommand) can
  reuse the existing `createSanctuaryServer` path without
  duplicating dependency wiring. Non-breaking for existing consumers
  that only use `server` and `config`.

### Fixed

- **`principal-policy/loader.ts` closing `],` absorbed into line
  comment.** A recent memory_attest commit had the closing bracket
  of `tier3_always_allow` tucked onto the same line as a `//`
  comment, absorbing it into the comment and leaving the array
  unclosed. This silently broke esbuild parse for 10 test files,
  dropping the baseline from 1113 to 1015 passing. Fixed in commit
  `3bc5cc6`. Baseline restored to 1113; after the compliance
  generator tests the new baseline is 1193+.

- **Three pre-existing `TS6133` unused-import errors** in
  `src/cocoon/cli.ts`, `src/cocoon/config-reader.ts`, and
  `src/l1-cognitive/memory-attest.ts`. Removed during the session
  that built the compliance generator, because the new
  interim-stopgap test-baseline rule in `Sanctuary/CLAUDE.md`
  requires a clean typecheck before every commit. Commit `d175b23`.

### Documentation

- **`Sanctuary/CLAUDE.md` commit discipline stopgap** (commit
  `e99174f`). Every commit to Sanctuary main must run
  `npm run typecheck && npm test` against a clean working tree
  before staging; block the commit if either fails. Interim
  instruction-layer defense until a pre-commit hook lands in a
  follow-up session per `docs/audit/test-baseline-hardening-plan.md`.

- **`docs/audit/` directory established** as the canonical home for
  long-lived audit-class artifacts (postmortems, hardening plans,
  incident reports). Inaugural artifacts: the commit `4ac95830`
  postmortem and the test baseline hardening plan. Commit `eead299`.

## [0.6.1] - 2026-04-04 — Security remediation pass

### Security

- **DELTA-01 — domain separation in `sanctuary_sign_challenge`.** Tool now
  requires a `purpose` argument and signs
  `"sanctuary-sign-challenge-v1" || 0x00 || purpose || 0x00 || nonce`
  instead of raw nonce bytes. Raw-nonce signatures no longer verify;
  cross-purpose signatures do not verify. Prevents signature replay
  across verifiers.
- **DELTA-05 — handshake auto-publish now signs its payload.** The
  outbound Verascore envelope carries body.signature (Ed25519 over
  JSON.stringify(data)) plus body.publicKey so /api/publish can
  verify it end-to-end.
- **DELTA-04 — handshake auto-publish defaults to false.** When
  enabled, the published envelope strips counterparty-identifying
  fields (counterparty_signed_by → "redacted") until explicit consent
  is wired through.
- **DELTA-08 — `sanctuary_link_to_human` redacts target email.** Tool
  response now returns only `***@domain`; a compromised agent cannot
  read back which address it emailed.
- **DELTA-17 — principal-policy tier alignment test.** New test
  asserts that sanctuary_bootstrap/export_identity_bundle are Tier 1,
  link_to_human/sign_challenge are Tier 2 (anomaly-gated), and
  policy_status is Tier 3 — guards against future drift.

## [0.6.0] - 2026-04-04

### Added

- **Quickstart package** (`@sanctuary-framework/quickstart@0.1.0`) — zero-dep
  `npx` CLI that generates an Ed25519 identity, writes `~/.sanctuary/quickstart-identity.json`
  (0600), and publishes a self-attested SHR to Verascore in under 60 seconds.
  E2E tested against a local node:http mock.
- **5 new MCP tools** (brings total to 72+):
  - `sanctuary/bootstrap` — one-shot setup (identity + bundle + quickstart JSON)
  - `sanctuary/policy_status` — report current Principal Policy state
  - `sanctuary/export_identity_bundle` — portable identity export
  - `sanctuary/link_to_human` — bind an agent identity to a human principal
  - `sanctuary/sign_challenge` — sign a Verascore claim nonce with the agent key
- **Post-handshake auto-publish hook** — `handshake_respond` POSTs a handshake
  attestation envelope to Verascore `/api/publish` after a successful response.
  Gated by `config.verascore.auto_publish_handshakes` (default true). HTTPS-only.
  Failures are audit-logged but non-blocking.
- **Docs** — `server/docs/OWASP.md` (OWASP LLM Top-10 mapping) and
  `server/docs/DID.md` (did:key method and identity bundle format).
- Integration test `server/test/integration/auto-publish-handshake.test.ts`
  exercising auto-publish against a real local HTTP mock.

### Changed

- Server version bumped to `0.6.0`.

## [0.4.2] - 2026-04-01

### Fixed

- **sovereignty_audit blocked on existing installations** — The v0.4.1 fix added `sovereignty_audit` to `DEFAULT_POLICY.tier3_always_allow`, but existing installations already had a `principal-policy.yaml` on disk from v0.3.1 that was loaded instead. The policy loader now **merges** default tier3 entries into user policy files, so new read-only tools from upgrades are automatically permitted without requiring operators to edit their policy file. This is upgrade-safe: user customizations are preserved and defaults are additive.

## [0.4.1] - 2026-04-01

### Fixed

- **Critical: Packaging bug** — `dist/cli.js` contained a wrong require path for `package.json` in the dashboard module, causing the MCP server to crash silently on startup and expose zero tools through OpenClaw. Root cause: `src/principal-policy/dashboard.ts` used a separate `createRequire` with a path that resolved differently in the bundle vs source. Fix: import version from `config.ts` instead of duplicating the require.
- **sovereignty_audit permission gate** — The audit tool was documented as Tier 3 (auto-allow) but was never added to the `tier3_always_allow` list, causing it to default to Tier 1 (require approval) per SEC-011. Now correctly classified as Tier 3 alongside `shr_generate` and `monitor_health`.
- **Missing Tier 3 classifications** — `shr_gateway_export`, `bridge_commit`, `bridge_verify`, and `bridge_attest` were also missing from `tier3_always_allow`. All read-only or outbound-only tools now correctly auto-allow.

### Changed

- `SANCTUARY_VERSION` is now exported from `config.ts` for use by other modules, eliminating duplicate `createRequire` calls.

## [0.4.0] - 2026-04-01

### Added

- **Decommissioning Certificate** — Policy framework for decommission operations (Tier 1, requires approval). Tool implementation deferred to v0.5.0.
- **L2 Hardening Path** — 2 new tools (`sanctuary/l2_hardening_status`, `sanctuary/l2_verify_isolation`). Checks process isolation (container/VM/sandbox), memory protection (ASLR, canaries, Argon2id), filesystem permissions, runtime integrity. New "Hardened" tier between Degraded and Full.
- **SHR Gateway Export** — 1 new tool (`sanctuary/shr_gateway_export`). Transforms SHR into authorization context for Ping Identity Agent Gateway or other identity providers with trust levels and capability signals.
- **Context Gating** — 5 tools for field-level context filtering with policy templates (`context_gate_set_policy`, `context_gate_filter`, `context_gate_apply_template`, `context_gate_list_policies`, `context_gate_recommend`).
- **Concordia Bridge** — 3 tools for optional composition with Concordia Protocol (`bridge_commit`, `bridge_verify`, `bridge_attest`).
- **Hermes Integration** — adapter and examples for Hermes agent framework.
- **LangChain Integration** — adapter using official `langchain-mcp-adapters`.
- **CrewAI Integration** — adapter using native `mcps` field.
- **Incident class mapping** in sovereignty audit — 5 real-world incidents (Meta Sev 1, OpenClaw CVE flood, context leakage, inbox deletion, Claude Code leak) mapped to sovereignty gaps.
- **NIST CAISI mapping** in SHR spec (Section 9) — maps NIST's five security dimensions to SHR coverage.

### Changed

- L3 ZK proofs repositioned: existing Schnorr + range proofs via Fiat-Shamir ARE genuine ZK proofs. "Commitment-only" label was a categorization error.
- Dashboard rate limiting: sliding-window per-IP (120 req/min general, 20 req/min decisions).
- `reputation_export` moved from Tier 3 to Tier 1.
- Version dynamically read from package.json (resolves issue #6).
- Validation added for `withhold-all` and `service-mediated` config values (resolves issue #4).
- Tool surface increased from 46 to 54 tools.

### Fixed

- Issue #6: Version mismatch between package.json and reported version.
- Issue #4: Dead config values (`withhold-all`, `service-mediated`) accepted without validation.
- Issue #3: Tier asymmetry — `reputation_export` now correctly at Tier 1.
- Issue #2: Dashboard had no rate limiting.
- TypeScript strict-mode compilation errors preventing npm publish.

### Security

- SEC-025: Case-insensitive context gate pattern matching.
- SEC-026: Logging-strict template allow list now enforced (removed dead code).
- SEC-027: Size limits for context objects and policy rules.

### Migration from v0.3.1

**No breaking changes to the MCP tool interface.** All v0.3.1 tools remain available with the same names and parameters.

The Concordia Bridge tools are **additive** — they provide optional composition with Concordia Protocol but do not replace any existing tools.

**Critical upgrade step:** After updating the npm package, your MCP host (OpenClaw, Claude Code, etc.) must restart its gateway to re-enumerate the tool surface. A stale gateway registration may show only a subset of tools.

See `docs/MIGRATION_v0.3_to_v0.4.md` for detailed upgrade instructions.

---

## [0.3.1] - 2026-03-29

### Added

- Sovereignty audit tool with security gap analysis and incident class mapping
- SHR (Sovereignty Health Report) generation and verification tools
- Handshake protocol (initiate, respond, complete, status)
- Federation MCP-to-MCP tools
- SHR v1.0 spec published to `docs/SHR_SPEC.md`
- Installation section with OpenClaw and Claude Code setup instructions
- LangChain integration reference with examples
- GitHub Pages blog at sanctuaryprotocol.ai

### Changed

- Author attribution updated from CIMC to Erik Newton across all public-facing docs (per mandatory attribution rule)
- Tool count updated to 46 in all documentation

### Fixed

- GitHub issue #2: Dashboard rate limiting (20–120 req/min sliding window)
- GitHub issue #3: `reputation_export` tier asymmetry
- GitHub issue #4: Dead config values validation
- GitHub issue #6: Version mismatch dynamic resolution

### Security

- Security review findings: all PASS (resolved Critical and High findings before merge)
- SEC-ADDENDUM conditions resolved
- StderrApprovalChannel unused config parameter prefixed with underscore

---

## [0.3.0] - 2026-03-25

### Added

- Principal Policy Framework — govern agent autonomy and delegation across four sovereignty layers
- Bootstrap Escrow and Guarantee tools — secure initial credential exchange
- L2 Context Gating foundations — field-level filtering and obfuscation policies
- Policy templates for enterprise patterns (logging-strict, export-blocked, minimal-context)

---

## [0.2.0] - 2026-03-20

### Added

- Initial L1–L4 tool surface (core 46 tools across four sovereignty layers)
  - **L1 Cognitive Sovereignty:** ED25519 identity, SHR generation, reputation export
  - **L2 Operational Isolation:** state encryption, audit logging, context gating
  - **L3 Selective Disclosure:** cryptographic proofs (Schnorr, range proofs), ZK gates
  - **L4 Verifiable Reputation:** federation handshake, cross-domain trust
- Ed25519 identity management (key generation, recovery, rotation)
- Encrypted state operations (AES-256-GCM)
- Reputation system with tier-based verification (Unverified, Self-Attested, Verified-Degraded, Verified-Full)
- MCP tool schema with 54 tools across all layers
- Comprehensive test suite (484 tests)
- Apache-2.0 license for code, CC-BY-4.0 for spec

---

## Release Versioning

- **0.2.x:** Initial foundation (L1–L4 core, identity, reputation)
- **0.3.x:** Audit, federation, integration (sovereignty audit, SHR spec, handshake, integrations)
- **0.4.x:** Lifecycle, hardening, composition (decommissioning, L2 hardening, gateway export, context gating)
- **0.5.x–0.6.x:** Quickstart, bootstrap, SIEM, framework integrations
- **0.7.x:** Tool name cleanup, Cocoon CLI
- **0.8.x:** EU AI Act compliance, test baseline hardening
- **0.9.x:** Sovereignty Dashboard, one-command wrap, security hardening, deep-audit polish

