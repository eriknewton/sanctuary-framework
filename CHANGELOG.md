# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## v1.0.0-rc.1 (2026-04-23)

First release candidate for the v1.0 line. Bundles the v1.0 MVP sprint
(WP-MVP-1 through WP-MVP-11 plus follow-ups, 26 PRs merged between
v0.10.6 and `5a73ba4`) with five intrinsic defects surfaced by the
2026-04-23 acceptance drill on moltbook.

### Fixed (drill blockers)

- **Finding A — wrap inserts Sanctuary on empty Claude Code config.**
  Pre-v1.0 wrap exited non-zero when `~/.claude/settings.json` existed
  but had no `mcpServers` key (the first-install default), forcing
  operators to seed an unrelated placeholder before wrap would proceed.
  The empty-servers exit gate is gone; `cli.ts` now bootstraps a fresh
  config at the platform's canonical path when none exists for an
  explicitly-hinted platform (`--claude-code`, `--cursor`, `--cline`,
  `--openclaw`, `--hermes`), and re-wrap detection moved off the
  Sanctuary-filtered servers list onto a new `rawConfigContainsSanctuary`
  helper that inspects the raw config directly.
- **Finding B — exact-match Sanctuary filter (config-reader.ts).**
  `extractServers` used a case-insensitive substring match on
  "sanctuary" to skip the canonical entry that wrap installs, which
  silently dropped operator-installed siblings like `sanctuary-helper`
  or `my-sanctuary-fork` and made every re-wrap of an already-wrapped
  config exit non-zero with "no MCP servers configured". Tightened to
  an exact lowercase match across all four adapter platforms
  (claude-code, cursor, hermes, cline). Stacked-entry prevention is
  preserved; sibling preservation is restored; combined with Finding A,
  re-wrap is now idempotent with an informative
  "Sanctuary already wrapped — updating the existing Sanctuary entry"
  message.
- **Finding C — probe `~/.claude.json` for Claude Code MCP config.**
  Modern Claude Code writes its MCP config to `~/.claude.json` (the
  file `claude mcp add` updates). Added it as the FIRST entry in
  `getPlatformPaths()["claude-code"]`. Probe order is preference order:
  `~/.claude.json` → `~/.claude/settings.json` (legacy) →
  `~/.config/claude-code/settings.json` (XDG sibling). Bootstrap
  (Finding A) creates one at the canonical path when neither legacy nor
  modern config is present.
- **Finding I — linkify the L4 claim CTA on the dashboard.** The L4
  panel rendered "Claim your profile at verascore.ai" as plain text;
  operators who treated it as an instruction had to manually retype the
  URL. Wrapped the entire CTA phrase in an anchor pointing at
  `https://www.verascore.ai` (the apex 307-redirects, so the www host
  is canonical) with `target="_blank" rel="noopener noreferrer"`.

### Added (release pipeline)

- **Finding N — `.github/workflows/publish-on-tag.yml`.** Closes the
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

- **WP-MVP-1** — Fortress Modes v1.0 (#44): Tier 1 Private / Tier 2
  Federated / Tier 3 Interop hooks. Follow-ups: Hermes wrap adapter
  (#52, Tier B), Cline wrap adapter (#53, Layer 1).
- **WP-MVP-2** — Operator Console v1.0 (#38, #46): browser-primary HTML
  reference surface, six views, persistent attestation header.
- **WP-MVP-3** — Federation Protocol v0.1 foundation (#29):
  trust-root, signed-event envelope, audit-batch, hard-gate
  walkthrough. Follow-ups: lifecycle orchestrator (#30), libp2p wire
  adapter (#34), failure-mode operator surfaces + recovery cascade
  (#36), three-mode acceptance drill §12.1-§12.7 (#35), §12.8 + §12.9
  closeout (#37).
- **WP-MVP-4** — Agent Contract v0.1 implementation (#33).
- **WP-MVP-5** — Policy Engine v0.1 (#31): four canonical slots,
  deterministic compile, signed gates.
- **WP-MVP-6** — Egress Controls + Spend Budgets + Retention Windows
  v1.0 (#39).
- **WP-MVP-7** — Chat v1.0 (#42): libp2p transport with per-epoch
  AES-256-GCM forward-secret encryption.
- **WP-MVP-8** — Recovery Flows v1.0 (#40), Recovery Cascade v1.0 (#45):
  guardian threshold + DMswitch + multi-principal.
- **WP-MVP-9** — Attestation UX v1.0 (#43): three-layer badge surface,
  failure-mode catalog, degrade-not-destroy.
- **WP-MVP-10** — Concordia + Verascore Optional Composition v1.0
  (#47): opt-in, default-off, real Concordia v0.4.0 Python sidecar via
  JSON-RPC 2.0 over stdio. Hardening: composition v1.0 hardening (#49,
  size cap + hash pin + HKDF sidecar key), production-caller surface
  tightening (#50, HKDF default + `emitForCommitment`), commitment-
  boundary → propose → emit production pipeline (#51).
- **WP-MVP-11** — Template Library Starter Set v1.0 (#41), Console
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
- The drill script itself has independent drift (findings F, G —
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

## v0.9.0-rc.3 (unreleased — in progress)

### Fixed
- Constant-time comparison for L3 commitment verification (audit #15)
- Non-macOS fallback storage warning on first wrap (SEC-063)
- Audit log size-based rotation with configurable limits (audit #18)

### Changed
- Bumped `@modelcontextprotocol/sdk` to ^1.29.0 — resolves path-to-regexp DoS, hono advisories
- Removed 3 `as any` casts with typed adapters (audit #1, #2, #3)
- Paginated reputation store `loadAll()` via async iterator (audit #31)
- HKDF namespace key cache (LRU, 15-min TTL) in StateStore (audit #36)
- Async TLS cert reads in dashboard (audit #33)
- Combined zero-width char regex into single pattern (audit #38)
- Refreshed CLAUDE.md and README version/tool claims to match v0.9.0-rc.1
- Updated CHANGELOG to Keep-a-Changelog format through rc.3

### Added
- Test coverage for 9 previously untested source files
- Regression tests for 1MB input cap and encoded-payload re-scanning mitigations

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

