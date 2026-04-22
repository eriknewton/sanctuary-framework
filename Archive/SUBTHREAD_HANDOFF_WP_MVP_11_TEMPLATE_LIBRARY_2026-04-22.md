---
title: "WP-MVP-11 Template Library Starter Set v1.0 — Subthread Handoff"
status: complete
created: 2026-04-22
branch: wp-mvp-11-template-library
pr: "#41"
commit: 66b6821
base_sha: 163ed39
---

# WP-MVP-11 Template Library Starter Set v1.0 — Subthread Handoff

## What shipped

PR #41 on branch `wp-mvp-11-template-library` against base `163ed39`.

**34 files / 1823 insertions.** Five canonical agent templates, template registry, init logic, CLI subcommands, dashboard API routes, and 87 integration tests.

### Files created

- `server/src/templates/types.ts` — TemplateMetadata, TemplateDefaults, TemplateCommitments, TemplateBundle, TemplateRegistryEntry types
- `server/src/templates/registry.ts` — Lazy-loading template registry with validation, lint, cache
- `server/src/templates/init.ts` — Deterministic CompiledPolicy builder from template bundles
- `server/src/templates/cli.ts` — CLI subcommands (list, init)
- `server/src/templates/index.ts` — Barrel export
- `server/src/templates/{research-assistant,coding-assistant,ops-runner,planner,handoff-coordinator}/` — Five template bundle directories (5 files each)
- `server/test/templates/template-library.test.ts` — 87 integration tests

### Files modified

- `server/src/cli.ts` — Added `template` subcommand dispatch + help text
- `server/src/dashboard/api.ts` — Added `GET /api/templates` and `GET /api/templates/:name` routes
- `.test-baseline` — 2074 -> 2161 (Linux-CI floor estimate)

## Deviations from spawn prompt

**None.** All five templates, all CLI subcommands, all API routes, all eight acceptance criteria implemented exactly as specified.

## Design decisions made in-thread

1. **Deterministic `compiled_at`:** Template init fixes `compiled_at` to a version-derived timestamp (2026-01-01T00:00:00.000Z for all v1.0.0 templates) so the CompiledPolicy canonical JSON is byte-stable across runs. The signed event envelope naturally differs (unique event_id + emitted_at per emission) but the inner `policy_blob` is identical.

2. **Template loading from source:** Templates are loaded from the source directory (`server/src/templates/`), not from compiled `dist/`. The registry detects dist-mode paths and resolves back to src. This means templates are inspectable by operators as shipped source files.

3. **Channel template factory reuse:** Templates compose on top of the shipped WP-MVP-5 channel template factories via `applyChannelTemplate`. No new policy engine surfaces created; templates are pure overlays of egress/budget/retention/commitment-class on top of existing channel templates.

4. **CLI `init` is preview-only:** The `sanctuary template init` command builds and displays the compiled policy but does not sign it (no node key available in CLI context without a running server). It outputs the policy blob and tells the operator to use `packPolicyUpdate` with their node signing key to emit the signed event. The `initTemplate` function in code does the full sign+emit for programmatic use.

5. **Lint check at load time:** The naming-discipline + no-em-dash lint runs at template bundle load time, not just in tests. A template with em-dashes will fail to load with a `TemplateValidationError`.

## Acceptance criteria results

| # | Criterion | Status |
|---|-----------|--------|
| 1 | Five templates load end-to-end | PASS |
| 2 | Deterministic template load | PASS |
| 3 | Policy engine compile-path coverage | PASS |
| 4 | Defaults respect shipped surfaces | PASS |
| 5 | Registry API returns all five | PASS |
| 6 | Public-facing copy clean | PASS |
| 7 | Signed-event fields correct | PASS |
| 8 | Baseline + CI | typecheck clean, 0 vulns, baseline updated |

## Test counts

- macOS: 2214 passed / 3 skipped (168 test files)
- .test-baseline: 2161 (Linux-CI floor estimate; macOS-Linux gap historically ~53 tests)
- New tests: 87

## Escalation items

None. No new `event_class`, envelope extension key, capability bit, `event_type` prefix, retention slot, or channel template was needed. All five templates compose cleanly on shipped WP-MVP-5 + WP-MVP-6 surfaces.

## Coordinator state files

This subthread did NOT write to COWORK_CONTEXT.md, TASKS.md, or any `.claude/` file.
