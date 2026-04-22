# Subthread Handoff: WP-MVP-11 Follow-up #1

**Branch:** `wp-mvp-11-followup-1`
**PR:** #48
**Base:** `c2f90fd` (WP-MVP-10 squash-merge)
**Spawn prompt:** `Review/Sanctuary/WP-MVP-11_Followup_1_Console_and_X-Miner_Spawn_Prompt_2026-04-22.md`

---

## Decision A: X-Miner + GitHub-Miner

**Pick:** Ship both (recommended default).

**Rationale:** GitHub-Miner uses a single personal access token (fine-grained PAT) passed via the secret broker, which is the same single-API-key shape as X-Miner's xAI API key. No material divergence in broker-credential plumbing. Marginal cost was ~20 minutes (template directory + onboarding.md + egress swap).

## Decision B: "Add Agent" button on Agents view

**Pick:** "Add Agent" button on Agents view (recommended default).

**Rationale:** PR #46's Agents view has a clear `action-bar` div pattern (used by Fortress view for transition buttons) and the empty-state message naturally leads to the action. The button opens a template-picker `<dialog>` modal with a two-step flow: (1) pick a template card, (2) configure and scaffold. No new view was needed.

---

## Shipped surfaces

### 1. POST `/api/templates/:name/init` endpoint
- **File:** `server/src/dashboard/api.ts:184-240`
- **Routes through:** `initTemplate()` from `server/src/templates/init.ts` (same code path as CLI)
- **Request body:** `{ agent_name: string, model_provider: string, overrides?: { egress_allow: string[] } }`
- **Response:** `{ agent_id, signed_event_id, policy_version, template_name, attestation_panel_url }`
- **Validation:** agent_name required, alphanumeric+hyphens+underscores only, template must exist
- **Signing:** uses `deps.nodeId/nodePrivateKey/principalId` if configured; falls back to ephemeral 32-byte key

### 2. Console scaffolding flow
- **HTML:** `server/public/console/index.html` - "Add Agent" button (line 66), template-picker dialog (lines 182-210)
- **JS:** `server/public/console/console.js` - `openTemplatePicker()`, `selectTemplate()`, `handleScaffoldSubmit()` functions
- **CSS:** `server/public/console/console.css` - template card grid, scaffold readonly fieldset, policy preview
- **Flow:** Add Agent button → fetch GET /api/templates → card grid → click card → fetch GET /api/templates/:name → scaffold form (agent name, model provider, policy preview, egress) → POST init → success message + agent roster refresh

### 3. X-Miner template
- **Directory:** `server/src/templates/x-miner/` (5 files)
- **Channel:** `read-outputs-only`
- **Tier:** B (adapter-wrapped)
- **Egress:** `api.x.ai` (POST)
- **Budget:** 100k tokens/day, $5 USD/month
- **Retention:** memory 30d, outputs 90d
- **Commitment classes:** `data-delivery`, `output-publish`

### 4. GitHub-Miner template
- **Directory:** `server/src/templates/github-miner/` (5 files)
- **Channel:** `read-outputs-only`
- **Tier:** B (adapter-wrapped)
- **Egress:** `api.github.com` (GET)
- **Budget:** 100k tokens/day, $5 USD/month
- **Retention:** memory 30d, outputs 90d
- **Commitment classes:** `data-delivery`, `output-publish`
- **Default model_provider:** `anthropic` (operator can switch to `mistral`)

---

## Acceptance criteria traceability

| Criterion | Test file | Lines |
|-----------|-----------|-------|
| POST init endpoint returns 200 with agent_id + signed_event_id | `test/templates/x-miner-sla.test.ts` | 79-90 |
| POST init rejects missing agent_name | `test/templates/x-miner-sla.test.ts` | 104-115 |
| POST init rejects invalid agent_name | `test/templates/x-miner-sla.test.ts` | 117-130 |
| POST init returns 404 for unknown template | `test/templates/x-miner-sla.test.ts` | 132-143 |
| GitHub-Miner scaffolds through same path | `test/templates/x-miner-sla.test.ts` | 93-102 |
| Full path under 600s wall clock | `test/templates/x-miner-sla.test.ts` | 63-91 |
| X-Miner loads, lints, inits with signed policy_update | `test/templates/template-library.test.ts` | 68-117 (loop over TEMPLATE_NAMES) |
| GitHub-Miner loads, lints, inits with signed policy_update | `test/templates/template-library.test.ts` | 68-117 (loop) |
| X-Miner defaults respect shipped surfaces | `test/templates/template-library.test.ts` | 178-280 (loop) |
| Onboarding no-em-dash lint passes | `test/templates/template-library.test.ts` | 336-345 (loop) |
| Deterministic template load (byte-equal) | `test/templates/template-library.test.ts` | 122-155 (loop) |
| Console template-picker dialog exists | `test/console/console-v1.test.ts` | 430-435 |

---

## Deviations from spawn prompt

1. **Test count assertions updated.** Three assertions in `template-library.test.ts` changed from hardcoded `5` to `TEMPLATE_NAMES.length`. These checked "exactly five templates" which is naturally wrong after adding X-Miner and GitHub-Miner. The existing `for (const name of TEMPLATE_NAMES)` loops auto-test the new templates. This is a mechanical count fix, not a behavioral regression.

2. **Console dialog count assertion updated.** One assertion in `console-v1.test.ts` changed from `<= 1` to `<= 2` to accommodate the template-picker dialog alongside the existing envelope dialog. Both dialogs are verified by ID.

3. **xAI API host stability.** Verified `api.x.ai` as the current xAI Grok API endpoint. This is the domain xAI documents for API access as of 2026-04-22.

---

## v1.x backlog candidates

- **Signed template manifests.** Templates ship as plain dir bundles at v1.0. v1.x could add content-hash signing to detect tampering of shipped templates.
- **Model-provider dropdown population from a registry.** Currently hardcoded to xai/anthropic/openai/mistral in the scaffold form. v1.x could populate from a live provider registry.
- **Custom template authoring from console.** Operators authoring new templates currently use the CLI (`sanctuary template list` + dir-bundle copy). v1.x could add a console-based template editor.
- **Egress override composition.** The POST init endpoint accepts `overrides.egress_allow` but the current scaffold form only supports adding one extra host. v1.x could support multiple additions and removals.

---

## Test counts

- **macOS (pre-commit):** 2541 passed, 3 skipped (168 test files)
- **Baseline:** bumped from 2436 to 2541 (macOS floor; Linux-CI floor TBD from CI run)
- **Typecheck:** clean
- **npm audit:** 0 vulnerabilities
