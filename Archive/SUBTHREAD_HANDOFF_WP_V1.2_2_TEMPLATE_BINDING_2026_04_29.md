# WP-V1.2-2 Template Binding Handoff

Branch: `wp-v1.2-2-channel-template-binding`

## Summary

- Replaced the v1.1 five-template internal library with the six design-canonical templates:
  `request-approve-act`, `read-then-report`, `scheduled-digest`, `plan-draft-only`,
  `fortress-relay`, and `concierge-loop`.
- Converted `POST /api/hub/agents/:agent_id/template` to a Tier 1 `policy_change`
  approval flow. The route accepts `{ "template_id": "<canonical-id>" }` and still
  tolerates the previous `channel_template_id` body key for caller compatibility.
- Added approval and activity rendering for template binding, including before and
  after template provenance in `agent_policy_change_engaged`.
- Reworked the v1.1 Policy page into the Policy Center surface with six cards,
  a Per-agent rules table, and a template picker that submits the Tier 1 binding ask.
- Updated template IDs in starter templates and tests, and bumped `.test-baseline`
  from `2883` to `2886`.

## Verification

- `npm run test -- test/policy-engine/channel-templates.test.ts test/hub/hub-v1.1.test.ts test/dashboard/v1_1/templates.test.ts test/dashboard/v1_1/shell-html.test.ts`
  passed: 68 tests.
- `npm run typecheck` passed.
- `npm run build` passed.
- `npm audit --omit=dev` passed with 0 vulnerabilities.
- Retired ID sweep over `server/src` and `server/test` returned no matches.
- Standalone dashboard served successfully at `http://127.0.0.1:3502/v1.1?token=DEV`
  with isolated storage. The served HTML bundle contains the six template IDs,
  Per-agent rules markup, picker actions, and `template_id` POST body.

## Not Completed

- Full Safari plus Chrome wrapped-agent browser drill was not completed in this
  environment. The local dashboard server ran, but the isolated storage path had
  no wrapped agent, and no browser automation package was installed for viewport
  screenshots. A manual drill should wrap a test harness, bind a different
  template, approve the inbox item, and confirm the table plus activity feed
  update at 800, 1280, 1440, and 1920 px.

## Open Decisions

- Picker shape shipped as an inline dropdown-style picker anchored to the
  Template cell.
- `scheduled-digest` external trigger semantics remain conservative: the template
  encodes read/subscription and egress defaults, not webhook-specific behavior.
- Severity tags are display metadata in this PR. Enforcement remains tied to the
  compiled policy and Tier 1 binding gate.

## 2026-04-29 morning — library reconciliation fix

The initial library reconciliation introduced starter-template test failures
because the new six design-canonical channel templates do not preserve all
operator-visible behaviors of the retired v1.1-internal templates. Specifically:

- ops-runner needs credentials.share; no new template grants credentials
- coding-assistant needs memory.grant plus outputs.subscribe; read-then-report is too narrow
- handoff-coordinator needs plans.grant plus intra-mesh-escrow concordia class
- research-assistant promises no credentials, no plans, and no bidirectional sync; request-approve-act was too broad

Fix shape: introduced `slot_augmentations` on starter `template.json` metadata
that layers persona-specific grants on top of the channel template's base policy.
The channel templates (Policy Center primitives) stay clean and match the
screenshot; starter personas compose channel plus augmentations.

Files changed by this fix:

- `server/src/templates/types.ts`
- `server/src/templates/registry.ts`
- `server/src/templates/init.ts`
- `server/src/templates/coding-assistant/template.json`
- `server/src/templates/ops-runner/template.json`
- `server/src/templates/handoff-coordinator/template.json`
- `server/src/templates/research-assistant/template.json`
- `server/test/console/console-v1.test.ts`
- `server/src/dashboard/v1_1/wiring.ts`
- `server/src/cocoon/cli.ts`
- `server/src/hub/types.ts`
- `server/src/hub/hub-service.ts`

Verification:

- `npm test -- test/templates/template-library.test.ts test/policy-engine/channel-templates.test.ts` passed: 100 tests.
- `npm test -- test/console/console-v1.test.ts test/composition/composition-v1.test.ts` passed: 101 tests.
- `npm test -- test/hub/hub-v1.1.test.ts test/hub/fortress-tier1.test.ts test/drills/v1.1-hub-drill.test.ts test/cocoon/wrap-agent-registry.test.ts` passed: 70 tests.
- `npm test` passed: 3054 passed, 3 skipped.
- `npm run typecheck` passed.
- `npm run build` passed.
- `npm audit --omit=dev` passed with 0 vulnerabilities.
- Real dashboard drill passed against `http://127.0.0.1:3502/v1.1?token=DEV`: wrap registered Claude Code, template binding enqueued Tier 1 `policy_change`, approval persisted `channel_template_id: request-approve-act` and the compiled policy id, and activity feed emitted `activity.lifecycle.agent_policy_change_engaged`.
