---
title: WP-V1.2-4 Follow-up — Click-to-Chat UX Polish — build subthread handoff
type: subthread_handoff
spawn_prompt: Review/Sanctuary/Click_To_Chat_UX_Polish_Spawn_Prompt_2026-04-30.md
worktree: .claude/worktrees/gracious-keller-73d058 (harness-managed; renamed branch to wp-v1.2-4-followup-click-to-chat)
base_sha: 72cc6ef (origin/main; F9 squash-merge from PR #97)
branch: wp-v1.2-4-followup-click-to-chat
commit: 9602926
pr: https://github.com/eriknewton/sanctuary-framework/pull/98
status: PR open; CI pending at handoff write
---

# Click-to-Chat UX Polish — subthread handoff

## What shipped

Direct-agent chat session-open is now synchronous on the operator's click. Removed the second confirmation (Tier 1 inbox approval ask) on the click-to-chat path; the click affordance IS the operator's affirmative action.

Server side:
- `HubService.openDirectAgentSession` (new): synchronous direct call to `OperatorChatService.openDirectAgentSession`; returns the session record. Emits `direct_agent_session_open` with `approval_inbox_item_id: null`.
- `HubService.requestDirectAgentSession`: `@deprecated`; legacy inbox-routed shape retained for back-compat; same Tier 1 inbox flow.
- `POST /api/hub/chat/agents/:id/session/start`: returns 200 + session record (was 202 + inbox_item_id).
- `principal-policy/loader.ts`: `direct_agent_session_open` moved from `tier1_always_approve` to `tier3_always_allow` with comment.

Dashboard SPA (`server/src/dashboard/v1_1/client.ts`):
- `onDirectAgentStart` hits the synchronous route and populates `sessionByAgentId` on response.
- Optimistic render via `clickInflightAgentId` (replaced the inbox-pending intermediate UI).
- CTA copy: "Open direct chat" (was "Open direct chat (Tier 1)").

Type changes:
- `OperatorChatSession.approval_inbox_item_id`: `string` → `string | null`.
- `OperatorDirectAgentSessionOpenPayload.approval_inbox_item_id`: same nullable change.
- `OperatorChatService.openDirectAgentSession({approvalInboxItemId})`: now optional with default `null`.

Tests:
- `test/hub/chat-routes.test.ts`: 5 tests rewritten + 1 added (synchronous shape, audit-event nullable check, no-inbox-item invariant). Net +1 test.
- `test/dashboard/v1_1/dashboard-welcome.test.ts`: 2 tests reframed.
- `test/principal-policy/policy-loader.test.ts`: +1 test for Tier 3 reclassification.

Total: 10 files / 242 insertions / 101 deletions / +1 test.

## Real-server drill output

Wrapped Claude Code + OpenClaw in `/tmp/click-to-chat-drill` against built dist:
- `POST /session/start` → 200 + session record + `approval_inbox_item_id: null`
- Inbox query after session-start: 0 items (no Tier 1 approval enqueued)
- Operator message persists with role=operator
- Active sessions: 2 (one per agent), both with null approval_inbox_item_id
- Activity feed: `direct_agent_session_open` → `operator_direct_agent_chat` → `direct_agent_session_close` lifecycle
- Served HTML: `clickInflightAgentId` × 5, `>Open direct chat<` × 1, deprecated framing × 0

## Hard gates

- typecheck clean
- 3248 tests passing / 3 skip; baseline 3161 unchanged (87 headroom)
- `npm audit --omit=dev`: 0 vulnerabilities
- non-dependency hold preserved
- em-dash, naming-discipline, dead-claims sweeps clean
- F9 round-trip preserved
- audit emission preserved; only trigger path changes

## Deviation flags surfaced in PR body

1. **Audit shape: `approval_inbox_item_id` is now `string | null`.** Spawn prompt anticipated this in §4.7. Alternatives (synthetic id; field omission) considered and rejected.
2. **Real-browser drill scope.** Curl-driven drill against built dist verified wire-level behavior; visual rendering at 800/1280/1440/1920 px requires a manual pass on Erik's MBA before merge.
3. **File scope vs estimate.** Spawn prompt scoped ~50-150 lines / ~5 files; PR is ~341 lines / 10 files. Type changes ripple through types + audit-event contract; test rewrites are honest.

## Open items for coordinator

- Erik's manual real-browser pass at the four widths (acceptance criterion 9 partial; the curl drill closes the wire-level loop).
- Spawn prompt's "v1.0.2 housekeeping" thread for fully removing `requestDirectAgentSession` is a v1.3 cleanup, not this PR.
- F10 (autonomous-poll wake) is unblocked — composable with this PR; queue spawn prompt next.

## Setup notes worth carrying forward

- Harness placed me in `.claude/worktrees/gracious-keller-73d058/` (not the spawn-prompt-prescribed path). Reusing that worktree was the right call vs creating a duplicate; renamed the branch from `claude/gracious-keller-73d058` → `wp-v1.2-4-followup-click-to-chat` to match PR convention.
- Pre-commit hook needed manual install per the spawn-prompt template (worktree workaround).
- A variable named `optimisticOpenAgentId` would have tripped the competitor-name sweep (substring `OpenAgent`); renamed to `clickInflightAgentId`. Worth folding the substring-collision lesson into the spawn-prompt template's variable-naming guidance.
