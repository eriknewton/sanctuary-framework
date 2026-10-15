# Seeded Demo Fortress

Run a disposable fortress for dashboard demos:

```sh
SANCTUARY_PASSPHRASE='demo passphrase' npx tsx scripts/demo/seed-fortress.ts --port 3517
```

The script redirects `HOME`, `SANCTUARY_STORAGE_PATH`, and the custody-lock root to a fresh temp directory, sets `SANCTUARY_DASHBOARD_AUTO_OPEN=false`, never touches the login keychain, and refuses port `3501` so the operator's real dashboard is not reused.

This is a disposable fixture, not a production fortress. Its agents are hub registry entries built like `sanctuary wrap` records without a harness process behind them, so active rows render as protected for the console's two-minute liveness window and then age to Unknown. The approval requests auto-deny after one hour. The Sentinel row is emitted by a fixture reporter. There is no enforcer in this fixture, so blocked egress and lockdown are not available and are not fabricated.

The operator bearer token is written to `operator-token.txt` inside the printed demo root with mode `0600`. The demo prints only the token file path and a line explaining where to paste it, and no part of the token. The dashboard's own startup line on stderr shows a hint of the token's first and last four characters, as every Sanctuary dashboard does. Paste the file contents into the console when it asks for operator authorization.

| Seeded item | Product path used | Read path | Status |
| --- | --- | --- | --- |
| four protected-agent registry entries | `buildLocalAgentRecord` plus `upsertPersistedLocalAgent`, matching a wrap without a confinement outcome | `GET /api/hub/agents` | Seeded |
| two pending approvals | `DashboardApprovalChannel.requestApproval` for `demo_state_export_request` and `demo_policy_template_change` | `GET /api/pending` | Seeded |
| one Sentinel finding | `SentinelDispatcher.reportFinding` | `GET /api/sentinels/findings` | Seeded |
| blocked egress event | No kernel-enforcer verdict is minted by this fixture | `GET /api/audit-log` | Not available on this fixture |
| locked-down agent | No approval or verified enforcement probe is run by this fixture | `GET /api/hub/agents` | Not available on this fixture |

The fortress label is prefixed with `demo-`, using the existing fortress id label path. No new persisted demo flag is written.

The CLI owns the empty private root before seeding begins. SIGINT or SIGTERM during seeding closes started resources, removes the root, and reports an interruption (exit 130 or 143 respectively). After the dashboard is ready, either signal stops it and removes the root with exit 0. Startup errors also remove the root. If the root cannot be removed, the CLI prints `Could not remove demo root <root>: <reason>` and keeps an earlier nonzero exit code; otherwise it exits 1. Add `--keep` to retain the root after a stop or startup failure; a kept root includes any token file already written.

For a kept root, stop its demo process first, then run the printed `--teardown <root>` command. Teardown accepts only a demo-prefixed directory directly under the platform temp parent, needs that path as its value (a bare `--teardown` is a usage error and starts nothing), and refuses a live pid recorded in its mode-0600 `demo.pid` file. A reused pid can cause a safe refusal; an invalid pid file also refuses removal. With no pid file or a dead pid, teardown proceeds. Trying teardown while the demo is running leaves the root intact and prints the pid and root in one error line.
