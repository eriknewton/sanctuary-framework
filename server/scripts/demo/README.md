# Seeded Demo Fortress

Run a disposable fortress for dashboard demos:

```sh
SANCTUARY_PASSPHRASE='demo passphrase' npx tsx scripts/demo/seed-fortress.ts --port 3517
```

The script redirects `HOME`, `SANCTUARY_STORAGE_PATH`, and the custody-lock root to a fresh temp directory, sets `SANCTUARY_DASHBOARD_AUTO_OPEN=false`, never touches the login keychain, and refuses port `3501` so the operator's real dashboard is not reused.

This is a disposable fixture, not a production fortress. Its agents are hub registry entries built like `sanctuary wrap` records without a harness process behind them, so active rows render as protected for the console's two-minute liveness window and then age to Unknown. The approval requests auto-deny after one hour. The Sentinel row is emitted by a fixture reporter. There is no enforcer in this fixture, so blocked egress and lockdown are not available and are not fabricated.

The operator bearer token is written to `operator-token.txt` inside the printed demo root with mode `0600`. The token is never printed; paste the file contents into the console when it asks for operator authorization.

| Seeded item | Product path used | Read path | Status |
| --- | --- | --- | --- |
| four protected-agent registry entries | `buildLocalAgentRecord` plus `upsertPersistedLocalAgent`, matching a wrap without a confinement outcome | `GET /api/hub/agents` | Seeded |
| two pending approvals | `DashboardApprovalChannel.requestApproval` for `demo_state_export_request` and `demo_policy_template_change` | `GET /api/pending` | Seeded |
| one Sentinel finding | `SentinelDispatcher.reportFinding` | `GET /api/sentinels/findings` | Seeded |
| blocked egress event | No kernel-enforcer verdict is minted by this fixture | `GET /api/audit-log` | Not available on this fixture |
| locked-down agent | No approval or verified enforcement probe is run by this fixture | `GET /api/hub/agents` | Not available on this fixture |

The fortress label is prefixed with `demo-`, using the existing fortress id label path. No new persisted demo flag is written.
