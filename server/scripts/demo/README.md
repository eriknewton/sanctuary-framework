# Seeded Demo Fortress

Run a disposable fortress for dashboard demos:

```sh
SANCTUARY_PASSPHRASE='demo passphrase' npx tsx scripts/demo/seed-fortress.ts --port 3517 --no-open
```

The script redirects `HOME` and `SANCTUARY_STORAGE_PATH` to a fresh temp directory, sets `SANCTUARY_DASHBOARD_AUTO_OPEN=false`, never touches the login keychain, and refuses port `3501` so the operator's real dashboard is not reused.

| Seeded item | Product path used | Read path | Status |
| --- | --- | --- | --- |
| Four protected agents | `upsertPersistedLocalAgent`, the same persisted hub registry path that protecting an agent (`sanctuary wrap`) uses | `GET /api/hub/agents` | Seeded |
| Two pending approvals | `DashboardApprovalChannel.requestApproval` | `GET /api/pending` | Seeded |
| One Sentinel finding | `SentinelDispatcher.reportFinding` | `GET /api/sentinels/findings` | Seeded |
| Verified audit chain marker | `AuditLog.query` over the persisted chain, then `AuditLog.appendCritical` | `GET /api/audit-log` | Seeded |
| Blocked egress event | No macOS kernel-enforcer verdict is minted by this fixture | `GET /api/audit-log` | Not available on this fixture |

The fortress label is prefixed with `demo-`, using the existing fortress id label path. No new persisted demo flag is written.
