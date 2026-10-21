# Seeded Demo Fortress

Run a disposable fortress for dashboard demos:

```sh
SANCTUARY_PASSPHRASE='demo passphrase' npx tsx scripts/demo/seed-fortress.ts --port 3517
```

The script redirects `HOME`, `SANCTUARY_STORAGE_PATH`, and the custody-lock root to a fresh temp directory, sets `SANCTUARY_DASHBOARD_AUTO_OPEN=false`, never touches the login keychain, and refuses port `3501` so the operator's real dashboard is not reused.

This is a disposable fixture, not a production fortress. Its agents are hub registry entries built like `sanctuary wrap` records without a harness process behind them. The console shows an agent as protected only with current per-agent enforcement evidence, and this fixture has no enforcer, so every seeded agent reads Unknown rather than protected. The Sentinel row is emitted by a fixture reporter. There is no enforcer in this fixture, so blocked egress and lockdown are not available and are not fabricated.

## Held approvals

The two held approvals are raised through the real approval gate, as the named agent's MCP server would raise them:

- a Tier 1 `state_export` from the first seeded agent (`state_export` is always Tier 1 under the default policy);
- a Tier 2 `state_write` to a namespace the session has not seen, from the second seeded agent (a first write to a new namespace is a Tier 2 anomaly under the default policy).

Each card's Agent column shows the requester: the agent the asking server process is configured for, from the same server-set agent id a wrapped harness carries. The card's sentence names the operation but no target, because the card does not carry the call's arguments. Deciding a hold from the console releases it the way production does, and the gate writes its own decision entry to the audit log: operation `gate_approve:<operation>` or `gate_deny:<operation>`. That entry is on the layer the console labels Sentinels, which is where production records gate decisions, so to find it on the Evidence screen search for `gate_approve` rather than filtering to Charter. The fixture writes no decision entry of its own. Its only Charter-layer entry is the `demo_approvals_seeded` marker. A decided hold also appears under the Approvals screen's Decided filter for the life of the demo process.

The holds auto-deny after one hour, and stopping the demo auto-denies any hold still open; the gate records both as denials, as it would in production. Reset the demo shortly before presenting (see below).

## Operator token

The operator bearer token is written to `operator-token.txt` inside the printed demo root with mode `0600`. The demo prints only the token file path and a line explaining where to paste it, and no part of the token. The dashboard's own startup line on stderr shows a hint of the token's first and last four characters, as every Sanctuary dashboard does. Paste the file contents into the console when it asks for operator authorization.

Add `--token-file <path>` to keep one token across runs. If the file does not exist, the demo mints a token and creates the file with mode `0600`. If it exists, the demo reuses its token, so a console tab that already has the token keeps working after a restart. A reused file must be a regular file you own with no group or other permission bits, holding one token; anything else is refused and the demo does not start. Failure mode: a refused token file prints `refusing demo token file ...` and exits 1 before any demo root is created; fix the file's mode or remove it and rerun.

## One-command reset

From `server/`:

```sh
npm run demo:reset
```

This stops the demo that the previous `demo:reset` started, then starts a fresh one on port 3517 with `--token-file ~/.sanctuary-demo/operator-token`, and prints the dashboard URL, the token file path, the log path and the stop command. The token is the same after every reset, so reload the open tab instead of pasting the token again. A full reset takes about three seconds.

- `SANCTUARY_DEMO_PORT`, `SANCTUARY_DEMO_STATE_DIR` and `SANCTUARY_DEMO_PASSPHRASE` override the port, the state directory (token, log, and the record of the last demo), and the throwaway fortress passphrase. Your own `SANCTUARY_PASSPHRASE` is not used.
- When it starts a demo, the reset records that process's pid, its start time and its demo root in `demo-instance` in the state directory. On the next run it signals that pid only if all three still match: the pid is alive, its start time is unchanged, and the demo root's own `demo.pid` names it. If any of them differs, it signals nothing, prints the `kill -TERM <pid>` command to run yourself if that process is your demo, and exits 1. Remove `demo-instance` after checking, then rerun.
- Failure mode: a demo started by hand on the same port is not stopped, so the new demo fails to bind and the reset prints the log tail with an address-in-use error; stop the hand-started demo and rerun.
- Failure mode: if a crashed demo left its root behind and the guarded teardown cannot remove it, the reset keeps its record, prints the root's path and exits 1; remove that root and rerun.
- Failure mode: if the previous demo does not exit within ten seconds, the reset stops with a message and starts nothing; stop that pid by hand and rerun.

| Seeded item | Product path used | Read path | Status |
| --- | --- | --- | --- |
| four registry agents | `buildLocalAgentRecord` plus `upsertPersistedLocalAgent`, matching a wrap without a confinement outcome | `GET /api/hub/agents` | Seeded |
| two pending approvals | `ApprovalGate.evaluate` for `state_export` (Tier 1) and `state_write` to a new namespace (Tier 2), each raised as a seeded agent | `GET /api/hub/inbox` | Seeded |
| one Sentinel finding | `SentinelDispatcher.reportFinding` | `GET /api/sentinels/findings` | Seeded |
| blocked egress event | No kernel-enforcer verdict is minted by this fixture | `GET /api/audit-log` | Not available on this fixture |
| locked-down agent | No approval or verified enforcement probe is run by this fixture | `GET /api/hub/agents` | Not available on this fixture |

The fortress label is prefixed with `demo-`, using the existing fortress id label path. No new persisted demo flag is written. Seeded agents keep their registry ids (`agent:<harness>:fortress-<id>`), because the registry has no display-name field and the id must match what a real wrap writes.

The CLI owns the empty private root before seeding begins. SIGINT or SIGTERM during seeding closes started resources, removes the root, and reports an interruption (exit 130 or 143 respectively). After the dashboard is ready, either signal stops it and removes the root with exit 0. Startup errors also remove the root. If the root cannot be removed, the CLI prints `Could not remove demo root <root>: <reason>` and keeps an earlier nonzero exit code; otherwise it exits 1. Add `--keep` to retain the root after a stop or startup failure; a kept root includes any token file already written.

For a kept root, stop its demo process first, then run the printed `--teardown <root>` command. Teardown accepts only a demo-prefixed directory directly under the platform temp parent, needs that path as its value (a bare `--teardown` is a usage error and starts nothing), and refuses a live pid recorded in its mode-0600 `demo.pid` file. A reused pid can cause a safe refusal; an invalid pid file also refuses removal. With no pid file or a dead pid, teardown proceeds. Trying teardown while the demo is running leaves the root intact and prints the pid and root in one error line.
