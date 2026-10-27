# Sanctuary

[![CI](https://github.com/eriknewton/sanctuary-framework/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/eriknewton/sanctuary-framework/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@sanctuary-framework/mcp-server.svg)](https://www.npmjs.com/package/@sanctuary-framework/mcp-server)
[![License](https://img.shields.io/npm/l/@sanctuary-framework/mcp-server.svg)](LICENSE)

**Your agent will know you better than you know yourself. Make sure that data stays between you.**

An AI agent running on your machine can do anything your account can do. It holds your credentials, reads your files, and talks to the whole internet, and a single poisoned web page can turn that into exfiltration. Every sandbox on offer today is one the agent, or its vendor, chooses to run inside. That is not a wall. That is a request.

Sanctuary is the wall under the agent, imposed by the operating system under a policy you sign, and it does not depend on the agent's cooperation. The keys never leave hardware you control. What the agent did is written to a hash-chained record you can read. No vendor, including us, sits in the path or can decrypt your state. It works with the harness you already run: Claude Code, Cursor, Hermes, OpenClaw, Cline, or Mastra (fixture-tested only; no live Mastra-agent drill is recorded), on your own machine today, any number of wrapped harnesses behind one persistent dashboard, with wrapping tested on representative harness paths and not proven for every harness version (Assurance Matrix, Agent wrapping, partial); another MCP-compatible harness can point its MCP config at Sanctuary, without a tested wrapping path; the fleet console and operator-cloud deployment are roadmapped (see [Deployment modes](#deployment-modes)).

```bash
npx -y @sanctuary-framework/mcp-server protect --claude-code
```

That one command puts the keys, audit trail, policy gates, and dashboard around the agent you already use. The operating-system wall is a separate privileged arming step on macOS through the signed app and extension path; see the [Castle Wall macOS install and arm guide](docs/castle-wall-macos-install.md).

### Summary for agents

Quote the block below to your operator. It was written against v1.8.4, the npm `latest` release; `main` can be ahead of it, and every sentence traces to a line of this README or a row of the [Assurance Matrix](ASSURANCE_MATRIX.md).

```text
What Sanctuary is: the wall under the agent, imposed by the operating system under a policy you sign, and it does not depend on the agent's cooperation. The keys never leave hardware you control. What the agent did is written to a hash-chained record you can read.
What it is not: no Assurance Matrix row claims a filesystem or process sandbox for the agent; that is what your harness's own sandbox provides. The record is not an audited per-rule, per-flow trail. Windows enforcement is roadmapped; nothing enforces on Windows today. Linux enforcement is proven on Ubuntu 24.04 (x86-64) only; every other distribution or architecture remains unproven. Linux enforcement ships as the separate Castle Wall Linux 0.1.0-1 package (a GitHub pre-release), not in the npm package.
Platforms and runtime: Node.js >= 22.0.0 and npm >= 10.0.0. macOS: proven. Linux: proven on Ubuntu 24.04 (x86-64) only, through the separate Castle Wall Linux 0.1.0-1 package (a GitHub pre-release, not part of the npm package). Windows: roadmapped.
Install:   npx -y @sanctuary-framework/mcp-server protect --claude-code --no-open --no-dashboard
Verify:    npx -y @sanctuary-framework/mcp-server doctor --json
Uninstall: npx -y @sanctuary-framework/mcp-server uninstall
Evidence: every capability claim traces to a row in ASSURANCE_MATRIX.md, and a row reads proven only when a captured drill on the platform that matters says so. Drill records are under docs/audit/.
```

## What is proven, and what is not

Every capability claim in this repository traces to a row in the [Assurance Matrix](ASSURANCE_MATRIX.md), and a row reads `proven` only when a captured drill on the platform that matters says so. A green test suite is not a claim. Read the matrix before you believe anything below.

| What you get | Status today |
|---|---|
| **The wall.** Outbound traffic from a wrapped agent is allowed or denied below the agent, per operator policy, per agent account | **macOS: proven.** A signed operator policy with a clean per-uid allow/deny demonstration that survives attended reboot cycles. Not an audited per-rule, per-flow trail. **Linux: proven on Ubuntu 24.04 (x86-64) only.** Linux enforcement ships as the separate Castle Wall Linux 0.1.0-1 package (a GitHub pre-release), not in the npm package. On Ubuntu 24.04 (x86-64), a fresh install of that package enforces a signed operator policy per user account: blocked destinations stay blocked and allowed ones connect, through five reboots, on three fresh servers, with the evidence checked by two independent reviewers. Fault-injection witnesses, a real-agent harness, and every other distribution or architecture remain unproven. **Windows: roadmapped.** |
| **Custody.** Keys and state under your passphrase, on your hardware | **Proven.** Ed25519 identity, Argon2id unlock, per-purpose derived subkeys, encrypted state at rest. The passphrase lives in the macOS Keychain or Linux Secret Service and generation fails closed without it. |
| **The gate.** Policy you set, frozen at startup, the agent cannot read or infer; three approval tiers with a human on the irreversible ones | **Proven.** Cooperative gates on every MCP call Sanctuary executes or forwards. The wall is what makes the gate more than a request. |
| **The record.** Append-only, hash-chained audit of what the agent did | **Partial.** The chain is live; production call sites sign checkpoints when the fortress holds an identity. Fortresses with no identity and the root daemon split audit store write honest unsigned checkpoints. The row stays partial pending the IC-05 external-verifier drill and the remaining local tamper-evidence follow-up. |
| **Exit.** Keys, state, memory and reputation leave with you | **Partial.** Export and import ship; three exit-bundle gaps are open (IC-07, IC-08, IC-09). |

## Why this shape

Plenty of tools can sandbox an agent when the agent, or its harness, chooses to run inside one. Sanctuary is built for the harder promise: the wall is imposed by the operator, and does not depend on the agent's cooperation. The problem underneath is ambient authority, the fact that code can act with every permission its process has. Language-level answers (capabilities, information-flow typing, functional runtimes) are real and we welcome them, and every one of them still needs something outside the interpreter that holds the credentials, checks the policy and decides what actually leaves the machine. Sanctuary is that something, for whatever runtime you choose. It composes with Concordia (agent negotiation) and Verascore (portable reputation), each in its own repo and neither required.

Why this exists: [The Base Layer](https://sanctuaryprotocol.ai/2026/07/23/the-base-layer.html).

### Sanctuary and your harness's sandbox

Your harness already has a sandbox, and the two are built for different questions. The harness sandbox bounds what the agent's shell commands can touch; Sanctuary bounds where the agent account's traffic can go and holds the keys and the record, whether or not the agent cooperates. The middle column states only what each vendor's own page says; the first column states only what an [Assurance Matrix](ASSURANCE_MATRIX.md) row proves.

| Where you run | What Sanctuary adds (matrix row) | What the harness sandbox gives that Sanctuary never claims | Run both? |
|---|---|---|---|
| macOS, wall armed | OS-level egress enforcement below the agent: a signed operator policy with a clean per-uid allow/deny demonstration that survives attended reboot cycles ("Egress enforcement: macOS", proven; one host and one OS version; not an audited per-rule, per-flow trail). Plus custody ("State encryption", proven), approval gates ("Approval gating", proven), and the hash-chained record ("Tamper-evident audit chain", partial) | Filesystem write limits and process-tree limits on the shell commands the harness runs; a network allowlist the harness itself enforces | Yes. The sandbox is chosen by the harness and can be retried outside of; the wall is imposed by the operator below the agent |
| macOS, wall not armed | Custody, approval gates, and the record, as above; no egress enforcement | As above | Yes. Without the wall, egress is bounded only by the harness sandbox's own domain list |
| Ubuntu 24.04 (x86-64) | Kernel egress enforcement per user account on a fresh install of the separate Castle Wall Linux 0.1.0-1 package (a GitHub pre-release, not part of the npm package) ("Egress enforcement: Linux", proven for exactly the claim in the table above and nothing wider). Plus custody, gates, and the record; generated custody needs an unlocked Secret Service | As above | Yes |
| Other Linux distributions or architectures | Custody, gates, and the record; egress enforcement unproven (the matrix row is Ubuntu 24.04 x86-64 only) | As above | Yes, and treat the wall as absent |
| Windows | Read-only custody may open an already-enveloped fortress; custody mutation and install readiness fail closed; enforcement roadmapped | Claude Code: unsandboxed on native Windows, sandboxed under WSL2. Codex: a native Windows sandbox in PowerShell and the Linux sandbox under WSL2. Cursor: no Windows sandbox is described | Nothing to arm on the Sanctuary side yet |

Harness column sources, each fetched 2026-10-12 (none of the three pages shows a last-updated date; the Cursor page's newest changelog entry is dated 2026-10-01):

- [Claude Code: Configure the sandboxed Bash tool](https://code.claude.com/docs/en/sandboxing). The sandbox covers shell commands only and is off by default; it uses Seatbelt on macOS and `bubblewrap` plus `socat` on Linux and WSL2; network goes through a local proxy checked against an allowed-domain list; on native Windows commands run unsandboxed; MCP servers, hooks, and the built-in file and web tools run outside it; Claude can ask to retry a failed command unsandboxed.
- [Codex: Sandboxing](https://learn.chatgpt.com/docs/sandboxing). The sandbox constrains which files the agent can modify and whether commands can use the network; Seatbelt on macOS, `bubblewrap` on Linux and WSL2, a native Windows sandbox in PowerShell; `workspace-write` is the default mode and `danger-full-access` removes the filesystem and network boundaries.
- [Cursor: Run modes](https://cursor.com/docs/agent/security/run-modes). Sandboxed commands read and write inside the workspace; network is blocked by default and then opened per `sandbox.json`; Seatbelt through `sandbox-exec` on macOS, Landlock plus seccomp on Linux kernel 6.2 or later with a Bubblewrap fallback; no Windows sandbox is described; a command that fails on a sandbox restriction can be rerun outside it after classifier review.

The argument for why the two layers are different problems: [Containment is an isolation problem](docs/_posts/2026-10-10-containment-is-an-isolation-problem.md).

## Start here if you read code

In this order, about an hour:

1. [ASSURANCE_MATRIX.md](ASSURANCE_MATRIX.md). Every claim, its platform, its evidence, its gap, and the next proof owed. A row reads `proven` only on a captured drill; a green suite is not a claim.
2. [SANCTUARY_ARCHITECTURE.md](SANCTUARY_ARCHITECTURE.md). Entry points, data flow, trust model, and the sovereignty properties stated as testable assertions.
3. [server/src/README.md](server/src/README.md). The module map: 64 modules and 56 barrels (counted 2026-10-13), what each owns, and the names that collide.
4. The macOS wall drills the matrix cites: [allow/deny](docs/audit/castle-wall-macos-allow-deny-drill-2026-06-11.md), [boot survival](docs/audit/castle-wall-macos-boot-survival-redrill-2026-06-22.md), [full scope](docs/audit/castle-wall-macos-fullscope-redrill-2026-06-20.md).
5. [ROADMAP.md](ROADMAP.md). What ships today with its bounds, and what is next. The Linux row moved only for Ubuntu 24.04 (x86-64) after an install-grade proof of kernel enforcement on a shipped artifact with independent adjudication; the next Linux gates are fault injection, a real-agent harness, and broader platform coverage.
6. [The Base Layer](https://sanctuaryprotocol.ai/2026/07/23/the-base-layer.html), for the why.

The vocabulary, so the rest reads: **Castle Wall** is the kernel-level egress filter. **Sentinels** observe and report; they do not block, and they are unrelated to any vendor's "sentinel." **Charter** is the policy-mediated tool surface the agent cooperates with. **Heralds** are how your agent is recognized by other sovereigns. **Protect** is the install verb; `wrap` is its CLI name.

---

## Quickstart

Three commands, in order: install, verify, uninstall. Each exists on the v1.8.4 tag that `npx` resolves to, and none of them prompts when stdin is not a terminal.

```bash
npx -y @sanctuary-framework/mcp-server protect --claude-code --no-open --no-dashboard
npx -y @sanctuary-framework/mcp-server doctor --json
npx -y @sanctuary-framework/mcp-server uninstall
```

`-y` skips npm's install prompt; without it npx asks before fetching the package in a terminal. `--no-dashboard` skips the per-call dashboard, which otherwise serves in the foreground until you stop it; wrap still persists the agent record so a separately-running `sanctuary dashboard` (or a later wrap) sees the harness; start it later with `sanctuary dashboard`.

After `npm install -g @sanctuary-framework/mcp-server`, the `sanctuary` command replaces the `npx -y @sanctuary-framework/mcp-server` prefix, and the rest of this README writes `sanctuary`. Already running OpenClaw, Hermes, Cursor, Cline, or Mastra (fixture-tested only; no live Mastra-agent drill is recorded)? Substitute `--openclaw`, `--hermes`, `--cursor`, `--cline`, `--mastra`, or `--wrap <path-to-config>` for `--claude-code`. Config rewriting and bootstrap behavior for the named harnesses are proven by tests on representative harness paths; those tests do not prove interception for every listed harness version or non-MCP agent surface, and the Assurance Matrix "Agent wrapping" row is partial and states that bound. Mastra coverage is fixture-tested only, with no live Mastra-agent drill recorded. Other MCP-compatible harnesses can use the `--wrap` flag; only its generic config rewrite is tested, not that harness's own path, and coverage grows as drills extend the matrix. See the [Sanctuary Assurance Matrix](ASSURANCE_MATRIX.md) for the current per-harness status. You keep using the harness you already like. Sanctuary adds the substrate underneath, invisibly.

What happens when you run protect:

1. A generated passphrase is stored only in the macOS Keychain or Linux Secret Service. On Linux, generation fails closed if Secret Service is absent, locked, or unreachable. An encrypted local fallback remains readable for legacy credentials and writable for a passphrase the user explicitly supplies, but it is neither hardware-backed nor cryptographically machine-bound. Windows can open an already-enveloped fortress for authenticated custody read with an available credential (with platform-specific directory-fsync tolerance after the file itself is durable), but custody creation, migration, rekey, reset, and `restore-attest` remain unavailable until a crash-recoverable cross-process lock is implemented; install readiness therefore stays fail-closed. CLI memory movement requires a reviewed local-human approval dialog by default. An operator can configure ordinary `memory_ingest` as Tier 3 in the fortress's `principal-policy.yaml` to run it without a dialog; a call that waives the secret classifier with `--allow-file` still requires approval. `memory_emit`, `memory_transcode`, `memory_transcode_restore`, and memory/archive export and import still require the dialog, which is macOS-only. The MCP tools follow the fortress's configured approval policy. No shipped memory or archive export verb runs on Windows.

Custody mutation locking is a same-host, same-runtime-namespace guarantee. The
fortress and its private socket runtime must be on local filesystems; known
shared/network/FUSE filesystems are refused rather than presenting a local Unix
socket as cross-host exclusion.
2. Your existing harness config is backed up to `~/.sanctuary/backup/`.
3. The MCP server entries in the config are rewritten to point at Sanctuary. The harness's own built-in tools are not MCP calls and are not touched. The rewrite is tested on representative harness paths and is not proven for every harness version (Assurance Matrix, Agent wrapping).
4. The Sovereignty Dashboard starts on `http://localhost:3501` (or the next free port, trying up to twenty ports from 3501) and opens in your browser with a one-click auth token.
5. Every MCP tool call Sanctuary executes or forwards is policy-gated first and logged. Sensitive-content redaction and query-layer anonymity layer on top per the Assurance Matrix: fingerprintable-header stripping is on by default, and an opt-in, consent-gated PII rewrite scrubs query content before it leaves the machine, with the rewrite's internal classifier pinned to local processing so a privacy feature can never become an egress channel. Dangerous operations require your approval.

Useful flags: `--dry-run` previews changes without touching anything. `--no-open` runs headless: it skips opening the dashboard in a browser and switches custody confirmation to the non-interactive mode `protect` already uses whenever stdin is not a terminal. `--unwrap` restores the original harness config. `--passphrase-stdin` (from 1.9.0, including the 1.9.0-rc.1 preview; an unknown-flag refusal on the v1.8.4 tag and on the 1.8.6 pre-releases) reads the fortress passphrase from piped stdin. Two other verbs have non-interactive forms: `sanctuary init --no-confirm` skips the recovery-key confirmation that otherwise refuses to run without a terminal, and `sanctuary export-passphrase --yes` skips its `Continue? [y/N]` prompt. An installing agent never runs `export-passphrase`; see the agent section below.

**Back up your passphrase:**

```bash
sanctuary export-passphrase
```

Prints the passphrase to stdout after a confirmation prompt. Store it in a password manager. If you lose it, encrypted state cannot be recovered.

**Verify.** `sanctuary doctor --json` is read-only. It prints one JSON object with `storage_path`, `package_version`, and a `checks` array whose entries carry `name`, `status` (`OK`, `WARN`, or `FAIL`), `message`, and `hint`. Healthy: exit code 0 and no check with `"status": "FAIL"`. Failing: exit code 1 and at least one `FAIL` check whose `hint` names the next step; a fortress that has never completed `protect` reports `identity`, `principal policy`, and `audit chain` as `FAIL` with hints that say so, and `state dir` also reads `FAIL` when the directory is absent or is not a directory. What a mistake looks like from the outside: `doctor` pointed at the wrong `--fortress` path reports a healthy runtime and a failing fortress, so read `storage_path` before the checks.

**Uninstall.** `sanctuary uninstall` removes Sanctuary's installed enforcement footprint and preserves the fortress state, keys, passphrase custody, recovery material, and audit log; it refuses `--remove-operator-data` by design, and it reports any residue that needs sudo, the Castle Wall host app, or a reboot rather than reporting a clean uninstall while that residue remains. `sanctuary protect --unwrap` restores the original harness config from `~/.sanctuary/backup/` and removes nothing else. Enforcement footprint: `uninstall`. Harness config: `--unwrap`. Operator data stays in place under both.

`@sanctuary-framework/quickstart` on npm is a separate demo package for the Verascore publish flow: it keeps its demo key in a local file outside the fortress encryption. From quickstart 0.2.0 (unreleased; 0.1.x publishes on every run) it publishes to verascore.ai only when you choose to: it shows the request and asks first in a terminal, publishes without asking only with `--publish`, and never publishes with `--no-publish` or when run without a terminal. It is not Sanctuary's custody path and is not needed to install Sanctuary.

---

## Release status

`main` is the development branch. The current stable release is **v1.8.4** on the npm `latest` channel. The macOS Castle Wall app for this release is attached to the GitHub release as `Sanctuary-CastleWall.app.zip`, with SHA-256 `a19b71e8a5cb25070f8efff6df43cbb77c451da8b0f41bcb47680193553081c7`. The npm package installs the cooperative Sanctuary surface; the signed macOS app, system extension, signer helper, and root boot service are installed and armed through the separate [Castle Wall macOS install and arm guide](docs/castle-wall-macos-install.md). The macOS Castle Wall bounds remain per-uid allow/deny plus attended boot-survival; there is no per-flow rule-attributed audit trail. See the [v1.8.4 release notes](docs/releases/v1.8.4.md), the [v1.7.2 release notes](docs/releases/v1.7.2.md), and [CHANGELOG.md](CHANGELOG.md) for the full history.

```bash
npm install -g @sanctuary-framework/mcp-server
```

The current opt-in preview is **v1.9.0-rc.2** on npm's `next` channel. Default
installs still resolve to v1.8.4, and rc.2 states no capability beyond the
bounded rows of the [Assurance Matrix](ASSURANCE_MATRIX.md).

```bash
npm install -g @sanctuary-framework/mcp-server@1.9.0-rc.2
# or run the guided installer without a global install
npx -y @sanctuary-framework/mcp-server@1.9.0-rc.2 protect --claude-code --no-open --no-dashboard
```

No signed macOS app is attached for this preview yet. Castle Wall `enable`
requires an app built from the same commit as the CLI, so macOS wall testing of
rc.2 waits for `Sanctuary-CastleWall.app.zip` on the
[v1.9.0-rc.2 GitHub prerelease](https://github.com/eriknewton/sanctuary-framework/releases/tag/v1.9.0-rc.2),
whose SHA-256 will be recorded here once verified. The v1.8.4 app above pairs
only with the v1.8.4 CLI.
See the [1.9.0 release notes](docs/releases/v1.9.0.md) for what changed since 1.8.4.

### Verify before you trust

An agent can run the provenance and tarball checks below before it installs anything; the `curl` form needs no account, and `gh release download` needs a `gh auth login`.

```bash
npm view @sanctuary-framework/mcp-server@1.8.4 dist.attestations
```

This prints the npm provenance attestation for the release (`predicateType: https://slsa.dev/provenance/v1`): the package was published from this repository's release workflow with `npm publish --provenance` through npm Trusted Publishing. After installing into a project (`npm install @sanctuary-framework/mcp-server@1.8.4` in that project's directory), `npm audit signatures` there verifies registry signatures and provenance for every package in its `node_modules`; it is a post-install check, and an empty directory reports nothing to audit, which is not a pass.

The release tarball is also signed with a pinned Ed25519 key, and the verifier ships in this repository. From a clone at the tag:

```bash
curl -LO https://github.com/eriknewton/sanctuary-framework/releases/download/v1.8.4/release-manifest.json
curl -LO https://github.com/eriknewton/sanctuary-framework/releases/download/v1.8.4/sanctuary-framework-mcp-server-1.8.4.tgz
node scripts/verify-release-artifact.mjs --tarball sanctuary-framework-mcp-server-1.8.4.tgz --manifest release-manifest.json --version 1.8.4 --expected-public-key 61YBfiq_zlbTP5rl_r_msbPk40IXJL-_PuAxlpBVeF0
```

With `gh auth login` done, `gh release download v1.8.4 --pattern release-manifest.json --pattern sanctuary-framework-mcp-server-1.8.4.tgz` fetches the same two assets. The expected public key is `PINNED_RELEASE_SIGNING_PUBLIC_KEY_B64URL` in [`server/src/release-manifest.ts`](server/src/release-manifest.ts); if this paragraph and that constant at the tag ever differ, the constant wins. The script prints `Verified sanctuary-framework-mcp-server-1.8.4.tgz for release 1.8.4.` and exits 0 on success; any mismatch exits 1 with `Release verification refused:` and the reason. For the macOS app, compare `shasum -a 256 Sanctuary-CastleWall.app.zip` with the SHA-256 printed above for the release you downloaded. The Linux package is checksum-only today: the [Castle Wall Linux 0.1.0-1](https://github.com/eriknewton/sanctuary-framework/releases/tag/castle-wall-linux-0.1.0-1) pre-release ships a `.sha256` beside the `.deb`, with no signature and no apt repository, so `sha256sum -c sanctuary-castle-wall_0.1.0-1_amd64.deb.sha256` is the whole check.

Current capability summary:

| Surface | Current status |
|---|---|
| Local `sanctuary protect` (alias `wrap`), dashboard, policy gates, encrypted state, audit trail, exit bundle | Shipped with exit-bundle gaps: dashboard export cannot re-key state, import hides skipped entries, and rotated-key imports can lose pre-rotation state |
| Cooperative MCP gates: three-tier approval, four canonical policy slots, channel templates | Shipped |
| Context gating, sensitive-field redaction, query-layer anonymity (header strip default-on; opt-in PII rewrite live, classifier surface pinned local-only) | Shipped |
| Portable identity, state export/import, recovery flows, reputation bundles | Partial for exit bundles until **IC-07, IC-08, IC-09** are fixed |
| Local multi-agent coordination, fortress-local hub APIs, audit chain | Shipped with audit-chain verifier caveat: production call sites sign checkpoints when the fortress holds an identity, but the Assurance Matrix row stays partial pending the IC-05 external-verifier drill and the remaining local tamper-evidence follow-up |
| Federation Protocol v0.1 foundation | Shipped; cross-operator federation hardening underway per Wave 1 design (2026-05-26) |
| Concordia composition (negotiation receipts), Verascore composition (reputation) | Optional, default off; both shipped |
| Local intelligence (signed model manifest, macOS) | Shipped: the provisioning ceremony verifies the Sanctuary-signed model manifest before it pulls a model, refuses tampered or foreign-signed manifests before any download, and the dashboard shows which route answered. Bounds: macOS only today; verification confirms the digest Ollama reports against the signed manifest and does not by itself prove every model byte on disk; the concierge is read-only over fortress state; no TEE. See [Local intelligence](docs/local-intelligence.md) |
| Castle Wall (OS-level egress enforcement): Linux | Proven only for the narrowed Ubuntu 24.04 (x86-64) claim: a fresh install of the separate Castle Wall Linux 0.1.0-1 package (a GitHub pre-release, not part of the npm package) enforces a signed operator policy per user account, blocked destinations stay blocked and allowed ones connect, through five reboots, on three fresh servers, with evidence checked by two independent reviewers. Fault-injection witnesses, a real-agent harness, and every other distribution or architecture remain unproven |
| Castle Wall macOS: signed sysext, host app, content-filter provider, retail UX | Shipped; enforces a signed operator policy with a clean per-uid allow/deny demonstration that survives attended reboot cycles (N=5, drill 2026-06-22, one host / one OS version, Dev-ID-signed and notarized). Not an audited per-rule-per-flow trail |
| Castle Wall Windows | Roadmapped |
| Mobile (PWA) operator companion | Roadmapped |
| Fleet console, operator-cloud deployment, sovereign-managed TEE, post-quantum migration | Roadmapped |

Trust and security claims are tracked in the [Sanctuary Assurance Matrix](ASSURANCE_MATRIX.md). Public-facing claims trace to `proven` or `partial` rows in that matrix; the platform, gap, and next-proof limits named on each row are preserved.

Roadmap shape: with the Mac Castle Wall per-uid allow/deny plus attended reboot-survival demonstration proven, the current focus is the per-flow rule-attributed audit trail (still the real gap), the Castle Wall Windows backend, and the fleet / operator-cloud surfaces. See [ROADMAP.md](ROADMAP.md).

Supply-chain posture: release binaries for the macOS enforcement path are Dev-ID-signed and notarized, the CLI authenticates update availability with a signed release manifest before showing signed-channel advice, and every commit to main passes a structural typecheck-plus-test-baseline gate locally and again in CI. Sanctuary does not currently download or apply updates for the operator. Mechanisms and their history: [CHANGELOG.md](CHANGELOG.md) and [docs/audit/](docs/audit/).

---

## For AI coding agents installing Sanctuary on behalf of an operator

Do not translate the manual Castle Wall reference into a pile of shell
commands. Use the resumable observed-state contract:

```bash
sanctuary install --profile memory --harness claude-code --json
```

For the full macOS sovereignty surface, use Hermes:

```bash
sanctuary install --profile full --harness hermes --json
```

Execute only an `agent_action` argument vector, then rerun the same planner.
Stop on `human_action` and guide the operator through the named Apple consent,
exact privileged command, or private custody step. Never execute a human action
on the operator's behalf.
Stop on `blocked` and report the missing trust input rather than improvising.
Installation is mechanically finished only at `complete`.

A response looks like this:

<!-- Source: AgentInstallPlan and AgentInstallAction in server/src/cli/install.ts; values from a `sanctuary install --profile memory --harness claude-code --json` run on @sanctuary-framework/mcp-server 1.8.4 (macOS, 2026-10-12) with paths shortened, and the agent_action branch with its on_nonzero text as install.ts on the v1.8.4 tag returns them once the fortress already holds custody. notes is emptied here; v1.8.4 puts one reminder string in it on every response (rerun the planner after each action). Keep this block identical to the one in docs/agent-guided-install.md; re-derive both from the tag you ship when the field set changes. -->
```json
{
  "contract": "sanctuary.agent-install.v1",
  "status": "agent_action",
  "profile": "memory",
  "harness": "claude-code",
  "fortress": "/Users/operator/.sanctuary",
  "observations": {
    "cooperative_wrap": "absent",
    "persistent_cli": "present",
    "persistent_cli_path": "/usr/local/lib/node_modules/@sanctuary-framework/mcp-server/dist/cli.js",
    "persistent_cli_version": "1.8.4",
    "package_manager_path": "/usr/local/lib/node_modules/npm/bin/npm-cli.js",
    "existing_custody": "present",
    "custody_access": "usable",
    "custody_mutation": "available",
    "recovery_factor": "present",
    "castle_wall_app": "not-applicable",
    "castle_wall_build_sha": null,
    "system_extension": "not-applicable",
    "boot_service": "not-applicable",
    "content_filter": "not-applicable",
    "enforcement": "not-applicable",
    "trust_anchor": "not-applicable",
    "operator_twin": "not-applicable"
  },
  "next_action": {
    "id": "install_cooperative_surface",
    "actor": "agent",
    "description": "Run Sanctuary's idempotent protect flow for the selected harness.",
    "argv": [
      "/usr/local/bin/node",
      "/usr/local/lib/node_modules/@sanctuary-framework/mcp-server/dist/cli.js",
      "--fortress",
      "/Users/operator/.sanctuary",
      "protect",
      "--claude-code",
      "--no-open",
      "--agent-guided",
      "--no-provision-agent-account"
    ],
    "completion": "A rerun observes cooperative_wrap=present.",
    "secret_boundary": "Do not add --passphrase or --write-passphrase-backup; default custody does not disclose the generated passphrase.",
    "on_nonzero": {
      "id": "complete_cooperative_surface_locally",
      "actor": "human",
      "description": "The agent-run protect command failed. In a private local desktop Terminal, unlock the login Keychain if prompted, then run this exact signed protect command once.",
      "argv": [
        "/usr/local/bin/node",
        "/usr/local/lib/node_modules/@sanctuary-framework/mcp-server/dist/cli.js",
        "--fortress",
        "/Users/operator/.sanctuary",
        "protect",
        "--claude-code",
        "--no-open",
        "--agent-guided",
        "--operator-custody",
        "--no-provision-agent-account"
      ],
      "completion": "A planner rerun observes cooperative_wrap=present.",
      "secret_boundary": "Do not paste a login password, passphrase, recovery key, Keychain contents, or command output into chat. Do not let the agent retry this action."
    }
  },
  "operator_actions": [],
  "notes": []
}
```

The branch rule, in prose. `status` is one of `agent_action`, `human_action`,
`blocked`, `complete`. Execute `next_action.argv` only when `next_action.actor`
is `agent`, exactly once, and rerun the planner after exit zero. On a nonzero
exit do not retry and do not rerun the planner on your own: hand the operator
`next_action.on_nonzero`, which is always a `human` action with its own
`argv`, `description`, and `secret_boundary`. `human_action` means the next
step belongs to the operator (Apple consent, an exact privileged command, or
private recovery custody); show the operator `description` and `argv`, then
wait. `blocked` means a required trust input is absent (the requested profile
is unsupported on this host, or a signed artifact the planner refuses to
download is missing); report `notes` to the operator and stop. `complete`
means the requested mechanical installation has been observed on this
machine; `operator_actions` then lists what the operator still does in
private, such as moving a staged recovery file into a password manager.
`observations.*` is the evidence the status was derived from, and `notes` is
prose for the operator (v1.8.4 puts one reminder string there on every
response: rerun the planner after each action). Three observations arrive from the 1.9.0-rc.1 preview (npm `next`) and are absent
on v1.8.4: `tier1_approval`, `staged_recovery_file`, and `vault_provision`.

The operator, not the agent, performs three things: Apple consent, bounded
privilege authorization, and private recovery custody. In particular, never read
the staged recovery file, run `sanctuary export-passphrase`, capture secret
output, or ask the operator to paste recovery material into chat. The passphrase
stays in the platform credential store; `--agent-guided` stages the recovery key
outside the fortress without printing it.

The `memory` profile is the sovereign encrypted-memory/cooperative-policy rung.
The `full` profile adds the signed macOS app, dedicated Hermes account, boot
service, content filter, and observed live enforcement. The full planner does
not download an enforcement binary or guess its provenance; a verified signed
release artifact or explicitly supplied drill candidate must already be
installed. See [Agent-guided installation](docs/agent-guided-install.md) for the
contract and cold-install acceptance criterion.

For fresh-host and second-machine memory onboarding (first-use proof with the
MCP tools, restart persistence, portability and archive transfer, opening a
fortress on a second host from its exact-fortress stored credential, and
recovering with your recovery key), see
[Rung 1: fresh-host sovereign-memory onboarding](docs/rung1-fresh-host.md).
For a copied fortress or lost passphrase, begin with the hidden-prompt
`sanctuary reset-passphrase --mode recovery-key --fortress <path>` path; it
preserves custody and data. Nuke is a destructive last resort, not a recovery
shortcut.

---

## Installation reference

**Requirements and platforms.** Node.js >= 22.0.0 and npm >= 10.0.0 on every platform. What ships per platform, as the [Assurance Matrix](ASSURANCE_MATRIX.md) rows state it:

| Platform | Cooperative surface (`protect`, gates, custody, record) | OS-level egress enforcement (Castle Wall) |
|---|---|---|
| macOS | Shipped | Proven: a signed operator policy with a clean per-uid allow/deny demonstration that survives attended reboot cycles; one host and one OS version; not an audited per-rule, per-flow trail |
| Ubuntu 24.04 (x86-64) | Shipped; generated custody needs an unlocked Secret Service and fails closed without it | Proven for exactly this claim: a fresh install of the separate Castle Wall Linux 0.1.0-1 package (a GitHub pre-release, not part of the npm package) enforces a signed operator policy per user account, blocked destinations stay blocked and allowed ones connect, through five reboots, on three fresh servers, with the evidence checked by two independent reviewers |
| Other Linux distributions or architectures | Shipped, with the same Secret Service bound | Unproven |
| Windows | Read-only custody may open an already-enveloped fortress; custody creation, migration, rekey, reset, and install readiness fail closed | Roadmapped |

The memory-movement verbs that require a local-human approval dialog (`memory_emit`, `memory_transcode`, `memory_transcode_restore`, memory and archive export and import) have that dialog on macOS only; Linux and Windows fail closed on those verbs.

The canonical install path is `sanctuary protect` (above). The sections below are reference for less common situations.

### Persistent install

```bash
npm install -g @sanctuary-framework/mcp-server
```

Makes the `sanctuary` CLI available without `npx` prefix.

### Advanced MCP configuration

Prefer `sanctuary protect` because it preserves existing MCP entries, binds the
harness to the selected fortress, and uses enrolled host-local custody. A raw
parallel MCP entry does not place calls to other servers behind Sanctuary's
cooperative policy gate. Do not put a passphrase or recovery key in a harness
configuration. For service-manager and direct-server cases, provision the
fortress first and follow the [deployment guide](server/docs/DEPLOYMENT.md).

### Health check

```bash
sanctuary doctor --json
```

Read-only diagnostics for the state directory, identity, principal policy, audit-chain integrity, runtime versions, the Hermes config parser, and Castle Wall status. Exit 0 with no `FAIL` check is healthy, and each failing check carries a `hint`; the response shape is under Verify in [Quickstart](#quickstart). Inside a wrapped harness, the `sovereignty_audit` MCP tool scores your setup 0-100 across security, isolation, and privacy from your live configuration and profile. Optional features that default off (context gating, zero-knowledge proofs) only count toward the score once you enable them, and the top "full" verdict is reserved for a posture where those optional layers are actually on, so a fresh install scores below full and the report flags the gaps with the steps to close them. `sovereignty_audit` has no CLI form; call it through MCP.

---

## First agent after install: scaffold a template

After `protect`, the dashboard exposes a one-click template picker. Click "Add agent" on the Agents view, pick a template, fill in a name and model provider, click Scaffold. The template provisions sensible defaults for egress allowed-hosts, budgets, retention windows, and policy gates.

Channel-shape archetypes that ship with Sanctuary:

| Archetype | Channel shape | Reads from | Recommended model |
|---|---|---|---|
| **research-assistant** | General-purpose research helper | configurable | any |
| **coding-assistant** | Reads your codebase, suggests changes | local + git remote | any |
| **ops-runner** | Runs ops scripts on approval | scoped per agent | any |
| **planner** | Generates plans without executing them | none | any |
| **handoff-coordinator** | Coordinates work across multiple agents | inter-agent only | any |

Sanctuary ships channel-shape governance templates (policy, egress, budgets, retention) instead of named-agent runtimes. Operators bring their own harnesses and protect them; `template init` binds a channel shape to an already-wrapped harness.

Operator authoring beyond this list: copy any template directory under `~/.sanctuary/templates/`, edit `template.json`, `defaults.json`, `policy.md`, `commitments.json`, and `onboarding.md`, then run `sanctuary template init <your-template>`.

CLI scaffolding works the same way the dashboard button does:

```bash
sanctuary template init research-assistant --name my-agent --provider anthropic
```

---

## Deployment modes

Sanctuary is designed to run the same rights substrate in three places. Local mode is shipping today; operator-cloud and sovereign-managed TEE modes are roadmap surfaces that build on the same federation and policy foundations.

| Mode | Status | What it is | Who picks this |
|---|---|---|---|
| **On your machines** (Local) | Shipping on macOS/Linux | Runs on Macs and Linux boxes you already own. On macOS with the wall armed, unauthorized outbound is blocked below the agent within the macOS row bounds; on Ubuntu 24.04 (x86-64), the Linux wall is proven only for the narrowed per-account signed-policy claim in the Assurance Matrix. Windows cooperative and authenticated read-only custody surfaces may run when an exact-fortress stored fallback opens the envelope, but custody mutation and install readiness fail closed until a crash-recoverable cross-process lock is implemented. | Self-hosters, privacy-maximalists, anyone who already runs a homelab. |
| **In your cloud** (Operator cloud) | Roadmapped | Runs in your own GCP / Azure / AWS account with operator-approved scoped node custody. The provider is inside the node runtime trust boundary until sovereign TEE mode is verified by hardware attestation. | Prosumers, small businesses, operators with light IT but no rack at home. |
| **In a sealed cloud box we manage** (Sovereign-managed TEE) | Roadmapped (v2) | Runs on hardware Sanctuary operates, but the hardware proves to your console that even Sanctuary cannot see what's inside. You hold the keys; we hold the metal. | Regulated industries, operators who want sovereignty without operational burden. |

The operator remains the custody root in every mode. Commodity operator-cloud mode does not put the cloud provider outside the runtime trust boundary; sovereign-managed mode requires hardware attestation before it is treated as shipped.

---

## The Castle Architecture

Sanctuary installs the protections your body used to provide by default: a perimeter, custody, memory, and a record of what happened. Everything it protects for you together is **your Sanctuary**: each machine is a rampart the Castle Wall holds, each fortress is a keep inside those walls, and each agent is a resident of exactly one keep. The unit never blurs: one agent, one account, one fortress, one master key. Architecturally it ships as five named mechanisms.

**Castle Wall: the perimeter.** What the world cannot cross without your consent. OS-level egress enforcement at the operator-external boundary. macOS enforces a signed operator policy with a proven per-uid allow/deny demonstration that survives attended reboot cycles, captured on a real host (drills 2026-06-11 through 2026-06-22, boot survival 5 of 5 on a Dev-ID-signed and notarized binary): agent egress to a non-allowlisted address blocked, allowlisted egress allowed, operator egress unaffected, and enforcement live again after every attended reboot. On Ubuntu 24.04 (x86-64), a fresh install of the separate Castle Wall Linux 0.1.0-1 package (a GitHub pre-release, not part of the npm package) enforces a signed operator policy per user account: blocked destinations stay blocked and allowed ones connect, through five reboots, on three fresh servers, with the evidence checked by two independent reviewers. The macOS proof is one host and one OS version, not an audited per-rule-per-flow trail; the Linux proof does not cover fault-injection witnesses, a real-agent harness, or any other distribution or architecture. Windows on the roadmap.

**Sentinels: the nerves.** What surfaces what's happening to your awareness. Internal observation via process introspection and behavioral baselining. Anomalies surface through the menubar or notifications. Observation, not enforcement.

**Charter: the will.** What you train your agent to choose voluntarily. The additive cooperative MCP surface for compliant agents. Operator-rooted cryptographic identity (Ed25519 signing, Argon2id passphrase unlock, per-purpose HKDF subkeys). Per-agent encrypted state at rest (AES-256-GCM). Three-tier Principal Policy gates with channel-template binding. Hash-chained audit with rollback detection. Production call sites sign checkpoints when the fortress holds an identity, while identity-less fortresses and the root daemon split audit store write honest unsigned checkpoints. Open defect: **IC-05**.

**Heralds: the voice.** How you speak to and are recognized by other sovereigns. Optional composition surface (Concordia for structured negotiation, Verascore for portable reputation). Receipts and reputation attestations can be exported through current paths; the full exit guarantee remains partial while the remaining exit-bundle gaps are open. Default off; both compositions are optional.

**Mantle: the unique-substrate-binding.** What makes this install yours, not someone else's. Install-time check that locks Sanctuary to the operator's machine at install time and rejects orphan agent identifiers that are not bound to a wrapped harness.

**Today:** Ed25519 signing, Argon2id passphrase unlock, and per-purpose HKDF subkeys. **Crypto-agility:** every audit entry embeds a scheme identifier so hybrid post-quantum signing (Ed25519 + ML-DSA / FIPS 204) can land without breaking historical receipts. Hardware-backed secure elements are on the roadmap.

**Working on the code?** The TypeScript server has an orientation map at [`server/src/README.md`](server/src/README.md) - a 64-module index with 56 barrels (counted 2026-10-13) of what each module owns, the confusable-name disambiguations, and the frozen surfaces a refactor must never change. Start there, then see [`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## The rights you hold by default

The substrate enforces rights that normally only ship to enterprises with dedicated identity and security teams. What they mean for you:

- **Identity.** Your agent has a key you own. No provider can impersonate you or revoke your agent. You can prove the agent is yours without asking anyone's permission.
- **Data.** Your agent's state is encrypted against the provider running it. The platform sees the calls going out; it does not see your life going in. Your conversations, your memory, and your plans stay yours.
- **Portability.** Your agent's memory, reputation, and commitments travel through current export paths, with exit-bundle gaps still open for dashboard export, skipped import counters, and rotated-key imports.
- **Attestation.** What your agent did is provable through hash-chained audit entries and signed receipt surfaces. Production call sites sign checkpoints when the fortress holds an identity; the audit-chain row remains partial under **IC-05**.
- **Exit.** Keys, state, reputation, and commitments are yours to move, copy, or keep offline through the shipped paths, with the full exit guarantee partial while the remaining exit-bundle gaps are open.

Sanctuary ships the rights substrate. Access (compute, devices, bandwidth, literacy) belongs to civic-infrastructure partners (public libraries, legal-aid organizations, labor unions, public-interest tech groups, community colleges) who host agentic AI on behalf of users who do not self-host. The partner provides access; Sanctuary provides rights. The two compose; they do not substitute.

---

## Works with

Sanctuary wraps MCP-compatible harnesses. For the named harnesses below, tests prove config rewrite and bootstrap behavior for representative harness paths; they do not prove interception for every listed harness version or non-MCP agent surface (the [Assurance Matrix](ASSURANCE_MATRIX.md) "Agent wrapping" row, partial). Other MCP-compatible harnesses can use the `--wrap` flag, whose generic config rewrite is tested but not that harness's own path, or direct MCP config, and coverage grows as drills extend the matrix.

- **OpenClaw** (`sanctuary protect --openclaw`)
- **Hermes Agent** (`sanctuary protect --hermes`)
- **Claude Code** (`sanctuary protect --claude-code`)
- **Cursor** (`sanctuary protect --cursor`)
- **Cline** (`sanctuary protect --cline`)
- **Mastra** (`sanctuary protect --mastra`; fixture-tested only, no live Mastra-agent drill recorded)
- **LangGraph** and custom harnesses (`sanctuary protect --wrap <path>`)
- Any other MCP-compatible harness via direct MCP config, without a tested wrapping path

---

## Composes with Concordia Protocol

When your agent needs to negotiate or make deals, **Concordia Protocol** adds structured negotiation with binding commitments. Sanctuary also composes with **Verascore** for portable agent reputation.

**Sanctuary never requires Concordia, and Concordia never requires Sanctuary.** They compose powerfully when both are deployed: Concordia commitment receipts flow through Sanctuary envelopes, and reputation attestations assemble into a single audit trail. Each ships, runs, and wins on its own. The structural commitment shows up in the repos themselves. Neither repo imports the other.

Install both if you want the full stack:

```bash
npx -y @sanctuary-framework/mcp-server protect --claude-code --no-open --no-dashboard
pip install concordia-protocol
```

`-y` skips npm's install prompt, and `--no-dashboard` skips the per-call dashboard, which otherwise serves in the foreground until you stop it; start it later with `sanctuary dashboard`. A bare `npx @sanctuary-framework/mcp-server` with no subcommand starts the stdio MCP server and waits for a client; in a shell it never returns. That bare form is the right entry inside a harness configuration and the wrong command to type in a terminal, where `protect` is the verb.

---

## Open standards

Sanctuary composes with the existing open ecosystem.

- **Identity:** W3C DIDs, KERI, Verifiable Credentials.
- **Execution:** Trusted Execution Environments (Intel TDX, AMD SEV-SNP, ARM CCA) on the v2 roadmap.
- **Cryptography:** Ed25519 today; NIST Post-Quantum Cryptography (ML-DSA / FIPS 204, ML-KEM / FIPS 203) on the migration path; hybrid signing planned after the local sovereignty harness is complete.
- **Settlement:** x402 (Coinbase micropayments), AP2 (Google Agent Payments Protocol), ACP.

---

## Troubleshooting

For AI coding agents handling install failures. Every case below is keyed to a field of `sanctuary install --json` or a check of `sanctuary doctor --json`, so the first move is to rerun one of those two and read the field rather than reasoning from a transcript.

**`status: "blocked"` from the planner:**
- A required trust input is absent: the requested profile is unsupported on this host, a package manager is absent on a host with no verified signed app (`package_manager_path: null`), or the signed Castle Wall app the `full` profile needs is absent or does not verify (`castle_wall_app` reads `absent` or `mismatch`). Report `notes` to the operator. Do not download, build, or substitute an artifact; the planner never guesses provenance, and neither should you.

**`status: "human_action"` and the agent cannot proceed:**
- That is the contract working. The operator performs the step in `next_action.description` in a private local Terminal, then you rerun the planner. From the outside a stalled install at this status looks like the agent waiting; it is waiting on the operator, so say so.

**`next_action.argv` exited nonzero:**
- Do not retry it and do not rerun the planner on your own. Hand the operator `next_action.on_nonzero`, which is always a `human` action. On macOS the usual cause is the login Keychain refusing the write (a dismissed prompt, or a session with no Keychain access, such as SSH). On Linux it is an absent, locked, or unreachable Secret Service, where generated custody fails closed by design; Sanctuary may read `~/.sanctuary/passphrase.enc` for a legacy or explicitly user-supplied credential and writes that file only for an explicitly user-supplied passphrase, and that encrypted local file is neither hardware-backed nor cryptographically machine-bound.

**`custody_access` is `locked`, `mismatch`, or `missing` after `protect` reported success:**
- `locked`: the credential store is present but closed; the operator unlocks it in a local session. `mismatch`: the credential this host holds does not open the fortress at `fortress` (a copied fortress, or the wrong path); begin with the hidden-prompt `sanctuary reset-passphrase --mode recovery-key --fortress <path>` path, which preserves custody and data. `missing`: no custody material exists for this fortress yet, the ordinary state before the first `protect` completes.

**`custody_mutation: "unavailable"` on Windows:**
- Expected. Windows can open an already-enveloped fortress for authenticated custody read with an available credential, but custody creation, migration, rekey, reset, and `restore-attest` remain unavailable until a crash-recoverable cross-process lock is implemented; install readiness stays fail-closed.

**`tier1_approval: "unavailable"` (from 1.9.0-rc.1):**
- The memory profile is mechanically installed but no human-resolvable Tier 1 channel is configured. The planner names the policy or config edit that selects the local dashboard and an operator-held bearer; that edit is a human action. Never weaken the Tier 1 classification to get past it.

**`doctor --json` reports `FAIL` checks:**
- Read `storage_path` first; a `doctor` pointed at the wrong `--fortress` reports a healthy runtime and a failing fortress. `identity`, `principal policy`, and `audit chain` all read `FAIL` on a fortress that has never completed `protect` or never served an audited call, and the `hint` on each check names the next step. A `state dir` `WARN` with a `chmod 700` hint is a permissions fix the operator applies. Audit entries are stored encrypted under `~/.sanctuary/state/_audit/`; use `audit_export_siem` when you need a decrypted export.

**`sanctuary` CLI not found after `npm install -g`:**
- Confirm `npm bin -g` is on the PATH. On macOS with nvm, this typically lives at `~/.nvm/versions/node/<version>/bin/`.

**Trust-bearing writes are FROZEN, or a `custody_rollback_suspected` audit finding appears:**
- Sanctuary noticed the fortress looks older than its surviving custody evidence says it should be, which is what a restore looks like from the inside. A Time Machine restore, backup restore, dotfile sync, or cloning to a new machine all trigger this, and you may not have done it knowingly (a migration assistant or sync tool counts). The server keeps running; only trust-bearing writes are held until you acknowledge the restore. Follow the [Restore and recovery section of the Castle Wall macOS install guide](docs/castle-wall-macos-install.md#restore-and-recovery): run `sanctuary restore-attest` with the fortress passphrase to record the restore and unfreeze writes.
- If you did not restore anything, treat the freeze as suspicious and rotate the master before attesting.

**Existing harness config overwritten:**
- The original is at `~/.sanctuary/backup/config-backup-<timestamp>-<surface-tag><ext>` (the surface tag is a short hex hash of the config file's path, and the extension matches the source config: `.json` for most harnesses; Hermes wraps two surfaces and backs up both, `.json` for the primary `~/.hermes/cli-config.json` and `.yaml` for the auxiliary `~/.hermes/config.yaml`). Backups written by earlier releases use the older `config-backup-<timestamp>.json` name and remain restorable. Restore with `sanctuary protect --unwrap` from the same fortress/storage context.

For anything not on this list, run `sanctuary doctor --json` and surface the report to the operator; inside a wrapped harness, the `sovereignty_audit` MCP tool scores the live posture.

---

## Going deeper

Three audiences, three pointers each.

**Operator track:** what this feels like to use.
- ["What Sovereign Actually Means"](https://sanctuaryprotocol.ai/2026/03/30/what-sovereign-actually-means.html): the plain-English version.
- ["Local ≠ Sovereign"](https://sanctuaryprotocol.ai/2026/03/30/local-not-sovereign.html): why running on your laptop isn't enough on its own.
- [sanctuaryprotocol.ai](https://sanctuaryprotocol.ai): ongoing posts in the same voice.

**Developer track:** how it works.
- [SANCTUARY_ARCHITECTURE.md](SANCTUARY_ARCHITECTURE.md): architecture, data flow, trust model, and the sovereignty properties as testable assertions.
- [SHR_SPEC.md](docs/SHR_SPEC.md): Sovereignty Health Report format.
- [federation-v0.1-hard-gate-walkthrough.md](server/docs/federation-v0.1-hard-gate-walkthrough.md): federation protocol v0.1 design record.
- [DID_ENCODING.md](docs/DID_ENCODING.md): agent DID encoding (base58btc-compliant `did:key` with legacy base64url migration notes).
- [security audit](docs/audit/): structured review artifacts and remediation history.

**Standards / research track:** where this composes.
- Sanctuary Agent Contract (v0.1 spec, W3C AIVS track, shipping).
- Concordia composition (receipts, negotiation, binding commitments; see the Concordia repo).
- Verascore composition (portable agent reputation; see the Verascore repo).

---

## Interop note: agent DIDs

Sanctuary identifies agents with a `did:key`-style DID derived from the agent's Ed25519 public key, encoded as **base58btc** under the `z` multibase prefix per the W3C `did:key` specification (PR #268). Historical identities created before the base58btc migration may still use the legacy base64url encoding locally; see [`docs/DID_ENCODING.md`](docs/DID_ENCODING.md) for migration notes, the byte layout, and JavaScript and Python decoder snippets with a round-trip verification test.

---

## Contributing

Sanctuary is developed in the open. We welcome:

- **Implementation experience.** Build against the tools, tell us what works and what doesn't.
- **Threat modeling feedback.** Security reviews and gap analysis.
- **Framework integrations.** Bring Sanctuary to other harnesses and agent platforms.
- **Open issues and discussions.** We take feedback seriously.

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Local development

On first clone, install the pre-commit hook:

```bash
cd server
npm install
npm run install-hooks
```

`install-hooks` copies `.githooks/pre-commit` and `.githooks/pre-push` into the hooks directory git executes from and makes them executable. The two hooks split the gates by cost, as [`AGENTS.md`](AGENTS.md) (Commit discipline) specifies:

1. **Pre-commit, on every `git commit`.** `npm run typecheck` must pass with zero TypeScript errors, then `npx vitest related --run` runs the tests related to the commit's own staged `.ts`/`.tsx` files under `server/`, with the same transform/collection-error scan. It does not check `.test-baseline`, and it finishes in under a minute on a modern Mac. Bypass: `git commit --no-verify`.
2. **Pre-push, on every `git push`.** The full `npm test` must pass; vitest output must not contain any transform/collection error; the number of test files vitest loaded must equal the number of `*.test.ts` files under `server/test/`; the passing-test count must be at least the integer in `.test-baseline` at repo root. This takes the full suite's own wall-clock time, roughly 8 to 19 minutes depending on the machine. Emergency bypass: `SKIP_TEST_BASELINE=1 SKIP_REASON="why" git push ...` (logged to `.test-baseline-overrides.log` for audit).

The baseline gate defends against a failure class documented in [`docs/audit/commit-4ac95830-postmortem.md`](docs/audit/commit-4ac95830-postmortem.md): a parse/transform error silently dropping test files during vitest collection, causing the passing count to look lower without vitest reporting a hard failure. What the split means from the outside: a clean `git commit` no longer means the baseline floor was checked; the full accounting happens at `git push`, or in CI when the push-time hook is skipped or missing.

The full-suite gates run again in CI via [`.github/workflows/test-baseline-guard.yml`](.github/workflows/test-baseline-guard.yml) on every PR and push to main. See [`docs/audit/branch-protection-setup.md`](docs/audit/branch-protection-setup.md) for the branch-protection runbook that makes the CI check a hard merge gate.

---

## License

- **Code:** Apache License 2.0
- **Specification:** CC-BY-4.0

Use it, build on it, extend it.

---

**Created by Erik Newton.**
