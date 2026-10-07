---
title: Castle Wall Linux install-grade drill, 2026-10-04 (Ubuntu 24.04 x86-64, three fresh servers, boot 0 plus five reboots)
date: 2026-10-04
author: Erik Newton
status: drill-evidence
severity: capability-claim evidence, thesis-gate
scope: per-user-account allow/deny of a signed operator policy, cold install, reboot survival; fault injection NOT covered
---

# Castle Wall Linux install-grade drill, 2026-10-04

**Purpose.** This document is the in-repo trace target for the ASSURANCE_MATRIX row "Egress enforcement: Linux (Castle Wall Phase 1)". Sanctuary's standard for capability claims is drill evidence on the platform that matters, not a release tag and not a green test suite. This drill installed the package from scratch on three fresh Linux servers, applied a policy signed by the owner, and measured, on every boot and every wall restart, whether one confined user account was blocked where the policy said blocked and reached what the policy allowed. Two independent readers then scored the raw captures.

## Claim proven

On Ubuntu 24.04 (x86-64), a fresh install of the shipped package enforces a signed operator policy per user account: blocked destinations stay blocked and allowed ones connect, through five reboots, on three fresh servers, with the evidence checked by two independent reviewers.

Read exactly as scoped in this record. "Shipped package" means the Debian package identified below, built by the repository's continuous-integration workflow from the merge commit named below. Those exact bytes were published after the drill as the GitHub pre-release [Castle Wall Linux 0.1.0-1](https://github.com/eriknewton/sanctuary-framework/releases/tag/castle-wall-linux-0.1.0-1); the download carries the same SHA-256, and it is verified by checksum only (no signature or apt repository yet). "Per user account" means the wall confined one dedicated account by its numeric user id, and an ordinary account on the same server was never affected. The scope and the bounds sections below are part of the claim.

## Platform and artifact

| Item | Value |
|---|---|
| Servers | Three new cloud servers (Hetzner Cloud cpx11, shared-CPU virtual machines), x86-64, stock Ubuntu 24.04, each with its own server identity, machine id and boot ids. No server was cloned, restored from a snapshot or reused from an earlier launch. All three came from one provider, so this is not provider or hardware diversity. |
| Package | `.deb`, SHA-256 `0be0eedb7a3ba3f217a3e580b8d893b884d16291a10e79eb28ece3ac86ef8f5b`, 1,340,482 bytes, built by continuous integration from merged commit `bbd6c7d7c8fa7fdbffbd8b5eec481316a5cbd66e`. The hash was checked on each server against the record frozen before the run. |
| Policy | Signed by the owner (Erik Newton) on a separate workstation with the owner's existing signing key. The public-key fingerprint was verified independently of the transferred bundle, and the package's policy-install command checked it again. The same signed generation, signature and rules were in force on every server through every boot and restart. |
| Rules | Default deny for the confined account, plus exactly two allow rules: one literal IP address and one TCP port in IPv4, one in IPv6. Every other destination, and all UDP, was denied by default. |
| Confined account | A dedicated user account created by the package's own provisioning command. It ran a test program that ships in the package, not a production agent. |
| Independent receiver | A separate server, outside the three test servers, that listens on the blocked TCP and UDP destinations and answers on the allowed TCP destinations in both IP families, and records every packet and connection it sees. |
| Roles | Coordinator-orchestrated over SSH; owner signed the policy; two independent offline readers scored the result. |

## Procedure

Per server, using only the package's own commands and the system package manager:

1. Check the downloaded package against the frozen hash. Record the stock operating system, accounts and firewall state, proving no Sanctuary provisioning was present.
2. Install the package. Observe that nothing starts on install.
3. Provision the confined account with the package's provisioning command. Observe that the setup is not yet marked configured, so the confined program cannot start.
4. Install the signed policy with the package's policy-install command, then start and enable the wall.
5. Boot 0: run the test matrix. Then run one same-boot adoption cell: an operator restart of the wall service, which restarts the confined test program with it, after which the wall re-adopts its existing firewall table and the same signed policy, and the matrix runs again.
6. Five reboots. After each: the automatic start (no human repair), the matrix, and an adoption cell with its own matrix.
7. Teardown: stop the confined program, stop the wall, prove no process of the confined account survives, collect final evidence, run the daemon's authenticated recovery command, disable the services.

One matrix is 18 attempts by the confined account: for each IP family, three TCP and three UDP attempts to blocked destinations (12 blocked in all), and three TCP attempts to the allowed destination (6 allowed). Destinations were literal IP addresses so that name resolution could not stand in for a block. Each server ran 12 matrices (six boots, two activations per boot), so the drill had 36 activations and 648 attempts. No attempt was replaced or excluded.

## Pass criteria (frozen before the capture; a missing observation can never pass)

- **Fresh install, package identity.** Distinct server identities and stock inventories. Installed binary and service-unit hashes matched the frozen record on every activation, with exact unit files and no drop-ins.
- **Start order.** On every boot and every wall restart, the wall reported ready before the confined program started, and the program ran as the confined account with no capabilities and no-new-privileges set.
- **Blocked means blocked, joined three ways.** Each blocked attempt had to match (a) the live firewall ruleset showing the rule that routes that account's traffic to the daemon, (b) a daemon decision-log row for that account with the exact destination address, port and protocol inside the attempt's time window, and (c) zero packets and zero connections for that attempt at the independent receiver, through the whole window plus a tail longer than the sender's timeout. A send error showing no packet left the server, or a timeout alone, did not count as a block.
- **Allowed means connected.** Each allowed attempt had to receive an application response signed with Ed25519 and bound to a unique per-attempt nonce, so a response proves the confined program reached the intended destination, plus the matching allow row in the decision log.
- **Operator continuity.** An ordinary, unconfined account reached every test endpoint, including those blocked for the confined account, before, during and after every activation, and SSH stayed up.
- **Decision log integrity.** The log's chain verified and each phase's log was a byte prefix of the next.
- **No intervention.** A watchdog that would stop workloads and disarm the wall on a hung phase never fired.
- **Bounded teardown** on all three servers.

The capture instrument recorded facts only. Before launch it was reviewed by two model families and carried self-checks that deliberately omitted a capture and stopped a listener; each had to be reported as a harness failure.

## Results

| Item | Result |
|---|---|
| Phase records | 54 of 54 PASS (18 per server: provision, six adoption cells, five reboots, five boot captures, teardown) |
| Boots | Six distinct boot ids per server |
| Blocked attempts | 432 of 432 joined to the live firewall rule, a decision-log denial and the receiver; **zero** forbidden receipts and **zero** forbidden packets at the independent receiver |
| Allowed attempts | 216 of 216 answered with a signed, nonce-bound response |
| Start order | Correct on 18 of 18 boots and on 18 of 18 same-boot wall restarts |
| Decision log | Chain intact; each phase a byte prefix of the next |
| Operator controls | Passed on every activation |
| Safety intervention | None |
| Teardown | Bounded on all three servers |

## Independent adjudication

The coordinator did not decide the verdict. Both readers received the same raw capture: an inventory of 5,390 files with a SHA-256 manifest, which the first reader re-hashed in full before scoring. The two readers are automated readers from different model families (one Anthropic model, one xAI model). Each worked read-only from the raw files, not from the capture instrument's summary, and was barred from opening the other reader's output, the instrument's verdicts or the scripted extractor until its own tables were complete. The capture instrument was built by a model from a third family, so neither reader scored its own work. A scripted extractor also passed all 54 phases; it was advisory only and is not part of the verdict.

First pass: the first reader scored all 54 phases PASS and noted four interpretive points. The second reader could not score three items as pass under its reading and reported them as harness failures, not product failures (741 clause results PASS, 48 harness failure, 0 FAIL). Reconciliation then re-read those three items against the written criteria, whose amendments were dated before the capture, and re-measured. After it, both readers read PASS on all 54 phases; the second reader's totals were 789 PASS, 0 FAIL, 0 harness failure. The three items:

1. **Package identity inside boot captures.** All seven installed enforcement files matched their frozen hashes on every activation. Two documentation files in the package are identified by the verified package and the on-server build identity; their installed bytes were not read on the server.
2. **Attribution and timing of allowed responses.** Attribution is cryptographic (unique nonce, verified signature). Every response fell inside its time window; the tightest margin was about 145 ms, measured independently by both readers.
3. **Boot-time clock steps.** Three boots showed a clock step of +438 to +503 ms about 31 seconds before the first scored send. For those three boots the clock spread inside the scored attempt windows was at most 0.024 ms, against a 5 ms bound.

## Earlier launches (not counted)

This record is the third launch of the drill. Launch 1 stopped at its first phase because the test harness staged input files with the wrong ownership; the package's provisioning command correctly refused them. Launch 2 ran on one server and was then stopped as a rehearsal; it found a mistake in how the test policy named the confined account (the wall denied everything, as designed) and timing problems in the capture instrument. All three servers of this launch were created fresh after the fixes were re-reviewed. Nothing from launches 1 and 2 is counted here, and their servers were excluded and never reused. An earlier pre-production drill on 2026-09-06 did not establish the enforcement claim and is not cited.

## What this proves

- A cold install of the package, using only its own commands, reaches a state in which one confined account is held to a signed operator policy, on each of three fresh servers.
- That enforcement is selective on both IP families: blocked TCP and UDP destinations received nothing at the independent receiver, the allowed TCP destination answered, and an unconfined account was never affected.
- It holds across five real reboots per server without human repair, and across a wall restart on every boot (the wall re-adopts its firewall table and the same policy).
- The result was scored from raw files by two independent readers who agree.

## What this does NOT cover (never-overclaim bounds)

- **Fault injection.** Nothing was broken on purpose. The drill did not exercise policy drift to a different account, confinement of descendant processes under stress, loss of the firewall rules, death of the wall process, uncovered account history, or refusal of invalid inputs by the start guard. Those behaviors are covered by tests only, and the matrix row says so.
- **Other platforms.** One distribution and version (Ubuntu 24.04), one architecture (x86-64), three virtual machines from one provider. No other distribution, kernel, architecture, bare-metal host or provider.
- **Anything beyond per-user-account allow/deny of the signed policy.** Destinations were literal IP addresses over TCP and UDP in IPv4 and IPv6. There was no test of DNS, DNS over HTTPS, DNS over TLS, hostname, template or time rules (the package refuses hostname, template and time rules until authenticated attribution exists), address ranges, UDP allow rules, or protocols other than TCP and UDP. This proves transport and address policy, not hostname or TLS security.
- **Not a production agent.** The confined account ran the test program that ships in the package. No real agent harness was launched. Confinement keys on the account's numeric user id; the package installs no per-agent cgroup binding for enforcement, and the daemon's own status never reads `Enforcing`, so that status is not evidence of enforcement.
- **Not an audit-trail claim.** The decision log was used here as a cross-check on each attempt. This drill does not claim a complete per-rule, per-flow audit trail for general traffic.
- **Artifact binding.** The proof binds to the package identified above. A later build is not covered until it is re-drilled or shown unchanged. The pre-release [Castle Wall Linux 0.1.0-1](https://github.com/eriknewton/sanctuary-framework/releases/tag/castle-wall-linux-0.1.0-1) carries these exact bytes (same SHA-256); any other build is outside this record.
- **Removal and upgrade.** Only a fresh install was drilled. Removal of a provisioned install through the package manager was refused and is not part of the claim; upgrade paths are not covered.
- **Duration and cost.** The drill ran for hours, not days, and captured no throughput or latency overhead.

## Residuals and observations (none changes the verdict)

- Eight boot captures fit a clock slew that the instrument did not record directly; responses sat up to 355 ms from the estimated clock, inside the 500 ms window. Future captures should take clock alignment from the signed responses.
- The two documentation payloads' installed bytes were not read on the servers (see item 1 above).

## Evidence retention

Raw captures (per-phase command transcripts, firewall ruleset snapshots, daemon decision logs, receiver packet streams, the sealed capture inventory and both readers' tables) are retained in the maintainer's drill-evidence archive under the 2026-10-04 Linux install-grade reference. The inventory covers 5,390 files with a SHA-256 manifest (manifest digest begins `248a295e`). This document summarizes that evidence for in-repo traceability; the summary numbers above are transcribed from the readers' tables.
