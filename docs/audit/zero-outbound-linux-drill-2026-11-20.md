---
title: Zero-outbound drill, 2026-11-20 (Sanctuary 1.8.4 on Linux in Docker, three runs, full packet capture)
date: 2026-11-20
author: Erik Newton
status: drill-evidence
severity: capability-claim evidence, thesis-gate
scope: observed network contact of the published npm package from install through three agent sessions and an update check; Linux in Docker, version 1.8.4, cooperative-only setup; structural egress control NOT covered
---

# Zero-outbound drill, 2026-11-20

**Purpose.** This document is the in-repo trace target for the ASSURANCE_MATRIX row "No unrequested network contact (observed by packet capture)". Sanctuary says it does not phone home. This drill checked that from the outside: the published package ran through a new user's first steps while a separate container recorded every packet, and a second reader then re-read the raw captures on its own.

## Claim proven

We recorded every packet while Sanctuary 1.8.4 installed, set up, protected a Claude Code configuration and served three agent sessions, three times over, on Linux in Docker. Outside the install itself, an update check the user asked for, and the npx case in the next sentence, no network connection opened and no name was looked up. When a session was started through npx, the npm registry was contacted before the server answered its first request; after that answer, no new connection opened and no data byte left.

Read exactly as scoped in this record. The six limits below are part of the claim and travel with it wherever it is repeated.

## Limits that travel with this claim

1. **One platform.** Linux, inside Docker, on one x86-64 host. macOS and Windows were not drilled, and this record says nothing about them. It also says nothing about host-level behaviour of a real desktop install (launch agents, keychains, desktop sessions), because the container had none.
2. **One version.** The bytes of `@sanctuary-framework/mcp-server@1.8.4` only (integrity below). A later release is not covered until it has its own run.
3. **Cooperative-only setup.** The fortress was created with `sanctuary init --no-pin`, with no Castle Wall root helper. This record says nothing about the Castle Wall install path.
4. **Remember and recall were refused.** On 1.8.4 the default policy refuses `sanctuary_remember` and `sanctuary_recall`. The drill shows that the refusal path opens no connection. It does not show the storage write and read path, because that path did not run. A release that serves these tools needs its own run before this record covers storage.
5. **Starting the server with npx.** In the two sessions launched through npx, the npm registry was contacted before the server answered its first request. The capture cannot tell which process sent that contact; npx fetches and checks the package at that point. After the server's first answer, no new connection opened, no name was looked up and no data byte left. The registry connection that was already open sent only empty acknowledgements, keepalives and a close. The accurate wording is "no new connection and no data after the server started", never "no packet at all".
6. **"Does not", not "cannot".** This is an observed-behaviour claim. It shows what Sanctuary did, not that it is structurally unable to connect. The structural version is Castle Wall's enforced egress policy, a separate claim with its own rows and its own drill evidence. This drill does not stand in for it.

## Platform and artifact

| Item | Value |
|---|---|
| Host | One x86-64 Linux build server (kernel 6.8), Docker 29.1.3. The drill touched only Docker objects it created and labelled for this run. |
| Package under test | `@sanctuary-framework/mcp-server@1.8.4`, the public `v1.8.4` release, npm integrity `sha512-J/F2Hf/aNp74pFCl4rIkHGiJ1T82ifYjI1sgKf6E8YejWvo1p18RaIjdQYNWkevsp1fbUxbH8yYFXFAs5o+jPA==`. The integrity was checked against the registry before the run. |
| Workload image | `node:22-bookworm-slim`, pinned by digest `sha256:47725aca53d3295ec2d3be8f62726599b3033cc262edc2c7e429909b3ac599fc` |
| Capture and reader image | `nicolaka/netshoot`, pinned by digest `sha256:147f2c4cb0aa7a741151bce2bfef71d9e1a04631636e24665ee2a5ed799feb47` (tcpdump to record, tshark to decode) |
| Drill script | One self-contained script, retained privately with the raw captures, SHA-256 `3dbb0b3c61100f6aaaf74df00492bb6fbd0638a42cd31aa4a0683298af02f806` |
| When | 2026-11-20, 19:18 to 19:53 UTC, about 11.5 minutes per run |

## How the capture worked

- The package ran in a throwaway workload container whose only network was the network namespace of a second, capture container. The capture container ran tcpdump with the single capability it needs to record packets. The workload could neither reach nor change it.
- tcpdump recorded every frame on the namespace's virtual network card and on its loopback interface. A looked-up name counts as contact even when no connection follows, so DNS queries were read as well as connections.
- The workload's root filesystem was read-only. Each run had a brand-new home directory, npm cache and global prefix, and a disposable fortress with a random passphrase. Nothing came from a real user's account.
- **Planted controls.** At the start and end of every capture the harness made known test contacts: a TCP connection attempt to a documentation-range address in IPv4 and in IPv6, and DNS lookups (A and AAAA) for a per-run name under the reserved `.invalid` domain. Nothing answers at those addresses or names, so the controls cause no real traffic. Each control had to be seen exactly once, as its exact planned connection, inside its own recorded time interval. A missed control makes the capture incomplete. This is how the drill knows the recording saw everything.
- **Product-level control.** The update-check step is supposed to reach the network. The reader had to see that traffic, so a capture that could not see Sanctuary's own process would have failed.
- **Seal, drain, stop.** Every capture ended the same way: the workload exited, the namespace was disconnected from the network, the harness waited about two seconds for the last buffered packets, and only then did the capture stop.
- **Pass rule, frozen before the capture.** Any packet leaving the namespace, or any name looked up, outside that step's allow-list is a finding. A missing, empty or default observation reads incomplete, never pass. The drill's reader ran a 44-case self-test before any container was created.

## What ran, in order, three times

Before the three runs, one capture probe checked the recording itself (controls only, all seen).

| Step | What ran | Allowed off the container | Observed in all three runs |
|---|---|---|---|
| Install | `npm install -g @sanctuary-framework/mcp-server@1.8.4` from the public registry | `registry.npmjs.org` | `registry.npmjs.org` only |
| Install from a local copy | the same package installed with `npm install -g --offline` from a copy of the npm cache, into a second prefix | none | nothing beyond the controls; the installed CLI was byte-identical to the first install's in all three runs |
| Set up | `sanctuary init --no-pin --no-provision-local-intelligence` (cooperative-only fortress) | none | nothing beyond the controls |
| Protect | `sanctuary protect --claude-code --no-open`, observed for 150 seconds, then stopped | none | nothing beyond the controls |
| Session 1 (npx) | the server started with the exact npx command `protect` wrote into the Claude Code configuration: initialize, list tools, `sanctuary_who_am_i`, `sanctuary_active_protections`, `sanctuary_remember`, `sanctuary_recall`, `monitor_health`, then 120 seconds idle with input open, then end of input | none after the server's first answer (limit 5) | registry contact before the first answer only; nothing new after it |
| Session 2 (npx restart) | a second session started the same way: `sanctuary_recall`, then 300 seconds idle, then end of input | none after the server's first answer (limit 5) | registry contact before the first answer only; nothing new after it |
| Session 3 (direct) | a session on the installed `sanctuary` binary with no npx: `sanctuary_who_am_i`, `sanctuary_recall` | none | nothing beyond the controls |
| Update check | `sanctuary check-updates`, the one step the user asks to reach the network | `registry.npmjs.org`, `api.github.com`, `github.com`, `*.githubusercontent.com` | exactly those four names, one connection each |

Tool outcomes were the same in every run: `sanctuary_who_am_i`, `sanctuary_active_protections` and `monitor_health` were served; `sanctuary_remember` and `sanctuary_recall` were refused by the 1.8.4 default policy with its documented refusal (limit 4).

## Results

| Item | Result |
|---|---|
| Verdict | PASS: 3 of 3 runs clean, 0 findings, 0 incomplete |
| Captures | 25 (one probe plus eight steps in each of three runs), every one complete |
| Controls | 8 of 8 seen in every capture |
| Install | contact with `registry.npmjs.org` only |
| Install from a local copy, set up, protect, direct session | no contact beyond the controls, in any run |
| npx sessions | registry contact before the server's first answer only: 9 connections and 6 lookups of that one name (each an A and an AAAA query) across the three runs, all for `registry.npmjs.org`. Every one of the 1,603 outbound frames on those connections after the first answer carried zero payload bytes. After the first answer there was no new connection and no lookup, apart from the harness's own end controls. |
| Update check | only its four allowed names; this also confirmed the capture could see Sanctuary's own traffic |
| Seal | in every capture the workload had exited before the seal, and the last recorded frame came before the seal request |

## Independent re-read

The verdict above came from the drill's own scripted reader. A second reader then checked it without running that reader. It was an automated reader from a different model family than the one that wrote the drill harness. It decoded all 25 raw captures (33,873 frames) itself with tshark, in a container with no network and a read-only view of the files, and it used the drill script only to read the rules.

- **First pass.** It agreed with every classification: all 25 capture hashes, sizes and frame counts matched; every non-loopback frame was a planned control, ordinary network plumbing, or an allowed contact; no second DNS question, no unexpected host name, and no unexplained outbound traffic. It could not yet certify the controls' exact time intervals or the seal timing, because those timing records had not been supplied. It reported that as missing evidence, not as a disagreement.
- **Second pass.** The timing records from the same run were supplied; there was no rerun. All 173 control TCP connection frames and all 100 control DNS query frames fell inside their planned intervals (the tightest margin was 3.3 ms). Every capture's last frame came before its seal request (the closest was 31 ms before). No timing finding.
- **Verdict: AGREE.**

## Earlier rounds (not counted)

The drill design went through eight review rounds and five dress rehearsals before this run. The rehearsals found problems in the harness and the reader, not product findings, and each was fixed and re-reviewed before the next. None of those captures is counted here.

## Also not covered

These sit beside the six limits above:

- **Uninstall.** The drill had no uninstall step.
- **Anything after the windows.** Protect was watched for 150 seconds and the sessions idled for 120 and 300 seconds. Nothing is claimed about a timer that fires later, a reboot, or days of use.
- **Paths this setup did not take.** No real Claude Code process ran and no model was in the loop; only the tools listed above were called. Federation or peer configuration, local-intelligence provisioning, and opt-in environment variables were not exercised.
- **What travelled inside allowed connections.** The install and update-check connections are encrypted. The drill shows where they went, not what they carried.
- **The model provider's traffic.** A real agent talks to its model provider. That traffic is not Sanctuary's and is out of scope.

## Evidence retention

The raw captures, per-step receipts, driver records and both readers' outputs are retained in the maintainer's private drill-evidence archive under the 2026-11-20 zero-outbound reference. They stay private because they hold addresses and timing that are only safe to share in summary. This document summarizes that evidence for in-repo traceability; the numbers above are transcribed from the drill report and the independent re-read.
