---
layout: default
title: How Sanctuary works
description: The parts of Sanctuary, from the security boundary and private memory to query privacy, approvals, records and the fleet direction.
permalink: /how-it-works/
---

# Security, privacy and control belong in one product.

An agent can hold your work, your history and the context that makes it useful. Sanctuary brings together the controls for protecting that relationship: an enforced boundary, custody for the data you store with it, privacy for supported queries, approval policies and a record you can check.

The product’s direction is one dashboard across your agents, machines and data. Today’s components have different levels of evidence. The [Assurance Matrix](https://github.com/eriknewton/sanctuary-framework/blob/main/ASSURANCE_MATRIX.md) records those differences; the [platform records](/evidence/) show the demonstrated enforcement scope.

## Start with your own agent. Grow toward a fleet. {#fleet}

A private memory vault, released as a candidate, is the first step. The next stage aims for a complete setup on one dedicated Mac, combining the vault, an operating-system wall and a verified local model; that stage remains in progress. The destination is one console across machines and operating systems. Fleet enrollment and cross-machine policy management belong to that next product stage, not a claim of a completed fleet experience today.

Setup integrations include Claude Code, Hermes, OpenClaw, Cursor and Cline. Mastra is fixture-tested only, without a recorded live-agent drill. Wrapping remains partial: tests prove configuration rewrite and bootstrap behavior for representative harness paths, not interception for every listed harness version or non-MCP agent surface. The current deployment guide ships local mode; operator-cloud deployment is roadmapped. That future mode would also require trust in the host and its provider. Calling an outside model from a local agent is a different step from hosting the agent in the cloud.
{: #tools}

## Put the security boundary below the agent {#boundary}

Castle Wall is the network boundary. Within the [demonstrated scope](/evidence/), the operating system enforces a signed destination policy for the agent’s own account. Enforcement does not depend on the agent voluntarily following the rule.

On macOS, the wall requires a separate signed app, system extension and privileged setup. Adding Sanctuary to an MCP configuration does not complete that setup. The macOS proof covers one Mac on one operating-system version (Tahoe 26.5.1) and the drilled build, through attended reboots. Launching the host app after a reboot has not been verified on hardware. It is not unattended reboot survival and not an audited per-rule, per-flow trail, and a destination allowlist controls which destinations are reachable, not what an allowed connection carries. The Ubuntu proof covers a fresh installation of the recorded package on Ubuntu 24.04 x86-64, on three fresh servers from one provider, with a test program in one confined account rather than a real agent. Its destinations were literal IP addresses over TCP and UDP, so DNS, DNS over HTTPS, DNS over TLS and hostname rules are outside it. Fault injection, other distributions, versions and architectures, bare metal, upgrades and removal of an installed package are also outside it. Neither proof measures overhead or sustained operation.

## Keep memory under your control {#memory}

Sanctuary stores fortress state in encrypted form and provides memory and state export/import tools. Custody and approval have platform requirements. Memory custody is partial and ships as a candidate. Before relying on a host for daily use, confirm restart persistence on that exact host: store a memory, restart, and read it back with no secret typed. At inference time, stored memory content is exposed to whichever model vendor you choose; custody covers the vault at rest and in transit between fortresses only. Master-key rotation does not yet cover memory: while memory is stored, rotation refuses and changes nothing, and there is no shipped procedure yet to rotate a fortress that holds memory records. Plaintext memory export, ingest and transcode require a local approval dialog that is available only on macOS; Linux and Windows refuse those operations today. Encryption tests are not evidence of hardware-backed custody, and complete migration, exit and erasure guarantees remain in progress.

## Keep supported queries private {#queries}

In Sanctuary’s query path, fingerprintable headers are stripped by default. With your consent, personal details can be rewritten before a query leaves, using a classifier that processes them locally. Coverage is bounded by the test corpus of sample personal details and the provider adapters shipped when it was drilled. Personal-detail shapes outside that corpus, and provider adapters added later, are covered only after the corpus and the evidence are extended for them. This is a protection in the supported query path, not a claim that every connection from every harness passes through it.

## Decide which actions require approval {#approvals}

Every MCP tool call Sanctuary executes or forwards is checked against policy and logged. You choose which operations require approval. An unavailable approval channel must not be treated as permission. The policy engine and that refusal are covered by unit tests; no single end-to-end drill yet covers operator timing or every approval channel. In the dashboard, some approval sources can go stale until you reload the page. Native tools outside Sanctuary’s path are not covered by its MCP policy gate.

## Keep a record you can check {#records}

The audit chain and offline checkpoint verifier provide tools for examining the record. Production signing depends on an available signing identity: a fortress without one, and the root daemon’s separate audit store, write honestly unsigned checkpoints. The audit chain remains partial: its tamper evidence is tested in code but not yet drilled with an outside verifier, and single-file export carries one chain when several exist. There is no demonstrated per-rule, per-flow trail or outside acceptance of an artifact as evidence for a named control.

## Keep your options open {#portability}

State and memory export/import are part of the product; full exit and erasure are still being completed. The exit guarantee is partial: some export and import paths do not yet carry every key and counter, and state from before an identity-key rotation is not yet guaranteed to survive import (IC-07, IC-08, IC-09). Plaintext memory export requires the macOS-only approval dialog described above. The plugin host provides an extension point alongside supported agent tools. It does not establish compatibility with every security plugin or a production integration with a named third-party vendor.

## The architecture behind the product

Castle Wall supplies the enforced network boundary. Sentinels observe activity. The Charter contains cooperative tools and approval rules. Heralds cover optional recognition and reputation connections. Mantle handles installation and binding to the host. These parts support the product story; their names do not establish that every capability is proven on every platform.

The [Castle Architecture reference](https://github.com/eriknewton/sanctuary-framework/blob/main/README.md#the-castle-architecture) explains the mechanisms. Sanctuary works independently of Concordia and Verascore.

[Choose a supported installation path](/install/) or use the [agent-guided installation contract](/agent-guided-install.html).
