---
layout: default
title: How Sanctuary works
description: The parts of Sanctuary, from the security boundary and private memory to query privacy, approvals, records and the fleet direction.
permalink: /how-it-works/
---

# Security, privacy and control belong in one product.

An agent can hold your work, your history and the context that makes it useful. Sanctuary brings together the controls for protecting that relationship: an enforced boundary, custody for the data you store with it, privacy for supported queries, approval policies and a record you can check.

The product’s direction is one dashboard across your agents, machines and data. Today’s components have different levels of evidence. The [Assurance Matrix](https://github.com/eriknewton/sanctuary-framework/blob/main/ASSURANCE_MATRIX.md) records those differences; the [platform records](/evidence/) show the demonstrated enforcement scope.

## Start with your own agent. Grow toward a fleet.

A private memory vault is the first step. The next stage aims for a complete setup on one dedicated Mac, combining the vault, an operating-system wall and a verified local model; that stage remains in progress. The destination is one console across machines and operating systems. Fleet enrollment and cross-machine policy management belong to that next product stage, not a claim of a completed fleet experience today.

Setup integrations include Claude Code, Hermes, OpenClaw, Cursor and Cline. Mastra is fixture-tested only, without a recorded live-agent drill. Wrapping remains partial: configuration tests do not cover every harness version or native tool surface. The current deployment guide ships local mode; operator-cloud deployment is roadmapped. That future mode would also require trust in the host and its provider. Calling an outside model from a local agent is a different step from hosting the agent in the cloud.

## Put the security boundary below the agent

Castle Wall is the network boundary. Within the [demonstrated scope](/evidence/), the operating system enforces a signed destination policy for the agent’s own account. Enforcement does not depend on the agent voluntarily following the rule.

On macOS, the wall requires a separate signed app, system extension and privileged setup. Adding Sanctuary to an MCP configuration does not complete that setup. The Ubuntu proof covers a fresh installation of the recorded package on Ubuntu 24.04 x86-64; other distributions, architectures, real-agent harnesses, DNS and hostname paths remain outside that proof.

## Keep memory under your control

Sanctuary stores fortress state in encrypted form and provides memory and state export/import tools. Custody and approval have platform requirements. Encryption tests are not evidence of hardware-backed custody, and complete migration, exit and erasure guarantees remain in progress.

## Keep supported queries private

In Sanctuary’s query path, fingerprintable headers are stripped by default. With your consent, personal details can be rewritten before a query leaves, using a classifier that processes them locally. This is a protection in the supported query path, not a claim that every connection from every harness passes through it.

## Decide which actions require approval

Every MCP tool call Sanctuary executes or forwards is checked against policy and logged. You choose which operations require approval. An unavailable approval channel must not be treated as permission; end-to-end proof across all approval channels remains outstanding. Native tools outside Sanctuary’s path are not covered by its MCP policy gate.

## Keep a record you can check

The audit chain and offline checkpoint verifier provide tools for examining the record. Production signing depends on an available signing identity; some checkpoints are honestly unsigned. The audit-chain row remains partial, and there is no demonstrated per-rule, per-flow trail or outside acceptance of an artifact as evidence for a named control.

## Keep your options open

State and memory export/import are part of the product; full exit and erasure are still being completed. The plugin host provides an extension point alongside supported agent tools. It does not establish compatibility with every security plugin or a production integration with a named third-party vendor.

## The architecture behind the product

Castle Wall supplies the enforced network boundary. Sentinels observe activity. The Charter contains cooperative tools and approval rules. Heralds cover optional recognition and reputation connections. Mantle handles installation and binding to the host. These parts support the product story; their names do not establish that every capability is proven on every platform.

The [Castle Architecture reference](https://github.com/eriknewton/sanctuary-framework/blob/main/README.md#castle-architecture) explains the mechanisms. Sanctuary works independently of Concordia and Verascore.

[Choose a supported installation path](/install/) or use the [agent-guided installation contract](/agent-guided-install.html).
