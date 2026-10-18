---
layout: default
title: How Sanctuary works
description: The parts of Sanctuary, from the security boundary and private memory to query privacy, approvals, records and the fleet direction.
permalink: /how-it-works/
---

# Security, privacy and control belong in one product.

An agent can hold your work, your history and the context that makes it useful. Sanctuary brings together the controls for protecting that relationship: an enforced boundary, custody for the data you store with it, privacy for supported queries, approval policies and a record you can check.

The product’s direction is one dashboard across your agents, machines and data. Each part below links to its entry on the [Limits page](/limits/), which renders the [Assurance Matrix](https://github.com/eriknewton/sanctuary-framework/blob/main/ASSURANCE_MATRIX.md); the [platform records](/evidence/) show the dated demonstrations.

## Start with your own agent. Grow toward a fleet.

A private memory vault is the first step. The next stage aims for a complete setup on one dedicated Mac, combining the vault, an operating-system wall and a verified local model. The destination is one console across machines and operating systems.

Setup integrations include Claude Code, Hermes, OpenClaw, Cursor and Cline. The current deployment guide covers local mode. {% include matrix-evidence.html claim="Agent wrapping (MCP interception)" %}

## Put the security boundary below the agent

Castle Wall is the network boundary. The operating system enforces a signed destination policy for the agent’s own account. Enforcement does not depend on the agent voluntarily following the rule.

On macOS, the wall requires a separate signed app, system extension and privileged setup. Adding Sanctuary to an MCP configuration does not complete that setup. {% include matrix-evidence.html claim="Egress enforcement: macOS (Castle Wall Phase 1)" label="macOS" %} {% include matrix-evidence.html claim="Egress enforcement: Linux (Castle Wall Phase 1)" label="Ubuntu 24.04 x86-64" %}

## Keep memory under your control

Sanctuary stores fortress state in encrypted form and provides memory and state export/import tools. {% include matrix-evidence.html claim="Sovereign encrypted memory custody (Rung 1, candidate)" label="Memory custody" %} {% include matrix-evidence.html claim="State encryption" label="State encryption" %}

## Keep supported queries private

In Sanctuary’s query path, fingerprintable headers are stripped by default. With your consent, personal details can be rewritten before a query leaves, using a classifier that processes them locally. {% include matrix-evidence.html claim="Query anonymity (selective disclosure)" %}

## Decide which actions require approval

Every MCP tool call Sanctuary executes or forwards is checked against policy and logged. You choose which operations require approval. An unavailable approval channel must not be treated as permission. {% include matrix-evidence.html claim="Approval gating (Tier 1 / Tier 2 / Tier 3 policy)" label="Approval gating" %} {% include matrix-evidence.html claim="Dashboard approval flow" label="Dashboard approvals" %}

## Keep a record you can check

The audit chain and offline checkpoint verifier provide tools for examining the record. {% include matrix-evidence.html claim="Tamper-evident audit chain" label="Audit chain" %} {% include matrix-evidence.html claim="Verifiable transparency checkpoint format and offline verifier" label="Checkpoint verifier" %}

## Keep your options open

State and memory export/import are part of the product. The plugin host provides an extension point alongside supported agent tools. {% include matrix-evidence.html claim="Export / exit bundle" %}

## The architecture behind the product

Castle Wall supplies the enforced network boundary. Sentinels observe activity. The Charter contains cooperative tools and approval rules. Heralds cover optional recognition and reputation connections. Mantle handles installation and binding to the host.

The [Castle Architecture reference](https://github.com/eriknewton/sanctuary-framework/blob/main/README.md#the-castle-architecture) explains the mechanisms. Sanctuary works independently of Concordia and Verascore.

[Choose a supported installation path](/install/) or use the [agent-guided installation contract](/agent-guided-install.html).
