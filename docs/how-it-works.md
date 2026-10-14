---
layout: default
title: How Sanctuary works
description: The difference between operating-system enforcement and cooperative agent tools.
permalink: /how-it-works/
---

# Your rules, enforced by the operating system.

Castle Wall is Sanctuary’s network boundary. On macOS, within the [demonstrated scope](/evidence/), enforcement does not depend on the agent’s cooperation. The person running the machine approves and signs the rules, and the operating system applies them to the account running the agent.

## Installing a tool is a different step

The macOS operating-system wall requires a separate signed app, system extension and privileged setup. Adding Sanctuary to an MCP configuration does not complete that setup. MCP, the Model Context Protocol, lets an AI agent call tools; a successful connection to those tools does not establish that the wall is armed.

[Choose an installation path](/install/) or read the [canonical agent installation contract](/agent-guided-install.html).

## Read the rest of the architecture in context

Castle Wall handles the network boundary. Sentinels observe activity; the Charter contains cooperative tools and approval rules; Heralds cover optional recognition and reputation connections; Mantle concerns installation and binding to the host. These names describe the architecture, not a promise that every part is proven.

The [Castle Architecture reference](https://github.com/eriknewton/sanctuary-framework/blob/main/README.md#castle-architecture) explains those mechanisms. The [Assurance Matrix](https://github.com/eriknewton/sanctuary-framework/blob/main/ASSURANCE_MATRIX.md) records what each has demonstrated and what remains partial or unproven. Sanctuary works independently of Concordia and Verascore.

## Start with the platform record

The [macOS and Ubuntu evidence rows](/evidence/) name the tested platforms, artifacts and bounds. The Ubuntu proof covers a fresh installation of the recorded package on Ubuntu 24.04 x86-64; it does not establish support for other distributions, architectures or real-agent harnesses, or for DNS and hostname paths.
