---
layout: default
title: Install Sanctuary
description: Choose an installation path, read its prerequisites, and follow the guide for your operating system and harness.
permalink: /install/
---

# Install Sanctuary

Start with the memory profile for the cooperative path supported by Protect, or choose the full agent-guided profile on macOS with Hermes. The full profile has separate operating-system setup and consent requirements. Choose your profile below, then let the agent follow the installation contract.

[macOS with Hermes: full setup](#macos-with-hermes-full-setup) · [MCP configuration: cooperative setup](#cooperative-setup-for-an-existing-mcp-harness) · [Ubuntu 24.04 package install](#ubuntu-2404-x86-64)

## macOS with Hermes: full setup

Use a Mac and a local agent with shell access. Arrange an interactive macOS login session and an operator who can complete Apple consent and the exact privileged action when requested.

Read the [macOS install and arm reference](/castle-wall-macos-install.html) to obtain and verify the signed release app. Keep the app version, checksum and release record together. Place the verified app at `/Applications/Sanctuary-CastleWall.app`.

Give your local agent this instruction:

> Follow the [agent-guided installation contract](/agent-guided-install.html) for the full Hermes profile. Start with the command below. When `status` is `agent_action` and `next_action.actor` is `agent`, run only `next_action.argv`, exactly once. After exit zero, run the planner again. On a nonzero exit, follow `next_action.on_nonzero` and stop autonomous retries. Stop for `human_action` or `blocked`. Report completion only when the planner returns `complete`.

```bash
/Applications/Sanctuary-CastleWall.app/Contents/MacOS/sanctuary install --profile full --harness hermes --json
```

Command source: the [canonical installation contract](/agent-guided-install.html).

Keep passphrases, recovery keys and dashboard tokens out of the agent conversation. Complete recovery custody in a private local session. Never ask the agent to read the staged recovery file or print a credential.

## Cooperative setup for an existing MCP harness

Prerequisites for the npm path: Node.js 22 or newer and npm 10 or newer. Before installing, open the [release verification instructions](https://github.com/eriknewton/sanctuary-framework/blob/main/README.md#verify-before-you-trust).

Choose the action that matches your task. Install first and check the result afterward. Removal is a separate action, only when you intend to remove the npm installation.

**Install for Claude Code**, using the README's headless command:

```bash
npx -y @sanctuary-framework/mcp-server protect --claude-code --no-open --no-dashboard
```

**Check the installation:**

```bash
npx -y @sanctuary-framework/mcp-server doctor --json
```

**Remove only when intended**, using a separate command:

```bash
npx -y @sanctuary-framework/mcp-server uninstall
```

Treat this as cooperative MCP setup; it does not install and arm the macOS operating-system wall.

Wrapping remains partial: representative harness configuration paths are tested, and the evidence does not cover every harness version or built-in non-MCP tool.

For a guided cooperative setup, use the memory profile and follow the same single-action and human-action contract:

```bash
npx -y @sanctuary-framework/mcp-server install --profile memory --harness claude-code --json
```

Command source: the README's agent installation section and the canonical planner contract.

For another harness, consult the [configuration reference](https://github.com/eriknewton/sanctuary-framework/blob/main/README.md#works-with) before changing a flag. Do not infer a full-profile installation from a successful MCP connection.

## Check the result

After the npm setup, run the README's verification command:

```bash
npx -y @sanctuary-framework/mcp-server doctor --json
```

Read `storage_path` first to confirm the intended fortress. Then inspect the exit code and every check's `status`, `message` and `hint`; use the [health-check reference](https://github.com/eriknewton/sanctuary-framework/blob/main/README.md#health-check) to interpret the result.

For the full profile, follow the planner through its observed-state checks until `complete`; a successful package installation alone is insufficient.

## Ubuntu 24.04, x86-64

The October 4, 2026 proof applies to a fresh installation of the exact package named in the drill record, on Ubuntu 24.04 x86-64 hosts, for per-account signed-policy allow and deny behavior.

Installation is manual from the [recorded package release](https://github.com/eriknewton/sanctuary-framework/releases/tag/castle-wall-linux-0.1.0-1). Download its three assets into one directory and follow that page’s “Verify before installing” checksum step. Then follow the [operator install guide at the same tag](https://github.com/eriknewton/sanctuary-framework/blob/castle-wall-linux-0.1.0-1/castle-wall-daemon/packaging/ubuntu/README.md). The guide calls the checked package `install.deb`; rename the downloaded file or use its full filename in those commands.

The owner signs the policy on a separate workstation with `sanctuary-linux-policy-sign` from `server/` at that tag; no npm release ships that signer yet. Read the [Ubuntu evidence record](/audit/castle-wall-linux-install-grade-drill-2026-10-04.html) before evaluating the result.

The full-profile macOS planner is not the Ubuntu installation route.

Other Linux platforms, DNS and hostname paths, real-agent harnesses, upgrades and provisioned removal are outside the recorded proof.

## Remove an npm installation

Use the README's uninstall command:

```bash
npx -y @sanctuary-framework/mcp-server uninstall
```

Read its result and the [uninstall reference](https://github.com/eriknewton/sanctuary-framework/blob/main/README.md#quickstart). Follow any named operator action. Consult [restore and recovery](/castle-wall-macos-install.html#restore-and-recovery) before changing an existing fortress.

For Ubuntu, use the exact package's documentation and retain the removal bound above.

## If setup stops

Use the named next action in the planner response. On `blocked`, stop and read the reason. On `human_action`, give the operator the instructions without executing the privileged command yourself.

[troubleshooting](https://github.com/eriknewton/sanctuary-framework/blob/main/README.md#troubleshooting), [contract](/agent-guided-install.html), [security policy](https://github.com/eriknewton/sanctuary-framework/blob/main/SECURITY.md).
