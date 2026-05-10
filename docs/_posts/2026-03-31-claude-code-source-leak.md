---
layout: post
title: "Anthropic's Claude Code Leak: Sovereignty Doesn't Stop at the API Call"
date: 2026-03-31
author: Erik Newton
description: "On March 31, Anthropic accidentally shipped a source map in their npm package that exposed 512,000 lines of Claude Code source code. This is the third major agentic infrastructure failure in two weeks, and it maps to the same architectural gap."
image: /images/blog/claude-code-source-leak.png
---

On March 31, 2026, security researcher Chaofan Shou discovered that the entire source code of Claude Code (Anthropic's flagship agentic coding tool) was sitting in plain sight on the npm registry. A 59.8 MB source map file, bundled into version 2.1.88 of the @anthropic-ai/claude-code package, contained the full, unobfuscated TypeScript source. 1,900 files. 512,000 lines. Everything.

Within hours, the codebase was mirrored across GitHub, forked over a thousand times, and dissected in real time. Internal model codenames (Capybara, Fennec, Numbat), unreleased features behind 44 feature flags, OAuth flows, multi-agent coordination logic, the internal API client, all exposed. Anthropic scrambled to pull the package, but the code was already everywhere.

This is the third major agentic infrastructure failure in two weeks. Meta's Sev 1 on March 18 (an agent autonomously posting proprietary data to an internal forum. Nine OpenClaw CVEs between March 18–21) including a CVSS 9.9 sandbox escape. And now Anthropic shipping their own source code in a production npm package.

Three different organizations. Three different failure modes. One shared root cause.

## A Build Pipeline Is a Sovereignty Boundary

The instinct is to call this a simple packaging mistake, someone forgot to add `*.map` to `.npmignore`. And technically, that's what happened. Bun's bundler generates source maps by default. A misconfigured build step shipped them to production.

But framing this as a configuration oversight misses the structural point. A build pipeline that publishes to a public registry is an outbound data flow. It moves artifacts from inside your sovereignty boundary to outside it. The question is whether anything in your infrastructure verifies what's crossing that boundary before it crosses.

At Anthropic, the answer was no. The same toolchain that generated the production bundle also generated a source map containing the full original source, and nothing between the build step and `npm publish` checked what was in the package.

This is the same class of problem as Meta's agent posting proprietary data to a forum. The same class as an agent sending full context (secrets, memory, internal reasoning) to a remote LLM provider on every inference call. The boundary exists. Data crosses it. Nothing verifies what's crossing.

## What Context Gating Would Have Caught

Sanctuary's L2 context gating was designed for inference calls, controlling what context an agent sends to remote providers. But the principle applies to any outbound data flow: if something leaves your sovereignty boundary, you should have a policy that specifies what's allowed to leave, and a mechanism that enforces it.

A context gating policy for a build pipeline would look like this: before any artifact is published to a public registry, filter the contents against a policy. Source maps? Deny. Internal configuration files? Deny. Files matching `*.map`, `*.env`, `credentials.*`? Deny. The policy is declarative. The enforcement is structural. The human doesn't need to remember to update `.npmignore`: the policy catches it.

This isn't hypothetical. Sanctuary's `context_gate_filter` does exactly this for inference calls today: you define per-provider policies with allow/redact/hash/deny actions, and the filter enforces them before any data leaves. The same architecture applies to any outbound boundary; API calls, build pipelines, agent posts to forums, webhook payloads.

## The Pattern Across All Three Incidents

| Incident | Date | What crossed the boundary | What should have stopped it |
|----------|------|--------------------------|----------------------------|
| Meta Sev 1 | March 18 | Proprietary code, strategies, user data posted to internal forum | L2 mandatory approval gate, L3 selective disclosure |
| OpenClaw CVEs | March 18–21 | Sandbox bypass, child processes inheriting unrestricted access | L2 operational isolation, cryptographic execution attestation |
| Claude Code leak | March 31 | 512K lines of source code shipped in npm package | L2 context gating, outbound data flow verification |

Every one of these is a failure at the sovereignty boundary. Data that should have stayed inside crossed to the outside. The boundary was implicit (convention, configuration, human memory) rather than structural (policy-enforced, cryptographically verified, mandatory).

## Sovereignty Is Structural or It Doesn't Exist

Anthropic built Claude Code with an internal feature called "Undercover Mode", a mechanism to prevent the AI from accidentally revealing internal information in commits and PRs. The irony is painful: the tool had a feature to prevent leaking secrets in code output, but the build pipeline that shipped the tool had no equivalent mechanism to prevent leaking its own source.

You cannot bolt sovereignty onto a system through features. It must be architectural. The approval gate must be mandatory, not advisory. The context filter must be structural, not optional. The boundary enforcement must apply to every outbound flow, not just the ones you remembered to configure.

This is what Sanctuary's four-layer model provides. Not a feature. An architecture.

## Try It

```bash
npx @sanctuary-framework/mcp-server
```

Run `sanctuary/sovereignty_audit` on your agent's environment. Run `sanctuary/context_gate_set_policy` to define what's allowed to leave your sovereignty boundary. The next incident won't wait for you to update your `.npmignore`.

Source: [github.com/eriknewton/sanctuary-framework](https://github.com/eriknewton/sanctuary-framework). 51 MCP tools. 420 tests. Apache-2.0.

---

*Three incidents in two weeks. Meta, OpenClaw, Anthropic. The organizations are different. The failure is the same: data crossing sovereignty boundaries without structural enforcement. Sanctuary exists to make those boundaries architectural.*
