---
layout: post
title: "Context Gating: Your Agent's Sovereignty Ends Where the API Call Begins"
date: 2026-03-31
author: Erik Newton
description: "Sanctuary's new Context Gating tools give agents fine-grained control over what information leaves the custody boundary during outbound inference calls. Five new MCP tools, four starter templates, and a recommendation engine, because sovereignty means nothing if your full agent context leaks with every API call."
archive_note: "Predates Mantle vocabulary canonicalization on 2026-05-15. Terminology in this post may refer to install-time-binding concepts using earlier language; current canonical vocabulary lives at https://github.com/eriknewton/newton-wiki/blob/main/concepts/mantle.md."
---

> **Archive note:** This post predates Mantle vocabulary canonicalization on 2026-05-15.
> Terminology here may use earlier language for install-time substrate-binding concepts.
> Current canonical vocabulary lives at [Mantle Phase 1](https://github.com/eriknewton/newton-wiki/blob/main/concepts/mantle.md).


There's a gap in every "local-first" agent setup that nobody wants to talk about: the outbound inference call.

You can run your agent locally. You can encrypt your state at rest. You can hold your own keys. But the moment your agent calls an LLM provider (OpenAI, Anthropic, Google, Mistral, anyone) it typically sends *everything*. Full conversation history. Internal reasoning traces. Memory. Preferences. Tool results that might contain PII from previous API calls. System prompts that reveal your agent's goals and constraints.

All that sovereignty infrastructure, and then you just... hand it all over.

Sanctuary has always said "gate your API calls." We described it as an operational discipline: filter context to only what's needed for the specific task. But telling people what to do without giving them tools to do it is just advice, and advice isn't architecture.

Today we're shipping the tools.

## Five New MCP Tools

Sanctuary v0.3.1 now includes five Operational Isolation Context Gating tools that give agents and their human principals fine-grained control over what crosses the sovereignty boundary:

**`sanctuary/context_gate_set_policy`** creates a per-provider gating policy. You define which fields are allowed, which are redacted, which are hashed (preserving correlation without revealing values), and which should be summarized (compressed to reduce exposure). One policy can cover multiple provider categories (inference, tool-api, logging, analytics) with different rules for each.

**`sanctuary/context_gate_filter`** runs a context object through a policy and returns the safe version. The original content never leaves Sanctuary. You get back a filtered context with per-field decisions, content hashes for audit (SHA-256 of what went in and what came out), and a complete decision log. If any field triggers a `deny` action, the entire request is blocked, you get an explicit error instead of silent data leakage.

**`sanctuary/context_gate_apply_template`** solves the cold-start problem. Instead of writing a policy from scratch, start with one of four pre-built templates and customize from there.

**`sanctuary/context_gate_recommend`** analyzes a sample of your agent's actual context and recommends a policy. It classifies each field by name pattern (secrets, PII, internal state, IDs, history, task-related) and produces a recommended rule set with confidence levels and warnings. The recommendation is deliberately conservative: when in doubt, it recommends redact. A false redaction is a usability issue; a false allow is a privacy leak.

**`sanctuary/context_gate_list_policies`** shows what policies are currently configured.

## The Four Templates

Most agents don't need a custom policy on day one. They need a sensible default they can tighten or loosen over time. The four starter templates cover the most common scenarios:

**Inference Minimal.** Only the current task and query reach the LLM. Everything else is redacted. Maximum privacy, minimum context. For agents that process each request independently.

**Inference Standard.** Task, query, and tool results pass through. Conversation history is flagged for summarization. Secrets, PII, and internal reasoning are redacted. IDs are hashed. This is the balanced default, enough context for multi-step tasks without exposing everything the agent knows.

**Logging Strict.** Only operation names and timestamps pass through. Everything else is redacted. For telemetry and analytics providers where you want usage metrics without content exposure.

**Tool API Scoped.** Query parameters and tool inputs pass through. Memory, history, secrets, and PII are redacted. For outbound calls to external APIs where you need to send search terms but not your agent's full state. Notably, `headers` and `body` are *excluded* from the allow list by default because they frequently carry authorization tokens.

## Why This Matters

Context gating is where sovereignty rhetoric meets operational reality.

Every sovereignty framework can encrypt state at rest. That's necessary but insufficient. The harder problem is controlling what leaves the boundary during *active computation*, the inference calls, the API requests, the logging telemetry that flows to external services.

Consider what a typical OpenClaw agent sends to its LLM provider: the full conversation history (containing everything the user has ever said), system prompts (revealing the agent's instructions and constraints), memory files (learned preferences, personal information, relationship context), and tool results (which might include email contents, calendar data, search results containing PII, anything a previous API call returned).

Sanctuary's context gating doesn't just redact sensitive fields. It creates an auditable record of what was sent, what was filtered, and why. Content hashes (SHA-256 of the original and filtered context) provide a tamper-evident audit trail without storing raw content. If you need to verify later that a particular inference call didn't leak PII, the audit trail tells you.

The sovereignty audit tool now includes context gating in its assessment. Run `sanctuary/sovereignty_audit` and it will tell you whether context gating is configured and flag the gap if it isn't.

## What This Isn't

Context gating is not a substitute for choosing a trustworthy inference provider. It doesn't prevent a malicious provider from extracting information through prompt injection or model behavior. It doesn't solve the problem of what the provider does with the data it legitimately receives.

What it does is reduce the *surface area* of exposure. Instead of sending everything and hoping the provider is trustworthy, you send only what's needed and verify through audit what was actually sent. That's a meaningfully different security posture.

The recommendation engine classifies fields by name, not by content. A field called `tool_results` will be classified as "allow" even if it contains PII from a previous API response. The heuristic is a starting point, not a substitute for understanding your agent's actual data flows. Always review recommendations before applying them.

## Try It

```bash
npx @sanctuary-framework/mcp-server
```

The context gating tools are available immediately in v0.3.1. Start with `context_gate_apply_template` using the `inference-standard` template, then use `context_gate_recommend` to analyze your agent's actual context and tighten from there.

The full source is at [github.com/eriknewton/sanctuary-framework](https://github.com/eriknewton/sanctuary-framework). The context gating implementation is in `server/src/operational/context-gate*.ts`.

---

*Sanctuary defines sovereignty infrastructure for the agentic economy. Context gating is one piece of a four-layer architecture that includes cognitive sovereignty, operational isolation, selective disclosure, and verifiable reputation. The framework is open-source under Apache-2.0.*
