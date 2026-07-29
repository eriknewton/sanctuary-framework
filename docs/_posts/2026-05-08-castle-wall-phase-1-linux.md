---
title: "The Castle Wall, Live on Linux"
date: 2026-05-08
description: "Cooperative gates do not stop a prompt-injected agent. Kernel-level enforcement does. Castle Wall Phase 1 shipped this week on Linux: 203 Rust tests against a real kernel binding, with plain-DNS, DoH, and DoT bypass coverage verified end-to-end on real cgroups."
author: "Erik Newton"
image: /images/blog/castle-wall-phase-1-linux.jpg
archive_note: "Predates Mantle vocabulary canonicalization on 2026-05-15. Terminology in this post may refer to install-time-binding concepts using earlier language; current canonical vocabulary lives at https://github.com/eriknewton/newton-wiki/blob/main/concepts/mantle.md."
claims_era_note: true
---

> **Archive note:** This post predates Mantle vocabulary canonicalization on 2026-05-15.
> Terminology here may use earlier language for install-time substrate-binding concepts.
> Current canonical vocabulary lives at [Mantle Phase 1](https://github.com/eriknewton/newton-wiki/blob/main/concepts/mantle.md).


# The Castle Wall, Live on Linux

An agent under prompt injection executed 75 percent of remote commands across 34 sessions in a recent breach. The result, per OWASP GenAI's Q1 2026 round-up, was 195 million taxpayer records and 220 million civil records exfiltrated from a national-government deployment. The agent was not malicious. It was cooperative. The instructions came from somewhere it should not have trusted, and the runtime had no way to refuse the network call.

Adaptive prompt injection now exceeds an 85 percent success rate against state-of-the-art defenses per public reporting. CVE-2025-53773 (CVSS 9.6) confirmed prompt-injection remote code execution in a flagship coding-agent product. CVE-2025-32711 (CVSS 9.3) confirmed zero-click prompt injection in a hyperscaler M365 component. Snyk's ToxicSkills study found 13.4 percent of agent skills in the wild carry critical security issues, with 1,184 confirmed-malicious skills active and daily submissions ten times what they were three months earlier.

This is the threat model.

An L7 proxy can inspect traffic that goes through it. A managed-cloud control plane can govern agents that route through its substrate. Neither structurally answers the question of what stops a prompt-injected agent from issuing a curl call that bypasses the proxy entirely. If the agent itself is compromised, asking the agent to behave is asking the wrong layer of the stack to enforce.

The Castle Architecture answers that question at the kernel. The operating system itself blocks unauthorized cross-boundary calls regardless of what transport the agent picks or what prompt-injection state it is in. That is the floor. Everything else, every L7 inspection layer, every cooperative-MCP gate, every managed-cloud governance product, sits above the floor and composes with it. None of them replace it.

Today the floor is real on Linux. The rest of this post explains how it works, what it costs, and why kernel-level enforcement is the load-bearing differentiator when the agent itself cannot be trusted.

## The Castle Architecture

Sanctuary's enforcement model has four layers, each with a distinct contract. The contracts compose; none of them substitute for another. The model is named after the way a real castle defends a perimeter, observes its interior, governs its inhabitants, and accounts to neighbors.

**The Castle Wall.** Operating-system-level filtering at the boundary between the operator's machine and the external world, on the outbound path. Outbound calls (HTTP, DNS, custom protocols) route through a wall the operator's policies define. The kernel itself enforces. Within that proven scope, a prompt-injected or jailbroken agent does not get to choose; the operating system routes the call. This is the load-bearing answer to the question every honest enterprise buyer asks: how does the substrate enforce against an agent determined to escape? Ingress filtering of inbound webhooks and callbacks is roadmap, not part of the shipped surface.

**Sentinels.** Internal observation, not enforcement. Behavioral baselining via process introspection, eBPF observability, and audit-log analysis. Anomalies surface to the operator via system notifications. Sentinels see what the wall cannot: file-access patterns, internal model calls, cross-agent coordination, prompt-injection signatures inside internal communications. The sentinels surface; the operator decides. Sentinels ship in v1.3.

**The Charter.** Additive sovereignty surface for compliant agents. Encrypted state, signed audit, mandate primitives, four canonical policy slots, substrate selector, receipt integration. Compliant agents that voluntarily route through Sanctuary's MCP get the full sovereignty surface. Non-compliant agents do not break the castle; they hit the wall at the boundary and the sentinels inside. The Charter is the v1.2 ship and is already live.

**The Heralds.** Cryptographic receipts on cross-castle transactions, portable reputation that survives vendor churn, audit-trail evidence operators can carry across vendor relationships. This is how operators hold each other honest when they have no prior relationship. Concordia receipts plus Verascore reputation, composed with the substrate, not bound to it.

## The castle-walking principle

The castle must be both real AND delightful. Both sides of this line are critical. Real enforcement at the wall, AND approval response under two seconds when policy prompts the operator. Default-deny outbound, AND smart always-allow rules with learning, so routine traffic does not require repeated approvals. Sentinels that observe, AND do not surface noise. A Charter path that remains additive and fully usable.

If a future design strengthens enforcement at the cost of usability beyond a tolerable threshold, restructure. If a future design improves usability by softening enforcement to cooperative-only where the security claim requires hard enforcement, restructure. Both failure modes are equally destructive.

The principle has teeth. Every Sanctuary spec, every PR, every scope-lock since the architecture landed has had to answer the castle-walking test: does this proposal preserve real Castle Wall enforcement, and remain delightful? Specs that rely on cooperative behavior for a security guarantee must name the paired hard-enforcement piece and confirm both ship together. Cooperative-only work without paired hard-enforcement does not ship.

This is what kept the Castle Wall from drifting back into the cooperative-only path during build. The pressure to cut corners on either side is constant; the pressure to cut corners on enforcement specifically gets dressed up as developer experience. It isn't.

## What shipped on Linux

Castle Wall Phase 1 on Linux landed in PRs #124 and #125 last week, with the chain-wiring fix in PR #131 and the full TCP-bypass coverage closed in PR #132. 203 Rust integration and unit tests pass against a real kernel binding, including the DoH and DoT bypass coverage that makes the difference between a real wall and a hopeful one. Here is what is in the box.

**Kernel binding.** The wall enforces at the Linux kernel level using nftables for packet routing decisions, cgroup v2 for per-process scope (each wrapped agent gets its own egress policy, not a shared one), and NFQUEUE for in-line decisions on packets the kernel hands up to user space. Allowed traffic flows with low added latency in our test rig; formal p99 numbers are owed to the Assurance Matrix before we publish them as claims. Disallowed traffic does not reach the wire.

**Bypass coverage.** A prompt-injected agent does not just send HTTP. It tries DNS exfiltration. It tries DNS-over-HTTPS to a vendor-controlled resolver. It tries DNS-over-TLS to the same. It tries raw sockets. It tries every transport a normal Linux process can reach. The Phase 1 daemon enforces against the full set, verified end-to-end on real cgroups with real packet flow: plain-DNS, DoH, and DoT bypass attempts each spawn a real subprocess inside the agent's cgroup, emit a real packet, get caught by the kernel's cgroupv2 socket match, route through the per-agent chain into NFQUEUE, and resolve to a deny verdict in the audit log. The DoH and DoT tests matter because every previous L7 agent firewall the category has shipped misses one or both, and every miss is a ship-side covert channel.

**Daemon architecture.** The kernel-touching code lives in a privileged daemon written in Rust. The unprivileged Sanctuary process talks to the daemon over a JSON-RPC inter-process channel authenticated with an Ed25519 handshake on every session, so a compromised user-space process cannot speak for an unrelated wrapped agent. The daemon never trusts user-space input on its own merit; every policy update is signed, and the manifest store implements trust-on-first-use against the operator's own key.

**Audit log.** Every decision the wall makes (allow, deny, prompt the operator, escalate) appends to a write-ahead log with a chained SHA-256 hash. Tampering with the log invalidates the chain at the tamper point and forward. Crash recovery is correct: the daemon's failure-mode dispatcher (F-1 through F-7) handles every state where partial writes, kernel restarts, or wedged user-space callers could otherwise leave enforcement in an ambiguous state.

**CI surface.** The Linux daemon builds on every PR. Cargo audit gates against the RustSec advisory database with `--deny warnings`, so any unmaintained dependency or fresh CVE breaks CI before it lands on main. A cross-compilation gate verifies the daemon builds on macOS-host CI for Phase 2 readiness.

203 tests passing on a CI run against a real kernel binding is not a marketing line. It is what every operator considering Phase 1 deployment can verify themselves on their own hardware, on the open-source repo, with the same toolchain we used to ship.

## Composition, not substitution

The Castle Wall does not replace the L7 agent firewall category. It sits below it. An L7 proxy inspects the content of allowed traffic; the wall decides whether the traffic is allowed in the first place. Both can coexist on the same operator host, and both improve the security posture together. Defense in depth is the right answer; it is not a competition between layers.

The same composition holds across the operator-governance category. Hosted agent-governance products govern agents inside their substrate; the wall governs the operator's substrate itself. Managed egress-filtering services inspect what crosses a managed boundary; the wall inspects what crosses the operator's own boundary. None of these are wrong; none of them replace the wall.

Composition holds across the partner surface, too. Sanctuary signs Coinbase x402 payment requests with operator-held keys; x402 routes the value. Anthropic's Model Context Protocol provides the cooperative tool surface every modern harness already speaks; Sanctuary speaks MCP natively as a parallel server. Google's AP2 ships mandate primitives that bind authorized scope; Concordia receipts bind the negotiation outcome itself. Hermes A2A coordinates agent-to-agent messages across protocols; the operator's boundary stays the operator's. The substrate position is the layer that makes the whole stack honest about who owns the operator's record.

## What's next

Phase 1 ships on Linux today. macOS Phase 1 follows once the platform's developer-program review clears. The macOS path uses the Network Extension framework with process supervision, which requires Apple's entitlement review for the relevant capabilities. The filing window is a known-quantity 4 to 8 weeks post-submission. The application filing is the gate, not the engineering.

Windows Phase 2 sits behind macOS, using Windows Filtering Platform. Container and microVM isolation, Phase 3, is queued for the highest-assurance enterprise deployments where additional isolation between the wrapped agent and the operator's host filesystem matters.

Sentinels work begins in v1.3, after Phase 1 macOS clears entitlement review. The eBPF baselining and anomaly-surface UX were designed alongside the wall and have been waiting on the wall to land first. They are next.

## Your kernel

The pitch has been the same since [the Sovereignty Manifesto](https://sanctuaryprotocol.ai/2026/05/07/sovereignty-manifesto.html) landed. Your agent. Your machine. Your keys. The substrate that defends those rights has to be a substrate the operator owns at the layer that matters. For enforcement, that layer is the kernel. As of last week, the kernel-level layer is real for any operator running Sanctuary on Linux.

If you are an operator running agents on real money or real records, this is the floor your substrate should be built on. If you are an enterprise buyer evaluating sovereign deployment, the pilot demo is concrete and reproducible: a wrapped agent under prompt injection, a curl-call exfiltration attempt, the wall blocking the call, the operator-approval surface firing, you approving or denying in under ten seconds end-to-end, the audit log recording every step.

Your agent. Your machine. Your keys. And now your kernel.

Erik Newton
Sanctuary Framework
