---
RFC: 0003
title: Castle Architecture
date: 2026-04-30
status: accepted
author: Erik Newton
---

# ADR: Castle Architecture for Sanctuary Enforcement

## Status

Proposed. On Erik approval, becomes canonical for v1.x onward. Every spec, PR, and scope-lock from this date forward must reference this ADR and answer the castle-walking test (defined below).

## Context

Sanctuary's enforcement story drifted between the original proxy-sandbox concept and the current v1.x implementation. The drift collapsed the enforcement layer into "voluntary MCP-gate" cooperative security, where agents that voluntarily route their tool calls through Sanctuary's MCP get the full sovereignty surface (encrypted state, signed audit, mandate primitives, four canonical policy slots), and agents that bypass the MCP get nothing.

An engineer friend reviewing the architecture observed correctly: an MCP-based implementation offers no guarantees. The agent voluntarily uses Sanctuary's MCP; nothing prevents it from acting outside the MCP's view. Prompt-injected agents, jailbroken agents, or agents whose harness simply does not bother with sovereignty primitives all bypass the cooperative path. Verascore-as-eventual-catch is empty as deterrence at the moment of action because agents do not reason about reputation consequences.

This ADR addresses the drift directly. It names the castle architecture as canonical, replaces voluntary-MCP-gate as the enforcement layer with OS-level egress enforcement, and establishes the operating discipline that prevents future drift.

## Decision

The Castle Architecture is the canonical enforcement model for Sanctuary. Four layers, each with a distinct enforcement contract.

### Layer 1: Castle Wall (hard enforcement at the operator-external boundary)

**Enforcement contract:** the operating system itself blocks unauthorized cross-boundary actions. The agent does not get a choice. Even a prompt-injected agent attempting to bypass Sanctuary cannot, because the OS routes outbound network calls, inbound external connections, and cross-boundary identity assertions through Sanctuary's egress filter before they leave or enter the operator's machine.

**Implementation:** OS-level network filtering plus process supervision. Linux: netfilter / NFQUEUE plus per-process cgroup routing. macOS: Network Extension framework or pf rules with process supervision. Windows: Windows Filtering Platform. The wrapped agent runs as a normal user process with normal access to the operator's filesystem, internal compute, and internal LLM calls. Only the egress is constrained.

**What flows through the wall:** outbound network calls (HTTP, DNS, custom protocols), inbound external connections (webhooks, callbacks), cross-boundary identity assertions (the agent claims to be the operator to an external service), payments and mandates and commitments and receipts that bind external counterparties.

**What does NOT flow through the wall:** internal compute, internal filesystem access, internal LLM calls (which stay in the castle via the substrate selector), internal process exec, internal communication between agents inside the castle.

### Layer 2: Sentinels (internal observation, not enforcement)

**Enforcement contract:** none. Sentinels observe; they surface anomalies to the operator; they do not block.

**Implementation:** process introspection, eBPF observability, syscall observation, audit-log analysis, behavioral baselining. Anomalies fire OS notifications via the v1.2 menubar surface. The operator decides whether to approve, deny, suspend, or escalate.

**What sentinels watch:** file access patterns deviating from baseline, internal LLM call patterns deviating from baseline, internal communication patterns deviating from baseline, cross-agent coordination patterns, sudden changes in tool-call distributions, prompt-injection signatures in internal communications.

### Layer 3: Cooperative MCP (additive extension, not enforcement)

**Enforcement contract:** none. The MCP path is additive sovereignty surface available to compliant agents.

**What it provides for compliant agents:** encrypted state at rest, signed audit, mandate primitives, four canonical policy slots (memory, credentials, plans, outputs), substrate selector, Concordia receipt integration, Verascore reputation hooks. Compliant agents that voluntarily route through the MCP get the full sovereignty surface.

**What it does NOT provide:** enforcement against non-compliant agents. Non-compliant agents that bypass the MCP still hit Layer 1 at the wall and Layer 2 inside the castle.

### Layer 4: Cryptographic Receipts and Reputation (cross-castle accountability)

**Enforcement contract:** none. Layer 4 operates on actions that have already crossed the wall.

**What it provides:** signed Concordia receipts on cross-castle transactions, Verascore reputation aggregating across operators, portable reputation across vendor churn, audit-trail evidence for compliance, dispute resolution substrate.

**What it does NOT provide:** enforcement at the moment of action. Layer 4 is outside-in accountability operating on already-crossed-the-wall behavior.

## The castle-walking principle

The castle MUST be both real AND delightful. Both sides of this line are critical. We do not give in to either side entirely. The principle has five concrete commitments:

1. **Hard enforcement at the wall** AND approval response under 2 seconds when policy prompts the operator.
2. **Default-deny outbound** AND smart always-allow rules with learning, so routine traffic does not require repeated approvals.
3. **Castle wall ships before enterprise pilots** AND operators experience the wall as polite, not punishing. The wall is invisible until it matters; when it matters, the operator-facing copy is plain English plus a one-click approve.
4. **Sentinels observe** AND do not surface noise. Notification fatigue kills the product. Only high-signal anomalies surface; routine variations are baselined and silenced.
5. **Cooperative MCP path remains additive and fully usable.** Compliant agents do not lose anything; they gain the full sovereignty surface. Non-compliant agents hit the wall; they do not break the castle.

If any decision strengthens enforcement at the cost of usability beyond a tolerable threshold, restructure. If any decision improves usability by softening enforcement to cooperative-only, restructure. Both failure modes are equally destructive.

## Consequences

The Castle Architecture has the following consequences for v1.x and beyond.

**v1.x roadmap.** An Egress Enforcement work package (WP-V1.x-CASTLE-WALL) ships as a v1.x scope item, not v2-deferred. Specific scope at `Review/Sanctuary/Egress_Enforcement_WP_Scope_2026-04-30.md`. macOS plus Linux ship Phase 1; Windows is Phase 2; container or microVM isolation is Phase 3 for highest-assurance enterprises.

**Sentinels gain clarity.** WP-V1.3-1 (sentinel baseline pack), WP-V1.3-2 (anomaly detection pipeline), and WP-V1.3-7 (auto-trigger ladder) become Layer 2 surface. Their job is observation plus operator-facing notification, not enforcement. The notification UX from the v1.2 build pivot is the surface.

**Cooperative MCP repositions as Layer 3.** Existing tool surface, Tier 1 inline approval, four canonical policy slots, audit log, exit bundle remain. They are additive sovereignty primitives for compliant agents. Marketing copy and partner pitches must not present them as the enforcement story.

**Verascore repositions as Layer 4.** External accountability, not internal deterrent. Verascore's value remains real for cross-castle commerce. Verascore is not the answer to "how does Sanctuary enforce against a prompt-injected agent."

**Pilots gate on castle wall shipping.** Enterprise pilots cannot honestly demonstrate Sanctuary's security claims without the wall. The pilot demo includes a prompt-injection attempt against a wrapped agent showing the wall blocking unauthorized egress and the menubar notification surfacing the attempt. Without the wall, the demo is a polite fiction.

**Sovereignty Manifesto and partnership outreach update.** Public claims must reflect real enforcement, not voluntary cooperation. Drafts in `Review/Strategic_Plan_2026-04-30/` are updated alongside this ADR.

## Operating discipline

To prevent future drift, three structural anchors:

### Anchor 1: This ADR is canonical

Every spec, every PR, every scope-lock from this ADR's approval onward must reference the Castle Architecture and the layer it operates in. Specs that do not name their enforcement layer do not pass review.

### Anchor 2: The fourth scope test

The three scope tests already established (substrate vs feature, per-version one-question, North Star metric) gain a fourth: **the castle-walking test.**

> Does this proposal preserve real castle-wall enforcement (Layer 1) AND remain delightful for operators and agents to use?
>
> If it strengthens enforcement at the cost of usability beyond a tolerable threshold, restructure.
>
> If it improves usability by softening enforcement to cooperative-only (Layer 3) where Layer 1 enforcement is required for the security claim, restructure.
>
> If it relies on cooperative agent behavior (Layer 3) for a security guarantee, name the paired Layer 1 enforcement piece, and confirm both ship together. Cooperative-only WPs without paired hard-enforcement pieces do not ship.

This test folds into CLAUDE.md as part of the refactor pass.

### Anchor 3: Pilot-gate on enforcement

Enterprise pilots and external partner demos cannot ship without the castle wall demonstrably blocking an unauthorized egress attempt. Specifically: the pilot demo must include a prompt-injection scenario against a wrapped agent, the wall blocking the unauthorized action, the menubar surfacing the attempt, and the operator approving or denying in under 10 seconds end-to-end. This is the demo that makes the security claim honest.

## Open questions

1. **Cross-platform sequencing.** macOS first, Linux fast follow, Windows later. Confirm Phase 1 timeline against pilot pipeline timeline. (Coordinator recommendation: Phase 1 macOS plus Linux completes within 4-8 weeks of Claude-driven execution after v1.2 ships.)
2. **Default-deny vs default-allow on outbound.** Default-deny aligns with sovereignty thesis but introduces friction. Default-allow with policy-driven block list is faster to adopt but weaker. Coordinator recommendation: default-deny with operator-facing first-run wizard that auto-allows common developer endpoints (GitHub, npm, package registries) and prompts for everything else. Friction acceptable for sovereignty-conscious operators; the wizard reduces it for the rest.
3. **Sandboxing-incompatible runtimes.** Some agent runtimes may not work cleanly with egress filtering (browser-based agents, agents that expect raw network sockets, etc.). Document the compatibility matrix; surface incompatibility transparently to operators; offer the cooperative-MCP path as a fallback for those runtimes (with explicit acknowledgment that the security claim is weaker).
4. **Per-process vs system-wide enforcement.** Per-process is correct for the castle architecture (each wrapped agent has its own egress policy) but harder to implement. System-wide is easier but coarser. Coordinator recommendation: per-process, using cgroup or namespace isolation on Linux, process-supervisor approach on macOS.

## Glossary

- **Castle:** the operator's machine plus operator-controlled compute. The trust perimeter Sanctuary defends.
- **Castle wall:** the boundary between the castle and the external world. Layer 1 enforcement layer.
- **Sentinels:** internal observation agents. Layer 2.
- **Cooperative MCP:** the voluntary tool surface for compliant agents. Layer 3.
- **Cross-castle:** transactions or messages crossing between castles (different operators).
- **Castle-walking principle:** the discipline of holding both real enforcement AND delightful UX simultaneously.
- **Egress filter:** the network-layer component that intercepts outbound calls and applies policy. Layer 1 implementation.
- **Wrapped agent:** an agent runtime (Claude Code, OpenClaw, Hermes, Cline, Mastra, Cursor, etc.) running inside the castle. Sanctuary does not constrain the runtime internally; only at the wall.

## References

- Engineer-friend critique 2026-04-30 evening (informal, via Erik direct).
- v2 product thesis: `Review/Sanctuary/Sanctuary_Product_Thesis_v2_2026-04-21.md`.
- v3 thesis refinement: `Review/Sanctuary/Thesis_V2_Refinement_and_Scope_Tests_2026-04-30.md`.
- Egress enforcement WP scope: `Review/Sanctuary/Egress_Enforcement_WP_Scope_2026-04-30.md`.
- Strategic plan: `Review/Strategic_Plan_2026-04-30/01_Strategic_Plan.md`.
- Engineer-friend response draft: `Review/Strategic_Plan_2026-04-30/07_Engineer_Friend_Response.md`.
