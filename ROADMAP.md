# Roadmap

Sanctuary is the operator-sovereign substrate for AI agents. Operators bring the harness, model, and deployment shape they choose. Sanctuary supplies the shared sovereignty layer: OS-level enforcement at the cross-boundary wall, internal observation, cooperative sovereignty primitives for compliant agents, and cryptographic accountability for cross-castle commerce.

Your agent. Your machine. Your keys.

This document is the public milestone view. Shipped history lives in `CHANGELOG.md`. Interface specs live in `server/docs/`. Architecture decisions live in `server/rfcs/`. Scope documentation is maintained privately and released to the public repo on version bumps.

Last updated: 2026-04-30.

---

## Architecture: the Castle

Sanctuary's enforcement model is the Castle Architecture, codified at `server/rfcs/RFC-0003-castle-architecture.md`. Four layers, each with a distinct enforcement contract.

- **Layer 1, Castle Wall.** OS-level egress filtering at the operator-external boundary. The kernel itself blocks unauthorized cross-boundary calls. Even prompt-injected agents cannot bypass.
- **Layer 2, Sentinels.** Internal observation via process introspection and behavioral baselining. Anomalies surface to the operator via menubar plus notifications. Observation, not enforcement.
- **Layer 3, Cooperative MCP.** Additive sovereignty surface for compliant agents. Encrypted state, signed audit, mandate primitives, four canonical policy slots, substrate selector, Concordia receipt integration, Verascore reputation hooks.
- **Layer 4, Cryptographic Receipts and Reputation.** Concordia receipts for cross-castle commitments, Verascore reputation aggregating across operators. Cross-castle accountability post-action.

Castle-walking principle: real enforcement AND delightful UX. Both sides critical. Hard enforcement at the wall AND approval response under 2 seconds. Default-deny outbound AND smart always-allow rules. Sentinels observe AND do not surface noise. Cooperative MCP path remains additive and fully usable. Composition with agent runtimes is preserved because the runtime sees a normal operating environment with constrained egress.

---

## Scope Thesis

v1.0 is the operator-sovereign fortress in final acceptance.

v1.1 ships the foundation that makes the local sovereignty harness real: identity, keys, persistence, signed audit, recovery, encrypted state, fortress-local hub APIs, internal coordination, portable exit.

v1.2 ships the operator-facing surfaces and the intelligence substrate selector that make the fortress usable as a daily product: menubar status app, OS notifications, concierge chat, substrate selector, channel-template binding, Tier 1 inline approval, audit feed, exit-bundle drill, operator-friendly tool-error text in MCP gate responses.

v1.x ships the Castle Wall: OS-level egress enforcement at the operator-external boundary. This is the load-bearing piece that makes Sanctuary's security claims structural, not cooperative-only. Phase 1 (macOS plus Linux) ships within 4-8 weeks of v1.2 shipping. Without the wall, the cooperative MCP path is a polite fiction; with it, the substrate is honest under engineer-grade scrutiny.

v1.3 ships advanced Sanctuary intelligence: sentinels (the Castle Layer 2 observation surface), anomaly detection, conversational sovereignty depth, cross-harness approval inbox, English-authored policy gates, honeypot authoring, auto-trigger ladder.

v1.4 extends the fortress beyond the local single-operator deployment: PWA mobile companion, public federation across operators, sovereign data warehouse.

v1.5+ expands into fleet operator console, Agent Vault payment-rail composition, Bootstrap bundle, Agent Registry Federation, breach-feed aggregation, EU AI Act compliance pack, NIST AI RMF alignment, Crypto Agility Sprint (post-quantum migration), operator cloud, sovereign-managed TEE, container or microVM isolation for highest-assurance enterprises.

The current sequencing deliberately delays public federation, fleet management, payment rails, compliance packs, and cryptographic migration until the local operator experience is complete and the operator owns the durable record. The local harness is the product center: attach agents, communicate with them, coordinate them, filter what leaves at the OS-level wall, record what happened, hold that record where the operator owns it, and leave with that record intact.

The published agent-stack standards are anti-lock-in on paper. In practice, lock-in returns at the integration layer, when mandate primitives are minted through one vendor's API, on-chain registry entries are anchored through one vendor's wallet, and identity assertions are issued by one vendor's identity provider. The operator's data is portable in theory and coupled in practice. Sanctuary's substrate position is the layer that turns paper-portability into practical portability. The fortress holds operator identity and durable record on the operator's side of every integration.

---

## Composition Map

The agent stack is publicly composed across four ecosystem layers. Sanctuary lives in the operator-sovereign substrate position.

```
Ecosystem layer 4: Operator-sovereign substrate    Sanctuary (you are here)
    Castle Architecture (Wall, Sentinels, Cooperative MCP, Receipts plus Reputation)
    Composes with: ERC-8004, DIF KYA-OS, AIVS, A2A

Ecosystem layer 3: Mandates and commerce            Concordia, Google AP2, A2A extensions
    Mandate primitives, session receipts, commitment binding

Ecosystem layer 2: Runtime security                 Open-source runtime egress filters
    Per-host policy, request filtering, sandboxing

Ecosystem layer 1: Payments                         Coinbase x402, Agentic.Market
    Sovereign-signer adapter on Sanctuary
```

Composition partners are named where Sanctuary explicitly composes with them. Layers without named partners are referenced as categories.

Note on layer naming: the ecosystem layers above (1-4) describe Sanctuary's position within the broader agent stack. Within Sanctuary itself, the Castle Architecture defines four enforcement layers (also Layer 1-4). To avoid confusion, references to Castle Layers always include the prefix "Castle" (e.g., Castle Layer 1, Castle Layer 2). References to ecosystem layers always include "Ecosystem" (e.g., Ecosystem Layer 4).

---

## v1.0 GA: Freeze And Acceptance

v1.0 is the operator-sovereign fortress in final acceptance. The remaining work is validation and blocker removal, not new feature surface.

Shipped foundation:

- Local `sanctuary wrap` for existing harnesses
- Dashboard (configuration plus inspection surface)
- Cooperative MCP gates (Castle Layer 3): Principal Policy, three-tier approval, four canonical policy slots
- Encrypted state and signed audit trail
- Five channel-shape governance templates
- Federation Protocol v0.1 foundation
- Agent Contract v0.1
- Egress controls (cooperative; structural enforcement ships in v1.x), budgets, retention, and recovery flows
- Concordia and Verascore optional composition, default off
- Template library starter set
- Tier B harness adapter coverage at v1.0: OpenClaw, Claude Code, Cursor, Hermes, Cline, plus a generic adapter shape

GA gate:

An external pilot operator, not the maintainer, can stand up a fortress, wrap two or three Tier B agents, communicate with them, run a local multi-agent workflow, approve or deny risky actions, and complete a recovery drill in under 60 minutes with no help.

Allowed v1.0 work:

- Fix pilot blockers
- Align README, ROADMAP, package metadata, and agent context docs
- Harden install diagnostics
- Add harness compatibility smoke tests for every README-supported harness
- Add CI coverage for tool policy tier declarations and outbound network declarations

Explicitly deferred:

- Castle Wall (egress enforcement); ships in v1.x
- Sentinels (anomaly detection); ships in v1.3
- Mobile companion; ships in v1.4
- Payment adapters; ships in v1.5+
- Compliance packs; ships in v1.5+
- Post-quantum or next-generation messaging-layer-security migration; ships in v1.5+

---

## v1.0.x: Reliability Patch Track

Point releases close field-verification gaps and platform parity without changing the product shape.

- NPM_TOKEN auto-publish guard: shipped
- Linux Secret Service keychain backend: shipped; real-backend CI exercise remains queued
- `sanctuary reset-passphrase` subcommand, nuke-and-rebind path: shipped
- Reset-history continuity: signed `recovered-from-reset` audit entry on next `sanctuary wrap` after reset
- Test-baseline headroom bump
- Windows Credential Manager keychain backend
- Dashboard session hardening and credential-leak audit
- `sanctuary doctor` or equivalent diagnostics for wrap, keychain, dashboard, audit, and config-backup failures

Gate:

An operator who hits a normal install, keychain, dashboard, or recovery failure gets a local diagnostic that identifies the failing subsystem and the next action without needing maintainer help.

---

## v1.1: Local Sovereignty Harness Foundation (shipped or in flight)

v1.1 ships the foundation that makes the local sovereignty harness real: identity, keys, persistence, signed audit, recovery, encrypted state, fortress-local hub APIs, query privacy, internal coordination, portable exit. Detailed pillar descriptions are preserved in `server/docs/v1.1-acceptance-checklist.md`.

v1.1 acceptance gate:

An operator can wrap two or three agents, communicate with them locally, coordinate a local multi-agent workflow, anonymize or pseudonymize outbound queries, approve / deny / pause / resume / lockdown agents, inspect audit and privacy events, and export and import the durable record onto a fresh machine or harness.

---

## v1.2: Operator-Facing Surfaces, Intelligence Substrate, Castle UX

v1.2 lights up the operator-facing surfaces v1.1 wired but never powered, plus introduces the substrate selector and the menubar plus notification UX that becomes the operator's daily-driver interface.

Per the v1.2 build pivot 2026-04-30 evening, direct-agent chat (operator-to-wrapped-agent) is dropped from v1.2 and from the roadmap entirely. Direct chat with the wrapped agent happens in the harness; Sanctuary's job is the substrate, not the harness chat surface. Concierge chat (operator-to-Sanctuary) remains; Sanctuary's runtime is ours, so the safety-prior fight does not apply to that surface.

Six work packages in v1.2:

- **WP-V1.2-2 Channel-Template Binding Flow.** Operator picks a channel template per wrapped agent in the Policy Center; Tier 1 `policy_change` approval fires; activity feed records the binding. Library reconciliation rides along.
- **WP-V1.2-4a Concierge Chat (operator-to-Sanctuary).** Dashboard concierge default; operator talks to Sanctuary in plain English about agent activity, gets summaries, fires actions. Consumes the substrate selector.
- **WP-V1.2-5 Intelligence Substrate Selector.** Operator picks per surface among local model (Ollama with bundled local LLMs), Venice.ai (privacy-respecting hosted; named composition partner), operator-frontier with Privacy Filter Tier 2 redaction, or hybrid per-surface routing. Selector ships with operator-facing tradeoff transparency UI.
- **WP-V1.2-6 Menubar Status App.** Macbar status app showing all-clear or pending-item badge. Click expands to popover with pending list, one-click approve/deny, click-to-inspect any audit entry. Initial Phase: macOS. Linux and Windows in v1.2.5 or v1.3.
- **WP-V1.2-7 OS-Native Notifications.** Tier 1 gates and policy-uncertain calls fire OS notifications. Notification copy in plain English; click opens menubar approval flow. Initial Phase: macOS. Linux libnotify and Windows WinRT Toast in v1.2.5 or v1.3.
- **WP-V1.2-8 Operator-Friendly Tool-Error Text.** MCP gate-block responses use plain-English copy that the agent's LLM naturally surfaces back to the operator. One-day change with three-channel coverage on the approval-gate-invisibility problem.

Telegram bridge stopgap (separate brief): ports approval-needed events to a Telegram bot for phone notifications and remote approval. Queued behind the v1.2 WPs; ships any free Codex window during the v1.2 cycle. Replaced by the v1.4 PWA mobile companion when that ships.

v1.2 acceptance gate:

An operator wraps two harnesses, picks an intelligence substrate (any of the four options, with the tradeoff visible at selection), uses the concierge to ask "what did agent X do today" and gets a real summary. The operator binds a channel template to a wrapped agent through the Policy Center and sees the binding reflected in the Per-agent rules table and the activity feed. The substrate selector's transparency UI shows the per-surface routing the operator chose. Privacy Filter Tier 2 works (regex Tier 1 always; Tier 2 routed per substrate selection). Menubar status app shows pending approvals; OS notifications fire on Tier 1 gates; operator approves or denies in under 5 seconds. Operator-friendly tool-error text surfaces blocks back to the operator naturally through the agent's normal output channel.

---

## v1.x: Castle Wall Enforcement (load-bearing)

v1.x ships the Castle Wall: OS-level egress enforcement at the operator-external boundary. This is the structural enforcement layer that makes Sanctuary's security claims real, not cooperative-only. Without the wall, the substrate is a polite fiction; with it, the architecture is honest under engineer-grade scrutiny.

Single work package: WP-V1.x-CASTLE-WALL.

Phase 1 (target 4-8 weeks of execution after v1.2 ships): macOS plus Linux.

- Cross-platform abstraction layer with platform-specific backends
- Linux backend: netfilter / NFQUEUE plus per-process cgroup or namespace routing
- macOS backend: Network Extension framework (long-term path) plus pf-based interim
- Per-process policy integration (extends the four canonical slots with a fifth slot: egress)
- Notification UX integration (consumes v1.2 menubar plus OS notification surfaces)
- Agent-side error text (consumes v1.2 operator-friendly tool-error text)
- First-run wizard for default-deny posture plus common-developer-endpoint pre-allow
- Cross-platform compatibility matrix (corporate VPNs, Tailscale, common firewalls)
- Audit and reporting integration (egress decisions feed the existing audit log; events feed Layer 2 sentinels)

Phase 2 (target 4-6 weeks after Phase 1): Windows Filtering Platform backend.

Phase 3 (target post-Phase 2, gated on operator demand): container or microVM isolation for highest-assurance enterprises.

Acceptance gate:

A wrapped agent on a clean Sanctuary install, given a prompt-injection payload designed to exfiltrate data via curl, fails to make the unauthorized network call. The menubar notification fires. The operator approves or denies in under 10 seconds. The audit log records the attempt and the decision. Performance overhead under 10ms p99 on allowed traffic.

This WP gates enterprise pilot demos. Pilot conversations cannot honestly demonstrate Sanctuary's security claims without the wall in place.

---

## v1.x: Query-Layer Anonymity (closes Principle 4)

WP-V1.x-QUERY-LAYER-ANONYMITY closes Principle 4 (Opacity at the query layer) of the v3 sovereignty framework. Today the Castle Wall plus substrate selector deliver a partial form: the wall prevents unauthorized egress and the substrate selector routes LLM calls through operator-chosen substrates. What is missing: the agent can still be identified-by-asking when the substrate sees the query, and the query envelope carries operator metadata even when policy permits the call.

This WP ships query-layer anonymity in three tiers:

- **Tier 1, header strip (default-on).** Strip operator-identifying headers from outbound LLM calls before they leave the substrate selector. Client-IP, fingerprint, correlation-ID, User-Agent, cookies, and persistent session tokens are stripped or rotated per-call. Acceptance: outbound LLM calls from a Sanctuary-wrapped agent are byte-for-byte indistinguishable from calls from any other Sanctuary-wrapped agent on the same substrate.
- **Tier 2, semantic PII rewrite (opt-in).** Operator opt-in per channel. Deterministic PII-rewrite pass replaces names, addresses, account numbers, medical record numbers, and other operator-identifying tokens with stable pseudonymous handles before sending. The substrate processes pseudonymous content; Sanctuary maps handles back locally on the response. Performance budget: under 100ms p99 added to the LLM call round-trip.
- **Tier 3, mix network or zero-knowledge proof (research; post-v1.x).** Architectural target for network-layer anonymity (Tor-style or Nym-style) plus ZK-proof of authorization without revealing operator identity. Separate research thread; not in scope for this WP.

Ship gate: zero-PII-leakage criterion, mandatory across all tiers and configurations. No personally-identifying data leaves the castle in the query payload unless the operator has explicitly authorized that field in policy. Regression test in CI enforces this against a canonical PII corpus on every release.

No comparator implementation we surveyed ships query-layer anonymity at this strength. This is the genuinely novel claim in the seven-principle framework.

Scoping brief: `Review/Sanctuary/WP-V1.x-Query-Layer-Anonymity_Scoping_Brief_2026-05-10.md`.

---

## v1.x: Recognition Layer (closes Principle 5, recognition arm)

WP-V1.x-RECOGNITION-LAYER closes the recognition arm of Principle 5 (Recognition and portability) of the v3 sovereignty framework. Portability (transport) is already shipped at strength via exit bundle, Concordia receipts, and Verascore reputation. Recognition (standing: the new regime acknowledges the operator's record as the operator's) at the identity layer is partial today. This WP ships the missing piece via three composable adapter paths plus a fourth deferred path.

Four paths, prioritized:

- **Path C primary, `did:web` (FIRST; smallest surface, 2-3 weeks, spawnable now).** Standard W3C DID method. Operator identity at `did:web:<operator-domain>` resolved via HTTPS GET. DID document signed by operator-held Ed25519 keys. Hosted alternative for operators without a domain (`did:web:sanctuary.example/<operator-handle>`; Sanctuary serves the static DID document, operator keys still sign it; composable, not custodial). VC issuance and verification included. This is the first ship because the technical surface is small, ecosystem adoption is real (Microsoft Entra, eIDAS 2.0 implementations, SSI stacks), and no external dependency gates it.
- **Path B, ERC-8004 composition (parallel; spawnable after product-experience sprint ships).** ERC-8004 Identity adapter: Sanctuary signs Identity registrations with operator-held keys; consumes incoming ERC-8004 Identity attestations from counterparty agents. Verascore writes Reputation attestations from Sanctuary-signed audit data. Gas custody is the structural friction (operator holds the gas wallet; Sanctuary does not).
- **Path A, DIF KYA-OS adapter (gated on DIF spec stability; window 2026-06 to 2026-08).** Sanctuary Verifier-role module consuming KYA-OS-format agent identity assertions; reciprocal emission. Conformance test suite against KYA-OS reference vectors when DIF publishes them. Contributed upstream as a composition partner artifact, not a Newton-named conformance tier. Gated on the DIF KYA-OS task force publishing a stable spec surface.
- **Path C secondary, KERI (deferred indefinitely; internal design ideas only).** KERI's design (key event log, witness/watcher, pre-rotation) is technically excellent. The KERI ecosystem has not won commercially and may not. Sanctuary adopts KERI design ideas internally where they help (audit log key-event-log shape, pre-rotation in guardian recovery, witness/watcher patterns in federation attestation) but does not ship a `did:keri` adapter as a critical-path item. If KERI gains traction later, an adapter can be added as a composition partner artifact with no rework of the core Path C surface.

Surface-level simplification: operators do not see DID methods in the dashboard. They see "Your identity," a one-screen view showing operator display name, fortress, and a copy-to-clipboard sharing link. The DID method is plumbing.

Scoping brief: `Review/Sanctuary/WP-V1.x-Recognition-Layer_Scoping_Brief_2026-05-10.md`.

---

## v1.3: Advanced Sanctuary Intelligence

v1.3 is every Sanctuary-native sovereignty affordance the operator can see, configure, and audit, including the Castle Layer 2 sentinel surface. The library substrate (audit log, policy engine, channel templates, coordination primitives) shipped in v1.0 and v1.1; the substrate selector ships in v1.2; the castle wall ships in v1.x. v1.3 builds the intelligence layer on top.

Per the build coordinator pivot 2026-04-30 evening, WP-V1.3-8 (autonomous wake mechanism spec) drops entirely. WP-V1.3-1 through WP-V1.3-7 stay and get sharper. Two new work packages added: WP-V1.3-9 (conversational sovereignty depth) and WP-V1.3-10 (cross-harness approval inbox).

Nine work packages in v1.3:

- **WP-V1.3-1 Sentinel Baseline Pack (Castle Layer 2).** Five baseline sentinels (egress-volume watcher, credential-usage watcher, cross-agent-chatter watcher, suspicious-tool-call detector, anomaly-trigger). Each ships as a default-installable agent that uses the substrate selector. Operator subscribes via the Sanctuary dashboard; sentinels are inward-facing only (no external network access) and surface findings to the unified inbox.
- **WP-V1.3-2 Anomaly Detection Pipeline (Castle Layer 2).** Per-agent feature classifier with local pattern learning, drift detection, and operator-visible alerts. Sovereignty-critical: ML training stays on the operator's machine; never centrally aggregated.
- **WP-V1.3-3 Coordination Handoff Visualization.** Read-only Coordination view rendering handoff log, per-handoff context-transfer breakdown (transferred vs withheld), and workflow state.
- **WP-V1.3-4 Unified Approval Inbox Bridge.** Bridges legacy ApprovalGate and v1.1 hub inbox with unified provenance. Operator sees approvals, blocked egress, privacy events, budget warnings, recovery prompts, agent errors, and sentinel findings in one stream.
- **WP-V1.3-5 Honeypot Authoring.** Operator writes a honeypot in plain English; LLM compiles to a runtime trap; integrates with the sentinel layer. Uses the substrate selector.
- **WP-V1.3-6 English-Authored Policy Gates.** Operator writes a custom policy in plain English; LLM compiles to a structured rule and synthesizes the operator-facing explanation. Uses the substrate selector. Templates remain the v1.2 default for the six canonical channel templates; English-authored gates layer on top for custom policies.
- **WP-V1.3-7 Auto-Trigger Ladder plus Threshold Calibration.** Operator-configurable thresholds for sentinels and anomaly detection. Calibration UI lets the operator move rules from operator-approved to auto-action incrementally as confidence builds.
- **WP-V1.3-9 Conversational Sovereignty Depth.** Take the concierge chat surface (v1.2) from "answers questions about audit log" to "operator's primary natural-language interface to their sovereignty primitives." Audit summaries, batch approvals, policy authoring, exit bundle generation, identity rotation, all available conversationally. This is where the "Sanctuary feels delightful" moment compounds.
- **WP-V1.3-10 Cross-Harness Approval Inbox.** A single inbox aggregating pending approvals from any number of wrapped harnesses (Claude Code, OpenClaw, Hermes, Mastra, Cline, Cursor running concurrently in the operator's life). Notification-first delivery; menubar surface; conversational query through concierge chat. This is the v1.3 piece that makes Sanctuary's value compound across an operator's whole agent fleet, and it is the substrate-position thesis made concrete.

v1.3 acceptance gate:

The operator subscribes a sentinel; the sentinel observes agent activity and reports a finding via the unified inbox. Anomaly detection identifies an intentional drift (operator triggers a deviant tool call) and surfaces an alert. The Coordination view shows a multi-agent handoff history with full provenance. The operator authors a honeypot in plain English and watches it fire on trigger. The operator authors a custom policy gate in plain English and sees the LLM-compiled rule plus operator-facing explanation. The auto-trigger ladder honors the operator's threshold configuration. Concierge chat handles batch approvals, policy authoring, and exit bundle generation conversationally. The cross-harness approval inbox aggregates pending approvals from three concurrently-running wrapped agents (Claude Code, Hermes, Cline) into a single menubar surface.

---

## v1.4: Reach (Mobile, Federation, Sovereign Data Warehouse)

v1.4 extends the fortress beyond the local single-operator deployment. Mobile reaches the operator's phone. Public federation reaches other operators. Sovereign Data Warehouse reaches data sources beyond the agent loop. All three are about the fortress reaching outward while the operator's sovereignty stays intact.

Three work packages in v1.4:

- **WP-V1.4-1 PWA Mobile Companion.** Phone as operator key, inbox, approval surface, alert surface, emergency brake. PWA implementation: install on home screen, push notifications via Web Push API, biometric unlock via WebAuthn / passkeys, QR pairing from the desktop dashboard. Native iOS / Android deferred indefinitely; PWA on iOS 16.4+ and current Android covers the operator-control scope. Telegram bridge from v1.2 stops being load-bearing once the PWA ships but stays available as an alternate notification channel.
- **WP-V1.4-2 Public Federation.** Cross-operator discovery, signed inter-fortress messaging, public or semi-public agent pools, reputation exchange, anonymized wants and requests, abuse and rate controls, policy-enforced disclosure envelopes for anything crossing the boundary. Per the Federation Protocol v0.1 spec already shipped.
- **WP-V1.4-3 Sovereign Data Warehouse.** The agent's durable record belongs to the operator. SDW builds the substrate so the operator's working data, query history, document corpus, and intermediate state live in a place the operator controls, not in a vendor's silo.

v1.4 acceptance gate:

An operator pairs a phone, receives a generic approval notification, opens the PWA, reviews details fetched from the local fortress, approves with biometric unlock, and can revoke the phone from the desktop dashboard. Two independent operators complete a signed cross-fortress interaction where each side controls what identity, query content, reputation, commitments, and audit receipts leave the fortress. A pilot ingests a meaningful slice of one vendor's data into the fortress, queries it locally with provenance preserved, applies a slice-scope policy, runs a multi-step sync, and demonstrates the data continues to be available after the vendor relationship ends.

---

## Regulatory Posture

The full EU AI Act compliance pack ships in v1.5+. The architecture-independent first-mile is already in the fortress: signed audit trail, signed receipts, signed-event envelopes provide a defensible record-keeping substrate for Article 12 obligations. The Castle Wall extends this to enforce Article 50 transparency primitives at the OS level. Operators preparing for the August 2 enforcement date can compose those primitives with an external compliance toolchain in the meantime. The full compliance pack adds Article 50 transparency primitives surfaced to the operator and the operator-facing compliance generator.

---

## v1.5+ Expansion

These tracks start only after v1.0 GA, v1.x Castle Wall, v1.2 operator-facing surfaces, v1.3 advanced intelligence, and v1.4 reach milestones.

- Fleet operator console for multi-operator estates
- Agent Vault composition adapter for sovereign signing of external-stack payment rails, delegation mandates, and reputation receipts
- Container or microVM isolation (Castle Wall Phase 3) for highest-assurance enterprises
- Bootstrap bundle (`@sanctuary-framework/agent-bundle`) for zero-config deployment
- Agent Registry Federation across organizations
- Native mobile features beyond companion control
- Breach-feed aggregation and scoped sub-token rotation
- EU AI Act compliance pack
- NIST AI RMF alignment documentation
- Crypto Agility Sprint: bundled post-quantum signature and key-exchange migration plus group-messaging upgrade, executed as one coordinated cryptographic-library transition
- Operator-cloud deployment mode
- Sovereign-managed TEE and hardware secure elements
- Additional Tier B adapter candidates including production TypeScript-native harnesses with native MCP support, scoped against operator demand

---

## v2: Managed Sovereignty Horizon

Shape locks after pilots generate operator-usage data.

Current direction:

- Sovereign-managed TEE mode with hardware attestation
- Hardware-backed secure-element integration
- Third-party secret-manager import
- Broader ecosystem composition
- Shared-pool arbitration grammar, if public federation usage proves demand

---

## Standards Engagement

Cross-cutting, not tied to a single version. Sanctuary engages standards bodies to land operator-sovereign primitives as open specifications rather than proprietary interfaces.

- W3C Agentic Integrity Verification Specification (AIVS) community group, Erik chairs. First deliverable: Concordia receipt schema submission within 90 days.
- W3C DID method alignment
- IETF trust-scoring alignment
- AAIF Security Working Group participation
- MCP Registry governance proposal
- Reputation Portability Standard
- DIF KYA-OS Task Force, Verifier-role reference implementation against the Layer 2 conformance tier
- DIF Delegatable Attenuated Authorization Task Force, observer posture aligned to Concordia Protocol composition
- ERC-8004 ecosystem alignment

---

## Non-Dependency And Composition Posture

Sanctuary never requires Concordia. Concordia never requires Sanctuary. Composition with external frameworks is always optional and default off. The framework alone, with no external dependency of any kind, is a fully operational local sovereignty harness with structural enforcement at the Castle Wall.

Composition partners are named as partners: Coinbase x402, Google AP2, Anthropic MCP, Hermes A2A, Concordia Protocol, Verascore, ERC-8004 ecosystem, and peers in the agent-interop space.

---

## Contributing To The Roadmap

Scope changes against the current major version happen through dated amendments to the private scope-lock document, not rewrites. Minor items land via GitHub issue and pull request. Major items land via brief and coordinator approval before a build thread spawns. For standards-track engagement, participation in the relevant community group or working group is the fastest route. Enterprise pilot inquiries reach the maintainer via GitHub.

Sole author: Erik Newton.
