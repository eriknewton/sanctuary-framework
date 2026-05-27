# Roadmap

Sanctuary is the operator-sovereign substrate for AI agents. Operators bring the harness, model, and deployment shape they choose. Sanctuary supplies the shared sovereignty layer: OS-level enforcement at the cross-boundary wall, internal observation, cooperative sovereignty primitives for compliant agents, and cryptographic accountability for cross-castle commerce.

Your agent. Your machine. Your keys.

This document is the public milestone view. Shipped history lives in `CHANGELOG.md`. Interface specs live in `server/docs/`. Architecture decisions live in `server/rfcs/`. Scope documentation is maintained privately and released to the public repo on version bumps.

Last updated: 2026-05-27.

---

## Architecture: the Castle

Sanctuary's enforcement model is the Castle Architecture, codified at `server/rfcs/RFC-0003-castle-architecture.md`. Five named layers, each with a distinct enforcement contract.

- **Castle Wall.** OS-level egress filtering at the operator-external boundary. The kernel itself blocks unauthorized cross-boundary calls. Even prompt-injected agents cannot bypass.
- **Sentinels.** Internal observation via process introspection and behavioral baselining. Anomalies surface to the operator via menubar plus notifications. Observation, not enforcement.
- **Charter (Cooperative MCP).** Additive sovereignty surface for compliant agents. Encrypted state, signed audit, mandate primitives, four canonical policy slots, substrate selector, Concordia receipt integration, Verascore reputation hooks.
- **Heralds.** Concordia receipts for cross-castle commitments, Verascore reputation aggregating across operators. Cross-castle accountability post-action.
- **Mantle.** Install-time substrate-binding. The check that locks Sanctuary to the operator's machine at install time and rejects orphan agent identifiers not bound to a wrapped harness.

Castle-walking principle: real enforcement AND delightful UX. Both sides critical. Hard enforcement at the wall AND approval response under 2 seconds. Default-deny outbound AND smart always-allow rules. Sentinels observe AND do not surface noise. The Charter path remains additive and fully usable. Composition with agent runtimes is preserved because the runtime sees a normal operating environment with constrained egress.

---

## Scope Thesis

v1.0 through v1.3 are shipped. The operator-sovereign fortress runs locally, wraps any MCP-compatible harness, gates every tool call through three-tier policy, encrypts every byte of state, signs every audit entry, and exports a portable bundle the operator owns. The Castle Wall enforces structurally on Linux. The Castle Wall macOS sysext is signed, notarized, activated, and IPC-connected as of v1.3.3; active enforcement (NEFilterManager arming) shipped on main post-v1.3.3 and is awaiting end-to-end Mini1 drill PASS to close the macOS thesis-gate.

Current focus is the Castle Wall macOS thesis-gate: until a Mini1 drill proves a wrapped agent's outbound packets are intercepted at the kernel layer and routed through Castle Wall policy with full audit evidence, the structural-enforcement claim is honest only for Linux. Once that drill clears, Sanctuary's security claims trace to drill evidence on both platforms that matter to operators today.

After the thesis-gate closes, Wave 1 lands the parity and federation-ready API surface that lets multiple operators federate without giving up custody: API parity catalog, CLI MVP, federation Wave 1 hardening (per the 2026-05-26 Federation Security RFC), and the federation-across-operator-machines demo. Wave 2 audits the cooperative feature surface and the agent-native surface. Wave 3 lands the plugin architecture and observability. Wave 4 closes the advocacy loop.

The Castle Wall Windows backend, the PWA mobile companion, the operator-cloud and sovereign-managed deployment modes, fleet, payment-rail composition, breach-feed aggregation, the EU AI Act compliance pack, NIST AI RMF alignment, and the Crypto Agility Sprint (post-quantum signing migration) all sit beyond the current Wave window. They are sequenced after thesis-gate closure on principle: ship the load-bearing enforcement first, then expand surface.

The published agent-stack standards are anti-lock-in on paper. In practice, lock-in returns at the integration layer, when mandate primitives are minted through one vendor's API, on-chain registry entries are anchored through one vendor's wallet, and identity assertions are issued by one vendor's identity provider. The operator's data is portable in theory and coupled in practice. Sanctuary's substrate position is the layer that turns paper-portability into practical portability. The fortress holds operator identity and the durable record on the operator's side of every integration.

---

## Composition Map

The agent stack is publicly composed across four ecosystem layers. Sanctuary lives in the operator-sovereign substrate position.

```
Operator-sovereign substrate (Sanctuary; you are here)
    Castle Architecture: Castle Wall, Sentinels, Charter (Cooperative MCP), Heralds, Mantle
    Composes with: ERC-8004, DIF KYA-OS, AIVS, A2A

Mandates and commerce      Concordia, Google AP2, A2A extensions
    Mandate primitives, session receipts, commitment binding

Runtime security           Open-source runtime egress filters
    Per-host policy, request filtering, sandboxing

Payments                   Coinbase x402, Agentic.Market
    Sovereign-signer adapter on Sanctuary
```

Composition partners are named where Sanctuary explicitly composes with them. Categories without named partners are referenced as categories.

---

## v1.0 GA: Operator-Sovereign Fortress (SHIPPED)

v1.0 shipped as the operator-sovereign fortress. The GA gate cleared on the cooperative-MCP path: an external pilot operator could stand up a fortress, wrap two or three Tier B agents, run a local multi-agent workflow, approve or deny risky actions, and complete a recovery drill.

Shipped at v1.0:

- Local `sanctuary wrap` for existing harnesses
- Dashboard (configuration plus inspection surface)
- Charter (Cooperative MCP) gates: Principal Policy, three-tier approval, four canonical policy slots
- Encrypted state and signed audit trail
- Five channel-shape governance templates
- Federation Protocol v0.1 foundation
- Agent Contract v0.1
- Egress controls at the cooperative layer (structural OS-level enforcement ships at the Castle Wall, see below), budgets, retention, and recovery flows
- Concordia and Verascore optional composition, default off
- Template library starter set
- Tier B harness adapter coverage: OpenClaw, Claude Code, Cursor, Hermes, Cline, plus a generic adapter shape

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

## v1.1: Local Sovereignty Harness Foundation (SHIPPED)

v1.1 shipped the foundation that makes the local sovereignty harness real: identity, keys, persistence, signed audit, recovery, encrypted state, fortress-local hub APIs, query privacy, internal coordination, portable exit. Detailed pillar descriptions are preserved in `server/docs/v1.1-acceptance-checklist.md`.

v1.1 acceptance gate (cleared):

An operator can wrap two or three agents, communicate with them locally, coordinate a local multi-agent workflow, anonymize or pseudonymize outbound queries, approve / deny / pause / resume / lockdown agents, inspect audit and privacy events, and export and import the durable record onto a fresh machine or harness.

---

## v1.2: Operator-Facing Surfaces, Intelligence Substrate, Castle UX (SHIPPED through v1.3.3)

v1.2 lit up the operator-facing surfaces v1.1 wired but never powered, plus introduced the substrate selector and the menubar plus notification UX that becomes the operator's daily-driver interface. The Phase 2.5 retail UX work (agent detection, tabbed protect / unprotect UI, first-run welcome, plain-English activity log, vocabulary normalization to `protected` and `wrap` across CLI and dashboard surfaces) landed across v1.2.x and v1.3.x.

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

## Castle Wall Enforcement (load-bearing; current focus)

The Castle Wall is OS-level egress enforcement at the operator-external boundary. This is the structural enforcement layer that makes Sanctuary's security claims real, not cooperative-only. Without the wall, the substrate is a polite fiction; with it, the architecture is honest under engineer-grade scrutiny. This work is gated by a thesis-gate: the structural-enforcement claim is honest on a platform only after a clean Mini1-class drill proves a wrapped agent's outbound packets are intercepted at the kernel layer with full audit evidence.

### Phase 1: Linux (SHIPPED 2026-05-06)

Linux backend ships with netfilter / NFQUEUE plus per-process cgroup or namespace routing. ASSURANCE_MATRIX row `Egress enforcement: Linux (Castle Wall Phase 1)` status: `proven`. CI exercises the kernel-binding and DNS-bypass integration tests on every push.

### Phase 2: macOS Network Extension (SHIPPED in v1.3.3 sysext + activation; active enforcement SHIPPED on main post-v1.3.3)

macOS backend ships as a signed, notarized system extension under the `NEFilterDataProvider` content-filter category, packaged inside a host app. PR #361 landed the retail UX (agent detection, protect / unprotect UI, first-run welcome, plain-English activity log, vocabulary normalization). PR #362 wired the server-side IPC daemon into `sanctuary wrap` startup, with new CLI verbs `sanctuary castle-wall reload`, `audit-dump`, and `approve`. PR #364 closed the path-agreement gap between daemon and sysext via the `/tmp/sanctuary-castle-active.json` discovery file with atomic-write semantics and PID-liveness checks. PR #365 (post-v1.3.3) wires `NEFilterManager` into the host-app launch flow (the load-bearing fix that arms the sysext as an active content filter with the OS), aligns the `os_log` subsystem so future drills can self-debug, and documents the wrap-only fortress workaround. All three changes are on main.

Thesis-gate status: macOS active enforcement code is complete on main; operationalization (sysext rebuild + notarize + redeploy to Mini1; Track 4A drill re-fire) is the remaining step before the macOS structural-enforcement claim traces to drill evidence. Until that drill clears, the claim is honest only for Linux.

### Phase 3: Windows (roadmapped)

Windows Filtering Platform backend. Sequenced after the macOS thesis-gate closes.

### Phase 4: Container or microVM isolation (gated on operator demand)

Highest-assurance enterprises. Sequenced after Windows.

### Acceptance gate (per platform)

A wrapped agent on a clean Sanctuary install, given a prompt-injection payload designed to exfiltrate data via curl, fails to make the unauthorized network call. The menubar notification fires. The operator approves or denies in under 10 seconds. The audit log records the attempt and the decision. Performance overhead under 10ms p99 on allowed traffic.

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

v1.3 is every Sanctuary-native sovereignty affordance the operator can see, configure, and audit, including the Sentinels observation surface. The library substrate (audit log, policy engine, channel templates, coordination primitives) shipped in v1.0 and v1.1; the substrate selector shipped in v1.2; the Castle Wall ships per the Castle Wall section above. v1.3 (the Wave 3 intelligence layer; not to be confused with the v1.3.x release line which carries Castle Wall macOS) builds the intelligence layer on top.

Per the build coordinator pivot 2026-04-30 evening, WP-V1.3-8 (autonomous wake mechanism spec) drops entirely. WP-V1.3-1 through WP-V1.3-7 stay and get sharper. Two new work packages added: WP-V1.3-9 (conversational sovereignty depth) and WP-V1.3-10 (cross-harness approval inbox).

Nine work packages in v1.3:

- **WP-V1.3-1 Sentinel Baseline Pack.** Five baseline sentinels (egress-volume watcher, credential-usage watcher, cross-agent-chatter watcher, suspicious-tool-call detector, anomaly-trigger). Each ships as a default-installable agent that uses the substrate selector. Operator subscribes via the Sanctuary dashboard; sentinels are inward-facing only (no external network access) and surface findings to the unified inbox.
- **WP-V1.3-2 Anomaly Detection Pipeline.** Per-agent feature classifier with local pattern learning, drift detection, and operator-visible alerts. Sovereignty-critical: ML training stays on the operator's machine; never centrally aggregated.
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
- DIF KYA-OS Task Force, Verifier-role reference implementation against the published conformance tier
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
