# Roadmap

Sanctuary is the operator-owned place to run and govern agents. Operators can attach the harness, model, and deployment shape they choose; Sanctuary supplies the shared sovereignty layer: secure identity, controlled egress, query privacy, signed audit, internal agent coordination, operator approvals, and portable exit.

Your agent. Your machine. Your keys.

This document is the public milestone view. Shipped history lives in `CHANGELOG.md`. Interface specs live in `server/docs/`. Scope documentation is maintained privately and released to the public repo on version bumps.

Last updated: 2026-04-27.

---

## Scope Thesis

v1.1 makes Sanctuary the complete local sovereignty harness.

v1.2 makes the harness available from the operator's phone.

v1.3 makes the operator's data sovereign before the data crosses any boundary.

v1.4 opens sovereign agent-to-agent interaction across operator boundaries.

v1.5+ expands into fleet, payments, compliance, advanced cryptography, operator cloud, and managed TEE modes.

The current sequencing deliberately delays public federation, fleet management, payment rails, compliance packs, and cryptographic migration until the local operator experience is complete and the operator owns the durable record. The local harness is the product center: attach agents, communicate with them, coordinate them, filter what leaves, record what happened, hold that record where the operator owns it, and leave with that record intact.

The published agent-stack standards are anti-lock-in on paper. In practice, lock-in returns at the integration layer, when mandate primitives are minted through one vendor's API, on-chain registry entries are anchored through one vendor's wallet, and identity assertions are issued by one vendor's identity provider. The operator's data is portable in theory and coupled in practice. Sanctuary's L4 control plane is the substrate that turns paper-portability into practical portability. The fortress holds operator identity and durable record on the operator's side of every integration.

---

## Composition Map

The agent stack is now publicly composed across four layers. Sanctuary lives at L4.

```
L4  Operator-sovereign control plane    Sanctuary (you are here)
    Identity, keys, signed receipts, approvals, fortress
    Composes with: ERC-8004, DIF MCP-I, AIVS, A2A

L3  Mandates and commerce                Concordia, Google AP2, A2A extensions
    Mandate primitives, session receipts, commitment binding

L2  Runtime security                     Open-source runtime egress filters
    Per-host policy, request filtering, sandboxing

L1  Payments                             Coinbase x402, Agentic.Market
    Sovereign-signer adapter at v1.5+
```

Composition partners are named where Sanctuary explicitly composes with them. Layers without named partners are referenced as categories.

---

## v1.0 GA: Freeze And Acceptance

v1.0 is the operator-sovereign fortress in final acceptance. The remaining work is validation and blocker removal, not new feature surface.

Shipped foundation:

- Local `sanctuary wrap` for existing harnesses
- Dashboard, policy gates, encrypted state, and signed audit trail
- Five channel-shape governance templates
- Federation Protocol v0.1 foundation
- Agent Contract v0.1
- Egress controls, budgets, retention, and recovery flows
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

- New federation modes
- Mobile app work
- Payment adapters
- Compliance packs
- Post-quantum or RFC 9420 class migration

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
- Operator attestation surface: global, per-agent, and per-action badges over existing fortress attestation primitives, with degrade-not-destroy posture on attestation failure

Gate:

An operator who hits a normal install, keychain, dashboard, or recovery failure gets a local diagnostic that identifies the failing subsystem and the next action without needing maintainer help.

The attestation surface is the operator-facing layer that makes the fortress legible to a non-technical operator. Existing fortress primitives already produce signed attestation events. The v1.0.x scope is the persistent badge surface, the failure-mode catalog, and the operator-visible degraded states. Design-research panel work runs in parallel and may shift specifics.

---

## v1.1: Local Sovereignty Harness Foundation

v1.1 ships the foundation that makes the local sovereignty harness real: identity, keys, persistence, signed audit, recovery, encrypted state, fortress-local hub APIs, and a v1.1 dashboard surface that renders the wrapped harnesses an operator runs. The library substrate for channel-shape template binding, signed coordination handoffs, and unified approval inbox all ships in v1.1; the operator-facing wiring for those substrates ships in v1.2 (see WP-V1.2-2, WP-V1.2-3, WP-V1.2-4 below).

v1.1 acceptance: an operator can wrap two or three harnesses against one fortress, see them in the v1.1 dashboard Agents view, run a Tier 1 action through the legacy ApprovalGate channel with signed audit entry, and recover the fortress from a passphrase backup if principal loss simulates. This is the foundation. Operator-facing template binding, multi-agent workflow handoffs, and a unified approval inbox arrive in v1.2.

### 1. Query Privacy And Anonymized Query Mode

This is the first v1.1 pillar because it protects the boundary most users understand: what the agent sends to remote models, tools, relays, and counterparties.

Capabilities:

- Local sensitive-span detection for PII, secrets, credentials, account identifiers, client names, project names, file paths, and sensitive domain terms
- Stable local placeholders such as `PERSON_1`, `CLIENT_1`, `PROJECT_1`, `SECRET_1`, and `ACCOUNT_1`
- Encrypted local placeholder vault
- Recursive, bounded filtering of nested payloads
- Identity-bound privacy policies
- Policy-bound rehydration of model responses when permitted
- Safe audit metadata: detector class, field path, action, hashes, policy id, and destination category without raw sensitive content
- Dashboard privacy panel showing what was filtered, why, and which policy caused the decision
- First enforcement path on actual remote-bound traffic, not only standalone filtering tools

Gate:

A pilot sends a query containing PII, secrets, project identifiers, and client identifiers through a wrapped agent. Sanctuary proves the remote-bound payload was filtered, the local mapping remains encrypted, the response is rehydrated only when policy permits, and the audit log contains only safe metadata.

Terminology:

The technical docs should use "query minimization" and "pseudonymization" where precision matters. "Anonymized Query Mode" is acceptable as product language only if the limits are documented. Full anonymization would require unlinkability, metadata protection, traffic-analysis defenses, and provider-side guarantees.

### 2. Operator-Agent Communication And Control

The operator must be able to talk to agents and govern them from the local control surface.

Capabilities:

- Dashboard chat or command surface for wrapped agents
- Unified local inbox for pending approvals, blocked egress, privacy events, budget warnings, recovery prompts, and agent errors
- Agent registry across local wrapped harnesses with status, model/provider, policy, budget, and last activity
- Agent controls for pause, resume, restart, unwrap, template assignment, policy change, and lockdown
- Live local activity feed backed by audit events
- Policy center for channel templates, per-agent rules, egress allowlists, retention, budgets, and privacy-filter settings

Gate:

A pilot can operate two or three wrapped agents from the dashboard, talk to them, resolve approvals and blocked egress, change policy, trigger lockdown, and understand what each agent is doing without CLI help.

### 3. Internal Agent Coordination

Sanctuary should provide the internal plumbing for agent-to-agent coordination before opening the boundary to public federation.

Capabilities:

- Local agent registry
- Signed local agent-to-agent messages
- Handoff records with sender, recipient, task scope, policy context, and audit references
- Shared local workflow state where policy permits
- Internal-only coordination channels with egress controls at the outer boundary
- Audit trail for handoffs, approvals, denials, and completed coordination steps

Gate:

A pilot runs a local multi-agent workflow where one agent delegates to another, the handoff is signed and audited, policy controls what context crosses between agents, and no public federation is required.

### 4. Portability And Exit

Exit is a core sovereignty promise, not an afterthought.

Capabilities:

- One-click export bundle containing public identity, encrypted state, policy, audit receipts, reputation bundle, commitments, placeholder-vault metadata, and manifest hashes
- One-click import into a fresh machine or fortress with conflict handling and verification before activation
- Re-keying flow for encrypted state so import does not require carrying the original passphrase forward forever
- Third-party verifier CLI for exported audit and reputation bundles
- Harness migration flow: unwrap from one supported harness and re-wrap another while preserving identity, reputation, policies, privacy vault continuity, and audit continuity
- Dashboard-guided exit drill that preserves the same Tier 1 approval gates as the CLI path

Gate:

A pilot moves an agent from one harness or machine to another, verifies identity, reputation, privacy-vault metadata, policy, and audit continuity, and can demonstrate that the original platform no longer controls the agent's durable record.

Drill artifact: `server/docs/exit-drill-v0.1.md`.

### v1.1 Acceptance Gate

v1.1 passes only when an operator can:

- Wrap two or three agents
- Communicate with them locally
- Coordinate a local multi-agent workflow
- Anonymize or pseudonymize outbound queries
- Approve, deny, pause, resume, and lockdown agents
- Inspect audit and privacy events
- Export and import the durable record onto a fresh machine or harness

---

## Efficient v1.1 Build Sequence For Codex

Build v1.1 contract-first, then parallelize implementation behind stable interfaces. This reduces merge conflicts, avoids repeated full-suite runs, and keeps agents from editing the same hot files.

### Step 0: Scope Lock And Contracts

Owner: coordinator Codex instance.

Outputs:

- v1.1 acceptance checklist in `server/docs/`
- Minimal shared interfaces for privacy events, hub events, local agent records, handoff records, and exit-bundle manifests
- Tool registration checklist requiring policy tier, outbound network behavior, audit shape, and privacy impact
- Targeted test plan by workstream

Do not parallelize this step. Parallel work should start after the contracts land.

### Step 1: Query Privacy Core

Outputs:

- Recursive bounded detector and filter
- Placeholder vault
- Policy-bound rehydration
- Safe privacy audit events
- Unit tests with nested objects, long payloads, secret-like values, client/project placeholders, and denial cases

Keep this independent from dashboard UI. Emit events through the shared contract.

### Step 2: Remote-Bound Enforcement Path

Outputs:

- First enforced path for remote-bound model/tool payloads
- Integration test proving raw sensitive spans do not leave through that path
- Failure mode: if privacy policy cannot be loaded or filtering fails, outbound traffic fails closed unless the operator explicitly overrides

This is the schedule risk. Keep the first enforcement path narrow and real instead of trying to generalize every transport at once.

### Step 3: Operator Hub Primitives

Outputs:

- Local inbox API
- Local agent registry API
- Activity feed backed by audit events
- Agent controls: pause, resume, restart, unwrap, lockdown
- Policy and budget summaries

Build the API before polishing the dashboard.

### Step 4: Internal Coordination

Outputs:

- Local signed message and handoff record types
- Agent-to-agent handoff API
- Context transfer through policy gates
- Audit entries for handoffs and coordination outcomes
- Integration test for a two-agent local workflow

Do not include public discovery or cross-operator federation in this step.

### Step 5: Exit Bundle And Verifier

Outputs:

- `SANCTUARY_EXIT_BUNDLE_V1` manifest
- Export command
- Import command with verify-before-activate
- Re-keying flow
- Standalone verifier CLI
- Harness migration drill test

Keep the dashboard wizard out until the CLI and manifest are stable.

### Step 6: Dashboard Flows

Outputs:

- Privacy panel
- Unified inbox
- Local agent registry
- Activity feed
- Exit wizard
- Operator-agent chat or command surface

The dashboard should consume the APIs from Steps 1-5, not define their data model.

### Step 7: Acceptance Drills And Release Hardening

Outputs:

- Privacy drill
- Local coordination drill
- Hub drill
- Exit drill
- Full test run and baseline update
- README and roadmap alignment

Run targeted tests during workstream development. Run the full suite at integration checkpoints and before release.

---

## Parallel Build Map

Use one coordinator and multiple implementation agents with disjoint write scopes. Claude Code can take any worker slice below. The coordinator should own shared contracts, tool registration policy, final integration, and release notes.

| Workstream | Can Start After | Suggested Write Scope | Parallel With | Deliverable |
|---|---|---|---|---|
| Privacy core | Step 0 | `server/src/privacy/**`, privacy tests | Hub, exit, coordination | Detector, placeholder vault, rehydration, audit events |
| Remote-bound enforcement | Step 0 plus privacy event contract | egress/gateway/wrap enforcement modules, integration tests | Hub, exit | Proof that filtered payload is what leaves |
| Operator hub API | Step 0 | dashboard API modules, local registry modules, hub tests | Privacy, exit, coordination | Inbox, registry, controls, activity feed |
| Internal coordination | Step 0 | local coordination/message modules, handoff tests | Privacy, exit, hub | Signed local handoffs and audited local workflow |
| Exit bundle | Step 0 | exit/export/import/verifier modules, CLI tests | Privacy, hub, coordination | Manifest, export/import, re-keying, verifier CLI |
| Dashboard UI | Hub API stable, privacy event shape stable | dashboard frontend files only | Final CLI/verifier work | Privacy panel, inbox, registry, exit wizard |
| Harness compatibility | Anytime after v1.0 freeze | fixture configs, integration docs, smoke tests | All feature work | Wrap matrix for supported harnesses |
| Docs and drills | Contracts stable, then again at end | `server/docs/**`, README excerpts | All feature work | Acceptance drills and operator-facing docs |

Parallelization rules:

- Do not let multiple agents edit shared contracts after Step 0 without coordinator approval.
- Do not let dashboard work invent API shapes.
- Do not let privacy enforcement and privacy detector agents both own the same filter internals.
- Keep Concordia, Verascore, payments, and public federation out of v1.1 workstreams.
- Prefer targeted Vitest files during development; run the full `npm test` gate only at integration checkpoints and before merge.

---

## v1.2: Operator-Facing Surfaces + Intelligence Substrate

The v1.1 acceptance audit (`Review/Sanctuary/V1.1.x_Operator_Path_Audit_Pass_B_2026-04-27.md`), the v1.2 scope brief (`Review/Sanctuary/V1.2_Scope_Brief_2026-04-27.md`), and the Intelligence Layer Drift Audit (`Review/Sanctuary/Intelligence_Layer_Drift_Audit_and_Substrate_Resolution_2026-04-29.md`) define v1.2 as the milestone that lights up the operator-facing surfaces v1.1 wired but never powered.

Mobile companion moves to v1.4 as a PWA (deferred per coordinator decision 2026-04-29 so the desktop ships feature-complete first). Sovereign Data Warehouse moves to v1.4 (pulled back per Erik directive 2026-04-29 evening so v1.3 can deliver advanced Sanctuary intelligence affordances first). Unified inbox bridge and coordination handoff visualization move to v1.3 (alongside sentinels and anomaly detection, where they pair more naturally).

Five WPs in v1.2:

- **WP-V1.2-2 Channel-Template Binding Flow** (operator picks a channel template per wrapped agent in the Policy Center; Tier 1 `policy_change` approval fires; activity feed records the binding). Library reconciliation rides along: the v1.1 internal template IDs are retired in favor of the six design-canonical templates surfaced in the Policy Center.
- **WP-V1.2-4a+b Operator Chat (concierge + direct-agent)** — concierge surface (Dashboard nav default; operator talks to Sanctuary in plain English about agent activity, gets summaries, fires actions); direct-agent surface (Agents view, click an agent, talk directly to it; Tier 1 gated). Both consume the substrate selector from WP-V1.2-5 for the LLM call.
- **WP-V1.2-5 Intelligence Substrate Selector** (the architecture, not a substrate). Operator picks per surface among local model (Ollama with bundled Gemma 2 2B + Phi-4 Mini), Venice.ai (privacy-respecting hosted; named composition partner per Erik directive 2026-04-29), operator-frontier with Privacy Filter Tier 2 redaction, or hybrid per-surface routing. Selector ships with operator-facing tradeoff transparency UI; per-operator marketing claims become defensible only via this surface.
- **Telegram bridge stopgap** (separate brief at `Review/Sanctuary/Telegram_Mobile_Channel_Stopgap_Brief_2026-04-29.md`; queued behind v1.2-2 + v1.2-4 + v1.2-5; ships any free Codex window during the v1.2 cycle). Ports approval-needed events to a Telegram bot so the operator gets phone notifications + remote approval before the PWA mobile companion lands in v1.4.

Recommended sequencing: WP-V1.2-2 first (well-bounded; library reconciliation alongside picker UI), then WP-V1.2-5 (substrate selector unblocks chat), then WP-V1.2-4a+b in parallel as soon as the substrate selector's local-model integration is stable. Coordination handoff visualization (formerly WP-V1.2-4c) defers to v1.3.

v1.2 acceptance gate:

An operator wraps two harnesses, picks an intelligence substrate (any of the four options, with the tradeoff visible at selection), uses the concierge to ask "what did agent X do today" and gets a real summary, clicks an agent in Agents view to open direct chat, types a message, gets a response with a Tier 1 approval gate honored. The operator binds a channel template to a wrapped agent through the Policy Center and sees the binding reflected in the Per-agent rules table and the activity feed. The substrate selector's transparency UI shows the per-surface routing the operator chose. Privacy Filter Tier 2 works (regex Tier 1 always; Tier 2 routed per substrate selection).

---

## v1.3: Advanced Sanctuary Intelligence

v1.3 is every Sanctuary-native sovereignty affordance the operator can see, configure, and audit. The library substrate (audit log, policy engine, channel templates, coordination primitives) shipped in v1.0 and v1.1; the substrate selector ships in v1.2. v1.3 builds the intelligence layer on top.

Per the Intelligence Layer Drift Audit (2026-04-29), this milestone closes the drift identified in twelve drift-catalog rows by sequencing the locked-2026-04-20 sentinel, anomaly, English-gate, honeypot, and auto-trigger affordances into a coherent operator-facing intelligence release.

Seven WPs in v1.3:

- **WP-V1.3-1 Sentinel Baseline Pack** — five baseline sentinels (egress-volume watcher, credential-usage watcher, cross-agent-chatter watcher, suspicious-tool-call detector, anomaly-trigger). Each ships as a default-installable agent that uses the substrate selector. Operator subscribes via the Sanctuary dashboard; sentinels are inward-facing only (no external network access) and surface findings to the unified inbox.
- **WP-V1.3-2 Anomaly Detection Pipeline** — per-agent feature classifier with local pattern learning, drift detection, and operator-visible alerts. Sovereignty-critical: ML training stays on the operator's machine; never centrally aggregated.
- **WP-V1.3-3 Coordination Handoff Visualization** (formerly v1.2-4c) — read-only Coordination view rendering handoff log, per-handoff context-transfer breakdown (transferred vs withheld), and workflow state.
- **WP-V1.3-4 Unified Approval Inbox Bridge** (formerly v1.2-3) — bridges legacy ApprovalGate and v1.1 hub inbox with unified provenance. Operator sees approvals, blocked egress, privacy events, budget warnings, recovery prompts, agent errors, and sentinel findings in one stream.
- **WP-V1.3-5 Honeypot Authoring** (pulled forward from v1.4 per Erik directive 2026-04-29 evening) — operator writes a honeypot in plain English; LLM compiles to a runtime trap; integrates with the sentinel layer. Uses the substrate selector.
- **WP-V1.3-6 English-Authored Gates** (pulled forward from v1.4 per Erik directive 2026-04-29 evening) — operator writes a custom policy in plain English; LLM compiles to a structured rule and synthesizes the operator-facing explanation. Uses the substrate selector. Templates remain the v1.2 default for the six canonical channel templates; English-authored gates layer on top for custom policies.
- **WP-V1.3-7 Auto-Trigger Ladder + Threshold Calibration** (pulled forward from v1.4 per Erik directive 2026-04-29 evening) — operator-configurable thresholds for sentinels and anomaly detection. Calibration UI lets the operator move rules from operator-approved to auto-action incrementally as confidence builds.

v1.3 acceptance gate:

The operator subscribes a sentinel; the sentinel observes agent activity and reports a finding via the unified inbox. Anomaly detection identifies an intentional drift (operator triggers a deviant tool call) and surfaces an alert. The Coordination view shows a multi-agent handoff history with full provenance. The operator authors a honeypot in plain English and watches it fire on trigger. The operator authors a custom policy gate in plain English and sees the LLM-compiled rule plus operator-facing explanation. The auto-trigger ladder honors the operator's threshold configuration.

---

## v1.4: Reach — Mobile, Federation, Sovereign Data Warehouse

v1.4 extends the fortress beyond the local single-operator deployment. Mobile reaches your phone. Public federation reaches other operators. Sovereign Data Warehouse reaches data sources beyond the agent loop. All three are about the fortress reaching outward while the operator's sovereignty stays intact.

SDW pushed back from v1.3 per Erik directive 2026-04-29 evening so v1.3 can deliver the advanced Sanctuary intelligence affordances first. Mobile pushed back from v1.2 per coordinator decision 2026-04-29 so the desktop ships feature-complete first.

Three WPs in v1.4:

- **WP-V1.4-1 PWA Mobile Companion** (formerly WP-V1.2-1) — phone as operator key, inbox, approval surface, alert surface, emergency brake. PWA implementation: install on home screen, push notifications via Web Push API, biometric unlock via WebAuthn / passkeys, QR pairing from the desktop dashboard. Defers native iOS/Android indefinitely; PWA on iOS 16.4+ and current Android covers the operator-control scope. Telegram bridge from v1.2 stops being load-bearing once the PWA ships but stays available as an alternate notification channel.
- **WP-V1.4-2 Public Federation** — cross-operator discovery, signed inter-fortress messaging, public or semi-public agent pools, reputation exchange, anonymized wants and requests, abuse and rate controls, policy-enforced disclosure envelopes for anything crossing the boundary. Per the Federation Protocol v0.1 spec already shipped (`Review/Sanctuary/Federation_Protocol_V0.1_Spec_2026-04-21.md`).
- **WP-V1.4-3 Sovereign Data Warehouse** (pushed from v1.3 per Erik directive 2026-04-29 evening). The agent's durable record belongs to the operator. SDW builds the substrate so the operator's working data, query history, document corpus, and intermediate state live in a place the operator controls, not in a vendor's silo. Composes with the v1.2 substrate selector: the operator's local model handles SDW queries; Venice or frontier-with-filter available for capability-heavy SDW analysis.

  Three sub-deliverables:

  - **Ingestion Adapter Template** — pluggable adapter interface for pulling vendor-side state (chat history, document corpus, project state, query logs) into the operator's fortress. Per-source provenance envelope. Operator-controlled scheduling, retention, deletion. Audit entries on every ingestion event.
  - **Sovereign Data Lake Schema And Indexing Primitive** — operator-sovereign storage layout for ingested and locally generated data. Cross-source query routing preserves provenance. Vendor-state and operator-state separated at the schema layer. Slice-scope policy DSL extension so policies bind to data slices, not just actions. Local index suitable for working sizes a single operator generates. (Schema design is a real research project, not a port.)
  - **Continuous-Sync Orchestration** — workflow primitive for long-running sync jobs across vendor sources. Composes with the v1.1 internal coordination layer for multi-step sync. Failure modes degrade without losing provenance. Operator-visible status and intervention surface.

v1.4 acceptance gate:

An operator pairs a phone, receives a generic approval notification, opens the PWA, reviews details fetched from the local fortress, approves with biometric unlock, and can revoke the phone from the desktop dashboard. Two independent operators complete a signed cross-fortress interaction where each side controls what identity, query content, reputation, commitments, and audit receipts leave the fortress. A pilot ingests a meaningful slice of one vendor's data into the fortress, queries it locally with provenance preserved, applies a slice-scope policy, runs a multi-step sync, and demonstrates the data continues to be available after the vendor relationship ends.

---

### Regulatory Posture

The full EU AI Act compliance pack ships in v1.5+. The architecture-independent first-mile is already in the fortress: signed audit trail, signed receipts, and signed-event envelopes provide a defensible record-keeping substrate for Article 12 obligations. Operators preparing for the August 2 enforcement date can compose those primitives with an external compliance toolchain in the meantime. The full compliance pack adds Article 50 transparency primitives and the operator-facing compliance generator.

---

## v1.5+ Expansion

These tracks start only after v1.1 has completed the local harness and v1.2, v1.3, and v1.4 have validated mobile, sovereign data, and public federation.

- Fleet operator console for multi-operator estates
- Agent Vault composition adapter for sovereign signing of external-stack payment rails, delegation mandates, and reputation receipts
- Runtime transport-layer interception generalized beyond the first privacy enforcement path
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

- W3C Agentic Integrity Verification Specification community group
- W3C DID method alignment
- IETF trust-scoring alignment
- AAIF Security Working Group participation
- MCP Registry governance proposal
- Reputation Portability Standard
- DIF MCP-I Task Force, Verifier-role reference implementation against the L2 conformance tier
- DIF Delegatable Attenuated Authorization Task Force, observer posture aligned to Concordia Protocol composition

---

## Non-Dependency And Composition Posture

Sanctuary never requires Concordia. Concordia never requires Sanctuary. Composition with external frameworks is always optional and default off. The framework alone, with no external dependency of any kind, is a fully operational local sovereignty harness.

Composition partners are named as partners: Coinbase x402, Google AP2, Anthropic MCP, Hermes A2A, and peers in the agent-interop space.

---

## Contributing To The Roadmap

Scope changes against the current major version happen through dated amendments to the private scope-lock document, not rewrites. Minor items land via GitHub issue and pull request. Major items land via brief and coordinator approval before a build thread spawns. For standards-track engagement, participation in the relevant community group or working group is the fastest route. Enterprise pilot inquiries reach the maintainer via GitHub.

Sole author: Erik Newton.
