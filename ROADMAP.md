# Roadmap

Sanctuary Framework ships the rights substrate for operator-sovereign AI agents: Identity, Data, Portability, Attestation, Exit. Open source, self-hostable, composition-friendly.

Your agent. Your machine. Your keys.

This document is a thin milestone view. Shipped history lives in `CHANGELOG.md`. Interface specs live in `server/docs/`. Scope documentation is maintained privately and released to the public repo on version bumps.

Last updated: 2026-04-24.

---

## v1.0 (in final acceptance)

v1.0 is the operator-sovereign fortress. Eleven work packages merged. Package-level status:

- Fortress modes (solo, networked, audited): shipped
- Console (single-fortress and cross-fortress chat): shipped
- Federation Protocol v0.1 (per-node HKDF subkeys, signed events, canonical audit node): shipped; spec at `server/docs/federation-protocol-v0.1-spec.md`
- Agent Contract v0.1 (ten contract points, Agent Card schema, three-tier harness taxonomy): shipped
- Policy engine (four canonical slots, five channel templates, no-LLM-at-gate enforcement): shipped
- Egress controls, budgets, retention: shipped
- Chat transport (libp2p; forward-secret per-epoch encryption): shipped
- Recovery cascade and guardian flow: shipped
- Attestation UX (three-layer persistent-badge surface, degrade-not-destroy on failure): shipped
- Concordia and Verascore optional composition (default off, non-dependency preserved): shipped
- Template library starter set (channel-shape governance archetypes, five): shipped

Remaining v1.0 gate: pilot operator stands up a fortress plus two or three Tier B agents plus a multi-agent workflow plus a recovery drill in under 60 minutes, with no help. Drill rerun queued on the v1.0.0-rc.2 release candidate (published on npm tag `next`).

---

## v1.0.x (patch track)

Point releases close field-verification gaps and platform parity.

- NPM_TOKEN auto-publish guard: shipped
- Linux Secret Service keychain backend: shipped (real-backend CI exercise queued for v1.0.2)
- `sanctuary reset-passphrase` subcommand, nuke-and-rebind path: shipped (recovery-shares and guardian-approval paths stubbed for v1.0.x follow-up)
- Reset-history continuity: signed "recovered-from-reset" audit entry on next `sanctuary wrap` after a reset, hashing the prior chain genesis forward; queued for v1.0.2
- Test-baseline headroom bump: queued for v1.0.2
- Windows Credential Manager keychain backend: queued

---

## v1.1 (product completion track)

This track closes the three user-facing promises that make Sanctuary feel complete rather than merely well-instrumented: privacy at the query boundary, the dashboard as the operator's hub, and exit without platform lock-in. Work may ship in v1.0.x if low-risk, but the track is complete only when the drills below pass.

### Query minimization and privacy filtering

- Local privacy-filter foundation: shipped deterministic local detector/placeholder substitution for common PII and secret spans.
- OpenAI `privacy-filter` adapter surface: shipped JSON span normalization into Sanctuary placeholders; runtime invocation and dashboard configuration remain queued.
- Placeholder vault: shipped encrypted local placeholders for detected spans such as `EMAIL_1`, `PHONE_1`, `SSN_1`, `CARD_1`, `SECRET_1`, `PERSON_1`, `ADDRESS_1`, and `ACCOUNT_1`; project and organization placeholders remain queued.
- Policy-bound rehydration: allow reversible substitution only when the destination policy permits it; otherwise the placeholder remains the exported form.
- Privacy audit surface: record detector class, field path, action, hashes, policy id, and destination category without storing raw sensitive content in the audit log.
- Dashboard privacy panel: show what was filtered, why, and which policy caused the decision.

Gate: privacy drill passes. A pilot sends a query containing PII, secrets, and project-specific identifiers through a wrapped agent; Sanctuary proves the remote-bound payload was filtered, the local mapping remains encrypted, and the audit log contains only safe metadata.

Terminology: until transport unlinkability and traffic-analysis defenses exist, the public promise is "query minimization and PII filtering," not strong anonymization.

### Operator hub completion

- Unified inbox for pending approvals, blocked egress, privacy events, budget warnings, recovery prompts, and agent errors.
- Agent registry across wrapped harnesses, tenants, and federation nodes, with status, model/provider, policy, budget, and last-activity columns.
- Agent controls for start, stop, restart, unwrap, template assignment, and policy changes.
- Live activity feed across all agents and nodes, backed by audit events.
- Policy center for channel templates, per-agent rules, egress allowlists, retention, budgets, and privacy-filter settings.
- Guided import/export/recovery flows surfaced in the dashboard rather than requiring CLI-only operation.

Gate: hub drill passes. A pilot operates two or three wrapped Tier B agents from the dashboard, resolves approvals and blocked egress, changes policy, and completes a recovery/export action without CLI help.

### Portability and exit workflows

- One-click export bundle containing public identity, state, policy, audit receipts, reputation bundle, commitments, and manifest hashes.
- One-click import into a fresh machine or fortress, with conflict handling and verification before activation.
- Re-keying flow for encrypted state so export/import does not require carrying forward the original passphrase forever.
- Third-party verifier CLI for exported audit/reputation bundles.
- Harness migration flow: unwrap from one supported harness and re-wrap another while preserving identity, reputation, policies, and audit continuity.

Gate: exit drill passes. A pilot moves an agent from one harness or machine to another, verifies identity/reputation/audit continuity, and can demonstrate the original platform no longer controls the agent's durable record.

Drill artifact: `server/docs/exit-drill-v0.1.md`.

---

## v1.1 (cryptographic primitives sprint)

Bundled cryptographic primitives upgrade. One coordinated thread, four to eight weeks, spawns after v1.0 pilot acceptance clears.

- Group messaging upgrade with post-compromise security properties (RFC 9420 class of protocol)
- Post-quantum signature and key-exchange primitives, hybrid migration-safe via the `signature_scheme` field shipped in Federation Protocol v0.1
- Underlying elliptic-curve library major-version migration across the crypto stack

Gate: v1.0 MVP acceptance drill clears on a pilot operator with no help.

---

## v1.x (framework extensions)

Composition surfaces and operator variants. Spawn independently once v1.1 stabilizes. Order is not final.

- Fleet operator console for multi-operator estates managed through a single pane (closed-source product variant; the framework alone remains fully operational with no fleet console present)
- Public-pool federation mode (multi-principal data model, patron-scope keys under operator-scope, volunteer-compute composition; v1.0 spec surface preserves the six invariants that make this possible without a breaking change)
- Civic-layer integration for operators served by civic partners (the rights substrate ships at zero cost; the access substrate, compute and device and bandwidth and literacy, is the civic partner's domain; composition, not substitution)
- Agent Vault composition adapter for sovereign signing of external-stack payment rails, delegation mandates, and reputation receipts (composition partners include Coinbase x402, Google AP2, and peers)
- Runtime transport-layer interception: move policy enforcement from config-rewriting to actual MCP proxy interception at the transport layer
- Bootstrap bundle (`@sanctuary-framework/agent-bundle`) for zero-config deployment
- Agent Registry Federation: multi-organization agent discovery with sovereignty-gated trust boundaries
- Named channel templates and authoring flow
- Cross-fortress chat interop bridge
- Native mobile surface (phone-first operator experience with biometric unlock and push notifications)
- Breach-feed aggregation and scoped sub-token rotation
- EU AI Act compliance pack (Annex IV artifacts generator)
- NIST AI RMF alignment documentation

---

## v2 (post-pilot horizon)

Shape locks after first real pilots generate operator-usage data. Current direction:

- Curated rate table and shared-pool arbitration grammar
- Broader ecosystem composition (additional payment and attestation rails; cross-framework receipt portability)
- Hardware-backed secure-element integration and third-party secret-manager import

---

## Standards engagement

Cross-cutting, not tied to a single version. Sanctuary engages standards bodies to land operator-sovereign primitives as open specifications rather than proprietary interfaces.

- W3C Agentic Integrity Verification Specification community group (Agent Contract v0.1 submission pathway; Ed25519 as a first-class signature algorithm)
- W3C DID method alignment (Ed25519 key material mapped cleanly to DIDs)
- IETF trust-scoring alignment (Verascore dimensions in conversation with draft-sharif)
- AAIF Security Working Group participation (sovereignty primitives in the agent-authentication frame)
- MCP Registry governance proposal (Sovereignty Health Report as a governance verification shape for registry-listed MCP servers)
- Reputation Portability Standard (cross-ecosystem reputation verification over Concordia receipts)

---

## Non-dependency and composition posture

Sanctuary never requires Concordia. Concordia never requires Sanctuary. Composition with external frameworks is always optional and default off. The framework alone, with no external dependency of any kind, is a fully operational sovereign fortress.

Composition partners are named as partners: Coinbase x402, Google AP2, Anthropic MCP, Hermes A2A, and peers in the agent-interop space.

---

## Contributing to the roadmap

Scope changes against the current major version happen through dated amendments to the private scope-lock document, not rewrites. Minor items land via GitHub issue and pull request. Major items land via brief and coordinator approval before a build thread spawns. For standards-track engagement, participation in the relevant community group or working group is the fastest route. Enterprise pilot inquiries reach the maintainer via GitHub.

Sole author: Erik Newton.
