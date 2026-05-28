# Sanctuary Roadmap

Sovereignty used to be embodied. In the physical world, your body provided the perimeter, the custody, the memory, and the audit trail by default. In the agent world, action moves to substrates that don't carry those guarantees. Sanctuary installs the architecture that does. The same substrate serves any sovereign acting through agents: a person, a company, eventually an agent itself.

This roadmap covers what Sanctuary ships today and what's coming next, with rationale for why each piece matters. Detailed shipped history lives in [`CHANGELOG.md`](CHANGELOG.md). Trust claims trace to rows in the [Sanctuary Assurance Matrix](ASSURANCE_MATRIX.md), preserving the platform, gap, and next-proof limits named on each row.

Last updated: 2026-05-27.

---

## Architecture: the Castle

Sanctuary's enforcement model is the Castle Architecture, codified at [`server/rfcs/RFC-0003-castle-architecture.md`](server/rfcs/RFC-0003-castle-architecture.md). Five named mechanisms, each with a distinct enforcement contract.

- **Castle Wall (the perimeter).** OS-level egress enforcement at the operator-external boundary. The kernel itself blocks unauthorized cross-boundary calls. Even prompt-injected agents cannot bypass. Linux backend proven (shipped 2026-05-06); macOS active enforcement code on main awaiting end-to-end Mini1 drill PASS; Windows on the roadmap.
- **Sentinels (the nerves).** Internal observation via process introspection and behavioral baselining. Anomalies surface to the operator via menubar and notifications. Observation, not enforcement.
- **Charter (the will).** Cooperative MCP surface for compliant agents. Encrypted state, signed audit, mandate primitives, four canonical policy slots, substrate selector, Concordia receipt integration, Verascore reputation hooks.
- **Heralds (the voice).** Concordia receipts for cross-castle commitments, Verascore reputation aggregating across operators. Cross-castle accountability post-action.
- **Mantle (the unique-substrate-binding).** Install-time substrate-binding. The check that locks Sanctuary to the operator's machine at install time and rejects orphan agent identifiers not bound to a wrapped harness.

Castle-walking principle: real enforcement AND delightful operator experience. Hard enforcement at the wall AND approval response under two seconds. Default-deny outbound AND smart always-allow rules. Sentinels observe AND do not surface noise. The Charter cooperative path remains additive and fully usable.

---

## What's shipping today, and why

### Wrap any AI agent harness in one command

`sanctuary protect` wraps OpenClaw, Hermes, Claude Code, Cursor, and Cline today (others via the `--wrap` flag for any MCP-compatible harness). The operator's existing harness continues to work; Sanctuary adds the substrate underneath, invisibly. **Why it matters:** the install motion has to be one minute or operators bounce. Per-harness compatibility status lives in the [Assurance Matrix](ASSURANCE_MATRIX.md).

*Status: shipped through v1.3.3.*

### Castle Wall on Linux: kernel-level enforcement

OS-level egress filtering via netfilter / NFQUEUE with per-process cgroup routing. Outbound calls blocked at the kernel even when the agent is prompt-injected, jailbroken, or simply not bothering to cooperate. **Why it matters:** this is the load-bearing security claim. Without kernel-level enforcement, the substrate is a polite fiction; with it, the architecture holds under adversarial conditions.

*Status: shipped (Phase 1, 2026-05-06). ASSURANCE_MATRIX row "Egress enforcement: Linux (Castle Wall Phase 1)" is proven.*

### Cryptographic identity, encrypted state, signed audit chain

Ed25519 identity you hold (Argon2id passphrase unlock, per-purpose HKDF subkeys). AES-256-GCM state at rest. Hash-chained signed audit log with a standalone external verifier. Identity keys never leave Sanctuary in plaintext. **Why it matters:** the cryptographic primitives are what makes "your keys" a structural claim rather than a marketing claim. Audit chain integrity is tamper-evident; legacy entries auto-migrate to schema-2 envelopes on first verified read.

*Status: shipped. ASSURANCE_MATRIX rows "State encryption," "State envelope integrity / default verify-on-read," "Tamper-evident audit chain," "Critical audit durability (appendCritical)," "did:key encoding," and "Identity signing authority" are all proven.*

### Three-tier Principal Policy gates with human-in-the-loop approval

Risky operations (key rotation, state export, identity deletion, reputation import, secure delete) require explicit approval through an out-of-band channel (stderr prompt, dashboard SSE, or signed webhook). Behavioral anomalies trigger approval. Routine operations auto-allow with audit logging. **Why it matters:** structural human-in-the-loop for the operations that actually matter; fail-closed semantics mean the gate denies rather than auto-approves when the approval channel is unreachable.

*Status: shipped. ASSURANCE_MATRIX row "Approval gating (Tier 1 / Tier 2 / Tier 3 policy)" is proven.*

### Query-layer privacy

Outbound queries strip operator-identifying headers (client-IP, fingerprint, correlation-ID, User-Agent, cookies, persistent session tokens) by default. Operator-opt-in PII rewrite available per channel: deterministic pseudonymous substitution before the query leaves the substrate selector. **Why it matters:** the agent can still be identified-by-asking unless the query layer itself is anonymized. No comparator we surveyed ships this at strength.

*Status: Tiers 1 + 2 shipped. ASSURANCE_MATRIX row "Query anonymity (selective disclosure)" is proven.*

### Portable identity, state export, recovery flows

Operator can export their full identity bundle (keys, state, reputation, audit chain) and import on a fresh machine or fresh harness. Recovery key for lost-passphrase scenarios. Tier-1 approval required for export and import. **Why it matters:** the "exit" guarantee is structural, not contractual. Nothing the operator builds up in Sanctuary is locked to the platform; everything is portable, encrypted, and operator-controlled.

*Status: shipped. ASSURANCE_MATRIX row "Export / exit bundle" is proven.*

### Local multi-agent coordination and Sovereignty Dashboard

Wrap many agents on one machine. Coordinate workflows across them with handoff visualization. See them all in one dashboard at `http://localhost:3501`. Menubar status app with click-to-approve. Plain-English activity log. Cross-harness approval inbox aggregating pending approvals from concurrent wrapped agents. **Why it matters:** operators run more than one agent; the substrate has to scale beyond a single wrap without forcing the operator into many control surfaces.

*Status: shipped.*

### Concordia and Verascore composition (optional, default off)

Concordia adds structured negotiation between agents with binding commitments and signed session transcripts. Verascore adds portable agent reputation. Both compose with Sanctuary's audit chain but neither is required. **Why it matters:** Sanctuary's non-dependency principle is structural: each component ships, runs, and wins on its own. Composition is power, not coupling.

*Status: composition surfaces shipped; both compositions optional.*

### Castle Wall on macOS: sysext + IPC integration shipped; active enforcement on main

v1.3.3 shipped the signed system extension `ai.sanctuaryprotocol.macos.castle-wall`, the host app, the Phase 2.5 retail UX (agent detection, protect / unprotect UI, first-run welcome, plain-English activity log, vocabulary normalization), the Track 4A IPC integration wiring the daemon into `sanctuary protect` startup, and the Track 4A.2 sysext socket-path discovery. PR #365 (post-v1.3.3) wired `NEFilterManager` into the host-app launch flow, aligned the `os_log` subsystem so future drills can self-debug, and documented the wrap-only fortress workaround. **Why it matters:** Macs are where retail operators live; without macOS enforcement parity the security claim is asymmetric.

*Status: code complete on main; end-to-end Mini1 drill PASS pending. ASSURANCE_MATRIX row "Egress enforcement: macOS" currently partial; closes when the drill PASSes.*

---

## What's coming, and why it matters

### Coming next

Concrete, scoped, on the engineering path. Each item has named decision artifacts, ratified scope, and a sequenced position in the build queue.

#### Castle Wall enforces on macOS

End-to-end Mini1 drill closes the macOS thesis-gate. A wrapped agent's outbound packets are intercepted at the kernel layer via `NEFilterDataProvider`, routed through Castle Wall policy with full audit evidence, and the operator-facing notification fires. **Why it matters:** closes the cross-platform security claim. Retail surfaces can honestly say "Castle Wall enforces on Linux and macOS" once this PASSes.

*Status: in flight. PR #365 landed the load-bearing code; sysext rebuild + Mini1 drill re-fire remaining.*

#### Castle Wall on Windows

Windows Filtering Platform backend. Same drill discipline as Linux Phase 1 and macOS. **Why it matters:** Windows operators get the same kernel-level enforcement everyone else has. Sequenced after the macOS thesis-gate closes so the cross-platform discipline holds before opening a third platform.

*Status: planning.*

#### One console for many machines

Operator runs Sanctuary on a Mac, a Linux home server, and a cloud VPS, and sees one unified agent list, one audit feed, and one place to apply policy changes that propagate everywhere. The substrate scales across the operator's hardware, not across a vendor's network. **Why it matters:** the operator-substrate model (versus the vendor-substrate model) is the structural differentiator. Federation across your own machines is not a feature a vendor-substrate competitor can copy without abandoning their business model.

*Status: Phase A scoping complete (auth model + Federation Security RFC v7 ratified). Implementation gated on Castle Wall macOS drill PASS.*

#### Plugin ecosystem

The security vendors operators already use (Crowdstrike, Cloudflare, Lakera, Pi-hole, NextDNS, and others) plug into Sanctuary as first-class enforcement. Their verdicts contribute to audit events with per-plugin attribution. Sanctuary does not build detection intelligence in-house; the substrate hosts everyone. **Why it matters:** composes Sanctuary with the rest of the operator's security stack rather than competing with it. Every vendor partnership is a distribution channel and a co-marketing surface.

*Status: Plugin Security RFC in scope; gated on the cooperative-feature audit so the contract reflects which features are toggleable vs always-enforced.*

#### Agent-native ergonomic surface

Wrapped agents reach for Sanctuary's tools by default because the cooperative path is shorter than the non-cooperative path. Convenience verbs over primitives (`sanctuary_remember(key, value)` instead of `state_write(namespace, key, value, metadata, ...)`). Discoverable help (`sanctuary_help(intent)` returns the right tool plus a working example). Structured denial responses with paths forward, not dead ends. **Why it matters:** empirical evidence shows agents reach for native non-Sanctuary alternatives when the Sanctuary path is longer. Fixing the ergonomics is what makes voluntary use real.

*Status: design scoped; implementation queued.*

#### Feature-usage observability

Operator sees which security features actually fired today, with per-plugin attribution per audit event. Color-coded health rows for each feature (green when invocations match expectations; yellow when stale; red when zero invocations in a meaningful window). Drill-down to recent invocations and plugin contributions. OS notifications for high-signal anomalies only. **Why it matters:** the operator pays for security features; they should be able to see when those features actually work.

*Status: design scoped; depends on the plugin ecosystem schema.*

#### Sovereign Data Warehouse

Your agent's working data, query history, document corpus, and intermediate state live on your substrate, not in a vendor's silo. The data-custody operationalization of the embodiment framing: in the physical world, your body holds your memory; in the agent world, your substrate has to. **Why it matters:** the "your data" claim is structural only if the operator's working data actually lives where the operator controls it.

*Status: scoped; not yet built.*

### On the horizon

Scoped and acknowledged, but without a near-term timeline. Each item ships when external conditions warrant (operator demand, regulatory pull, hardware maturity, research progress, partnership opportunity).

- **Recognition layer expansions (ERC-8004 + DIF KYA-OS).** Path C `did:web` builds 1-4 shipped; Paths A and B planning. Composable adapter surfaces for on-chain reputation registries and decentralized-identity verifiable credentials.
- **PWA mobile companion.** Your phone as approval surface, alert surface, emergency brake. Install on home screen; push notifications via Web Push; biometric unlock via WebAuthn / passkeys; QR pairing from the desktop dashboard.
- **Query-layer anonymity Tier 3.** Mix-network or zero-knowledge-proof network-layer anonymity on top of the existing Tier 1 + Tier 2 query-layer privacy. Closes the last sovereignty principle (opacity at the query layer) at strength. Research-grade.
- **Post-quantum cryptography migration.** Hybrid Ed25519 + ML-DSA / FIPS 204 signing for the audit chain. Audit entries already embed a scheme identifier so the migration lands without breaking historical receipts.
- **EU AI Act compliance pack and NIST AI RMF alignment.** Article 50 transparency primitives surfaced to the operator; operator-facing compliance generator; documentation aligning Sanctuary to NIST AI RMF controls. Architecture-independent first-mile (signed audit, signed receipts, signed-event envelopes) shipped; full pack ships when regulated-industry pilot demand materializes.
- **Operator-cloud deployment mode.** Sanctuary running in the operator's own GCP / Azure / AWS account. Same code, same keys, on rented hardware the operator controls. Prosumer / small-business deployment path.
- **Sovereign-managed TEE.** Trusted Execution Environment with hardware-backed remote attestation (Intel TDX, AMD SEV-SNP, ARM CCA). Sanctuary operates the hardware; the hardware proves to the operator's console that even Sanctuary cannot see inside. Highest-assurance deployment.
- **Fleet operator console.** Multi-operator-estate management for organizations running Sanctuary across many operators. Ships when organizational-scale customers materialize.
- **Castle Wall Phase 3 (container or microVM isolation).** Per-agent microVM enforcement for highest-assurance enterprises where per-process isolation is insufficient. Ships on explicit enterprise demand.

---

## Standards engagement

Sanctuary engages standards bodies to land operator-sovereign primitives as open specifications rather than proprietary interfaces.

- W3C Agentic Integrity Verification Specification (AIVS) community group, Erik chairs. First deliverable: Concordia receipt schema submission within 90 days.
- W3C DID method alignment.
- IETF trust-scoring alignment.
- AAIF Security Working Group participation.
- MCP Registry governance proposal.
- Reputation Portability Standard.
- DIF KYA-OS Task Force, Verifier-role reference implementation against the published conformance tier.
- DIF Delegatable Attenuated Authorization Task Force, observer posture aligned to Concordia Protocol composition.
- ERC-8004 ecosystem alignment.

---

## Non-dependency and composition posture

Sanctuary never requires Concordia. Concordia never requires Sanctuary. Composition with external frameworks is always optional and default off. The framework alone, with no external dependency of any kind, is a fully operational local sovereignty harness with structural enforcement at the Castle Wall.

Composition partners are named as partners: Coinbase x402, Google AP2, Anthropic MCP, Hermes A2A, Concordia Protocol, Verascore, ERC-8004 ecosystem, and peers in the agent-interop space.

---

## Contributing

Minor scope items land via GitHub issue and pull request. Major items land via brief and maintainer approval before implementation begins. Standards-track engagement happens through participation in the relevant community group or working group. Enterprise pilot inquiries reach the maintainer via GitHub.

Sole author: Erik Newton.
