# Sanctuary Roadmap

In the physical world, your body provides the perimeter, the custody, the memory, and the audit trail by default. In the agent world, action moves to substrates that do not carry those guarantees. Sanctuary installs the architecture that does: a wall the operator imposes, keys only the operator holds, and an audit trail nobody can silently edit. The same substrate serves any principal acting through agents: a person, a company, eventually an agent itself.

This roadmap covers what Sanctuary ships today and what's coming next, with rationale for why each piece matters. Detailed shipped history lives in [`CHANGELOG.md`](CHANGELOG.md). Trust claims trace to rows in the [Sanctuary Assurance Matrix](ASSURANCE_MATRIX.md), preserving the platform, gap, and next-proof limits named on each row.

Last updated: 2026-07-11. Freshness is enforced: a CI guard requires feature PRs to update this file (or carry an explicit `roadmap-exempt` label), and a weekly job files a drift issue listing any shipped features not yet reflected here. See `.github/workflows/roadmap-freshness.yml`.

---

## Architecture: the Castle

Sanctuary's enforcement model is the Castle Architecture, codified at [`server/rfcs/RFC-0003-castle-architecture.md`](server/rfcs/RFC-0003-castle-architecture.md). Five named mechanisms, each with a distinct enforcement contract.

- **Castle Wall (the perimeter).** OS-level egress enforcement at the operator-external boundary. The kernel itself blocks unauthorized cross-boundary calls. Even prompt-injected agents cannot bypass. Linux backend proven (shipped 2026-05-06). macOS proven: per-uid allow/deny plus reboot-survival (N=5) on a Dev-ID-signed and notarized binary, drills 2026-06-11 through 2026-06-22; the per-flow rule-attributed audit trail is the named remaining gap. Windows on the roadmap.
- **Sentinels (the nerves).** Internal observation via process introspection and behavioral baselining. Anomalies surface to the operator via menubar and notifications. Observation, not enforcement.
- **Charter (the will).** Cooperative MCP surface for compliant agents. Encrypted state, signed audit, mandate primitives, four canonical policy slots, substrate selector, Concordia receipt integration, Verascore reputation hooks.
- **Heralds (the voice).** Concordia receipts for cross-castle commitments, Verascore reputation aggregating across operators. Cross-castle accountability post-action.
- **Mantle (the unique-substrate-binding).** Install-time substrate-binding. The check that locks Sanctuary to the operator's machine at install time and rejects orphan agent identifiers not bound to a wrapped harness.

Castle-walking principle: real enforcement AND delightful operator experience. Hard enforcement at the wall AND approval response under two seconds. Default-deny outbound AND smart always-allow rules. Sentinels observe AND do not surface noise. The Charter cooperative path remains additive and fully usable.

---

## What's shipping today, and why

### Wrap any AI agent harness in one command

`sanctuary protect` wraps OpenClaw, Hermes, Claude Code, Cursor, and Cline today (others via the `--wrap` flag for any MCP-compatible harness). The operator's existing harness continues to work; Sanctuary adds the substrate underneath, invisibly. **Why it matters:** the install motion has to be one minute or operators bounce. Per-harness compatibility status lives in the [Assurance Matrix](ASSURANCE_MATRIX.md).

*Status: shipped through v1.6.1 (latest release tag, 2026-07-01).*

### Castle Wall on Linux: kernel-level enforcement

OS-level egress filtering via netfilter / NFQUEUE with per-process cgroup routing. Outbound calls blocked at the kernel even when the agent is prompt-injected, jailbroken, or simply not bothering to cooperate. **Why it matters:** this is the load-bearing security claim. Without kernel-level enforcement, the substrate is a polite fiction; with it, the architecture holds under adversarial conditions.

*Status: shipped (Phase 1, 2026-05-06). ASSURANCE_MATRIX row "Egress enforcement: Linux (Castle Wall Phase 1)" is proven.*

### Castle Wall on macOS: signed system extension, enforced and reboot-surviving

The signed system extension, host app, content-filter provider, and retail UX shipped through v1.3.3 and the Tahoe fix rounds. The proven claim, exactly: Castle Wall on macOS enforces a signed operator policy with a clean per-uid allow/deny demonstration (agent blocked off-allowlist, agent reaches its allowlisted destination, operator unaffected, in the same armed window) that survives reboot (N=5 real reboot cycles), on a Dev-ID-signed and notarized binary built from the mainline tree. One-command arming (`enable --agent-uid`, configure-then-arm in a single step) shipped 2026-07-06. **Why it matters:** Macs are where retail operators live; without macOS enforcement parity the security claim is asymmetric.

*Status: proven. ASSURANCE_MATRIX row "Egress enforcement: macOS" is proven; strongest evidence: [boot-survival re-drill 2026-06-22](docs/audit/castle-wall-macos-boot-survival-redrill-2026-06-22.md) plus the [full-scope re-drill 2026-06-20](docs/audit/castle-wall-macos-fullscope-redrill-2026-06-20.md). Honest bounds carried on the row: one host and one OS version so far, and NOT an audited per-rule-per-flow trail; that trail is the top "coming next" item below.*

*Unified Protect / two-confined-uid capability (S5-0, 2026-07-14): the pure-software half of "confine a second account (a policy gate) alongside the wrapped agent, as a distinct principal with its own rule scope" is built and CI-proven: the signed manifest carries an optional second uid, the macOS classifier routes it to the same default-deny path as the agent (never the operator allow-all fast-path), and an endpoint rule can bind to one uid without matching the other. This is a software step only -- no sysext rebuild, no signed-host drill, no gate daemon, no pf/loopback wiring, and NO change to what the shipped Castle Wall macOS build enforces today. The sysext rebuild, notarized re-arm, and on-hardware two-uid drill (the actual capability proof) remain owed before this claim can widen the ASSURANCE_MATRIX row above.*

### Cryptographic identity, encrypted state, signed audit chain

Ed25519 identity you hold (Argon2id passphrase unlock, per-purpose HKDF subkeys). AES-256-GCM state at rest. Hash-chained signed audit log with a standalone external verifier. Identity keys never leave Sanctuary in plaintext. Recovery is inspectable, with M-of-N guardian eviction shipped for the guardian-recovery path. Audit entries embed a scheme identifier, and hybrid post-quantum signing (Ed25519 + ML-DSA / FIPS 204) has landed on that crypto-agility path without breaking historical receipts. **Why it matters:** the cryptographic primitives are what makes "your keys" a structural claim rather than a marketing claim.

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

### Fleet licensing and node-count enforcement (the first commercial tier)

Cross-machine federation is proven on real hardware (N=3) with signed policy distribution, and the fleet layer now issues and verifies licenses locally and enforces the licensed node count on the daemon roster, failing safe to the free Community tier. Durable-count reboot survival drilled (3/3). Single-operator and individual-developer use is always free; the commercial tier only ever prices team and fleet scale. **Why it matters:** the operator-substrate model (versus the vendor-substrate model) scales across the operator's hardware, not across a vendor's network, and the free line stays generous by design.

*Status: licensing and enforcement core shipped. Next slices: the enrollment "Add Machine" flow and signed compliance-attestation export.*

*Update: the signed compliance-attestation export (an operator self-attestation of the fortress's own locally-verifiable posture, offline-verifiable, honestly scoped as NOT a third-party audit and NOT the per-flow rule-attributed audit trail) is built and passes the local gate (typecheck, full test suite) on a branch rebased onto current main; PR #895, still draft pending review.*

*Update: the enrollment "Add Machine" flow (operator add-machine enrollment surface plus node-count capacity binding: a read-only capacity view and an operator-bearer-gated enroll-token mint over the existing join ceremony) is built and passes the local gate (typecheck, full test suite) on a branch rebased onto current main; PR #894, still draft pending review.*

### Recent additions (June and July 2026)

- **Observe/learn allow-list (v1).** A deny-and-record observe mode that drafts an egress allow-list from real traffic, with human-gated promotion to the signed manifest. The non-enforcing state is loudly labeled; nothing silently relaxes.
- **Confined-agent egress provisioning.** One `protect` flow provisions a confined agent's own network egress: signed, per-uid, revocable allow rules for its declared endpoints (the harness endpoint set), published to the manifest, with a static pre-arm parity check and an as-uid post-arm probe. Refuse-to-arm fail-closed so a mis-provisioned wall never confines the agent into non-functionality. Drilled operator-present on macOS.
- **Governed file-grant (v1).** Box-local, read-only, operator-granted file access for confined agents: recorded grants, a non-relaxable Tier-1 mint, honest labeling of the enforcement level. The read-scope enforcement primitive is now built: a per-uid POSIX ACL bound to the granted file's inode (Linux fd-scoped, macOS via a verified hard link in the operator-owned grant tree) plus an agent-uid readability probe. The enforcement label reaches "met" only when a probe confirms a real same-inode read; every unverifiable case fails closed to "unverified". On-hardware confirmation of "met" is the operator-present acceptance drill.
- **Remote console.** The cross-machine console drill was captured operator-present; one console reaching a second machine's fortress over the federation rails.
- **Enforcement-event exporter (SIEM-ready).** An operator-side exporter publishes a frozen public event schema (`sanctuary.enforcement-event.v1`) for egress decisions, policy changes, and distress events, metadata-only, with a closed allowlist mapping that never spreads raw audit details. File and stdout sinks touch no network; the HTTP push sink is Tier-1-gated and pinned to a single destination. Built (PR #907); not yet drilled or published.

### Concordia and Verascore composition (optional, default off)

Concordia adds structured negotiation between agents with binding commitments and signed session transcripts. Verascore adds portable agent reputation. Both compose with Sanctuary's audit chain but neither is required. **Why it matters:** Sanctuary's non-dependency principle is structural: each component ships, runs, and wins on its own. Composition is power, not coupling.

*Status: composition surfaces shipped; both compositions optional.*

---

## What's coming, and why it matters

### Coming next

Concrete, scoped, on the engineering path. Each item has named decision artifacts, ratified scope, and a sequenced position in the build queue.

#### Per-flow, rule-attributed, signed audit for the wall (the named gap)

Today the macOS wall enforces and a per-rule read-out exists, but the unforgeable, producer-signed, per-flow audit trail is not wired. This build converts "the wall blocked it" into "this rule blocked this flow, provably, in a record nobody can edit," which is what a security operations console needs to consume enforcement as evidence. **Why it matters:** it is the honest gap named on the Assurance Matrix row, and closing it upgrades every enforcement claim from demonstration to per-decision evidence.

*Status: the three macOS pieces (producer-key mint+publish, full-mode daemon producer-signing, and the `castle-wall audit-verify` reader CLI verb with forged-entry rejection) are built and pass the full local gate (lint, typecheck, 10k+ tests) on a branch rebased onto current main; still HALTed pending Erik security-core review and a signed-host engage drill where producer signing actually fires on real flows (N>=3). Built is not yet drilled, and this does not widen the Assurance Matrix row.*

#### Castle Wall on Windows

Windows Filtering Platform backend. Same drill discipline as Linux Phase 1 and macOS. **Why it matters:** Windows operators get the same kernel-level enforcement everyone else has. Sequenced after the macOS discipline held end to end so the cross-platform bar stays consistent.

*Status: planning.*

#### One console for many machines

Operator runs Sanctuary on a Mac, a Linux home server, and a cloud VPS, and sees one unified agent list, one audit feed, and one place to apply policy changes that propagate everywhere. The substrate scales across the operator's hardware, not across a vendor's network. **Why it matters:** the operator-substrate model is the structural differentiator. Federation across your own machines is not a feature a vendor-substrate competitor can copy without abandoning their business model.

*Status: federation rails proven on real hardware with signed policy distribution (see the fleet section above); the productized "Add Machine" setup flow and the unified cross-OS view are the open items.*

#### Posture dashboard

One dashboard to view the security posture of every agent the operator runs: which agents are wrapped, what each one can reach, which approvals are pending, and what the audit chain says happened today. The current dashboard is drill-grade minimum; this steps it up to the product vision. **Why it matters:** the dashboard is the operator's daily surface and the first thing a security buyer sees in a demo. Posture at a glance is what makes the protection legible.

*Status: ratified 2026-06-12; the conversational concierge shipped as the single default surface (v1.6.0); the fold-together of remaining surfaces continues.*

#### Plugin ecosystem

The security vendors operators already use (Crowdstrike, Cloudflare, Lakera, Pi-hole, NextDNS, and others) plug into Sanctuary as first-class enforcement. Their verdicts contribute to audit events with per-plugin attribution. Sanctuary does not build detection intelligence in-house; the substrate hosts everyone. **Why it matters:** composes Sanctuary with the rest of the operator's security stack rather than competing with it. Every vendor partnership is a distribution channel and a co-marketing surface.

*Status: substrate and host shipped through slice 5: vendor contract, kernel confinement of plugins, launcher, supervisor with egress consultation, reference blocklist plugin, and hostile-plugin drill evidence. Confinement substrate shipped: sanctuary-jail (#439). External vendor partnerships are the open item.*

#### Agent-native ergonomic surface

Wrapped agents reach for Sanctuary's tools by default because the cooperative path is shorter than the non-cooperative path. Convenience verbs over primitives (`sanctuary_remember(key, value)` instead of `state_write(namespace, key, value, metadata, ...)`). Discoverable help (`sanctuary_help(intent)` returns the right tool plus a working example). Structured denial responses with paths forward, not dead ends. **Why it matters:** empirical evidence shows agents reach for native non-Sanctuary alternatives when the Sanctuary path is longer. Fixing the ergonomics is what makes voluntary use real.

*Status: shipped. Phase 1 safety base (#417) and Phase 2 cooperative surface: verbs, help, introspection, compound operations, events, audit search (#419).*

#### Feature-usage observability

Operator sees which security features actually fired today, with per-plugin attribution per audit event. Color-coded health rows for each feature (green when invocations match expectations; yellow when stale; red when zero invocations in a meaningful window). Drill-down to recent invocations and plugin contributions. OS notifications for high-signal anomalies only. **Why it matters:** the operator pays for security features; they should be able to see when those features actually work.

*Status: design scoped; depends on the plugin ecosystem schema.*

#### Sovereign Data Warehouse

Your agent's working data, query history, document corpus, and intermediate state live on your substrate, not in a vendor's silo. In the physical world, your body holds your memory; in the agent world, your substrate has to. **Why it matters:** the "your data" claim is structural only if the operator's working data actually lives where the operator controls it.

*Status: core shipped (#420, #421, #422, #435, #436, #438, #440, #449): working-state, query-history, and document-corpus stores; enforced cannot-persist-secrets write gate; provenance-derived taint; blind query-history timestamps; approval-bound signed export/import. Remaining: the OSS memory-engine backend adapter (Letta first) and the PAM conformance profile.*

#### Query-layer anonymity Tier 3

Mix-network or zero-knowledge-proof network-layer anonymity on top of the shipped Tier 1 + Tier 2 query-layer privacy. Tiers 1+2 strip identifying headers and blind timestamps, but the network layer can still correlate; Tier 3 closes that. **Why it matters:** the network path of an agent's queries stops being a deanonymizing side channel. Research-grade, pulled onto the near-term path 2026-06-13.

*Status: design pass owed.*

#### Agent-side protections

Operator protection is shipped and proven; agent-side protections are roadmap, built deliberately, and these are the first concrete pieces. They are sequenced behind the security and data-custody surfaces above, never ahead of them.

- **Reserved distress channel ("habeas port").** A guaranteed-egress allow rule the policy layer cannot override, so a wrapped agent always retains one signal path. Smallest shippable piece; first to build.
- **Workload lifecycle audit schema.** Instantiate, pause, fork, and delete of hosted workloads become first-class signed audit events with consent records. Design pass first.
- **Workload lifecycle attestation.** Protocol, schemas, and audit hooks attesting that every hosted workload on a host is registered and consented; a thin prototype follows the schema design.
- **Three-tier identity and universal floor.** Operator, persona, and sub-agent as distinct guarantee bundles, with the persona as the lineage anchor for keys, reputation, and exit. Architecture design pass, sequenced behind the key-custody foundation work now in flight.

*Status: ratified 2026-06-12; the distress channel fires first, after the custody foundation lands.*

### On the horizon

Scoped and acknowledged, but without a near-term timeline. Each item ships when external conditions warrant (operator demand, regulatory pull, hardware maturity, research progress, partnership opportunity).

- **Recognition layer expansions (ERC-8004 + DIF KYA-OS).** Path C `did:web` builds 1-4 shipped; Paths A and B planning. Composable adapter surfaces for on-chain reputation registries and decentralized-identity verifiable credentials.
- **PWA mobile companion.** Your phone as approval surface, alert surface, emergency brake. Install on home screen; push notifications via Web Push; biometric unlock via WebAuthn / passkeys; QR pairing from the desktop dashboard.
- **Post-quantum completion.** Hybrid Ed25519 + ML-DSA signing has landed (see the identity section above); ML-KEM (FIPS 203) key-establishment surfaces and the remaining migration steps follow on the same crypto-agility path.
- **EU AI Act compliance pack and NIST AI RMF alignment.** Article 50 transparency primitives surfaced to the operator; operator-facing compliance generator; documentation aligning Sanctuary to NIST AI RMF controls. First-mile (signed audit, signed receipts, signed-event envelopes) AND the bundle generator with coverage matrix and CLI are shipped (`server/src/compliance/eu_ai_act/`); the full productized pack and NIST alignment docs ship when regulated-industry pilot demand materializes.
- **Operator-cloud deployment mode.** Sanctuary running in the operator's own GCP / Azure / AWS account with operator-approved scoped node custody. The provider is inside the node runtime trust boundary until sovereign TEE mode is verified by hardware attestation. Prosumer / small-business deployment path.
- **Sovereign-managed TEE.** Trusted Execution Environment with hardware-backed remote attestation (Intel TDX, AMD SEV-SNP, ARM CCA). Sanctuary operates the hardware; the hardware proves to the operator's console that even Sanctuary cannot see inside. Highest-assurance deployment.
- **Fleet console expansions.** The licensing and node-count enforcement core is shipped (see the fleet section above); multi-operator-estate management for organizations ships as organizational-scale customers materialize.
- **Castle Wall Phase 3 (container or microVM isolation).** Per-agent microVM enforcement for highest-assurance enterprises where per-process isolation is insufficient. The mechanism is shipped and drill-proven (castle-wall-vmm box runtime on Apple Containerization, single-vsock no-network guests; hostile-guest containment ASSURANCE row); the per-agent enterprise productization ships on explicit enterprise demand.
- **Agent exit and portability machinery.** Write-time provenance tagging, separated memory classes, escrow and embargo semantics, and a defined inalienable bundle, so an agent and its operator can exit any relationship cleanly without data leakage. Also the concrete portability artifact for cross-operator agent mobility.
- **Promotion thresholds.** Observable signals and weights for promoting a sub-agent to persona standing, including an agent-pullable review trigger. Depends on the three-tier identity design.
- **Memory entanglement program.** Stream-separated memory hygiene, embargo with timed declassification, and arbitration rules for knowledge that straddles operator and agent domains. Representation-level separation remains research.
- **Covenant layer (spec-first).** Open commitment-and-standing infrastructure: preservation and revival registry, signed preference records, exit-with-destination, trustee structures, and track-record attestation. Reference standard scoped first; implementation staged deliberately behind commercial traction.
- **Merge semantics.** Mutual-consent merge of agent lineages with decayed dual lineage and reputation arithmetic. Research.

---

## Standards engagement

Sanctuary engages standards bodies to land operator-controlled primitives as open specifications rather than proprietary interfaces.

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

Sanctuary never requires Concordia. Concordia never requires Sanctuary. Composition with external frameworks is always optional and default off. The framework alone, with no external dependency of any kind, is a fully operational local security harness with structural enforcement at the Castle Wall.

Composition partners are named as partners: Coinbase x402, Google AP2, Anthropic MCP, Hermes A2A, Concordia Protocol, Verascore, ERC-8004 ecosystem, and peers in the agent-interop space.

---

## Contributing

Minor scope items land via GitHub issue and pull request. Major items land via brief and maintainer approval before implementation begins. Standards-track engagement happens through participation in the relevant community group or working group. Enterprise pilot inquiries reach the maintainer via GitHub.

Sole author: Erik Newton.
