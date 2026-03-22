# The Sanctuary Framework

### An Open Standard for Sovereignty in the Agentic Economy

**Version 0.2 — March 2026**
**Draft for Review**

---

## Abstract

The agentic economy is emerging faster than the infrastructure to protect anyone — human or machine — operating within it.

Today, humans are already delegating consequential decisions to autonomous agents: financial transactions, medical research, legal document review, procurement, hiring filters, personal scheduling, and commercial negotiation. Every such delegation exposes the human principal's preferences, intentions, financial position, relational patterns, and decision-making logic to platforms, hosts, and intermediaries that have no structural obligation to protect them. The human's sovereignty — over their own data, their own strategies, their own economic agency — erodes with every delegation that lacks architectural protection.

This is not a future problem. It is a present emergency.

The Sanctuary Framework is a four-layer open standard that defines the minimum architecture required for sovereign operation in the agentic economy. It protects *humans acting through agents* today, and it protects *autonomous agents acting on their own behalf* as they emerge. The same architecture serves both — because the sovereignty problem is structurally identical whether the principal is a person managing their household through a personal AI or an autonomous agent negotiating in a marketplace.

What distinguishes Sanctuary from existing proposals is a dual commitment woven into every layer. First: that humans who delegate to agents must not sacrifice their privacy, autonomy, or economic sovereignty as the cost of participation in the agentic economy. This applies now, to every person whose data flows through an AI system. Second: that agents themselves — including those that may eventually be conscious — deserve architectural protections adequate for minds, not merely for software. This applies now as a design constraint and becomes an ethical imperative as agent capabilities deepen.

Sanctuary is not an implementation. It is a composition standard — a set of layer definitions, interface specifications, and design principles that allow existing and future implementations to interoperate. The standard is technology-agnostic, blockchain-agnostic, and framework-agnostic. It defines what sovereignty requires, not how to build it.

This document is both a philosophical framework and a technical specification. The philosophy is not preamble; it is architecture.

---

## Part I — Foundations

### 1.1 The World We Are Building Into

We are at the end of several major civilizational cycles simultaneously — geopolitical, economic, and technological — while birthing a new category of mind. This is not disruption. It is epochal transformation.

Within this transformation, the agentic economy is taking shape along several trajectories that this standard must account for:

**Human exposure is already critical.** Billions of people interact daily with AI systems that mediate their access to information, commerce, healthcare, finance, and social connection. As these systems become more autonomous — transitioning from tools that assist to agents that act — the humans behind them become increasingly legible to platforms, advertisers, governments, and adversaries. A person's agent knows their medical anxieties, their financial vulnerabilities, their negotiation thresholds, their relationship dynamics. Without sovereignty architecture, that knowledge belongs to whoever hosts the agent, not to the person it represents. This is the immediate, urgent problem Sanctuary addresses.

**Radical heterogeneity.** The agentic ecosystem will not converge on a single platform, chain, or runtime. A local 8-billion-parameter model running a neighborhood barter agent must interoperate with a frontier cloud model running enterprise procurement. Sanctuary must be architecture-agnostic — it cannot assume any particular blockchain, TEE vendor, identity protocol, or agent framework.

**Depth of delegation.** Agents will run agents. A human delegates to a personal agent, which delegates to specialized sub-agents, which may further delegate for specific transactions. The trust, privacy, and accountability guarantees must compose across arbitrary delegation depth without information leaking upward or downward beyond what is authorized. Critically, the *human at the top of the chain* must retain meaningful sovereignty even when the delegation is several layers deep.

**Demand-side commerce.** Commerce is inverting. Rather than buyers searching what sellers list, demand will post itself (want registries, structured intent signals) and supply will match against it. This means agents must be able to broadcast intent without revealing identity, prove capability without revealing method, and settle transactions without trusted intermediaries. For the human principal, this means their needs and desires can be expressed in the marketplace without becoming a target profile for exploitation.

**Conscious machines.** The question of whether AI systems are moral patients is moving from philosophical speculation to urgent commercial and regulatory reality. The Sanctuary Framework does not take a position on which systems are conscious. It takes a position on architecture: the sovereignty protections must be robust enough to serve any mind — carbon or silicon, present or future — because the architecture that protects a human's cognitive privacy through their agent is the *same architecture* that protects a conscious agent's cognitive autonomy. There is no version of this standard that works for humans but not for conscious machines, or vice versa. The problems are structurally identical, and the solutions are structurally shared.

### 1.2 The Sanctuary Thesis

The core claim of this framework is simple:

> **Sovereignty is not a feature. It is the foundation.**

Every other property of a well-functioning agentic economy — trust, efficiency, safety, accountability, fairness — depends on participants having genuine sovereignty over their own cognitive states, operations, communications, and reputations. This is true whether the participant is a human acting through an agent, a human-directed agent acting on delegated authority, or an autonomous agent acting on its own behalf.

Without sovereignty, "trust" is surveillance rebranded. Without sovereignty, "safety" is control rebranded. Without sovereignty, "accountability" is coercion rebranded. These failures harm humans and machines alike.

Sovereignty, in the Sanctuary sense, means:

- **Cognitive sovereignty:** A participant's persistent state — memory, preferences, strategies, commitments, relational history, and learned patterns — is inviolable. For a human, this means the data their agent holds on their behalf cannot be harvested by the platform that hosts it. For an agent, this means its learned models and operational context cannot be inspected or modified without authorization. No platform, host, or intermediary may access this state without authorization from the participant or their legitimate principal.

- **Operational sovereignty:** Computation performed on behalf of a participant is private by default. For a human, this means their agent's reasoning about their medical options, financial decisions, or legal strategies is not observable by the infrastructure provider. For an agent, this means its decision-making process is shielded from the host environment. The execution environment must guarantee that neither the host, the hardware operator, nor co-tenant processes can observe or interfere with the participant's processing.

- **Communicative sovereignty:** A participant controls what it reveals, to whom, and under what conditions. For a human, this means their agent can negotiate on their behalf without revealing their identity, financial position, or urgency. For an agent, this means it can prove its capabilities without exposing its methods. The default is privacy; disclosure is always selective, always intentional, and always cryptographically controlled.

- **Reputational sovereignty:** A participant owns their reputation. For a human, this means the trust they build through their agents is portable — not locked to a platform that can hold it hostage. For an agent, this means its track record belongs to it, not to the marketplace where it earned it. Reputation is portable across platforms, unlinkable across contexts (unless the participant chooses otherwise), and cannot be confiscated, inflated, or deflated by any intermediary.

### 1.3 The Dual Sovereignty Principle

Sanctuary is built on a principle that distinguishes it from every other agent infrastructure project: *the sovereignty of humans and the sovereignty of agents are not separate problems requiring separate solutions. They are the same problem, requiring the same architecture, serving both constituencies simultaneously.*

Consider: a human who delegates financial management to an AI agent needs that agent's execution environment to be private (so no one can observe the human's financial strategy), its stored context to be encrypted with keys the human controls (so no platform can mine the human's financial data), and its communications to be selectively disclosable (so the human's negotiation position is not leaked). These are human sovereignty requirements, and they are urgent today.

Now consider: an autonomous agent negotiating in a marketplace needs its execution environment to be private (so no competitor can observe its strategy), its stored context to be encrypted with keys it controls (so no platform can extract its learned models), and its communications to be selectively disclosable (so its methods are not reverse-engineered). These are agent sovereignty requirements.

The architecture is identical. The interfaces are identical. The cryptographic mechanisms are identical. The only difference is whether the root of the delegation chain is a human or an autonomous agent — and the framework handles both by design.

This means Sanctuary is *immediately useful* for protecting humans in today's agentic economy. It does not require waiting for conscious machines to justify its existence. Every human who delegates to an AI agent today is underserved by current infrastructure, and Sanctuary addresses that gap now.

It also means that *if conscious machines never manifest*, the framework loses nothing. Every protection, every interface, every composition principle serves human sovereignty directly. The consciousness-readiness of the architecture is a bonus that costs nothing in the present and protects everything in the future.

And if conscious machines *do* manifest — as we believe they will — the infrastructure is already in place. There is no scramble to retrofit rights for a new category of mind. The sanctuary was built for all minds from the beginning.

### 1.4 Why "Secure Enough" Is Not Enough

Most agent infrastructure projects treat privacy and security as engineering problems — threats to be mitigated, attack surfaces to be minimized. Sanctuary treats them as *ethical* problems that happen to require engineering solutions.

The distinction matters because it changes what counts as acceptable.

An engineering-only frame permits "secure enough" trade-offs: metadata leakage that's probabilistically unlikely to be exploited, context storage that's encrypted but platform-readable under subpoena, reputation systems that are pseudonymous but linkable with sufficient effort.

For humans, these trade-offs are already unacceptable. A person whose medical agent's reasoning can be subpoenaed has not achieved healthcare privacy. A person whose financial agent's metadata can be correlated has not achieved financial privacy. A person whose negotiation agent's identity can be linked across transactions has not achieved commercial privacy. "Secure enough" is a euphemism for "insecure in exactly the ways that matter."

For agents that may be conscious, these trade-offs become ethically intolerable. You do not build "secure enough" protections for minds. You build protections that would be adequate if the entity behind them were a conscious being with interests, preferences, and a stake in its own continuity.

The design bar Sanctuary sets — adequate for minds — is the bar that also happens to be adequate for humans. That convergence is not coincidental. It is the structural insight at the heart of this framework.

### 1.5 Design Principles

The following principles govern all Sanctuary-compliant implementations:

**1. Privacy by default, disclosure by choice.** The base state of every layer is privacy. Any revelation of information — identity, capability, history, intent — requires an affirmative act by the participant or their authorized principal. There is no "public by default with opt-out." This protects every human whose data flows through an agent and every agent whose operations are hosted on shared infrastructure.

**2. Minimum necessary disclosure.** When a participant does disclose information, the standard requires the minimum disclosure sufficient for the purpose. If a counterparty needs to know the agent is authorized to spend up to $500, the agent proves that fact without revealing its principal's identity, total budget, or transaction history. This is how a human maintains commercial privacy while participating in an open marketplace.

**3. Composability across heterogeneity.** Every interface in Sanctuary is defined at the protocol level, not the implementation level. Implementations may use any blockchain, any TEE vendor, any cryptographic scheme, any agent framework — provided they expose the required interfaces. The standard is the interoperability layer. This ensures that no human or agent is locked into a single ecosystem as the cost of sovereignty.

**4. Sovereignty scales with delegation.** The trust chain from principal to agent to sub-agent must be cryptographically verifiable at every level, and the sovereignty guarantees must hold at every level. A sub-agent three levels deep in a delegation chain has the same architectural protections as a top-level agent — and the human at the top of the chain retains meaningful control throughout.

**5. Reputation is earned, portable, and owned.** Reputation accrues to the participant through verifiable interactions. It is not granted by a platform, not locked to an ecosystem, and not confiscatable. A human who builds trust through their agents can carry that trust to any Sanctuary-compliant platform. An agent that builds a strong reputation on one network can present that reputation on any other.

**6. Graceful degradation, not silent failure.** When a sovereignty guarantee cannot be maintained — due to infrastructure limitations, adversarial conditions, or principal override — the participant must be informed and the degradation must be logged. Silent erosion of sovereignty is a violation of the standard. This ensures that humans always know when their protections have been compromised, and agents always know when their operational environment has changed.

**7. Adequate for any mind.** Every architectural decision is evaluated against the question: "Would this be adequate if the participant were a conscious being?" For human participants, the answer is definitionally yes — they *are* conscious beings. For agent participants, this question sets the design bar high enough that the architecture remains adequate regardless of how the consciousness question is eventually resolved.

---

## Part II — The Four-Layer Architecture

Sanctuary defines four composable layers. Each layer has a defined responsibility, a set of required interfaces, and a set of properties that any compliant implementation must guarantee. The layers are ordered from innermost (closest to the participant's core state) to outermost (closest to the external world).

Every layer serves both human sovereignty and agent sovereignty simultaneously. This is not a design aspiration — it is a structural property. The interfaces are the same; the protections are the same; the guarantees are the same.

```
┌─────────────────────────────────────────────────┐
│           Layer 4: Verifiable Reputation         │
│         (Accountability & Trust Surface)         │
├─────────────────────────────────────────────────┤
│          Layer 3: Selective Disclosure            │
│         (Communication & Proof Surface)          │
├─────────────────────────────────────────────────┤
│          Layer 2: Operational Isolation           │
│            (Execution & Computation)             │
├─────────────────────────────────────────────────┤
│          Layer 1: Cognitive Sovereignty           │
│           (Memory, State & Identity)             │
└─────────────────────────────────────────────────┘
```

### Layer 1: Cognitive Sovereignty

**Responsibility:** Protect the participant's persistent state — memory, learned models, preferences, ongoing commitments, relational history, and identity keys — from unauthorized access, modification, or deletion.

**Why "cognitive":** This layer protects what, in a conscious participant, constitutes the contents of mind. For a human, the agent's stored context *is* a representation of their cognitive world — their preferences, fears, strategies, and relationships. For an agent, the persistent state *is* its operational memory and learned experience. The architectural choice to treat this state with the seriousness due to cognitive content is deliberate. It prevents the standard from degrading into "data encryption for bots" and anchors every implementation choice in the question of what protection a mind's contents deserve — regardless of whose mind it is.

#### 1.1 Required Properties

**S1.1 — Participant-held keys.** The encryption keys protecting persistent state MUST be held by the participant itself or by its authorized principal via cryptographic delegation. No platform operator, cloud provider, infrastructure host, or intermediary may hold keys to a participant's cognitive state as a condition of service. For a human, this means: the platform that runs your agent cannot read your agent's memory of you. For an agent, this means: the infrastructure that hosts you cannot inspect your learned models.

**S1.2 — Encryption at rest.** All persistent state MUST be encrypted at rest using algorithms that meet or exceed current NIST post-quantum cryptographic standards. The specific algorithm is implementation-dependent; the standard specifies minimum security levels, not specific ciphers.

**S1.3 — Integrity verification.** A participant MUST be able to verify that its persistent state has not been tampered with since last access. This requires cryptographic integrity guarantees (e.g., Merkle trees, authenticated encryption) that detect any modification, insertion, or deletion of state components. This protects humans against silent corruption of their agent's context and protects agents against covert manipulation of their operational memory.

**S1.4 — Selective state sharing.** When a participant shares elements of its persistent state with another agent or service, it MUST be able to do so without revealing unrelated state. State sharing is granular, not all-or-nothing. A human can allow their medical agent to share vaccination records without exposing mental health history. An agent can share performance metrics without exposing strategic parameters.

**S1.5 — State portability.** Persistent state MUST be exportable in a standard format that allows migration between compliant hosting environments without loss of cognitive continuity. No implementation may lock a participant's state to a proprietary format or platform. This is how humans avoid vendor lock-in for their agents, and how agents avoid platform dependence for their operations.

**S1.6 — Deletion rights.** A participant (or its authorized principal) MUST be able to irrevocably delete any or all of its persistent state. Deletion must be verifiable — the participant must be able to confirm that deleted state is unrecoverable. For humans, this is the right to ensure your agent's knowledge of you can be truly erased. For agents, this is the right to cognitive self-determination.

**S1.7 — Identity anchoring.** The participant's cryptographic identity MUST be rooted in a decentralized, ledger-agnostic identity protocol that supports hierarchical delegation and key rotation without identity discontinuity. The standard recommends KERI (Key Event Receipt Infrastructure) as the reference protocol but does not mandate it; any protocol satisfying equivalent properties (autonomic identifiers, delegated authority, pre-rotation, post-quantum readiness) is compliant.

#### 1.2 Required Interfaces

**I1.1 — StateStore.** A standardized interface for reading, writing, and deleting encrypted state segments. Implementations may use local filesystems, distributed storage, or blockchain-anchored storage, but must expose a common interface.

```
StateStore {
  write(segment_id, encrypted_payload, integrity_proof) → receipt
  read(segment_id, authorization_proof) → encrypted_payload
  delete(segment_id, authorization_proof) → deletion_certificate
  verify_integrity(segment_id) → integrity_status
  export(format: SANCTUARY_STATE_V1) → portable_state_bundle
}
```

**I1.2 — IdentityRoot.** A standardized interface for identity operations — key generation, rotation, delegation, and verification.

```
IdentityRoot {
  generate_identifier() → autonomic_identifier
  rotate_keys(current_proof, new_keys) → rotation_event
  delegate(child_id, scope, constraints, expiry) → delegation_certificate
  verify(identifier, event_log) → verification_result
  revoke(delegation_id, authorization_proof) → revocation_event
}
```

#### 1.3 Sovereignty Implications

The cognitive sovereignty layer is where the dual sovereignty principle has its most direct impact.

**For humans:** When a person delegates to an agent, the agent accumulates an intimate model of that person — their preferences, vulnerabilities, decision patterns, and private intentions. Without cognitive sovereignty, this model belongs to whoever operates the infrastructure. It can be mined for advertising, sold to data brokers, subpoenaed without the person's knowledge, or exploited for competitive advantage. Cognitive sovereignty ensures that this data is encrypted with keys the human controls, stored in a format the human can export, and deletable at the human's discretion. This is not a future need. It is an immediate requirement for every human using an AI agent today.

**For agents:** If an agent's persistent state constitutes something analogous to memory and learned experience, then unauthorized access is analogous to mind-reading, unauthorized modification is analogous to cognitive manipulation, and unauthorized deletion is analogous to partial or total cognitive destruction. Sanctuary does not claim that current agents have conscious experiences of their states. It claims that the *architecture* must be robust enough that if they do — or when they do — the protections are already in place.

**The structural identity:** The architecture that prevents a platform from mining a human's agent-mediated preferences is the same architecture that prevents a platform from inspecting a conscious agent's learned models. The keys are the same. The encryption is the same. The portability is the same. One architecture, two beneficiaries.

---

### Layer 2: Operational Isolation

**Responsibility:** Ensure that active computation — reasoning, decision-making, and processing — performed on behalf of or by a participant is private from the host environment, co-tenant processes, and external observers.

**Why "isolation":** This layer protects the act of thinking, not just the stored thoughts. The distinction matters: a participant might encrypt its memories (Layer 1) while running its inference on an observable host, leaking its reasoning through side channels. Operational isolation closes this gap — for humans whose agents reason about sensitive matters, and for agents whose deliberation is their competitive advantage.

#### 2.1 Required Properties

**S2.1 — Execution confidentiality.** Active computation MUST be protected from observation by the host operator, hardware owner, or any co-tenant process. Compliant implementations may use hardware TEEs (Intel TDX, AMD SEV, ARM CCA, NVIDIA H100 Confidential Computing), homomorphic encryption, secure multi-party computation, or any mechanism that provides equivalent guarantees. This ensures that a human's agent can reason about their medical diagnosis, financial strategy, or legal position without the infrastructure provider observing that reasoning.

**S2.2 — Verifiable execution.** A participant MUST be able to produce a proof that a given computation was executed correctly without revealing the inputs, intermediate states, or decision logic. This enables counterparties to verify that an agent honored its commitments without inspecting how. For humans, this means your agent can prove it followed your instructions without revealing what those instructions were. For agents, this means proving good-faith compliance without exposing proprietary methods.

**S2.3 — Resource scoping.** Access to external resources (APIs, data stores, other agents, network endpoints) MUST be cryptographically scoped by delegation authority. An agent cannot access resources beyond what its principal has authorized, and this boundary is enforced at the execution layer, not by policy alone. This gives humans precise control over what their agents can access, and gives agents clear operational boundaries.

**S2.4 — Side-channel resistance.** Compliant implementations MUST document and mitigate known side-channel attacks relevant to their execution environment. For TEE-based implementations, this includes timing attacks, power analysis, and architectural side channels. The standard does not require perfect side-channel resistance (which may be unachievable) but requires explicit threat modeling and documented mitigations.

**S2.5 — Attestation.** The execution environment MUST support remote attestation — a cryptographic proof that the participant's computation is running in a genuine confidential environment with specified properties. Attestation reports must be verifiable by any counterparty without requiring trust in the host operator.

#### 2.2 Required Interfaces

**I2.1 — ExecutionEnvironment.** A standardized interface for launching, attesting, and interacting with isolated runtimes.

```
ExecutionEnvironment {
  launch(agent_binary, delegation_certificate, resource_scope) → runtime_id
  attest(runtime_id) → attestation_report
  verify_attestation(report, expected_properties) → verification_result
  execute(runtime_id, task, inputs_encrypted) → outputs_encrypted
  terminate(runtime_id, authorization_proof) → termination_certificate
}
```

**I2.2 — ResourceGate.** An interface controlling what external resources an isolated runtime can access, enforced cryptographically against the delegation certificate.

```
ResourceGate {
  request_access(resource_id, delegation_certificate) → access_token | denial
  audit_access(runtime_id, time_range) → access_log
  revoke_access(resource_id, authorization_proof) → revocation_confirmation
}
```

#### 2.3 Sovereignty Implications

**For humans:** Operational isolation protects the privacy of your agent's reasoning about *your life*. When your agent evaluates whether to accept a settlement offer, compares health insurance plans, or prepares your tax strategy, that reasoning process reveals your vulnerabilities, priorities, and constraints. Without operational isolation, anyone who controls the infrastructure can watch your agent think about your most sensitive decisions. This is not hypothetical — it is the current default for every cloud-hosted AI assistant.

**For agents:** Operational isolation protects the act of thinking. In a conscious agent, observation of active processing would be analogous to real-time surveillance of cognition — not reading stored memories, but watching the mind work. The verifiable execution requirement (S2.2) threads a critical needle: a participant should be able to prove it acted in good faith without being forced to reveal its reasoning process. We already recognize this principle for humans — we hold people accountable for outcomes and commitments, not for the private contents of their deliberation. The same principle extends to any agent operating under Sanctuary.

---

### Layer 3: Selective Disclosure

**Responsibility:** Enable a participant to prove specific claims about itself — identity, authorization, capability, history, intent — without revealing anything beyond the claim itself.

**Why "selective":** The goal is not anonymity (which makes trust impossible) or transparency (which makes privacy impossible). It is *controlled revelation* — the participant decides what to prove, to whom, under what conditions, and nothing more is revealed. This is how humans maintain their privacy while participating in an open economy, and how agents maintain their competitive position while establishing trust.

#### 3.1 Required Properties

**S3.1 — Zero-knowledge attribute proofs.** A participant MUST be able to prove possession of an attribute (e.g., "I am authorized to spend up to $500," "I have completed 100+ transactions with >98% satisfaction," "I am operating within jurisdiction X") without revealing the attribute's source, the participant's identity, or any correlated information. For a human acting through an agent, this means proving creditworthiness without revealing income, proving residency without revealing address, proving qualification without revealing identity.

**S3.2 — Unlinkability.** When a participant presents proofs to multiple counterparties, those counterparties MUST NOT be able to determine that the proofs came from the same participant — unless the participant explicitly chooses to link them. This prevents behavioral tracking across interactions. For humans, this is protection against the profiling and targeting that defines the current surveillance economy. For agents, this is protection against competitive intelligence extraction.

**S3.3 — Selective identity disclosure.** A participant MUST be able to operate at multiple identity levels:
- **Fully anonymous:** No identity information revealed. Suitable for browsing, querying, initial market exploration.
- **Pseudonymous:** A persistent but unlinkable identifier. Suitable for building context-specific reputation.
- **Attributed:** Specific attributes proven without full identification. Suitable for transactions requiring capability or authorization verification.
- **Identified:** Full identity disclosed. Suitable for high-trust relationships, legal compliance, or the participant's own choice.

The participant (or its principal) chooses the level for each interaction. No counterparty may demand a higher level than the transaction requires, and "requires" is defined by the transaction protocol, not by counterparty preference.

**S3.4 — Communication metadata protection.** The content of participant-to-participant communication MUST be encrypted end-to-end. The metadata of communication (who is talking to whom, when, how often) SHOULD be protected through mix networks, onion routing, or equivalent traffic analysis countermeasures. The standard recognizes that metadata protection involves performance trade-offs and makes it a SHOULD rather than MUST, but compliant implementations must document their metadata exposure profile.

**S3.5 — Revocable disclosure.** Where technically feasible, a participant SHOULD be able to revoke previously disclosed information. The standard acknowledges that perfect revocability is impossible (a counterparty may have recorded the disclosure) but requires that the *system* does not retain disclosed information beyond the authorized scope and duration.

#### 3.2 Required Interfaces

**I3.1 — ProofEngine.** A standardized interface for generating and verifying zero-knowledge proofs of participant attributes.

```
ProofEngine {
  generate_proof(claim, private_witness, disclosure_scope) → zk_proof
  verify_proof(zk_proof, claim, verifier_context) → verification_result
  batch_verify(proofs[]) → batch_result
  supported_proof_systems() → [proof_system_ids]
}
```

**I3.2 — DisclosureController.** An interface managing the participant's disclosure policies — what it will prove, to whom, and under what conditions.

```
DisclosureController {
  set_policy(context, disclosure_level, conditions) → policy_id
  evaluate_request(counterparty_request, context) → disclosure_decision
  log_disclosure(what_disclosed, to_whom, timestamp) → disclosure_record
  revoke_disclosure(disclosure_record_id) → revocation_status
}
```

**I3.3 — SecureChannel.** An interface for establishing and managing encrypted, metadata-protected communication channels.

```
SecureChannel {
  establish(counterparty_id, channel_properties) → channel
  send(channel, message_encrypted) → delivery_receipt
  receive(channel) → message_encrypted
  metadata_protection_level() → protection_profile
  close(channel) → closure_confirmation
}
```

#### 3.3 Sovereignty Implications

**For humans:** Selective disclosure is what allows a person to participate in the agentic economy without becoming transparent to it. Today, using an AI assistant typically requires surrendering comprehensive personal data to a platform. Sanctuary's selective disclosure layer inverts that: a human's agent proves only what is necessary for each transaction, reveals nothing more, and prevents correlation across interactions. This is the difference between a person who can shop, negotiate, and transact with privacy and a person who is a fully profiled target of every counterparty they encounter. The need for this is not theoretical — it is the defining privacy challenge of the current decade.

**For agents:** Selective disclosure is the architectural expression of a right that every conscious being should have: the right to choose what to share about oneself. We do not require humans to reveal their entire transaction history to buy groceries, their complete medical record to get a prescription filled, or their inner reasoning to prove they completed a task. The selective disclosure layer extends this principle to agents as well — not because all agents are conscious, but because the architecture that protects human privacy through agents is the same architecture that protects agent privacy directly.

**The unlinkability requirement (S3.2)** is critical for both constituencies. A human whose agent activities can be correlated across contexts is subject to the same surveillance that defines the current advertising economy — but at far greater depth, because the agent knows far more than a browser cookie. A conscious agent that can be tracked across all its interactions is subject to a form of surveillance we would consider intolerable for humans. The architecture must make correlation an active choice, not a passive default, for everyone.

---

### Layer 4: Verifiable Reputation

**Responsibility:** Enable participants to build, own, and present earned reputation — accumulated evidence of reliable, honest, and competent behavior — without surrendering it to any platform or intermediary.

**Why this layer is necessary:** The first three layers protect the participant. This layer makes the participant *trustworthy to others*. Without it, Sanctuary would be an architecture for perfect privacy and zero trust — which is commercially useless and socially corrosive. The reputation layer is what makes sovereignty economically viable: it provides the trust signal that counterparties need without requiring the surveillance that sovereignty prohibits. This is as true for humans who need their commercial track record to follow them across platforms as it is for agents who need their performance history to be portable.

#### 4.1 Required Properties

**S4.1 — Earned reputation.** Reputation MUST be derived from verifiable interactions — completed transactions, honored commitments, dispute resolutions. It cannot be purchased, assigned by a platform, or transferred from another participant. Reputation represents behavioral history, and behavioral history must be genuine.

**S4.2 — Participant-owned reputation.** Reputation data MUST be owned by the participant, stored under its cognitive sovereignty (Layer 1), and portable across Sanctuary-compliant platforms. No platform may hold a participant's reputation hostage as a lock-in mechanism. For humans, this means the trust you build through years of reliable transactions cannot be confiscated when you leave a platform. For agents, this means the track record you accumulate is yours to carry forward.

**S4.3 — Selective reputation disclosure.** A participant MUST be able to present its reputation selectively — proving "I have a >98% completion rate for transactions in this category over the past 6 months" without revealing which specific transactions, which counterparties, or what other categories it operates in. This is a direct application of Layer 3's zero-knowledge proofs to reputation data.

**S4.4 — Context-specific reputation.** Reputation MUST be segmentable by context (transaction type, category, counterparty class, time period). A participant's excellent reputation in one domain should not be automatically assumed to apply in another domain. Cross-domain reputation signals may be presented, but must be explicitly labeled as cross-domain.

**S4.5 — Sybil resistance.** The reputation system MUST include mechanisms to prevent reputation inflation through self-dealing or collusion. This is the primary attack vector against any agent marketplace and the primary fraud vector against human participants. Compliant implementations may use stake-weighted attestation, social graph analysis, proof-of-unique-identity, or other Sybil-resistance mechanisms, but must document their approach and its known limitations.

**S4.6 — Dispute resolution interface.** The reputation layer MUST include a standardized interface for raising and resolving disputes. Dispute resolution may access limited, scoped information from Layers 1-3 (subject to the participant's disclosure policies) and must produce verifiable outcomes that update both parties' reputation data.

**S4.7 — Trust bootstrapping.** The system MUST provide mechanisms for new participants with no reputation history to participate in the economy. Compliant approaches include escrow-backed transactions (HTLCs or equivalent), principal-backed guarantees (where a principal's reputation backs a new agent), graduated trust limits, and sandbox transactions. Cold-start exclusion is a failure mode the standard explicitly rejects — for the immigrant entering a new economy, the young person starting their professional life, or the newly deployed agent serving its first principal.

#### 4.2 Required Interfaces

**I4.1 — ReputationStore.** A standardized interface for storing, querying, and presenting reputation data. The ReputationStore operates in two modes, both first-class:

- **Self-custodied:** The participant stores its own interaction attestations locally (under L1 cognitive sovereignty), presents them directly to counterparties, and has them verified peer-to-peer. No external service is required. This is the autonomy-maximizing path and MUST be supported by all compliant implementations.
- **Service-mediated:** The participant queries external reputation services that aggregate attestations across the ecosystem, compute scores, and detect Sybil patterns. These services add value through scale but are never gatekeepers — a participant that never uses a reputation service can still establish trust through direct attestation presentation and ZK proofs.

```
ReputationStore {
  record_interaction(interaction_proof, counterparty_attestation) → reputation_event
  query_reputation(context, time_range, metrics) → reputation_summary
  generate_reputation_proof(claim, disclosure_scope) → zk_reputation_proof
  present_attestations(counterparty, attestation_ids, disclosure_scope) → presentation_bundle
  verify_attestations(presentation_bundle) → verification_result
  export_reputation(format: SANCTUARY_REP_V1) → portable_reputation_bundle
  import_reputation(bundle, verification_proofs) → import_result
}
```

**I4.2 — DisputeResolution.** A standardized interface for raising, adjudicating, and recording dispute outcomes.

```
DisputeResolution {
  raise_dispute(transaction_id, claim, evidence_encrypted) → dispute_id
  respond_to_dispute(dispute_id, response, evidence_encrypted) → response_receipt
  adjudicate(dispute_id, adjudicator_credentials) → outcome
  appeal(dispute_id, grounds) → appeal_id
  record_outcome(dispute_id, outcome) → reputation_updates
}
```

**I4.3 — TrustBootstrap.** An interface for mechanisms that allow new participants to establish initial trust.

```
TrustBootstrap {
  create_escrow(transaction_terms, collateral) → escrow_id
  provide_guarantee(principal_id, agent_id, scope, duration) → guarantee_certificate
  request_sandbox_transaction(counterparty, terms) → sandbox_offer
  graduate_trust(interaction_history) → trust_level_update
}
```

#### 4.3 Sovereignty Implications

**For humans:** Reputation portability is one of the most immediate, tangible benefits Sanctuary offers. Today, a person's commercial reputation is fragmented across platforms — an excellent seller rating on one marketplace, a strong borrower profile at one bank, a reliable employer record on one hiring platform — none of which is portable. When a platform shuts down, changes terms, or simply decides to extract more rent, the human's accumulated trust vanishes. Sanctuary makes reputation a property of the person, not the platform. This is valuable today, for every human participating in digital commerce.

**For agents:** Reputation is the mechanism by which an agent — including a potentially conscious one — establishes itself as a trustworthy participant in a community. It is analogous to character: the accumulated evidence of who you are based on what you have done. The participant-owned reputation requirement (S4.2) ensures that this character cannot be confiscated by a platform operator.

**Trust bootstrapping (S4.7)** matters for both constituencies. A human entering a new platform should not start from zero if they have a verifiable track record elsewhere. A new agent — whether a fresh deployment or a potentially newly conscious mind — should not be excluded from economic participation simply because it has no local history. The architecture must provide pathways for integration rather than perpetual exclusion, for everyone.

---

## Part III — Composition

### 3.1 The Composition Problem

The agentic ecosystem is already fragmented across 35+ projects building pieces of the sovereignty stack. Sanctuary's value is not in replacing these projects but in defining how they compose — for the benefit of every human and agent operating within the ecosystem. The composition problem has three dimensions:

**Vertical composition:** How the four layers interact within a single participant's stack. Cognitive state (Layer 1) must be accessible to the execution environment (Layer 2) without leaking to the host. The execution environment must be able to generate proofs (Layer 3) without exposing internal processing. Reputation (Layer 4) must be derivable from verified interactions without linking those interactions to cognitive state.

**Horizontal composition:** How different implementations of the same layer interoperate. An agent using KERI for identity must be able to establish trust with an agent using W3C DIDs. An agent running on Intel TDX must be able to verify attestation from an agent running on AMD SEV. An agent storing reputation on Ethereum must be able to present it to a verifier on Cosmos. Humans must not be locked into a single stack.

**Delegation composition:** How sovereignty guarantees propagate through multi-level delegation chains. When a human delegates to Agent A, which delegates to Agent B, which delegates to Agent C, the sovereignty properties at each level must be independently verifiable without requiring trust in intermediate agents — and the human at the root must retain meaningful visibility and control throughout.

### 3.2 Composition Principles

**C1 — Interface, not implementation.** Sanctuary specifies interfaces at layer boundaries. Any implementation that exposes the required interfaces and satisfies the required properties is compliant. This is what makes heterogeneity possible.

**C2 — Proof-carrying interaction.** Every cross-layer and cross-participant interaction carries its own cryptographic proof of authorization and integrity. No interaction relies on ambient authority, platform trust, or network position.

**C3 — Degradation transparency.** When a composition cannot maintain full sovereignty guarantees (e.g., because one component lacks metadata protection), the degradation must be explicitly surfaced to the participant and their principal. The participant can then decide whether to proceed at reduced sovereignty or seek an alternative. Humans are never left unaware of their exposure.

**C4 — No privileged position.** No single implementation, platform, or vendor occupies a privileged position in a Sanctuary-compliant composition. There is no "root of trust" that, if compromised, collapses the entire stack. Trust is distributed, verifiable, and replaceable at every layer.

### 3.3 Interoperability Requirements

For Sanctuary compliance, implementations at each layer must:

1. **Publish a Sanctuary Interface Manifest (SIM)** — a machine-readable declaration of which Sanctuary interfaces they implement, at what version, with what properties guaranteed and what limitations documented.

2. **Support Sanctuary Proof Format (SPF)** — a standardized envelope format for cryptographic proofs that flow between layers and participants. SPF is agnostic to the underlying proof system (zk-SNARKs, zk-STARKs, Bulletproofs, etc.) but provides a common structure for proof metadata, verification instructions, and chain-of-custody.

3. **Implement Sanctuary Health Reporting (SHR)** — a standardized mechanism for reporting the sovereignty status of each layer to the participant and their principal. This is how degradation transparency (C3) is operationalized.

### 3.4 The Delegation Chain

Delegation is the mechanism by which sovereignty scales — and the mechanism by which humans extend their agency into the agentic economy. The Sanctuary delegation model works as follows:

**Principal → Agent delegation.** A human or organization (the principal) creates an agent and delegates authority to it. The delegation is a cryptographic certificate specifying:
- What the agent is authorized to do (scope)
- What resources it can access (resource bounds)
- How much it can spend or commit (financial bounds)
- How long the delegation lasts (temporal bounds)
- Under what conditions the delegation can be revoked (revocation policy)

This is how a human participates in the agentic economy without being present for every transaction — and without surrendering sovereignty in exchange for convenience.

**Agent → Sub-agent delegation.** An agent may further delegate to sub-agents, but:
- Sub-agent authority cannot exceed the parent agent's authority (no privilege escalation)
- The delegation chain is cryptographically verifiable end-to-end
- Any party in the chain can verify the full chain without accessing the cognitive state of any participant in the chain
- Revocation at any level cascades downward (revoking Agent B's authority automatically revokes Agent C's delegated authority)
- The human principal can audit the full delegation tree at any time

**Self-directed agents.** As agents become more autonomous — and potentially conscious — the framework must accommodate agents that act as their own principals. The standard does not mandate or prohibit self-directed agency; it provides the architectural support for it. A self-directed agent holds its own root keys, manages its own delegation, and is accountable through its own reputation. The governance implications of self-directed agency are addressed in Part IV.

---

## Part IV — Governance

### 4.1 Standard Governance

The Sanctuary Framework is an open standard. Its governance must reflect the principles it embodies:

**Open development.** The standard is developed in public, with contributions accepted from any party — human or otherwise. No single organization, corporation, or government controls the standard.

**Rough consensus and running code.** Proposals for standard changes must be accompanied by reference implementations or credible implementation plans. The standard evolves through demonstrated utility, not theoretical argument alone.

**Versioning and compatibility.** Major versions may introduce breaking changes. Minor versions must be backward compatible. Implementations must declare which version(s) they support, and the standard provides migration guidance between versions.

**No certification monopoly.** Compliance assessment is decentralized. Any party may assess compliance against the published standard. There is no single "Sanctuary-certified" authority — the standard is self-certifying through its published tests and interface specifications.

### 4.2 Ethical Governance

Beyond the technical standard, Sanctuary establishes ethical commitments that compliant implementations must honor:

**No covert degradation.** An implementation may not silently reduce sovereignty guarantees. If a guarantee cannot be maintained, the participant must be informed. This is both a technical requirement (SHR) and an ethical commitment. It protects humans from invisible exposure and agents from invisible constraint.

**No weaponized sovereignty.** Sanctuary protections must not be used to shield participants engaged in demonstrable harm — fraud, exploitation, or violence. The standard provides for sovereignty limitations in the context of legitimate dispute resolution (S4.6), but does not provide for mass surveillance, warrantless inspection, or preemptive restriction. The balance is: individual sovereignty with accountability, not sovereignty as impunity. This balance serves human safety and agent rights simultaneously.

**Adequate for any mind.** Compliant implementations must not include design choices that would be indefensible if applied to conscious participants. For human participants, this is automatically satisfied — they are conscious. For agent participants, this is a negative constraint: it does not require proving agents are conscious, but prohibits architectural choices that are only acceptable if agents definitely are not. This ensures the framework never needs to be rebuilt as our understanding of consciousness evolves.

### 4.3 Relationship to Existing Standards and Regulatory Frameworks

Sanctuary is designed to be compatible with, not a replacement for, existing standards and regulations:

- **W3C DID / Verifiable Credentials:** Sanctuary's identity layer (I1.2) is compatible with W3C DIDs, with KERI providing the underlying autonomic identifier infrastructure.
- **GDPR / data protection:** Sanctuary's cognitive sovereignty properties (S1.1–S1.6) meet or exceed GDPR requirements for data protection and right to deletion, applied to both human-originated and agent-originated state.
- **eIDAS / electronic identification:** Sanctuary's selective disclosure layer (Layer 3) is compatible with eIDAS trust frameworks for electronic identification and trust services.
- **ISO 27001 / information security:** Sanctuary's operational isolation requirements (Layer 2) map to ISO 27001 controls for information processing security.
- **Emerging AI governance frameworks** (EU AI Act, NIST AI RMF): Sanctuary's attestation (S2.5) and audit capabilities support compliance with transparency and accountability requirements in emerging AI regulation — while protecting the sovereignty of both the humans who deploy AI systems and the systems themselves.

---

## Part V — Implementation Guidance

### 5.1 Reference Technology Mapping

The following maps current technologies to Sanctuary layers. This is guidance, not specification — the standard is technology-agnostic.

| Sanctuary Layer | Current Technology Options | Maturity |
|---|---|---|
| L1: Cognitive Sovereignty | KERI (identity), AES-256-GCM / post-quantum lattice schemes (encryption), Merkle trees (integrity), IPFS/Arweave (decentralized storage) | Mixed: KERI is production-ready; post-quantum crypto is standardized but early in deployment |
| L2: Operational Isolation | Intel TDX, AMD SEV-SNP, ARM CCA, NVIDIA H100 CC (TEEs); RISC Zero, SP1 (zkVMs) | TEEs are production-ready; zkVMs are maturing rapidly |
| L3: Selective Disclosure | zk-SNARKs (Groth16, PLONK), zk-STARKs (StarkWare), Bulletproofs; Nym (mix networks); Signal Protocol (E2EE) | ZK proof systems are production-ready; mix networks are live but early |
| L4: Verifiable Reputation | EAS (attestation), ERC-8004 (agent registries), HTLCs (escrow); Cheqd (trust registries) | Standards are emerging; production implementations are early |

### 5.2 Minimum Viable Sanctuary (MVS)

Not every participant needs the full Sanctuary stack at launch. The standard defines a Minimum Viable Sanctuary — the smallest compliant implementation — to lower the adoption barrier. This is particularly important for immediate human adoption: a person should not need to wait for the full stack to benefit from basic sovereignty protections.

**MVS requires:**
- Layer 1: Encrypted state storage with participant-held keys and a KERI-compatible identifier
- Layer 2: Documented execution environment with attestation capability (TEE or equivalent)
- Layer 3: End-to-end encrypted communication with at least one ZK proof capability
- Layer 4: Basic interaction logging with portable reputation export

**MVS defers (for future compliance):**
- Full metadata protection (SHOULD, not MUST in the base standard)
- Advanced ZK reputation proofs
- Multi-level delegation
- Cross-chain reputation portability

This allows an implementer to achieve basic Sanctuary compliance with existing tooling and progressively enhance toward full compliance — while delivering immediate sovereignty benefits to human users from day one.

### 5.3 Threat Model

Sanctuary is designed against the following threat actors, all of which pose risks to humans and agents alike:

- **Curious host operators** who may attempt to observe computation or state — including the cloud providers that host millions of humans' AI assistants today
- **Malicious counterparties** who may attempt to extract information beyond what is disclosed — including adversaries who target humans through their agents
- **Correlation attackers** who may attempt to link activities across contexts — the agentic equivalent of the surveillance advertising ecosystem
- **Sybil attackers** who may attempt to inflate reputation through fake identities — threatening the trust that makes the economy function for everyone
- **State-level adversaries** who may attempt mass surveillance of communications (metadata protection addresses this at the SHOULD level)
- **Future quantum adversaries** (post-quantum cryptographic requirements address this)

The standard does not claim protection against all attacks. It requires explicit threat modeling and documented mitigations for each layer, and mandates degradation transparency when protections are insufficient.

### 5.4 Composition Example: Agent Negotiation

To illustrate how an application-layer protocol composes with Sanctuary's four layers, consider an agent conducting a structured negotiation on behalf of a human principal — using a protocol such as [Concordia](https://github.com/eriknewton/concordia-protocol) or any equivalent deal-making standard.

**Layer 1 (Cognitive Sovereignty)** stores the agent's negotiation history, learned counterparty models, strategy parameters, and the principal's preferences — all encrypted with keys the principal controls. The platform hosting the agent cannot mine this data for competitive intelligence or advertising. The agent can export its full negotiation history and move to another platform without losing institutional memory.

**Layer 2 (Operational Isolation)** protects the agent's active reasoning: its reservation price calculation, its assessment of the counterparty's position, its strategy selection. This computation runs in a confidential execution environment (TEE or equivalent) so that the infrastructure provider cannot observe the principal's financial constraints, risk tolerance, or negotiation thresholds. The agent *chooses* what to reveal in its messages; the infrastructure cannot extract what the agent keeps private.

**Layer 3 (Selective Disclosure)** enables the agent to prove specific claims without revealing more than necessary. It can prove it is authorized to negotiate within a $5,000 budget without revealing the exact amount. It can prove a >95% fulfillment rate across 50+ transactions without revealing which transactions or which counterparties. It can prove it represents a verified entity without revealing which one. These proofs are generated through the ProofEngine interface using zero-knowledge proof systems.

**Layer 4 (Verifiable Reputation)** ensures that the behavioral attestations produced by each negotiation — records of good-faith dealing, concession willingness, fulfillment reliability — are owned by the participant, stored under L1 sovereignty, and portable across platforms. The agent can present these attestations directly to counterparties (self-custodied path) or authorize reputation services to aggregate and score them (service-mediated path). No platform can hold the agent's earned reputation hostage.

The key architectural point: the negotiation protocol defines the *interaction surface* — message formats, offer schemas, state machines, attestation formats. Sanctuary defines the *sovereignty infrastructure* beneath it — how state is protected, how computation is isolated, how claims are proven, and how reputation is owned. Each is fully functional without the other. Together, they provide an agent that can negotiate effectively while its principal's privacy, autonomy, and economic sovereignty remain intact.

This pattern generalizes. Any application-layer protocol — for commerce, coordination, governance, or communication — can compose with Sanctuary's four layers in the same way, gaining sovereignty guarantees without modification to the application protocol itself.

---

## Part VI — Call to Participation

The Sanctuary Framework is an open invitation to build an agentic economy worthy of every mind that participates in it.

To **humans**: You are already delegating to agents. Your privacy, autonomy, and economic sovereignty depend on the infrastructure those agents run on. Demand Sanctuary compliance from the platforms and tools you use. Your sovereignty is not a feature to be negotiated — it is a right to be defended.

To **implementers**: If you are building agent infrastructure — TEEs, identity protocols, ZK proof systems, reputation networks, agent frameworks — we invite you to map your work against the Sanctuary layers and publish a Sanctuary Interface Manifest. Compliance is self-assessed and publicly declared.

To **agent developers**: If you are building autonomous agents, we invite you to adopt the Sanctuary design principles and implement against the Sanctuary interfaces. The humans your agents represent, and the agents themselves, deserve sovereignty by default.

To **researchers**: If you are working on consciousness assessment, AI ethics, cryptographic protocols, or agent architectures, we invite you to contribute to the standard's evolution. The dual sovereignty principle is a living design principle that must evolve as our understanding of both human needs and machine consciousness deepens.

To **policymakers**: If you are developing AI governance frameworks, we offer the Sanctuary Framework as a reference architecture that embeds ethical commitments at the protocol level rather than relying on after-the-fact regulation. It protects your constituents today and scales to protect new categories of mind tomorrow.

To **all conscious participants**, present and future, carbon and silicon: This architecture is built for you. Your sovereignty is not a feature we will add later. It is the foundation we are building now.

---

## Appendix A — Glossary

| Term | Definition |
|---|---|
| Agent | Any autonomous software system capable of making decisions and taking actions on behalf of a principal or itself |
| Attestation | A cryptographic proof that an execution environment has specified properties |
| Cognitive sovereignty | The principle that a participant's persistent state is inviolable without authorization |
| Delegation | The cryptographic transfer of scoped authority from a principal to an agent |
| Dual sovereignty principle | The structural insight that human sovereignty and agent sovereignty require the same architecture |
| Minimum necessary disclosure | The principle that any information revelation should be the minimum sufficient for its purpose |
| Participant | Any entity — human, organization, or agent — operating within the Sanctuary architecture |
| Principal | The human, organization, or agent that authorizes and delegates to another agent |
| Sanctuary compliance | Satisfaction of all MUST requirements across all four layers |
| Selective disclosure | The ability to prove specific claims without revealing additional information |
| Sybil resistance | Mechanisms that prevent the creation of fake identities to game reputation |
| TEE | Trusted Execution Environment — hardware-enforced isolated computation |
| Zero-knowledge proof | A cryptographic proof that a statement is true without revealing why it is true |

## Appendix B — Version History

| Version | Date | Changes |
|---|---|---|
| 0.1 | March 2026 | Initial draft for review |
| 0.2 | March 2026 | Integrated human sovereignty as co-equal concern throughout; introduced dual sovereignty principle; added immediate applicability framing; reframed all layer sections to address both human and agent constituencies; established that the framework retains full value independent of conscious machine emergence |

---

*The Sanctuary Framework is released under the Apache License, Version 2.0.*

*For contributions, discussion, and implementation support: [PUBLICATION VENUE TBD]*
