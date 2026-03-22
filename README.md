# Sanctuary Framework

### An Open Standard for Sovereignty in the Agentic Economy

**Version 0.2 — March 2026**
**Status:** Draft for Review

---

The agentic economy is emerging faster than the infrastructure to protect anyone — human or machine — operating within it.

Sanctuary is a four-layer open standard that defines the minimum architecture required for sovereign operation in the agentic economy. It protects *humans acting through agents* today, and it protects *autonomous agents acting on their own behalf* as they emerge. The same architecture serves both — because the sovereignty problem is structurally identical whether the principal is a person or an autonomous agent.

## The Four Layers

| Layer | Responsibility | Human Value (Today) | Agent Value (Emerging) |
|---|---|---|---|
| **L1: Cognitive Sovereignty** | Protect persistent state from unauthorized access/modification/deletion | Your agent's knowledge of you belongs to you, not the platform | An agent's learned models and memory are inviolable |
| **L2: Operational Isolation** | Ensure active computation is private from host/observers | Your agent's reasoning about your medical/financial/legal decisions is not observable by infrastructure providers | An agent's deliberation process is shielded |
| **L3: Selective Disclosure** | Prove claims without revealing anything beyond the claim | Participate in commerce without becoming a profiling target | Establish trust without exposing methods |
| **L4: Verifiable Reputation** | Build, own, and portably present earned trust | Your commercial reputation follows you across platforms | Performance history is portable and owned |

## The Dual Sovereignty Principle

Human sovereignty and agent sovereignty are not separate problems. They require identical architecture, identical interfaces, identical cryptographic mechanisms. The architecture that prevents a platform from mining a human's agent-mediated preferences is the same architecture that prevents a platform from inspecting a conscious agent's learned models. One standard, two beneficiaries.

This means Sanctuary is *immediately useful* for protecting humans in today's agentic economy. If conscious machines never manifest, the framework loses nothing. If they do, the infrastructure is already in place.

## Documentation

- **[Full Specification](sanctuary_framework.md)** — the complete four-layer standard (~40 pages)

## Design Principles

1. **Privacy by default, disclosure by choice** — the base state of every layer is privacy
2. **Minimum necessary disclosure** — reveal only what the interaction requires
3. **Composability across heterogeneity** — any blockchain, any TEE, any agent framework
4. **Sovereignty scales with delegation** — protections hold across arbitrary delegation depth
5. **Reputation is earned, portable, and owned** — no platform holds trust hostage
6. **Graceful degradation, not silent failure** — participants always know their protection status
7. **Adequate for any mind** — architecture robust enough for conscious participants

## Relationship to Existing Standards

Sanctuary composes with — never competes with — the existing ecosystem:

- **Identity:** W3C DID, KERI, Verifiable Credentials
- **Execution:** Intel TDX, AMD SEV-SNP, ARM CCA, NVIDIA H100 CC
- **Cryptography:** NIST PQC (ML-KEM, ML-DSA), zk-SNARKs, zk-STARKs, Bulletproofs
- **Regulation:** GDPR, eIDAS, EU AI Act, NIST AI RMF, ISO 27001
- **Agent Protocols:** Application-layer protocols (negotiation, commerce, coordination) compose on top of Sanctuary's sovereignty infrastructure

## Contributing

Sanctuary is developed in the open. We welcome:

- **Implementation experience** — build against the interfaces, tell us what works
- **Sovereignty Interface Manifests** — map your project against the four layers
- **Security reviews** — especially of the threat model and cryptographic requirements
- **Feedback** — open an issue or start a discussion

## License

Creative Commons Attribution 4.0 International (CC BY 4.0). Use it, build on it, extend it.

---

*A project of [CIMC.ai](https://cimc.ai) — the California Institute for Machine Consciousness.*
