# Roadmap

12-month public roadmap for Sanctuary Framework. Updated April 2026.

## Q2 2026 (April – June)

### v0.8.0
- Per-upstream rate limiting: integrate CallGovernor with proxy router for per-server quotas
- Signed tool provenance: capability manifests attesting security review status
- Collapse YAML/TS policy sources of truth into single authoritative source
- Remove `tool_overrides` from UpstreamServer (tier assignment from Principal Policy only)

### Cocoon Runtime Enforcement
- Move from config-rewriting to actual runtime MCP proxy interception
- Enforce principal policy at the transport layer, not just the configuration layer

### Compliance
- EU AI Act Article 19 compliance artifact generator (SHR → audit trail mapping)
- NIST AI RMF alignment documentation

### Standards Engagement
- AAIF Security Working Group participation
- W3C Agentic Integrity Verification Specification CG: advocate for Ed25519 as first-class signature algorithm
- Position SHR as candidate governance standard for MCP Registry

## Q3 2026 (July – September)

### v0.9.0
- Delegation chain metadata format: verifiable authorization chains
- Agent decommissioning certificates: secure lifecycle termination
- Upstream server count limits with validation

### Enterprise Readiness
- Enterprise pilot deployments targeting finance, healthcare, and energy verticals
- Managed Agents integration guide and reference architecture

### Ecosystem Growth
- Rust reference implementation (specification-compatible, for goose/AAIF integration)
- Python reference implementation (for Concordia Protocol native composition)
- Interoperability test suite for cross-ecosystem agent trust verification

### Events
- AGNTCon + MCPCon San Jose (October 22-23): talk proposal submitted

## Q4 2026 (October – December)

### v1.0.0 — Stable Release
- Stable API with backward-compatibility guarantees
- Long-term support (LTS) commitment
- Comprehensive migration guide from 0.x to 1.0

### MCP Registry Integration
- SHR as governance verification standard for MCP Registry launch (Q4 2026)
- Automated sovereignty scoring for registry-listed MCP servers

### Research
- Academic publication targeting NDSS, CCS, or IEEE S&P security conferences
- Concordia Protocol bridge: cross-protocol negotiation with sovereignty guarantees

## Q1–Q2 2027

### Standards Harmonization
- W3C DID method specification alignment (Ed25519 → DIDs)
- IETF trust scoring alignment (Verascore dimensions → IETF draft-sharif)

### Community
- Community-elected Technical Steering Committee operational
- Bootstrap bundle (`@sanctuary-framework/agent-bundle`) for zero-config deployment

### Federation
- Agent Registry Federation: multi-organization agent discovery with sovereignty-gated trust boundaries
- Reputation Portability Standard: cross-ecosystem reputation verification

## How to Influence the Roadmap

- Open a GitHub Issue with your use case or feature request
- Participate in RFC discussions for upcoming features
- Join the AAIF Security Working Group to shape governance standards
- Enterprise pilot partners: contact the maintainer via GitHub

## Status Key

Items move through: **Planned** → **In Progress** → **Shipped** → **Stable**

Current version: **v0.7.0** (shipped April 8, 2026)
Next milestone: **v0.8.0** (targeting May 2026)
