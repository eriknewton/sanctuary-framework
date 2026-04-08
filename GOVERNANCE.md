# Governance

Sanctuary Framework follows an open-source maintainer governance model. This document describes how decisions are made, how contributions are reviewed, and how the project plans to evolve its governance as the community grows.

## Project Lead

**Erik Newton** (@eriknewton) — sole author, maintainer, and decision-maker for the project. Erik is responsible for architecture decisions, security reviews, release management, and standards engagement.

## Decision Process

Decisions are categorized by impact:

### Tier 1: Routine Changes
Bug fixes, documentation improvements, test additions, dependency updates.

- **Review:** 1 maintainer approval
- **SLA:** 72 hours
- **Merge criteria:** All tests pass (1071+ tests), no breaking changes

### Tier 2: Feature Additions
New MCP tools within existing layers, new integrations, adapter implementations.

- **Review:** RFC discussion on GitHub Issues (7-day comment period)
- **SLA:** 2-week review and decision
- **Merge criteria:** RFC approved, all tests pass, security review for cryptographic changes

### Tier 3: Architectural Changes
New sovereignty layers, protocol modifications, cryptographic algorithm changes, breaking API changes.

- **Review:** RFC with 14-day community comment period + external security review
- **SLA:** 4-week review and decision
- **Merge criteria:** RFC consensus, security audit, maintainer sign-off

## Release Process

- Semantic versioning (MAJOR.MINOR.PATCH)
- Breaking changes require a MAJOR version bump and 2-release deprecation notice
- All releases gated by full test suite passing
- Security releases follow expedited review (24-hour SLA for critical issues)

## Security

Security vulnerabilities should be reported via the process described in [SECURITY.md](SECURITY.md). Critical issues receive a 24-hour response SLA.

## Future Governance

As the contributor community grows, the project intends to adopt a Technical Steering Committee (TSC) model:

- **Lead Maintainer:** Architecture, RFC approval, security decisions
- **Security Chair:** Quarterly cryptographic reviews, CVE triage
- **Community Chair:** Elected annually; issue triage, contributor onboarding
- **Standards Liaison:** W3C, IETF, AAIF coordination
- **Rotating Member:** 2-year seat for vendor, enterprise, or research representatives

TSC decisions on Tier 3 changes require majority vote. The project will transition to this model when it has at least 3 active contributors from different organizations.

## Code of Conduct

Contributors are expected to engage respectfully and constructively. The project follows the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/) (v2.1).

## License

Code is licensed under Apache-2.0. The specification is licensed under CC-BY-4.0. See [LICENSE](LICENSE) for details.
