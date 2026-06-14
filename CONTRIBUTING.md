# Contributing to the Sanctuary Framework

Thank you for your interest in Sanctuary. This document covers how to contribute to the open standard.

## How to Participate

**Discussion first.** Before opening a pull request, start a conversation. Use GitHub Discussions for open-ended questions and ideas. Use Issues for specific problems — a gap in the spec, an ambiguity in an interface definition, a conflict with an existing standard.

**Implementation experience is the most valuable contribution.** If you've built against Sanctuary's interfaces, we want to hear what worked, what didn't, and what was missing. Open an "Implementation Experience" issue with your findings.

## Proposing Changes to the Specification

Changes to the Sanctuary Framework specification go through an RFC process:

1. Create a file in `rfcs/` following the naming convention `NNNN-short-title.md`.
2. Describe the problem, propose the change, and identify which layers, interfaces, and properties are affected.
3. Open a pull request with the RFC. Discussion happens on the PR.
4. Once accepted, the RFC is merged and the spec is updated accordingly.

RFCs are appropriate for: changes to required properties (S-prefixed), changes to required interfaces (I-prefixed), new design principles, new composition requirements, changes to conformance levels, and changes to the threat model.

RFCs are **not** needed for: clarifications that don't change requirements, typographical fixes, improvements to examples, or additions to the glossary.

## Conventions

The specification uses RFC 2119 language: MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL have their standard meanings. Be precise when proposing changes that use these terms — the difference between MUST and SHOULD is the difference between a compliance requirement and a best practice.

## The Dual Sovereignty Principle

Every proposed change must serve both human sovereignty and agent sovereignty. This is not a preference — it is the central structural constraint of the framework. If a proposal improves protections for one constituency at the expense of the other, it needs reworking.

## What We're Looking For

- **Sovereignty Interface Manifests (SIMs):** Map your project against the four layers and share what you find.
- **Security reviews:** Especially of the threat model, the cryptographic requirements, and the composition principles.
- **Regulatory analysis:** How does Sanctuary interact with jurisdiction-specific requirements beyond those already referenced?
- **Implementation reports:** What did you build? What interfaces did you implement? What was missing?

## Contributing Code (MCP Server)

### Getting Started

1. Fork the repository and clone your fork
2. Install dependencies: `cd server && npm install`
3. Run the test suite: `npm test` (must stay green; the enforced minimum is tracked in `.test-baseline`)

### Development Guidelines

- TypeScript with strict mode, ESM + CJS dual output
- All MCP tools must include input validation via Zod schemas
- Every new tool requires a corresponding test file
- Every bug fix requires a regression test
- Use conventional commit format: `feat:`, `fix:`, `docs:`, `test:`, `security:`
- Run `npm run lint` before pushing; CI enforces zero ESLint errors (warnings are reported, not blocking)
- An `.editorconfig` at the repo root sets the basics (UTF-8, LF, 2-space indent, final newline); most editors apply it automatically

### Pull Request Process

1. Create a branch from `main`
2. Make your changes with tests
3. Run `npm test` and `npm run lint` — tests must pass and lint must report zero errors
4. Submit PR with description of changes and motivation
5. Address review feedback; maintainer merges after approval

### Review Tiers

- **Tier 1 (routine):** Bug fixes, docs, test improvements — 72-hour review SLA
- **Tier 2 (features):** New tools, integrations — RFC + 7-day comment period
- **Tier 3 (architectural):** New layers, protocol changes, crypto algorithms — RFC + 14-day comment + security review

### Security Reports

Do not open a public issue for security vulnerabilities. Follow the responsible disclosure process in [SECURITY.md](SECURITY.md).

## Governance

See [GOVERNANCE.md](GOVERNANCE.md) for the full decision-making process and the planned Technical Steering Committee model.

## License

Code contributions are licensed under [Apache License 2.0](LICENSE). Specification contributions are licensed under [CC-BY-4.0](LICENSE). By submitting a pull request, you agree that your contribution is licensed under the same terms as the file you are modifying.
