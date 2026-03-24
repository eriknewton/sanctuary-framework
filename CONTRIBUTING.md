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

## License

All contributions are licensed under the [Apache License 2.0](LICENSE). By submitting a pull request, you agree that your contribution is licensed under the same terms.
