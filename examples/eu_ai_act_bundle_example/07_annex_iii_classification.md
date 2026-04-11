# Annex III Classification Candidates

*Rule-based candidate classifications for Annex III of Regulation (EU) 2024/1689*

---

| Field | Value |
|---|---|
| **Regulation** | EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10 |
| **Coverage matrix version** | v1 |
| **Bundle generated** | 2026-04-10T12:00:00.000Z |
| **Reporting period** | 2026-04-01T00:00:00.000Z → 2026-04-30T23:59:59.999Z |
| **Agent DID** | `did:sanctuary:meridian-hr-screening-agent` |
| **Legal provider** | Meridian Financial Holdings, Inc. |
| **Provider contact** | ai-compliance@meridian.example.com |
| **Intended purpose** | Automated CV screening and candidate shortlisting for open requisitions |
| **Annex III classification** | §4 employment, workers management, self-employment |
| **Signer DID** | `did:key:z7QGcerokfUuai3m1bqsYJXTl-M2VQCiaH4laBp4AW1izyg` |
| **Signer public key (base64url)** | `nHq6JH1Lmot5tW6rGCV05fjNlUAomh-JWgaeAFtYs8o` |

---


## Introduction

This document reports the Annex III candidate classifications for
the agent identified above, produced by the Sanctuary rule-based
classification helper. It is **not** a legal determination — it is
a keyword-weighted narrowing of the search space intended to help
the enterprise reviewer focus on the relevant sections of Annex III
of Regulation (EU) 2024/1689.

The classifier compares the agent's intended purpose against a
structured catalog of the eight Annex III high-risk categories and
their sub-points. Every keyword has a coarse weight (1.0 high, 0.6
medium, 0.3 low); the sum is clamped to [0, 1] and reported as the
**rule_based_confidence** field. The name is deliberately awkward so
downstream consumers cannot mistake it for a machine-learning model
prediction.

---

## Classified intended purpose (deployer-supplied)

> Automated CV screening and candidate shortlisting for open requisitions

---

## Candidate categories

#### Candidate 1: Annex III §4(a) — Employment — recruitment and candidate evaluation

- **Category ID:** `annex_iii_4_a_employment_recruitment`
- **rule_based_confidence:** 1.00 (100%)
- **Matched keywords:** `cv screening`, `candidate shortlist`


---

## Final classification determination

[MANUAL INPUT REQUIRED: final Annex III category determined by legal review of the regulation text, including the category number and sub-point and a one-paragraph justification linking the agent's intended purpose to the verbatim regulation language]

---

## Why the classifier is rule-based, not model-based

The classification helper uses a keyword-weighted rule-based scoring
system with no trained model, no machine learning, and no probability
distribution. The decision to use a rule-based classifier is
deliberate for three reasons:

1. **Auditability.** Every match is traceable to a specific keyword
   in a checked-in catalog file (`server/src/compliance/eu_ai_act/annex_iii.ts`).
   An auditor can grep for the keyword and see why the category
   matched.

2. **No training data contamination.** A trained classifier would
   inherit whatever biases its training set contained, and the
   provenance of such a training set would itself become part of
   the compliance surface.

3. **Honest uncertainty.** A rule-based score of 0.9 means "nine
   weighted keywords matched" — a concrete, reproducible signal.
   A model prediction of 0.9 means "the model is confident" — a
   signal whose meaning depends on the model's calibration, which
   the deployer cannot independently verify.

If no candidate category cleared the minimum threshold (0.4), the
"Candidate categories" section above is empty. **This does not mean
the agent is out of scope of the EU AI Act.** It means the keyword
catalog did not find a clear match against the deployer-supplied
intended purpose. The deployer is still responsible for reviewing
Annex III in full and determining whether any category applies.

---

## Advisory

This classification is a RULE-BASED keyword match, NOT a machine-learning model prediction, and NOT legal advice. The rule_based_confidence score reflects the sum of matched keyword weights, clamped to [0, 1]. Use this to narrow the deployer's review — the final Annex III classification determination must be made by a human reviewer against the full regulation text (Annex III of Regulation (EU) 2024/1689). An empty result means no category cleared the minimum threshold; it does NOT mean the agent is out of scope of the Act.


---

## Document Signature

This document is cryptographically signed by the provider's primary
Ed25519 identity (DID `did:key:z7QGcerokfUuai3m1bqsYJXTl-M2VQCiaH4laBp4AW1izyg`, public key
`nHq6JH1Lmot5tW6rGCV05fjNlUAomh-JWgaeAFtYs8o`). The signature for this document is recorded
in the bundle manifest `00_bundle_manifest.json` under the entry
with this filename, alongside its SHA-256 digest.

**Verification procedure:** compute the SHA-256 of this file's raw
byte content, compare it against the `sha256` field for this file
in the bundle manifest, then verify the `signature` field against
the SHA-256 using the signer's public key with Ed25519. A successful
check proves this document was emitted by the named Sanctuary
instance and has not been altered since generation.

---

## Disclaimer

**This document is not legal advice.** It is a technical artifact
generated by the Sanctuary Framework EU AI Act Compliance Artifact
Generator. It is not a legal interpretation of Regulation (EU)
2024/1689 and does not constitute a legal opinion. Consult qualified
legal counsel before filing or relying on this document for
regulatory submissions, self-assessment, or CE marking procedures.

The coverage claims in this document reflect the state of the
Sanctuary Framework v0.8.0 runtime as of the
generation timestamp above. The coverage matrix is versioned
(`v1`) and aligned to the regulation text
identified by `EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10`; if the European Commission
publishes implementing acts, delegated acts, or guidance that
modifies the applicable requirements, this document must be
regenerated against the updated matrix.

---

*Generated by [Sanctuary Framework](https://github.com/eriknewton/sanctuary-framework)
v0.8.0 · Author: Erik Newton · License: Apache-2.0*
