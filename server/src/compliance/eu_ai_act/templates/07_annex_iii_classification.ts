/**
 * Sanctuary MCP Server — EU AI Act Template: Annex III Classification
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Document 07 (Phase 2, optional) of the EU AI Act Compliance
 * Bundle. Included only when the bundle input provides an intended
 * purpose or the classification helper has been run against one.
 *
 * This document reports the rule-based candidate classifications
 * and explicitly leaves the final legal determination as
 * [MANUAL INPUT REQUIRED].
 */

import { HEADER_TEMPLATE, FOOTER_TEMPLATE } from "./shared.js";

export const ANNEX_III_CLASSIFICATION_TEMPLATE = `${HEADER_TEMPLATE}
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

> {{ classified_intended_purpose }}

---

## Candidate categories

{{ candidates_rendered }}

---

## Final classification determination

{{ final_classification | final Annex III category determined by legal review of the regulation text, including the category number and sub-point and a one-paragraph justification linking the agent's intended purpose to the verbatim regulation language }}

---

## Why the classifier is rule-based, not model-based

The classification helper uses a keyword-weighted rule-based scoring
system with no trained model, no machine learning, and no probability
distribution. The decision to use a rule-based classifier is
deliberate for three reasons:

1. **Auditability.** Every match is traceable to a specific keyword
   in a checked-in catalog file (\`server/src/compliance/eu_ai_act/annex_iii.ts\`).
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

{{ classifier_advisory }}

${FOOTER_TEMPLATE}`;
