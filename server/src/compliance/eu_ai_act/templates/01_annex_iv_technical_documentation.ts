/**
 * Sanctuary MCP Server — EU AI Act Template: Annex IV Technical Documentation
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Document 01 of the EU AI Act Compliance Bundle.
 *
 * Covers Annex IV (per Article 11) technical documentation for
 * high-risk AI systems: §1 general description, §2 detailed
 * description of elements, §3 monitoring, §4 performance metrics,
 * §5 risk management, §6 lifecycle changes, §7 standards, §8
 * declaration of conformity, §9 post-market monitoring plan.
 *
 * Row content is rendered per-section by the generator walking the
 * coverage matrix's Annex IV rows. The sections_* slots below receive
 * pre-rendered row blocks.
 */

import { HEADER_TEMPLATE, FOOTER_TEMPLATE } from "./shared.js";

export const ANNEX_IV_TECHNICAL_DOCUMENTATION_TEMPLATE =
  `${HEADER_TEMPLATE}
## Introduction

This document is the Annex IV Technical Documentation for the
high-risk AI system identified above, prepared under Article 11 of
Regulation (EU) 2024/1689 (the "EU AI Act").

The document maps each numbered Annex IV section to the evidence
that the Sanctuary Framework auto-emits for that section, and
identifies exactly where enterprise-supplied business context is
required. Sections marked **FULL** are machine-verifiable against
the live Sanctuary instance that generated this bundle. Sections
marked **PARTIAL** carry auto-filled structured evidence alongside
explicit \`[MANUAL INPUT REQUIRED: ...]\` markers for enterprise
completion. Sections marked **MANUAL ONLY** are outside Sanctuary's
architectural scope and must be authored by the enterprise in full.

**How to use this document:**

1. Review each section below in order.
2. For every \`[MANUAL INPUT REQUIRED: ...]\` marker, replace the
   marker with the relevant enterprise fact.
3. Verify the auto-filled evidence against the live Sanctuary
   instance by running the listed \`evidence_emitter\` tools.
4. Sign the completed document with the provider's legal signature
   (the Sanctuary cryptographic signature below is the runtime
   authenticity attestation, not a substitute for a signed legal
   declaration).

---

## §1 — General Description

{{ sections_1 }}

## §2 — Detailed Description of Elements

{{ sections_2 }}

## §3 — Monitoring, Functioning and Control

{{ sections_3 }}

## §4 — Performance Metrics

{{ sections_4 }}

## §5 — Risk Management System (Article 9)

{{ sections_5 }}

## §6 — Changes Through Lifecycle

{{ sections_6 }}

## §7 — Standards Applied

{{ sections_7 }}

## §8 — EU Declaration of Conformity

{{ sections_8 }}

## §9 — Post-Market Monitoring Plan (Article 72)

{{ sections_9 }}

${FOOTER_TEMPLATE}`;
