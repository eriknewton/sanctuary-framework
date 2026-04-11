/**
 * Sanctuary MCP Server — EU AI Act Template: Delta Report
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Document 08 (Phase 2, conditional) of the EU AI Act Compliance
 * Bundle. Included only when the bundle was generated with a
 * `delta_from_bundle_path` referencing a prior bundle on disk.
 *
 * Reports what changed in the coverage matrix, regulation version,
 * and matrix version between the prior bundle and the current one.
 * Enables enterprises to maintain a rolling compliance record
 * without re-reading the full bundle on every update.
 */

import { HEADER_TEMPLATE, FOOTER_TEMPLATE } from "./shared.js";

export const DELTA_TEMPLATE = `${HEADER_TEMPLATE}
## Introduction

This document reports what changed in the Sanctuary EU AI Act
coverage matrix between the **prior** bundle referenced below and
the **current** bundle identified in the header table above.

A delta document is intended for enterprises that maintain a
rolling compliance record — e.g., a quarterly or monthly
regeneration cadence — and want to review only the changes since
the last bundle without re-reading every document.

**The delta is computed from the two manifests, not from the
document bodies.** Specifically, it compares:

1. The \`regulation_version\` field (external regulation text changes)
2. The \`matrix_version\` field (structural matrix schema changes)
3. The per-row \`coverage\` flag in \`coverage_rows[]\`
4. The per-row \`evidence_emitter[]\` array

Row \`last_reviewed_date\` is compared when both bundles expose it
in the coverage_rows summary. A delta row may reflect any
combination of these changes — they are not mutually exclusive.

---

## Prior bundle reference

| Field | Value |
|---|---|
| **Path** | \`{{ prior_bundle_path }}\` |
| **Generated at** | {{ prior_generated_at }} |
| **Signer DID** | \`{{ prior_signer_did }}\` |
| **Regulation version** | {{ prior_regulation_version }} |
| **Matrix version** | \`{{ prior_matrix_version }}\` |

## Current bundle reference

| Field | Value |
|---|---|
| **Generated at** | {{ current_generated_at }} |
| **Signer DID** | \`{{ current_signer_did }}\` |
| **Regulation version** | {{ current_regulation_version }} |
| **Matrix version** | \`{{ current_matrix_version }}\` |

---

## Summary

| Change category | Count |
|---|---|
| Regulation version bumped | {{ regulation_version_changed }} |
| Matrix version bumped | {{ matrix_version_changed }} |
| Rows added | {{ rows_added_count }} |
| Rows removed | {{ rows_removed_count }} |
| Rows changed | {{ rows_changed_count }} |

{{ no_changes_note }}

---

## Rows added

{{ rows_added_rendered }}

## Rows removed

{{ rows_removed_rendered }}

## Rows changed

{{ rows_changed_rendered }}

---

## Warnings

{{ warnings_rendered }}

---

## How to use this delta

1. If **regulation version bumped**, the coverage matrix has been
   re-aligned to updated regulation text (implementing acts,
   delegated acts, or OJ errata). Every \`full\` row should be
   re-verified against the new text before the current bundle is
   treated as authoritative.
2. If **matrix version bumped**, the matrix schema changed (row
   set, coverage classification rules, or row structure). Review
   the v1 → v2 (or later) migration notes in the repository's
   \`docs/audit/\` directory.
3. For each **row changed**, walk the \`review_notes\` field of the
   current coverage matrix entry for that row (available in
   \`docs/compliance/eu_ai_act_coverage_matrix_v1.md\`) — the reason
   for the change is recorded there.
4. For **rows added** or **rows removed**, the matrix structure
   itself evolved. Treat these as matrix_version changes even if
   the matrix_version field happens not to have bumped.

This delta document is cryptographically signed into the current
bundle's manifest, so an auditor can verify that the delta reflects
the exact state claimed by the current bundle.

${FOOTER_TEMPLATE}`;
