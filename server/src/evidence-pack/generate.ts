/**
 * Sanctuary MCP Server - Law-firm Evidence Pack: generator
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Assembles the quarterly evidence pack from already-resolved inputs, each of
 * which arrives as a typed {@link ReadOutcome} so a failed or absent read can
 * never render as a definitive claim (see `read-outcome.ts`). This function is
 * pure over its deps (no I/O, no server boot), so tests drive the real
 * aggregation, shortfall, rendering, PDF, and signing paths with synthetic
 * fixtures and never touch a real fortress. The CLI (`cli.ts`) resolves the
 * deps from a running server and writes the result to disk.
 */

import type { AuditEntry } from "../operational/audit-log.js";
import type { StoredIdentity } from "../core/identity.js";
import { renderMarkdownDocumentsToPdf } from "../compliance/eu_ai_act/pdf.js";
import type {
  CustodyFacts,
  DaemonStoreDisclosure,
  EvidencePack,
  EvidencePackFile,
  EvidencePackInput,
  EvidencePackManifest,
  QuarterAggregation,
  RetentionFacts,
  ShortfallReport,
} from "./types.js";
import {
  foldOutcome,
  populated,
  readFailed,
  type ReadOutcome,
} from "./read-outcome.js";
import { isRecognizedDaemonStatus } from "./types.js";
import { isInWindow, quarterWindow } from "./quarter.js";
import { aggregateQuarter, detectShortfall } from "./aggregate.js";
import { renderSections } from "./sections.js";
import { buildPackManifest, makePackSigner, signFile } from "./signer.js";

/** Working product name shown on the cover and in the manifest. */
export const PRODUCT_NAME = "Sanctuary Evidence Pack";

/** Basename of the single human-readable Markdown report. */
export const REPORT_FILENAME = "01_evidence_pack.md";
/** Basename of the signed manifest. */
export const MANIFEST_FILENAME = "00_pack_manifest.json";
/** Basename of the rendered PDF. */
export const PDF_FILENAME = "evidence-pack.pdf";
/** Basename of the gathered transparency-checkpoint bundle (slice 2). */
export const TRANSPARENCY_BUNDLE_FILENAME = "transparency-bundle.json";
/** Basename of the gathered audit-chain JSONL export (slice 2). */
export const AUDIT_CHAIN_FILENAME = "audit-chain.jsonl";
/** Basename of the gathered public-anchor evidence (slice 2). */
export const ANCHOR_EVIDENCE_FILENAME = "anchor-evidence.json";

/** The result of reading the audit log for the pack (one read: entries + retention). */
export interface AuditReadData {
  entries: readonly AuditEntry[];
  retention: RetentionFacts;
  /**
   * G-2: when the F2 daemon store was merged (`included`), the daemon entries on
   * their own (a subset of `entries`), so the generator -- which owns the quarter
   * window -- can count how many fall INSIDE the window and render that windowed
   * figure in the §7 daemon note instead of the all-time total. Absent for a
   * non-split / unreadable / absent daemon store.
   */
  daemon_entries?: readonly AuditEntry[];
  /**
   * D9C-1: the instant the audit census was taken (captured by the caller
   * BEFORE the pack stamps its generation time). The attested coverage window
   * must never post-date this cut: entries appended between the census and
   * generation were not counted, so signing coverage through the later
   * generation instant would attest a window the census never saw. Absent for
   * legacy callers, whose coverage falls back to the generation instant.
   */
  census_taken_at?: string;
}

/** Already-resolved inputs the generator needs (see module doc-comment). */
export interface BuildEvidencePackDeps {
  /**
   * The audit-log read as a {@link ReadOutcome}: `populated` with the entries +
   * retention when the log was read, or `read_failed` with a reason. On
   * `read_failed`, the decision-count and coverage sections render
   * incomplete-with-reason and the manifest coverage is marked non-determinable
   * - never a false "no denials" or "full quarter covered".
   */
  audit: ReadOutcome<AuditReadData>;
  /** The fortress primary identity used to sign every emitted file. */
  signer: StoredIdentity;
  /** The fortress master key (used transiently for signing only). */
  masterKey: Uint8Array;
}

/**
 * D5-3 (dry-bar round 5): default (not-gathered) discrete exports. A caller
 * that OMITS `input.discrete_exports` did not READ the transparency bundle,
 * audit chain, or anchor evidence, so this default must NOT mint an
 * `empty_verified` witness -- that is a definitive "read to completion, zero
 * records" for a read that never happened, which §10 renders as three definitive
 * negatives ("emitted no signed transparency checkpoints yet", "the audit-chain
 * export was empty", "no public-anchor evidence is available"). That is the
 * exact R3-5/C4 witness-minting class. A NON-read yields `read_failed`, whose
 * §10 arms render the honest "Not included: <reason>" instead of a false empty.
 * The shipped `runEvidencePack` always supplies real gathers; this default only
 * covers a programmatic `buildEvidencePack` caller that omits them.
 */
function defaultDiscreteExports(): {
  transparency: ReadOutcome<string>;
  audit_chain: ReadOutcome<string>;
  anchor: ReadOutcome<string>;
} {
  const notGathered = (): ReadOutcome<string> =>
    readFailed(
      "discrete exports were not gathered by this pack run (the caller omitted them)."
    );
  return {
    transparency: notGathered(),
    audit_chain: notGathered(),
    anchor: notGathered(),
  };
}

/**
 * Dry-9 fix-round-2: the SINGLE chokepoint that serializes the SIGNED manifest
 * `coverage` from the honesty-guarded {@link ShortfallReport}. Every field the
 * signed manifest asserts about coverage is derived HERE, from the SAME values
 * the prose reads, so the machine-verified artifact and the human-readable
 * report can never diverge. BY CONSTRUCTION this function cannot emit:
 *
 *  - P1: a definitive covered span when coverage is NOT DETERMINABLE. A populated
 *    report with `coverage_determinable === false` (a present-but-unparseable
 *    audit-census cut that cannot bound the window) fails closed to the SAME
 *    `{ determinable: false, reason }` shape a `read_failed` / `empty_verified`
 *    audit read produces -- never a span silently widened to the generation
 *    instant.
 *  - P2: a RAW, unrecognized daemon status in the enum-shaped `daemon_store.status`
 *    field. An untyped / JSON caller's smuggled value (e.g. `"quarantined"`)
 *    normalizes to the explicit `"unrecognized"` sentinel via
 *    {@link isRecognizedDaemonStatus}; the field is ALWAYS a recognized value.
 *  - P3: an EMPTY covered span without its `zero_of_quarter_covered` marker. The
 *    marker is re-derived from the span itself (`covered_from` ==
 *    `covered_to_exclusive`), so no upstream path can hand this function an empty
 *    span and have it serialized bare.
 *
 * Valid, fully-covered quarters flow through unchanged (no marker, a recognized
 * status, a real determinable span), so the shipped manifest shape is untouched.
 */
function serializeManifestCoverage(
  shortfall: ReadOutcome<ShortfallReport>
): EvidencePackManifest["coverage"] {
  return foldOutcome<ShortfallReport, EvidencePackManifest["coverage"]>(
    shortfall,
    {
      populated: (s) => {
        // P1: the covered window was not determinable (e.g. an unparseable
        // audit-census cut). Fail closed to the not-determinable shape; NEVER
        // sign a definitive span. This is checked FIRST so no widened span can
        // reach the determinable branch below.
        if (!s.coverage_determinable) {
          return { determinable: false, reason: s.explanation };
        }
        // P3: re-derive the empty-span marker from the span itself so an empty
        // span is structurally inseparable from its marker. `covered_to_exclusive`
        // is EXCLUSIVE, so equal bounds are already a zero-width window.
        const emptySpan =
          new Date(s.covered_from).getTime() >=
          new Date(s.covered_to_exclusive).getTime();
        const zeroCovered = s.zero_of_quarter_covered || emptySpan;
        // P2: normalize the enum-shaped daemon status. A missing disclosure
        // defaults to `absent` (the documented default); a recognized status
        // passes through; anything else (an untyped/JSON caller's smuggled
        // string) becomes the explicit `unrecognized` sentinel, NEVER the raw
        // value.
        const rawStatus = s.daemon_store?.status ?? "absent";
        const status: DaemonStoreDisclosure["status"] | "unrecognized" =
          isRecognizedDaemonStatus(rawStatus) ? rawStatus : "unrecognized";
        return {
          determinable: true,
          covered_from: s.covered_from,
          covered_to_exclusive: s.covered_to_exclusive,
          shortfall: s.shortfall,
          in_progress_quarter: s.in_progress_quarter,
          // Codex-F1 (dry-bar round 7): serialize the definitive at-cap boolean
          // ONLY when it was actually computed; otherwise the explicit
          // not-determinable marker (never a flattering definitive `false`).
          ...(s.retention_at_cap_determinable
            ? { retention_at_cap: s.retention_at_cap }
            : { retention_at_cap_determinable: false as const }),
          // P1/P3 (Dry-9): an empty span always carries the marker; omitted
          // (never `false`) for a normally-covered quarter so the shipped shape
          // is unchanged.
          ...(zeroCovered ? { zero_of_quarter_covered: true as const } : {}),
          // G-1 follow-up: carry the (normalized) daemon disclosure so
          // `shortfall: false` is never read as a complete-census signal when a
          // present daemon store was excluded.
          daemon_store: {
            status,
            ...(s.daemon_store?.unreadable_reason
              ? { unreadable_reason: s.daemon_store.unreadable_reason }
              : {}),
          },
        };
      },
      emptyVerified: () => ({
        determinable: false,
        reason: "the coverage window could not be determined.",
      }),
      readFailed: (reason) => ({ determinable: false, reason }),
    }
  );
}

/**
 * Build the complete in-memory evidence pack. Every read-dependent claim flows
 * through a {@link ReadOutcome}, so a `read_failed` source renders incomplete
 * language and NEVER a definitive negative.
 */
export function buildEvidencePack(
  input: EvidencePackInput,
  deps: BuildEvidencePackDeps
): EvidencePack {
  const window = quarterWindow(input.quarter);
  const generatedAt = input.generated_at_override ?? new Date().toISOString();

  // Derive the aggregation + shortfall from the audit read. Both are
  // read_failed exactly when the audit read is - a failed read can never
  // produce a zero-count aggregation or a "full quarter covered" bound.
  const aggregation = foldOutcome<AuditReadData, ReadOutcome<QuarterAggregation>>(
    deps.audit,
    {
      populated: (data) => populated(aggregateQuarter(data.entries, window)),
      emptyVerified: () =>
        readFailed("the audit log read returned no verifiable result."),
      readFailed: (reason) => readFailed(reason),
    }
  );
  const shortfall = foldOutcome<AuditReadData, ReadOutcome<ShortfallReport>>(
    deps.audit,
    {
      populated: (data) => {
        const lastEntryAt =
          aggregation.status === "populated"
            ? aggregation.value.last_entry_at
            : null;
        const report = detectShortfall(window, data.retention, {
          generatedAt,
          lastEntryAt,
          // D9C-1: bound the attested window at the census cut so it never
          // post-dates the operations actually counted.
          censusTakenAt: data.census_taken_at,
        });
        // G-2: the §7 daemon note renders "N merged into the counts above". The
        // counts above are quarter-windowed, so N must be the daemon entries
        // that fall INSIDE the window, not the all-time total the read layer
        // recorded. Compute it here, where the window is known.
        if (
          report.daemon_store?.status === "included" &&
          data.daemon_entries !== undefined
        ) {
          const windowed = data.daemon_entries.reduce(
            (n, e) => (isInWindow(e.timestamp, window) ? n + 1 : n),
            0
          );
          report.daemon_store = {
            ...report.daemon_store,
            windowed_entry_count: windowed,
          };
        }
        return populated(report);
      },
      emptyVerified: () =>
        readFailed("the audit log read returned no verifiable result."),
      readFailed: (reason) => readFailed(reason),
    }
  );

  const custody: ReadOutcome<CustodyFacts> =
    input.custody ?? readFailed("custody facts were not supplied for this pack.");
  const inventory = input.inventory;
  const discrete = input.discrete_exports ?? defaultDiscreteExports();

  const sections = renderSections({
    input,
    window,
    generatedAt,
    signerDid: deps.signer.did,
    productName: PRODUCT_NAME,
    aggregation,
    shortfall,
    custody,
    inventory,
    discreteExports: {
      transparency: { outcome: discrete.transparency, filename: TRANSPARENCY_BUNDLE_FILENAME },
      audit_chain: { outcome: discrete.audit_chain, filename: AUDIT_CHAIN_FILENAME },
      anchor: { outcome: discrete.anchor, filename: ANCHOR_EVIDENCE_FILENAME },
    },
  });

  // The signed Markdown report concatenates every section with a horizontal
  // rule between them. This is the artifact the manifest signs; the PDF is a
  // human-readable render of the same sections.
  const reportMarkdown =
    sections.map((s) => s.markdown).join("\n\n---\n\n") + "\n";

  const ds = makePackSigner(deps.signer, deps.masterKey);
  const reportFile: EvidencePackFile = signFile(
    REPORT_FILENAME,
    reportMarkdown,
    "text/markdown",
    ds
  );
  const files: EvidencePackFile[] = [reportFile];

  // Sign each gathered discrete export into the manifest (only the populated
  // ones) so the whole output directory is tamper-evident under one manifest.
  // The transparency bundle ALSO carries its own Castle Wall signatures.
  if (discrete.transparency.status === "populated") {
    files.push(
      signFile(TRANSPARENCY_BUNDLE_FILENAME, discrete.transparency.value, "application/json", ds)
    );
  }
  if (discrete.audit_chain.status === "populated") {
    files.push(
      signFile(AUDIT_CHAIN_FILENAME, discrete.audit_chain.value, "application/jsonl", ds)
    );
  }
  if (discrete.anchor.status === "populated") {
    files.push(
      signFile(ANCHOR_EVIDENCE_FILENAME, discrete.anchor.value, "application/json", ds)
    );
  }

  // Manifest coverage: derived through the SINGLE serialization chokepoint so
  // the SIGNED artifact and the prose read the same honesty-guarded values (P1
  // not-determinable fail-closed, P2 normalized daemon status, P3 empty-span
  // marker). See serializeManifestCoverage above.
  const coverage = serializeManifestCoverage(shortfall);

  const manifest = buildPackManifest({
    productName: PRODUCT_NAME,
    firmName: input.firm_name,
    window,
    generatedAt,
    signer: deps.signer,
    files,
    coverage,
    ds,
  });

  // R2-2 (dry-bar): the footer digest is the REPORT file's SHA-256
  // (`reportFile.sha256`), not the manifest's, so the label must say "Report
  // SHA-256". The shared PDF builder defaults the label to "Manifest SHA-256"
  // (correct for the EU AI Act bundle it was written for); passing the label
  // explicitly keeps this pack's footer from claiming to show the manifest hash.
  const pdf = renderMarkdownDocumentsToPdf(
    sections.map((s) => ({ title: s.title, markdown: s.markdown })),
    {
      footerLabel: PRODUCT_NAME,
      footerDigest: reportFile.sha256,
      footerDigestLabel: "Report SHA-256",
    }
  );

  return { manifest, files, pdf, aggregation, shortfall };
}
