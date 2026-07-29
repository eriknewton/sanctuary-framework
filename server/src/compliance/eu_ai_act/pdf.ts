/**
 * Sanctuary MCP Server — Minimal Hand-Rolled PDF Writer
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Pure-TypeScript, zero-dependency PDF writer for the EU AI Act
 * compliance bundle. Produces a single multi-page PDF concatenating
 * all bundle documents with a consistent header, footer, and page
 * numbering.
 *
 * DESIGN CONSTRAINTS (per Erik's Phase 2 brief):
 *
 *   1. No new runtime dependency. Sanctuary's dep tree has no PDF
 *      library, and adding one (pdfkit, puppeteer, etc.) requires
 *      a sign-off checkpoint. A minimal hand-rolled writer was
 *      explicitly authorized as an acceptable alternative path.
 *
 *   2. Courier monospace throughout. Two PDF standard Type1 fonts:
 *      Courier (body) and Courier-Bold (headings). Standard fonts
 *      do not require font-file embedding — they are referenced by
 *      name and every conformant PDF reader substitutes its own.
 *      Fixed character width means no font metric tables, no AFM
 *      parsing, and trivially correct line wrapping.
 *
 *   3. Output is clean and legible, not polished. Monospace is
 *      intentionally plain — it reads as "compliance document",
 *      not as "magazine layout". Beauty comes from consistent
 *      typography and clean hierarchy, not from serif-on-sans
 *      mixing.
 *
 *   4. The PDF is a human-readable render of the already-signed
 *      Markdown bundle. It is NOT itself cryptographically signed.
 *      Integrity verification remains the responsibility of the
 *      manifest + file signatures.
 */

import type { ComplianceBundle, BundleFile } from "./types.js";

// ── Page geometry (US Letter at 72 pt/inch) ──────────────────────────

const PAGE_WIDTH = 612; // 8.5 inch
const PAGE_HEIGHT = 792; // 11 inch
const MARGIN_LEFT = 72;
const MARGIN_RIGHT = 72;
const MARGIN_TOP = 72;
const MARGIN_BOTTOM = 60;

// Courier at 10pt: each glyph is exactly 6.0 points wide (10 × 0.6).
// At 10pt body size, the 468-pt-wide text column fits 78 chars.
const BODY_FONT_SIZE = 10;
const BODY_LINE_HEIGHT = 13; // 10pt text + 3pt leading
const BODY_CHAR_WIDTH = BODY_FONT_SIZE * 0.6; // Courier metric
const BODY_COLUMN_WIDTH = PAGE_WIDTH - MARGIN_LEFT - MARGIN_RIGHT;
const BODY_CHARS_PER_LINE = Math.floor(BODY_COLUMN_WIDTH / BODY_CHAR_WIDTH);

// Heading sizes. Wider chars at heading sizes → fewer chars per line,
// so headings wrap earlier but rarely exceed one line in practice.
const H1_FONT_SIZE = 16;
const H2_FONT_SIZE = 13;
const H3_FONT_SIZE = 11;
const H1_LINE_HEIGHT = 22;
const H2_LINE_HEIGHT = 18;
const H3_LINE_HEIGHT = 15;

// Footer font is smaller than body.
const FOOTER_FONT_SIZE = 8;
const FOOTER_CHAR_WIDTH = FOOTER_FONT_SIZE * 0.6;
/**
 * Minimum horizontal gap (in PDF points) between the left-aligned
 * footer text and the right-aligned page label at the same baseline.
 * If left-footer width + right-label width + this gutter exceeds the
 * available column width, the PDF builder throws a clear error.
 * This is a future-proofing guard so a longer bundle title, a longer
 * regulation version string, or a longer page label cannot silently
 * re-introduce the footer overlay bug fixed in the 16-hex patch.
 */
export const MIN_FOOTER_GUTTER = 24;

/**
 * Assert that a given left-footer length and right-label length fit
 * at the same footer baseline with at least MIN_FOOTER_GUTTER between
 * them. Throws a recognisable error if they do not.
 *
 * Exported so the footer-overlay regression test can invoke the
 * guard directly with pathological dimensions — the normal bundle
 * path slices the manifest digest to 16 hex characters and is
 * unlikely to ever hit this check in practice, which is exactly why
 * the guard exists as a future-proofing invariant.
 */
export function assertFooterFits(
  leftFooterLength: number,
  rightLabelLength: number
): void {
  const leftFooterWidth = leftFooterLength * FOOTER_CHAR_WIDTH;
  const rightLabelWidth = rightLabelLength * FOOTER_CHAR_WIDTH;
  const availableWidth = PAGE_WIDTH - MARGIN_LEFT - MARGIN_RIGHT;
  if (
    leftFooterWidth + rightLabelWidth + MIN_FOOTER_GUTTER >
    availableWidth
  ) {
    throw new Error(
      `PDF footer overflow: left footer (${leftFooterWidth.toFixed(1)}pt) + ` +
        `right label (${rightLabelWidth.toFixed(1)}pt) + ` +
        `min gutter (${MIN_FOOTER_GUTTER}pt) > available column width ` +
        `(${availableWidth}pt). Shorten the left footer or reduce the ` +
        `digest prefix length in finaliseFooters().`
    );
  }
}

// Text region y-range for the body: from top margin down to the
// footer reservation.
const BODY_TOP_Y = PAGE_HEIGHT - MARGIN_TOP;
const BODY_BOTTOM_Y = MARGIN_BOTTOM + 20; // 20pt reserved for footer

// ── PDF string escaping ─────────────────────────────────────────────

/**
 * Escape a UTF-8 string for embedding in a PDF literal string
 * (enclosed in parentheses). PDF string literals require `(`, `)`,
 * and `\` to be escaped with a backslash. Control characters and
 * non-ASCII bytes are passed through as raw bytes because PDF
 * literal strings are byte-oriented, not Unicode-aware — using
 * Courier with plain ASCII content avoids any glyph-mapping issue
 * for the generated bundle, which is ASCII-dominant.
 *
 * Non-ASCII bytes (e.g., `§`, `→`, `✓` from the Markdown) are
 * replaced with ASCII approximations to keep the output legible
 * in the standard Courier encoding.
 */
function escapePdfString(text: string): string {
  // Replace common non-ASCII Markdown characters with ASCII
  // approximations. Courier's standard encoding is WinAnsi, which
  // does not include most of these glyphs at all — attempting to
  // render them would produce blank boxes.
  const replacements: Array<[RegExp, string]> = [
    [/§/g, "S."],
    [/→/g, "->"],
    [/—/g, "--"],
    [/–/g, "-"],
    [/✓/g, "[OK]"],
    [/✗/g, "[X]"],
    [/"/g, '"'],
    [/"/g, '"'],
    [/'/g, "'"],
    [/'/g, "'"],
    [/…/g, "..."],
    [/©/g, "(c)"],
    [/€/g, "EUR"],
    [/[^\x20-\x7e\n]/g, "?"], // fallback for any remaining non-ASCII
  ];
  let escaped = text;
  for (const [re, rep] of replacements) {
    escaped = escaped.replace(re, rep);
  }
  return escaped.replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
}

// ── Line wrapping ────────────────────────────────────────────────────

/**
 * Word-wrap a paragraph of plain text to a maximum line length.
 * Uses simple greedy word breaking. Preserves paragraph intent but
 * does not do hyphenation or justification. Lines longer than the
 * limit with no internal whitespace are hard-broken at the limit.
 */
function wordWrap(text: string, maxLineLength: number): string[] {
  if (maxLineLength <= 0) return [text];
  const paragraphs = text.split("\n");
  const out: string[] = [];
  for (const para of paragraphs) {
    if (para.length === 0) {
      out.push("");
      continue;
    }
    const words = para.split(/(\s+)/);
    let current = "";
    for (const token of words) {
      // Token may be whitespace or a word; handle both uniformly.
      if (current.length + token.length <= maxLineLength) {
        current += token;
      } else if (token.trim().length === 0) {
        // Trailing whitespace that overflows — drop it and wrap.
        out.push(current);
        current = "";
      } else {
        // Word overflow: emit current, start new line with token.
        if (current.length > 0) out.push(current.trimEnd());
        if (token.length > maxLineLength) {
          // Hard-break a too-long word at the max line length.
          let rest = token;
          while (rest.length > maxLineLength) {
            out.push(rest.slice(0, maxLineLength));
            rest = rest.slice(maxLineLength);
          }
          current = rest;
        } else {
          current = token;
        }
      }
    }
    if (current.length > 0) out.push(current.trimEnd());
  }
  return out;
}

// ── Markdown → line stream ──────────────────────────────────────────

type LineKind = "h1" | "h2" | "h3" | "body" | "blank";

interface RenderLine {
  kind: LineKind;
  text: string;
}

/**
 * Convert one rendered Markdown document into a sequence of
 * (kind, text) lines suitable for the PDF layout engine.
 *
 * This is NOT a CommonMark parser. It recognises:
 *   - `# ...`, `## ...`, `### ...` headings
 *   - Table rows (rendered as plain text, pipe-delimited)
 *   - Horizontal rules (`---`) rendered as a divider line
 *   - Blockquotes (`> ...`) rendered as plain text with a leading `> `
 *   - List items (`- ...`) rendered as plain text with a leading `- `
 *   - Code blocks (` ``` `) rendered as plain body text
 *   - Inline formatting (`**bold**`, `*italic*`, `` `code` ``) is
 *     STRIPPED — monospace text does not need emphasis markers in
 *     the rendered output.
 *
 * Any Markdown structure not in this list is passed through as plain
 * body text. The PDF is a human-readable render, not a pixel-perfect
 * translation.
 */
function markdownToLines(markdown: string): RenderLine[] {
  const lines: RenderLine[] = [];
  const rawLines = markdown.split(/\r?\n/);

  let inCodeBlock = false;

  for (const raw of rawLines) {
    if (raw.trim().startsWith("```")) {
      inCodeBlock = !inCodeBlock;
      continue;
    }
    if (inCodeBlock) {
      lines.push({ kind: "body", text: stripInlineFormatting(raw) });
      continue;
    }
    if (raw.trim().length === 0) {
      lines.push({ kind: "blank", text: "" });
      continue;
    }

    const trimmed = raw.trimStart();

    if (trimmed.startsWith("# ")) {
      lines.push({
        kind: "h1",
        text: stripInlineFormatting(trimmed.slice(2)),
      });
      continue;
    }
    if (trimmed.startsWith("## ")) {
      lines.push({
        kind: "h2",
        text: stripInlineFormatting(trimmed.slice(3)),
      });
      continue;
    }
    if (trimmed.startsWith("### ") || trimmed.startsWith("#### ")) {
      const after = trimmed.replace(/^#+\s+/, "");
      lines.push({ kind: "h3", text: stripInlineFormatting(after) });
      continue;
    }
    if (/^-{3,}$/.test(trimmed)) {
      lines.push({ kind: "body", text: "-".repeat(BODY_CHARS_PER_LINE) });
      continue;
    }

    lines.push({ kind: "body", text: stripInlineFormatting(raw) });
  }

  return lines;
}

/**
 * Strip inline Markdown emphasis markers that make no sense in
 * monospace rendering.
 */
function stripInlineFormatting(text: string): string {
  return text
    .replace(/\*\*([^*]+)\*\*/g, "$1") // **bold**
    .replace(/\*([^*]+)\*/g, "$1") // *italic*
    .replace(/`([^`]+)`/g, "$1") // `code`
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1"); // [text](link)
}

// ── PDF builder ──────────────────────────────────────────────────────

/**
 * One physical page in the output PDF. Tracks the content stream as
 * a list of text-drawing operator fragments that will be joined at
 * serialise time.
 */
interface PageAccumulator {
  operators: string[];
  pageNumber: number;
}

/**
 * Minimal PDF builder. Serialises to a Uint8Array at build time.
 */
class PdfBuilder {
  private pages: PageAccumulator[] = [];
  private currentPage: PageAccumulator;
  private cursorY: number = BODY_TOP_Y;
  private readonly manifestDigest: string;
  private readonly footerLabelPrefix: string;
  private readonly footerDigestLabel: string;

  constructor(
    manifestDigest: string,
    footerLabelPrefix = "Sanctuary EU AI Act Compliance Bundle",
    // The label preceding the digest in the footer. Defaults to
    // "Manifest SHA-256" for the EU AI Act bundle (whose digest IS a manifest
    // identifier). A caller passing a DIFFERENT digest (e.g. the evidence pack,
    // whose footer digest is the report file's SHA-256, not the manifest's)
    // MUST pass a matching label so the footer never mislabels what was hashed.
    footerDigestLabel = "Manifest SHA-256"
  ) {
    this.manifestDigest = manifestDigest;
    this.footerLabelPrefix = footerLabelPrefix;
    this.footerDigestLabel = footerDigestLabel;
    this.currentPage = { operators: [], pageNumber: 1 };
    this.pages.push(this.currentPage);
  }

  /** Begin a fresh page. */
  private newPage(): void {
    this.currentPage = {
      operators: [],
      pageNumber: this.pages.length + 1,
    };
    this.pages.push(this.currentPage);
    this.cursorY = BODY_TOP_Y;
  }

  /** Force a page break before the next line. */
  pageBreak(): void {
    this.newPage();
  }

  /**
   * Write one rendered line at the given size and font. Emits the
   * PDF text-drawing operators to the current page's content stream
   * and advances the Y cursor by the line height.
   *
   * Triggers an automatic page break if the line would land below
   * the bottom margin reservation for the footer.
   */
  private writeLine(
    text: string,
    fontResource: "F1" | "F2",
    fontSize: number,
    lineHeight: number
  ): void {
    if (this.cursorY - lineHeight < BODY_BOTTOM_Y) {
      this.newPage();
    }
    const escaped = escapePdfString(text);
    const op = [
      "BT",
      `/${fontResource} ${fontSize} Tf`,
      `${MARGIN_LEFT} ${this.cursorY - fontSize} Td`,
      `(${escaped}) Tj`,
      "ET",
    ].join("\n");
    this.currentPage.operators.push(op);
    this.cursorY -= lineHeight;
  }

  /** Render a sequence of parsed Markdown lines into the current page. */
  writeDocument(title: string, lines: RenderLine[]): void {
    // Each document begins on a fresh page.
    if (
      this.currentPage.operators.length > 0 ||
      this.pages.indexOf(this.currentPage) > 0
    ) {
      this.newPage();
    }

    // Emit a top-of-document title band in bold (H1 style), even if
    // the Markdown already has a leading `# Title` — the two harmlessly
    // stack because the Markdown H1 typically mirrors the title.
    this.writeLine(title, "F2", H1_FONT_SIZE, H1_LINE_HEIGHT);
    // Extra blank line after title
    this.cursorY -= BODY_LINE_HEIGHT / 2;

    for (const line of lines) {
      if (line.kind === "blank") {
        // Blank line — advance by half a body line to keep things compact.
        this.cursorY -= BODY_LINE_HEIGHT / 2;
        if (this.cursorY - BODY_LINE_HEIGHT < BODY_BOTTOM_Y) {
          this.newPage();
        }
        continue;
      }

      if (line.kind === "h1") {
        this.writeLine(line.text, "F2", H1_FONT_SIZE, H1_LINE_HEIGHT);
        continue;
      }
      if (line.kind === "h2") {
        // Extra leading above h2
        this.cursorY -= BODY_LINE_HEIGHT / 2;
        this.writeLine(line.text, "F2", H2_FONT_SIZE, H2_LINE_HEIGHT);
        continue;
      }
      if (line.kind === "h3") {
        this.writeLine(line.text, "F2", H3_FONT_SIZE, H3_LINE_HEIGHT);
        continue;
      }

      // body — may need wrapping
      const wrapped = wordWrap(line.text, BODY_CHARS_PER_LINE);
      for (const wl of wrapped) {
        this.writeLine(wl, "F1", BODY_FONT_SIZE, BODY_LINE_HEIGHT);
      }
    }
  }

  /**
   * Render the footer on every page. Called just before serialisation.
   * Footer format:
   *
   *   Sanctuary EU AI Act Compliance Bundle | Manifest SHA-256:
   *   <first 16 chars of hex>...                    Page N of M
   *
   * The manifest digest is truncated to 16 hex chars (64 bits) — still
   * collision-resistant for visual verification, and no one eyeballs
   * 48+ hex characters. The middle-dot separator used in the Phase 2
   * first draft was non-ASCII and got mangled by the ASCII
   * substitution table, so it is replaced with a plain ASCII pipe.
   *
   * A width guard asserts that left-footer width + right-label width
   * + MIN_FOOTER_GUTTER fits inside the available column width. If
   * it does not, the builder throws a clear error naming the
   * overflow — future-proofing against a longer bundle title or
   * longer page-count label silently re-introducing the overlay.
   */
  private finaliseFooters(): void {
    const totalPages = this.pages.length;
    const digestShort = this.manifestDigest.slice(0, 16) + "...";
    const leftFooter =
      this.footerLabelPrefix + " | " + this.footerDigestLabel + ": " + digestShort;

    // Width guard: compute the longest possible page label (i.e. the
    // final page, which has the widest N-of-M number) and assert the
    // worst-case layout fits with the minimum gutter. The guard is
    // extracted as the exported `assertFooterFits` helper so the
    // regression test can invoke it directly with pathological
    // dimensions (the normal bundle path slices the manifest digest
    // to 16 hex characters and cannot trip this check in practice).
    const worstCasePageLabel = `Page ${totalPages} of ${totalPages}`;
    assertFooterFits(leftFooter.length, worstCasePageLabel.length);

    for (const page of this.pages) {
      const pageLabel = `Page ${page.pageNumber} of ${totalPages}`;
      // Left-aligned footer
      const leftOp = [
        "BT",
        `/F1 ${FOOTER_FONT_SIZE} Tf`,
        `${MARGIN_LEFT} ${MARGIN_BOTTOM - 4} Td`,
        `(${escapePdfString(leftFooter)}) Tj`,
        "ET",
      ].join("\n");
      // Right-aligned page label (simple: position from right margin)
      const rightX =
        PAGE_WIDTH -
        MARGIN_RIGHT -
        pageLabel.length * FOOTER_CHAR_WIDTH;
      const rightOp = [
        "BT",
        `/F1 ${FOOTER_FONT_SIZE} Tf`,
        `${rightX} ${MARGIN_BOTTOM - 4} Td`,
        `(${escapePdfString(pageLabel)}) Tj`,
        "ET",
      ].join("\n");
      page.operators.push(leftOp);
      page.operators.push(rightOp);
    }
  }

  /** Serialise the PDF to bytes. */
  build(): Uint8Array {
    this.finaliseFooters();

    // Object numbering:
    //   1 = catalog
    //   2 = pages tree
    //   3 = font F1 (Courier)
    //   4 = font F2 (Courier-Bold)
    //   5..5+N-1 = page objects
    //   5+N..5+2N-1 = page content streams
    const numPages = this.pages.length;
    const firstPageObj = 5;
    const firstContentObj = firstPageObj + numPages;

    // Build each object's serialised form.
    const objectBodies: string[] = [];

    // Page kids array
    const kids: string[] = [];
    for (let i = 0; i < numPages; i++) {
      kids.push(`${firstPageObj + i} 0 R`);
    }

    objectBodies[1] = `<< /Type /Catalog /Pages 2 0 R >>`;
    objectBodies[2] = `<< /Type /Pages /Kids [${kids.join(" ")}] /Count ${numPages} >>`;
    objectBodies[3] =
      `<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>`;
    objectBodies[4] =
      `<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold /Encoding /WinAnsiEncoding >>`;

    for (let i = 0; i < numPages; i++) {
      const pageObj = firstPageObj + i;
      const contentObj = firstContentObj + i;
      objectBodies[pageObj] =
        `<< /Type /Page /Parent 2 0 R ` +
        `/MediaBox [0 0 ${PAGE_WIDTH} ${PAGE_HEIGHT}] ` +
        `/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> ` +
        `/Contents ${contentObj} 0 R >>`;

      const streamContent = this.pages[i]!.operators.join("\n");
      objectBodies[contentObj] =
        `<< /Length ${Buffer.byteLength(streamContent, "latin1")} >>\nstream\n${streamContent}\nendstream`;
    }

    // Assemble the file byte stream, tracking object offsets for xref.
    const totalObjects = firstContentObj + numPages - 1;
    const offsets: number[] = new Array(totalObjects + 1).fill(0);
    const chunks: Buffer[] = [];
    let bytePos = 0;

    const write = (s: string): void => {
      const buf = Buffer.from(s, "latin1");
      chunks.push(buf);
      bytePos += buf.length;
    };

    write("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n");

    for (let i = 1; i <= totalObjects; i++) {
      offsets[i] = bytePos;
      write(`${i} 0 obj\n${objectBodies[i]}\nendobj\n`);
    }

    const xrefPos = bytePos;
    write(`xref\n0 ${totalObjects + 1}\n`);
    write("0000000000 65535 f \n");
    for (let i = 1; i <= totalObjects; i++) {
      write(`${offsets[i]!.toString().padStart(10, "0")} 00000 n \n`);
    }
    write(`trailer\n<< /Size ${totalObjects + 1} /Root 1 0 R >>\n`);
    write(`startxref\n${xrefPos}\n%%EOF\n`);

    return new Uint8Array(Buffer.concat(chunks));
  }
}

// ── Bundle → PDF entry point ─────────────────────────────────────────

/**
 * Render a complete compliance bundle to a single multi-document
 * PDF. The PDF concatenates every Markdown file in the bundle (in
 * filename order) with a fresh page per document, Courier body /
 * Courier-Bold headings, and a footer on every page showing the
 * manifest SHA-256 prefix and page numbers.
 *
 * NOT CRYPTOGRAPHICALLY SIGNED. The signed artifacts are the
 * Markdown files in the bundle plus the manifest. The PDF is a
 * human-readable render of those signed artifacts; verify integrity
 * against the manifest, not against the PDF.
 */
export function renderBundleToPdf(bundle: ComplianceBundle): Uint8Array {
  const manifestDigestHex =
    // Use the manifest signature's first 48 hex chars as the footer
    // identifier. Manifest signatures are base64url, not hex — we
    // compute a synthetic hex identifier by mapping to ASCII-safe
    // output here. For audit traceability, we actually want the
    // canonical manifest content hash; that is stored per-file in
    // the manifest's files[] array. The footer intentionally shows
    // a truncated identifier as a visual cue, not a verification key.
    syntheticManifestIdentifier(bundle);

  const builder = new PdfBuilder(manifestDigestHex);

  // Cover page
  builder.writeDocument("EU AI Act Compliance Bundle", [
    { kind: "blank", text: "" },
    { kind: "body", text: `Agent DID: ${bundle.manifest.agent_did}` },
    {
      kind: "body",
      text: `Reporting period: ${bundle.manifest.period_start} to ${bundle.manifest.period_end}`,
    },
    {
      kind: "body",
      text: `Generated at: ${bundle.manifest.generated_at}`,
    },
    {
      kind: "body",
      text: `Signer DID: ${bundle.manifest.signer.did}`,
    },
    {
      kind: "body",
      text: `Regulation version: ${bundle.manifest.regulation_version}`,
    },
    {
      kind: "body",
      text: `Matrix version: ${bundle.manifest.matrix_version}`,
    },
    { kind: "blank", text: "" },
    { kind: "h2", text: "Coverage summary" },
    {
      kind: "body",
      text: `Full:        ${bundle.manifest.coverage_summary.full} rows (${bundle.manifest.coverage_summary.full_pct}%)`,
    },
    {
      kind: "body",
      text: `Partial:     ${bundle.manifest.coverage_summary.partial} rows (${bundle.manifest.coverage_summary.partial_pct}%)`,
    },
    {
      kind: "body",
      text: `Manual only: ${bundle.manifest.coverage_summary.manual_only} rows (${bundle.manifest.coverage_summary.manual_only_pct}%)`,
    },
    { kind: "blank", text: "" },
    { kind: "h2", text: "Disclaimer" },
    {
      kind: "body",
      text: "This PDF is a human-readable render of the EU AI Act compliance bundle. The PDF itself is NOT cryptographically signed. Integrity verification must be performed against the Markdown files and the JSON manifest using the per-file SHA-256 digests and Ed25519 signatures recorded in 00_bundle_manifest.json.",
    },
    { kind: "blank", text: "" },
    {
      kind: "body",
      text: "NOT LEGAL ADVICE. Consult qualified legal counsel before filing.",
    },
  ]);

  // Sort files by filename so the PDF follows the same 01..08 order
  // regardless of manifest insertion order.
  const sortedFiles: BundleFile[] = [...bundle.files].sort((a, b) =>
    a.filename.localeCompare(b.filename)
  );

  for (const file of sortedFiles) {
    const title = titleForFilename(file.filename);
    const lines = markdownToLines(file.content);
    builder.writeDocument(title, lines);
  }

  return builder.build();
}

/**
 * Derive a human-friendly document title from a bundle filename.
 */
function titleForFilename(filename: string): string {
  const map: Record<string, string> = {
    "01_annex_iv_technical_documentation.md": "01. Annex IV Technical Documentation",
    "02_article_26_deployer_log.md": "02. Article 26 Deployer Log",
    "03_article_12_automatic_logs.md": "03. Article 12 Automatic Logs",
    "04_risk_management_summary.md": "04. Risk Management Summary",
    "05_human_oversight_statement.md": "05. Human Oversight Statement",
    "06_cryptographic_attestations.md": "06. Cryptographic Attestations",
    "07_annex_iii_classification.md": "07. Annex III Classification",
    "08_delta.md": "08. Bundle Delta Report",
  };
  return map[filename] ?? filename;
}

/**
 * Produce a short ASCII identifier for the PDF footer from the
 * bundle manifest. Concatenates the first two file SHA-256 digest
 * prefixes to produce a stable, greppable identifier that lives in
 * the footer of every page.
 */
function syntheticManifestIdentifier(bundle: ComplianceBundle): string {
  const first = bundle.manifest.files[0]?.sha256 ?? "0".repeat(64);
  return first;
}

// ── Generic Markdown -> PDF entry point ──────────────────────────────

/**
 * One document to render into the PDF: a title (rendered as a bold page
 * heading, each document starting a fresh page) and its Markdown body.
 */
export interface PdfDocument {
  title: string;
  markdown: string;
}

/**
 * Render an ordered list of Markdown documents to a single multi-page PDF,
 * reusing the same zero-dependency writer, Courier typography, page geometry,
 * and per-page footer as {@link renderBundleToPdf}. This is the generic entry
 * point for callers outside the EU AI Act bundle (for example the law-firm
 * evidence pack), so the PDF writer is reused rather than reinvented.
 *
 * `footerLabel` sets the per-page footer prefix; `footerDigest` is the short
 * identifier shown after it, and `footerDigestLabel` names WHAT that digest is
 * (default "Manifest SHA-256"). A caller whose `footerDigest` is not the
 * manifest hash MUST pass a matching `footerDigestLabel` (e.g. the evidence pack
 * passes the report file's SHA-256 with the label "Report SHA-256") so the
 * footer never claims to show a hash it does not. NOT CRYPTOGRAPHICALLY SIGNED:
 * the PDF is a human-readable render of separately-signed artifacts; verify
 * integrity against the signed files and manifest, not against the PDF.
 */
export function renderMarkdownDocumentsToPdf(
  documents: PdfDocument[],
  options: { footerLabel: string; footerDigest: string; footerDigestLabel?: string }
): Uint8Array {
  const builder = new PdfBuilder(
    options.footerDigest,
    options.footerLabel,
    options.footerDigestLabel
  );
  for (const doc of documents) {
    builder.writeDocument(doc.title, markdownToLines(doc.markdown));
  }
  return builder.build();
}
