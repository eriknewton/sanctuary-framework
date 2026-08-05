#!/usr/bin/env node
/**
 * Standalone offline transparency verifier.
 *
 * This entrypoint is intentionally smaller than `sanctuary verify-transparency`:
 * it verifies exported bundles with a caller-supplied key and does not import
 * fortress storage, audit-log, or server runtime modules. Host-side
 * `--against-log` checks stay on the full Sanctuary CLI, and so does the
 * network-touching `--fetch-anchors` mode: this artifact performs NO I/O
 * beyond reading the files it is handed. Anchor evidence (--check-anchors),
 * multi-bundle fork detection (--compare), and the freshness policy
 * (--expect-fresh) all run fully offline here.
 */

import { readFile } from "node:fs/promises";
import { stdout, stderr, exit, argv } from "node:process";
import type { Writable } from "node:stream";

import {
  compareTransparencyChains,
  isVerifierCheckpointRecord,
  verifyTransparencyCheckpoints,
  type TransparencyVerifyReport,
  type VerifierCheckpointRecord,
} from "./verify.js";
import {
  parseFreshnessWindow,
  verifyAnchorEvidence,
  type AnchorCoverage,
} from "./anchor-verify.js";

export const STANDALONE_EXIT_PARTIAL = 10;

interface StandaloneArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
}

interface ParsedFlags {
  values: Record<string, string | undefined>;
  flags: Record<string, boolean>;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

export async function runStandaloneTransparencyVerifier(
  args: StandaloneArgs
): Promise<number> {
  const out = args.out ?? stdout;
  const err = args.err ?? stderr;
  const input = args.argv;

  if (input.includes("--help") || input.includes("-h")) {
    printStandaloneUsage(out);
    return 0;
  }

  let opts: ParsedFlags;
  try {
    opts = parseFlags(
      input,
      [
        "--input",
        "--public-key",
        "--public-key-file",
        "--check-anchors",
        "--rekor-public-key-file",
        "--expect-fresh",
        "--compare",
      ],
      ["--trust-embedded", "--allow-partial", "--json"]
    );
  } catch (error) {
    write(err, `Error: ${error instanceof Error ? error.message : String(error)}\n`);
    printStandaloneUsage(err);
    return 2;
  }

  if (!opts.values["--input"]) {
    write(err, "Error: --input <path> is required\n");
    printStandaloneUsage(err);
    return 2;
  }
  for (const dependent of ["--expect-fresh", "--rekor-public-key-file"] as const) {
    if (opts.values[dependent] && !opts.values["--check-anchors"]) {
      write(err, `Error: ${dependent} requires --check-anchors <anchors.json>\n`);
      return 2;
    }
  }
  let expectFreshMs: number | undefined;
  if (opts.values["--expect-fresh"]) {
    try {
      expectFreshMs = parseFreshnessWindow(opts.values["--expect-fresh"]!);
    } catch (error) {
      write(err, `Error: ${error instanceof Error ? error.message : String(error)}\n`);
      return 2;
    }
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(opts.values["--input"]!, "utf8"));
  } catch (error) {
    write(
      err,
      `Error reading ${opts.values["--input"]}: ${error instanceof Error ? error.message : String(error)}\n`
    );
    return 1;
  }

  let publicKey: string | undefined;
  let publicKeySource: string | undefined;
  try {
    if (opts.values["--public-key"]) {
      publicKey = opts.values["--public-key"];
      publicKeySource = "--public-key flag";
    } else if (opts.values["--public-key-file"]) {
      publicKey = decodeKeyBytes(await readFile(opts.values["--public-key-file"]!));
      publicKeySource = `--public-key-file ${opts.values["--public-key-file"]}`;
    }
  } catch (error) {
    write(
      err,
      `Error reading public key: ${error instanceof Error ? error.message : String(error)}\n`
    );
    return 1;
  }

  const report = verifyTransparencyCheckpoints(parsed, {
    ...(publicKey ? { publicKey } : {}),
    ...(opts.flags["--trust-embedded"] ? { trustEmbedded: true } : {}),
    ...(opts.flags["--allow-partial"] ? { allowPartial: true } : {}),
  });

  // --check-anchors: fully offline anchor-evidence verification.
  let anchorsCoverage: AnchorCoverage | null = null;
  if (opts.values["--check-anchors"]) {
    let anchorsDoc: unknown;
    try {
      anchorsDoc = JSON.parse(
        await readFile(opts.values["--check-anchors"]!, "utf8")
      );
    } catch (error) {
      write(
        err,
        `Error reading ${opts.values["--check-anchors"]}: ${error instanceof Error ? error.message : String(error)}\n`
      );
      return 1;
    }
    let rekorPublicKeyPem: string | undefined;
    if (opts.values["--rekor-public-key-file"]) {
      try {
        rekorPublicKeyPem = await readFile(
          opts.values["--rekor-public-key-file"]!,
          "utf8"
        );
      } catch (error) {
        write(
          err,
          `Error reading Rekor public key: ${error instanceof Error ? error.message : String(error)}\n`
        );
        return 1;
      }
    }
    const anchorResult = verifyAnchorEvidence(extractRecords(parsed), anchorsDoc, {
      ...(rekorPublicKeyPem ? { rekorPublicKeyPem } : {}),
      ...(expectFreshMs !== undefined ? { expectFreshMs } : {}),
    });
    report.findings.push(...anchorResult.findings);
    report.not_checked.push(...anchorResult.not_checked);
    anchorsCoverage = anchorResult.coverage;
  }

  // --compare: offline multi-bundle split-view detection.
  let compareSummary: {
    input: string;
    other_verdict: TransparencyVerifyReport["verdict"];
    relation: string;
    divergent_counter: number | null;
    overlap: { from: number; to: number } | null;
  } | null = null;
  if (opts.values["--compare"]) {
    let otherParsed: unknown;
    try {
      otherParsed = JSON.parse(await readFile(opts.values["--compare"]!, "utf8"));
    } catch (error) {
      write(
        err,
        `Error reading ${opts.values["--compare"]}: ${error instanceof Error ? error.message : String(error)}\n`
      );
      return 1;
    }
    const otherReport = verifyTransparencyCheckpoints(otherParsed, {
      ...(publicKey ? { publicKey } : {}),
      ...(opts.flags["--trust-embedded"] ? { trustEmbedded: true } : {}),
      allowPartial: true,
    });
    if (otherReport.verdict === "FAIL") {
      report.findings.push({
        kind: "compare_input_invalid",
        message: `the comparison bundle ${opts.values["--compare"]} fails verification on its own (${otherReport.findings.length} finding(s)); refusing to draw fork conclusions from unverified evidence`,
      });
    } else {
      const comparison = compareTransparencyChains(
        extractRecords(parsed),
        extractRecords(otherParsed)
      );
      report.findings.push(...comparison.findings);
      report.not_checked.push(...comparison.notes);
      compareSummary = {
        input: opts.values["--compare"]!,
        other_verdict: otherReport.verdict,
        relation: comparison.relation,
        divergent_counter: comparison.divergent_counter,
        overlap: comparison.overlap,
      };
    }
  }

  if (report.findings.length > 0) report.verdict = "FAIL";

  const payload = {
    ...report,
    ...(publicKeySource ? { public_key_source: publicKeySource } : {}),
    ...(anchorsCoverage ? { anchors: anchorsCoverage } : {}),
    ...(compareSummary ? { compare: compareSummary } : {}),
  };

  if (opts.flags["--json"]) {
    write(out, JSON.stringify(payload, null, 2) + "\n");
  } else {
    printHumanReport(out, payload);
  }

  if (report.verdict === "PASS") return 0;
  if (report.verdict === "PARTIAL") return STANDALONE_EXIT_PARTIAL;
  return 1;
}

function parseFlags(
  args: string[],
  valueFlags: string[],
  boolFlags: string[]
): ParsedFlags {
  const values: Record<string, string | undefined> = {};
  const flags: Record<string, boolean> = {};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    const valueFlag = valueFlags.find(
      (name) => arg === name || arg.startsWith(`${name}=`)
    );
    if (valueFlag) {
      if (arg.includes("=")) {
        values[valueFlag] = arg.slice(valueFlag.length + 1);
      } else {
        const value = args[++i];
        if (value === undefined || value.startsWith("--")) {
          throw new Error(`${valueFlag} requires a value`);
        }
        values[valueFlag] = value;
      }
      continue;
    }
    if (boolFlags.includes(arg)) {
      flags[arg] = true;
      continue;
    }
    if (arg === "--against-log" || arg === "--fortress" || arg === "--passphrase") {
      throw new Error(
        `${arg} is host-mode only; use "sanctuary verify-transparency" on the fortress host`
      );
    }
    if (arg === "--fetch-anchors" || arg === "--allow-unsafe-rekor-url") {
      throw new Error(
        `${arg} performs network I/O; this standalone artifact is offline-only. Use "sanctuary verify-transparency --fetch-anchors", or verify the receipt-embedded proofs offline with --check-anchors alone`
      );
    }
    throw new Error(`unknown option: ${arg}`);
  }
  return { values, flags };
}

const STANDALONE_BUNDLE_FORMAT = "SANCTUARY_TRANSPARENCY_BUNDLE_V1";

function extractRecords(parsed: unknown): VerifierCheckpointRecord[] {
  let candidates: unknown[] = [];
  if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
    const candidate = parsed as Record<string, unknown>;
    candidates =
      candidate.format === STANDALONE_BUNDLE_FORMAT &&
      Array.isArray(candidate.checkpoints)
        ? candidate.checkpoints
        : [parsed];
  } else if (Array.isArray(parsed)) {
    candidates = parsed;
  }
  return candidates.filter(isVerifierCheckpointRecord);
}

function decodeKeyBytes(bytes: Uint8Array): string {
  // 32 = RFC 8032 Ed25519 public key. Literal rather than an import because this
  // CLI is part of the standalone offline verifier (see `verify.ts`), which must
  // compile without any Sanctuary server module. Must match
  // `ED25519_PUBLIC_KEY_BYTES` in `core/crypto-suite-registry.ts`.
  if (bytes.length === 32) return toBase64url(bytes);
  const text = Buffer.from(bytes).toString("utf8").trim();
  const decoded = fromBase64url(text);
  if (decoded.length !== 32) {
    throw new Error(
      `public key file must contain raw 32 bytes or a base64url 32-byte key (decoded ${decoded.length} bytes)`
    );
  }
  return text;
}

function fromBase64url(s: string): Uint8Array {
  const pad = (4 - (s.length % 4)) % 4;
  const std = (s + "=".repeat(pad)).replace(/-/g, "+").replace(/_/g, "/");
  return new Uint8Array(Buffer.from(std, "base64"));
}

function toBase64url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function printHumanReport(
  out: Writable,
  report: TransparencyVerifyReport & {
    public_key_source?: string;
    anchors?: AnchorCoverage;
    compare?: {
      input: string;
      other_verdict: TransparencyVerifyReport["verdict"];
      relation: string;
      divergent_counter: number | null;
      overlap: { from: number; to: number } | null;
    };
  }
): void {
  write(out, `Verdict: ${report.verdict}\n`);
  write(
    out,
    `Checkpoints: ${report.checkpoints_verified}` +
      (report.counter_range
        ? ` (counters ${report.counter_range.from}..${report.counter_range.to})`
        : "") +
      `\n`
  );
  write(out, `Signature basis: ${report.signature_basis} key\n`);
  if (report.public_key_source) {
    write(out, `Public key source: ${report.public_key_source}\n`);
  }
  if (report.anchors) {
    const coverage = report.anchors;
    write(
      out,
      `Anchor coverage (log signatures: ${coverage.log_signature_basis === "pinned-rekor-key" ? "verified under pinned log key" : "NOT verified, no pinned log key"}):\n` +
        `  ${coverage.verified} verified, ${coverage.consistent} consistent, ${coverage.unverified} unverified, ${coverage.invalid} invalid, ` +
        `${coverage.anchor_failed} failed-at-anchor-time, ${coverage.unanchored} unanchored ` +
        `(of ${coverage.checkpoints} checkpoint(s))\n`
    );
    if (coverage.log_signature_basis === "none") {
      write(
        out,
        `  anchors checked for internal consistency only (operator-supplied evidence); supply --rekor-public-key-file for log-attested verification\n`
      );
    }
    if (coverage.newest_verified_integrated_time !== null) {
      write(
        out,
        `  newest log-attested anchor: ${new Date(coverage.newest_verified_integrated_time * 1000).toISOString()}\n`
      );
    }
  }
  if (report.compare) {
    write(
      out,
      `Compared against ${report.compare.input} (its verdict: ${report.compare.other_verdict}): ` +
        `relation ${report.compare.relation}` +
        (report.compare.divergent_counter !== null
          ? `, FORK at counter ${report.compare.divergent_counter}`
          : "") +
        (report.compare.overlap
          ? ` (shared counters ${report.compare.overlap.from}..${report.compare.overlap.to})`
          : "") +
        `\n`
    );
  }
  if (report.findings.length > 0) {
    write(out, `Findings (${report.findings.length}):\n`);
    for (const finding of report.findings) {
      write(out, `  [${finding.kind}] ${finding.message}\n`);
    }
  }
  write(out, `Not checked by this run:\n`);
  for (const item of report.not_checked) {
    write(out, `  - ${item}\n`);
  }
}

function printStandaloneUsage(out: Writable): void {
  write(
    out,
    `Usage: node verify-transparency.js --input <path> [options]

Verify an exported Sanctuary enforcement-checkpoint bundle offline with no
fortress, storage directory, passphrase, or Sanctuary server install. Checks:
Ed25519 signatures against the pinned public key, strict counter continuity,
rollback findings, previous-checkpoint hash linkage, key consistency, and
complete-from-genesis by default.

Options:
  --input <path>            Bundle, checkpoint array, or single record (JSON).
  --public-key <key>        Signer public key, base64url (obtained out-of-band).
  --public-key-file <path>  Signer public key file (raw 32 bytes or base64url).
  --trust-embedded          Verify against the key embedded in the records.
                            Proves internal consistency only; stated in output.
  --allow-partial           Accept a suffix fragment not starting at genesis
                            (counter 1). Reports verdict PARTIAL and exits 10,
                            never a clean PASS / exit 0.
  --check-anchors <path>    Verify the operator's exported anchor evidence
                            (salted commitments, Rekor entry binding, RFC 6962
                            inclusion proofs) against this bundle, offline,
                            and report anchor coverage. Without a pinned log
                            key this checks internal consistency of the
                            operator-supplied evidence only; anchors report
                            "consistent", never "verified".
  --rekor-public-key-file <path>
                            Pinned Rekor log public key (SPKI PEM, obtained
                            out-of-band). Enables log-signature verification;
                            required for anchors to count as "verified" and
                            for --expect-fresh.
  --expect-fresh <window>   FAIL unless the newest log-attested anchor is
                            within the window (e.g. 36h, 7d).
  --compare <path>          Verify a second, independently obtained bundle and
                            detect split views (same counter, different signed
                            contents = FORK).
  --json                    Emit the full report as JSON.

Host check: this standalone artifact is offline-only (it performs no network
I/O). To recompute the latest checkpoint against the live audit log, run
"sanctuary verify-transparency --against-log" on the fortress host; to fetch
fresh inclusion proofs from the log, use "sanctuary verify-transparency
--fetch-anchors".

Exit codes: 0 PASS (complete from genesis), 10 PARTIAL (suffix fragment via
--allow-partial; verified but not genesis-rooted), 1 FAIL, 2 usage error.
`
  );
}

if (import.meta.url === `file://${argv[1]}`) {
  runStandaloneTransparencyVerifier({ argv: argv.slice(2) })
    .then((code) => exit(code))
    .catch((error) => {
      write(stderr, `verify-transparency: ${error instanceof Error ? error.message : String(error)}\n`);
      exit(1);
    });
}
