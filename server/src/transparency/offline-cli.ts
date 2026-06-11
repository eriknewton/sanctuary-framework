#!/usr/bin/env node
/**
 * Standalone offline transparency verifier.
 *
 * This entrypoint is intentionally smaller than `sanctuary verify-transparency`:
 * it verifies exported bundles with a caller-supplied key and does not import
 * fortress storage, audit-log, or server runtime modules. Host-side
 * `--against-log` checks stay on the full Sanctuary CLI.
 */

import { readFile } from "node:fs/promises";
import { stdout, stderr, exit, argv } from "node:process";
import type { Writable } from "node:stream";

import {
  verifyTransparencyCheckpoints,
  type TransparencyVerifyReport,
} from "./verify.js";

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
      ["--input", "--public-key", "--public-key-file"],
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
  const payload = {
    ...report,
    ...(publicKeySource ? { public_key_source: publicKeySource } : {}),
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
    throw new Error(`unknown option: ${arg}`);
  }
  return { values, flags };
}

function decodeKeyBytes(bytes: Uint8Array): string {
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
  report: TransparencyVerifyReport & { public_key_source?: string }
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
  --json                    Emit the full report as JSON.

Host check: this standalone artifact is offline-only. To recompute the latest
checkpoint against the live audit log, run "sanctuary verify-transparency
--against-log" on the fortress host.

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
