/**
 * sanctuary transparency — verifiable enforcement-checkpoint commands.
 *
 *   sanctuary transparency checkpoint   Emit one signed checkpoint now
 *   sanctuary transparency export      Export a publishable bundle
 *   sanctuary transparency verify      Verify checkpoints (alias below)
 *   sanctuary verify-transparency      Offline/host verification
 *
 * Publishing a bundle (website, repo, anywhere) is an OPERATOR action:
 * nothing here performs network I/O. See docs/transparency.md for what a
 * verifying party can and cannot conclude.
 */

import { realpathSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { join } from "node:path";
import { Writable } from "node:stream";

import { FilesystemStorage } from "../storage/filesystem.js";
import {
  AuditIntegrityError,
  AuditLog,
} from "../l2-operational/audit-log.js";
import {
  deriveMasterKey,
  type KeyDerivationParams,
} from "../core/key-derivation.js";
import { bytesToString, fromBase64url, toBase64url } from "../core/encoding.js";
import { resolveStoragePath } from "../paths.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
import {
  TRANSPARENCY_BUNDLE_FORMAT,
  type TransparencyBundle,
} from "../transparency/checkpoint.js";
import {
  TransparencyEmitError,
  emitEnforcementCheckpoint,
  readPersistedCheckpoints,
} from "../transparency/emitter.js";
import {
  CASTLE_GLOBAL_PINNED_PUBKEY_PATH,
  resolveTransparencySigner,
} from "../transparency/signer.js";
import {
  isVerifierCheckpointRecord,
  verifyTransparencyCheckpoints,
  type TransparencyVerifyReport,
  type VerifierCheckpointRecord,
} from "../transparency/verify.js";
import { verifyAgainstLog } from "../transparency/against-log.js";

const require = createRequire(import.meta.url);
const { version: PKG_VERSION } = require("../../package.json") as {
  version: string;
};

export interface TransparencyCommandArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

export async function runTransparencyCommand(
  args: TransparencyCommandArgs
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const [sub, ...rest] = args.argv;

  if (!sub || sub === "--help" || sub === "-h") {
    printUsage(sub ? out : err);
    return sub ? 0 : 2;
  }
  if (sub === "checkpoint") {
    if (rest.includes("--help") || rest.includes("-h")) {
      printCheckpointUsage(out);
      return 0;
    }
    return runCheckpoint(rest, out, err, args.env ?? process.env);
  }
  if (sub === "export") {
    if (rest.includes("--help") || rest.includes("-h")) {
      printExportUsage(out);
      return 0;
    }
    return runBundleExport(rest, out, err, args.env ?? process.env);
  }
  if (sub === "verify") {
    return runVerifyTransparencyCommand({ ...args, argv: rest });
  }
  write(err, `Unknown transparency command: ${sub}\n`);
  printUsage(err);
  return 2;
}

// ---- checkpoint -------------------------------------------------------------

async function runCheckpoint(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv
): Promise<number> {
  let masterKey: Uint8Array | undefined;
  try {
    const opts = parseFlags(argv, [
      "--fortress",
      "--passphrase",
      "--binary",
    ], ["--local-sign", "--json"]);
    const storagePath = opts.values["--fortress"] ?? resolveStoragePath(env);
    const storage = new FilesystemStorage(join(storagePath, "state"));
    masterKey = await resolveMasterKey(storage, opts.values["--passphrase"], env);
    const auditLog = new AuditLog(storage, masterKey);
    const signer = await resolveTransparencySigner({
      fortressPath: storagePath,
      masterKey,
      env,
      mode: opts.flags["--local-sign"] ? "local" : "auto",
    });
    const binaryPath =
      opts.values["--binary"] ?? realpathSync(process.argv[1] ?? "");
    const record = await emitEnforcementCheckpoint({
      storage,
      auditLog,
      fortressId: fortressIdFromStoragePath(storagePath),
      fortressPath: storagePath,
      masterKey,
      signer,
      binaryPath,
      version: PKG_VERSION,
    });
    // Record the emission in the audit log (covered by the NEXT checkpoint).
    await auditLog.appendCritical({
      layer: "l2",
      operation: "transparency_checkpoint_emitted",
      identity_id: record.fortress_id,
      result: "success",
      details: {
        counter: record.counter,
        merkle_root: record.audit.merkle_root,
        highest_sequence: record.audit.highest_sequence,
        signer_kid: record.signer_kid,
      },
    });
    if (opts.flags["--json"]) {
      write(out, JSON.stringify(record, null, 2) + "\n");
    } else {
      write(
        out,
        `Enforcement checkpoint ${record.counter} emitted.\n` +
          `  audit root     ${record.audit.merkle_root}\n` +
          `  audit window   seq ${record.audit.lowest_sequence}..${record.audit.highest_sequence} (${record.audit.entry_count} entries)\n` +
          `  policy rules   ${record.policy.rules_count} (rules hash ${record.policy.rules_sha256.slice(0, 16)}...)\n` +
          `  enforcement    ${record.enforcement.total_allowed} allowed / ${record.enforcement.total_blocked} blocked\n` +
          `  signer         ${record.signer_kid}\n` +
          `Export a publishable bundle with: sanctuary transparency export\n`
      );
    }
    return 0;
  } catch (error) {
    return reportError(err, "transparency checkpoint", error);
  } finally {
    masterKey?.fill(0);
  }
}

// ---- export -----------------------------------------------------------------

async function runBundleExport(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv
): Promise<number> {
  try {
    const opts = parseFlags(argv, ["--fortress", "--output"], []);
    const storagePath = opts.values["--fortress"] ?? resolveStoragePath(env);
    const storage = new FilesystemStorage(join(storagePath, "state"));
    const checkpoints = await readPersistedCheckpoints(storage);
    if (checkpoints.length === 0) {
      write(
        err,
        "No enforcement checkpoints exist for this fortress. Emit one first: sanctuary transparency checkpoint\n"
      );
      return 1;
    }
    const keys = new Set(checkpoints.map((checkpoint) => checkpoint.public_key));
    if (keys.size > 1) {
      write(
        err,
        `Refusing to export: checkpoints carry ${keys.size} different signing keys. A bundle must verify under one key; investigate the key history before publishing.\n`
      );
      return 1;
    }
    const bundle: TransparencyBundle = {
      format: TRANSPARENCY_BUNDLE_FORMAT,
      exported_at: new Date().toISOString(),
      public_key: checkpoints[0]!.public_key,
      checkpoints,
    };
    const json = JSON.stringify(bundle, null, 2) + "\n";
    if (opts.values["--output"]) {
      await writeFile(opts.values["--output"]!, json, "utf8");
      write(
        err,
        `Exported ${checkpoints.length} checkpoint(s) to ${opts.values["--output"]}\n` +
          `Verify anywhere with: sanctuary verify-transparency --input ${opts.values["--output"]} --public-key <pinned-key>\n` +
          `Publishing the bundle is an operator action; nothing was transmitted.\n`
      );
    } else {
      write(out, json);
    }
    return 0;
  } catch (error) {
    return reportError(err, "transparency export", error);
  }
}

// ---- verify -------------------------------------------------------------------

export async function runVerifyTransparencyCommand(
  args: TransparencyCommandArgs
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;
  const argv = args.argv;

  if (argv.includes("--help") || argv.includes("-h")) {
    printVerifyUsage(out);
    return 0;
  }

  let masterKey: Uint8Array | undefined;
  try {
    const opts = parseFlags(
      argv,
      ["--input", "--public-key", "--public-key-file", "--fortress", "--passphrase"],
      ["--trust-embedded", "--against-log", "--allow-partial", "--json"]
    );
    const inputPath = opts.values["--input"];
    if (!inputPath) {
      write(err, "Error: --input <path> is required\n");
      printVerifyUsage(err);
      return 2;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(await readFile(inputPath, "utf8"));
    } catch (error) {
      write(
        err,
        `Error reading ${inputPath}: ${error instanceof Error ? error.message : String(error)}\n`
      );
      return 1;
    }

    const key = await resolveVerificationKey(opts, env, err);
    if (key.status === "error") return 1;

    const report = verifyTransparencyCheckpoints(parsed, {
      ...(key.publicKey ? { publicKey: key.publicKey } : {}),
      ...(opts.flags["--trust-embedded"] ? { trustEmbedded: true } : {}),
      ...(opts.flags["--allow-partial"] ? { allowPartial: true } : {}),
    });

    let hostResult = null;
    if (opts.flags["--against-log"] && report.checkpoints_verified > 0) {
      const storagePath = opts.values["--fortress"] ?? resolveStoragePath(env);
      const storage = new FilesystemStorage(join(storagePath, "state"));
      // Counter recount needs decryption; optional, honestly noted when absent.
      let auditLog: AuditLog | undefined;
      try {
        masterKey = await resolveMasterKey(
          storage,
          opts.values["--passphrase"],
          env
        );
        auditLog = new AuditLog(storage, masterKey);
      } catch {
        auditLog = undefined;
      }
      const records = extractRecords(parsed);
      hostResult = await verifyAgainstLog({
        records,
        storage,
        ...(auditLog ? { auditLog } : {}),
      });
      report.findings.push(...hostResult.findings);
      if (report.findings.length > 0) report.verdict = "FAIL";
      // Host recomputation upgrades (removes) the corresponding offline caveat.
      if (hostResult.merkle_root_recomputed) {
        report.not_checked = report.not_checked.filter(
          (item) => !item.startsWith("audit-log contents:")
        );
      }
      for (const note of hostResult.notes) report.not_checked.push(note);
    } else if (opts.flags["--against-log"]) {
      report.not_checked.push(
        "host check skipped: no schema-valid checkpoints to check against the log"
      );
    }

    const payload = {
      ...report,
      ...(key.source ? { public_key_source: key.source } : {}),
      ...(hostResult
        ? {
            against_log: {
              checked_counter: hostResult.checked_counter,
              merkle_root_recomputed: hostResult.merkle_root_recomputed,
              counters_recomputed: hostResult.counters_recomputed,
            },
          }
        : {}),
    };
    if (opts.flags["--json"]) {
      write(out, JSON.stringify(payload, null, 2) + "\n");
    } else {
      printHumanReport(out, payload);
    }
    return report.verdict === "PASS" ? 0 : 1;
  } catch (error) {
    return reportError(err, "verify-transparency", error);
  } finally {
    masterKey?.fill(0);
  }
}

function extractRecords(parsed: unknown): VerifierCheckpointRecord[] {
  let candidates: unknown[] = [];
  if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
    const candidate = parsed as Record<string, unknown>;
    candidates =
      candidate.format === TRANSPARENCY_BUNDLE_FORMAT &&
      Array.isArray(candidate.checkpoints)
        ? candidate.checkpoints
        : [parsed];
  } else if (Array.isArray(parsed)) {
    candidates = parsed;
  }
  // Host mode only ever runs over schema-valid records; malformed entries are
  // already findings in the offline report.
  return candidates.filter(isVerifierCheckpointRecord);
}

interface ResolvedKey {
  status: "ok" | "error";
  publicKey?: string;
  source?: string;
}

/**
 * Key resolution order (explicit beats implicit; nothing silent):
 *   1. --public-key <base64url>
 *   2. --public-key-file <path> (raw 32 bytes, or base64url text)
 *   3. the root-owned global Castle Wall pin, when present on this host
 *   4. the fortress-local pin, when present
 *   5. --trust-embedded (explicit opt-in; weaker basis, stated in output)
 */
async function resolveVerificationKey(
  opts: ParsedFlags,
  env: NodeJS.ProcessEnv,
  err: Writable
): Promise<ResolvedKey> {
  if (opts.values["--public-key"]) {
    return {
      status: "ok",
      publicKey: opts.values["--public-key"],
      source: "--public-key flag",
    };
  }
  if (opts.values["--public-key-file"]) {
    const path = opts.values["--public-key-file"]!;
    try {
      const bytes = await readFile(path);
      return {
        status: "ok",
        publicKey: decodeKeyBytes(bytes),
        source: `--public-key-file ${path}`,
      };
    } catch (error) {
      write(
        err,
        `Error reading public key file ${path}: ${error instanceof Error ? error.message : String(error)}\n`
      );
      return { status: "error" };
    }
  }
  if (!opts.flags["--trust-embedded"]) {
    for (const candidate of [
      CASTLE_GLOBAL_PINNED_PUBKEY_PATH,
      join(opts.values["--fortress"] ?? resolveStoragePath(env), "castle-pinned-pubkey.bin"),
    ]) {
      try {
        const bytes = await readFile(candidate);
        if (bytes.length === 32) {
          return {
            status: "ok",
            publicKey: toBase64url(bytes),
            source: `pinned key at ${candidate}`,
          };
        }
      } catch {
        // try next candidate
      }
    }
  }
  // No pinned key. The verifier itself fails closed unless --trust-embedded.
  return { status: "ok" };
}

function decodeKeyBytes(bytes: Uint8Array): string {
  if (bytes.length === 32) return toBase64url(bytes);
  const text = bytesToString(bytes).trim();
  const decoded = fromBase64url(text);
  if (decoded.length !== 32) {
    throw new Error(
      `public key file must contain raw 32 bytes or a base64url 32-byte key (decoded ${decoded.length} bytes)`
    );
  }
  return text;
}

function printHumanReport(
  out: Writable,
  report: TransparencyVerifyReport & {
    public_key_source?: string;
    against_log?: {
      checked_counter: number | null;
      merkle_root_recomputed: boolean;
      counters_recomputed: boolean;
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
  if (report.against_log) {
    write(
      out,
      `Against live log (checkpoint ${report.against_log.checked_counter ?? "n/a"}): ` +
        `merkle root ${report.against_log.merkle_root_recomputed ? "recomputed and MATCHED" : "not recomputed"}; ` +
        `counters ${report.against_log.counters_recomputed ? "recounted and MATCHED" : "not recounted"}\n`
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

// ---- shared helpers -----------------------------------------------------------

interface ParsedFlags {
  values: Record<string, string | undefined>;
  flags: Record<string, boolean>;
}

function parseFlags(
  argv: string[],
  valueFlags: string[],
  boolFlags: string[]
): ParsedFlags {
  const values: Record<string, string | undefined> = {};
  const flags: Record<string, boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    const valueFlag = valueFlags.find(
      (name) => arg === name || arg.startsWith(`${name}=`)
    );
    if (valueFlag) {
      if (arg.includes("=")) {
        values[valueFlag] = arg.slice(valueFlag.length + 1);
      } else {
        const value = argv[++i];
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
    throw new Error(`unknown option: ${arg}`);
  }
  return { values, flags };
}

async function resolveMasterKey(
  storage: FilesystemStorage,
  passphraseFlag: string | undefined,
  env: NodeJS.ProcessEnv
): Promise<Uint8Array> {
  if (env.SANCTUARY_RECOVERY_KEY) {
    const key = fromBase64url(env.SANCTUARY_RECOVERY_KEY);
    if (key.length !== 32) {
      throw new Error("SANCTUARY_RECOVERY_KEY must decode to 32 bytes");
    }
    return key;
  }
  const passphrase = passphraseFlag ?? env.SANCTUARY_PASSPHRASE;
  if (!passphrase) {
    throw new Error(
      "requires SANCTUARY_PASSPHRASE, --passphrase, or SANCTUARY_RECOVERY_KEY"
    );
  }
  let existingParams: KeyDerivationParams | undefined;
  const raw = await storage.read("_meta", "key-params");
  if (raw) {
    existingParams = JSON.parse(bytesToString(raw)) as KeyDerivationParams;
  }
  const derived = await deriveMasterKey(passphrase, existingParams);
  return derived.key;
}

function reportError(err: Writable, context: string, error: unknown): number {
  if (error instanceof AuditIntegrityError) {
    write(
      err,
      `${context}: REFUSED, the audit chain failed integrity verification (${error.findings.length} finding(s): ${[...new Set(error.findings.map((finding) => finding.kind))].join(", ")}). A checkpoint is never emitted or verified over a log that does not verify.\n`
    );
    return 1;
  }
  if (error instanceof TransparencyEmitError) {
    write(err, `${context}: ${error.message}\n`);
    return 1;
  }
  write(
    err,
    `${context}: ${error instanceof Error ? error.message : String(error)}\n`
  );
  return 1;
}

// ---- usage --------------------------------------------------------------------

function printUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary transparency <command> [options]

Commands:
  checkpoint   Emit one signed enforcement checkpoint now.
  export       Export all checkpoints as a publishable, offline-verifiable bundle.
  verify       Verify checkpoints (same as "sanctuary verify-transparency").

Checkpoints contain hashes and counts only: no state content, no rule
details, no key material. Publishing a bundle is an operator action;
no command here performs network I/O.
`
  );
}

function printCheckpointUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary transparency checkpoint [options]

Emit one signed enforcement checkpoint over the local fortress: the
audit-log Merkle root, policy hashes, emitting-binary hash/version,
per-rule enforcement counters (opaque labels), and a strictly monotonic
counter, signed by the Castle Wall signing key (root signer helper when
installed). Refuses, emitting nothing, if the audit chain fails
verification, no Castle Wall policy exists, or no signer is reachable.

Options:
  --fortress <path>     Override fortress path.
  --passphrase <val>    Fortress passphrase (or SANCTUARY_PASSPHRASE).
  --local-sign          Use the fortress-local pinned key (dev/test path).
  --binary <path>       Override the binary hashed into the checkpoint.
  --json                Emit the full signed record as JSON.
`
  );
}

function printExportUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary transparency export [--output <path>] [--fortress <path>]

Write a self-contained SANCTUARY_TRANSPARENCY_BUNDLE_V1 JSON document that
any third party can verify offline with only the signer's public key:

  sanctuary verify-transparency --input bundle.json --public-key <key>

Options:
  --output <path>     Write to a file (default: stdout).
  --fortress <path>   Override fortress path.
`
  );
}

function printVerifyUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary verify-transparency --input <path> [options]

Verify an enforcement-checkpoint chain: Ed25519 signatures against the
pinned public key, strict counter continuity (gaps, duplicates, and
rollbacks are findings), and previous-checkpoint hash linkage. With
--against-log (on the fortress host) the latest checkpoint's Merkle root
is recomputed from the live audit log, tail truncation is detected, and,
when a passphrase is available, per-rule counters are recounted.

Options:
  --input <path>            Bundle, checkpoint array, or single record (JSON).
  --public-key <key>        Signer public key, base64url (obtained out-of-band).
  --public-key-file <path>  Signer public key file (raw 32 bytes or base64url).
  --trust-embedded          Verify against the key embedded in the records.
                            Proves internal consistency only; stated in output.
  --allow-partial           Accept a suffix fragment not starting at genesis
                            (counter 1). Reports as partial, never a clean PASS.
  --against-log             Also cross-check the live audit log (host mode).
  --fortress <path>         Fortress path for --against-log / pin discovery.
  --passphrase <val>        Enables counter recount in --against-log mode.
  --json                    Emit the full report as JSON.

Exit codes: 0 PASS, 1 FAIL, 2 usage error.
`
  );
}
