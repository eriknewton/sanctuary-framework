/**
 * sanctuary transparency — verifiable enforcement-checkpoint commands.
 *
 *   sanctuary transparency checkpoint   Emit one signed checkpoint now
 *   sanctuary transparency export      Export a publishable bundle
 *   sanctuary transparency verify      Verify checkpoints (alias below)
 *   sanctuary transparency anchor      Opt-in public-log anchoring
 *   sanctuary verify-transparency      Offline/host verification
 *
 * Publishing a bundle (website, repo, anywhere) is an OPERATOR action.
 * The ONLY network I/O in this feature is transparency anchoring, which
 * is OFF by default and transmits nothing until the operator explicitly
 * enables it ("sanctuary transparency anchor enable"); even then only a
 * salted hash commitment leaves the machine. See
 * docs/transparency-checkpoints.md for what a verifying party can and
 * cannot conclude.
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
import { resolveCliMasterKey } from "../core/master-custody.js";
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
  compareTransparencyChains,
  isVerifierCheckpointRecord,
  verifyTransparencyCheckpoints,
  type CompareChainsResult,
  type TransparencyVerifyReport,
  type VerifierCheckpointRecord,
} from "../transparency/verify.js";
import {
  parseFreshnessWindow,
  verifyAnchorEvidence,
  type AnchorCoverage,
  type FetchedAnchorEntry,
} from "../transparency/anchor-verify.js";
import { verifyAgainstLog } from "../transparency/against-log.js";
import type { FetchLike } from "../transparency/rekor-client.js";

const require = createRequire(import.meta.url);
const { version: PKG_VERSION } = require("../../package.json") as {
  version: string;
};

/**
 * Dedicated exit code for a PARTIAL verify-transparency result (a suffix
 * fragment verified internally but NOT rooted at genesis, accepted via
 * --allow-partial). Distinct from 0 (clean PASS) and 1 (FAIL) so automation
 * can never read incomplete evidence as a complete-from-genesis verification.
 */
export const EXIT_PARTIAL = 10;

export interface TransparencyCommandArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
  /** Injected HTTP transport for anchoring and --fetch-anchors (tests). */
  fetchFn?: FetchLike;
  /** Injected clock for --expect-fresh (tests). */
  now?: () => Date;
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
    return runCheckpoint(rest, out, err, args.env ?? process.env, args.fetchFn);
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
  if (sub === "anchor") {
    return runAnchorCommand(rest, out, err, args.env ?? process.env, args.fetchFn);
  }
  write(err, `Unknown transparency command: ${sub}\n`);
  printUsage(err);
  return 2;
}

// ---- anchor -------------------------------------------------------------------

/**
 * Opt-in external anchoring (Sigstore Rekor). Enabling REQUIRES explicit
 * operator confirmation of the plain-language consent text (hard
 * constraint #1: nothing leaves the machine without explicit, confirmed
 * intent). Non-interactive runs must pass --yes; an interactive run is
 * asked y/N on the terminal.
 */
async function runAnchorCommand(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv,
  fetchFn?: FetchLike
): Promise<number> {
  const [verb, ...rest] = argv;
  if (!verb || verb === "--help" || verb === "-h") {
    printAnchorUsage(verb ? out : err);
    return verb ? 0 : 2;
  }
  if (rest.includes("--help") || rest.includes("-h")) {
    printAnchorUsage(out);
    return 0;
  }
  if (!["enable", "disable", "status", "now", "export"].includes(verb)) {
    write(err, `Unknown anchor command: ${verb}\n`);
    printAnchorUsage(err);
    return 2;
  }

  let masterKey: Uint8Array | undefined;
  try {
    const opts = parseFlags(
      rest,
      ["--fortress", "--passphrase", "--rekor-url", "--output"],
      ["--yes", "--json", "--allow-unsafe-rekor-url"]
    );
    const storagePath = opts.values["--fortress"] ?? resolveStoragePath(env);
    const storage = new FilesystemStorage(join(storagePath, "state"));
    const {
      ANCHOR_CONSENT_TEXT,
      anchorPendingCheckpoints,
      buildAnchorsExport,
      disableAnchoring,
      enableAnchoring,
      readAnchorConfig,
      readAnchorReceipts,
    } = await import("../transparency/anchoring.js");

    if (verb === "status") {
      // Status needs the master key only to AUTHENTICATE the config; a
      // tampered config must be reported, not summarized.
      masterKey = await resolveMasterKey(storage, opts.values["--passphrase"], env);
      const state = await readAnchorConfig({ storage, masterKey });
      const receipts =
        state.status === "absent" ? [] : await readAnchorReceipts(storage);
      const anchored = receipts.filter((r) => r.status === "anchored");
      const failed = receipts.filter((r) => r.status === "failed");
      const payload = {
        anchoring:
          state.status === "absent" ? "off (never enabled; default)" : state.status,
        ...(state.status !== "absent"
          ? {
              rekor_url: state.config.rekor_url,
              // Surfaced unconditionally so the unsafe-URL override can
              // never be silently on.
              allow_unsafe_rekor_url: state.config.allow_unsafe_url,
            }
          : {}),
        receipts: {
          anchored: anchored.length,
          failed: failed.length,
          latest_anchored_counter: anchored.at(-1)?.counter ?? null,
        },
      };
      if (opts.flags["--json"]) {
        write(out, JSON.stringify(payload, null, 2) + "\n");
      } else {
        write(out, `Anchoring: ${payload.anchoring}\n`);
        if (state.status !== "absent") {
          write(out, `Rekor log: ${state.config.rekor_url}\n`);
          if (state.config.allow_unsafe_url) {
            write(
              out,
              `WARNING: --allow-unsafe-rekor-url is in effect for this log URL (http and loopback/private/metadata addresses permitted). Re-run "anchor enable" without the flag to restore the default URL guard.\n`
            );
          }
        }
        write(
          out,
          `Receipts: ${anchored.length} anchored, ${failed.length} failed` +
            (anchored.length > 0
              ? ` (latest anchored checkpoint: ${anchored.at(-1)!.counter})`
              : "") +
            `\n`
        );
        if (failed.length > 0) {
          write(
            out,
            `Retry failed anchors with: sanctuary transparency anchor now\n`
          );
        }
      }
      return 0;
    }

    masterKey = await resolveMasterKey(storage, opts.values["--passphrase"], env);
    const auditLog = new AuditLog(storage, masterKey);
    const fortressId = fortressIdFromStoragePath(storagePath);

    if (verb === "export") {
      const doc = await buildAnchorsExport({ storage, masterKey, fortressId });
      const anchored = doc.receipts.filter((r) => r.status === "anchored").length;
      const json = JSON.stringify(doc, null, 2) + "\n";
      if (opts.values["--output"]) {
        await writeFile(opts.values["--output"]!, json, "utf8");
        write(
          err,
          `Exported anchor evidence for ${doc.receipts.length} receipt(s) (${anchored} anchored) to ${opts.values["--output"]}\n` +
            `This file contains the LOCAL commitment salt: whoever holds it can link this fortress's\n` +
            `public anchors to its checkpoint history. Hand it to auditors deliberately, with the bundle:\n` +
            `  sanctuary verify-transparency --input bundle.json --public-key <key> --check-anchors ${opts.values["--output"]}\n` +
            `Nothing was transmitted.\n`
        );
      } else {
        write(out, json);
      }
      return 0;
    }

    if (verb === "enable") {
      write(out, `\n${ANCHOR_CONSENT_TEXT}\n\n`);
      if (!opts.flags["--yes"]) {
        const confirmed = await confirmInteractive(
          out,
          "Enable transparency anchoring? [y/N] "
        );
        if (confirmed === null) {
          write(
            err,
            "Not enabled: anchoring requires explicit consent. Re-run with --yes after reading the statement above, or answer interactively on a terminal.\n"
          );
          return 2;
        }
        if (!confirmed) {
          write(err, "Not enabled (operator declined). Nothing was transmitted or changed.\n");
          return 2;
        }
      }
      const config = await enableAnchoring({
        storage,
        masterKey,
        auditLog,
        fortressId,
        ...(opts.values["--rekor-url"]
          ? { rekorUrl: opts.values["--rekor-url"] }
          : {}),
        ...(opts.flags["--allow-unsafe-rekor-url"]
          ? { allowUnsafeRekorUrl: true }
          : {}),
      });
      write(
        out,
        `Anchoring ENABLED (log: ${config.rekor_url}). Consent recorded in the audit log.\n` +
          `Each future checkpoint emission publishes a salted hash commitment to the public log.\n` +
          `Anchor existing checkpoints now with: sanctuary transparency anchor now\n`
      );
      if (config.allow_unsafe_url) {
        write(
          out,
          `WARNING: --allow-unsafe-rekor-url is in effect: the URL guard (https-only, no loopback/private/link-local/metadata addresses) is bypassed for this log URL. The override is recorded in the config and the audit log, and "anchor status" reports it.\n`
        );
      }
      return 0;
    }

    if (verb === "disable") {
      const config = await disableAnchoring({
        storage,
        masterKey,
        auditLog,
        fortressId,
      });
      write(
        out,
        `Anchoring DISABLED. Nothing will be transmitted. Previously published anchors remain in the public log (${config.rekor_url}) and stay verifiable.\n`
      );
      return 0;
    }

    // verb === "now": anchor every checkpoint lacking a success receipt.
    const result = await anchorPendingCheckpoints({
      storage,
      masterKey,
      auditLog,
      ...(fetchFn ? { fetchFn } : {}),
    });
    if ("status" in result && result.status === "disabled") {
      write(
        err,
        "Anchoring is not enabled (it is off by default). Enable it first: sanctuary transparency anchor enable\n"
      );
      return 1;
    }
    const summary = result as Exclude<typeof result, { status: "disabled" }>;
    write(
      out,
      `Anchored ${summary.anchored} checkpoint(s); ${summary.already_anchored} already anchored; ${summary.failed} failed.\n`
    );
    for (const item of summary.outcomes) {
      if (item.outcome.status === "anchored") {
        write(
          out,
          `  checkpoint ${item.counter}: anchored (Rekor index ${item.outcome.receipt.rekor.log_index})\n`
        );
      } else if (item.outcome.status === "failed") {
        write(
          err,
          `  checkpoint ${item.counter}: FAILED, ${item.outcome.error}\n`
        );
      }
    }
    if (summary.failed > 0) {
      write(
        err,
        `Anchor coverage is incomplete (loud by design; emission is never blocked). Re-run "sanctuary transparency anchor now" when the log is reachable.\n`
      );
      return 1;
    }
    return 0;
  } catch (error) {
    return reportError(err, `transparency anchor ${verb}`, error);
  } finally {
    masterKey?.fill(0);
  }
}

/**
 * Interactive y/N confirmation. Returns null when no TTY is attached
 * (non-interactive runs must use --yes; consent is never assumed).
 */
async function confirmInteractive(
  out: Writable,
  question: string
): Promise<boolean | null> {
  if (process.stdin.isTTY !== true) return null;
  const readline = await import("node:readline/promises");
  const rl = readline.createInterface({
    input: process.stdin,
    output: out as NodeJS.WritableStream,
  });
  try {
    const answer = (await rl.question(question)).trim().toLowerCase();
    return answer === "y" || answer === "yes";
  } finally {
    rl.close();
  }
}

// ---- checkpoint -------------------------------------------------------------

async function runCheckpoint(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv,
  fetchFn?: FetchLike
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
    // Opt-in external anchoring (default OFF; nothing transmitted unless
    // the operator enabled it). FAIL LOUD: an anchor failure is reported
    // and exits nonzero, but the emitted checkpoint above stands; local
    // evidence never depends on a third party's uptime.
    let anchorFailed = false;
    try {
      const { anchorCheckpoint, readAnchorConfig } = await import(
        "../transparency/anchoring.js"
      );
      const anchorState = await readAnchorConfig({ storage, masterKey });
      if (anchorState.status === "enabled") {
        const outcome = await anchorCheckpoint({
          storage,
          masterKey,
          auditLog,
          record,
          ...(fetchFn ? { fetchFn } : {}),
        });
        if (outcome.status === "anchored") {
          write(
            out,
            `[anchor] checkpoint ${record.counter} anchored to ${anchorState.config.rekor_url} (Rekor index ${outcome.receipt.rekor.log_index}).\n`
          );
        } else if (outcome.status === "already_anchored") {
          write(
            out,
            `[anchor] checkpoint ${record.counter} was already anchored (Rekor index ${outcome.receipt.rekor.log_index}).\n`
          );
        } else if (outcome.status === "failed") {
          anchorFailed = true;
          write(
            err,
            `[anchor] checkpoint ${record.counter} emission succeeded but ANCHORING FAILED: ${outcome.error}\n` +
              `[anchor] The failure was recorded in the audit log. Retry with: sanctuary transparency anchor now\n`
          );
        }
      }
    } catch (anchorError) {
      // Config tamper or receipt-store failure: refuse to anchor, say so
      // loudly, and exit nonzero. The emitted checkpoint above stands.
      anchorFailed = true;
      write(
        err,
        `[anchor] checkpoint ${record.counter} emission succeeded but ANCHORING REFUSED: ${anchorError instanceof Error ? anchorError.message : String(anchorError)}\n`
      );
    }
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
    return anchorFailed ? 1 : 0;
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
      [
        "--input",
        "--public-key",
        "--public-key-file",
        "--fortress",
        "--passphrase",
        "--check-anchors",
        "--rekor-public-key-file",
        "--expect-fresh",
        "--compare",
      ],
      [
        "--trust-embedded",
        "--against-log",
        "--allow-partial",
        "--json",
        "--fetch-anchors",
        "--allow-unsafe-rekor-url",
      ]
    );
    const inputPath = opts.values["--input"];
    if (!inputPath) {
      write(err, "Error: --input <path> is required\n");
      printVerifyUsage(err);
      return 2;
    }
    // Anchor-dependent flags fail closed at usage time: a run that silently
    // ignored --expect-fresh would read as fresher than it proved.
    for (const dependent of ["--expect-fresh", "--rekor-public-key-file"] as const) {
      if (opts.values[dependent] && !opts.values["--check-anchors"]) {
        write(err, `Error: ${dependent} requires --check-anchors <anchors.json>\n`);
        return 2;
      }
    }
    if (opts.flags["--fetch-anchors"] && !opts.values["--check-anchors"]) {
      write(err, "Error: --fetch-anchors requires --check-anchors <anchors.json>\n");
      return 2;
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

    // ---- --check-anchors: auditor-side anchor verification ------------------
    let anchorsCoverage: AnchorCoverage | null = null;
    if (opts.values["--check-anchors"]) {
      const anchorsPath = opts.values["--check-anchors"]!;
      let anchorsDoc: unknown;
      try {
        anchorsDoc = JSON.parse(await readFile(anchorsPath, "utf8"));
      } catch (error) {
        write(
          err,
          `Error reading ${anchorsPath}: ${error instanceof Error ? error.message : String(error)}\n`
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
      const records = extractRecords(parsed);
      const fetchedEntries = new Map<number, FetchedAnchorEntry>();
      if (opts.flags["--fetch-anchors"]) {
        const { fetchAnchorEntries, validateRekorUrl } = await import(
          "../transparency/anchoring.js"
        );
        const { isTransparencyAnchorsExport } = await import(
          "../transparency/anchor-verify.js"
        );
        if (!isTransparencyAnchorsExport(anchorsDoc)) {
          report.findings.push({
            kind: "anchors_input_invalid",
            message: `${anchorsPath} is not a SANCTUARY_TRANSPARENCY_ANCHORS_V1 export; cannot fetch entries for it`,
          });
        } else {
          // Same SSRF posture as anchoring itself: validate the log URL
          // fail-closed before any request, with the same explicit unsafe
          // escape hatch for local/dev logs.
          validateRekorUrl(
            anchorsDoc.rekor_url,
            opts.flags["--allow-unsafe-rekor-url"] === true
          );
          const { HttpRekorClient } = await import(
            "../transparency/rekor-client.js"
          );
          const client = new HttpRekorClient({
            baseUrl: anchorsDoc.rekor_url,
            ...(args.fetchFn ? { fetchFn: args.fetchFn } : {}),
          });
          const outcomes = await fetchAnchorEntries({
            receipts: anchorsDoc.receipts,
            client,
          });
          for (const outcome of outcomes) {
            if (outcome.status === "fetched") {
              fetchedEntries.set(outcome.counter, outcome.entry);
            } else if (outcome.status === "not_found") {
              report.findings.push({
                kind: "anchor_entry_not_found",
                counter: outcome.counter,
                message: `the log at ${anchorsDoc.rekor_url} denies that the anchor entry for checkpoint ${outcome.counter} exists (UUID ${outcome.uuid}); the receipt's anchored claim is refuted by the log`,
              });
            } else {
              report.not_checked.push(
                `anchor entry fetch for checkpoint ${outcome.counter}: log unreachable (${outcome.message}); fell back to receipt-embedded material where present`
              );
            }
          }
        }
      }
      const anchorResult = verifyAnchorEvidence(records, anchorsDoc, {
        ...(rekorPublicKeyPem ? { rekorPublicKeyPem } : {}),
        ...(expectFreshMs !== undefined ? { expectFreshMs } : {}),
        ...(args.now ? { now: args.now } : {}),
        ...(fetchedEntries.size > 0 ? { fetchedEntries } : {}),
      });
      report.findings.push(...anchorResult.findings);
      report.not_checked.push(...anchorResult.not_checked);
      anchorsCoverage = anchorResult.coverage;
    }

    // ---- --compare: multi-bundle split-view detection ------------------------
    let compareSummary:
      | (Pick<CompareChainsResult, "relation" | "divergent_counter" | "overlap"> & {
          input: string;
          other_verdict: TransparencyVerifyReport["verdict"];
        })
      | null = null;
    if (opts.values["--compare"]) {
      const comparePath = opts.values["--compare"]!;
      let otherParsed: unknown;
      try {
        otherParsed = JSON.parse(await readFile(comparePath, "utf8"));
      } catch (error) {
        write(
          err,
          `Error reading ${comparePath}: ${error instanceof Error ? error.message : String(error)}\n`
        );
        return 1;
      }
      // The comparison bundle is verified under the SAME key basis; a
      // suffix fragment is fine for fork detection, so partial is allowed
      // for it regardless of the primary's --allow-partial.
      const otherReport = verifyTransparencyCheckpoints(otherParsed, {
        ...(key.publicKey ? { publicKey: key.publicKey } : {}),
        ...(opts.flags["--trust-embedded"] ? { trustEmbedded: true } : {}),
        allowPartial: true,
      });
      if (otherReport.verdict === "FAIL") {
        report.findings.push({
          kind: "compare_input_invalid",
          message: `the comparison bundle ${comparePath} fails verification on its own (${otherReport.findings.length} finding(s): ${[...new Set(otherReport.findings.map((f) => f.kind))].join(", ")}); refusing to draw fork conclusions from unverified evidence`,
        });
      } else {
        const comparison = compareTransparencyChains(
          extractRecords(parsed),
          extractRecords(otherParsed)
        );
        report.findings.push(...comparison.findings);
        report.not_checked.push(...comparison.notes);
        compareSummary = {
          input: comparePath,
          other_verdict: otherReport.verdict,
          relation: comparison.relation,
          divergent_counter: comparison.divergent_counter,
          overlap: comparison.overlap,
        };
      }
    }

    // Verdict reassembly after every evidence source contributed findings.
    if (report.findings.length > 0) report.verdict = "FAIL";

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
      ...(anchorsCoverage ? { anchors: anchorsCoverage } : {}),
      ...(compareSummary ? { compare: compareSummary } : {}),
    };
    if (opts.flags["--json"]) {
      write(out, JSON.stringify(payload, null, 2) + "\n");
    } else {
      printHumanReport(out, payload);
    }
    // Exit-code mapping. 0 is reserved EXCLUSIVELY for a clean PASS
    // (complete-from-genesis, authentic genesis sentinel, zero findings). A
    // PARTIAL suffix (verified internally but not genesis-rooted, accepted via
    // --allow-partial) returns the dedicated code 10 so automation can never
    // read it as a complete verification. Everything else (FAIL) is 1.
    if (report.verdict === "PASS") return 0;
    if (report.verdict === "PARTIAL") return EXIT_PARTIAL;
    return 1;
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
  if (report.against_log) {
    write(
      out,
      `Against live log (checkpoint ${report.against_log.checked_counter ?? "n/a"}): ` +
        `merkle root ${report.against_log.merkle_root_recomputed ? "recomputed and MATCHED" : "not recomputed"}; ` +
        `counters ${report.against_log.counters_recomputed ? "recounted and MATCHED" : "not recounted"}\n`
    );
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
  // Unified custody (master-custody.ts): never derive a fortress master verb-locally.
  if (env.SANCTUARY_RECOVERY_KEY) {
    return resolveCliMasterKey(storage, {
      recoveryKey: env.SANCTUARY_RECOVERY_KEY,
    });
  }
  const passphrase = passphraseFlag ?? env.SANCTUARY_PASSPHRASE;
  if (!passphrase) {
    throw new Error(
      "requires SANCTUARY_PASSPHRASE, --passphrase, or SANCTUARY_RECOVERY_KEY"
    );
  }
  return resolveCliMasterKey(storage, { passphrase });
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
  anchor       Opt-in anchoring of checkpoint commitments to a public
               transparency log (Sigstore Rekor). OFF by default.

Checkpoints contain hashes and counts only: no state content, no rule
details, no key material. Publishing a bundle is an operator action.
The only network I/O in this feature is anchoring, which transmits
nothing until explicitly enabled, and then only a salted hash.
`
  );
}

function printAnchorUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary transparency anchor <command> [options]

Anchor checkpoint commitments to the public Sigstore Rekor transparency
log so the enforcement history is fork-evident and freshness-bounded:
once anchored, even this machine cannot quietly rewrite or withhold it.

OFF BY DEFAULT. Enabling requires explicit consent. What is published
per checkpoint: a salted SHA-256 commitment (64 hex characters), a
signature from a dedicated derived anchoring key, and that key's public
half. Never published: checkpoint contents, counts, policy or rule data,
audit data, fortress identifiers, or any state content.

Anchor failures are LOUD, never blocking: a Rekor outage is recorded in
the audit log and reported, and local checkpoint emission continues.

Commands:
  enable    Show the consent statement and switch anchoring on.
            Requires --yes when not running on a terminal.
  disable   Switch anchoring off (published anchors stay verifiable).
  status    Show the anchoring state and receipt coverage.
  now       Anchor every checkpoint that lacks a success receipt
            (catch-up after an outage).
  export    Write the anchor evidence file (salt, anchoring public key,
            receipts) an auditor needs for verify-transparency
            --check-anchors. Local only; nothing is transmitted. The file
            links this fortress's public anchors to its history for
            whoever holds it; hand it out deliberately.

Options:
  --fortress <path>     Override fortress path.
  --passphrase <val>    Fortress passphrase (or SANCTUARY_PASSPHRASE).
  --output <path>       Write the evidence file here (export only;
                        default: stdout).
  --rekor-url <url>     Override the transparency log URL (enable only).
                        Must be https and must not point at a loopback,
                        private, link-local, or metadata address.
  --allow-unsafe-rekor-url
                        Escape hatch for a LOCAL/DEV Rekor instance:
                        bypasses the URL guard above (enable only). Must
                        be re-passed at every enable; recorded in the
                        config and the audit log, and reported by status.
  --yes                 Non-interactive consent confirmation (enable only).
  --json                Machine-readable output (status only).
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
                            (counter 1). Reports verdict PARTIAL and exits 10,
                            never a clean PASS / exit 0.
  --against-log             Also cross-check the live audit log (host mode).
  --fortress <path>         Fortress path for --against-log / pin discovery.
  --passphrase <val>        Enables counter recount in --against-log mode.
  --check-anchors <path>    Verify external anchor evidence (the operator's
                            "sanctuary transparency anchor export" file):
                            salted commitments recomputed against THIS
                            bundle, Rekor entry binding, RFC 6962 inclusion
                            proofs, and anchor-coverage reporting. Without a
                            pinned log key this checks internal consistency
                            of the operator-supplied evidence only; anchors
                            report "consistent", never "verified".
  --rekor-public-key-file <path>
                            Pinned Rekor log public key (SPKI PEM, obtained
                            out-of-band). Enables log-signature checks
                            (signed entry timestamps, checkpoint notes);
                            required for anchors to count as "verified" and
                            for --expect-fresh.
  --fetch-anchors           Fetch fresh entries and inclusion proofs from
                            the log named in the anchors file instead of
                            trusting receipt-embedded material. The log URL
                            passes the same SSRF guard as anchoring
                            (--allow-unsafe-rekor-url for local/dev logs).
  --expect-fresh <window>   FAIL unless the newest log-attested anchor is
                            within the window (e.g. 36h, 7d). Requires
                            --check-anchors and a pinned Rekor key.
  --compare <path>          Verify a second, independently obtained bundle
                            and detect split views: the same counter with
                            different signed contents is a FORK finding.
  --json                    Emit the full report as JSON.

Exit codes: 0 PASS (complete from genesis), 10 PARTIAL (suffix fragment via
--allow-partial; verified but not genesis-rooted), 1 FAIL, 2 usage error.
`
  );
}
