/**
 * `sanctuary exit` CLI.
 *
 * Operator-facing export/import/verifier path for SANCTUARY_EXIT_BUNDLE_V1.
 * Dashboard wizard work consumes the same module APIs later.
 */

import { createReadStream, openSync } from "node:fs";
import { access, readFile as fsReadFile, mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { Readable, Writable } from "node:stream";
import { FilesystemStorage } from "../storage/filesystem.js";
import { AuditLog } from "../operational/audit-log.js";
import { StateStore } from "../cognitive/state-store.js";
import { IdentityManager } from "../cognitive/tools.js";
import { ReputationStore } from "../reputation/reputation-store.js";
import { loadConfig } from "../config.js";
import { loadPrincipalPolicy, MalformedPrincipalPolicyError } from "../principal-policy/loader.js";
import { resolveCliMasterKey } from "../core/master-custody.js";
import {
  exportExitBundle,
  importExitBundle,
  exitBundleManifestShape,
  ExitBundleStateImportIncompleteError,
  type ImportExitBundleResult,
} from "./bundle.js";
import type {
  ExitBundleDidWebBinding,
  ExitBundleVerifierResult,
} from "../contracts/v1.1/exit-bundle-manifest.js";
import { verifyExitBundle, InvalidExitBundleError } from "./verifier.js";
import { inspectExitBundle, inspectExitCode } from "./inspect.js";
import { loadFortressDidWebRecord } from "../recognition/did-web.js";
import { flagValue, flagValues } from "../cli/argv.js";

const EXIT_EXPORT_ABORTED_EXIT_CODE = 78;

/**
 * Failure classes that mean the SIGNED MANIFEST itself did not verify (bad
 * signature, unknown/invalid scheme or version, or a manifest-internal
 * integrity break: aggregate-hash mismatch, unsafe/duplicate artifact path).
 * Every OTHER failure class is a downstream artifact problem (a hash mismatch,
 * a bad reputation bundle, an unverifiable attestation): the manifest's own
 * signature is cryptographically valid even though the overall verdict fails.
 * The `verify` CLI's `manifest:` line must reflect the manifest-specific
 * status, not the overall verdict, so a valid manifest with a failing
 * downstream artifact is not mislabeled `manifest: failed`.
 */
const MANIFEST_INTEGRITY_FAILURE_CLASSES: ReadonlySet<
  NonNullable<ExitBundleVerifierResult["failure_class"]>
> = new Set([
  "manifest_signature_invalid",
  "manifest_unknown_version",
  "manifest_signature_scheme_invalid",
  "aggregate_hash_mismatch",
  "artifact_path_unsafe",
  "artifact_path_duplicate",
]);

/**
 * True when the signed manifest itself verified, regardless of any downstream
 * artifact failure. A passing overall verdict trivially implies a verified
 * manifest; a failing verdict implies a verified manifest UNLESS the failure
 * class is itself a manifest-integrity break.
 */
function manifestSignatureVerified(result: ExitBundleVerifierResult): boolean {
  if (result.passed) return true;
  if (result.failure_class === undefined) return true;
  return !MANIFEST_INTEGRITY_FAILURE_CLASSES.has(result.failure_class);
}

export interface ExitCommandArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
  stdin?: NodeJS.ReadableStream;
  env?: NodeJS.ProcessEnv;
}

interface ExitContext {
  storagePath: string;
  stateStoragePath: string;
  storage: FilesystemStorage;
  masterKey: Uint8Array;
  auditLog: AuditLog;
  identityManager: IdentityManager;
  reputationStore: ReputationStore;
  keySource: "passphrase" | "recovery-key" | "unknown";
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

function writeStateSkippedCounters(
  stream: Writable,
  state: ImportExitBundleResult["state"],
): void {
  write(stream, `state_skipped_keys: ${state.skipped_keys}\n`);
  write(stream, `state_skipped_invalid_sig: ${state.skipped_invalid_sig}\n`);
  write(stream, `state_skipped_unknown_kid: ${state.skipped_unknown_kid}\n`);
}

function hasFlag(argv: string[], name: string): boolean {
  return argv.includes(name);
}

export async function confirmTier1(
  prompt: string,
  assumeYes: boolean,
  _stdin: NodeJS.ReadableStream,
  err: Writable
): Promise<boolean> {
  if (assumeYes) return true;

  // SEC: Tier 1 approval must come from the operator's terminal, not stdin.
  let input: NodeJS.ReadableStream;
  try {
    const fd = openSync("/dev/tty", "r");
    input = createReadStream("/dev/tty", {
      fd,
      autoClose: true,
      encoding: "utf8",
    });
  } catch {
    write(err, "\nTier 1 approval required but no interactive terminal available.\n");
    write(err, "Use --yes flag for explicit non-interactive approval.\n");
    return false;
  }

  const readline = await import("node:readline/promises");
  const rl = readline.createInterface({
    input: input as Readable,
    output: err,
  });
  let answer: string;
  try {
    answer = await rl.question(`${prompt} [y/N] `);
  } finally {
    rl.close();
    (input as Readable).destroy();
  }
  return /^y(es)?$/i.test(answer.trim());
}

async function openExitContext(
  argv: string[],
  env: NodeJS.ProcessEnv
): Promise<ExitContext> {
  const passphrase =
    flagValue(argv, "--passphrase") ?? env.SANCTUARY_PASSPHRASE;
  const recoveryKey = env.SANCTUARY_RECOVERY_KEY;
  const config = await loadConfig();
  await mkdir(config.storage_path, { recursive: true, mode: 0o700 });
  const stateStoragePath = join(config.storage_path, "state");
  const storage = new FilesystemStorage(stateStoragePath);

  let masterKey: Uint8Array;
  let keySource: ExitContext["keySource"];
  // Unified custody (master-custody.ts): never derive a fortress master verb-locally.
  if (passphrase) {
    masterKey = await resolveCliMasterKey(storage, {
      passphrase,
      bootstrap: true,
      storagePathHint: config.storage_path,
    });
    keySource = "passphrase";
  } else if (recoveryKey) {
    masterKey = await resolveCliMasterKey(storage, {
      recoveryKey,
      bootstrap: true,
      storagePathHint: config.storage_path,
    });
    keySource = "recovery-key";
  } else {
    throw new Error(
      "sanctuary exit requires SANCTUARY_PASSPHRASE, --passphrase, or SANCTUARY_RECOVERY_KEY."
    );
  }

  const auditLog = new AuditLog(storage, masterKey);
  const stateStore = new StateStore(storage, masterKey);
  const identityManager = new IdentityManager(storage, masterKey);
  await identityManager.load();
  const reputationStore = new ReputationStore(storage, masterKey);
  void stateStore;

  return {
    storagePath: config.storage_path,
    stateStoragePath,
    storage,
    masterKey,
    auditLog,
    identityManager,
    reputationStore,
    keySource,
  };
}

export function printExitHelp(out: Writable = process.stdout): void {
  write(out, `
Usage: sanctuary exit <command> [options]

Commands:
  export --out <dir>          Create a SANCTUARY_EXIT_BUNDLE_V1 directory
  verify <dir>                Verify manifest, artifacts, signatures, and exported-set completeness
  import <dir> [--activate]   Verify, report conflicts, and optionally activate
  manifest-shape              Print the v1.1 manifest shape
  inspect <dir>               Read-only: what the bundle carries and WHICH
                              credential it DECLARES it needs. No passphrase,
                              no writes, and no import is attempted.

Options:
  --passphrase <value>              Current destination/source passphrase
  --source-passphrase <value>       Source passphrase for state re-key on import
                                    (legacy bundles only; envelope-era bundles
                                    use the bundle re-key key instead)
  --source-recovery-key <value>     Bundle re-key key (displayed at export) or
                                    legacy source recovery key for state re-key
  --legacy-source-master            On import, with --source-recovery-key: confirm
                                    the key is the SOURCE FORTRESS MASTER, not a
                                    bundle re-key key. Required for bundles with
                                    no source_custody block; without it the import
                                    refuses rather than guessing.
  --destination-identity-id <id>    Destination signer for re-keyed state
  --import-state                    Import encrypted state during activation.
                                    Requires --activate and source credentials.
  --state-namespace <name>          Restrict the export to a namespace; repeatable.
                                    Omit it to export EVERY namespace.
  --conflict <skip|overwrite|version>
  --force-rebind                    On import: explicitly replace an existing fortress
                                    public identity (Tier 1 confirmation)
  --accept-unverifiable-attestations
                                    On verify only: relax the read-only preview verdict
                                    to tolerate reputation attestations whose signer DID
                                    is not in the bundle. This is a non-authoritative
                                    preview flag; it does NOT affect import, which always
                                    verifies strictly and never admits an unverifiable
                                    attestation.
  --did-web <identifier>            Embed a specific did:web identifier in the export
                                    manifest. Requires --did-web-authority-host.
                                    Overrides fortress-config auto-inclusion.
  --did-web-authority-host <host>   Authority host for --did-web (required with it).
  --did-web-published-at <iso8601>  Operator's claimed publication time for the DID
                                    Document (optional; ISO 8601).
  --no-did-web                      Explicit opt-out: skip did:web inclusion even if
                                    a fortress-config record exists. (Alias for
                                    --include-did-web=false.)
  --did-web-allowed-host <host>     On import: host allowed for outbound did:web
                                    resolution; repeatable. Empty means refuse to
                                    resolve (no-outbound-by-default).
  --skip-did-web-verify             On import: skip did:web resolution entirely.
  --json
  --yes, -y                         Explicit non-interactive Tier 1 approval
  --help, -h

did:web auto-inclusion (build 3):
  Running "sanctuary did-web issue --authority-host <host>" registers the
  operator's did:web identifier at <storage>/recognition/did-web.json.
  Subsequent "sanctuary exit export" runs auto-include this identifier in
  the manifest's identity_binding without requiring any --did-web flag.
  Per-fortress isolation is structural: the record lives under the
  fortress's storage_path, so different fortresses carry different
  registered identifiers.
`);
}

export function printExitExportHelp(out: Writable = process.stdout): void {
  write(out, `sanctuary exit export. Create a SANCTUARY_EXIT_BUNDLE_V1 directory.

Usage:
  sanctuary exit export --out <dir> [options]

Description:
  Exports identity, audit receipts, reputation data, policy metadata, optional
  encrypted state namespaces, and optional did:web binding into a portable exit
  bundle. Export requires Tier 1 approval unless --yes is supplied.

  When state is exported, a one-time BUNDLE RE-KEY KEY is displayed: it is the
  credential that re-keys the bundle's encrypted state at import
  (--source-recovery-key). It is never written into the bundle; store it
  separately. Fortress credentials never travel inside the bundle.

Options:
  --out <dir>                       Destination bundle directory.
  --passphrase <value>              Current fortress passphrase.
  --state-namespace <name>          Restrict the export to a namespace; repeatable.
                                    Omit it to export EVERY namespace found in the
                                    fortress state directory.
  --did-web <identifier>            Embed a specific did:web identifier.
  --did-web-authority-host <host>   Required with --did-web.
  --did-web-published-at <iso8601>  Claimed DID Document publication time.
  --no-did-web                      Skip did:web auto-inclusion.
  --json                            Output as JSON.
  --yes, -y                         Explicit non-interactive Tier 1 approval.
  --help, -h                        Show this help.

Environment:
  SANCTUARY_PASSPHRASE    Current fortress passphrase.
  SANCTUARY_RECOVERY_KEY  Recovery key alternative to passphrase.

Examples:
  sanctuary exit export --out ./exit-bundle
  sanctuary exit export --out ./exit-bundle --state-namespace memories --yes
`);
}

export async function runExitCommand(args: ExitCommandArgs): Promise<number> {
  const argv = args.argv;
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const stdin = args.stdin ?? process.stdin;
  const env = args.env ?? process.env;

  if (
    argv.length === 0 ||
    argv[0] === "help" ||
    hasFlag(argv, "--help") ||
    hasFlag(argv, "-h")
  ) {
    printExitHelp(out);
    return 0;
  }

  const command = argv[0]!;
  const json = hasFlag(argv, "--json");

  try {
    if (command === "manifest-shape") {
      write(out, JSON.stringify(exitBundleManifestShape(), null, 2) + "\n");
      return 0;
    }

    if (command === "verify" || command === "verify-exit-bundle") {
      const dir = argv[1];
      if (!dir) {
        write(
          err,
          command === "verify-exit-bundle"
            ? "Usage: sanctuary verify-exit-bundle <dir>\n"
            : "Usage: sanctuary exit verify <dir>\n",
        );
        return 2;
      }
      let result;
      try {
        result = await verifyExitBundle(dir, {
          acceptUnverifiableAttestations: hasFlag(
            argv,
            "--accept-unverifiable-attestations"
          ),
        });
      } catch (e) {
        if (e instanceof InvalidExitBundleError) {
          write(err, `Error: ${e.message}\n`);
          return 1;
        }
        throw e;
      }
      if (json) {
        write(
          out,
          JSON.stringify(
            { verdict: result.passed ? "PASS" : "FAIL", ...result },
            null,
            2,
          ) + "\n",
        );
      } else {
        write(out, `verdict: ${result.passed ? "PASS" : "FAIL"}\n`);
        write(
          out,
          `manifest: ${manifestSignatureVerified(result) ? "verified" : "failed"}\n`
        );
        write(out, `identity: ${result.manifest_summary.identity_id}\n`);
        write(out, `artifacts: ${result.manifest_summary.artifact_count}\n`);
        if (result.reputation) {
          write(
            out,
            `reputation: ${result.reputation.verified_attestations}/${result.reputation.attestation_count} attestations verified\n`
          );
          write(
            out,
            `reputation completeness: ${result.reputation.completeness}\n`
          );
        }
        // ADDITIVE ONLY: every line above this point is a shipped display
        // string and stays byte-identical (frozen-surface rule). The state
        // lines are appended, never interleaved, so an operator script that
        // greps for `identity:` or `artifacts:` is unaffected.
        if (result.state) {
          // `entry_count === null` means the artifact's entries list could not
          // be read at all. Printing `0` there would be the absent-as-empty
          // conflation on the operator's screen, so it gets its own token and
          // a warning (pushed by the verifier) rather than a plausible number.
          write(
            out,
            `state_entries: ${result.state.entry_count ?? "unreadable"}\n`
          );
          if (result.state.empty_reason !== undefined) {
            write(out, `empty_reason: ${result.state.empty_reason}\n`);
          }
        }
        for (const warning of result.warnings) write(out, `warning: ${warning}\n`);
        for (const item of result.unsupported_artifacts) {
          write(out, `unsupported: ${item}\n`);
        }
      }
      return result.passed ? 0 : 1;
    }

    if (command === "inspect") {
      const dir = argv[1];
      if (!dir) {
        write(err, "Usage: sanctuary exit inspect <dir>\n");
        return 2;
      }
      let report;
      try {
        report = await inspectExitBundle(dir);
      } catch (e) {
        if (e instanceof InvalidExitBundleError) {
          write(err, `Error: ${e.message}\n`);
          return 1;
        }
        throw e;
      }
      if (json) {
        write(out, JSON.stringify(report, null, 2) + "\n");
      } else {
        write(out, `verdict: ${report.verdict}\n`);
        write(out, `identity: ${report.identity_id}\n`);
        write(out, `fortress: ${report.fortress_id}\n`);
        write(out, `exported_at: ${report.exported_at}\n`);
        write(out, `artifacts: ${report.artifact_count}\n`);
        // `unreadable` and `unknown` are distinct and neither is `0`: the first
        // means the artifact's entry list could not be read, the second that
        // there is no encrypted_state artifact at all. Printing a number for
        // either would be the absent-as-benign conflation on screen.
        write(
          out,
          `state_entries: ${report.state === undefined ? "unknown" : (report.state.entry_count ?? "unreadable")}\n`
        );
        write(
          out,
          `namespaces: ${report.state?.namespaces.join(", ") ?? "unknown"}\n`,
        );
        if (report.state?.empty_reason !== undefined) {
          write(out, `empty_reason: ${report.state.empty_reason}\n`);
        }
        write(out, `legacy_kdf_params: ${report.legacy_kdf_params}\n`);
        write(out, `source_custody: ${report.source_custody}\n`);
        write(out, `declares: ${report.declared_rekey_material}\n`);
        write(out, `to try: ${report.suggested_command}\n`);
        // Printed unconditionally, including on the happy path: the whole
        // defect this command exists to close was an answer that sounded more
        // certain than it was. A limit shown only on failures is not a limit.
        write(out, `credential check: ${report.credential_bound}\n`);
        for (const warning of report.warnings) {
          write(out, `warning: ${warning}\n`);
        }
      }
      return inspectExitCode(report);
    }

    if (command === "export") {
      if (hasFlag(argv.slice(1), "--help") || hasFlag(argv.slice(1), "-h")) {
        printExitExportHelp(out);
        return 0;
      }
      const outDir = flagValue(argv, "--out");
      if (!outDir) {
        write(err, "Usage: sanctuary exit export --out <dir>\n");
        return 2;
      }
      const approved = await confirmTier1(
        "Tier 1 approval required: export complete Sanctuary exit bundle?",
        hasFlag(argv, "--yes") || hasFlag(argv, "-y"),
        stdin,
        err
      );
      if (!approved) {
        write(err, "Aborted.\n");
        return EXIT_EXPORT_ABORTED_EXIT_CODE;
      }
      const config = await loadConfig();
      const ctx = await openExitContext(argv, env);
      let policy;
      try {
        policy = await loadPrincipalPolicy(ctx.storagePath);
      } catch (policyErr) {
        if (policyErr instanceof MalformedPrincipalPolicyError) {
          write(err, `\nSanctuary cannot proceed.\n${policyErr.message}\n`);
          return 1;
        }
        throw policyErr;
      }
      // Recognition-Layer Path C primary did:web binding resolution.
      //
      // Build 2 shipped CLI-explicit override: operator passes
      // --did-web + --did-web-authority-host to embed a did:web
      // binding in the manifest's identity_binding.
      //
      // Build 3 adds fortress-config auto-inclusion: if `did-web issue`
      // has been run on this fortress, `<storage>/recognition/did-web.json`
      // exists and is treated as the operator's registered did:web
      // identifier. Subsequent exit-bundle exports auto-include it
      // without requiring any --did-web flag.
      //
      // Resolution order:
      //   1. --no-did-web (alias: --include-did-web=false)
      //        → explicit operator opt-out, no binding embedded.
      //   2. --did-web <identifier> [--did-web-authority-host <host>]
      //        → explicit CLI override; bypasses fortress-config.
      //   3. fortress-config record present
      //        → auto-include with the registered identifier +
      //          authority_host. Operator may add
      //          --did-web-published-at to claim a publication time.
      //   4. neither flags nor record
      //        → silent skip (no binding embedded; backward compat).
      const includeDidWebFlag = flagValue(argv, "--include-did-web");
      const explicitOptOut =
        hasFlag(argv, "--no-did-web") || includeDidWebFlag === "false";
      const didWebIdentifier = flagValue(argv, "--did-web");
      const didWebAuthorityHost = flagValue(argv, "--did-web-authority-host");
      const didWebPublishedAt = flagValue(argv, "--did-web-published-at");
      let exportDidWeb: ExitBundleDidWebBinding | undefined;
      let didWebSource:
        | "cli-override"
        | "fortress-config"
        | "opted-out"
        | "no-record"
        | undefined;
      if (explicitOptOut) {
        didWebSource = "opted-out";
      } else if (didWebIdentifier !== undefined) {
        if (didWebAuthorityHost === undefined) {
          write(
            err,
            "Error: --did-web requires --did-web-authority-host=<host>\n",
          );
          return 2;
        }
        exportDidWeb = {
          identifier: didWebIdentifier,
          authority_host: didWebAuthorityHost,
          ...(didWebPublishedAt !== undefined
            ? { published_at: didWebPublishedAt }
            : {}),
        };
        didWebSource = "cli-override";
      } else {
        const record = await loadFortressDidWebRecord(ctx.storagePath);
        if (record !== null) {
          exportDidWeb = {
            identifier: record.identifier.did,
            authority_host: record.identifier.authority_host,
            ...(didWebPublishedAt !== undefined
              ? { published_at: didWebPublishedAt }
              : {}),
          };
          didWebSource = "fortress-config";
        } else {
          didWebSource = "no-record";
        }
      }
      // `--state-namespace` is repeatable and OPTIONAL. When the operator names
      // none, `flagValues` returns [], which must NOT be forwarded:
      // passing an empty selection meant "export nothing" and produced a signed
      // bundle with zero state entries. Spread it conditionally so "named none"
      // reaches the exporter as an absent option, which is its contract for
      // "discover and export every namespace." Same shape as
      // `didWebAllowedHosts` on the import path below; `exportEncryptedState`
      // now throws on an empty array so this cannot silently regress.
      const stateNamespaces = flagValues(argv, "--state-namespace");
      const result = await exportExitBundle({
        bundleDir: outDir,
        storage: ctx.storage,
        masterKey: ctx.masterKey,
        identityManager: ctx.identityManager,
        auditLog: ctx.auditLog,
        reputationStore: ctx.reputationStore,
        policy,
        config,
        stateStoragePath: ctx.stateStoragePath,
        ...(stateNamespaces.length > 0 ? { stateNamespaces } : {}),
        keySource: ctx.keySource,
        // The CLI is an operator terminal: safe to mint + display the
        // bundle re-key key (it is never written into the bundle).
        mintStateRekeyKey: true,
        // Operator-driven full-fortress export: the ownership partition (exit
        // machinery Slice 1) is deliberately not applied here. Named, auditable
        // acknowledgement, not a silent skip.
        unpartitionedLegacyExport: true,
        ...(exportDidWeb !== undefined ? { didWeb: exportDidWeb } : {}),
      });
      if (json) {
        write(
          out,
          JSON.stringify(
            { ...result, did_web_source: didWebSource },
            null,
            2,
          ) + "\n",
        );
      } else {
        write(out, `exported: ${result.bundle_dir}\n`);
        write(out, `manifest_hash: ${result.manifest_hash}\n`);
        // How much state actually travelled is the one number an operator needs
        // to sanity-check an exit bundle, and until now the export path printed
        // neither it nor `result.warnings` (verify and import both print
        // warnings). A successful-looking export with no state count is how a
        // silently-empty bundle passed for a good one.
        write(out, `state_entries: ${result.state_entry_count}\n`);
        if (didWebSource === "fortress-config" && exportDidWeb) {
          write(
            out,
            `did:web: auto-included from fortress config (${exportDidWeb.identifier})\n`,
          );
        } else if (didWebSource === "cli-override" && exportDidWeb) {
          write(
            out,
            `did:web: included via CLI override (${exportDidWeb.identifier})\n`,
          );
        } else if (didWebSource === "opted-out") {
          write(out, `did:web: skipped (operator opt-out via --no-did-web)\n`);
        } else if (didWebSource === "no-record") {
          write(
            out,
            `did:web: not included (no fortress config; run "sanctuary did-web issue" to register)\n`,
          );
        }
        for (const warning of result.warnings ?? []) {
          write(out, `warning: ${warning}\n`);
        }
        for (const item of result.unsupported_artifacts) {
          write(out, `unsupported: ${item}\n`);
        }
        if (result.state_rekey_key !== undefined) {
          write(
            out,
            [
              "",
              "BUNDLE RE-KEY KEY (displayed once, NOT stored in the bundle):",
              `  ${result.state_rekey_key}`,
              "Store it separately from the bundle directory. Importing this",
              "bundle's encrypted state requires it:",
              "  sanctuary exit import <dir> --activate --import-state \\",
              "    --source-recovery-key <key>",
              "If it is lost, re-export the bundle from the source fortress.",
              "",
            ].join("\n")
          );
        }
      }
      // Outside the --json branch on purpose: a zero-state export is the one
      // outcome an operator must not be able to miss, and it goes to stderr so
      // it survives `sanctuary exit export --json > bundle.json`. Symmetric with
      // the import path's "NO STATE was imported" block below. It is a WARNING,
      // not a failure: a fresh fortress with no state has nothing to export, and
      // the bundle still carries a usable identity, policy set, and audit
      // receipts. The exporter no longer has a silent way to reach zero, so a
      // zero here means the source fortress really is empty.
      if (result.state_entry_count === 0) {
        write(
          err,
          [
            "",
            "WARNING: NO STATE was exported. This bundle carries zero state entries.",
            stateNamespaces.length > 0
              ? `The named namespaces matched nothing: ${stateNamespaces.join(", ")}`
              : "Every namespace under the fortress state directory was searched.",
            "It can restore identity, policy, and audit receipts, but no memory or",
            "namespace data, and no bundle re-key key was minted (nothing to re-key).",
            "Confirm the source fortress is genuinely empty before treating this as",
            // A concrete path the operator can list, not a CLI command: state
            // enumeration is an MCP tool (state_list), so naming a `sanctuary
            // state ...` command here would send them to something that does
            // not exist.
            `a complete exit. Each namespace is a directory under:`,
            `  ${ctx.stateStoragePath}`,
            "",
          ].join("\n")
        );
      }
      return 0;
    }

    if (command === "import" || command === "import-exit-bundle") {
      const dir = argv[1];
      if (!dir) {
        write(
          err,
          command === "import-exit-bundle"
            ? "Usage: sanctuary import-exit-bundle <dir> [--activate]\n"
            : "Usage: sanctuary exit import <dir> [--activate]\n",
        );
        return 2;
      }

      // Pre-flight: validate the bundle directory and manifest BEFORE
      // prompting for a passphrase. Catches the most common operator
      // error (wrong path or malformed bundle) without forcing auth.
      const bundleRoot = resolve(dir);
      try {
        await access(bundleRoot);
      } catch {
        write(err, `Error: bundle directory not found: ${bundleRoot}\n`);
        return 1;
      }
      const manifestPath = join(bundleRoot, "manifest.json");
      try {
        const raw = await fsReadFile(manifestPath, "utf8");
        JSON.parse(raw);
      } catch {
        write(
          err,
          `Error: bundle manifest missing or malformed at ${manifestPath}\n`
        );
        return 1;
      }

      const activate = hasFlag(argv, "--activate");
      const importState = hasFlag(argv, "--import-state");
      const forceRebind = hasFlag(argv, "--force-rebind");
      const sourcePassphrase = flagValue(argv, "--source-passphrase");
      const sourceRecoveryKey = flagValue(argv, "--source-recovery-key");
      // A4: the named confirmation that a recovery key on a bundle WITHOUT a
      // source_custody block is the source fortress's raw master. Meaningless
      // on its own, so refuse the shape rather than ignoring the flag.
      const legacySourceMaster = hasFlag(argv, "--legacy-source-master");
      if (legacySourceMaster && !sourceRecoveryKey) {
        write(
          err,
          "--legacy-source-master requires --source-recovery-key (it confirms " +
            "how that key is interpreted)\n",
        );
        return 2;
      }
      if (importState && !activate) {
        write(err, "--import-state requires --activate\n");
        return 2;
      }
      if (!importState && (sourcePassphrase || sourceRecoveryKey)) {
        write(
          err,
          "--source-passphrase and --source-recovery-key require --import-state\n"
        );
        return 2;
      }
      // F-1.3.1-N-003 follow-through: --import-state without source
      // credentials can never import (the exported state is encrypted under
      // the source master key, which only --source-passphrase /
      // --source-recovery-key supply). Without this gate the request silently
      // ends in `staged_requires_source_key` (no resume path exists) or, for a
      // stateless bundle, the post-activate WARNING tells the operator to
      // "re-run with --import-state" — which they already did. Fail closed
      // with actionable guidance instead.
      if (importState && !sourcePassphrase && !sourceRecoveryKey) {
        write(
          err,
          "--import-state requires --source-passphrase or --source-recovery-key " +
            "(the source fortress credentials that decrypt the exported state)\n"
        );
        return 2;
      }
      if (activate) {
        const prompt = forceRebind
          ? "Tier 1 approval required: activate verified imported exit bundle AND replace the existing fortress public identity (force-rebind)?"
          : "Tier 1 approval required: activate verified imported exit bundle?";
        const approved = await confirmTier1(
          prompt,
          hasFlag(argv, "--yes") || hasFlag(argv, "-y"),
          stdin,
          err
        );
        if (!approved) {
          write(err, "Aborted.\n");
          return 1;
        }
      }
      const ctx = await openExitContext(argv, env);
      const conflict =
        (flagValue(argv, "--conflict") as "skip" | "overwrite" | "version" | undefined) ??
        "skip";
      if (!["skip", "overwrite", "version"].includes(conflict)) {
        write(err, "--conflict must be skip, overwrite, or version\n");
        return 2;
      }
      // Recognition-Layer Path C primary build 2: did:web import-side
      // flags. --did-web-allowed-host is repeatable; an empty list
      // means the importer refuses to leave the fortress (no-outbound-
      // by-default) and surfaces a warning if the manifest carries a
      // did_web binding. --skip-did-web-verify is the explicit
      // operator override for accepting the manifest signature alone.
      const didWebAllowedHosts = flagValues(
        argv,
        "--did-web-allowed-host",
      );
      const skipDidWebVerify = hasFlag(argv, "--skip-did-web-verify");
      let result;
      try {
        result = await importExitBundle({
          bundleDir: dir,
          storage: ctx.storage,
          masterKey: ctx.masterKey,
          identityManager: ctx.identityManager,
          auditLog: ctx.auditLog,
          reputationStore: ctx.reputationStore,
          activate,
          forceRebind,
          conflictResolution: conflict,
          ...(importState && sourcePassphrase
            ? { sourcePassphrase }
            : {}),
          ...(importState && sourceRecoveryKey
            ? { sourceRecoveryKey }
            : {}),
          ...(importState && sourceRecoveryKey && legacySourceMaster
            ? { legacyRecoveryKeyIsMaster: true }
            : {}),
          destinationSignerIdentityId: flagValue(argv, "--destination-identity-id"),
          ...(didWebAllowedHosts.length > 0
            ? { didWebAllowedHosts }
            : {}),
          skipDidWebVerify,
        });
      } catch (e) {
        if (e instanceof InvalidExitBundleError) {
          write(err, `Error: ${e.message}\n`);
          return 1;
        }
        if (e instanceof ExitBundleStateImportIncompleteError) {
          if (json) {
            write(
              out,
              JSON.stringify(
                { verdict: "FAIL", error: e.message, state: e.state },
                null,
                2,
              ) + "\n",
            );
          } else {
            writeStateSkippedCounters(err, e.state);
          }
          write(err, `Error: ${e.message}\n`);
          return 1;
        }
        throw e;
      }
      if (json) {
        write(
          out,
          JSON.stringify(
            { verdict: result.verified ? "PASS" : "FAIL", ...result },
            null,
            2,
          ) + "\n",
        );
      } else {
        write(out, `verdict: ${result.verified ? "PASS" : "FAIL"}\n`);
        write(out, `verified: ${result.verified}\n`);
        write(out, `activated: ${result.activated}\n`);
        write(out, `state_conflicts: ${result.conflicts.state_conflicts.length}\n`);
        write(out, `reputation_conflicts: ${result.conflicts.reputation_conflicts.length}\n`);
        write(out, `state_status: ${result.state.status}\n`);
        write(out, `state_imported_keys: ${result.state.imported_keys}\n`);
        writeStateSkippedCounters(out, result.state);
        write(out, `reputation_imported_attestations: ${result.reputation.imported_attestations}\n`);
        for (const warning of result.warnings) write(out, `warning: ${warning}\n`);
        for (const item of result.unsupported_artifacts) {
          write(out, `unsupported: ${item}\n`);
        }
      }
      if (
        activate &&
        result.activated &&
        result.state.status === "not_requested" &&
        result.state.imported_keys === 0
      ) {
        write(
          err,
          [
            "WARNING: Bundle activated but NO STATE was imported to the target fortress.",
            "Identity, audit chain, and did-web entries were NOT transferred.",
            "To import state, re-run with: sanctuary exit import <dir> --activate --import-state",
            "Without --import-state, only the manifest binding is activated.",
            "",
          ].join("\n")
        );
      }
      return result.verified ? 0 : 1;
    }

    write(err, `Unknown exit command: ${command}\n`);
    return 2;
  } catch (error) {
    write(err, error instanceof Error ? `${error.message}\n` : `${String(error)}\n`);
    return 1;
  }
}
