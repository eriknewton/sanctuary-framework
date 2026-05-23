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
import { AuditLog } from "../l2-operational/audit-log.js";
import { StateStore } from "../l1-cognitive/state-store.js";
import { IdentityManager } from "../l1-cognitive/tools.js";
import { ReputationStore } from "../l4-reputation/reputation-store.js";
import { loadConfig } from "../config.js";
import { loadPrincipalPolicy, MalformedPrincipalPolicyError } from "../principal-policy/loader.js";
import { deriveMasterKey, type KeyDerivationParams } from "../core/key-derivation.js";
import { bytesToString, fromBase64url, stringToBytes } from "../core/encoding.js";
import { exportExitBundle, importExitBundle, exitBundleManifestShape } from "./bundle.js";
import type { ExitBundleDidWebBinding } from "../contracts/v1.1/exit-bundle-manifest.js";
import { verifyExitBundle, InvalidExitBundleError } from "./verifier.js";
import { loadFortressDidWebRecord } from "../recognition/did-web.js";

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

function flagValue(argv: string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

function hasFlag(argv: string[], name: string): boolean {
  return argv.includes(name);
}

function repeatedFlagValues(argv: string[], name: string): string[] {
  const values: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === name && argv[i + 1]) values.push(argv[++i]!);
  }
  return values;
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
  let keySource: ExitContext["keySource"] = "unknown";
  if (passphrase) {
    let existingParams: KeyDerivationParams | undefined;
    const raw = await storage.read("_meta", "key-params");
    if (raw) existingParams = JSON.parse(bytesToString(raw)) as KeyDerivationParams;
    const derived = await deriveMasterKey(passphrase, existingParams);
    masterKey = derived.key;
    if (!existingParams) {
      await storage.write(
        "_meta",
        "key-params",
        stringToBytes(JSON.stringify(derived.params))
      );
    }
    keySource = "passphrase";
  } else if (recoveryKey) {
    masterKey = fromBase64url(recoveryKey);
    if (masterKey.length !== 32) {
      throw new Error("SANCTUARY_RECOVERY_KEY must decode to 32 bytes.");
    }
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
  verify <dir>                Verify manifest, audit receipts, and reputation bundle
  import <dir> [--activate]   Verify, report conflicts, and optionally activate
  manifest-shape              Print the v1.1 manifest shape

Options:
  --passphrase <value>              Current destination/source passphrase
  --source-passphrase <value>       Source passphrase for state re-key on import
  --source-recovery-key <value>     Source recovery key for state re-key on import
  --destination-identity-id <id>    Destination signer for re-keyed state
  --import-state                    Import encrypted state during activation.
                                    Requires --activate and source credentials.
  --state-namespace <name>          Export a namespace; repeatable
  --conflict <skip|overwrite|version>
  --force-rebind                    On import: explicitly replace an existing fortress
                                    public identity (Tier 1 confirmation)
  --accept-unverifiable-attestations
                                    On import: accept reputation attestations whose
                                    signer DID is not in the bundle (Tier 1 confirmation)
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

Options:
  --out <dir>                       Destination bundle directory.
  --passphrase <value>              Current fortress passphrase.
  --state-namespace <name>          Export a namespace; repeatable.
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

  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
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
        write(out, `manifest: ${result.passed ? "verified" : "failed"}\n`);
        write(out, `identity: ${result.manifest_summary.identity_id}\n`);
        write(out, `artifacts: ${result.manifest_summary.artifact_count}\n`);
        if (result.reputation) {
          write(
            out,
            `reputation: ${result.reputation.verified_attestations}/${result.reputation.attestation_count} attestations verified\n`
          );
        }
        for (const warning of result.warnings) write(out, `warning: ${warning}\n`);
        for (const item of result.unsupported_artifacts) {
          write(out, `unsupported: ${item}\n`);
        }
      }
      return result.passed ? 0 : 1;
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
        return 1;
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
        stateNamespaces: repeatedFlagValues(argv, "--state-namespace"),
        keySource: ctx.keySource,
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
        for (const item of result.unsupported_artifacts) {
          write(out, `unsupported: ${item}\n`);
        }
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
      const acceptUnverifiableAttestations = hasFlag(
        argv,
        "--accept-unverifiable-attestations"
      );
      const sourcePassphrase = flagValue(argv, "--source-passphrase");
      const sourceRecoveryKey = flagValue(argv, "--source-recovery-key");
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
        if (acceptUnverifiableAttestations) {
          const acceptApproved = await confirmTier1(
            "Tier 1 approval required: accept unverifiable reputation attestations on import?",
            hasFlag(argv, "--yes") || hasFlag(argv, "-y"),
            stdin,
            err
          );
          if (!acceptApproved) {
            write(err, "Aborted.\n");
            return 1;
          }
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
      const didWebAllowedHosts = repeatedFlagValues(
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
          acceptUnverifiableAttestations,
          conflictResolution: conflict,
          ...(importState && sourcePassphrase
            ? { sourcePassphrase }
            : {}),
          ...(importState && sourceRecoveryKey
            ? { sourceRecoveryKey }
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
