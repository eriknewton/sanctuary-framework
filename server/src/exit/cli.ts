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
import { resolveCliMasterKey, readCustodyEnvelope } from "../core/master-custody.js";
import {
  exportExitBundle,
  importExitBundle,
  exitBundleManifestShape,
  ExitBundleImportError,
  ExitBundleStateImportIncompleteError,
  recoverInterruptedExitImportsOrThrow,
  EXIT_RECOVERY_VERB,
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

/**
 * F2 (Exit V2 D1 operator finding, 2026-08-23): THE single shared table of
 * plain-English sentences for every `failure_class` the verifier can emit.
 * Both the human-mode `verify` output and the `--json` output's
 * `reason_text` field read from this SAME object (see the `verify` command
 * handler below) - never a hand-mirrored switch in one branch and this
 * table in the other - so the two surfaces cannot describe the same
 * failure differently. `Record<NonNullable<...failure_class>, string>`
 * means TypeScript itself refuses to compile if a class is ever added to
 * the contract's union without a sentence here (full-set parity enforced
 * at the type level, not just by a test).
 *
 * Drill trigger (D1-OP-F2): human-mode `verify` on a refused bundle printed
 * `verdict: FAIL` and three neutral fields with no reason at all, even
 * though the JSON path already carried a specific `failure_class` -
 * "Mostly greek" was Erik's own read of the human output.
 */
const FAILURE_CLASS_EXPLANATIONS: Record<
  NonNullable<ExitBundleVerifierResult["failure_class"]>,
  string
> = {
  manifest_signature_invalid:
    "The bundle's signed manifest does not verify against its claimed signer. It may be corrupted, tampered with, or exported by a different process than the one that signed it.",
  manifest_unknown_version:
    "This bundle's manifest format version is not one this Sanctuary build knows how to verify. Update Sanctuary, or re-export the bundle from a compatible version.",
  manifest_signature_scheme_invalid:
    "The manifest declares a signature scheme this Sanctuary build does not support. Update Sanctuary, or re-export the bundle from a compatible version.",
  artifact_hash_mismatch:
    "At least one artifact's contents do not match the hash recorded in the signed manifest. The file was altered, or the bundle is corrupted.",
  artifact_missing:
    "At least one artifact the manifest lists could not be found in the bundle directory. The download or copy is incomplete.",
  artifact_size_mismatch:
    "At least one artifact's size does not match what the signed manifest recorded. The file was truncated, altered, or the bundle is corrupted.",
  aggregate_hash_mismatch:
    "The combined hash of the bundle's artifacts does not match the value the manifest signed. The bundle's artifact set does not match what was originally exported.",
  artifact_path_unsafe:
    "The manifest names an artifact path that cannot be trusted to stay inside the bundle directory. Refusing this bundle.",
  artifact_path_duplicate:
    "The manifest lists the same artifact path more than once. This bundle is malformed.",
  artifact_kind_duplicate:
    "The manifest lists more than one artifact of a kind this format allows only once. This bundle is malformed.",
  artifact_set_invalid:
    "The set of artifacts in this bundle does not match what this manifest version requires (something is missing or something extra is present). This bundle is malformed.",
  artifact_directory_unlisted_file:
    "A file exists in the bundle directory that the manifest does not list. Refusing to trust an unaccounted-for file.",
  artifact_path_escapes_root:
    "An artifact path in the manifest points outside the bundle directory. This bundle is malformed or was tampered with.",
  archive_contains_symlink:
    "The bundle contains a symbolic link, which this format never uses legitimately. Refusing this bundle.",
  private_material_present:
    "The bundle appears to contain private key material that should never leave a fortress. Refusing to import it; do not share this bundle with anyone.",
  identity_binding_mismatch:
    "The identity recorded in the manifest does not match the identity artifact inside the bundle.",
  identity_signature_invalid:
    "The identity artifact's own signature does not verify.",
  rotation_chain_invalid:
    "This identity's key-rotation history does not verify from its retired keys forward to the current one.",
  reputation_bundle_signature_invalid:
    "The reputation data's signature does not verify.",
  reputation_completeness_mismatch:
    "The reputation data does not account for the number of attestations the manifest claims.",
  reputation_attestation_signature_invalid:
    "At least one reputation attestation's signature does not verify.",
  reputation_unverifiable_attestations:
    "At least one reputation attestation was signed by a party this bundle does not identify, so it cannot be verified. Re-run with --accept-unverifiable-attestations to preview anyway (import always verifies strictly regardless of this flag).",
  known_signers_invalid:
    "The bundle's table of known signers, used to verify reputation attestations, is malformed, incorrectly signed, or otherwise cannot be trusted.",
  encrypted_state_entries_unreadable:
    "The bundle's encrypted state passed its own signature and hash checks, but its internal entry list is not in the shape this Sanctuary build expects to read.",
  other:
    "The verifier reported a failure it does not have a specific category for. Check the warnings below for detail.",
};

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

  // F1 (Exit V2 drill D1, 2026-08-22): "fortress open" for every `sanctuary
  // exit` subcommand, run BEFORE identityManager.load() or any other
  // reader below touches storage (LOW-G, coordinator gate, 2026-08-22:
  // moved earlier in this function - a killed import can leave identity
  // or state data mid-write, and the checks below should see the
  // RECOVERED fortress, not the half-applied one). `...OrThrow` (MEDIUM-3,
  // coordinator gate, 2026-08-22) so a partial/unparseable rollback stops
  // fortress open instead of silently proceeding against a possibly
  // half-applied target.
  await recoverInterruptedExitImportsOrThrow(storage, auditLog);

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

/**
 * F1 fix-round (independent gate on #1304, HIGH): named refusals for
 * `openFortressForRecoveryOnly` below. `recover`'s entire point is to roll
 * back an interrupted import without itself being a thing that mutates a
 * fortress; these name exactly what is missing and which OTHER verb is the
 * one that would legitimately perform the write `recover` refuses to do.
 */
export class ExitRecoverNoFortressError extends Error {
  constructor(storagePath: string) {
    super(
      `No fortress found at ${storagePath}: there is no custody envelope ` +
        "and no legacy custody markers. Nothing to recover. `sanctuary exit " +
        `${EXIT_RECOVERY_VERB}\` deliberately never establishes custody; if ` +
        "you intended to create a new fortress, run a normal Sanctuary " +
        "operation instead (for example `sanctuary exit export`, or start " +
        "the Sanctuary MCP server)."
    );
    this.name = "ExitRecoverNoFortressError";
  }
}

export class ExitRecoverLegacyMigrationRequiredError extends Error {
  constructor() {
    super(
      "This fortress uses legacy (pre-envelope) custody. `sanctuary exit " +
        `${EXIT_RECOVERY_VERB}\` deliberately never migrates custody as a ` +
        "side effect. Run `sanctuary exit export`, `sanctuary exit import`, " +
        "or any other normal Sanctuary operation against this fortress " +
        "first to complete the migration, then re-run `sanctuary exit " +
        `${EXIT_RECOVERY_VERB}\`.`
    );
    this.name = "ExitRecoverLegacyMigrationRequiredError";
  }
}

/**
 * F1 fix-round (independent gate on #1304, HIGH): `recover`'s OWN open
 * path, deliberately NOT `openExitContext` above. `openExitContext` always
 * passes `bootstrap: true` to `resolveCliMasterKey`, and `establishMaster`
 * (core/master-custody.ts) can MINT a brand-new custody envelope on a
 * virgin fortress via that flag, or MIGRATE a legacy (pre-envelope)
 * fortress to an envelope regardless of that flag (the legacy branches key
 * off `_meta` markers, not `firstRun`) - both real writes, and both used to
 * happen before the exit-admission lock was ever acquired
 * (`recoverInterruptedExitImportsOrThrow`, which owns the lock, only runs
 * AFTER `mkdir` + master-key resolution in `openExitContext`). On a fresh
 * fortress `recover` used to print "nothing to recover" AFTER silently
 * creating custody state; on a legacy fortress it migrated custody before
 * ever discovering a held admission lock.
 *
 * The fix: peek at custody with a read-only `readCustodyEnvelope` call - no
 * `mkdir`, no `establishMaster`, so nothing on disk changes - before
 * resolving anything. If no envelope exists, refuse BY NAME (distinguishing
 * "no fortress here at all" from "legacy fortress, needs migration") and
 * never call `resolveCliMasterKey` at all, so `establishMaster`'s mutating
 * branches are structurally unreachable from this function. Only once an
 * envelope is CONFIRMED present does it resolve the master key -
 * `establishMaster`'s `if (envelope) {...}` branch unwraps and returns
 * without ever writing, so this is non-mutating regardless of the
 * `bootstrap` flag, and `bootstrap` is not passed here at all. Nothing
 * above `recoverInterruptedExitImportsOrThrow` performs a write, so the
 * admission lock it acquires genuinely gates every possible one.
 *
 * Deliberately does NOT load IdentityManager or construct ReputationStore:
 * `recover` needs neither, and skipping them removes any question of
 * whether their own load paths could write (see
 * fortress-open-recovery-wiring.test.ts's own note on IdentityManager's
 * primary-identity-pointer persistence for why that question is live for
 * OTHER verbs, just not for this one).
 */
async function openFortressForRecoveryOnly(
  argv: string[],
  env: NodeJS.ProcessEnv
): Promise<{ recovered: number }> {
  const passphrase =
    flagValue(argv, "--passphrase") ?? env.SANCTUARY_PASSPHRASE;
  const recoveryKey = env.SANCTUARY_RECOVERY_KEY;
  const config = await loadConfig();
  const stateStoragePath = join(config.storage_path, "state");
  const storage = new FilesystemStorage(stateStoragePath);

  // Read-only peek. `readCustodyEnvelope` is a plain `storage.read` (see
  // storage/filesystem.ts: `read()` never creates a directory, it catches
  // ENOENT and returns null) - a missing fortress leaves NOTHING on disk.
  const envelope = await readCustodyEnvelope(storage);
  if (!envelope) {
    // Legacy markers (core/master-custody.ts's `establishMaster`): present
    // without an envelope means this fortress predates envelope custody
    // and opening it normally would migrate it - a write `recover` must
    // not perform as a side effect of a "did anything need rolling back"
    // check.
    const legacyParams = await storage.read("_meta", "key-params");
    const legacyRecoveryHash = await storage.read("_meta", "recovery-key-hash");
    if (legacyParams || legacyRecoveryHash) {
      throw new ExitRecoverLegacyMigrationRequiredError();
    }
    throw new ExitRecoverNoFortressError(config.storage_path);
  }

  let masterKey: Uint8Array;
  if (passphrase) {
    masterKey = await resolveCliMasterKey(storage, {
      passphrase,
      storagePathHint: config.storage_path,
    });
  } else if (recoveryKey) {
    masterKey = await resolveCliMasterKey(storage, {
      recoveryKey,
      storagePathHint: config.storage_path,
    });
  } else {
    throw new Error(
      "sanctuary exit requires SANCTUARY_PASSPHRASE, --passphrase, or SANCTUARY_RECOVERY_KEY."
    );
  }

  const auditLog = new AuditLog(storage, masterKey);
  // The ONLY write this function's success path can perform, and only
  // once `recoverInterruptedExitImportsOrThrow` has acquired the
  // exit-admission lock internally (storage/exit-import-journal.ts).
  return recoverInterruptedExitImportsOrThrow(storage, auditLog);
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
  recover                     Open THIS fortress (not a bundle directory) and
                              roll back any interrupted exit-import journal
                              entry left by a killed import, rotation, or
                              resume. Needs fortress credentials same as
                              export/import. Mutates nothing beyond finishing
                              that rollback; safe to run when there is
                              nothing to recover. Refuses (never creates or
                              migrates custody) if no fortress exists yet,
                              or if the fortress still uses pre-envelope
                              legacy custody - run export/import or a normal
                              Sanctuary operation first in either case.

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
  --accept-compromised-rotation-keys
                                    On import: explicitly admit state entries whose
                                    only valid source signature is a key retired by
                                    a compromised-reason rotation. Refused by default.
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
        // F2: `reason_text` reads FAILURE_CLASS_EXPLANATIONS, the same
        // table the human branch below reads for its `reason:` sentence -
        // one table, never a hand-mirrored copy per output mode. Additive
        // field, only present when there is a failure_class to explain;
        // every existing JSON key is untouched.
        const reasonText =
          result.failure_class !== undefined
            ? { reason_text: FAILURE_CLASS_EXPLANATIONS[result.failure_class] }
            : {};
        write(
          out,
          JSON.stringify(
            { verdict: result.passed ? "PASS" : "FAIL", ...result, ...reasonText },
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
        //
        // F2 (Exit V2 D1 operator finding, 2026-08-23): same additive-only
        // discipline - a refused bundle previously printed `verdict: FAIL`
        // and three neutral fields with NO reason at all. `reason:` is the
        // machine-branchable failure_class (the exact string `--json`'s
        // `reason_text` key is looked up from too); the sentence under it
        // is FAILURE_CLASS_EXPLANATIONS[<that class>].
        if (result.failure_class !== undefined) {
          write(out, `reason: ${result.failure_class}\n`);
          write(out, `${FAILURE_CLASS_EXPLANATIONS[result.failure_class]}\n`);
        }
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

    // F1 (Exit V2 D1 operator finding, 2026-08-23): the verb every
    // recovery hint in the codebase names (EXIT_RECOVERY_VERB, defined in
    // storage/exit-import-journal.ts and re-exported via bundle.js).
    // Deliberately `openFortressForRecoveryOnly`, NOT `openExitContext`
    // (fix round, independent gate on #1304, HIGH): that function refuses
    // by name rather than bootstrapping or migrating custody as a side
    // effect, and only resolves anything after confirming an envelope
    // already exists, so the exit-admission lock it acquires internally
    // (recoverInterruptedExitImportsOrThrow -> withExitAdmissionLock) gates
    // every possible write, not just the ones after mkdir/master-key
    // resolution.
    if (command === EXIT_RECOVERY_VERB) {
      const { recovered } = await openFortressForRecoveryOnly(argv, env);
      if (json) {
        write(out, JSON.stringify({ recovered }, null, 2) + "\n");
      } else if (recovered > 0) {
        write(
          out,
          `recovered: ${recovered} journal entr${recovered === 1 ? "y" : "ies"} rolled back\n`
        );
      } else {
        write(out, "nothing to recover\n");
      }
      return 0;
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
        write(out, `rotation_hop_count: ${report.rotation.hop_count}\n`);
        write(
          out,
          `rotation_chain_signature_verified: ${report.rotation.chain_signature_verified}\n`,
        );
        write(
          out,
          `rotation_terminates_at_current: ${report.rotation.terminates_at_current}\n`,
        );
        if (report.rotation.invalid_reason !== undefined) {
          write(out, `rotation_invalid_reason: ${report.rotation.invalid_reason}\n`);
        }
        write(out, `rotation_compromised_hops: ${report.rotation.compromised_hops}\n`);
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
      // "re-run with --import-state" - which they already did. Fail closed
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
      const acceptCompromisedRotationKeys = hasFlag(
        argv,
        "--accept-compromised-rotation-keys",
      );
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
          acceptCompromisedRotationKeys,
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
                { verdict: "FAIL", code: e.code, error: e.message, state: e.state },
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
        if (e instanceof ExitBundleImportError) {
          if (json) {
            write(
              out,
              JSON.stringify(
                { verdict: "FAIL", code: e.code, error: e.message },
                null,
                2,
              ) + "\n",
            );
          } else {
            write(err, `Error [${e.code}]: ${e.message}\n`);
          }
          return 1;
        }
        throw e;
      }
      if (json) {
        const verdict = result.verified ? "PASS" : "FAIL";
        write(
          out,
          JSON.stringify(
            {
              verdict,
              ...(!result.verified
                ? { code: "BUNDLE_VERIFICATION_FAILED" }
                : {}),
              ...result,
            },
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
