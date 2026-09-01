/**
 * sanctuary doctor
 *
 * Read-only local health diagnostic.
 */

import { execSync as nodeExecSync } from "node:child_process";
import { createHash } from "node:crypto";
import { access, constants, readFile, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { getSanctuaryVersion } from "../version.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { IdentityManager } from "../cognitive/tools.js";
import { resolveCliMasterKey } from "../core/master-custody.js";
import { detectCustodyFactorOrphan } from "../wrap/orphan-detection.js";
import { getPlatformPaths } from "../wrap/config-reader.js";
import { hermesConfigYamlPath, hermesSanctuaryEntryEnvValue } from "../wrap/hermes-yaml.js";
import { readSdwOwnerPin } from "../sdw/memory-isolation.js";
import { SDW_OWNER_PIN_KEY } from "../sdw/write-gate.js";
import { SDW_META_NAMESPACE } from "../sdw/records.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
import { EXIT_IMPORT_JOURNAL_NAMESPACE, EXIT_RECOVERY_VERB } from "../exit/bundle.js";
import {
  describePyYamlCandidateFailure,
  probePyYamlCandidates,
  type ParseParityOptions,
} from "../wrap/hermes-yaml-parse-parity.js";
import { parsePolicy } from "../principal-policy/loader.js";
import { resolveStoragePath } from "../paths.js";
import { checkNodeVersion } from "./node-version.js";
import { verifyFortressAuditFullPicture } from "../operational/audit-store-split.js";
import {
  exportAuditChain,
  fortressRanAuditStoreSplitMigration,
} from "./audit-chain-export.js";
import {
  verifyAuditChainRecords,
  type ExportRecord,
} from "./audit-chain-verify.js";
import {
  consumeFlagValue,
  FORTRESS_FLAG_USAGE_EXIT_CODE,
  fortressFlagRefusalText,
  shellQuoteSingleArg,
} from "./argv.js";

// Canonical version source. A bare `require("../../package.json")` resolves to
// the repo-root package.json (no `version`) when bundled to server/dist/; the
// helper reads server/package.json from both src/ and dist/ and never returns
// undefined.
const PKG_VERSION = getSanctuaryVersion();

export type DoctorStatus = "OK" | "WARN" | "FAIL";

export interface DoctorCheck {
  name: string;
  status: DoctorStatus;
  message: string;
  hint: string;
}

export interface DoctorCommandArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  execSyncFn?: (command: string) => string;
  storagePath?: string;
  nodeVersion?: string;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

export async function runDoctorCommand(
  args: DoctorCommandArgs,
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const argv = args.argv;
  if (argv.includes("--help") || argv.includes("-h")) {
    printUsage(out);
    return 0;
  }

  const json = argv.includes("--json");
  const env = args.env ?? process.env;
  // Must match consumeFlagValue in ./argv.ts: a dropped --fortress value must
  // refuse, never silently resolve the default fortress; running doctor
  // checks against the wrong fortress is a constraint-5 violation.
  const consumedFortress = consumeFlagValue(argv, "--fortress");
  if (consumedFortress.error !== undefined) {
    write(err, `${fortressFlagRefusalText(consumedFortress.error)}\n`);
    return FORTRESS_FLAG_USAGE_EXIT_CODE;
  }
  const storagePath =
    consumedFortress.value ??
    args.storagePath ??
    env.SANCTUARY_FORTRESS_PATH ??
    resolveStoragePath(env);

  try {
    const checks = await runDoctorChecks({
      env,
      storagePath,
      platform: args.platform ?? process.platform,
      execSyncFn: args.execSyncFn,
      nodeVersion: args.nodeVersion,
    });
    if (json) {
      write(
        out,
        JSON.stringify(
          {
            storage_path: storagePath,
            package_version: PKG_VERSION,
            checks,
          },
          null,
          2,
        ) + "\n",
      );
    } else {
      for (const check of checks) {
        write(out, `${check.status.padEnd(4)} ${check.name}: ${check.message}. Hint: ${check.hint}\n`);
      }
    }
    return checks.some((check) => check.status === "FAIL") ? 1 : 0;
  } catch (error) {
    write(err, `sanctuary doctor: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
}

export async function runDoctorChecks(opts: {
  env: NodeJS.ProcessEnv;
  storagePath: string;
  platform: NodeJS.Platform;
  execSyncFn?: (command: string) => string;
  nodeVersion?: string;
  /**
   * Test-only seams for the Hermes config-parser check. Deliberately NOT on
   * `DoctorCommandArgs`: nothing on the CLI surface (argv or env) may steer
   * which interpreter is probed, matching the wrap guard's rule that the
   * candidate list is code-controlled. Doctor is read-only and decides nothing,
   * so an internal seam here cannot bypass a mutating gate.
   */
  hermesConfigPath?: string;
  pyYamlProbe?: ParseParityOptions;
}): Promise<DoctorCheck[]> {
  const checks: DoctorCheck[] = [];
  checks.push(checkRequiredNodeVersion(opts.nodeVersion));
  checks.push(await checkStateDir(opts.storagePath));
  const masterKey = await resolveMasterKeyIfAvailable(opts.storagePath, opts.env);
  checks.push(await checkIdentity(opts.storagePath, masterKey));
  checks.push(await checkPolicy(opts.storagePath));
  checks.push(await checkAuditChain(opts.storagePath, masterKey ?? undefined));
  checks.push(await checkCustodyFactors(opts.storagePath));
  checks.push(await checkInterruptedExitImport(opts.storagePath));
  checks.push(await checkExitAdmissionLock(opts.storagePath));
  checks.push(checkRuntime());
  checks.push(await checkHermesConfigParser(opts));
  checks.push(await checkCastleWall(opts));
  const harnessIds = await collectWrappedHarnessAgentIds();
  checks.push(checkWrappedHarnessAgentIds(harnessIds));
  checks.push(await checkSdwOwnerTransferLock(opts.storagePath));
  checks.push(await checkSdwOwnerPin(opts.storagePath, masterKey, harnessIds));
  if (masterKey) masterKey.fill(0);
  return checks;
}

/**
 * Bound on ONE candidate-interpreter probe in the doctor check. Shorter than
 * wrap's 5s parse budget on purpose: doctor is an interactive diagnostic, and
 * the worst case is (candidates x this), paid only on hosts that actually have
 * a Hermes config.
 */
const DOCTOR_PYYAML_PROBE_TIMEOUT_MS = 3000;

/**
 * Hermes config parser: can wrap actually validate a Hermes `config.yaml`?
 *
 * WHY THIS CHECK EXISTS. `sudo sanctuary protect --hermes` edits
 * `~/.hermes/config.yaml` through a line scanner whose view is validated
 * against a REAL PyYAML parse before any byte is written, and that guard is
 * fail-closed: no PyYAML, no wrap. Before this check, an operator learned that
 * only by running protect and watching it refuse partway through. Worse, the
 * condition is invisible from the shell -- `python3 -c 'import yaml'` can
 * succeed for the operator while the interpreter wrap resolves has no PyYAML at
 * all (the 2026-07-22 drill), so "it works in my terminal" is not evidence.
 *
 * IT SHARES THE MATCHER WITH THE THING IT PREDICTS. This runs
 * {@link probePyYamlCandidates} -- the same chokepoint, same candidate list,
 * same parse program, same selection-by-importability rule that wrap uses --
 * with an EMPTY document, which that program defines as a valid parse. So the
 * check measures the exact predicate wrap depends on rather than a second copy
 * of it that can drift (the first fix attempt at this shipped RED precisely
 * because a hand-rolled "first EXISTING python3" copy disagreed with the real
 * requirement).
 *
 * Scoped to hosts that have a Hermes config: elsewhere there is nothing to
 * wrap, so no interpreter is spawned and the check reports n/a rather than
 * inventing a verdict about a path this host does not use.
 *
 * Severity is WARN, not FAIL: this blocks ONE optional surface (the Hermes wrap
 * path), and doctor reserves FAIL for fortress-integrity problems. The
 * fail-closed refusal itself stays where it belongs, on the mutating wrap path,
 * which exits non-zero and writes nothing.
 */
async function checkHermesConfigParser(opts: {
  env: NodeJS.ProcessEnv;
  hermesConfigPath?: string;
  pyYamlProbe?: ParseParityOptions;
}): Promise<DoctorCheck> {
  const name = "hermes config parser";
  const home = opts.env.HOME ?? homedir();
  const configPath = opts.hermesConfigPath ?? join(home, ".hermes", "config.yaml");
  try {
    await access(configPath, constants.R_OK);
  } catch {
    return ok(name, `n/a (no Hermes config at ${configPath})`, "none");
  }
  // Empty document: a valid parse for this program, so the probe exercises the
  // real interpreter selection without reading the operator's config content.
  const probe = await probePyYamlCandidates("", {
    timeoutMs: DOCTOR_PYYAML_PROBE_TIMEOUT_MS,
    ...opts.pyYamlProbe,
  });
  if (probe.selected !== undefined) {
    return ok(name, `PyYAML parse validator resolves to ${probe.selected.interpreter}`, "none");
  }
  return warn(
    name,
    "no python3 Sanctuary probes can import yaml, so 'sanctuary protect --hermes' would refuse to edit config.yaml",
    describePyYamlCandidateFailure(probe.outcomes),
  );
}

/**
 * MEDIUM-D (coordinator gate, 2026-08-22), Codex-tightened: a fortress
 * left with an interrupted exit-import is genuinely BROKEN (a real risk
 * of the LATER data-loss reconciliation `recoverInterruptedExitImportsOrThrow`
 * exists to prevent), not a benign degraded state - so this is FAIL, not
 * WARN, unlike the other checks in this file. Read-only: `storage.list()`
 * does not require a master key, so this check runs unconditionally
 * (never gated on credential availability), matching doctor's
 * never-abort, always-diagnose contract while still surfacing something
 * an operator must act on.
 */
async function checkInterruptedExitImport(storagePath: string): Promise<DoctorCheck> {
  const storage = new FilesystemStorage(join(storagePath, "state"));
  let entries;
  try {
    entries = await storage.list(EXIT_IMPORT_JOURNAL_NAMESPACE);
  } catch (error) {
    return warn(
      "exit import recovery",
      `could not check for an interrupted exit import: ${error instanceof Error ? error.message : String(error)}`,
      "re-run after confirming the fortress storage path is reachable",
    );
  }
  if (entries.length > 0) {
    return fail(
      "exit import recovery",
      "interrupted exit import pending recovery",
      // F1/F4 (Exit V2 D1 operator finding, 2026-08-23): names
      // EXIT_RECOVERY_VERB (imported above from exit/bundle.js, defined in
      // storage/exit-import-journal.ts) - the verb that actually opens
      // this fortress and rolls the journal back, not `exit verify` (which
      // only checks a bundle directory and never touches local state; a
      // drill operator who followed that old hint got PASS twice while
      // this FAIL stayed). The internal tracking fragment ("ITEM-3
      // (coordinator gate, 2026-08-22)") that used to prefix this text is
      // removed per the same finding: it is not guidance, just noise on
      // an operator's screen. Round-3: `recover` takes a REQUIRED
      // `--fortress <path>` with no ambient fallback, so this hint
      // interpolates the ACTUAL `storagePath` this check already has -
      // the one hint site in the codebase that can, since every other
      // site throws from inside library code with no path string handy.
      // Round-4 fix (independent gate on #1304, P2): shell-quoted - an
      // unquoted path containing a space (e.g. `/tmp/My Fortress`) would
      // otherwise render a suggested command that splits into two
      // arguments and fails, or does something the operator never typed.
      `run \`sanctuary exit ${EXIT_RECOVERY_VERB} --fortress ${shellQuoteSingleArg(storagePath)}\` ` +
        "to recover. If that itself reports the journal could not be " +
        "safely rolled back, this needs operator intervention: inspect " +
        "the journal entries directly " +
        "under <fortress state path>/_exit_import_journal, confirm which " +
        "value at the affected location is the one you want to keep, and " +
        "only then remove the journal entry - do not remove it first.",
    );
  }
  return ok(
    "exit import recovery",
    "no interrupted exit import pending",
    "n/a",
  );
}

/**
 * MEDIUM-3 (Codex gate, 2026-08-22): the writer guard's fortress-wide
 * admission lock is a plain file, not visible through
 * checkInterruptedExitImport above (which only lists journal entries,
 * never the lock file - list() filters to entry files and the lock is
 * not one). A held lock now blocks recovery outright by design (no
 * auto-stale-break), so a stuck fortress with no journal-namespace
 * finding otherwise reads as healthy while actually wedged on this file.
 */
async function checkExitAdmissionLock(storagePath: string): Promise<DoctorCheck> {
  const storage = new FilesystemStorage(join(storagePath, "state"));
  let lockDir: string;
  try {
    lockDir = storage.namespacePath(EXIT_IMPORT_JOURNAL_NAMESPACE);
  } catch (error) {
    return warn(
      "exit admission lock",
      `could not resolve the admission lock path: ${error instanceof Error ? error.message : String(error)}`,
      "re-run after confirming the fortress storage path is reachable",
    );
  }
  const lockPath = join(lockDir, "admission.lock");
  let raw: string;
  try {
    raw = await readFile(lockPath, "utf8");
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      (error as NodeJS.ErrnoException).code === "ENOENT"
    ) {
      return ok("exit admission lock", "no admission lock held", "n/a");
    }
    return warn(
      "exit admission lock",
      `could not check the admission lock: ${error instanceof Error ? error.message : String(error)}`,
      "re-run after confirming the fortress storage path is reachable",
    );
  }
  let owner: string | undefined;
  let pid: number | undefined;
  let acquiredAt: string | undefined;
  try {
    const candidate = JSON.parse(raw) as Record<string, unknown>;
    if (typeof candidate.owner === "string") owner = candidate.owner;
    if (typeof candidate.pid === "number") pid = candidate.pid;
    if (typeof candidate.acquired_at === "string") acquiredAt = candidate.acquired_at;
  } catch {
    // owner/pid/acquiredAt stay undefined; handled by the check below.
  }
  if (owner === undefined || pid === undefined || acquiredAt === undefined) {
    return fail(
      "exit admission lock",
      "admission lock present, metadata unreadable",
      `inspect ${lockPath} directly; if no exit-import, rotate-master, ` +
        "resume, or recovery process is actually running against this " +
        "fortress, remove it - confirm that first, do not remove it on assumption alone.",
    );
  }
  const ownerAlive = isPidAlive(pid);
  return fail(
    "exit admission lock",
    `held by owner=${owner} pid=${pid} acquired_at=${acquiredAt} ` +
      `(process ${ownerAlive ? "alive" : "not found"})`,
    ownerAlive
      ? `pid ${pid} is still running; wait for it to finish, or inspect ` +
          `${lockPath} directly before deciding to remove it`
      : `pid ${pid} is not running; confirm no OTHER exit-import, ` +
          "rotate-master, resume, or recovery process is active against this " +
          `fortress, then remove ${lockPath} - confirm that first, do not remove it on assumption alone.`,
  );
}

function isPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return !(error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === "ESRCH");
  }
}

/**
 * Custody-factor orphan check (element 5): WARN before a lockout. If the
 * envelope enrolled an OS-keyring custody factor but the keyring item is GONE,
 * surface a WARN so the operator re-enrolls / confirms their recovery key
 * before they are locked out. A locked/unreachable keyring is inconclusive
 * (no GUI / SSH) and reports OK rather than a false alarm; no enrolled keychain
 * factor is OK (nothing to orphan). Read-only; never unlocks anything.
 */
async function checkCustodyFactors(storagePath: string): Promise<DoctorCheck> {
  const storage = new FilesystemStorage(join(storagePath, "state"));
  let result;
  try {
    result = await detectCustodyFactorOrphan(storage, storagePath);
  } catch (error) {
    return warn(
      "custody factors",
      `could not check custody factors: ${error instanceof Error ? error.message : String(error)}`,
      "re-run after unlocking the OS keyring",
    );
  }
  if (result.verdict === "orphaned") {
    return warn(
      "custody factors",
      `enrolled OS-keyring custody factor is MISSING (service ${result.custodyService})`,
      "confirm your recovery key is saved off-host, then re-run sanctuary wrap / init to re-enroll the keychain factor",
    );
  }
  if (result.verdict === "inconclusive") {
    return ok(
      "custody factors",
      "OS keyring unreachable this session; keychain factor not verified",
      "unlock the OS keyring (GUI) to verify, or provide SANCTUARY_RECOVERY_KEY",
    );
  }
  if (result.verdict === "no-factor") {
    return ok("custody factors", "no OS-keyring custody factor enrolled", "none");
  }
  return ok(
    "custody factors",
    `enrolled OS-keyring custody factor present (service ${result.custodyService})`,
    "none",
  );
}

function checkRequiredNodeVersion(nodeVersion?: string): DoctorCheck {
  const result = checkNodeVersion(nodeVersion);
  if (result.supported) {
    return ok(
      "node version",
      `Node.js ${result.actualVersion} satisfies ${result.requiredMajor}.x or later`,
      "none",
    );
  }
  return fail(
    "node version",
    result.message,
    `upgrade Node.js to ${result.requiredMajor}.x or later`,
  );
}

async function checkStateDir(storagePath: string): Promise<DoctorCheck> {
  try {
    const s = await stat(storagePath);
    if (!s.isDirectory()) {
      return fail("state dir", `${storagePath} is not a directory`, "move it aside and run sanctuary init");
    }
    const mode = s.mode & 0o777;
    if ((mode & 0o077) !== 0) {
      return warn("state dir", `${storagePath} permissions are ${mode.toString(8)}`, `chmod 700 ${storagePath}`);
    }
    await access(storagePath, constants.W_OK);
    return ok("state dir", `${storagePath} exists and is writable`, "none");
  } catch (error) {
    const code = error instanceof Error && "code" in error
      ? (error as NodeJS.ErrnoException).code
      : undefined;
    if (code === "ENOENT") {
      return fail("state dir", `${storagePath} does not exist`, "run sanctuary init");
    }
    return fail("state dir", `cannot inspect ${storagePath}`, "check filesystem permissions");
  }
}

async function checkIdentity(
  storagePath: string,
  masterKey: Uint8Array | null,
): Promise<DoctorCheck> {
  const storage = new FilesystemStorage(join(storagePath, "state"));
  const metas = await storage.list("_identities");
  if (metas.length === 0) {
    return fail("identity", "no identity records found", "run identity_create or sanctuary init");
  }
  if (!masterKey) {
    return warn("identity", `${metas.length} encrypted identity record(s) found; no key available to decrypt`, "set SANCTUARY_PASSPHRASE or SANCTUARY_RECOVERY_KEY");
  }
  const manager = new IdentityManager(storage, masterKey);
  const loaded = await manager.load();
  const primary = manager.getDefault();
  if (!primary) {
    return fail("identity", `${loaded.total} identity record(s), none loaded`, "check passphrase or recovery key");
  }
  return ok(
    "identity",
    `primary ${primary.identity_id} fingerprint ${fingerprint(primary.public_key)}`,
    "none",
  );
}

async function checkPolicy(storagePath: string): Promise<DoctorCheck> {
  const policyPath = join(storagePath, "principal-policy.yaml");
  try {
    const content = await readFile(policyPath, "utf8");
    parsePolicy(content);
    return ok("principal policy", `${policyPath} is present and parses`, "none");
  } catch (error) {
    const code = error instanceof Error && "code" in error
      ? (error as NodeJS.ErrnoException).code
      : undefined;
    if (code === "ENOENT") {
      return fail("principal policy", `${policyPath} is missing`, "run sanctuary init or restore principal-policy.yaml");
    }
    return fail("principal policy", "principal-policy.yaml is malformed", "fix the policy file syntax");
  }
}

async function checkAuditChain(
  storagePath: string,
  masterKey?: Uint8Array,
): Promise<DoctorCheck> {
  const storage = new FilesystemStorage(join(storagePath, "state"));
  // F2 HIGH-R3 + MEDIUM-1 (round 3): after the writer-split the daemon's
  // enforcement evidence lives in `_audit-daemon`, so the single-chain
  // `exportAuditChain` verify below is NOT a full verdict. When the migration
  // ran:
  //   - with a master key available, run the chain-aware full-picture verifier
  //     and FAIL on known tamper (operator/daemon findings, daemon missing),
  //     WARN on unverifiable-at-this-privilege states, OK only when fully
  //     verified. Doctor is an operator health command: when it CAN verify and
  //     finds tamper it must FAIL (exit non-zero), not just WARN.
  //   - without a master key, WARN and point at `audit-store-status`.
  if (await fortressRanAuditStoreSplitMigration(storage)) {
    if (!masterKey) {
      return warn(
        "audit chain",
        "this fortress ran the F2 audit store writer-split; a full verify needs " +
          "the master key (run with the fortress passphrase / recovery key)",
        "run 'sanctuary castle-wall audit-store-status' (as root for a full " +
          "sealed-region + daemon-chain verify)",
      );
    }
    const report = await verifyFortressAuditFullPicture({ storage, masterKey });
    const op = report.operator.status;
    const dm = report.daemon.status;
    const tamper =
      op === "findings" || dm === "findings" || dm === "missing";
    if (tamper) {
      return fail(
        "audit chain",
        `audit store split verification FAILED (operator: ${op}, daemon: ${dm})`,
        "run 'sanctuary castle-wall audit-store-status' (as root) and investigate the findings",
      );
    }
    const unverifiable =
      op === "verified_suffix_only" ||
      dm === "present_unreadable" ||
      dm === "key_unavailable" ||
      op === "key_unavailable";
    if (unverifiable) {
      return warn(
        "audit chain",
        `audit store split partially verified at this privilege (operator: ${op}, daemon: ${dm})`,
        "re-run as root for a full sealed-region + daemon-chain verify",
      );
    }
    return ok(
      "audit chain",
      `audit store split fully verified (operator: ${op}, daemon: ${dm})`,
      "none",
    );
  }
  const entryMetas = await storage.list("_audit");
  if (entryMetas.length === 0) {
    return fail("audit chain", "no audit entries found", "start Sanctuary and perform an audited operation");
  }
  const sink = new CaptureWritable();
  await exportAuditChain(storage, sink);
  const records = sink.text()
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as ExportRecord);
  const report = verifyAuditChainRecords(records);
  if (report.verdict === "PASS") {
    if (report.signatures_verified === 0 && report.signatures_skipped > 0) {
      return warn(
        "audit chain",
        "no checkpoint signature was verified",
        "wire a production checkpoint signer before treating checkpoint signatures as evidence",
      );
    }
    return ok("audit chain", `${report.entries_verified} entries verified`, "none");
  }
  if (
    report.findings.length > 0 &&
    report.findings.every((finding) => finding.kind === "checkpoint_signature_missing_key")
  ) {
    return warn(
      "audit chain",
      "checkpoint signatures were not verified against a pinned public key",
      "run 'sanctuary audit-chain verify --public-key <signer-public-key>' with the signer key obtained out-of-band",
    );
  }
  return fail("audit chain", `${report.findings.length} integrity finding(s)`, "run sanctuary audit-chain export and verify for details");
}

/**
 * Wrapped-harness agent identity (IC-16 follow-through). `sanctuary wrap`
 * writes `SANCTUARY_AGENT_ID` into the harness's `sanctuary` MCP entry; the
 * server's multi-agent isolation guard keys on it. A wrap performed before
 * that landed has a `sanctuary` entry with no such variable, so the server it
 * spawns resolves no identity and the durable guard refuses it.
 * Read-only: reports the entries that need `sanctuary wrap` re-run. Failure
 * mode from the outside: two harnesses wrapped before the upgrade both look
 * isolated in the docs and are not, and nothing else says so.
 */
interface WrappedHarnessEntry {
  readonly platform: string;
  readonly path: string;
  readonly agentId: string | null;
}

async function collectWrappedHarnessAgentIds(): Promise<WrappedHarnessEntry[]> {
  const found: WrappedHarnessEntry[] = [];
  for (const [platform, paths] of Object.entries(getPlatformPaths())) {
    for (const path of paths) {
      let raw: string;
      try {
        raw = await readFile(path, "utf-8");
      } catch {
        continue;
      }
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(raw) as Record<string, unknown>;
      } catch {
        continue;
      }
      const entry = sanctuaryMcpEntry(parsed);
      if (entry === null) continue;
      const env = entry.env as Record<string, unknown> | undefined;
      const agentId = env?.SANCTUARY_AGENT_ID;
      found.push({
        platform,
        path,
        agentId: typeof agentId === "string" && agentId.length > 0 ? agentId : null,
      });
    }
  }
  // Hermes loads its MCP surface from config.yaml, not from the JSON paths
  // above; read it through the wrap writer's own block scanner.
  const yamlPath = hermesConfigYamlPath();
  let yaml: string | null;
  try {
    yaml = await readFile(yamlPath, "utf-8");
  } catch {
    yaml = null;
  }
  const hermesId = hermesSanctuaryEntryEnvValue(yaml, "SANCTUARY_AGENT_ID");
  if (hermesId !== undefined) {
    found.push({ platform: "hermes", path: yamlPath, agentId: hermesId });
  }
  return found;
}

function checkWrappedHarnessAgentIds(entries: readonly WrappedHarnessEntry[]): DoctorCheck {
  const missing = entries.filter((e) => e.agentId === null).map((e) => `${e.platform}: ${e.path}`);
  if (entries.length === 0) return ok("wrapped harness ids", "no wrapped harness config found", "n/a");
  if (missing.length === 0) {
    return ok("wrapped harness ids", `${entries.length} wrapped harness entr${entries.length === 1 ? "y" : "ies"} carry SANCTUARY_AGENT_ID`, "n/a");
  }
  return warn(
    "wrapped harness ids",
    `${missing.length} wrapped harness entr${missing.length === 1 ? "y" : "ies"} without SANCTUARY_AGENT_ID (${missing.join("; ")})`,
    "re-run sanctuary wrap on each harness so the multi-agent isolation guard has an identity to pin",
  );
}

async function checkSdwOwnerPin(
  storagePath: string,
  masterKey: Uint8Array | null,
  entries: readonly WrappedHarnessEntry[],
): Promise<DoctorCheck> {
  if (masterKey === null) {
    return warn(
      "sdw owner pin",
      "not checked because no custody key was available",
      "set SANCTUARY_PASSPHRASE or SANCTUARY_RECOVERY_KEY",
    );
  }
  const storage = new FilesystemStorage(join(storagePath, "state"));
  try {
    const pin = await readSdwOwnerPin(storage, masterKey);
    if (pin.status === "absent") {
      return warn(
        "sdw owner pin",
        "unassigned; a fresh empty SDW will be claimed on first wrapped use, while an existing SDW will refuse",
        "for an existing SDW, stop all Sanctuary processes and run 'sanctuary sdw-owner claim --agent-id <wrapped-agent-id>'",
      );
    }
    if (pin.status === "invalid") {
      return fail(
        "sdw owner pin",
        "present but failed authentication",
        "do not overwrite it; inspect custody and restore history before attempting recovery",
      );
    }
    if (
      pin.data.fortress_id !== fortressIdFromStoragePath(storagePath) ||
      pin.data.owner_ref !== "fleet-self"
    ) {
      return fail(
        "sdw owner pin",
        "authenticated but bound to a different fortress or owner scope",
        "do not run claim or transfer; investigate a copied or mismatched state directory",
      );
    }
    const ids = entries
      .map((entry) => entry.agentId)
      .filter((id): id is string => id !== null);
    if (!ids.includes(pin.data.agent_id)) {
      return warn(
        "sdw owner pin",
        `pinned to ${pin.data.agent_id}, which matches no wrapped harness entry on this host`,
        "re-wrap the owning harness, or use the interactive sdw-owner transfer command after verifying the intended new owner",
      );
    }
    return ok(
      "sdw owner pin",
      `pinned to ${pin.data.agent_id}, a wrapped harness on this host`,
      "none",
    );
  } catch (error) {
    return fail(
      "sdw owner pin",
      `could not be read: ${error instanceof Error ? error.message : String(error)}`,
      "inspect fortress state-directory permissions",
    );
  }
}

/**
 * Owner transfer uses the filesystem backend's fail-closed CAS lock. It is
 * intentionally never auto-broken because doing so can create two concurrent
 * owners. Surface the exact lock and its holder here so crash recovery does
 * not require filesystem archaeology or an unsafe guessed unlink.
 */
async function checkSdwOwnerTransferLock(storagePath: string): Promise<DoctorCheck> {
  const lockPath = join(
    storagePath,
    "state",
    SDW_META_NAMESPACE,
    `.${SDW_OWNER_PIN_KEY}.enc.compare-replace.lock`,
  );
  let raw: string;
  try {
    raw = await readFile(lockPath, "utf8");
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      (error as NodeJS.ErrnoException).code === "ENOENT"
    ) {
      return ok("sdw owner transfer lock", "no transfer lock held", "n/a");
    }
    return warn(
      "sdw owner transfer lock",
      `could not check the transfer lock: ${error instanceof Error ? error.message : String(error)}`,
      "re-run after confirming the fortress storage path is reachable",
    );
  }

  let pid: number | undefined;
  let acquiredAt: string | undefined;
  try {
    const candidate = JSON.parse(raw) as Record<string, unknown>;
    if (typeof candidate.pid === "number") pid = candidate.pid;
    if (typeof candidate.acquired_at === "string") acquiredAt = candidate.acquired_at;
  } catch {
    // Missing or malformed metadata is handled below. Presence alone is
    // enough to fail: a transfer cannot safely proceed while this path exists.
  }
  const holder =
    pid === undefined || acquiredAt === undefined
      ? "metadata unreadable"
      : `pid=${pid} acquired_at=${acquiredAt} (process ${isPidAlive(pid) ? "alive" : "not found"})`;
  return fail(
    "sdw owner transfer lock",
    `transfer lock present, ${holder}`,
    "never remove it while any Sanctuary process may be running; stop all " +
      `Sanctuary processes, confirm the holder is dead, then remove exactly ${lockPath}`,
  );
}

/** The `sanctuary` MCP entry in any of the harness config shapes wrap writes. */
function sanctuaryMcpEntry(parsed: Record<string, unknown>): Record<string, unknown> | null {
  const candidates = [
    (parsed.mcpServers as Record<string, unknown> | undefined)?.sanctuary,
    ((parsed.mcp as Record<string, unknown> | undefined)?.servers as Record<string, unknown> | undefined)?.sanctuary,
    (parsed.mcp_servers as Record<string, unknown> | undefined)?.sanctuary,
  ];
  for (const candidate of candidates) {
    if (candidate !== null && typeof candidate === "object") return candidate as Record<string, unknown>;
  }
  return null;
}

function checkRuntime(): DoctorCheck {
  const npmVersion = runVersion("npm --version");
  return ok(
    "runtime",
    `package ${PKG_VERSION}, node ${process.version}, npm ${npmVersion ?? "unavailable"}`,
    npmVersion ? "none" : "install npm or check PATH",
  );
}

async function checkCastleWall(opts: {
  storagePath: string;
  env: NodeJS.ProcessEnv;
  platform: NodeJS.Platform;
  execSyncFn?: (command: string) => string;
}): Promise<DoctorCheck> {
  if (opts.platform !== "darwin") {
    return ok("castle wall sysext", "n/a (not macOS)", "none");
  }
  const execSyncFn = opts.execSyncFn ??
    ((command: string) =>
      nodeExecSync(command, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim());
  try {
    const raw = execSyncFn("systemextensionsctl list 2>/dev/null | grep castle-wall");
    const state = raw.includes("[activated enabled]")
      ? "[activated enabled]"
      : raw.includes("[activated waiting for user]")
        ? "[activated waiting for user]"
        : "not loaded";
    const status = state === "[activated enabled]" ? "OK" : "WARN";
    return {
      name: "castle wall sysext",
      status,
      message: state,
      hint: status === "OK" ? "none" : "approve the system extension in System Settings",
    };
  } catch {
    return warn("castle wall sysext", "not loaded", "run sanctuary castle-wall status");
  }
}

async function resolveMasterKeyIfAvailable(
  storagePath: string,
  env: NodeJS.ProcessEnv,
): Promise<Uint8Array | null> {
  if (!env.SANCTUARY_RECOVERY_KEY && !env.SANCTUARY_PASSPHRASE) return null;
  const storage = new FilesystemStorage(join(storagePath, "state"));
  // Unified custody (master-custody.ts): never derive a fortress master verb-locally.
  // Doctor is a read-only diagnostic: an unresolvable master degrades the
  // identity check (null) instead of aborting the run. Recovery key keeps
  // precedence over passphrase, matching the legacy resolution order.
  //
  // STATED BOUND (HIGH-2, coordinator gate, 2026-08-22): this file does NOT
  // call `recoverInterruptedExitImportsOrThrow` (server/src/exit/bundle.ts),
  // even where a master key is available. Every check in this file,
  // including this one, is deliberately read-only and never-aborting by
  // design (the whole point of `doctor` is to diagnose a fortress that may
  // already be broken); recovery is a WRITE that can also THROW, both of
  // which contradict that contract. A fortress with a half-applied
  // exit-import is still diagnosable read-only by every check here; it
  // just is not RECOVERED by running `doctor`.
  try {
    return await resolveCliMasterKey(storage, {
      ...(env.SANCTUARY_RECOVERY_KEY !== undefined
        ? { recoveryKey: env.SANCTUARY_RECOVERY_KEY }
        : { passphrase: env.SANCTUARY_PASSPHRASE! }),
      storagePathHint: storagePath,
    });
  } catch {
    return null;
  }
}

function runVersion(command: string): string | null {
  try {
    return nodeExecSync(command, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return null;
  }
}

function fingerprint(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}

function ok(name: string, message: string, hint: string): DoctorCheck {
  return { name, status: "OK", message, hint };
}

function warn(name: string, message: string, hint: string): DoctorCheck {
  return { name, status: "WARN", message, hint };
}

function fail(name: string, message: string, hint: string): DoctorCheck {
  return { name, status: "FAIL", message, hint };
}

class CaptureWritable extends Writable {
  private chunks: string[] = [];
  override _write(chunk: unknown, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    this.chunks.push(String(chunk));
    callback();
  }
  text(): string {
    return this.chunks.join("");
  }
}

function printUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary doctor [--json] [--fortress <path>]

Runs read-only local diagnostics for state directory, identity, principal
policy, audit-chain integrity, runtime versions, the Hermes config parser,
and Castle Wall status.
`,
  );
}
