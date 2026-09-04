import { isAbsolute, normalize as normalizePath } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import { RESERVED_ACCOUNT_NAMES, SAFE_SERVICE_ACCOUNT_RE } from "./account-name-policy.js";
import { stripTrailingSlashes } from "../../strings.js";

/**
 * Auto-provision Step 2 (Build 1): dedicated agent service-account plumbing.
 *
 * Mirrors `egress-gate/harness-daemon.ts`'s pure-plan + injected-ops shape
 * deliberately: plan/create logic here must be unit-testable against mocks
 * without ever touching a real host, exactly like the harness-daemon
 * plumbing it will hand off to (`planAgentHarnessDaemonInstall`).
 *
 * THIS MODULE IS PLUMBING ONLY. The actual `sysadminctl -addUser` / `dscl`
 * creation of a real macOS account is drill-only, reserved for an
 * Erik-present console ceremony on real hardware (see the build spec's "What
 * NOT to do"). Root-only in practice: production `ops.createUser` must be
 * backed by a root-privileged `sysadminctl`/`dscl` invocation; this module
 * does not itself check the calling uid (`process.getuid`) because that
 * check belongs to the CLI orchestration layer (`orchestrate.ts`), which
 * already gates the whole privileged sub-flow on a TTY confirm.
 *
 * Idempotency (fix M1-adjacent): `planAccountCreate` inspects the account's
 * CURRENT existence via an injected probe and returns a `skip` plan when an
 * account with the target name already exists and its uid matches the
 * requested uid -- never a blind re-create. A NAME match with a DIFFERENT
 * uid is a conflict and is refused (never silently overwritten): this
 * mirrors harness-daemon.ts's care not to let a routine retry clobber a
 * different, live state.
 */

/**
 * The account-name contract (safe charset + reserved privileged names) is
 * single-sourced in `./account-name-policy.ts` (zero-import module) and
 * consumed by all three refusal sites: this file, `egress-gate/gate-daemon.ts`
 * and `egress-gate/harness-daemon.ts`. Re-exported here so existing consumers
 * (`egress-gate/gate-account.ts`, the provision barrel, the structural guard)
 * keep their import paths. The WIDEN rationale (Erik-ratified 2026-08-05) and
 * the full doc comments live with the declarations in that module.
 */
export { RESERVED_ACCOUNT_NAMES, SAFE_SERVICE_ACCOUNT_RE } from "./account-name-policy.js";

/** Derive the canonical dedicated account name for an agent id, e.g. "hermes" -> "sanctuary-hermes". */
export function deriveAgentAccountName(agentId: string): string {
  return `sanctuary-${agentId}`;
}

/** Inputs describing the account to plan/create. */
export interface AccountProvisionOptions {
  /** The dedicated account name, e.g. "sanctuary-hermes". */
  accountName: string;
  /** The lowest uid this account may be assigned (the arm-time ceiling). */
  ceiling: number;
  /** Human-readable full name / comment field for the account. */
  comment?: string;
  /**
   * FIX F7 (HIGH/PLAUSIBLE, Codex second family, 2026-07-07 fix-round): the
   * account's `NFSHomeDirectory`, set at create time to the SAME path the
   * re-home step moves secrets onto (`/var/sanctuary-agents/<accountName>`).
   * Without this, `sysadminctl -addUser` defaults the new account's
   * directory-service home to something else entirely, so the confined
   * harness (running as this account) resolves `~/.hermes` to a directory
   * that never received the moved secrets -- the agent cannot find its own
   * config even though the wall arms successfully. Required (not optional):
   * `planAccountCreate` throws if this is absent for a `create` plan.
   */
  homeDirectory: string;
  /**
   * Known-live uids this service account must never reuse. This is a
   * caller-provided backstop for live principals the UID census might miss
   * (for example the console operator or a previously-observed agent/gate uid).
   */
  excludedUids?: readonly number[];
}

/** The directory-service fields that settle the service-account shape this module creates. */
export interface ServiceAccountRecord {
  readonly uid: number;
  readonly homeDirectory?: string;
  readonly isHidden?: boolean;
  readonly userShell?: string;
}

/** Filesystem/directory-service operations, injected so tests never touch the host. */
export interface AccountProvisionOps {
  /**
   * Return the uid of an EXISTING account with this name, or `undefined` if
   * no such account exists. Never throws for "not found"; only for a genuine
   * probe failure (directory service unreachable, etc).
   */
  lookupAccountUid(accountName: string): Promise<number | undefined>;
  /**
   * Read the directory-service record for this account, or `undefined` when absent.
   * This is the post-create/skip truth source; callers must not infer service
   * account completeness from `createUser` returning.
   */
  lookupAccountRecord(accountName: string): Promise<ServiceAccountRecord | undefined>;
  /**
   * Resolve a home path into the comparison form used for `NFSHomeDirectory`.
   * Production resolves symlinked prefixes (`/var` -> `/private/var`) and tests
   * inject the same behavior deterministically.
   */
  canonicalizeHomeDirectory(path: string): Promise<string>;
  /**
   * Return the highest uid visible in the local account census. This is only
   * a candidate-selection input; create safety is settled by a direct
   * per-candidate uid lookup immediately before `createUser`.
   */
  highestAssignedUid(): Promise<number>;
  /**
   * Return account names currently assigned to this exact uid, using a bounded
   * uid-specific directory-service lookup (for example
   * `dscl . -search /Users UniqueID <uid>`). A lookup failure must throw so the
   * create path refuses rather than treating unknown state as unassigned.
   */
  lookupAccountNamesByUid(uid: number): Promise<readonly string[]>;
  /**
   * Create the no-login service account with the given uid. Must set
   * `UserShell=/usr/bin/false`, no admin group membership, no interactive
   * password, AND (fix F7) set `NFSHomeDirectory` to `homeDirectory` so the
   * account's directory-service home matches the re-home target. Production
   * backing is `sysadminctl -addUser`; drill-only, never invoked by tests.
   */
  createUser(accountName: string, uid: number, comment: string | undefined, homeDirectory: string): Promise<void>;
  /**
   * Apply post-create service-account hardening that `sysadminctl` cannot
   * express directly, currently `IsHidden=1`. This is separate from
   * {@link createUser} so a failed post-create `dscl` write is inside the
   * observed recovery envelope, not an untracked partial mutation.
   */
  hardenCreatedUser(accountName: string): Promise<void>;
}

/** A planned account-provision step. Pure. */
export type AccountProvisionPlan =
  | {
      action: "skip";
      accountName: string;
      uid: number;
      reason: string;
    }
  | {
      action: "create";
      accountName: string;
      uid: number;
    }
  | {
      action: "conflict";
      accountName: string;
      existingUid: number;
      requestedCeiling: number;
      reason: string;
    };

/** Thrown when an observed account record does not match the service-account contract. */
export class AccountProvisionVerificationError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "AccountProvisionVerificationError";
  }
}

export const EXPECTED_SERVICE_ACCOUNT_IS_HIDDEN = true;
export const EXPECTED_SERVICE_ACCOUNT_SHELL = "/usr/bin/false";

const DSCL_UNIQUE_ID_LIST_LINE_RE = /^(.+?)\s+(-?\d+)\s*$/;

interface DsclResidueParserResult<T> {
  readonly value: T;
  readonly nextLineIndex: number;
}

type DsclResidueParser<T> = (
  lines: readonly string[],
  lineIndex: number,
) => DsclResidueParserResult<T> | undefined;

function countNonEmptyLines(stdout: string): number {
  return stdout.split(/\r?\n/).filter((line) => line.trim().length > 0).length;
}

/**
 * Parse dscl stdout only when every non-empty line is consumed by the parser.
 * Unparsed output is not evidence of absence: a search/list result with residue
 * is unknown DirectoryService state and must fail closed rather than proving a
 * uid free.
 */
export function parseDsclOutputWithNoUnparsedResidue<T>(
  stdout: string,
  context: string,
  parseAt: DsclResidueParser<T>,
): T[] {
  const lines = stdout.split(/\r?\n/);
  const values: T[] = [];
  const residueLineNumbers: number[] = [];
  let parsedNonEmptyLines = 0;
  const totalNonEmptyLines = countNonEmptyLines(stdout);
  let index = 0;

  while (index < lines.length) {
    const line = lines[index]!;
    if (line.trim().length === 0) {
      index += 1;
      continue;
    }
    const parsed = parseAt(lines, index);
    if (
      parsed === undefined ||
      parsed.nextLineIndex <= index ||
      parsed.nextLineIndex > lines.length
    ) {
      residueLineNumbers.push(index + 1);
      index += 1;
      continue;
    }
    for (let consumedIndex = index; consumedIndex < parsed.nextLineIndex; consumedIndex += 1) {
      if (lines[consumedIndex]!.trim().length > 0) parsedNonEmptyLines += 1;
    }
    values.push(parsed.value);
    index = parsed.nextLineIndex;
  }

  if (residueLineNumbers.length > 0) {
    const shown = residueLineNumbers.slice(0, 8).join(", ");
    const suffix = residueLineNumbers.length > 8 ? `, +${residueLineNumbers.length - 8} more` : "";
    throw new AccountUidEnumerationError(
      `Refusing to trust ${context}: dscl output returned ${totalNonEmptyLines} non-empty ` +
        `line${totalNonEmptyLines === 1 ? "" : "s"}, but only ${parsedNonEmptyLines} parsed/accounted for ` +
        `(${residueLineNumbers.length} unparsed at line${residueLineNumbers.length === 1 ? "" : "s"} ` +
        `${shown}${suffix}). Unparsed output is not evidence of absence; repair DirectoryService output ` +
        `before rerunning.`,
    );
  }

  return values;
}

export interface AccountProvisionRollbackResult {
  readonly message: string;
}

/** Thrown when local account UID enumeration cannot be trusted. */
export class AccountUidEnumerationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AccountUidEnumerationError";
  }
}

export function parseServiceAccountIsHidden(value: string | undefined): boolean | undefined {
  if (value === undefined) return undefined;
  const normalized = value.trim().toLowerCase();
  if (normalized === "1" || normalized === "yes" || normalized === "true") return true;
  if (normalized === "0" || normalized === "no" || normalized === "false") return false;
  return false;
}

function normalizeComparableHome(path: string): string {
  const normalized = normalizePath(path);
  if (normalized === "/") return normalized;
  return stripTrailingSlashes(normalized);
}

function homeDirectoryShapeProblem(path: string, label: string): string | undefined {
  if (!isAbsolute(path)) {
    return `${label} is ${path}, expected an absolute path`;
  }
  if (path.split("/").includes("..")) {
    return `${label} is ${path}, expected a path with no ".." segments`;
  }
  return undefined;
}

async function canonicalizeComparableHome(
  ops: Pick<AccountProvisionOps, "canonicalizeHomeDirectory">,
  path: string,
): Promise<string> {
  return normalizeComparableHome(await ops.canonicalizeHomeDirectory(path));
}

export function serviceAccountRepairGuidance(
  accountName: string,
  expected: {
    readonly homeDirectory: string;
    readonly uid?: number;
    readonly uidFloor?: number;
    readonly excludedUids?: readonly number[];
  },
): string {
  const uidInstruction =
    expected.uid !== undefined
      ? String(expected.uid)
      : `an unused integer >= ${expected.uidFloor ?? 1}` +
        (expected.excludedUids !== undefined && expected.excludedUids.length > 0
          ? ` and not one of ${[...new Set(expected.excludedUids)].sort((a, b) => a - b).join(", ")}`
          : "");
  return (
    `Safe repair: preserve ${expected.homeDirectory}, repair "${accountName}" in place, then re-run. ` +
    `Set UniqueID=${uidInstruction}, NFSHomeDirectory=${expected.homeDirectory}, IsHidden=1 (or YES), and ` +
    `UserShell=${EXPECTED_SERVICE_ACCOUNT_SHELL}; do not delete the account home to recover this state.`
  );
}

export function serviceAccountConflictGuidance(
  accountName: string,
  expected: { readonly homeDirectory: string; readonly ceiling: number; readonly excludedUids?: readonly number[] },
): string {
  return (
    `Recovery: if "${accountName}" is the intended Sanctuary service account, repair it in place with a valid ` +
    `service uid and required attributes. ` +
    serviceAccountRepairGuidance(accountName, {
      homeDirectory: expected.homeDirectory,
      uidFloor: expected.ceiling,
      excludedUids: expected.excludedUids,
    }) +
    ` If it is unrelated, rename that account or choose a different agent id before rerunning; do not delete ` +
    `the account home as part of recovery.`
  );
}

export function describeServiceAccountRecord(record: ServiceAccountRecord | undefined): string {
  if (record === undefined) return "account record absent";
  return (
    `account record uid=${record.uid}, NFSHomeDirectory=${record.homeDirectory ?? "<missing>"}, ` +
    `IsHidden=${record.isHidden === undefined ? "<missing>" : record.isHidden ? "1" : "0"}, ` +
    `UserShell=${record.userShell ?? "<missing>"}`
  );
}

interface DsclUidListRecord {
  readonly accountName: string;
  readonly uid: number;
}

function parseDsclUidListRecordAt(
  lines: readonly string[],
  lineIndex: number,
): DsclResidueParserResult<DsclUidListRecord> | undefined {
  const line = lines[lineIndex]!;
  if (/^\s/.test(line)) return undefined;
  const match = DSCL_UNIQUE_ID_LIST_LINE_RE.exec(line);
  if (match === null) return undefined;
  const accountName = match[1]!.trimEnd();
  const uid = Number(match[2]);
  if (accountName.length === 0 || !Number.isSafeInteger(uid)) return undefined;
  return { value: { accountName, uid }, nextLineIndex: lineIndex + 1 };
}

/**
 * Parse `dscl . -list /Users UniqueID` output into the highest visible UID.
 * Negative UIDs are valid on macOS (`nobody -2`) and must parse rather than be
 * silently dropped. Any non-empty unparseable line fails closed because a
 * malformed UID census is not a trustworthy candidate-selection input. `root 0`
 * remains a cheap local-node sanity signal, not a completeness proof: names can
 * sort after root, so create safety is settled by a direct lookup of the exact
 * candidate uid before mutation.
 */
export function parseHighestAssignedUidFromDsclList(stdout: string, floor: number): number {
  if (!Number.isSafeInteger(floor)) {
    throw new AccountUidEnumerationError(`UID enumeration floor must be a safe integer (got ${String(floor)}).`);
  }

  const records = parseDsclOutputWithNoUnparsedResidue(
    stdout,
    "dscl . -list /Users UniqueID",
    parseDsclUidListRecordAt,
  );
  let highest = floor;
  let sawRootUidZero = false;
  for (const record of records) {
    if (record.accountName === "root" && record.uid === 0) sawRootUidZero = true;
    highest = Math.max(highest, record.uid);
  }

  if (!sawRootUidZero) {
    const total = countNonEmptyLines(stdout);
    throw new AccountUidEnumerationError(
      `Refusing to choose a service uid: dscl . -list /Users UniqueID returned ${total} non-empty ` +
        `line${total === 1 ? "" : "s"} and ${records.length} parsed record${records.length === 1 ? "" : "s"}, but did not ` +
        `include the required macOS local-node root uid record (root 0). ` +
        `Run /usr/bin/dscl . -list /Users UniqueID locally and rerun only after it returns the local root record; ` +
        `an untrusted UID census is not a safe input for service-account allocation.`,
    );
  }

  return highest;
}

export async function serviceAccountRecordProblems(
  record: ServiceAccountRecord | undefined,
  expected: { readonly uid: number; readonly homeDirectory: string },
  ops: Pick<AccountProvisionOps, "canonicalizeHomeDirectory">,
): Promise<string[]> {
  if (record === undefined) return ["account record is absent"];
  const problems: string[] = [];
  if (record.uid !== expected.uid) {
    problems.push(`uid is ${record.uid}, expected ${expected.uid}`);
  }
  if (record.homeDirectory === undefined) {
    problems.push(`NFSHomeDirectory is <missing>, expected ${expected.homeDirectory}`);
  } else {
    const observedShapeProblem = homeDirectoryShapeProblem(record.homeDirectory, "NFSHomeDirectory");
    if (observedShapeProblem !== undefined) {
      problems.push(`${observedShapeProblem}, expected ${expected.homeDirectory}`);
    } else {
      try {
        const observedCanonical = await canonicalizeComparableHome(ops, record.homeDirectory);
        const expectedCanonical = await canonicalizeComparableHome(ops, expected.homeDirectory);
        if (observedCanonical !== expectedCanonical) {
          problems.push(
            `NFSHomeDirectory is ${record.homeDirectory} (canonical ${observedCanonical}), ` +
              `expected ${expected.homeDirectory} (canonical ${expectedCanonical})`,
          );
        }
      } catch (err) {
        problems.push(
          `NFSHomeDirectory canonicalization failed ` +
            `(${err instanceof Error ? err.message : String(err)}); observed ${record.homeDirectory}, ` +
            `expected ${expected.homeDirectory}`,
        );
      }
    }
  }
  if (record.isHidden !== EXPECTED_SERVICE_ACCOUNT_IS_HIDDEN) {
    problems.push(
      `IsHidden is ${record.isHidden === undefined ? "<missing>" : record.isHidden ? "1" : "0"}, expected 1`,
    );
  }
  if (record.userShell !== EXPECTED_SERVICE_ACCOUNT_SHELL) {
    problems.push(`UserShell is ${record.userShell ?? "<missing>"}, expected ${EXPECTED_SERVICE_ACCOUNT_SHELL}`);
  }
  return problems;
}

/**
 * Plan account provisioning. Pure decision logic given the two probe
 * results; execution (the actual create) happens in {@link executeAccountProvisionPlan}.
 *
 * - `skip`: an account with this exact name already exists AND its uid is
 *   already >= ceiling (a valid dedicated uid). Idempotent re-run: do not
 *   re-create, do not touch it.
 * - `conflict`: an account with this exact name exists but its uid is BELOW
 *   the ceiling (e.g. it collides with an existing operator/system account
 *   of the same name, or a prior provision used a different ceiling).
 *   Refuse rather than silently reassigning -- an account rename/uid change
 *   is out of scope and could strand file ownership.
 * - `create`: no account with this name exists. uid = the candidate integer
 *   at or above the ceiling and greater than the highest uid visible in the
 *   census. Execution must still directly observe that this exact candidate
 *   uid is unassigned before creating it.
 */
export function planAccountCreate(
  options: AccountProvisionOptions,
  probe: { existingUid: number | undefined; highestAssignedUid: number },
): AccountProvisionPlan {
  const { accountName, ceiling, homeDirectory } = options;

  if (!SAFE_SERVICE_ACCOUNT_RE.test(accountName)) {
    throw new Error(`Account name is not a safe service-account name (got: ${JSON.stringify(accountName)}).`);
  }
  // INVARIANT: the whole point of a dedicated agent account is that the wall
  // can attribute and confine it by its own uid. Provisioning onto a
  // privileged existing name would instead hand the agent that name's
  // authority (root, or an `admin` account's sudo) and collapse the
  // attribution onto a uid shared with the operator.
  if (RESERVED_ACCOUNT_NAMES.has(accountName)) {
    throw new Error(`Refusing to plan a dedicated agent account named "${accountName}" (privileged/reserved name).`);
  }
  if (!Number.isSafeInteger(ceiling) || ceiling < 1) {
    throw new Error(`Ceiling must be a positive integer (got: ${ceiling}).`);
  }
  // FIX F7: the account MUST be created with its NFSHomeDirectory bound to
  // the re-home target, or the confined harness cannot find its moved
  // secrets. Refuse to plan a `create` without one rather than silently
  // falling back to whatever sysadminctl would otherwise default to.
  const expectedHomeProblem = homeDirectoryShapeProblem(homeDirectory, "Home directory");
  if (expectedHomeProblem !== undefined) {
    throw new Error(`${expectedHomeProblem} (got: ${JSON.stringify(homeDirectory)}).`);
  }

  if (probe.existingUid !== undefined) {
    if (probe.existingUid >= ceiling) {
      return {
        action: "skip",
        accountName,
        uid: probe.existingUid,
        reason: `account "${accountName}" already exists at uid ${probe.existingUid} (>= ceiling ${ceiling}); idempotent no-op.`,
      };
    }
    return {
      action: "conflict",
      accountName,
      existingUid: probe.existingUid,
      requestedCeiling: ceiling,
      reason: `account "${accountName}" already exists at uid ${probe.existingUid}, which is below the ceiling (${ceiling}); refusing to reassign or reuse an existing sub-ceiling account.`,
    };
  }

  const uid = Math.max(ceiling, probe.highestAssignedUid + 1);
  return { action: "create", accountName, uid };
}

function sortedUniqueSafeUids(uids: readonly number[] | undefined): number[] {
  const unique = new Set<number>();
  for (const uid of uids ?? []) {
    if (!Number.isSafeInteger(uid)) {
      throw new AccountProvisionVerificationError(
        `Excluded uid must be a safe integer (got ${String(uid)}); refusing to rely on a malformed live-uid backstop.`,
      );
    }
    unique.add(uid);
  }
  return [...unique].sort((a, b) => a - b);
}

function describeAccountNames(names: readonly string[]): string {
  return [...new Set(names)].sort().map((name) => JSON.stringify(name)).join(", ");
}

/**
 * DirectoryService account-name reads are case-insensitive for ASCII on this
 * macOS path, but non-ASCII codepoints that Unicode-lowercase into ASCII are
 * still distinct records here (for example U+212A KELVIN SIGN -> "k"). Folding
 * those to ASCII would classify a foreign uid holder as this service account.
 */
function directoryServiceAsciiCaseFold(name: string): string {
  return name.replace(/[A-Z]/g, (char) => char.toLowerCase());
}

function directoryServiceAccountNamesEqual(left: string, right: string): boolean {
  return directoryServiceAsciiCaseFold(left) === directoryServiceAsciiCaseFold(right);
}

function uniqueDirectoryServiceAccountNames(names: readonly string[]): string[] {
  const seen = new Set<string>();
  const unique: string[] = [];
  for (const name of names) {
    const folded = directoryServiceAsciiCaseFold(name);
    if (seen.has(folded)) continue;
    seen.add(folded);
    unique.push(name);
  }
  return unique;
}

function foreignUidHolders(accountName: string, holders: readonly string[]): string[] {
  return holders.filter((name) => !directoryServiceAccountNamesEqual(name, accountName));
}

function uidHeldOnlyByServiceAccount(accountName: string, holders: readonly string[]): boolean {
  return holders.length > 0 && holders.every((name) => directoryServiceAccountNamesEqual(name, accountName));
}

function postCreateUidHolderConflictGuidance(accountName: string): string {
  return (
    `Recovery: do not treat the create as successful until the uid lookup returns only ` +
    `${JSON.stringify(accountName)}. Inspect the other holder names, rename or reassign unrelated accounts, ` +
    `or choose a different agent id before rerunning; do not delete the account home as part of recovery.`
  );
}

function existingUidHolderConflictGuidance(accountName: string, uid: number, foreignHolders: readonly string[]): string {
  return (
    `Recovery: uid ${uid} must be held only by ${JSON.stringify(accountName)} before rerunning. ` +
    `Rename or reassign the colliding account${foreignHolders.length === 1 ? "" : "s"} ` +
    `${describeAccountNames(foreignHolders)} away from uid ${uid}; do not delete account homes as part of recovery.`
  );
}

function assertPlanAvoidsExcludedUids(plan: AccountProvisionPlan, options: AccountProvisionOptions): void {
  if (plan.action === "conflict") return;
  const excluded = sortedUniqueSafeUids(options.excludedUids);
  if (!excluded.includes(plan.uid)) return;
  throw new AccountProvisionVerificationError(
    `Refusing to use uid ${plan.uid} for service account "${plan.accountName}": it is in the caller-supplied ` +
      `excluded uid set (${excluded.join(", ")}). ` +
      serviceAccountConflictGuidance(plan.accountName, {
        homeDirectory: options.homeDirectory,
        ceiling: options.ceiling,
        excludedUids: excluded,
      }),
  );
}

async function assertCreateUidUnassigned(
  plan: Extract<AccountProvisionPlan, { action: "create" }>,
  options: AccountProvisionOptions,
  ops: Pick<AccountProvisionOps, "lookupAccountNamesByUid">,
): Promise<void> {
  let holders: readonly string[];
  try {
    holders = await ops.lookupAccountNamesByUid(plan.uid);
  } catch (err) {
    throw new AccountProvisionVerificationError(
      `Refusing to create service account "${plan.accountName}" at uid ${plan.uid}: the candidate uid could not ` +
        `be directly observed as unassigned ` +
        `(${err instanceof Error ? err.message : String(err)}). ` +
        serviceAccountRepairGuidance(plan.accountName, {
          homeDirectory: options.homeDirectory,
          uidFloor: options.ceiling,
          excludedUids: options.excludedUids,
        }),
      { cause: err },
    );
  }
  if (holders.length === 0) return;
  throw new AccountProvisionVerificationError(
    `Refusing to create service account "${plan.accountName}" at uid ${plan.uid}: direct uid lookup found ` +
      `${describeAccountNames(holders)} already assigned to that uid. ` +
      `The UID census is only a candidate-selection input; it is not proof that the candidate uid is unassigned. ` +
      serviceAccountConflictGuidance(plan.accountName, {
        homeDirectory: options.homeDirectory,
        ceiling: options.ceiling,
        excludedUids: options.excludedUids,
      }),
  );
}

async function assertCreatedUidHeldOnlyByCreatedAccount(
  plan: Extract<AccountProvisionPlan, { action: "create" }>,
  ops: Pick<AccountProvisionOps, "lookupAccountNamesByUid">,
): Promise<void> {
  let holders: readonly string[] | undefined;
  let lastErr: unknown;
  for (let attempt = 1; attempt <= POST_CREATE_RECORD_READ_ATTEMPTS; attempt += 1) {
    try {
      holders = await ops.lookupAccountNamesByUid(plan.uid);
      lastErr = undefined;
      const uniqueHolders = uniqueDirectoryServiceAccountNames(holders);
      const foreignHolders = foreignUidHolders(plan.accountName, uniqueHolders);
      if (foreignHolders.length > 0) {
        throw new AccountProvisionVerificationError(
          `post-create uid lookup for service account "${plan.accountName}" at uid ${plan.uid} found ` +
            `${describeAccountNames(uniqueHolders)}; expected only ${JSON.stringify(plan.accountName)}. ` +
            postCreateUidHolderConflictGuidance(plan.accountName),
        );
      }
      if (uidHeldOnlyByServiceAccount(plan.accountName, uniqueHolders)) return;
    } catch (err) {
      if (err instanceof AccountProvisionVerificationError) throw err;
      holders = undefined;
      lastErr = err;
    }
    if (attempt < POST_CREATE_RECORD_READ_ATTEMPTS) {
      await sleep(POST_CREATE_RECORD_READ_RETRY_DELAY_MS);
    }
  }

  if (lastErr !== undefined) {
    throw new AccountProvisionVerificationError(
      `post-create uid lookup for service account "${plan.accountName}" at uid ${plan.uid} failed ` +
        `(${lastErr instanceof Error ? lastErr.message : String(lastErr)})`,
      { cause: lastErr },
    );
  }

  const uniqueHolders = uniqueDirectoryServiceAccountNames(holders ?? []);
  throw new AccountProvisionVerificationError(
    `post-create uid lookup for service account "${plan.accountName}" at uid ${plan.uid} found ` +
      `${uniqueHolders.length === 0 ? "no account names" : describeAccountNames(uniqueHolders)}; ` +
      `expected only ${JSON.stringify(plan.accountName)}. ` +
      postCreateUidHolderConflictGuidance(plan.accountName),
  );
}

async function assertExistingUidHeldOnlyByServiceAccount(
  plan: Extract<AccountProvisionPlan, { action: "skip" }>,
  ops: Pick<AccountProvisionOps, "lookupAccountNamesByUid">,
): Promise<void> {
  let holders: readonly string[];
  try {
    holders = await ops.lookupAccountNamesByUid(plan.uid);
  } catch (err) {
    throw new AccountProvisionVerificationError(
      `Existing service account "${plan.accountName}" at uid ${plan.uid} could not be checked for shared uid ` +
        `holders (${err instanceof Error ? err.message : String(err)}). Refusing to proceed until direct uid lookup is available.`,
      { cause: err },
    );
  }

  const uniqueHolders = uniqueDirectoryServiceAccountNames(holders);
  const foreignHolders = foreignUidHolders(plan.accountName, uniqueHolders);
  if (foreignHolders.length > 0) {
    throw new AccountProvisionVerificationError(
      `Existing service account "${plan.accountName}" at uid ${plan.uid} shares that uid with ` +
        `${describeAccountNames(foreignHolders)}. Refusing to proceed. ` +
        existingUidHolderConflictGuidance(plan.accountName, plan.uid, foreignHolders),
    );
  }
  if (!uidHeldOnlyByServiceAccount(plan.accountName, uniqueHolders)) {
    throw new AccountProvisionVerificationError(
      `Existing service account "${plan.accountName}" at uid ${plan.uid} could not be directly confirmed as the ` +
        `only holder of that uid; lookup found ${
          uniqueHolders.length === 0 ? "no account names" : describeAccountNames(uniqueHolders)
        }. Refusing to proceed until the directory-service uid lookup returns only ${JSON.stringify(plan.accountName)}.`,
    );
  }
}

export async function rollbackCreatedServiceAccount(
  ops: Pick<AccountProvisionOps, "lookupAccountRecord">,
  accountName: string,
  plannedUid: number,
): Promise<AccountProvisionRollbackResult> {
  let before: ServiceAccountRecord | undefined;
  try {
    before = await ops.lookupAccountRecord(accountName);
  } catch (err) {
    return {
      message:
        `rollback NOT attempted: pre-delete read failed ` +
        `(${err instanceof Error ? err.message : String(err)}); account state is unknown and no account deletion was attempted`,
    };
  }
  if (before === undefined) {
    return {
      message: "rollback not needed: account record absence was observed before any account deletion was attempted",
    };
  }
  return {
    message:
      `rollback deletion NOT attempted: observed ${describeServiceAccountRecord(before)} after a failed create ` +
      `for planned uid ${plannedUid}; a name-based account delete is not atomic with that observation, so the ` +
      `record is left in place for in-place repair`,
  };
}

const POST_CREATE_RECORD_READ_ATTEMPTS = 3;
const POST_CREATE_RECORD_READ_RETRY_DELAY_MS = 50;

export async function lookupAccountRecordAfterCreate(
  ops: Pick<AccountProvisionOps, "lookupAccountRecord">,
  accountName: string,
): Promise<ServiceAccountRecord | undefined> {
  let lastErr: unknown;
  for (let attempt = 1; attempt <= POST_CREATE_RECORD_READ_ATTEMPTS; attempt += 1) {
    try {
      const record = await ops.lookupAccountRecord(accountName);
      lastErr = undefined;
      if (record !== undefined) return record;
      if (attempt < POST_CREATE_RECORD_READ_ATTEMPTS) {
        await sleep(POST_CREATE_RECORD_READ_RETRY_DELAY_MS);
      }
    } catch (err) {
      lastErr = err;
      if (attempt < POST_CREATE_RECORD_READ_ATTEMPTS) {
        await sleep(POST_CREATE_RECORD_READ_RETRY_DELAY_MS);
      }
    }
  }
  if (lastErr !== undefined) throw lastErr;
  return undefined;
}

/**
 * Execute a plan: for `skip`/`conflict`, no mutation. For `create`, calls
 * `ops.createUser`, then reads the directory-service record back and verifies
 * the service-account shape. Real creation is drill-only; unit tests inject a
 * mock `AccountProvisionOps`, never a real `sysadminctl`/`dscl` invocation.
 */
export async function executeAccountProvisionPlan(
  plan: AccountProvisionPlan,
  options: AccountProvisionOptions,
  ops: AccountProvisionOps,
): Promise<{ uid: number; observed: string }> {
  if (plan.action === "conflict") {
    throw new Error(
      `${plan.reason} ${serviceAccountConflictGuidance(plan.accountName, {
        homeDirectory: options.homeDirectory,
        ceiling: options.ceiling,
        excludedUids: options.excludedUids,
      })}`,
    );
  }
  const expected = { uid: plan.uid, homeDirectory: options.homeDirectory };
  if (plan.action === "skip") {
    assertPlanAvoidsExcludedUids(plan, options);
    const observed = await ops.lookupAccountRecord(plan.accountName);
    const problems = await serviceAccountRecordProblems(observed, expected, ops);
    if (problems.length > 0) {
      throw new AccountProvisionVerificationError(
        `Existing service account "${plan.accountName}" is incomplete (${problems.join("; ")}). ` +
          `Observed ${describeServiceAccountRecord(observed)}. Refusing to proceed. ` +
          serviceAccountRepairGuidance(plan.accountName, expected),
      );
    }
    await assertExistingUidHeldOnlyByServiceAccount(plan, ops);
    return { uid: plan.uid, observed: describeServiceAccountRecord(observed) };
  }
  await assertCreateUidUnassigned(plan, options, ops);
  assertPlanAvoidsExcludedUids(plan, options);
  // FIX F7: bind NFSHomeDirectory to the re-home target at create time.
  try {
    await ops.createUser(plan.accountName, plan.uid, options.comment, options.homeDirectory);
    await ops.hardenCreatedUser(plan.accountName);
  } catch (err) {
    const rollback = await rollbackCreatedServiceAccount(ops, plan.accountName, plan.uid);
    throw new AccountProvisionVerificationError(
      `Creating service account "${plan.accountName}" failed ` +
        `(${err instanceof Error ? err.message : String(err)}). ${rollback.message}. ` +
        serviceAccountRepairGuidance(plan.accountName, expected),
      { cause: err },
    );
  }
  try {
    await assertCreatedUidHeldOnlyByCreatedAccount(plan, ops);
  } catch (err) {
    const rollback = await rollbackCreatedServiceAccount(ops, plan.accountName, plan.uid);
    throw new AccountProvisionVerificationError(
      `Service account "${plan.accountName}" create returned, but the post-create uid-holder check failed ` +
        `(${err instanceof Error ? err.message : String(err)}). ${rollback.message}.`,
      { cause: err },
    );
  }
  let observed: ServiceAccountRecord | undefined;
  try {
    observed = await lookupAccountRecordAfterCreate(ops, plan.accountName);
  } catch (err) {
    const rollback = await rollbackCreatedServiceAccount(ops, plan.accountName, plan.uid);
    throw new AccountProvisionVerificationError(
      `Service account "${plan.accountName}" create returned, but the post-create record could not be read ` +
        `(${err instanceof Error ? err.message : String(err)}). ${rollback.message}. ` +
        serviceAccountRepairGuidance(plan.accountName, expected),
      { cause: err },
    );
  }
  const problems = await serviceAccountRecordProblems(observed, expected, ops);
  if (problems.length > 0) {
    const rollback = await rollbackCreatedServiceAccount(ops, plan.accountName, plan.uid);
    throw new AccountProvisionVerificationError(
      `Service account "${plan.accountName}" create did not verify (${problems.join("; ")}). ` +
        `Observed ${describeServiceAccountRecord(observed)}. ${rollback.message}. ` +
        serviceAccountRepairGuidance(plan.accountName, expected),
    );
  }
  return { uid: plan.uid, observed: describeServiceAccountRecord(observed) };
}

/**
 * Convenience: probe + plan + execute in one call, for callers (the
 * orchestrator) that do not need to inspect the plan before executing it.
 * Kept separate from {@link planAccountCreate} so unit tests can exercise
 * pure planning without an ops object at all.
 */
export async function planAndCreateAccount(
  options: AccountProvisionOptions,
  ops: AccountProvisionOps,
): Promise<{ plan: AccountProvisionPlan; uid: number; observed: string }> {
  let existingRecord: ServiceAccountRecord | undefined;
  try {
    existingRecord = await ops.lookupAccountRecord(options.accountName);
  } catch (err) {
    throw new AccountProvisionVerificationError(
      `Existing service account "${options.accountName}" could not be read well enough to plan ` +
        `(${err instanceof Error ? err.message : String(err)}). Refusing to create over an unknown or malformed ` +
        `directory-service record. ` +
        serviceAccountRepairGuidance(options.accountName, {
          homeDirectory: options.homeDirectory,
          uidFloor: options.ceiling,
        }),
      { cause: err },
    );
  }
  const existingUid = existingRecord?.uid;
  const highestAssignedUid = await ops.highestAssignedUid();
  const plan = planAccountCreate(options, { existingUid, highestAssignedUid });
  const result = await executeAccountProvisionPlan(plan, options, ops);
  return { plan, uid: result.uid, observed: result.observed };
}
