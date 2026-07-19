import { normalize as normalizePath } from "node:path";

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
 * POSIX-ish service-account name, deliberately the SAME conservative charset
 * as harness-daemon.ts's SAFE_ACCOUNT_RE (kept in lockstep by a structural
 * test): lowercase start, then a conservative charset. This rejects anything
 * that could smuggle shell metacharacters or spaces into a `dscl`/
 * `sysadminctl` argv.
 */
export const SAFE_SERVICE_ACCOUNT_RE = /^[a-z_][a-z0-9._-]{0,63}$/;

/** Privileged account names an agent service account must never collide with. */
const RESERVED_ACCOUNT_NAMES = new Set(["root", "_root", "daemon", "wheel", "admin"]);

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
  /** Return the highest uid currently assigned to any local account. */
  highestAssignedUid(): Promise<number>;
  /**
   * Create the hidden, no-login service account with the given uid. Must
   * set `IsHidden=1`, `UserShell=/usr/bin/false`, no admin group membership,
   * and no interactive password (service-account shape), AND (fix F7) set
   * `NFSHomeDirectory` to `homeDirectory` so the account's directory-service
   * home matches the re-home target. Production backing is
   * `sysadminctl -addUser` + `dscl`; drill-only, never invoked by tests.
   */
  createUser(accountName: string, uid: number, comment: string | undefined, homeDirectory: string): Promise<void>;
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

function normalizeComparableHome(path: string): string {
  const normalized = normalizePath(path);
  if (normalized === "/") return normalized;
  return normalized.replace(/\/+$/, "");
}

async function canonicalizeComparableHome(
  ops: Pick<AccountProvisionOps, "canonicalizeHomeDirectory">,
  path: string,
): Promise<string> {
  return normalizeComparableHome(await ops.canonicalizeHomeDirectory(path));
}

export function describeServiceAccountRecord(record: ServiceAccountRecord | undefined): string {
  if (record === undefined) return "account record absent";
  return (
    `account record uid=${record.uid}, NFSHomeDirectory=${record.homeDirectory ?? "<missing>"}, ` +
    `IsHidden=${record.isHidden === undefined ? "<missing>" : record.isHidden ? "1" : "0"}, ` +
    `UserShell=${record.userShell ?? "<missing>"}`
  );
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
 * - `create`: no account with this name exists. uid = lowest free integer
 *   strictly greater than both the ceiling and every currently-assigned uid,
 *   so the new account can never collide with an existing one and is always
 *   >= ceiling (satisfying `validateAgentOrigin`'s floor).
 */
export function planAccountCreate(
  options: AccountProvisionOptions,
  probe: { existingUid: number | undefined; highestAssignedUid: number },
): AccountProvisionPlan {
  const { accountName, ceiling, homeDirectory } = options;

  if (!SAFE_SERVICE_ACCOUNT_RE.test(accountName)) {
    throw new Error(`Account name is not a safe service-account name (got: ${JSON.stringify(accountName)}).`);
  }
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
  if (!homeDirectory.startsWith("/") || homeDirectory.includes("..")) {
    throw new Error(`Home directory must be an absolute path with no ".." segments (got: ${JSON.stringify(homeDirectory)}).`);
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
    throw new Error(plan.reason);
  }
  const expected = { uid: plan.uid, homeDirectory: options.homeDirectory };
  if (plan.action === "skip") {
    const observed = await ops.lookupAccountRecord(plan.accountName);
    const problems = await serviceAccountRecordProblems(observed, expected, ops);
    if (problems.length > 0) {
      throw new AccountProvisionVerificationError(
        `Existing service account "${plan.accountName}" is incomplete (${problems.join("; ")}). ` +
          `Observed ${describeServiceAccountRecord(observed)}. Refusing to proceed; account was not created by this run.`,
      );
    }
    return { uid: plan.uid, observed: describeServiceAccountRecord(observed) };
  }
  // FIX F7: bind NFSHomeDirectory to the re-home target at create time.
  await ops.createUser(plan.accountName, plan.uid, options.comment, options.homeDirectory);
  let observed: ServiceAccountRecord | undefined;
  try {
    observed = await ops.lookupAccountRecord(plan.accountName);
  } catch (err) {
    throw new AccountProvisionVerificationError(
      `Service account "${plan.accountName}" create returned, but the post-create record could not be read ` +
        `(${err instanceof Error ? err.message : String(err)}). Refusing to proceed before arming.`,
      { cause: err },
    );
  }
  const problems = await serviceAccountRecordProblems(observed, expected, ops);
  if (problems.length > 0) {
    throw new AccountProvisionVerificationError(
      `Service account "${plan.accountName}" create did not verify (${problems.join("; ")}). ` +
        `Observed ${describeServiceAccountRecord(observed)}. Refusing to proceed before arming.`,
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
  const existingRecord = await ops.lookupAccountRecord(options.accountName);
  const existingUid = existingRecord?.uid;
  const highestAssignedUid = await ops.highestAssignedUid();
  const plan = planAccountCreate(options, { existingUid, highestAssignedUid });
  const result = await executeAccountProvisionPlan(plan, options, ops);
  return { plan, uid: result.uid, observed: result.observed };
}
