/**
 * Auto-provision Step 2 (Build 1): arm-time uid-existence gate (fix H1).
 *
 * `validateAgentOrigin` (castle-wall/allowlist/agent-origin.ts) is
 * STRUCTURAL only: it checks that `agent_uid` is a positive integer >= the
 * ceiling, but it never checks that an account with that uid actually
 * EXISTS on the host. Before this fix there was no existence check anywhere
 * in the arm path (`runEnable` / `runArmDisarm` in cli/castle-wall.ts calls
 * straight through to the host-app headless invoke once the descriptor
 * validates).
 *
 * That gap is exploitable by an entirely mundane failure: account creation
 * (`account.ts`'s `planAndCreateAccount`) partially fails (e.g. `dscl`
 * crashes after `sysadminctl -addUser` half-completes), yet the orchestrator
 * already wrote a structurally-valid agent-origin descriptor for the
 * intended uid earlier in the flow. Arming would then classify every
 * non-system flow `.agent` under a uid that does not exist -- the wall
 * reports "protected" over an agent that is NOT actually confined (nothing
 * runs at that uid to be confined). This gate closes that: immediately
 * before the orchestrator calls the shipped `enable --agent-uid=N`, hard
 * -check that account N exists and its uid is EXACTLY the uid about to be
 * armed. Any mismatch or absence refuses to arm.
 */

/** Injected existence probe so tests never touch the host's directory service. */
export interface UidExistenceOps {
  /**
   * Return the uid of the account with this name, or `undefined` if no such
   * account exists. Production backing: `id -u <name>` / `dscl . -read
   * /Users/<name> UniqueID`, fail-closed to `undefined` on ANY probe error
   * (never guess "exists").
   */
  lookupAccountUid(accountName: string): Promise<number | undefined>;
}

/** Result of {@link checkUidExistenceBeforeArm}. */
export type UidExistenceCheckResult =
  | { ok: true; accountName: string; uid: number }
  | { ok: false; accountName: string; reason: string };

/**
 * Hard existence + uid-match check. Refuses (returns `ok: false`) unless the
 * account named `accountName` exists AND its uid is EXACTLY `expectedUid`.
 * Fail-closed: any probe exception propagates as a thrown error (the caller
 * must treat a throw the same as `ok: false` -- never arm on an
 * indeterminate result).
 */
export async function checkUidExistenceBeforeArm(
  accountName: string,
  expectedUid: number,
  ops: UidExistenceOps,
): Promise<UidExistenceCheckResult> {
  const actualUid = await ops.lookupAccountUid(accountName);
  if (actualUid === undefined) {
    return {
      ok: false,
      accountName,
      reason: `refusing to arm: account "${accountName}" does not exist (expected uid ${expectedUid}). Arming now would classify every flow as the confined agent under a uid nothing runs as.`,
    };
  }
  if (actualUid !== expectedUid) {
    return {
      ok: false,
      accountName,
      reason: `refusing to arm: account "${accountName}" exists but at uid ${actualUid}, not the expected uid ${expectedUid}. A stale or conflicting descriptor would confine the wrong identity.`,
    };
  }
  return { ok: true, accountName, uid: actualUid };
}
