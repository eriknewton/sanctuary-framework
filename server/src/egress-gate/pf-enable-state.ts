/**
 * THE pf ENABLE-REFERENCE CHOKEPOINT: acquire, resolve, release. One module
 * owns the entire lifecycle of the `pfctl -E` reference this fortress holds,
 * because that lifecycle was got wrong at three separate call sites and the
 * cost of each mistake was a wrong-allow.
 *
 * WHAT A pf ENABLE REFERENCE IS. `pfctl -E` enables pf and returns a numeric
 * TOKEN naming one entry in the kernel's enable-reference table. pf stays
 * enabled while at least one reference is held; `pfctl -X <token>` releases
 * one. The table lives in the kernel and a reboot ZEROES it. The registry file
 * that persists our token does not reboot. That asymmetry is the whole bug
 * family below.
 *
 * TWO MEASURED DEFECTS THIS MODULE EXISTS TO CLOSE (Mini1, 2026-07-26, merged
 * main `ed7722ce`; evidence `p5-drill-2026-07-26/`):
 *
 *   F-PFBOOT (HIGH, fails closed). The arm path decided whether to run
 *   `pfctl -E` from the RECORD alone: `if (existingEnableToken === undefined)`.
 *   After one reboot the persisted token was byte-identical
 *   (`2276319666065282592`), pf was `Status: Disabled`, `pfctl -s References`
 *   held nothing, the anchor was gone, and uid 503's loopback confinement had
 *   collapsed (ports 22 / 5900 / 11434 / 5432 CONNECTED 3/3 against blocked
 *   3/3 in the armed control). Every recovery verb then deadlocked on the same
 *   missing `-E`.
 *
 *   F-PFTHIRDPARTY (HIGH, fails OPEN, no reboot required). With pf enabled by
 *   a reference Sanctuary does NOT own and our own token kernel-invalid, the
 *   product reported the gate LIVE. Releasing that third-party reference --
 *   changing nothing else -- destroyed uid 503's loopback confinement in the
 *   SAME boot session and the SAME generation while the gate, the peer
 *   resolver and the agent all kept running. This is why a global
 *   `pfctl -s info` -> `Status: Enabled` read is NECESSARY BUT NOT SUFFICIENT:
 *   it is an unattributed fact about the host, not a fact about us.
 *
 * THE INVARIANT THIS MODULE ENFORCES. Whenever the confined-uid union is
 * non-empty, Sanctuary holds ITS OWN live pf enable reference, minted in THIS
 * boot session. Holding our own reference is what makes a third party's
 * release survivable: the refcount cannot fall to zero underneath our anchor.
 *
 * HOW "OURS, LIVE, THIS BOOT" IS ESTABLISHED, and why each leg is there:
 *
 *   1. BOOT SESSION (`kern.bootsessionuuid`). A token minted in a different
 *      boot session names a reference the kernel destroyed at boot. This leg
 *      is a DEFINITE NEGATIVE that costs zero pfctl calls and that an
 *      unreadable or broken pfctl cannot make wrong. It is a fast path, not a
 *      necessary condition: a record with no session (state written by a build
 *      that predates this module) still resolves through legs 2 and 3.
 *      The same mechanism already guards the harness release barrier's hold
 *      file (`release-barrier.ts`), so this is a reuse, not a new dependency.
 *
 *   2. pf ENABLED (`pfctl -s info` -> `Status: Enabled`). Necessary: with pf
 *      disabled no reference of any kind exists. Not sufficient: it cannot
 *      tell our reference from anybody else's. That gap IS F-PFTHIRDPARTY.
 *
 *   3. ATTRIBUTION (`pfctl -s References` contains our exact token). Captured
 *      on hardware: the `TOKEN` column carries the same value `-E` returned,
 *      so "is MY token live?" is directly answerable. `Process Name` is always
 *      `pfctl` and the owning PID has already exited, so THE TOKEN IS THE ONLY
 *      USABLE DISCRIMINATOR from this surface.
 *
 * "COULD NOT LOOK" IS REPRESENTABLE, AND IT IS NEVER "YES". Every observation
 * here returns a discriminated union with a `known: false` arm. The resolver's
 * three-state verdict (`ours-live` / `not-ours` / `unknown`) collapses to
 * exactly one permission: ONLY `ours-live` may reuse a recorded token.
 * `unknown` re-acquires. That fail direction is deliberate and asymmetric --
 * a needless `-E` can at worst leave pf enabled with one extra reference
 * (over-enforcing, releasable, visible), whereas trusting the record risks pf
 * being disabled while we report armed, which is the wrong-allow both findings
 * are about.
 *
 * PFCTL FACTS PINNED FROM HARDWARE, not from documentation or memory
 * (`T1-pf-reference-observation.log`, `T2-pf-exitcodes-corrected.log`; the
 * exit codes were re-measured with no pipe after a first pass captured grep's
 * status instead of pfctl's):
 *
 *   - `pfctl -E` writes BOTH `pf enabled` and `Token : <n>` to STDERR, exit 0.
 *     A parser reading stdout alone gets nothing.
 *   - `pfctl -X <stale>` with pf DISABLED exits 1, stderr `pfctl: pf not enabled`.
 *   - `pfctl -X <stale>` with pf ENABLED exits 1, stderr `pfctl: pf: token invalid`.
 *     TWO distinct messages. Suppressing only one still throws on the more
 *     common post-reboot case.
 *   - `pfctl -X <valid>`, last reference: exit 0, stderr `pf disabled`.
 *   - `pfctl -X <valid>`, others remain: exit 0, stderr
 *     `disable request successful. 1 more pf enable reference(s) remaining, ...`.
 *   - `pfctl -s References` with nothing held prints exactly
 *     `No pf starter references held`; otherwise a `TOKENS:` header, a column
 *     header, then one row per reference.
 *
 * Every command runs through the injected {@link ExecCommandRunner}, so the
 * whole state machine is unit-testable against fixtures built FROM the
 * captured drill output without root or a real pf.
 */

import { execFile } from "node:child_process";

import type { ExecCommandResult, ExecCommandRunner } from "./exec-runner.js";

/**
 * A pf enable reference this fortress holds, bound to the boot session that
 * minted it. Persisted by the anchor registry; the binding is what lets a
 * later boot recognize the token as dead without asking pf anything.
 */
export interface PfEnableReference {
  /** The numeric token `pfctl -E` returned. */
  token: string;
  /**
   * `kern.bootsessionuuid` at mint time. OPTIONAL because the sysctl can fail
   * and because state written before this module carries no binding; an
   * absent session simply forfeits the cheap definite-negative fast path and
   * falls through to the pfctl attribution legs. It is NEVER read as consent.
   */
  boot_session_uuid?: string;
}

/** A pf enable token is always a run of decimal digits. */
export const PF_ENABLE_TOKEN_RE = /^\d+$/;

/** What `pfctl -s info` said about pf's global enable state, right now. */
export type PfEnabledObservation =
  | { known: true; enabled: boolean }
  | { known: false; reason: string };

/** Which enable-reference tokens the kernel currently holds, right now. */
export type PfEnableReferencesObservation =
  | { known: true; tokens: string[] }
  | { known: false; reason: string };

/**
 * The three-state verdict on a recorded reference. ONLY `ours-live` permits
 * reuse; both other arms re-acquire. `not-ours` is a DEFINITE negative (we
 * looked and the reference is not there); `unknown` is "we could not look",
 * kept distinct so a diagnostic never reports a failed probe as a fact.
 */
export type PfEnableReferenceResolution =
  | { status: "ours-live"; reference: PfEnableReference; evidence: string[] }
  | { status: "not-ours"; reason: string }
  | { status: "unknown"; reason: string };

/** What {@link releasePfEnableReference} did with the token it was handed. */
export type PfEnableReferenceDisposition =
  /** `pfctl -X` succeeded: the reference this fortress held is released. */
  | "released"
  /**
   * The kernel has no such reference -- pfctl said the token is invalid, or pf
   * is not enabled at all. Nothing to release and nothing leaked.
   */
  | "already-gone";

/** Result of {@link releasePfEnableReference}. */
export interface PfEnableReferenceRelease {
  disposition: PfEnableReferenceDisposition;
  /** The evidence behind an `already-gone` call (absent for `released`). */
  reason?: string;
}

/** Reads `kern.bootsessionuuid`. Injected so tests never shell out. */
export type BootSessionReader = () => Promise<string>;

/** The one regex in this codebase that decides what "pf is enabled" looks like. */
const PF_STATUS_ENABLED_RE = /^Status:\s+Enabled\b/m;

/** pfctl's sentinel for an EMPTY reference table (captured verbatim). */
const PF_NO_REFERENCES_RE = /^No pf starter references held\s*$/m;

/** The header pfctl prints above a NON-empty reference table. */
const PF_REFERENCES_HEADER_RE = /^TOKENS:\s*$/m;

/**
 * pfctl's own words for "that reference does not exist", BOTH spellings. The
 * message depends on pf's state at release time, and the post-reboot case is
 * the `pf not enabled` one -- a fix that suppresses only `token invalid`
 * still throws on the common path (drill section 5.1).
 */
const PF_REFERENCE_ABSENT_RE = /token\s+invalid|pf\s+not\s+enabled/i;

/** The token line `pfctl -E` prints (on STDERR, drill T2 section B). */
const PF_ENABLE_TOKEN_LINE_RE = /Token\s*:\s*(\d+)/;

/** Hard timeout for the sysctl read backing {@link readBootSessionUuid}. */
const BOOT_SESSION_TIMEOUT_MS = 5_000;

/**
 * THE production boot-session reader: `sysctl -n kern.bootsessionuuid`, a
 * random UUID the kernel mints once per boot. Throws when unreadable or empty
 * (callers decide their own fail direction from that; nothing here silently
 * substitutes a value that would make a stale token look current).
 *
 * This is the SINGLE reader for the whole subsystem: `release-barrier.ts`'s
 * hold-file binding and this module's reference binding must never disagree
 * about what boot they are in.
 */
export function readBootSessionUuid(): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      "/usr/sbin/sysctl",
      ["-n", "kern.bootsessionuuid"],
      { timeout: BOOT_SESSION_TIMEOUT_MS, encoding: "utf8" },
      (error, stdout) => {
        if (error) {
          reject(new Error(`cannot read kern.bootsessionuuid: ${error.message}`, { cause: error }));
          return;
        }
        const uuid = stdout.trim();
        if (uuid.length === 0) {
          reject(new Error("kern.bootsessionuuid is empty"));
          return;
        }
        resolve(uuid);
      },
    );
  });
}

/**
 * THE pf-enabled predicate. Every decision that depends on "is pf enabled
 * right now" routes through here, so there is one place that knows how to read
 * it and one thing to change in a test.
 *
 * NEVER THROWS: an unreadable pf is `{ known: false }` and each caller states
 * its own fail direction explicitly. Collapsing that into `enabled: false`
 * would be a claim about the world made from something that is not an
 * observation of it.
 */
export async function observePfEnabled(runner: ExecCommandRunner): Promise<PfEnabledObservation> {
  let info: ExecCommandResult;
  try {
    info = await runner.run("pfctl", ["-s", "info"]);
  } catch (err) {
    return {
      known: false,
      reason: `pfctl -s info failed to run: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  if (info.code !== 0) {
    return { known: false, reason: `pfctl -s info exited ${info.code}` };
  }
  return { known: true, enabled: PF_STATUS_ENABLED_RE.test(info.stdout) };
}

/**
 * Parse the token column out of `pfctl -s References` output.
 *
 * FORMAT, captured on hardware rather than assumed:
 *
 *   No pf starter references held
 *
 * or
 *
 *   TOKENS:
 *   PID      Process Name                 TOKEN                    TIMESTAMP
 *   4063     pfctl                        15053025338191571182     0 days 00:00:00
 *
 * The TIMESTAMP column is three whitespace-separated fields (`0 days
 * 00:00:00`), so the token is the 4th field from the END. Counting backwards
 * rather than forwards keeps the parse correct if a `Process Name` ever
 * contains a space -- every captured row says `pfctl`, but a positional parse
 * that assumes one word would misread a value silently, and misreading here
 * means misattributing a reference.
 *
 * Returns `null` when the output is in NEITHER recognized shape, or when a
 * data row cannot be parsed. That is deliberately "could not look" rather than
 * "no tokens": silently dropping a row we failed to read would let us conclude
 * a reference is absent because our parser is out of date.
 */
export function parsePfEnableReferenceTokens(stdout: string): string[] | null {
  if (PF_NO_REFERENCES_RE.test(stdout)) return [];
  if (!PF_REFERENCES_HEADER_RE.test(stdout)) return null;
  const tokens: string[] = [];
  for (const rawLine of stdout.split("\n")) {
    const line = rawLine.trim();
    if (line.length === 0) continue;
    if (/^TOKENS:$/.test(line)) continue;
    const fields = line.split(/\s+/);
    // The column header row, identified positively by its first field.
    if (fields[0] === "PID") continue;
    if (fields.length < 4) return null;
    const token = fields[fields.length - 4];
    if (token === undefined || !PF_ENABLE_TOKEN_RE.test(token)) return null;
    tokens.push(token);
  }
  return tokens;
}

/**
 * Observe which enable-reference tokens the kernel currently holds. This is
 * the ATTRIBUTION surface: `pfctl -s info` says pf is enabled, this says by
 * whom -- and by token exactly, which is the only discriminator the surface
 * offers (`Process Name` is always `pfctl`; the owning PID has exited).
 *
 * NEVER THROWS; an unreadable or unrecognized table is `{ known: false }`.
 */
export async function observePfEnableReferences(
  runner: ExecCommandRunner,
): Promise<PfEnableReferencesObservation> {
  let refs: ExecCommandResult;
  try {
    refs = await runner.run("pfctl", ["-s", "References"]);
  } catch (err) {
    return {
      known: false,
      reason: `pfctl -s References failed to run: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  if (refs.code !== 0) {
    return { known: false, reason: `pfctl -s References exited ${refs.code}` };
  }
  const tokens = parsePfEnableReferenceTokens(refs.stdout);
  if (tokens === null) {
    return {
      known: false,
      reason:
        "pfctl -s References printed neither the empty-table sentinel nor a parseable TOKENS " +
        "table; the pf enable reference cannot be attributed from this output",
    };
  }
  return { known: true, tokens };
}

/** Injected surfaces {@link resolvePfEnableReference} reads. */
export interface PfEnableReferenceOps {
  runner: ExecCommandRunner;
  /** Defaults to {@link readBootSessionUuid}. */
  bootSession?: BootSessionReader;
}

async function currentBootSessionOrNull(ops: PfEnableReferenceOps): Promise<string | null> {
  const read = ops.bootSession ?? readBootSessionUuid;
  try {
    const uuid = (await read()).trim();
    return uuid.length > 0 ? uuid : null;
  } catch {
    return null;
  }
}

/**
 * Decide whether a RECORDED reference is ours, live, and from this boot.
 *
 * The legs run cheapest-and-most-certain first:
 *
 *   1. A recorded boot session that differs from the current one is a DEFINITE
 *      negative with no pfctl call at all. This is the leg an unreadable or
 *      misbehaving pfctl cannot corrupt, which is exactly why a reference-count
 *      parse alone is not enough.
 *   2. pf observed DISABLED is a definite negative: no reference can exist.
 *      pf UNREADABLE is `unknown`.
 *   3. Our exact token present in `pfctl -s References` is the positive
 *      evidence. Absent is a definite negative and is the F-PFTHIRDPARTY case:
 *      pf is enabled by somebody else and our token is kernel-invalid.
 *
 * A recorded session that MATCHES is never treated as sufficient on its own --
 * legs 2 and 3 still run. Matching only removes a shortcut; it grants nothing.
 */
export async function resolvePfEnableReference(
  ops: PfEnableReferenceOps,
  record: PfEnableReference | undefined,
): Promise<PfEnableReferenceResolution> {
  if (record === undefined) {
    return { status: "not-ours", reason: "no pf enable reference is recorded (first arm)" };
  }
  if (!PF_ENABLE_TOKEN_RE.test(record.token)) {
    return {
      status: "not-ours",
      reason: `the recorded pf enable token ${JSON.stringify(record.token)} is not numeric`,
    };
  }
  const evidence: string[] = [];

  const currentBoot = await currentBootSessionOrNull(ops);
  if (record.boot_session_uuid !== undefined && currentBoot !== null) {
    if (record.boot_session_uuid !== currentBoot) {
      return {
        status: "not-ours",
        reason:
          `the recorded pf enable reference was minted in boot session ${record.boot_session_uuid} ` +
          `and this host is in boot session ${currentBoot}; a reboot zeroes pf's reference table, ` +
          "so the token names a reference the kernel no longer has",
      };
    }
    evidence.push(`recorded boot session matches the current one (${currentBoot})`);
  } else if (record.boot_session_uuid === undefined) {
    evidence.push(
      "the recorded reference carries no boot session, so it is resolved by pfctl attribution alone",
    );
  } else {
    evidence.push(
      "the current boot session is unreadable, so it is resolved by pfctl attribution alone",
    );
  }

  const enabled = await observePfEnabled(ops.runner);
  if (!enabled.known) {
    return { status: "unknown", reason: `pf's enable state could not be read: ${enabled.reason}` };
  }
  if (!enabled.enabled) {
    return {
      status: "not-ours",
      reason: "pf is not enabled, so no enable reference of any kind is held",
    };
  }
  evidence.push("pf is observed enabled");

  const refs = await observePfEnableReferences(ops.runner);
  if (!refs.known) {
    return {
      status: "unknown",
      reason: `pf is enabled but the reference table could not be read: ${refs.reason}`,
    };
  }
  if (!refs.tokens.includes(record.token)) {
    return {
      status: "not-ours",
      reason:
        `pf is enabled but the recorded token ${record.token} is absent from pfctl -s References ` +
        `(${refs.tokens.length} reference(s) held, none ours); pf is being held enabled by a ` +
        "reference this fortress does not own, and releasing it would disable pf under the anchor",
    };
  }
  evidence.push(`the recorded token ${record.token} is present in pfctl -s References`);
  return { status: "ours-live", reference: record, evidence };
}

/**
 * Release one pf enable reference by token.
 *
 * A `pfctl -X` that fails BECAUSE the kernel has no such reference is not a
 * teardown failure; it is the truth about a token a reboot invalidated, and
 * treating it as an error is what left the measured host with a registry entry
 * no product path could clear. Both captured failure messages are recognized,
 * and an unreadable-message failure is cross-checked against an OBSERVATION of
 * pf before it is believed. Anything still unexplained THROWS: state is never
 * cleared over a failure we cannot account for.
 *
 * Fail direction: an unreleased reference leaves pf ENABLED, which
 * over-enforces. It can never leave a confined uid with reach it should not
 * have.
 */
export async function releasePfEnableReference(
  ops: PfEnableReferenceOps,
  token: string,
): Promise<PfEnableReferenceRelease> {
  if (!PF_ENABLE_TOKEN_RE.test(token)) {
    throw new Error("releasePfEnableReference: token must be a numeric pfctl reference token");
  }
  const release = await ops.runner.run("pfctl", ["-X", token]);
  if (release.code === 0) {
    return { disposition: "released" };
  }
  const stderr = release.stderr.trim();
  if (PF_REFERENCE_ABSENT_RE.test(`${stderr}\n${release.stdout}`)) {
    return {
      disposition: "already-gone",
      reason:
        `pfctl -X reported the enable token ${token} unusable (${stderr}); the kernel holds no ` +
        "such reference, so there is nothing to release",
    };
  }
  const enabled = await observePfEnabled(ops.runner);
  if (enabled.known && !enabled.enabled) {
    return {
      disposition: "already-gone",
      reason:
        `pfctl -X exited ${release.code} (${stderr}) and pf is observed not enabled, so the ` +
        `reference named by token ${token} cannot exist`,
    };
  }
  throw new Error(`pfctl -X exited ${release.code}: ${stderr}`);
}

/** Outcome of {@link ensurePfEnableReference}. */
export interface PfEnableReferenceEnsured {
  /** The reference this fortress holds now. */
  reference: PfEnableReference;
  /**
   * True when THIS call ran `pfctl -E`. A caller whose subsequent work fails
   * must release exactly this reference and no other.
   */
  acquired: boolean;
  /** The verdict on the recorded reference that produced the decision. */
  resolution: PfEnableReferenceResolution;
  /** What happened to the superseded token, when one was superseded. */
  supersededRelease?: PfEnableReferenceRelease;
  /** Positive observations behind the outcome, for diagnostics and logs. */
  evidence: string[];
}

/**
 * ENSURE this fortress holds its own live pf enable reference, and say which
 * one. THE chokepoint every arm path goes through; there is no second door.
 *
 * Reuse happens on exactly one verdict (`ours-live`). Otherwise `pfctl -E`
 * runs, the FRESH reference is bound to the current boot session, and the
 * superseded token is released best-effort AFTER the new one is held, so pf's
 * reference count never dips to zero underneath a loaded anchor.
 *
 * THE INVARIANT IS ASSERTED, NOT ASSUMED. A 0-exit `-E` is not evidence that
 * pf is enabled or that we own a reference; both are read back. Only DEFINITE
 * negative evidence throws -- an unreadable probe is recorded and left to the
 * caller's own fail-closed settle probe, so a transient pfctl read failure
 * cannot become an availability cliff.
 */
export async function ensurePfEnableReference(
  ops: PfEnableReferenceOps,
  record: PfEnableReference | undefined,
): Promise<PfEnableReferenceEnsured> {
  const resolution = await resolvePfEnableReference(ops, record);
  if (resolution.status === "ours-live") {
    return {
      reference: resolution.reference,
      acquired: false,
      resolution,
      evidence: [...resolution.evidence, "reusing the reference this fortress already holds"],
    };
  }

  const enable = await ops.runner.run("pfctl", ["-E"]);
  if (enable.code !== 0) {
    throw new Error(`pfctl -E exited ${enable.code}: ${enable.stderr.trim()}`);
  }
  // The token arrives on STDERR (drill T2 section B); read both streams so a
  // future pfctl that moves it to stdout keeps working.
  const tokenMatch = PF_ENABLE_TOKEN_LINE_RE.exec(`${enable.stdout}\n${enable.stderr}`);
  if (tokenMatch === null) {
    throw new Error(
      "pfctl -E exited 0 but printed no numeric token; refusing to proceed with an untracked " +
        "pf enable reference (it could never be released at teardown)",
    );
  }
  const token = tokenMatch[1] as string;
  const evidence: string[] = [`acquired pf enable reference ${token} (${resolution.reason})`];

  /**
   * Refusing to report a reference we just took means giving it back. Without
   * this, every assertion failure below would leak exactly the reference this
   * call acquired -- the same unbounded-leak-on-retry shape the arm path's own
   * catch already guards, reproduced one layer down.
   */
  const refuse = async (message: string): Promise<never> => {
    await releasePfEnableReference(ops, token).catch(() => undefined);
    throw new Error(message);
  };

  // ASSERT the invariant the verb was supposed to establish. Before this, a
  // 0-exit `-E` that left pf disabled surfaced only as a generic 5-second
  // settle timeout, and in the field as a wrong-allow.
  const enabledAfter = await observePfEnabled(ops.runner);
  if (enabledAfter.known && !enabledAfter.enabled) {
    await refuse(
      `pfctl -E exited 0 and returned token ${token}, but pf is still not enabled ` +
        "(pfctl -s info lacks 'Status: Enabled'); refusing to report a held enable reference " +
        "over a pf that would enforce nothing",
    );
  }
  if (enabledAfter.known) evidence.push("pf is observed enabled after the acquire");

  const refsAfter = await observePfEnableReferences(ops.runner);
  if (refsAfter.known && !refsAfter.tokens.includes(token)) {
    await refuse(
      `pfctl -E returned token ${token} but pfctl -s References does not list it, so this ` +
        "fortress does not own a pf enable reference; refusing to report one",
    );
  }
  if (refsAfter.known) {
    evidence.push(`token ${token} is present in pfctl -s References`);
  } else {
    evidence.push(`the reference table could not be re-read after the acquire: ${refsAfter.reason}`);
  }

  const bootSession = await currentBootSessionOrNull(ops);
  const reference: PfEnableReference = {
    token,
    ...(bootSession !== null ? { boot_session_uuid: bootSession } : {}),
  };
  if (bootSession === null) {
    evidence.push(
      "kern.bootsessionuuid was unreadable, so this reference is recorded without a boot binding " +
        "and will be re-resolved by pfctl attribution next time",
    );
  }

  // Release the superseded reference LAST, so the count never dips to zero.
  // Best-effort by design: a release we cannot explain leaves pf enabled with
  // one extra reference, which over-enforces and is visible in
  // `pfctl -s References`; it can never relax the anchor.
  let supersededRelease: PfEnableReferenceRelease | undefined;
  if (record !== undefined && PF_ENABLE_TOKEN_RE.test(record.token) && record.token !== token) {
    supersededRelease = await releasePfEnableReference(ops, record.token).catch(
      (err: unknown): PfEnableReferenceRelease => ({
        disposition: "already-gone",
        reason:
          `the superseded token ${record.token} could not be released ` +
          `(${err instanceof Error ? err.message : String(err)}); pf keeps an extra enable ` +
          "reference, which over-enforces and is visible in pfctl -s References",
      }),
    );
    evidence.push(`superseded token ${record.token}: ${supersededRelease.disposition}`);
  }

  return {
    reference,
    acquired: true,
    resolution,
    ...(supersededRelease !== undefined ? { supersededRelease } : {}),
    evidence,
  };
}
