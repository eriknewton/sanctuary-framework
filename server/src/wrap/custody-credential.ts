/**
 * Sanctuary — THE fortress custody-credential resolver (one chokepoint).
 *
 * WHY THIS EXISTS (A73, 2026-09-07). `sanctuary init` enrolls an OS-keyring
 * custody factor for the fortress and `doctor` reports `custody factors: OK`,
 * but `protect` resolved its credential on a private chain that never looked at
 * that factor: it MINTED a fresh passphrase, wrote it to a different keyring
 * item, and then refused to start because the credential it had just minted did
 * not unlock the envelope `init` had written. `export-passphrase` read only the
 * `sanctuary-passphrase[-<id>]` family, so it reported "No stored passphrase
 * found" on a fortress whose custody was fine. The install planner observed the
 * fortress and reported `custody_access: usable`, then emitted an argv that
 * could not use any of it. Three verbs, three private lookup orders, one
 * enrolment path, and no bridge between them.
 *
 * Every one of those defects is the same defect: a per-verb credential chain.
 * So the chain lives here once, and `protect` (wrap/cli.ts),
 * `export-passphrase` (cli/export-passphrase.ts), and the install planner (cli/install.ts) all
 * call it. A new verb that needs the fortress credential calls this, or it
 * reintroduces the class.
 *
 * ── THE ORDER, AND WHY IT IS THIS ORDER ────────────────────────────────
 *
 *   1. `--passphrase`                explicit operator input, highest authority
 *   2. `SANCTUARY_PASSPHRASE`        operator-supplied for this invocation
 *   3. `SANCTUARY_RECOVERY_KEY`      operator-held root credential
 *   4. the enrolled OS-keyring custody factor for THIS fortress
 *   5. the stored fortress passphrase (keyring, else encrypted fallback file)
 *
 * Operator-supplied first (1-3) because a credential the operator typed is an
 * INSTRUCTION, not a hint: if the operator names a credential and it does not
 * unlock, the run must fail closed and say so rather than quietly succeeding
 * with some other factor and hiding the operator's mistake. That is why the
 * first PRESENT operator source is authoritative and never falls through to the
 * host-local factors (4-5).
 *
 * Host-local factors after them, and among themselves they DO fall through,
 * because they are lookups rather than instructions: nobody asserted anything
 * by having them on disk, so trying the next one on a mismatch cannot hide an
 * operator error. The enrolled custody factor precedes the stored passphrase
 * because `init` enrolls the custody factor and does not enroll a passphrase,
 * so on the documented new-user path the custody factor is the only host-local
 * credential that exists; a stale `sanctuary-passphrase` item from an older
 * install must never win over the factor this fortress was actually created
 * with.
 *
 * ── WHY MINTING IS LAST AND CONDITIONAL ────────────────────────────────
 *
 * Minting a passphrase is CREATING custody, not resolving it. It is reachable
 * only when the fortress has no custody envelope and no legacy custody marker
 * at all — a directory `init` never touched. That verdict is about the
 * DIRECTORY, so a leftover host-local keyring item (a removed fortress, an
 * `init` that failed after enrolling) does not suppress it: a key is not a
 * wrap of a fortress that does not exist. Over an existing envelope a mint
 * can only ever produce a credential that does not unlock it (the A73 blocker),
 * and on a legacy fortress it would derive a parallel master. So a fortress
 * with ANY existing custody state fails closed here instead, and the refusal
 * names the sources that were tried.
 *
 * ── WHY A HOST-LOCAL CANDIDATE IS NEVER TAKEN ON PRESENCE ALONE ────────
 *
 * A host-local factor is returned only when it is PROVEN to open this
 * fortress, or when the fortress is one this SOURCE could still be the
 * credential of. The second clause is the pre-envelope (legacy) fortress,
 * whose master is Argon2id(passphrase, `_meta/key-params`): the stored
 * passphrase is taken as-is there and custody establishment migrates in
 * place, while an OS-keyring custody item is skipped as present-but-
 * unverifiable, because nothing on such a fortress was ever derived from one.
 * Selecting the item instead let a stale or planted `sanctuary-custody-<id>`
 * SHADOW the passphrase that does open the fortress, and the boot then
 * refused with a credential it had chosen itself.
 *
 * Nothing in this module writes to the fortress or to the OS keyring. The mint
 * decision is REPORTED to the caller (`status: "mint-required"`); the caller
 * performs it through the ordinary passphrase path.
 */

import { homedir, platform as osPlatform } from "node:os";
import { join } from "node:path";

import {
  ACCEPTED_CUSTODY_CREDENTIAL_SOURCES,
  CustodyUnlockError,
  readCustodyEnvelope,
  unlockExistingMasterReadOnly,
} from "../core/master-custody.js";
import type { StorageBackend } from "../storage/interface.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { readKeychainCustodyKeyStatus } from "./keychain-custody.js";
import {
  observeStoredPassphrase,
  observeStoredPassphraseVia,
  readStoredPassphrase,
} from "./passphrase.js";

/** One credential source the resolver knows how to consult. */
export type CustodyCredentialSource =
  | "explicit-passphrase"
  | "env-passphrase"
  | "env-recovery-key"
  | "enrolled-custody-key"
  | "stored-passphrase";

/**
 * The resolution order. Index-for-index this MUST MATCH
 * `ACCEPTED_CUSTODY_CREDENTIAL_SOURCES` in `core/master-custody.ts`, which is
 * the operator-facing wording of the same list; a `CustodyUnlockError` that
 * names sources in a different order than the resolver tries them is a lie an
 * operator would act on. The pairing is asserted mechanically in
 * `test/wrap/custody-credential-resolver.test.ts`.
 */
export const CUSTODY_CREDENTIAL_SOURCE_ORDER: readonly CustodyCredentialSource[] = [
  "explicit-passphrase",
  "env-passphrase",
  "env-recovery-key",
  "enrolled-custody-key",
  "stored-passphrase",
] as const;

/**
 * Sources the operator supplied for THIS invocation. The first present one is
 * authoritative: it is used as given and the host-local factors below it are
 * not consulted, so a wrong operator-supplied credential fails loudly instead
 * of being masked by a factor that happens to work.
 */
const OPERATOR_SUPPLIED_SOURCES: readonly CustodyCredentialSource[] = [
  "explicit-passphrase",
  "env-passphrase",
  "env-recovery-key",
] as const;

/**
 * Sources that live on this host rather than in the invocation. The install
 * planner allows only these, because the argv it emits names no credential and
 * its contract forbids adding one.
 */
export const HOST_LOCAL_CUSTODY_SOURCES: readonly CustodyCredentialSource[] = [
  "enrolled-custody-key",
  "stored-passphrase",
] as const;

/**
 * THE predicate for "the operator supplied this credential on this
 * invocation". An empty string is NOT a supplied credential: an exported-but-
 * empty `SANCTUARY_PASSPHRASE` is what a GUI launcher, a LaunchAgent plist
 * with an empty `EnvironmentVariables` entry, or `env SANCTUARY_PASSPHRASE=`
 * leaves behind, and it carries no instruction at all.
 *
 * MUST MATCH every boot entry point that decides whether to consult the
 * host-local factors: `createSanctuaryServer` (`src/index.ts`) and
 * `startStandaloneDashboard` (`src/dashboard-standalone.ts`) both call THIS
 * function rather than re-testing the value. A caller that used
 * `!== undefined` instead treated an empty value as an operator instruction,
 * skipped the host-local lookup, and then handed `establishMaster` nothing —
 * so one boot path opened a fortress the other refused, which is the exact
 * class of divergence this module exists to close.
 */
export function isOperatorSuppliedCredential(
  supplied: string | undefined,
): supplied is string {
  return supplied !== undefined && supplied.length > 0;
}

/**
 * The first operator-supplied value in preference order, or `undefined` when
 * none of them is supplied. Empty values fall THROUGH to the next candidate,
 * exactly as the operator-source loop in
 * {@link resolveFortressCustodyCredential} does (an empty
 * `--passphrase` does not suppress `SANCTUARY_PASSPHRASE`).
 */
export function firstOperatorSuppliedCredential(
  ...candidates: readonly (string | undefined)[]
): string | undefined {
  return candidates.find(isOperatorSuppliedCredential);
}

/** Operator-facing name of a source. Never a value. */
export function custodyCredentialSourceLabel(
  source: CustodyCredentialSource,
): string {
  return ACCEPTED_CUSTODY_CREDENTIAL_SOURCES[
    CUSTODY_CREDENTIAL_SOURCE_ORDER.indexOf(source)
  ]!;
}

/**
 * Where a resolved credential came from, for the operator-facing notices only.
 * `location` describes the destination ("macOS Keychain", "SANCTUARY_PASSPHRASE",
 * the fallback file's path); `displaySource` is the short token the wrap CLI
 * already prints and branches its fallback-file warning on. Neither ever
 * carries a value.
 */
export interface CustodyCredentialProvenance {
  location: string;
  displaySource: string;
}

/** The resolved credential, in the shape `establishMaster` consumes. */
export type ResolvedCustodyCredential = CustodyCredentialProvenance &
  (
    | { source: CustodyCredentialSource; kind: "passphrase"; passphrase: string }
    | { source: CustodyCredentialSource; kind: "recovery-key"; recoveryKey: string }
    | { source: CustodyCredentialSource; kind: "keychain-key"; keychainKey: Uint8Array }
  );

/**
 * Non-secret account of what the resolver saw. `found` is "material was
 * present", `rejected` is "present AND proven not to unlock this fortress",
 * `indeterminate` is "present but unusable right now" (a locked keyring, an
 * unreadable fallback file). Absent, indeterminate and rejected are three
 * different answers and are never collapsed: an indeterminate factor may still
 * be the valid one, so it must not be reported as a mismatch.
 */
export interface CustodyCredentialReport {
  found: CustodyCredentialSource[];
  rejected: CustodyCredentialSource[];
  indeterminate: CustodyCredentialSource[];
  /**
   * Non-secret reason a source reads indeterminate (a locked keyring, an
   * unreadable fallback file). Present only for sources in `indeterminate`;
   * never carries a credential value.
   */
  details: Partial<Record<CustodyCredentialSource, string>>;
  /**
   * True when something about the FORTRESS, not the credential, prevented a
   * verdict: an unreadable envelope, a failed envelope MAC, a rotation in
   * flight. Kept separate from `rejected` because "the fortress could not be
   * evaluated" must never be reported to an operator as "your credential is
   * wrong" (AGENTS.md: absent, indeterminate and failed are three answers).
   */
  integrityIndeterminate: boolean;
  /** True when this fortress already holds a custody envelope. */
  envelopePresent: boolean;
  /**
   * True when this directory has NEVER been locked with anything: no custody
   * envelope AND no pre-envelope (legacy) marker. The resolver's own mint
   * predicate, published so a caller decides "is there custody here?" from the
   * same fact the mint verdict is computed from.
   *
   * NOT the negation of {@link envelopePresent}. A legacy fortress has no
   * envelope and a master already, so envelope presence answers "which custody
   * FORMAT is this", never "is there custody here". A caller that reads
   * `!envelopePresent` as "virgin" mints a parallel master over live
   * pre-envelope data, which is the whole failure this module exists to
   * prevent. Consumed by {@link resolveHostLocalBootCredential}.
   */
  noCustodyStateAtAll: boolean;
  /**
   * True when an OS-keyring custody item was PRESENT on this host and this
   * fortress has no custody envelope to authenticate it against, so the
   * resolver skipped it.
   *
   * Its own answer, kept apart from the other three: `rejected` is "proven not
   * to unlock", `integrityIndeterminate` is "the FORTRESS could not be
   * evaluated", and this is "the fortress is fine and this item cannot be a
   * credential of it". Collapsing it into either one would send an operator to
   * restore custody state that is not damaged, or to unlock a keyring that is
   * already open. Consumed by {@link custodyCredentialRefusal}, which uses it
   * to say why the item was passed over; the credential that DOES open the
   * fortress comes from {@link legacyCustodyMode}, because it differs by mode.
   */
  custodyKeyUnverifiable: boolean;
  /**
   * Which pre-envelope (LEGACY) custody mode this fortress is in, when it has
   * no envelope and a legacy marker was read: `recovery-key` when
   * `_meta/recovery-key-hash` is present (the master IS the recovery key, and
   * no passphrase can ever open it), `passphrase` when only `_meta/key-params`
   * is (the master is Argon2id(passphrase, params)).
   *
   * `undefined` for an enveloped fortress, for a directory with no custody at
   * all, and for the one case where a marker read THREW: an unreadable marker
   * still means "custody may exist" (so {@link noCustodyStateAtAll} is false
   * and nothing mints), but it does not tell us which mode, and naming a mode
   * we did not read would print a remedy for a credential that cannot open
   * this fortress. Consumed by {@link custodyCredentialRefusal}, which owes a
   * legacy fortress the remedy for ITS mode.
   */
  legacyCustodyMode?: "recovery-key" | "passphrase";
  /**
   * How the OS-keyring CUSTODY-KEY item itself classified on this host, in the
   * vocabulary of `probeKeychainCustodyKey`: `found` (the item exists and
   * yielded material, whether or not it then unlocked), `not-found` (the
   * keyring answered and holds no such item), `unreachable` (the keyring is
   * locked or absent, so its contents are unknowable). `undefined` when the
   * enrolled-custody-key source was not consulted at all (excluded by `allow`,
   * or short-circuited by an operator-supplied credential).
   *
   * Recorded here so a diagnostic can state keyring reachability WITHOUT a
   * second keyring read: two independent reads can disagree (an unlock between
   * them, a transient D-Bus fault), and a refusal whose actionable block says
   * "the item is MISSING" while its accepted-sources block says the same item
   * was present is a message an operator acts on wrongly. One read, one
   * answer. Consumed by `startStandaloneDashboard` (`src/dashboard-standalone.ts`).
   */
  enrolledCustodyKeyItem?: "found" | "not-found" | "unreachable";
}

export type CustodyCredentialResolution =
  | {
      status: "resolved";
      credential: ResolvedCustodyCredential;
      report: CustodyCredentialReport;
    }
  /** No custody state exists at all; the caller may create custody. */
  | { status: "mint-required"; report: CustodyCredentialReport }
  | { status: "unresolved"; report: CustodyCredentialReport };

export interface CustodyCredentialResolverOptions {
  /** Fortress root (the directory holding `state/`). */
  storagePath: string;
  home?: string;
  platformOverride?: NodeJS.Platform;
  /** Environment to read the two credential env vars from. */
  env?: NodeJS.ProcessEnv;
  /** Value of an explicit `--passphrase`, when the verb accepts one. */
  explicitPassphrase?: string;
  /**
   * Restrict the resolver to these sources. Defaults to the full order. The
   * install planner passes {@link HOST_LOCAL_CUSTODY_SOURCES} so its answer
   * describes the argv it is about to emit, which names no credential.
   */
  allow?: readonly CustodyCredentialSource[];
  /**
   * Whether "no custody state at all" may report `mint-required`. Read-only
   * observers pass false: they must never suggest creating custody.
   */
  allowMint?: boolean;
  /** Test seam: fortress storage backend. */
  storage?: StorageBackend;
  /** Test seam: the enrolled-custody-factor read (keychain chokepoint). */
  readCustodyKey?: typeof readKeychainCustodyKeyStatus;
  /** Test seam: the stored-passphrase observation. */
  observePassphrase?: typeof observeStoredPassphrase;
}

/**
 * Operator-facing destination of the enrolled custody factor. It is the OS
 * keyring by construction (`wrap/keychain-custody.ts` has NO fallback file for
 * this factor by design), so this is a fixed string rather than a probe.
 */
export const ENROLLED_CUSTODY_FACTOR_LOCATION = "OS keyring custody factor";

/** `_meta` records that mark a pre-envelope (legacy) fortress. */
const LEGACY_CUSTODY_MARKERS = ["key-params", "recovery-key-hash"] as const;

/**
 * Resolve the credential this fortress should be opened with. Read-only: it
 * never writes the fortress, never writes the OS keyring, and never mints.
 */
export async function resolveFortressCustodyCredential(
  opts: CustodyCredentialResolverOptions,
): Promise<CustodyCredentialResolution> {
  const home = opts.home ?? homedir();
  const platform = opts.platformOverride ?? osPlatform();
  const env = opts.env ?? process.env;
  const allow = new Set(opts.allow ?? CUSTODY_CREDENTIAL_SOURCE_ORDER);
  const storage =
    opts.storage ?? new FilesystemStorage(join(opts.storagePath, "state"));
  const readCustodyKey = opts.readCustodyKey ?? readKeychainCustodyKeyStatus;
  const observePassphrase = opts.observePassphrase ?? observeStoredPassphrase;

  const found: CustodyCredentialSource[] = [];
  const rejected: CustodyCredentialSource[] = [];
  const indeterminate: CustodyCredentialSource[] = [];
  const details: Partial<Record<CustodyCredentialSource, string>> = {};
  let integrityIndeterminate = false;
  /** Set exactly once, at the single keyring read below. See the report field. */
  let enrolledCustodyKeyItem: "found" | "not-found" | "unreachable" | undefined;
  /** See the report field: present item, no envelope to authenticate it against. */
  let custodyKeyUnverifiable = false;

  // An envelope that exists but cannot be read is NOT "no custody". Fail
  // toward "custody exists", so an unreadable or tampered envelope can never
  // route the caller into minting over it.
  let envelope: Awaited<ReturnType<typeof readCustodyEnvelope>> = null;
  let envelopeReadable = true;
  try {
    envelope = await readCustodyEnvelope(storage);
  } catch {
    envelopeReadable = false;
    integrityIndeterminate = true;
  }
  const envelopePresent = envelope !== null || !envelopeReadable;

  // "This directory has never been locked with anything": no envelope AND no
  // pre-envelope marker. Computed HERE, before the host-local step, because it
  // gates that step as well as the mint verdict below. Markers are read only
  // when there is no envelope; with one present they cannot change any answer.
  const legacyMarkers: LegacyCustodyMarkers = envelopePresent
    ? { present: false }
    : await readLegacyCustodyMarkers(storage);
  const noCustodyStateAtAll = !envelopePresent && !legacyMarkers.present;
  const legacyCustodyMode = legacyMarkers.present
    ? legacyMarkers.mode
    : undefined;

  const report = (): CustodyCredentialReport => ({
    found: [...found],
    rejected: [...rejected],
    indeterminate: [...indeterminate],
    details: { ...details },
    integrityIndeterminate,
    envelopePresent,
    noCustodyStateAtAll,
    custodyKeyUnverifiable,
    ...(legacyCustodyMode === undefined ? {} : { legacyCustodyMode }),
    ...(enrolledCustodyKeyItem === undefined
      ? {}
      : { enrolledCustodyKeyItem }),
  });

  // ── 1-3. Operator-supplied credentials ────────────────────────────────
  // The first PRESENT one wins outright. No fall-through: see the header.
  for (const source of OPERATOR_SUPPLIED_SOURCES) {
    if (!allow.has(source)) continue;
    const supplied =
      source === "explicit-passphrase"
        ? opts.explicitPassphrase
        : source === "env-passphrase"
          ? env.SANCTUARY_PASSPHRASE
          : env.SANCTUARY_RECOVERY_KEY;
    // THE supplied-credential predicate, shared with both boot entry points so
    // an empty value means the same thing everywhere (see the function's note).
    if (!isOperatorSuppliedCredential(supplied)) continue;
    found.push(source);
    const provenance: CustodyCredentialProvenance =
      source === "explicit-passphrase"
        ? { location: "", displaySource: "explicit-pending-authentication" }
        : source === "env-passphrase"
          ? { location: "SANCTUARY_PASSPHRASE", displaySource: "env" }
          : { location: "SANCTUARY_RECOVERY_KEY", displaySource: "env-recovery-key" };
    return {
      status: "resolved",
      credential:
        source === "env-recovery-key"
          ? { ...provenance, source, kind: "recovery-key", recoveryKey: supplied }
          : { ...provenance, source, kind: "passphrase", passphrase: supplied },
      report: report(),
    };
  }

  // ── A directory with no custody at all ────────────────────────────────
  // Nothing here has ever been locked, so no host-local factor can be the wrap
  // of it and probing for one can only produce a credential that opens
  // nothing. The verdict is about the DIRECTORY, so it is settled here, before
  // the keyring is touched: the caller either mints (and `establishMaster`
  // performs the audited first run) or, as a read-only observer, hears that
  // there is nothing to open.
  //
  // This is checked AFTER the operator-supplied sources on purpose: a
  // `SANCTUARY_PASSPHRASE` handed to a virgin fortress is the credential the
  // first run must be created with, not a mint.
  //
  // A leftover `sanctuary-custody` item survives a removed fortress directory
  // and an `init` that failed after enrolling. Returning it as resolved here
  // is what made `protect` skip `mint-required` and then refuse anyway:
  // `firstRun` will not create custody from a keychain credential
  // (`wrap/custody-flow.ts`), and `establishMaster` will not create custody
  // without one (`core/master-custody.ts`). A key is not a wrap of a fortress
  // that does not exist.
  if (noCustodyStateAtAll) {
    return opts.allowMint === true
      ? { status: "mint-required", report: report() }
      : { status: "unresolved", report: report() };
  }

  // ── 4-5. Host-local factors, verified against the envelope ────────────
  // These fall through on a mismatch, so each candidate must be PROVEN before
  // it is handed back: an unverified guess here is exactly the A73 failure
  // (a credential that does not open the fortress reaching custody
  // establishment and aborting the run).
  //
  // Custody exists by the time control reaches here, but verification still
  // needs something to verify AGAINST, and there are two reasons it can be
  // missing:
  //
  //  - A LEGACY fortress: no envelope, but a `_meta/key-params` or
  //    `_meta/recovery-key-hash` marker says it was locked before envelopes
  //    existed. There is nothing to verify against, so a candidate that COULD
  //    be this fortress's credential is taken as-is and custody establishment
  //    migrates it in place. Trying to "verify" the passphrase here would
  //    reject every candidate and route a legacy fortress into minting, which
  //    is the failure this module exists to prevent. This is the ONLY
  //    remaining no-envelope case: the virgin one returned above.
  //
  //    "Could be this fortress's credential" is per SOURCE and is not a
  //    formality. A pre-envelope master is Argon2id(passphrase, key-params),
  //    so the stored passphrase is the only host-local source a legacy
  //    fortress can ever be opened with; nothing there was derived from an
  //    OS-keyring custody factor, so a `sanctuary-custody-<id>` item on this
  //    host cannot be its credential and cannot be checked against it either.
  //    Taking that item as-is is what let a stale or planted keyring item
  //    SHADOW the valid stored passphrase: the resolver returned the item,
  //    the stored passphrase was never consulted, and establishment then
  //    refused because legacy migration needs the passphrase. Present but
  //    unverifiable is its own answer (`custodyKeyUnverifiable`): skip the
  //    item, keep going, and let the passphrase resolve.
  //
  //  - An envelope that EXISTS but cannot be read: the fortress does have a
  //    lock and this run cannot check any key against it. Returning a factor
  //    here would hand back a credential nothing authenticated —
  //    `export-passphrase` would print an unproven credential, and the install
  //    planner would call the fortress openable on the strength of it. So an
  //    unreadable envelope makes every host-local candidate INDETERMINATE,
  //    which is neither "resolved" nor "your credential is wrong".
  const canVerify = envelope !== null;
  const verifyHostLocal = async (
    credential: {
      passphrase?: string;
      keychainKey?: Uint8Array;
    },
    /**
     * What this SOURCE means on a legacy fortress, where there is no envelope
     * to check anything against. `migrates-legacy` is the stored passphrase:
     * legacy custody is passphrase-derived, so it is taken as-is and
     * establishment migrates in place. `needs-an-envelope` is the enrolled
     * custody key: no pre-envelope fortress was ever locked with one, so an
     * item that is present here is unverifiable rather than usable.
     */
    onLegacyFortress: "migrates-legacy" | "needs-an-envelope",
  ): Promise<CandidateVerdict> => {
    if (!envelopeReadable) {
      return {
        status: "indeterminate",
        detail: UNREADABLE_ENVELOPE_DETAIL,
        cause: "fortress",
      };
    }
    if (!canVerify) {
      return onLegacyFortress === "migrates-legacy"
        ? { status: "unlocks" }
        : {
            status: "indeterminate",
            detail: UNVERIFIABLE_CUSTODY_KEY_DETAIL,
            cause: "candidate",
          };
    }
    return verifyCandidate(storage, opts.storagePath, credential);
  };
  let resolved: ResolvedCustodyCredential | null = null;
  let custodyKey: Uint8Array | undefined;
  try {
    if (allow.has("enrolled-custody-key")) {
      // LOOKUP SIDE of the OS-keyring custody family. The service names this
      // reaches must match `CUSTODY_SERVICE_PREFIX` and the write identities in
      // `wrap/keychain-custody.ts` (the ENROL side `init` uses); the whole A73
      // defect was a verb looking somewhere the enrolment never wrote. Both
      // sides go through that module's own read list rather than composing a
      // name here, and `test/structure/frozen-surfaces.test.ts` pins the
      // composed names so a change to either side trips.
      const read = await readCustodyKey(opts.storagePath, {
        home,
        platformOverride: platform,
      }).catch(() => ({
        status: "unreachable" as const,
        detail: "custody-factor identity could not be determined",
        key: undefined,
      }));
      // The ONE keyring-reachability observation this process makes. Every
      // consumer (the accepted-sources listing here, the dashboard's actionable
      // unlock block) reads it from the report rather than probing again.
      enrolledCustodyKeyItem = read.status;
      if (read.status === "found" && read.key !== undefined) {
        custodyKey = read.key;
        found.push("enrolled-custody-key");
        // A keyring custody item is only ever selected on the strength of an
        // envelope wrap it opens; there is no legacy fortress it could be the
        // credential of. See `onLegacyFortress` above.
        const verdict = await verifyHostLocal(
          { keychainKey: custodyKey },
          "needs-an-envelope",
        );
        if (verdict.status === "unlocks") {
          resolved = {
            source: "enrolled-custody-key",
            kind: "keychain-key",
            keychainKey: custodyKey,
            location: ENROLLED_CUSTODY_FACTOR_LOCATION,
            displaySource: "enrolled-custody-key",
          };
          // Ownership of the buffer transfers to the caller.
          custodyKey = undefined;
        } else if (verdict.status === "mismatch") {
          rejected.push("enrolled-custody-key");
        } else {
          // Which thing could not be evaluated decides the remedy the refusal
          // prints, so the two causes are never merged: a damaged fortress is
          // restored from backup, while an item that simply is not a
          // credential of a pre-envelope fortress needs the passphrase.
          if (verdict.cause === "fortress") integrityIndeterminate = true;
          else custodyKeyUnverifiable = true;
          indeterminate.push("enrolled-custody-key");
          details["enrolled-custody-key"] ??= verdict.detail;
        }
      } else if (read.status === "unreachable") {
        found.push("enrolled-custody-key");
        indeterminate.push("enrolled-custody-key");
        details["enrolled-custody-key"] =
          read.detail ?? "the OS keyring is locked or unreachable";
      } else if (read.status === "found") {
        // Found but no bytes: a malformed item, not an answer about custody.
        found.push("enrolled-custody-key");
        indeterminate.push("enrolled-custody-key");
        details["enrolled-custody-key"] =
          "the keyring item exists but carries no readable key material";
      }
    }

    if (resolved === null && allow.has("stored-passphrase")) {
      // LOOKUP SIDE of the stored-passphrase family: must match
      // `KEYCHAIN_SERVICE_DEFAULT` and `fortressKeychainReadServices` in
      // `wrap/passphrase.ts`, pinned in `test/structure/frozen-surfaces.test.ts`.
      //
      // observeStoredPassphrase returns the RICH observation and only throws
      // on an unexpected fault, so a locked keyring or an unreadable fallback
      // arrives as data rather than as a lost distinction.
      let observed: Awaited<ReturnType<typeof observeStoredPassphrase>>;
      try {
        observed = await observePassphrase({
          storagePath: opts.storagePath,
          home,
          platformOverride: platform,
          // The resolver is a READ. Never let a resolution repair or rewrite
          // anything under the fortress directory.
          readOnly: true,
        });
      } catch (error) {
        observed = { status: "absent", keyringUnreachable: true };
        details["stored-passphrase"] =
          error instanceof Error ? error.message : "stored passphrase unreadable";
      }
      if (observed.status === "found") {
        found.push("stored-passphrase");
        // The one host-local source a pre-envelope fortress CAN be opened
        // with, so on a legacy fortress it is taken as-is and establishment
        // migrates in place. See `onLegacyFortress` above.
        const verdict = await verifyHostLocal(
          {
            passphrase: observed.result.value,
          },
          "migrates-legacy",
        );
        if (verdict.status === "unlocks") {
          resolved = {
            source: "stored-passphrase",
            kind: "passphrase",
            passphrase: observed.result.value,
            location: observed.result.location,
            displaySource: observed.result.source,
          };
        } else if (verdict.status === "mismatch") {
          rejected.push("stored-passphrase");
        } else {
          // Same cause split as the custody-key branch above. Every
          // indeterminate verdict this source can produce today is a
          // FORTRESS condition (it is taken as-is on a legacy fortress), and
          // reading the cause rather than assuming it keeps that true if the
          // passphrase ever gains a candidate-side unverifiable state.
          if (verdict.cause === "fortress") integrityIndeterminate = true;
          indeterminate.push("stored-passphrase");
          details["stored-passphrase"] ??= verdict.detail;
        }
      } else if (
        observed.status === "fallback-unreadable" ||
        observed.keyringUnreachable
      ) {
        found.push("stored-passphrase");
        indeterminate.push("stored-passphrase");
        details["stored-passphrase"] ??=
          observed.status === "fallback-unreadable"
            ? `the encrypted fallback credential is unreadable (${observed.reason})`
            : observed.keyringDetail ?? "the OS keyring is locked or unreachable";
      }
    }
  } finally {
    custodyKey?.fill(0);
  }

  if (resolved !== null) {
    return { status: "resolved", credential: resolved, report: report() };
  }

  // No candidate authenticated, and this fortress HAS custody (the no-custody
  // case returned above), so minting is not on the table: a minted credential
  // could only ever fail to open the envelope it was not part of.
  return { status: "unresolved", report: report() };
}

/**
 * The three answers about one host-local candidate. `indeterminate` is its own
 * answer and carries a non-secret reason: a rotation in flight or an
 * unreadable envelope is not evidence the credential is wrong, so it must not
 * be reported as a mismatch (which would steer an operator toward a recovery
 * ceremony they do not need). There is deliberately no "this directory has no
 * custody" verdict: that is a question about the fortress, answered before any
 * candidate is consulted.
 */
type CandidateVerdict =
  | { status: "unlocks" }
  | { status: "mismatch" }
  | {
      status: "indeterminate";
      detail: string;
      /**
       * WHICH thing could not be evaluated, carried as a typed field rather
       * than inferred from the wording of `detail`: `fortress` means the
       * custody state itself is unreadable (the report's
       * `integrityIndeterminate`, remedy = restore from backup), `candidate`
       * means the fortress is fine and this SOURCE cannot be authenticated
       * against it (remedy = a credential that can be). The refusal picks a
       * different remedy for each, so a string comparison here would be a
       * cross-file contract in prose.
       */
      cause: "fortress" | "candidate";
    };

/** Non-secret reason attached to every candidate when the envelope is unreadable. */
const UNREADABLE_ENVELOPE_DETAIL =
  "this fortress's custody envelope could not be read, so no host-local " +
  "factor can be verified against it";

/**
 * Non-secret reason attached to a keyring custody item on a pre-envelope
 * fortress: it is present, it is not this fortress's credential, and there is
 * nothing to prove that either way.
 */
const UNVERIFIABLE_CUSTODY_KEY_DETAIL =
  "this fortress has no custody envelope, so a keyring custody item cannot " +
  "be verified against it and is not used";

/** Non-secret reason attached when the fortress itself could not be evaluated. */
const UNEVALUABLE_FORTRESS_DETAIL =
  "the fortress could not be evaluated (custody state unreadable, or a " +
  "custody rotation in flight)";

/** A host-local candidate is only usable if it PROVABLY opens this fortress. */
async function verifyCandidate(
  storage: StorageBackend,
  storagePathHint: string,
  credential: { passphrase?: string; keychainKey?: Uint8Array },
): Promise<CandidateVerdict> {
  let master: Uint8Array | null = null;
  try {
    master = await unlockExistingMasterReadOnly(storage, {
      ...credential,
      storagePathHint,
    });
    return { status: "unlocks" };
  } catch (error) {
    return error instanceof CustodyUnlockError
      ? { status: "mismatch" }
      : {
          status: "indeterminate",
          detail: UNEVALUABLE_FORTRESS_DETAIL,
          cause: "fortress",
        };
  } finally {
    master?.fill(0);
  }
}

/**
 * What the pre-envelope custody markers said. `present: false` is the only
 * shape that means "this directory has never been locked"; `mode` is absent on
 * a present result only when a marker read threw, so the mode is unknown
 * rather than absent (see the report field).
 */
type LegacyCustodyMarkers =
  | { present: false }
  | { present: true; mode?: "recovery-key" | "passphrase" };

/**
 * Priority order for deciding the legacy custody mode. MUST MATCH the legacy
 * branch order in `establishMaster` (`src/core/master-custody.ts`):
 * `recovery-key-hash` outranks `key-params`.
 */
const LEGACY_CUSTODY_MARKER_PRIORITY = [
  "recovery-key-hash",
  "key-params",
] as const satisfies readonly (typeof LEGACY_CUSTODY_MARKERS)[number][];

/**
 * Read the pre-envelope (legacy) custody markers and say which mode they put
 * this fortress in.
 *
 * MUST MATCH the legacy branch ORDER in `establishMaster`
 * (`src/core/master-custody.ts`): `_meta/recovery-key-hash` outranks
 * `_meta/key-params`. A recovery-key-mode fortress can carry both markers and
 * only the recovery key opens it, so reading them in array order would tell an
 * operator to supply a passphrase that provably cannot unlock their data.
 */
async function readLegacyCustodyMarkers(
  storage: StorageBackend,
): Promise<LegacyCustodyMarkers> {
  const seen = new Set<(typeof LEGACY_CUSTODY_MARKERS)[number]>();
  const unreadable = new Set<(typeof LEGACY_CUSTODY_MARKERS)[number]>();
  for (const marker of LEGACY_CUSTODY_MARKERS) {
    try {
      if ((await storage.read("_meta", marker)) !== null) seen.add(marker);
    } catch {
      // Unreadable is not "absent": fail toward "custody may exist". The mode
      // stays unknown, which is a third answer and not a default to either.
      unreadable.add(marker);
    }
  }
  // Decide the mode in PRIORITY order, and only while every higher-priority
  // marker was readable: an unreadable `recovery-key-hash` above a readable
  // `key-params` must NOT read as passphrase mode, because the fortress may be
  // a recovery-key one whose marker simply could not be read, and the
  // passphrase remedy would then name a credential that cannot open it.
  for (const marker of LEGACY_CUSTODY_MARKER_PRIORITY) {
    if (unreadable.has(marker)) return { present: true };
    if (seen.has(marker)) {
      return {
        present: true,
        mode: marker === "recovery-key-hash" ? "recovery-key" : "passphrase",
      };
    }
  }
  return unreadable.size > 0 ? { present: true } : { present: false };
}

/**
 * Compose the refusal for a resolution that produced no credential. Names
 * every source the resolver accepts, in the order it tries them, plus which
 * ones were present and rejected — never a value, and never which wrap
 * matched (CustodyUnlockError stays generic about the crypto).
 */
export function custodyCredentialRefusal(
  report: CustodyCredentialReport,
  storagePathHint?: string,
): CustodyUnlockError {
  const accepted = ACCEPTED_CUSTODY_CREDENTIAL_SOURCES.map(
    (label) => `    - ${label}`,
  ).join("\n");
  const describe = (sources: CustodyCredentialSource[]): string =>
    sources.map(custodyCredentialSourceLabel).join(", ");
  // "could not be evaluated" and "nothing unlocks it" are different answers to
  // an operator: the first is a fortress-integrity condition to repair, the
  // second is a credential to supply. Collapsing them would send an operator
  // hunting for a credential that is not the problem.
  const lines = [
    report.integrityIndeterminate
      ? `Sanctuary: this fortress's custody state could not be evaluated${
          storagePathHint ? ` (${storagePathHint})` : ""
        }.`
      : `Sanctuary: no credential unlocks this fortress${
          storagePathHint ? ` (${storagePathHint})` : ""
        }.`,
    "  Accepted credentials, in the order they are tried:",
    accepted,
  ];
  lines.push(
    report.found.length === 0
      ? "  Present on this host: none of them."
      : `  Present on this host: ${describe(report.found)}.`,
  );
  if (report.rejected.length > 0) {
    lines.push(`  Tried and did not unlock: ${describe(report.rejected)}.`);
  }
  for (const source of report.indeterminate) {
    const detail = report.details[source];
    lines.push(
      `  Present but unusable right now: ${custodyCredentialSourceLabel(source)}` +
        `${detail ? ` (${detail})` : ""}.`,
    );
  }
  if (report.indeterminate.length > 0) {
    // The remedy follows the CAUSE. Telling an operator to unlock a keyring
    // when the envelope is the unreadable thing sends them at the wrong door,
    // and so does telling them to unlock a keyring whose item was read fine
    // and simply is not a credential of a fortress created before custody
    // envelopes. Three causes, three doors.
    const onlyTheUnverifiableCustodyKey =
      report.custodyKeyUnverifiable &&
      !report.integrityIndeterminate &&
      report.indeterminate.every((source) => source === "enrolled-custody-key");
    lines.push(
      report.integrityIndeterminate
        ? "  Restore this fortress's custody state from backup, then retry."
        : onlyTheUnverifiableCustodyKey
          ? "  The OS-keyring custody item on this host is not a credential for it: " +
            "a fortress created before custody envelopes was never locked with one."
          : "  Unlock the OS keyring and retry.",
    );
  }
  // A pre-envelope (LEGACY) fortress gets the remedy for the mode it is
  // actually in, and this block owns that remedy: the keyring-skip line above
  // explains only WHY an item was passed over, because that explanation is
  // mode-independent while the credential that opens the fortress is not.
  //
  // Composed here rather than left to `establishMaster`'s legacy branch,
  // because a legacy fortress now fails closed at the resolver and never
  // reaches that branch (see `resolveHostLocalBootCredential`). The two
  // operator-facing phrases below are the contract this replaced and MUST
  // MATCH the legacy refusals in `src/core/master-custody.ts`: "no credentials
  // provided" from `CustodyCredentialMissingError` for recovery-key mode, and
  // "passphrase required" from the passphrase-mode branch. Both are pinned by
  // `test/security/sec-020-recovery-key-restart.test.ts`; changing the wording
  // here without changing it there is the drift that test exists to catch.
  if (report.legacyCustodyMode === "recovery-key") {
    lines.push(
      "  This fortress was locked in recovery-key mode before custody envelopes " +
        "existed, and no credentials provided on this host open it. Supply " +
        "SANCTUARY_RECOVERY_KEY (the key captured at creation); custody migrates " +
        "on that unlock. A passphrase cannot open a recovery-key fortress.",
    );
  } else if (report.legacyCustodyMode === "passphrase") {
    lines.push(
      "  This fortress was locked before custody envelopes existed and uses " +
        "passphrase-mode key derivation: passphrase required. Supply it as " +
        "SANCTUARY_PASSPHRASE or --passphrase (or run " +
        "`sanctuary export-passphrase` to retrieve it from the OS keyring); " +
        "custody migrates on that unlock.",
    );
  }
  lines.push(
    "  Refusing to continue with a credential that does not verify.",
  );
  return new CustodyUnlockError(lines.join("\n"));
}

// ── Hands-free BOOT credential (H1): one helper, two boot paths ─────────

/**
 * Outcome of a hands-free boot credential resolution (H1).
 *
 * `fail-closed` carries BOTH the composed refusal and the raw report: the MCP
 * stdio boot prints the composed message as-is, while the standalone dashboard
 * folds the accepted-sources listing into its own actionable diagnostic
 * (enrolled factors, keyring reachability, tenant discovery). Handing back only
 * a string would force the dashboard to re-derive the listing and the two
 * refusals would drift.
 */
export type HostLocalBootCredential =
  | {
      kind: "passphrase";
      value: string;
      provenance: CustodyCredentialProvenance;
    }
  | {
      kind: "keychain-key";
      key: Uint8Array;
      provenance: CustodyCredentialProvenance;
    }
  /** No custody state at all: the caller's audited first run may create it. */
  | { kind: "virgin" }
  | {
      kind: "fail-closed";
      message: string;
      report: CustodyCredentialReport;
    };

export interface HostLocalBootCredentialOptions {
  storage: StorageBackend;
  /** Fortress root (the directory holding `state/`). */
  storagePath: string;
  /**
   * Test seam: the exact-fortress stored-passphrase read. Defaults to the real
   * {@link readStoredPassphrase}; the observation is built from it by
   * {@link observeStoredPassphraseVia} either way, so both boot paths see the
   * SAME collapsing of a locked keyring and an unreadable fallback file.
   */
  readStored?: typeof readStoredPassphrase;
  /** Test seam: the enrolled-custody-factor read (keychain chokepoint). */
  readCustodyKey?: typeof readKeychainCustodyKeyStatus;
}

/**
 * Resolve the exact-fortress credential for a hands-free BOOT (H1), READ-ONLY,
 * through THE shared resolver above restricted to
 * {@link HOST_LOCAL_CUSTODY_SOURCES}.
 *
 * A73: each boot path used to run its own chain — the stored passphrase first,
 * with no check that it opens THIS fortress and no fall-through on a mismatch,
 * then (or never) the custody factor. That is a different order from the one
 * `protect` uses, so a leftover `sanctuary-passphrase-<id>` item from an
 * earlier failed mint made `protect` succeed and the process it launched fail
 * closed. Routing every boot through one resolver makes them agree by
 * construction: every host-local candidate is verified against this fortress's
 * envelope before it is returned, and a candidate that does not open it is
 * skipped rather than handed to `establishMaster` to discover.
 *
 * The restriction to host-local sources is what makes this hands-free: the
 * operator-supplied credentials (`--passphrase`, `SANCTUARY_PASSPHRASE`,
 * `SANCTUARY_RECOVERY_KEY`) are handled by the CALLER before this runs — they
 * outrank everything and must not be re-read here. Nothing here mints,
 * generates, or writes: the ABSENCE OF ALL CUSTODY STATE (no envelope and no
 * pre-envelope marker) is what separates a virgin fortress (fall through to
 * the audited first run) from an existing one — envelope-format or legacy —
 * that must fail closed when nothing opens it.
 *
 * MUST MATCH the two call sites that consume it: `createSanctuaryServer`
 * (`src/index.ts`) and `startStandaloneDashboard` (`src/dashboard-standalone.ts`).
 * `protect --claude-code --agent-guided` spawns the second one, so a boot path
 * that resolves differently from `protect` breaks the install contract's own
 * next action.
 */
export async function resolveHostLocalBootCredential(
  args: HostLocalBootCredentialOptions,
): Promise<HostLocalBootCredential> {
  const resolution = await resolveFortressCustodyCredential({
    storagePath: args.storagePath,
    storage: args.storage,
    allow: HOST_LOCAL_CUSTODY_SOURCES,
    // A boot never creates custody through the resolver. The caller's audited
    // first run is the only mint, and it is reached only when this fortress
    // has no envelope and no legacy marker at all.
    allowMint: false,
    ...(args.readCustodyKey === undefined
      ? {}
      : { readCustodyKey: args.readCustodyKey }),
    // UNCONDITIONAL, not "only when a seam was injected": the two observers
    // disagree. `observeStoredPassphrase` reports a locked keyring plus a
    // damaged fallback file as `fallback-unreadable` (naming the file), while
    // the `readStoredPassphrase` adapter collapses it to
    // `absent + keyringUnreachable` (naming the keyring). Picking the observer
    // by whether a TEST seam was passed made the MCP boot print one
    // stored-passphrase line and the dashboard print the other for the same
    // host state. Both boots take this branch, so both print the same line.
    observePassphrase: (opts) =>
      observeStoredPassphraseVia(args.readStored ?? readStoredPassphrase, opts),
  });

  if (resolution.status === "resolved") {
    const credential = resolution.credential;
    const provenance: CustodyCredentialProvenance = {
      location: credential.location,
      displaySource: credential.displaySource,
    };
    switch (credential.kind) {
      case "keychain-key":
        return { kind: "keychain-key", key: credential.keychainKey, provenance };
      case "passphrase":
        return { kind: "passphrase", value: credential.passphrase, provenance };
      case "recovery-key":
        // A recovery key is an operator-supplied source and is excluded by the
        // allow list above, so reaching this means the resolver returned a
        // source it was not permitted to consult. Fail closed rather than boot
        // on an unexpected credential class (MUST-NEVER 5).
        return {
          kind: "fail-closed",
          message:
            `Refusing to start: the hands-free boot credential resolution for ` +
            `${args.storagePath} returned a credential class this path does not accept.`,
          report: resolution.report,
        };
    }
  }

  // INVARIANT: `virgin` means this directory has never been locked with
  // ANYTHING, so envelope presence is not the discriminator here. A legacy
  // marker (`_meta/key-params`, `_meta/recovery-key-hash`) IS custody state:
  // that fortress has a master already and no envelope, and mapping it to
  // `virgin` sends both boots into `establishMaster`'s first run, which then
  // refuses one layer down with a generic "passphrase required" the resolver's
  // own remedy never reaches. An editor who later reads `kind === "virgin"` as
  // "no custody, safe to mint" would mint a parallel master over live
  // pre-envelope data. The resolver already computes the fact this must turn
  // on; read it rather than re-deriving it from the envelope.
  if (resolution.report.noCustodyStateAtAll) return { kind: "virgin" };

  // Any custody state at all (an envelope, or a legacy marker) plus no
  // resolved credential is an existing fortress that cannot be opened
  // hands-free. The refusal names the credential SOURCES the resolver accepts,
  // which of them were present, rejected or unverifiable on this host, and the
  // remedy for THIS state; it never carries a value.
  return {
    kind: "fail-closed",
    message: custodyCredentialRefusal(resolution.report, args.storagePath)
      .message,
    report: resolution.report,
  };
}
