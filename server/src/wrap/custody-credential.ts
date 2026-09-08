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
import { observeStoredPassphrase } from "./passphrase.js";

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
  const noCustodyStateAtAll =
    !envelopePresent && (await noLegacyCustodyMarkers(storage));

  const report = (): CustodyCredentialReport => ({
    found: [...found],
    rejected: [...rejected],
    indeterminate: [...indeterminate],
    details: { ...details },
    integrityIndeterminate,
    envelopePresent,
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
    if (supplied === undefined || supplied.length === 0) continue;
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
  //    existed. There is nothing to verify against, so the first present
  //    candidate is taken as-is and custody establishment migrates it in
  //    place. Trying to "verify" here would reject every candidate and route a
  //    legacy fortress into minting, which is the failure this module exists
  //    to prevent. This is the ONLY remaining no-envelope case: the virgin one
  //    returned above.
  //
  //  - An envelope that EXISTS but cannot be read: the fortress does have a
  //    lock and this run cannot check any key against it. Returning a factor
  //    here would hand back a credential nothing authenticated —
  //    `export-passphrase` would print an unproven credential, and the install
  //    planner would call the fortress openable on the strength of it. So an
  //    unreadable envelope makes every host-local candidate INDETERMINATE,
  //    which is neither "resolved" nor "your credential is wrong".
  const canVerify = envelope !== null;
  const verifyHostLocal = async (credential: {
    passphrase?: string;
    keychainKey?: Uint8Array;
  }): Promise<CandidateVerdict> => {
    if (!envelopeReadable) {
      return { status: "indeterminate", detail: UNREADABLE_ENVELOPE_DETAIL };
    }
    if (!canVerify) return { status: "unlocks" };
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
      if (read.status === "found" && read.key !== undefined) {
        custodyKey = read.key;
        found.push("enrolled-custody-key");
        const verdict = await verifyHostLocal({ keychainKey: custodyKey });
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
          integrityIndeterminate = true;
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
        const verdict = await verifyHostLocal({
          passphrase: observed.result.value,
        });
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
          integrityIndeterminate = true;
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
  | { status: "indeterminate"; detail: string };

/** Non-secret reason attached to every candidate when the envelope is unreadable. */
const UNREADABLE_ENVELOPE_DETAIL =
  "this fortress's custody envelope could not be read, so no host-local " +
  "factor can be verified against it";

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
      : { status: "indeterminate", detail: UNEVALUABLE_FORTRESS_DETAIL };
  } finally {
    master?.fill(0);
  }
}

/** True when the fortress carries no pre-envelope custody marker either. */
async function noLegacyCustodyMarkers(storage: StorageBackend): Promise<boolean> {
  for (const marker of LEGACY_CUSTODY_MARKERS) {
    try {
      if ((await storage.read("_meta", marker)) !== null) return false;
    } catch {
      // Unreadable is not "absent": fail toward "custody may exist".
      return false;
    }
  }
  return true;
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
    // when the envelope is the unreadable thing sends them at the wrong door.
    lines.push(
      report.integrityIndeterminate
        ? "  Restore this fortress's custody state from backup, then retry."
        : "  Unlock the OS keyring and retry.",
    );
  }
  lines.push(
    "  Refusing to continue with a credential that does not verify.",
  );
  return new CustodyUnlockError(lines.join("\n"));
}
