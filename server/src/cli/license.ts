/**
 * `sanctuary license`  -  the Erik-operated fleet license issuance CLI (PR-1).
 *
 * Verbs:
 *  - `issue`   -  unlock custody, resolve the DEFAULT operator identity as the
 *               issuer, sign a v2 license token, append a ledger row, and PRINT
 *               the license token (base64url of `{claims,signature}`) the
 *               operator pastes into the future Activate screen.
 *  - `list`    -  read-only table of every issued license (no custody unlock).
 *  - `revoke`  -  mark a license revoked in the local ledger (re-signs the row's
 *               revocation status; needs custody unlock to sign).
 *
 * This is the SELL side of the entitlement scaffold: it produces enforceable
 * signed licenses and records them tamper-evidently. It does NOT wire
 * enforcement (PR-2), a payment processor, self-serve, or the distributed
 * revocation-push rail (PR-3)  -  `revoke` here is LOCAL ledger bookkeeping only.
 *
 * Keychain safety (mirrors federation-operator-signing): custody unlocks via
 * `resolveCliMasterKey` (passphrase / recovery-key via env or flag), the
 * no-modal headless path  -  a headless session with only a keychain credential
 * gets an actionable fail-closed error, never a macOS keychain modal and never
 * a silent downgrade. NEVER #6: the issuer private key is decrypted transiently
 * inside `sign()` (which zeroes it in a `finally`); nothing here logs, prints,
 * or returns private-key material.
 *
 * Fail-closed (non-zero exit, no secret in output) on: no fortress unlockable,
 * no DEFAULT operator identity, invalid flags, unknown tier, expiry in the
 * past, negative node count, unknown licenseId on revoke.
 */

import type { Writable } from "node:stream";
import { toBase64url } from "../core/encoding.js";
import { randomBytes } from "../core/random.js";
import { isEntitlementTier } from "../entitlement/tier.js";
import {
  type EntitlementClaimsV2,
  type EntitlementToken,
} from "../entitlement/token.js";
import {
  appendRow,
  issueLicense,
  listLicenses,
  revokeLicense,
  type LicenseListEntry,
} from "../entitlement/ledger.js";
import {
  loadLedger,
  resolveLedgerPath,
  saveLedger,
  withLedgerMutationLock,
} from "../entitlement/ledger-io.js";
import {
  checkLedgerFreshness,
  readLedgerGenerationAnchor,
  writeLedgerGenerationAnchor,
} from "../entitlement/ledger-antirollback.js";
import { openIssuer, openVerifier } from "./custody-unlock.js";
import { flagValue } from "./argv.js";

/** Default feature set for the standard Team offering (sold set, not tier-implied). */
const DEFAULT_TEAM_FEATURES = ["roster", "policy-dist"] as const;
const KNOWN_FEATURES = new Set(["roster", "policy-dist", "kill-safety", "console"]);
const DEFAULT_GRACE_DAYS = 14;
const SECONDS_PER_DAY = 86_400;

function write(stream: Writable, text: string): void {
  stream.write(text);
}

function hasFlag(argv: string[], name: string): boolean {
  return argv.includes(name);
}

/** Parse an ISO-8601 or Unix-seconds string to Unix seconds, or null if invalid. */
function parseTime(value: string): number | null {
  // Pure integer -> treat as Unix seconds.
  if (/^\d+$/.test(value)) {
    const n = Number(value);
    return Number.isFinite(n) ? n : null;
  }
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) return null;
  return Math.floor(ms / 1000);
}

/** A fresh 128-bit base64url license id. */
function generateLicenseId(): string {
  return toBase64url(randomBytes(16));
}

interface IssueFlags {
  tier?: string;
  subject?: string;
  nodes?: string;
  period?: string;
  expires?: string;
  graceDays?: string;
  features?: string;
  pricingUnit?: string;
  passphrase?: string;
  recoveryKey?: string;
  fortressPath?: string;
}

function parseIssueFlags(argv: string[], env: NodeJS.ProcessEnv): IssueFlags {
  return {
    tier: flagValue(argv, "--tier"),
    subject: flagValue(argv, "--subject"),
    nodes: flagValue(argv, "--nodes"),
    period: flagValue(argv, "--period"),
    expires: flagValue(argv, "--expires"),
    graceDays: flagValue(argv, "--grace-days"),
    features: flagValue(argv, "--features"),
    pricingUnit: flagValue(argv, "--pricing-unit"),
    passphrase: flagValue(argv, "--passphrase") ?? env.SANCTUARY_PASSPHRASE,
    recoveryKey: env.SANCTUARY_RECOVERY_KEY,
    fortressPath: flagValue(argv, "--fortress"),
  };
}

async function runIssue(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv,
): Promise<number> {
  const flags = parseIssueFlags(argv, env);

  // Validate flags BEFORE any custody unlock (cheap, no crypto, no secret).
  if (!flags.tier || !isEntitlementTier(flags.tier) || flags.tier === "community") {
    write(err, "issue: --tier must be one of team | fleet | enterprise\n");
    return 1;
  }
  // Capture the validated, narrowed values so the mutation closure below (which
  // TS does not flow-narrow into) uses typed locals, not `!` assertions.
  const tier: EntitlementClaimsV2["tier"] = flags.tier;
  if (!flags.subject || flags.subject.length === 0) {
    write(err, "issue: --subject <id> is required\n");
    return 1;
  }
  const subject = flags.subject;
  if (!flags.nodes) {
    write(err, "issue: --nodes <N|unlimited> is required\n");
    return 1;
  }
  let entitledCount: number | null;
  if (flags.nodes === "unlimited") {
    entitledCount = null;
  } else {
    const n = Number(flags.nodes);
    if (!Number.isInteger(n) || n < 0) {
      write(err, "issue: --nodes must be a non-negative integer or 'unlimited'\n");
      return 1;
    }
    entitledCount = n;
  }
  const period = flags.period ?? "monthly";
  if (period !== "monthly" && period !== "annual") {
    write(err, "issue: --period must be monthly | annual\n");
    return 1;
  }
  const pricingUnit = flags.pricingUnit ?? "node";
  if (pricingUnit !== "node" && pricingUnit !== "seat" && pricingUnit !== "fleet") {
    write(err, "issue: --pricing-unit must be node | seat | fleet\n");
    return 1;
  }
  if (!flags.expires) {
    write(err, "issue: --expires <ISO8601-or-unix> is required\n");
    return 1;
  }
  const notAfter = parseTime(flags.expires);
  if (notAfter === null) {
    write(err, "issue: --expires is not a valid ISO-8601 date or Unix timestamp\n");
    return 1;
  }
  const nowMs = Date.now();
  const notBefore = Math.floor(nowMs / 1000);
  if (notAfter <= notBefore) {
    write(err, "issue: --expires is in the past\n");
    return 1;
  }
  const graceDays =
    flags.graceDays !== undefined ? Number(flags.graceDays) : DEFAULT_GRACE_DAYS;
  if (!Number.isFinite(graceDays) || graceDays < 0) {
    write(err, "issue: --grace-days must be a non-negative number\n");
    return 1;
  }
  const graceUntil =
    graceDays === 0 ? null : notAfter + Math.floor(graceDays) * SECONDS_PER_DAY;

  // Feature set: explicit --features, else the standard Team default set.
  const featureList = flags.features
    ? flags.features.split(",").map((s) => s.trim()).filter((s) => s.length > 0)
    : [...DEFAULT_TEAM_FEATURES];
  for (const f of featureList) {
    if (!KNOWN_FEATURES.has(f)) {
      write(
        err,
        `issue: unknown feature '${f}' (known: roster, policy-dist, kill-safety, console)\n`,
      );
      return 1;
    }
  }

  let issuer: Awaited<ReturnType<typeof openIssuer>>;
  try {
    issuer = await openIssuer({
      ...(flags.passphrase !== undefined ? { passphrase: flags.passphrase } : {}),
      ...(flags.recoveryKey !== undefined ? { recoveryKey: flags.recoveryKey } : {}),
      ...(flags.fortressPath !== undefined ? { fortressPath: flags.fortressPath } : {}),
      operationLabel: "license issuance",
    });
  } catch (e) {
    write(err, `issue: ${(e as Error).message}\n`);
    return 1;
  }

  try {
    const ledgerPath = await resolveLedgerPath();
    // Serialize the WHOLE load -> verify+freshness -> mutate -> save -> advance
    // anchor sequence under the advisory lock so two concurrent `issue`/`revoke`
    // cannot lost-update the ledger or race the anchor (spec §5).
    const encoded = await withLedgerMutationLock(ledgerPath, async () => {
      const ledger = await loadLedger(ledgerPath);
      // Verify integrity AND freshness BEFORE appending: never extend a tampered
      // OR rolled-back ledger (fail-closed, spec §6). checkLedgerFreshness pins
      // the fortress issuer key (NOT the ledger file) and compares the ledger
      // generation against the external master-MAC'd anchor.
      const fresh = await checkLedgerFreshness(
        ledger,
        issuer.issuerPublicKey,
        issuer.storage,
        issuer.masterKey,
      );
      if (!fresh.ok) {
        throw new LedgerFailClosed(
          `existing license ledger failed its integrity/freshness check (${fresh.reason}); refusing to append`,
        );
      }

      // Freshness coordinate: bump strictly above BOTH the on-disk ledger
      // generation and the external anchor, so a rolled-back on-disk ledger
      // cannot re-issue at a stale generation the anchor already passed.
      //
      // HONEST RESIDUAL - the one-mutation self-healing lag (issuer-local, NOT a
      // token bypass): the durable blob write below lands BEFORE the anchor bump.
      // If the process crashes AFTER the durable blob (gen N+1) but BEFORE the
      // anchor advances, the anchor lags at N. The ledger (N+1 >= N) still
      // verifies (benign lag under the `>=` freshness rule), but that LAST
      // mutation is not yet rollback-protected until the NEXT mutation, whose
      // `max(ledgerGen, anchorGen) + 1` self-heals the anchor to N+2, after
      // which replaying the N or N+1 snapshot reads as tampered. This is the
      // inherent one-mutation bound of an on-disk monotonic anchor (the same
      // class `core/anti-rollback.ts` documents as its Stage-1 residual). It is
      // issuer-local bookkeeping and does NOT forge a customer token: the token
      // layer gates enforcement and verifies against the real issuer key.
      const anchor = await readLedgerGenerationAnchor(
        issuer.storage,
        issuer.masterKey,
      );
      const anchorGen = anchor.status === "valid" ? anchor.data.generation : 0;
      const nextGeneration = Math.max(ledger.generation ?? 0, anchorGen) + 1;

      const { token, row } = issueLicense(
        {
          licenseId: generateLicenseId(),
          subject,
          tier,
          pricingUnit,
          entitledCount,
          period,
          notBefore,
          notAfter,
          graceUntil,
          featureFlags: featureList,
          issuer: issuer.issuerId,
        },
        issuer.sign,
        notBefore,
      );
      const nextLedger = appendRow(
        ledger,
        row,
        issuer.sign,
        issuer.issuerPublicKey,
        nextGeneration,
      );
      // WRITE ORDERING (spec §4, the F1 failure class): persist the BLOB (durable
      // rename) FIRST, THEN advance the anchor. A crash between leaves
      // ledger.generation >= anchor.generation -> verify uses `>=` -> benign lag,
      // never a false-brick. The dangerous order (anchor first) would leave
      // ledger.generation < anchor.generation on a crash and false-brick.
      await saveLedger(ledgerPath, nextLedger);
      await writeLedgerGenerationAnchor(
        issuer.storage,
        issuer.masterKey,
        nextGeneration,
      );

      // The license token the operator pastes into Activate: base64url of the
      // JSON {claims,signature}. NEVER any secret-key material.
      return toBase64url(new TextEncoder().encode(JSON.stringify(token)));
    });

    write(out, `${encoded}\n`);
    return 0;
  } catch (e) {
    write(err, `issue: ${(e as Error).message}\n`);
    return 1;
  } finally {
    issuer.masterKey.fill(0);
  }
}

/**
 * A fail-closed ledger condition surfaced as a clean operator message (the CLI
 * maps it to a non-zero exit). Thrown from inside the mutation lock so the lock
 * is released in its `finally` before the message is printed.
 */
class LedgerFailClosed extends Error {}

function formatShortId(id: string): string {
  return id.length > 12 ? `${id.slice(0, 12)}…` : id;
}

function formatTime(unix: number): string {
  try {
    return new Date(unix * 1000).toISOString();
  } catch {
    return String(unix);
  }
}

/**
 * The banner+note printed for UNVERIFIED (no-custody) list output, so an
 * unverified glance can never be mistaken for a verified/valid claim.
 */
const UNVERIFIED_NOTE =
  "UNVERIFIED: this is a raw read of the ledger file WITHOUT integrity or " +
  "freshness checking. It may be tampered, rolled back, or wholesale forged. " +
  "To VERIFY, pass --passphrase / SANCTUARY_PASSPHRASE (or SANCTUARY_RECOVERY_KEY) " +
  "so `list` pins the trusted issuer key from your fortress and checks the " +
  "anti-rollback anchor.";

async function runList(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv,
): Promise<number> {
  const fortress = flagValue(argv, "--fortress");
  const asJson = hasFlag(argv, "--json");
  const passphrase = flagValue(argv, "--passphrase") ?? env.SANCTUARY_PASSPHRASE;
  const recoveryKey = env.SANCTUARY_RECOVERY_KEY;
  const verified = Boolean(passphrase) || Boolean(recoveryKey);

  // ── VERIFIED mode: custody unlocked → pin the issuer key from the fortress
  // (NOT the ledger file) and run integrity + freshness. A whole-ledger
  // substitution under an attacker keypair fails (pinned key ≠ attacker key);
  // an old/empty snapshot fails the external generation anchor. This closes the
  // `list` self-cert residual: the trust root is the operator's own key, not a
  // claim inside the file being verified.
  if (verified) {
    let verifier: Awaited<ReturnType<typeof openVerifier>>;
    try {
      verifier = await openVerifier({
        ...(passphrase !== undefined ? { passphrase } : {}),
        ...(recoveryKey !== undefined ? { recoveryKey } : {}),
        ...(fortress !== undefined ? { fortressPath: fortress } : {}),
        operationLabel: "license issuance",
      });
    } catch (e) {
      write(err, `list: ${(e as Error).message}\n`);
      return 1;
    }
    try {
      const ledgerPath = await resolveLedgerPath();
      const ledger = await loadLedger(ledgerPath);
      // Freshness (integrity + external anti-rollback anchor). An empty ledger
      // passes integrity but its generation is 0, so an empty substitution is
      // caught here when the anchor is non-zero.
      const fresh = await checkLedgerFreshness(
        ledger,
        verifier.issuerPublicKey,
        verifier.storage,
        verifier.masterKey,
      );
      if (!fresh.ok) {
        write(
          err,
          "WARNING: license ledger FAILED its integrity/freshness check " +
            `(${fresh.reason}` +
            (fresh.rowIndex !== undefined ? ` at row ${fresh.rowIndex}` : "") +
            "). This ledger has been TAMPERED with or ROLLED BACK and is NOT " +
            "trustworthy; refusing to display it as valid.\n",
        );
        return 1;
      }
      return emitList(listLicenses(ledger), asJson, out, /*unverified*/ false, err);
    } catch (e) {
      write(err, `list: ${(e as Error).message}\n`);
      return 1;
    } finally {
      verifier.masterKey.fill(0);
    }
  }

  // ── UNVERIFIED mode: no custody unlock. `list` stays usable for a quick read,
  // but it MUST NOT claim the ledger is valid/verified. Print the entries
  // clearly labeled UNVERIFIED with the how-to-verify note. Exit 0 (it is a
  // read), but never emit a green/verified claim. This removes the old FALSE
  // "valid" (the self-cert finding) without forcing a custody unlock for a
  // glance.
  if (fortress) process.env.SANCTUARY_STORAGE_PATH = fortress;
  try {
    const ledgerPath = await resolveLedgerPath();
    const ledger = await loadLedger(ledgerPath);
    return emitList(listLicenses(ledger), asJson, out, /*unverified*/ true, err);
  } catch (e) {
    write(err, `list: ${(e as Error).message}\n`);
    return 1;
  }
}

/**
 * Emit a license listing. In UNVERIFIED mode a loud note is written to stderr
 * (JSON) or interleaved into the table header (text) so no reader can mistake an
 * unchecked read for a verified one. Zero rows prints the same empty message in
 * both modes. Returns exit 0.
 */
function emitList(
  entries: LicenseListEntry[],
  asJson: boolean,
  out: Writable,
  unverified: boolean,
  err: Writable,
): number {
  if (asJson) {
    if (unverified) write(err, `${UNVERIFIED_NOTE}\n`);
    // Machine-readable output carries an explicit verification status so a
    // consumer parsing JSON cannot treat unverified rows as trusted.
    write(
      out,
      JSON.stringify(
        { verified: !unverified, entries },
        null,
        2,
      ) + "\n",
    );
    return 0;
  }
  if (entries.length === 0) {
    // Same as today: an empty ledger is not a tamper signal by itself.
    if (unverified) write(err, `${UNVERIFIED_NOTE}\n`);
    write(out, "No licenses issued yet.\n");
    return 0;
  }
  if (unverified) {
    write(out, "*** UNVERIFIED READ (no --passphrase): see the note below ***\n");
  }
  write(
    out,
    "LICENSE       SUBJECT              TIER        NODES      PERIOD   EXPIRES                   GRACE   REVOKED\n",
  );
  for (const e of entries) {
    write(out, formatListRow(e) + "\n");
  }
  if (unverified) write(out, `\n${UNVERIFIED_NOTE}\n`);
  return 0;
}

function formatListRow(e: LicenseListEntry): string {
  const nodes = e.entitledCount === null ? "unlimited" : String(e.entitledCount);
  const grace = e.graceUntil === null ? "-" : formatTime(e.graceUntil).slice(0, 10);
  const revoked = e.revoked ? `yes(${formatTime(e.revokedAt ?? 0).slice(0, 10)})` : "no";
  return [
    formatShortId(e.licenseId).padEnd(13),
    e.subject.slice(0, 20).padEnd(20),
    e.tier.padEnd(11),
    nodes.padEnd(10),
    e.period.padEnd(8),
    formatTime(e.notAfter).padEnd(25),
    grace.padEnd(7),
    revoked,
  ].join(" ");
}

async function runRevoke(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv,
): Promise<number> {
  const licenseId = argv.find((a) => !a.startsWith("--"));
  if (!licenseId) {
    write(err, "revoke: a <licenseId> argument is required\n");
    return 1;
  }
  const reason = flagValue(argv, "--reason") ?? null;
  const passphrase = flagValue(argv, "--passphrase") ?? env.SANCTUARY_PASSPHRASE;
  const recoveryKey = env.SANCTUARY_RECOVERY_KEY;
  const fortressPath = flagValue(argv, "--fortress");

  let issuer: Awaited<ReturnType<typeof openIssuer>>;
  try {
    issuer = await openIssuer({
      ...(passphrase !== undefined ? { passphrase } : {}),
      ...(recoveryKey !== undefined ? { recoveryKey } : {}),
      ...(fortressPath !== undefined ? { fortressPath } : {}),
      operationLabel: "license issuance",
    });
  } catch (e) {
    write(err, `revoke: ${(e as Error).message}\n`);
    return 1;
  }

  try {
    const ledgerPath = await resolveLedgerPath();
    // Serialize the whole sequence under the advisory lock (spec §5).
    await withLedgerMutationLock(ledgerPath, async () => {
      const ledger = await loadLedger(ledgerPath);
      // Verify integrity AND freshness before mutating: never modify a tampered
      // OR rolled-back ledger (fail-closed, spec §6). Pins the fortress issuer
      // key + the external anti-rollback anchor.
      const fresh = await checkLedgerFreshness(
        ledger,
        issuer.issuerPublicKey,
        issuer.storage,
        issuer.masterKey,
      );
      if (!fresh.ok) {
        throw new LedgerFailClosed(
          `license ledger failed its integrity/freshness check (${fresh.reason}); refusing to modify`,
        );
      }

      // Self-healing anchor: `max(ledgerGen, anchorGen) + 1` heals a
      // one-mutation crash lag (durable blob at N+1, anchor still at N) up to
      // N+2 on this next mutation. See the fuller HONEST RESIDUAL note on the
      // `issue` path above: the last pre-crash mutation is benign-lagged, not
      // rollback-protected, until the next mutation self-heals; issuer-local,
      // NOT a customer-token bypass.
      const anchor = await readLedgerGenerationAnchor(
        issuer.storage,
        issuer.masterKey,
      );
      const anchorGen = anchor.status === "valid" ? anchor.data.generation : 0;
      const nextGeneration = Math.max(ledger.generation ?? 0, anchorGen) + 1;

      const next = revokeLicense(
        ledger,
        licenseId,
        Math.floor(Date.now() / 1000),
        reason,
        issuer.sign,
        issuer.issuerPublicKey,
        nextGeneration,
      );
      // WRITE ORDERING (spec §4): durable blob FIRST, then advance the anchor.
      await saveLedger(ledgerPath, next);
      await writeLedgerGenerationAnchor(
        issuer.storage,
        issuer.masterKey,
        nextGeneration,
      );
    });
    write(out, `Revoked license ${formatShortId(licenseId)}.\n`);
    return 0;
  } catch (e) {
    write(err, `revoke: ${(e as Error).message}\n`);
    return 1;
  } finally {
    issuer.masterKey.fill(0);
  }
}

const USAGE = `sanctuary license  -  fleet license issuance (Erik-operated)

Usage:
  sanctuary license issue --tier <team|fleet|enterprise> --subject <id> \\
      --nodes <N|unlimited> --period <monthly|annual> --expires <ISO8601-or-unix> \\
      [--grace-days 14] [--features roster,policy-dist,kill-safety,console] \\
      [--pricing-unit node|seat|fleet]
  sanctuary license list [--json]
  sanctuary license revoke <licenseId> [--reason <text>]

Custody: set SANCTUARY_PASSPHRASE or --passphrase (or SANCTUARY_RECOVERY_KEY).
issue/revoke sign with the DEFAULT operator identity; list is read-only.
`;

/**
 * Entry point for `sanctuary license`. Returns a process exit code (0 success,
 * non-zero on any fail-closed condition). Never throws to the caller.
 */
export async function runLicenseCommand(args: {
  argv: string[];
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
}): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;
  const [verb, ...rest] = args.argv;

  switch (verb) {
    case "issue":
      return runIssue(rest, out, err, env);
    case "list":
      return runList(rest, out, err, env);
    case "revoke":
      return runRevoke(rest, out, err, env);
    case undefined:
    case "help":
    case "--help":
    case "-h":
      write(out, USAGE);
      return verb === undefined ? 1 : 0;
    default:
      write(err, `license: unknown verb '${verb}'\n\n${USAGE}`);
      return 1;
  }
}

// Re-export the token type so a consumer that imports the CLI surface can
// narrow the printed license without reaching into entitlement internals.
export type { EntitlementClaimsV2, EntitlementToken };
