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
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { FilesystemStorage } from "../storage/filesystem.js";
import { IdentityManager } from "../cognitive/tools.js";
import { resolveCliMasterKey } from "../core/master-custody.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { sign } from "../core/identity.js";
import { toBase64url } from "../core/encoding.js";
import { randomBytes } from "../core/random.js";
import { loadConfig } from "../config.js";
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
  verifyLedgerIntegrity,
  type IssuerSigner,
  type LicenseListEntry,
} from "../entitlement/ledger.js";
import {
  loadLedger,
  resolveLedgerPath,
  saveLedger,
} from "../entitlement/ledger-io.js";

/** Default feature set for the standard Team offering (sold set, not tier-implied). */
const DEFAULT_TEAM_FEATURES = ["roster", "policy-dist"] as const;
const KNOWN_FEATURES = new Set(["roster", "policy-dist", "kill-safety", "console"]);
const DEFAULT_GRACE_DAYS = 14;
const SECONDS_PER_DAY = 86_400;

function write(stream: Writable, text: string): void {
  stream.write(text);
}

function flagValue(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(name);
  return i >= 0 && i + 1 < argv.length ? argv[i + 1] : undefined;
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

/**
 * Open the fortress headless (keychain-safe), resolve the DEFAULT operator
 * identity as the ISSUER, and return an {@link IssuerSigner} bound to it plus
 * the issuer id (the public-key fingerprint verifiers pin). Fail-closed: throws
 * when custody cannot be unlocked or no default operator identity exists. The
 * caller owns zeroing `masterKey`.
 */
async function openIssuer(opts: {
  passphrase?: string;
  recoveryKey?: string;
  fortressPath?: string;
}): Promise<{
  sign: IssuerSigner;
  issuerId: string;
  issuerPublicKey: Uint8Array;
  masterKey: Uint8Array;
}> {
  if (!opts.passphrase && !opts.recoveryKey) {
    throw new Error(
      "an unlocked operator identity is required: set SANCTUARY_PASSPHRASE, " +
        "--passphrase, or SANCTUARY_RECOVERY_KEY (this verb never prompts the " +
        "macOS keychain in a headless session)",
    );
  }
  if (opts.fortressPath) {
    process.env.SANCTUARY_STORAGE_PATH = opts.fortressPath;
  }
  const config = await loadConfig();
  await mkdir(config.storage_path, { recursive: true, mode: 0o700 });
  const stateStoragePath = join(config.storage_path, "state");
  const storage = new FilesystemStorage(stateStoragePath);

  const masterKey = await resolveCliMasterKey(storage, {
    ...(opts.passphrase !== undefined ? { passphrase: opts.passphrase } : {}),
    ...(opts.recoveryKey !== undefined ? { recoveryKey: opts.recoveryKey } : {}),
    storagePathHint: config.storage_path,
  });

  const identityManager = new IdentityManager(storage, masterKey);
  const loadResult = await identityManager.load();
  if (loadResult.loaded === 0) {
    masterKey.fill(0);
    throw new Error(
      loadResult.total > 0
        ? "operator identity files found but none could be decrypted (wrong passphrase?)"
        : "no operator identity in this fortress: license issuance requires a " +
          "default operator identity (run `sanctuary identity create`, or " +
          "re-run `sanctuary init` without --no-identity)",
    );
  }
  const identity = identityManager.getDefault();
  if (!identity?.encrypted_private_key || !identity.public_key) {
    masterKey.fill(0);
    throw new Error("no default operator identity is set in this fortress");
  }

  const identityEncryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const encryptedPrivateKey = identity.encrypted_private_key;
  const issuerPublicKey = decodePublicKey(identity.public_key);
  if (issuerPublicKey === null) {
    masterKey.fill(0);
    throw new Error("default operator identity public key is malformed");
  }

  const signer: IssuerSigner = (message: Uint8Array): Uint8Array =>
    // core/identity.sign decrypts the private key transiently and zeroes it in
    // a finally (NEVER #6). We return the raw 64-byte signature; the caller
    // base64url-encodes it. No key material is exposed here.
    sign(message, encryptedPrivateKey, identityEncryptionKey);

  return {
    sign: signer,
    issuerId: identity.identity_id,
    issuerPublicKey,
    masterKey,
  };
}

function decodePublicKey(b64: string): Uint8Array | null {
  try {
    const key = Buffer.from(
      b64.replace(/-/g, "+").replace(/_/g, "/"),
      "base64",
    );
    return key.length === 32 ? new Uint8Array(key) : null;
  } catch {
    return null;
  }
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
  if (!flags.subject || flags.subject.length === 0) {
    write(err, "issue: --subject <id> is required\n");
    return 1;
  }
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
    });
  } catch (e) {
    write(err, `issue: ${(e as Error).message}\n`);
    return 1;
  }

  try {
    const ledgerPath = await resolveLedgerPath();
    const ledger = await loadLedger(ledgerPath);
    // Verify the existing ledger BEFORE appending: never extend a tampered
    // ledger (fail-closed).
    if (ledger.rows.length > 0) {
      const integrity = verifyLedgerIntegrity(ledger, issuer.issuerPublicKey);
      if (!integrity.ok) {
        write(
          err,
          `issue: existing license ledger failed its integrity check (${integrity.reason}); refusing to append\n`,
        );
        return 1;
      }
    }

    const { token, row } = issueLicense(
      {
        licenseId: generateLicenseId(),
        subject: flags.subject,
        tier: flags.tier,
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
    const nextLedger = appendRow(ledger, row);
    await saveLedger(ledgerPath, nextLedger);

    // The license token the operator pastes into Activate: base64url of the
    // JSON {claims,signature}. NEVER any secret-key material.
    const encoded = toBase64url(
      new TextEncoder().encode(JSON.stringify(token)),
    );
    write(out, `${encoded}\n`);
    return 0;
  } catch (e) {
    write(err, `issue: ${(e as Error).message}\n`);
    return 1;
  } finally {
    issuer.masterKey.fill(0);
  }
}

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

async function runList(
  argv: string[],
  out: Writable,
  err: Writable,
): Promise<number> {
  const fortress = flagValue(argv, "--fortress");
  if (fortress) process.env.SANCTUARY_STORAGE_PATH = fortress;
  const asJson = hasFlag(argv, "--json");
  try {
    const ledgerPath = await resolveLedgerPath();
    const ledger = await loadLedger(ledgerPath);
    const entries = listLicenses(ledger);
    if (asJson) {
      write(out, JSON.stringify(entries, null, 2) + "\n");
      return 0;
    }
    if (entries.length === 0) {
      write(out, "No licenses issued yet.\n");
      return 0;
    }
    write(
      out,
      "LICENSE       SUBJECT              TIER        NODES      PERIOD   EXPIRES                   GRACE   REVOKED\n",
    );
    for (const e of entries) {
      write(out, formatListRow(e) + "\n");
    }
    return 0;
  } catch (e) {
    write(err, `list: ${(e as Error).message}\n`);
    return 1;
  }
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
    });
  } catch (e) {
    write(err, `revoke: ${(e as Error).message}\n`);
    return 1;
  }

  try {
    const ledgerPath = await resolveLedgerPath();
    const ledger = await loadLedger(ledgerPath);
    if (ledger.rows.length > 0) {
      const integrity = verifyLedgerIntegrity(ledger, issuer.issuerPublicKey);
      if (!integrity.ok) {
        write(
          err,
          `revoke: license ledger failed its integrity check (${integrity.reason}); refusing to modify\n`,
        );
        return 1;
      }
    }
    let next;
    try {
      next = revokeLicense(ledger, licenseId, Math.floor(Date.now() / 1000), reason, issuer.sign);
    } catch (e) {
      write(err, `revoke: ${(e as Error).message}\n`);
      return 1;
    }
    await saveLedger(ledgerPath, next);
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
      return runList(rest, out, err);
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
