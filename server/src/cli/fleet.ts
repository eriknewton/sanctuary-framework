/**
 * `sanctuary fleet attest`  -  the signed compliance-ATTESTATION export CLI.
 *
 * Verbs:
 *  - `export [--json] [--fortress <path>] [--out <file>]`  -  unlock custody
 *    (same `openIssuer` path `license issue` uses), compose the fortress's
 *    OWN already-resolved posture (license/activation status + the central
 *    fleet roster reported by a reachable local daemon, or honest zeros when
 *    unreachable), sign it with the DEFAULT operator identity, and print/write
 *    the signed document.
 *  - `verify <file|-> [--json] [--operator-key <base64url>|--pin <base64url>]`
 *    -  OFFLINE verify: recompute the canonical signing bytes and check
 *    `signature`. Needs NO custody unlock - the signature is checkable
 *    offline by design.
 *
 *    IDENTITY PROVENANCE (the A1 honesty fix, 2026-07-07): a doc signed by
 *    ANY key is internally self-consistent, so verifying ONLY against the
 *    document's OWN embedded `public_key` proves nothing about WHO signed
 *    it - an attacker can sign a fake posture with their OWN key and embed
 *    it. `verify` therefore prints "VALID signed compliance attestation"
 *    ONLY when the caller supplies `--operator-key`/`--pin` (an
 *    independently-known operator public key) AND it matches the embedded
 *    key AND the signature checks out against that pinned key. Without a
 *    pin, `verify` prints "well-formed, self-consistent, provenance
 *    UNVERIFIED" - never "VALID" - because nothing outside the document
 *    itself was checked.
 *
 * ── THE SINGLE MOST IMPORTANT INVARIANT (see `entitlement/compliance-attestation.ts`) ──
 * The exported document is an OPERATOR SELF-ATTESTATION of this fortress's OWN
 * locally-verifiable posture at a point in time. It is NOT a third-party audit
 * and NOT a per-flow rule-attributed audit trail. Every string this CLI prints
 * about the feature says so; never let a rewrite drop that framing.
 *
 * Keychain safety + fail-closed custody: `export` reuses `openIssuer` (see
 * `cli/custody-unlock.ts`), the SAME unlock `sanctuary license issue` uses.
 * No custody unlockable / no default operator identity -> `export` FAILS
 * non-zero and prints NOTHING (never an unsigned or placeholder document,
 * AGENTS.md #5). `verify` never touches custody at all.
 */

import type { Writable } from "node:stream";
import { writeFile } from "node:fs/promises";
import { fromBase64urlStrict } from "../core/encoding.js";
import {
  buildAttestationBody,
  serializeSignedAttestation,
  verifySignedAttestation,
  CLAIMS_SCOPE_DISCLAIMER,
  type AttestationLicenseStatus,
  type AttestationLicenseView,
  type AttestationPostureView,
  type SignedAttestation,
} from "../entitlement/compliance-attestation.js";
import { generateIdentityId } from "../core/identity.js";
import { resolveEntitlement, type EntitlementClaimsV2 } from "../entitlement/token.js";
import { readFleetActivation } from "../entitlement/activation.js";
import { resolveFleetCap } from "../entitlement/fleet-cap.js";
import { isLicenseRevoked } from "../entitlement/revocation-list.js";
import { revocationVerifiability } from "../entitlement/revocation-antirollback.js";
import { openIssuer } from "./custody-unlock.js";
import { dashboardRequest, DashboardRequestError } from "./dashboard-request.js";
import { ED25519_PUBLIC_KEY_BYTES } from "../core/crypto-suite-registry.js";
import {
  consumeFlagValue,
  flagValue,
  FORTRESS_FLAG_USAGE_EXIT_CODE,
  fortressFlagRefusalText,
} from "./argv.js";

function write(stream: Writable, text: string): void {
  stream.write(text);
}

function hasFlag(argv: string[], name: string): boolean {
  return argv.includes(name);
}

/**
 * Best-effort read of the local daemon's `GET /api/fleet/status` for the
 * central-roster posture (node counts, eviction serial, policy-distribution
 * rollup are NOT on that response today - see the honest-`null` note below).
 * Injected as `fetchPosture` so tests never need a real daemon or network.
 *
 * The daemon route is a CONVENIENCE source for the roster-derived fields, not a
 * trust boundary the attestation relies on for its signature - the signature
 * covers whatever posture this function returns, honest `null`s included for
 * anything unmeasured. A daemon that is DOWN (unreachable, non-200, malformed
 * body) resolves to the honest "roster_unavailable" branch - never a fabricated
 * count.
 *
 * CREDENTIAL (2026-08-02): the route now requires an operator-derived
 * credential (loopback position alone is refused - a co-resident agent uid
 * shares that position). `export` runs AS the operator, so it presents the
 * operator bearer through the SAME channel every other API-client CLI verb
 * uses: {@link dashboardRequest}, reading `SANCTUARY_DASHBOARD_AUTH_TOKEN`.
 * No new credential channel is invented here.
 *
 * A daemon that is REACHABLE but REFUSES us is NOT the same event as a daemon
 * that is down, and must never collapse into it: silently emitting the
 * roster-unavailable branch would ship a DEGRADED attestation that says
 * "no roster was found" when the truth is "a roster exists and we were not
 * allowed to read it". That is exactly the silent security downgrade AGENTS.md
 * constraint 5 forbids, so an auth refusal throws
 * {@link DaemonPostureAuthError} and `export` fails loudly, non-zero, printing
 * no document at all.
 */
export type PostureFetcher = () => Promise<{
  centralNodesTotal: number;
  admitted: number;
  /** null = this source does not measure it (the A3 fix: never a stand-in 0). */
  revoked: number | null;
  /** null = this source does not measure it (the A3 fix: never a stand-in 0). */
  untrusted: number | null;
  /** null = this source does not measure it (the A3 fix: never a stand-in 0). */
  evictionSerial: number | null;
  /** null = this source does not measure it - never a zero-filled rollup. */
  policyDistribution: { inSync: number; drifted: number; unknown: number } | null;
  bannerState: string;
} | null>;

const DEFAULT_DASHBOARD_URL = "http://127.0.0.1:3502";

/**
 * The daemon is REACHABLE but REFUSED the posture read (HTTP 401/403).
 *
 * Distinct from every other fetch failure on purpose. "The daemon is down" and
 * "the daemon will not talk to us" are different facts about the fortress, and
 * only the first one honestly maps to the attestation's roster-unavailable
 * branch. Collapsing the second into the first would sign a document asserting
 * a posture nobody measured, with nothing in it saying so.
 */
export class DaemonPostureAuthError extends Error {
  constructor(detail: string) {
    super(detail);
    this.name = "DaemonPostureAuthError";
  }
}

/**
 * The DEFAULT posture fetcher: a best-effort GET against the local daemon's
 * read-only fleet-status route, carrying the operator bearer from
 * `SANCTUARY_DASHBOARD_AUTH_TOKEN` (the channel {@link dashboardRequest}
 * already resolves for every API-client CLI verb).
 *
 * Returns null on a daemon that is down, slow, or returns something unexpected,
 * so the caller falls back to the honest roster-unavailable branch. THROWS
 * {@link DaemonPostureAuthError} when the daemon answers 401/403 - see the
 * fetchDaemonPosture note above for why that one case must not be silent.
 */
async function fetchDaemonPosture(
  dashboardUrl: string,
  authToken: string,
): ReturnType<PostureFetcher> {
  let body: Record<string, unknown>;
  try {
    body = (await dashboardRequest("/api/fleet/status", {}, {
      dashboardUrl,
      authToken,
    })) as Record<string, unknown>;
  } catch (cause) {
    if (cause instanceof DashboardRequestError && cause.kind === "auth") {
      throw new DaemonPostureAuthError(cause.message);
    }
    // Daemon down / not implemented / server error / malformed body: honestly
    // unmeasured, and the attestation says so via "roster_unavailable".
    return null;
  }
  const admitted =
    typeof body.admitted_node_count === "number" ? body.admitted_node_count : 0;
  const bannerState =
    typeof body.banner_state === "string" ? body.banner_state : "unknown";
  // The shipped `/api/fleet/status` response does not carry revoked/untrusted
  // counts, the eviction serial, or the policy-distribution rollup (it is a
  // BANNER endpoint, not a full roster dump). Report what it honestly gives
  // us (admitted count + banner) and an explicit `null` (NOT a zero) for the
  // rest, so a reader can distinguish "measured zero" from "never measured"
  // (the A3 fix - do NOT fabricate precision the endpoint does not provide).
  // A future daemon route (spec §2c) can widen this by wiring the real
  // `buildFleetRoster` rollup without changing the attestation shape (that
  // richer wiring is a flagged follow-up, not required for this fix).
  return {
    centralNodesTotal: admitted,
    admitted,
    revoked: null,
    untrusted: null,
    evictionSerial: null,
    policyDistribution: null,
    bannerState,
  };
}

/** Map a resolved entitlement + activation record into the attestation's license view. */
function buildLicenseView(args: {
  resolution: ReturnType<typeof resolveEntitlement>;
  claims: EntitlementClaimsV2 | null;
}): AttestationLicenseView {
  const { resolution, claims } = args;
  if (!resolution.granted || resolution.tier === "community") {
    return {
      licenseId: null,
      subject: null,
      tier: "community",
      entitledNodes: null,
      notAfter: null,
      features: [],
      status: "community",
    };
  }
  const status: AttestationLicenseStatus =
    resolution.graceActive === true ? "grace" : "active";
  return {
    licenseId: resolution.licenseId ?? null,
    subject: claims?.subject ?? null,
    tier: resolution.tier,
    entitledNodes: resolution.entitledCount ?? null,
    notAfter: claims ? new Date(claims.notAfter * 1000).toISOString() : null,
    features: resolution.featureFlags ? [...resolution.featureFlags] : [],
    status,
  };
}

interface ExportFlags {
  json: boolean;
  out?: string;
  fortressPath?: string;
  passphrase?: string;
  recoveryKey?: string;
}

function parseExportFlags(
  argv: string[],
  env: NodeJS.ProcessEnv,
  fortressPath: string | undefined,
): ExportFlags {
  return {
    json: hasFlag(argv, "--json"),
    out: flagValue(argv, "--out"),
    fortressPath,
    passphrase: flagValue(argv, "--passphrase") ?? env.SANCTUARY_PASSPHRASE,
    recoveryKey: env.SANCTUARY_RECOVERY_KEY,
  };
}

async function runExport(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv,
  fetchPosture: PostureFetcher,
): Promise<number> {
  // Must match consumeFlagValue in ./argv.ts: a dropped --fortress value must
  // refuse, never silently resolve the default fortress; exporting fleet
  // attestation for the wrong fortress is a constraint-5 violation.
  const consumedFortress = consumeFlagValue(argv, "--fortress");
  if (consumedFortress.error !== undefined) {
    write(err, `${fortressFlagRefusalText(consumedFortress.error)}\n`);
    return FORTRESS_FLAG_USAGE_EXIT_CODE;
  }
  const flags = parseExportFlags(consumedFortress.argv, env, consumedFortress.value);

  let issuer: Awaited<ReturnType<typeof openIssuer>>;
  try {
    issuer = await openIssuer({
      ...(flags.passphrase !== undefined ? { passphrase: flags.passphrase } : {}),
      ...(flags.recoveryKey !== undefined ? { recoveryKey: flags.recoveryKey } : {}),
      ...(flags.fortressPath !== undefined ? { fortressPath: flags.fortressPath } : {}),
    });
  } catch (e) {
    write(err, `attest export: ${(e as Error).message}\n`);
    return 1;
  }

  try {
    const now = Math.floor(Date.now() / 1000);

    // Resolve the license/activation view. ABSENT/INVALID both honestly
    // collapse to community (fail-closed by construction - see activation.ts);
    // this NEVER refuses to attest an unlicensed fortress (spec §4).
    const record = await readFleetActivation(issuer.storage, issuer.masterKey);
    let resolution: ReturnType<typeof resolveEntitlement>;
    let claims: EntitlementClaimsV2 | null = null;
    if (record.status === "valid") {
      resolution = resolveEntitlement({
        token: record.data.token,
        issuerPublicKey: issuer.issuerPublicKey,
        now,
      });
      if (record.data.token.claims.version === 2) {
        claims = record.data.token.claims as EntitlementClaimsV2;
      }
    } else {
      resolution = resolveEntitlement({
        token: undefined,
        issuerPublicKey: issuer.issuerPublicKey,
        now,
      });
    }
    // ── Revocation-aware resolution (the A2 fix). A license can be VALID by
    // its own token claims (in-window, well-signed) yet have been REVOKED by
    // the issuer afterward (refund, compromise, kill) - the revocation rail
    // is a SEPARATE signed record `resolveEntitlement` never consults. This
    // mirrors the SAME fail-closed logic `runFleetReResolve` uses (re-
    // resolve.ts) so export can never sign a REVOKED-but-in-window license as
    // "active": consult the single {@link revocationVerifiability} chokepoint
    // (present-clean / absent / CORRUPT-or-unverifiable) and, on a clean
    // list, {@link isLicenseRevoked} for this specific license id. Any of
    // "revoked" OR "the revocation list itself is unverifiable" forces the
    // resolution to community/revoked - this is READ-ONLY (no write, no log
    // append, no wall/enforcement touch): export never mutates fleet state.
    const licenseIdForRevocationCheck =
      typeof resolution.licenseId === "string" ? resolution.licenseId : null;
    const verifiability = await revocationVerifiability(issuer.storage, issuer.masterKey);
    let revoked = false;
    if (verifiability.status === "clean") {
      const status = await isLicenseRevoked(
        issuer.storage,
        issuer.masterKey,
        licenseIdForRevocationCheck,
      );
      revoked = status.revoked;
    }
    const revocationListUnverifiable = verifiability.status === "unverifiable";
    const effectiveResolution =
      resolution.granted && (revoked || revocationListUnverifiable)
        ? resolveEntitlement({ token: undefined, issuerPublicKey: issuer.issuerPublicKey, now })
        : resolution;
    const effectiveClaims =
      resolution.granted && (revoked || revocationListUnverifiable) ? null : claims;

    const grandfatheredBaseline =
      record.status === "valid" ? record.data.grandfatheredBaseline : 0;
    const cap = resolveFleetCap(
      {
        granted: effectiveResolution.granted,
        tier: effectiveResolution.tier,
        ...(effectiveResolution.entitledCount !== undefined
          ? { entitledCount: effectiveResolution.entitledCount }
          : {}),
        ...(effectiveResolution.pricingUnit !== undefined
          ? { pricingUnit: effectiveResolution.pricingUnit }
          : {}),
        ...(effectiveResolution.graceActive !== undefined
          ? { graceActive: effectiveResolution.graceActive }
          : {}),
        ...(effectiveResolution.reason !== undefined
          ? { reason: effectiveResolution.reason }
          : {}),
      },
      grandfatheredBaseline,
    );
    const licenseView = buildLicenseView({
      resolution: effectiveResolution,
      claims: effectiveClaims,
    });

    let roster: Awaited<ReturnType<PostureFetcher>>;
    try {
      roster = await fetchPosture();
    } catch (cause) {
      if (cause instanceof DaemonPostureAuthError) {
        // The daemon is UP and REFUSED us. Falling through to the
        // roster-unavailable zeros here would sign a document asserting "no
        // roster was found" when the truth is "a roster exists and we were not
        // allowed to read it" - a silently DEGRADED attestation, which is the
        // security downgrade AGENTS.md constraint 5 forbids. Fail loudly,
        // non-zero, printing no document at all (the same posture this command
        // already takes when custody will not unlock), and name the credential
        // channel so the operator can fix it in one step.
        write(
          err,
          "attest export: the local daemon refused the fleet-posture read " +
            "(operator credential required).\n" +
            "  Export will NOT emit a degraded attestation that reports an " +
            "unmeasured roster as absent.\n" +
            "  Set SANCTUARY_DASHBOARD_AUTH_TOKEN to this fortress's operator " +
            "token and re-run, or stop the daemon to attest the honestly " +
            "roster-unavailable posture.\n" +
            `  Detail: ${(cause as Error).message}\n`,
        );
        return 1;
      }
      // The posture fetcher must never abort or corrupt an export; any OTHER
      // failure (network, parse, unexpected shape) falls through to the
      // honest roster-unavailable zeros below.
      roster = null;
    }
    const postureView: AttestationPostureView = roster
      ? {
          centralNodesTotal: roster.centralNodesTotal,
          admitted: roster.admitted,
          revoked: roster.revoked,
          untrusted: roster.untrusted,
          maxNodes: cap.maxNodes,
          overCap: cap.maxNodes !== null && roster.centralNodesTotal > cap.maxNodes,
          evictionSerial: roster.evictionSerial,
          policyDistribution: roster.policyDistribution,
          bannerState: roster.bannerState,
        }
      : {
          // No posture source reachable at all: centralNodesTotal/admitted
          // are honestly 0 (a MEASURED fact - no roster was found), but
          // revoked/untrusted/evictionSerial/policyDistribution are `null`
          // (NOT measured-zero, the A3 fix) because nothing was checked.
          centralNodesTotal: 0,
          admitted: 0,
          revoked: null,
          untrusted: null,
          maxNodes: cap.maxNodes,
          overCap: false,
          evictionSerial: null,
          policyDistribution: null,
          bannerState: "roster_unavailable",
        };

    const body = buildAttestationBody({
      fortressId: issuer.issuerId,
      issuerFingerprint: generateIdentityId(issuer.issuerPublicKey),
      license: licenseView,
      posture: postureView,
      now: new Date(now * 1000).toISOString(),
    });
    const document = serializeSignedAttestation(body, issuer.sign, issuer.issuerPublicKey);
    const rendered = JSON.stringify(document, null, 2);

    if (flags.out) {
      await writeFile(flags.out, `${rendered}\n`, "utf8");
    }
    write(out, `${rendered}\n`);
    return 0;
  } catch (e) {
    write(err, `attest export: ${(e as Error).message}\n`);
    return 1;
  } finally {
    issuer.masterKey.fill(0);
  }
}

async function readStdin(stream: NodeJS.ReadableStream): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function runVerify(
  argv: string[],
  out: Writable,
  err: Writable,
  stdin: NodeJS.ReadableStream,
): Promise<number> {
  const asJson = hasFlag(argv, "--json");
  const target = argv.find((a) => !a.startsWith("--"));
  if (!target) {
    write(err, "attest verify: a <file|-> argument is required\n");
    return 1;
  }

  // The independently-pinned operator public key (A1 fix): supplied by the
  // caller from OUTSIDE this document (their own record of the operator's
  // identity), never read from the document itself. Absent this flag, verify
  // can only prove self-consistency, never identity provenance.
  const pinRaw = flagValue(argv, "--operator-key") ?? flagValue(argv, "--pin");
  let pinnedOperatorKey: Uint8Array | undefined;
  if (pinRaw !== undefined) {
    try {
      pinnedOperatorKey = fromBase64urlStrict(pinRaw);
    } catch {
      write(err, "attest verify: --operator-key/--pin is not valid base64url\n");
      return 1;
    }
    if (pinnedOperatorKey.length !== ED25519_PUBLIC_KEY_BYTES) {
      write(
        err,
        "attest verify: --operator-key/--pin must decode to a 32-byte Ed25519 public key\n",
      );
      return 1;
    }
  }

  let raw: string;
  try {
    if (target === "-") {
      raw = await readStdin(stdin);
    } else {
      const { readFile } = await import("node:fs/promises");
      raw = await readFile(target, "utf8");
    }
  } catch (e) {
    write(err, `attest verify: could not read ${target}: ${(e as Error).message}\n`);
    return 1;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    write(err, "attest verify: not valid JSON\n");
    return 1;
  }

  const result = verifySignedAttestation(
    parsed,
    pinnedOperatorKey !== undefined ? { pinnedOperatorKey } : undefined,
  );
  if (!result.ok) {
    if (asJson) {
      write(out, JSON.stringify({ ok: false, reason: result.reason }, null, 2) + "\n");
    } else {
      write(err, `attest verify: FAILED (${result.reason})\n`);
    }
    return 1;
  }

  if (asJson) {
    write(
      out,
      JSON.stringify(
        { ok: true, provenance: result.provenance, attestation: result.attestation },
        null,
        2,
      ) + "\n",
    );
  } else if (result.provenance === "verified") {
    // ONLY this branch (pinned key matched + signature verified against it)
    // may say "VALID": identity provenance was actually established against a
    // key the caller trusts from outside the document.
    write(out, "VALID signed compliance attestation.\n");
    write(
      out,
      "Provenance VERIFIED: the signature checks out against the operator " +
        "key you pinned with --operator-key/--pin.\n\n",
    );
    write(out, `${JSON.stringify(result.attestation, null, 2)}\n`);
  } else {
    // No pinned key was supplied: the document is well-formed and internally
    // consistent (unaltered since signing) but nothing outside the document
    // was checked - a doc signed by ANY key, including an attacker's own,
    // reaches this branch identically. NEVER print "VALID" here.
    write(
      out,
      "well-formed, self-consistent, provenance UNVERIFIED (pin the operator " +
        "key with --operator-key/--pin to verify provenance).\n",
    );
    write(
      out,
      "NOTE: this proves the document is unaltered since signing and was " +
        "signed by the holder of the embedded public key. It does NOT prove " +
        "that key belongs to a specific operator - a doc signed by ANY key " +
        "(including an attacker's own) reaches this same result. Pin the " +
        "operator's independently known public key with --operator-key/--pin " +
        "to establish provenance.\n\n",
    );
    write(out, `${JSON.stringify(result.attestation, null, 2)}\n`);
  }
  return 0;
}

const ATTEST_USAGE = `sanctuary fleet attest  -  signed compliance-attestation export

${CLAIMS_SCOPE_DISCLAIMER}

Usage:
  sanctuary fleet attest export [--json] [--fortress <path>] [--out <file>] \\
      [--dashboard-url <url>]
  sanctuary fleet attest verify <file|-> [--json] \\
      [--operator-key <base64url>|--pin <base64url>]

Custody (export only): set SANCTUARY_PASSPHRASE or --passphrase (or
SANCTUARY_RECOVERY_KEY). export signs with the DEFAULT operator identity, the
SAME key 'sanctuary license issue' signs licenses with. verify is OFFLINE and
needs no custody unlock.

Daemon posture (export only): the local daemon's fleet-status read requires an
operator credential, so set SANCTUARY_DASHBOARD_AUTH_TOKEN to this fortress's
operator token. A daemon that is DOWN yields the honest roster-unavailable
posture; a daemon that is UP and refuses the read FAILS the export rather than
signing an attestation that reports an unmeasured roster as absent.

verify prints "VALID" ONLY when --operator-key/--pin (an independently known
operator public key) is supplied and matches the document. Without a pin,
verify prints "well-formed, self-consistent, provenance UNVERIFIED" - a doc
signed by ANY key looks identical without a pin, so this is never "VALID".
`;

async function runAttestCommand(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv,
  stdin: NodeJS.ReadableStream,
  fetchPosture?: PostureFetcher,
): Promise<number> {
  const [verb, ...rest] = argv;
  switch (verb) {
    case "export": {
      const dashboardUrl =
        flagValue(rest, "--dashboard-url") ?? env.SANCTUARY_DASHBOARD_URL ?? DEFAULT_DASHBOARD_URL;
      // The operator bearer, read from the SAME env var every other API-client
      // CLI verb uses (see dashboard-request.ts). Threaded from the injected
      // `env` rather than `process.env` so tests never mutate global state. The
      // empty string sends NO Authorization header, which is the correct
      // request to make against a daemon with auth disabled - the daemon, not
      // this CLI, decides whether that is enough.
      const authToken = env.SANCTUARY_DASHBOARD_AUTH_TOKEN ?? "";
      const posture =
        fetchPosture ?? (() => fetchDaemonPosture(dashboardUrl, authToken));
      return runExport(rest, out, err, env, posture);
    }
    case "verify":
      return runVerify(rest, out, err, stdin);
    case undefined:
    case "help":
    case "--help":
    case "-h":
      write(out, ATTEST_USAGE);
      return verb === undefined ? 1 : 0;
    default:
      write(err, `fleet attest: unknown verb '${verb}'\n\n${ATTEST_USAGE}`);
      return 1;
  }
}

const USAGE = `sanctuary fleet  -  fleet control-plane operator surfaces

Usage:
  sanctuary fleet attest export|verify ...   (see 'sanctuary fleet attest --help')
`;

/**
 * Entry point for `sanctuary fleet`. Returns a process exit code (0 success,
 * non-zero on any fail-closed condition). Never throws to the caller.
 */
export async function runFleetCommand(args: {
  argv: string[];
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
  stdin?: NodeJS.ReadableStream;
  /** Test seam: override the posture source `attest export` reads from. */
  fetchPosture?: PostureFetcher;
}): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;
  const stdin = args.stdin ?? process.stdin;
  const [group, ...rest] = args.argv;

  if (group === "attest") {
    return runAttestCommand(rest, out, err, env, stdin, args.fetchPosture);
  }
  if (group === undefined || group === "help" || group === "--help" || group === "-h") {
    write(out, USAGE);
    return group === undefined ? 1 : 0;
  }
  write(err, `fleet: unknown verb '${group}'\n\n${USAGE}`);
  return 1;
}

export type { SignedAttestation };
