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
 *  - `verify <file|-> [--json]`  -  OFFLINE verify: recompute the canonical
 *    signing bytes, check the embedded `public_key` against `signature`, and
 *    report the attested posture. Needs NO custody unlock - the signature is
 *    checkable offline by design.
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
import { openIssuer } from "./custody-unlock.js";

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

/**
 * Best-effort read of the local daemon's `GET /api/fleet/status` for the
 * central-roster posture (node counts, eviction serial, policy-distribution
 * rollup are NOT on that response today - see the honest-zeros note below).
 * Injected as `fetchPosture` so tests never need a real daemon or network.
 *
 * The daemon route is a READ (no operator-bearer gate); it is a CONVENIENCE
 * source for the roster-derived fields, not a trust boundary the attestation
 * relies on for its signature - the signature covers whatever posture this
 * function returns, honest zeros included. Any failure (daemon unreachable,
 * non-200, malformed body) resolves to the honest "roster_unavailable" branch
 * -  never a fabricated count.
 */
export type PostureFetcher = () => Promise<{
  centralNodesTotal: number;
  admitted: number;
  revoked: number;
  untrusted: number;
  evictionSerial: number;
  policyDistribution: { inSync: number; drifted: number; unknown: number };
  bannerState: string;
} | null>;

const DEFAULT_DASHBOARD_URL = "http://127.0.0.1:3502";

/**
 * The DEFAULT posture fetcher: a best-effort unauthenticated GET against the
 * local daemon's read-only fleet-status route. Returns null (never throws) on
 * ANY failure so the caller can fall back to the honest roster-unavailable
 * zeros - a daemon that is down, slow, or returns something unexpected must
 * never block or corrupt an attestation export.
 */
async function fetchDaemonPosture(
  dashboardUrl: string,
): ReturnType<PostureFetcher> {
  try {
    const res = await fetch(`${dashboardUrl}/api/fleet/status`, {
      method: "GET",
    });
    if (!res.ok) return null;
    const body = (await res.json()) as Record<string, unknown>;
    const admitted =
      typeof body.admitted_node_count === "number" ? body.admitted_node_count : 0;
    const bannerState =
      typeof body.banner_state === "string" ? body.banner_state : "unknown";
    // The shipped `/api/fleet/status` response does not carry revoked/untrusted
    // counts, the eviction serial, or the policy-distribution rollup (it is a
    // BANNER endpoint, not a full roster dump). Report what it honestly gives
    // us (admitted count + banner) and honest zeros for the rest rather than
    // fabricating precision the endpoint does not provide; a future daemon
    // route (spec §2c) can widen this without changing the attestation shape.
    return {
      centralNodesTotal: admitted,
      admitted,
      revoked: 0,
      untrusted: 0,
      evictionSerial: 0,
      policyDistribution: { inSync: 0, drifted: 0, unknown: 0 },
      bannerState,
    };
  } catch {
    return null;
  }
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

function parseExportFlags(argv: string[], env: NodeJS.ProcessEnv): ExportFlags {
  return {
    json: hasFlag(argv, "--json"),
    out: flagValue(argv, "--out"),
    fortressPath: flagValue(argv, "--fortress"),
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
  const flags = parseExportFlags(argv, env);

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
    const grandfatheredBaseline =
      record.status === "valid" ? record.data.grandfatheredBaseline : 0;
    const cap = resolveFleetCap(
      {
        granted: resolution.granted,
        tier: resolution.tier,
        ...(resolution.entitledCount !== undefined
          ? { entitledCount: resolution.entitledCount }
          : {}),
        ...(resolution.pricingUnit !== undefined
          ? { pricingUnit: resolution.pricingUnit }
          : {}),
        ...(resolution.graceActive !== undefined
          ? { graceActive: resolution.graceActive }
          : {}),
        ...(resolution.reason !== undefined ? { reason: resolution.reason } : {}),
      },
      grandfatheredBaseline,
    );
    const licenseView = buildLicenseView({ resolution, claims });

    let roster: Awaited<ReturnType<PostureFetcher>>;
    try {
      roster = await fetchPosture();
    } catch {
      // The posture fetcher must never abort or corrupt an export; any
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
          centralNodesTotal: 0,
          admitted: 0,
          revoked: 0,
          untrusted: 0,
          maxNodes: cap.maxNodes,
          overCap: false,
          evictionSerial: 0,
          policyDistribution: { inSync: 0, drifted: 0, unknown: 0 },
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

  const result = verifySignedAttestation(parsed);
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
      JSON.stringify({ ok: true, attestation: result.attestation }, null, 2) + "\n",
    );
  } else {
    write(out, "VALID signed compliance attestation.\n");
    write(
      out,
      "NOTE: this proves the document is self-consistent (unaltered since " +
        "signing) and was signed by the holder of the embedded public key. It " +
        "does NOT by itself prove that key belongs to a specific operator - " +
        "pin `public_key` against the operator's independently known identity " +
        "to establish that.\n\n",
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
  sanctuary fleet attest verify <file|-> [--json]

Custody (export only): set SANCTUARY_PASSPHRASE or --passphrase (or
SANCTUARY_RECOVERY_KEY). export signs with the DEFAULT operator identity, the
SAME key 'sanctuary license issue' signs licenses with. verify is OFFLINE and
needs no custody unlock.
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
      const posture = fetchPosture ?? (() => fetchDaemonPosture(dashboardUrl));
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
