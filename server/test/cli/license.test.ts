/**
 * `sanctuary license` CLI tests (PR-1 — fleet license issuance).
 *
 * Verifies the SELL-side surface end to end against a real keychain-free
 * fortress seeded WITH a default operator identity (the issuer):
 *   - `issue` prints a license token that INDEPENDENTLY resolves `granted` and
 *     appends a tamper-evident ledger row; no secret-key material in output.
 *   - `list` reflects issued + revoked state; `--json` round-trips.
 *   - `revoke` marks the row and surfaces in `list`.
 *   - Fail-closed non-zero exits: unknown tier, past expiry, negative nodes,
 *     no fortress unlock, unknown licenseId on revoke — none leak a secret.
 *
 * The fortress is seeded keychain-free (mocked `security` exec) so the real
 * macOS login keychain is never touched — the pattern in identity-create.test.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Writable } from "node:stream";
import { runLicenseCommand } from "../../src/cli/license.js";
import { fromBase64url } from "../../src/core/encoding.js";
import { runInit as runInitRaw, type InitOptions } from "../../src/wrap/init.js";
import type { ExecResult } from "../../src/wrap/passphrase.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { resolveCliMasterKey } from "../../src/core/master-custody.js";
import {
  resolveEntitlement,
  type EntitlementToken,
} from "../../src/entitlement/index.js";

// ── Keychain-free fortress seeding (mirrors identity-create.test.ts) ──────
type ExecCall = { cmd: string; args: string[]; input?: string };

function unescapeSecurityToken(value: string): string {
  return value.replace(/\\(.)/g, "$1");
}
function readSecurityToken(input: string | undefined, flag: string): string {
  const escapedFlag = flag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = input?.match(
    new RegExp(`${escapedFlag} "((?:[^"\\\\]|\\\\.)*)"`),
  );
  return match ? unescapeSecurityToken(match[1]!) : "";
}
function makeRecoveryKeychainMock(): {
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>;
} {
  const calls: ExecCall[] = [];
  const stored = new Map<string, string>();
  const keyFor = (a: string, s: string): string => `${a}:${s}`;
  const exec = async (
    cmd: string,
    args: string[],
    input?: string,
  ): Promise<ExecResult> => {
    calls.push(input === undefined ? { cmd, args } : { cmd, args, input });
    if (cmd !== "security") return { stdout: "", stderr: "unknown", code: 1 };
    if (args[0] === "-i") {
      stored.set(
        keyFor(readSecurityToken(input, "-a"), readSecurityToken(input, "-s")),
        readSecurityToken(input, "-w"),
      );
      return { stdout: "", stderr: "", code: 0 };
    }
    if (args[0] === "find-generic-password") {
      const account = args[args.indexOf("-a") + 1] ?? "";
      const service = args[args.indexOf("-s") + 1] ?? "";
      const value = stored.get(keyFor(account, service));
      if (value) return { stdout: value + "\n", stderr: "", code: 0 };
      return { stdout: "", stderr: "not found", code: 44 };
    }
    return { stdout: "", stderr: "unknown", code: 1 };
  };
  return { exec };
}
async function runInit(
  options: InitOptions,
): Promise<Awaited<ReturnType<typeof runInitRaw>>> {
  const keychain = makeRecoveryKeychainMock();
  return runInitRaw(options, {
    recoveryKeychain: {
      home: "/tmp/sanctuary-test-home",
      platformOverride: "darwin",
      exec: keychain.exec,
    },
  });
}
function extractRecoveryKey(fileContent: string): string {
  const keyLine = fileContent
    .split("\n")
    .map((l) => l.trim())
    .find((l) => /^[A-Za-z0-9_-]{43}$/.test(l));
  if (!keyLine) throw new Error("recovery key not found");
  return keyLine;
}
class StringWritable extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void,
  ): void {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }
  get text(): string {
    return this.chunks.join("");
  }
}

/** Seed a keychain-free fortress WITH a default operator identity (the issuer). */
async function seedFortressWithIdentity(
  fortressPath: string,
): Promise<string> {
  const result = await runInit({
    fortress: fortressPath,
    noConfirm: true,
    noPin: true,
    noIdentity: false, // mint the default operator identity (the issuer)
  });
  const recoveryFile = await readFile(result.recoveryKeyDisclosurePath, "utf-8");
  return extractRecoveryKey(recoveryFile);
}

/** Decode a printed license token (base64url of JSON {claims,signature}). */
function decodeLicense(encoded: string): EntitlementToken {
  const json = new TextDecoder().decode(fromBase64url(encoded.trim()));
  return JSON.parse(json) as EntitlementToken;
}

/** Recover the issuer (default operator identity) public key from a fortress. */
async function issuerPublicKey(
  fortressPath: string,
  recoveryKey: string,
): Promise<Uint8Array> {
  const storage = new FilesystemStorage(join(fortressPath, "state"));
  const masterKey = await resolveCliMasterKey(storage, {
    recoveryKey,
    storagePathHint: fortressPath,
  });
  try {
    const mgr = new IdentityManager(storage, masterKey);
    await mgr.load();
    const id = mgr.getDefault();
    if (!id) throw new Error("no default identity");
    const b64 = id.public_key.replace(/-/g, "+").replace(/_/g, "/");
    return new Uint8Array(Buffer.from(b64, "base64"));
  } finally {
    masterKey.fill(0);
  }
}

const FUTURE = "2030-01-01T00:00:00Z";

describe("sanctuary license — help + arg validation (no fortress needed)", () => {
  it("prints usage on --help (exit 0)", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runLicenseCommand({ argv: ["--help"], out, err, env: {} });
    expect(code).toBe(0);
    expect(out.text).toContain("sanctuary license");
    expect(out.text).toContain("issue");
  });

  it("unknown verb → non-zero", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runLicenseCommand({ argv: ["bogus"], out, err, env: {} });
    expect(code).toBe(1);
    expect(err.text).toContain("unknown verb");
  });

  it("issue with unknown tier → exit 1, no secret", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: ["issue", "--tier", "root", "--subject", "x", "--nodes", "5", "--expires", FUTURE],
      out,
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text).toContain("--tier");
  });

  it("issue with community tier is rejected (paid-only)", async () => {
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: ["issue", "--tier", "community", "--subject", "x", "--nodes", "5", "--expires", FUTURE],
      out: new StringWritable(),
      err,
      env: {},
    });
    expect(code).toBe(1);
  });

  it("issue with a past expiry → exit 1", async () => {
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: ["issue", "--tier", "fleet", "--subject", "x", "--nodes", "5", "--expires", "2000-01-01T00:00:00Z"],
      out: new StringWritable(),
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text).toContain("past");
  });

  it("issue with negative nodes → exit 1", async () => {
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: ["issue", "--tier", "fleet", "--subject", "x", "--nodes", "-3", "--expires", FUTURE],
      out: new StringWritable(),
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text).toContain("--nodes");
  });

  it("issue with an unknown --plan → exit 1, no secret", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: ["issue", "--plan", "pro", "--subject", "x", "--expires", FUTURE],
      out,
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text).toContain("unknown --plan");
    expect(out.text).toBe("");
  });

  it("issue with --extra-nodes but no --plan → exit 1 (ambiguous flag, refuses rather than ignoring it)", async () => {
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: [
        "issue", "--extra-nodes", "3", "--subject", "x",
        "--nodes", "5", "--tier", "fleet", "--expires", FUTURE,
      ],
      out: new StringWritable(),
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text).toContain("--extra-nodes requires --plan");
  });

  it("issue with a negative --extra-nodes → exit 1", async () => {
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: [
        "issue", "--plan", "team", "--extra-nodes", "-1",
        "--subject", "x", "--expires", FUTURE,
      ],
      out: new StringWritable(),
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text).toContain("--extra-nodes must be a non-negative integer");
  });

  it("THE NEGATIVE TEST (mandatory): --plan combined with a conflicting raw flag REFUSES loudly, never silently overrides", async () => {
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: [
        "issue", "--plan", "team", "--extra-nodes", "0", "--tier", "fleet",
        "--subject", "x", "--expires", FUTURE,
      ],
      out: new StringWritable(),
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text).toContain("--plan team conflicts with explicit --tier");
  });

  it("--plan combined with --nodes, --features, AND --pricing-unit all together lists every conflicting flag", async () => {
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: [
        "issue", "--plan", "team", "--nodes", "5", "--features", "roster",
        "--pricing-unit", "seat", "--subject", "x", "--expires", FUTURE,
      ],
      out: new StringWritable(),
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text).toContain("--nodes");
    expect(err.text).toContain("--features");
    expect(err.text).toContain("--pricing-unit");
    // The refusal path must never reach the raw-flag validators (e.g. it
    // does not report "unknown feature 'roster'" — 'roster' is valid; the
    // point is the refusal happens BEFORE any raw-flag value is inspected).
    expect(err.text).not.toContain("unknown feature");
  });

  describe("--extra-nodes strict integer parsing (round-2 finding, register id EFC-01)", () => {
    const REFUSAL = /--extra-nodes must be a non-negative integer up to \d+/;

    it.each([
      ["exponent notation", "1e3"],
      ["leading plus", "+5"],
      ["leading zero", "05"],
      ["decimal point", "5.5"],
      ["surrounding whitespace", " 5"],
      ["trailing whitespace", "5 "],
      ["hex-looking literal", "0x5"],
      ["empty string", ""],
      ["Infinity keyword", "Infinity"],
      ["NaN keyword", "NaN"],
      ["thousands separator", "1,000"],
      // Number("9007199254740993") is NOT the safe integer it names — it
      // silently rounds to 9007199254740992 (MAX_SAFE_INTEGER + 1), the exact
      // class of "unsafe entitledCount signed into the ledger" the finding
      // named. Canonical decimal syntax alone (the regex) does not catch
      // this — only Number.isSafeInteger does.
      ["unsafe integer beyond MAX_SAFE_INTEGER", "9007199254740993"],
    ])("rejects --extra-nodes with %s ('%s')", async (_label, value) => {
      const err = new StringWritable();
      const code = await runLicenseCommand({
        argv: ["issue", "--plan", "team", "--extra-nodes", value, "--subject", "x", "--expires", FUTURE],
        out: new StringWritable(),
        err,
        env: {},
      });
      expect(code).toBe(1);
      expect(err.text).toMatch(REFUSAL);
    });

    it("accepts --extra-nodes exactly AT the plan's maxExtraNodes bound but refuses one past it", async () => {
      const { TEAM_MAX_EXTRA_NODES } = await import("../../src/entitlement/plan-catalog.js");

      const overErr = new StringWritable();
      const overCode = await runLicenseCommand({
        argv: [
          "issue", "--plan", "team", "--extra-nodes", String(TEAM_MAX_EXTRA_NODES + 1),
          "--subject", "x", "--expires", FUTURE,
        ],
        out: new StringWritable(),
        err: overErr,
        env: {},
      });
      expect(overCode).toBe(1);
      expect(overErr.text).toMatch(REFUSAL);

      // AT the bound: passes extra-nodes validation and proceeds to the next
      // fail-closed gate (no fortress unlockable) — proves the bound is
      // inclusive, not off-by-one, without needing a real fortress.
      const atErr = new StringWritable();
      const atCode = await runLicenseCommand({
        argv: [
          "issue", "--plan", "team", "--extra-nodes", String(TEAM_MAX_EXTRA_NODES),
          "--subject", "x", "--expires", FUTURE,
        ],
        out: new StringWritable(),
        err: atErr,
        env: {},
      });
      expect(atCode).toBe(1);
      expect(atErr.text).not.toMatch(REFUSAL);
      expect(atErr.text).toMatch(/unlocked operator identity is required|keychain/);
    });
  });

  describe("--plan conflict detection covers both `--flag value` and `--flag=value` syntax, in both orders (round-2 finding, register id EFC-02)", () => {
    const PLAN_FILLED = ["--tier", "--nodes", "--features", "--pricing-unit", "--grace-days"] as const;
    const RAW_VALUE: Record<(typeof PLAN_FILLED)[number], string> = {
      "--tier": "fleet",
      "--nodes": "5",
      "--features": "roster",
      "--pricing-unit": "seat",
      "--grace-days": "30",
    };

    for (const flag of PLAN_FILLED) {
      const value = RAW_VALUE[flag];

      it(`refuses '${flag} ${value}' (space form) BEFORE --plan`, async () => {
        const err = new StringWritable();
        const code = await runLicenseCommand({
          argv: [
            "issue", flag, value, "--plan", "team",
            "--subject", "x", "--expires", FUTURE,
          ],
          out: new StringWritable(),
          err,
          env: {},
        });
        expect(code).toBe(1);
        expect(err.text).toContain(`--plan team conflicts with explicit ${flag}`);
      });

      it(`refuses '${flag} ${value}' (space form) AFTER --plan`, async () => {
        const err = new StringWritable();
        const code = await runLicenseCommand({
          argv: [
            "issue", "--plan", "team", flag, value,
            "--subject", "x", "--expires", FUTURE,
          ],
          out: new StringWritable(),
          err,
          env: {},
        });
        expect(code).toBe(1);
        expect(err.text).toContain(`--plan team conflicts with explicit ${flag}`);
      });

      it(`refuses '${flag}=${value}' (equals form) BEFORE --plan`, async () => {
        const err = new StringWritable();
        const code = await runLicenseCommand({
          argv: [
            "issue", `${flag}=${value}`, "--plan", "team",
            "--subject", "x", "--expires", FUTURE,
          ],
          out: new StringWritable(),
          err,
          env: {},
        });
        expect(code).toBe(1);
        expect(err.text).toContain(`--plan team conflicts with explicit ${flag}`);
      });

      it(`refuses '${flag}=${value}' (equals form) AFTER --plan — THE FINDING'S EXACT REPRO ('--plan=team --tier=fleet' shape`, async () => {
        const err = new StringWritable();
        const code = await runLicenseCommand({
          argv: [
            "issue", "--plan", "team", `${flag}=${value}`,
            "--subject", "x", "--expires", FUTURE,
          ],
          out: new StringWritable(),
          err,
          env: {},
        });
        expect(code).toBe(1);
        expect(err.text).toContain(`--plan team conflicts with explicit ${flag}`);
      });
    }

    it("THE FINDING'S LITERAL REPRO: '--plan=team --tier=fleet' (both flags in equals form) refuses, never silently overrides", async () => {
      const err = new StringWritable();
      const out = new StringWritable();
      const code = await runLicenseCommand({
        argv: ["issue", "--plan=team", "--tier=fleet", "--subject", "x", "--expires", FUTURE],
        out,
        err,
        env: {},
      });
      expect(code).toBe(1);
      expect(err.text).toContain("--plan team conflicts with explicit --tier");
      expect(out.text).toBe("");
    });
  });

  it("--grace-days default: --plan team fills grace from the catalog's defaultGraceDays (round-2 finding, register id EFC-03)", async () => {
    let tmp: string | undefined;
    try {
      tmp = await mkdtemp(join(tmpdir(), "sanctuary-license-grace-fill-"));
      const fortressPath = join(tmp, "f");
      const recoveryKey = await seedFortressWithIdentity(fortressPath);
      delete process.env.SANCTUARY_STORAGE_PATH;

      const out = new StringWritable();
      const code = await runLicenseCommand({
        argv: [
          "issue", "--fortress", fortressPath, "--plan", "team",
          "--subject", "grace-co", "--expires", FUTURE,
        ],
        out,
        err: new StringWritable(),
        env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
      });
      expect(code).toBe(0);

      const token = decodeLicense(out.text);
      // graceUntil = notAfter + 14 days (the catalog's defaultGraceDays), not
      // some other value — proves the preset FILLS it from the template
      // rather than relying on the CLI's separate DEFAULT_GRACE_DAYS fallback
      // happening to match today.
      const claims = token.claims as { notAfter: number; graceUntil: number | null };
      expect(claims.graceUntil).not.toBeNull();
      expect(claims.graceUntil! - claims.notAfter).toBe(14 * 86_400);
    } finally {
      delete process.env.SANCTUARY_STORAGE_PATH;
      delete process.env.SANCTUARY_RECOVERY_KEY;
      if (tmp) await rm(tmp, { recursive: true, force: true });
    }
  });

  it("USAGE and the unknown-feature error render the known-features list and grace default FROM the catalog constants, not a hand-mirrored literal (round-2 finding, register id EFC-04)", async () => {
    const { ALL_ENTITLEMENT_FEATURE_FLAGS, DEFAULT_GRACE_DAYS, PLAN_NAMES } = await import(
      "../../src/entitlement/plan-catalog.js"
    );
    // Independent oracle (finding EFC-04's own instruction): assert against
    // literal expected values, NOT by re-importing the same constant the
    // production code renders from — a bug in the constant itself must still
    // be caught by a test that does not share its source.
    expect([...ALL_ENTITLEMENT_FEATURE_FLAGS]).toEqual([
      "roster", "policy-dist", "kill-safety", "console",
    ]);
    expect(DEFAULT_GRACE_DAYS).toBe(14);
    expect([...PLAN_NAMES]).toEqual(["team"]);

    const usageOut = new StringWritable();
    await runLicenseCommand({ argv: ["--help"], out: usageOut, err: new StringWritable(), env: {} });
    expect(usageOut.text).toContain("roster,policy-dist,kill-safety,console");
    expect(usageOut.text).toContain("--grace-days 14");
    // Plan-name drift guard: USAGE's --plan example must contain EVERY name
    // PLAN_NAMES knows (a newly catalogued plan automatically shows up in
    // help text with no separate edit), and the example's --plan segment
    // must contain NO plan-shaped token absent from PLAN_NAMES (a catalog
    // rename or removal is caught here before it can mislead an operator).
    // Scoped to the `--plan <...>` segment specifically, not the whole
    // USAGE string, because `--tier <team|fleet|enterprise>` uses the
    // unrelated EntitlementTier vocabulary and legitimately contains
    // "team" as a TIER name even if "team" were ever removed from PLAN_NAMES.
    const planSegment = usageOut.text.match(/--plan <([^>]+)>/);
    expect(planSegment).not.toBeNull();
    const renderedPlanNames = planSegment![1].split("|");
    for (const name of PLAN_NAMES) {
      expect(renderedPlanNames).toContain(name);
    }
    for (const rendered of renderedPlanNames) {
      expect(PLAN_NAMES as readonly string[]).toContain(rendered);
    }

    const featErr = new StringWritable();
    await runLicenseCommand({
      argv: [
        "issue", "--tier", "fleet", "--subject", "x", "--nodes", "5",
        "--expires", FUTURE, "--features", "roster,bogus",
      ],
      out: new StringWritable(),
      err: featErr,
      env: {},
    });
    expect(featErr.text).toContain("known: roster, policy-dist, kill-safety, console");
  });

  it("issue with an unknown feature → exit 1", async () => {
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: [
        "issue", "--tier", "fleet", "--subject", "x", "--nodes", "5",
        "--expires", FUTURE, "--features", "roster,teleport",
      ],
      out: new StringWritable(),
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text).toContain("unknown feature");
  });

  it("issue with valid flags but NO fortress unlock → exit 1, actionable, no secret", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: ["issue", "--tier", "fleet", "--subject", "x", "--nodes", "5", "--expires", FUTURE],
      out,
      err,
      env: {}, // no passphrase / recovery key
    });
    expect(code).toBe(1);
    expect(err.text).toMatch(/unlocked operator identity is required|keychain/);
    expect(out.text).toBe("");
  });

  it("THE A4 REGRESSION TEST: issue on a fortress with NO default operator identity keeps the EXACT original message, unchanged by the custody-unlock extraction", async () => {
    // Before PR-1's custody-unlock was extracted to a shared cli/custody-unlock.ts
    // (so `fleet attest export` could reuse the SAME unlock path), this message
    // was hardcoded inline in license.ts as "license issuance requires a default
    // operator identity...". The extraction generalized it to "this operation
    // requires..." for the new `fleet` caller, which silently changed the
    // license CLI's own wording - the A4 fix threads an operationLabel through
    // so `issue`/`revoke`/verified `list` see this EXACT original text, byte
    // for byte, while only the NEW `fleet attest` caller gets the generic text.
    let tmp: string | undefined;
    try {
      tmp = await mkdtemp(join(tmpdir(), "sanctuary-license-no-identity-test-"));
      const fortressPath = join(tmp, "f");
      const result = await runInit({
        fortress: fortressPath,
        noConfirm: true,
        noPin: true,
        noIdentity: true, // NO default operator identity minted
      });
      const recoveryFile = await readFile(result.recoveryKeyDisclosurePath, "utf-8");
      const recoveryKey = extractRecoveryKey(recoveryFile);
      delete process.env.SANCTUARY_STORAGE_PATH;

      const out = new StringWritable();
      const err = new StringWritable();
      const code = await runLicenseCommand({
        argv: [
          "issue", "--fortress", fortressPath, "--tier", "fleet",
          "--subject", "x", "--nodes", "5", "--expires", FUTURE,
        ],
        out,
        err,
        env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
      });
      expect(code).toBe(1);
      expect(err.text).toBe(
        "issue: no operator identity in this fortress: license issuance requires a " +
          "default operator identity (run `sanctuary identity create`, or " +
          "re-run `sanctuary init` without --no-identity)\n",
      );
      expect(out.text).toBe("");
    } finally {
      delete process.env.SANCTUARY_STORAGE_PATH;
      delete process.env.SANCTUARY_RECOVERY_KEY;
      if (tmp) await rm(tmp, { recursive: true, force: true });
    }
  });
});

describe("sanctuary license — end-to-end (keychain-free fortress)", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-license-test-"));
  });
  afterEach(async () => {
    delete process.env.SANCTUARY_STORAGE_PATH;
    delete process.env.SANCTUARY_RECOVERY_KEY;
    try {
      await rm(tmp, { recursive: true, force: true });
    } catch {
      // best-effort
    }
  });

  it("issue prints a token that independently resolves granted; no secret leaks", async () => {
    const fortressPath = join(tmp, "f");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: [
        "issue", "--fortress", fortressPath,
        "--tier", "fleet", "--subject", "acme-fleet",
        "--nodes", "25", "--period", "annual", "--expires", FUTURE,
        "--features", "roster,policy-dist,console",
      ],
      out,
      err,
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(code).toBe(0);
    expect(err.text).toBe("");

    const token = decodeLicense(out.text);
    expect(token.claims).toBeTruthy();
    expect(token.signature).toBeTruthy();
    // No secret-key material in the printed output — the token is claims+signature only.
    expect(out.text).not.toMatch(/private/i);

    // Full chain: the printed token INDEPENDENTLY resolves granted against the
    // issuer's public key (recovered from the fortress). This proves the CLI
    // signed a real, verifiable v2 license.
    const pub = await issuerPublicKey(fortressPath, recoveryKey);
    const resolved = resolveEntitlement({
      token,
      issuerPublicKey: pub,
      now: Math.floor(Date.parse(FUTURE) / 1000) - 86_400, // one day before expiry
    });
    expect(resolved.granted).toBe(true);
    expect(resolved.tier).toBe("fleet");
    expect(resolved.entitledCount).toBe(25);
    expect(resolved.period).toBe("annual");
    expect(resolved.featureFlags).toEqual(["console", "policy-dist", "roster"]);
  });

  it("--plan team --extra-nodes 3 issues a license that independently resolves the catalog's D1/D2 claim (10+3 nodes, full feature set, node pricing)", async () => {
    const fortressPath = join(tmp, "f-plan");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: [
        "issue", "--fortress", fortressPath,
        "--plan", "team", "--extra-nodes", "3",
        "--subject", "plan-co", "--period", "annual", "--expires", FUTURE,
      ],
      out,
      err,
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(code).toBe(0);
    expect(err.text).toBe("");

    const token = decodeLicense(out.text);
    const pub = await issuerPublicKey(fortressPath, recoveryKey);
    const resolved = resolveEntitlement({
      token,
      issuerPublicKey: pub,
      now: Math.floor(Date.parse(FUTURE) / 1000) - 86_400,
    });
    expect(resolved.granted).toBe(true);
    expect(resolved.tier).toBe("team");
    expect(resolved.entitledCount).toBe(13); // 10 included + 3 extra (D1)
    expect(resolved.pricingUnit).toBe("node");
    expect(resolved.period).toBe("annual");
    // D2: the plan preset grants the FULL feature set, unlike the raw
    // --tier team default (which stays roster+policy-dist only).
    expect([...(resolved.featureFlags ?? [])].sort()).toEqual(
      ["console", "kill-safety", "policy-dist", "roster"].sort(),
    );
  });

  it("list reflects an issued license, and revoke marks it revoked", async () => {
    const fortressPath = join(tmp, "f2");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;
    const env = { SANCTUARY_RECOVERY_KEY: recoveryKey };

    // Issue.
    const issueOut = new StringWritable();
    const issueCode = await runLicenseCommand({
      argv: [
        "issue", "--fortress", fortressPath, "--tier", "team",
        "--subject", "beta-co", "--nodes", "5", "--expires", FUTURE,
      ],
      out: issueOut,
      err: new StringWritable(),
      env,
    });
    expect(issueCode).toBe(0);
    const token = decodeLicense(issueOut.text);
    const licenseId = (token.claims as { licenseId: string }).licenseId;

    // list --json shows it, not revoked.
    const listOut = new StringWritable();
    const listCode = await runLicenseCommand({
      argv: ["list", "--fortress", fortressPath, "--json"],
      out: listOut,
      err: new StringWritable(),
      env,
    });
    expect(listCode).toBe(0);
    const listedDoc = JSON.parse(listOut.text) as {
      verified: boolean;
      entries: Array<{ licenseId: string; subject: string; revoked: boolean }>;
    };
    // Verified mode (recovery key present) → the JSON is marked verified.
    expect(listedDoc.verified).toBe(true);
    const listed = listedDoc.entries;
    expect(listed).toHaveLength(1);
    expect(listed[0]!.licenseId).toBe(licenseId);
    expect(listed[0]!.subject).toBe("beta-co");
    expect(listed[0]!.revoked).toBe(false);

    // Revoke.
    const revCode = await runLicenseCommand({
      argv: ["revoke", licenseId, "--fortress", fortressPath, "--reason", "test"],
      out: new StringWritable(),
      err: new StringWritable(),
      env,
    });
    expect(revCode).toBe(0);

    // list now shows revoked.
    const list2 = new StringWritable();
    await runLicenseCommand({
      argv: ["list", "--fortress", fortressPath, "--json"],
      out: list2,
      err: new StringWritable(),
      env,
    });
    const listed2Doc = JSON.parse(list2.text) as {
      verified: boolean;
      entries: Array<{ revoked: boolean; revokeReason: string | null }>;
    };
    expect(listed2Doc.verified).toBe(true);
    expect(listed2Doc.entries[0]!.revoked).toBe(true);
    expect(listed2Doc.entries[0]!.revokeReason).toBe("test");
  });

  it("revoke of an unknown licenseId → exit 1", async () => {
    const fortressPath = join(tmp, "f3");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: ["revoke", "does-not-exist", "--fortress", fortressPath],
      out: new StringWritable(),
      err,
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(code).toBe(1);
    expect(err.text).toMatch(/unknown/);
  });

  it("list on a fortress with no ledger prints the empty message (exit 0)", async () => {
    const fortressPath = join(tmp, "f4");
    await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;
    const out = new StringWritable();
    const code = await runLicenseCommand({
      argv: ["list", "--fortress", fortressPath],
      out,
      err: new StringWritable(),
      env: {},
    });
    expect(code).toBe(0);
    expect(out.text).toContain("No licenses issued yet");
  });

  it("list on a TAMPERED on-disk ledger exits non-zero with a loud warning, never renders it as trusted", async () => {
    const fortressPath = join(tmp, "f5");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;
    const env = { SANCTUARY_RECOVERY_KEY: recoveryKey };

    // Issue a real license so there is a signed ledger on disk.
    const issueOut = new StringWritable();
    const issueCode = await runLicenseCommand({
      argv: [
        "issue", "--fortress", fortressPath, "--tier", "fleet",
        "--subject", "victim", "--nodes", "5", "--expires", FUTURE,
      ],
      out: issueOut,
      err: new StringWritable(),
      env,
    });
    expect(issueCode).toBe(0);

    // Tamper the ledger file on disk: inflate the signed entitledCount. (We do
    // NOT repair the rowHash here; the point is the CLI runs the integrity check
    // AT ALL and refuses to display a tampered ledger — exit non-zero.)
    const ledgerPath = join(fortressPath, "state", "fleet-license-ledger.json");
    const raw = JSON.parse(await readFile(ledgerPath, "utf-8")) as {
      rows: Array<{ token: { claims: { entitledCount: number } } }>;
    };
    raw.rows[0]!.token.claims.entitledCount = 999_999;
    const { writeFile } = await import("node:fs/promises");
    await writeFile(ledgerPath, JSON.stringify(raw, null, 2) + "\n");

    // VERIFIED list (recovery key present) must FAIL closed: non-zero exit + a
    // loud tamper warning on stderr, and it must NOT print the (tampered)
    // license rows as if trusted. The verified path pins the issuer key from the
    // fortress (NOT the ledger file) and runs integrity + freshness.
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: ["list", "--fortress", fortressPath],
      out,
      err,
      env,
    });
    expect(code).toBe(1);
    expect(err.text).toMatch(/FAILED its integrity\/freshness check|TAMPERED/);
    expect(out.text).not.toContain("victim");

    // Same for --json: no trusted rows are emitted on tamper.
    const jsonOut = new StringWritable();
    const jsonErr = new StringWritable();
    const jsonCode = await runLicenseCommand({
      argv: ["list", "--fortress", fortressPath, "--json"],
      out: jsonOut,
      err: jsonErr,
      env,
    });
    expect(jsonCode).toBe(1);
    expect(jsonOut.text).toBe("");
    expect(jsonErr.text).toMatch(/TAMPERED|integrity\/freshness check/);
  });
});

describe("sanctuary license — anti-rollback fast-follow (list key-pin + external anchor)", () => {
  let tmp: string;
  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-license-ar-"));
  });
  afterEach(async () => {
    delete process.env.SANCTUARY_STORAGE_PATH;
    delete process.env.SANCTUARY_RECOVERY_KEY;
    try {
      await rm(tmp, { recursive: true, force: true });
    } catch {
      // best-effort
    }
  });

  it("UNVERIFIED list (no passphrase) prints entries labeled UNVERIFIED, never claims valid, exit 0", async () => {
    const fortressPath = join(tmp, "f");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;

    // Issue a real license so there is a ledger to read.
    await runLicenseCommand({
      argv: [
        "issue", "--fortress", fortressPath, "--tier", "fleet",
        "--subject", "acme", "--nodes", "5", "--expires", FUTURE,
      ],
      out: new StringWritable(),
      err: new StringWritable(),
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
    });

    // Unverified list: NO passphrase / recovery key.
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: ["list", "--fortress", fortressPath],
      out,
      err,
      env: {},
    });
    expect(code).toBe(0); // a read is allowed
    // The entry is shown (usable read) but LOUDLY labeled UNVERIFIED, and it
    // NEVER claims the ledger is valid/verified.
    expect(out.text).toContain("acme");
    expect(out.text).toMatch(/UNVERIFIED/);
    expect(out.text).not.toMatch(/\bvalid\b/i);
    expect(out.text).not.toMatch(/\bverified\b/i);

    // --json unverified: the document is explicitly marked verified:false.
    const jsonOut = new StringWritable();
    const jsonErr = new StringWritable();
    const jsonCode = await runLicenseCommand({
      argv: ["list", "--fortress", fortressPath, "--json"],
      out: jsonOut,
      err: jsonErr,
      env: {},
    });
    expect(jsonCode).toBe(0);
    const doc = JSON.parse(jsonOut.text) as { verified: boolean; entries: unknown[] };
    expect(doc.verified).toBe(false);
    expect(doc.entries).toHaveLength(1);
    expect(jsonErr.text).toMatch(/UNVERIFIED/);
  });

  it("VERIFIED list of a whole-ledger substitution under an ATTACKER keypair → tampered + exit ≠ 0", async () => {
    const fortressPath = join(tmp, "f2");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;
    const env = { SANCTUARY_RECOVERY_KEY: recoveryKey };

    // Issue a real license so the anchor advances to generation 1.
    await runLicenseCommand({
      argv: [
        "issue", "--fortress", fortressPath, "--tier", "fleet",
        "--subject", "victim", "--nodes", "5", "--expires", FUTURE,
      ],
      out: new StringWritable(),
      err: new StringWritable(),
      env,
    });

    // The attacker replaces the ledger file WHOLESALE with a self-consistent
    // ledger they built under their OWN keypair (forging an enterprise/unlimited
    // grant). Every signature inside it is valid — under the ATTACKER key. The
    // old self-cert bug would trust the file's own `issuerPublicKey`; the fix
    // pins the operator key from the fortress, so the attacker key ≠ pinned key.
    const { generateKeypair, generateIdentityId } = await import(
      "../../src/core/identity.js"
    );
    const { ed25519 } = await import("@noble/curves/ed25519");
    const {
      appendRow,
      emptyLedger,
      issueLicense,
    } = await import("../../src/entitlement/ledger.js");
    const { saveLedger } = await import("../../src/entitlement/ledger-io.js");
    const attacker = generateKeypair();
    const attackerId = generateIdentityId(attacker.publicKey);
    const attackerSign = (m: Uint8Array): Uint8Array =>
      ed25519.sign(m, attacker.privateKey);
    const { row } = issueLicense(
      {
        licenseId: "attacker-forged",
        subject: "attacker",
        tier: "enterprise",
        pricingUnit: "fleet",
        entitledCount: null,
        period: "annual",
        notBefore: Math.floor(Date.now() / 1000),
        notAfter: Math.floor(Date.parse(FUTURE) / 1000),
        graceUntil: null,
        featureFlags: ["roster", "policy-dist"],
        issuer: attackerId,
      },
      attackerSign,
      Math.floor(Date.now() / 1000),
    );
    const forged = appendRow(emptyLedger(), row, attackerSign, attacker.publicKey, 99);
    const ledgerPath = join(fortressPath, "state", "fleet-license-ledger.json");
    await saveLedger(ledgerPath, forged);

    // Verified list must report tampered and exit non-zero (pinned key mismatch).
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: ["list", "--fortress", fortressPath],
      out,
      err,
      env,
    });
    expect(code).toBe(1);
    expect(err.text).toMatch(/FAILED its integrity\/freshness check|TAMPERED/);
    expect(out.text).not.toContain("attacker");
  });

  it("VERIFIED list of an OLD genuine snapshot (rolled back below the anchor) → tampered + exit ≠ 0", async () => {
    const fortressPath = join(tmp, "f3");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;
    const env = { SANCTUARY_RECOVERY_KEY: recoveryKey };
    const ledgerPath = join(fortressPath, "state", "fleet-license-ledger.json");

    // Issue #1 → ledger + anchor at generation 1. Snapshot the genuine file.
    await runLicenseCommand({
      argv: [
        "issue", "--fortress", fortressPath, "--tier", "fleet",
        "--subject", "co-1", "--nodes", "5", "--expires", FUTURE,
      ],
      out: new StringWritable(),
      err: new StringWritable(),
      env,
    });
    const genuineSnapshotGen1 = await readFile(ledgerPath, "utf-8");

    // Issue #2 → ledger + anchor advance to generation 2.
    await runLicenseCommand({
      argv: [
        "issue", "--fortress", fortressPath, "--tier", "fleet",
        "--subject", "co-2", "--nodes", "5", "--expires", FUTURE,
      ],
      out: new StringWritable(),
      err: new StringWritable(),
      env,
    });

    // The attacker restores the GENUINE gen-1 snapshot (e.g. to erase co-2's
    // issuance). Its own signatures are all valid, but its generation (1) is
    // below the external anchor (2) → rollback.
    const { writeFile } = await import("node:fs/promises");
    await writeFile(ledgerPath, genuineSnapshotGen1);

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: ["list", "--fortress", fortressPath],
      out,
      err,
      env,
    });
    expect(code).toBe(1);
    expect(err.text).toMatch(/FAILED its integrity\/freshness check|rollback|TAMPERED/);
    // The stale view (co-1 only, co-2 erased) is NOT rendered as valid.
    expect(out.text).not.toContain("co-1");
  });

  it("CONCURRENT issue: two racing mutations serialize; both rows land, generation is consistent", async () => {
    const fortressPath = join(tmp, "f4");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;
    const env = { SANCTUARY_RECOVERY_KEY: recoveryKey };

    // Fire two `issue` commands concurrently against the same fortress. The
    // advisory lock must serialize them so neither lost-updates the ledger.
    const [c1, c2] = await Promise.all([
      runLicenseCommand({
        argv: [
          "issue", "--fortress", fortressPath, "--tier", "fleet",
          "--subject", "race-a", "--nodes", "5", "--expires", FUTURE,
        ],
        out: new StringWritable(),
        err: new StringWritable(),
        env,
      }),
      runLicenseCommand({
        argv: [
          "issue", "--fortress", fortressPath, "--tier", "fleet",
          "--subject", "race-b", "--nodes", "5", "--expires", FUTURE,
        ],
        out: new StringWritable(),
        err: new StringWritable(),
        env,
      }),
    ]);
    expect(c1).toBe(0);
    expect(c2).toBe(0);

    // BOTH rows must be present (no lost update), and a verified list must pass
    // (chain + anchor consistent, generation == 2).
    const listOut = new StringWritable();
    const listErr = new StringWritable();
    const listCode = await runLicenseCommand({
      argv: ["list", "--fortress", fortressPath, "--json"],
      out: listOut,
      err: listErr,
      env,
    });
    expect(listCode).toBe(0);
    const doc = JSON.parse(listOut.text) as {
      verified: boolean;
      entries: Array<{ subject: string }>;
    };
    expect(doc.verified).toBe(true);
    const subjects = doc.entries.map((e) => e.subject).sort();
    expect(subjects).toEqual(["race-a", "race-b"]);
  });
});
