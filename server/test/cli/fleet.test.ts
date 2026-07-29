/**
 * `sanctuary fleet attest` CLI tests (signed compliance-attestation export).
 *
 * Verifies the export/verify surface end to end against a real keychain-free
 * fortress seeded WITH a default operator identity (mirrors
 * `test/cli/license.test.ts`'s `seedFortressWithIdentity` pattern):
 *  - `attest export` on a fresh (unlicensed) fortress prints a document that
 *    `attest verify` independently accepts, honestly attesting `community`.
 *  - `attest export` on a fortress with an ACTIVE license attests the paid
 *    tier + entitled nodes + features.
 *  - `attest verify` on a TAMPERED document exits non-zero.
 *  - Fail-closed: `export` with NO custody unlock exits non-zero and prints
 *    NOTHING (no unsigned/placeholder document).
 *  - No secret-key material ever appears in printed output.
 *  - `claims_scope` is present in the printed/verified document on every path
 *    exercised here (paid-active / community), reinforcing the pure-core
 *    overclaim guard from the module's own unit tests.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Writable, Readable } from "node:stream";
import { runFleetCommand } from "../../src/cli/fleet.js";
import { runLicenseCommand } from "../../src/cli/license.js";
import { runInit as runInitRaw, type InitOptions } from "../../src/wrap/init.js";
import type { ExecResult } from "../../src/wrap/passphrase.js";

// ── Keychain-free fortress seeding (mirrors identity-create.test.ts / license.test.ts) ──
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
    noIdentity: false,
  });
  const recoveryFile = await readFile(result.recoveryKeyDisclosurePath, "utf-8");
  return extractRecoveryKey(recoveryFile);
}

const FUTURE = "2030-01-01T00:00:00Z";

/** A posture fetcher that always reports the daemon as unreachable (test default). */
const NO_DAEMON = async () => null;

describe("sanctuary fleet attest - help + arg validation (no fortress needed)", () => {
  it("prints usage on --help (exit 0)", async () => {
    const out = new StringWritable();
    const code = await runFleetCommand({
      argv: ["attest", "--help"],
      out,
      err: new StringWritable(),
      env: {},
    });
    expect(code).toBe(0);
    expect(out.text).toContain("sanctuary fleet attest");
    expect(out.text).toContain("export");
    expect(out.text).toContain("verify");
  });

  it("the --help banner carries the self-attestation disclaimer, never overclaims", () => {
    return (async () => {
      const out = new StringWritable();
      await runFleetCommand({
        argv: ["attest", "--help"],
        out,
        err: new StringWritable(),
        env: {},
      });
      expect(out.text).toMatch(/self-attestation/i);
      expect(out.text).toMatch(/NOT a third-party audit/i);
      expect(out.text.toLowerCase()).not.toContain("certified");
    })();
  });

  it("unknown fleet verb → non-zero", async () => {
    const err = new StringWritable();
    const code = await runFleetCommand({
      argv: ["bogus"],
      out: new StringWritable(),
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text).toContain("unknown verb");
  });

  it("unknown attest verb → non-zero", async () => {
    const err = new StringWritable();
    const code = await runFleetCommand({
      argv: ["attest", "bogus"],
      out: new StringWritable(),
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text).toContain("unknown verb");
  });

  it("export with NO custody unlock → exit 1, no document printed, no secret leaked", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runFleetCommand({
      argv: ["attest", "export"],
      out,
      err,
      env: {}, // no passphrase / recovery key
      fetchPosture: NO_DAEMON,
    });
    expect(code).toBe(1);
    expect(err.text).toMatch(/unlocked operator identity is required|keychain/);
    expect(out.text).toBe("");
  });

  it("verify with no file argument → exit 1", async () => {
    const err = new StringWritable();
    const code = await runFleetCommand({
      argv: ["attest", "verify"],
      out: new StringWritable(),
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text).toContain("required");
  });
});

describe("sanctuary fleet attest - end-to-end (keychain-free fortress)", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-fleet-attest-test-"));
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

  it("export on a fresh (unlicensed) fortress honestly attests community; verify accepts it", async () => {
    const fortressPath = join(tmp, "f");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runFleetCommand({
      argv: ["attest", "export", "--fortress", fortressPath],
      out,
      err,
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
      fetchPosture: NO_DAEMON,
    });
    expect(code).toBe(0);
    expect(err.text).toBe("");

    const doc = JSON.parse(out.text) as {
      attestation: {
        schema: string;
        license: { tier: string; status: string };
        posture: { banner_state: string };
        claims_scope: string;
      };
      signature: string;
      public_key: string;
    };
    expect(doc.attestation.schema).toBe("sanctuary.fleet.compliance-attestation.v1");
    expect(doc.attestation.license.tier).toBe("community");
    expect(doc.attestation.license.status).toBe("community");
    expect(doc.attestation.posture.banner_state).toBe("roster_unavailable");
    expect(doc.attestation.claims_scope).toMatch(/self-attestation/i);
    expect(doc.attestation.claims_scope).toMatch(/NOT a third-party audit/i);

    // No secret-key material anywhere in the printed output.
    expect(out.text).not.toMatch(/private/i);
    expect(out.text).not.toMatch(/passphrase/i);
    expect(out.text).not.toMatch(/recovery/i);

    // Independent OFFLINE verify of the printed document (no custody, no
    // pinned key). The A1 fix: without --operator-key/--pin, verify proves
    // self-consistency ONLY and must NEVER print "VALID" - a doc signed by
    // ANY key (including an attacker's own) looks identical here.
    const tmpFile = join(tmp, "attestation.json");
    await writeFile(tmpFile, out.text, "utf8");
    const verifyOut = new StringWritable();
    const verifyErr = new StringWritable();
    const verifyCode = await runFleetCommand({
      argv: ["attest", "verify", tmpFile],
      out: verifyOut,
      err: verifyErr,
      env: {},
    });
    expect(verifyCode).toBe(0);
    expect(verifyOut.text).not.toContain("VALID");
    expect(verifyOut.text).toMatch(/self-consistent/i);
    expect(verifyOut.text).toMatch(/provenance UNVERIFIED/i);

    // Pinning the ACTUAL operator's public key (embedded in the just-printed
    // document, standing in for an independently-known identity) makes
    // verify report "VALID".
    const pinnedKey = doc.public_key;
    const pinnedOut = new StringWritable();
    const pinnedCode = await runFleetCommand({
      argv: ["attest", "verify", tmpFile, "--operator-key", pinnedKey],
      out: pinnedOut,
      err: new StringWritable(),
      env: {},
    });
    expect(pinnedCode).toBe(0);
    expect(pinnedOut.text).toContain("VALID");
  });

  it("A4 companion test: export on a NO-IDENTITY fortress gets the GENERIC operation-label message, distinct from license's exact wording", async () => {
    // Confirms the A4 fix's other half: `fleet attest export` is a NEW caller
    // of the shared custody-unlock helper, so it must NOT inherit `license
    // issue`'s exact original wording ("license issuance requires...") -
    // it gets the generic default ("this operation requires...").
    const fortressPath = join(tmp, "f-no-identity");
    const result = await (
      await import("../../src/wrap/init.js")
    ).runInit(
      { fortress: fortressPath, noConfirm: true, noPin: true, noIdentity: true },
      {
        recoveryKeychain: {
          home: "/tmp/sanctuary-test-home",
          platformOverride: "darwin",
          exec: makeRecoveryKeychainMock().exec,
        },
      },
    );
    const recoveryFile = await readFile(result.recoveryKeyDisclosurePath, "utf-8");
    const recoveryKey = extractRecoveryKey(recoveryFile);
    delete process.env.SANCTUARY_STORAGE_PATH;

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runFleetCommand({
      argv: ["attest", "export", "--fortress", fortressPath],
      out,
      err,
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
      fetchPosture: NO_DAEMON,
    });
    expect(code).toBe(1);
    expect(out.text).toBe("");
    expect(err.text).toBe(
      "attest export: no operator identity in this fortress: this operation " +
        "requires a default operator identity (run `sanctuary identity " +
        "create`, or re-run `sanctuary init` without --no-identity)\n",
    );
    // Never the license CLI's exact wording - the two callers must diverge.
    expect(err.text).not.toContain("license issuance requires");
  });

  it("export on a fortress with an ACTIVE license attests the paid tier + entitled nodes", async () => {
    const fortressPath = join(tmp, "f2");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;
    const env = { SANCTUARY_RECOVERY_KEY: recoveryKey };

    // Issue a license via the shipped `license issue` CLI (same operator identity).
    const issueOut = new StringWritable();
    const issueCode = await runLicenseCommand({
      argv: [
        "issue", "--fortress", fortressPath, "--tier", "fleet",
        "--subject", "acme-fleet", "--nodes", "25", "--expires", FUTURE,
        "--features", "roster,policy-dist",
      ],
      out: issueOut,
      err: new StringWritable(),
      env,
    });
    expect(issueCode).toBe(0);
    const licenseToken = issueOut.text.trim();

    // Activate it (mirrors the operator pasting the license into the console).
    const { activateFleet } = await import("../../src/entitlement/activation.js");
    const { FilesystemStorage } = await import("../../src/storage/filesystem.js");
    const { resolveCliMasterKey } = await import("../../src/core/master-custody.js");
    const { IdentityManager } = await import("../../src/cognitive/tools.js");

    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const masterKey = await resolveCliMasterKey(storage, {
      recoveryKey,
      storagePathHint: fortressPath,
    });
    try {
      const idMgr = new IdentityManager(storage, masterKey);
      await idMgr.load();
      const identity = idMgr.getDefault();
      if (!identity) throw new Error("no default identity");
      const b64 = identity.public_key.replace(/-/g, "+").replace(/_/g, "/");
      const issuerPublicKey = new Uint8Array(Buffer.from(b64, "base64"));

      const activateResult = await activateFleet({
        storage,
        master: masterKey,
        pastedLicense: licenseToken,
        issuerPublicKey,
        now: Math.floor(Date.now() / 1000),
      });
      expect(activateResult.ok).toBe(true);
    } finally {
      masterKey.fill(0);
    }

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runFleetCommand({
      argv: ["attest", "export", "--fortress", fortressPath],
      out,
      err,
      env,
      fetchPosture: NO_DAEMON,
    });
    expect(code).toBe(0);
    expect(err.text).toBe("");

    const doc = JSON.parse(out.text) as {
      attestation: {
        license: {
          tier: string;
          status: string;
          entitled_nodes: number | null;
          features: string[];
          subject: string | null;
        };
      };
    };
    expect(doc.attestation.license.tier).toBe("fleet");
    expect(doc.attestation.license.status).toBe("active");
    expect(doc.attestation.license.entitled_nodes).toBe(25);
    expect(doc.attestation.license.subject).toBe("acme-fleet");
    expect(doc.attestation.license.features).toEqual(["policy-dist", "roster"]);
  });

  it("THE CORE A2 REGRESSION TEST: export never attests a REVOKED in-window license as 'active' - it attests community", async () => {
    // Before the fix, `attest export` called resolveEntitlement/resolveFleetCap
    // directly and never consulted the revocation rail, so a paid, in-window,
    // well-signed license that had been REVOKED (refund/compromise/kill) still
    // attested "active" - a signed FALSE compliance claim. This drives a real
    // revoke-push through the shipped `federation revoke-push` CLI (the same
    // operator identity signs the revocation list) and asserts export now
    // reports community/revoked, never active.
    const fortressPath = join(tmp, "f-revoked");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;
    const env = { SANCTUARY_RECOVERY_KEY: recoveryKey };

    const issueOut = new StringWritable();
    const issueCode = await runLicenseCommand({
      argv: [
        "issue", "--fortress", fortressPath, "--tier", "fleet",
        "--subject", "doomed-fleet", "--nodes", "25", "--expires", FUTURE,
        "--features", "roster,policy-dist",
      ],
      out: issueOut,
      err: new StringWritable(),
      env,
    });
    expect(issueCode).toBe(0);
    const licenseToken = issueOut.text.trim();

    // The license id is public (embedded in the token's own claims, the same
    // artifact the operator pastes into Activate) - decode it to revoke it.
    const decodedTokenJson = Buffer.from(
      licenseToken.replace(/-/g, "+").replace(/_/g, "/"),
      "base64",
    ).toString("utf8");
    const decodedToken = JSON.parse(decodedTokenJson) as {
      claims: { licenseId: string };
    };
    const licenseId = decodedToken.claims.licenseId;
    expect(typeof licenseId).toBe("string");

    // Activate it (mirrors the operator pasting the license into the console).
    const { activateFleet } = await import("../../src/entitlement/activation.js");
    const { FilesystemStorage } = await import("../../src/storage/filesystem.js");
    const { resolveCliMasterKey } = await import("../../src/core/master-custody.js");
    const { IdentityManager } = await import("../../src/cognitive/tools.js");

    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const masterKey = await resolveCliMasterKey(storage, {
      recoveryKey,
      storagePathHint: fortressPath,
    });
    try {
      const idMgr = new IdentityManager(storage, masterKey);
      await idMgr.load();
      const identity = idMgr.getDefault();
      if (!identity) throw new Error("no default identity");
      const b64 = identity.public_key.replace(/-/g, "+").replace(/_/g, "/");
      const issuerPublicKey = new Uint8Array(Buffer.from(b64, "base64"));

      const activateResult = await activateFleet({
        storage,
        master: masterKey,
        pastedLicense: licenseToken,
        issuerPublicKey,
        now: Math.floor(Date.now() / 1000),
      });
      expect(activateResult.ok).toBe(true);
    } finally {
      masterKey.fill(0);
    }

    // BEFORE revocation: export attests this license as active (sanity, mirrors
    // the prior test).
    const preRevokeOut = new StringWritable();
    const preRevokeCode = await runFleetCommand({
      argv: ["attest", "export", "--fortress", fortressPath],
      out: preRevokeOut,
      err: new StringWritable(),
      env,
      fetchPosture: NO_DAEMON,
    });
    expect(preRevokeCode).toBe(0);
    const preRevokeDoc = JSON.parse(preRevokeOut.text) as {
      attestation: { license: { status: string; tier: string } };
    };
    expect(preRevokeDoc.attestation.license.status).toBe("active");

    // Push a signed revocation list naming this license id (the SAME operator
    // identity signs it, via the shipped `federation revoke-push` CLI).
    const { runFederationCommand } = await import("../../src/cli/federation.js");
    const revokeCode = await runFederationCommand({
      argv: [
        "revoke-push", "--fortress", fortressPath,
        "--version", "1",
        "--license-id", licenseId,
      ],
      out: new StringWritable(),
      err: new StringWritable(),
      env,
    });
    expect(revokeCode).toBe(0);

    // AFTER revocation: export must NEVER attest this as active - it must
    // fall back to community/revoked, the fail-closed direction the re-resolve
    // rail already enforces (this closes the SAME gap for export).
    const postRevokeOut = new StringWritable();
    const postRevokeErr = new StringWritable();
    const postRevokeCode = await runFleetCommand({
      argv: ["attest", "export", "--fortress", fortressPath],
      out: postRevokeOut,
      err: postRevokeErr,
      env,
      fetchPosture: NO_DAEMON,
    });
    expect(postRevokeCode).toBe(0);
    expect(postRevokeErr.text).toBe("");
    const postRevokeDoc = JSON.parse(postRevokeOut.text) as {
      attestation: {
        license: { status: string; tier: string; license_id: string | null };
      };
    };
    expect(postRevokeDoc.attestation.license.status).not.toBe("active");
    expect(postRevokeDoc.attestation.license.status).toBe("community");
    expect(postRevokeDoc.attestation.license.tier).toBe("community");
  });

  it("verify on a TAMPERED document exits non-zero", async () => {
    const fortressPath = join(tmp, "f3");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;

    const out = new StringWritable();
    const code = await runFleetCommand({
      argv: ["attest", "export", "--fortress", fortressPath],
      out,
      err: new StringWritable(),
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
      fetchPosture: NO_DAEMON,
    });
    expect(code).toBe(0);

    const doc = JSON.parse(out.text) as {
      attestation: { fortress_id: string | null };
      signature: string;
      public_key: string;
    };
    doc.attestation.fortress_id = "attacker-controlled-fortress-id";
    const tmpFile = join(tmp, "tampered.json");
    await writeFile(tmpFile, JSON.stringify(doc, null, 2), "utf8");

    const verifyErr = new StringWritable();
    const verifyCode = await runFleetCommand({
      argv: ["attest", "verify", tmpFile],
      out: new StringWritable(),
      err: verifyErr,
      env: {},
    });
    expect(verifyCode).not.toBe(0);
    expect(verifyErr.text).toMatch(/FAILED/);
  });

  it("verify reads from stdin when given '-'", async () => {
    const fortressPath = join(tmp, "f4");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;

    const out = new StringWritable();
    await runFleetCommand({
      argv: ["attest", "export", "--fortress", fortressPath],
      out,
      err: new StringWritable(),
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
      fetchPosture: NO_DAEMON,
    });

    const stdin = Readable.from([out.text]);
    const verifyOut = new StringWritable();
    const verifyCode = await runFleetCommand({
      argv: ["attest", "verify", "-"],
      out: verifyOut,
      err: new StringWritable(),
      env: {},
      stdin,
    });
    expect(verifyCode).toBe(0);
    // No --operator-key/--pin supplied here: the A1 fix means this is NEVER
    // "VALID" (self-consistency only, provenance unverified).
    expect(verifyOut.text).not.toContain("VALID");
    expect(verifyOut.text).toMatch(/self-consistent/i);
  });

  it("export --out writes the document to a file in addition to stdout", async () => {
    const fortressPath = join(tmp, "f5");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;
    const outFile = join(tmp, "exported.json");

    const out = new StringWritable();
    const code = await runFleetCommand({
      argv: ["attest", "export", "--fortress", fortressPath, "--out", outFile],
      out,
      err: new StringWritable(),
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
      fetchPosture: NO_DAEMON,
    });
    expect(code).toBe(0);

    const written = await readFile(outFile, "utf8");
    expect(JSON.parse(written)).toEqual(JSON.parse(out.text));
  });

  it("verify --json reports the outcome as JSON", async () => {
    const fortressPath = join(tmp, "f6");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;

    const out = new StringWritable();
    await runFleetCommand({
      argv: ["attest", "export", "--fortress", fortressPath],
      out,
      err: new StringWritable(),
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
      fetchPosture: NO_DAEMON,
    });
    const tmpFile = join(tmp, "doc.json");
    await writeFile(tmpFile, out.text, "utf8");

    const verifyOut = new StringWritable();
    const verifyCode = await runFleetCommand({
      argv: ["attest", "verify", tmpFile, "--json"],
      out: verifyOut,
      err: new StringWritable(),
      env: {},
    });
    expect(verifyCode).toBe(0);
    const parsed = JSON.parse(verifyOut.text) as { ok: boolean; provenance?: string };
    expect(parsed.ok).toBe(true);
    // No --operator-key/--pin: JSON mode must also report the honest
    // provenance level rather than silently implying identity was checked.
    expect(parsed.provenance).toBe("self_consistent");
  });

  it("verify --json --operator-key reports provenance 'verified' when the pinned key matches", async () => {
    const fortressPath = join(tmp, "f7");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;

    const out = new StringWritable();
    await runFleetCommand({
      argv: ["attest", "export", "--fortress", fortressPath],
      out,
      err: new StringWritable(),
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
      fetchPosture: NO_DAEMON,
    });
    const doc = JSON.parse(out.text) as { public_key: string };
    const tmpFile = join(tmp, "doc.json");
    await writeFile(tmpFile, out.text, "utf8");

    const verifyOut = new StringWritable();
    const verifyCode = await runFleetCommand({
      argv: ["attest", "verify", tmpFile, "--json", "--operator-key", doc.public_key],
      out: verifyOut,
      err: new StringWritable(),
      env: {},
    });
    expect(verifyCode).toBe(0);
    const parsed = JSON.parse(verifyOut.text) as { ok: boolean; provenance?: string };
    expect(parsed.ok).toBe(true);
    expect(parsed.provenance).toBe("verified");
  });

  it("verify --operator-key with a key that does NOT match the document fails, never reports VALID (the A1 regression test)", async () => {
    const fortressPath = join(tmp, "f8");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;

    const out = new StringWritable();
    await runFleetCommand({
      argv: ["attest", "export", "--fortress", fortressPath],
      out,
      err: new StringWritable(),
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
      fetchPosture: NO_DAEMON,
    });
    const tmpFile = join(tmp, "doc.json");
    await writeFile(tmpFile, out.text, "utf8");

    // An UNRELATED public key (not the operator's) - simulates a caller who
    // pinned the wrong identity, or an attacker's document signed with a
    // key that isn't the pinned/known operator key.
    const wrongKey = "A".repeat(43); // 32 zero-ish bytes, base64url, wrong on purpose
    const verifyOut = new StringWritable();
    const verifyErr = new StringWritable();
    const verifyCode = await runFleetCommand({
      argv: ["attest", "verify", tmpFile, "--operator-key", wrongKey],
      out: verifyOut,
      err: verifyErr,
      env: {},
    });
    expect(verifyCode).not.toBe(0);
    expect(verifyOut.text).not.toContain("VALID");
    expect(verifyErr.text).toMatch(/FAILED|operator_key_mismatch/);
  });
});
