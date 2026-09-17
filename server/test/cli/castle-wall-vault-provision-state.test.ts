// fail-before-exempt: current change only initializes custody for the existing confirmed-gate fixture, preserving its unchanged helper-call assertion. Enrolled-custody re-pin behavior is covered by castle-wall-repin-custody.test.ts.
/**
 * The vault-level Castle Wall state, and the confirmation gate on the one verb
 * that moves this machine's trust anchor.
 *
 * Capability the tests below pin (register row
 * defect.a73-default-init-fails-on-pre-existing-global-pin):
 *
 *   1. Whether a vault is on this machine's Castle Wall is a claim about the
 *      VAULT, and it is answered from one derivation: a surface reports
 *      "walled" only when it has positively observed both the machine's
 *      trust-anchor verdict and this vault's own arming.
 *   2. `doctor`, `castle-wall status`, the `sanctuary status` table, and the
 *      agent-guided install planner each render that state, and none of them
 *      reports a vault as protected on the strength of machine-wide facts.
 *   3. `castle-wall re-pin` runs only from an interactive terminal with a typed
 *      confirmation, and a refusal moves nothing.
 *
 * Isolation: every fortress is a per-test temp directory and every machine-wide
 * path is a temp path. Nothing here reads or writes the real machine-wide
 * anchor, the operator's login keychain, or a real `~/.sanctuary`.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Readable, Writable } from "node:stream";

import {
  CASTLE_WALL_NOT_YET_WALLED,
  CASTLE_WALL_PROVISION_META_KEY,
  castleWallProvisionRecordPath,
  deriveCastleWallProvision,
  readPersistedCastleWallProvision,
} from "../../src/castle-wall/provision-state.js";
import { runRePin, runStatus } from "../../src/cli/castle-wall.js";
import { runDoctorChecks } from "../../src/cli/doctor.js";
import { renderTable } from "../../src/cli/status.js";
import { classifyMetaKey } from "../../src/core/master-rotation.js";
import { initializeTestCustody } from "../helpers/custody-fixture.js";

/** Collect a CLI writable's output. */
function capture(chunks: string[]): Writable {
  return new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(chunk.toString());
      callback();
    },
  });
}

const silent = (): Writable =>
  new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  });

/** Write the vault-level claim the way `init` writes it. */
async function plantNotYetWalled(fortressPath: string): Promise<void> {
  await mkdir(join(fortressPath, "state", "_meta"), { recursive: true, mode: 0o700 });
  await writeFile(castleWallProvisionRecordPath(fortressPath), CASTLE_WALL_NOT_YET_WALLED, {
    mode: 0o600,
  });
}

describe("the vault-level wall state has ONE derivation", () => {
  it("reports walled only from BOTH halves, positively observed", () => {
    expect(deriveCastleWallProvision({ trustAnchor: "consistent", armed: true })).toBe(
      "walled",
    );
    // Either half missing, unknown, or negative keeps the vault's own claim.
    expect(deriveCastleWallProvision({ trustAnchor: "consistent", armed: false })).toBe(
      "not_yet_walled",
    );
    expect(
      deriveCastleWallProvision({ trustAnchor: "consistent", armed: "unknown" }),
    ).toBe("not_yet_walled");
    expect(deriveCastleWallProvision({ trustAnchor: "unknown", armed: true })).toBe(
      "not_yet_walled",
    );
    expect(deriveCastleWallProvision({ trustAnchor: "broken", armed: true })).toBe(
      "not_yet_walled",
    );
    expect(
      deriveCastleWallProvision({ trustAnchor: "unprovisioned", armed: true }),
    ).toBe("not_yet_walled");
  });

  it("keeps master rotation able to carry the at-rest record", () => {
    // A `_meta` key rotation does not recognize makes master rotation refuse
    // every fortress that carries it, so this key and its classification are
    // pinned together with the writer.
    expect(classifyMetaKey(CASTLE_WALL_PROVISION_META_KEY)).toBe("plaintext-keep");
  });
});

describe("the vault-level wall state is readable, and never guessed", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-vault-provision-"));
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("distinguishes a claim, no claim, and a claim it could not read", async () => {
    const claimed = join(tmp, "claimed");
    await plantNotYetWalled(claimed);
    await expect(readPersistedCastleWallProvision(claimed)).resolves.toEqual({
      state: "not-yet-walled",
    });

    // A fortress that predates the state makes no claim either way.
    await expect(readPersistedCastleWallProvision(join(tmp, "nothing"))).resolves.toEqual(
      { state: "absent" },
    );

    // Content that is not a state token is missing information, never a pass.
    const garbled = join(tmp, "garbled");
    await mkdir(join(garbled, "state", "_meta"), { recursive: true, mode: 0o700 });
    await writeFile(castleWallProvisionRecordPath(garbled), "walled-ish", { mode: 0o600 });
    await expect(readPersistedCastleWallProvision(garbled)).resolves.toEqual({
      state: "unreadable",
    });
  });

  it("keeps doctor from reporting a leftover machine-wide extension as this vault's protection", async () => {
    const fortressPath = join(tmp, "not-on-the-wall");
    await plantNotYetWalled(fortressPath);

    // The exact host shape: a Mac armed by an EARLIER install still lists an
    // enabled Castle Wall extension, and the vault in front of the operator is
    // on no wall at all.
    const activated = () =>
      "ai.sanctuaryprotocol.macos.castle-wall (1.0/42)\tCastle Wall\t[activated enabled]";
    const checks = await runDoctorChecks({
      storagePath: fortressPath,
      env: {},
      platform: "darwin",
      execSyncFn: activated,
    });
    const wall = checks.find((check) => check.name === "castle wall sysext");
    expect(wall).toBeDefined();
    expect(wall!.status).toBe("WARN");
    expect(wall!.message).toContain(CASTLE_WALL_NOT_YET_WALLED);

    // A fortress that makes no claim is judged exactly as it was before.
    const unclaimed = await runDoctorChecks({
      storagePath: join(tmp, "no-claim"),
      env: {},
      platform: "darwin",
      execSyncFn: activated,
    });
    expect(
      unclaimed.find((check) => check.name === "castle wall sysext")!.status,
    ).toBe("OK");
  });

  it("never reports OK from machine evidence when the vault claim exists and does not parse", async () => {
    // Every one of these is a record that EXISTS at the claim's path. Absent is
    // a different fact and is covered by its own case below; these four are
    // "there is a claim here and I cannot read it", which AGENTS.md rule 1
    // makes not-proven. Before this, all four fell into the absent path and
    // doctor reported OK from `[activated enabled]` alone — on a host whose
    // enabled extension belongs to an EARLIER install.
    const corrupted: Array<[string, string]> = [
      ["empty", ""],
      ["whitespace only", "   \n"],
      ["unparseable", "\u0000\u0001binary-garbage"],
      ["wrong type", "walled"],
    ];
    const activated = () =>
      "ai.sanctuaryprotocol.macos.castle-wall (1.0/42)\tCastle Wall\t[activated enabled]";

    for (const [label, contents] of corrupted) {
      const fortressPath = join(tmp, `corrupt-${label.replace(/\s+/g, "-")}`);
      await mkdir(join(fortressPath, "state", "_meta"), { recursive: true, mode: 0o700 });
      await writeFile(castleWallProvisionRecordPath(fortressPath), contents, {
        mode: 0o600,
      });
      await expect(readPersistedCastleWallProvision(fortressPath)).resolves.toEqual({
        state: "unreadable",
      });

      const checks = await runDoctorChecks({
        storagePath: fortressPath,
        env: {},
        platform: "darwin",
        execSyncFn: activated,
      });
      const wall = checks.find((check) => check.name === "castle wall sysext");
      expect(wall, label).toBeDefined();
      expect(wall!.status, label).toBe("WARN");
      expect(wall!.message, label).toContain("unreadable");
    }
  });

  it("keeps a fortress with NO claim from reading as a vault-level protection claim", async () => {
    // `absent` is honest: this fortress predates the state, and doctor observes
    // neither half of the `walled` pair, so the machine's own extension state
    // is all it may report. The OK line therefore has to SAY that, or a reader
    // takes a green line about a system extension as an answer about a vault.
    const checks = await runDoctorChecks({
      storagePath: join(tmp, "no-claim-at-all"),
      env: {},
      platform: "darwin",
      execSyncFn: () =>
        "ai.sanctuaryprotocol.macos.castle-wall (1.0/42)\tCastle Wall\t[activated enabled]",
    });
    const wall = checks.find((check) => check.name === "castle wall sysext")!;
    expect(wall.status).toBe("OK");
    expect(wall.message).toContain("machine-level");
    expect(wall.message).toContain("no vault-level protection is asserted");
  });

  it("prints an unreadable claim on castle-wall status, not silence", async () => {
    // Silence here reads as "this fortress makes no claim", which is a
    // different and more reassuring fact than "there is a claim and I cannot
    // read it". `doctor` sends the operator to this surface, so it has to say
    // the same thing doctor just said.
    const fortressPath = join(tmp, "status-unreadable");
    await mkdir(join(fortressPath, "state", "_meta"), { recursive: true, mode: 0o700 });
    await writeFile(castleWallProvisionRecordPath(fortressPath), "walled", { mode: 0o600 });

    const chunks: string[] = [];
    await runStatus([], {
      out: capture(chunks),
      err: silent(),
      env: { SANCTUARY_STORAGE_PATH: fortressPath },
      platform: "linux",
    });
    expect(chunks.join("")).toContain("Vault wall provisioning: unreadable");
  });

  it("prints the state on castle-wall status, without touching the parsed verdict lines", async () => {
    const fortressPath = join(tmp, "status-fortress");
    await plantNotYetWalled(fortressPath);

    const chunks: string[] = [];
    await runStatus([], {
      out: capture(chunks),
      err: silent(),
      env: { SANCTUARY_STORAGE_PATH: fortressPath },
      platform: "linux",
    });
    const text = chunks.join("");
    expect(text).toContain(`Vault wall provisioning: ${CASTLE_WALL_NOT_YET_WALLED}`);
    // The three authoritative trust-anchor lines the install planner parses
    // byte-for-byte must stay unique to the anchor verdict.
    expect(text).not.toContain("Trust anchor: no global pin provisioned");
  });

  it("renders the state in the sanctuary status table only when the document carries it", () => {
    expect(
      renderTable({
        ok: true,
        castle_wall: { arm_state: "unknown", castle_wall_provision: "not_yet_walled" },
      }),
    ).toContain("vault on wall: not_yet_walled");
    // A document without the field renders exactly as it did before.
    expect(renderTable({ ok: true, castle_wall: { arm_state: "armed" } })).not.toContain(
      "vault on wall",
    );
  });
});

describe("castle-wall re-pin is operator-present, in code", () => {
  it("refuses a non-interactive caller and moves nothing", async () => {
    // The callers this defends against are non-interactive by construction:
    // wrap's auto-provision hands its children a black-hole stdin, the install
    // planner executes an argv, and a headless enable never prompts. An agent
    // holding a pty that types the confirmation is operator-equivalent and is
    // deliberately out of scope.
    let installPinCalls = 0;
    const chunks: string[] = [];
    const code = await runRePin([], {
      out: silent(),
      err: capture(chunks),
      env: { SANCTUARY_STORAGE_PATH: "/nonexistent-fortress" },
      platform: "darwin",
      signerClientInvoke: async (_args: string[], _stdin: Uint8Array | null) => {
        installPinCalls += 1;
        return { stdout: "", stderr: "", code: 0 };
      },
    });

    expect(code).toBe(1);
    // Nothing was asked of the signer helper, so the anchor cannot have moved.
    expect(installPinCalls).toBe(0);
    const text = chunks.join("");
    expect(text).toContain("requires an interactive terminal");
    expect(text).toContain("no flag or environment variable that skips this");
  });

  it("aborts on any answer that is not the confirmation word", async () => {
    let installPinCalls = 0;
    const chunks: string[] = [];
    const code = await runRePin([], {
      out: silent(),
      err: capture(chunks),
      env: { SANCTUARY_STORAGE_PATH: "/nonexistent-fortress" },
      platform: "darwin",
      confirmStdin: Readable.from(["y\n"]),
      signerClientInvoke: async (_args: string[], _stdin: Uint8Array | null) => {
        installPinCalls += 1;
        return { stdout: "", stderr: "", code: 0 };
      },
    });

    expect(code).toBe(1);
    expect(installPinCalls).toBe(0);
    expect(chunks.join("")).toContain("Aborted: the trust anchor was not moved.");
  });

  it("proceeds past the gate when the operator types the confirmation", async () => {
    // Past the gate is all this asserts: the migration itself needs a real
    // signer helper, so the proof here is that the gate stopped refusing and
    // the helper was actually asked.
    const fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-repin-confirmed-"));
    try {
      const passphrase = "test-confirmed-repin-passphrase";
      await initializeTestCustody(fortressPath, { passphrase });
      let installPinCalls = 0;
      const code = await runRePin([], {
        out: silent(),
        err: silent(),
        env: {
          SANCTUARY_STORAGE_PATH: fortressPath,
          SANCTUARY_PASSPHRASE: passphrase,
        },
        platform: "darwin",
        confirmStdin: Readable.from(["re-pin\n"]),
        signerClientInvoke: async (_args: string[], _stdin: Uint8Array | null) => {
          installPinCalls += 1;
          return { stdout: "", stderr: "helper unavailable in this test", code: 1 };
        },
      });

      expect(installPinCalls).toBeGreaterThan(0);
      expect(code).toBe(1);
    } finally {
      await rm(fortressPath, { recursive: true, force: true });
    }
  });
});
