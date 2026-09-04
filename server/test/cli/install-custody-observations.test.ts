/**
 * Rung 1 install evidence: the read-only, ambient-env-blind daily-UX probe
 * (`custody_access` / `recovery_factor`) and the plan wiring that surfaces them
 * plus the `restart_and_verify_rung1` human action.
 *
 * The stored-credential reader is injected, so the suite never spawns `security`
 * / `secret-tool` against the operator's keyring, and the probe never reads
 * ambient credential env.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  probeCustodyAccess,
  buildAgentInstallPlan,
  type InstallProbeResult,
} from "../../src/cli/install.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { establishMaster } from "../../src/core/master-custody.js";
import {
  PassphraseKeyringUnreachableError,
  persistUserProvidedPassphrase,
  type PassphraseResult,
  type PassphraseOptions,
} from "../../src/wrap/passphrase.js";

const PASSPHRASE = "install-probe-correct-horse-not-a-real-secret";

function reader(
  behavior:
    | { kind: "null" }
    | { kind: "value"; value: string }
    | { kind: "locked" },
): (opts?: PassphraseOptions) => Promise<PassphraseResult | null> {
  return async () => {
    if (behavior.kind === "locked") {
      throw new PassphraseKeyringUnreachableError("macOS Keychain", "locked");
    }
    if (behavior.kind === "null") return null;
    return { value: behavior.value, source: "keychain", location: "test-keyring" };
  };
}

const custodyAbsent = async () => ({ status: "not-found" as const });
const mutationAvailable = async () => ({
  available: true as const,
  command: "process-owned-unix-domain-socket",
});

async function seedFortress(dir: string, mintRecoveryKey: boolean): Promise<void> {
  await mkdir(join(dir, "state"), { recursive: true, mode: 0o700 });
  const storage = new FilesystemStorage(join(dir, "state"));
  const custody = await establishMaster({
    storage,
    passphrase: PASSPHRASE,
    firstRun: { installMode: "headless", mintRecoveryKey },
    storagePathHint: dir,
  });
  custody.masterKey.fill(0);
}

async function seedKeychainFortress(
  dir: string,
  keychainKey: Uint8Array,
): Promise<void> {
  await mkdir(join(dir, "state"), { recursive: true, mode: 0o700 });
  const storage = new FilesystemStorage(join(dir, "state"));
  const custody = await establishMaster({
    storage,
    keychainKey,
    firstRun: { installMode: "interactive", mintRecoveryKey: true },
    storagePathHint: dir,
  });
  custody.masterKey.fill(0);
}

describe("probeCustodyAccess (Rung 1 daily-UX probe)", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "install-probe-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("virgin fortress: missing / absent", async () => {
    await mkdir(join(dir, "state"), { recursive: true });
    const r = await probeCustodyAccess(
      dir,
      "linux",
      reader({ kind: "null" }),
      undefined,
      custodyAbsent,
    );
    expect(r.custodyAccess).toBe("missing");
    expect(r.recoveryFactor).toBe("absent");
  });

  it("copied host (envelope, no stored credential): absent / recovery UNKNOWN (unauthenticated)", async () => {
    // Without a credential the probe cannot MAC-verify the envelope, so it must
    // NOT trust the wrap list — recovery_factor is unknown, never a claim
    // (AGENTS.md rule 7). custody_access is absent (no stored credential here).
    await seedFortress(dir, true);
    const r = await probeCustodyAccess(
      dir,
      "linux",
      reader({ kind: "null" }),
      undefined,
      custodyAbsent,
    );
    expect(r.custodyAccess).toBe("absent");
    expect(r.recoveryFactor).toBe("unknown");
  });

  it("does not mistake an ambient operator passphrase for unattended readiness", async () => {
    await seedFortress(dir, true);
    const prior = process.env.SANCTUARY_PASSPHRASE;
    process.env.SANCTUARY_PASSPHRASE = PASSPHRASE;
    try {
      const r = await probeCustodyAccess(
        dir,
        "linux",
        reader({ kind: "null" }),
        mutationAvailable,
        custodyAbsent,
      );
      expect(r).toEqual({
        custodyAccess: "absent",
        custodyMutation: "available",
        recoveryFactor: "unknown",
      });
    } finally {
      if (prior === undefined) delete process.env.SANCTUARY_PASSPHRASE;
      else process.env.SANCTUARY_PASSPHRASE = prior;
    }
  });

  it("locked keyring: locked", async () => {
    await seedFortress(dir, true);
    const r = await probeCustodyAccess(
      dir,
      "linux",
      reader({ kind: "locked" }),
      undefined,
      custodyAbsent,
    );
    expect(r.custodyAccess).toBe("locked");
  });

  it("usable: the stored credential opens the fortress", async () => {
    await seedFortress(dir, true);
    const r = await probeCustodyAccess(
      dir,
      "linux",
      reader({ kind: "value", value: PASSPHRASE }),
      mutationAvailable,
      custodyAbsent,
    );
    expect(r.custodyAccess).toBe("usable");
    expect(r.custodyMutation).toBe("available");
    expect(r.recoveryFactor).toBe("unknown");
  });

  it("never reports usable when the authoritative custody sentinel is missing", async () => {
    await seedFortress(dir, true);
    const storage = new FilesystemStorage(join(dir, "state"));
    await storage.delete("_meta", "custody-sentinel");
    const r = await probeCustodyAccess(
      dir,
      "linux",
      reader({ kind: "value", value: PASSPHRASE }),
      mutationAvailable,
      custodyAbsent,
    );
    expect(r).toEqual({
      custodyAccess: "unknown",
      custodyMutation: "available",
      recoveryFactor: "unknown",
    });
  });

  it("never reports usable while a rotation journal blocks runtime unlock", async () => {
    await seedFortress(dir, true);
    const storage = new FilesystemStorage(join(dir, "state"));
    await storage.write("_meta", "rotation-journal", Buffer.from("pending"));
    const r = await probeCustodyAccess(
      dir,
      "linux",
      reader({ kind: "value", value: PASSPHRASE }),
      mutationAvailable,
      custodyAbsent,
    );
    expect(r).toEqual({
      custodyAccess: "unknown",
      custodyMutation: "available",
      recoveryFactor: "unknown",
    });
  });

  it("recognizes and scrubs the custody-key factor enrolled by interactive init", async () => {
    const keychainKey = new Uint8Array(32).fill(0x61);
    await seedKeychainFortress(dir, keychainKey);
    const observed = keychainKey.slice();
    const r = await probeCustodyAccess(
      dir,
      "linux",
      reader({ kind: "null" }),
      mutationAvailable,
      async () => ({ status: "found", key: observed }),
    );
    expect(r).toEqual({
      custodyAccess: "usable",
      custodyMutation: "available",
      recoveryFactor: "unknown",
    });
    expect([...observed]).toEqual(new Array(32).fill(0));
    keychainKey.fill(0);
  });

  it("mismatch: a stored credential that does not open this fortress", async () => {
    await seedFortress(dir, true);
    const r = await probeCustodyAccess(
      dir,
      "linux",
      reader({ kind: "value", value: "wrong" }),
      undefined,
      custodyAbsent,
    );
    expect(r.custodyAccess).toBe("mismatch");
  });

  it("no-recovery fortress: recovery_factor absent", async () => {
    await seedFortress(dir, false);
    const r = await probeCustodyAccess(
      dir,
      "linux",
      reader({ kind: "value", value: PASSPHRASE }),
      mutationAvailable,
      custodyAbsent,
    );
    expect(r.recoveryFactor).toBe("absent");
    expect(r.custodyAccess).toBe("usable");
  });

  it("no OS keyring platform: unavailable custody_access, recovery UNKNOWN (unauthenticated)", async () => {
    // A platform with no OS keyring cannot open custody hands-free, and the probe
    // never authenticated the envelope, so recovery_factor stays unknown.
    await seedFortress(dir, true);
    const r = await probeCustodyAccess(
      dir,
      "win32",
      reader({ kind: "null" }),
      undefined,
      custodyAbsent,
    );
    expect(r.custodyAccess).toBe("unavailable");
    expect(r.recoveryFactor).toBe("unknown");
  });

  it("decryptable Windows fallback reports authenticated access while mutation remains unavailable", async () => {
    await seedFortress(dir, true);
    const persisted = await persistUserProvidedPassphrase(PASSPHRASE, {
      storagePath: dir,
      platformOverride: "win32",
    });
    expect(persisted.source).toBe("fallback-file");
    const r = await probeCustodyAccess(dir, "win32");
    expect(r).toEqual({
      custodyAccess: "usable",
      custodyMutation: "unavailable",
      recoveryFactor: "unknown",
    });
  });

  it("attacker-added plaintext recovery-key wrap cannot flip recovery_factor to present", async () => {
    // Seed a fortress with NO recovery factor, then append a forged
    // { type: "recovery-key" } wrap to the on-disk envelope WITHOUT recomputing
    // the MAC — the exact bare-write tampering AGENTS.md rule 7 warns about.
    await seedFortress(dir, false);
    const storage = new FilesystemStorage(join(dir, "state"));
    const raw = await storage.read("_meta", "custody-envelope");
    expect(raw).not.toBeNull();
    const env = JSON.parse(Buffer.from(raw!).toString("utf8"));
    env.wraps.push({
      id: "forged-recovery-wrap",
      type: "recovery-key",
      verified: true,
      payload: { v: 1, alg: "aes-256-gcm", iv: "AAAA", ct: "AAAA" },
      created_at: new Date().toISOString(),
    });
    await storage.write(
      "_meta",
      "custody-envelope",
      Buffer.from(JSON.stringify(env), "utf8"),
    );
    // Even with the CORRECT stored passphrase, the tampered wrap list fails the
    // envelope MAC, so the probe reports integrity as indeterminate and NEVER
    // mislabels it as a credential mismatch or claims recovery.
    const r = await probeCustodyAccess(
      dir,
      "linux",
      reader({ kind: "value", value: PASSPHRASE }),
      undefined,
      custodyAbsent,
    );
    expect(r.custodyAccess).toBe("unknown");
    expect(r.recoveryFactor).toBe("unknown");
  });
});

describe("buildAgentInstallPlan surfaces Rung 1 evidence and the restart action", () => {
  function completeMemoryProbe(
    over: Partial<InstallProbeResult> = {},
  ): InstallProbeResult {
    return {
      cooperativeWrap: "present",
      persistentCli: "present",
      persistentCliPath: "/usr/local/bin/sanctuary",
      persistentCliVersion: "1.0.0",
      packageManagerPath: "/usr/bin/npm",
      existingCustody: "present",
      custodyAccess: "usable",
      custodyMutation: "available",
      recoveryFactor: "present",
      nodePath: "/usr/bin/node",
      castleWallApp: "not-applicable",
      castleWallBuildSha: null,
      systemExtension: "not-applicable",
      bootService: "not-applicable",
      contentFilter: "not-applicable",
      enforcement: "not-applicable",
      trustAnchor: "not-applicable",
      operatorTwin: "not-applicable",
      ...over,
    };
  }

  it("completes the memory profile and adds restart_and_verify_rung1", () => {
    const plan = buildAgentInstallPlan({
      profile: "memory",
      harness: "claude-code",
      fortress: "/tmp/fortress",
      platform: "linux",
      observed: completeMemoryProbe(),
    });
    expect(plan.status).toBe("complete");
    expect(plan.observations.custody_access).toBe("usable");
    expect(plan.observations.custody_mutation).toBe("available");
    expect(plan.observations.recovery_factor).toBe("present");
    const restart = plan.operator_actions.find(
      (a) => a.id === "restart_and_verify_rung1",
    );
    expect(restart).toBeDefined();
    expect(restart!.actor).toBe("human");
  });

  function plan(over: Partial<InstallProbeResult>) {
    return buildAgentInstallPlan({
      profile: "memory",
      harness: "claude-code",
      fortress: "/tmp/fortress",
      platform: "linux",
      observed: completeMemoryProbe(over),
    });
  }

  it.each(["missing", "unavailable"] as const)(
    "%s custody never marks Rung 1 complete",
    (custodyAccess) => {
      const p = plan({ custodyAccess });
      expect(p.status).toBe("blocked");
      expect(p.operator_actions.some((a) => a.id === "restart_and_verify_rung1")).toBe(false);
    },
  );

  it("locked keyring: human_action -> unlock_local_keyring, not complete", () => {
    const p = plan({ custodyAccess: "locked" });
    expect(p.status).toBe("human_action");
    expect(p.next_action?.id).toBe("unlock_local_keyring");
  });

  it.each(["absent", "mismatch"] as const)(
    "blocks the impossible %s + authenticated-factor composition",
    (custodyAccess) => {
      const p = plan({ custodyAccess, recoveryFactor: "present" });
      expect(p.status).toBe("blocked");
      expect(p.next_action).toBeNull();
      expect(p.notes.join(" ")).toContain("internally inconsistent");
    },
  );

  it("composes the real absent/unknown probe result into an attended attempt", async () => {
    const dir = await mkdtemp(join(tmpdir(), "install-compose-absent-"));
    try {
      await seedFortress(dir, true);
      const observed = await probeCustodyAccess(
        dir,
        "linux",
        reader({ kind: "null" }),
        undefined,
        custodyAbsent,
      );
      expect(observed).toMatchObject({ custodyAccess: "absent", recoveryFactor: "unknown" });
      const p = plan(observed);
      expect(p.status).toBe("human_action");
      expect(p.next_action?.id).toBe("attempt_custody_recovery");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("composes the real mismatch/unknown probe result into an attended attempt", async () => {
    const dir = await mkdtemp(join(tmpdir(), "install-compose-mismatch-"));
    try {
      await seedFortress(dir, true);
      const observed = await probeCustodyAccess(
        dir,
        "linux",
        reader({ kind: "value", value: "wrong" }),
        undefined,
        custodyAbsent,
      );
      expect(observed).toMatchObject({ custodyAccess: "mismatch", recoveryFactor: "unknown" });
      const p = plan(observed);
      expect(p.status).toBe("human_action");
      expect(p.next_action?.id).toBe("attempt_custody_recovery");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("absent + UNKNOWN recovery (real copied-host): attended attempt, never a recovery claim", () => {
    // The common copied-host shape from the live probe: custody could not be
    // authenticated, so recovery is UNPROVEN. Offer a nondestructive attempt
    // and make no factor claim.
    const p = plan({ custodyAccess: "absent", recoveryFactor: "unknown" });
    expect(p.status).toBe("human_action");
    expect(p.next_action?.id).toBe("attempt_custody_recovery");
    expect(p.next_action?.argv).toEqual([
      "sanctuary",
      "reset-passphrase",
      "--mode",
      "recovery-key",
      "--fortress",
      "/tmp/fortress",
    ]);
  });

  it("carries arbitrary fortress paths as structured argv, never shell text", () => {
    const hostilePath = "/tmp/fortress with spaces;$(touch /tmp/never-run)'\"";
    const p = buildAgentInstallPlan({
      profile: "memory",
      harness: "claude-code",
      fortress: hostilePath,
      platform: "linux",
      observed: completeMemoryProbe({
        custodyAccess: "absent",
        recoveryFactor: "unknown",
      }),
    });
    expect(p.next_action?.id).toBe("attempt_custody_recovery");
    expect(p.next_action?.argv).toEqual([
      "sanctuary",
      "reset-passphrase",
      "--mode",
      "recovery-key",
      "--fortress",
      hostilePath,
    ]);
    expect(p.next_action?.description).not.toContain(hostilePath);
  });

  it("absent + AUTHENTICATED no recovery factor: blocked, no supported nondestructive path", () => {
    const p = plan({ custodyAccess: "absent", recoveryFactor: "absent" });
    expect(p.status).toBe("blocked");
    expect(p.next_action).toBeNull();
    expect(p.operator_actions.some((a) => a.id === "attempt_custody_recovery")).toBe(false);
  });

  it("mismatch + unknown recovery (attacker-wrap shape): never the DEFINITIVE recovery path", () => {
    // The MAC-fail shape probeCustodyAccess returns for a tampered wrap list:
    // custody_access=mismatch, recovery_factor=unknown. The planner must never
    // claim an authenticated recovery factor (AGENTS.md rule 7): it may offer
    // only the nondestructive attempt.
    const p = plan({ custodyAccess: "mismatch", recoveryFactor: "unknown" });
    expect(p.status).not.toBe("complete");
    expect(p.next_action?.id).toBe("attempt_custody_recovery");
  });

  it("unknown custody: human_action -> diagnose_custody_access, never a recovery-factor claim", () => {
    const p = plan({ custodyAccess: "unknown", recoveryFactor: "unknown" });
    expect(p.status).toBe("human_action");
    expect(p.next_action?.id).toBe("diagnose_custody_access");
  });

  it("authenticated access stays true while unavailable mutation blocks completion separately", () => {
    const p = plan({ custodyAccess: "usable", custodyMutation: "unavailable" });
    expect(p.status).toBe("blocked");
    expect(p.observations.custody_access).toBe("usable");
    expect(p.observations.custody_mutation).toBe("unavailable");
    expect(p.next_action?.id).toBe("restore_custody_lock_capability");
  });

  it("full profile applies the same real absent/unknown custody gate", () => {
    const p = buildAgentInstallPlan({
      profile: "full",
      harness: "hermes",
      fortress: "/tmp/fortress",
      platform: "darwin",
      observed: completeMemoryProbe({
        persistentCliPath: "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/sanctuary",
        nodePath: "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/sanctuary",
        castleWallApp: "present",
        castleWallBuildSha: "a61a7322ca80",
        systemExtension: "[activated enabled]",
        bootService: "present",
        contentFilter: "enabled",
        enforcement: "live",
        trustAnchor: "consistent",
        operatorTwin: "absent",
        custodyAccess: "absent",
        recoveryFactor: "unknown",
      }),
    });
    expect(p.status).toBe("human_action");
    expect(p.next_action?.id).toBe("attempt_custody_recovery");
  });
});
