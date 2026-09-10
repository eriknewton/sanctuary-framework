// fail-before-exempt: fixture-only edit. The shared InstallProbeResult fixture gains the additive vaultProvision observation with the neutral "unknown" value; no assertion changed. The behavior it feeds is proven in test/cli/install.test.ts (repin_trust_anchor fires for unprovisioned and for a not-yet-walled vault).
/**
 * Rung 1 install evidence: the read-only, ambient-env-blind daily-UX probe
 * (`custody_access` / `recovery_factor`) and the plan wiring that surfaces them
 * plus the `restart_and_verify_rung1` human action.
 *
 * The stored-credential reader is injected, so the suite never spawns `security`
 * / `secret-tool` against the operator's keyring, and the probe never reads
 * ambient credential env.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { cp, mkdtemp, rm, mkdir, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  createInstallOps,
  probeCustodyAccess,
  probeStagedRecoveryFile,
  buildAgentInstallPlan,
  type InstallProbeResult,
} from "../../src/cli/install.js";
import { agentGuidedRecoveryOutputPath } from "../../src/wrap/custody-flow.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import {
  CUSTODY_ENVELOPE_KEY,
  establishMaster,
} from "../../src/core/master-custody.js";
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

  it("never reports a recovery factor from an envelope swapped out from under the unlock", async () => {
    // The probe reads the envelope BEFORE any credential is proven. Plant the
    // swap in the window between that read and the unlock: the fortress the
    // credential authenticates (B, no recovery wrap) is not the fortress whose
    // wrap list was read (A, with a recovery wrap). Originally the probe
    // reported `usable` plus A's recovery claim for a fortress it never opened.
    //
    // What is asserted is the PROPERTY, not the mechanism that used to enforce
    // it. The probe no longer compares two of its own reads — that pair is
    // defeated by a swap put back before the second one (see the next test) —
    // and instead reports from the envelope the unlock authenticated. So the
    // answer here is now about B, the fortress actually at this path: this host
    // does hold a credential that opens it, and it carries no recovery factor.
    // A's recovery wrap must not appear in either field.
    await seedFortress(dir, true);
    const swapped = await mkdtemp(join(tmpdir(), "install-probe-swapped-"));
    const OTHER_PASSPHRASE = "a-second-fortress-passphrase-not-a-real-secret";
    try {
      await mkdir(join(swapped, "state"), { recursive: true, mode: 0o700 });
      const otherCustody = await establishMaster({
        storage: new FilesystemStorage(join(swapped, "state")),
        passphrase: OTHER_PASSPHRASE,
        firstRun: { installMode: "headless", mintRecoveryKey: false },
        storagePathHint: swapped,
      });
      otherCustody.masterKey.fill(0);

      const swapOnRead = async (): Promise<PassphraseResult> => {
        // The stored-credential read is the probe's own step between the two
        // envelope reads, so it is the exact seam an attacker's write would
        // race. Swap the whole custody state, then answer with the credential
        // that opens the NEW one.
        await rm(join(dir, "state"), { recursive: true, force: true });
        await cp(join(swapped, "state"), join(dir, "state"), { recursive: true });
        return {
          value: OTHER_PASSPHRASE,
          source: "keychain",
          location: "test-keyring",
        };
      };

      const r = await probeCustodyAccess(
        dir,
        "linux",
        swapOnRead,
        mutationAvailable,
        custodyAbsent,
      );
      expect(r.custodyAccess).toBe("usable");
      // B's answer, not A's. A had a recovery wrap; reporting "unknown" or
      // "present" here would be the original defect in a new spelling.
      expect(r.recoveryFactor).toBe("absent");
    } finally {
      await rm(swapped, { recursive: true, force: true });
    }
  });

  it("reports the AUTHENTICATED envelope's facts when a swap is put back before the recheck", async () => {
    // The swap-then-swap-BACK schedule the previous test cannot reach. The
    // probe's own two reads (the pre-authentication load and the post-unlock
    // recheck) are taken at instants an attacker with write access chooses
    // between, so comparing them proves only that they agree with EACH OTHER.
    // Serve the foreign envelope A to both of those reads and this fortress's
    // real envelope B to everything in between: the comparison passes, and
    // before the fix the probe reported A's recovery wrap for a fortress it
    // authenticated as B. The fix reads the wrap list off the envelope the
    // unlock authenticated, which no later write can substitute.
    await seedFortress(dir, false); // B: this fortress, NO recovery wrap.
    const foreign = await mkdtemp(join(tmpdir(), "install-probe-foreign-"));
    try {
      await mkdir(join(foreign, "state"), { recursive: true, mode: 0o700 });
      const foreignCustody = await establishMaster({
        storage: new FilesystemStorage(join(foreign, "state")),
        passphrase: "a-foreign-fortress-passphrase-not-a-real-secret",
        firstRun: { installMode: "headless", mintRecoveryKey: true },
        storagePathHint: foreign,
      });
      foreignCustody.masterKey.fill(0);
      // A: read BEFORE the spy is installed, or the spy would intercept it.
      const foreignEnvelope = await new FilesystemStorage(
        join(foreign, "state"),
      ).read("_meta", CUSTODY_ENVELOPE_KEY);
      expect(foreignEnvelope).not.toBeNull();

      // Envelope reads inside the authentication window, in order:
      //   1  the probe's own pre-authentication load
      //   2  the resolver's presence read
      //   3  the resolver's verification unlock, before the unwrap
      //   4  the resolver's verification unlock, its own snapshot recheck
      //   5  the probe's authenticating unlock, before the unwrap
      //   6  the probe's authenticating unlock, its own snapshot recheck
      // Read 1 is the copy the pre-fix code compared against, and read 7 (which
      // exists only before the fix) is that comparison's second half. Reads 3-6
      // must see ONE envelope or the unlocks refuse on their own recheck, which
      // is why the swap-back lands after 6 rather than anywhere earlier.
      const ENVELOPE_READS_IN_THE_AUTHENTICATION_WINDOW = 6;
      const realRead = FilesystemStorage.prototype.read;
      let envelopeReads = 0;
      const spy = vi
        .spyOn(FilesystemStorage.prototype, "read")
        .mockImplementation(async function (
          this: FilesystemStorage,
          namespace: string,
          key: string,
        ) {
          if (namespace !== "_meta" || key !== CUSTODY_ENVELOPE_KEY) {
            return realRead.call(this, namespace, key);
          }
          envelopeReads += 1;
          return envelopeReads === 1 ||
            envelopeReads > ENVELOPE_READS_IN_THE_AUTHENTICATION_WINDOW
            ? foreignEnvelope
            : realRead.call(this, namespace, key);
        } as typeof FilesystemStorage.prototype.read);

      try {
        const r = await probeCustodyAccess(
          dir,
          "linux",
          reader({ kind: "value", value: PASSPHRASE }),
          mutationAvailable,
          custodyAbsent,
        );
        // B has no recovery wrap; A has one. Before the fix this read "unknown"
        // from A — a recovery claim about a fortress the probe never opened.
        expect(r.custodyAccess).toBe("usable");
        expect(r.recoveryFactor).toBe("absent");
      } finally {
        spy.mockRestore();
      }
    } finally {
      await rm(foreign, { recursive: true, force: true });
    }
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
      stagedRecoveryFile: "present",
      nodePath: "/usr/bin/node",
      castleWallApp: "not-applicable",
      castleWallBuildSha: null,
      systemExtension: "not-applicable",
      bootService: "not-applicable",
      contentFilter: "not-applicable",
      enforcement: "not-applicable",
      trustAnchor: "not-applicable",
      // Base fixture: this vault carries no wall claim, which is not a claim of
      // protection either. Tests that need one set it explicitly.
      vaultProvision: "unknown",
      operatorTwin: "not-applicable",
      ...over,
    };
  }

  // The staged-file custody instruction must describe an OBSERVED file, not a
  // composed path (register row defect.a73-install-reports-complete-on-
  // unopenable-fortress, staged-file half). "unknown" is its own branch.
  function recoveryAction(
    staged: InstallProbeResult["stagedRecoveryFile"],
  ): string {
    const plan = buildAgentInstallPlan({
      profile: "memory",
      harness: "claude-code",
      fortress: "/tmp/fortress",
      platform: "darwin",
      observed: completeMemoryProbe({ stagedRecoveryFile: staged }),
    });
    const action = plan.operator_actions.find(
      (candidate) => candidate.id === "private_recovery_custody",
    );
    expect(action).toBeDefined();
    return action!.description;
  }

  it("tells the operator to move the staged file only when one exists", () => {
    const description = recoveryAction("present");
    expect(description).toContain("move the staged recovery file at");
    expect(description).toContain("Sanctuary Recovery");
    expect(description).not.toContain("export-passphrase");
  });

  it("names no staged path when there is no staged file", () => {
    const description = recoveryAction("absent");
    expect(description).toContain("staged no recovery file");
    expect(description).toContain("export-passphrase");
    expect(description).not.toContain("Sanctuary Recovery");
  });

  it("says so when the staged file could not be observed", () => {
    const description = recoveryAction("unknown");
    expect(description).toContain("could not be observed");
    expect(description).toContain("Sanctuary Recovery");
    expect(description).toContain("export-passphrase");
  });

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

describe("staged recovery file observation, against the real filesystem", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-staged-recovery-"));
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("distinguishes present, absent, and unknown at the exact staged path", async () => {
    const fortress = join(tmp, "fortress");
    const staged = agentGuidedRecoveryOutputPath(fortress);

    // Nothing staged: the instruction must send the operator to
    // export-passphrase, not to a path that does not exist.
    expect(await probeStagedRecoveryFile(fortress)).toBe("absent");

    await mkdir(join(tmp, "Sanctuary Recovery"), { recursive: true, mode: 0o700 });
    await writeFile(staged, "Recovery key:\n", { mode: 0o600 });
    expect(await probeStagedRecoveryFile(fortress)).toBe("present");

    // A symlink is never "present": moving and deleting it would act on
    // something other than the file the instruction names.
    await rm(staged);
    await symlink(join(tmp, "somewhere-else.txt"), staged);
    expect(await probeStagedRecoveryFile(fortress)).toBe("unknown");

    await rm(staged);
    await mkdir(staged, { mode: 0o700 });
    expect(await probeStagedRecoveryFile(fortress)).toBe("unknown");
  });

  it("reports the staged file from disk through the PRODUCTION probe wiring, with nothing injected", async () => {
    // Wired-consumer test (AGENTS.md rule 4). Every test above injects the
    // observation, so a createInstallOps that returned a hardcoded
    // stagedRecoveryFile would leave all of them green while the shipped
    // install plan told every operator to go move a file that is not there.
    // This one builds the real ops object and asserts the value came off disk.
    //
    // Linux + the memory profile deliberately: it keeps the probe on the
    // branch that spawns no macOS keyring subprocess, and the fortress below
    // has no custody envelope, so the stored-credential read is never reached.
    const fortress = join(tmp, "wired-fortress");
    await mkdir(join(fortress, "state"), { recursive: true, mode: 0o700 });
    const ops = createInstallOps({ platform: "linux", env: {} });
    const probeArgs = {
      profile: "memory" as const,
      harness: "claude-code" as const,
      fortress,
    };

    // Only the custody-access observations are overridden below, and only to
    // reach the completion branch that renders the custody instruction; the
    // stagedRecoveryFile value carried into the plan is the one the production
    // probe just read off disk, which is what this test exists to prove.
    const reachCompletion = (observed: InstallProbeResult): InstallProbeResult => ({
      ...observed,
      // A CI runner has no global `sanctuary` on PATH, so the real probe reports
      // the persistent CLI absent and the plan stops at install_persistent_cli
      // before the completion branch this test needs; pin the toolchain
      // observations too. stagedRecoveryFile is deliberately NOT overridden.
      persistentCli: "present",
      persistentCliPath: "/usr/local/bin/sanctuary",
      packageManagerPath: "/usr/bin/npm",
      nodePath: "/usr/bin/node",
      cooperativeWrap: "present",
      custodyAccess: "usable",
      custodyMutation: "available",
      recoveryFactor: "present",
    });
    const instructions = (observed: InstallProbeResult): string =>
      buildAgentInstallPlan({
        ...probeArgs,
        platform: "linux",
        observed: reachCompletion(observed),
      })
        .operator_actions.map((action) => action.description)
        .join("\n");

    const absent = await ops.probe(probeArgs);
    expect(absent.stagedRecoveryFile).toBe("absent");
    expect(instructions(absent)).toContain("staged no recovery file");

    await mkdir(join(tmp, "Sanctuary Recovery"), { recursive: true, mode: 0o700 });
    await writeFile(agentGuidedRecoveryOutputPath(fortress), "Recovery key:\n", {
      mode: 0o600,
    });

    const present = await ops.probe(probeArgs);
    expect(present.stagedRecoveryFile).toBe("present");
    expect(instructions(present)).toContain(
      agentGuidedRecoveryOutputPath(fortress),
    );
  });
});
