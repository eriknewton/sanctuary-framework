import { afterEach, describe, expect, it } from "vitest";
import { chmod, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { runDoctorChecks, runDoctorCommand } from "../../src/cli/doctor.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { migrateFortressAuditStoreSplit } from "../../src/operational/audit-store-split.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { deriveMasterKey, derivePurposeKey } from "../../src/core/key-derivation.js";
import { stringToBytes } from "../../src/core/encoding.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { createIdentity } from "../../src/core/identity.js";
import {
  hermesParityPythonCandidates,
  type SidecarExec,
} from "../../src/wrap/hermes-yaml-parse-parity.js";

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

describe("sanctuary doctor", () => {
  const tempDirs: string[] = [];
  const passphrase = "doctor-secret-passphrase";

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      // maxRetries/retryDelay: a doctor run can leave a brief lingering write
      // in the fortress dir as it settles; without retries the recursive rm
      // intermittently races it and throws ENOTEMPTY on shared CI runners. The
      // retry lets the write finish (Node retries rm on ENOTEMPTY/EBUSY/EPERM).
      await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  async function makeFortress(opts: { identity?: boolean; policy?: "valid" | "invalid"; audit?: boolean } = {}): Promise<string> {
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-doctor-"));
    tempDirs.push(fortress);
    await chmod(fortress, 0o700);
    const storage = new FilesystemStorage(join(fortress, "state"));
    const derived = await deriveMasterKey(passphrase);
    await storage.write("_meta", "key-params", stringToBytes(JSON.stringify(derived.params)));

    if (opts.identity) {
      const identityKey = derivePurposeKey(derived.key, "identity-encryption");
      const { storedIdentity } = createIdentity("doctor-id", identityKey, "passphrase");
      const manager = new IdentityManager(storage, derived.key);
      await manager.save(storedIdentity);
    }

    if (opts.policy === "valid") {
      await writeFile(
        join(fortress, "principal-policy.yaml"),
        `version: 1
tier1_always_approve:
  - identity_sign
approval_channel:
  type: stderr
  timeout_seconds: 300
`,
      );
    } else if (opts.policy === "invalid") {
      await writeFile(join(fortress, "principal-policy.yaml"), "version: 1\n");
    }

    if (opts.audit) {
      const auditLog = new AuditLog(storage, derived.key, { checkpointInterval: 0 });
      await auditLog.appendCritical({
        layer: "l2",
        operation: "state_read",
        identity_id: "agent-a",
        result: "success",
      });
      await auditLog.flush();
    }

    derived.key.fill(0);
    return fortress;
  }

  it("reports OK checks for a healthy fixture and does not print secrets", async () => {
    const fortress = await makeFortress({ identity: true, policy: "valid", audit: true });
    const out = new Capture();
    const code = await runDoctorCommand({
      argv: ["--fortress", fortress],
      out,
      env: { SANCTUARY_PASSPHRASE: passphrase },
      platform: "linux",
    });
    expect(code).toBe(0);
    expect(out.text()).toContain("OK   state dir");
    expect(out.text()).toContain("OK   identity");
    expect(out.text()).toContain("OK   principal policy");
    expect(out.text()).toContain("OK   audit chain");
    expect(out.text()).toContain("n/a (not macOS)");
    expect(out.text()).not.toContain(passphrase);
    expect(out.text()).not.toContain("encrypted_private_key");
  });

  it("emits JSON shape and exits non-zero when checks fail", async () => {
    const fortress = await makeFortress({ policy: "invalid" });
    const out = new Capture();
    const code = await runDoctorCommand({
      argv: ["--fortress", fortress, "--json"],
      out,
      env: {},
      platform: "linux",
    });
    expect(code).toBe(1);
    const parsed = JSON.parse(out.text());
    expect(parsed.storage_path).toBe(fortress);
    expect(parsed.checks.some((check: { status: string }) => check.status === "FAIL")).toBe(true);
    expect(out.text()).not.toContain(passphrase);
  });

  it("covers missing state dir, permissive permissions, missing key, malformed policy, and missing audit", async () => {
    const missing = join(tmpdir(), `sanctuary-missing-${Date.now()}`);
    const missingChecks = await runDoctorChecks({
      storagePath: missing,
      env: {},
      platform: "linux",
    });
    expect(missingChecks.find((check) => check.name === "state dir")?.status).toBe("FAIL");

    const fortress = await makeFortress({ identity: true, policy: "invalid" });
    await chmod(fortress, 0o755);
    const checks = await runDoctorChecks({
      storagePath: fortress,
      env: {},
      platform: "linux",
    });
    expect(checks.find((check) => check.name === "state dir")?.status).toBe("WARN");
    expect(checks.find((check) => check.name === "identity")?.status).toBe("WARN");
    expect(checks.find((check) => check.name === "principal policy")?.status).toBe("FAIL");
    expect(checks.find((check) => check.name === "audit chain")?.status).toBe("FAIL");
  });

  it("reports macOS Castle Wall sysext states", async () => {
    const fortress = await makeFortress({ identity: true, policy: "valid", audit: true });
    const checks = await runDoctorChecks({
      storagePath: fortress,
      env: { SANCTUARY_PASSPHRASE: passphrase },
      platform: "darwin",
      execSyncFn: () => "com.sanctuary.castle-wall [activated waiting for user]",
    });
    const castle = checks.find((check) => check.name === "castle wall sysext");
    expect(castle?.status).toBe("WARN");
    expect(castle?.message).toBe("[activated waiting for user]");
  });

  it("prints help without running checks", async () => {
    const out = new Capture();
    const code = await runDoctorCommand({ argv: ["--help"], out });
    expect(code).toBe(0);
    expect(out.text()).toContain("Usage: sanctuary doctor");
    expect(out.text()).toContain("--json");
  });

  // F2 MEDIUM-1 (adversarial re-gate round 3, 2026-07-14): on a migrated
  // fortress, doctor is an operator health command; when it CAN verify (the
  // master key is available via the passphrase) and finds KNOWN tamper in the
  // sealed legacy region, it must FAIL (exit non-zero), not merely WARN. The
  // routine load skips the sealed region, so this only closes via the
  // chain-aware full-picture verifier doctor now calls.
  it("MEDIUM-1: FAILs (exit non-zero) on a migrated fortress with a tampered sealed entry when it can verify", async () => {
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-doctor-f2-"));
    tempDirs.push(fortress);
    await chmod(fortress, 0o700);
    const statePath = join(fortress, "state");
    const storage = new FilesystemStorage(statePath);
    const derived = await deriveMasterKey(passphrase);
    await storage.write("_meta", "key-params", stringToBytes(JSON.stringify(derived.params)));

    // Pre-split history that will become the sealed prefix.
    const auditLog = new AuditLog(storage, derived.key, { checkpointInterval: 0 });
    for (let i = 0; i < 4; i++) {
      await auditLog.appendCritical({
        layer: "l2",
        operation: `pre-split-${i}`,
        identity_id: "agent-a",
        result: "success",
      });
    }
    await auditLog.flush();
    await migrateFortressAuditStoreSplit({ storage, masterKey: derived.key });

    // Tamper one sealed entry IN PLACE (hash_mismatch, not deletion).
    const auditDir = join(statePath, "_audit");
    const files = (await readdir(auditDir)).filter((f) => f.startsWith("entry-")).sort();
    const target = join(auditDir, files[1]!);
    const raw = JSON.parse(await readFile(target, "utf-8"));
    raw.timestamp = "1999-01-01T00:00:00.000Z";
    await writeFile(target, JSON.stringify(raw));
    derived.key.fill(0);

    // With the passphrase available, doctor CAN verify -> the audit chain FAILs.
    const withKey = await runDoctorChecks({
      storagePath: fortress,
      env: { SANCTUARY_PASSPHRASE: passphrase },
      platform: "linux",
    });
    const chainCheck = withKey.find((c) => c.name === "audit chain");
    expect(chainCheck?.status).toBe("FAIL");

    // The full command exits non-zero.
    const out = new Capture();
    const code = await runDoctorCommand({
      argv: ["--fortress", fortress],
      out,
      env: { SANCTUARY_PASSPHRASE: passphrase },
      platform: "linux",
    });
    expect(code).toBe(1);
    expect(out.text()).toContain("FAIL audit chain");
    expect(out.text()).not.toContain(passphrase);

    // WITHOUT the key it cannot verify: it must WARN (point at audit-store-status), not FAIL.
    const noKey = await runDoctorChecks({
      storagePath: fortress,
      env: {},
      platform: "linux",
    });
    expect(noKey.find((c) => c.name === "audit chain")?.status).toBe("WARN");
  });

  // -- Hermes config parser (PyYAML) --------------------------------------
  //
  // `sudo sanctuary protect --hermes` refuses to touch config.yaml unless a
  // REAL PyYAML parse can be run to check the line scanner against. Before this
  // check the operator found that out only by running protect and watching it
  // stop partway. Every case simulates the host layout through the injected
  // probe exec, so none of them depends on which python on THIS machine happens
  // to carry PyYAML -- the exact coupling that made the first fix attempt pass
  // on a dev Mac and fail on the drill host.

  function probeExec(opts: { withPyYaml: string[]; absent?: string[] }): SidecarExec {
    const withPyYaml = new Set(opts.withPyYaml);
    const absent = new Set(opts.absent ?? []);
    return async (command) => {
      if (absent.has(command)) return { stdout: "", stderr: "", code: null };
      if (withPyYaml.has(command)) {
        return { stdout: JSON.stringify({ hasBlock: false, entryNames: [] }), stderr: "", code: 0 };
      }
      return { stdout: "", stderr: "", code: 20 }; // ran, no PyYAML
    };
  }

  it("hermes config parser: n/a (and spawns nothing) when this host has no Hermes config", async () => {
    const fortress = await makeFortress({ identity: true, policy: "valid" });
    let spawned = 0;
    const checks = await runDoctorChecks({
      storagePath: fortress,
      env: {},
      platform: "linux",
      hermesConfigPath: join(fortress, "definitely-absent", "config.yaml"),
      pyYamlProbe: {
        exec: async () => {
          spawned += 1;
          return { stdout: "", stderr: "", code: 20 };
        },
      },
    });
    const check = checks.find((c) => c.name === "hermes config parser");
    expect(check?.status).toBe("OK");
    expect(check?.message).toContain("n/a");
    expect(spawned).toBe(0);
  });

  it("hermes config parser: THE INVERSE-LAYOUT CASE -- names the later interpreter that can actually import yaml", async () => {
    // The first candidate exists and runs fine; it simply has no PyYAML. A
    // first-EXISTING resolver reports failure here; resolution by capability
    // must walk past it and name the one that works.
    const fortress = await makeFortress({ identity: true, policy: "valid" });
    const hermesConfigPath = join(fortress, "hermes-config.yaml");
    await writeFile(hermesConfigPath, "mcp_servers:\n  weather: {}\n");
    const candidates = hermesParityPythonCandidates();
    const checks = await runDoctorChecks({
      storagePath: fortress,
      env: {},
      platform: "linux",
      hermesConfigPath,
      pyYamlProbe: { exec: probeExec({ withPyYaml: [candidates[2]!] }) },
    });
    const check = checks.find((c) => c.name === "hermes config parser");
    expect(check?.status).toBe("OK");
    expect(check?.message).toContain(candidates[2]!);
    expect(check?.message).not.toContain(candidates[0]!);
  });

  it("hermes config parser: WARNs and names every probed interpreter when none can import yaml", async () => {
    const fortress = await makeFortress({ identity: true, policy: "valid" });
    const hermesConfigPath = join(fortress, "hermes-config.yaml");
    await writeFile(hermesConfigPath, "mcp_servers:\n  weather: {}\n");
    const candidates = hermesParityPythonCandidates();
    const checks = await runDoctorChecks({
      storagePath: fortress,
      env: {},
      platform: "linux",
      hermesConfigPath,
      pyYamlProbe: {
        exec: probeExec({ withPyYaml: [], absent: [candidates[0]!] }),
      },
    });
    const check = checks.find((c) => c.name === "hermes config parser");
    expect(check?.status).toBe("WARN");
    expect(check?.message).toContain("protect --hermes");
    for (const candidate of candidates) {
      expect(check?.hint).toContain(candidate);
    }
    // Per-candidate outcomes, so the remedy is not aimed at a path that is not there.
    expect(check?.hint).toContain("could not be run");
    expect(check?.hint).toContain("ran but cannot import yaml");
  });
});
