import { afterEach, describe, expect, it } from "vitest";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { runDoctorChecks, runDoctorCommand } from "../../src/cli/doctor.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { deriveMasterKey, derivePurposeKey } from "../../src/core/key-derivation.js";
import { stringToBytes } from "../../src/core/encoding.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { createIdentity } from "../../src/core/identity.js";

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
});
