import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { Writable } from "node:stream";

import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { generateRandomKey } from "../../src/core/random.js";
import { toBase64url } from "../../src/core/encoding.js";
import {
  parseCastleWallArgs,
  runProvisionPin,
  runAuditDump,
  runReload,
  runStatus,
} from "../../src/cli/castle-wall.js";
import { runInit } from "../../src/wrap/init.js";

class CaptureStream extends Writable {
  chunks: string[] = [];
  override _write(chunk: unknown, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    this.chunks.push(String(chunk));
    callback();
  }
  text(): string {
    return this.chunks.join("");
  }
}

describe("castle-wall CLI verbs", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function makeFortress() {
    const fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-cw-cli-"));
    tempDirs.push(fortressPath);
    const masterKey = generateRandomKey();
    const recoveryKey = toBase64url(masterKey);
    return { fortressPath, masterKey, recoveryKey };
  }

  function fingerprint(pub: Uint8Array): string {
    return createHash("sha256").update(pub).digest("hex").slice(0, 16);
  }

  it("provision-pin creates keypair files", async () => {
    const { fortressPath } = await makeFortress();
    const out = new CaptureStream();
    const err = new CaptureStream();
    const code = await runProvisionPin({
      out,
      err,
      env: {
        SANCTUARY_STORAGE_PATH: fortressPath,
        SANCTUARY_PASSPHRASE: "test-passphrase",
      },
    });

    expect(code).toBe(0);
    expect(err.text()).toBe("");

    const pubPath = join(fortressPath, "castle-pinned-pubkey.bin");
    const privPath = join(fortressPath, "castle-pinned-privkey.enc");
    const pub = await readFile(pubPath);
    const priv = await readFile(privPath, "utf8");
    const pubStat = await stat(pubPath);

    expect(pub.length).toBe(32);
    expect(priv).toContain("\"alg\":\"aes-256-gcm\"");
    expect((pubStat.mode & 0o777)).toBe(0o600);
    expect(out.text().trim()).toBe(fingerprint(pub));
  });

  it("provision-pin is idempotent", async () => {
    const { fortressPath } = await makeFortress();
    const pubPath = join(fortressPath, "castle-pinned-pubkey.bin");
    const existing = Buffer.from(new Uint8Array(32).fill(7));
    await writeFile(pubPath, existing, { mode: 0o600 });

    const out = new CaptureStream();
    const err = new CaptureStream();
    const code = await runProvisionPin({
      out,
      err,
      env: {
        SANCTUARY_STORAGE_PATH: fortressPath,
        SANCTUARY_PASSPHRASE: "test-passphrase",
      },
    });

    const after = await readFile(pubPath);
    expect(code).toBe(0);
    expect(err.text()).toBe("");
    expect(Buffer.compare(after, existing)).toBe(0);
    expect(out.text()).toContain(fingerprint(existing));
    expect(out.text()).toContain("Pinned key already provisioned");
  });

  it("status with pinned key", async () => {
    const { fortressPath } = await makeFortress();
    const pub = Buffer.from(new Uint8Array(32).fill(3));
    await writeFile(join(fortressPath, "castle-pinned-pubkey.bin"), pub, {
      mode: 0o600,
    });
    const out = new CaptureStream();
    const code = await runStatus({
      out,
      env: { SANCTUARY_STORAGE_PATH: fortressPath },
      platform: "linux",
    });

    expect(code).toBe(0);
    expect(out.text()).toContain(`Pinned key fingerprint: ${fingerprint(pub)}`);
  });

  it("status without pinned key", async () => {
    const { fortressPath } = await makeFortress();
    const out = new CaptureStream();
    const code = await runStatus({
      out,
      env: { SANCTUARY_STORAGE_PATH: fortressPath },
      platform: "linux",
    });

    expect(code).toBe(0);
    expect(out.text()).toContain(
      "No pinned key provisioned. Run: sanctuary castle-wall provision-pin",
    );
  });

  it("status on non-macOS", async () => {
    const { fortressPath } = await makeFortress();
    const out = new CaptureStream();
    const code = await runStatus({
      out,
      env: { SANCTUARY_STORAGE_PATH: fortressPath },
      platform: "linux",
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("Castle Wall sysext: not applicable (non-macOS)");
  });

  it("status with sysext running", async () => {
    const { fortressPath } = await makeFortress();
    const pub = Buffer.from(new Uint8Array(32).fill(9));
    await writeFile(join(fortressPath, "castle-pinned-pubkey.bin"), pub, {
      mode: 0o600,
    });
    const out = new CaptureStream();
    const code = await runStatus({
      out,
      env: { SANCTUARY_STORAGE_PATH: fortressPath },
      platform: "darwin",
      execSyncFn: () =>
        "com.sanctuary.castle-wall [activated enabled] (state: enabled)",
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("Castle Wall sysext: [activated enabled]");
  });

  it("parses approve scope and fortress flags", () => {
    expect(
      parseCastleWallArgs(["request-1", "--scope=session", "--fortress", "/tmp/f"]),
    ).toEqual({
      requestId: "request-1",
      scope: "session",
      fortress: "/tmp/f",
    });
  });

  it("reload is an idempotent no-op when no daemon is running", async () => {
    const { fortressPath } = await makeFortress();
    const out = new CaptureStream();
    const code = await runReload(["--fortress", fortressPath], {
      out,
      platform: "darwin",
    });
    expect(code).toBe(0);
    expect(out.text()).toContain("No Castle Wall daemon running");
  });

  it("audit-dump emits only Castle Wall audit entries", async () => {
    const { fortressPath, masterKey, recoveryKey } = await makeFortress();
    const auditLog = new AuditLog(new FilesystemStorage(join(fortressPath, "state")), masterKey, {
      integrityMode: "lenient",
    });
    await auditLog.append("l1", "egress_allowed", "agent-1", { fortress_id: "f" }, "success");
    await auditLog.append("l2", "broker_secret_read", "agent-1", {}, "success");
    await auditLog.flush();

    const out = new CaptureStream();
    const code = await runAuditDump(["--fortress", fortressPath, "--since", "5m"], {
      out,
      env: {
        SANCTUARY_STORAGE_PATH: fortressPath,
        SANCTUARY_RECOVERY_KEY: recoveryKey,
      },
    });
    expect(code).toBe(0);
    const lines = out.text().trim().split("\n");
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0]!).operation).toBe("egress_allowed");
  });

  it("init auto-provisions the Castle Wall pinned key", async () => {
    const fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-cw-init-"));
    tempDirs.push(fortressPath);

    await runInit({ fortress: fortressPath, noConfirm: true });

    const out = new CaptureStream();
    const code = await runStatus({
      out,
      platform: "linux",
      env: { SANCTUARY_STORAGE_PATH: fortressPath },
    });
    expect(code).toBe(0);
    expect(out.text()).toContain("Pinned key fingerprint:");
  });
});
