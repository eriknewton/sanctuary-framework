import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { Writable } from "node:stream";

import { ed25519 } from "@noble/curves/ed25519";

import {
  AuditLog,
  type PersistedAuditEnvelopeV2,
} from "../../src/l2-operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { generateRandomKey } from "../../src/core/random.js";
import { hashToString } from "../../src/core/hashing.js";
import { bytesToString, stringToBytes, toBase64url } from "../../src/core/encoding.js";
import {
  parseCastleWallArgs,
  runProvisionPin,
  runRePin,
  runAuditDump,
  runAuditFindings,
  runReload,
  runSetupSharedDir,
  runStatus,
  type HostAppInvoker,
} from "../../src/cli/castle-wall.js";
import type { ShimInvoker } from "../../src/castle-wall/runtime/helper-signer.js";
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
    // Faithful legacy fortress: persist the recovery-key-hash marker so the
    // unified custody path (master-custody.ts) recognizes and migrates it.
    // (The pre-custody CLI accepted SANCTUARY_RECOVERY_KEY with no marker at
    // all; that fail-open is gone.)
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    await storage.write(
      "_meta",
      "recovery-key-hash",
      stringToBytes(hashToString(masterKey)),
    );
    return { fortressPath, masterKey, recoveryKey };
  }

  function fingerprint(pub: Uint8Array): string {
    return createHash("sha256").update(pub).digest("hex").slice(0, 16);
  }

  it("provision-pin creates keypair files", async () => {
    const { fortressPath, recoveryKey } = await makeFortress();
    const out = new CaptureStream();
    const err = new CaptureStream();
    const code = await runProvisionPin({
      out,
      err,
      env: {
        SANCTUARY_STORAGE_PATH: fortressPath,
        SANCTUARY_RECOVERY_KEY: recoveryKey,
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
      // Simulate a machine without the host app installed: output must stay
      // exactly as before the content-filter probe existed.
      hostAppCandidates: [],
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("Castle Wall sysext: [activated enabled]");
    expect(out.text()).not.toContain("Content filter:");
  });

  describe("status content-filter probe", () => {
    async function makeDarwinFixture() {
      const { fortressPath } = await makeFortress();
      const hostAppPath = join(fortressPath, "CastleWallHostApp");
      await writeFile(hostAppPath, "#!/bin/sh\n", { mode: 0o755 });
      return { fortressPath, hostAppPath };
    }

    function statusInvoker(response: {
      stdout: string;
      exitCode: number;
      stderr?: string;
    }): { invoke: HostAppInvoker; calls: string[][] } {
      const calls: string[][] = [];
      const invoke: HostAppInvoker = async (binaryPath, args) => {
        calls.push([binaryPath, ...args]);
        return {
          stdout: response.stdout,
          stderr: response.stderr ?? "",
          exitCode: response.exitCode,
        };
      };
      return { invoke, calls };
    }

    it("reports the filter enabled when the host app resolves", async () => {
      const { fortressPath, hostAppPath } = await makeDarwinFixture();
      const out = new CaptureStream();
      const { invoke, calls } = statusInvoker({
        stdout:
          JSON.stringify({ ok: true, action: "status", state: "enabled" }) +
          "\n",
        exitCode: 0,
      });

      const code = await runStatus({
        out,
        env: { SANCTUARY_STORAGE_PATH: fortressPath },
        platform: "darwin",
        execSyncFn: () =>
          "com.sanctuary.castle-wall [activated enabled] (state: enabled)",
        hostAppCandidates: [hostAppPath],
        hostAppInvoke: invoke,
      });

      expect(code).toBe(0);
      expect(out.text()).toContain("Content filter: enabled");
      expect(calls).toEqual([[hostAppPath, "--headless", "status"]]);
    });

    it("reports the filter disabled (sysext installed but not filtering)", async () => {
      const { fortressPath, hostAppPath } = await makeDarwinFixture();
      const out = new CaptureStream();
      const { invoke } = statusInvoker({
        stdout:
          JSON.stringify({ ok: true, action: "status", state: "disabled" }) +
          "\n",
        exitCode: 0,
      });

      const code = await runStatus({
        out,
        env: { SANCTUARY_STORAGE_PATH: fortressPath },
        platform: "darwin",
        execSyncFn: () =>
          "com.sanctuary.castle-wall [activated enabled] (state: enabled)",
        hostAppCandidates: [hostAppPath],
        hostAppInvoke: invoke,
      });

      expect(code).toBe(0);
      expect(out.text()).toContain("Castle Wall sysext: [activated enabled]");
      expect(out.text()).toContain("Content filter: disabled");
    });

    it("reports unknown with the report error on probe failure", async () => {
      const { fortressPath, hostAppPath } = await makeDarwinFixture();
      const out = new CaptureStream();
      const { invoke } = statusInvoker({
        stdout:
          JSON.stringify({
            ok: false,
            action: "status",
            state: "unknown",
            error: "NEFilterManager load failed",
          }) + "\n",
        exitCode: 1,
      });

      const code = await runStatus({
        out,
        env: { SANCTUARY_STORAGE_PATH: fortressPath },
        platform: "darwin",
        execSyncFn: () => "",
        hostAppCandidates: [hostAppPath],
        hostAppInvoke: invoke,
      });

      expect(code).toBe(0);
      expect(out.text()).toContain(
        "Content filter: unknown (NEFilterManager load failed)",
      );
    });

    it("reports unknown with the exit code when output is unparseable", async () => {
      const { fortressPath, hostAppPath } = await makeDarwinFixture();
      const out = new CaptureStream();
      const { invoke } = statusInvoker({
        stdout: "not json\n",
        exitCode: 4,
      });

      const code = await runStatus({
        out,
        env: { SANCTUARY_STORAGE_PATH: fortressPath },
        platform: "darwin",
        execSyncFn: () => "",
        hostAppCandidates: [hostAppPath],
        hostAppInvoke: invoke,
      });

      expect(code).toBe(0);
      expect(out.text()).toContain(
        "Content filter: unknown (host app exited with code 4)",
      );
    });

    it("reports unknown for a non-enabled/disabled state (consent missing)", async () => {
      const { fortressPath, hostAppPath } = await makeDarwinFixture();
      const out = new CaptureStream();
      const { invoke } = statusInvoker({
        stdout:
          JSON.stringify({
            ok: true,
            action: "status",
            state: "needs_user_approval",
          }) + "\n",
        exitCode: 0,
      });

      const code = await runStatus({
        out,
        env: { SANCTUARY_STORAGE_PATH: fortressPath },
        platform: "darwin",
        execSyncFn: () => "",
        hostAppCandidates: [hostAppPath],
        hostAppInvoke: invoke,
      });

      expect(code).toBe(0);
      expect(out.text()).toContain(
        "Content filter: unknown (host app reported state 'needs_user_approval')",
      );
    });

    it("reports unknown when the invoker itself throws", async () => {
      const { fortressPath, hostAppPath } = await makeDarwinFixture();
      const out = new CaptureStream();
      const invoke: HostAppInvoker = async () => {
        throw new Error("spawn EACCES");
      };

      const code = await runStatus({
        out,
        env: { SANCTUARY_STORAGE_PATH: fortressPath },
        platform: "darwin",
        execSyncFn: () => "",
        hostAppCandidates: [hostAppPath],
        hostAppInvoke: invoke,
      });

      expect(code).toBe(0);
      expect(out.text()).toContain("Content filter: unknown (spawn EACCES)");
    });

    it("stays silent on non-macOS even when an invoker is injected", async () => {
      const { fortressPath, hostAppPath } = await makeDarwinFixture();
      const out = new CaptureStream();
      const invoke: HostAppInvoker = async () => {
        throw new Error("must not be invoked off-darwin");
      };

      const code = await runStatus({
        out,
        env: { SANCTUARY_STORAGE_PATH: fortressPath },
        platform: "linux",
        hostAppCandidates: [hostAppPath],
        hostAppInvoke: invoke,
      });

      expect(code).toBe(0);
      expect(out.text()).toContain(
        "Castle Wall sysext: not applicable (non-macOS)",
      );
      expect(out.text()).not.toContain("Content filter:");
    });
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

describe("castle-wall setup-shared-dir", () => {
  it("is a no-op on non-macOS platforms", async () => {
    const out = new CaptureStream();
    const execCommands: string[] = [];
    const code = await runSetupSharedDir({
      out,
      platform: "linux",
      execSyncFn: (command) => {
        execCommands.push(command);
        return "";
      },
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("not applicable");
    expect(execCommands).toEqual([]);
  });

  it("refuses to run unprivileged on macOS", async () => {
    const err = new CaptureStream();
    const execCommands: string[] = [];
    const code = await runSetupSharedDir({
      err,
      platform: "darwin",
      getuid: () => 501,
      execSyncFn: (command) => {
        execCommands.push(command);
        return "";
      },
    });

    expect(code).toBe(1);
    expect(err.text()).toContain("sudo sanctuary castle-wall setup-shared-dir");
    expect(execCommands).toEqual([]);
  });

  it("requires SUDO_USER when running as root", async () => {
    const err = new CaptureStream();
    const code = await runSetupSharedDir({
      err,
      env: {},
      platform: "darwin",
      getuid: () => 0,
    });

    expect(code).toBe(1);
    expect(err.text()).toContain("SUDO_USER unset");
  });

  it("creates the shared dir root-owned (root:wheel), not operator-owned (A2/B2)", async () => {
    const out = new CaptureStream();
    const execCommands: string[] = [];
    const code = await runSetupSharedDir({
      out,
      env: { SUDO_USER: "agentmac" },
      platform: "darwin",
      getuid: () => 0,
      execSyncFn: (command) => {
        execCommands.push(command);
        return "";
      },
    });

    expect(code).toBe(0);
    expect(execCommands).toHaveLength(3);
    expect(execCommands[0]).toContain("mkdir -p");
    expect(execCommands[0]).toContain("/Library/Application Support/Sanctuary");
    // F-A2-1: the custody dir must be root-owned so an operator-UID process
    // cannot unlink + swap the signing key / trust-anchor pin inside it. The
    // operator account name must NOT appear in the chown target.
    expect(execCommands[1]).toContain("chown root:wheel");
    expect(execCommands[1]).not.toContain("agentmac");
    expect(execCommands[1]).not.toContain(":admin");
    expect(execCommands[1]).toContain("/Library/Application Support/Sanctuary");
    expect(execCommands[2]).toContain("chmod 0755");
    expect(execCommands[2]).toContain("/Library/Application Support/Sanctuary");
    expect(out.text()).toContain("/Library/Application Support/Sanctuary");
    expect(out.text()).toContain("Shared dir ready");
  });

  it("rejects shell metacharacters in SUDO_USER", async () => {
    const err = new CaptureStream();
    const execCommands: string[] = [];
    const code = await runSetupSharedDir({
      err,
      env: { SUDO_USER: "bad;rm -rf" },
      platform: "darwin",
      getuid: () => 0,
      execSyncFn: (command) => {
        execCommands.push(command);
        return "";
      },
    });

    expect(code).toBe(1);
    expect(err.text()).toContain("Invalid SUDO_USER");
    expect(execCommands).toEqual([]);
  });
});

describe("castle-wall audit-chain operator override", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function makeFortress() {
    const fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-cw-override-"));
    tempDirs.push(fortressPath);
    const masterKey = generateRandomKey();
    const recoveryKey = toBase64url(masterKey);
    // Faithful legacy fortress: persist the recovery-key-hash marker so the
    // unified custody path (master-custody.ts) recognizes and migrates it.
    // (The pre-custody CLI accepted SANCTUARY_RECOVERY_KEY with no marker at
    // all; that fail-open is gone.)
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    await storage.write(
      "_meta",
      "recovery-key-hash",
      stringToBytes(hashToString(masterKey)),
    );
    return { fortressPath, masterKey, recoveryKey };
  }

  /** Mirrors the re-pin test's mock signer helper (helper key + nonce signing). */
  function makeMockHelper() {
    const seed = ed25519.utils.randomPrivateKey();
    const pub = ed25519.getPublicKey(seed);
    const invoke: ShimInvoker = async (args, stdin) => {
      const mode = args[0];
      if (mode === "get-pubkey" || mode === "re-pin") {
        return { stdout: toBase64url(pub), stderr: "", code: 0 };
      }
      const sig = ed25519.sign(stdin ?? new Uint8Array(0), seed);
      return { stdout: toBase64url(sig), stderr: "", code: 0 };
    };
    return { pub, invoke };
  }

  /**
   * Seed a fortress audit chain that fails integrity verification: append a real
   * critical entry, then corrupt its stored `entry_hash` so a reload reports an
   * `entry_hash_mismatch`. The payload still decrypts, so the entry stays in the
   * chain and later appends land at a fresh sequence (no overwrite).
   */
  async function seedBrokenChain(
    fortressPath: string,
    masterKey: Uint8Array,
  ): Promise<void> {
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const writer = new AuditLog(storage, masterKey);
    await writer.appendCritical({
      layer: "l1",
      operation: "filter_started",
      identity_id: "seed",
      result: "success",
      details: { seed: true },
    });
    await writer.flush();

    const metas = await storage.list("_audit");
    let corrupted = false;
    for (const meta of metas) {
      const raw = await storage.read("_audit", meta.key);
      if (!raw) continue;
      let parsed: unknown;
      try {
        parsed = JSON.parse(bytesToString(raw));
      } catch {
        continue;
      }
      const env = parsed as Partial<PersistedAuditEnvelopeV2>;
      if (
        typeof env.entry_hash === "string" &&
        typeof env.encrypted_payload_bytes === "string" &&
        typeof env.sequence === "number"
      ) {
        env.entry_hash =
          env.entry_hash.slice(0, -1) +
          (env.entry_hash.endsWith("a") ? "b" : "a");
        await storage.write(
          "_audit",
          meta.key,
          stringToBytes(JSON.stringify(env)),
        );
        corrupted = true;
        break;
      }
    }
    if (!corrupted) throw new Error("seedBrokenChain: no chain entry to corrupt");
  }

  async function auditChainKeys(fortressPath: string): Promise<string[]> {
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    return (await storage.list("_audit")).map((m) => m.key).sort();
  }

  async function readAuditOperations(
    fortressPath: string,
    masterKey: Uint8Array,
  ): Promise<Array<{ sequence: number; operation: string }>> {
    const reader = new AuditLog(
      new FilesystemStorage(join(fortressPath, "state")),
      masterKey,
      { integrityMode: "lenient" },
    );
    const q = await reader.query({ limit: 1000 });
    return q.entries.map((e, i) => ({
      sequence: typeof e.sequence === "number" ? e.sequence : i,
      operation: e.operation,
    }));
  }

  it("re-pin refuses on a broken chain without --accept-broken-chain (unchanged default)", async () => {
    const { fortressPath, masterKey, recoveryKey } = await makeFortress();
    const env = {
      SANCTUARY_STORAGE_PATH: fortressPath,
      SANCTUARY_RECOVERY_KEY: recoveryKey,
    };
    expect(
      await runProvisionPin({ out: new CaptureStream(), err: new CaptureStream(), env }),
    ).toBe(0);
    await seedBrokenChain(fortressPath, masterKey);

    const out = new CaptureStream();
    const err = new CaptureStream();
    const helper = makeMockHelper();
    const code = await runRePin([], {
      out,
      err,
      env,
      platform: "darwin",
      signerClientInvoke: helper.invoke,
    });

    expect(code).not.toBe(0);
    expect(err.text()).toContain("audit integrity findings");
    // No override entry was written — the fail-closed default did not consent.
    const ops = await readAuditOperations(fortressPath, masterKey);
    expect(
      ops.some((o) => o.operation === "castle_wall_accept_broken_chain_override"),
    ).toBe(false);
    // No rotation proof either: the privileged action never ran.
    expect(ops.some((o) => o.operation === "policy_loaded")).toBe(false);
  });

  it("re-pin with --accept-broken-chain writes an audited override entry THEN proceeds", async () => {
    const { fortressPath, masterKey, recoveryKey } = await makeFortress();
    const env = {
      SANCTUARY_STORAGE_PATH: fortressPath,
      SANCTUARY_RECOVERY_KEY: recoveryKey,
    };
    expect(
      await runProvisionPin({ out: new CaptureStream(), err: new CaptureStream(), env }),
    ).toBe(0);
    await seedBrokenChain(fortressPath, masterKey);

    const out = new CaptureStream();
    const err = new CaptureStream();
    const helper = makeMockHelper();
    const code = await runRePin(["--accept-broken-chain"], {
      out,
      err,
      env,
      platform: "darwin",
      signerClientInvoke: helper.invoke,
    });

    expect(code).toBe(0);
    // The override is loud on stderr and names the finding count.
    expect(err.text()).toMatch(/--accept-broken-chain/);
    expect(err.text()).toMatch(/integrity finding/);
    // Re-pin proceeded: the rotation proof was recorded.
    expect(out.text()).toMatch(/migrated to the signer helper/);

    const ops = await readAuditOperations(fortressPath, masterKey);
    const overrideOp = ops.find(
      (o) => o.operation === "castle_wall_accept_broken_chain_override",
    );
    const rotationOp = ops.find((o) => o.operation === "policy_loaded");
    expect(overrideOp).toBeTruthy();
    expect(rotationOp).toBeTruthy();
    // Consent landed BEFORE the privileged action (override seq < rotation seq).
    expect(overrideOp!.sequence).toBeLessThan(rotationOp!.sequence);
  });

  it("re-pin with --accept-broken-chain writes no override entry on a clean chain", async () => {
    const { fortressPath, masterKey, recoveryKey } = await makeFortress();
    const env = {
      SANCTUARY_STORAGE_PATH: fortressPath,
      SANCTUARY_RECOVERY_KEY: recoveryKey,
    };
    expect(
      await runProvisionPin({ out: new CaptureStream(), err: new CaptureStream(), env }),
    ).toBe(0);
    // No seedBrokenChain: the chain is clean.

    const helper = makeMockHelper();
    const code = await runRePin(["--accept-broken-chain"], {
      out: new CaptureStream(),
      err: new CaptureStream(),
      env,
      platform: "darwin",
      signerClientInvoke: helper.invoke,
    });

    expect(code).toBe(0);
    const ops = await readAuditOperations(fortressPath, masterKey);
    // The rotation proof is recorded, but NO spurious override entry.
    expect(ops.some((o) => o.operation === "policy_loaded")).toBe(true);
    expect(
      ops.some((o) => o.operation === "castle_wall_accept_broken_chain_override"),
    ).toBe(false);
  });

  it("audit-findings lists integrity findings on a broken chain and is read-only", async () => {
    const { fortressPath, masterKey, recoveryKey } = await makeFortress();
    await seedBrokenChain(fortressPath, masterKey);

    const before = await auditChainKeys(fortressPath);

    const out = new CaptureStream();
    const err = new CaptureStream();
    const code = await runAuditFindings(["--fortress", fortressPath], {
      out,
      err,
      env: {
        SANCTUARY_STORAGE_PATH: fortressPath,
        SANCTUARY_RECOVERY_KEY: recoveryKey,
      },
    });

    expect(code).toBe(0);
    const lines = out.text().trim().split("\n").filter(Boolean);
    expect(lines.length).toBeGreaterThan(0);
    const parsed = lines.map((l) => JSON.parse(l) as { index: number; kind: string });
    expect(parsed[0]!.index).toBe(0);
    expect(parsed.some((p) => p.kind === "entry_hash_mismatch")).toBe(true);
    expect(err.text()).toMatch(/audit integrity finding/);

    // Read-only: the audit chain key set is unchanged, and no override or other
    // entry was appended by inspecting findings.
    const after = await auditChainKeys(fortressPath);
    expect(after).toEqual(before);
    const ops = await readAuditOperations(fortressPath, masterKey);
    expect(
      ops.some((o) => o.operation === "castle_wall_accept_broken_chain_override"),
    ).toBe(false);
  });

  it("audit-findings reports a clean chain", async () => {
    const { fortressPath, masterKey, recoveryKey } = await makeFortress();
    // Write a normal, uncorrupted entry so the store exists and verifies clean.
    const writer = new AuditLog(
      new FilesystemStorage(join(fortressPath, "state")),
      masterKey,
    );
    await writer.appendCritical({
      layer: "l1",
      operation: "filter_started",
      identity_id: "seed",
      result: "success",
    });
    await writer.flush();

    const out = new CaptureStream();
    const code = await runAuditFindings(["--fortress", fortressPath], {
      out,
      err: new CaptureStream(),
      env: {
        SANCTUARY_STORAGE_PATH: fortressPath,
        SANCTUARY_RECOVERY_KEY: recoveryKey,
      },
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("No audit integrity findings");
  });

  it("parses --accept-broken-chain", () => {
    expect(parseCastleWallArgs(["--accept-broken-chain"]).acceptBrokenChain).toBe(
      true,
    );
    expect(parseCastleWallArgs([]).acceptBrokenChain).toBeUndefined();
  });
});
