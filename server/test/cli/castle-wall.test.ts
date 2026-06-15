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
import { DEFAULT_DENY_BUCKET } from "../../src/castle-wall/audit/per-rule-report.js";
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

  /** Seed a fortress with flows decided by several distinct rules + default-deny. */
  async function seedRuleAttributedFlows() {
    const fortress = await makeFortress();
    const auditLog = new AuditLog(
      new FilesystemStorage(join(fortress.fortressPath, "state")),
      fortress.masterKey,
      { integrityMode: "lenient" },
    );
    // rule "allow-anthropic": 2 allows
    await auditLog.append("l1", "egress_allowed", "agent-1", { decision: "allow", rule_id: "allow-anthropic", destination: { host: "api.anthropic.com", ip: "1.1.1.1", port: 443, protocol: "tcp" } }, "success");
    await auditLog.append("l1", "egress_allowed", "agent-1", { decision: "allow", rule_id: "allow-anthropic" }, "success");
    // rule "deny-tracker": 1 deny (Rust producer-signed key shape)
    await auditLog.append("l1", "egress_blocked", "agent-1", { decision: "drop", rule_id_matched: "deny-tracker" }, "failure");
    // rule "allow-github": 1 allow
    await auditLog.append("l1", "egress_allowed", "agent-1", { decision: "allow", rule_id: "allow-github" }, "success");
    // default-deny: 1 deny with no rule
    await auditLog.append("l1", "egress_blocked", "agent-1", { decision: "drop" }, "failure");
    // a non-flow lifecycle event that must be excluded from the read-out
    await auditLog.append("l1", "filter_started", "system", {}, "success");
    await auditLog.flush();
    return fortress;
  }

  it("audit-dump --by-rule rolls flows up per rule with allow/deny split + default-deny bucket", async () => {
    const { fortressPath, recoveryKey } = await seedRuleAttributedFlows();
    const out = new CaptureStream();
    const code = await runAuditDump(["--fortress", fortressPath, "--by-rule"], {
      out,
      env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(code).toBe(0);
    const groups = out.text().trim().split("\n").map((l) => JSON.parse(l));

    const byRule = new Map(groups.map((g) => [g.rule, g]));
    expect(byRule.get("allow-anthropic")).toMatchObject({ total: 2, allow: 2, deny: 0, default_deny: false });
    expect(byRule.get("deny-tracker")).toMatchObject({ total: 1, allow: 0, deny: 1, default_deny: false });
    expect(byRule.get("allow-github")).toMatchObject({ total: 1, allow: 1, deny: 0, default_deny: false });

    // default-deny rolls into the explicit null-rule bucket, never a fabricated rule.
    const defaultDeny = groups.find((g) => g.default_deny === true);
    expect(defaultDeny).toBeDefined();
    expect(defaultDeny.total).toBe(1);
    expect(defaultDeny.deny).toBe(1);

    // The lifecycle event (filter_started) is not a flow and must not appear.
    expect(groups.some((g) => g.rule === "filter_started")).toBe(false);
  });

  it("audit-dump --rule <id> shows only that rule's attributed flows", async () => {
    const { fortressPath, recoveryKey } = await seedRuleAttributedFlows();
    const out = new CaptureStream();
    const code = await runAuditDump(["--fortress", fortressPath, "--rule", "allow-anthropic"], {
      out,
      env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(code).toBe(0);
    const flows = out.text().trim().split("\n").map((l) => JSON.parse(l));
    expect(flows).toHaveLength(2);
    expect(flows.every((f) => f.rule_id === "allow-anthropic")).toBe(true);
    expect(flows.every((f) => f.decision === "allow")).toBe(true);
    // The recorded destination host surfaces for operator legibility.
    expect(flows.some((f) => f.destination_host === "api.anthropic.com")).toBe(true);
  });

  it("audit-dump --rule default-deny shows the no-matching-rule flows", async () => {
    const { fortressPath, recoveryKey } = await seedRuleAttributedFlows();
    const out = new CaptureStream();
    const code = await runAuditDump(["--fortress", fortressPath, "--rule", "default-deny"], {
      out,
      env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(code).toBe(0);
    const flows = out.text().trim().split("\n").map((l) => JSON.parse(l));
    expect(flows).toHaveLength(1);
    expect(flows[0].rule_id).toBeNull();
    expect(flows[0].decision).toBe("deny");
  });

  it("audit-dump --rule treats the bucket DISPLAY label as a literal rule id (alias is only `default-deny`)", async () => {
    // A real rule literally named exactly the bucket display string must remain
    // selectable: only the short `--rule default-deny` is the bucket alias. The
    // alias must never shadow a literal rule.
    const fortress = await makeFortress();
    const auditLog = new AuditLog(
      new FilesystemStorage(join(fortress.fortressPath, "state")),
      fortress.masterKey,
      { integrityMode: "lenient" },
    );
    // A genuine allow rule whose id collides with the bucket display label.
    await auditLog.append("l1", "egress_allowed", "agent-1", { decision: "allow", rule_id: DEFAULT_DENY_BUCKET }, "success");
    // A genuine no-matching-rule (null) flow -> the real default-deny bucket.
    await auditLog.append("l1", "egress_blocked", "agent-1", { decision: "drop" }, "failure");
    await auditLog.flush();

    // `--rule "<display label>"` selects the LITERAL rule's allow flow, not the
    // null-rule bucket's deny flow.
    const litOut = new CaptureStream();
    const litCode = await runAuditDump(["--fortress", fortress.fortressPath, "--rule", DEFAULT_DENY_BUCKET], {
      out: litOut,
      env: { SANCTUARY_STORAGE_PATH: fortress.fortressPath, SANCTUARY_RECOVERY_KEY: fortress.recoveryKey },
    });
    expect(litCode).toBe(0);
    const litFlows = litOut.text().trim().split("\n").map((l) => JSON.parse(l));
    expect(litFlows).toHaveLength(1);
    expect(litFlows[0].rule_id).toBe(DEFAULT_DENY_BUCKET);
    expect(litFlows[0].decision).toBe("allow");

    // `--rule default-deny` still selects the genuine null-rule bucket flow.
    const bucketOut = new CaptureStream();
    const bucketCode = await runAuditDump(["--fortress", fortress.fortressPath, "--rule", "default-deny"], {
      out: bucketOut,
      env: { SANCTUARY_STORAGE_PATH: fortress.fortressPath, SANCTUARY_RECOVERY_KEY: fortress.recoveryKey },
    });
    expect(bucketCode).toBe(0);
    const bucketFlows = bucketOut.text().trim().split("\n").map((l) => JSON.parse(l));
    expect(bucketFlows).toHaveLength(1);
    expect(bucketFlows[0].rule_id).toBeNull();
    expect(bucketFlows[0].decision).toBe("deny");
  });

  it("audit-dump --rule with no value is a usage error, not a silent raw dump", async () => {
    const { fortressPath, recoveryKey } = await seedRuleAttributedFlows();
    const out = new CaptureStream();
    const err = new CaptureStream();
    const code = await runAuditDump(["--fortress", fortressPath, "--rule"], {
      out,
      err,
      env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    // Non-zero usage exit, an explanatory stderr line, and crucially NO raw
    // audit entries dumped to stdout (the prior silent-fallback bug).
    expect(code).not.toBe(0);
    expect(err.text()).toContain("--rule requires a rule id");
    expect(out.text()).toBe("");
  });

  it("audit-dump --rule immediately followed by another flag is a usage error", async () => {
    const { fortressPath, recoveryKey } = await seedRuleAttributedFlows();
    const out = new CaptureStream();
    const err = new CaptureStream();
    // `--rule --by-rule`: `--rule` must NOT swallow the following flag as its value.
    const code = await runAuditDump(["--fortress", fortressPath, "--rule", "--by-rule"], {
      out,
      err,
      env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(code).not.toBe(0);
    expect(err.text()).toContain("--rule requires a rule id");
    expect(out.text()).toBe("");
  });

  it("audit-dump --by-rule is deterministic across N>=3 runs (identical output)", async () => {
    const { fortressPath, recoveryKey } = await seedRuleAttributedFlows();
    const runOnce = async () => {
      const out = new CaptureStream();
      const code = await runAuditDump(["--fortress", fortressPath, "--by-rule"], {
        out,
        env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_RECOVERY_KEY: recoveryKey },
      });
      expect(code).toBe(0);
      return out.text();
    };
    const a = await runOnce();
    const b = await runOnce();
    const c = await runOnce();
    expect(b).toBe(a);
    expect(c).toBe(a);
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

describe("castle-wall operability fixes (drill 2026-06-13: F1/F2a/F2b/F3)", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function makeFortress() {
    const fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-cw-ops-"));
    tempDirs.push(fortressPath);
    const masterKey = generateRandomKey();
    const recoveryKey = toBase64url(masterKey);
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

  // ── F1: signer-client shim auto-discovery ────────────────────────────────

  it("F1: SANCTUARY_CASTLE_SIGNER_CLIENT env var still wins over auto-discovery", async () => {
    const { fortressPath, recoveryKey } = await makeFortress();
    const helper = makeMockHelper();
    // An env path is set; auto-discovery candidates would also resolve, but the
    // env var takes precedence — and because signerClientInvoke is injected the
    // bundle probe is never the deciding factor. Assert success + no shim error.
    const err = new CaptureStream();
    const code = await runRePin([], {
      out: new CaptureStream(),
      err,
      env: {
        SANCTUARY_STORAGE_PATH: fortressPath,
        SANCTUARY_RECOVERY_KEY: recoveryKey,
        SANCTUARY_CASTLE_SIGNER_CLIENT: "/some/env/shim",
      },
      platform: "darwin",
      signerClientInvoke: helper.invoke,
      // Auto-discovery would also find this, proving env still wins (no error).
      signerClientCandidates: ["/Applications/whatever/castle-wall-signer-client"],
      fileExistsFn: async () => true,
    });
    expect(code).toBe(0);
    expect(err.text()).not.toContain("signer-client shim path unknown");
  });

  it("F1: auto-discovery resolves an injected bundle candidate when env is unset", async () => {
    const { fortressPath, recoveryKey } = await makeFortress();
    const helper = makeMockHelper();
    // No env var, no ctx.signerClientPath. Auto-discovery finds the injected
    // executable candidate, so re-pin does NOT hit the "path unknown" wall.
    const err = new CaptureStream();
    const out = new CaptureStream();
    const code = await runRePin([], {
      out,
      err,
      env: {
        SANCTUARY_STORAGE_PATH: fortressPath,
        SANCTUARY_RECOVERY_KEY: recoveryKey,
      },
      platform: "darwin",
      signerClientInvoke: helper.invoke,
      signerClientCandidates: [
        "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/castle-wall-signer-client",
      ],
      fileExistsFn: async (p) => p.endsWith("castle-wall-signer-client"),
    });
    expect(code).toBe(0);
    expect(err.text()).not.toContain("signer-client shim path unknown");
    expect(out.text()).toContain(fingerprint(helper.pub));
  });

  it("F1: falls through to the 'path unknown' error when nothing resolves", async () => {
    const { fortressPath, recoveryKey } = await makeFortress();
    // No env, no ctx path, no signerClientInvoke, and auto-discovery finds
    // nothing executable → the original fail-closed error fires (exit 1).
    const err = new CaptureStream();
    const code = await runRePin([], {
      out: new CaptureStream(),
      err,
      env: {
        SANCTUARY_STORAGE_PATH: fortressPath,
        SANCTUARY_RECOVERY_KEY: recoveryKey,
      },
      platform: "darwin",
      signerClientCandidates: ["/Applications/missing/castle-wall-signer-client"],
      fileExistsFn: async () => false,
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("signer-client shim path unknown");
  });

  // ── F2a: loud target-fortress announcement ───────────────────────────────

  it("F2a: announces the resolved target fortress before state-touching work", async () => {
    const { fortressPath, recoveryKey } = await makeFortress();
    const helper = makeMockHelper();
    const err = new CaptureStream();
    await runRePin([], {
      out: new CaptureStream(),
      err,
      env: {
        SANCTUARY_STORAGE_PATH: fortressPath,
        SANCTUARY_RECOVERY_KEY: recoveryKey,
      },
      platform: "darwin",
      signerClientInvoke: helper.invoke,
    });
    expect(err.text()).toContain(
      `Re-pinning trust anchor for fortress: ${fortressPath}`,
    );
    // Explicit storage path → NOT flagged as the default fortress.
    expect(err.text()).not.toContain("default fortress; set SANCTUARY_STORAGE_PATH");
  });

  it("F2a: flags the DEFAULT fortress note when SANCTUARY_STORAGE_PATH is unset", async () => {
    // No SANCTUARY_STORAGE_PATH → resolveStoragePath defaults to ~/.sanctuary.
    // We don't let it proceed to real state (no shim resolvable, no invoke), so
    // it returns 1 at the shim-resolution wall — but the announcement (which
    // runs FIRST) must already carry the default-fortress note.
    const err = new CaptureStream();
    const code = await runRePin([], {
      out: new CaptureStream(),
      err,
      env: {},
      platform: "darwin",
      signerClientCandidates: [],
      fileExistsFn: async () => false,
    });
    expect(code).toBe(1); // hit the shim-unknown wall, no state touched
    expect(err.text()).toContain("Re-pinning trust anchor for fortress:");
    expect(err.text()).toContain(
      "(default fortress; set SANCTUARY_STORAGE_PATH to target another)",
    );
  });

  // ── F2b: don't mask a successful migration behind a post-migration error ──

  it("F2b: post-migration audit failure degrades to a warning, prints fp, exits 0", async () => {
    const { fortressPath } = await makeFortress();
    const helper = makeMockHelper();
    // installPin() succeeds (mock helper), but resolveMasterKey FAILS because the
    // supplied recovery key does not match the fortress's recovery-key-hash
    // marker. That throw lands in the POST-migration audit-bookkeeping phase, so
    // the migration must NOT be reported as a failure.
    const out = new CaptureStream();
    const err = new CaptureStream();
    const code = await runRePin([], {
      out,
      err,
      env: {
        SANCTUARY_STORAGE_PATH: fortressPath,
        // Wrong recovery key → establishMaster rejects it (post-installPin throw).
        SANCTUARY_RECOVERY_KEY: toBase64url(generateRandomKey()),
      },
      platform: "darwin",
      signerClientInvoke: helper.invoke,
    });
    expect(code).toBe(0);
    // The migrated fingerprint is still printed to stdout.
    expect(out.text()).toContain(fingerprint(helper.pub));
    // The warning explains the audit-record failure but affirms the migration.
    expect(err.text()).toContain("Trust anchor migrated to");
    expect(err.text()).toContain("The pin migration itself succeeded.");
  });

  // ── F3: status reports the global pin + a consistency verdict ─────────────

  it("F3: status reports CONSISTENT when global pin == signer-helper key", async () => {
    const { fortressPath } = await makeFortress();
    const helper = makeMockHelper();
    const out = new CaptureStream();
    const code = await runStatus({
      out,
      env: { SANCTUARY_STORAGE_PATH: fortressPath },
      platform: "darwin",
      execSyncFn: () => "com.sanctuary.castle-wall [activated enabled]",
      hostAppCandidates: [],
      // Global pin equals the mock helper's key → authoritative CONSISTENT.
      globalPinReader: async () => helper.pub,
      signerClientInvoke: helper.invoke,
    });
    expect(code).toBe(0);
    expect(out.text()).toContain(
      `Global pin (enforcement anchor): ${fingerprint(helper.pub)}`,
    );
    expect(out.text()).toContain(
      "Trust anchor: CONSISTENT (global pin == signer-helper key)",
    );
  });

  it("F3: status reports BROKEN when global pin != signer-helper key", async () => {
    const { fortressPath } = await makeFortress();
    const helper = makeMockHelper();
    const otherPin = ed25519.getPublicKey(ed25519.utils.randomPrivateKey());
    const out = new CaptureStream();
    const code = await runStatus({
      out,
      env: { SANCTUARY_STORAGE_PATH: fortressPath },
      platform: "darwin",
      execSyncFn: () => "com.sanctuary.castle-wall [activated enabled]",
      hostAppCandidates: [],
      // Global pin differs from the helper key → authoritative BROKEN.
      globalPinReader: async () => otherPin,
      signerClientInvoke: helper.invoke,
    });
    expect(code).toBe(0);
    expect(out.text()).toContain(
      `Global pin (enforcement anchor): ${fingerprint(otherPin)}`,
    );
    expect(out.text()).toContain(
      "Trust anchor: BROKEN (global pin != signer-helper key; box cannot arm until re-pinned)",
    );
  });

  it("F3: status reports 'none' gracefully when no global pin is provisioned", async () => {
    const { fortressPath } = await makeFortress();
    const out = new CaptureStream();
    const enoent = Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    const code = await runStatus({
      out,
      env: { SANCTUARY_STORAGE_PATH: fortressPath },
      platform: "darwin",
      execSyncFn: () => "com.sanctuary.castle-wall [activated enabled]",
      hostAppCandidates: [],
      globalPinReader: async () => {
        throw enoent;
      },
    });
    expect(code).toBe(0);
    expect(out.text()).toContain(
      "Global pin (enforcement anchor): none (no global pin provisioned)",
    );
    expect(out.text()).toContain("Trust anchor: no global pin provisioned");
  });

  it("F3: status reports 'unreadable' gracefully on EACCES (root-owned global pin)", async () => {
    const { fortressPath } = await makeFortress();
    const out = new CaptureStream();
    const eacces = Object.assign(new Error("EACCES"), { code: "EACCES" });
    const code = await runStatus({
      out,
      env: { SANCTUARY_STORAGE_PATH: fortressPath },
      platform: "darwin",
      execSyncFn: () => "com.sanctuary.castle-wall [activated enabled]",
      hostAppCandidates: [],
      globalPinReader: async () => {
        throw eacces;
      },
    });
    expect(code).toBe(0);
    expect(out.text()).toContain(
      "Global pin (enforcement anchor): unreadable (root-owned; re-run with elevation to inspect)",
    );
  });

  // ── FIX 1: signer-client discovery uses the owner-trust check (parity) ─────

  it("FIX 1: owner-trusted candidate (owned by current uid) is accepted and used", async () => {
    const { fortressPath, recoveryKey } = await makeFortress();
    const helper = makeMockHelper();
    // A real on-disk candidate owned by the current uid passes the DEFAULT
    // owner-trust predicate (no fileExistsFn injected — the production
    // isOwnerTrustedExecutable check runs). Re-pin must NOT hit the
    // "path unknown" wall; signerClientInvoke completes the migration.
    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-cw-bundle-"));
    tempDirs.push(bundleDir);
    const candidate = join(bundleDir, "castle-wall-signer-client");
    await writeFile(candidate, "#!/bin/sh\n", { mode: 0o755 });
    const currentUid = process.getuid?.();
    const err = new CaptureStream();
    const out = new CaptureStream();
    const code = await runRePin([], {
      out,
      err,
      env: {
        SANCTUARY_STORAGE_PATH: fortressPath,
        SANCTUARY_RECOVERY_KEY: recoveryKey,
      },
      platform: "darwin",
      getuid: () => currentUid ?? 0,
      signerClientCandidates: [candidate],
      signerClientInvoke: helper.invoke,
    });
    expect(code).toBe(0);
    expect(err.text()).not.toContain("signer-client shim path unknown");
    expect(out.text()).toContain(fingerprint(helper.pub));
  });

  it("FIX 1: candidate owned by a DIFFERENT uid is rejected (not root, not us)", async () => {
    const { fortressPath, recoveryKey } = await makeFortress();
    // The candidate exists and is executable, but getuid reports a uid that is
    // NEITHER the file owner NOR root, so the owner-trust check rejects it and
    // discovery falls through to the fail-closed "path unknown" wall (exit 1).
    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-cw-bundle-"));
    tempDirs.push(bundleDir);
    const candidate = join(bundleDir, "castle-wall-signer-client");
    await writeFile(candidate, "#!/bin/sh\n", { mode: 0o755 });
    const ownerUid = (await stat(candidate)).uid;
    const err = new CaptureStream();
    const code = await runRePin([], {
      out: new CaptureStream(),
      err,
      env: {
        SANCTUARY_STORAGE_PATH: fortressPath,
        SANCTUARY_RECOVERY_KEY: recoveryKey,
      },
      platform: "darwin",
      // A uid that is not the file owner and not root → owner-trust fails.
      getuid: () => ownerUid + 99999,
      signerClientCandidates: [candidate],
      // No signerClientInvoke: discovery must be the deciding factor.
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("signer-client shim path unknown");
  });

  // ── FIX 4: the DISCOVERED path actually reaches the spawned client ────────

  it("FIX 4: with no signerClientInvoke, the discovered owner-trusted path is what the client spawns", async () => {
    const { fortressPath, recoveryKey } = await makeFortress();
    // No signerClientInvoke → the default HelperSignerClient spawn runner runs.
    // The owner-trusted discovered candidate is a real (owner==us) file but not
    // a working shim, so the spawn fails — and the failure message echoes the
    // EXACT discovered path, proving the resolved candidate is what gets spawned
    // (host-independent: never touches a real /Applications install).
    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-cw-bundle-"));
    tempDirs.push(bundleDir);
    const candidate = join(bundleDir, "castle-wall-signer-client");
    // 0o644 (no exec bit): isOwnerTrustedExecutable accepts it (owner==us, regular
    // file), but spawn fails — proving discovery, not invocation, picked the path.
    await writeFile(candidate, "not-a-real-shim\n", { mode: 0o644 });
    const currentUid = process.getuid?.();
    const err = new CaptureStream();
    const code = await runRePin([], {
      out: new CaptureStream(),
      err,
      env: {
        SANCTUARY_STORAGE_PATH: fortressPath,
        SANCTUARY_RECOVERY_KEY: recoveryKey,
      },
      platform: "darwin",
      getuid: () => currentUid ?? 0,
      signerClientCandidates: [candidate],
    });
    // Not the "path unknown" wall — discovery resolved the candidate.
    expect(err.text()).not.toContain("signer-client shim path unknown");
    // The spawn failure surfaces the resolved discovered path verbatim.
    expect(err.text()).toContain(candidate);
    expect(code).toBe(1);
  });

  // ── FIX 2: status degrades (never throws) on a malformed-length local pin ──

  it("FIX 2: malformed-length local pin still prints the global-pin verdict and returns 0", async () => {
    const { fortressPath } = await makeFortress();
    const helper = makeMockHelper();
    // Write a local pinned-pubkey file with the WRONG length (not 32 bytes).
    // The old code re-threw on this, aborting status BEFORE the F3 global-pin
    // verdict. It must now degrade to a warning and fall through.
    await writeFile(
      join(fortressPath, "castle-pinned-pubkey.bin"),
      new Uint8Array([1, 2, 3]),
    );
    const out = new CaptureStream();
    let code: number | undefined;
    await expect(
      (async () => {
        code = await runStatus({
          out,
          env: { SANCTUARY_STORAGE_PATH: fortressPath },
          platform: "darwin",
          execSyncFn: () => "com.sanctuary.castle-wall [activated enabled]",
          hostAppCandidates: [],
          globalPinReader: async () => helper.pub,
          signerClientInvoke: helper.invoke,
        });
      })(),
    ).resolves.toBeUndefined(); // status must NEVER throw
    expect(code).toBe(0);
    // Degraded local-key warning is printed instead of throwing.
    expect(out.text()).toContain("Local fortress key: unreadable");
    // F3 global-pin verdict still prints (the whole point of degrading).
    expect(out.text()).toContain(
      `Global pin (enforcement anchor): ${fingerprint(helper.pub)}`,
    );
  });
});
