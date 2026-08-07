import { spawn } from "node:child_process";
import { mkdir, mkdtemp, rm, stat, symlink, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { mcpChildFortressExists } from "../../src/mcp-child-fortress-refusal.js";
import { runInit } from "../../src/wrap/init.js";
import type { ExecResult } from "../../src/wrap/passphrase.js";

const CLI_PATH = join(process.cwd(), "dist", "cli.js");

type ExecCall = { cmd: string; args: string[]; input?: string };

const FORTRESS_MARKER_TEST_CASES = [
  { name: "custody-envelope", path: ["state", "_meta", "custody-envelope.enc"] },
  { name: "custody-sentinel", path: ["state", "_meta", "custody-sentinel.enc"] },
  { name: "legacy-key-params", path: ["state", "_meta", "key-params.enc"] },
  {
    name: "legacy-recovery-key-hash",
    path: ["state", "_meta", "recovery-key-hash.enc"],
  },
] as const;

function unescapeSecurityToken(value: string): string {
  return value.replace(/\\(.)/g, "$1");
}

function readSecurityToken(input: string | undefined, flag: string): string {
  const escapedFlag = flag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = input?.match(new RegExp(`${escapedFlag} "((?:[^"\\\\]|\\\\.)*)"`));
  return match ? unescapeSecurityToken(match[1]!) : "";
}

function makeRecoveryKeychainMock(): {
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>;
} {
  const calls: ExecCall[] = [];
  const stored = new Map<string, string>();
  const keyFor = (account: string, service: string): string =>
    `${account}:${service}`;

  const exec = async (
    cmd: string,
    args: string[],
    input?: string,
  ): Promise<ExecResult> => {
    calls.push(input === undefined ? { cmd, args } : { cmd, args, input });
    if (cmd !== "security") return { stdout: "", stderr: "unknown", code: 1 };
    if (args[0] === "-i") {
      const account = readSecurityToken(input, "-a");
      const service = readSecurityToken(input, "-s");
      const value = readSecurityToken(input, "-w");
      stored.set(keyFor(account, service), value);
      return { stdout: "", stderr: "", code: 0 };
    }
    if (args[0] === "find-generic-password") {
      const account = args[args.indexOf("-a") + 1] ?? "";
      const service = args[args.indexOf("-s") + 1] ?? "";
      const value = stored.get(keyFor(account, service));
      if (value) return { stdout: `${value}\n`, stderr: "", code: 0 };
      return { stdout: "", stderr: "not found", code: 44 };
    }
    return { stdout: "", stderr: "unknown", code: 1 };
  };

  return { exec };
}

function runCliUntilExit(fortressPath: string): Promise<{
  code: number | null;
  stderr: string;
}> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI_PATH], {
      env: {
        ...process.env,
        SANCTUARY_FORTRESS_PATH: fortressPath,
        SANCTUARY_NO_UPDATE_CHECK: "1",
      },
      stdio: ["ignore", "ignore", "pipe"],
    });

    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf-8");
    });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stderr }));
  });
}

function runCliUntilStarted(fortressPath: string): Promise<{
  stderr: string;
}> {
  return new Promise((resolve, reject) => {
    let sawStarted = false;
    let settled = false;
    const child = spawn(process.execPath, [CLI_PATH], {
      env: {
        ...process.env,
        SANCTUARY_FORTRESS_PATH: fortressPath,
        SANCTUARY_NO_UPDATE_CHECK: "1",
      },
      stdio: ["ignore", "ignore", "pipe"],
    });

    let stderr = "";
    const timeout = setTimeout(() => {
      child.kill("SIGTERM");
      if (!settled) {
        settled = true;
        reject(new Error(`MCP child did not start. stderr:\n${stderr}`));
      }
    }, 5000);

    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf-8");
      if (stderr.includes("Sanctuary MCP Server") && stderr.includes("running")) {
        clearTimeout(timeout);
        sawStarted = true;
        child.kill("SIGTERM");
      }
    });
    child.on("error", (err) => {
      clearTimeout(timeout);
      if (!settled) {
        settled = true;
        reject(err);
      }
    });
    child.on("close", (code) => {
      clearTimeout(timeout);
      if (settled) return;
      settled = true;
      if (sawStarted) {
        resolve({ stderr });
        return;
      }
      if (!stderr.includes("Sanctuary MCP Server")) {
        reject(new Error(`MCP child exited early with ${code}. stderr:\n${stderr}`));
        return;
      }
      resolve({ stderr });
    });
  });
}

async function withSanctuaryPassphrase<T>(
  passphrase: string,
  fn: () => Promise<T>,
): Promise<T> {
  const previous = process.env.SANCTUARY_PASSPHRASE;
  process.env.SANCTUARY_PASSPHRASE = passphrase;
  try {
    return await fn();
  } finally {
    if (previous === undefined) {
      delete process.env.SANCTUARY_PASSPHRASE;
    } else {
      process.env.SANCTUARY_PASSPHRASE = previous;
    }
  }
}

describe("MCP child fortress refusal", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-mcp-child-"));
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("refuses to boot against a missing fortress without creating it", async () => {
    const fortressPath = join(tmp, "missing-fortress");

    const result = await runCliUntilExit(fortressPath);
    const jsonLine = result.stderr
      .split(/\r?\n/)
      .find((line) => line.includes('"FORTRESS_NOT_FOUND"'));

    expect(result.code).toBe(78);
    expect(jsonLine).toBeDefined();
    expect(JSON.parse(jsonLine!)).toMatchObject({
      level: "error",
      code: "FORTRESS_NOT_FOUND",
      fortress_path: fortressPath,
      caller_kind: "mcp_child",
      docs_url:
        "https://github.com/eriknewton/sanctuary-framework/blob/main/server/docs/fortress-lifecycle.md",
    });
    expect(existsSync(fortressPath)).toBe(false);
  });

  it("refuses to boot against an empty existing directory", async () => {
    const fortressPath = join(tmp, "empty-fortress");
    await mkdir(fortressPath, { recursive: true, mode: 0o700 });

    const result = await runCliUntilExit(fortressPath);
    const jsonLine = result.stderr
      .split(/\r?\n/)
      .find((line) => line.includes('"FORTRESS_NOT_FOUND"'));

    expect(result.code).toBe(78);
    expect(jsonLine).toBeDefined();
    expect((await stat(fortressPath)).isDirectory()).toBe(true);
    expect(existsSync(join(fortressPath, "state"))).toBe(false);
  });

  it("recognizes current and legacy fortress markers instead of path existence", async () => {
    const emptyFortressPath = join(tmp, "empty-markerless-fortress");
    const markerlessStatePath = join(tmp, "markerless-state-fortress");
    await mkdir(emptyFortressPath, { recursive: true, mode: 0o700 });
    await mkdir(join(markerlessStatePath, "state"), {
      recursive: true,
      mode: 0o700,
    });

    expect(await mcpChildFortressExists(emptyFortressPath)).toBe(false);
    expect(await mcpChildFortressExists(markerlessStatePath)).toBe(false);

    for (const marker of FORTRESS_MARKER_TEST_CASES) {
      const fortressPath = join(tmp, `marker-${marker.name}`);
      const markerPath = join(fortressPath, ...marker.path);
      await mkdir(dirname(markerPath), { recursive: true, mode: 0o700 });
      await writeFile(markerPath, "{}", { mode: 0o600 });

      expect(await mcpChildFortressExists(fortressPath)).toBe(true);
    }

    const symlinkMarkerFortressPath = join(tmp, "symlink-marker-fortress");
    const symlinkMarker = FORTRESS_MARKER_TEST_CASES[0]!;
    const symlinkMarkerPath = join(
      symlinkMarkerFortressPath,
      ...symlinkMarker.path,
    );
    const symlinkTargetPath = join(tmp, "external-marker-target");
    await mkdir(dirname(symlinkMarkerPath), { recursive: true, mode: 0o700 });
    await writeFile(symlinkTargetPath, "{}", { mode: 0o600 });
    await symlink(symlinkTargetPath, symlinkMarkerPath);

    expect(await mcpChildFortressExists(symlinkMarkerFortressPath)).toBe(false);
  });

  it("boots normally when the resolved fortress path has initialized custody markers", async () => {
    const fortressPath = join(tmp, "initialized-fortress");
    const keychain = makeRecoveryKeychainMock();

    await withSanctuaryPassphrase("mcp-child-test-passphrase", async () => {
      await runInit(
        { fortress: fortressPath, noConfirm: true },
        {
          recoveryKeychain: {
            home: "/tmp/sanctuary-test-home",
            platformOverride: "darwin",
            exec: keychain.exec,
          },
        },
      );

      expect(await mcpChildFortressExists(fortressPath)).toBe(true);

      const result = await runCliUntilStarted(fortressPath);

      expect(result.stderr).not.toContain("FORTRESS_NOT_FOUND");
      expect(result.stderr).toContain("Sanctuary MCP Server");
    });
  });

  it("leaves explicit sanctuary init able to create a missing fortress", async () => {
    const fortressPath = join(tmp, "explicit-init-fortress");
    const keychain = makeRecoveryKeychainMock();

    const result = await runInit(
      { fortress: fortressPath, noConfirm: true },
      {
        recoveryKeychain: {
          home: "/tmp/sanctuary-test-home",
          platformOverride: "darwin",
          exec: keychain.exec,
        },
      },
    );

    expect(result.fortressPath).toBe(fortressPath);
    expect((await stat(fortressPath)).isDirectory()).toBe(true);
    expect(await mcpChildFortressExists(fortressPath)).toBe(true);
  });
});
