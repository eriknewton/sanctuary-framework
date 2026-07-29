import { spawn } from "node:child_process";
import { mkdir, mkdtemp, rm, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { runInit } from "../../src/wrap/init.js";
import type { ExecResult } from "../../src/wrap/passphrase.js";

const CLI_PATH = join(process.cwd(), "dist", "cli.js");

type ExecCall = { cmd: string; args: string[]; input?: string };

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

  it("boots normally when the resolved fortress path already exists", async () => {
    const fortressPath = join(tmp, "existing-fortress");
    await mkdir(fortressPath, { recursive: true, mode: 0o700 });

    const result = await runCliUntilStarted(fortressPath);

    expect(result.stderr).not.toContain("FORTRESS_NOT_FOUND");
    expect(result.stderr).toContain("Sanctuary MCP Server");
    expect((await stat(fortressPath)).isDirectory()).toBe(true);
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
  });
});
