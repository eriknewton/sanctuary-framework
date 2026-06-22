import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import {
  chmod,
  mkdir,
  mkdtemp,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  formatFortressPathWritableError,
  preflightFortressPathWritable,
} from "../../src/paths.js";
import { runInit, type RunInitDeps } from "../../src/wrap/init.js";
import { runWrap, type RunWrapDeps } from "../../src/wrap/cli.js";
import type { ExecResult } from "../../src/wrap/passphrase.js";

const chmodChecksRun =
  process.platform === "linux" &&
  typeof process.getuid === "function" &&
  process.getuid() !== 0;
const chmodIt = chmodChecksRun ? it : it.skip;

describe("fortress path writability preflight", () => {
  let tmp: string;
  let chmodRestorePaths: string[];
  let originalStoragePath: string | undefined;
  let originalFortressPath: string | undefined;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-fortress-preflight-"));
    chmodRestorePaths = [];
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    originalFortressPath = process.env.SANCTUARY_FORTRESS_PATH;
    delete process.env.SANCTUARY_STORAGE_PATH;
    delete process.env.SANCTUARY_FORTRESS_PATH;
  });

  afterEach(async () => {
    for (const path of chmodRestorePaths.reverse()) {
      await chmod(path, 0o700).catch(() => {});
    }
    restoreEnv("SANCTUARY_STORAGE_PATH", originalStoragePath);
    restoreEnv("SANCTUARY_FORTRESS_PATH", originalFortressPath);
    vi.restoreAllMocks();
    await rm(tmp, { recursive: true, force: true });
  });

  it("allows a normal writable fortress target", async () => {
    const fortressPath = join(tmp, "new-fortress");

    await expect(preflightFortressPathWritable(fortressPath)).resolves.toEqual({
      ok: true,
    });
  });

  it("lets init proceed for a normal writable fortress target", async () => {
    const fortressPath = join(tmp, "init-ok");

    const result = await runInit(
      {
        fortress: fortressPath,
        noConfirm: true,
        noPin: true,
      },
      {
        recoveryKeychain: makeLinuxRecoveryKeychain(),
        provisionPin: vi.fn(async () => 0),
      } satisfies RunInitDeps,
    );

    expect(result.fortressPath).toBe(fortressPath);
    const stateDir = await stat(join(fortressPath, "state"));
    expect(stateDir.isDirectory()).toBe(true);
  });

  it("formats an actionable message without banned copy", () => {
    const message = formatFortressPathWritableError("/tmp/nope/fortress", {
      ok: false,
      path: "/tmp/nope",
      reason: "EACCES",
    });

    expect(message).toContain("/tmp/nope/fortress");
    expect(message).toContain("EACCES");
    expect(message).toContain("/tmp/nope");
    expect(message).toContain("--fortress <writable-path>");
    expect(message).not.toContain("—");
    expect(message.toLowerCase()).not.toContain("sovereignty");
  });

  chmodIt("reports a non-writable parent for a missing fortress path", async () => {
    const parent = join(tmp, "locked-parent");
    const fortressPath = join(parent, "fortress");
    await mkdir(parent, { recursive: true });
    chmodRestorePaths.push(parent);
    await chmod(parent, 0o500);

    const result = await preflightFortressPathWritable(fortressPath);

    expect(result).toMatchObject({
      ok: false,
      path: parent,
      reason: "EACCES",
    });
  });

  chmodIt("allows an existing writable fortress even when its parent is not writable", async () => {
    const parent = join(tmp, "locked-parent-existing");
    const fortressPath = join(parent, "fortress");
    await mkdir(fortressPath, { recursive: true, mode: 0o700 });
    chmodRestorePaths.push(parent);
    await chmod(parent, 0o500);

    await expect(preflightFortressPathWritable(fortressPath)).resolves.toEqual({
      ok: true,
    });
  });

  chmodIt("init prints the actionable error before writing custody state", async () => {
    const parent = join(tmp, "locked-init-parent");
    const fortressPath = join(parent, "fortress");
    await mkdir(parent, { recursive: true });
    chmodRestorePaths.push(parent);
    await chmod(parent, 0o500);
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    await expect(
      runInit({
        fortress: fortressPath,
        noConfirm: true,
        noPin: true,
      }),
    ).rejects.toThrow("fortress path is not writable");

    const stderr = errSpy.mock.calls.map((call) => call.join(" ")).join("\n");
    expect(stderr).toContain("Sanctuary init: Sanctuary cannot create its secure storage");
    expect(stderr).toContain(fortressPath);
    expect(stderr).toContain(parent);
    expect(stderr).toContain("EACCES");
    expect(stderr).toContain("--fortress <writable-path>");
    expect(stderr).not.toContain("—");
    expect(stderr.toLowerCase()).not.toContain("sovereignty");
    await expect(stat(join(fortressPath, "state"))).rejects.toThrow();
  });

  chmodIt("wrap prints the actionable error on stderr and exits before rewrite", async () => {
    const parent = join(tmp, "locked-wrap-parent");
    const fortressPath = join(parent, "fortress");
    const configPath = join(tmp, "agent", "mcp.json");
    await mkdir(parent, { recursive: true });
    await mkdir(join(tmp, "agent"), { recursive: true });
    await writeFile(
      configPath,
      JSON.stringify({
        mcpServers: {
          alpha: { command: "node", args: ["alpha.js"] },
        },
      }),
      "utf-8",
    );
    chmodRestorePaths.push(parent);
    await chmod(parent, 0o500);

    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const stdoutSpy = vi
      .spyOn(process.stdout, "write")
      .mockImplementation((() => true) as typeof process.stdout.write);
    const exitSpy = vi
      .spyOn(process, "exit")
      .mockImplementation((code?: string | number | null) => {
        throw new Error(`process.exit:${code}`);
      });
    const rewriteConfig = vi.fn<NonNullable<RunWrapDeps["rewriteConfig"]>>();
    const resolvePassphrase = vi.fn(async () => ({
      value: "fixture-passphrase",
      location: "fixture-keychain",
      source: "generated" as const,
    }));

    await expect(
      runWrap(
        {
          wrap: configPath,
          fortress: fortressPath,
          noDashboard: true,
          noOpen: true,
        },
        {
          rewriteConfig,
          resolvePassphrase,
          openBrowser: async () => {},
        },
      ),
    ).rejects.toThrow("process.exit:2");

    const stderr = errSpy.mock.calls.map((call) => call.join(" ")).join("\n");
    const stdout = stdoutSpy.mock.calls.map((call) => String(call[0])).join("");
    expect(exitSpy).toHaveBeenCalledWith(2);
    expect(resolvePassphrase).not.toHaveBeenCalled();
    expect(rewriteConfig).not.toHaveBeenCalled();
    expect(stderr).toContain("Sanctuary wrap: Sanctuary cannot create its secure storage");
    expect(stderr).toContain(fortressPath);
    expect(stderr).toContain(parent);
    expect(stderr).toContain("EACCES");
    expect(stderr).toContain("--fortress <writable-path>");
    expect(stderr).not.toContain("—");
    expect(stderr.toLowerCase()).not.toContain("sovereignty");
    expect(stdout).not.toContain("Sanctuary cannot create its secure storage");
  });
});

function makeLinuxRecoveryKeychain(): NonNullable<RunInitDeps["recoveryKeychain"]> {
  const stored = new Map<string, string>();
  const exec = async (
    cmd: string,
    args: string[],
    input?: string,
  ): Promise<ExecResult> => {
    if (cmd !== "secret-tool") {
      return { stdout: "", stderr: "unexpected command", code: 1 };
    }
    const service = args[args.indexOf("service") + 1] ?? "";
    if (args[0] === "store") {
      stored.set(service, (input ?? "").trim());
      return { stdout: "", stderr: "", code: 0 };
    }
    if (args[0] === "lookup") {
      const value = stored.get(service);
      return value
        ? { stdout: `${value}\n`, stderr: "", code: 0 }
        : { stdout: "", stderr: "not found", code: 1 };
    }
    return { stdout: "", stderr: "unexpected args", code: 1 };
  };

  return {
    home: "/tmp/sanctuary-test-home",
    platformOverride: "linux",
    exec,
  };
}

function restoreEnv(key: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[key];
  } else {
    process.env[key] = value;
  }
}
