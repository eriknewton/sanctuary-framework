import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runWrap, type DashboardStarter, type RunWrapDeps } from "../../src/cocoon/cli.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";

describe("wrap CLI cleanup", () => {
  let tempHome: string | undefined;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;

  afterEach(async () => {
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalStoragePath === undefined)
      delete process.env.SANCTUARY_STORAGE_PATH;
    else process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;

    if (tempHome) {
      await rm(tempHome, { recursive: true, force: true });
      tempHome = undefined;
    }
    vi.restoreAllMocks();
  });

  it("flushes wrap audit writes before tenant storage teardown", async () => {
    tempHome = await mkdtemp(join(tmpdir(), "sanctuary-wrap-cleanup-"));
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    process.env.HOME = tempHome;

    const tenantDir = join(tempHome, "tenant");
    process.env.SANCTUARY_STORAGE_PATH = tenantDir;
    const configPath = join(tempHome, "openclaw.json");
    await writeFile(
      configPath,
      JSON.stringify({
        mcp: {
          servers: {
            demo: { command: "node", args: ["demo-server.js"] },
          },
        },
      }),
      "utf-8",
    );

    const startDashboard: DashboardStarter = async (opts) => ({
      url: `http://127.0.0.1:${opts.port}`,
      port: opts.port,
      host: "127.0.0.1",
      stop: async () => {},
      publish: () => {},
      publishActivity: () => {},
      publishApproval: () => {},
    });
    const rewriteConfig: RunWrapDeps["rewriteConfig"] = async (
      _agentConfig,
      command,
      args,
    ) => {
      await writeFile(
        configPath,
        JSON.stringify({
          mcp: {
            servers: {
              sanctuary: { command, args },
            },
          },
        }),
        "utf-8",
      );
      return configPath;
    };
    const flushSpy = vi.spyOn(AuditLog.prototype, "flush");

    await runWrap(
      { wrap: configPath, noOpen: true },
      {
        startDashboard,
        openBrowser: async () => {},
        resolvePassphrase: async () => ({
          value: "cleanup-passphrase",
          location: "macOS Keychain",
          source: "generated",
        }),
        rewriteConfig,
      },
    );

    expect(flushSpy).toHaveBeenCalled();
    const auditEntries = await readdir(join(tenantDir, "state", "_audit"));
    expect(auditEntries.length).toBeGreaterThan(0);
    await expect(
      rm(join(tenantDir, "state"), { recursive: true, force: true }),
    ).resolves.toBeUndefined();
  });
});
