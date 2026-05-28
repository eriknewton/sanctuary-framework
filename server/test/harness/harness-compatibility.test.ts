import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  access,
  cp,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  PORT_FALLBACK_ATTEMPTS,
  runWrap,
  type DashboardStarter,
  type RunWrapDeps,
  type WrapOptions,
} from "../../src/wrap/cli.js";
import type { DashboardHandle } from "../../src/dashboard/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = join(__dirname, "..", "..", "..");
const fixturesDir = join(__dirname, "fixtures");
const readmePath = join(repoRoot, "README.md");
const localAgentRecordsPath = join(
  repoRoot,
  "server",
  "src",
  "contracts",
  "v1.1",
  "local-agent-records.ts"
);

type HarnessFixture = {
  label: string;
  localKind: string;
  options: WrapOptions;
  configPath: (home: string) => string;
  fixture: string;
  serversKey: "mcp.servers" | "mcp_servers" | "mcpServers";
};

const harnesses: HarnessFixture[] = [
  {
    label: "OpenClaw",
    localKind: "openclaw",
    options: { openclaw: true },
    configPath: (home) => join(home, ".openclaw", "openclaw.json"),
    fixture: "openclaw.json",
    serversKey: "mcp.servers",
  },
  {
    label: "Hermes Agent",
    localKind: "hermes",
    options: { hermes: true },
    configPath: (home) => join(home, ".hermes", "cli-config.json"),
    fixture: "hermes.json",
    serversKey: "mcp_servers",
  },
  {
    label: "Claude Code",
    localKind: "claude_code",
    options: { claudeCode: true },
    configPath: (home) => join(home, ".claude.json"),
    fixture: "flat-mcp.json",
    serversKey: "mcpServers",
  },
  {
    label: "Cursor",
    localKind: "cursor",
    options: { cursor: true },
    configPath: (home) => join(home, ".cursor", "mcp.json"),
    fixture: "flat-mcp.json",
    serversKey: "mcpServers",
  },
  {
    label: "Cline",
    localKind: "cline",
    options: { cline: true },
    configPath: (home) =>
      join(
        home,
        "Library",
        "Application Support",
        "Code",
        "User",
        "globalStorage",
        "saoudrizwan.claude-dev",
        "settings",
        "cline_mcp_settings.json"
      ),
    fixture: "flat-mcp.json",
    serversKey: "mcpServers",
  },
  {
    label: "Mastra",
    localKind: "mastra",
    options: {},
    configPath: (home) => join(home, "mastra", "mcp.json"),
    fixture: "flat-mcp.json",
    serversKey: "mcpServers",
  },
  {
    label: "Generic MCP",
    localKind: "generic_mcp",
    options: {},
    configPath: (home) => join(home, "generic", "mcp.json"),
    fixture: "flat-mcp.json",
    serversKey: "mcpServers",
  },
];

describe("harness compatibility matrix", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;
  let originalPassphrase: string | undefined;
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    tmpHome = join(
      tmpdir(),
      `sanctuary-harness-${Date.now()}-${Math.random().toString(36).slice(2)}`
    );
    await mkdir(tmpHome, { recursive: true });
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    originalPassphrase = process.env.SANCTUARY_PASSPHRASE;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
    process.env.SANCTUARY_PASSPHRASE = "fixture-passphrase";
    stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(async () => {
    stderrSpy.mockRestore();
    restoreEnv("HOME", originalHome);
    restoreEnv("SANCTUARY_STORAGE_PATH", originalStoragePath);
    restoreEnv("SANCTUARY_PASSPHRASE", originalPassphrase);
    vi.restoreAllMocks();
    await rm(tmpHome, { recursive: true, force: true });
  });

  for (const harness of harnesses) {
    describe(harness.label, () => {
      it("dry-run validates config without writing backup, wrap, identity, or audit artifacts", async () => {
        const configPath = await installFixture(harness);
        const original = await readFile(configPath, "utf-8");

        await runWrap(resolveOptions(harness, configPath, { dryRun: true }), deps());

        expect(await readFile(configPath, "utf-8")).toBe(original);
        await expect(access(join(storagePath(), "backup"))).rejects.toThrow();
        await expect(access(join(storagePath(), "identities"))).rejects.toThrow();
        await expect(access(join(storagePath(), "audit"))).rejects.toThrow();
      });

      it("backs up, wraps, emits dashboard URL, and unwraps byte-equal config", async () => {
        const configPath = await installFixture(harness);
        const original = await readFile(configPath, "utf-8");
        const dashboardUrls: string[] = [];

        await runWrap(
          resolveOptions(harness, configPath, { noOpen: true }),
          deps({ dashboardUrls })
        );

        const backupDir = join(storagePath(), "backup");
        const backupNames = await readdir(backupDir);
        expect(backupNames.some((name) => name.startsWith("config-backup-"))).toBe(true);
        expect(JSON.parse(await readFile(join(backupDir, "cocoon-meta.json"), "utf-8"))).toMatchObject({
          originalPath: configPath,
        });
        expect(extractSanctuaryEntry(JSON.parse(await readFile(configPath, "utf-8")), harness.serversKey)).toMatchObject({
          command: "npx",
          args: ["@sanctuary-framework/mcp-server"],
        });
        expect(stderrText()).toContain("Sovereignty Dashboard running at");
        expect(stderrText()).toMatch(/http:\/\/127\.0\.0\.1:35\d\d\?token=/);
        expect(dashboardUrls).toHaveLength(1);
        expect(dashboardUrls[0]).toMatch(/http:\/\/127\.0\.0\.1:3501\?token=/);
        await expect(access(join(storagePath(), "identities"))).rejects.toThrow();
        await expect(access(join(storagePath(), "audit"))).rejects.toThrow();

        await runWrap({ unwrap: true }, deps());
        expect(await readFile(configPath, "utf-8")).toBe(original);
      });
    });
  }

  it("keeps identity/audit unsupported status explicit across all covered harnesses", () => {
    expect(harnesses.map((h) => h.localKind).sort()).toEqual([
      "claude_code",
      "cline",
      "cursor",
      "generic_mcp",
      "hermes",
      "mastra",
      "openclaw",
    ]);
  });
});

describe("harness compatibility negative paths", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;
  let stderrSpy: ReturnType<typeof vi.spyOn>;
  let exitSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    tmpHome = join(
      tmpdir(),
      `sanctuary-harness-negative-${Date.now()}-${Math.random().toString(36).slice(2)}`
    );
    await mkdir(tmpHome, { recursive: true });
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
    stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    exitSpy = vi.spyOn(process, "exit").mockImplementation((code?: string | number | null) => {
      throw new Error(`process.exit:${code}`);
    });
  });

  afterEach(async () => {
    stderrSpy.mockRestore();
    exitSpy.mockRestore();
    restoreEnv("HOME", originalHome);
    restoreEnv("SANCTUARY_STORAGE_PATH", originalStoragePath);
    vi.restoreAllMocks();
    await rm(tmpHome, { recursive: true, force: true });
  });

  it("reports a clear error for missing explicit config", async () => {
    await expect(
      runWrap({ wrap: join(tmpHome, "missing.json") }, deps())
    ).rejects.toThrow("process.exit:1");
    expect(stderrText()).toContain("Configuration Not Found");
    expect(stderrText()).toContain("Could not read config file");
  });

  it("reports malformed JSON diagnostics for invalid config", async () => {
    const configPath = join(tmpHome, "broken.json");
    await writeFile(configPath, "{ not-json");

    await expect(runWrap({ wrap: configPath }, deps())).rejects.toThrow(
      "process.exit:1"
    );
    expect(stderrText()).toContain("Invalid JSON");
  });

  it("fails clearly when every dashboard fallback port is busy", async () => {
    const configPath = await installFixture({
      ...harnesses[0]!,
      configPath: (home) => join(home, "generic.json"),
      fixture: "flat-mcp.json",
    });
    const busyStarter: DashboardStarter = async (opts) => {
      const err = new Error(`EADDRINUSE: port ${opts.port}`) as Error & { code: string };
      err.code = "EADDRINUSE";
      throw err;
    };

    await expect(
      runWrap({ wrap: configPath, noOpen: true, port: 4500 }, deps({ startDashboard: busyStarter }))
    ).rejects.toThrow(
      `No free dashboard port in the ${PORT_FALLBACK_ATTEMPTS} ports starting at 4500`
    );
  });

  it("fails closed on passphrase resolver failure before mutating config", async () => {
    const configPath = await installFixture({
      ...harnesses[0]!,
      configPath: (home) => join(home, "generic.json"),
      fixture: "flat-mcp.json",
    });
    const original = await readFile(configPath, "utf-8");

    await expect(
      runWrap(
        { wrap: configPath, noOpen: true },
        deps({
          resolvePassphrase: async () => {
            throw new Error("simulated keychain failure");
          },
        })
      )
    ).rejects.toThrow("simulated keychain failure");
    expect(await readFile(configPath, "utf-8")).toBe(original);
  });

  it("aborts on backup failure before rewrite mutation", async () => {
    const configPath = await installFixture({
      ...harnesses[0]!,
      configPath: (home) => join(home, "generic.json"),
      fixture: "flat-mcp.json",
    });
    const original = await readFile(configPath, "utf-8");

    await expect(
      runWrap(
        { wrap: configPath, noOpen: true },
        deps({
          resolvePassphrase: async () => {
            await rm(configPath);
            return {
              value: "fixture-passphrase",
              location: "fixture-keychain",
              source: "generated" as const,
            };
          },
        })
      )
    ).rejects.toThrow(/ENOENT|no such file/i);
    await writeFile(configPath, original);
    expect(await readFile(configPath, "utf-8")).toBe(original);
  });
});

describe("harness README parity", () => {
  it("maps every README-supported wrap target to LocalHarnessKind or generic_mcp", async () => {
    const readme = await readFile(readmePath, "utf-8");
    const records = await readFile(localAgentRecordsPath, "utf-8");
    const kinds = new Set(
      Array.from(records.matchAll(/\|\s+"([^"]+)"/g), (match) => match[1])
    );

    for (const kind of [
      "openclaw",
      "hermes",
      "claude_code",
      "cursor",
      "cline",
      "mastra",
      "generic_mcp",
      "other",
    ]) {
      expect(kinds.has(kind)).toBe(true);
    }

    expect(readme).toContain("OpenClaw");
    expect(readme).toContain("Hermes Agent");
    expect(readme).toContain("Claude Code");
    expect(readme).toContain("Cursor");
    expect(readme).toContain("Cline");
    expect(readme).toContain("Mastra");
    expect(readme).toContain("LangGraph");
    expect(readme).toContain("custom harnesses");
    expect(readme).toContain("Any other MCP-compatible harness");
    expect(readme).toContain("sanctuary protect --wrap <path>");
    expect(records).toContain("LangGraph wraps land via the generic");
  });
});

function restoreEnv(name: string, value: string | undefined): void {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

function storagePath(): string {
  return process.env.SANCTUARY_STORAGE_PATH!;
}

function stderrText(): string {
  return (console.error as unknown as { mock: { calls: unknown[][] } }).mock.calls
    .map((call) => call.join(" "))
    .join("\n");
}

async function installFixture(harness: HarnessFixture): Promise<string> {
  const target = harness.configPath(process.env.HOME!);
  await mkdir(dirname(target), { recursive: true });
  await cp(join(fixturesDir, harness.fixture), target);
  return target;
}

function resolveOptions(
  harness: HarnessFixture,
  configPath: string,
  extra: WrapOptions
): WrapOptions {
  const base =
    harness.localKind === "mastra" || harness.localKind === "generic_mcp"
      ? { wrap: configPath }
      : harness.options;
  return { ...base, ...extra };
}

function deps(
  opts: {
    dashboardUrls?: string[];
    startDashboard?: DashboardStarter;
    resolvePassphrase?: RunWrapDeps["resolvePassphrase"];
    rewriteConfig?: RunWrapDeps["rewriteConfig"];
    beforeDashboard?: () => Promise<void>;
  } = {}
): RunWrapDeps {
  const startDashboard: DashboardStarter =
    opts.startDashboard ??
    (async (startOpts) => {
      await opts.beforeDashboard?.();
      const handle = {
        url: `http://127.0.0.1:${startOpts.port}`,
        port: startOpts.port,
        host: "127.0.0.1",
        mode: "co-located",
        stop: async () => {},
      } as DashboardHandle;
      opts.dashboardUrls?.push(`${handle.url}?token=${startOpts.authToken}`);
      return handle;
    });

  return {
    startDashboard,
    openBrowser: async () => {},
    resolvePassphrase:
      opts.resolvePassphrase ??
      (async () => ({
        value: "fixture-passphrase",
        location: "fixture-keychain",
        source: "generated" as const,
      })),
    rewriteConfig: opts.rewriteConfig,
  };
}

function extractSanctuaryEntry(
  parsed: Record<string, unknown>,
  serversKey: HarnessFixture["serversKey"]
): Record<string, unknown> | undefined {
  if (serversKey === "mcp.servers") {
    return ((parsed.mcp as Record<string, unknown>).servers as Record<string, unknown>)
      .sanctuary as Record<string, unknown>;
  }
  return (parsed[serversKey] as Record<string, unknown>).sanctuary as
    | Record<string, unknown>
    | undefined;
}
