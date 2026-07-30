import { afterEach, describe, expect, it, vi } from "vitest";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  createProtectPreflightOps,
  protectPreflightExitCode,
  renderProtectPreflightJson,
  renderProtectPreflightReport,
  runProtectPreflight,
  type AccessKind,
  type AccessResult,
  type ExecFileResult,
  type FsEntry,
  type ProtectPreflightCheckId,
  type ProtectPreflightOps,
  type ProtectPreflightReport,
  type ProviderHttpRequest,
} from "../../src/wrap/preflight.js";
import {
  __resetProcessShutdownStateForTest,
  runWrap,
} from "../../src/wrap/cli.js";
import {
  CLI_SUBPROCESS_TEST_TIMEOUT_MS,
  runCliRaw,
} from "../cli/helpers/run-cli.js";

const OPERATOR_HOME = "/Users/operator";
const FORTRESS = `${OPERATOR_HOME}/.sanctuary`;
const CASTLE_SOCKET = `${FORTRESS}/castle.sock`;
const SIGNER = "/Applications/Sanctuary.app/Contents/MacOS/signer-client";
const ROOT_SANCTUARY = "/usr/local/bin/sanctuary";
const FDA_PROBE = `${OPERATOR_HOME}/Library/Caches/com.apple.containermanagerd`;
const HERMES_GATEWAY_PLIST = `${OPERATOR_HOME}/Library/LaunchAgents/ai.hermes.gateway.plist`;
const PRETEND_TIME = new Date("2026-07-29T12:00:00.000Z");

interface FixtureOpsInput {
  env?: NodeJS.ProcessEnv;
  platform?: string;
  uid?: number;
  entries?: Map<string, FsEntry>;
  executable?: Set<string>;
  readText?: Map<string, { ok: true; text: string } | { ok: false; reason: string; code?: string }>;
  readDir?: Map<string, { ok: true } | { ok: false; reason: string; code?: string }>;
  readFileSample?: Map<string, { ok: true } | { ok: false; reason: string; code?: string }>;
  execFile?: (cmd: string, args: string[]) => Promise<ExecFileResult>;
  fetch?: (url: string, request: ProviderHttpRequest) => Promise<{ status: number }>;
  access?: (path: string, kind: AccessKind) => Promise<AccessResult>;
}

function present(kind: "file" | "dir"): FsEntry {
  return {
    kind: "present",
    isFile: kind === "file",
    isDirectory: kind === "dir",
    isSymbolicLink: false,
  };
}

function absentEntry(): FsEntry {
  return { kind: "absent" };
}

function unknownEntry(reason = "EIO"): FsEntry {
  return { kind: "unknown", reason, code: reason };
}

function execResult(
  code: number,
  stdout = "",
  stderr = "",
  errorCode?: string,
): ExecFileResult {
  return { code, stdout, stderr, errorCode };
}

function baseEnv(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    HOME: OPERATOR_HOME,
    PATH: "/usr/bin:/usr/local/bin",
    SANCTUARY_STORAGE_PATH: FORTRESS,
    SANCTUARY_CASTLE_SIGNER_CLIENT: SIGNER,
    VENICE_API_KEY: "test-venice-key",
    ...overrides,
  };
}

function fixtureOps(input: FixtureOpsInput = {}): ProtectPreflightOps {
  const entries = input.entries ?? new Map<string, FsEntry>([[FDA_PROBE, present("dir")]]);
  const executable = input.executable ?? new Set<string>([ROOT_SANCTUARY, SIGNER]);
  const readText = input.readText ?? new Map();
  const readDir = input.readDir ?? new Map([[FDA_PROBE, { ok: true }]]);
  const readFileSample = input.readFileSample ?? new Map();
  const env = input.env ?? baseEnv();
  return {
    now: () => PRETEND_TIME,
    platform: () => input.platform ?? "darwin",
    cwd: () => fileURLToPath(new URL("../../", import.meta.url)),
    env: () => env,
    homeDir: () => env.HOME ?? OPERATOR_HOME,
    getuid: () => input.uid ?? 501,
    execFile:
      input.execFile ??
      (async (cmd, args) => {
        const joined = args.join(" ");
        if (cmd.endsWith("lsof")) return execResult(1);
        if (cmd === "systemextensionsctl") {
          return execResult(
            0,
            "1 extension(s)\n--- com.apple.system_extension.network_extension\n[activated enabled] ai.sanctuaryprotocol.castlewall\n",
          );
        }
        if (cmd === "launchctl" && joined.includes("system/ai.sanctuaryprotocol.castle-wall.daemon")) {
          return execResult(113, "", "Could not find service");
        }
        if (cmd === "launchctl" && joined.includes("gui/501/ai.hermes.gateway")) {
          return execResult(113, "", "Could not find service");
        }
        if (cmd.endsWith("ps")) return execResult(0, "UID PID COMMAND\n");
        return execResult(1, "", `unexpected exec ${cmd} ${joined}`);
      }),
    entry: async (path) => entries.get(path) ?? absentEntry(),
    access:
      input.access ??
      (async (path) =>
        executable.has(path)
          ? { ok: true }
          : { ok: false, reason: "ENOENT", code: "ENOENT" }),
    readText:
      async (path) =>
        readText.get(path) ?? { ok: false, reason: "ENOENT", code: "ENOENT" },
    readDir:
      async (path) =>
        readDir.get(path) ?? { ok: false, reason: "ENOENT", code: "ENOENT" },
    readFileSample:
      async (path) =>
        readFileSample.get(path) ?? { ok: false, reason: "ENOENT", code: "ENOENT" },
    fetch: input.fetch ?? (async () => ({ status: 200 })),
  };
}

function row(
  report: ProtectPreflightReport,
  id: ProtectPreflightCheckId,
) {
  const found = report.rows.find((candidate) => candidate.id === id);
  if (found === undefined) throw new Error(`missing row ${id}`);
  return found;
}

function failingReportFixture(): ProtectPreflightReport {
  return {
    command: "sanctuary protect preflight",
    generated_at: PRETEND_TIME.toISOString(),
    strict: false,
    summary: { pass: 0, fail: 1, undetermined: 0 },
    rows: [
      {
        id: "signer_client",
        check: "signer client",
        status: "FAIL",
        state: "env_missing",
        detail: "SANCTUARY_CASTLE_SIGNER_CLIENT is not set.",
        remedy: "Export SANCTUARY_CASTLE_SIGNER_CLIENT.",
        findings: ["F-3"],
      },
    ],
  };
}

describe("protect preflight", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    __resetProcessShutdownStateForTest();
  });

  it("reports PASS for every check when the fixture is known healthy", async () => {
    const report = await runProtectPreflight({
      ops: fixtureOps(),
    });

    expect(report.summary).toEqual({ pass: 7, fail: 0, undetermined: 0 });
    expect(protectPreflightExitCode(report)).toBe(0);
    expect(report.rows.map((candidate) => candidate.status)).toEqual([
      "PASS",
      "PASS",
      "PASS",
      "PASS",
      "PASS",
      "PASS",
      "PASS",
    ]);
    expect(row(report, "provider_liveness").providers?.[0]?.state).toBe("live");
    expect(JSON.parse(renderProtectPreflightJson(report))).toMatchObject({
      command: "sanctuary protect preflight",
      summary: { pass: 7, fail: 0, undetermined: 0 },
    });
    expect(renderProtectPreflightReport(report)).toContain("| PASS");
  });

  it("escapes backslashes before pipes in rendered table cells", () => {
    const report = failingReportFixture();
    report.rows[0]!.detail = String.raw`path \| injected | next`;
    report.rows[0]!.remedy = "line one\nline two";

    const rendered = renderProtectPreflightReport(report);

    expect(rendered).toContain(String.raw`path \\\| injected \| next`);
    expect(rendered).toContain("line one line two");
  });

  it("reports every drill-mini2 failure in one run, including billing_dead and exact safe-mode bootout remedy", async () => {
    const report = await runProtectPreflight({
      ops: fixtureOps({
        env: baseEnv({
          PATH: "/missing",
          SANCTUARY_CASTLE_SIGNER_CLIENT: "",
          VENICE_API_KEY: "billing-dead",
        }),
        executable: new Set(),
        entries: new Map([
          [CASTLE_SOCKET, present("file")],
          [FDA_PROBE, present("dir")],
          [HERMES_GATEWAY_PLIST, present("file")],
        ]),
        readDir: new Map([
          [FDA_PROBE, { ok: false, reason: "EACCES", code: "EACCES" }],
        ]),
        execFile: async (cmd, args) => {
          const joined = args.join(" ");
          if (cmd.endsWith("lsof")) {
            return execResult(
              0,
              `COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nnode 42 root 5u unix 0x0 0t0 ${CASTLE_SOCKET}\n`,
            );
          }
          if (cmd === "launchctl" && joined.includes("system/ai.sanctuaryprotocol.castle-wall.daemon")) {
            return execResult(0, "{\n  pid = 42;\n}\n");
          }
          if (cmd === "systemextensionsctl") {
            return execResult(0, "[activated waiting for user] ai.sanctuaryprotocol.castlewall\n");
          }
          if (cmd === "launchctl" && joined.includes("gui/501/ai.hermes.gateway")) {
            return execResult(0, "{\n  state = running;\n  pid = 88;\n}\n");
          }
          if (cmd.endsWith("ps")) {
            return execResult(0, "UID PID COMMAND\n501 88 python -m hermes_cli.main gateway\n");
          }
          return execResult(1, "", `unexpected ${cmd} ${joined}`);
        },
        fetch: async () => ({ status: 402 }),
      }),
    });

    expect(report.summary).toEqual({ pass: 0, fail: 7, undetermined: 0 });
    expect(row(report, "castle_sock_holder")).toMatchObject({
      status: "FAIL",
      state: "launchd_safe_mode_boot_daemon",
      remedy: "sudo launchctl bootout system/ai.sanctuaryprotocol.castle-wall.daemon",
    });
    expect(row(report, "root_path_sanctuary").remedy).toContain(
      "node server/dist/cli.js",
    );
    expect(row(report, "signer_client").state).toBe("env_missing");
    expect(row(report, "sysext_approval").state).toBe("[activated waiting for user]");
    expect(row(report, "full_disk_access").state).toBe("full_disk_access_denied");
    expect(row(report, "provider_liveness")).toMatchObject({
      status: "FAIL",
      state: "billing_dead",
    });
    expect(row(report, "provider_liveness").providers?.[0]).toMatchObject({
      state: "billing_dead",
      detail: "provider returned HTTP 402 billing_dead",
    });
    expect(row(report, "operator_twin_services").remedy).toContain(
      "launchctl bootout gui/501",
    );
    expect(row(report, "operator_twin_services").remedy).toContain(
      "launchctl disable gui/501/ai.hermes.gateway",
    );
  });

  it("sends Gemini preflight credentials in the x-goog-api-key header, not the URL", async () => {
    const requests: Array<{ url: string; request: ProviderHttpRequest }> = [];
    const report = await runProtectPreflight({
      ops: fixtureOps({
        env: baseEnv({
          VENICE_API_KEY: "",
          GEMINI_API_KEY: "gemini-secret",
          GOOGLE_API_KEY: "",
        }),
        fetch: async (url, request) => {
          requests.push({ url, request });
          return { status: 200 };
        },
      }),
    });

    expect(row(report, "provider_liveness")).toMatchObject({
      status: "PASS",
      state: "all_configured_providers_live",
    });
    expect(requests).toEqual([
      {
        url: "https://generativelanguage.googleapis.com/v1beta/models",
        request: {
          method: "GET",
          headers: { "x-goog-api-key": "gemini-secret" },
        },
      },
    ]);
  });

  it("reports UNDETERMINED instead of passing by omission when probes cannot establish facts", async () => {
    const report = await runProtectPreflight({
      ops: fixtureOps({
        env: baseEnv({
          PATH: "/mystery",
          SANCTUARY_CASTLE_SIGNER_CLIENT: "/mystery/signer-client",
          VENICE_API_KEY: "",
        }),
        executable: new Set(),
        entries: new Map([
          [CASTLE_SOCKET, unknownEntry("EIO")],
          [FDA_PROBE, unknownEntry("EIO")],
          [HERMES_GATEWAY_PLIST, unknownEntry("EIO")],
        ]),
        access: async () => ({ ok: false, reason: "EIO", code: "EIO" }),
        execFile: async (cmd, args) => {
          const joined = args.join(" ");
          if (cmd === "systemextensionsctl") return execResult(1, "", "blocked", "EIO");
          if (cmd === "launchctl" && joined.includes("gui/501/ai.hermes.gateway")) {
            return execResult(1, "", "blocked", "EIO");
          }
          if (cmd.endsWith("ps")) return execResult(1, "", "blocked", "EIO");
          return execResult(1, "", "blocked", "EIO");
        },
      }),
    });

    expect(report.summary).toEqual({ pass: 0, fail: 0, undetermined: 7 });
    expect(report.rows.every((candidate) => candidate.status === "UNDETERMINED")).toBe(true);
    expect(protectPreflightExitCode(report)).toBe(0);
    expect(protectPreflightExitCode(report, true)).toBe(2);
  });

  it("does not write when run against a read-only fixture tree", async () => {
    const tmp = await mkdtemp(join(tmpdir(), "sanctuary-preflight-readonly-"));
    const home = join(tmp, "home");
    const bin = join(tmp, "bin");
    const sanctuaryBin = join(bin, "sanctuary");
    try {
      await mkdir(home, { recursive: true });
      await mkdir(bin, { recursive: true });
      await writeFile(sanctuaryBin, "#!/bin/sh\nexit 0\n");
      await chmod(sanctuaryBin, 0o755);
      await chmod(home, 0o555);
      const before = await treeSnapshot(tmp);

      const report = await runProtectPreflight({
        ops: {
          ...createProtectPreflightOps(),
          platform: () => "linux",
          now: () => PRETEND_TIME,
          cwd: () => tmp,
          env: () => ({
            HOME: home,
            PATH: bin,
            SANCTUARY_STORAGE_PATH: join(tmp, "fortress"),
            VENICE_API_KEY: "",
            OPENAI_API_KEY: "",
            ANTHROPIC_API_KEY: "",
            GEMINI_API_KEY: "",
            GOOGLE_API_KEY: "",
            TELEGRAM_BOT_TOKEN: "",
          }),
          homeDir: () => home,
          getuid: () => 501,
        },
      });

      expect(row(report, "root_path_sanctuary").status).toBe("PASS");
      expect(await treeSnapshot(tmp)).toEqual(before);
      const source = await readFile(
        fileURLToPath(new URL("../../src/wrap/preflight.ts", import.meta.url)),
        "utf8",
      );
      expect(source).not.toMatch(/\b(writeFile|mkdir|rm|unlink|rename|chown)\b/);
    } finally {
      await chmod(home, 0o755).catch(() => {});
      await rm(tmp, { recursive: true, force: true });
    }
  });

  it("runs the actual CLI verb: sanctuary protect --preflight --json", async () => {
    const tmp = await mkdtemp(join(tmpdir(), "sanctuary-preflight-cli-"));
    const home = join(tmp, "home");
    const bin = join(tmp, "bin");
    const helper = join(tmp, "signer-client");
    try {
      await mkdir(home, { recursive: true });
      await mkdir(bin, { recursive: true });
      await writeFile(join(bin, "sanctuary"), "#!/bin/sh\nexit 0\n");
      await writeFile(helper, "#!/bin/sh\nexit 0\n");
      await chmod(join(bin, "sanctuary"), 0o755);
      await chmod(helper, 0o755);

      const result = await runCliRaw(["protect", "--preflight", "--json"], {
        attemptTimeoutMs: 30_000,
        env: {
          HOME: home,
          USERPROFILE: home,
          PATH: `${bin}${delimiter}${process.env.PATH ?? ""}`,
          SANCTUARY_STORAGE_PATH: join(tmp, "fortress"),
          SANCTUARY_CASTLE_SIGNER_CLIENT: helper,
          VENICE_API_KEY: "",
          OPENAI_API_KEY: "",
          ANTHROPIC_API_KEY: "",
          GEMINI_API_KEY: "",
          GOOGLE_API_KEY: "",
          TELEGRAM_BOT_TOKEN: "",
        },
      });

      expect([0, 2]).toContain(result.code);
      const parsed = JSON.parse(result.stdout) as ProtectPreflightReport;
      expect(parsed.command).toBe("sanctuary protect preflight");
      expect(parsed.rows.map((candidate) => candidate.id)).toEqual([
        "castle_sock_holder",
        "root_path_sanctuary",
        "signer_client",
        "sysext_approval",
        "full_disk_access",
        "provider_liveness",
        "operator_twin_services",
      ]);
      expect(result.stderr).not.toContain("Bootstrapped");
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
  }, CLI_SUBPROCESS_TEST_TIMEOUT_MS);

  it("protect refuses before config detection or bootstrap when preflight fails", async () => {
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new Error(`process.exit:${code ?? 0}`);
    }) as never);
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await expect(
        runWrap(
          { protectCommand: true, hermes: true },
          { runProtectPreflight: async () => failingReportFixture() },
        ),
      ).rejects.toThrow("process.exit:2");
      expect(exitSpy).toHaveBeenCalledWith(2);
      expect(consoleErrorSpy.mock.calls.map((call) => String(call[0])).join("")).toContain(
        "Sanctuary protect refused before any host mutation",
      );
    } finally {
      exitSpy.mockRestore();
      stderrSpy.mockRestore();
      consoleErrorSpy.mockRestore();
    }
  });
});

async function treeSnapshot(root: string): Promise<string[]> {
  const results: string[] = [];
  async function walk(path: string, rel: string): Promise<void> {
    const current = await stat(path);
    results.push(`${rel || "."}:${current.isDirectory() ? "dir" : "file"}:${current.mode & 0o777}`);
    if (!current.isDirectory()) return;
    const entries = await readdir(path);
    entries.sort();
    for (const entry of entries) {
      await walk(join(path, entry), rel === "" ? entry : join(rel, entry));
    }
  }
  await walk(root, "");
  return results;
}
