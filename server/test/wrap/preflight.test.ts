import { afterEach, describe, expect, it, vi } from "vitest";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  createProtectPreflightOps,
  describeProtectPreflightBlockers,
  describeProtectPreflightStrictWarnings,
  protectPreflightExitCode,
  renderProtectPreflightJson,
  renderProtectPreflightReport,
  runOperatorTwinPreflight,
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

// One row per check id, in the order runProtectPreflight emits them. Expected
// pass/fail/undetermined counts in an all-one-status fixture are derived from
// this list's length rather than a bare number, so adding or removing a
// check id cannot silently desync from what the assertions expect.
const ALL_PREFLIGHT_CHECK_IDS: ProtectPreflightCheckId[] = [
  "castle_sock_holder",
  "fortress_custody",
  "root_path_sanctuary",
  "signer_client",
  "sysext_approval",
  "full_disk_access",
  "provider_liveness",
  "operator_twin_services",
  "boot_runtime_devtools",
];

// Must match XCODE_SELECT_PATH / OTOOL_PATH / OTOOL_PROBE_TARGET in
// ../../src/wrap/preflight.ts. Pinning the exact executable AND args (not
// just "the command name ends with xcode-select") means a regression that
// starts passing different or mutating args (e.g. `xcode-select --install`)
// fails these fixtures instead of silently matching a permissive stub.
const XCODE_SELECT_CMD = "/usr/bin/xcode-select";
const XCODE_SELECT_ARGS = ["-p"];
const OTOOL_CMD = "/usr/bin/otool";
const OTOOL_ARGS = ["-L", "/bin/ls"];

function isExactCall(cmd: string, args: string[], expectedCmd: string, expectedArgs: string[]): boolean {
  return cmd === expectedCmd && args.length === expectedArgs.length && args.every((arg, index) => arg === expectedArgs[index]);
}

type OwnerResult =
  | { ok: true; uid: number; gid: number }
  | { ok: false; reason: string; code?: string };

interface FixtureOpsInput {
  env?: NodeJS.ProcessEnv;
  platform?: string;
  uid?: number;
  entries?: Map<string, FsEntry>;
  owner?: Map<string, OwnerResult>;
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
    // OpenAI, not Venice: OpenAI's endpoint genuinely rejects an invalid
    // credential (see PROVIDER_INVALID_CREDENTIAL_RESPONSE below), so a
    // generic "healthy host" fixture can honestly reach PASS. Venice's
    // endpoint cannot, and is exercised only where a test says so by name.
    OPENAI_API_KEY: "test-openai-key",
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
        if (isExactCall(cmd, args, XCODE_SELECT_CMD, XCODE_SELECT_ARGS)) {
          return execResult(0, "/Library/Developer/CommandLineTools\n");
        }
        if (isExactCall(cmd, args, OTOOL_CMD, OTOOL_ARGS)) {
          return execResult(
            0,
            `${OTOOL_ARGS[1]}:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1.0.0)\n`,
          );
        }
        return execResult(1, "", `unexpected exec ${cmd} ${joined}`);
      }),
    entry: async (path) => entries.get(path) ?? absentEntry(),
    owner: async (path) =>
      (input.owner ?? new Map<string, OwnerResult>([[FORTRESS, { ok: true, uid: 501, gid: 20 }]])).get(
        path,
      ) ?? { ok: false, reason: "ENOENT", code: "ENOENT" },
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
    fetch:
      input.fetch ??
      (async (url, request) => {
        // A fixture-realistic default: only the credential(s) actually
        // configured in this fixture's env count as "valid", so PASS
        // assertions exercise the preflight's real/invalid-credential
        // discrimination probe instead of every request trivially
        // succeeding regardless of what credential was presented.
        //
        // defect.preflight-provider-liveness-probe-not-authenticated
        const validCredentials = new Set(
          [
            env.VENICE_API_KEY,
            env.OPENAI_API_KEY,
            env.ANTHROPIC_API_KEY,
            env.GEMINI_API_KEY,
            env.GOOGLE_API_KEY,
            env.TELEGRAM_BOT_TOKEN,
          ].filter((value): value is string => typeof value === "string" && value.length > 0),
        );
        const presented =
          request.headers?.Authorization?.replace(/^Bearer\s+/, "") ??
          request.headers?.["x-api-key"] ??
          request.headers?.["x-goog-api-key"] ??
          /\/bot([^/]+)\//.exec(url)?.[1];
        return presented !== undefined && validCredentials.has(presented)
          ? { status: 200 }
          : { status: 401 };
      }),
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

    expect(report.summary).toEqual({ pass: ALL_PREFLIGHT_CHECK_IDS.length, fail: 0, undetermined: 0 });
    expect(protectPreflightExitCode(report)).toBe(0);
    expect(report.rows.map((candidate) => candidate.id)).toEqual(ALL_PREFLIGHT_CHECK_IDS);
    expect(report.rows.map((candidate) => candidate.status)).toEqual(
      ALL_PREFLIGHT_CHECK_IDS.map(() => "PASS"),
    );
    expect(row(report, "fortress_custody").state).toBe("operator_owned");
    expect(row(report, "provider_liveness").providers?.[0]?.state).toBe("live");
    expect(row(report, "boot_runtime_devtools").state).toBe("developer_tools_present");
    expect(JSON.parse(renderProtectPreflightJson(report))).toMatchObject({
      command: "sanctuary protect preflight",
      summary: { pass: ALL_PREFLIGHT_CHECK_IDS.length, fail: 0, undetermined: 0 },
    });
    expect(renderProtectPreflightReport(report)).toContain("| PASS");
  });

  it("exposes the authoritative operator-twin row without running provider probes", async () => {
    const fetch = vi.fn(async () => ({ status: 200 }));
    const twin = await runOperatorTwinPreflight({
      ops: fixtureOps({ fetch }),
    });

    expect(twin).toMatchObject({
      id: "operator_twin_services",
      status: "PASS",
      state: "no_operator_gateway",
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("accepts the canonical executable sealed launcher without a root PATH dependency", async () => {
    const sealedLauncher =
      "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/sanctuary";
    const report = await runProtectPreflight({
      sealedLauncherPath: sealedLauncher,
      ops: fixtureOps({
        env: baseEnv({ PATH: "/missing" }),
        executable: new Set([sealedLauncher]),
      }),
    });

    expect(row(report, "root_path_sanctuary")).toMatchObject({
      status: "PASS",
      state: "canonical_sealed_launcher",
      remedy: "none",
    });
    expect(row(report, "root_path_sanctuary").detail).toContain(sealedLauncher);
  });

  it("does not accept a caller-selected executable as the sealed launcher", async () => {
    const report = await runProtectPreflight({
      sealedLauncherPath: "/tmp/sanctuary",
      ops: fixtureOps({
        env: baseEnv({ PATH: "/missing" }),
        executable: new Set(["/tmp/sanctuary"]),
      }),
    });

    expect(row(report, "root_path_sanctuary")).toMatchObject({
      status: "FAIL",
      state: "sealed_launcher_noncanonical",
    });

    const missingCanonical = await runProtectPreflight({
      sealedLauncherPath:
        "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/sanctuary",
      ops: fixtureOps({
        env: baseEnv({ PATH: "/missing" }),
        executable: new Set(),
      }),
    });
    expect(row(missingCanonical, "root_path_sanctuary")).toMatchObject({
      status: "FAIL",
      state: "sealed_launcher_not_executable",
    });
  });

  it("reports an unknown sealed-launcher probe conservatively", async () => {
    const unknownCanonical = await runProtectPreflight({
      sealedLauncherPath:
        "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/sanctuary",
      ops: fixtureOps({
        env: baseEnv({ PATH: "/missing" }),
        access: async () => ({ ok: false, reason: "EIO", code: "EIO" }),
      }),
    });
    expect(row(unknownCanonical, "root_path_sanctuary")).toMatchObject({
      status: "UNDETERMINED",
      state: "sealed_launcher_probe_unknown",
    });
  });

  it("validates and forwards the sealed launcher before the automatic preflight", async () => {
    const source = await readFile(
      fileURLToPath(new URL("../../src/wrap/cli.ts", import.meta.url)),
      "utf8",
    );
    const validation = source.indexOf(
      "await validateSealedLauncher(options.sealedLauncher)",
    );
    const preflight = source.indexOf(
      "const preflight = await (deps.runProtectPreflight ?? runProtectPreflight)",
    );

    expect(validation).toBeGreaterThan(-1);
    expect(preflight).toBeGreaterThan(validation);
    expect(source.slice(preflight, preflight + 320)).toContain(
      "sealedLauncherPath: options.sealedLauncher",
    );
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
          OPENAI_API_KEY: "",
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
        // The drill-mini2 state: the fortress itself is ROOT-owned.
        owner: new Map<string, OwnerResult>([[FORTRESS, { ok: true, uid: 0, gid: 20 }]]),
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
          if (isExactCall(cmd, args, XCODE_SELECT_CMD, XCODE_SELECT_ARGS)) {
            // The real xcode-select -p exit shape when Command Line Tools
            // are not installed: nonzero exit, no spawn-level error.
            return execResult(
              2,
              "",
              "xcode-select: error: unable to get active developer directory, use `sudo xcode-select --switch path/to/Xcode.app` to specify one",
            );
          }
          return execResult(1, "", `unexpected ${cmd} ${joined}`);
        },
        fetch: async () => ({ status: 402 }),
      }),
    });

    expect(report.summary).toEqual({ pass: 0, fail: ALL_PREFLIGHT_CHECK_IDS.length, undetermined: 0 });
    expect(row(report, "boot_runtime_devtools")).toMatchObject({
      status: "FAIL",
      state: "developer_tools_missing",
    });
    expect(row(report, "castle_sock_holder")).toMatchObject({
      status: "FAIL",
      state: "launchd_safe_mode_boot_daemon",
      remedy: "sudo launchctl bootout system/ai.sanctuaryprotocol.castle-wall.daemon",
    });
    expect(row(report, "fortress_custody")).toMatchObject({
      status: "FAIL",
      state: "root_owned_fortress",
      remedy: "Run: sudo sanctuary castle-wall repair-custody",
    });
    expect(row(report, "fortress_custody").detail).toContain("dead-man lever");
    expect(row(report, "root_path_sanctuary").remedy).toContain(
      "canonical signed-app launcher",
    );
    expect(row(report, "root_path_sanctuary").remedy).not.toMatch(
      /\bnode\b|\bnpm\b|\bnpx\b/,
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

  it("lets only the automatic retry accept the exact launchd boot daemon for this fortress", async () => {
    const ops = fixtureOps({
      env: baseEnv(),
      entries: new Map([[CASTLE_SOCKET, present("file")]]),
      execFile: async (cmd, args) => {
        if (cmd.endsWith("lsof")) {
          return execResult(
            0,
            `COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nnode 42 root 5u unix 0x0 0t0 ${CASTLE_SOCKET}\n`,
          );
        }
        if (cmd === "launchctl" && args.join(" ").includes("system/ai.sanctuaryprotocol.castle-wall.daemon")) {
          return execResult(
            0,
            `{\n  pid = 42;\n  environment = {\n    SANCTUARY_STORAGE_PATH => ${FORTRESS}\n  }\n}\n`,
          );
        }
        return execResult(1, "", "not configured");
      },
    });

    const explicit = await runProtectPreflight({ ops });
    expect(row(explicit, "castle_sock_holder")).toMatchObject({
      status: "FAIL",
      state: "launchd_safe_mode_boot_daemon",
    });

    const retry = await runProtectPreflight({
      ops,
      allowMatchingBootDaemon: true,
    });
    expect(row(retry, "castle_sock_holder")).toMatchObject({
      status: "PASS",
      state: "matching_launchd_safe_mode_boot_daemon",
      remedy: "none",
    });
  });

  it("still refuses a launchd daemon whose loaded fortress does not match", async () => {
    const report = await runProtectPreflight({
      allowMatchingBootDaemon: true,
      ops: fixtureOps({
        env: baseEnv(),
        entries: new Map([[CASTLE_SOCKET, present("file")]]),
        execFile: async (cmd, args) => {
          if (cmd.endsWith("lsof")) {
            return execResult(
              0,
              `COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nnode 42 root 5u unix 0x0 0t0 ${CASTLE_SOCKET}\n`,
            );
          }
          if (cmd === "launchctl" && args.join(" ").includes("system/ai.sanctuaryprotocol.castle-wall.daemon")) {
            return execResult(
              0,
              "{\n  pid = 42;\n  environment = {\n    SANCTUARY_STORAGE_PATH => /Users/other/.sanctuary\n  }\n}\n",
            );
          }
          return execResult(1, "", "not configured");
        },
      }),
    });

    expect(row(report, "castle_sock_holder")).toMatchObject({
      status: "FAIL",
      state: "launchd_safe_mode_boot_daemon",
    });
  });

  it("sends Gemini preflight credentials in the x-goog-api-key header, not the URL, and reads UNDETERMINED (Gemini's endpoint does not return a recognized rejection)", async () => {
    const requests: Array<{ url: string; request: ProviderHttpRequest }> = [];
    const report = await runProtectPreflight({
      ops: fixtureOps({
        env: baseEnv({
          OPENAI_API_KEY: "",
          VENICE_API_KEY: "",
          GEMINI_API_KEY: "gemini-secret",
          GOOGLE_API_KEY: "",
        }),
        // "gemini-secret" succeeds; any other credential (including the
        // invalid-credential probe) gets Gemini's real invalid-credential
        // status (see PROVIDER_INVALID_CREDENTIAL_RESPONSE below) so this
        // exercises the second (invalid-credential) request honestly.
        fetch: async (url, request) => {
          requests.push({ url, request });
          return { status: request.headers?.["x-goog-api-key"] === "gemini-secret" ? 200 : 400 };
        },
      }),
    });

    expect(row(report, "provider_liveness")).toMatchObject({
      status: "UNDETERMINED",
      state: "provider_probe_unknown",
    });
    expect(row(report, "provider_liveness").providers?.[0]).toMatchObject({
      status: "UNDETERMINED",
      state: "credential_discrimination_inconclusive",
    });
    expect(requests).toHaveLength(2);
    expect(requests[0]).toEqual({
      url: "https://generativelanguage.googleapis.com/v1beta/models",
      request: {
        method: "GET",
        headers: { "x-goog-api-key": "gemini-secret" },
      },
    });
    // The discrimination probe reuses the same URL/method with a credential
    // guaranteed not to be "gemini-secret".
    expect(requests[1]?.url).toBe(requests[0]?.url);
    expect(requests[1]?.request.method).toBe("GET");
    expect(requests[1]?.request.headers?.["x-goog-api-key"]).not.toBe("gemini-secret");
  });

  it("reports UNDETERMINED instead of passing by omission when probes cannot establish facts", async () => {
    const report = await runProtectPreflight({
      ops: fixtureOps({
        env: baseEnv({
          PATH: "/mystery",
          SANCTUARY_CASTLE_SIGNER_CLIENT: "/mystery/signer-client",
          OPENAI_API_KEY: "",
          VENICE_API_KEY: "",
        }),
        executable: new Set(),
        entries: new Map([
          [CASTLE_SOCKET, unknownEntry("EIO")],
          [FDA_PROBE, unknownEntry("EIO")],
          [HERMES_GATEWAY_PLIST, unknownEntry("EIO")],
        ]),
        owner: new Map<string, OwnerResult>([
          [FORTRESS, { ok: false, reason: "EIO", code: "EIO" }],
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

    expect(report.summary).toEqual({ pass: 0, fail: 0, undetermined: ALL_PREFLIGHT_CHECK_IDS.length });
    expect(report.rows.every((candidate) => candidate.status === "UNDETERMINED")).toBe(true);
    expect(protectPreflightExitCode(report)).toBe(0);
    expect(protectPreflightExitCode(report, true)).toBe(2);
  });

  it("fortress_custody FAILs on any non-operator owner and PASSes on an absent fortress", async () => {
    const mismatch = await runProtectPreflight({
      ops: fixtureOps({
        owner: new Map<string, OwnerResult>([[FORTRESS, { ok: true, uid: 777, gid: 20 }]]),
      }),
    });
    expect(row(mismatch, "fortress_custody")).toMatchObject({
      status: "FAIL",
      state: "owner_mismatch",
      remedy: "Run: sudo sanctuary castle-wall repair-custody",
    });
    expect(protectPreflightExitCode(mismatch)).toBe(2);

    const absent = await runProtectPreflight({
      ops: fixtureOps({
        owner: new Map<string, OwnerResult>([
          [FORTRESS, { ok: false, reason: "ENOENT", code: "ENOENT" }],
        ]),
      }),
    });
    expect(row(absent, "fortress_custody")).toMatchObject({
      status: "PASS",
      state: "no_fortress",
    });
  });

  it("fortress_custody resolves the operator from the sudo identity when run under sudo", async () => {
    // Root under sudo: operator resolves to uid 501 via SUDO_*, and a
    // root-owned fortress still FAILs loudly.
    const report = await runProtectPreflight({
      ops: fixtureOps({
        uid: 0,
        env: baseEnv({ SUDO_UID: "501", SUDO_GID: "20", SUDO_USER: "operator" }),
        owner: new Map<string, OwnerResult>([[FORTRESS, { ok: true, uid: 0, gid: 0 }]]),
        execFile: async (cmd, args) => {
          const joined = args.join(" ");
          if (cmd === "/usr/bin/dscl") {
            return execResult(0, `NFSHomeDirectory: ${OPERATOR_HOME}\n`);
          }
          if (cmd.endsWith("lsof")) return execResult(1);
          if (cmd === "systemextensionsctl") {
            return execResult(0, "[activated enabled] ai.sanctuaryprotocol.castlewall\n");
          }
          if (cmd === "launchctl") return execResult(113, "", "Could not find service");
          if (cmd.endsWith("ps")) return execResult(0, "UID PID COMMAND\n");
          return execResult(1, "", `unexpected exec ${cmd} ${joined}`);
        },
      }),
    });
    expect(row(report, "fortress_custody")).toMatchObject({
      status: "FAIL",
      state: "root_owned_fortress",
    });
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
      expect(parsed.rows.map((candidate) => candidate.id)).toEqual(ALL_PREFLIGHT_CHECK_IDS);
      expect(result.stderr).not.toContain("Bootstrapped");
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
  }, CLI_SUBPROCESS_TEST_TIMEOUT_MS);

  // defect.preflight-provider-liveness-probe-not-authenticated
  it("does not PASS provider liveness when the endpoint returns HTTP 2xx regardless of the credential presented", async () => {
    // A placeholder credential is not on normalizeCredential's literal
    // denylist, so it is treated as configured.
    const fetch = vi.fn(async () => ({ status: 200 }));
    const report = await runProtectPreflight({
      ops: fixtureOps({
        env: baseEnv({ OPENAI_API_KEY: "", VENICE_API_KEY: "clearly-not-a-real-venice-key-0000" }),
        fetch,
      }),
    });

    const providerRow = row(report, "provider_liveness");
    expect(providerRow.status).toBe("UNDETERMINED");
    expect(providerRow.state).toBe("provider_probe_unknown");
    expect(providerRow.providers?.[0]).toMatchObject({
      status: "UNDETERMINED",
      state: "credential_not_verifiable",
    });
    // The configured credential AND the invalid-credential discrimination
    // probe both hit the endpoint; only a genuine status difference between
    // the two would have justified a PASS.
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(protectPreflightExitCode(report)).toBe(0);
    // Reachable-but-credential-unverifiable is the honest-UNDETERMINED
    // shape strict-arm allows through (see the block below): the 2xx to the
    // configured credential already proved the endpoint reachable, so
    // strict no longer blocks on this specific row.
    //
    // defect.strict-arm-blocks-on-reachable-unverifiable-provider
    expect(protectPreflightExitCode(report, true)).toBe(0);
  });

  // defect.strict-arm-blocks-on-reachable-unverifiable-provider
  describe("strict-arm and the reachable-unverifiable provider", () => {
    it("(a)+(f) strict allows arming with a WARN when a provider is reachable but credential-unverifiable, and the row stays honestly UNDETERMINED", async () => {
      const report = await runProtectPreflight({
        ops: fixtureOps({
          env: baseEnv({ OPENAI_API_KEY: "", VENICE_API_KEY: "clearly-not-a-real-venice-key-0000" }),
          fetch: async () => ({ status: 200 }),
        }),
      });

      const providerRow = row(report, "provider_liveness");
      // (f) honesty preserved: never relabeled PASS.
      expect(providerRow.status).toBe("UNDETERMINED");
      expect(providerRow.providers?.[0]).toMatchObject({
        status: "UNDETERMINED",
        state: "credential_not_verifiable",
        reachableUnverifiable: true,
      });
      // (a) strict no longer blocks on this row alone.
      expect(protectPreflightExitCode(report, true)).toBe(0);
      expect(describeProtectPreflightBlockers(report, true)).toBe("");
      const warnings = describeProtectPreflightStrictWarnings(report, true);
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("Venice");
      expect(warnings[0]).toContain("could not be verified");
    });

    it("(b) strict still refuses on an unreachable provider", async () => {
      const report = await runProtectPreflight({
        ops: fixtureOps({
          env: baseEnv({ OPENAI_API_KEY: "", VENICE_API_KEY: "test-venice-key" }),
          fetch: async () => {
            throw new Error("ECONNREFUSED");
          },
        }),
      });

      const providerRow = row(report, "provider_liveness");
      expect(providerRow.status).toBe("FAIL");
      expect(providerRow.providers?.[0]).toMatchObject({
        status: "FAIL",
        state: "network_error",
        reachableUnverifiable: false,
      });
      expect(protectPreflightExitCode(report, true)).toBe(2);
      expect(protectPreflightExitCode(report, false)).toBe(2);
      expect(describeProtectPreflightStrictWarnings(report, true)).toEqual([]);
    });

    it("(c) strict still refuses on a provably-bad credential (a real 401)", async () => {
      const report = await runProtectPreflight({
        ops: fixtureOps({
          env: baseEnv({ OPENAI_API_KEY: "test-openai-key" }),
          fetch: async () => ({ status: 401 }),
        }),
      });

      const providerRow = row(report, "provider_liveness");
      expect(providerRow.status).toBe("FAIL");
      expect(providerRow.providers?.[0]).toMatchObject({
        status: "FAIL",
        state: "auth_failed",
        reachableUnverifiable: false,
      });
      expect(protectPreflightExitCode(report, true)).toBe(2);
      expect(protectPreflightExitCode(report, false)).toBe(2);
      expect(describeProtectPreflightStrictWarnings(report, true)).toEqual([]);
    });

    it("(d) strict still refuses on an UNDETERMINED row from a non-provider check, even with a healthy provider", async () => {
      // Linux has no darwin-only surfaces to probe, so several checks read
      // "not_darwin" UNDETERMINED while provider_liveness (which never
      // gates on platform) resolves cleanly with OpenAI's real rejection of
      // an invalid credential.
      const report = await runProtectPreflight({
        ops: fixtureOps({ platform: "linux" }),
      });

      const providerRow = row(report, "provider_liveness");
      expect(providerRow.status).toBe("PASS");
      expect(row(report, "castle_sock_holder")).toMatchObject({
        status: "UNDETERMINED",
        state: "not_darwin",
      });
      expect(protectPreflightExitCode(report, true)).toBe(2);
      expect(describeProtectPreflightBlockers(report, true)).toContain("castle.sock holder");
      // No provider triggered the carve-out, so there is nothing to warn
      // about even though strict still refuses for an unrelated reason.
      expect(describeProtectPreflightStrictWarnings(report, true)).toEqual([]);
    });

    it("(e) non-strict behavior is unchanged: a reachable-unverifiable provider never blocked and still doesn't", async () => {
      const report = await runProtectPreflight({
        ops: fixtureOps({
          env: baseEnv({ OPENAI_API_KEY: "", VENICE_API_KEY: "clearly-not-a-real-venice-key-0000" }),
          fetch: async () => ({ status: 200 }),
        }),
      });

      expect(protectPreflightExitCode(report, false)).toBe(0);
      expect(describeProtectPreflightStrictWarnings(report, false)).toEqual([]);
    });

    it("CLI: --strict arm proceeds (exit 0) and prints a WARN naming the provider, instead of refusing", async () => {
      const exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
        throw new Error(`process.exit:${code ?? 0}`);
      }) as never);
      const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
      const consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
      const reachableUnverifiableReport: ProtectPreflightReport = {
        command: "sanctuary protect preflight",
        generated_at: PRETEND_TIME.toISOString(),
        strict: true,
        summary: { pass: 0, fail: 0, undetermined: 1 },
        rows: [
          {
            id: "provider_liveness",
            check: "provider liveness",
            status: "UNDETERMINED",
            state: "provider_probe_unknown",
            detail: "Venice: credential_not_verifiable (provider endpoint reachable; credential validity not verifiable at the available endpoint; source env:VENICE_API_KEY)",
            remedy: "Verify each configured provider from the operator account before arming Castle Wall.",
            findings: ["F-12"],
            providers: [
              {
                provider: "Venice",
                source: "env:VENICE_API_KEY",
                status: "UNDETERMINED",
                state: "credential_not_verifiable",
                detail:
                  "provider endpoint reachable; credential validity not verifiable at the available endpoint (it accepted an invalid credential too)",
                reachableUnverifiable: true,
              },
            ],
          },
        ],
      };
      try {
        await expect(
          runWrap(
            { protectCommand: true, hermes: true, preflight: true, preflightStrict: true },
            { runProtectPreflight: async () => reachableUnverifiableReport },
          ),
        ).rejects.toThrow("process.exit:0");
        expect(exitSpy).toHaveBeenCalledWith(0);
        const message = consoleErrorSpy.mock.calls.map((call) => String(call[0])).join("");
        expect(message).toContain("WARNING");
        expect(message).toContain("Venice");
        expect(message).toContain("could not be verified");
      } finally {
        exitSpy.mockRestore();
        stderrSpy.mockRestore();
        consoleErrorSpy.mockRestore();
      }
    });
  });

  it("still PASSes provider liveness when the endpoint genuinely rejects an invalid credential", async () => {
    const report = await runProtectPreflight({
      // OpenAI is baseEnv's default provider precisely because its endpoint
      // genuinely rejects an invalid credential; fixtureOps' default fetch
      // only accepts the exact configured credential, so this proves the
      // discrimination probe does not regress a genuinely credential
      // -checking endpoint to UNDETERMINED.
      ops: fixtureOps(),
    });

    const providerRow = row(report, "provider_liveness");
    expect(providerRow.status).toBe("PASS");
    expect(providerRow.providers?.[0]).toMatchObject({
      status: "PASS",
      state: "live",
    });
    expect(providerRow.providers?.[0]?.detail).toContain("rejected an invalid credential");
  });

  // defect.preflight-provider-liveness-probe-not-authenticated
  it("does not PASS provider liveness when the invalid-credential probe returns a status that is not a recognized rejection", async () => {
    // The configured credential succeeds; the invalid-credential probe hits
    // an unrelated failure class that is not a genuine authentication
    // rejection and not a success. That ambiguity alone must never resolve
    // to PASS.
    const fetch = vi.fn(async (_url: string, request: ProviderHttpRequest) => ({
      status: request.headers?.Authorization === "Bearer test-venice-key" ? 200 : 503,
    }));
    const report = await runProtectPreflight({
      ops: fixtureOps({
        env: baseEnv({ OPENAI_API_KEY: "", VENICE_API_KEY: "test-venice-key" }),
        fetch,
      }),
    });

    const providerRow = row(report, "provider_liveness");
    expect(providerRow.status).toBe("UNDETERMINED");
    expect(providerRow.providers?.[0]).toMatchObject({
      status: "UNDETERMINED",
      state: "credential_discrimination_inconclusive",
    });
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  function extractPresentedCredential(url: string, request: ProviderHttpRequest): string | undefined {
    const fromUrl = /\/bot([^/]+)\//.exec(url)?.[1];
    return (
      request.headers?.Authorization?.replace(/^Bearer\s+/, "") ??
      request.headers?.["x-api-key"] ??
      request.headers?.["x-goog-api-key"] ??
      (fromUrl === undefined ? undefined : decodeURIComponent(fromUrl))
    );
  }

  // Each provider's own response to an invalid-but-well-formed credential:
  // some endpoints answer with a genuine authentication rejection, others
  // do not, and the row's status must reflect exactly which is true for
  // that provider rather than assume the same outcome everywhere.
  const PROVIDER_INVALID_CREDENTIAL_RESPONSE: Record<string, number> = {
    openai: 401,
    anthropic: 401,
    telegram: 401,
    venice: 200,
    google_gemini: 400,
  };

  // The aggregate provider_liveness row state for each outcome class (see
  // checkProviderLiveness): a lone UNDETERMINED provider reads
  // "provider_probe_unknown"; all-PASS reads "all_configured_providers_live".
  const AGGREGATE_STATE_FOR_STATUS: Record<"PASS" | "UNDETERMINED", string> = {
    PASS: "all_configured_providers_live",
    UNDETERMINED: "provider_probe_unknown",
  };

  // defect.preflight-provider-liveness-probe-not-authenticated
  it.each([
    [
      "openai",
      "OPENAI_API_KEY",
      "PASS",
      "live",
      "rejected an invalid credential at this endpoint",
    ],
    [
      "anthropic",
      "ANTHROPIC_API_KEY",
      "PASS",
      "live",
      "rejected an invalid credential at this endpoint",
    ],
    [
      "telegram",
      "TELEGRAM_BOT_TOKEN",
      "PASS",
      "live",
      "rejected an invalid credential at this endpoint",
    ],
    [
      "venice",
      "VENICE_API_KEY",
      "UNDETERMINED",
      "credential_not_verifiable",
      "accepted an invalid credential too",
    ],
    [
      "google_gemini",
      "GEMINI_API_KEY",
      "UNDETERMINED",
      "credential_discrimination_inconclusive",
      "did not return a recognized rejection",
    ],
  ] as const)(
    "%s's row reads %s/%s (%s), matching that provider's own invalid-credential response",
    async (providerId, envName, expectedStatus, expectedState, expectedDetailSubstring) => {
      const realCredential = "the-configured-real-credential";
      const fetch = vi.fn(async (url: string, request: ProviderHttpRequest) => {
        const presented = extractPresentedCredential(url, request);
        return {
          status:
            presented === realCredential ? 200 : PROVIDER_INVALID_CREDENTIAL_RESPONSE[providerId],
        };
      });

      const report = await runProtectPreflight({
        ops: fixtureOps({
          env: baseEnv({ OPENAI_API_KEY: "", VENICE_API_KEY: "", [envName]: realCredential }),
          fetch,
        }),
      });

      const providerRow = row(report, "provider_liveness");
      expect(providerRow.status).toBe(expectedStatus);
      expect(providerRow.state).toBe(AGGREGATE_STATE_FOR_STATUS[expectedStatus]);
      expect(providerRow.providers?.[0]).toMatchObject({ status: expectedStatus, state: expectedState });
      expect(providerRow.providers?.[0]?.detail).toContain(expectedDetailSubstring);
    },
  );

  // Shared scaffolding for the boot_runtime_devtools row tests below: every
  // command except xcode-select/otool resolves the way the "healthy" fixture
  // does, so each test only has to vary the xcode-select/otool outcome it is
  // actually exercising.
  function devtoolsFixtureExecFile(
    respond: (cmd: string, args: string[]) => ExecFileResult | undefined,
  ): (cmd: string, args: string[]) => Promise<ExecFileResult> {
    return async (cmd, args) => {
      const overridden = respond(cmd, args);
      if (overridden !== undefined) return overridden;
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
    };
  }

  // defect.boot-installer-requires-devtools-unchecked-by-preflight
  it("FAILs the boot runtime devtools row when Command Line Tools are absent", async () => {
    const report = await runProtectPreflight({
      ops: fixtureOps({
        execFile: devtoolsFixtureExecFile((cmd, args) => {
          if (isExactCall(cmd, args, XCODE_SELECT_CMD, XCODE_SELECT_ARGS)) {
            // The real xcode-select -p exit shape when Command Line Tools
            // are not installed: nonzero exit, no spawn-level error.
            return execResult(
              2,
              "",
              "xcode-select: error: unable to get active developer directory, use `sudo xcode-select --switch path/to/Xcode.app` to specify one",
            );
          }
          return undefined;
        }),
      }),
    });

    expect(row(report, "boot_runtime_devtools")).toMatchObject({
      status: "FAIL",
      state: "developer_tools_missing",
    });
    expect(row(report, "boot_runtime_devtools").remedy).toContain("xcode-select --install");
    expect(protectPreflightExitCode(report)).toBe(2);
  });

  it("reports the devtools row as UNDETERMINED, not FAIL, when the xcode-select probe itself cannot run", async () => {
    const report = await runProtectPreflight({
      ops: fixtureOps({
        execFile: devtoolsFixtureExecFile((cmd, args) => {
          if (isExactCall(cmd, args, XCODE_SELECT_CMD, XCODE_SELECT_ARGS)) {
            return execResult(1, "", "blocked", "EIO");
          }
          return undefined;
        }),
      }),
    });

    expect(row(report, "boot_runtime_devtools")).toMatchObject({
      status: "UNDETERMINED",
      state: "developer_tools_probe_unknown",
    });
  });

  it("reports the devtools row as UNDETERMINED, not FAIL, when the xcode-select probe times out (code:null, signal, killed)", async () => {
    const report = await runProtectPreflight({
      ops: fixtureOps({
        execFile: devtoolsFixtureExecFile((cmd, args) => {
          if (isExactCall(cmd, args, XCODE_SELECT_CMD, XCODE_SELECT_ARGS)) {
            // A timed-out/killed subprocess has no errorCode (Node reports
            // code:null there, which the exec wrapper coerces to 1) --
            // signal/killed are what actually distinguish this from a
            // genuine nonzero exit.
            return { code: 1, stdout: "", stderr: "", signal: "SIGTERM", killed: true };
          }
          return undefined;
        }),
      }),
    });

    expect(row(report, "boot_runtime_devtools")).toMatchObject({
      status: "UNDETERMINED",
      state: "developer_tools_probe_unknown",
    });
  });

  it("FAILs the devtools row when xcode-select reports present but otool -L does not work (stale/partial toolchain)", async () => {
    const report = await runProtectPreflight({
      ops: fixtureOps({
        execFile: devtoolsFixtureExecFile((cmd, args) => {
          if (isExactCall(cmd, args, XCODE_SELECT_CMD, XCODE_SELECT_ARGS)) {
            return execResult(0, "/Library/Developer/CommandLineTools\n");
          }
          if (isExactCall(cmd, args, OTOOL_CMD, OTOOL_ARGS)) {
            return execResult(1, "", "otool: error: unable to load libLTO.dylib");
          }
          return undefined;
        }),
      }),
    });

    expect(row(report, "boot_runtime_devtools")).toMatchObject({
      status: "FAIL",
      state: "developer_tools_broken",
    });
    expect(row(report, "boot_runtime_devtools").remedy).toContain("xcode-select --install");
    expect(protectPreflightExitCode(report)).toBe(2);
  });

  it("reports the devtools row as UNDETERMINED when xcode-select reports present but the otool probe itself cannot run", async () => {
    const report = await runProtectPreflight({
      ops: fixtureOps({
        execFile: devtoolsFixtureExecFile((cmd, args) => {
          if (isExactCall(cmd, args, XCODE_SELECT_CMD, XCODE_SELECT_ARGS)) {
            return execResult(0, "/Library/Developer/CommandLineTools\n");
          }
          if (isExactCall(cmd, args, OTOOL_CMD, OTOOL_ARGS)) {
            return execResult(1, "", "blocked", "EIO");
          }
          return undefined;
        }),
      }),
    });

    expect(row(report, "boot_runtime_devtools")).toMatchObject({
      status: "UNDETERMINED",
      state: "otool_probe_unknown",
    });
  });

  it("reports the devtools row as UNDETERMINED, not FAIL, when the otool probe times out (code:null, signal, killed)", async () => {
    const report = await runProtectPreflight({
      ops: fixtureOps({
        execFile: devtoolsFixtureExecFile((cmd, args) => {
          if (isExactCall(cmd, args, XCODE_SELECT_CMD, XCODE_SELECT_ARGS)) {
            return execResult(0, "/Library/Developer/CommandLineTools\n");
          }
          if (isExactCall(cmd, args, OTOOL_CMD, OTOOL_ARGS)) {
            return { code: 1, stdout: "", stderr: "", signal: "SIGTERM", killed: true };
          }
          return undefined;
        }),
      }),
    });

    expect(row(report, "boot_runtime_devtools")).toMatchObject({
      status: "UNDETERMINED",
      state: "otool_probe_unknown",
    });
  });

  it("does not PASS the devtools row for a mutating xcode-select invocation (e.g. --install) that the fixture does not model", async () => {
    // isExactCall only matches the literal ["-p"] read probe, so any other
    // arg vector falls through to the fixture's generic "unexpected exec"
    // branch rather than silently matching a permissive stub.
    const report = await runProtectPreflight({
      ops: fixtureOps({
        execFile: devtoolsFixtureExecFile((cmd, args) => {
          if (cmd === XCODE_SELECT_CMD && args[0] === "--install") {
            return execResult(0, "");
          }
          return undefined;
        }),
      }),
    });

    expect(row(report, "boot_runtime_devtools").status).not.toBe("PASS");
  });

  // defect.protect-preflight-refusal-copy-wrong-under-strict
  it("protectPreflightExitCode and describeProtectPreflightBlockers agree on the blocking set for the same explicit strict value, even when it differs from report.strict", () => {
    const undeterminedOnlyReport: ProtectPreflightReport = {
      command: "sanctuary protect preflight",
      generated_at: PRETEND_TIME.toISOString(),
      // Deliberately built non-strict; the loop below still passes an
      // explicit strict flag to both functions, the way cli.ts does.
      strict: false,
      summary: { pass: 0, fail: 0, undetermined: 1 },
      rows: [
        {
          id: "provider_liveness",
          check: "provider liveness",
          status: "UNDETERMINED",
          state: "credential_not_verifiable",
          detail: "cannot prove the credential is valid",
          remedy: "Verify manually.",
          findings: ["F-12"],
        },
      ],
    };

    for (const strict of [false, true]) {
      const exitCode = protectPreflightExitCode(undeterminedOnlyReport, strict);
      const blockers = describeProtectPreflightBlockers(undeterminedOnlyReport, strict);
      expect(exitCode === 2).toBe(blockers.length > 0);
    }
  });

  // defect.protect-preflight-refusal-copy-wrong-under-strict
  it("names the actual blocking status classes, including --strict-blocking UNDETERMINED rows, in describeProtectPreflightBlockers", () => {
    const undeterminedOnlyStrict: ProtectPreflightReport = {
      command: "sanctuary protect preflight",
      generated_at: PRETEND_TIME.toISOString(),
      strict: true,
      summary: { pass: 0, fail: 0, undetermined: 1 },
      rows: [
        {
          id: "provider_liveness",
          check: "provider liveness",
          status: "UNDETERMINED",
          state: "credential_not_verifiable",
          detail: "cannot prove the credential is valid",
          remedy: "Verify manually.",
          findings: ["F-12"],
        },
      ],
    };

    const message = describeProtectPreflightBlockers(undeterminedOnlyStrict);
    expect(message).toContain("provider liveness");
    expect(message).toContain("--strict");
    expect(message).not.toContain("FAIL:");

    // The same UNDETERMINED row is not named when --strict is off, since it
    // does not block a non-strict run.
    expect(
      describeProtectPreflightBlockers({ ...undeterminedOnlyStrict, strict: false }),
    ).toBe("");
  });

  // defect.protect-preflight-refusal-copy-wrong-under-strict
  it("CLI refusal names the UNDETERMINED row under --strict instead of claiming FAIL rows exist", async () => {
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new Error(`process.exit:${code ?? 0}`);
    }) as never);
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const undeterminedOnlyStrictReport: ProtectPreflightReport = {
      command: "sanctuary protect preflight",
      generated_at: PRETEND_TIME.toISOString(),
      strict: true,
      summary: { pass: 0, fail: 0, undetermined: 1 },
      rows: [
        {
          id: "provider_liveness",
          check: "provider liveness",
          status: "UNDETERMINED",
          state: "credential_not_verifiable",
          detail: "cannot prove the credential is valid",
          remedy: "Verify manually.",
          findings: ["F-12"],
        },
      ],
    };
    try {
      await expect(
        runWrap(
          { protectCommand: true, hermes: true, preflightStrict: true },
          { runProtectPreflight: async () => undeterminedOnlyStrictReport },
        ),
      ).rejects.toThrow("process.exit:2");
      expect(exitSpy).toHaveBeenCalledWith(2);
      const message = consoleErrorSpy.mock.calls.map((call) => String(call[0])).join("");
      expect(message).toContain("Sanctuary protect refused before any host mutation");
      // The refusal names only the rows that actually block.
      expect(message).toContain("provider liveness");
      expect(message).toContain("--strict");
      expect(message).not.toContain("Fix the FAIL rows");
    } finally {
      exitSpy.mockRestore();
      stderrSpy.mockRestore();
      consoleErrorSpy.mockRestore();
    }
  });

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
