/**
 * Tests for Hermes gateway argv resolution (D1: the headless
 * `ai.hermes.gateway` egress-making process, never a GUI .app): resolves to
 * the re-homed Hermes runtime tree, fail-closed (throws) when it is absent.
 *
 * FIX F-INTERP (Mini1 confined-Hermes drill 2026-07-26): the resolution
 * decides on a MEASURED capability (can the AGENT uid execute this
 * interpreter, and what version does it report) rather than on `pathExists`,
 * and refuses to pair an interpreter with site-packages built for a different
 * CPython ABI. The pre-fix code launched a system 3.14 against a 3.11 venv,
 * which crash-looped every real Hermes install under launchd.
 */

import { describe, it, expect } from "vitest";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
  chmodSync,
  existsSync,
  mkdirSync,
  symlinkSync,
  realpathSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { execFileSync } from "node:child_process";

import {
  resolveHermesGatewayArgv,
  interpreterVersionProbeArgv,
  hermesCliImportProbeArgv,
  parseInterpreterVersion,
  parseHermesCliImportProbeOutput,
  parseVenvSitePackagesVersion,
  runInterpreterProbeBounded,
  INTERPRETER_VERSION_PROBE_SOURCE,
  renderHermesCliImportProbeSource,
  type HarnessArgvOps,
  type InterpreterVersion,
} from "../../../src/castle-wall/provision/harness-argv.js";

const agentHome = "/var/sanctuary-agents/sanctuary-hermes";
const hermesAgentDir = `${agentHome}/.hermes/hermes-agent`;
const systemPython = "/opt/homebrew/bin/python3";
const mainModule = `${hermesAgentDir}/hermes_cli/main.py`;
const sitePackages = `${hermesAgentDir}/venv/lib/python3.11/site-packages`;
const venvPython = `${hermesAgentDir}/venv/bin/python`;
const AGENT_UID = 503;

/**
 * `existing` drives `pathExists`; `runnableAsAgent` maps an interpreter path
 * to the version it reports WHEN RUN AS THE AGENT UID. A path absent from
 * `runnableAsAgent` is one the agent uid cannot execute -- which is exactly
 * the distinction the pre-fix code could not make.
 */
function mockOps(
  existing: Set<string>,
  runnableAsAgent: Record<string, InterpreterVersion> = {},
): HarnessArgvOps {
  return {
    pathExists: async (path) => existing.has(path),
    realpath: async () => undefined,
    probeInterpreterAsUid: async (path, uid) =>
      uid === AGENT_UID ? runnableAsAgent[path] : undefined,
    probeHermesCliImportAsUid: async (path, uid, pythonPathEntries) => {
      if (uid !== AGENT_UID || runnableAsAgent[path] === undefined) return undefined;
      for (const entry of pythonPathEntries) {
        if (entry === hermesAgentDir && existing.has(mainModule)) {
          return `${hermesAgentDir}/hermes_cli/__init__.py`;
        }
        if (existing.has(`${entry}/hermes_cli/__init__.py`)) {
          return `${entry}/hermes_cli/__init__.py`;
        }
        if (existing.has(`${entry}/hermes_cli/main.py`)) {
          return `${entry}/hermes_cli/main.py`;
        }
      }
      return undefined;
    },
  };
}

function fixturePythonPath(): string {
  const stdout = execFileSync(
    "/usr/bin/env",
    ["python3", "-I", "-c", "import os, sys; print(os.path.realpath(sys.executable))"],
    { encoding: "utf8" },
  );
  const python = stdout.trim();
  if (!python.startsWith("/")) throw new Error(`fixture python path is not absolute: ${python}`);
  return python;
}

function fixturePythonVersion(python: string): InterpreterVersion {
  const stdout = execFileSync(python, ["-I", "-c", INTERPRETER_VERSION_PROBE_SOURCE], { encoding: "utf8" });
  const version = parseInterpreterVersion(stdout);
  if (version === undefined) throw new Error(`fixture python did not report a parseable version: ${stdout}`);
  return version;
}

function tempFixtureOps(): HarnessArgvOps {
  return {
    pathExists: async (path) => existsSync(path),
    realpath: async (path) => {
      try {
        return realpathSync(path);
      } catch {
        return undefined;
      }
    },
    probeInterpreterAsUid: async (path, uid) => {
      if (uid !== AGENT_UID) return undefined;
      const stdout = await runInterpreterProbeBounded(
        { file: path, args: ["-I", "-c", INTERPRETER_VERSION_PROBE_SOURCE] },
        5_000,
      );
      if (stdout === undefined) return undefined;
      return parseInterpreterVersion(stdout);
    },
    probeHermesCliImportAsUid: async (path, uid, pythonPathEntries) => {
      if (uid !== AGENT_UID) return undefined;
      const stdout = await runInterpreterProbeBounded(
        { file: path, args: ["-I", "-c", renderHermesCliImportProbeSource(pythonPathEntries)] },
        5_000,
      );
      if (stdout === undefined) return undefined;
      return parseHermesCliImportProbeOutput(stdout);
    },
  };
}

function writePipxHermesFixture(input: {
  venvDir: string;
  python: string;
  withHermesCli: boolean;
}): { venvPython: string; sitePackages: string } {
  const version = fixturePythonVersion(input.python);
  const binDir = join(input.venvDir, "bin");
  const sitePackages = join(input.venvDir, "lib", `python${version.major}.${version.minor}`, "site-packages");
  mkdirSync(binDir, { recursive: true });
  mkdirSync(sitePackages, { recursive: true });
  const venvPythonPath = join(binDir, "python");
  symlinkSync(input.python, venvPythonPath);
  writeFileSync(join(binDir, "hermes"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  if (input.withHermesCli) {
    const packageDir = join(sitePackages, "hermes_cli");
    mkdirSync(packageDir, { recursive: true });
    writeFileSync(join(packageDir, "__init__.py"), "");
    writeFileSync(join(packageDir, "main.py"), "def main():\n    return None\n");
  }
  return { venvPython: venvPythonPath, sitePackages };
}

describe("castle-wall/provision/harness-argv", () => {
  describe("F-INTERP: resolve by capability, never by existence", () => {
    it("prefers the re-homed venv interpreter when the AGENT UID can execute it (ABI-consistent by construction)", async () => {
      // The exact drill-host shape: a 3.14 system python on PATH, a 3.11 venv,
      // and an agent uid that can run the venv interpreter fine.
      const ops = mockOps(new Set([systemPython, mainModule, sitePackages, venvPython]), {
        [venvPython]: { major: 3, minor: 11 },
        [systemPython]: { major: 3, minor: 14 },
      });
      const resolved = await resolveHermesGatewayArgv(ops, { agentHome, agentUid: AGENT_UID });
      expect(resolved.harnessId).toBe("hermes");
      expect(resolved.launch.programArguments).toEqual([
        venvPython,
        "-m",
        "hermes_cli.main",
        "gateway",
        "run",
        "--accept-hooks",
      ]);
      // The venv interpreter carries its own site-packages; PYTHONPATH is only
      // the source tree hermes_cli lives in.
      expect(resolved.launch.environment).toEqual({
        HERMES_ACCEPT_HOOKS: "1",
        HOME: agentHome,
        PYTHONPATH: hermesAgentDir,
      });
    });

    it("REGRESSION (F-INTERP): never pairs a system interpreter with foreign-ABI site-packages -- refuses loudly, naming both versions", async () => {
      // The pre-fix production path: no usable venv interpreter, system python
      // is 3.14, the re-homed venv is 3.11. The pre-fix code returned
      // python3.14 + PYTHONPATH into 3.11 site-packages, and the harness
      // crash-looped with ModuleNotFoundError: _cffi_backend.
      const ops = mockOps(new Set([systemPython, mainModule, sitePackages]), {
        [systemPython]: { major: 3, minor: 14 },
      });
      await expect(resolveHermesGatewayArgv(ops, { agentHome, agentUid: AGENT_UID })).rejects.toThrow(
        /Python 3\.14 but the re-homed site-packages .* are Python 3\.11 \(C-extension ABI mismatch\)/,
      );
    });

    it("accepts a system interpreter ONLY when its own reported version matches the venv site-packages", async () => {
      const ops = mockOps(new Set([systemPython, mainModule, sitePackages]), {
        [systemPython]: { major: 3, minor: 11 },
      });
      const resolved = await resolveHermesGatewayArgv(ops, { agentHome, agentUid: AGENT_UID });
      expect(resolved.launch.programArguments[0]).toBe(systemPython);
      expect(resolved.launch.environment.PYTHONPATH).toBe(`${hermesAgentDir}:${sitePackages}`);
    });

    it("skips a matching-version system interpreter the AGENT UID cannot execute, and takes the next one that it can", async () => {
      const ops = mockOps(new Set([systemPython, "/usr/bin/python3", mainModule, sitePackages]), {
        // /opt/homebrew/bin/python3 is deliberately absent from the runnable
        // map: it exists, but not for this uid.
        "/usr/bin/python3": { major: 3, minor: 11 },
      });
      const resolved = await resolveHermesGatewayArgv(ops, { agentHome, agentUid: AGENT_UID });
      expect(resolved.launch.programArguments[0]).toBe("/usr/bin/python3");
    });

    it("REGRESSION (F-INTERP): a venv interpreter that EXISTS but is not executable by the agent uid is not chosen on existence alone", async () => {
      // `pathExists` is true for the venv python here. The pre-fix module used
      // existence probes to decide; the fix requires the uid to actually run it.
      const ops = mockOps(new Set([systemPython, mainModule, sitePackages, venvPython]), {
        [systemPython]: { major: 3, minor: 11 },
      });
      const resolved = await resolveHermesGatewayArgv(ops, { agentHome, agentUid: AGENT_UID });
      expect(resolved.launch.programArguments[0]).toBe(systemPython);
    });

    it("probes as the AGENT uid, never as the caller (root)", async () => {
      const seen: Array<{ path: string; uid: number }> = [];
      const ops: HarnessArgvOps = {
        pathExists: async (path) => new Set([mainModule, sitePackages, venvPython]).has(path),
        realpath: async () => undefined,
        probeInterpreterAsUid: async (path, uid) => {
          seen.push({ path, uid });
          return path === venvPython ? { major: 3, minor: 11 } : undefined;
        },
        probeHermesCliImportAsUid: async (path, uid, pythonPathEntries) =>
          path === venvPython && uid === AGENT_UID && pythonPathEntries.includes(hermesAgentDir)
            ? `${hermesAgentDir}/hermes_cli/__init__.py`
            : undefined,
      };
      await resolveHermesGatewayArgv(ops, { agentHome, agentUid: AGENT_UID });
      expect(seen).toEqual([{ path: venvPython, uid: AGENT_UID }]);
    });

    it("fail-closed: refuses when no interpreter is executable as the agent uid, and names every rejection", async () => {
      const ops = mockOps(new Set([systemPython, mainModule, sitePackages]));
      await expect(
        resolveHermesGatewayArgv(ops, { agentHome, agentUid: AGENT_UID }),
      ).rejects.toThrow(/could not be executed as uid 503/);
    });

    it("fail-closed: refuses without a positive integer agent uid (an unmeasurable capability is never assumed)", async () => {
      const ops = mockOps(new Set([systemPython, mainModule, sitePackages, venvPython]), {
        [venvPython]: { major: 3, minor: 11 },
      });
      await expect(
        resolveHermesGatewayArgv(ops, { agentHome, agentUid: 0 }),
      ).rejects.toThrow(/positive integer uid/);
    });
  });

  describe("fail-closed resolution of the re-homed tree", () => {
    it("every resolved program path is absolute (never a relative/guessed path)", async () => {
      const ops = mockOps(new Set([systemPython, mainModule, sitePackages]), {
        [systemPython]: { major: 3, minor: 11 },
      });
      const resolved = await resolveHermesGatewayArgv(ops, { agentHome, agentUid: AGENT_UID });
      expect(resolved.launch.programArguments[0]?.startsWith("/")).toBe(true);
    });

    it("fail-closed: throws when the re-homed runtime is absent (never guesses a global python)", async () => {
      const ops = mockOps(new Set([systemPython]), { [systemPython]: { major: 3, minor: 11 } });
      await expect(
        resolveHermesGatewayArgv(ops, { agentHome, agentUid: AGENT_UID }),
      ).rejects.toThrow(/re-homed Hermes runtime/);
    });

    it("fail-closed: throws when system Python exists but hermes_cli is absent", async () => {
      const ops = mockOps(new Set([systemPython, sitePackages]), {
        [systemPython]: { major: 3, minor: 11 },
      });
      await expect(
        resolveHermesGatewayArgv(ops, { agentHome, agentUid: AGENT_UID }),
      ).rejects.toThrow(/re-homed Hermes runtime/);
    });

    it("fail-closed: throws when the runtime exists but site-packages are absent", async () => {
      const ops = mockOps(new Set([systemPython, mainModule]), {
        [systemPython]: { major: 3, minor: 11 },
      });
      await expect(
        resolveHermesGatewayArgv(ops, { agentHome, agentUid: AGENT_UID }),
      ).rejects.toThrow(/site-packages/);
    });

    it("an executable venv interpreter resolves even with no site-packages directory (its own sys.path carries them)", async () => {
      const ops = mockOps(new Set([mainModule, venvPython]), {
        [venvPython]: { major: 3, minor: 11 },
      });
      const resolved = await resolveHermesGatewayArgv(ops, { agentHome, agentUid: AGENT_UID });
      expect(resolved.launch.programArguments[0]).toBe(venvPython);
    });
  });

  describe("pipx Hermes runtime fallback", () => {
    it("REGRESSION: resolves a standard pipx hermes-agent venv when the re-homed source tree is absent", async () => {
      const root = mkdtempSync(join(tmpdir(), "pipx-hermes-default-"));
      try {
        const operatorHome = join(root, "operator");
        const pipxVenv = join(operatorHome, ".local", "pipx", "venvs", "hermes-agent");
        const fixture = writePipxHermesFixture({
          venvDir: pipxVenv,
          python: fixturePythonPath(),
          withHermesCli: true,
        });

        const resolved = await resolveHermesGatewayArgv(tempFixtureOps(), {
          agentHome,
          agentUid: AGENT_UID,
          operatorHome,
          env: {},
        });

        expect(resolved.harnessId).toBe("hermes");
        expect(resolved.launch.programArguments).toEqual([
          fixture.venvPython,
          "-m",
          "hermes_cli.main",
          "gateway",
          "run",
          "--accept-hooks",
        ]);
        expect(resolved.launch.environment).toEqual({
          HERMES_ACCEPT_HOOKS: "1",
          HOME: agentHome,
          PYTHONPATH: fixture.sitePackages,
        });
      } finally {
        rmSync(root, { recursive: true, force: true });
      }
    }, 20_000);

    it("respects PIPX_BIN_DIR by following the hermes command symlink back to its pipx venv", async () => {
      const root = mkdtempSync(join(tmpdir(), "pipx-hermes-bindir-"));
      try {
        const operatorHome = join(root, "operator");
        const pipxVenv = join(root, "custom-pipx-store", "venvs", "hermes-agent");
        const fixture = writePipxHermesFixture({
          venvDir: pipxVenv,
          python: fixturePythonPath(),
          withHermesCli: true,
        });
        const binDir = join(root, "custom-bin");
        mkdirSync(binDir, { recursive: true });
        symlinkSync(join(pipxVenv, "bin", "hermes"), join(binDir, "hermes"));

        const resolved = await resolveHermesGatewayArgv(tempFixtureOps(), {
          agentHome,
          agentUid: AGENT_UID,
          operatorHome,
          env: { PIPX_HOME: join(root, "empty-pipx-home"), PIPX_BIN_DIR: binDir },
        });

        const canonicalVenv = dirname(dirname(realpathSync(join(binDir, "hermes"))));
        expect(resolved.launch.programArguments[0]).toBe(join(canonicalVenv, "bin", "python"));
        expect(resolved.launch.environment.PYTHONPATH).toBe(
          join(canonicalVenv, "lib", dirname(fixture.sitePackages).split("/").pop()!, "site-packages"),
        );
      } finally {
        rmSync(root, { recursive: true, force: true });
      }
    }, 20_000);

    it("fail-closed: a pipx venv without importable hermes_cli does not resolve on layout existence alone", async () => {
      const root = mkdtempSync(join(tmpdir(), "pipx-hermes-no-import-"));
      try {
        const operatorHome = join(root, "operator");
        const pipxVenv = join(operatorHome, ".local", "pipx", "venvs", "hermes-agent");
        const fixture = writePipxHermesFixture({
          venvDir: pipxVenv,
          python: fixturePythonPath(),
          withHermesCli: false,
        });

        await expect(
          resolveHermesGatewayArgv(tempFixtureOps(), {
            agentHome,
            agentUid: AGENT_UID,
            operatorHome,
            env: {},
          }),
        ).rejects.toThrow(
          new RegExp(
            `Acceptable layouts: .*re-homed runtime .*pipx runtime .*Pipx probe paths tried: .*${fixture.venvPython.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}.*${fixture.sitePackages.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}.*could not import hermes_cli`,
          ),
        );
      } finally {
        rmSync(root, { recursive: true, force: true });
      }
    }, 20_000);
  });

  describe("the as-uid probe surface", () => {
    it("builds a sudo -n -u '#uid' argv running the interpreter in isolated mode", () => {
      const { file, args } = interpreterVersionProbeArgv(503, "/opt/homebrew/bin/python3");
      expect(file).toBe("/usr/bin/sudo");
      expect(args).toEqual([
        "-n",
        "-u",
        "#503",
        "/opt/homebrew/bin/python3",
        "-I",
        "-c",
        INTERPRETER_VERSION_PROBE_SOURCE,
      ]);
    });

    it("builds a sudo -n -u '#uid' argv for the hermes_cli import probe in isolated mode", () => {
      const { file, args } = hermesCliImportProbeArgv(503, "/opt/homebrew/bin/python3", ["/opt/hermes"]);
      expect(file).toBe("/usr/bin/sudo");
      expect(args.slice(0, 6)).toEqual(["-n", "-u", "#503", "/opt/homebrew/bin/python3", "-I", "-c"]);
      expect(args[6]).toContain("find_spec('hermes_cli')");
      expect(args[6]).toContain('"/opt/hermes"');
    });

    it("refuses a non-positive uid or a relative interpreter path", () => {
      expect(() => interpreterVersionProbeArgv(0, "/usr/bin/python3")).toThrow(/positive integer uid/);
      expect(() => interpreterVersionProbeArgv(503, "python3")).toThrow(/absolute interpreter path/);
    });

    it("parses only a bare major.minor line; anything else is 'not measured'", () => {
      expect(parseInterpreterVersion("3.11\n")).toEqual({ major: 3, minor: 11 });
      expect(parseInterpreterVersion("  3.14  ")).toEqual({ major: 3, minor: 14 });
      expect(parseInterpreterVersion("Python 3.11.15")).toBeUndefined();
      expect(parseInterpreterVersion("3.11\nwarning: something")).toBeUndefined();
      expect(parseInterpreterVersion("")).toBeUndefined();
    });

    it("parses only a single absolute hermes_cli origin line", () => {
      expect(parseHermesCliImportProbeOutput("/x/site-packages/hermes_cli/__init__.py\n")).toBe(
        "/x/site-packages/hermes_cli/__init__.py",
      );
      expect(parseHermesCliImportProbeOutput("relative/hermes_cli/__init__.py\n")).toBeUndefined();
      expect(parseHermesCliImportProbeOutput("/x/hermes_cli/__init__.py\nwarning")).toBeUndefined();
    });

    it("reads the ABI version out of a venv site-packages path", () => {
      expect(parseVenvSitePackagesVersion(sitePackages)).toEqual({ major: 3, minor: 11 });
      expect(parseVenvSitePackagesVersion(`${sitePackages}/`)).toEqual({ major: 3, minor: 11 });
      expect(parseVenvSitePackagesVersion("/somewhere/lib/site-packages")).toBeUndefined();
    });
  });
});

// ---------------------------------------------------------------------------
// FIX (Codex adversarial review, HIGH, 2026-07-26): the as-uid interpreter
// probe's timeout must be a HARD deadline over the whole process TREE.
//
// The pre-fix probe used `promisify(execFile)(..., { timeout })`, whose kill
// signal is `SIGTERM` and which then WAITS for the child to exit. A candidate
// that ignores `SIGTERM` therefore hangs the caller -- and the FIRST candidate
// this module probes is the agent-home venv interpreter, which the module
// documents as AGENT-WRITABLE. So a hostile interpreter could hang `protect`
// and the root boot supervisor instead of failing closed to a parked agent.
//
// These tests drive REAL processes (`/bin/sh`, no sudo, nothing outside a
// private tmpdir), because the defect lives entirely in the child-process
// primitive and a mocked child would prove nothing.
// ---------------------------------------------------------------------------
/** `kill(pid, 0)`: alive (or alive-but-not-ours) vs. definitively gone. */
function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** Poll until `pid` is gone, so a slow box reads as slow rather than as a failure. */
async function expectDead(pid: number, withinMs: number): Promise<void> {
  const deadline = Date.now() + withinMs;
  while (Date.now() < deadline) {
    if (!isAlive(pid)) return;
    await delay(25);
  }
  expect(isAlive(pid), `pid ${pid} survived the probe deadline (F-PROBE-PGROUP-ESCAPE)`).toBe(false);
}

/**
 * Best-effort cleanup so a FAILING run (which is exactly the mutation run) does
 * not leak a spinning shell into CI. Signals the pid only, never `-pid`: the
 * recorded pid is not necessarily a group leader, and signalling a group id we
 * did not create is how a test starts killing unrelated processes.
 */
function reap(pid: number | undefined): void {
  if (pid === undefined || !Number.isSafeInteger(pid) || pid <= 0) return;
  try {
    process.kill(pid, "SIGKILL");
  } catch {
    // Already gone.
  }
}

describe("runInterpreterProbeBounded (hard deadline, process-group kill)", () => {
  it("settles at the deadline even when the child IGNORES SIGTERM (the reviewer's reproduction)", async () => {
    const timeoutMs = 300;
    const started = Date.now();
    const result = await runInterpreterProbeBounded(
      { file: "/bin/sh", args: ["-c", 'trap "" TERM; while true; do sleep 1; done'] },
      timeoutMs,
    );
    const elapsed = Date.now() - started;
    // Fail-closed: a probe that could not be measured is "this uid cannot
    // execute this interpreter", never a version.
    expect(result).toBeUndefined();
    // THE ASSERTION. Pre-fix this promise did not settle until an EXTERNAL
    // SIGKILL arrived; the reviewer measured 1203ms against a 200ms timeout.
    // The bound allows generous scheduling slop and is still far below any
    // wait-for-a-SIGTERM-ignoring-child time.
    expect(elapsed).toBeLessThan(timeoutMs + 2_000);
  }, 20_000);

  it("kills the whole process GROUP, so an interpreter spawned by sudo cannot survive the deadline", async () => {
    // The production probe's direct child is `/usr/bin/sudo` and the
    // interpreter is ITS child, so killing only the direct child leaves the
    // interpreter running. This models that shape: a SIGTERM-ignoring parent
    // whose background grandchild keeps appending to a file forever.
    const dir = mkdtempSync(join(tmpdir(), "probe-group-"));
    try {
      const marker = join(dir, "grandchild.log");
      const script = join(dir, "parent.sh");
      const parentScript = [
        "#!/bin/sh",
        'trap "" TERM',
        `( while true; do echo tick >> ${marker}; sleep 0.05; done ) &`,
        "while true; do sleep 1; done",
      ].join("\n");
      writeFileSync(script, parentScript);
      chmodSync(script, 0o755);

      const result = await runInterpreterProbeBounded({ file: "/bin/sh", args: [script] }, 400);
      expect(result).toBeUndefined();

      // Give the kill a moment to land, then prove the GRANDCHILD stopped
      // writing: two samples 600ms apart must be identical.
      await delay(400);
      const first = existsSync(marker) ? readFileSync(marker, "utf8").length : 0;
      await delay(600);
      const second = existsSync(marker) ? readFileSync(marker, "utf8").length : 0;
      expect(second).toBe(first);
      // Sanity: the grandchild really did run before the deadline, so a passing
      // assertion above cannot be a never-started false negative.
      expect(first).toBeGreaterThan(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 20_000);

  it("kills a same-group descendant even when the direct child EXITS first (F-PROBE-PGROUP-ESCAPE)", async () => {
    // THE UNTESTED MIDDLE the re-review found. The test above keeps the direct
    // child ALIVE, so the pre-fix `exited` gate never engaged. Here the direct
    // child forks a descendant into the SAME process group (a plain `&` in a
    // non-interactive shell does not change process group), hands it the
    // inherited stdout pipe, and EXITS IMMEDIATELY. Pre-fix, `child.on("exit")`
    // set `exited = true`, the deadline declined to send `kill(-pid)` at all,
    // and the descendant ran on past the bound.
    const dir = mkdtempSync(join(tmpdir(), "probe-pgroup-escape-"));
    let escapee: number | undefined;
    try {
      const marker = join(dir, "descendant.log");
      const pidFile = join(dir, "descendant.pid");
      const script = join(dir, "exit-and-leave-a-descendant.sh");
      writeFileSync(
        script,
        [
          "#!/bin/sh",
          `( while true; do echo tick >> ${marker}; sleep 0.05; done ) &`,
          `echo $! > ${pidFile}`,
          "echo 3.11",
          "exit 0",
        ].join("\n"),
      );
      chmodSync(script, 0o755);

      const timeoutMs = 400;
      const started = Date.now();
      const result = await runInterpreterProbeBounded({ file: "/bin/sh", args: [script] }, timeoutMs);
      const elapsed = Date.now() - started;

      // Fail-closed, and bounded: `close` never fires (the descendant holds the
      // stdout pipe), so this is the deadline path even though the direct child
      // exited in single-digit milliseconds.
      expect(result).toBeUndefined();
      expect(elapsed).toBeGreaterThanOrEqual(timeoutMs - 50);
      expect(elapsed).toBeLessThan(timeoutMs + 2_000);

      escapee = Number.parseInt(readFileSync(pidFile, "utf8").trim(), 10);
      expect(Number.isSafeInteger(escapee)).toBe(true);
      expect(escapee).toBeGreaterThan(0);
      // Sanity: the descendant really did run, so a pass below cannot be a
      // never-started false negative.
      expect(existsSync(marker) ? readFileSync(marker, "utf8").length : 0).toBeGreaterThan(0);

      // THE ASSERTION. The descendant must be gone. Polled rather than sampled
      // once, so a slow CI box reads as slow, not as a failure.
      await expectDead(escapee, 5_000);
    } finally {
      reap(escapee);
      rmSync(dir, { recursive: true, force: true });
    }
  }, 20_000);

  it("still settles at the deadline when a descendant ESCAPES the group via setsid (documented scope)", async () => {
    // A descendant that calls `setsid(2)` before the deadline leaves the
    // process group, so process-group kill cannot reach it -- documented in
    // `runInterpreterProbeBounded` as out of scope for CLEANUP, because the
    // probe already runs as the agent's own uid and agent-uid code can spawn a
    // survivor without going near this probe. What must NOT degrade is the
    // CALLER's bound: the escapee holds the inherited stdout pipe open, so
    // `close` never fires, and the deadline must still settle and still drop
    // our handles. This test pins that.
    const dir = mkdtempSync(join(tmpdir(), "probe-setsid-escape-"));
    let escapee: number | undefined;
    try {
      const pidFile = join(dir, "escapee.pid");
      const script = join(dir, "escape.cjs");
      writeFileSync(
        script,
        [
          'const { spawn } = require("node:child_process");',
          'const { writeFileSync } = require("node:fs");',
          // `detached: true` is Node's setsid: a NEW session and process group.
          // `stdio` fd 1 hands it OUR inherited stdout pipe, so the pipe stays
          // open after this process exits.
          'const child = spawn(process.execPath, ["-e", "setTimeout(() => undefined, 30000)"], {',
          "  detached: true,",
          '  stdio: ["ignore", 1, "ignore"],',
          "});",
          `writeFileSync(${JSON.stringify(pidFile)}, String(child.pid));`,
          "child.unref();",
          'console.log("3.11");',
        ].join("\n"),
      );

      const timeoutMs = 500;
      const started = Date.now();
      const result = await runInterpreterProbeBounded({ file: process.execPath, args: [script] }, timeoutMs);
      const elapsed = Date.now() - started;

      expect(result).toBeUndefined();
      // `>=` proves this really is the DEADLINE path: the escaped descendant is
      // holding the pipe, so `close` cannot have fired early and made the test
      // pass without exercising the cleanup at all.
      expect(elapsed).toBeGreaterThanOrEqual(timeoutMs - 50);
      expect(elapsed).toBeLessThan(timeoutMs + 3_000);

      escapee = Number.parseInt(readFileSync(pidFile, "utf8").trim(), 10);
      expect(Number.isSafeInteger(escapee)).toBe(true);
      expect(escapee).toBeGreaterThan(0);
    } finally {
      reap(escapee);
      rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);

  it("returns the child's stdout on a clean exit, and undefined on a non-zero exit", async () => {
    await expect(
      runInterpreterProbeBounded({ file: "/bin/sh", args: ["-c", "echo 3.11"] }, 5_000),
    ).resolves.toBe("3.11\n");
    await expect(
      runInterpreterProbeBounded({ file: "/bin/sh", args: ["-c", "echo 3.11; exit 3"] }, 5_000),
    ).resolves.toBeUndefined();
  }, 20_000);

  it("a spawn failure (no such file) is undefined, never a throw", async () => {
    await expect(
      runInterpreterProbeBounded({ file: "/nonexistent/interpreter", args: [] }, 5_000),
    ).resolves.toBeUndefined();
  }, 20_000);
});
