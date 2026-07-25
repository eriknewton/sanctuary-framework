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
  resolveHermesGatewayArgv,
  interpreterVersionProbeArgv,
  parseInterpreterVersion,
  parseVenvSitePackagesVersion,
  INTERPRETER_VERSION_PROBE_SOURCE,
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
    probeInterpreterAsUid: async (path, uid) =>
      uid === AGENT_UID ? runnableAsAgent[path] : undefined,
  };
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
      expect(resolved.programArguments).toEqual([
        venvPython,
        "-m",
        "hermes_cli.main",
        "gateway",
        "run",
        "--accept-hooks",
      ]);
      // The venv interpreter carries its own site-packages; PYTHONPATH is only
      // the source tree hermes_cli lives in.
      expect(resolved.environment).toEqual({
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
      expect(resolved.programArguments[0]).toBe(systemPython);
      expect(resolved.environment?.PYTHONPATH).toBe(`${hermesAgentDir}:${sitePackages}`);
    });

    it("skips a matching-version system interpreter the AGENT UID cannot execute, and takes the next one that it can", async () => {
      const ops = mockOps(new Set([systemPython, "/usr/bin/python3", mainModule, sitePackages]), {
        // /opt/homebrew/bin/python3 is deliberately absent from the runnable
        // map: it exists, but not for this uid.
        "/usr/bin/python3": { major: 3, minor: 11 },
      });
      const resolved = await resolveHermesGatewayArgv(ops, { agentHome, agentUid: AGENT_UID });
      expect(resolved.programArguments[0]).toBe("/usr/bin/python3");
    });

    it("REGRESSION (F-INTERP): a venv interpreter that EXISTS but is not executable by the agent uid is not chosen on existence alone", async () => {
      // `pathExists` is true for the venv python here. The pre-fix module used
      // existence probes to decide; the fix requires the uid to actually run it.
      const ops = mockOps(new Set([systemPython, mainModule, sitePackages, venvPython]), {
        [systemPython]: { major: 3, minor: 11 },
      });
      const resolved = await resolveHermesGatewayArgv(ops, { agentHome, agentUid: AGENT_UID });
      expect(resolved.programArguments[0]).toBe(systemPython);
    });

    it("probes as the AGENT uid, never as the caller (root)", async () => {
      const seen: Array<{ path: string; uid: number }> = [];
      const ops: HarnessArgvOps = {
        pathExists: async (path) => new Set([mainModule, sitePackages, venvPython]).has(path),
        probeInterpreterAsUid: async (path, uid) => {
          seen.push({ path, uid });
          return path === venvPython ? { major: 3, minor: 11 } : undefined;
        },
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
      expect(resolved.programArguments[0]?.startsWith("/")).toBe(true);
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
      expect(resolved.programArguments[0]).toBe(venvPython);
    });
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

    it("reads the ABI version out of a venv site-packages path", () => {
      expect(parseVenvSitePackagesVersion(sitePackages)).toEqual({ major: 3, minor: 11 });
      expect(parseVenvSitePackagesVersion(`${sitePackages}/`)).toEqual({ major: 3, minor: 11 });
      expect(parseVenvSitePackagesVersion("/somewhere/lib/site-packages")).toBeUndefined();
    });
  });
});
