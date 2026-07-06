import { describe, expect, it } from "vitest";
import { Writable } from "node:stream";

import {
  CASTLE_SIGNER_HELPER_LABEL,
  assessSignerHelperReadiness,
  buildHelperPublicKeyQuery,
  parseLaunchctlPrintForPid,
  runSignerHelperStatus,
  type ExecResult,
  type SignerHelperReadinessInputs,
} from "../../src/cli/castle-wall-signer-helper.js";

class CaptureStream extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: unknown,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    this.chunks.push(String(chunk));
    callback();
  }
  text(): string {
    return this.chunks.join("");
  }
}

const HELPER_KEY = new Uint8Array(32).fill(7);
const OTHER_KEY = new Uint8Array(32).fill(9);

function runningPrint(): ExecResult {
  return { code: 0, stdout: "\tstate = running\n\tpid = 4242\n", stderr: "" };
}

function notLoadedPrint(): ExecResult {
  return { code: 113, stdout: "", stderr: "Could not find service" };
}

function baseInputs(overrides: Partial<SignerHelperReadinessInputs> = {}): SignerHelperReadinessInputs {
  return {
    execFileFn: () => runningPrint(),
    queryHelperPublicKey: async () => HELPER_KEY,
    readGlobalPin: async () => HELPER_KEY,
    statCustodyDir: async () => ({ uid: 0, mode: 0o755 }),
    platform: "darwin",
    ...overrides,
  };
}

describe("castle-wall signer-helper boot-readiness preflight", () => {
  // ── parseLaunchctlPrintForPid (pure) ─────────────────────────────────

  describe("parseLaunchctlPrintForPid", () => {
    it("extracts a live pid from launchctl print output", () => {
      expect(parseLaunchctlPrintForPid(runningPrint())).toBe(4242);
    });

    it("returns null on a non-zero exit (job not loaded)", () => {
      expect(parseLaunchctlPrintForPid(notLoadedPrint())).toBeNull();
    });

    it("returns null when there is no pid line even on exit 0", () => {
      expect(
        parseLaunchctlPrintForPid({ code: 0, stdout: "\tstate = not running\n", stderr: "" }),
      ).toBeNull();
    });
  });

  // ── assessSignerHelperReadiness (pure decision logic) ─────────────────

  describe("assessSignerHelperReadiness", () => {
    it("reports READY when every check passes", async () => {
      const result = await assessSignerHelperReadiness(baseInputs());
      expect(result.ready).toBe(true);
      expect(result.remediation).toBe("none");
      expect(result.checks.map((c) => c.status)).toEqual(["pass", "pass", "pass", "pass"]);
    });

    it("is macOS-only: fails closed with an explicit skip on non-darwin", async () => {
      const result = await assessSignerHelperReadiness(baseInputs({ platform: "linux" }));
      expect(result.ready).toBe(false);
      expect(result.remediation).toBe("unknown");
      expect(result.checks[0]?.status).toBe("skipped");
    });

    it("missing launchd job -> remediation is approve_background_item", async () => {
      const result = await assessSignerHelperReadiness(
        baseInputs({ execFileFn: () => notLoadedPrint() }),
      );
      expect(result.ready).toBe(false);
      expect(result.remediation).toBe("approve_background_item");
      const launchdCheck = result.checks.find((c) => c.id === "launchd_job_visible");
      expect(launchdCheck?.status).toBe("fail");
      expect(result.guidance).toMatch(/Background Item/);
    });

    it("launchd job loaded but XPC unreachable -> approve_background_item, and pin_match is skipped", async () => {
      const result = await assessSignerHelperReadiness(
        baseInputs({
          queryHelperPublicKey: async () => {
            throw new Error("shim spawn failed: ENOENT");
          },
        }),
      );
      expect(result.ready).toBe(false);
      expect(result.remediation).toBe("approve_background_item");
      const xpcCheck = result.checks.find((c) => c.id === "xpc_reachable");
      expect(xpcCheck?.status).toBe("fail");
      expect(xpcCheck?.detail).toMatch(/ENOENT/);
      const pinCheck = result.checks.find((c) => c.id === "pin_match");
      expect(pinCheck?.status).toBe("skipped");
    });

    it("no signer-client shim resolvable -> xpc_reachable is skipped, not failed", async () => {
      const result = await assessSignerHelperReadiness(
        baseInputs({ queryHelperPublicKey: undefined }),
      );
      const xpcCheck = result.checks.find((c) => c.id === "xpc_reachable");
      expect(xpcCheck?.status).toBe("skipped");
      // Without XPC we cannot verify readiness even though launchd + custody pass.
      expect(result.ready).toBe(false);
    });

    it("pin mismatch -> remediation is pin_mismatch (distinct from approval / custody)", async () => {
      const result = await assessSignerHelperReadiness(
        baseInputs({ readGlobalPin: async () => OTHER_KEY }),
      );
      expect(result.ready).toBe(false);
      expect(result.remediation).toBe("pin_mismatch");
      const pinCheck = result.checks.find((c) => c.id === "pin_match");
      expect(pinCheck?.status).toBe("fail");
      expect(result.guidance).toMatch(/re-pin/);
    });

    it("no global pin provisioned yet -> pin_match skipped, not failed", async () => {
      const result = await assessSignerHelperReadiness(
        baseInputs({
          readGlobalPin: async () => {
            const err = new Error("ENOENT") as NodeJS.ErrnoException;
            err.code = "ENOENT";
            throw err;
          },
        }),
      );
      const pinCheck = result.checks.find((c) => c.id === "pin_match");
      expect(pinCheck?.status).toBe("skipped");
      expect(result.ready).toBe(false);
    });

    it("group-writable custody directory -> remediation is repair_custody_directory", async () => {
      const result = await assessSignerHelperReadiness(
        baseInputs({ statCustodyDir: async () => ({ uid: 0, mode: 0o775 }) }),
      );
      expect(result.ready).toBe(false);
      expect(result.remediation).toBe("repair_custody_directory");
      const custodyCheck = result.checks.find((c) => c.id === "custody_directory");
      expect(custodyCheck?.status).toBe("fail");
      expect(custodyCheck?.detail).toMatch(/group\/other-writable/);
    });

    it("custody directory not root-owned -> fails even if mode is tight", async () => {
      const result = await assessSignerHelperReadiness(
        baseInputs({ statCustodyDir: async () => ({ uid: 501, mode: 0o700 }) }),
      );
      expect(result.ready).toBe(false);
      expect(result.remediation).toBe("repair_custody_directory");
      const custodyCheck = result.checks.find((c) => c.id === "custody_directory");
      expect(custodyCheck?.detail).toMatch(/not root/);
    });

    it("custody directory missing entirely -> fails closed, not skipped", async () => {
      const result = await assessSignerHelperReadiness(
        baseInputs({
          statCustodyDir: async () => {
            throw new Error("ENOENT: no such file or directory");
          },
        }),
      );
      expect(result.ready).toBe(false);
      const custodyCheck = result.checks.find((c) => c.id === "custody_directory");
      expect(custodyCheck?.status).toBe("fail");
    });

    it("remediation precedence: launchd-missing wins even when custody is ALSO broken", async () => {
      const result = await assessSignerHelperReadiness(
        baseInputs({
          execFileFn: () => notLoadedPrint(),
          statCustodyDir: async () => ({ uid: 501, mode: 0o777 }),
        }),
      );
      // Both launchd_job_visible and custody_directory fail; remediation must
      // point at the Background Item approval first (the earliest actionable
      // step an operator should take), not the custody directory.
      expect(result.remediation).toBe("approve_background_item");
    });
  });

  // ── buildHelperPublicKeyQuery ──────────────────────────────────────────

  describe("buildHelperPublicKeyQuery", () => {
    it("returns undefined when neither a shim path nor an invoker is given", () => {
      expect(buildHelperPublicKeyQuery(undefined, undefined)).toBeUndefined();
    });

    it("builds a query function that resolves via the injected shim invoker", async () => {
      const query = buildHelperPublicKeyQuery(undefined, async (args) => {
        expect(args).toEqual(["get-pubkey"]);
        return { stdout: Buffer.from(HELPER_KEY).toString("base64url"), stderr: "", code: 0 };
      });
      expect(query).toBeDefined();
      const key = await query!();
      expect(key).toEqual(HELPER_KEY);
    });
  });

  // ── runSignerHelperStatus (CLI entry point) ────────────────────────────

  describe("runSignerHelperStatus", () => {
    it("refuses on non-macOS platforms", async () => {
      const err = new CaptureStream();
      const code = await runSignerHelperStatus([], { platform: "linux", err });
      expect(code).toBe(1);
      expect(err.text()).toMatch(/macOS-only/);
    });

    it("prints PASS for every check and exits 0 when ready", async () => {
      const out = new CaptureStream();
      const code = await runSignerHelperStatus([], {
        platform: "darwin",
        out,
        execFileFn: () => runningPrint(),
        signerClientInvoke: async () => ({
          stdout: Buffer.from(HELPER_KEY).toString("base64url"),
          stderr: "",
          code: 0,
        }),
        globalPinReader: async () => HELPER_KEY,
        statCustodyDirFn: async () => ({ uid: 0, mode: 0o755 }),
      });
      expect(code).toBe(0);
      expect(out.text()).toContain(`[PASS] launchd_job_visible`);
      expect(out.text()).toContain(CASTLE_SIGNER_HELPER_LABEL);
      expect(out.text()).toContain("READY");
    });

    it("prints FAIL + guidance and exits 1 when the helper is not loaded", async () => {
      const out = new CaptureStream();
      const code = await runSignerHelperStatus([], {
        platform: "darwin",
        out,
        execFileFn: () => notLoadedPrint(),
        globalPinReader: async () => HELPER_KEY,
        statCustodyDirFn: async () => ({ uid: 0, mode: 0o755 }),
      });
      expect(code).toBe(1);
      expect(out.text()).toContain("[FAIL] launchd_job_visible");
      expect(out.text()).toContain("NOT READY");
      expect(out.text()).toMatch(/Background Item/);
    });
  });
});
