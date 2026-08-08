import { describe, expect, it } from "vitest";
import { Writable } from "node:stream";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  formatLivenessProbeResultLine,
  runLivenessProbeCommand,
} from "../../src/cli/liveness-probe.js";
import {
  HERMES_ENDPOINT_SET,
  publishProvisionedEgressRules,
} from "../../src/castle-wall/provision/index.js";
import {
  cosLivenessFromReachabilityReport,
  type CosLivenessOutcome,
} from "../../src/castle-wall/provision/orchestrate.js";

const LIVENESS_OVERCLAIM_PATTERN = /brain|provider|process|running|alive|healthy/i;

class CaptureStream extends Writable {
  chunks: string[] = [];

  _write(chunk: Buffer | string, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    this.chunks.push(String(chunk));
    callback();
  }

  text(): string {
    return this.chunks.join("");
  }
}

async function writeCommittedReachabilityConfig(
  fortressPath: string,
  uid = 503,
): Promise<void> {
  const egressDir = join(fortressPath, "policy", "egress");
  await mkdir(egressDir, { recursive: true, mode: 0o700 });
  await writeFile(
    join(egressDir, "agent-origin.json"),
    JSON.stringify({
      mode: "uid",
      agent_uid: uid,
      system_uid_allow_ceiling: 500,
    }),
    { mode: 0o600 },
  );
  const published = await publishProvisionedEgressRules({
    fortressPath,
    endpointSet: HERMES_ENDPOINT_SET,
    reloadPolicy: async () => ({ ok: true }),
    now: () => new Date("2026-08-02T00:00:00.000Z"),
  });
  expect(published.ok).toBe(true);
}

async function runReachabilityProbe(
  fortressPath: string,
  execFileFn: (file: string, args: string[]) => Promise<{ stdout: string; stderr: string }>,
  argv: string[] = ["--fortress", fortressPath],
): Promise<{ code: number; out: string; err: string }> {
  const out = new CaptureStream();
  const err = new CaptureStream();
  const args = {
    argv,
    out,
    err,
    env: {},
    execFileFn,
    collectSystemResolvers: async () => ["1.1.1.1"],
  };
  const code = await runLivenessProbeCommand(args);
  return { code, out: out.text(), err: err.text() };
}

/**
 * Exact hostname match for the probe fakes. Substring matching on a URL is a
 * weak test (and CodeQL flags it): "api.venice.ai.evil.test" contains
 * "api.venice.ai". These fakes stand in for real egress decisions, so they
 * compare the parsed hostname.
 */
function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

describe("sanctuary liveness-probe CLI", () => {
  it("prints help for the standalone verb", async () => {
    const out = new CaptureStream();
    const err = new CaptureStream();

    const code = await runLivenessProbeCommand({ argv: ["--help"], out, err });

    expect(code).toBe(0);
    expect(out.text()).toContain("Usage: sanctuary liveness-probe");
    expect(out.text()).toContain("<fortress>/policy/egress/rules");
    expect(out.text()).not.toContain("telegram.json");
    expect(err.text()).toBe("");
  });

  it("refuses a MISSING fortress instead of degrading it to no_channel_configured (re-gate round 3)", async () => {
    // This test previously enshrined the bypass: a nonexistent fortress read as
    // the benign "no probe channel configured" case, so a caller pointed at the
    // wrong path — or a fortress that vanished under it — got a quiet unverified
    // instead of a refusal. An absent CONFIG FILE inside a VERIFIED fortress is
    // still the benign case; a missing fortress BASE is a config error.
    const out = new CaptureStream();
    const err = new CaptureStream();
    // Guaranteed-absent: a child of a freshly created temp dir, so the pin does
    // not depend on a hard-coded /tmp path staying nonexistent on the runner.
    const parent = await mkdtemp(join(tmpdir(), "sanctuary-liveness-missing-"));
    const missingFortress = join(parent, "no-such-fortress");

    const code = await runLivenessProbeCommand({
      argv: ["--fortress", missingFortress],
      out,
      err,
      env: {},
    });

    expect(code).toBe(2);
    expect(out.text()).toBe("");
    expect(err.text()).toContain("config_unreadable");
    // The credential path must never reach operator output on any error path.
    expect(err.text()).not.toContain("telegram.json");
    expect(err.text()).not.toContain(missingFortress);
    await rm(parent, { recursive: true, force: true });
  });

  it("returns config-error exit for malformed CLI options", async () => {
    const out = new CaptureStream();
    const err = new CaptureStream();

    const code = await runLivenessProbeCommand({
      argv: ["--unknown"],
      out,
      err,
      env: {},
    });

    expect(code).toBe(2);
    expect(err.text()).toContain("Unknown liveness-probe option: --unknown");
    expect(out.text()).toBe("");
  });

  it("refuses a trailing fortress flag before reading the default fortress", async () => {
    const out = new CaptureStream();
    const err = new CaptureStream();

    const code = await runLivenessProbeCommand({
      argv: ["--fortress"],
      out,
      err,
      env: {},
    });

    expect(code).toBe(2);
    expect(err.text()).toContain("--fortress requires a value");
    expect(out.text()).toBe("");
  });

  it("renders verified liveness only as the confined reachability differential", () => {
    const committedEndpoints = HERMES_ENDPOINT_SET.endpoints.map((endpoint) => ({
      name: endpoint.name,
      host: endpoint.host,
      port: endpoint.port,
    }));
    const result = cosLivenessFromReachabilityReport({
      ok: true,
      rows: [
        ...committedEndpoints.map((endpoint) => ({
          ...endpoint,
          expected: "reachable" as const,
          observed: "reachable" as const,
          pass: true,
        })),
        {
          name: "negative control (non-listed host must be blocked)",
          host: "example.com",
          port: 443,
          expected: "blocked" as const,
          observed: "blocked" as const,
          pass: true,
        },
      ],
    }, {
      committedEndpoints,
    });
    const line = formatLivenessProbeResultLine(result);

    expect(line).toBe(
      "verified: confined path verified: the agent uid reaches all 6 declared endpoints and remains blocked elsewhere.",
    );
    expect(line).not.toMatch(LIVENESS_OVERCLAIM_PATTERN);
  });

  it("does not render a legacy verified Telegram branch as verified liveness", () => {
    const line = formatLivenessProbeResultLine({
      kind: "cos_liveness_verified",
      evidence: {
        kind: "roundTrip",
        roundTrip: {
          channel: "telegram",
          requestId: "request-1",
          responseId: "response-1",
        },
      },
    } as unknown as CosLivenessOutcome);

    expect(line).toContain("unverified");
    expect(line).not.toMatch(/^verified:/);
    expect(line).not.toMatch(/Telegram round trip verified/i);
  });

  it("does not render hand-built malformed verified reachability evidence as verified liveness", () => {
    const line = formatLivenessProbeResultLine({
      kind: "cos_liveness_verified",
      evidence: {
        kind: "reachability",
        declaredEndpointCount: 3,
        reachableEndpointCount: 3,
        negativeControlBlocked: true,
        rows: [
          {
            endpoint: "A (a.example:443)",
            expected: "reachable",
            observed: "reachable",
            pass: true,
          },
          {
            endpoint: "A (a.example:443)",
            expected: "reachable",
            observed: "reachable",
            pass: true,
          },
          {
            endpoint: "B (b.example:443)",
            expected: "reachable",
            observed: "reachable",
            pass: true,
          },
          {
            endpoint: "negative control (control.example:443)",
            expected: "blocked",
            observed: "blocked",
            pass: true,
          },
        ],
      },
    } as unknown as CosLivenessOutcome);

    expect(line).toContain("unverified");
    expect(line).not.toMatch(/^verified:/);
    expect(line).not.toMatch(/confined path verified/i);
  });

  it("exits 0 when all declared endpoints reach and the negative control stays blocked", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-cli-liveness-ok-"));
    try {
      await writeCommittedReachabilityConfig(dir);
      const result = await runReachabilityProbe(dir, async (_file, args) => {
        const url = args[args.length - 1]!;
        if (hostOf(url) === "example.com") throw new Error("blocked control");
        return { stdout: "", stderr: "" };
      }, [`--fortress=${dir}`]);

      expect(result.code).toBe(0);
      expect(result.out).toContain(
        "verified: confined path verified: the agent uid reaches all 6 declared endpoints and remains blocked elsewhere.",
      );
      expect(result.err).toBe("");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("exits 1 and names the failing declared endpoint when reachability is partial", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-cli-liveness-partial-"));
    try {
      await writeCommittedReachabilityConfig(dir);
      const result = await runReachabilityProbe(dir, async (_file, args) => {
        const url = args[args.length - 1]!;
        if (hostOf(url) === "api.venice.ai") throw new Error("endpoint blocked");
        if (hostOf(url) === "example.com") throw new Error("blocked control");
        return { stdout: "", stderr: "" };
      });

      expect(result.code).toBe(1);
      expect(result.out).toContain("unverified reason=declared_endpoints_unreachable");
      expect(result.out).toContain("LLM (Venice)");
      expect(result.out).not.toMatch(LIVENESS_OVERCLAIM_PATTERN);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("exits 1 when all declared endpoints reach but the negative control is also reachable", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-cli-liveness-wall-down-"));
    try {
      await writeCommittedReachabilityConfig(dir);
      const result = await runReachabilityProbe(dir, async () => ({ stdout: "", stderr: "" }));

      expect(result.code).toBe(1);
      expect(result.out).toContain("unverified reason=negative_control_reachable");
      expect(result.out).toContain("negative control");
      expect(result.out).not.toMatch(/^verified:/m);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("exits 2 when committed confinement config cannot identify an agent uid", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-cli-liveness-no-origin-"));
    try {
      const published = await publishProvisionedEgressRules({
        fortressPath: dir,
        endpointSet: HERMES_ENDPOINT_SET,
        reloadPolicy: async () => ({ ok: true }),
        now: () => new Date("2026-08-02T00:00:00.000Z"),
      });
      expect(published.ok).toBe(true);
      const result = await runReachabilityProbe(dir, async () => ({ stdout: "", stderr: "" }));

      expect(result.code).toBe(2);
      expect(result.out).toBe("");
      expect(result.err).toContain("liveness-probe config error: agent_origin_absent");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("prints only a sanitized allowlist code when committed rules cannot be read", async () => {
    const sentinel = "ALLOWLIST_LEAK_SENTINEL_1c454";
    const dir = await mkdtemp(join(tmpdir(), `sanctuary-cli-liveness-${sentinel}-`));
    try {
      const egressDir = join(dir, "policy", "egress");
      await mkdir(egressDir, { recursive: true, mode: 0o700 });
      await writeFile(
        join(egressDir, "agent-origin.json"),
        JSON.stringify({
          mode: "uid",
          agent_uid: 503,
          system_uid_allow_ceiling: 500,
        }),
        { mode: 0o600 },
      );
      await writeFile(join(egressDir, "rules"), "not a directory", { mode: 0o600 });

      const result = await runReachabilityProbe(dir, async () => ({ stdout: "", stderr: "" }));

      expect(result.code).toBe(2);
      expect(result.out).toBe("");
      expect(result.err).toBe("liveness-probe config error: allowlist_unreadable\n");
      expect(`${result.out}${result.err}`).not.toContain(sentinel);
      expect(`${result.out}${result.err}`).not.toContain(dir);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
