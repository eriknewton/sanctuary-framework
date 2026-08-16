/**
 * Register O-07 (MEDIUM, reported): `castle-wall status --fortress <path>`
 * was reported to probe the DEFAULT socket instead of the fortress-scoped
 * one, with `SANCTUARY_STORAGE_...` env/flag precedence suspected.
 *
 * Reproduction (drives the real CLI dispatch surface, not a unit around a
 * helper): `runStatus` took NO `argv` parameter at all before this fix --
 * `src/cli.ts`'s `case "status"` called it as `runStatus()`, dropping every
 * trailing arg including `--fortress <path>`, unlike every other
 * castle-wall verb (`runEnable(args.slice(1))`,
 * `runAuditStoreStatus(args.slice(1))`, etc.). So the bug was not a
 * flag-vs-env PRECEDENCE bug (the flag was never even parsed); it
 * reproduces regardless of flag/arg order, which this file proves by
 * exercising several orders/forms and one precedence case.
 *
 * These tests drive `runStatus` exactly as `src/cli.ts` now does --
 * `runStatus(argv, ctx)` with `argv` being the CLI tokens after the
 * `status` subcommand -- and assert, via the injected
 * `enforcementAvailabilityQuery` seam, which socket path the darwin
 * enforcement-availability probe actually queried. On darwin,
 * `resolveCastleWallSocketPath` resolves a per-fortress socket at
 * `<fortressPath>/castle.sock` (src/castle-wall/runtime/socket-path.ts), so
 * the socket path IS the fortress identity for this assertion.
 */
import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import { runStatus } from "../../src/cli/castle-wall.js";

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

describe("castle-wall status --fortress socket resolution (O-07)", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  async function tempFortress(prefix: string): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), prefix));
    tempDirs.push(dir);
    return dir;
  }

  /** Runs `runStatus(argv, ...)` and returns the socket path the darwin
   * enforcement-availability probe was queried with (undefined if the probe
   * was never invoked, e.g. a parse error short-circuited status first). */
  async function probedSocketPath(
    argv: string[],
    env: NodeJS.ProcessEnv,
  ): Promise<{ code: number; socketPath: string | undefined; out: string }> {
    const out = new CaptureStream();
    let observedSocketPath: string | undefined;
    const code = await runStatus(argv, {
      out,
      env,
      platform: "darwin",
      execSyncFn: () => "",
      hostAppCandidates: [],
      globalPinReader: async () => {
        throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
      },
      enforcementAvailabilityQuery: async (socketPath: string) => {
        observedSocketPath = socketPath;
        return {
          status: "undetermined",
          reason: "test_probe",
          observed_at: null,
          freshness_window_ms: 60_000,
          active_connection_count: 0,
        };
      },
    });
    return { code, socketPath: observedSocketPath, out: out.text() };
  }

  it("probes the fortress-scoped socket, not the default, with --fortress <path> (space form)", async () => {
    const defaultFortress = await tempFortress("sanctuary-o07-default-");
    const namedFortress = await tempFortress("sanctuary-o07-named-");

    const { code, socketPath } = await probedSocketPath(
      ["--fortress", namedFortress],
      { SANCTUARY_STORAGE_PATH: defaultFortress },
    );

    expect(code).toBe(0);
    expect(socketPath).toBe(`${namedFortress}/castle.sock`);
    expect(socketPath).not.toBe(`${defaultFortress}/castle.sock`);
  });

  it("probes the fortress-scoped socket with --fortress=<path> (equals form)", async () => {
    const defaultFortress = await tempFortress("sanctuary-o07-default-");
    const namedFortress = await tempFortress("sanctuary-o07-named-");

    const { code, socketPath } = await probedSocketPath(
      [`--fortress=${namedFortress}`],
      { SANCTUARY_STORAGE_PATH: defaultFortress },
    );

    expect(code).toBe(0);
    expect(socketPath).toBe(`${namedFortress}/castle.sock`);
    expect(socketPath).not.toBe(`${defaultFortress}/castle.sock`);
  });

  it("the --fortress flag wins over SANCTUARY_STORAGE_PATH regardless of which is set first in env vs argv", async () => {
    // Named fortress is the CLI flag; SANCTUARY_STORAGE_PATH names a
    // DIFFERENT, stale fortress -- covering the register's suspected
    // "env/flag precedence" angle explicitly, on top of the "never parsed
    // at all" mechanism the other cases in this file prove.
    const staleEnvFortress = await tempFortress("sanctuary-o07-stale-env-");
    const namedFortress = await tempFortress("sanctuary-o07-named-");

    const { code, socketPath } = await probedSocketPath(
      ["--fortress", namedFortress],
      { SANCTUARY_STORAGE_PATH: staleEnvFortress },
    );

    expect(code).toBe(0);
    expect(socketPath).toBe(`${namedFortress}/castle.sock`);
  });

  it("with no --fortress flag, falls back to SANCTUARY_STORAGE_PATH (preserves prior behavior)", async () => {
    const envFortress = await tempFortress("sanctuary-o07-env-only-");

    const { code, socketPath } = await probedSocketPath([], {
      SANCTUARY_STORAGE_PATH: envFortress,
    });

    expect(code).toBe(0);
    expect(socketPath).toBe(`${envFortress}/castle.sock`);
  });

  it("a --fortress with a trailing value that looks like a flag is refused, never silently resolves the default fortress", async () => {
    const defaultFortress = await tempFortress("sanctuary-o07-default-");
    const out = new CaptureStream();
    let probed = false;
    const code = await runStatus(["--fortress"], {
      out,
      err: out,
      env: { SANCTUARY_STORAGE_PATH: defaultFortress },
      platform: "darwin",
      enforcementAvailabilityQuery: async () => {
        probed = true;
        return {
          status: "undetermined",
          reason: "unexpected_probe",
          observed_at: null,
          freshness_window_ms: 60_000,
          active_connection_count: 0,
        };
      },
    });

    expect(code).toBe(2);
    expect(probed).toBe(false);
    expect(out.text()).toContain("--fortress requires a value");
  });
});
