/**
 * Dashboard port fallback — v0.10.1 regression guard for v0.10.0-rc.2 finding #2.
 *
 * v0.10.0-rc.2 had `MAX_PORT = 3510` hardcoded. The fallback loop was
 * `for (port = preferredPort; port <= MAX_PORT; port++)`. When
 * `preferredPort > 3510` — the documented tenant ports 3511/3512 — the
 * body never ran, `lastErr` was never assigned, and the loop threw
 * `No free dashboard port in range 3511-3510: unknown`. Empty range,
 * meaningless message, and multi-tenant setups starting above 3510 were
 * silently unusable. (The rc.2 soak had to fall back to 3502/3503.)
 *
 * The fix makes the fallback window relative to `preferredPort`, trying
 * the next PORT_FALLBACK_ATTEMPTS consecutive ports regardless of the
 * absolute number, and produces an exhaustion error that names both the
 * attempt count and the start/end ports.
 *
 * Tests target the real exported `startDashboardWithFallback`, not an
 * inline re-implementation, so future edits to that loop surface here.
 */

import { describe, it, expect } from "vitest";
import {
  PORT_FALLBACK_ATTEMPTS,
  startDashboardWithFallback,
} from "../../src/wrap/cli.js";
import type { DashboardStarter } from "../../src/wrap/cli.js";

function makeStarter(busyPorts: number[]): {
  starter: DashboardStarter;
  attempts: number[];
} {
  const attempts: number[] = [];
  const starter: DashboardStarter = async (opts) => {
    attempts.push(opts.port);
    if (busyPorts.includes(opts.port)) {
      const err = new Error(`EADDRINUSE: port ${opts.port}`) as Error & {
        code: string;
      };
      err.code = "EADDRINUSE";
      throw err;
    }
    return {
      url: `http://localhost:${opts.port}`,
      port: opts.port,
      host: "127.0.0.1",
      stop: async () => {},
      publish: () => {},
      publishActivity: () => {},
      publishApproval: () => {},
    };
  };
  return { starter, attempts };
}

describe("startDashboardWithFallback — rc.2 MAX_PORT regression", () => {
  it("binds to preferredPort when free (baseline)", async () => {
    const { starter, attempts } = makeStarter([]);
    const handle = await startDashboardWithFallback(starter, 3501, "t", "test");
    expect(handle.port).toBe(3501);
    expect(attempts).toEqual([3501]);
  });

  it("succeeds on preferredPort 3511 when it is free (rc.2 would have thrown)", async () => {
    // The rc.2 bug: MAX_PORT=3510 made preferredPort=3511 produce an
    // empty loop body and an immediate "No free dashboard port in range
    // 3511-3510" error even though 3511 itself was available.
    const { starter, attempts } = makeStarter([]);
    const handle = await startDashboardWithFallback(starter, 3511, "t", "test");
    expect(handle.port).toBe(3511);
    expect(attempts).toEqual([3511]);
  });

  it("walks the next N ports above preferredPort=3511 when 3511 is busy", async () => {
    const { starter, attempts } = makeStarter([3511, 3512, 3513]);
    const handle = await startDashboardWithFallback(starter, 3511, "t", "test");
    expect(handle.port).toBe(3514);
    expect(attempts).toEqual([3511, 3512, 3513, 3514]);
  });

  it("tries exactly PORT_FALLBACK_ATTEMPTS ports before giving up", async () => {
    const preferred = 3511;
    const busy: number[] = [];
    for (let i = 0; i < PORT_FALLBACK_ATTEMPTS; i++) busy.push(preferred + i);
    const { starter, attempts } = makeStarter(busy);
    await expect(
      startDashboardWithFallback(starter, preferred, "t", "test")
    ).rejects.toThrow(/No free dashboard port in the 20 ports starting at 3511/);
    expect(attempts.length).toBe(PORT_FALLBACK_ATTEMPTS);
    expect(attempts[0]).toBe(preferred);
    expect(attempts[PORT_FALLBACK_ATTEMPTS - 1]).toBe(
      preferred + PORT_FALLBACK_ATTEMPTS - 1
    );
  });

  it("exhaustion error names a sensible port range (not backwards, not empty)", async () => {
    const preferred = 3511;
    const busy: number[] = [];
    for (let i = 0; i < PORT_FALLBACK_ATTEMPTS; i++) busy.push(preferred + i);
    const { starter } = makeStarter(busy);
    try {
      await startDashboardWithFallback(starter, preferred, "t", "test");
      throw new Error("expected throw");
    } catch (e) {
      const msg = (e as Error).message;
      // rc.2 produced "No free dashboard port in range 3511-3510" — a
      // backwards range. The fixed message names the forward window.
      expect(msg).toMatch(/tried 3511-3530/);
      expect(msg).not.toMatch(/3511-3510/);
    }
  });

  it("propagates non-EADDRINUSE errors immediately without cycling ports", async () => {
    let callCount = 0;
    const starter: DashboardStarter = async () => {
      callCount++;
      throw new Error("TLS cert missing");
    };
    await expect(
      startDashboardWithFallback(starter, 3501, "t", "test")
    ).rejects.toThrow("TLS cert missing");
    expect(callCount).toBe(1);
  });
});
