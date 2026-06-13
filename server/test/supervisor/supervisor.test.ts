/**
 * Phase S1 — Supervisor lifecycle state machine.
 *
 * Covers the two launch-time gates the brief makes load-bearing plus the
 * health/restart semantics:
 *   - M2 idempotency: protecting an already-supervised agent is a no-op,
 *     never a double-launch (the codex idempotency double-launch lens);
 *   - M3 rotation: refuse-to-launch while a master rotation is in flight (the
 *     codex rotation-race lens);
 *   - H3 health: `protected` (green) requires FRESH enforcement evidence,
 *     never pid-liveness alone;
 *   - restart-backoff + burst-park; needs-unlock parking; key zeroing.
 */

import { describe, expect, it } from "vitest";
import {
  Supervisor,
  type AgentLauncher,
  type LaunchedChild,
  type SupervisionSpec,
} from "../../src/supervisor/supervisor.js";

/** A controllable mock child whose exit the test drives. */
class MockChild implements LaunchedChild {
  private exitCb: ((info: { code: number | null; signal: string | null }) => void) | null = null;
  stopped = false;
  onExit(cb: (info: { code: number | null; signal: string | null }) => void): void {
    this.exitCb = cb;
  }
  async stop(): Promise<void> {
    this.stopped = true;
  }
  /** Test driver: fire the exit callback. */
  fireExit(code = 1, signal: string | null = null): void {
    this.exitCb?.({ code, signal });
  }
}

class MockLauncher implements AgentLauncher {
  children: MockChild[] = [];
  launchCount = 0;
  lastKey: Uint8Array | null = null;
  fail = false;
  async launch(spec: SupervisionSpec): Promise<LaunchedChild> {
    this.launchCount++;
    this.lastKey = spec.transientKey;
    if (this.fail) throw new Error("launch failed");
    const c = new MockChild();
    this.children.push(c);
    return c;
  }
}

function makeKey(byte = 7): Uint8Array {
  return new Uint8Array([byte, byte, byte, byte]);
}

function makeSupervisor(over?: {
  launcher?: MockLauncher;
  rotation?: boolean;
  enforcementAt?: () => string | null;
  now?: () => number;
}) {
  const launcher = over?.launcher ?? new MockLauncher();
  let nowMs = 1_000_000;
  const now = over?.now ?? (() => nowMs);
  const sup = new Supervisor({
    launcher,
    isRotationInProgress: async () => over?.rotation ?? false,
    latestEnforcementAt: over?.enforcementAt ?? (() => null),
    now,
    // Synchronous schedule so restart timers fire deterministically in-test.
    schedule: (fn) => {
      queueMicrotask(fn);
      return () => {};
    },
  });
  return { sup, launcher, advance: (ms: number) => { nowMs += ms; } };
}

describe("Supervisor.protect", () => {
  it("launches a child and reports protecting", async () => {
    const { sup, launcher } = makeSupervisor();
    const r = await sup.protect({ agent_id: "a1", harness: "claude_code", config_path: "/c", transientKey: makeKey() });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.kind).toBe("protecting");
    expect(launcher.launchCount).toBe(1);
  });

  it("is resource-level idempotent: re-protecting a running agent does NOT double-launch (M2)", async () => {
    const { sup, launcher } = makeSupervisor();
    const k1 = makeKey(1);
    const k2 = makeKey(2);
    const r1 = await sup.protect({ agent_id: "a1", harness: "claude_code", config_path: "/c", transientKey: k1 });
    const r2 = await sup.protect({ agent_id: "a1", harness: "claude_code", config_path: "/c", transientKey: k2 });
    expect(launcher.launchCount).toBe(1);
    if (r2.ok) expect(r2.kind).toBe("already-protected");
    // The duplicate key the second call carried was zeroed.
    expect([...k2]).toEqual([0, 0, 0, 0]);
    void r1;
  });

  it("REFUSES to launch while a master rotation is in progress (M3)", async () => {
    const { sup, launcher } = makeSupervisor({ rotation: true });
    const key = makeKey();
    const r = await sup.protect({ agent_id: "a1", harness: "claude_code", config_path: "/c", transientKey: key });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("rotation_in_progress");
    expect(launcher.launchCount).toBe(0); // never launched
    expect([...key]).toEqual([0, 0, 0, 0]); // key zeroed on refusal
  });

  it("reports unavailable AND zeroes the key + drops the entry on an initial launch failure (codex H4)", async () => {
    const launcher = new MockLauncher();
    launcher.fail = true;
    const { sup } = makeSupervisor({ launcher });
    const key = makeKey(13);
    const r = await sup.protect({ agent_id: "a1", harness: "claude_code", config_path: "/c", transientKey: key });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("unavailable");
    // Key zeroed (no extended heap residency) and no resident entry left.
    expect([...key]).toEqual([0, 0, 0, 0]);
    expect(sup.status("a1")).toEqual([]);
  });

  it("coalesces CONCURRENT protects for the same agent_id onto ONE launch (codex H1)", async () => {
    const launcher = new MockLauncher();
    // Make launch slow so both calls are in flight together.
    let resolveLaunch!: () => void;
    const gate = new Promise<void>((r) => {
      resolveLaunch = r;
    });
    const orig = launcher.launch.bind(launcher);
    launcher.launch = async (spec) => {
      await gate;
      return orig(spec);
    };
    const { sup } = makeSupervisor({ launcher });
    const k1 = makeKey(1);
    const k2 = makeKey(2);
    const p1 = sup.protect({ agent_id: "a1", harness: "claude_code", config_path: "/c", transientKey: k1 });
    const p2 = sup.protect({ agent_id: "a1", harness: "claude_code", config_path: "/c", transientKey: k2 });
    await Promise.resolve();
    resolveLaunch();
    const [r1, r2] = await Promise.all([p1, p2]);
    expect(launcher.launchCount).toBe(1); // exactly one launch despite the race
    expect(r1.ok && r2.ok).toBe(true);
    // The losing duplicate's key was zeroed.
    expect([...k2]).toEqual([0, 0, 0, 0]);
  });

  it("does NOT keep the key resident when refused for rotation (codex H4/M3)", async () => {
    const { sup } = makeSupervisor({ rotation: true });
    const key = makeKey(5);
    await sup.protect({ agent_id: "a1", harness: "claude_code", config_path: "/c", transientKey: key });
    expect([...key]).toEqual([0, 0, 0, 0]);
    expect(sup.status("a1")).toEqual([]); // entry dropped, not parked-with-key
  });
});

describe("Supervisor key residency on park (codex R2-H1)", () => {
  it("zeroes the transient key when an agent is parked crashed after a burst", async () => {
    const { sup, launcher } = makeSupervisor();
    const key = makeKey(21);
    await sup.protect({ agent_id: "a1", harness: "claude_code", config_path: "/c", transientKey: key });
    for (let i = 0; i < 7; i++) {
      launcher.children[launcher.children.length - 1].fireExit(1);
      await new Promise((r) => setTimeout(r, 5));
    }
    expect(sup.status("a1")[0].state).toBe("crashed");
    // No child running, no restart pending ⇒ key must not stay resident.
    expect([...key]).toEqual([0, 0, 0, 0]);
  });
});

describe("Supervisor launch timeout (codex R2-M1)", () => {
  it("fails closed + drops the entry + zeroes the key when a launch hangs", async () => {
    const launcher = new MockLauncher();
    // A launch that never resolves.
    launcher.launch = () => new Promise<LaunchedChild>(() => {});
    const sup = new Supervisor({
      launcher,
      isRotationInProgress: async () => false,
      latestEnforcementAt: () => null,
      launchTimeoutMs: 10,
      // Real timers so the timeout actually fires.
    });
    const key = makeKey(33);
    const r = await sup.protect({ agent_id: "a1", harness: "claude_code", config_path: "/c", transientKey: key });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("unavailable");
    // The agent was dropped (not wedged) so a later protect is not coalesced
    // onto a stale promise, and the key was zeroed.
    expect(sup.status("a1")).toEqual([]);
    expect([...key]).toEqual([0, 0, 0, 0]);
  });

  it("stops + drops a child that resolves AFTER its protect timed out (codex R3-H3 orphan)", async () => {
    let releaseLaunch!: (c: LaunchedChild) => void;
    const launchGate = new Promise<LaunchedChild>((r) => {
      releaseLaunch = r;
    });
    const child = new MockChild();
    const launcher = new MockLauncher();
    launcher.launch = () => launchGate;
    const sup = new Supervisor({
      launcher,
      isRotationInProgress: async () => false,
      latestEnforcementAt: () => null,
      launchTimeoutMs: 10,
    });
    const key = makeKey(44);
    const r = await sup.protect({ agent_id: "a1", harness: "claude_code", config_path: "/c", transientKey: key });
    expect(r.ok).toBe(false); // timed out
    expect(sup.status("a1")).toEqual([]); // entry dropped
    // Now the late launch finally resolves with a real child.
    releaseLaunch(child);
    await new Promise((res) => setTimeout(res, 10));
    // The orphan child was stopped, not attached.
    expect(child.stopped).toBe(true);
    expect(sup.status("a1")).toEqual([]);
  });
});

describe("Supervisor restart-timeout late-attach guard (codex R4 generation token)", () => {
  it("a restart launch that resolves AFTER its restart-timeout does not attach an orphan", async () => {
    // First launch returns a normal child; the restart launch hangs past the
    // restart timeout, then resolves late.
    const firstChild = new MockChild();
    let restartResolve!: (c: LaunchedChild) => void;
    const restartGate = new Promise<LaunchedChild>((r) => {
      restartResolve = r;
    });
    const lateChild = new MockChild();
    let call = 0;
    const launcher = new MockLauncher();
    launcher.launch = () => {
      call++;
      if (call === 1) return Promise.resolve(firstChild);
      return restartGate; // the restart hangs
    };
    const sup = new Supervisor({
      launcher,
      isRotationInProgress: async () => false,
      latestEnforcementAt: () => null,
      launchTimeoutMs: 10,
      // Real-ish restart schedule: fire soon but asynchronously.
      schedule: (fn) => {
        const t = setTimeout(fn, 1);
        return () => clearTimeout(t);
      },
    });
    await sup.protect({ agent_id: "a1", harness: "claude_code", config_path: "/c", transientKey: makeKey(50) });
    // Crash the first child ⇒ a restart is scheduled, then hangs + times out.
    firstChild.fireExit(1);
    await new Promise((r) => setTimeout(r, 40)); // > restart delay + timeout
    expect(sup.status("a1")[0].state).toBe("crashed"); // parked on timeout
    // The hung restart launch finally resolves with a late child.
    restartResolve(lateChild);
    await new Promise((r) => setTimeout(r, 10));
    // The late child was stopped, not attached/promoted to running.
    expect(lateChild.stopped).toBe(true);
    expect(sup.status("a1")[0].state).toBe("crashed");
  });
});

describe("Supervisor crash-restart rotation interlock (codex H2)", () => {
  it("parks needs-unlock instead of relaunching under a retired master when rotation began mid-life", async () => {
    const launcher = new MockLauncher();
    let rotating = false;
    let nowMs = 1_000_000;
    const sup = new Supervisor({
      launcher,
      isRotationInProgress: async () => rotating,
      latestEnforcementAt: () => null,
      now: () => nowMs,
      schedule: (fn) => {
        queueMicrotask(fn);
        return () => {};
      },
    });
    await sup.protect({ agent_id: "a1", harness: "claude_code", config_path: "/c", transientKey: makeKey(8) });
    expect(launcher.launchCount).toBe(1);
    // A rotation starts, THEN the child crashes.
    rotating = true;
    nowMs += 10;
    launcher.children[0].fireExit(1);
    await new Promise((r) => setTimeout(r, 5));
    // Did NOT relaunch under the retired master.
    expect(launcher.launchCount).toBe(1);
    expect(sup.status("a1")[0].state).toBe("needs-unlock");
  });
});

describe("Supervisor health (H3: enforcement-evidenced, not pid-liveness)", () => {
  it("a running child with NO enforcement evidence is degraded, never protected", async () => {
    const { sup } = makeSupervisor({ enforcementAt: () => null });
    await sup.protect({ agent_id: "a1", harness: "claude_code", config_path: "/c", transientKey: makeKey() });
    const [s] = sup.status("a1");
    expect(s.state).toBe("degraded");
    expect(sup.protectedCount()).toBe(0);
  });

  it("a running child with FRESH evidence is protected (green)", async () => {
    const now = 2_000_000;
    const { sup } = makeSupervisor({
      now: () => now,
      enforcementAt: () => new Date(now - 1_000).toISOString(), // 1s old
    });
    await sup.protect({ agent_id: "a1", harness: "claude_code", config_path: "/c", transientKey: makeKey() });
    expect(sup.status("a1")[0].state).toBe("protected");
    expect(sup.protectedCount()).toBe(1);
  });

  it("a running child with STALE evidence falls back to degraded", async () => {
    const now = 2_000_000;
    const { sup } = makeSupervisor({
      now: () => now,
      enforcementAt: () => new Date(now - 10 * 60_000).toISOString(), // 10 min old
    });
    await sup.protect({ agent_id: "a1", harness: "claude_code", config_path: "/c", transientKey: makeKey() });
    expect(sup.status("a1")[0].state).toBe("degraded");
  });
});

describe("Supervisor restart / crash", () => {
  it("restarts a crashed child (survives agent crash — Tier A)", async () => {
    const { sup, launcher } = makeSupervisor();
    await sup.protect({ agent_id: "a1", harness: "claude_code", config_path: "/c", transientKey: makeKey() });
    expect(launcher.launchCount).toBe(1);
    launcher.children[0].fireExit(1);
    await new Promise((r) => setTimeout(r, 5)); // let the microtask restart run
    expect(launcher.launchCount).toBe(2);
    expect(sup.status("a1")[0].restarts).toBe(1);
  });

  it("parks crashed after a rapid-failure burst instead of looping forever", async () => {
    const { sup, launcher } = makeSupervisor();
    await sup.protect({ agent_id: "a1", harness: "claude_code", config_path: "/c", transientKey: makeKey() });
    // Crash repeatedly; the default burst cap is 5.
    for (let i = 0; i < 10; i++) {
      const child = launcher.children[launcher.children.length - 1];
      child.fireExit(1);
      await new Promise((r) => setTimeout(r, 5));
    }
    expect(sup.status("a1")[0].state).toBe("crashed");
    // Did not launch unboundedly.
    expect(launcher.launchCount).toBeLessThanOrEqual(6);
  });

  it("does NOT restart a child stopped by unprotect", async () => {
    const { sup, launcher } = makeSupervisor();
    await sup.protect({ agent_id: "a1", harness: "claude_code", config_path: "/c", transientKey: makeKey() });
    const child = launcher.children[0];
    await sup.unprotect("a1");
    expect(child.stopped).toBe(true);
    child.fireExit(0);
    await new Promise((r) => setTimeout(r, 5));
    expect(launcher.launchCount).toBe(1); // no restart after intentional stop
  });
});

describe("Supervisor unprotect / park / shutdown", () => {
  it("unprotect on an unknown agent returns not_found", async () => {
    const { sup } = makeSupervisor();
    const r = await sup.unprotect("ghost");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("not_found");
  });

  it("unprotect removes the spec and zeroes the resident key", async () => {
    const { sup } = makeSupervisor();
    const key = makeKey(9);
    await sup.protect({ agent_id: "a1", harness: "claude_code", config_path: "/c", transientKey: key });
    await sup.unprotect("a1");
    expect(sup.status("a1")).toEqual([]);
    expect([...key]).toEqual([0, 0, 0, 0]);
  });

  it("parkAllNeedsUnlock surfaces 'waiting for you', not 'broken' (reboot, Tier A)", () => {
    const { sup } = makeSupervisor();
    sup.parkAllNeedsUnlock([{ agent_id: "a1", harness: "claude_code", config_path: "/c" }]);
    expect(sup.status("a1")[0].state).toBe("needs-unlock");
    expect(sup.protectedCount()).toBe(0);
  });

  it("shutdown stops all children and clears the registry", async () => {
    const { sup, launcher } = makeSupervisor();
    await sup.protect({ agent_id: "a1", harness: "claude_code", config_path: "/c", transientKey: makeKey() });
    await sup.protect({ agent_id: "a2", harness: "claude_code", config_path: "/c", transientKey: makeKey() });
    await sup.shutdown();
    expect(launcher.children.every((c) => c.stopped)).toBe(true);
    expect(sup.status()).toEqual([]);
  });

  it("re-protecting a CRASHED agent re-launches (not a no-op)", async () => {
    const { sup, launcher } = makeSupervisor();
    await sup.protect({ agent_id: "a1", harness: "claude_code", config_path: "/c", transientKey: makeKey() });
    // Force into crashed via burst.
    for (let i = 0; i < 7; i++) {
      launcher.children[launcher.children.length - 1].fireExit(1);
      await new Promise((r) => setTimeout(r, 5));
    }
    expect(sup.status("a1")[0].state).toBe("crashed");
    const before = launcher.launchCount;
    const r = await sup.protect({ agent_id: "a1", harness: "claude_code", config_path: "/c", transientKey: makeKey() });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.kind).toBe("protecting");
    expect(launcher.launchCount).toBe(before + 1);
  });
});

describe("Supervisor never logs the transient key", () => {
  it("the log sink receives no field equal to the raw key bytes", async () => {
    const seen: unknown[] = [];
    const launcher = new MockLauncher();
    const sup = new Supervisor({
      launcher,
      isRotationInProgress: async () => true, // force the rotation-refused log path
      latestEnforcementAt: () => null,
      log: (_e, fields) => seen.push(fields),
    });
    const key = makeKey(42);
    await sup.protect({ agent_id: "a1", harness: "claude_code", config_path: "/c", transientKey: key });
    const flat = JSON.stringify(seen);
    expect(flat).not.toContain("42,42,42,42");
    expect(flat).not.toContain("KgKgKg"); // any base64 of the key
  });
});
