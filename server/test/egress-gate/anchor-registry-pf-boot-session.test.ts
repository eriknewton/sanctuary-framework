/**
 * REGISTRY-LEVEL REGRESSIONS for the two pf enable-state defects measured on
 * Mini1 on 2026-07-26 against merged main `ed7722ce`, plus the operator escape
 * hatch the drill found does not exist.
 *
 * `pf-enable-state.test.ts` covers the chokepoint against captured pfctl
 * output. This file covers what the REGISTRY does with it, which is where the
 * defect was actually reachable from the product:
 *
 *   1. the boot binding is PERSISTED beside the token and threaded back into
 *      the next arm, so the resolver has provenance to judge;
 *   2. a stale record is REPLACED in the same save that commits the union, so
 *      the fix cannot rebuild the deadlock through `normalizeState`'s
 *      "committed but no token = dirty" door;
 *   3. a rollback restores the token and its boot session TOGETHER;
 *   4. the last-uid teardown no longer re-asserts the union it is about to
 *      flush, which is what deadlocked `--unprotect-egress-gate`.
 *
 * All pfctl interaction is injected; nothing here touches a real pf or host.
 */

import { describe, it, expect } from "vitest";

import {
  PfAnchorRegistry,
  PF_ANCHOR_REGISTRY_STATE_VERSION,
  type ArmPfAnchorResult,
  type PfAnchorRegistryOps,
  type PfAnchorRegistryState,
  type PfAnchorRegistryStore,
} from "../../src/egress-gate/anchor-registry.js";
import type { PfLivenessResult } from "../../src/egress-gate/pf-anchor.js";
import type { PfEnableReference } from "../../src/egress-gate/pf-enable-state.js";

import {
  CAPTURED_BOOT_SESSION_AFTER,
  CAPTURED_BOOT_SESSION_BEFORE,
  CAPTURED_ENABLE_TOKEN,
  CAPTURED_STALE_REGISTRY_TOKEN,
} from "./fixtures/pf-hardware-capture.js";

const ENTRY = { agent_uid: 503, gate_port: 49296, fortress_path: "/f/drill" };

function memStore(initial: PfAnchorRegistryState | null): PfAnchorRegistryStore & {
  saved: PfAnchorRegistryState[];
} {
  let current = initial;
  const saved: PfAnchorRegistryState[] = [];
  return {
    saved,
    async load() {
      return current === null ? null : (JSON.parse(JSON.stringify(current)) as PfAnchorRegistryState);
    },
    async save(state) {
      current = JSON.parse(JSON.stringify(state)) as PfAnchorRegistryState;
      saved.push(current);
    },
  };
}

function memLock() {
  const held = new Set<string>();
  return {
    async acquire(p: string) {
      if (held.has(p)) throw new Error("held");
      held.add(p);
    },
    async release(p: string) {
      held.delete(p);
    },
  };
}

const live: PfLivenessResult = { live: true, reasons: [] };

interface Harness {
  registry: PfAnchorRegistry;
  store: ReturnType<typeof memStore>;
  armCalls: Array<{ uids: number[]; existing?: PfEnableReference }>;
  disarmCalls: Array<{ enableToken?: string }>;
}

function harness(opts: {
  initial?: PfAnchorRegistryState | null;
  arm?: (existing: PfEnableReference | undefined) => Promise<ArmPfAnchorResult>;
  disarm?: () => Promise<void>;
  liveness?: () => Promise<PfLivenessResult>;
} = {}): Harness {
  const store = memStore(opts.initial ?? null);
  const armCalls: Array<{ uids: number[]; existing?: PfEnableReference }> = [];
  const disarmCalls: Array<{ enableToken?: string }> = [];
  const ops: PfAnchorRegistryOps = {
    store,
    lock: memLock(),
    runner: { async run() { return { code: 0, stdout: "", stderr: "" }; } },
    armUnion: async (entries, options) => {
      armCalls.push({
        uids: entries.map((e) => e.agent_uid),
        ...(options.existingEnableReference !== undefined
          ? { existing: options.existingEnableReference }
          : {}),
      });
      if (opts.arm !== undefined) return opts.arm(options.existingEnableReference);
      // Default: behave like the fixed chokepoint. Reuse a reference bound to
      // THIS boot; otherwise mint a fresh one bound to the current boot.
      const existing = options.existingEnableReference;
      const reusable =
        existing !== undefined && existing.boot_session_uuid === CAPTURED_BOOT_SESSION_AFTER;
      return {
        settleProbes: 1,
        enableReference: reusable
          ? existing
          : { token: CAPTURED_ENABLE_TOKEN, boot_session_uuid: CAPTURED_BOOT_SESSION_AFTER },
        acquiredEnableReference: !reusable,
      };
    },
    disarm: async (options) => {
      disarmCalls.push({
        ...(options.enableToken !== undefined ? { enableToken: options.enableToken } : {}),
      });
      await (opts.disarm ?? (async () => {}))();
    },
    unionLiveness: opts.liveness ?? (async () => live),
  };
  return { registry: new PfAnchorRegistry(ops), store, armCalls, disarmCalls };
}

/** The exact on-disk state the drill left after the reboot. */
const POST_REBOOT_STATE: PfAnchorRegistryState = {
  version: PF_ANCHOR_REGISTRY_STATE_VERSION,
  committed: [ENTRY],
  enable_token: CAPTURED_STALE_REGISTRY_TOKEN,
  enable_token_boot_session: CAPTURED_BOOT_SESSION_BEFORE,
};

describe("the pf enable reference is persisted WITH its boot session", () => {
  it("saves the token and the boot binding together on a first arm", async () => {
    const h = harness();
    await h.registry.addOrUpdate(ENTRY);
    const last = h.store.saved[h.store.saved.length - 1]!;
    expect(last.enable_token).toBe(CAPTURED_ENABLE_TOKEN);
    expect(last.enable_token_boot_session).toBe(CAPTURED_BOOT_SESSION_AFTER);
  });

  it("threads the WHOLE record back into the next arm, not a bare token", async () => {
    const h = harness({ initial: POST_REBOOT_STATE });
    await h.registry.addOrUpdate(ENTRY);
    expect(h.armCalls[0]?.existing).toEqual({
      token: CAPTURED_STALE_REGISTRY_TOKEN,
      boot_session_uuid: CAPTURED_BOOT_SESSION_BEFORE,
    });
  });

  it("F-PFBOOT: replaces a stale record in the SAME save that commits the union", async () => {
    // The measured post-reboot file carried enable_token 2276319666065282592
    // byte-identical to its pre-reboot value while pf was Status: Disabled.
    // The replacement must land in the commit save: a fix that cleared the
    // stale token without minting its replacement in the same write would trip
    // `normalizeState`'s "committed set with no token = dirty" rule and rebuild
    // the deadlock through a different door.
    const h = harness({ initial: POST_REBOOT_STATE });
    const result = await h.registry.addOrUpdate(ENTRY);
    expect(result.dirty).toBe(false);
    const last = h.store.saved[h.store.saved.length - 1]!;
    expect(last.committed).toHaveLength(1);
    expect(last.enable_token).toBe(CAPTURED_ENABLE_TOKEN);
    expect(last.enable_token_boot_session).toBe(CAPTURED_BOOT_SESSION_AFTER);
    // The committed union and the fresh reference are one write.
    expect(last.pending).toBeUndefined();
  });

  it("drops a malformed boot binding rather than comparing against something unusable", async () => {
    const h = harness({
      initial: { ...POST_REBOOT_STATE, enable_token_boot_session: "   " },
    });
    await h.registry.addOrUpdate(ENTRY);
    // The token survives (it may still be attributable via pfctl); the unusable
    // binding does not, so the resolver falls back to attribution rather than
    // comparing against whitespace.
    expect(h.armCalls[0]?.existing).toEqual({ token: CAPTURED_STALE_REGISTRY_TOKEN });
  });

  it("a rollback restores the token and its boot session TOGETHER", async () => {
    // Restoring a bare token here would hand the next arm a reference with no
    // provenance -- the F-PFBOOT shape rebuilt inside the rollback path.
    const prior: PfAnchorRegistryState = {
      version: PF_ANCHOR_REGISTRY_STATE_VERSION,
      committed: [ENTRY],
      enable_token: "111",
      enable_token_boot_session: CAPTURED_BOOT_SESSION_AFTER,
    };
    let attempt = 0;
    const h = harness({
      initial: prior,
      arm: async (existing) => {
        attempt += 1;
        // The registry is clean and live, so reconcile-on-entry does not arm.
        // Arm #1 is the forward apply (adding a second uid); it fails, and
        // arm #2 is the rollback re-asserting the previous union.
        if (attempt === 1) throw new Error("forward apply failed");
        return {
          settleProbes: 1,
          enableReference: existing ?? {
            token: "222",
            boot_session_uuid: CAPTURED_BOOT_SESSION_AFTER,
          },
          acquiredEnableReference: existing === undefined,
        };
      },
    });
    await expect(
      h.registry.addOrUpdate({ agent_uid: 504, gate_port: 20001, fortress_path: "/f/b" }),
    ).rejects.toThrow(/forward apply failed/);
    const last = h.store.saved[h.store.saved.length - 1]!;
    expect(last.enable_token).toBe("111");
    expect(last.enable_token_boot_session).toBe(CAPTURED_BOOT_SESSION_AFTER);
  });
});

describe("the operator escape hatch: a full teardown does not re-assert first", () => {
  it("removing the LAST uid flushes without re-arming the union it is discarding", async () => {
    // MEASURED DEADLOCK. After the reboot, `--unprotect-egress-gate` failed at
    // stage `recover` even though its desired set is EMPTY, because
    // reconcile-on-entry re-asserted the previous non-empty union first and
    // that re-assert needed the very pf state that was missing. Boot
    // self-bring-up pointed at `--repair-egress-gate`; repair pointed at
    // `--unprotect-egress-gate`; unprotect said "investigate". A closed loop
    // whose only measured exit was an out-of-band `pfctl -E`, which is exactly
    // the action that creates the F-PFTHIRDPARTY wrong-allow.
    const h = harness({
      initial: POST_REBOOT_STATE,
      arm: async () => {
        throw new Error("pf anchor union settle-probe timed out after 5000ms");
      },
      // Drift is reported, so the OLD code would have tried to re-assert.
      liveness: async () => ({ live: false, reasons: ["pf is not enabled"] }),
    });

    const result = await h.registry.remove(ENTRY.agent_uid);

    expect(result.committed).toEqual([]);
    expect(result.dirty).toBe(false);
    // The union was never re-armed on the way out.
    expect(h.armCalls).toEqual([]);
    // The flush ran, and it was handed the recorded token to release.
    expect(h.disarmCalls).toEqual([{ enableToken: CAPTURED_STALE_REGISTRY_TOKEN }]);
    const last = h.store.saved[h.store.saved.length - 1]!;
    expect(last.committed).toEqual([]);
    expect(last.enable_token).toBeUndefined();
    expect(last.enable_token_boot_session).toBeUndefined();
  });

  it("removing ONE of TWO uids still reconciles (the survivors' rules must stay exact)", async () => {
    // The skip is scoped to the last uid leaving. With a survivor, the anchor
    // must keep holding its rules exactly, so drift repair still applies.
    const other = { agent_uid: 504, gate_port: 20001, fortress_path: "/f/b" };
    let livenessProbes = 0;
    const h = harness({
      initial: {
        version: PF_ANCHOR_REGISTRY_STATE_VERSION,
        committed: [ENTRY, other],
        enable_token: CAPTURED_ENABLE_TOKEN,
        enable_token_boot_session: CAPTURED_BOOT_SESSION_AFTER,
      },
      liveness: async () => {
        livenessProbes += 1;
        return livenessProbes === 1 ? { live: false, reasons: ["drift"] } : live;
      },
    });
    const result = await h.registry.remove(ENTRY.agent_uid);
    expect(result.committed.map((e) => e.agent_uid)).toEqual([504]);
    // Two arms: the reconcile re-assert of [503, 504], then the new union [504].
    expect(h.armCalls.map((c) => c.uids)).toEqual([[503, 504], [504]]);
    expect(h.disarmCalls).toEqual([]);
  });

  it("the teardown completes even when the recorded reference is already gone", async () => {
    // `pfctl -X` on a token a reboot invalidated exits 1 with either
    // `pfctl: pf not enabled` or `pfctl: pf: token invalid`. The chokepoint
    // treats that as the truth about the token rather than as a teardown
    // failure, so the registry entry can actually be cleared.
    const h = harness({ initial: POST_REBOOT_STATE, disarm: async () => {} });
    const result = await h.registry.remove(ENTRY.agent_uid);
    expect(result.committed).toEqual([]);
    expect((await h.registry.list()).entries).toEqual([]);
  });
});
