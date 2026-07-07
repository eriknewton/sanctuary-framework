/**
 * Tests for the provision lockfile (fix L1): fail-loud on collision, always
 * releases even when the wrapped function throws.
 */

import { describe, it, expect } from "vitest";

import {
  withProvisionLock,
  ProvisionLockHeldError,
  type ProvisionLockOps,
} from "../../../src/castle-wall/provision/lockfile.js";

function mockOps(initiallyHeld = false): ProvisionLockOps & { held: boolean; releaseCalls: number } {
  const state = { held: initiallyHeld, releaseCalls: 0 };
  return {
    get held() {
      return state.held;
    },
    get releaseCalls() {
      return state.releaseCalls;
    },
    acquire: async () => {
      if (state.held) {
        const err = new Error("EEXIST") as NodeJS.ErrnoException;
        err.code = "EEXIST";
        throw err;
      }
      state.held = true;
    },
    release: async () => {
      state.held = false;
      state.releaseCalls += 1;
    },
  };
}

describe("castle-wall/provision/lockfile", () => {
  it("runs fn while holding the lock, then releases it", async () => {
    const ops = mockOps();
    let ranWhileHeld = false;
    const result = await withProvisionLock("/tmp/lock", ops, async () => {
      ranWhileHeld = ops.held;
      return 42;
    });
    expect(result).toBe(42);
    expect(ranWhileHeld).toBe(true);
    expect(ops.held).toBe(false);
    expect(ops.releaseCalls).toBe(1);
  });

  it("L1: fails loud with ProvisionLockHeldError when the lock is already held (no waiting)", async () => {
    const ops = mockOps(true);
    await expect(withProvisionLock("/tmp/lock", ops, async () => "should not run")).rejects.toThrow(
      ProvisionLockHeldError,
    );
    // Never acquired by this call, so release must not be invoked either.
    expect(ops.releaseCalls).toBe(0);
  });

  it("releases the lock even when fn throws (never strands the lock)", async () => {
    const ops = mockOps();
    await expect(
      withProvisionLock("/tmp/lock", ops, async () => {
        throw new Error("boom mid-flow");
      }),
    ).rejects.toThrow("boom mid-flow");
    expect(ops.held).toBe(false);
    expect(ops.releaseCalls).toBe(1);
  });

  it("propagates a non-EEXIST acquire error unchanged", async () => {
    const ops: ProvisionLockOps = {
      acquire: async () => {
        throw new Error("disk full");
      },
      release: async () => undefined,
    };
    await expect(withProvisionLock("/tmp/lock", ops, async () => "x")).rejects.toThrow("disk full");
  });
});
