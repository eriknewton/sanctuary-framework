// fail-before-exempt: pins pre-existing #1051 helper (chownCreatedDirChain)
// semantics for gate F1; the helper is unchanged by this PR, so these tests
// legitimately pass against main (nothing to go red-against-main here).
/**
 * Unit tests for `chownCreatedDirChain`'s OWN semantics (PR #1084 gate F1):
 * the helper previously had no failing check anywhere -- a gate mutation that
 * turned it into a silent no-op left the entire suite green, because the only
 * coverage was of the WIRING that calls it. These tests pin the helper's three
 * behavioral guarantees by execution:
 *   1. created-only chown: pre-existing ancestors are opened for verification
 *      but never chowned; exactly the created chain is chowned, in order;
 *   2. non-ancestor stop refusal: a `firstCreated` that is not an ancestor of
 *      the leaf throws (never silently leaves created directories misowned);
 *   3. symlinked-component refusal: a symlink anywhere in the verified chain
 *      fails the `O_NOFOLLOW | O_DIRECTORY` open and the helper refuses to
 *      chown through it.
 *
 * Observation mechanism: `node:fs/promises` is partially mocked so `open`
 * returns a proxy whose `chown` RECORDS (path, uid, gid) before delegating.
 * The targets are chowned to the CURRENT uid/gid, so the real chown is a
 * permitted no-op and the tests run unprivileged.
 */
import { mkdir, mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { chownCreatedDirChain } from "../../src/storage/custody-fs.js";

const { chownCalls } = vi.hoisted(() => ({
  chownCalls: [] as { path: string; uid: number; gid: number }[],
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    open: async (...args: Parameters<typeof actual.open>) => {
      const handle = await actual.open(...args);
      const path = String(args[0]);
      return new Proxy(handle, {
        get(target, prop) {
          if (prop === "chown") {
            return async (uid: number, gid: number) => {
              chownCalls.push({ path, uid, gid });
              return target.chown(uid, gid);
            };
          }
          const value = Reflect.get(target, prop, target);
          return typeof value === "function" ? value.bind(target) : value;
        },
      });
    },
  };
});

const SELF = { uid: process.getuid!(), gid: process.getgid!() };

describe("chownCreatedDirChain semantics", () => {
  const roots: string[] = [];

  beforeEach(() => {
    chownCalls.length = 0;
  });

  afterEach(async () => {
    for (const root of roots.splice(0)) {
      await rm(root, { recursive: true, force: true });
    }
  });

  async function makeRoot(): Promise<string> {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-chown-chain-"));
    roots.push(root);
    return root;
  }

  it("chowns exactly the created chain, never the pre-existing parent", async () => {
    const root = await makeRoot();
    const pre = join(root, "pre");
    const c1 = join(pre, "c1");
    const c2 = join(c1, "c2");
    await mkdir(c2, { recursive: true, mode: 0o700 });

    await chownCreatedDirChain(c1, c2, SELF);

    expect(chownCalls.map((call) => call.path)).toEqual([c1, c2]);
    expect(chownCalls.every((call) => call.uid === SELF.uid && call.gid === SELF.gid)).toBe(
      true,
    );
    // The pre-existing parent is opened for no-follow verification but MUST
    // NOT be chowned (chowning dirs this call did not create is the
    // ownership-transfer overreach the created-chain bound exists to prevent).
    expect(chownCalls.map((call) => call.path)).not.toContain(pre);
  });

  it("refuses a firstCreated that is not an ancestor of the leaf", async () => {
    const root = await makeRoot();

    await expect(
      chownCreatedDirChain(join(root, "x"), join(root, "y", "z"), SELF),
    ).rejects.toThrow(/is not an ancestor of/);
    expect(chownCalls).toEqual([]);
  });

  it("refuses to chown through a symlinked path component", async () => {
    const root = await makeRoot();
    const a = join(root, "a");
    const elsewhere = join(root, "elsewhere");
    await mkdir(a, { recursive: true, mode: 0o700 });
    await mkdir(join(elsewhere, "c"), { recursive: true, mode: 0o700 });
    // a/b -> elsewhere: a symlinked component inside the chain to verify.
    await symlink(elsewhere, join(a, "b"));

    await expect(
      chownCreatedDirChain(join(a, "b"), join(a, "b", "c"), SELF),
    ).rejects.toThrow(/refusing to chown through/);
    expect(chownCalls).toEqual([]);
  });
});
