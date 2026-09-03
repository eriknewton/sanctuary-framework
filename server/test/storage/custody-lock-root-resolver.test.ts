/**
 * Unit tests for the custody kernel-lock ROOT resolver
 * ({@link resolveCustodyLockRoot}) and the hardening the ensure path carries
 * onto whatever root it selects.
 *
 * The kernel lock is a cross-process rendezvous keyed on uid: every cooperating
 * same-uid process MUST resolve the SAME root, or two processes hold "exclusive"
 * locks in different directories (a silent custody-safety break). These tests
 * pin that the resolver is a PURE function of (uid, env, platform) with a fixed
 * precedence, that its length guard fails closed, and that the owner/mode
 * hardening is applied on a non-/tmp branch just as on /tmp.
 *
 * Pure-function + temp-dir only; no sockets, no keychain, no operator state.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { chmod, mkdir, mkdtemp, rm, symlink } from "node:fs/promises";
import { join } from "node:path";

import {
  resolveCustodyLockRoot,
  ensureKernelSocketRuntimeDirectory,
  CrossProcessLockError,
  type CustodyLockRootContext,
} from "../../src/storage/cross-process-lock.js";

const LEAF = "sanctuary-custody-locks";
// Must match KERNEL_SOCKET_PATH_MAX_BYTES + the ".reaper" worst-case leaf in
// cross-process-lock.ts. Kept here so a divergence in the cap breaks a test.
const SOCKET_PATH_CAP = 100;
const WORST_ENTRY_BYTES = 40 + ".reaper".length; // 47

/** Longest composed entry path under a root: `${root}/${40-hex}.reaper`. */
function worstEntryBytes(root: string): number {
  return Buffer.byteLength(root) + 1 + WORST_ENTRY_BYTES;
}

// A realistic macOS DARWIN_USER_TEMP_DIR (`/var/folders/<2>/<30>/T`, 48 bytes).
// The descriptive leaf pushes the composed socket path past sun_path, so the
// resolver must deterministically use the hardened /tmp fallback here.
const DARWIN_TMPDIR = "/var/folders/tf/2m3v8md13vv8zm3hpxbfr6nw0000gn/T";

describe("resolveCustodyLockRoot", () => {
  describe("precedence table over injected {uid, env, platform}", () => {
    // Divergence: if step 1 stopped winning, this would resolve to the XDG path.
    it("1. explicit override wins over every other signal", () => {
      const root = resolveCustodyLockRoot(501, {
        env: {
          SANCTUARY_CUSTODY_LOCK_ROOT: "/run/sanctuary/locks",
          XDG_RUNTIME_DIR: "/run/user/501",
          TMPDIR: "/var/x",
        },
        platform: "linux",
      });
      expect(root).toBe("/run/sanctuary/locks");
    });

    // Divergence: if the XDG branch were dropped, this falls through to /tmp.
    it("2. Linux uses $XDG_RUNTIME_DIR when set/usable", () => {
      const root = resolveCustodyLockRoot(501, {
        env: { XDG_RUNTIME_DIR: "/run/user/501" },
        platform: "linux",
      });
      expect(root).toBe(`/run/user/501/${LEAF}`);
    });

    // Divergence: if step 3 read a hardcoded /tmp instead of os.tmpdir(env),
    // this would not carry the injected TMPDIR base.
    it("3. macOS uses os.tmpdir() (DARWIN_USER_TEMP_DIR) when it fits", () => {
      const root = resolveCustodyLockRoot(501, {
        env: { TMPDIR: "/run/x" },
        platform: "darwin",
      });
      expect(root).toBe(`/run/x/${LEAF}-501`);
    });

    // Divergence: if the fallback leaf changed, or step 4 were removed, the
    // no-signal case would not land on the hardened /tmp path.
    it("4. falls back to hardened /tmp/<leaf>-<uid> with no other signal", () => {
      const root = resolveCustodyLockRoot(501, { env: {}, platform: "linux" });
      expect(root).toBe(`/tmp/${LEAF}-501`);
    });

    it("ignores $XDG_RUNTIME_DIR on macOS (Linux-only signal)", () => {
      const root = resolveCustodyLockRoot(501, {
        env: { XDG_RUNTIME_DIR: "/run/user/501", TMPDIR: DARWIN_TMPDIR },
        platform: "darwin",
      });
      // XDG ignored; DARWIN base overflows -> deterministic /tmp fallback.
      expect(root).toBe(`/tmp/${LEAF}-501`);
    });

    // "Usable" is a PURE predicate (set, non-empty, ABSOLUTE) -- never a stat.
    // Divergence: a resolver that stat-probed XDG could accept/reject this
    // per-process; a relative value must deterministically be treated as unusable.
    it("treats a relative/garbage XDG_RUNTIME_DIR as unusable (no probing)", () => {
      const root = resolveCustodyLockRoot(501, {
        env: { XDG_RUNTIME_DIR: "relative/not-absolute" },
        platform: "linux",
      });
      expect(root).toBe(`/tmp/${LEAF}-501`);
    });

    it("treats an empty/whitespace override as absent", () => {
      const root = resolveCustodyLockRoot(501, {
        env: { SANCTUARY_CUSTODY_LOCK_ROOT: "   ", XDG_RUNTIME_DIR: "/run/user/501" },
        platform: "linux",
      });
      expect(root).toBe(`/run/user/501/${LEAF}`);
    });
  });

  describe("determinism / rendezvous contract", () => {
    it("returns the same path across repeated calls (no time/randomness)", () => {
      const ctx: CustodyLockRootContext = {
        env: { XDG_RUNTIME_DIR: "/run/user/501" },
        platform: "linux",
      };
      const a = resolveCustodyLockRoot(501, ctx);
      const b = resolveCustodyLockRoot(501, ctx);
      const c = resolveCustodyLockRoot(501, ctx);
      expect(a).toBe(b);
      expect(b).toBe(c);
    });

    it("two processes with identical env agree on the root", () => {
      const env = { XDG_RUNTIME_DIR: "/run/user/501" };
      const proc1 = resolveCustodyLockRoot(501, { env: { ...env }, platform: "linux" });
      const proc2 = resolveCustodyLockRoot(501, { env: { ...env }, platform: "linux" });
      expect(proc1).toBe(proc2);
    });

    // Documents the rendezvous contract: with uid and platform fixed, the ONLY
    // input that changes the path is the environment (here XDG set vs unset).
    // Divergence: any hidden per-process input (pid, time, probe) would make
    // these two equal when they must differ, or unequal when they must match.
    it("only an env difference (XDG set vs unset) changes the Linux path", () => {
      const withXdg = resolveCustodyLockRoot(501, {
        env: { XDG_RUNTIME_DIR: "/run/user/501" },
        platform: "linux",
      });
      const withoutXdg = resolveCustodyLockRoot(501, { env: {}, platform: "linux" });
      expect(withXdg).toBe(`/run/user/501/${LEAF}`);
      expect(withoutXdg).toBe(`/tmp/${LEAF}-501`);
      expect(withXdg).not.toBe(withoutXdg);
    });
  });

  describe("socket-path length cap (sun_path budget)", () => {
    it("keeps the longest realistic runtime-dir root under the cap", () => {
      // Longest realistic non-fallback root: a large-uid XDG path.
      const root = resolveCustodyLockRoot(4294967295, {
        env: { XDG_RUNTIME_DIR: "/run/user/4294967295" },
        platform: "linux",
      });
      expect(root).toBe(`/run/user/4294967295/${LEAF}`);
      expect(worstEntryBytes(root)).toBeLessThanOrEqual(SOCKET_PATH_CAP);
    });

    // Divergence: an override that overflows must FAIL CLOSED, never silently
    // downgrade to a shorter root (which would break rendezvous with a peer
    // that honored the override). If the guard were removed this would return a
    // string instead of throwing.
    it("an overflowing explicit override is a HARD ERROR (fail closed)", () => {
      const tooLong = "/" + "x".repeat(60);
      expect(worstEntryBytes(tooLong)).toBeGreaterThan(SOCKET_PATH_CAP);
      expect(() =>
        resolveCustodyLockRoot(501, {
          env: { SANCTUARY_CUSTODY_LOCK_ROOT: tooLong },
          platform: "linux",
        }),
      ).toThrow(CrossProcessLockError);
    });

    // Divergence: proves step 3 does NOT silently truncate or emit an
    // over-length macOS path; it deterministically uses the fallback instead.
    it("a macOS os.tmpdir root that overflows falls to the fallback deterministically", () => {
      const root = resolveCustodyLockRoot(501, {
        env: { TMPDIR: DARWIN_TMPDIR },
        platform: "darwin",
      });
      const overflowing = join(DARWIN_TMPDIR, `${LEAF}-501`);
      expect(worstEntryBytes(overflowing)).toBeGreaterThan(SOCKET_PATH_CAP);
      expect(root).toBe(`/tmp/${LEAF}-501`);
      expect(worstEntryBytes(root)).toBeLessThanOrEqual(SOCKET_PATH_CAP);
    });

    // Pins the cap boundary exactly (worstEntry = len(root)+1+47 <= 100, i.e.
    // root <= 52 bytes). Divergence: an off-by-one in custodyLockRootFits would
    // flip one of these two assertions.
    it("enforces the cap boundary to the byte (52 fits, 53 fails closed)", () => {
      const root52 = "/" + "a".repeat(51); // 52 bytes -> worstEntry 100
      expect(Buffer.byteLength(root52)).toBe(52);
      expect(worstEntryBytes(root52)).toBe(SOCKET_PATH_CAP);
      expect(
        resolveCustodyLockRoot(501, {
          env: { SANCTUARY_CUSTODY_LOCK_ROOT: root52 },
          platform: "linux",
        }),
      ).toBe(root52);

      const root53 = "/" + "a".repeat(52); // 53 bytes -> worstEntry 101
      expect(worstEntryBytes(root53)).toBe(SOCKET_PATH_CAP + 1);
      expect(() =>
        resolveCustodyLockRoot(501, {
          env: { SANCTUARY_CUSTODY_LOCK_ROOT: root53 },
          platform: "linux",
        }),
      ).toThrow(CrossProcessLockError);
    });
  });
});

describe("ensureKernelSocketRuntimeDirectory hardening (carried onto every branch)", () => {
  // The ensure path applies ONE owner/mode hardening block to whatever the
  // resolver returns, so proving it on a non-/tmp branch (driven here via the
  // override and XDG branches to controllable temp dirs) proves it is carried
  // regardless of which precedence branch selected the root. Owner mismatch
  // needs root to construct, so we exercise the mode/symlink guards (which share
  // the same block) without root.
  const hasUid = typeof process.getuid === "function";
  let base: string;

  beforeEach(async () => {
    // A SHORT base (directly under /tmp, not os.tmpdir()'s long macOS
    // /var/folders path) so the composed root stays under the socket-path cap
    // and the test exercises the owner/mode hardening, not the length guard.
    base = await mkdtemp("/tmp/cl-");
  });
  afterEach(async () => {
    await rm(base, { recursive: true, force: true });
  });

  it.runIf(hasUid)("accepts a pre-created 0700 uid-owned root (override branch)", async () => {
    const root = join(base, "locks");
    await mkdir(root, { mode: 0o700 });
    const resolved = await ensureKernelSocketRuntimeDirectory({
      env: { SANCTUARY_CUSTODY_LOCK_ROOT: root },
      platform: "linux",
    });
    expect(resolved).toBe(root);
  });

  // Divergence: if the mode check were dropped, a group/other-accessible root
  // would be accepted. This must be refused on the XDG (non-/tmp) branch too.
  it.runIf(hasUid)("refuses a pre-created wrong-mode root on the XDG branch", async () => {
    // XDG branch composes <xdg>/sanctuary-custody-locks; pre-create it 0777.
    const badDir = join(base, LEAF);
    await mkdir(badDir, { mode: 0o777 });
    await chmod(badDir, 0o777); // defeat umask so the mode is genuinely broad
    await expect(
      ensureKernelSocketRuntimeDirectory({
        env: { XDG_RUNTIME_DIR: base },
        platform: "linux",
      }),
    ).rejects.toThrow(/mode 0700/);
  });

  // Divergence: if the symlink check were dropped, a symlinked root would pass
  // and later O_NOFOLLOW opens would operate on an attacker-chosen target.
  it.runIf(hasUid)("refuses a symlinked root (override branch)", async () => {
    const realTarget = join(base, "real");
    await mkdir(realTarget, { mode: 0o700 });
    const linkPath = join(base, "link");
    await symlink(realTarget, linkPath);
    await expect(
      ensureKernelSocketRuntimeDirectory({
        env: { SANCTUARY_CUSTODY_LOCK_ROOT: linkPath },
        platform: "linux",
      }),
    ).rejects.toThrow(/non-symlink directory/);
  });
});
