/**
 * Unit tests for the custody kernel-lock ROOT resolver
 * ({@link resolveCustodyLockRoot}) and the ancestor + owner/mode hardening the
 * ensure path carries onto whatever root it selects.
 *
 * The kernel lock is a cross-process rendezvous keyed on uid: every cooperating
 * same-uid process MUST resolve the SAME root, or two processes hold "exclusive"
 * locks in different directories (a silent custody-safety break). These tests
 * pin that:
 *  - the resolver is a PURE function of (uid, platform, uniform env) with a fixed
 *    precedence, requiring an ABSOLUTE path on every branch (fail closed on a
 *    relative value, which would resolve per-process against cwd);
 *  - the Linux path is DERIVED from the uid and does NOT read `$XDG_RUNTIME_DIR`,
 *    so two same-uid processes with different env (one XDG-set, one XDG-unset)
 *    get the identical path, never two directories, and a Linux overflow fails
 *    closed rather than downgrading to a world-writable /tmp;
 *  - the ensure path verifies the full ancestor chain (no world-writable,
 *    non-sticky, or foreign-owned ancestor above the 0700 leaf), fails closed
 *    when a required runtime dir is absent, and carries the leaf owner/mode
 *    hardening on a non-/tmp branch just as on /tmp.
 *
 * Pure-function + temp-dir only; no sockets, no keychain, no operator state.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { chmod, mkdir, mkdtemp, rename, rm, symlink, unlink } from "node:fs/promises";
import { existsSync } from "node:fs";
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
    // Divergence: if step 1 stopped winning, this would resolve to the Linux
    // uid-derived path.
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

    // BUG 2: the Linux path is DERIVED from the uid, never read from
    // $XDG_RUNTIME_DIR. Divergence: a resolver that read XDG would return
    // whatever the (here bogus) XDG value composed, not the uid-derived path.
    it("2. Linux derives /run/user/<uid> from the uid (ignores $XDG_RUNTIME_DIR)", () => {
      const root = resolveCustodyLockRoot(501, {
        env: { XDG_RUNTIME_DIR: "/some/other/place" },
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
    // no-signal macOS case would not land on the hardened /tmp path.
    it("4. macOS falls back to hardened /tmp/<leaf>-<uid> with no other signal", () => {
      const root = resolveCustodyLockRoot(501, { env: {}, platform: "darwin" });
      expect(root).toBe(`/tmp/${LEAF}-501`);
    });

    it("ignores $XDG_RUNTIME_DIR on macOS (never a signal on any platform)", () => {
      const root = resolveCustodyLockRoot(501, {
        env: { XDG_RUNTIME_DIR: "/run/user/501", TMPDIR: DARWIN_TMPDIR },
        platform: "darwin",
      });
      // XDG ignored; DARWIN base overflows -> deterministic /tmp fallback.
      expect(root).toBe(`/tmp/${LEAF}-501`);
    });

    it("treats an empty/whitespace override as absent (falls to the Linux branch)", () => {
      const root = resolveCustodyLockRoot(501, {
        env: { SANCTUARY_CUSTODY_LOCK_ROOT: "   ", XDG_RUNTIME_DIR: "/run/user/501" },
        platform: "linux",
      });
      expect(root).toBe(`/run/user/501/${LEAF}`);
    });
  });

  describe("BUG 1: every branch REQUIRES an absolute path (fail closed on relative)", () => {
    // A relative value resolves against each process's cwd -- a hidden
    // per-process input that would split the rendezvous. Divergence: without the
    // absolute check each of these returns a cwd-relative string instead of
    // throwing.
    it("rejects a relative override (fail closed)", () => {
      expect(() =>
        resolveCustodyLockRoot(501, {
          env: { SANCTUARY_CUSTODY_LOCK_ROOT: "locks" },
          platform: "linux",
        }),
      ).toThrow(CrossProcessLockError);
      expect(() =>
        resolveCustodyLockRoot(501, {
          env: { SANCTUARY_CUSTODY_LOCK_ROOT: "relative/locks" },
          platform: "darwin",
        }),
      ).toThrow(/absolute/);
    });

    it("rejects a relative macOS $TMPDIR (fail closed)", () => {
      expect(() =>
        resolveCustodyLockRoot(501, {
          env: { TMPDIR: "relative/not-absolute" },
          platform: "darwin",
        }),
      ).toThrow(/absolute/);
    });

    // Linux never reads XDG, so a relative XDG cannot select a relative path; it
    // is simply ignored and the absolute uid-derived path is used.
    it("a relative $XDG_RUNTIME_DIR cannot poison the Linux path (ignored)", () => {
      const root = resolveCustodyLockRoot(501, {
        env: { XDG_RUNTIME_DIR: "relative/not-absolute" },
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

    // BUG 2, the deep one: a login-session process has $XDG_RUNTIME_DIR set while
    // a sudo/cron/systemd-system process of the SAME uid does not. Reading XDG
    // would split them onto two roots. The uid-derived path must be IDENTICAL for
    // both. Divergence: any read of XDG (or any other env split) makes these two
    // differ -- the exact custody-safety break this fix closes.
    it("two same-uid processes with DIFFERENT env (XDG set vs unset) agree on ONE root", () => {
      const loginSession = resolveCustodyLockRoot(1000, {
        env: { XDG_RUNTIME_DIR: "/run/user/1000", DBUS_SESSION_BUS_ADDRESS: "x" },
        platform: "linux",
      });
      const cronOrSudo = resolveCustodyLockRoot(1000, {
        env: {}, // no XDG_RUNTIME_DIR, as under sudo/cron/systemd-system
        platform: "linux",
      });
      expect(loginSession).toBe(`/run/user/1000/${LEAF}`);
      expect(cronOrSudo).toBe(`/run/user/1000/${LEAF}`);
      expect(loginSession).toBe(cronOrSudo); // ONE root, never two dirs
    });

    // The Linux root is ALWAYS under /run/user/<uid> and NEVER /tmp: a /tmp
    // downgrade would split from a peer whose runtime dir was present.
    it("the Linux root is never a /tmp path regardless of env", () => {
      for (const env of [
        {},
        { XDG_RUNTIME_DIR: "/run/user/501" },
        { XDG_RUNTIME_DIR: "" },
        { TMPDIR: "/tmp" },
      ]) {
        const root = resolveCustodyLockRoot(501, { env, platform: "linux" });
        expect(root).toBe(`/run/user/501/${LEAF}`);
        expect(root.startsWith("/tmp/")).toBe(false);
      }
    });
  });

  describe("socket-path length cap (sun_path budget)", () => {
    it("keeps the largest realistic Linux runtime-dir root under the cap", () => {
      // Largest realistic uid (2^32-1, 10 digits).
      const root = resolveCustodyLockRoot(4294967295, {
        env: {},
        platform: "linux",
      });
      expect(root).toBe(`/run/user/4294967295/${LEAF}`);
      expect(worstEntryBytes(root)).toBeLessThanOrEqual(SOCKET_PATH_CAP);
    });

    // Divergence: an override that overflows must FAIL CLOSED, never silently
    // downgrade to a shorter root (which would break rendezvous with a peer
    // that honored the override).
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

    // BUG 2: a Linux derived path that overflows fails CLOSED -- it does NOT
    // downgrade to /tmp (which would reintroduce the login-vs-sudo split). The
    // synthetic oversized uid exercises the guard; every real uid (<= 2^32-1)
    // fits. Divergence: a /tmp fallback here returns a string instead of throwing.
    it("a Linux uid whose derived runtime path overflows fails CLOSED (never /tmp)", () => {
      const bigUid = 1e19; // 20-digit string form; synthetic, larger than any real uid
      const derived = `/run/user/${bigUid}/${LEAF}`;
      expect(worstEntryBytes(derived)).toBeGreaterThan(SOCKET_PATH_CAP);
      expect(() =>
        resolveCustodyLockRoot(bigUid, { env: {}, platform: "linux" }),
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
  // The ensure path applies ONE ancestor-chain check plus a leaf owner/mode
  // hardening block to whatever the resolver returns, so proving them on a
  // non-/tmp branch (driven here via the absolute override branch to controllable
  // temp dirs) proves they are carried regardless of which precedence branch
  // selected the root. Owner mismatch needs root to construct, so we exercise the
  // mode/symlink/ancestor guards (which share the same code) without root.
  const hasUid = typeof process.getuid === "function";
  const uid = hasUid ? process.getuid!() : -1;
  let base: string;

  beforeEach(async () => {
    // A SHORT base (directly under /tmp, not os.tmpdir()'s long macOS
    // /var/folders path) so the composed root stays under the socket-path cap
    // and the test exercises the hardening, not the length guard.
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

  // Divergence: if the leaf mode check were dropped, a group/other-accessible
  // root would be accepted. Must be refused on a non-/tmp (override) branch too.
  it.runIf(hasUid)("refuses a pre-created wrong-mode leaf (override branch)", async () => {
    const badDir = join(base, "locks");
    await mkdir(badDir, { mode: 0o777 });
    await chmod(badDir, 0o777); // defeat umask so the mode is genuinely broad
    await expect(
      ensureKernelSocketRuntimeDirectory({
        env: { SANCTUARY_CUSTODY_LOCK_ROOT: badDir },
        platform: "linux",
      }),
    ).rejects.toThrow(/mode 0700/);
  });

  // Divergence: if the leaf symlink check were dropped, a symlinked root would
  // pass and later O_NOFOLLOW opens would operate on an attacker-chosen target.
  it.runIf(hasUid)("refuses a symlinked leaf (override branch)", async () => {
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

  // BUG 3: a world-writable, non-sticky ANCESTOR above the 0700 leaf is a
  // parent-swap surface (recursive mkdir would create/trust it). It must be
  // refused before the leaf is created. Divergence: without the ancestor walk the
  // leaf is created under the world-writable dir and ensure returns it.
  it.runIf(hasUid)("refuses a world-writable non-sticky ancestor (parent-swap surface)", async () => {
    const wwParent = join(base, "wwparent");
    await mkdir(wwParent);
    await chmod(wwParent, 0o777); // world-writable, NO sticky bit
    const root = join(wwParent, "locks");
    await expect(
      ensureKernelSocketRuntimeDirectory({
        env: { SANCTUARY_CUSTODY_LOCK_ROOT: root },
        platform: "linux",
      }),
    ).rejects.toThrow(/world-writable|sticky|ancestor/);
    // And it must NOT have created the leaf under the unsafe parent.
    expect(existsSync(root)).toBe(false);
  });

  // NEW (group-writable ancestor): a group-writable, non-sticky ANCESTOR lets any
  // member of its group host a component swap. It must be refused just like a
  // world-writable non-sticky one, unless the group is root/this-uid's-own and the
  // sticky bit prevents non-owner renames. Divergence: without the group-writable
  // clause the leaf is created under the group-writable dir and ensure returns it.
  it.runIf(hasUid)("refuses a group-writable non-sticky ancestor (parent-swap surface)", async () => {
    const gwParent = join(base, "gwparent");
    await mkdir(gwParent);
    await chmod(gwParent, 0o770); // group-writable, NO sticky bit
    const root = join(gwParent, "locks");
    await expect(
      ensureKernelSocketRuntimeDirectory({
        env: { SANCTUARY_CUSTODY_LOCK_ROOT: root },
        platform: "linux",
      }),
    ).rejects.toThrow(/group-writable|sticky|ancestor/);
    // And it must NOT have created the leaf under the unsafe parent.
    expect(existsSync(root)).toBe(false);
  });

  // BUG 3 (TOCTOU): a symlink COMPONENT of the resolver's parent path, safe at
  // ancestry-verify time and repointed at attacker space before the mkdir, must
  // not redirect where the leaf is created. The fix resolves the parent to its
  // realpath (symlink-free) BEFORE the check and binds creation to that verified
  // parent (fd-relative on Linux, canonical path + inode recheck on Darwin), so the
  // swap is neutralized. Divergence: creating at the original (symlinked) resolver
  // string instead would create the leaf in attacker space here.
  it.runIf(hasUid)(
    "neutralizes a symlink swap between verify and create (leaf lands under the verified inode, never attacker space)",
    async () => {
      const safe = join(base, "safe");
      const attacker = join(base, "attacker");
      await mkdir(safe, { mode: 0o700 });
      await mkdir(attacker, { mode: 0o700 });
      const link = join(base, "link");
      await symlink(safe, link); // parent of the leaf is a symlink -> safe
      const override = join(link, "locks");

      const resolved = await ensureKernelSocketRuntimeDirectory(
        { env: { SANCTUARY_CUSTODY_LOCK_ROOT: override }, platform: "linux" },
        {
          __testAfterAncestryVerified: async () => {
            // Swap the symlink to attacker space AFTER the ancestry check + fd pin.
            await unlink(link);
            await symlink(attacker, link);
          },
        },
      );
      expect(resolved).toBe(override);
      // The leaf was created under the VERIFIED (canonical == safe) inode, never
      // under attacker space. With the binding removed (mkdir on the original
      // symlinked string), the swap would have created attacker/locks instead.
      expect(existsSync(join(safe, "locks"))).toBe(true);
      expect(existsSync(join(attacker, "locks"))).toBe(false);
    },
  );

  // BUG 3 (inode binding): the verified parent directory ENTRY is replaced with a
  // DIFFERENT inode after the check. The pinned parent descriptor + inode recheck
  // must ensure the leaf is never created inside the swapped-in (attacker) inode:
  // Linux creates it fd-relative to the pinned original inode; Darwin detects the
  // rebind and fails closed. Both keep attacker space clean. Divergence: without
  // the binding the mkdir on the original string lands in the attacker inode.
  it.runIf(hasUid)(
    "never creates the leaf inside a swapped-in parent inode (fd/inode binding)",
    async () => {
      const target = join(base, "target");
      const attacker = join(base, "attacker");
      await mkdir(target, { mode: 0o700 });
      await mkdir(attacker, { mode: 0o700 });
      const override = join(target, "locks");
      // Darwin fails closed (throws); Linux binds the create to the pinned inode
      // (succeeds, leaf under the original directory). Both are safe, so tolerate
      // either outcome and assert the security invariant below.
      await ensureKernelSocketRuntimeDirectory(
        { env: { SANCTUARY_CUSTODY_LOCK_ROOT: override }, platform: "linux" },
        {
          __testAfterAncestryVerified: async () => {
            await rename(target, join(base, "target.bak"));
            await rename(attacker, target); // `target` now resolves to the attacker inode
          },
        },
      ).catch(() => {});
      // The leaf must never appear inside the swapped-in attacker inode (now `target`).
      expect(existsSync(join(base, "target", "locks"))).toBe(false);
    },
  );

  // BUG 2: on Linux with no override and no per-user runtime dir present, ensure
  // fails CLOSED -- it does NOT create /run/user/<uid> and does NOT downgrade to
  // /tmp. Guarded to only run where /run/user/<uid> genuinely does not exist
  // (true on the macOS/CI-mac runner) so the test never touches real /run state.
  const linuxRuntimeAbsent = hasUid && !existsSync(`/run/user/${uid}`);
  it.runIf(linuxRuntimeAbsent)(
    "Linux with no runtime dir + no override fails CLOSED (no /tmp fallback)",
    async () => {
      await expect(
        ensureKernelSocketRuntimeDirectory({ env: {}, platform: "linux" }),
      ).rejects.toThrow(/absent|fail closed/);
      // Fail-closed means it never created the derived path nor a /tmp fallback.
      expect(existsSync(`/run/user/${uid}/${LEAF}`)).toBe(false);
    },
  );
});
