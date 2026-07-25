import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";

/**
 * Safety-rail battery for the autonomous drill-loop harness
 * (`scripts/drill-loop/`).
 *
 * WHY THIS FILE EXISTS AND WHAT SHAPE IT HAS
 *
 * The first version of that harness shipped CI-green and was reviewed UNSOUND:
 * a REJECTED `--storage` path armed the operator's real `~/.sanctuary` fortress
 * as root. The old tests only ever exercised HOST-REJECT-FIRST, so every case
 * died at the first rail and NO case ever reached the path rail. Coverage of
 * the happy prefix of a gauntlet tells you nothing about the rest of it.
 *
 * The SECOND version fixed that and was reviewed UNSOUND again, by three
 * independent lenses, two of which wrote working exploits:
 *
 *   - `clean-markers` deleted a file inside a (fake) real fortress as root,
 *     through an unchecked INTERMEDIATE symlink, with every rail passing;
 *   - the accepted storage directory could be swapped for a symlink to a real
 *     fortress AFTER validation and BEFORE use, winning in 44 attempts;
 *   - a planted `hostname` on PATH made the artifact print WRAPPER=ACCEPT on
 *     the operator's MacBook Air.
 *
 * And the reason the suite stayed green through all of it was structural
 * again, one level up: it exercised every RAIL and only the one VERB that
 * touches nothing, and the function deciding which home the path rail anchored
 * to was stubbed out in both batteries.
 *
 * So the coverage rules this file now holds are:
 *
 *   1. The host rail is deliberately STUBBED TO PASS for wrapper-level cases,
 *      so execution reaches the path rail. Its own deny-first behavior is
 *      proven separately at rail level, where it runs on any machine.
 *   2. Every rejection asserts BOTH halves: a nonzero exit AND no ACCEPT token.
 *   3. Rejections assert the REASON. A deny for the wrong reason is a fail.
 *   4. The happy path is asserted too. A rail that rejects everything is not
 *      sound, it is broken.
 *   5. EVERY VERB gets a case, not just the oracle, and the two verbs that
 *      were exploited get the exploits themselves as fixtures.
 *   6. The layers the PR body calls load-bearing are asserted STRUCTURALLY on
 *      the shipped artifact, so deleting one goes red instead of silently
 *      leaving the suite green.
 *   7. What is overridden in a battery is CONSTANTS, never functions, and the
 *      shipped values of those constants are themselves asserted.
 *
 * Nothing here touches a real fortress. Every fortress in every case is a fake
 * one inside a temp directory.
 */

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const DRILL_LOOP = path.join(REPO_ROOT, "scripts", "drill-loop");
const PROBE = path.join(DRILL_LOOP, "lib", "probe.sh");
const RAILS = path.join(DRILL_LOOP, "lib", "rails.sh");
const DRIVERS = path.join(DRILL_LOOP, "drivers");
const BUILD_WRAPPER = path.join(DRILL_LOOP, "build-wrapper.sh");
const SELFTEST = path.join(DRILL_LOOP, "selftest.sh");
const SHA_FILE = path.join(DRILL_LOOP, "wrapper.sha256");

/** The value the SHIPPED artifact must carry. Asserted, never overridden. */
const SHIPPED_BASE = "/private/var/sanctuary-drill";
const SHIPPED_PATH_LINE = "PATH=/usr/bin:/bin:/usr/sbin:/sbin";

interface Ran {
  status: number;
  out: string;
}

/** Run a probe (or any command) and capture status plus merged output. */
function run(cmd: string, args: string[], env?: NodeJS.ProcessEnv): Ran {
  const r = spawnSync(cmd, args, {
    encoding: "utf8",
    ...(env ? { env: { ...process.env, ...env } } : {}),
  });
  return {
    status: r.status ?? -1,
    out: `${r.stdout ?? ""}${r.stderr ?? ""}`,
  };
}

function probe(...args: string[]): Ran {
  return run("bash", [PROBE, ...args]);
}

/**
 * A rejection must be nonzero, must not print an ACCEPT token, and must give
 * the expected reason. All three, every time.
 */
function expectReject(r: Ran, reason: string | RegExp): void {
  expect(r.status, `expected a nonzero exit; output was:\n${r.out}`).not.toBe(0);
  expect(r.out, "a rejected input must never print an ACCEPT token").not.toContain(
    "ACCEPT"
  );
  if (typeof reason === "string") {
    expect(r.out).toContain(reason);
  } else {
    expect(r.out).toMatch(reason);
  }
}

function expectAccept(r: Ran, contains: string): void {
  expect(r.status, `expected exit 0; output was:\n${r.out}`).toBe(0);
  expect(r.out).toContain(contains);
}

let sandbox: string;
/**
 * The root-owned base's stand-in, and the per-operator ANCHOR under it. The
 * storage rail anchors to the ANCHOR now, not to a home directory: see the
 * BLOCKER 1 block in lib/rails.sh for why that difference is the fix.
 */
let base: string;
let anchor: string;
let me: string;
let myUid: number;
/**
 * This machine's REAL hardware fingerprint, read through the real rail. The
 * wrapper battery substitutes the allowlist, not the lookup, so the ioreg
 * read, the UUID shape validation and the hashing all genuinely run.
 *
 * Empty on a machine with no IOPlatformExpertDevice (i.e. Linux CI), where the
 * wrapper-level cases are skipped and the rail-level cases carry the coverage.
 */
let localFingerprint = "";
let hasHardwareIdentity = false;

/**
 * HOW THE WRAPPER-LEVEL CASES BEHAVE ON A MACHINE WITH NO HARDWARE IDENTITY,
 * AND WHY THEY NO LONGER RETURN SILENTLY.
 *
 * ROUND-3 H4. The commit that turned CI green made all 20 wrapper-level cases
 * -- every verb, both round-2 exploit fixtures, the TOCTOU fixture -- `return`
 * early on any hardware-less machine. A vitest `it()` that returns early
 * PASSES. There was no `it.skip`, no `ctx.skip()` and no annotation, and the
 * case count was 151 either way, so `.test-baseline` could not notice. Linux CI
 * is the authoritative gate under the coordinator's baseline-floor rule, so on
 * the gate that actually decides, all 20 cases were green having asserted
 * nothing. That is structurally the same miss as round 2's stubbed
 * `wrapper_home_of`, one layer up, introduced deliberately.
 *
 * `ctx.skip()` would make it visible, and would also drop the passing count on
 * Linux below the baseline floor, which is a strict-upward ratchet. So instead:
 *
 *   1. NO CASE IS SILENT. On a hardware-less machine every wrapper case still
 *      RUNS the real artifact and asserts a real property -- that it refuses,
 *      prints the machine-readable REJECT token, never prints ACCEPT, and (for
 *      the exploit fixtures) that the victim fortress survives. That is not a
 *      consolation assertion: "the wrapper fails closed with no hardware
 *      identity" is exactly the property the host rail exists to have.
 *   2. THE CASES ARE COUNTED. Every case increments a counter, and a final case
 *      asserts the exact expected number executed, and that on a machine WITH a
 *      hardware identity the same number took the FULL path. A case that
 *      vanishes changes a number, and a forced hardware-less branch on the
 *      drill platform goes red.
 *
 * `wrapperFullPath()` is what a case calls to learn which half it is in; the
 * counting is a side effect of asking, so a case cannot be counted without
 * asking and cannot ask without being counted.
 */
const WRAPPER_LEVEL_CASES = 28;
let wrapperCasesExecuted = 0;
let wrapperCasesFullPath = 0;

function wrapperFullPath(): boolean {
  wrapperCasesExecuted += 1;
  const full = myUid !== 0 && hasHardwareIdentity;
  if (full) wrapperCasesFullPath += 1;
  return full;
}

/**
 * The assertion a wrapper case makes when this machine cannot get past the host
 * rail: the artifact ran, it refused, and it said so in the machine-readable
 * shape every other refusal uses.
 */
function expectHostRailRefusal(r: Ran): void {
  expect(r.status, `expected a nonzero exit; output was:\n${r.out}`).not.toBe(0);
  expect(r.out, "a hardware-less machine must never see an ACCEPT token").not.toContain(
    "WRAPPER=ACCEPT"
  );
  expect(r.out, "every refusal prints the same machine-readable token").toContain("WRAPPER=REJECT");
}

beforeAll(() => {
  me = os.userInfo().username;
  myUid = typeof process.getuid === "function" ? process.getuid() : 1000;
  const r = run("bash", [
    "-c",
    `. "${RAILS}"; rails_host_fingerprint_local`,
  ]);
  if (r.status === 0) {
    localFingerprint = r.out.trim();
    hasHardwareIdentity = /^[0-9a-f]{64}$/.test(localFingerprint);
  }
});

beforeEach(() => {
  // Canonicalized: on a Mac `os.tmpdir()` sits under /var/folders and /var is a
  // symlink into /private, so an uncanonicalized fixture path is not equal to
  // its own resolution. The rails deliberately require canonical input, since a
  // rail that accepted "something that resolves to the right place" would be
  // accepting the exact shape the symlink exploits used.
  sandbox = fs.realpathSync(
    fs.mkdtempSync(path.join(os.tmpdir(), "sanctuary-drill-rails-"))
  );
  base = path.join(sandbox, "base");
  anchor = path.join(base, me);
  fs.mkdirSync(anchor, { recursive: true });
  // A stand-in for a real default fortress. The denylist and the symlink cases
  // both aim at THIS, never at a real one.
  fs.mkdirSync(path.join(anchor, ".sanctuary"));
  fs.mkdirSync(path.join(anchor, ".sanctuary-loop-good"));
  fs.mkdirSync(path.join(sandbox, "outside", ".sanctuary-loop-outside"), {
    recursive: true,
  });
});

afterEach(() => {
  fs.rmSync(sandbox, { recursive: true, force: true });
});

describe("drill-loop rails: disposable-storage rail (the BLOCKER and the HIGH)", () => {
  it("rejects an EMPTY storage path, the most dangerous value in the system", () => {
    // An empty SANCTUARY_STORAGE_PATH is not "unset": resolveStoragePath in
    // server/src/paths.ts falls back to <home>/.sanctuary, the REAL fortress.
    expectReject(probe("storage", anchor, ""), "empty storage path");
  });

  it("rejects a MISSING storage argument at the rail's own arity check", () => {
    expectReject(probe("storage", anchor), "expected 2 args");
  });

  it("rejects the default fortress by denylist", () => {
    expectReject(
      probe("storage", anchor, path.join(anchor, ".sanctuary")),
      /protected fortress|default fortress directory/
    );
  });

  it("rejects a .sanctuary-loop-* SYMLINK pointing at the fortress", () => {
    const evil = path.join(anchor, ".sanctuary-loop-evil");
    fs.symlinkSync(path.join(anchor, ".sanctuary"), evil);
    expectReject(probe("storage", anchor, evil), "final component is a symlink");
  });

  it("rejects a symlink even when its target is harmless", () => {
    const benign = path.join(sandbox, "benign");
    fs.mkdirSync(benign);
    const link = path.join(anchor, ".sanctuary-loop-benign");
    fs.symlinkSync(benign, link);
    expectReject(probe("storage", anchor, link), "final component is a symlink");
  });

  it("rejects traversal back to the fortress", () => {
    expectReject(
      probe("storage", anchor, `${anchor}/.sanctuary-loop-x/../.sanctuary`),
      "relative component"
    );
  });

  it("rejects traversal with a trailing slash", () => {
    expectReject(
      probe("storage", anchor, `${anchor}/.sanctuary-loop-x/../`),
      "relative component"
    );
  });

  it("rejects a single-dot component", () => {
    expectReject(
      probe("storage", anchor, `${anchor}/./.sanctuary-loop-dot`),
      "relative component"
    );
  });

  it("rejects a path OUTSIDE the anchor that has a valid-looking basename", () => {
    expectReject(
      probe("storage", anchor, path.join(sandbox, "outside", ".sanctuary-loop-outside")),
      "is not the approved anchor"
    );
  });

  it("rejects a path whose PARENT is a symlink into the anchor", () => {
    const elsewhere = path.join(sandbox, "elsewhere");
    fs.mkdirSync(elsewhere);
    const parentLink = path.join(sandbox, "anchor-alias");
    fs.symlinkSync(elsewhere, parentLink);
    expectReject(
      probe("storage", anchor, path.join(parentLink, ".sanctuary-loop-x")),
      "is not the approved anchor"
    );
  });

  it("rejects a relative path", () => {
    expectReject(probe("storage", anchor, ".sanctuary-loop-rel"), "not an absolute path");
  });

  it("rejects a basename without the disposable prefix", () => {
    expectReject(
      probe("storage", anchor, path.join(anchor, "scratch")),
      "not a disposable loop fortress"
    );
  });

  it("rejects the bare prefix with no stamp", () => {
    expectReject(
      probe("storage", anchor, path.join(anchor, ".sanctuary-loop-")),
      "not a disposable loop fortress"
    );
  });

  it("rejects a basename with shell metacharacters", () => {
    expectReject(
      probe("storage", anchor, path.join(anchor, ".sanctuary-loop-a;rm -rf /")),
      "disallowed characters"
    );
  });

  it("rejects a path containing a newline", () => {
    expectReject(probe("storage", anchor, `${anchor}/.sanctuary-loop-a\nb`), "newline");
  });

  it("rejects an existing target that is a regular file", () => {
    const asFile = path.join(anchor, ".sanctuary-loop-file");
    fs.writeFileSync(asFile, "x");
    expectReject(probe("storage", anchor, asFile), "not a directory");
  });

  // The happy path. A rail that rejects everything is broken, not strict.
  it("ACCEPTS a genuine disposable fortress and prints its resolved path", () => {
    const good = path.join(anchor, ".sanctuary-loop-good");
    const r = probe("storage", anchor, good);
    expectAccept(r, "PROBE=ACCEPT");
    expect(r.out).toContain(fs.realpathSync(good));
  });

  it("ACCEPTS a valid path that does not exist yet", () => {
    expectAccept(probe("storage", anchor, path.join(anchor, ".sanctuary-loop-fresh")), "PROBE=ACCEPT");
  });

  it("ACCEPTS and canonicalizes duplicate and trailing slashes", () => {
    const r = probe("storage", anchor, `${anchor}//.sanctuary-loop-good/`);
    expectAccept(r, "PROBE=ACCEPT");
    expect(r.out).toContain(fs.realpathSync(path.join(anchor, ".sanctuary-loop-good")));
    expect(r.out).not.toContain("//.sanctuary");
  });
});

/**
 * BLOCKER 1, round 2. The caller no longer supplies a path at all, so there is
 * nothing to race, swap, or symlink. These cases prove the input that replaced
 * it cannot be turned back into one.
 */
describe("drill-loop rails: the run id is not a path", () => {
  it("ACCEPTS a plain stamp-shaped run id", () => {
    expectAccept(probe("run-id", "20260725t0230-1"), "PROBE=ACCEPT");
  });

  it("REJECTS an uppercase run id, because APFS is case-insensitive", () => {
    // ROUND-3 MED, found independently by both lenses and reproduced by Codex.
    // The drill hosts are Macs, whose default APFS volume is case-insensitive,
    // so `A` and `a` were two accepted, DISTINCT run ids deriving to two
    // distinct path strings naming ONE directory entry: two runs sharing a
    // disposable fortress and an evidence identity while every rail said they
    // were separate.
    expectReject(probe("run-id", "20260725T0230-1"), "disallowed characters");
    expectReject(probe("run-id", "A"), "disallowed characters");
    expectAccept(probe("run-id", "a"), "PROBE=ACCEPT");
  });

  it("REJECTS rather than silently folding case", () => {
    // Not normalized down: the evidence has to show the exact id the caller
    // supplied, and a rail that quietly rewrites its input is a rail whose
    // output nobody can reason about.
    const r = probe("run-id", "Ab");
    expectReject(r, "disallowed characters");
    expect(r.out, "the rail must not have folded the value to lowercase").not.toContain(
      "run-id=ab"
    );
  });

  it("rejects an empty run id", () => {
    expectReject(probe("run-id", ""), "empty run id");
  });

  it("rejects a run id containing a slash", () => {
    expectReject(probe("run-id", "a/b"), "disallowed characters");
  });

  it("rejects a traversal-shaped run id", () => {
    expectReject(probe("run-id", "../../.sanctuary"), "disallowed characters");
  });

  it("rejects a run id that starts with a dot, which could read as . or ..", () => {
    expectReject(probe("run-id", ".."), "must start with a lowercase letter or a digit");
  });

  it("rejects an option-shaped run id", () => {
    expectReject(probe("run-id", "-rf"), "must start with a lowercase letter or a digit");
  });

  it("rejects an over-long run id", () => {
    expectReject(probe("run-id", "a".repeat(80)), "longer than 64 characters");
  });

  it("rejects a run id with shell metacharacters", () => {
    expectReject(probe("run-id", "a;rm -rf /"), "disallowed characters");
  });

  it("DERIVES the storage path from base, operator and run id", () => {
    const r = probe("derive", base, me, "x1");
    expectAccept(r, "PROBE=ACCEPT");
    expect(r.out).toContain(path.join(base, me, ".sanctuary-loop-x1"));
  });

  it("refuses to derive from a relative base", () => {
    expectReject(probe("derive", "relative/base", me, "x1"), "not an absolute path");
  });

  it("refuses to derive from a base containing a traversal", () => {
    expectReject(probe("derive", "/var/../etc", me, "x1"), "relative component");
  });

  it("refuses to derive for an operator name that is not an account name", () => {
    expectReject(
      probe("derive", base, "Root Account", "x1"),
      "must start with a lowercase letter"
    );
    expectReject(probe("derive", base, "a/b", "x1"), "disallowed characters");
  });
});

/**
 * The root-owned base is what actually kills the TOCTOU class: an unprivileged
 * caller cannot create, rename or replace any component of the path the root
 * wrapper walks. The per-component predicate is PURE, so the security logic is
 * driven exhaustively here without root and without a fixture filesystem, the
 * same way the uid-0-alias refusal is.
 */
describe("drill-loop rails: the trusted (root-owned) directory chain", () => {
  it("accepts a component owned by root", () => {
    expectAccept(probe("trusted-component", "/some/dir", "0", "755", "501"), "PROBE=ACCEPT");
  });

  it("accepts a component owned by the very process doing the walking", () => {
    expectAccept(probe("trusted-component", "/some/dir", "501", "700", "501"), "PROBE=ACCEPT");
  });

  it("rejects a component owned by a THIRD party, who could replace it under us", () => {
    expectReject(
      probe("trusted-component", "/some/dir", "999", "755", "501"),
      "neither root nor this process"
    );
  });

  it("rejects a group-writable component", () => {
    expectReject(
      probe("trusted-component", "/some/dir", "0", "775", "501"),
      "group- or world-writable"
    );
  });

  it("rejects a world-writable component", () => {
    expectReject(
      probe("trusted-component", "/some/dir", "0", "777", "501"),
      "group- or world-writable"
    );
  });

  it("accepts a world-writable component that carries the STICKY bit", () => {
    // This is /tmp. Sticky means only an entry's own owner may rename or
    // remove it, so an existing component cannot be replaced under us.
    expectAccept(probe("trusted-component", "/tmp", "0", "1777", "501"), "PROBE=ACCEPT");
  });

  it("rejects an unparseable mode rather than guessing", () => {
    expectReject(probe("trusted-component", "/some/dir", "0", "rwx", "501"), "unparseable octal mode");
  });

  it("walks a REAL system directory chain and accepts it", () => {
    // /usr exists and is root-owned on both macOS and Linux.
    expectAccept(probe("trusted-chain", "base", "/usr"), "PROBE=ACCEPT");
  });

  it("walks the sandbox chain and accepts it", () => {
    expectAccept(probe("trusted-chain", "base", base), "PROBE=ACCEPT");
  });

  it("refuses a base that is a SYMLINK", () => {
    const link = path.join(sandbox, "base-link");
    fs.symlinkSync(base, link);
    expectReject(probe("trusted-chain", "base", link), "is a symlink");
  });

  it("refuses a base that does not exist", () => {
    expectReject(
      probe("trusted-chain", "base", path.join(sandbox, "no-such-base")),
      "does not resolve"
    );
  });

  it("refuses a base whose own directory is world-writable", () => {
    // The walker must actually CALL the per-component predicate. Without this
    // case, replacing the call with `true` left the whole suite green: the
    // predicate's own cases pass because they drive it directly.
    const wide = path.join(sandbox, "wide-base");
    fs.mkdirSync(wide);
    fs.chmodSync(wide, 0o777);
    expectReject(probe("trusted-chain", "base", wide), "group- or world-writable");
  });

  it("refuses a base whose INTERMEDIATE component is world-writable", () => {
    // And it must walk EVERY component, not just the leaf. The leaf here is
    // fine; its parent is not.
    const wide = path.join(sandbox, "wide-parent");
    const inner = path.join(wide, "inner");
    fs.mkdirSync(inner, { recursive: true });
    fs.chmodSync(inner, 0o755);
    fs.chmodSync(wide, 0o777);
    const r = probe("trusted-chain", "base", inner);
    expectReject(r, "group- or world-writable");
    expect(r.out, "the rejection must name the INTERMEDIATE component").toContain(wide);
  });

  it("refuses a relative base", () => {
    expectReject(probe("trusted-chain", "base", "relative"), "not an absolute path");
  });

  it("refuses the filesystem root as a base", () => {
    expectReject(probe("trusted-chain", "base", "/"), "filesystem root");
  });
});

/**
 * THE ONE RESOLUTION CHOKEPOINT. `clean-markers`, `preflight.sh` and
 * `teardown-verify.sh` all reach inside the storage directory through this and
 * nothing else. The executed exploit deleted a real fortress's audit lock as
 * root because the reviewed code lstat'd only the FINAL component.
 */
describe("drill-loop rails: safe-subpath, the resolution chokepoint", () => {
  let root: string;

  beforeEach(() => {
    root = path.join(anchor, ".sanctuary-loop-good");
    fs.mkdirSync(path.join(root, "state", "_audit"), { recursive: true });
    fs.writeFileSync(path.join(root, "state", "_audit", ".audit-write.lock"), "lock");
  });

  it("ACCEPTS a genuine nested target and prints its path", () => {
    const r = probe("safe-subpath", root, "state/_audit/.audit-write.lock");
    expectAccept(r, "PROBE=ACCEPT");
    expect(r.out).toContain(path.join(root, "state", "_audit", ".audit-write.lock"));
  });

  it("ACCEPTS a target that does not exist yet, so a caller may conclude it is absent", () => {
    expectAccept(probe("safe-subpath", root, "exclusive-routing.json"), "PROBE=ACCEPT");
  });

  it("refuses a symlinked INTERMEDIATE component, which is the executed exploit", () => {
    fs.rmSync(path.join(root, "state"), { recursive: true, force: true });
    fs.symlinkSync(path.join(anchor, ".sanctuary"), path.join(root, "state"));
    expectReject(
      probe("safe-subpath", root, "state/_audit/.audit-write.lock"),
      "is a symlink"
    );
  });

  it("refuses a symlinked FINAL component", () => {
    const target = path.join(root, "state", "_audit", ".audit-write.lock");
    fs.rmSync(target);
    fs.symlinkSync(path.join(anchor, ".sanctuary"), target);
    expectReject(
      probe("safe-subpath", root, "state/_audit/.audit-write.lock"),
      "is a symlink"
    );
  });

  it("refuses a traversal out of the root", () => {
    expectReject(
      probe("safe-subpath", root, "../../.sanctuary/state"),
      "relative or empty component"
    );
  });

  it("refuses an absolute path where a relative one belongs", () => {
    expectReject(probe("safe-subpath", root, "/etc/passwd"), "must not be absolute");
  });

  it("refuses a relative path with shell metacharacters", () => {
    expectReject(probe("safe-subpath", root, "state/$(id)"), "disallowed characters");
  });

  it("refuses an empty relative path", () => {
    expectReject(probe("safe-subpath", root, ""), "empty relative path");
  });

  it("refuses a root that is not in canonical resolved form", () => {
    // A rail that accepted "some path that resolves to the right place" would
    // be accepting the exact shape the symlink exploits used.
    const alias = path.join(sandbox, "root-alias");
    fs.symlinkSync(root, alias);
    expectReject(
      probe("safe-subpath", alias, "exclusive-routing.json"),
      /is a symlink|canonical resolved form/
    );
  });
});

/**
 * M1: `SUDO_USER` appeared nowhere in the reviewed artifact, so the grant
 * holder could aim the wrapper at any other account's directory. PURE
 * predicate, so the uid-0 branch is testable without root.
 */
describe("drill-loop rails: the caller binding", () => {
  it("does not bind an UNPRIVILEGED caller, which is not the concern", () => {
    expectAccept(probe("caller-binding", "501", "", "agentmac"), "PROBE=ACCEPT");
  });

  it("accepts root when SUDO_USER matches the operator account", () => {
    expectAccept(probe("caller-binding", "0", "agentmac", "agentmac"), "PROBE=ACCEPT");
  });

  it("refuses root with NO SUDO_USER rather than guessing who called", () => {
    expectReject(probe("caller-binding", "0", "", "agentmac"), "no SUDO_USER");
  });

  it("refuses root acting for an account other than the sudo caller", () => {
    expectReject(
      probe("caller-binding", "0", "agentmac", "someone-else"),
      "refusing to act for another account"
    );
  });

  it("refuses a non-numeric self uid", () => {
    expectReject(probe("caller-binding", "root", "agentmac", "agentmac"), "not numeric");
  });
});

/** The parsing core of preflight's real D7 daemon-freshness check. */
describe("drill-loop rails: etime parsing", () => {
  it("parses mm:ss", () => {
    expectAccept(probe("etime", "02:05"), "seconds=125");
  });

  it("parses hh:mm:ss", () => {
    expectAccept(probe("etime", "01:02:05"), "seconds=3725");
  });

  it("parses dd-hh:mm:ss", () => {
    expectAccept(probe("etime", "1-02:03:04"), "seconds=93784");
  });

  it("tolerates the whitespace ps pads with", () => {
    expectAccept(probe("etime", "   02:05  "), "seconds=125");
  });

  it("refuses a value it cannot parse rather than returning 0", () => {
    expectReject(probe("etime", "soon"), "unparseable");
  });

  it("does not read a leading zero as octal", () => {
    // `08` and `09` are the classic bash arithmetic trap here.
    expectAccept(probe("etime", "08:09"), "seconds=489");
  });
});

/**
 * THE HOST RAIL DECIDES ON HARDWARE, NOT ON A NAME.
 *
 * A live audit of the real machines (2026-07-25) killed the name allowlist:
 *
 *   Mini1, the intended drill host: `hostname -s` = "Mac", `scutil --get
 *     HostName` UNSET, LocalHostName "Agents-Mac-mini", ComputerName
 *     "Agent's Mac mini".
 *   MBA, which must never run it: `hostname -s` = "Eriks-MacBook-Air".
 *
 * Allowing Mini1 by short name means putting the literal string "Mac" on the
 * allowlist, and a large fraction of default-configured Macs answer exactly
 * that. An allowlist containing "Mac" silently converts "fail closed on an
 * unknown host" into "pass on many unknown hosts". Names are forgeable anyway:
 * BLOCKER 2 was a planted `hostname` producing WRAPPER=ACCEPT on the MacBook.
 *
 * So the decision is the machine's hardware UUID, the allowlist and denylist
 * live in the SAME identifier space, and names survive only as a deny-only
 * belt that can push the rail toward refusal and never toward acceptance.
 */
describe("drill-loop rails: host rail, decided on hardware", () => {
  const ALLOWED = "1".repeat(64);
  const DENIED = "2".repeat(64);
  const UNKNOWN = "3".repeat(64);

  // THE REQUIRED CASE from the machine audit.
  for (const generic of ["Mac", "Macintosh", "MacBook-Pro", "localhost", "Mac.localdomain"]) {
    it(`the generic name "${generic}" is not sufficient to pass the host rail`, () => {
      const r = probe("host-observed", UNKNOWN, generic, "", "", "");
      expect(r.status).not.toBe(0);
      expect(r.out).not.toContain("ACCEPT");
      expect(r.out, "a name must never be what admits a machine").toMatch(/fingerprint|allowlist/);
    });
  }

  it("accepts the allowlisted hardware", () => {
    expectAccept(probe("fingerprint-against", ALLOWED, DENIED, ALLOWED), "PROBE=ACCEPT");
  });

  it("refuses the denylisted hardware", () => {
    expectReject(
      probe("fingerprint-against", DENIED, DENIED, ALLOWED),
      "un-overridable denylist"
    );
  });

  it("refuses denylisted hardware that is ALSO on the allowlist", () => {
    // Deny beats allow, in the SAME identifier space. A denylist keyed on
    // names beside an allowlist keyed on hardware would silently stop
    // matching, which is the single worst bug this rail can have.
    expectReject(
      probe("fingerprint-against", DENIED, DENIED, `${DENIED} ${ALLOWED}`),
      "un-overridable denylist"
    );
  });

  it("refuses hardware that is on neither list", () => {
    expectReject(
      probe("fingerprint-against", UNKNOWN, DENIED, ALLOWED),
      "not on the compiled-in drill-host allowlist"
    );
  });

  // EVERY unusable lookup is a REJECT, never a skip, never a non-match that
  // reads as "well, it isn't the MacBook, so it must be fine".
  it("refuses an EMPTY fingerprint", () => {
    expectReject(probe("fingerprint-against", "", DENIED, ALLOWED), "no host fingerprint supplied");
  });

  it("refuses a truncated fingerprint", () => {
    expectReject(probe("fingerprint-against", "1111", DENIED, ALLOWED), "not 64 hex characters");
  });

  it("refuses an error string where a fingerprint belongs", () => {
    expectReject(
      probe("fingerprint-against", "ioreg: command not found", DENIED, ALLOWED),
      "not 64 hex characters"
    );
  });

  it("refuses an upper-case fingerprint rather than matching case-insensitively", () => {
    expectReject(
      probe("fingerprint-against", "A".repeat(64), DENIED, ALLOWED),
      "not lowercase hex"
    );
  });

  it("admits NOTHING when the allowlist is empty", () => {
    // Which is the shipped state, until a drill host is measured.
    expectReject(probe("fingerprint-against", ALLOWED, DENIED, ""), "allowlist is EMPTY");
  });

  it("the SHIPPED allowlist is empty and the SHIPPED denylist is not", () => {
    // The shipped lists, asserted directly, because no override can fake this
    // and because an accidentally-populated allowlist is the one change here
    // that would matter most.
    const rails = fs.readFileSync(path.join(DRILL_LOOP, "lib", "rails.sh"), "utf8");
    expect(rails).toMatch(/^RAILS_HOST_ALLOW_FP=''$/m);
    expect(rails).toMatch(/^RAILS_HOST_DENY_FP='[0-9a-f]{64}'$/m);
    // and the generic name allowlist is gone, not merely unused
    expect(rails).not.toMatch(/^RAILS_HOST_ALLOW=/m);
  });
});

describe("drill-loop rails: the UUID to fingerprint reduction", () => {
  const UUID = "DC6E6D25-7885-5B37-948A-5C942737CFF4";

  it("reduces a well-formed hardware UUID", () => {
    const r = probe("host-fingerprint-of", UUID);
    expectAccept(r, "PROBE=ACCEPT");
    expect(r.out).toMatch(/fingerprint=[0-9a-f]{64}/);
  });

  it("is a stable function: same machine, same fingerprint", () => {
    const a = probe("host-fingerprint-of", UUID).out;
    const b = probe("host-fingerprint-of", UUID).out;
    const c = probe("host-fingerprint-of", `A${UUID.slice(1)}`).out;
    expect(a).toBe(b);
    expect(a).not.toBe(c);
  });

  it("refuses an empty UUID", () => {
    expectReject(probe("host-fingerprint-of", ""), "empty hardware UUID");
  });

  it("refuses a truncated UUID", () => {
    expectReject(probe("host-fingerprint-of", "DC6E6D25-7885"), "not 36 characters");
  });

  it("refuses an error message where a UUID belongs", () => {
    // Both the too-short and the exactly-36-characters shapes, because a
    // truncated read and a chatty error are different failures.
    expectReject(
      probe("host-fingerprint-of", "ioreg: could not find IOPlatformExpertDevice"),
      "not 36 characters"
    );
    expectReject(
      probe("host-fingerprint-of", "ioreg: could not find IOPlatformExpe"),
      "uppercase-hex form"
    );
  });

  it("refuses a same-length value that is not a UUID", () => {
    expectReject(
      probe("host-fingerprint-of", "ZZZZZZZZ-7885-5B37-948A-5C942737CFF4"),
      "uppercase-hex form"
    );
  });
});

describe("drill-loop rails: names are a DENY-ONLY belt", () => {
  const ALLOWED = "1".repeat(64);

  it("refuses the daily driver by short name even on allowlisted hardware", () => {
    expectReject(probe("host", ALLOWED, "Eriks-MacBook-Air"), "un-overridable name denylist");
  });

  it("refuses the daily driver however it is spelled", () => {
    expectReject(probe("host", ALLOWED, "ERIKS-MACBOOK-AIR.local"), "un-overridable name denylist");
  });

  it("refuses the daily driver by its ComputerName, spaces and apostrophe included", () => {
    // `scutil --get ComputerName` returns "Erik’s MacBook Air". A denylist of
    // space-separated words cannot hold that literally, so it compares an
    // aggressively normalized form.
    expectReject(probe("host", ALLOWED, "Erik’s MacBook Air"), "un-overridable name denylist");
  });

  it("screens an observed name in a MIDDLE position", () => {
    expectReject(
      probe("host-observed", ALLOWED, "Mac", "Eriks-MacBook-Air", "", ""),
      "un-overridable name denylist"
    );
  });

  it("screens an observed name in the LAST position when the others are empty", () => {
    // This is the exact branch the reviewed `elif` chain dropped.
    expectReject(
      probe("host-observed", ALLOWED, "Mac", "", "", "Erik’s MacBook Air"),
      "un-overridable name denylist"
    );
  });

  it("does not require ANY name: the drill host reports no scutil HostName", () => {
    // Zero observed names must still reach the fingerprint decision, and that
    // decision must be the thing that refuses.
    expectReject(
      probe("host-observed", "3".repeat(64), "", "", "", ""),
      /allowlist|fingerprint/
    );
  });
});

describe("drill-loop rails: account rail (the operator-account pivot)", () => {
  it("rejects the root account by NAME", () => {
    expectReject(probe("account", "operator", "root"), "refusing the root account by name");
  });

  it("rejects an account that RESOLVES to uid 0 under another name", () => {
    expectReject(probe("uid", "operator", "toor", "0"), "refusing root by uid");
  });

  it("rejects a non-numeric uid", () => {
    expectReject(probe("uid", "operator", "weird", "0x0"), "not a plain non-negative integer");
  });

  it("rejects an account that does not exist", () => {
    expectReject(probe("account", "operator", "no-such-drill-account"), "does not exist on this host");
  });

  it("rejects an option-shaped account name", () => {
    expectReject(probe("account", "operator", "-rf"), "must start with a lowercase letter");
  });

  it("rejects an account name with shell metacharacters", () => {
    expectReject(probe("account", "operator", "a;id"), "disallowed characters");
  });

  it("rejects an over-long account name", () => {
    expectReject(probe("account", "operator", "a".repeat(40)), "longer than 31 characters");
  });

  it("rejects an account whose uid is not the one the caller expected", () => {
    expectReject(probe("account-uid", "agent", me, "999999"), "expected 999999");
  });

  it("accepts a valid non-root account and prints its uid", () => {
    if (myUid === 0) {
      expectReject(probe("account", "operator", me), /root/);
      return;
    }
    const r = probe("account", "operator", me);
    expectAccept(r, "PROBE=ACCEPT");
    expect(r.out).toContain(`uid=${myUid}`);
  });

  it("accepts an account whose uid matches the expectation", () => {
    if (myUid === 0) {
      expectReject(probe("account-uid", "agent", me, "0"), /uid 0/);
      return;
    }
    expectAccept(probe("account-uid", "agent", me, String(myUid)), "PROBE=ACCEPT");
  });
});

describe("drill-loop rails: secret-file permissions", () => {
  it("rejects a GROUP-WRITABLE 0660 passphrase file", () => {
    const p = path.join(sandbox, "pass.txt");
    fs.writeFileSync(p, "x");
    fs.chmodSync(p, 0o660);
    expectReject(probe("secret", p, me), "group- or world-WRITABLE");
  });

  it("rejects a group-READABLE 0640 passphrase file", () => {
    const p = path.join(sandbox, "pass.txt");
    fs.writeFileSync(p, "x");
    fs.chmodSync(p, 0o640);
    expectReject(probe("secret", p, me), "readable or writable by group or other");
  });

  it("rejects a world-writable 0666 passphrase file", () => {
    const p = path.join(sandbox, "pass.txt");
    fs.writeFileSync(p, "x");
    fs.chmodSync(p, 0o666);
    expectReject(probe("secret", p, me), "group- or world-WRITABLE");
  });

  it("rejects a SYMLINKED passphrase file", () => {
    const p = path.join(sandbox, "pass.txt");
    fs.writeFileSync(p, "x");
    fs.chmodSync(p, 0o600);
    const link = path.join(sandbox, "pass-link.txt");
    fs.symlinkSync(p, link);
    expectReject(probe("secret", link, me), "is a symlink");
  });

  it("rejects a passphrase path that is a directory", () => {
    const d = path.join(sandbox, "passdir");
    fs.mkdirSync(d);
    expectReject(probe("secret", d, me), "not a regular file");
  });

  it("accepts a 0600 file owned by the expected account", () => {
    const p = path.join(sandbox, "pass.txt");
    fs.writeFileSync(p, "x");
    fs.chmodSync(p, 0o600);
    if (myUid === 0) {
      expectReject(probe("secret", p, me), /root/);
      return;
    }
    expectAccept(probe("secret", p, me), "PROBE=ACCEPT");
  });
});

describe("drill-loop rails: loop lock (nightly and interactive must not interleave)", () => {
  it("refuses a lock held by a LIVE process", () => {
    const lock = path.join(sandbox, "loop.lock");
    fs.mkdirSync(lock);
    fs.writeFileSync(path.join(lock, "pid"), `${process.pid}\n`);
    expectReject(probe("lock", lock, "2"), "held by live pid");
  });

  it("acquires a free lock", () => {
    expectAccept(probe("lock", path.join(sandbox, "loop.lock"), "5"), "PROBE=ACCEPT");
  });

  it("lets EXACTLY ONE of two concurrent reclaimers of a stale lock proceed", () => {
    const lock = path.join(sandbox, "loop.lock");
    fs.mkdirSync(lock);
    const dead = spawnSync("bash", ["-c", "echo $$"], { encoding: "utf8" });
    const deadPid = (dead.stdout ?? "").trim();
    expect(deadPid).toMatch(/^\d+$/);
    fs.writeFileSync(path.join(lock, "pid"), `${deadPid}\n`);

    // The winner HOLDS the lock for five seconds. Without a hold this test
    // proves nothing: the first process would acquire and release faster than
    // the second could contend, and two sequential acquisitions of a free lock
    // would look like a race that never happened.
    const a = spawnSync(
      "bash",
      ["-c", `"$0" lock "$1" 20 5 &  "$0" lock "$1" 20 5 &  wait`, PROBE, lock],
      { encoding: "utf8", timeout: 60_000 }
    );
    const merged = `${a.stdout ?? ""}${a.stderr ?? ""}`;
    const accepts = (merged.match(/PROBE=ACCEPT/g) ?? []).length;
    expect(accepts, `expected exactly one winner; output was:\n${merged}`).toBe(1);
    expect(merged, "the loser must say why it refused").toContain("held by live pid");
  });
});

describe("drill-loop rails: wrapper assembly and drift", () => {
  it("the committed wrapper.sha256 matches a fresh assembly from the repo", () => {
    const r = run("bash", [BUILD_WRAPPER, "--verify-hash"]);
    expect(r.status, r.out).toBe(0);
    expect(r.out).toContain("wrapper hash OK");
  });

  it("the assembled wrapper is SELF-CONTAINED: it sources nothing at runtime", () => {
    const assembled = execFileSync("bash", [BUILD_WRAPPER, "--stdout"], { encoding: "utf8" });
    const executable = assembled
      .split("\n")
      .filter((line) => !/^\s*#/.test(line))
      .join("\n");
    expect(executable).not.toMatch(/^\s*(\.|source)\s+/m);
    expect(executable).toContain("rails_assert_disposable_storage()");
    expect(executable).toContain("wrapper_run_rails()");
  });

  it("accepts when repo, committed hash and installed file all agree", () => {
    const assembled = path.join(sandbox, "assembled");
    execFileSync("bash", [BUILD_WRAPPER, assembled], { stdio: "ignore" });
    const installed = path.join(sandbox, "installed");
    fs.copyFileSync(assembled, installed);
    expectAccept(probe("wrapper-hash", assembled, installed, SHA_FILE), "PROBE=ACCEPT");
  });

  it("refuses when the REPO has drifted from the committed hash", () => {
    const assembled = path.join(sandbox, "assembled");
    execFileSync("bash", [BUILD_WRAPPER, assembled], { stdio: "ignore" });
    const drifted = path.join(sandbox, "drifted");
    fs.copyFileSync(assembled, drifted);
    fs.appendFileSync(drifted, "# drift\n");
    expectReject(
      probe("wrapper-hash", drifted, assembled, SHA_FILE),
      "assembled wrapper does not match"
    );
  });

  it("refuses when the INSTALLED wrapper has drifted", () => {
    const assembled = path.join(sandbox, "assembled");
    execFileSync("bash", [BUILD_WRAPPER, assembled], { stdio: "ignore" });
    const drifted = path.join(sandbox, "drifted");
    fs.copyFileSync(assembled, drifted);
    fs.appendFileSync(drifted, "# drift\n");
    expectReject(
      probe("wrapper-hash", assembled, drifted, SHA_FILE),
      "installed wrapper does not match"
    );
  });

  it("refuses when the installed wrapper is missing", () => {
    const assembled = path.join(sandbox, "assembled");
    execFileSync("bash", [BUILD_WRAPPER, assembled], { stdio: "ignore" });
    expectReject(
      probe("wrapper-hash", assembled, path.join(sandbox, "nope"), SHA_FILE),
      "installed wrapper missing"
    );
  });

  it("refuses an installed wrapper that is not owned by root", () => {
    const assembled = path.join(sandbox, "assembled");
    execFileSync("bash", [BUILD_WRAPPER, assembled], { stdio: "ignore" });
    if (myUid === 0) {
      fs.chmodSync(assembled, 0o777);
      expectReject(probe("wrapper-ownership", assembled), "group- or world-writable");
      return;
    }
    expectReject(probe("wrapper-ownership", assembled), "not owned by root");
  });

  it("refuses an installed wrapper that is a symlink", () => {
    const assembled = path.join(sandbox, "assembled");
    execFileSync("bash", [BUILD_WRAPPER, assembled], { stdio: "ignore" });
    const link = path.join(sandbox, "installed-link");
    fs.symlinkSync(assembled, link);
    expectReject(probe("wrapper-ownership", link), "is a symlink");
  });
});

/**
 * THE STRUCTURAL ASSERTIONS.
 *
 * The coverage re-review found that three of the four layers the PR body calls
 * load-bearing had NO test at all: deleting `set -euo pipefail` from the
 * header, the gauntlet's non-empty post-condition, or the `wrapper_cli` guard
 * left the suite fully green. And the constant the path rail anchors to was
 * stubbed in both batteries, so mutating it to `/var/root` kept all 59 tests
 * passing.
 *
 * These cases assert those properties on the SHIPPED artifact, which no
 * override in any battery can fake.
 */
describe("drill-loop wrapper: the shipped artifact's own structure", () => {
  let assembled: string;

  beforeEach(() => {
    assembled = execFileSync("bash", [BUILD_WRAPPER, "--stdout"], { encoding: "utf8" });
  });

  const executableLines = (s: string): string =>
    s
      .split("\n")
      .filter((line) => !/^\s*#/.test(line))
      .join("\n");

  it("uses an ABSOLUTE interpreter, not `env bash`", () => {
    // `#!/usr/bin/env bash` asks PATH which bash to be. A planted `bash`
    // substituted the interpreter of this root-run artifact outright, and even
    // with a clean PATH, Homebrew's operator-writable /opt/homebrew/bin/bash
    // wins on a Mac.
    expect(assembled.split("\n")[0]).toBe("#!/bin/bash");
  });

  it("pins PATH before any external command can run", () => {
    const lines = assembled.split("\n");
    const pathAt = lines.findIndex((l) => l.trim() === SHIPPED_PATH_LINE);
    expect(pathAt, "the assembled artifact must pin PATH").toBeGreaterThan(0);
    // Nothing executable may precede it.
    const before = lines.slice(0, pathAt).filter((l) => l.trim() !== "" && !/^\s*#/.test(l));
    expect(before, `these executable lines run before PATH is pinned: ${before.join(" | ")}`).toEqual([]);
    expect(assembled).toContain("export PATH");
    // /usr/local/bin is operator-writable on a Mac and must not be in it.
    expect(SHIPPED_PATH_LINE).not.toContain("/usr/local/bin");
  });

  it("sets `set -euo pipefail` in its header", () => {
    // BLOCKER-defence layer 1. Deleting it left the reviewed suite green.
    expect(assembled).toContain("\nset -euo pipefail\n");
  });

  it("keeps BOTH non-empty storage post-conditions", () => {
    // BLOCKER-defence layers 3 and 4: one after the rail, one immediately
    // before the single place SANCTUARY_STORAGE_PATH is exported. Deleting
    // either left the reviewed suite green.
    const guards = executableLines(assembled).match(/\[ -z "\$STORAGE" \]/g) ?? [];
    expect(guards.length, "expected the post-rail guard AND the wrapper_cli guard").toBeGreaterThanOrEqual(2);
    expect(assembled).toContain("refusing to invoke the CLI with an empty storage path");
  });

  it("carries the SHIPPED root-owned base, not a battery's override", () => {
    // The reviewed build's equivalent anchor was a FUNCTION stubbed in both
    // batteries; mutating it to /var/root kept every test green. It is a
    // constant now, and this is the assertion no override can fake.
    expect(assembled).toContain(`RAILS_DISPOSABLE_BASE='${SHIPPED_BASE}'`);
  });

  it("has NO --storage flag and no other caller-supplied path", () => {
    // The whole of BLOCKER 1: an attacker cannot race a value they never
    // supply. `--base` exists on the unprivileged drivers for the batteries;
    // it must never reach the root artifact. The usage text still SAYS
    // "--storage" in the sentence explaining that it does not exist, so this
    // looks for the parser arm, not the string.
    const exec = executableLines(assembled);
    expect(exec).not.toMatch(/^\s*--storage\)/m);
    expect(exec).not.toMatch(/^\s*--base\)/m);
    expect(exec).toMatch(/^\s*--run-id\)/m);
    expect(exec).not.toContain("ARG_STORAGE");
  });

  it("no longer looks up anybody's home directory", () => {
    // `wrapper_home_of` was the stub that made the rail's anchor untested in
    // both batteries. It is gone rather than better-tested. The NOTE at the
    // bottom of wrapper-main.sh names it while explaining that, so this looks
    // at executable lines only.
    const exec = executableLines(assembled);
    expect(exec).not.toContain("wrapper_home_of");
    expect(exec).not.toContain("NFSHomeDirectory");
  });

  it("resolves its host identity by ABSOLUTE path, not through PATH", () => {
    const exec = executableLines(assembled);
    expect(exec).toContain("rails__sys hostname");
    expect(exec).toContain("rails__sys scutil");
    expect(exec).toMatch(/RAILS_SYSTEM_BIN_DIRS='\/usr\/bin \/bin \/usr\/sbin \/sbin'/);
  });

  it("hands EVERY observed host identity to the rail, in one branchless call", () => {
    // The reviewed wrapper's if/elif chain dropped the ComputerName alias in
    // one of its branches. A rail can only refuse what it is shown, and no
    // rail-level test can see an argument the caller never passes, so this
    // asserts the call site itself.
    const exec = executableLines(assembled);
    expect(exec).toContain(
      'rails_assert_host_allowed_observed \\\n      "$h_fp" "$h_short" "$h_full" "$h_computer" "$h_local"'
    );
    // and no branchy variant survives alongside it
    expect(exec).not.toMatch(/elif \[ -n "\$h_full" \]/);
  });

  it("exposes no environment or flag override anywhere in the shipped surface", () => {
    const sudoers = fs.readFileSync(
      path.join(DRILL_LOOP, "sudoers.d", "sanctuary-drill"),
      "utf8"
    );
    for (const forbidden of ["env_keep", "DRILL_LOOP_ALLOWED_HOSTS", "allow-host"]) {
      expect(executableLines(assembled), `assembled wrapper must not contain ${forbidden}`).not.toContain(forbidden);
      expect(executableLines(sudoers), `sudoers grant must not contain ${forbidden}`).not.toContain(forbidden);
    }
  });

  it("ships an EMPTY agent-account allowlist, so root acts for nobody yet", () => {
    // ROUND-3 M2. Same posture as the empty host allowlist: an unprovisioned
    // harness refuses rather than acting for whatever account it is handed.
    expect(assembled).toContain("RAILS_AGENT_ACCOUNT_ALLOW=''");
  });

  it("carries the four READ verbs the drivers observe through", () => {
    // BLOCKER 3: the drivers could not observe the root-owned registry, the
    // gate log, or the inside of a 0700 fortress, and folded "could not read"
    // into "clean". These verbs are the half that lets them actually look.
    const verbs = assembled.match(/^WRAPPER_VERBS='([^']*)'/m);
    expect(verbs, "the assembled wrapper must declare its verb list").not.toBeNull();
    for (const verb of ["registry-state", "fortress-state", "gate-log", "pf-anchor-rules"]) {
      expect(verbs![1].split(" ")).toContain(verb);
    }
    // ...and `retire`, without which the disposable fortresses accumulate
    // forever while the README claims a nightly teardown (M1).
    expect(verbs![1].split(" ")).toContain("retire");
  });

  it("has NO --passphrase-file flag: validated root surface with no consumer", () => {
    const exec = executableLines(assembled);
    expect(exec).not.toMatch(/^\s*--passphrase-file\)/m);
    expect(exec).not.toContain("ARG_PASSFILE");
  });

  it("keeps ONE PATH value across the header, the rails, and the drivers", () => {
    // The header hard-codes PATH because it runs BEFORE lib/rails.sh is
    // concatenated in, and the drivers pin theirs from `RAILS_SYSTEM_PATH`.
    // Three spellings of one security decision is how they drift apart, so
    // this asserts they agree.
    const rails = fs.readFileSync(RAILS, "utf8");
    const binDirs = rails.match(/^RAILS_SYSTEM_BIN_DIRS='([^']*)'/m);
    const sysPath = rails.match(/^RAILS_SYSTEM_PATH='([^']*)'/m);
    expect(binDirs, "lib/rails.sh must declare RAILS_SYSTEM_BIN_DIRS").not.toBeNull();
    expect(sysPath, "lib/rails.sh must declare RAILS_SYSTEM_PATH").not.toBeNull();
    expect(sysPath![1]).toBe(binDirs![1].split(" ").join(":"));
    expect(SHIPPED_PATH_LINE).toBe(`PATH=${sysPath![1]}`);
    // /usr/local/bin is operator-writable on a Mac and must be in none of them.
    expect(binDirs![1]).not.toContain("/usr/local/bin");
  });

  it("the DRIVERS resolve every observation tool absolutely, never through PATH", () => {
    // ROUND-3 BLOCKER 1, structurally. Round 2 closed the PATH class in the
    // root wrapper and left it open in the unprivileged drivers, whose entire
    // output is observations. Codex planted a `sudo` earlier in PATH and got a
    // fully green probe ladder and a clean teardown with no real sudo, no
    // installed wrapper, no pfctl and no agent account.
    //
    // This scans for a bare command NAME in COMMAND POSITION. `rails__sys grep`
    // is fine (the resolver holds the command position); `grep -q ...` is not.
    const forbidden = [
      "sudo",
      "curl",
      "tail",
      "grep",
      "sed",
      "awk",
      "head",
      "tr",
      "stat",
      "pfctl",
      "launchctl",
      "ioreg",
      "git",
      "ps",
      "date",
      "mktemp",
      "mkdir",
      "rm",
      "cat",
      "id",
    ].join("|");
    // Command position: line start, or right after ; & | ( ) && || $( then do else !
    const bare = new RegExp(
      String.raw`(?:^|[;&|(]|\bthen\b|\bdo\b|\belse\b|!)\s*(?:${forbidden})\b`,
      "m"
    );
    // Comments are stripped first (these files EXPLAIN the attack at length),
    // and so are STRING LITERALS: a message that says "sudo -n -u <agent> is
    // not covered by the grant" is documentation, not an invocation, and a
    // scanner that cannot tell them apart forces the documentation out.
    //
    // Stripped PER LINE, never across the file: a quote-pairing walk over the
    // whole text merges statements together at the first unbalanced quote and
    // then reports one enormous bogus line, which is a scanner that cannot be
    // trusted either way.
    const stripStrings = (line: string): string =>
      line.replace(/"(?:[^"\\]|\\.)*"/g, '""').replace(/'[^']*'/g, "''");
    for (const driver of fs.readdirSync(DRIVERS)) {
      const src = executableLines(fs.readFileSync(path.join(DRIVERS, driver), "utf8"));
      const offending = src
        .split("\n")
        .map(stripStrings)
        .filter((line) => bare.test(line))
        .filter((line) => !/^\s*(?:PATH=|export PATH)/.test(line));
      expect(
        offending,
        `${driver} invokes a bare command name; a planted binary on PATH answers for it:\n` +
          offending.join("\n")
      ).toEqual([]);
    }
  });

  it("the DRIVERS pin PATH from the rails' single source of truth", () => {
    for (const driver of fs.readdirSync(DRIVERS)) {
      const src = fs.readFileSync(path.join(DRIVERS, driver), "utf8");
      expect(src, `${driver} must pin PATH`).toContain('PATH="$RAILS_SYSTEM_PATH"');
      expect(src, `${driver} must export the pinned PATH`).toContain("export PATH");
      expect(
        src,
        `${driver} must resolve sudo through the absolute resolver`
      ).toContain('SUDO="$(rails_require_cmd sudo)"');
    }
  });

  it("install-wrapper VERIFIES before it installs, and removes a mismatch", () => {
    // ROUND-3 M3. It used to `install` first and hash second, so on any
    // mismatch it exited leaving a root-owned 0755 file that did NOT match the
    // committed hash sitting at exactly the path the NOPASSWD grant names.
    // `run-loop.sh` would refuse to use it; a hand-run `sudo
    // /usr/local/sbin/sanctuary-drill-wrapper` would not.
    //
    // This script cannot be executed here (it needs uid 0 and it writes to
    // /usr/local/sbin), so the ORDER is asserted structurally. That is a weaker
    // proof than running it and is stated as such.
    const src = fs.readFileSync(path.join(DRILL_LOOP, "install-wrapper.sh"), "utf8");
    const exec = executableLines(src);
    const stagedCompare = exec.indexOf('if [ "$STAGED" != "$WANT" ]');
    const installAt = exec.search(/^install -o root/m);
    expect(stagedCompare, "install-wrapper must compare the staged hash").toBeGreaterThan(-1);
    expect(installAt, "install-wrapper must install the artifact").toBeGreaterThan(-1);
    expect(
      stagedCompare,
      "the committed-hash comparison must happen BEFORE anything is written to the grant target"
    ).toBeLessThan(installAt);
    // ...and a post-install mismatch removes the artifact rather than leaving
    // an unreviewed root-owned file at the grant target.
    expect(exec).toMatch(/rm -f "\$DEST"\n\s*die "installed hash/);
    // ...and the DIRECTORY the grant rests on is chain-verified, which
    // `rails_assert_wrapper_ownership` never does (it checks only the file).
    expect(exec).toContain("rails_assert_trusted_dir_chain 'grant target dir'");
  });

  it("the sudoers grant pins secure_path", () => {
    const sudoers = fs.readFileSync(
      path.join(DRILL_LOOP, "sudoers.d", "sanctuary-drill"),
      "utf8"
    );
    expect(executableLines(sudoers)).toContain('secure_path="/usr/bin:/bin:/usr/sbin:/sbin"');
  });
});

/**
 * THE REGRESSION THAT WOULD HAVE CAUGHT BOTH BLOCKERS.
 *
 * These cases run the REAL assembled artifact, byte for byte, with TWO
 * CONSTANT overrides spliced in immediately before its entrypoint line:
 *
 *   RAILS_HOST_ALLOW / RAILS_HOST_DENY - stub the host rail to pass, so
 *     execution reaches the path rail. Without this every case dies at the
 *     host rail, which is exactly how the first unsound build stayed green.
 *   RAILS_DISPOSABLE_BASE - point the root-owned base at a temp directory, so
 *     nothing here reads or writes a real one.
 *
 * Both are CONSTANTS whose shipped values are asserted above. The reviewed
 * batteries overrode a FUNCTION instead, with no such assertion, and that is
 * why mutating it left 59 tests green.
 */
describe("drill-loop wrapper: every verb, not just the oracle", () => {
  let testWrapper: string;
  let agentWrapper: string;
  let victim: string;

  /**
   * CONSTANTS ONLY, spliced in immediately before the entrypoint. Never a
   * function: the reviewed batteries overrode `wrapper_home_of`, a FUNCTION,
   * and mutating it left every test green. Every constant overridden here has
   * its SHIPPED value asserted in the structural describe above, so an override
   * cannot hide a change to what runs as root.
   */
  function compose(
    dest: string,
    agentAllow: string,
    options: { gateHomeBase?: string; systemBinDirs?: string } = {}
  ): void {
    const assembled = execFileSync("bash", [BUILD_WRAPPER, "--stdout"], { encoding: "utf8" });
    const entrypoint = 'wrapper_main "$@"';
    const at = assembled.lastIndexOf(entrypoint);
    expect(at, "assembled wrapper must end with the wrapper_main entrypoint").toBeGreaterThan(0);
    // The host override is this machine's REAL hardware fingerprint, read
    // through the real `rails_host_fingerprint_local`. That is a stronger stub
    // than the old name one: the ioreg lookup, the UUID shape validation and
    // the hashing all actually run, and only the LIST is substituted.
    const overrides = [
      `RAILS_HOST_ALLOW_FP='${localFingerprint}'`,
      "RAILS_HOST_DENY_FP=''",
      "RAILS_HOST_DENY=''",
      `RAILS_DISPOSABLE_BASE='${base}'`,
      `RAILS_AGENT_ACCOUNT_ALLOW='${agentAllow}'`,
      ...(options.gateHomeBase ? [`RAILS_PRODUCT_GATE_HOME_BASE='${options.gateHomeBase}'`] : []),
      ...(options.systemBinDirs ? [`RAILS_SYSTEM_BIN_DIRS='${options.systemBinDirs}'`] : []),
      "",
    ].join("\n");
    fs.writeFileSync(dest, assembled.slice(0, at) + overrides + assembled.slice(at), {
      mode: 0o755,
    });
  }

  beforeEach(() => {
    testWrapper = path.join(sandbox, "test-wrapper");
    agentWrapper = path.join(sandbox, "test-wrapper-agent");
    // The DEFAULT test wrapper keeps the SHIPPED (empty) agent allowlist, so
    // the refusal it produces is the shipped behavior and not a fixture.
    compose(testWrapper, "");
    // And one with this account allowlisted, so the agent-taking verbs can be
    // exercised past that rail and the rail is seen to say yes as well as no.
    compose(agentWrapper, me);

    // A stand-in for a real fortress, OUTSIDE the disposable base. Every
    // exploit case below aims at this.
    victim = path.join(sandbox, "fake-fortress");
    fs.mkdirSync(path.join(victim, "state", "_audit"), { recursive: true });
    fs.writeFileSync(path.join(victim, "state", "_audit", ".audit-write.lock"), "FORTRESS");
    fs.writeFileSync(path.join(victim, "exclusive-routing.json"), "FORTRESS");
  });

  function wrapper(...args: string[]): Ran {
    return run("bash", [testWrapper, ...args]);
  }

  function agentWrapperRun(...args: string[]): Ran {
    return run("bash", [agentWrapper, ...args]);
  }

  const loopDir = (id: string): string => path.join(base, me, `.sanctuary-loop-${id}`);

  it("refuses --storage, because the flag no longer exists", () => {
    wrapperFullPath();
    // No branch needed: argument parsing happens BEFORE any rail, so this is
    // the same assertion on every platform.
    const r = wrapper("check", "--storage", victim, "--operator-account", me);
    expect(r.status).not.toBe(0);
    expect(r.out).not.toContain("WRAPPER=ACCEPT");
    expect(r.out).toContain("unknown or unsupported argument");
  });

  it("refuses the dead --passphrase-file flag, which reached no verb", () => {
    // ROUND-3 L1: parsed and rail-checked root-run surface with no consumer,
    // which is round 2's `--endpoint` finding under a new name. Deleted rather
    // than better documented.
    wrapperFullPath();
    const r = wrapper(
      "check",
      "--run-id",
      "good1",
      "--operator-account",
      me,
      "--passphrase-file",
      "/dev/null"
    );
    expect(r.status).not.toBe(0);
    expect(r.out).not.toContain("WRAPPER=ACCEPT");
    expect(r.out).toContain("unknown or unsupported argument");
  });

  it("refuses an EMPTY --run-id, and says which layer refused it", () => {
    // The reviewed suite had a case named "refuses an empty --storage at both
    // layers" that entered only ONE layer and asserted no reason at all.
    const r = wrapper("check", "--run-id", "", "--operator-account", me);
    if (!wrapperFullPath()) return expectHostRailRefusal(r);
    expect(r.status).not.toBe(0);
    expect(r.out).not.toContain("WRAPPER=ACCEPT");
    expect(r.out).toContain("WRAPPER=REJECT");
    expect(r.out, "the wrapper's own required-argument guard is the layer that fires").toContain(
      "--run-id is required"
    );
  });

  it("refuses a traversal-shaped run id, and prints REJECT", () => {
    const r = wrapper("check", "--run-id", "../../.sanctuary", "--operator-account", me);
    if (!wrapperFullPath()) return expectHostRailRefusal(r);
    expect(r.status).not.toBe(0);
    expect(r.out).not.toContain("WRAPPER=ACCEPT");
    expect(r.out).toContain("WRAPPER=REJECT");
    expect(r.out).toContain("run id rejected");
  });

  it("refuses an UPPERCASE run id, which aliases a lowercase one on APFS", () => {
    const r = wrapper("check", "--run-id", "GOOD1", "--operator-account", me);
    if (!wrapperFullPath()) return expectHostRailRefusal(r);
    expect(r.status).not.toBe(0);
    expect(r.out).not.toContain("WRAPPER=ACCEPT");
    expect(r.out).toContain("run id rejected");
  });

  it("prints WRAPPER=REJECT for a HOST rejection too, not only a path one", () => {
    // Review finding L2: `rails__die` exits, so a DIRECTLY called rail
    // terminated the script before the oracle's REJECT token was printed, and
    // `check` had two different contracts depending on which rail said no.
    // This case needs no platform branch: the SHIPPED host allowlist is empty,
    // so the shipped artifact refuses everywhere, which is the point.
    const assembled = execFileSync("bash", [BUILD_WRAPPER, "--stdout"], { encoding: "utf8" });
    const at = assembled.lastIndexOf('wrapper_main "$@"');
    const hostDenied = path.join(sandbox, "host-denied-wrapper");
    fs.writeFileSync(
      hostDenied,
      assembled.slice(0, at) + `RAILS_DISPOSABLE_BASE='${base}'\n` + assembled.slice(at),
      { mode: 0o755 }
    );
    const r = run("bash", [hostDenied, "check", "--run-id", "good1", "--operator-account", me]);
    expect(r.status).not.toBe(0);
    expect(r.out).not.toContain("WRAPPER=ACCEPT");
    expect(r.out, "a host rejection must print the same oracle token as any other").toContain(
      "WRAPPER=REJECT"
    );
    expect(r.out).toMatch(/host rail rejected|cannot establish this machine hardware identity/);
  });

  it("refuses --operator-account root before any sudo -u could happen", () => {
    const r = wrapper("check", "--run-id", "good1", "--operator-account", "root");
    if (!wrapperFullPath()) return expectHostRailRefusal(r);
    expect(r.status).not.toBe(0);
    expect(r.out).not.toContain("WRAPPER=ACCEPT");
    expect(r.out).toContain("operator account rejected");
  });

  it("refuses an unknown flag rather than passing it through", () => {
    wrapperFullPath();
    const r = wrapper("check", "--run-id", "good1", "--operator-account", me, "--danger");
    expect(r.status).not.toBe(0);
    expect(r.out).not.toContain("WRAPPER=ACCEPT");
    expect(r.out).toContain("unknown or unsupported argument");
  });

  it("refuses an unknown verb", () => {
    wrapperFullPath();
    const r = wrapper("definitely-not-a-verb", "--run-id", "good1", "--operator-account", me);
    expect(r.status).not.toBe(0);
    expect(r.out).not.toContain("WRAPPER=ACCEPT");
    expect(r.out).toContain("unknown verb");
  });

  it("ACCEPTS a genuine invocation and mints a root-owned-shaped directory", () => {
    const r = wrapper("check", "--run-id", "good1", "--operator-account", me);
    if (!wrapperFullPath()) return expectHostRailRefusal(r);
    expect(r.status, r.out).toBe(0);
    expect(r.out).toContain("WRAPPER=ACCEPT");
    expect(r.out).toContain(loopDir("good1"));
    expect(r.out).not.toMatch(/storage=\s/);
    expect(fs.statSync(loopDir("good1")).isDirectory()).toBe(true);
  });

  it("mint creates the disposable fortress", () => {
    const r = wrapper("mint", "--run-id", "good1", "--operator-account", me);
    if (!wrapperFullPath()) return expectHostRailRefusal(r);
    expectAccept(r, "WRAPPER=OK verb=mint");
    expect(fs.existsSync(loopDir("good1"))).toBe(true);
  });

  it("retire removes the whole disposable fortress", () => {
    // ROUND-3 M1: nothing removed them, ever, while the README said the loop
    // "tears it down each night". Unbounded accumulation of root-owned
    // directories, one per iteration forever, AND a dead `[ ! -d "$STORAGE" ]`
    // branch in teardown-verify that read as a covered case.
    const minted = wrapper("mint", "--run-id", "good1", "--operator-account", me);
    const r = wrapper("retire", "--run-id", "good1", "--operator-account", me);
    if (!wrapperFullPath()) return expectHostRailRefusal(r);
    expectAccept(minted, "WRAPPER=OK verb=mint");
    expectAccept(r, "WRAPPER=OK verb=retire");
    expect(
      fs.existsSync(loopDir("good1")),
      "retire exited 0 and the disposable fortress is still there"
    ).toBe(false);
  });

  it("fortress-state names a state for every entry, including present-empty", () => {
    // BLOCKER 3. The unprivileged drivers read a fortress the product chmods to
    // 0700 on every start, and absence-means-good is what "cannot look inside"
    // returns. Root reads it now, and a ZERO-LENGTH audit lock -- which is
    // UNBREAKABLE by design and bricks a fortress permanently -- is its own
    // state rather than folded into `present`.
    const minted = wrapper("mint", "--run-id", "good1", "--operator-account", me);
    const full = wrapperFullPath();
    if (full) {
      expectAccept(minted, "verb=mint");
      fs.mkdirSync(path.join(loopDir("good1"), "state", "_audit"), { recursive: true });
      fs.writeFileSync(path.join(loopDir("good1"), "state", "_audit", ".audit-write.lock"), "");
      fs.writeFileSync(path.join(loopDir("good1"), "exclusive-routing.json"), "x");
    }
    const r = wrapper("fortress-state", "--run-id", "good1", "--operator-account", me);
    if (!full) return expectHostRailRefusal(r);
    expectAccept(r, "WRAPPER=OK verb=fortress-state");
    expect(r.out).toContain("FORTRESS entry=exclusive-routing.json state=present");
    expect(r.out).toContain("FORTRESS entry=state/_audit/.audit-write.lock state=present-empty");
    expect(r.out).toContain("FORTRESS entry=state/.provision.lock state=absent");
    expect(r.out).toContain("WRAPPER=FORTRESS-END");
  });

  it("fortress-state REFUSES a symlinked entry rather than classifying it", () => {
    // Written first as "reports it as state=symlink", and the real artifact
    // said no: `rails_assert_safe_subpath` refuses any symlink in the chain
    // before the classifier can see one, so a `state=symlink` branch would have
    // been an unreachable predicate that read as a covered case. This asserts
    // what the code actually does, which is the stronger behavior.
    //
    // The property still matters: `[ -e ]` is FALSE for a dangling symlink, so
    // a hand-rolled check would report a symlinked marker as ABSENT, which is
    // the absence-means-good class wearing a different hat. The driver reads
    // this failure as COULD-NOT-OBSERVE, never as clean.
    const minted = wrapper("mint", "--run-id", "good1", "--operator-account", me);
    const full = wrapperFullPath();
    if (full) {
      expectAccept(minted, "verb=mint");
      fs.symlinkSync(
        path.join(sandbox, "no-such-target"),
        path.join(loopDir("good1"), "exclusive-routing.json")
      );
    }
    const r = wrapper("fortress-state", "--run-id", "good1", "--operator-account", me);
    expect(r.status).not.toBe(0);
    expect(r.out).not.toContain("WRAPPER=OK verb=fortress-state");
    if (!full) return expectHostRailRefusal(r);
    expect(r.out).toContain("is a symlink");
  });

  it("registry-state distinguishes ABSENT from unreadable", () => {
    // H1 / Codex #3. The reviewed check folded "no match", "cannot read" and
    // "not there" into one CLEAN verdict, against a path the product does not
    // use. There is no registry on a test machine, so the answer must be the
    // explicit ABSENT token rather than an empty success.
    const r = wrapper("registry-state", "--run-id", "good1", "--operator-account", me);
    if (!wrapperFullPath()) return expectHostRailRefusal(r);
    expectAccept(r, "WRAPPER=REGISTRY-ABSENT");
    expect(r.out).toContain("WRAPPER=OK verb=registry-state state=absent");
  });

  it("gate-log REFUSES when there is no log, rather than returning nothing", () => {
    // M5. The reason half of the probe ladder read a path nothing writes and
    // could not have read it anyway, so `P1-reason` and `N3` were permanently
    // SKIP: the half of the ladder that exists because a live `peer_unresolved`
    // strangle hid behind green-looking denials for a day was structurally
    // dead. "There is no log" must be an error, not an empty answer.
    const r = agentWrapperRun(
      "gate-log",
      "--run-id",
      "good1",
      "--operator-account",
      me,
      "--agent-account",
      me,
      "--agent-uid",
      String(myUid)
    );
    if (!wrapperFullPath()) return expectHostRailRefusal(r);
    expect(r.status).not.toBe(0);
    expect(r.out).not.toContain("WRAPPER=OK verb=gate-log");
    expect(r.out).toContain("CANNOT be evaluated");
  });

  it("gate-log reads from a checked fd, not a mutable pathname", () => {
    // ROUND-4 BLOCKER 1. The reviewed fix lstat'd the final log path and then
    // passed that path to tail. A gate-owned process could replace the file
    // between those two operations and make the root wrapper print another
    // file. This tail stub makes that substitution deterministic: old code
    // prints SECRET-TAIL-SUBSTITUTED, fixed code reads from stdin.
    const full = wrapperFullPath();
    const gateBase = path.join(sandbox, "gate-homes");
    const agentId = me.startsWith("sanctuary-") ? me.slice("sanctuary-".length) : me;
    const gateHome = path.join(gateBase, `sanctuary-gate-${agentId}`);
    const logDir = path.join(gateHome, "logs");
    fs.mkdirSync(logDir, { recursive: true });
    const attackLog = path.join(logDir, `egress-gate-${myUid}.out.log`);
    fs.writeFileSync(attackLog, `SAFE-GATE-LOG peer=${myUid}\n`);
    const victimLog = path.join(sandbox, "gate-tail-victim.log");
    fs.writeFileSync(victimLog, "SECRET-TAIL-SUBSTITUTED\n");
    const tailBin = path.join(sandbox, "tailbin");
    fs.mkdirSync(tailBin);
    fs.writeFileSync(
      path.join(tailBin, "tail"),
      `#!/bin/bash
args=("$@")
last="\${args[$((\${#args[@]}-1))]}"
if [ -n "\${DRILL_TEST_ATTACK_PATH:-}" ] && [ "$last" = "$DRILL_TEST_ATTACK_PATH" ]; then
  rm -f -- "$last"
  ln -s -- "$DRILL_TEST_VICTIM" "$last"
fi
exec /usr/bin/tail "$@"
`,
      { mode: 0o755 }
    );
    const gateWrapper = path.join(sandbox, "test-wrapper-gate-tail");
    compose(gateWrapper, me, {
      gateHomeBase: gateBase,
      systemBinDirs: `${tailBin} /usr/bin /bin /usr/sbin /sbin`,
    });
    const r = run(
      "bash",
      [
        gateWrapper,
        "gate-log",
        "--run-id",
        "good1",
        "--operator-account",
        me,
        "--agent-account",
        me,
        "--agent-uid",
        String(myUid),
      ],
      {
        DRILL_TEST_ATTACK_PATH: attackLog,
        DRILL_TEST_VICTIM: victimLog,
      }
    );
    expect(r.out, "root printed the substituted file").not.toContain("SECRET-TAIL-SUBSTITUTED");
    if (!full) return expectHostRailRefusal(r);
    expectAccept(r, "WRAPPER=OK verb=gate-log");
    expect(r.out).toContain("SAFE-GATE-LOG");
  });

  it("clean-markers removes the loop's own markers", () => {
    const minted = wrapper("mint", "--run-id", "good1", "--operator-account", me);
    const full = wrapperFullPath();
    const marker = path.join(loopDir("good1"), "exclusive-routing.json");
    if (full) {
      expectAccept(minted, "verb=mint");
      fs.writeFileSync(marker, "x");
    }
    const r = wrapper("clean-markers", "--run-id", "good1", "--operator-account", me);
    if (!full) return expectHostRailRefusal(r);
    expectAccept(r, "WRAPPER=OK verb=clean-markers");
    expect(fs.existsSync(marker)).toBe(false);
  });

  it("clean-markers refuses a symlinked INTERMEDIATE and the fortress file SURVIVES", () => {
    // THE EXECUTED EXPLOIT. `[ -L "$target" ]` lstats only the FINAL
    // component, so `state/` and `state/_audit/` were followed by the kernel
    // and never looked at, and a root `rm` deleted a real fortress's audit
    // write lock while every rail passed.
    //
    // The victim-survives half is asserted on EVERY platform: it is the actual
    // property, and a hardware-less machine refusing at the host rail is one
    // more way for it to hold.
    const minted = wrapper("mint", "--run-id", "good1", "--operator-account", me);
    const full = wrapperFullPath();
    if (full) {
      expectAccept(minted, "verb=mint");
      fs.symlinkSync(path.join(victim, "state"), path.join(loopDir("good1"), "state"));
    }
    const r = wrapper("clean-markers", "--run-id", "good1", "--operator-account", me);
    expect(r.status).not.toBe(0);
    expect(
      fs.existsSync(path.join(victim, "state", "_audit", ".audit-write.lock")),
      "the wrapper reached OUTSIDE the storage directory and deleted a fortress file"
    ).toBe(true);
    if (!full) return expectHostRailRefusal(r);
    expect(r.out).toContain("is a symlink");
  });

  it("clean-markers refuses a symlinked FINAL component and the fortress file SURVIVES", () => {
    const minted = wrapper("mint", "--run-id", "good1", "--operator-account", me);
    const full = wrapperFullPath();
    if (full) {
      expectAccept(minted, "verb=mint");
      fs.mkdirSync(path.join(loopDir("good1"), "state", "_audit"), { recursive: true });
      fs.symlinkSync(
        path.join(victim, "state", "_audit", ".audit-write.lock"),
        path.join(loopDir("good1"), "state", "_audit", ".audit-write.lock")
      );
    }
    const r = wrapper("clean-markers", "--run-id", "good1", "--operator-account", me);
    expect(r.status).not.toBe(0);
    expect(fs.existsSync(path.join(victim, "state", "_audit", ".audit-write.lock"))).toBe(true);
    if (!full) return expectHostRailRefusal(r);
    expect(r.out).toContain("is a symlink");
  });

  it("SURVIVES the TOCTOU race that swapped the accepted directory for a symlink", () => {
    // Codex won this in 44 attempts against the reviewed build. Note that this
    // sandbox is the WEAKER configuration: in production the base is
    // root-owned, so the racer could not create the leaf at all.
    const full = wrapperFullPath();
    if (full) {
      expectAccept(wrapper("mint", "--run-id", "race", "--operator-account", me), "verb=mint");
    }
    const dir = loopDir("race");
    const racer = spawnSync(
      "bash",
      [
        "-c",
        `for i in $(seq 1 200); do rm -rf "$1" 2>/dev/null; ln -s "$2" "$1" 2>/dev/null; rm -f "$1" 2>/dev/null; mkdir "$1" 2>/dev/null; done &
         for i in $(seq 1 40); do bash "$0" clean-markers --run-id race --operator-account "$3" >/dev/null 2>&1; done
         wait`,
        testWrapper,
        dir,
        victim,
        me,
      ],
      { encoding: "utf8", timeout: 120_000 }
    );
    expect(racer.error).toBeUndefined();
    expect(
      fs.existsSync(path.join(victim, "exclusive-routing.json")),
      "the race was won: a fortress marker outside the storage directory was deleted"
    ).toBe(true);
  });

  it("the agent-taking verbs refuse without an agent principal", () => {
    // ROUND-3 H3: the product's daemon labels are `<prefix>.<agent uid>`, and
    // `kickstart-daemons` had no `--agent-uid` in its call path at all. A verb
    // whose whole subject is one confined agent must say so rather than compose
    // a label out of an empty string.
    const full = wrapperFullPath();
    for (const verb of ["kickstart-daemons", "gate-state", "gate-log"]) {
      const r = wrapper(verb, "--run-id", "good1", "--operator-account", me);
      expect(r.status, `${verb} accepted a missing agent principal`).not.toBe(0);
      expect(r.out).not.toContain("WRAPPER=ACCEPT");
      if (full) expect(r.out).toContain("requires --agent-account and --agent-uid");
    }
  });

  it("refuses an agent account that is not on the compiled-in allowlist", () => {
    // ROUND-3 M2: `--agent-account` was the surviving caller-supplied steering
    // input, and it is the one that decides WHO root acts against. This uses
    // the wrapper carrying the SHIPPED (empty) allowlist, so the refusal is the
    // shipped behavior rather than a fixture.
    const r = wrapper(
      "arm",
      "--run-id",
      "good1",
      "--operator-account",
      me,
      "--agent-account",
      me,
      "--agent-uid",
      String(myUid)
    );
    if (!wrapperFullPath()) return expectHostRailRefusal(r);
    expect(r.status).not.toBe(0);
    expect(r.out).not.toContain("WRAPPER=ACCEPT");
    expect(r.out).toContain("not on the compiled-in drill agent allowlist");
  });

  it("kickstart-daemons reports a FAILED restart instead of printing OK over it", () => {
    // The reviewed verb ran `launchctl kickstart ... || true` and then printed
    // `WRAPPER=OK verb=kickstart-daemons` unconditionally. The kickstart IS
    // the verb's whole job, so its status is the verb's status. There is no
    // Sanctuary gate daemon on a test machine, so this must fail -- and it
    // proves the agent allowlist says YES as well as no.
    const r = agentWrapperRun(
      "kickstart-daemons",
      "--run-id",
      "good1",
      "--operator-account",
      me,
      "--agent-account",
      me,
      "--agent-uid",
      String(myUid)
    );
    if (!wrapperFullPath()) return expectHostRailRefusal(r);
    expect(r.status).not.toBe(0);
    expect(r.out).not.toContain("WRAPPER=OK verb=kickstart-daemons");
    expect(r.out).toContain("kickstart failed for");
    // ...and the labels it tried are the PRODUCT's, per confined uid (H3).
    expect(r.out).toContain(`ai.sanctuaryprotocol.egress-gate.${myUid}`);
    expect(r.out).toContain(`ai.sanctuaryprotocol.egress-gate-peer-resolver.${myUid}`);
  });

  it("pf-anchor-rules refuses when pfctl could not be run at all", () => {
    // The verb behind the pf fail-closed fix. `pfctl` needs root, and does not
    // exist on Linux at all, so a non-root run must REFUSE rather than print
    // an empty anchor and call it success. "Could not read" and "read, and it
    // was empty" have to be two different answers, or the stop-the-night check
    // is back to reporting CLEAN having observed nothing.
    const r = wrapper("pf-anchor-rules", "--run-id", "good1", "--operator-account", me);
    if (!wrapperFullPath()) return expectHostRailRefusal(r);
    expect(r.status).not.toBe(0);
    expect(r.out).not.toContain("WRAPPER=OK verb=pf-anchor-rules");
    // ...and it asks about the anchor the PRODUCT arms (H2).
    expect(r.out).toContain("could not read the pf anchor sanctuary.egress-gate");
  });

  it("arm refuses without an agent account, before touching the CLI", () => {
    const r = wrapper("arm", "--run-id", "good1", "--operator-account", me);
    if (!wrapperFullPath()) return expectHostRailRefusal(r);
    expect(r.status).not.toBe(0);
    expect(r.out).toContain("arm requires");
  });

  it("repair refuses a missing CLI rather than exec-ing whatever is there", () => {
    const r = wrapper("repair", "--run-id", "good1", "--operator-account", me);
    if (!wrapperFullPath()) return expectHostRailRefusal(r);
    expect(r.status).not.toBe(0);
    expect(r.out).toContain("CLI not found");
  });

  it("unprotect refuses a missing CLI", () => {
    const r = wrapper("unprotect", "--run-id", "good1", "--operator-account", me);
    if (!wrapperFullPath()) return expectHostRailRefusal(r);
    expect(r.status).not.toBe(0);
    expect(r.out).toContain("CLI not found");
  });

  it("EVERY verb refuses a traversal run id before doing anything", () => {
    const full = wrapperFullPath();
    for (const verb of [
      "check",
      "mint",
      "clean-markers",
      "retire",
      "gate-state",
      "kickstart-daemons",
      "arm",
      "repair",
      "unprotect",
      "pf-anchor-rules",
      "registry-state",
      "fortress-state",
      "gate-log",
    ]) {
      const r = wrapper(verb, "--run-id", "../../.sanctuary", "--operator-account", me);
      expect(r.status, `${verb} accepted a traversal run id`).not.toBe(0);
      expect(r.out, `${verb} printed ACCEPT for a traversal run id`).not.toContain("WRAPPER=ACCEPT");
      expect(r.out).toContain("WRAPPER=REJECT");
      if (full) expect(r.out).toContain("run id rejected");
    }
  });

  /**
   * THE COUNT. This is the case that makes H4 impossible to reintroduce.
   *
   * A wrapper-level case that vanishes -- deleted, renamed out of the file, or
   * turned back into a silent early `return` -- changes `wrapperCasesExecuted`
   * and this goes red. And on the platform the drill actually runs on, every
   * one of them must have taken the FULL path: forcing the hardware-less branch
   * on a Mac drops `wrapperCasesFullPath` and this goes red too.
   *
   * The reviewed suite could lose all 20 of these with the count identical at
   * 151 either way, which is precisely why `.test-baseline` could not see it.
   *
   * Vitest runs cases within a describe in declaration order, so this one runs
   * last and sees the final counters.
   */
  it("EXECUTED every wrapper-level case, and this is the count that proves it", () => {
    expect(
      wrapperCasesExecuted,
      `expected ${WRAPPER_LEVEL_CASES} wrapper-level cases to have executed; a case that ` +
        "vanishes or returns silently is the round-3 H4 defect, and the count is how it is seen"
    ).toBe(WRAPPER_LEVEL_CASES);
    if (myUid !== 0 && hasHardwareIdentity) {
      expect(
        wrapperCasesFullPath,
        "on a machine with a hardware identity EVERY wrapper case must take the full path"
      ).toBe(WRAPPER_LEVEL_CASES);
    } else {
      expect(wrapperCasesFullPath, "on a hardware-less machine no case can take the full path").toBe(
        0
      );
    }
  });
});

/**
 * The two batteries used to be different sets of cases while the README said
 * "Both run the same cases" (59 vs 52, differing in both directions). Running
 * the standalone battery FROM here makes drift between them impossible: the
 * drill host and CI execute the same file.
 */
describe("drill-loop: the standalone battery is the same battery", () => {
  it("selftest.sh passes in full", () => {
    const r = run("bash", [SELFTEST]);
    expect(r.status, r.out).toBe(0);
    expect(r.out).toMatch(/\n\d+ passed, 0 failed/);
  });
});
