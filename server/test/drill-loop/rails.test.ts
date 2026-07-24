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
 * The first version of that harness shipped CI-green and was then reviewed
 * UNSOUND: a REJECTED `--storage` path armed the operator's real `~/.sanctuary`
 * fortress as root. CI missed it for a structural reason worth stating plainly,
 * because it is the reason this file is shaped the way it is.
 *
 * The old tests only ever exercised HOST-REJECT-FIRST. Every case ran on a
 * machine the host rail refuses, so every case went red at the first rail and
 * NO case ever reached the path rail at all. The suite was green and the path
 * rail was untested. Coverage of the happy prefix of a gauntlet tells you
 * nothing about the rest of it.
 *
 * So the fixes here are to the coverage SHAPE, not only to the code:
 *
 *   1. The host rail is deliberately STUBBED TO PASS for the wrapper-level
 *      cases, exactly as the review prescribed, so execution reaches the path
 *      rail. The host rail's own deny-first behavior is proven separately at
 *      the rail level, where it can be driven on any machine.
 *   2. Every rejection asserts BOTH halves: a nonzero exit AND no ACCEPT token
 *      anywhere in the output. "Nonzero exit" alone would have been satisfied
 *      by a build that printed ACCEPT and failed later; "no ACCEPT" alone would
 *      have been satisfied by one that fell through silently.
 *   3. Rejections assert the REASON. Drill doctrine: a deny for the wrong
 *      reason is a fail, not a pass. Several fixtures below have more than one
 *      thing wrong with them, and a rail that rejected the symlink case because
 *      of a typo in its prefix check would look identical to one that rejected
 *      it because it refuses to follow symlinks.
 *   4. The happy path is asserted too. A rail that rejects everything is not
 *      sound, it is broken, and it would pass a suite that only checks
 *      rejections.
 *
 * Nothing here touches a real fortress. The `~/.sanctuary` denylist case and
 * the symlink-to-the-fortress case are reproduced against a FAKE `.sanctuary`
 * inside a temp home. That exercises the identical code path (final component
 * is a symlink; resolved target is a denylisted fortress name) with no way for
 * a test run to reach the operator's actual data.
 */

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const DRILL_LOOP = path.join(REPO_ROOT, "scripts", "drill-loop");
const RAILS = path.join(DRILL_LOOP, "lib", "rails.sh");
const PROBE = path.join(DRILL_LOOP, "lib", "probe.sh");
const WRAPPER_MAIN = path.join(DRILL_LOOP, "wrapper-main.sh");
const BUILD_WRAPPER = path.join(DRILL_LOOP, "build-wrapper.sh");
const SHA_FILE = path.join(DRILL_LOOP, "wrapper.sha256");

interface Ran {
  status: number;
  out: string;
}

/** Run a probe (or any command) and capture status plus merged output. */
function run(cmd: string, args: string[]): Ran {
  const r = spawnSync(cmd, args, { encoding: "utf8" });
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
let home: string;
let me: string;
let myUid: number;

beforeAll(() => {
  me = os.userInfo().username;
  myUid = typeof process.getuid === "function" ? process.getuid() : 1000;
});

beforeEach(() => {
  sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "sanctuary-drill-rails-"));
  home = path.join(sandbox, "home");
  fs.mkdirSync(home, { recursive: true });
  // A stand-in for the operator's real default fortress. The denylist and the
  // symlink cases both aim at THIS, never at the real one.
  fs.mkdirSync(path.join(home, ".sanctuary"));
  fs.mkdirSync(path.join(home, ".sanctuary-loop-good"));
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
    // The reviewed build reached `export SANCTUARY_STORAGE_PATH=""` and armed
    // it as root.
    expectReject(probe("storage", home, ""), "empty storage path");
  });

  it("rejects a MISSING storage argument at the rail's own arity check", () => {
    expectReject(probe("storage", home), "expected 2 args");
  });

  it("rejects the default fortress by denylist", () => {
    expectReject(
      probe("storage", home, path.join(home, ".sanctuary")),
      /protected fortress|default fortress directory/
    );
  });

  it("rejects a .sanctuary-loop-* SYMLINK pointing at the fortress", () => {
    // The HIGH finding. Lexical checks all pass: the basename has the right
    // prefix, the dirname is home, there is no `..`. Only an lstat catches it.
    const evil = path.join(home, ".sanctuary-loop-evil");
    fs.symlinkSync(path.join(home, ".sanctuary"), evil);
    expectReject(probe("storage", home, evil), "final component is a symlink");
  });

  it("rejects a symlink even when its target is harmless", () => {
    // The rail refuses to FOLLOW a symlink as root at all, rather than
    // reasoning about where this particular one points today.
    const benign = path.join(sandbox, "benign");
    fs.mkdirSync(benign);
    const link = path.join(home, ".sanctuary-loop-benign");
    fs.symlinkSync(benign, link);
    expectReject(probe("storage", home, link), "final component is a symlink");
  });

  it("rejects traversal back to the fortress", () => {
    expectReject(
      probe("storage", home, `${home}/.sanctuary-loop-x/../.sanctuary`),
      "relative component"
    );
  });

  it("rejects traversal with a trailing slash", () => {
    expectReject(
      probe("storage", home, `${home}/.sanctuary-loop-x/../`),
      "relative component"
    );
  });

  it("rejects a single-dot component", () => {
    expectReject(
      probe("storage", home, `${home}/./.sanctuary-loop-dot`),
      "relative component"
    );
  });

  it("rejects a path OUTSIDE home that has a valid-looking basename", () => {
    expectReject(
      probe("storage", home, path.join(sandbox, "outside", ".sanctuary-loop-outside")),
      "is not the resolved home"
    );
  });

  it("rejects a path whose PARENT is a symlink into home", () => {
    // The parent chain is resolved with `cd -P`, so a symlinked intermediate
    // cannot smuggle the path out of (or into) home.
    const elsewhere = path.join(sandbox, "elsewhere");
    fs.mkdirSync(elsewhere);
    const parentLink = path.join(sandbox, "home-alias");
    fs.symlinkSync(elsewhere, parentLink);
    expectReject(
      probe("storage", home, path.join(parentLink, ".sanctuary-loop-x")),
      "is not the resolved home"
    );
  });

  it("rejects a relative path", () => {
    expectReject(probe("storage", home, ".sanctuary-loop-rel"), "not an absolute path");
  });

  it("rejects a basename without the disposable prefix", () => {
    expectReject(
      probe("storage", home, path.join(home, "scratch")),
      "not a disposable loop fortress"
    );
  });

  it("rejects the bare prefix with no stamp", () => {
    expectReject(
      probe("storage", home, path.join(home, ".sanctuary-loop-")),
      "not a disposable loop fortress"
    );
  });

  it("rejects a basename with shell metacharacters", () => {
    expectReject(
      probe("storage", home, path.join(home, ".sanctuary-loop-a;rm -rf /")),
      "disallowed characters"
    );
  });

  it("rejects a path containing a newline", () => {
    expectReject(probe("storage", home, `${home}/.sanctuary-loop-a\nb`), "newline");
  });

  it("rejects an existing target that is a regular file", () => {
    const asFile = path.join(home, ".sanctuary-loop-file");
    fs.writeFileSync(asFile, "x");
    expectReject(probe("storage", home, asFile), "not a directory");
  });

  // The happy path. A rail that rejects everything is broken, not strict.
  it("ACCEPTS a genuine disposable fortress and prints its resolved path", () => {
    const good = path.join(home, ".sanctuary-loop-good");
    const r = probe("storage", home, good);
    expectAccept(r, "PROBE=ACCEPT");
    expect(r.out).toContain(fs.realpathSync(good));
  });

  it("ACCEPTS a valid path that does not exist yet", () => {
    expectAccept(probe("storage", home, path.join(home, ".sanctuary-loop-fresh")), "PROBE=ACCEPT");
  });

  it("ACCEPTS and canonicalizes duplicate and trailing slashes", () => {
    const r = probe("storage", home, `${home}//.sanctuary-loop-good/`);
    expectAccept(r, "PROBE=ACCEPT");
    expect(r.out).toContain(fs.realpathSync(path.join(home, ".sanctuary-loop-good")));
    expect(r.out).not.toContain("//.sanctuary");
  });
});

describe("drill-loop rails: host rail (the part that held, kept intact)", () => {
  it("rejects an unknown host, failing closed", () => {
    expectReject(probe("host", "some-random-box"), "not on the compiled-in drill-host allowlist");
  });

  it("rejects the operator's daily driver by short name", () => {
    expectReject(probe("host", "Eriks-MacBook-Air"), "un-overridable denylist");
  });

  it("rejects the daily driver however it is spelled", () => {
    expectReject(probe("host", "ERIKS-MACBOOK-AIR.local"), "un-overridable denylist");
  });

  it("rejects the daily driver even when passed as an extra 'allow' argument", () => {
    // Every name supplied is screened against the denylist; only the primary is
    // matched against the allowlist. So an extra argument can only ever cause a
    // rejection. There is deliberately no argument, flag, or environment
    // variable anywhere in this harness that can ADD a host.
    expectReject(probe("host", "agents-mac-mini", "Eriks-MacBook-Air"), "un-overridable denylist");
  });

  it("accepts a legitimate drill host", () => {
    expectAccept(probe("host", "agents-mac-mini"), "PROBE=ACCEPT");
  });

  it("exposes no environment or flag override anywhere in the shipped surface", () => {
    // The structural half of the claim above: not "we did not add one today"
    // but "there is none in the artifact that actually runs as root". Comment
    // lines are stripped, because these files explain at length WHY no override
    // exists and a scanner that cannot tell an explanation from an
    // implementation would force those explanations to be deleted.
    const assembled = execFileSync("bash", [BUILD_WRAPPER, "--stdout"], {
      encoding: "utf8",
    });
    const sudoers = fs.readFileSync(
      path.join(DRILL_LOOP, "sudoers.d", "sanctuary-drill"),
      "utf8"
    );
    const stripComments = (s: string): string =>
      s
        .split("\n")
        .filter((line) => !/^\s*#/.test(line))
        .join("\n");

    for (const forbidden of ["env_keep", "DRILL_LOOP_ALLOWED_HOSTS", "allow-host"]) {
      expect(stripComments(assembled), `assembled wrapper must not contain ${forbidden}`).not.toContain(forbidden);
      expect(stripComments(sudoers), `sudoers grant must not contain ${forbidden}`).not.toContain(forbidden);
    }
  });
});

describe("drill-loop rails: account rail (the operator-account pivot)", () => {
  it("rejects the root account by NAME", () => {
    expectReject(probe("account", "operator", "root"), "refusing the root account by name");
  });

  it("rejects an account that RESOLVES to uid 0 under another name", () => {
    // A name-only check is bypassable through an aliased uid-0 account, which
    // is why the uid half exists as its own predicate. It is driven directly
    // here because this machine has no uid-0 alias and creating one to satisfy
    // a test would be a worse idea than the test is worth. Production and this
    // test run the same function; only the source of the uid differs.
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
      // Running the suite as root is not a supported configuration for this
      // case: the current account IS root, so the rail correctly refuses it.
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
    // The LOW finding: the reviewed check inspected only the last octal digit
    // (`*[2367]`), so 0660 passed while the comment claimed group-writable was
    // refused. The mask is against 022 now.
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
    // The MED finding: `mv -> rm -rf -> mkdir` let two processes both observe
    // one stale lock and both proceed. The subtler steal it opens is worse: A
    // renames the stale lock away, B legitimately wins the fresh mkdir, and C
    // (still acting on its own earlier observation) renames B's LIVE lock away
    // and proceeds too. Reclaim now happens under its own single-winner
    // reclaim lock with the staleness facts RE-READ while holding it.
    const lock = path.join(sandbox, "loop.lock");
    fs.mkdirSync(lock);
    // A pid that is certainly dead: spawn something trivial and let it exit.
    const dead = spawnSync("bash", ["-c", "echo $$"], { encoding: "utf8" });
    const deadPid = (dead.stdout ?? "").trim();
    expect(deadPid).toMatch(/^\d+$/);
    fs.writeFileSync(path.join(lock, "pid"), `${deadPid}\n`);

    // The winner HOLDS the lock for five seconds. Without a hold this test
    // proves nothing: the first process would acquire and release faster than
    // the second could contend, and two sequential acquisitions of a free lock
    // would look like a race that never happened. (That is not hypothetical -
    // the first version of this test failed exactly that way under a loaded
    // full-suite run and passed when run alone.) The hold is also what keeps
    // the steal window open long enough for a broken reclaim to fall into it.
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
    // This is what turns "somebody edited rails.sh and forgot to rebuild" into
    // a red test rather than a wrapper whose behavior no longer matches the
    // hash that was reviewed.
    const r = run("bash", [BUILD_WRAPPER, "--verify-hash"]);
    expect(r.status, r.out).toBe(0);
    expect(r.out).toContain("wrapper hash OK");
  });

  it("the assembled wrapper is SELF-CONTAINED: it sources nothing at runtime", () => {
    // A root-run wrapper that sourced lib/rails.sh out of the operator-writable
    // repo would make any repo write a root code-execution primitive. Assembly
    // exists precisely so it does not have to.
    const assembled = execFileSync("bash", [BUILD_WRAPPER, "--stdout"], { encoding: "utf8" });
    const executable = assembled
      .split("\n")
      .filter((line) => !/^\s*#/.test(line))
      .join("\n");
    expect(executable).not.toMatch(/^\s*(\.|source)\s+/m);
    // and it really does carry the rails inline
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
      // As root the fixture IS root-owned, so assert the mode half instead.
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
 * THE REGRESSION THAT WOULD HAVE CAUGHT THE BLOCKER.
 *
 * These cases run the REAL wrapper body over the REAL rails, with the host rail
 * stubbed to PASS so execution actually reaches the path rail. That stub is the
 * whole point: without it, every case dies at the host rail and the path rail
 * is never touched, which is exactly how the unsound build stayed green.
 *
 * The composed script is the shipped `lib/rails.sh` plus the shipped
 * `wrapper-main.sh`, with two narrow overrides appended AFTER both:
 *
 *   RAILS_HOST_ALLOW / RAILS_HOST_DENY - stub the host rail to pass.
 *   wrapper_home_of - point the operator's home at a temp directory, so no
 *     case reads or writes a real home.
 *
 * `wrapper-main.sh` deliberately ends with definitions and no entrypoint;
 * build-wrapper.sh appends `wrapper_main "$@"` as the artifact's footer. That
 * is what makes this composition possible without any test-mode branch existing
 * in the shipped code.
 */
describe("drill-loop wrapper: the check oracle must not lie", () => {
  let testWrapper: string;

  beforeEach(() => {
    const hostname = execFileSync("hostname", ["-s"], { encoding: "utf8" }).trim();
    testWrapper = path.join(sandbox, "test-wrapper");

    // Start from the REAL assembled artifact, byte for byte, and inject the two
    // overrides immediately before its entrypoint line. Composing the parts by
    // hand instead would silently drop whatever the builder's header sets -
    // and the header is where `set -euo pipefail` lives, which is one of the
    // layers that stops a rail rejection from falling through. A test that
    // supplies its own header would be testing a shell configuration the
    // shipped wrapper does not necessarily have.
    const assembled = execFileSync("bash", [BUILD_WRAPPER, "--stdout"], {
      encoding: "utf8",
    });
    const entrypoint = 'wrapper_main "$@"';
    const at = assembled.lastIndexOf(entrypoint);
    expect(at, "assembled wrapper must end with the wrapper_main entrypoint").toBeGreaterThan(0);
    const overrides = [
      `RAILS_HOST_ALLOW='${hostname.toLowerCase()}'`,
      "RAILS_HOST_DENY=''",
      `wrapper_home_of() { printf '%s\\n' '${home}'; }`,
      "",
    ].join("\n");
    fs.writeFileSync(
      testWrapper,
      assembled.slice(0, at) + overrides + assembled.slice(at),
      { mode: 0o755 }
    );
  });

  function wrapper(...args: string[]): Ran {
    return run("bash", [testWrapper, ...args]);
  }

  it("prints REJECT, never ACCEPT, for a path the rails reject", () => {
    // The reviewed build printed `WRAPPER=ACCEPT storage=` here, because the
    // rail's `die` happened inside a command substitution and killed only the
    // subshell. The parent then exported an empty SANCTUARY_STORAGE_PATH, which
    // resolves to the REAL default fortress, and armed it as root.
    const r = wrapper("check", "--storage", path.join(home, ".sanctuary"), "--operator-account", me);
    expect(r.status).not.toBe(0);
    expect(r.out).not.toContain("WRAPPER=ACCEPT");
    expect(r.out).toContain("WRAPPER=REJECT");
    expect(r.out).toContain("storage rail rejected");
    // and specifically never the empty-storage fall-through
    expect(r.out).not.toMatch(/storage=\s*$/m);
  });

  it("prints REJECT for a symlinked disposable path", () => {
    const evil = path.join(home, ".sanctuary-loop-evil");
    fs.symlinkSync(path.join(home, ".sanctuary"), evil);
    const r = wrapper("check", "--storage", evil, "--operator-account", me);
    expect(r.status).not.toBe(0);
    expect(r.out).not.toContain("WRAPPER=ACCEPT");
    expect(r.out).toContain("storage rail rejected");
  });

  it("refuses an empty --storage at both layers", () => {
    const r = wrapper("check", "--storage", "", "--operator-account", me);
    expect(r.status).not.toBe(0);
    expect(r.out).not.toContain("WRAPPER=ACCEPT");
  });

  it("refuses --operator-account root before any sudo -u could happen", () => {
    // The MED finding: the reviewed build passed --operator-account straight
    // through to `sudo -u`, so `root` plus a caller-supplied URL yielded curl
    // as root.
    const r = wrapper(
      "check",
      "--storage",
      path.join(home, ".sanctuary-loop-good"),
      "--operator-account",
      "root"
    );
    expect(r.status).not.toBe(0);
    expect(r.out).not.toContain("WRAPPER=ACCEPT");
    expect(r.out).toContain("operator account rejected");
  });

  it("refuses an unknown flag rather than passing it through", () => {
    const r = wrapper(
      "check",
      "--storage",
      path.join(home, ".sanctuary-loop-good"),
      "--operator-account",
      me,
      "--danger"
    );
    expect(r.status).not.toBe(0);
    expect(r.out).toContain("unknown or unsupported argument");
  });

  it("refuses an unknown verb", () => {
    const r = wrapper("definitely-not-a-verb", "--storage", path.join(home, ".sanctuary-loop-good"), "--operator-account", me);
    expect(r.status).not.toBe(0);
    expect(r.out).toContain("unknown verb");
  });

  it("ACCEPTS a genuinely valid invocation, with a non-empty storage value", () => {
    if (myUid === 0) {
      // As root the operator rail refuses the current account, correctly.
      const r = wrapper(
        "check",
        "--storage",
        path.join(home, ".sanctuary-loop-good"),
        "--operator-account",
        me
      );
      expect(r.status).not.toBe(0);
      expect(r.out).toContain("operator account rejected");
      return;
    }
    const r = wrapper(
      "check",
      "--storage",
      path.join(home, ".sanctuary-loop-good"),
      "--operator-account",
      me
    );
    expect(r.status, r.out).toBe(0);
    expect(r.out).toContain("WRAPPER=ACCEPT");
    expect(r.out).toContain(fs.realpathSync(path.join(home, ".sanctuary-loop-good")));
    // the post-condition the reviewed build lacked
    expect(r.out).not.toMatch(/storage=\s/);
  });
});
