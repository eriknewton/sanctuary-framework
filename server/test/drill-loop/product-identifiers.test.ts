import { describe, it, expect, beforeAll } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

import { PF_ANCHOR_NAME } from "../../src/egress-gate/pf-anchor.js";
import {
  EGRESS_GATE_DAEMON_LABEL_PREFIX,
  egressGateDaemonLabel,
  egressGateDaemonLogPaths,
  egressGateDaemonPlistPath,
  egressGateRuntimeStatePath,
  renderEgressGateDaemonPlist,
} from "../../src/egress-gate/gate-daemon.js";
import {
  PEER_RESOLVER_DAEMON_LABEL_PREFIX,
  peerResolverDaemonLabel,
  peerResolverDaemonPlistPath,
} from "../../src/egress-gate/peer-resolver-daemon.js";
import { PF_ANCHOR_REGISTRY_PATH } from "../../src/egress-gate/anchor-registry.js";
import {
  CASTLE_WALL_BOOT_LABEL,
  CASTLE_WALL_BOOT_PLIST_PATH,
  renderBootLaunchDaemonPlist,
} from "../../src/cli/castle-wall-boot.js";
import { CASTLE_SIGNER_HELPER_LABEL } from "../../src/cli/castle-wall-signer-helper.js";
import {
  GATE_ACCOUNT_NAME_PREFIX,
  deriveGateAccountName,
} from "../../src/egress-gate/gate-account.js";
import { GATE_ACCOUNT_HOME_BASE } from "../../src/egress-gate/arming-wiring.js";
import { deriveAgentAccountName } from "../../src/castle-wall/provision/account.js";
import { SYSTEM_PYTHON3_CANDIDATES } from "../../src/castle-wall/provision/harness-argv.js";
import { hermesParityPythonCandidates } from "../../src/wrap/hermes-yaml-parse-parity.js";

/**
 * THE PIN. This file is the chokepoint for the round-3 BLOCKER, and it is worth
 * being explicit about why it exists rather than a four-line diff.
 *
 * Every compiled-in identifier through which the drill-loop harness observes
 * the Sanctuary product was WRONG at once: the launchd labels, the pf anchor
 * name, the pf-anchor registry path, and the gate log path. Zero of four
 * matched. Three of the checks keyed on them read "not found" as "good", so a
 * night that ran would have printed PASS and CLEAN for three named historical
 * defect layers it never measured, and two of those three sit inside the
 * stop-the-night verify. The fourth made `kickstart-daemons` -- step 0 of every
 * iteration -- target labels that do not exist, so no iteration could complete
 * even once.
 *
 * Correcting four strings is the SYMPTOM. This is the fix: the harness's
 * constants are asserted against the product's OWN EXPORTS, imported here, so
 * the next time the product renames something this test goes red instead of the
 * harness silently resuming its lying.
 *
 * Three properties are asserted, and all three are needed:
 *
 *   1. `lib/rails.sh`'s `RAILS_PRODUCT_*` constants equal the product's exports.
 *   2. The SHIPPED ASSEMBLED ARTIFACT carries those same values, so no battery
 *      override and no unbuilt edit can fake it.
 *   3. The DRIVERS derive their identifiers from those constants and carry no
 *      hard-coded copy, because a second declaration site is exactly how four
 *      identifiers drifted at once.
 *
 * If a case here fails, the product moved and this harness has not. Follow the
 * product; never edit `lib/rails.sh` to make this file green again by hand
 * without checking what the product actually does now.
 */

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const DRILL_LOOP = path.join(REPO_ROOT, "scripts", "drill-loop");
const RAILS = path.join(DRILL_LOOP, "lib", "rails.sh");
const BUILD_WRAPPER = path.join(DRILL_LOOP, "build-wrapper.sh");
const DRIVERS = path.join(DRILL_LOOP, "drivers");

/** A representative confined-agent uid. Any positive integer would do. */
const AGENT_UID = 503;

let railsSrc: string;
let assembled: string;

/** Read a single-quoted shell constant out of a script. */
function shellConst(src: string, name: string, where: string): string {
  const m = src.match(new RegExp(`^${name}='([^']*)'`, "m"));
  expect(m, `${where} does not declare ${name} as a single-quoted constant`).not.toBeNull();
  return m![1];
}

/** Compose a value through the harness's own shell composer, as production does. */
function railsCompose(fn: string, ...args: string[]): string {
  const quoted = args.map((a) => `'${a}'`).join(" ");
  return execFileSync("bash", ["-c", `. "${RAILS}"; ${fn} ${quoted}`], {
    encoding: "utf8",
  }).trim();
}

/**
 * Run one of the harness's PURE plist readers over plist XML. The content goes
 * through the environment rather than the command line: a rendered plist is
 * arbitrary XML and single-quote splicing it into a `bash -c` string would make
 * this helper's own quoting part of what is under test.
 */
function railsPlistRead(fn: string, plistXml: string): string {
  return execFileSync("bash", ["-c", `. "${RAILS}"; ${fn} "$DRILL_TEST_PLIST"`], {
    encoding: "utf8",
    env: { ...process.env, DRILL_TEST_PLIST: plistXml },
  }).trim();
}

/** The directory the product installs a system daemon's plist into. */
const LAUNCH_DAEMONS_DIR = path.dirname(CASTLE_WALL_BOOT_PLIST_PATH);

/**
 * The signer helper's plist, as it SHIPS: inside the app bundle, registered by
 * `SMAppService`, never written to {@link LAUNCH_DAEMONS_DIR}.
 */
const SIGNER_HELPER_BUNDLE_PLIST = path.join(
  REPO_ROOT,
  "castle-wall-macos",
  "Sources",
  "CastleWallSignerHelper",
  `${CASTLE_SIGNER_HELPER_LABEL}.plist`
);

/** Non-comment lines only: these files EXPLAIN the old wrong values at length. */
const executableLines = (s: string): string =>
  s
    .split("\n")
    .filter((line) => !/^\s*#/.test(line))
    .join("\n");

beforeAll(() => {
  railsSrc = fs.readFileSync(RAILS, "utf8");
  assembled = execFileSync("bash", [BUILD_WRAPPER, "--stdout"], { encoding: "utf8" });
});

describe("drill-loop: product identifiers are pinned to the product's own exports", () => {
  it("the pf anchor name matches PF_ANCHOR_NAME", () => {
    // H2: the stop-the-night pf check asked pfctl about `com.sanctuary/egress`
    // while the product arms `sanctuary.egress-gate`. Depending on pfctl's exit
    // status for an unknown anchor that is either a false CLEAN while the real
    // anchor is armed, or a night that stops every time.
    expect(shellConst(railsSrc, "RAILS_PRODUCT_PF_ANCHOR", "lib/rails.sh")).toBe(PF_ANCHOR_NAME);
    expect(shellConst(assembled, "RAILS_PRODUCT_PF_ANCHOR", "the assembled wrapper")).toBe(
      PF_ANCHOR_NAME
    );
  });

  it("the gate daemon label prefix matches EGRESS_GATE_DAEMON_LABEL_PREFIX", () => {
    expect(shellConst(railsSrc, "RAILS_PRODUCT_GATE_LABEL_PREFIX", "lib/rails.sh")).toBe(
      EGRESS_GATE_DAEMON_LABEL_PREFIX
    );
    expect(shellConst(assembled, "RAILS_PRODUCT_GATE_LABEL_PREFIX", "the assembled wrapper")).toBe(
      EGRESS_GATE_DAEMON_LABEL_PREFIX
    );
  });

  it("the peer-resolver label prefix matches PEER_RESOLVER_DAEMON_LABEL_PREFIX", () => {
    expect(shellConst(railsSrc, "RAILS_PRODUCT_RESOLVER_LABEL_PREFIX", "lib/rails.sh")).toBe(
      PEER_RESOLVER_DAEMON_LABEL_PREFIX
    );
    expect(
      shellConst(assembled, "RAILS_PRODUCT_RESOLVER_LABEL_PREFIX", "the assembled wrapper")
    ).toBe(PEER_RESOLVER_DAEMON_LABEL_PREFIX);
  });

  it("the pf-anchor registry path matches PF_ANCHOR_REGISTRY_PATH", () => {
    // H1: the harness watched `/Library/Application Support/Sanctuary/
    // egress-gate/registry.json`, a path that appears NOWHERE in server/src.
    expect(shellConst(railsSrc, "RAILS_PRODUCT_ANCHOR_REGISTRY", "lib/rails.sh")).toBe(
      PF_ANCHOR_REGISTRY_PATH
    );
    expect(shellConst(assembled, "RAILS_PRODUCT_ANCHOR_REGISTRY", "the assembled wrapper")).toBe(
      PF_ANCHOR_REGISTRY_PATH
    );
  });

  it("the gate account home base and name prefix match the product's", () => {
    expect(shellConst(railsSrc, "RAILS_PRODUCT_GATE_HOME_BASE", "lib/rails.sh")).toBe(
      GATE_ACCOUNT_HOME_BASE
    );
    expect(shellConst(railsSrc, "RAILS_PRODUCT_AGENT_ACCOUNT_PREFIX", "lib/rails.sh")).toBe(
      "sanctuary-"
    );
    expect(shellConst(railsSrc, "RAILS_PRODUCT_GATE_ACCOUNT_PREFIX", "lib/rails.sh")).toBe(
      GATE_ACCOUNT_NAME_PREFIX
    );
    expect(shellConst(assembled, "RAILS_PRODUCT_GATE_HOME_BASE", "the assembled wrapper")).toBe(
      GATE_ACCOUNT_HOME_BASE
    );
  });

  it("derives the exact gate account from the product's agent account", () => {
    const agentId = "hermes";
    const agentAccount = deriveAgentAccountName(agentId);
    const gateAccount = deriveGateAccountName(agentId);
    expect(railsCompose("rails_product_agent_id_from_account", agentAccount)).toBe(agentId);
    expect(railsCompose("rails_product_gate_account_for_agent_account", agentAccount)).toBe(
      gateAccount
    );
    expect(railsCompose("rails_product_gate_home_for_agent_account", agentAccount)).toBe(
      path.join(GATE_ACCOUNT_HOME_BASE, gateAccount)
    );
  });

  it("COMPOSES the per-uid daemon labels exactly as the product does", () => {
    // H3, and this is the half a prefix substitution alone could never have
    // fixed: the product's labels carry a `.<agent uid>` suffix and the
    // harness's carried none, and the verb that used them had no `--agent-uid`
    // in its call path at all.
    expect(railsCompose("rails_product_gate_label", String(AGENT_UID))).toBe(
      egressGateDaemonLabel(AGENT_UID)
    );
    expect(railsCompose("rails_product_resolver_label", String(AGENT_UID))).toBe(
      peerResolverDaemonLabel(AGENT_UID)
    );
    expect(railsCompose("rails_product_daemon_labels", String(AGENT_UID))).toBe(
      `${egressGateDaemonLabel(AGENT_UID)} ${peerResolverDaemonLabel(AGENT_UID)}`
    );
  });

  it("pins the ALWAYS-INSTALLED host daemon labels to the product's exports", () => {
    // The 2026-07-25 live finding. `kickstart-daemons` restarted ONLY the
    // per-uid gate labels, which the ARM creates -- three ladder steps after
    // the kickstart -- so on a clean host it reported a failed restart of two
    // daemons that legitimately did not exist yet, and no iteration could
    // begin. The daemons that DO exist on every installed host, and that
    // therefore have to be restarted for an iteration to be measuring the dist
    // just built, are these two. They are pinned for the same reason as the
    // rest: if the product renames one, this goes red instead of the harness
    // silently restarting nothing while reporting success.
    expect(shellConst(railsSrc, "RAILS_PRODUCT_CASTLE_WALL_LABEL", "lib/rails.sh")).toBe(
      CASTLE_WALL_BOOT_LABEL
    );
    expect(shellConst(railsSrc, "RAILS_PRODUCT_SIGNER_HELPER_LABEL", "lib/rails.sh")).toBe(
      CASTLE_SIGNER_HELPER_LABEL
    );
    expect(
      shellConst(assembled, "RAILS_PRODUCT_CASTLE_WALL_LABEL", "the assembled wrapper")
    ).toBe(CASTLE_WALL_BOOT_LABEL);
    expect(
      shellConst(assembled, "RAILS_PRODUCT_SIGNER_HELPER_LABEL", "the assembled wrapper")
    ).toBe(CASTLE_SIGNER_HELPER_LABEL);
    expect(railsCompose("rails_product_host_daemon_labels")).toBe(
      `${CASTLE_WALL_BOOT_LABEL} ${CASTLE_SIGNER_HELPER_LABEL}`
    );
  });

  it("composes the PLIST PATH the product installs a daemon's job at", () => {
    // The second of the two existence signals behind the absent-versus-failed
    // distinction: a job whose plist is on disk EXISTS even when launchd has
    // not bootstrapped it, and that state has to read as "present and it would
    // not restart" rather than as the expected pre-arm absence.
    expect(railsCompose("rails_product_daemon_plist_path", CASTLE_WALL_BOOT_LABEL)).toBe(
      CASTLE_WALL_BOOT_PLIST_PATH
    );
    expect(
      railsCompose("rails_product_daemon_plist_path", egressGateDaemonLabel(AGENT_UID))
    ).toBe(egressGateDaemonPlistPath(AGENT_UID));
    expect(
      railsCompose("rails_product_daemon_plist_path", peerResolverDaemonLabel(AGENT_UID))
    ).toBe(peerResolverDaemonPlistPath(AGENT_UID));
  });

  it("PARTITIONS the host daemons by whether they HAVE a plist to screen", () => {
    // 2026-07-25 follow-on. `preflight.sh` screens plist CONTENT (D7 staleness,
    // D9 absolute program), and before the arm the only labels it screened --
    // the per-uid gate daemons -- do not exist yet, so it was choosing between
    // an unearned pass and a wrong failure over an empty input set. The
    // always-installed host daemon joins that screen so the pre-arm run measures
    // something real.
    //
    // But only ONE of the two host daemons has a plist at
    // `<LaunchDaemons>/<label>.plist`. The signer helper ships INSIDE the signed
    // app bundle and is registered by `SMAppService.daemon(plistName:)`, so on
    // every correctly installed host there is no such file -- and screening it
    // by that path would have to call a correct host either permanently broken
    // or permanently excused. Both are wrong, so the classes are declared once,
    // here, against the product's own artifacts.
    const screenable = railsCompose("rails_product_plist_screenable_host_daemon_labels");
    const bundled = railsCompose("rails_product_bundle_registered_host_daemon_labels");
    expect(screenable).toBe(CASTLE_WALL_BOOT_LABEL);
    expect(bundled).toBe(CASTLE_SIGNER_HELPER_LABEL);

    // The two classes PARTITION the host set: every host daemon is screened by
    // exactly one signal, and none is screened by neither.
    const host = railsCompose("rails_product_host_daemon_labels").split(" ").sort();
    const partitioned = [...screenable.split(" "), ...bundled.split(" ")].sort();
    expect(partitioned).toEqual(host);
    expect(new Set(partitioned).size).toBe(partitioned.length);

    // THE EVIDENCE FOR THE SPLIT, not the assertion of it. The screenable one's
    // plist path is the product's own installed path; the bundled one's plist
    // lives in the app bundle source tree, names a BUNDLE-RELATIVE
    // `BundleProgram`, and carries no ProgramArguments for a D9 screen to read.
    expect(CASTLE_WALL_BOOT_PLIST_PATH.startsWith(`${LAUNCH_DAEMONS_DIR}/`)).toBe(true);
    const bundledPlist = fs.readFileSync(SIGNER_HELPER_BUNDLE_PLIST, "utf8");
    expect(bundledPlist).toContain(`<string>${CASTLE_SIGNER_HELPER_LABEL}</string>`);
    expect(bundledPlist).toContain("<key>BundleProgram</key>");
    expect(bundledPlist).not.toContain("<key>ProgramArguments</key>");
    // And nothing in the product writes it into /Library/LaunchDaemons, which
    // is what would make the plist screen the right signal for it after all.
    expect(
      fs.existsSync(path.join(REPO_ROOT, "server", "src", "cli", "castle-wall-signer-helper.ts"))
    ).toBe(true);
    expect(
      fs.readFileSync(
        path.join(REPO_ROOT, "server", "src", "cli", "castle-wall-signer-helper.ts"),
        "utf8"
      )
    ).not.toContain(LAUNCH_DAEMONS_DIR);
  });

  it("READS THE PROGRAM out of the plist shapes the product actually renders", () => {
    // THE TRAP THAT CAME WITH THE WIDER SCREEN. `preflight.sh`'s program reader
    // was "the first absolute .js/.cjs/.mjs anywhere in the file". Every plist
    // it had ever been handed was a gate daemon's, so the reader survived. The
    // Castle Wall boot daemon renders a 5-element shape whose program is a CLI
    // SHIM with no extension at all, so adding it to the screen would have
    // swapped one false FAIL ("no plist at ...") for another ("could not read a
    // JavaScript program path out of ...").
    //
    // These assertions run the harness's reader over plists the PRODUCT
    // rendered, not over hand-written fixtures, so the day a renderer changes
    // shape this goes red rather than the screen silently misreading it.
    const shimPlist = renderBootLaunchDaemonPlist({
      programArguments: [
        "/usr/local/bin/sanctuary",
        "castle-wall",
        "daemon",
        "--safe-mode",
        "--launchd",
      ],
      fortressPath: "/var/sanctuary-drill/fortress",
      signerClientPath: "/usr/local/bin/castle-wall-signer-client",
    });
    expect(railsPlistRead("rails_plist_program", shimPlist)).toBe("/usr/local/bin/sanctuary");
    // Nothing to interpret: the shim IS the file a rebuild rewrites.
    expect(railsPlistRead("rails_plist_dist_file", shimPlist)).toBe("/usr/local/bin/sanctuary");

    const interpreterPlist = renderBootLaunchDaemonPlist({
      programArguments: [
        "/opt/homebrew/bin/node",
        "/usr/local/lib/sanctuary/dist/cli.js",
        "castle-wall",
        "daemon",
        "--safe-mode",
        "--launchd",
      ],
      fortressPath: "/var/sanctuary-drill/fortress",
      signerClientPath: "/usr/local/bin/castle-wall-signer-client",
    });
    expect(railsPlistRead("rails_plist_program", interpreterPlist)).toBe(
      "/opt/homebrew/bin/node"
    );
    // ...but D7 must stat the SCRIPT. `npm run build` never rewrites the node
    // binary, so statting the interpreter would make every stale daemon look
    // current -- the D7 defect committed by the D7 check.
    expect(railsPlistRead("rails_plist_dist_file", interpreterPlist)).toBe(
      "/usr/local/lib/sanctuary/dist/cli.js"
    );

    // The per-uid gate daemon, the plist the screen was originally written for.
    const gatePlist = renderEgressGateDaemonPlist({
      agentUid: AGENT_UID,
      gateAccount: deriveGateAccountName("hermes"),
      gateHomeDirectory: path.join(GATE_ACCOUNT_HOME_BASE, deriveGateAccountName("hermes")),
      programArguments: [
        "/opt/homebrew/bin/node",
        "/usr/local/lib/sanctuary/dist/cli.js",
        "castle-wall",
        "egress-gate-daemon",
        `--agent-uid=${AGENT_UID}`,
      ],
      fortressPath: "/var/sanctuary-drill/fortress",
    });
    expect(railsPlistRead("rails_plist_program", gatePlist)).toBe("/opt/homebrew/bin/node");
    expect(railsPlistRead("rails_plist_dist_file", gatePlist)).toBe(
      "/usr/local/lib/sanctuary/dist/cli.js"
    );

    // And the shape that must answer NOTHING rather than something relative:
    // reporting `Contents/MacOS/...` as the program would make the D9
    // absolute-program screen fail every correctly installed host.
    expect(
      railsPlistRead("rails_plist_program", fs.readFileSync(SIGNER_HELPER_BUNDLE_PLIST, "utf8"))
    ).toBe("");
  });

  it("pins the PYTHON3 CANDIDATE LIST, IN ORDER, to the product's own", () => {
    // The third copy of a bug the product fixed twice. `preflight.sh` selected
    // the FIRST EXISTING candidate and then tested only that one for PyYAML, so
    // `/usr/bin/python3` -- present on every macOS box, and on the drill host the
    // one WITHOUT PyYAML -- always won, and the 2026-07-25 live run reported
    // `/usr/bin/python3 cannot import yaml` about a host where PyYAML was
    // importable in the next candidate. First-existing is not first-capable.
    //
    // The walk itself is mirrored in bash (preflight screens the dist, so it
    // must not answer a preflight question by RUNNING the dist -- see the long
    // note at that check). What must NOT be mirrored is the LIST: a fourth
    // hand-spelled copy is how four identifiers drifted at once in round 3, so
    // the harness takes the product's own array, ORDER INCLUDED. The order is
    // load-bearing: homebrew first is what makes the drill host's capable
    // interpreter the one tried first.
    expect(shellConst(railsSrc, "RAILS_PRODUCT_PYTHON3_CANDIDATES", "lib/rails.sh")).toBe(
      SYSTEM_PYTHON3_CANDIDATES.join(" ")
    );
    expect(railsCompose("rails_product_python3_candidates")).toBe(
      SYSTEM_PYTHON3_CANDIDATES.join(" ")
    );
    // The same list the product's fail-closed Hermes parse-parity resolver
    // probes, so "what preflight screened" and "what the product will resolve"
    // cannot diverge.
    expect(hermesParityPythonCandidates()).toEqual(SYSTEM_PYTHON3_CANDIDATES);
    // Absolute-only: a bare `python3` would be PATH-resolved, and PATH is an
    // environment input.
    for (const candidate of SYSTEM_PYTHON3_CANDIDATES) {
      expect(path.isAbsolute(candidate)).toBe(true);
    }
    // And preflight composes it rather than re-spelling any of them.
    const preflightSrc = executableLines(
      fs.readFileSync(path.join(DRIVERS, "preflight.sh"), "utf8")
    );
    for (const candidate of SYSTEM_PYTHON3_CANDIDATES) {
      expect(
        preflightSrc,
        `preflight.sh spells out "${candidate}" instead of composing the candidate list`
      ).not.toContain(candidate);
    }
  });

  it("composes the GATE LOG path the product actually writes", () => {
    // M5: the probe battery tailed `<fortress>/logs/egress-gate.log`, which
    // nothing writes. The gate daemon's stdout goes to the GATE SERVICE
    // ACCOUNT's home. `P1-reason` and `N3` were therefore permanently SKIP: the
    // reason-half of the ladder -- the half that exists because a live
    // `peer_unresolved` strangle hid behind green-looking denials for a full
    // day -- was structurally dead.
    const gateAccount = deriveGateAccountName("hermes");
    const gateHome = path.join(GATE_ACCOUNT_HOME_BASE, gateAccount);
    const { stdoutPath } = egressGateDaemonLogPaths({
      agentUid: AGENT_UID,
      gateAccount,
      gateHomeDirectory: gateHome,
    });

    const base = shellConst(railsSrc, "RAILS_PRODUCT_GATE_HOME_BASE", "lib/rails.sh");
    const logDir = shellConst(railsSrc, "RAILS_PRODUCT_GATE_LOG_DIR", "lib/rails.sh");
    const harnessPath = `${base}/${railsCompose(
      "rails_product_gate_account_for_agent_account",
      deriveAgentAccountName("hermes")
    )}/${logDir}/egress-gate-${AGENT_UID}.out.log`;

    expect(harnessPath).toBe(stdoutPath);
  });

  it("composes the GATE RUNTIME STATE path the daemon actually publishes", () => {
    // ROUND-5 B1. This document is where the harness learns the port the gate
    // ACTUALLY bound. Without it no probe can be aimed at the gate, because
    // the gate is a CONNECT proxy on a per-generation loopback port and there
    // is no `rdr` redirecting anything into it; every probe in the ladder was
    // a bare `curl` that could not have traversed the gate, while printing
    // `RESULT=PASS ... through the gate`.
    //
    // The port is chosen per generation (bind-first on `127.0.0.1:0`), so this
    // path is the ONLY thing that can be compiled in. Pin it to the product's
    // own composer so a rename goes red here rather than making every
    // through-gate probe silently unobservable on the next drill night.
    const harnessPath = railsCompose("rails_product_gate_runtime_state_path", String(AGENT_UID));
    expect(harnessPath).toBe(egressGateRuntimeStatePath(AGENT_UID));
  });

  it("the arm driver's answered prompt is the prompt the PRODUCT asks", () => {
    // ROUND-5 M4, and this is a SAFETY pin rather than a correctness one.
    //
    // `arm-expect.exp` used to answer `y` to ANY text matching
    // `(?i)\(y/n\)|\[y/N\]|continue\?`, an unbounded number of times, while
    // driving a ROOT-run operation whose effects are HOST-WIDE (the pf anchor,
    // the LaunchDaemons, the gate service account). A future product prompt of
    // the shape "a gate is already armed for uid N; tear it down? (y/n)" would
    // have got an unattended yes on a machine that may be running something
    // else. It now answers exactly ONE text and hard-stops on anything else.
    //
    // The cost of that correctness is a coupling: if the product REWORDS its
    // confirmation, every unattended night stops at an unrecognised prompt.
    // That failure is loud and safe, but it should be caught here rather than
    // at 3am, so the harness's allowlisted prompt is pinned to the literal the
    // product's one confirm actually passes.
    const orchestrate = fs.readFileSync(
      path.join(REPO_ROOT, "server", "src", "castle-wall", "provision", "orchestrate.ts"),
      "utf8"
    );
    const confirms = [...orchestrate.matchAll(/ops\.confirm\(\s*"([^"]+)"/g)].map((m) => m[1]);
    expect(
      confirms,
      "the provisioning flow must ask exactly ONE confirmation; a second one is a prompt " +
        "arm-expect.exp has never seen and will (correctly) refuse to answer"
    ).toHaveLength(1);

    const armExpect = fs.readFileSync(path.join(DRILL_LOOP, "expect", "arm-expect.exp"), "utf8");
    const allow = armExpect.match(/^set expected_arm_prompt \{(.+)\}$/m);
    expect(allow, "arm-expect.exp must declare its allowlisted prompt in one named place").not.toBeNull();
    // The allowlist entry is a Tcl regex; it must MATCH the product's literal.
    expect(new RegExp(allow![1]).test(confirms[0]), 
      `arm-expect.exp allows /${allow![1]}/ but the product asks "${confirms[0]}"`).toBe(true);
    // The SPECULATIVE `type ARM to confirm` branch must stay gone too: it
    // answered a prompt that occurs nowhere in the product, and an allowlist
    // with a speculative entry is not an allowlist.
    expect(orchestrate).not.toContain("type ARM to confirm");
    expect(armExpect).not.toMatch(/type \.\?ARM\.\? to confirm\}\s*\{\s*\n\s*send "ARM/);
    // ...and the generic auto-yes branch must be gone. This is the assertion
    // that would have caught the original defect.
    expect(armExpect).not.toMatch(/-re \{\(\?i\)\\\(y\/n\\\)[^}]*\}\s*\{\s*\n\s*send "y/);
  });

  it("declares each product identifier in exactly ONE place", () => {
    // Four identifiers drifted at once, which is what a second declaration site
    // buys you. wrapper-main.sh and the drivers must reference the constants,
    // never re-spell the values.
    const wrapperMain = executableLines(
      fs.readFileSync(path.join(DRILL_LOOP, "wrapper-main.sh"), "utf8")
    );
    const launchDaemonsDir = path.dirname(CASTLE_WALL_BOOT_PLIST_PATH);
    for (const value of [
      PF_ANCHOR_NAME,
      EGRESS_GATE_DAEMON_LABEL_PREFIX,
      PEER_RESOLVER_DAEMON_LABEL_PREFIX,
      PF_ANCHOR_REGISTRY_PATH,
      GATE_ACCOUNT_HOME_BASE,
      CASTLE_WALL_BOOT_LABEL,
      CASTLE_SIGNER_HELPER_LABEL,
      launchDaemonsDir,
    ]) {
      expect(
        wrapperMain,
        `wrapper-main.sh spells out "${value}" instead of using the RAILS_PRODUCT_* constant`
      ).not.toContain(value);
    }
    for (const driver of fs.readdirSync(DRIVERS)) {
      const src = executableLines(fs.readFileSync(path.join(DRIVERS, driver), "utf8"));
      for (const value of [
        PF_ANCHOR_NAME,
        EGRESS_GATE_DAEMON_LABEL_PREFIX,
        PEER_RESOLVER_DAEMON_LABEL_PREFIX,
        PF_ANCHOR_REGISTRY_PATH,
        CASTLE_WALL_BOOT_LABEL,
        CASTLE_SIGNER_HELPER_LABEL,
        launchDaemonsDir,
      ]) {
        expect(
          src,
          `${driver} spells out "${value}" instead of composing it from the RAILS_PRODUCT_* constants`
        ).not.toContain(value);
      }
    }
  });

  it("carries NO trace of the four wrong round-3 identifiers", () => {
    // A regression guard aimed at the exact strings, because "we fixed it" and
    // "no copy of the old value survives anywhere" are different claims and
    // round 3 was lost on the difference.
    const surfaces: Array<[string, string]> = [
      ["the assembled wrapper", executableLines(assembled)],
      [
        "wrapper-main.sh",
        executableLines(fs.readFileSync(path.join(DRILL_LOOP, "wrapper-main.sh"), "utf8")),
      ],
      ...fs
        .readdirSync(DRIVERS)
        .map(
          (d) =>
            [d, executableLines(fs.readFileSync(path.join(DRIVERS, d), "utf8"))] as [string, string]
        ),
    ];
    const dead = [
      "com.sanctuary.egress-gate",
      "com.sanctuary/egress",
      "/Library/Application Support/Sanctuary/egress-gate",
      "logs/egress-gate.log",
    ];
    for (const [where, src] of surfaces) {
      for (const value of dead) {
        expect(src, `${where} still carries the round-3 wrong identifier "${value}"`).not.toContain(
          value
        );
      }
    }
  });
});
