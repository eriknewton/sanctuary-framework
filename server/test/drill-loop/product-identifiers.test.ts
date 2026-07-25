import { describe, it, expect, beforeAll } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

import { PF_ANCHOR_NAME } from "../../src/egress-gate/pf-anchor.js";
import {
  EGRESS_GATE_DAEMON_LABEL_PREFIX,
  egressGateDaemonLabel,
  egressGateDaemonLogPaths,
} from "../../src/egress-gate/gate-daemon.js";
import {
  PEER_RESOLVER_DAEMON_LABEL_PREFIX,
  peerResolverDaemonLabel,
} from "../../src/egress-gate/peer-resolver-daemon.js";
import { PF_ANCHOR_REGISTRY_PATH } from "../../src/egress-gate/anchor-registry.js";
import {
  GATE_ACCOUNT_NAME_PREFIX,
  deriveGateAccountName,
} from "../../src/egress-gate/gate-account.js";
import { GATE_ACCOUNT_HOME_BASE } from "../../src/egress-gate/arming-wiring.js";
import { deriveAgentAccountName } from "../../src/castle-wall/provision/account.js";

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

  it("declares each product identifier in exactly ONE place", () => {
    // Four identifiers drifted at once, which is what a second declaration site
    // buys you. wrapper-main.sh and the drivers must reference the constants,
    // never re-spell the values.
    const wrapperMain = executableLines(
      fs.readFileSync(path.join(DRILL_LOOP, "wrapper-main.sh"), "utf8")
    );
    for (const value of [
      PF_ANCHOR_NAME,
      EGRESS_GATE_DAEMON_LABEL_PREFIX,
      PEER_RESOLVER_DAEMON_LABEL_PREFIX,
      PF_ANCHOR_REGISTRY_PATH,
      GATE_ACCOUNT_HOME_BASE,
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
