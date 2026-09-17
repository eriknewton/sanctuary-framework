/**
 * The install planner's PRODUCTION probe observes this vault's own wall state,
 * from this fortress.
 *
 * Why this test exists (AGENTS.md rule 4): every planner test injects the
 * observation, so a probe that returned a fixed value would leave all of them
 * green while the shipped installer never moved. That is exactly what happened:
 * the probe passed a hardcoded "arm state unknown" into the derivation, so no
 * vault could ever read as being on the wall and the planner named the same
 * re-pin action on every rerun.
 *
 * The one thing replaced here is the `castle-wall status` command itself, whose
 * real implementation shells out to `systemextensionsctl` and the installed
 * host app. Everything else is the production object graph: the real probe
 * wiring, the real at-rest claim read, the real derivation.
 *
 * Isolation: every fortress is a per-test temp directory. Nothing here reads or
 * writes the real machine-wide anchor, the operator's login keychain, or a real
 * `~/.sanctuary`.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ExclusiveEgressStatus } from "../../src/egress-gate/posture.js";

const statusScript = vi.hoisted(() => ({
  text: "",
  calls: [] as string[][],
}));

vi.mock("../../src/cli/castle-wall.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/cli/castle-wall.js")>();
  return {
    ...actual,
    // Only the command is replaced; its OUTPUT is the real verdict wording,
    // parsed by the real parser under test.
    runStatus: async (argv: string[], ctx: { out?: NodeJS.WritableStream }) => {
      statusScript.calls.push(argv);
      ctx.out?.write(statusScript.text);
      return 0;
    },
  };
});

const { createInstallOps } = await import("../../src/cli/install.js");
const { CASTLE_WALL_NOT_YET_WALLED, castleWallProvisionRecordPath } = await import(
  "../../src/castle-wall/provision-state.js"
);
const { failedExclusiveEgressStatus } = await import("../../src/egress-gate/posture.js");

// The authoritative verdict lines `reportGlobalPinAndVerdict` prints. Must match
// the constants in cli/install.ts; a drift here would make this test pass
// against a parser that no longer recognizes production wording.
const ANCHOR_CONSISTENT = "Trust anchor: CONSISTENT (global pin == signer-helper key)";
const ANCHOR_UNPROVISIONED =
  "Trust anchor: no global pin provisioned (run 'sanctuary castle-wall re-pin' to install it)";
const ENFORCEMENT_LIVE = "Enforcement availability: live";

describe("the production install probe reads THIS vault's wall state", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-install-vault-probe-"));
    statusScript.text = "";
    statusScript.calls.length = 0;
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  const probeFortress = async (
    contents: string | null,
    // Defaults to the pre-existing "no exclusive-egress evidence" behavior
    // (undefined/null = no cap) so these anchor/enforcement-focused tests stay
    // hermetic: the PRODUCTION default (no override) reaches the real S5-P
    // producer (`egress-gate/arming-wiring.ts`
    // createExclusiveEgressPostureProducer), whose registry component is a
    // single ROOT-OWNED, machine-wide file, never fortress-scoped -- exercising
    // it for real here would make these tests observe whatever fine-grained
    // agents happen to be provisioned on the host running the suite. The cap
    // itself is proven separately below via this same injection seam.
    resolveExclusiveEgress: (() => Promise<ExclusiveEgressStatus | null>) | undefined = async () =>
      null,
  ): Promise<Awaited<ReturnType<ReturnType<typeof createInstallOps>["probe"]>>> => {
    const fortress = join(tmp, `f-${statusScript.calls.length}-${Date.now()}`);
    await mkdir(join(fortress, "state", "_meta"), { recursive: true, mode: 0o700 });
    if (contents !== null) {
      await writeFile(castleWallProvisionRecordPath(fortress), contents, { mode: 0o600 });
    }
    const ops = createInstallOps({ platform: "darwin", env: {}, resolveExclusiveEgress });
    return await ops.probe({ profile: "full", harness: "claude-code", fortress });
  };

  it("asks about THIS fortress, never whatever the ambient environment points at", async () => {
    // The enforcement-availability line the arm half is derived from is
    // fortress-scoped. Reading it for a different fortress is the borrowed
    // evidence this whole state exists to close: the operator's brand new vault
    // would be reported armed because some other fortress on the box is.
    statusScript.text = `${ANCHOR_UNPROVISIONED}\n`;
    await probeFortress(CASTLE_WALL_NOT_YET_WALLED);
    expect(statusScript.calls).toHaveLength(1);
    expect(statusScript.calls[0]?.[0]).toBe("--fortress");
    expect(statusScript.calls[0]?.[1]).toContain(tmp);
  });

  it("reports the vault walled once BOTH halves are observed, so the plan can move on", async () => {
    statusScript.text = `${ANCHOR_CONSISTENT}\n${ENFORCEMENT_LIVE}\n`;
    const result = await probeFortress(CASTLE_WALL_NOT_YET_WALLED);
    expect(result.trustAnchor).toBe("consistent");
    expect(result.enforcement).toBe("live");
    expect(result.vaultProvision).toBe("walled");
  });

  it("keeps the vault off the wall while either half is missing", async () => {
    statusScript.text = `${ANCHOR_CONSISTENT}\n`;
    expect((await probeFortress(CASTLE_WALL_NOT_YET_WALLED)).vaultProvision).toBe(
      "not-yet-walled",
    );

    statusScript.text = `${ANCHOR_UNPROVISIONED}\n${ENFORCEMENT_LIVE}\n`;
    expect((await probeFortress(CASTLE_WALL_NOT_YET_WALLED)).vaultProvision).toBe(
      "not-yet-walled",
    );
  });

  it("distinguishes a claim it could not read from a fortress that makes none", async () => {
    // Both are NOT-PROVEN and neither is protection, but they are different
    // facts and the planner routes them the same way only because it must:
    // collapsing them would hide a corrupted record behind "this fortress is
    // old".
    statusScript.text = `${ANCHOR_CONSISTENT}\n`;
    expect((await probeFortress("walled")).vaultProvision).toBe("unreadable");
    expect((await probeFortress("")).vaultProvision).toBe("unreadable");
    expect((await probeFortress(null)).vaultProvision).toBe("unknown");
  });

  // Codex round-3 gate (2026-09-09): the production probe computed
  // `deriveInstallVaultProvision` without ever supplying `exclusiveEgress`, so
  // this planner could report `walled`/`complete` in exactly the scenario the
  // canonical posture (`principal-policy/posture.ts` `applyExclusiveEgress`)
  // reports as the DISTINCT non-green `coarse_only` / `not_yet_walled`: a
  // consistent anchor, live enforcement, and a fine-grained-provisioned agent
  // whose exclusive-egress stack is not live. These tests pin the fix at the
  // wiring boundary (`resolveInstallExclusiveEgressStatus` in cli/install.ts):
  // whatever the injected producer reports, the SAME cap the dashboard applies
  // must reach this planner's verdict.
  describe("wires the S5-P exclusive-egress producer into the production probe", () => {
    const LIVE_UNCAPPED: ExclusiveEgressStatus = {
      fine_grained_declared: true,
      exclusive_egress_live: true,
      mode: "exclusive",
      agents: [],
      reasons: [],
    };

    it("a fine-grained agent whose exclusive-egress stack is not live: never walled, even with a consistent anchor and live enforcement", async () => {
      statusScript.text = `${ANCHOR_CONSISTENT}\n${ENFORCEMENT_LIVE}\n`;
      const result = await probeFortress(CASTLE_WALL_NOT_YET_WALLED, async () =>
        failedExclusiveEgressStatus("test: exclusive-egress stack not live"),
      );
      expect(result.trustAnchor).toBe("consistent");
      expect(result.enforcement).toBe("live");
      expect(result.vaultProvision).not.toBe("walled");
    });

    it("a fine-grained agent whose exclusive-egress stack IS live: walled, same as the uncapped case", async () => {
      statusScript.text = `${ANCHOR_CONSISTENT}\n${ENFORCEMENT_LIVE}\n`;
      const result = await probeFortress(CASTLE_WALL_NOT_YET_WALLED, async () => LIVE_UNCAPPED);
      expect(result.vaultProvision).toBe("walled");
    });

    it("the producer throws: fails closed, never walled (must not silently read as 'no fine-grained agent')", async () => {
      statusScript.text = `${ANCHOR_CONSISTENT}\n${ENFORCEMENT_LIVE}\n`;
      const result = await probeFortress(CASTLE_WALL_NOT_YET_WALLED, async () => {
        throw new Error("gate liveness socket unreachable");
      });
      expect(result.vaultProvision).not.toBe("walled");
    });
  });
});
