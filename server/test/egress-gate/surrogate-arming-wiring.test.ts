/**
 * Credential surrogacy slice 1a: the helper's membership in the arming twin,
 * exercised through the production functions with only their file, launchctl and
 * stat seams injected.
 *
 * Capability prose. Root arming mints one placeholder per binding per generation,
 * writes three artifacts each owned by exactly its reader, installs the helper
 * LOCKED before the resolver reload, and tears all of it down when the policy
 * stops authorizing it. Every refusal here is an arming failure, not a
 * degradation.
 *
 * WHAT THIS FILE DOES NOT REACH, stated rather than implied. `productionBringUp`
 * is module-private and every step in it mutates a root-owned path on a real
 * host, so no test may call it. The order it composes these functions in is
 * pinned by a source-order assertion at the end of this file, and the BUILD_REPORT
 * records that distinction. The functions themselves are the production ones.
 */

import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  bootstrapSurrogateHelperDaemonForBoot,
  installSurrogateHelperForBringUp,
  removeSurrogateHelperForAgent,
  resolveSurrogateBringUpPlan,
  surrogateArtifactPaths,
  verifySurrogateBindingsGenerationForCommit,
  type SurrogateArmingFsOps,
} from "../../src/egress-gate/arming-wiring.js";
import {
  surrogateHelperDaemonLabel,
  surrogateHelperDaemonPlistPath,
} from "../../src/egress-gate/surrogate-helper-daemon.js";
import { gateSurrogatePlaceholderPath } from "../../src/egress-gate/gate-credential.js";
import {
  MAX_SURROGATE_BINDINGS_PER_AGENT,
  MAX_SURROGATE_BINDINGS_PER_HOST,
  SURROGATE_BINDINGS_FILE_KIND,
  isSurrogatePlaceholder,
  parseSurrogateBindingsFile,
  parseSurrogateDestinationsFile,
  parseSurrogatePlaceholderFile,
  renderSurrogateBindingsFile,
  type MintedSurrogateBinding,
  type SurrogateBinding,
} from "../../src/credential-surrogate/index.js";

const AGENT_ID = "sanctuary-hermes";
const AGENT_UID = 601;
const GATE_UID = 602;
const OPERATOR_UID = 501;
const GENERATION = 42;

/** One valid binding. Secret and env vary so a policy can hold many. */
function binding(index: number, agent: string = AGENT_ID): SurrogateBinding {
  return {
    secret: `test-secret-${index}`,
    agent,
    env: `SANCTUARY_TEST_SURROGATE_${index}`,
    destinations: [{ host: `api${index}.example.test`, port: 443 }],
    header: "Authorization",
  };
}

/** A fortress directory holding whichever of the two policy files a case needs. */
function withFortress(
  body: (fortress: string) => Promise<void>,
): () => Promise<void> {
  return async () => {
    const dir = mkdtempSync(join(tmpdir(), "surrogate-arming-"));
    try {
      await body(dir);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };
}

function writeSurrogatePolicy(fortress: string, bindings: readonly SurrogateBinding[]): void {
  writeFileSync(
    join(fortress, "surrogate-policy.json"),
    JSON.stringify({ surrogate_policy_version: 1, bindings }),
    { mode: 0o600 },
  );
}

/** The statFn seam: production reads the fortress directory owner. */
const statOperator = async (): Promise<{ uid: number }> => ({ uid: OPERATOR_UID });

/** Recording fsOps: every write and remove, in order, with owner and mode. */
function recordingFsOps(failOn?: string): {
  ops: SurrogateArmingFsOps;
  writes: { path: string; uid: number; mode: number; content: string }[];
  removes: string[];
} {
  const writes: { path: string; uid: number; mode: number; content: string }[] = [];
  const removes: string[] = [];
  return {
    writes,
    removes,
    ops: {
      async writeFileAs(path, content, uid, mode) {
        if (failOn !== undefined && path === failOn) throw new Error("injected write failure");
        writes.push({ path, uid, mode, content });
      },
      async removeFile(path) {
        removes.push(path);
      },
    },
  };
}

/**
 * Recording launchctl that answers `print` as NOT loaded, so the reload
 * chokepoint's settle loop proves the label unloaded and then bootstraps.
 */
function recordingLaunchctl(
  overrides: Partial<Record<string, { code: number; stdout?: string; stderr?: string }>> = {},
): {
  fn: (args: readonly string[]) => Promise<{ code: number; stdout: string; stderr: string }>;
  calls: string[];
} {
  const calls: string[] = [];
  return {
    calls,
    fn: async (args) => {
      calls.push(args.join(" "));
      const verb = args[0]!;
      const override = overrides[verb];
      if (override !== undefined) {
        return { code: override.code, stdout: override.stdout ?? "", stderr: override.stderr ?? "" };
      }
      if (verb === "print") return { code: 1, stdout: "", stderr: "Could not find service" };
      if (verb === "bootout") return { code: 1, stdout: "", stderr: "Boot-out failed: 36: Operation now in progress" };
      return { code: 0, stdout: "", stderr: "" };
    },
  };
}

const noSleep = async (): Promise<void> => undefined;

// ---------------------------------------------------------------------------
// resolveSurrogateBringUpPlan: the ONE mint site
// ---------------------------------------------------------------------------

describe("resolveSurrogateBringUpPlan (the one mint site; refusals are arming failures)", () => {
  it(
    "mints one placeholder per binding for THIS generation, with dense ordinals in policy order",
    withFortress(async (fortress) => {
      writeSurrogatePolicy(fortress, [binding(0), binding(1), binding(2)]);
      const plan = await resolveSurrogateBringUpPlan({
        agentId: AGENT_ID,
        storagePath: fortress,
        generationId: GENERATION,
        statFn: statOperator,
      });
      expect(plan.kind).toBe("install");
      if (plan.kind !== "install") throw new Error("unreachable");
      expect(plan.operatorUid).toBe(OPERATOR_UID);
      expect(plan.bindings.map((b) => b.ordinal)).toEqual([0, 1, 2]);
      expect(plan.bindings.map((b) => b.secret)).toEqual([
        "test-secret-0",
        "test-secret-1",
        "test-secret-2",
      ]);
      for (const b of plan.bindings) expect(isSurrogatePlaceholder(b.placeholder)).toBe(true);
      // One per binding, never one shared: a shared placeholder would let a
      // request bound for one destination be answered with another's value.
      expect(new Set(plan.bindings.map((b) => b.placeholder)).size).toBe(3);
    }),
  );

  it(
    "mints FRESH placeholders on every call, so a placeholder is never derivable from the generation",
    withFortress(async (fortress) => {
      writeSurrogatePolicy(fortress, [binding(0)]);
      const args = {
        agentId: AGENT_ID,
        storagePath: fortress,
        generationId: GENERATION,
        statFn: statOperator,
      };
      const first = await resolveSurrogateBringUpPlan(args);
      const second = await resolveSurrogateBringUpPlan(args);
      if (first.kind !== "install" || second.kind !== "install") throw new Error("unreachable");
      // Same generation, same policy, different placeholder: an agent that saw
      // one generation's placeholder learns nothing about the next.
      expect(first.bindings[0]!.placeholder).not.toBe(second.bindings[0]!.placeholder);
    }),
  );

  it(
    "yields `none` for an absent policy file, and for a policy that names only OTHER agents",
    withFortress(async (fortress) => {
      expect(
        (
          await resolveSurrogateBringUpPlan({
            agentId: AGENT_ID,
            storagePath: fortress,
            generationId: GENERATION,
            statFn: statOperator,
          })
        ).kind,
      ).toBe("none");

      writeSurrogatePolicy(fortress, [binding(0, "sanctuary-other")]);
      expect(
        (
          await resolveSurrogateBringUpPlan({
            agentId: AGENT_ID,
            storagePath: fortress,
            generationId: GENERATION,
            statFn: statOperator,
          })
        ).kind,
      ).toBe("none");
    }),
  );

  it(
    "REFUSES TO ARM on a present-and-broken policy, naming a fixed failure class and never the parser's text",
    withFortress(async (fortress) => {
      // Valid JSON, invalid document: the ENOENT split's "present and broken"
      // half. An absent file is the normal case and must not look like this.
      writeFileSync(
        join(fortress, "surrogate-policy.json"),
        JSON.stringify({ surrogate_policy_version: 1, bindings: [{ secret: "s" }] }),
      );
      await expect(
        resolveSurrogateBringUpPlan({
          agentId: AGENT_ID,
          storagePath: fortress,
          generationId: GENERATION,
          statFn: statOperator,
        }),
      ).rejects.toThrow(/surrogate policy present and unusable \(schema_error\); refusing to arm/);
    }),
  );

  it(
    "REFUSES TO ARM when a bound secret also carries a broker read grant (the conflict rule)",
    withFortress(async (fortress) => {
      writeSurrogatePolicy(fortress, [binding(0), binding(1)]);
      // The real broker document shape: skills[].secrets[]. Written directly
      // rather than through `saveBrokerPolicy` so this case stays a pure read of
      // what an operator (or an older writer) left on disk.
      writeFileSync(
        join(fortress, "broker-policy.json"),
        JSON.stringify({
          skills: [{ name: "some-skill", secrets: [{ name: "test-secret-1", scope: "read" }] }],
        }),
        { mode: 0o600 },
      );
      await expect(
        resolveSurrogateBringUpPlan({
          agentId: AGENT_ID,
          storagePath: fortress,
          generationId: GENERATION,
          statFn: statOperator,
        }),
      ).rejects.toThrow(/refusing to arm: 1 secret\(s\) are bound as surrogates AND carry a broker/);
    }),
  );
});

// ---------------------------------------------------------------------------
// rule 8: the binding table is capped where it is built
// ---------------------------------------------------------------------------

describe("surrogate binding table caps (AGENTS.md rule 8: capped, replaced whole, never grown from input)", () => {
  it(
    `REFUSES TO ARM at MAX_SURROGATE_BINDINGS_PER_AGENT + 1 (${MAX_SURROGATE_BINDINGS_PER_AGENT + 1}) bindings for one agent`,
    withFortress(async (fortress) => {
      const over = Array.from({ length: MAX_SURROGATE_BINDINGS_PER_AGENT + 1 }, (_u, i) => binding(i));
      writeSurrogatePolicy(fortress, over);
      // The per-AGENT cap is the PARSER's, so the arming refusal arrives as a
      // present-and-unusable policy rather than as its own message.
      await expect(
        resolveSurrogateBringUpPlan({
          agentId: AGENT_ID,
          storagePath: fortress,
          generationId: GENERATION,
          statFn: statOperator,
        }),
      ).rejects.toThrow(/present and unusable \(schema_error\)/);

      // ...and exactly at the cap it arms, so the bound is the cap and not an
      // unrelated failure.
      writeSurrogatePolicy(fortress, over.slice(0, MAX_SURROGATE_BINDINGS_PER_AGENT));
      const plan = await resolveSurrogateBringUpPlan({
        agentId: AGENT_ID,
        storagePath: fortress,
        generationId: GENERATION,
        statFn: statOperator,
      });
      if (plan.kind !== "install") throw new Error("unreachable");
      expect(plan.bindings).toHaveLength(MAX_SURROGATE_BINDINGS_PER_AGENT);
    }),
  );

  it(
    `REFUSES TO ARM at MAX_SURROGATE_BINDINGS_PER_HOST + 1 (${MAX_SURROGATE_BINDINGS_PER_HOST + 1}) bindings across all agents`,
    withFortress(async (fortress) => {
      // Spread across agents so every per-AGENT cap is satisfied: the ONLY thing
      // wrong with this policy is its total size, which is why the per-host cap
      // has to live at root arming, the one place that sees every agent at once.
      const perAgent = MAX_SURROGATE_BINDINGS_PER_AGENT;
      const total = MAX_SURROGATE_BINDINGS_PER_HOST + 1;
      const bindings = Array.from({ length: total }, (_u, i) =>
        binding(i, `sanctuary-agent-${Math.floor(i / perAgent)}`),
      );
      writeSurrogatePolicy(fortress, bindings);
      await expect(
        resolveSurrogateBringUpPlan({
          agentId: "sanctuary-agent-0",
          storagePath: fortress,
          generationId: GENERATION,
          statFn: statOperator,
        }),
      ).rejects.toThrow(
        new RegExp(
          `surrogate policy declares ${total} bindings, over the host ceiling of ${MAX_SURROGATE_BINDINGS_PER_HOST}`,
        ),
      );
    }),
  );
});

// ---------------------------------------------------------------------------
// installSurrogateHelperForBringUp: three artifacts, three owners, then reload
// ---------------------------------------------------------------------------

describe("installSurrogateHelperForBringUp (wired consumer: three artifacts, each owned by exactly its reader)", () => {
  function minted(count: number): MintedSurrogateBinding[] {
    return Array.from({ length: count }, (_u, i) => ({
      ...binding(i),
      ordinal: i,
      placeholder: `sanctuary_surrogate_${i.toString(16).padStart(32, "0")}`,
    }));
  }

  async function install(
    fsOps: SurrogateArmingFsOps,
    launchctl: (args: readonly string[]) => Promise<{ code: number; stdout: string; stderr: string }>,
    bindings: MintedSurrogateBinding[] = minted(2),
  ): Promise<void> {
    await installSurrogateHelperForBringUp({
      agentUid: AGENT_UID,
      gateUid: GATE_UID,
      operatorUid: OPERATOR_UID,
      generationId: GENERATION,
      bindings,
      fortressPath: "/Users/operator/.sanctuary",
      gateDaemonArgvPrefix: ["/usr/local/bin/node", "/opt/sanctuary/cli.js"],
      fsOps,
      runLaunchctlFn: launchctl,
      sleepMs: noSleep,
    });
  }

  it("writes bindings (root), destinations (gate), placeholders (agent) LAST, then the plist, then reloads", async () => {
    const fs = recordingFsOps();
    const lc = recordingLaunchctl();
    await install(fs.ops, lc.fn);

    const paths = surrogateArtifactPaths(AGENT_UID);
    expect(fs.writes.map((w) => w.path)).toEqual([
      paths.bindings,
      paths.destinations,
      paths.placeholders,
      paths.plist,
    ]);
    // Each file owned by exactly its reader. The agent's own placeholder file is
    // written LAST: a placeholder the agent holds before the helper's table
    // knows it is a placeholder that resolves to nothing.
    expect(fs.writes.map((w) => [w.uid, w.mode])).toEqual([
      [0, 0o600],
      [GATE_UID, 0o600],
      [AGENT_UID, 0o600],
      [0, 0o644],
    ]);
    // The reload runs AFTER every write, so the helper never loads a table that
    // is only half on disk.
    expect(lc.calls.some((c) => c === `bootstrap system ${paths.plist}`)).toBe(true);
    // The chokepoint has already booted the label out and settled until it was
    // reaped, so the final kickstart needs no `-k`: there is nothing running to
    // replace. The sequence, not the flag, is what makes the reload effective.
    expect(lc.calls.at(-1)).toBe(`kickstart system/${surrogateHelperDaemonLabel(AGENT_UID)}`);
    expect(lc.calls[0]).toBe(`bootout system/${surrogateHelperDaemonLabel(AGENT_UID)}`);
  });

  it("gives each reader ONLY what it is entitled to: the gate learns destinations, the agent learns names", async () => {
    const fs = recordingFsOps();
    const bindings = minted(2);
    await install(fs.ops, recordingLaunchctl().fn, bindings);
    const byPath = new Map(fs.writes.map((w) => [w.path, w.content]));
    const paths = surrogateArtifactPaths(AGENT_UID);

    // The agent's file: names and placeholders, nothing else.
    const placeholders = parseSurrogatePlaceholderFile(byPath.get(paths.placeholders)!);
    expect(placeholders.generationId).toBe(GENERATION);
    expect(placeholders.entries).toEqual(
      bindings.map((b) => ({ env: b.env, placeholder: b.placeholder })),
    );
    for (const b of bindings) {
      expect(byPath.get(paths.placeholders)).not.toContain(b.secret);
      expect(byPath.get(paths.placeholders)).not.toContain(b.destinations[0]!.host);
      expect(byPath.get(paths.placeholders)).not.toContain(b.header);
    }

    // The gate's file: destinations, and not a secret name, env name or header.
    const destinations = parseSurrogateDestinationsFile(byPath.get(paths.destinations)!);
    expect(destinations.generationId).toBe(GENERATION);
    expect(destinations.destinations).toHaveLength(2);
    for (const b of bindings) {
      expect(byPath.get(paths.destinations)).not.toContain(b.secret);
      expect(byPath.get(paths.destinations)).not.toContain(b.env);
      expect(byPath.get(paths.destinations)).not.toContain(b.placeholder);
    }

    // Root's file: the whole table, and it round-trips.
    const parsed = parseSurrogateBindingsFile(byPath.get(paths.bindings)!);
    expect(parsed.generationId).toBe(GENERATION);
    expect(parsed.bindings.map((b) => b.placeholder)).toEqual(bindings.map((b) => b.placeholder));
  });

  it("renders a helper plist that starts LOCKED, never at load, and can never write a core file", async () => {
    const fs = recordingFsOps();
    await install(fs.ops, recordingLaunchctl().fn);
    const plist = fs.writes.find((w) => w.path === surrogateHelperDaemonPlistPath(AGENT_UID))!.content;
    expect(plist).toContain("<key>RunAtLoad</key>");
    expect(plist).toMatch(/<key>RunAtLoad<\/key>\s*<false\/>/);
    // Both limit dictionaries, so no process that holds a value can dump one.
    expect(plist).toMatch(/<key>HardResourceLimits<\/key>[\s\S]*?<key>Core<\/key>\s*<integer>0<\/integer>/);
    expect(plist).toMatch(/<key>SoftResourceLimits<\/key>[\s\S]*?<key>Core<\/key>\s*<integer>0<\/integer>/);
    // The generation is in argv, so a helper whose plist outlived its table
    // refuses to start rather than serving it.
    expect(plist).toContain(`--generation=${GENERATION}`);
    expect(plist).toContain(`--agent-uid=${AGENT_UID}`);
    expect(plist).toContain(`--gate-uid=${GATE_UID}`);
    expect(plist).toContain(`--operator-uid=${OPERATOR_UID}`);
  });

  it("THROWS on a reload failure, so a bring-up never continues past a helper that did not load", async () => {
    const fs = recordingFsOps();
    const lc = recordingLaunchctl({ bootstrap: { code: 5, stderr: "Load failed" } });
    await expect(install(fs.ops, lc.fn)).rejects.toThrow(/exited 5/);
  });

  it("THROWS when an artifact write fails, before any later artifact is written", async () => {
    const paths = surrogateArtifactPaths(AGENT_UID);
    const fs = recordingFsOps(paths.destinations);
    await expect(install(fs.ops, recordingLaunchctl().fn)).rejects.toThrow(/injected write failure/);
    // The agent-readable placeholder file was never written, so the agent never
    // holds a placeholder for a table that does not exist.
    expect(fs.writes.map((w) => w.path)).toEqual([paths.bindings]);
  });
});

// ---------------------------------------------------------------------------
// removeSurrogateHelperForAgent: the one teardown every path shares
// ---------------------------------------------------------------------------

describe("removeSurrogateHelperForAgent (one bootout-and-delete; a forgotten path is a file that survives unprotect)", () => {
  it("boots the helper out and removes the plist and all three artifacts", async () => {
    const fs = recordingFsOps();
    const lc = recordingLaunchctl({ bootout: { code: 0 } });
    await removeSurrogateHelperForAgent({
      agentUid: AGENT_UID,
      runLaunchctlFn: lc.fn,
      fsOps: fs.ops,
      context: "test teardown",
    });
    const paths = surrogateArtifactPaths(AGENT_UID);
    expect(lc.calls).toEqual([`bootout system/${surrogateHelperDaemonLabel(AGENT_UID)}`]);
    expect(fs.removes).toEqual([
      paths.plist,
      paths.bindings,
      paths.destinations,
      paths.placeholders,
    ]);
    // The placeholder path is the agent-readable one; it must be in the set.
    expect(fs.removes).toContain(gateSurrogatePlaceholderPath(AGENT_UID));
  });

  it("still removes every artifact when the helper was never loaded (a fortress that never used surrogacy)", async () => {
    const fs = recordingFsOps();
    // Exit 3 is one of the not-loaded classes `launchctlBootoutWasNotLoaded`
    // tolerates. "Nothing to stop" must reach the SAME complete teardown as a
    // successful bootout, or a fortress that turned surrogacy off between arms
    // would keep a stale table and a stale plist forever.
    const lc = recordingLaunchctl({
      bootout: { code: 3, stderr: "Could not find service in domain" },
    });
    await expect(
      removeSurrogateHelperForAgent({
        agentUid: AGENT_UID,
        runLaunchctlFn: lc.fn,
        fsOps: fs.ops,
        context: "test teardown",
      }),
    ).resolves.toBeUndefined();
    const paths = surrogateArtifactPaths(AGENT_UID);
    expect(fs.removes).toEqual([
      paths.plist,
      paths.bindings,
      paths.destinations,
      paths.placeholders,
    ]);
  });

  it("THROWS rather than delete the table when the helper cannot be stopped", async () => {
    const fs = recordingFsOps();
    const lc = recordingLaunchctl({ bootout: { code: 1, stderr: "Operation not permitted" } });
    await expect(
      removeSurrogateHelperForAgent({
        agentUid: AGENT_UID,
        runLaunchctlFn: lc.fn,
        fsOps: fs.ops,
        context: "unprotect",
      }),
    ).rejects.toThrow(/refusing to continue with a root process that may still be holding credential values/);
    expect(fs.removes).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// bootstrapSurrogateHelperDaemonForBoot: only when a table exists, never mints
// ---------------------------------------------------------------------------

describe("bootstrapSurrogateHelperDaemonForBoot (boot path: only with a table, never a mint, skip when running)", () => {
  it("starts NOTHING when the agent has no bindings file", async () => {
    const lc = recordingLaunchctl();
    await bootstrapSurrogateHelperDaemonForBoot({
      agentUid: AGENT_UID,
      runLaunchctlFn: lc.fn,
      bindingsPresent: async () => false,
      sleepMs: noSleep,
    });
    // Not even a status probe: bootstrapping a label whose plist is absent would
    // turn "this agent never used surrogacy" into a loud boot failure.
    expect(lc.calls).toEqual([]);
  });

  it("reloads the helper when a bindings file exists and the label is not running", async () => {
    const lc = recordingLaunchctl();
    await bootstrapSurrogateHelperDaemonForBoot({
      agentUid: AGENT_UID,
      runLaunchctlFn: lc.fn,
      bindingsPresent: async () => true,
      sleepMs: noSleep,
    });
    expect(lc.calls[0]).toBe(`print system/${surrogateHelperDaemonLabel(AGENT_UID)}`);
    expect(lc.calls.some((c) => c === `bootstrap system ${surrogateHelperDaemonPlistPath(AGENT_UID)}`)).toBe(true);
  });

  it("SKIPS a helper that is already running, so a boot self-heal never drops its unlocked values", async () => {
    const label = surrogateHelperDaemonLabel(AGENT_UID);
    const lc = recordingLaunchctl({
      print: { code: 0, stdout: `system/${label} = {\n\tpid = 4242\n\tstate = running\n}\n` },
    });
    await bootstrapSurrogateHelperDaemonForBoot({
      agentUid: AGENT_UID,
      runLaunchctlFn: lc.fn,
      bindingsPresent: async () => true,
      sleepMs: noSleep,
    });
    expect(lc.calls).toEqual([`print system/${label}`]);
  });
});

// ---------------------------------------------------------------------------
// verifySurrogateBindingsGenerationForCommit: verify only, never allocate
// ---------------------------------------------------------------------------

describe("verifySurrogateBindingsGenerationForCommit (release commit VERIFIES the table's generation as root)", () => {
  function table(generationId: number): string {
    return renderSurrogateBindingsFile(generationId, [
      { ...binding(0), ordinal: 0, placeholder: `sanctuary_surrogate_${"0".repeat(32)}` },
    ]);
  }

  it("passes when the table on disk names the generation being committed", async () => {
    await expect(
      verifySurrogateBindingsGenerationForCommit({
        agentUid: AGENT_UID,
        generationId: GENERATION,
        readBindingsHeader: async () => table(GENERATION),
      }),
    ).resolves.toBeUndefined();
  });

  it("passes when there is no table at all (an agent with no bindings commits normally)", async () => {
    await expect(
      verifySurrogateBindingsGenerationForCommit({
        agentUid: AGENT_UID,
        generationId: GENERATION,
        readBindingsHeader: async () => null,
      }),
    ).resolves.toBeUndefined();
  });

  it("THROWS (loud park) on a stale table, and never rewrites or re-mints it", async () => {
    await expect(
      verifySurrogateBindingsGenerationForCommit({
        agentUid: AGENT_UID,
        generationId: GENERATION,
        readBindingsHeader: async () => table(GENERATION - 1),
      }),
    ).rejects.toThrow(
      new RegExp(`names generation ${GENERATION - 1}, but generation ${GENERATION} is being committed`),
    );
  });

  it("THROWS on a table nobody can parse, rather than releasing over it", async () => {
    await expect(
      verifySurrogateBindingsGenerationForCommit({
        agentUid: AGENT_UID,
        generationId: GENERATION,
        readBindingsHeader: async () => "not a surrogate artifact at all\n",
      }),
    ).rejects.toThrow(/is unreadable; refusing to release/);
  });

  it("reads the BINDINGS kind, so a file that landed at the wrong path is refused not parsed", async () => {
    // Same version, same generation, wrong kind token: this is the file the gate
    // uid may read, and accepting it here would be accepting a header from a
    // file with a different reader.
    const wrongKind = table(GENERATION).replace(SURROGATE_BINDINGS_FILE_KIND, "sanctuary-surrogate-destinations");
    await expect(
      verifySurrogateBindingsGenerationForCommit({
        agentUid: AGENT_UID,
        generationId: GENERATION,
        readBindingsHeader: async () => wrongKind,
      }),
    ).rejects.toThrow(/is unreadable; refusing to release/);
  });
});

// ---------------------------------------------------------------------------
// The order productionBringUp composes these in (source-order pin)
// ---------------------------------------------------------------------------

describe("productionBringUp composition order (source-order pin; the function itself mutates root-owned paths)", () => {
  /**
   * `productionBringUp` is module-private and every step in it writes under
   * /var/db/sanctuary or /Library, so no test may run it. This reads its source
   * and pins the ORDER design 3.4.1 requires. It is a weaker witness than a
   * runtime test and the BUILD_REPORT says so; it is still the only thing that
   * catches a future edit moving the helper install after the resolver reload.
   */
  const source = readFileSync(
    new URL("../../src/egress-gate/arming-wiring.ts", import.meta.url),
    "utf8",
  );
  const body = (() => {
    const start = source.indexOf("async function productionBringUp(");
    expect(start).toBeGreaterThan(0);
    const end = source.indexOf("\n}\n", start);
    expect(end).toBeGreaterThan(start);
    return source.slice(start, end);
  })();

  it("mints placeholders immediately after the bearer credential mint", () => {
    const bearerMint = body.indexOf("credAuthority.mint(");
    const surrogatePlan = body.indexOf("resolveSurrogateBringUpPlan(");
    expect(bearerMint).toBeGreaterThan(0);
    expect(surrogatePlan).toBeGreaterThan(bearerMint);
    // From the SAME committed generation as the bearer credential.
    expect(body).toContain("generationId: committed.generation_id");
  });

  it("installs the helper BEFORE the resolver reload, so the query socket exists before the gate serves", () => {
    const install = body.indexOf("installSurrogateHelperForBringUp(");
    const resolverReload = body.indexOf("reloadPeerResolverDaemonForBringUp(");
    expect(install).toBeGreaterThan(0);
    expect(resolverReload).toBeGreaterThan(install);
  });

  it("takes the no-bindings branch to a full teardown, not to a no-op", () => {
    const remove = body.indexOf("removeSurrogateHelperForAgent(");
    const resolverReload = body.indexOf("reloadPeerResolverDaemonForBringUp(");
    expect(remove).toBeGreaterThan(0);
    expect(remove).toBeLessThan(resolverReload);
    expect(body).toContain('context: "bring-up with no surrogate bindings"');
  });

  it("is the ONLY mint site in src/: no other module calls mintSurrogatePlaceholder", () => {
    // Design 3.2. A second mint site would hand the agent a placeholder the
    // helper's table has never heard of.
    const armingCalls = source.match(/mintSurrogatePlaceholder\(/g) ?? [];
    expect(armingCalls).toHaveLength(1);
    expect(body).not.toContain("mintSurrogatePlaceholder(");
    // ...and the call is inside resolveSurrogateBringUpPlan, which productionBringUp
    // reaches, rather than inline in the bring-up.
    const resolver = source.slice(
      source.indexOf("export async function resolveSurrogateBringUpPlan("),
      source.indexOf("export interface SurrogateArmingFsOps"),
    );
    expect(resolver).toContain("mintSurrogatePlaceholder()");
  });
});
