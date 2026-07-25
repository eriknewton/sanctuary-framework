/**
 * F-PFBOOT end-to-end recovery: the REAL `PfAnchorRegistry` over the REAL
 * `armPfAnchorUnion` / `disarmPfAnchor` / `checkPfAnchorUnionLiveness`, driven
 * against a simulated pf host that can be REBOOTED. Nothing here is a mock of
 * Sanctuary's own logic -- only `pfctl` is simulated -- so these tests exercise
 * the exact path `--repair-egress-gate`, the boot supervisor's `rearmAnchor`
 * (which calls `registry.addOrUpdate`) and `--unprotect-egress-gate` (which
 * calls `registry.remove`) take on a real machine.
 *
 * THE STATE UNDER TEST is the one the 2026-07-26 Mini1 drill produced and no
 * unit test covered: a persisted `enable_token` in the registry file over a pf
 * that is actually `Status: Disabled`, because a reboot zeroed the reference
 * the token names. On that host the drill measured, N=5 unattended reboots and
 * 0 passes:
 *   - a WRONG-ALLOW -- the confined uid's loopback confinement silently
 *     evaporated (sshd, Screen Sharing, Ollama, PostgreSQL all CONNECTED 3/3,
 *     against blocked 3/3 in the armed control on the same boot); and
 *   - NO PRODUCT PATH OUT -- arm, `--repair-egress-gate` and
 *     `--unprotect-egress-gate` were each refused, every one of them pointing
 *     at another that was deadlocked on the same missing `pfctl -E`.
 */

import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  PfAnchorRegistry,
  PF_ANCHOR_REGISTRY_STATE_VERSION,
  type PfAnchorRegistryEntry,
  type PfAnchorRegistryState,
  type PfAnchorRegistryStore,
} from "../../src/egress-gate/anchor-registry.js";
import { PF_ANCHOR_NAME, type PfCommandResult } from "../../src/egress-gate/pf-anchor.js";
import type { ProvisionLockOps } from "../../src/castle-wall/provision/lockfile.js";

const AGENT: PfAnchorRegistryEntry = {
  agent_uid: 503,
  gate_port: 49519,
  fortress_path: "/Users/agentmac/.sanctuary-s5-drill",
  generation_id: 24,
};

/** The literal token the drill watched survive five reboots while dead. */
const DRILL_STALE_TOKEN = "11053539743168208596";

/**
 * A pf host. Enough of `pfctl` to run the real arm/disarm/liveness code, plus
 * the one operation no mock in this repo had: `reboot()`.
 */
function fakePfHost(options: { rebootKeepsAnchorRules?: boolean } = {}) {
  let enabled = false;
  let anchorRules = "";
  let mainHooked = false;
  let nextToken = 1000;
  const liveTokens = new Set<string>();
  const calls: string[][] = [];

  const host = {
    calls,
    get enabled() {
      return enabled;
    },
    get anchorRules() {
      return anchorRules;
    },
    get liveTokenCount() {
      return liveTokens.size;
    },
    /** Arm out-of-band, the way the drill's first `protect` run did. */
    enablePfOutOfBand(): string {
      enabled = true;
      const token = String(nextToken++);
      liveTokens.add(token);
      return token;
    },
    /**
     * What a reboot does to pf: the enable state and EVERY reference token are
     * kernel state and are zeroed. Nothing on disk changes.
     */
    reboot(): void {
      enabled = false;
      liveTokens.clear();
      mainHooked = false;
      if (options.rebootKeepsAnchorRules !== true) anchorRules = "";
    },
    async run(command: string, args: readonly string[]): Promise<PfCommandResult> {
      calls.push([command, ...args]);
      const ok = (stdout = ""): PfCommandResult => ({ code: 0, stdout, stderr: "" });
      // pfctl -s info
      if (args[0] === "-s" && args[1] === "info") {
        return ok(
          enabled
            ? "Status: Enabled for 0 days 00:01:02           Debug: Urgent\n"
            : "Status: Disabled                              Debug: Urgent\n",
        );
      }
      // pfctl -E
      if (args[0] === "-E") {
        enabled = true;
        const token = String(nextToken++);
        liveTokens.add(token);
        return ok(`pf enabled\nToken : ${token}\n`);
      }
      // pfctl -X <token>
      if (args[0] === "-X") {
        const token = args[1] ?? "";
        if (!liveTokens.delete(token)) {
          return { code: 1, stdout: "", stderr: "pfctl: pf: token invalid" };
        }
        if (liveTokens.size === 0) enabled = false;
        return ok();
      }
      // pfctl -a <anchor> -f <file>  (load anchor rules)
      if (args[0] === "-a" && args[2] === "-f") {
        anchorRules = await readFile(args[3] ?? "", "utf8");
        return ok();
      }
      // pfctl -a <anchor> -F all  (flush anchor)
      if (args[0] === "-a" && args[2] === "-F") {
        anchorRules = "";
        return ok();
      }
      // pfctl -a <anchor> -sr  (print anchor rules)
      if (args[0] === "-a" && args[2] === "-sr") {
        return ok(anchorRules);
      }
      // pfctl -f <mainfile>  (install the main-ruleset hook)
      if (args.length === 2 && args[0] === "-f") {
        mainHooked = true;
        return ok();
      }
      // pfctl -sr  (print main ruleset)
      if (args.length === 1 && args[0] === "-sr") {
        return ok(
          mainHooked
            ? `anchor "com.apple/*" all\nanchor "${PF_ANCHOR_NAME}" on lo0 all\n`
            : 'anchor "com.apple/*" all\n',
        );
      }
      // pfctl -v -s Interfaces
      if (args[0] === "-v" && args[1] === "-s" && args[2] === "Interfaces") {
        return ok(["all", "en0", "lo0", "utun0", ""].join("\n"));
      }
      return { code: 1, stdout: "", stderr: `unscripted: ${command} ${args.join(" ")}` };
    },
  };
  return host;
}

function memStore(initial: PfAnchorRegistryState | null): PfAnchorRegistryStore & {
  current: PfAnchorRegistryState | null;
} {
  let current = initial;
  return {
    get current() {
      return current;
    },
    async load() {
      return current === null ? null : structuredClone(current);
    },
    async save(state) {
      current = structuredClone(state);
    },
  };
}

function memLock(): ProvisionLockOps {
  let held = false;
  return {
    async acquire() {
      if (held) {
        const err = new Error("EEXIST") as NodeJS.ErrnoException;
        err.code = "EEXIST";
        throw err;
      }
      held = true;
    },
    async release() {
      held = false;
    },
  };
}

async function baseConfPath(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "sanctuary-pf-recovery-"));
  const path = join(dir, "pf.conf");
  await writeFile(path, 'scrub-anchor "com.apple/*" all fragment reassemble\n', "utf8");
  return path;
}

async function makeRealRegistry(
  host: ReturnType<typeof fakePfHost>,
  initial: PfAnchorRegistryState | null,
) {
  const store = memStore(initial);
  const registry = new PfAnchorRegistry({
    store,
    lock: memLock(),
    runner: host,
    lockPath: join(tmpdir(), `sanctuary-pf-recovery-${process.pid}-${Math.random()}.lock`),
    armOptions: {
      mainConfPath: await baseConfPath(),
      settleConsecutive: 1,
      settleDelayMs: 0,
      settleTimeoutMs: 200,
      sleep: async () => {},
    },
  });
  return { registry, store };
}

/** The on-disk registry the drill photographed, verbatim in shape. */
function rebootedRegistryState(): PfAnchorRegistryState {
  return {
    version: PF_ANCHOR_REGISTRY_STATE_VERSION,
    committed: [AGENT],
    enable_token: DRILL_STALE_TOKEN,
    generation_floor: 23,
  };
}

describe("F-PFBOOT: the exclusive gate recovers from a reboot through product paths only", () => {
  for (const rebootKeepsAnchorRules of [true, false]) {
    const shape = rebootKeepsAnchorRules ? "shape A (rules loaded, inert)" : "shape B (anchor gone)";

    it(`re-arm after a reboot re-enables pf and clears the stale token -- ${shape}`, async () => {
      const host = fakePfHost({ rebootKeepsAnchorRules });
      // Arm for real, the way the first `protect --exclusive-egress` run does.
      const first = await makeRealRegistry(host, null);
      await first.registry.addOrUpdate(AGENT);
      expect(host.enabled).toBe(true);
      const armedState = structuredClone(first.store.current!);
      expect(armedState.enable_token).toBeDefined();

      // ...then reboot. The registry FILE is untouched; pf's kernel state is not.
      host.reboot();
      expect(host.enabled).toBe(false);

      // This is what the boot supervisor's `rearmAnchor` and
      // `--repair-egress-gate` both do: re-assert the committed entry.
      const after = await makeRealRegistry(host, armedState);
      const res = await after.registry.addOrUpdate(AGENT);

      // pf is enabled again, by the product, with no out-of-band `pfctl -E`.
      expect(host.enabled).toBe(true);
      expect(res.dirty).toBe(false);
      expect(res.committed.map((e) => e.agent_uid)).toEqual([503]);
      // The stale token is REPLACED, not carried forward across generations.
      expect(after.store.current?.enable_token).toBeDefined();
      expect(after.store.current?.enable_token).not.toBe(armedState.enable_token);
      // And the anchor holds the confinement rules again.
      expect(host.anchorRules).toContain("user = 503");
    });
  }

  it("re-arm from the drill's exact on-disk registry (a token five generations dead) succeeds", async () => {
    const host = fakePfHost({ rebootKeepsAnchorRules: true });
    const { registry, store } = await makeRealRegistry(host, rebootedRegistryState());

    const res = await registry.addOrUpdate(AGENT);

    expect(res.dirty).toBe(false);
    expect(host.enabled).toBe(true);
    expect(store.current?.enable_token).not.toBe(DRILL_STALE_TOKEN);
    // `pfctl -X` is never issued against the dead token: it names no reference.
    expect(host.calls.some((c) => c[1] === "-X" && c[2] === DRILL_STALE_TOKEN)).toBe(false);
  });

  it("unprotect after a reboot tears down completely, with no hand `pfctl -E`", async () => {
    // The drill's F7: `--unprotect-egress-gate` was refused post-reboot, so the
    // documented escape hatch did not exist.
    const host = fakePfHost({ rebootKeepsAnchorRules: true });
    const { registry, store } = await makeRealRegistry(host, rebootedRegistryState());

    const res = await registry.remove(503);

    expect(res.committed).toEqual([]);
    expect(res.dirty).toBe(false);
    expect(store.current?.committed).toEqual([]);
    expect(store.current?.enable_token).toBeUndefined();
    expect(host.anchorRules).toBe("");
    // No reference is left behind: teardown released what it acquired.
    expect(host.liveTokenCount).toBe(0);
    expect(host.enabled).toBe(false);
  });

  it("unprotect clears the committed entry when pf is enabled by a THIRD PARTY and our token is kernel-invalid (drill residue 7.1)", async () => {
    // Exactly the state the drill had to leave on Mini1: an operator ran
    // `sudo pfctl -E` out of band to get moving, so pf is enabled but the
    // reference belongs to that hand action, not to the token on disk. The old
    // teardown died here on `pfctl -X ... token invalid` and the `committed`
    // entry could not be removed by any product path.
    const host = fakePfHost({ rebootKeepsAnchorRules: true });
    host.reboot();
    const outOfBandToken = host.enablePfOutOfBand();
    expect(host.enabled).toBe(true);

    const { registry, store } = await makeRealRegistry(host, rebootedRegistryState());
    const res = await registry.remove(503);

    expect(res.committed).toEqual([]);
    expect(store.current?.committed).toEqual([]);
    expect(store.current?.enable_token).toBeUndefined();
    expect(host.anchorRules).toBe("");
    // The operator's OWN out-of-band reference is untouched -- teardown released
    // nothing it did not hold, and pf stays enabled for whoever else wants it.
    expect(host.enabled).toBe(true);
    expect(host.liveTokenCount).toBe(1);
    expect(outOfBandToken).toBeDefined();
  });

  it("a second reboot recovers again (the fix is not a one-shot)", async () => {
    const host = fakePfHost({ rebootKeepsAnchorRules: true });
    let state: PfAnchorRegistryState | null = null;
    for (let cycle = 0; cycle < 3; cycle += 1) {
      const { registry, store } = await makeRealRegistry(host, state);
      const res = await registry.addOrUpdate(AGENT);
      expect(res.dirty).toBe(false);
      expect(host.enabled).toBe(true);
      state = structuredClone(store.current!);
      host.reboot();
    }
    // Three arms across three boots, and no reference ever leaked: each boot
    // acquired exactly one, and the reboot zeroed it.
    expect(host.liveTokenCount).toBe(0);
  });

  it("an in-boot mutation does NOT take a second enable reference (no refcount leak)", async () => {
    const host = fakePfHost();
    const { registry } = await makeRealRegistry(host, null);
    await registry.addOrUpdate(AGENT);
    expect(host.liveTokenCount).toBe(1);
    await registry.addOrUpdate({ ...AGENT, gate_port: 49520 });
    await registry.addOrUpdate({ agent_uid: 505, gate_port: 49600, fortress_path: "/f/b" });
    // Still exactly ONE reference after three arms in one boot.
    expect(host.liveTokenCount).toBe(1);
    expect(host.calls.filter((c) => c[1] === "-E").length).toBe(1);
  });
});
