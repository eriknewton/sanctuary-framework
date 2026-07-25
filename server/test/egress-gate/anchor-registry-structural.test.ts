/**
 * Structural guard (Unified Protect Slice 5 S5-1, folds Codex B2): the raw
 * shared-anchor flush must be a REGISTRY-only mutation path, not a merely
 * documented "please don't call this." Once the registry is the single source
 * of truth for the shared anchor's contents, a stray `disarmPfAnchor(...-F all)`
 * or `armPfAnchor` from any OTHER egress-gate module would flush/replace the
 * whole anchor and drop other confined uids' rules -- exactly the HIGH-4 flaw.
 *
 * This test ratchets that: no egress-gate source module other than the anchor
 * owner (`pf-anchor.ts`) and the registry (`anchor-registry.ts`) may reference
 * `disarmPfAnchor`, `armPfAnchor`, or a bare `-F` flush. It is deliberately a
 * SOURCE scan (what a unit test can honestly assert), scoped to the module
 * whose invariant this is.
 *
 * Also exercises the FS-backed registry store round-trip against a temp dir
 * (no real host state: mkdtemp under the OS temp dir, never ~/.sanctuary).
 */

import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  createFsRegistryStore,
  PfAnchorRegistryStateError,
  PF_ANCHOR_REGISTRY_STATE_VERSION,
  type PfAnchorRegistryState,
} from "../../src/egress-gate/anchor-registry.js";

const EGRESS_GATE_SRC = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "src",
  "egress-gate",
);

// The two modules ALLOWED to own the raw single-uid arm/disarm + flush.
const OWNERS = new Set(["pf-anchor.ts", "anchor-registry.ts"]);

describe("egress-gate/anchor-registry structural guard (Codex B2)", () => {
  it("no non-owner egress-gate module calls disarmPfAnchor/armPfAnchor or a bare -F flush", () => {
    const offenders: string[] = [];
    for (const file of readdirSync(EGRESS_GATE_SRC)) {
      if (!file.endsWith(".ts") || OWNERS.has(file)) continue;
      // The barrel re-exports symbols by name; that is not a CALL. Only flag a
      // real invocation `disarmPfAnchor(` / `armPfAnchor(` or a `-F` flush arg.
      if (file === "index.ts") continue;
      const text = readFileSync(join(EGRESS_GATE_SRC, file), "utf8");
      if (/\bdisarmPfAnchor\s*\(/.test(text)) offenders.push(`${file}: calls disarmPfAnchor(`);
      if (/\barmPfAnchor\s*\(/.test(text)) offenders.push(`${file}: calls armPfAnchor(`);
      if (/["']-F["']/.test(text)) offenders.push(`${file}: uses a bare -F flush`);
    }
    expect(offenders).toEqual([]);
  });

  it("no egress-gate module other than pf-enable-state.ts invokes pfctl -E or -X", () => {
    // THE ANTI-DRIFT RATCHET FOR THE ENABLE-REFERENCE CHOKEPOINT.
    //
    // The pf enable reference is volatile kernel state; the record of it is a
    // durable file. Reasoning about that asymmetry inline was got wrong at
    // three call sites in `pf-anchor.ts` and cost two HIGH wrong-allows on
    // hardware (2026-07-26 Mini1): a token that outlived the reboot that
    // zeroed it, and a global `Status: Enabled` read mistaken for evidence
    // that the reference holding pf up was ours.
    //
    // `pf-enable-state.ts` now owns acquire, resolve and release end to end.
    // This test is what keeps that true: a second `pfctl -E` or `pfctl -X`
    // anywhere else in this module is a second door onto the same state, and
    // the whole point of the chokepoint is that there is no second door.
    const OWNER = "pf-enable-state.ts";
    const offenders: string[] = [];
    for (const file of readdirSync(EGRESS_GATE_SRC)) {
      if (!file.endsWith(".ts") || file === OWNER || file === "index.ts") continue;
      const text = readFileSync(join(EGRESS_GATE_SRC, file), "utf8");
      for (const [flag, label] of [
        [/\[\s*["']-E["']/, "pfctl -E (acquire)"],
        [/\[\s*["']-X["']/, "pfctl -X (release)"],
      ] as Array<[RegExp, string]>) {
        if (flag.test(text)) offenders.push(`${file}: invokes ${label} outside ${OWNER}`);
      }
    }
    expect(offenders).toEqual([]);
  });
});

describe("egress-gate/anchor-registry FS store", () => {
  it("round-trips state and returns null when the file is absent", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-reg-"));
    try {
      const path = join(dir, "registry.json");
      const store = createFsRegistryStore(path);
      expect(await store.load()).toBeNull(); // ENOENT -> null (first run)

      const state: PfAnchorRegistryState = {
        version: PF_ANCHOR_REGISTRY_STATE_VERSION,
        committed: [{ agent_uid: 502, gate_port: 19998, fortress_path: "/f/a" }],
        enable_token: "12345",
      };
      await store.save(state);
      const loaded = await store.load();
      expect(loaded).toEqual(state);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("throws a typed state error on non-JSON registry contents", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-reg-"));
    try {
      const path = join(dir, "registry.json");
      const { writeFile } = await import("node:fs/promises");
      await writeFile(path, "not json {{{");
      const store = createFsRegistryStore(path);
      await expect(store.load()).rejects.toBeInstanceOf(PfAnchorRegistryStateError);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
