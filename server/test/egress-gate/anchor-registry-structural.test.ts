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

const SERVER_SRC = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "src");
const EGRESS_GATE_SRC = join(SERVER_SRC, "egress-gate");

// The two modules ALLOWED to own the raw single-uid arm/disarm + flush.
const OWNERS = new Set(["pf-anchor.ts", "anchor-registry.ts"]);

/** Every `.ts` under `root`, RECURSIVELY, as repo-src-relative paths. */
function typescriptFilesUnder(root: string, prefix = ""): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const rel = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
    if (entry.isDirectory()) {
      found.push(...typescriptFilesUnder(join(root, entry.name), rel));
    } else if (entry.name.endsWith(".ts")) {
      found.push(rel);
    }
  }
  return found;
}

describe("egress-gate/anchor-registry structural guard (Codex B2)", () => {
  it("no non-owner egress-gate module calls disarmPfAnchor/armPfAnchor or a bare -F flush", () => {
    const offenders: string[] = [];
    // RECURSIVE (fix-round F5): a future `egress-gate/<subdir>/` must not be a
    // blind spot in a guard whose whole job is that there is no second door.
    for (const file of typescriptFilesUnder(EGRESS_GATE_SRC)) {
      if (OWNERS.has(file)) continue;
      // The barrel re-exports symbols by name; that is not a CALL. Only flag a
      // real invocation `disarmPfAnchor(` / `armPfAnchor(` or a `-F` flush arg.
      if (file === "index.ts" || file.endsWith("/index.ts")) continue;
      const text = readFileSync(join(EGRESS_GATE_SRC, file), "utf8");
      if (/\bdisarmPfAnchor\s*\(/.test(text)) offenders.push(`${file}: calls disarmPfAnchor(`);
      if (/\barmPfAnchor\s*\(/.test(text)) offenders.push(`${file}: calls armPfAnchor(`);
      if (/["']-F["']/.test(text)) offenders.push(`${file}: uses a bare -F flush`);
    }
    expect(offenders).toEqual([]);
  });

  it("no module in server/src other than pf-enable-state.ts invokes pfctl -E or -X", () => {
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
    // anywhere in the server is a second door onto the same state, and the
    // whole point of the chokepoint is that there is no second door.
    //
    // FIX-ROUND F5 widened this in three directions, because the ratchet is the
    // load-bearing part of the design and it was narrower than its own prose:
    //   - it walked ONE directory NON-recursively, so a future
    //     `egress-gate/pf/` subdirectory would have been unscanned;
    //   - it scanned only `egress-gate/`, so the same mistake made from
    //     `castle-wall/` or `wrap/` was invisible;
    //   - its regexes matched the flag only in array position 0, so
    //     `runner.run("pfctl", ["-q", "-E"])` walked straight past it.
    //
    // STATED BOUND, so the widening is not read as more than it is: this is a
    // SOURCE-TEXT scan, and it is gated on the file mentioning `pfctl` at all
    // (which is what keeps python's unrelated `["-E", "-c", ...]` in
    // `wrap/hermes-yaml-parse-parity.ts` from being a false positive). A caller
    // that builds the flag at runtime -- `[`-${"E"}`]`, or a variable holding
    // "-E" -- is NOT caught by any regex, here or anywhere. That residual is
    // covered by review, not by this test.
    const OWNER = "egress-gate/pf-enable-state.ts";
    const offenders: string[] = [];
    for (const file of typescriptFilesUnder(SERVER_SRC)) {
      if (file === OWNER || file.endsWith("/index.ts")) continue;
      const text = readFileSync(join(SERVER_SRC, file), "utf8");
      if (!text.includes("pfctl")) continue;
      for (const [flag, label] of [
        // The flag as ANY element of an argument array, not just the first.
        [/\[[^\]\n]*["']-E["']/, "pfctl -E (acquire)"],
        [/\[[^\]\n]*["']-X["']/, "pfctl -X (release)"],
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
