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
