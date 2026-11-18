/** Filesystem admission and the real custody boot decision share the complete initialization marker set. */
import { afterEach, expect, it, vi } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { EstablishMasterOptions } from "../../src/core/master-custody.js";

const roots: string[] = [];
afterEach(async () => { vi.doUnmock("../../src/core/custody-markers.js"); vi.resetModules(); for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true }); });

it.each(["published", "fixture"] as const)("every %s initialization key agrees with the custody first-run decision", async definition => {
  vi.resetModules();
  const store = await import("../setup/keychain-memory-store.js"); store.installInMemoryKeychainStore();
  const facts = await import("../../src/core/custody-markers.js");
  const original = { ...facts.FORTRESS_INITIALIZATION_KEYS };
  // A fixture definition exercises the consumer's dependence on the complete shared registry.
  if (definition === "fixture") {
    Object.assign(facts.FORTRESS_INITIALIZATION_KEYS, Object.fromEntries(Object.entries(original).map(([role, key]) => [role, `fixture-${key}`])));
    vi.doMock("../../src/core/custody-markers.js", () => ({
      ...facts,
      CUSTODY_ENVELOPE_KEY: facts.FORTRESS_INITIALIZATION_KEYS.envelope,
      CUSTODY_SENTINEL_KEY: facts.FORTRESS_INITIALIZATION_KEYS.sentinel,
      LEGACY_PASSPHRASE_KEY: facts.FORTRESS_INITIALIZATION_KEYS.legacyPassphrase,
      LEGACY_RECOVERY_KEY: facts.FORTRESS_INITIALIZATION_KEYS.legacyRecovery,
    }));
  }
  try {
    const { initializedFortressExists } = await import("../../src/evidence-pack/existing-fortress.js");
    const { establishMaster, ROTATION_JOURNAL_KEY, CUSTODY_ENVELOPE_COMMIT_JOURNAL_KEY } = await import("../../src/core/master-custody.js");
    const { MemoryStorage } = await import("../../src/storage/memory.js");
    const keys = Object.values(facts.FORTRESS_INITIALIZATION_KEYS);
    const nonMarkerReads = [ROTATION_JOURNAL_KEY, CUSTODY_ENVELOPE_COMMIT_JOURNAL_KEY];
    const decisions = []; let observedKeys: string[] = [];
    for (const key of [undefined, ...keys]) {
      const root = await mkdtemp(join(tmpdir(), "snapshot-marker-parity-")); roots.push(root);
      const metadata = join(root, facts.FORTRESS_STATE_DIRECTORY, "_meta"); await mkdir(metadata, { recursive: true });
      const storage = new MemoryStorage();
      if (key !== undefined) {
        const bytes = Buffer.from("synthetic custody marker");
        await writeFile(join(metadata, `${key}.enc`), bytes);
        await storage.write("_meta", key, bytes);
      }
      let firstRunReached = false;
      const options: EstablishMasterOptions = { storage, get firstRun() { firstRunReached = true; return undefined; } };
      const reads = vi.spyOn(storage, "read");
      await expect(establishMaster(options)).rejects.toThrow();
      if (key === undefined) observedKeys = [...new Set(reads.mock.calls.filter(([namespace]) => namespace === "_meta").map(([, name]) => name))].sort();
      decisions.push({ key, admitted: await initializedFortressExists(root, false), existing: !firstRunReached });
    }
    expect({ observedKeys, decisions }).toEqual({ observedKeys: [...keys, ...nonMarkerReads].sort(), decisions: [undefined, ...keys].map(key => ({ key, admitted: key !== undefined, existing: key !== undefined })) });
  } finally { Object.assign(facts.FORTRESS_INITIALIZATION_KEYS, original); }
});
