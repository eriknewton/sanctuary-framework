import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defaultConfig, loadConfig } from "../../../../server/src/config.js";
import { encrypt } from "../../../../server/src/core/encryption.js";
import { stringToBytes } from "../../../../server/src/core/encoding.js";
import { derivePurposeKey } from "../../../../server/src/core/key-derivation.js";
import { generateRandomKey } from "../../../../server/src/core/random.js";
import { createDefaultProfile, SovereigntyProfileStore } from "../../../../server/src/sovereignty-profile.js";
import { MemoryStorage } from "../../../../server/src/storage/memory.js";
import { registerFixture } from "../../registry.js";
import { captureError, outcome } from "./helpers.js";

const CLAIM_ID = "7";
const CLAIM_LABEL = "Config/profile fail-closed";

// Entrypoints: loadConfig in server/src/config.ts and SovereigntyProfileStore.load in server/src/sovereignty-profile.ts.
// Mirrored tests: server/test/unit/core/config.test.ts and server/test/sovereignty-profile.test.ts.
// Matrix claim: Config/profile fail-closed.

type ConfigLikeStore = {
  name: string;
  hasCorruptionTest: boolean;
  failClosedLoad: () => Promise<boolean>;
};

function assertConfigLikeStore(store: ConfigLikeStore): void {
  if (!store.hasCorruptionTest) {
    throw new Error(`config-like store ${store.name} lacks a corruption fixture`);
  }
}

async function withTempDir<T>(prefix: string, fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), prefix));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

registerFixture(CLAIM_ID, CLAIM_LABEL, "config-profile-fail-closed: happy path", async () => {
  const started = performance.now();
  const passed = await withTempDir("sanctuary-synth-config-profile-", async (dir) => {
    const configPath = join(dir, "sanctuary.json");
    await writeFile(configPath, JSON.stringify(defaultConfig()));
    const config = await loadConfig(configPath);
    const storage = new MemoryStorage();
    const store = new SovereigntyProfileStore(storage, generateRandomKey());
    const profile = await store.load();
    const configQuarantines = (await readdir(dir)).filter((file) => file.includes(".corrupted."));
    const profileQuarantines = await storage.list("_sovereignty_profile", "active.corrupted.");
    return (
      config.version === defaultConfig().version &&
      profile.features.approval_gate.enabled === true &&
      configQuarantines.length === 0 &&
      profileQuarantines.length === 0
    );
  });
  return outcome(started, passed, "expected valid config and profile to load without quarantine");
});

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "config-profile-fail-closed: corrupted config quarantined plus fail-closed",
  async () => {
    const started = performance.now();
    const passed = await withTempDir("sanctuary-synth-config-corrupt-", async (dir) => {
      const configPath = join(dir, "malformed.json");
      await writeFile(configPath, "{ not json");
      const err = await captureError(() => loadConfig(configPath));
      const files = await readdir(dir);
      const quarantine = files.find((file) => file.startsWith("malformed.json.corrupted."));
      const quarantinedText = quarantine ? await readFile(join(dir, quarantine), "utf8") : "";
      return (
        err instanceof Error &&
        err.name === "ConfigLoadError" &&
        "classification" in err &&
        err.classification === "corrupted" &&
        quarantine !== undefined &&
        quarantinedText === "{ not json"
      );
    });
    return outcome(started, passed, "expected corrupted config quarantine and ConfigLoadError");
  }
);

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "config-profile-fail-closed: corrupted sovereignty profile preserved plus fail-closed",
  async () => {
    const started = performance.now();
    const storage = new MemoryStorage();
    const originalRaw = stringToBytes("{ truncated encrypted profile");
    await storage.write("_sovereignty_profile", "active", originalRaw);
    const store = new SovereigntyProfileStore(storage, generateRandomKey());
    const err = await captureError(() => store.load());
    const active = await storage.read("_sovereignty_profile", "active");
    const entries = await storage.list("_sovereignty_profile");
    const quarantine = entries.find((entry) => entry.key.startsWith("active.corrupted."));
    const passed =
      err instanceof Error &&
      err.name === "ProfileLoadError" &&
      "classification" in err &&
      err.classification === "corrupted" &&
      err.message.includes("The file has NOT been modified") &&
      quarantine === undefined &&
      active !== null &&
      new TextDecoder().decode(active) === new TextDecoder().decode(originalRaw);
    return outcome(started, passed, "expected corrupted profile preservation and ProfileLoadError");
  }
);

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "config-profile-fail-closed: registry guard catches new config-like store",
  async () => {
    const started = performance.now();
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const invalidProfile = {
      ...createDefaultProfile(),
      features: {
        ...createDefaultProfile().features,
        approval_gate: { enabled: false },
      },
    };
    const encrypted = encrypt(
      stringToBytes(JSON.stringify(invalidProfile)),
      derivePurposeKey(masterKey, "sovereignty-profile")
    );
    await storage.write("_sovereignty_profile", "active", stringToBytes(JSON.stringify(encrypted)));
    const store = new SovereigntyProfileStore(storage, masterKey);
    const validStore: ConfigLikeStore = {
      name: "sovereignty-profile",
      hasCorruptionTest: true,
      failClosedLoad: async () => {
        const err = await captureError(() => store.load());
        return err instanceof Error && err.name === "ProfileLoadError";
      },
    };
    const syntheticStore: ConfigLikeStore = {
      name: "future-config-like-store",
      hasCorruptionTest: false,
      failClosedLoad: async () => false,
    };
    const err = await captureError(async () => {
      assertConfigLikeStore(validStore);
      if (!(await validStore.failClosedLoad())) throw new Error("valid store did not fail closed");
      assertConfigLikeStore(syntheticStore);
    });
    const passed = err instanceof Error && /lacks a corruption fixture/.test(err.message);
    return outcome(started, passed, `expected registry guard refusal, got ${String(err)}`);
  }
);
