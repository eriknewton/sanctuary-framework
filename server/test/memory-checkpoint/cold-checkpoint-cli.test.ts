/**
 * Checkpoint commands capture durable state across restarts.
 * LEGACY-BUG-001
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { runCheckpointCommand } from "../../src/cli/checkpoint.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import { bytesToString, fromBase64url } from "../../src/core/encoding.js";
import { resolveCliMasterKey } from "../../src/core/master-custody.js";
import { MemoryCheckpointStore } from "../../src/memory-checkpoint/index.js";
import { persistStoredIdentity } from "../util/persist-stored-identity.js";

// Only host custody and host liveness are replaced; CLI composition, encrypted
// filesystem state, namespace discovery, snapshotting are real.
vi.mock("../../src/core/master-custody.js", async (original) => ({
  ...await original<typeof import("../../src/core/master-custody.js")>(),
  resolveCliMasterKey: vi.fn(),
}));
vi.mock("../../src/egress-gate/parked-claim.js", async (original) => ({
  ...await original<typeof import("../../src/egress-gate/parked-claim.js")>(),
  assessHarnessParked: vi.fn(),
}));
vi.mock("../../src/egress-gate/harness-daemon.js", async (original) => ({
  ...await original<typeof import("../../src/egress-gate/harness-daemon.js")>(),
  AGENT_HARNESS_DAEMON_PLIST_PATH: "/nonexistent-cold-checkpoint-test/harness.plist",
}));

const tempDirs: string[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  for (const path of tempDirs.splice(0)) await rm(path, { recursive: true, force: true });
});

function capture() {
  let text = "";
  const stream = new Writable({ write(chunk, _encoding, done) { text += chunk.toString(); done(); } });
  return { stream, text: () => text };
}

async function fixture() {
  const path = await mkdtemp(join(tmpdir(), "cold-checkpoint-"));
  tempDirs.push(path);
  vi.stubEnv("SANCTUARY_STORAGE_PATH", path);
  const masterKey = generateRandomKey();
  vi.mocked(resolveCliMasterKey).mockResolvedValue(masterKey);
  const storage = new FilesystemStorage(join(path, "state"));
  const stateStore = new StateStore(storage, masterKey);
  const encKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity: identity } = createIdentity("checkpoint", encKey, "recovery-key");
  await persistStoredIdentity(storage, masterKey, identity);
  const write = (ns: string, value: string) => stateStore.write(
    ns, "note", value, identity.identity_id, identity.encrypted_private_key, encKey,
  );
  await write("alpha", "original");
  await write("beta", "original");
  const checkpoints = new MemoryCheckpointStore({ fortressPath: path });
  const call = async (argv: string[]) => {
    const out = capture();
    const err = capture();
    const code = await runCheckpointCommand({
      argv: [...argv, "--fortress", path], out: out.stream, err: err.stream,
      env: { SANCTUARY_PASSPHRASE: "isolated-test-custody" },
    });
    expect(code, err.text()).toBe(0);
    return out.text();
  };
  return { path, storage, stateStore, masterKey, identity, write, checkpoints, call };
}

describe("cold checkpoint CLI", () => {
  it("creates a complete checkpoint from a newly bootstrapped store", async () => {
    const f = await fixture();
    await f.call(["create"]);
    const records = await f.checkpoints.list();
    expect(records).toHaveLength(1);
    expect(records[0]!.namespaces).toEqual(["alpha", "beta"]);
    expect(records[0]!.total_keys).toBe(2);
    const raw = await f.checkpoints.readBundle(records[0]!.id, f.masterKey);
    expect(Object.keys(JSON.parse(bytesToString(fromBase64url(raw))).data).sort()).toEqual(["alpha", "beta"]);
  });

});
