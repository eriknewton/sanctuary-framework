/**
 * Checkpoint commands capture durable state across restarts.
 * LEGACY-BUG-001
 * CHECKPOINT-RESTORE-COLD-VERSION-FLOOR-01
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { mkdtemp, rm, readdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { runCheckpointCommand } from "../../src/cli/checkpoint.js";
import { StateStore, STATE_ENVELOPE_VERSION_ANCHORS_KEY } from "../../src/cognitive/state-store.js";
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

// Must match CHECKPOINT_RESTORE_VERSION_FLOOR_REFUSAL in memory-checkpoint/restore.ts.
const refusal = "memory checkpoint restore refused: checkpoint versions cannot be safely restored (CHECKPOINT-RESTORE-COLD-VERSION-FLOOR-01). State is unchanged.";
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
  const write = (ns: string, value: string, key = "note") => stateStore.write(
    ns, key, value, identity.identity_id, identity.encrypted_private_key, encKey,
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


async function durableBytes(root: string): Promise<Record<string, string>> {
  const result: Record<string, string> = {};
  async function walk(path: string, relative: string) {
    for (const item of await readdir(path, { withFileTypes: true })) {
      const name = join(relative, item.name);
      if (item.isDirectory()) await walk(join(path, item.name), name);
      else result[name] = (await readFile(join(path, item.name))).toString("hex");
    }
  }
  await walk(root, "");
  return result;
}

async function coldRestore(f: Awaited<ReturnType<typeof fixture>>, id: string) {
  const child = fileURLToPath(new URL("./fixtures/cold-restore-cli.mjs", import.meta.url));
  const args = ["--import", "tsx", "--experimental-test-module-mocks", child,
    "restore", id, "--fortress", f.path];
  try {
    const output = await promisify(execFile)(process.execPath, args, {
      cwd: fileURLToPath(new URL("../..", import.meta.url)),
      env: { ...process.env, SANCTUARY_STORAGE_PATH: f.path,
        SANCTUARY_PASSPHRASE: "isolated-test-custody",
        CHECKPOINT_TEST_MASTER_KEY: Buffer.from(f.masterKey).toString("hex") },
      timeout: 20_000, // Bound child lifetime below Vitest's 30-second test timeout.
    });
    return { code: 0, ...output };
  } catch (error) {
    const failure = error as Error & { code: number; stdout: string; stderr: string };
    return { code: failure.code, stdout: failure.stdout, stderr: failure.stderr };
  }
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

  it("refuses a cold restore below a durable anchor without changing any durable bytes", async () => {
    const f = await fixture();
    await f.call(["create"]);
    const [checkpoint] = await f.checkpoints.list();
    // Keep alpha eligible, then advance beta: preflight must cover the whole bundle.
    await f.write("beta", "advanced");
    await f.write("alpha", "added key", "post-checkpoint");
    await f.write("gamma", "added namespace");
    const before = await durableBytes(f.path);
    const result = await coldRestore(f, checkpoint!.id);
    expect(result.code, JSON.stringify(result)).toBe(1);
    expect(result.stderr).toContain(`Error: checkpoint restore failed. ${refusal}\n`);
    expect(result.stdout).not.toContain("Checkpoint restored:");
    expect(await durableBytes(f.path)).toEqual(before);
  });

  it.each(["read failure", "invalid MAC"])("refuses a cold restore on anchor %s without changing durable bytes", async (failure) => {
    const f = await fixture();
    await f.call(["create"]);
    const [checkpoint] = await f.checkpoints.list();
    const raw = await f.storage.read("_meta", STATE_ENVELOPE_VERSION_ANCHORS_KEY);
    expect(raw).not.toBeNull();
    // A malformed durable record exercises the real parser's read failure;
    // a valid envelope with changed data exercises MAC authentication.
    const record = JSON.parse(bytesToString(raw!));
    record.data["untrusted"] = 1;
    await f.storage.write("_meta", STATE_ENVELOPE_VERSION_ANCHORS_KEY,
      Buffer.from(failure === "read failure" ? "{" : JSON.stringify(record)));
    const before = await durableBytes(f.path);
    const result = await coldRestore(f, checkpoint!.id);
    expect(result.code, JSON.stringify(result)).toBe(1);
    expect(result.stderr).toContain(refusal);
    expect(await durableBytes(f.path)).toEqual(before);
  });

});
