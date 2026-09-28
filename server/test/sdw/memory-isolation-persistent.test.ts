import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

import { MemoryStorage } from "../../src/storage/memory.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import {
  claimSdwOwnerForOperator,
  createPersistentMultiAgentIsolationGuard,
  readSdwOwnerPin,
  transferSdwOwnerForOperator,
} from "../../src/sdw/memory-isolation.js";
import { writeReplayAnchor } from "../../src/sdw/write-gate.js";
import { MEMORY_PROVENANCE_BAD_SIGNER_NAMESPACE } from "../../src/sdw/memory-provenance-bad-signers.js";

const MASTER = new Uint8Array(32).fill(41);
const FORTRESS_ID = "fortress:ic16";
const SERVER_DIR = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const CHILD = join(SERVER_DIR, "test", "fixtures", "ic16-owner-process.ts");
const TSX = join(SERVER_DIR, "node_modules", ".bin", "tsx");
const dirs: string[] = [];

afterEach(async () => {
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

function guard(storage: MemoryStorage, agentId: string | undefined) {
  return createPersistentMultiAgentIsolationGuard({
    storage,
    masterKey: MASTER,
    fortressId: FORTRESS_ID,
    ownerRef: "fleet-self",
    ownerIdentity: () => agentId,
    now: () => "2026-09-01T00:00:00.000Z",
  });
}

async function child(
  mode: "guard" | "transfer",
  statePath: string,
  first: string,
  second?: string,
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const args = [
      CHILD,
      mode,
      statePath,
      Buffer.from(MASTER).toString("hex"),
      FORTRESS_ID,
      first,
      ...(second ? [second] : []),
    ];
    const proc = spawn(TSX, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (chunk) => (stdout += String(chunk)));
    proc.stderr.on("data", (chunk) => (stderr += String(chunk)));
    proc.once("error", reject);
    proc.once("close", (code) => {
      if (code !== 0) return reject(new Error(`child ${code}: ${stderr}`));
      resolve(JSON.parse(stdout.trim()) as Record<string, unknown>);
    });
  });
}

describe("IC-16 durable SDW owner isolation", () => {
  it("atomically elects one owner across two real server processes", async () => {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-ic16-processes-"));
    dirs.push(root);
    const statePath = join(root, "state");
    const results = await Promise.all([
      child("guard", statePath, "claude_code:fortress-00000000000001c6"),
      child("guard", statePath, "cursor:fortress-00000000000001c6"),
    ]);
    expect(results.filter((result) => result.allowed === true)).toHaveLength(1);
    expect(results.filter((result) => result.allowed === false)).toHaveLength(1);
    expect(results.find((result) => result.allowed === false)?.reason).toBe(
      "owner_scope_conflict",
    );

    const pin = await readSdwOwnerPin(new FilesystemStorage(statePath), MASTER);
    expect(pin.status).toBe("valid");
    if (pin.status === "valid") {
      expect(["claude_code:fortress-00000000000001c6", "cursor:fortress-00000000000001c6"]).toContain(pin.data.agent_id);
    }
  });

  it("uses a real cross-process compare-and-replace for owner transfer", async () => {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-ic16-transfer-"));
    dirs.push(root);
    const statePath = join(root, "state");
    expect(await child("guard", statePath, "claude_code:fortress-00000000000000a1")).toEqual({ allowed: true });
    const results = await Promise.all([
      child("transfer", statePath, "claude_code:fortress-00000000000000a1", "claude_code:fortress-00000000000000a2"),
      child("transfer", statePath, "claude_code:fortress-00000000000000a1", "claude_code:fortress-00000000000000a3"),
    ]);
    expect(results.filter((result) => result.status === "transferred")).toHaveLength(1);
    expect(
      results.filter(
        (result) => result.status === "changed" || result.status === "owner_mismatch",
      ),
    ).toHaveLength(1);
    const pin = await readSdwOwnerPin(new FilesystemStorage(statePath), MASTER);
    expect(pin.status).toBe("valid");
    if (pin.status === "valid") {
      expect(["claude_code:fortress-00000000000000a2", "claude_code:fortress-00000000000000a3"]).toContain(pin.data.agent_id);
    }
  });

  it("refuses missing identity, wrong identity, and a pin under the wrong master", async () => {
    const storage = new MemoryStorage();
    expect(await guard(storage, undefined)("memory_count")).toEqual({
      allowed: false,
      reason: "owner_identity_missing",
    });
    expect(await guard(storage, "claude_code:fortress-00000000000000a1")("memory_count")).toEqual({ allowed: true });
    expect(await guard(storage, "claude_code:fortress-00000000000000a2")("memory_count")).toEqual({
      allowed: false,
      reason: "owner_scope_conflict",
    });
    const wrongKeyGuard = createPersistentMultiAgentIsolationGuard({
      storage,
      masterKey: new Uint8Array(32).fill(42),
      fortressId: FORTRESS_ID,
      ownerRef: "fleet-self",
      ownerIdentity: () => "claude_code:fortress-00000000000000a1",
    });
    expect(await wrongKeyGuard("memory_count")).toEqual({
      allowed: false,
      reason: "owner_pin_invalid",
    });
  });

  it("never lets the first process silently inherit an existing unpinned SDW", async () => {
    const storage = new MemoryStorage();
    await writeReplayAnchor(storage, MASTER, {
      catalog: 0,
      chain_head: [],
      manifests: [],
      tombstones: [],
      export_state: 0,
    });
    expect(await guard(storage, "claude_code:fortress-00000000000000e9")("memory_count")).toEqual({
      allowed: false,
      reason: "owner_pin_missing_after_establishment",
    });
    expect(await readSdwOwnerPin(storage, MASTER)).toEqual({ status: "absent" });

    expect(
      await claimSdwOwnerForOperator({
        storage,
        masterKey: MASTER,
        fortressId: FORTRESS_ID,
        ownerRef: "fleet-self",
        agentId: "claude_code:fortress-00000000000000e9",
        now: () => "2026-09-01T00:00:00.000Z",
      }),
    ).toEqual({ status: "claimed" });
    expect(await guard(storage, "claude_code:fortress-00000000000000e9")("memory_count")).toEqual({
      allowed: true,
    });
  });

  it("treats bad-signer security metadata as an established legacy SDW", async () => {
    const storage = new MemoryStorage();
    await storage.write(
      MEMORY_PROVENANCE_BAD_SIGNER_NAMESPACE,
      "legacy-mark",
      new Uint8Array([1]),
    );
    expect(await guard(storage, "claude_code:fortress-00000000000000e9")("memory_count")).toEqual({
      allowed: false,
      reason: "owner_pin_missing_after_establishment",
    });
    expect(await readSdwOwnerPin(storage, MASTER)).toEqual({ status: "absent" });
  });

  it("transfers only from the exact authenticated current owner", async () => {
    const storage = new MemoryStorage();
    expect(await guard(storage, "claude_code:fortress-00000000000000a1")("memory_count")).toEqual({ allowed: true });
    expect(
      await transferSdwOwnerForOperator({
        storage,
        masterKey: MASTER,
        fortressId: FORTRESS_ID,
        ownerRef: "fleet-self",
        expectedAgentId: "claude_code:fortress-00000000000000ff",
        newAgentId: "claude_code:fortress-00000000000000a2",
      }),
    ).toEqual({ status: "owner_mismatch", agentId: "claude_code:fortress-00000000000000a1" });
    expect(
      await transferSdwOwnerForOperator({
        storage,
        masterKey: MASTER,
        fortressId: FORTRESS_ID,
        ownerRef: "fleet-self",
        expectedAgentId: "claude_code:fortress-00000000000000a1",
        newAgentId: "claude_code:fortress-00000000000000a2",
      }),
    ).toEqual({ status: "transferred" });
    expect(await guard(storage, "claude_code:fortress-00000000000000a1")("memory_count")).toMatchObject({
      allowed: false,
    });
    expect(await guard(storage, "claude_code:fortress-00000000000000a2")("memory_count")).toEqual({ allowed: true });
  });
});
