/**
 * Worlds for the acceptance tests: a temporary fortress whose concierge
 * binding is armed against a fake model in its own child process, booted
 * through the real createSanctuaryServer. A test file that boots an armed
 * world must mock `loadPinnedModelManifestKey` to the test catalog key
 * (`Q5E_PUBLIC_KEY`), because the armed record is signed with that key.
 *
 * Every child and server started here is stopped by the returned `close`,
 * which also asserts the pids are gone.
 */
import { fork, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { createRequire } from "node:module";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { vi } from "vitest";
import { StateStore } from "../../../src/cognitive/state-store.js";
import { createIdentity } from "../../../src/core/identity.js";
import { derivePurposeKey } from "../../../src/core/key-derivation.js";
import type { SubstrateConfig } from "../../../src/intelligence/types.js";
import { LocalOplog, type OplogRow } from "../../../src/local-recompile/oplog.js";
import { deriveLocalStoreKeys } from "../../../src/local-recompile/store-keys.js";
import { resolveCustodyLockRoot } from "../../../src/storage/cross-process-lock.js";
import { SubstrateSelector } from "../../../src/intelligence/selector.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../../src/storage/filesystem.js";
import { persistStoredIdentity } from "../../util/persist-stored-identity.js";
import { Q5E_PUBLIC_KEY, q5eIntegrityState, q5eRuntimeTags, Q5E_DEFAULT_DIGEST, Q5E_RUNTIME_TAG } from "../../intelligence/q5e-fixtures.js";
import { bootLocalTaskServer, isAlive, prepareFortress, type LocalTaskServer, type ServerSeams } from "./local-task-server.js";

const FAKE_CHILD = fileURLToPath(new URL("../fixtures/fake-ollama-child.ts", import.meta.url));
const TSX = createRequire(import.meta.url).resolve("tsx");

export interface FakeModel {
  port: number;
  pid: number;
  requests: Array<{ method: string; path: string; body: string }>;
  script(update: Record<string, unknown>): void;
  stop(): Promise<void>;
}

/** Start the fake model in its own process, so its work is never on the server's event loop. */
export async function startFakeModel(script: Record<string, unknown> = {}): Promise<FakeModel> {
  const child: ChildProcess = fork(FAKE_CHILD, [], { execArgv: ["--import", TSX], stdio: ["ignore", "ignore", "ignore", "ipc"] });
  const requests: FakeModel["requests"] = [];
  const stop = async () => {
    // A child that never started has no pid and may never emit exit; there is nothing to wait for.
    if (child.pid !== undefined && child.exitCode === null && child.signalCode === null) {
      const exited = once(child, "exit");
      child.kill("SIGKILL");
      await exited;
    }
    if (isAlive(child.pid)) throw new Error(`fake model ${child.pid} outlived stop`);
  };
  try {
    const port = await new Promise<number>((resolve, reject) => {
      child.on("message", (message: { type: string; port?: number } & FakeModel["requests"][number]) => {
        if (message.type === "listening") resolve(message.port!);
        if (message.type === "request") requests.push(message);
      });
      child.once("exit", () => reject(new Error("fake model exited")));
      // A fork that fails to start rejects here, and the catch below stops the child.
      child.once("error", reject);
    });
    const fake: FakeModel = { port, pid: child.pid!, requests, script: (update) => child.send({ type: "script", script: update }), stop };
    fake.script({ tag: Q5E_RUNTIME_TAG, digest: Q5E_DEFAULT_DIGEST, reply: "summary", ...script });
    return fake;
  } catch (error) {
    await stop();
    throw error;
  }
}

/** Write the armed concierge binding and the fake's loopback endpoint into the fortress, as an operator would. */
async function armFortress(storagePath: string, masterKey: Uint8Array, port: number): Promise<void> {
  const storage = new FilesystemStorage(join(storagePath, "state"));
  const auditLog = new AuditLog(storage, masterKey);
  const selector = new SubstrateSelector({ storage, masterKey, auditLog, identityId: "acceptance-provision", modelManifestV2PublicKey: Q5E_PUBLIC_KEY });
  await selector.load();
  const state = q5eIntegrityState("/var/lib/ollama/models");
  await selector.commitLocalIntegrityProvisioning(state, q5eRuntimeTags(state));
  const internals = selector as unknown as { config: SubstrateConfig; store: { save(config: SubstrateConfig): Promise<SubstrateConfig> } };
  await internals.store.save({ ...internals.config, ollamaEndpoint: `http://127.0.0.1:${port}` });
  await auditLog.flush();
}

export interface WorldOptions {
  /** Rewrites the default policy text before the first boot. */
  policy?: (text: string) => string;
  /** Records to write, signed by the fortress's default identity, before arming. */
  records?: Array<{ namespace: string; key: string; value: string }>;
  /** Leave the binding unarmed (the job then refuses at authority). */
  unarmed?: boolean;
  fakeScript?: Record<string, unknown>;
  seams?: ServerSeams;
  /** A fixed wall clock for the record writes, so two worlds' records carry the same timestamps. */
  recordTime?: number;
}

export interface World {
  server: LocalTaskServer;
  fake: FakeModel;
  storagePath: string;
  masterKey: Uint8Array;
  close(): Promise<void>;
}

/**
 * Prepare the fortress, write its records through a first boot, arm it, and
 * boot it again with the worker opted in. The second boot is the one measured.
 */
export async function openWorld(options: WorldOptions = {}): Promise<World> {
  const fortress = await prepareFortress(options.policy);
  const fake = await startFakeModel(options.fakeScript);
  let server: LocalTaskServer | undefined;
  try {
    const first = await bootLocalTaskServer({ storagePath: fortress.storagePath, seams: { spawnWorker: false } });
    let masterKey: Uint8Array;
    try {
      masterKey = Uint8Array.from(first.runtime.masterKey);
      // The writer the job's writer-key table will name; the second boot loads it.
      const storage = new FilesystemStorage(join(fortress.storagePath, "state"));
      const encKey = derivePurposeKey(masterKey, "identity-encryption");
      const { storedIdentity: identity } = createIdentity("writer", encKey, "recovery-key");
      await persistStoredIdentity(storage, masterKey, identity);
      const store = new StateStore(storage, masterKey);
      // Only Date is faked, and only while the records are written; every timer stays real.
      if (options.recordTime !== undefined) vi.useFakeTimers({ toFake: ["Date"], now: options.recordTime });
      try {
        for (const record of options.records ?? []) {
          await store.write(record.namespace, record.key, record.value, identity.identity_id, identity.encrypted_private_key, encKey);
        }
      } finally {
        if (options.recordTime !== undefined) vi.useRealTimers();
      }
    } finally {
      await first.close();
    }
    if (!options.unarmed) await armFortress(fortress.storagePath, masterKey, fake.port);
    server = await bootLocalTaskServer({ storagePath: fortress.storagePath, ...(options.seams ? { seams: options.seams } : {}) });
    const booted = server;
    return {
      server: booted,
      fake,
      storagePath: fortress.storagePath,
      masterKey,
      close: async () => {
        try {
          await booted.close();
        } finally {
          try {
            await fake.stop();
          } finally {
            await fortress.cleanup();
          }
        }
      },
    };
  } catch (error) {
    await server?.close().catch(() => undefined);
    await fake.stop().catch(() => undefined);
    await fortress.cleanup();
    throw error;
  }
}

/** Every retained operator-log row of a world, read with a key derived the way the server derives it. */
export async function operatorRows(world: { storagePath: string; masterKey: Uint8Array }): Promise<OplogRow[]> {
  const keys = deriveLocalStoreKeys(world.masterKey);
  keys.resultsKey.fill(0);
  const runtimeRoot = resolveCustodyLockRoot(process.getuid!(), { env: process.env, platform: process.platform });
  const oplog = new LocalOplog(new FilesystemStorage(join(world.storagePath, "state")), keys.oplogKey, { runtimeRoot });
  try {
    const status = await oplog.status();
    return await oplog.readRows(status.base_seq, status.rows);
  } finally {
    oplog.close();
  }
}

const JOB_END_KINDS = new Set(["job_committed", "job_refused", "job_failed", "job_dropped"]);
// Long enough for a few fake model calls on a loaded machine.
const JOB_END_WAIT_MS = 60_000;
const JOB_END_POLL_MS = 100;

/** Wait until `count` jobs have reached an end row in the operator log. */
export async function waitForJobEnds(world: { storagePath: string; masterKey: Uint8Array }, count: number): Promise<OplogRow[]> {
  const deadline = Date.now() + JOB_END_WAIT_MS;
  for (;;) {
    const rows = await operatorRows(world);
    if (rows.filter((row) => JOB_END_KINDS.has(row.kind)).length >= count) return rows;
    if (Date.now() > deadline) throw new Error(`only ${rows.filter((row) => JOB_END_KINDS.has(row.kind)).length} of ${count} jobs ended`);
    await new Promise((resolve) => setTimeout(resolve, JOB_END_POLL_MS));
  }
}
