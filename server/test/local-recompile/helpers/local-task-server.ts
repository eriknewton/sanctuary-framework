/**
 * A real server over a temporary filesystem fortress with the local task
 * worker opted in, connected to an in-memory MCP client. Every server and
 * worker it starts is closed in `close`, which also asserts the worker pid is gone.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createSanctuaryServer } from "../../../src/index.js";
import type { LocalTaskTestSeams } from "../../../src/local-recompile/compose.js";
import { writeDefaultPrincipalPolicyFile } from "../../../src/principal-policy/loader.js";
import { createTempFortress, TEST_PASSPHRASE } from "../../helpers/temp-fortress.js";

export type ServerSeams = LocalTaskTestSeams & { auditLogConfig?: { maxEntries?: number; maxTotalSizeBytes?: number } };

export interface LocalTaskServer {
  runtime: Awaited<ReturnType<typeof createSanctuaryServer>>;
  client: Client;
  storagePath: string;
  call(args: Record<string, unknown>): Promise<{ text: string; isError: boolean; items: number }>;
  callTool(name: string, args: Record<string, unknown>): Promise<{ text: string; isError: boolean }>;
  close(): Promise<void>;
}

export function isAlive(pid: number | undefined): boolean {
  if (pid === undefined) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/** A temporary fortress with the default policy on the callback channel; the caller owns its cleanup. */
export async function prepareFortress(policy?: (text: string) => string): Promise<{ storagePath: string; cleanup: () => Promise<void> }> {
  const fortress = await createTempFortress("local-task");
  await mkdir(fortress.storagePath, { recursive: true, mode: 0o700 }); // Owner-only fortress directory.
  const { policyPath } = await writeDefaultPrincipalPolicyFile(fortress.storagePath);
  const text = (await readFile(policyPath, "utf8")).replace("type: stderr", "type: callback");
  await writeFile(policyPath, policy ? policy(text) : text, { mode: 0o600 }); // Owner-only policy.
  return { storagePath: fortress.storagePath, cleanup: fortress.cleanup };
}

/** Boot one server; `policy` rewrites the default policy text before boot. With `storagePath`, the caller owns the fortress. */
export async function bootLocalTaskServer(options: {
  seams?: ServerSeams;
  policy?: (text: string) => string;
  storagePath?: string;
} = {}): Promise<LocalTaskServer> {
  const fortress = options.storagePath === undefined ? await prepareFortress(options.policy) : undefined;
  const storagePath = options.storagePath ?? fortress!.storagePath;
  // The server boots this fortress, named explicitly, whatever another fortress set since; the
  // previous value is restored when this server closes.
  const hadStoragePath = Object.hasOwn(process.env, "SANCTUARY_STORAGE_PATH");
  const previousStoragePath = process.env.SANCTUARY_STORAGE_PATH;
  const restoreStoragePath = () => {
    if (hadStoragePath) process.env.SANCTUARY_STORAGE_PATH = previousStoragePath;
    else delete process.env.SANCTUARY_STORAGE_PATH;
  };
  process.env.SANCTUARY_STORAGE_PATH = storagePath;
  let runtime: Awaited<ReturnType<typeof createSanctuaryServer>> | undefined;
  const client = new Client({ name: "local-task-test", version: "1.0.0" });
  try {
    runtime = await createSanctuaryServer({
      passphrase: TEST_PASSPHRASE,
      approvalCallback: async () => ({ decision: "approve", decided_at: new Date().toISOString(), decided_by: "human" }),
      __testLocalTask: { spawnWorker: true, ...options.seams },
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await runtime.server.connect(serverTransport);
    await client.connect(clientTransport);
  } catch (error) {
    await client.close().catch(() => undefined);
    await runtime?.cleanup().catch(() => undefined);
    restoreStoragePath();
    await fortress?.cleanup();
    throw error;
  }
  const booted = runtime;
  const callTool = async (name: string, args: Record<string, unknown>) => {
    const response = await client.callTool({ name, arguments: args });
    const content = response.content as Array<{ type: string; text: string }>;
    return { text: content[0]?.text ?? "", isError: response.isError === true, items: content.length };
  };
  let closed = false;
  return {
    runtime: booted,
    client,
    storagePath,
    call: (args) => callTool("sanctuary_local_task", args),
    callTool,
    close: async () => {
      if (closed) return;
      closed = true;
      const pid = localTaskPid(booted);
      try {
        await client.close();
      } finally {
        try {
          await booted.cleanup();
        } finally {
          restoreStoragePath();
          await fortress?.cleanup();
        }
      }
      if (pid !== undefined && isAlive(pid)) throw new Error(`worker ${pid} outlived cleanup`);
    },
  };
}

/** The worker pid as the runtime's local task status reports it. */
export function localTaskPid(runtime: Awaited<ReturnType<typeof createSanctuaryServer>>): number | undefined {
  // Optional so a wired-consumer test run against a base without the tool fails on its assertion, not here.
  return (runtime as Partial<typeof runtime>).localTask?.workerPid();
}

export const VALID_ARGS = {
  kind: "summarize",
  sources: { refs: [{ namespace: "notes", key: "one" }] },
  instruction: "Summarize the main points.",
};
