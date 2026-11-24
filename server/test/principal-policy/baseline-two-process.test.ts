/** Two servers on one fortress each keep the namespaces they saved, whichever of them saves its snapshot last. */
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createSanctuaryServer } from "../../src/index.js";
import { establishMaster } from "../../src/core/master-custody.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { generateDefaultPolicyYaml } from "../../src/principal-policy/loader.js";
import type { ApprovalResponse } from "../../src/principal-policy/types.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { TEST_PASSPHRASE } from "../helpers/temp-fortress.js";

const supported = process.platform === "darwin" || process.platform === "linux";
// A real boot imports the full server graph through tsx; 120 s bounds each wait on this box.
const CHILD_WAIT_MS = 120_000;

interface Child {
  process: ChildProcess;
  stdout: string;
  stderr: string;
}

function spawnChild(identityId: string, value: string): Child {
  const fixture = fileURLToPath(new URL("./baseline-two-process-child.ts", import.meta.url));
  const child = spawn(process.execPath, ["--import", "tsx", fixture, value], {
    stdio: ["pipe", "pipe", "pipe"],
    // The child inherits the stubbed test environment, VITEST included, and names only its own session identity.
    env: { ...process.env, SANCTUARY_SESSION_IDENTITY_ID: identityId },
  });
  const record: Child = { process: child, stdout: "", stderr: "" };
  child.stdout!.on("data", (chunk: Buffer) => { record.stdout += chunk.toString("utf8"); });
  child.stderr!.on("data", (chunk: Buffer) => { record.stderr += chunk.toString("utf8"); });
  return record;
}

async function within<T>(promise: Promise<T>, what: string, child: Child): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`timed out waiting for ${what}: ${child.stderr}`)), CHILD_WAIT_MS);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function ready(child: Child): Promise<Record<string, unknown>> {
  return within(new Promise((resolve, reject) => {
    const check = () => {
      const line = child.stdout.split("\n").find((candidate) => candidate.startsWith("{"));
      if (line) resolve(JSON.parse(line) as Record<string, unknown>);
    };
    child.process.stdout!.on("data", check);
    child.process.once("exit", (code) => reject(new Error(`child exited before ready (${code}): ${child.stderr}`)));
    check();
  }), "ready", child);
}

async function exitCleanly(child: Child): Promise<number | null> {
  const exited = once(child.process, "exit") as Promise<[number | null, NodeJS.Signals | null]>;
  child.process.stdin!.end("exit\n");
  const [code] = await within(exited, "exit", child);
  return code;
}

describe.skipIf(!supported)("two processes, one fortress", () => {
  const children: Child[] = [];
  let root: string | undefined;

  afterEach(async () => {
    for (const child of children.splice(0)) {
      if (child.process.exitCode === null && child.process.signalCode === null) {
        const exit = once(child.process, "exit");
        child.process.kill("SIGKILL");
        await exit;
      }
    }
    vi.unstubAllEnvs();
    if (root) await rm(root, { recursive: true, force: true });
    root = undefined;
  });

  it("two servers on one fortress both have their remembered namespaces known to the next load", async () => {
    root = await mkdtemp(join(tmpdir(), "baseline-two-process-"));
    const home = join(root, "home");
    const fortress = join(root, "fortress");
    await mkdir(home, { mode: 0o700 });
    await mkdir(fortress, { mode: 0o700 });
    vi.stubEnv("HOME", home);
    vi.stubEnv("SANCTUARY_STORAGE_PATH", fortress);
    vi.stubEnv("SANCTUARY_PASSPHRASE", TEST_PASSPHRASE);
    vi.stubEnv("SANCTUARY_SESSION_IDENTITY_ID", "");
    vi.stubEnv("SANCTUARY_FORTRESS_PATH", "");
    vi.stubEnv("SANCTUARY_RECOVERY_KEY", "");
    const yaml = generateDefaultPolicyYaml().replace(/approval_channel:\n {2}type: \w+/, "approval_channel:\n  type: callback");
    await writeFile(join(fortress, "principal-policy.yaml"), yaml, { mode: 0o600 });

    // Seed the fortress and both identities before either child starts.
    const deny = async (): Promise<ApprovalResponse> =>
      ({ decision: "deny", decided_at: new Date().toISOString(), decided_by: "human" });
    const seed = await createSanctuaryServer({ approvalCallback: deny });
    const identities: string[] = [];
    try {
      const handler = (seed.server as unknown as {
        _requestHandlers: Map<string, (request: unknown, extra: unknown) => Promise<{ content: Array<{ text: string }> }>>;
      })._requestHandlers.get("tools/call")!;
      for (const label of ["child-a", "child-b"]) {
        const result = await handler({ method: "tools/call", params: { name: "identity_create", arguments: { label } } }, {});
        identities.push((JSON.parse(result.content[0]!.text) as { identity_id: string }).identity_id);
      }
    } finally {
      await seed.cleanup();
    }

    const a = spawnChild(identities[0]!, "from-a");
    children.push(a);
    const b = spawnChild(identities[1]!, "from-b");
    children.push(b);
    expect(await ready(a)).toEqual({ ready: true, saved: true, approvals: 0 });
    expect(await ready(b)).toEqual({ ready: true, saved: true, approvals: 0 });
    // A saves its whole snapshot first, then B's whole snapshot overwrites it.
    expect(await exitCleanly(a)).toBe(0);
    expect(await exitCleanly(b)).toBe(0);

    const storage = new FilesystemStorage(join(fortress, "state"));
    const memoryNamespaces = (await storage.listNamespaces()).filter((namespace) => !namespace.startsWith("_"));
    expect(memoryNamespaces).toHaveLength(2);
    const est = await establishMaster({ storage, passphrase: TEST_PASSPHRASE });
    try {
      const tracker = new BaselineTracker(storage, est.masterKey);
      await tracker.load();
      for (const namespace of memoryNamespaces) expect(tracker.isNewNamespace(namespace)).toBe(false);
    } finally {
      await est.masterWriteBarrier?.release();
      est.masterKey.fill(0);
    }
  }, 4 * CHILD_WAIT_MS);
});
