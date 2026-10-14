import { createHash } from "node:crypto";
import { createServer } from "node:net";
import {
  rm,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  stat,
  writeFile,
} from "node:fs/promises";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { tmpdir } from "node:os";
import { join, relative, resolve, sep } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  DEMO_AGENT_PLATFORMS,
  DEMO_POLICY_TEMPLATE_CHANGE_OPERATION,
  DEMO_STATE_EXPORT_OPERATION,
  DEMO_TEMP_PREFIX,
  demoTempParent,
  seedDemoFortress,
  seededItemsForDemo,
} from "../../scripts/demo/seed-fortress-lib.js";
import { KERNEL_SOCKET_PATH_MAX_BYTES } from "../../src/storage/cross-process-lock.js";
import { buildLocalAgentRecord } from "../../src/wrap/cli.js";
import * as masterCustody from "../../src/core/master-custody.js";
import { getFreePort } from "../helpers/free-port.js";

const PASSPHRASE = "demo fixture passphrase with enough entropy for tests";
const DEMO_NOW_ISO = "2026-10-14T12:00:00.000Z";
const AGENT_READ_LIMIT = 10;
const SENTINEL_FINDINGS_READ_LIMIT = 10;
const AUDIT_READ_LIMIT = 100;
// 24 = BARRIER_READER_PREFIX_HEX_CHARS and 24 random hex chars in src/storage/cross-process-lock.ts.
const CUSTODY_READER_PREFIX_HEX_CHARS = 24;
const CUSTODY_READER_RANDOM_HEX_CHARS = 24;
const CUSTODY_READER_SEPARATOR = ".reader-";
const CUSTODY_READER_SOCKET_SUFFIX = ".sock";
const FILE_MODE_BITS = 0o777;
const OPERATOR_TOKEN_FILE_MODE = 0o600;
// 10_000 ms gives the real CLI seed enough time to boot on this Mac.
const CLI_READY_TIMEOUT_MS = 10_000;
// 5_000 ms bounds child teardown so a failed CLI test cannot leak a server.
const CLI_EXIT_TIMEOUT_MS = 5_000;

interface PathSnapshotEntry {
  kind: "dir" | "file";
  size: number;
  sha256?: string;
}

const envBeforeFile = { ...process.env };
const fakeHomes: string[] = [];

function restoreEnvKey(key: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[key];
  } else {
    process.env[key] = value;
  }
}

afterEach(async () => {
  restoreEnvKey("HOME", envBeforeFile.HOME);
  restoreEnvKey("SANCTUARY_STORAGE_PATH", envBeforeFile.SANCTUARY_STORAGE_PATH);
  restoreEnvKey(
    "SANCTUARY_DASHBOARD_AUTO_OPEN",
    envBeforeFile.SANCTUARY_DASHBOARD_AUTO_OPEN,
  );
  restoreEnvKey("SANCTUARY_PASSPHRASE", envBeforeFile.SANCTUARY_PASSPHRASE);
  restoreEnvKey(
    "SANCTUARY_CUSTODY_LOCK_ROOT",
    envBeforeFile.SANCTUARY_CUSTODY_LOCK_ROOT,
  );
  for (const fakeHome of fakeHomes.splice(0)) {
    await rm(fakeHome, { recursive: true, force: true });
  }
});

async function snapshotTree(root: string): Promise<Record<string, PathSnapshotEntry>> {
  const out: Record<string, PathSnapshotEntry> = {};
  async function walk(dir: string): Promise<void> {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      const key = relative(root, path);
      const info = await stat(path);
      if (entry.isDirectory()) {
        out[key] = { kind: "dir", size: 0 };
        await walk(path);
      } else if (entry.isFile()) {
        const bytes = await readFile(path);
        out[key] = {
          kind: "file",
          size: info.size,
          sha256: createHash("sha256").update(bytes).digest("hex"),
        };
      }
    }
  }
  await walk(root);
  return out;
}

async function makeFakeOperatorHome(): Promise<string> {
  const fakeHome = await mkdtemp(join(tmpdir(), "sanctuary-demo-fake-home-"));
  fakeHomes.push(fakeHome);
  const fakeSanctuary = join(fakeHome, ".sanctuary", "state");
  await mkdir(fakeSanctuary, { recursive: true });
  await writeFile(
    join(fakeSanctuary, "operator-owned.txt"),
    "operator home must stay unchanged\n",
  );
  return fakeHome;
}

async function getJson(baseUrl: string, path: string, token: string): Promise<unknown> {
  const response = await fetch(`${baseUrl}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  expect(response.status, `${path} status`).toBe(200);
  return response.json();
}

function dataRecord(payload: unknown): Record<string, unknown> {
  expect(payload).toBeTruthy();
  expect(typeof payload).toBe("object");
  return payload as Record<string, unknown>;
}

function assertUnder(root: string, candidate: string): void {
  const resolvedRoot = resolve(root);
  const resolvedCandidate = resolve(candidate);
  expect(
    resolvedCandidate === resolvedRoot ||
      resolvedCandidate.startsWith(`${resolvedRoot}${sep}`),
  ).toBe(true);
}

async function demoRootBasenames(): Promise<string[]> {
  const entries = await readdir(demoTempParent(), { withFileTypes: true });
  return entries
    .filter((entry) => entry.isDirectory() && entry.name.startsWith(DEMO_TEMP_PREFIX))
    .map((entry) => entry.name)
    .sort();
}

async function bindPort(port: number): Promise<ReturnType<typeof createServer>> {
  const server = createServer();
  await new Promise<void>((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(port, "127.0.0.1", () => {
      server.off("error", rejectListen);
      resolveListen();
    });
  });
  return server;
}

function statusCell(status: "seeded" | "not_available"): string {
  return status === "seeded" ? "Seeded" : "Not available on this fixture";
}

function readmeCell(cell: string): string {
  return cell.replace(/`/g, "").trim();
}

function parseSeededItemRows(readme: string): Map<string, string[]> {
  const rows = new Map<string, string[]>();
  for (const line of readme.split("\n")) {
    if (!line.startsWith("| ") || line.includes("---") || line.includes("Seeded item")) {
      continue;
    }
    const cells = line
      .split("|")
      .slice(1, -1)
      .map(readmeCell);
    rows.set(cells[0] ?? "", cells);
  }
  return rows;
}

async function pathExists(path: string): Promise<boolean> {
  return (await stat(path).catch(() => null)) !== null;
}

async function waitForExit(
  child: ChildProcessWithoutNullStreams,
): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
  return await new Promise((resolveExit, rejectExit) => {
    const timeout = setTimeout(() => {
      child.kill("SIGKILL");
      rejectExit(new Error("CLI child did not exit after signal"));
    }, CLI_EXIT_TIMEOUT_MS);
    child.once("error", (error) => {
      clearTimeout(timeout);
      rejectExit(error);
    });
    child.once("exit", (code, signal) => {
      clearTimeout(timeout);
      resolveExit({ code, signal });
    });
  });
}

async function waitForCliReady(
  child: ChildProcessWithoutNullStreams,
): Promise<{ stdout: string; stderr: string; home: string; tokenPath: string }> {
  let stdout = "";
  let stderr = "";
  return await new Promise((resolveReady, rejectReady) => {
    const timeout = setTimeout(() => {
      rejectReady(new Error(`CLI did not become ready: ${stderr}`));
    }, CLI_READY_TIMEOUT_MS);
    const maybeResolve = () => {
      const tokenPath = stdout.match(/^Operator token file: (.+)$/m)?.[1];
      const home = stdout.match(/^Demo HOME: (.+)$/m)?.[1];
      if (tokenPath && home) {
        clearTimeout(timeout);
        resolveReady({ stdout, stderr, home, tokenPath });
      }
    };
    child.stdout.on("data", (chunk) => {
      stdout += String(chunk);
      maybeResolve();
    });
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });
    child.once("error", (error) => {
      clearTimeout(timeout);
      rejectReady(error);
    });
    child.once("exit", (code, signal) => {
      clearTimeout(timeout);
      rejectReady(new Error(`CLI exited before ready (${signal ?? code}): ${stderr}`));
    });
  });
}

async function closeServer(server: ReturnType<typeof createServer>): Promise<void> {
  await new Promise<void>((resolveClose, rejectClose) => {
    server.close((error) => {
      if (error) rejectClose(error);
      else resolveClose();
    });
  });
}

describe("seedDemoFortress", () => {
  it("seeds a temp-only demo fortress through server read paths", async () => {
    const fakeHome = await makeFakeOperatorHome();
    const fakeHomeBefore = await snapshotTree(fakeHome);
    process.env.HOME = fakeHome;
    const port = await getFreePort();
    const seeded = await seedDemoFortress({
      passphrase: PASSPHRASE,
      port,
      startDashboard: true,
      removeOnStop: true,
      now: () => new Date(DEMO_NOW_ISO),
    });

    try {
      assertUnder(demoTempParent(), seeded.home);
      assertUnder(seeded.home, seeded.storagePath);
      expect(seeded.storagePath.endsWith(`${sep}demo-fortress`)).toBe(true);
      expect(process.env.SANCTUARY_CUSTODY_LOCK_ROOT).toBeTruthy();
      assertUnder(seeded.home, process.env.SANCTUARY_CUSTODY_LOCK_ROOT!);
      const longestCustodySocketPath = join(
        process.env.SANCTUARY_CUSTODY_LOCK_ROOT!,
        `${"a".repeat(CUSTODY_READER_PREFIX_HEX_CHARS)}${CUSTODY_READER_SEPARATOR}${"b".repeat(CUSTODY_READER_RANDOM_HEX_CHARS)}${CUSTODY_READER_SOCKET_SUFFIX}`,
      );
      expect(Buffer.byteLength(longestCustodySocketPath)).toBeLessThanOrEqual(
        KERNEL_SOCKET_PATH_MAX_BYTES,
      );
      assertUnder(seeded.home, seeded.authTokenPath);
      const tokenStats = await stat(seeded.authTokenPath);
      expect(tokenStats.mode & FILE_MODE_BITS).toBe(OPERATOR_TOKEN_FILE_MODE);
      expect((await readFile(seeded.authTokenPath, "utf8")).trim()).toBe(
        seeded.authToken,
      );

      const agentsPayload = dataRecord(
        await getJson(
          seeded.apiBaseUrl,
          `/api/hub/agents?limit=${AGENT_READ_LIMIT}`,
          seeded.authToken,
        ),
      );
      const agentsData = dataRecord(agentsPayload.data);
      const agents = agentsData.agents as Array<Record<string, unknown>>;
      expect(agents.map((agent) => agent.agent_id).sort()).toEqual(
        seeded.agentIds.slice().sort(),
      );
      const expectedByAgentId = new Map(
        DEMO_AGENT_PLATFORMS.map((platform) => {
          const record = buildLocalAgentRecord({
            storagePath: seeded.storagePath,
            platform,
          });
          return [record.agent_id, record] as const;
        }),
      );
      for (const agent of agents) {
        const expected = expectedByAgentId.get(String(agent.agent_id));
        expect(expected).toBeDefined();
        expect(agent.status).toBe(expected?.status);
        expect(agent.capabilities).toEqual(expected?.capabilities);
        expect(agent.protection_subject).toBeUndefined();
        expect(dataRecord(agent.budget_summary).daily).toBeUndefined();
        expect(dataRecord(agent.budget_summary).monthly).toBeUndefined();
      }

      const pending = (await getJson(
        seeded.apiBaseUrl,
        "/api/pending",
        seeded.authToken,
      )) as Array<Record<string, unknown>>;
      expect(pending).toHaveLength(2);
      expect(pending.map((item) => item.operation).sort()).toEqual([
        DEMO_POLICY_TEMPLATE_CHANGE_OPERATION,
        DEMO_STATE_EXPORT_OPERATION,
      ]);

      const findingsPayload = dataRecord(
        await getJson(
          seeded.apiBaseUrl,
          `/api/sentinels/findings?limit=${SENTINEL_FINDINGS_READ_LIMIT}`,
          seeded.authToken,
        ),
      );
      const findingsData = dataRecord(findingsPayload.data);
      const findings = findingsData.findings as Array<Record<string, unknown>>;
      expect(findings).toHaveLength(1);
      expect(findings[0]?.finding_id).toBe(seeded.findingId);
      expect(findings[0]?.evidence_audit_ids).toEqual([]);

      const auditPayload = dataRecord(
        await getJson(
          seeded.apiBaseUrl,
          `/api/audit-log?limit=${AUDIT_READ_LIMIT}`,
          seeded.authToken,
        ),
      );
      const entries = auditPayload.entries as Array<Record<string, unknown>>;
      expect(entries.some((entry) => entry.operation === "demo_agent_registered")).toBe(true);
      expect(
        entries.some((entry) => entry.operation === "sentinel_finding_emitted"),
      ).toBe(true);
      expect(
        entries.some((entry) => entry.operation === "demo_audit_chain_verified"),
      ).toBe(false);

      const snapshot = dataRecord(
        await getJson(seeded.apiBaseUrl, "/api/snapshot", seeded.authToken),
      );
      expect((snapshot.pending_approvals as unknown[]).length).toBe(2);

      const status = await fetch(`${seeded.apiBaseUrl}/api/status`, {
        headers: { Authorization: `Bearer ${seeded.authToken}` },
      });
      expect(status.status).toBe(200);
      const events = await fetch(`${seeded.apiBaseUrl}/events`, {
        headers: { Authorization: `Bearer ${seeded.authToken}` },
      });
      expect(events.status).toBe(200);
      await events.body?.cancel();

      const html = await fetch(`${seeded.apiBaseUrl}/v1.1`, {
        headers: { Authorization: `Bearer ${seeded.authToken}` },
      });
      expect(await html.text()).toContain(seeded.fortressId);

      const items = seeded.seededItems;
      expect(items).toEqual(seededItemsForDemo());
      expect(items.some((item) => item.item.includes("audit chain"))).toBe(false);
      expect(
        items
          .filter((item) => item.status === "not_available")
          .map((item) => item.item)
          .sort(),
      ).toEqual(["blocked egress event", "locked-down agent"]);
      const readme = await readFile(
        new URL("../../scripts/demo/README.md", import.meta.url),
        "utf8",
      );
      const readmeRows = parseSeededItemRows(readme);
      for (const item of items) {
        expect(readmeRows.get(item.item)).toEqual([
          item.item,
          item.producedBy,
          item.readPath,
          statusCell(item.status),
        ]);
      }
    } finally {
      await seeded.stop();
    }

    expect(process.env.HOME).toBe(fakeHome);
    expect(await snapshotTree(fakeHome)).toEqual(fakeHomeBefore);
  });

  it("restores environment and removes the minted root when master establishment fails", async () => {
    const fakeHome = await makeFakeOperatorHome();
    const fakeHomeBefore = await snapshotTree(fakeHome);
    const rootsBefore = await demoRootBasenames();
    process.env.HOME = fakeHome;
    const port = await getFreePort();
    const originalError = new Error("synthetic master establishment failure");
    const establishSpy = vi
      .spyOn(masterCustody, "establishMaster")
      .mockImplementationOnce(async () => {
        throw originalError;
      });

    try {
      await expect(
        seedDemoFortress({
          passphrase: PASSPHRASE,
          port,
          startDashboard: true,
          removeOnStop: true,
          now: () => new Date(DEMO_NOW_ISO),
        }),
      ).rejects.toBe(originalError);

      expect(process.env.HOME).toBe(fakeHome);
      expect(process.env.SANCTUARY_STORAGE_PATH).toBe(
        envBeforeFile.SANCTUARY_STORAGE_PATH,
      );
      expect(process.env.SANCTUARY_DASHBOARD_AUTO_OPEN).toBe(
        envBeforeFile.SANCTUARY_DASHBOARD_AUTO_OPEN,
      );
      expect(process.env.SANCTUARY_PASSPHRASE).toBe(
        envBeforeFile.SANCTUARY_PASSPHRASE,
      );
      expect(process.env.SANCTUARY_CUSTODY_LOCK_ROOT).toBe(
        envBeforeFile.SANCTUARY_CUSTODY_LOCK_ROOT,
      );
      expect(await snapshotTree(fakeHome)).toEqual(fakeHomeBefore);
      expect(await demoRootBasenames()).toEqual(rootsBefore);
    } finally {
      establishSpy.mockRestore();
    }

    const probe = await bindPort(port);
    try {
      expect(probe.listening).toBe(true);
    } finally {
      await closeServer(probe);
    }
  });

  it("writes a mode-0600 operator token file without printing the token", async () => {
    const port = await getFreePort();
    const child = spawn(
      process.execPath,
      ["--import", "tsx", "scripts/demo/seed-fortress.ts", "--port", String(port)],
      {
        cwd: process.cwd(),
        env: {
          ...process.env,
          SANCTUARY_PASSPHRASE: PASSPHRASE,
        },
      },
    );
    let ready:
      | { stdout: string; stderr: string; home: string; tokenPath: string }
      | undefined;
    try {
      ready = await waitForCliReady(child);
      const token = (await readFile(ready.tokenPath, "utf8")).trim();
      const tokenStats = await stat(ready.tokenPath);
      expect(tokenStats.mode & FILE_MODE_BITS).toBe(OPERATOR_TOKEN_FILE_MODE);
      expect(token.length).toBeGreaterThan(0);
      expect(ready.stdout).not.toContain(token);
      expect(ready.stdout).toContain("Paste the token from that file");
    } finally {
      child.kill("SIGTERM");
      await waitForExit(child).catch(() => undefined);
    }

    expect(ready).toBeDefined();
    if (ready) {
      const teardown = spawn(
        process.execPath,
        ["--import", "tsx", "scripts/demo/seed-fortress.ts", "--teardown", ready.home],
        { cwd: process.cwd(), env: process.env },
      );
      await waitForExit(teardown);
      expect(await pathExists(ready.home)).toBe(false);
    }
  });
});
