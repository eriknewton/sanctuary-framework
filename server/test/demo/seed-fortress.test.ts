import { createHash } from "node:crypto";
import { createServer, type AddressInfo } from "node:net";
import {
  chmod,
  rm,
  mkdir,
  mkdtemp,
  open,
  readdir,
  readFile,
  stat,
  writeFile,
} from "node:fs/promises";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { tmpdir } from "node:os";
import { join, relative, resolve, sep } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  DEMO_AGENT_PLATFORMS,
  DEMO_DIRECTORY_MODE,
  DEMO_LABEL_PREFIX,
  DEMO_PID_FILE_BASENAME,
  createDemoRoot,
  type SeedDemoFortressOptions,
  DEMO_POLICY_TEMPLATE_CHANGE_OPERATION,
  DEMO_STATE_EXPORT_OPERATION,
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
// 10_000 ms gives the real CLI seed time to boot on a build box or Mac.
const CLI_READY_TIMEOUT_MS = 10_000;
// 5_000 ms bounds child teardown so a failed CLI test cannot leak a server.
const CLI_EXIT_TIMEOUT_MS = 5_000;
// Must match HOLD_FOR_SIGNAL_ENV and HOLD_FOR_SIGNAL_LINE in server/scripts/demo/seed-fortress.ts.
const DEMO_SEED_HOLD_ENV = "SANCTUARY_DEMO_SEED_HOLD_FOR_SIGNAL";
const DEMO_SEED_HOLD_LINE = /^Demo seeding is holding for a signal\.$/m;
// 0o500 = owner read and search without write, so entries inside the directory cannot be unlinked.
const LOCKED_DIRECTORY_MODE = 0o500;

interface PathSnapshotEntry {
  kind: "dir" | "file";
  size: number;
  sha256?: string;
}

const envBeforeFile = { ...process.env };
interface CliRun {
  child: ChildProcessWithoutNullStreams;
  stdout: string;
  stderr: string;
  exit: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
  closed: boolean;
  home?: string;
}

let roots: Set<string>;
let children: CliRun[];
let stops: Array<() => Promise<void>>;
let servers: Array<ReturnType<typeof createServer>>;
let cleanupPromise: Promise<void> | undefined;

beforeEach(() => {
  roots = new Set();
  children = [];
  stops = [];
  servers = [];
  cleanupPromise = undefined;
});

function restoreEnvKey(key: string, value: string | undefined): void {
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
}

function cleanupOwned(): Promise<void> {
  cleanupPromise ??= (async () => {
    const errors: unknown[] = [];
    try {
      for (const run of children) {
        try {
          if (!run.closed) run.child.kill("SIGKILL");
          await run.exit;
        } catch (error) { errors.push(error); }
      }
      for (const stop of stops) {
        try { await stop(); } catch (error) { errors.push(error); }
      }
      for (const server of servers) {
        try { if (server.listening) await closeServer(server); } catch (error) { errors.push(error); }
      }
    } finally {
      try {
        // Children and servers are reaped first, even when an assertion or timeout interrupted the test.
        for (const root of roots) {
          try {
            await rm(root, { recursive: true, force: true });
            expect(await pathExists(root), `owned root removed: ${root}`).toBe(false);
          } catch (error) { errors.push(error); }
        }
      } finally {
        for (const key of ["HOME", "SANCTUARY_STORAGE_PATH", "SANCTUARY_DASHBOARD_AUTO_OPEN", "SANCTUARY_PASSPHRASE", "SANCTUARY_CUSTODY_LOCK_ROOT"]) {
          restoreEnvKey(key, envBeforeFile[key]);
        }
        vi.restoreAllMocks();
      }
    }
    if (errors.length) throw errors[0];
  })();
  return cleanupPromise;
}

afterEach(cleanupOwned);

function ownedDemoRoot(): string {
  const home = createDemoRoot();
  roots.add(home);
  return home;
}

// The shared cleanup owns the restore, registered before the directory exists, so a timeout that runs afterEach
// before a test's finally still makes the owned root removable; a restore only in a finally would run after the
// memoized removal had already failed.
async function lockOwnedDirectory(path: string): Promise<void> {
  // The restore must stay the first statement, before mkdir, writeFile and the locking chmod, because a timeout
  // between creating and locking the directory must still find the restore in the shared cleanup.
  stops.push(() => chmod(path, DEMO_DIRECTORY_MODE).catch(() => undefined));
  await mkdir(path);
  await writeFile(join(path, "pinned"), "held open by a read-only parent\n");
  await chmod(path, LOCKED_DIRECTORY_MODE);
}

function seedOwned(home: string, options: SeedDemoFortressOptions) {
  const pending = seedDemoFortress(home, options);
  // Register before awaiting: afterEach also owns resources produced by a late seed completion.
  stops.push(async () => {
    const seeded = await pending.catch(() => undefined);
    await seeded?.stop();
  });
  return pending;
}

async function snapshotTree(root: string): Promise<Record<string, PathSnapshotEntry>> {
  const out: Record<string, PathSnapshotEntry> = {};
  async function walk(dir: string): Promise<void> {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      const key = relative(root, path);
      if (entry.isDirectory()) {
        out[key] = { kind: "dir", size: 0 };
        await walk(path);
      } else if (entry.isFile()) {
        const bytes = await readFile(path);
        out[key] = {
          kind: "file",
          size: bytes.length,
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
  roots.add(fakeHome);
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

async function bindPort(port: number): Promise<ReturnType<typeof createServer>> {
  const server = createServer();
  servers.push(server);
  await new Promise<void>((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    // port-discipline: ignore - binds the exact port the demo used to prove stop released it; a fresh port proves nothing
    server.listen(port, "127.0.0.1", () => {
      server.off("error", rejectListen);
      resolveListen();
    });
  });
  return server;
}

// Holds an OS-assigned port open so a child told to use it fails to start its dashboard.
async function occupyEphemeralPort(): Promise<number> {
  const server = createServer();
  servers.push(server);
  await new Promise<void>((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", rejectListen);
      resolveListen();
    });
  });
  return (server.address() as AddressInfo).port;
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

// Reads a file's permission bits and contents through one handle, so both describe the same file.
async function readModeAndText(path: string): Promise<{ mode: number; text: string }> {
  const handle = await open(path, "r");
  try {
    return { mode: (await handle.stat()).mode & FILE_MODE_BITS, text: await handle.readFile("utf8") };
  } finally {
    await handle.close();
  }
}

async function pathExists(path: string): Promise<boolean> {
  return (await stat(path).catch(() => null)) !== null;
}

async function spawnCli(args: string[], extraEnv: Record<string, string> = {}): Promise<CliRun> {
  const fakeHome = await makeFakeOperatorHome();
  const child = spawn(process.execPath, ["--import", "tsx", "scripts/demo/seed-fortress.ts", ...args], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      HOME: fakeHome,
      SANCTUARY_STORAGE_PATH: join(fakeHome, "storage"),
      SANCTUARY_CUSTODY_LOCK_ROOT: join(fakeHome, "c"),
      SANCTUARY_DASHBOARD_AUTO_OPEN: "false",
      SANCTUARY_PASSPHRASE: PASSPHRASE,
      ...extraEnv,
    },
  });
  const run: CliRun = {
    child, stdout: "", stderr: "", closed: false,
    exit: Promise.resolve({ code: null, signal: null }),
  };
  children.push(run);
  run.exit = new Promise((resolveExit, rejectExit) => {
    child.once("error", rejectExit);
    child.once("close", (code, signal) => {
      run.closed = true;
      resolveExit({ code, signal });
    });
  });
  // A spawn failure is observed by the waiter and teardown, never an unhandled rejection.
  void run.exit.catch(() => undefined);
  child.stdout.on("data", (chunk) => {
    run.stdout += String(chunk);
    const home = run.stdout.match(/^Demo HOME: (.+)$/m)?.[1];
    if (home) {
      run.home = home;
      roots.add(home);
    }
  });
  child.stderr.on("data", (chunk) => { run.stderr += String(chunk); });
  return run;
}

async function waitForOutput(run: CliRun, pattern: RegExp): Promise<void> {
  await new Promise<void>((resolveReady, rejectReady) => {
    const finish = (error?: Error) => {
      clearTimeout(timeout);
      run.child.stdout.off("data", check);
      run.child.off("close", closed);
      if (error) rejectReady(error);
      else resolveReady();
    };
    const check = () => { if (pattern.test(run.stdout)) finish(); };
    const closed = () => finish(new Error(`CLI exited before expected output: ${run.stderr}`));
    const timeout = setTimeout(() => finish(new Error(`CLI output timed out: ${run.stderr}`)), CLI_READY_TIMEOUT_MS);
    run.child.stdout.on("data", check);
    run.child.once("close", closed);
    if (run.closed) closed();
    else check();
  });
}

async function waitForExit(run: CliRun) {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      run.exit,
      new Promise<never>((_, rejectExit) => {
        timeout = setTimeout(() => {
          run.child.kill("SIGKILL");
          rejectExit(new Error("CLI child did not exit in time"));
        }, CLI_EXIT_TIMEOUT_MS);
      }),
    ]);
  } finally {
    clearTimeout(timeout);
    if (run.child.killed) await run.exit;
  }
}

// Must match the startup banner in DashboardApprovalChannel's listen callback in
// server/src/principal-policy/dashboard.ts: every dashboard prints its URL line, then one hint line showing
// the token's first and last four characters.
const DASHBOARD_TOKEN_HINT_CHARS = 4;
const DASHBOARD_URL_LINE = /^  Sanctuary Principal Dashboard: http:\/\/127\.0\.0\.1:[0-9]+$/;

function assertNoTokenOutput(token: string, run: CliRun, dashboardStarted: boolean): void {
  // Every longer substring contains a four-character window, so these checks cover all lengths >= 4.
  const minimumSubstringLength = 4;
  expect(token.length).toBeGreaterThan(2 * DASHBOARD_TOKEN_HINT_CHARS + minimumSubstringLength);
  const hintLine = `  Auth token: ${token.slice(0, DASHBOARD_TOKEN_HINT_CHARS)}...${token.slice(-DASHBOARD_TOKEN_HINT_CHARS)}`;
  const stderrLines = run.stderr.split("\n");
  // Only the dashboard's own standard hint line, directly under its URL line, is set aside, and only once.
  const hintIndexes = stderrLines.flatMap((line, index) =>
    line === hintLine && index > 0 && DASHBOARD_URL_LINE.test(stderrLines[index - 1]!) ? [index] : []);
  expect(hintIndexes).toHaveLength(dashboardStarted ? 1 : 0);
  if (dashboardStarted) {
    const shown = stderrLines[hintIndexes[0]!]!;
    expect(shown.includes(token.slice(DASHBOARD_TOKEN_HINT_CHARS, -DASHBOARD_TOKEN_HINT_CHARS))).toBe(false);
  }
  const stderrElsewhere = stderrLines.filter((_, index) => !hintIndexes.includes(index)).join("\n");
  // The CLI's own output is all of stdout plus stderr outside that one line; neither carries a token window.
  expect(run.stdout).not.toContain("Auth token");
  for (let index = 0; index <= token.length - minimumSubstringLength; index++) {
    const fragment = token.slice(index, index + minimumSubstringLength);
    expect(run.stdout.includes(fragment), "stdout contains no token fragment").toBe(false);
    expect(stderrElsewhere.includes(fragment), "stderr outside the dashboard hint line contains no token fragment").toBe(false);
  }
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
    const home = ownedDemoRoot();
    try {
    const seeded = await seedOwned(home, {
      passphrase: PASSPHRASE,
      port,
      startDashboard: true,
      removeOnStop: true,
      now: () => new Date(DEMO_NOW_ISO),
    });

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
      const tokenFile = await readModeAndText(seeded.authTokenPath);
      expect(tokenFile.mode).toBe(OPERATOR_TOKEN_FILE_MODE);
      expect(tokenFile.text.trim()).toBe(seeded.authToken);

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
        // The hub serves a control only where its executor can run it (projectAgentCapabilities in
        // src/hub/hub-service.ts). Must match CastleWallAgentController.supports in
        // src/dashboard/v1_1/castle-wall-agent-controller.ts: pause, resume, restart and unwrap have no executor, and
        // lockdown follows its stored flag.
        expect(agent.capabilities).toEqual({
          ...expected?.capabilities,
          can_pause: false,
          can_resume: false,
          can_restart: false,
          can_unwrap: false,
        });
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
      const servedLabel = (await html.text()).match(/data-fortress-id="([^"]+)"/)?.[1];
      expect(servedLabel).toBe(seeded.fortressId);
      expect(servedLabel?.startsWith(DEMO_LABEL_PREFIX)).toBe(true);

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
      await seeded.stop();
      expect(await pathExists(home)).toBe(false);
      expect(process.env.HOME).toBe(fakeHome);
      expect(await snapshotTree(fakeHome)).toEqual(fakeHomeBefore);
    } finally {
      await cleanupOwned();
    }
    expect(await pathExists(home)).toBe(false);
  });

  it("restores environment and removes the minted root when master establishment fails", async () => {
    const fakeHome = await makeFakeOperatorHome();
    const fakeHomeBefore = await snapshotTree(fakeHome);
    const home = ownedDemoRoot();
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
        seedOwned(home, {
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
      expect(await pathExists(home)).toBe(false);
      const probe = await bindPort(port);
      expect(probe.listening).toBe(true);
    } finally {
      establishSpy.mockRestore();
      await cleanupOwned();
    }
    expect(await pathExists(home)).toBe(false);
  });

  it("writes a mode-0600 operator token file and prints no token fragment outside the dashboard's standard hint line", async () => {
    const run = await spawnCli(["--port", String(await getFreePort())]);
    try {
      await waitForOutput(run, /^Teardown: /m);
      const tokenPath = run.stdout.match(/^Operator token file: (.+)$/m)![1];
      const tokenFile = await readModeAndText(tokenPath);
      const token = tokenFile.text.trim();
      expect(tokenFile.mode).toBe(OPERATOR_TOKEN_FILE_MODE);
      expect(run.stdout).toContain("Paste the token from that file");
      run.child.kill("SIGTERM");
      expect(await waitForExit(run)).toEqual({ code: 0, signal: null });
      assertNoTokenOutput(token, run, true);
      expect(await pathExists(run.home!)).toBe(false);
    } finally {
      await cleanupOwned();
    }
    expect(await pathExists(run.home!)).toBe(false);
  });

  it("returns an empty private root before any seeding write", async () => {
    const home = ownedDemoRoot();
    try {
      expect(await readdir(home)).toEqual([]);
      expect((await stat(home)).mode & FILE_MODE_BITS).toBe(DEMO_DIRECTORY_MODE);
    } finally {
      await cleanupOwned();
    }
    expect(await pathExists(home)).toBe(false);
  });

  it.each(["SIGINT", "SIGTERM"] as const)("owns root cleanup when %s arrives at the first root announcement", async (signal) => {
    const run = await spawnCli(["--port", String(await getFreePort())]);
    try {
      await waitForOutput(run, /^Demo HOME: /m);
      run.child.kill(signal);
      const exit = await waitForExit(run);
      const interrupted = run.stderr.includes(`Demo seeding was interrupted by ${signal}.`);
      expect(run.stderr).toMatch(/Demo (seeding was interrupted by SIG(INT|TERM)|stopped after ready)\./);
      // POSIX interruption codes are 128 + SIGINT (2) or SIGTERM (15).
      expect(exit).toEqual({ code: interrupted ? 128 + (signal === "SIGINT" ? 2 : 15) : 0, signal: null });
      expect(await pathExists(run.home!)).toBe(false);
    } finally {
      await cleanupOwned();
    }
    expect(await pathExists(run.home!)).toBe(false);
  });

  it.each(["SIGINT", "SIGTERM"] as const)("exits with the interruption code and removes the root when %s arrives during seeding", async (signal) => {
    const run = await spawnCli(["--port", String(await getFreePort())], { [DEMO_SEED_HOLD_ENV]: "1" });
    try {
      await waitForOutput(run, DEMO_SEED_HOLD_LINE);
      run.child.kill(signal);
      // POSIX interruption codes are 128 + SIGINT (2) or SIGTERM (15).
      expect(await waitForExit(run)).toEqual({ code: 128 + (signal === "SIGINT" ? 2 : 15), signal: null });
      expect(run.stderr).toContain(`Demo seeding was interrupted by ${signal}.`);
      expect(run.stderr).not.toContain("Demo stopped after ready.");
      expect(run.stdout).not.toContain("Dashboard URL:");
      expect(await pathExists(run.home!)).toBe(false);
    } finally {
      await cleanupOwned();
    }
    expect(await pathExists(run.home!)).toBe(false);
  });

  it("keeps an interrupted root only when --keep is explicit", async () => {
    const run = await spawnCli(["--port", String(await getFreePort()), "--keep"], { [DEMO_SEED_HOLD_ENV]: "1" });
    try {
      await waitForOutput(run, DEMO_SEED_HOLD_LINE);
      run.child.kill("SIGINT");
      // POSIX interruption code: 128 + SIGINT (2).
      expect(await waitForExit(run)).toEqual({ code: 128 + 2, signal: null });
      expect(run.stderr).toContain("Demo seeding was interrupted by SIGINT.");
      expect(await pathExists(run.home!)).toBe(true);
    } finally {
      await cleanupOwned();
    }
    expect(await pathExists(run.home!)).toBe(false);
  });

  // uid 0 ignores directory write bits, so a root that cannot be removed cannot be built when running as root.
  it.skipIf(process.getuid?.() === 0)("reports a root it cannot remove and keeps the interruption exit code", async () => {
    const run = await spawnCli(["--port", String(await getFreePort())], { [DEMO_SEED_HOLD_ENV]: "1" });
    try {
      await waitForOutput(run, DEMO_SEED_HOLD_LINE);
      await lockOwnedDirectory(join(run.home!, "locked"));
      run.child.kill("SIGINT");
      // POSIX interruption code: 128 + SIGINT (2).
      expect(await waitForExit(run)).toEqual({ code: 128 + 2, signal: null });
      expect(run.stderr).toContain("Demo seeding was interrupted by SIGINT.");
      expect(run.stderr).toContain(`Could not remove demo root ${run.home}: `);
      expect(await pathExists(run.home!)).toBe(true);
    } finally {
      await cleanupOwned();
    }
    expect(await pathExists(run.home!)).toBe(false);
  });

  // fail-before-exempt: pins registration before mkdir, so it passes on the base; moving stops.push after mkdir
  // is the planted helper change that turns it red when the missing parent makes mkdir reject.
  it("registers the locked-directory restore before mkdir can fail", async () => {
    const root = ownedDemoRoot();
    const stopsBefore = stops.length;
    const restoresPerDirectory = 1; // Each locked directory needs one restore in the shared cleanup.
    await expect(lockOwnedDirectory(join(root, "missing-parent", "locked"))).rejects.toMatchObject({ code: "ENOENT" });
    // A failed creation must leave its restore registered so interruption cannot outrun cleanup ownership.
    expect(stops).toHaveLength(stopsBefore + restoresPerDirectory);
  });

  // fail-before-exempt: pins the locked-directory restore's place in the shared cleanup, so it passes on the base by
  // construction; its witness is a planted change that removes the restore from the shared cleanup and turns it red.
  // Removing the locking chmod must also turn the removal precondition red, preventing a vacuous cleanup pass.
  it.skipIf(process.getuid?.() === 0)("the shared cleanup restores a locked directory before it removes the owned root", async () => {
    const root = ownedDemoRoot();
    await lockOwnedDirectory(join(root, "locked"));
    // Cleanup proves restoration only if this runner enforces the directory write bits before the restore runs.
    const removalError = await rm(join(root, "locked", "pinned")).then(
      () => undefined,
      (error: unknown) => error,
    );
    expect(
      removalError,
      "lock precondition failed: the runner ignores directory write bits or the locking chmod is missing",
    ).toMatchObject({ code: "EACCES" });
    await cleanupOwned();
    expect(await pathExists(root)).toBe(false);
  });

  it("refuses teardown while the recorded demo pid is live and permits it after exit", async () => {
    const run = await spawnCli(["--port", String(await getFreePort()), "--keep"]);
    try {
      await waitForOutput(run, /^Teardown: /m);
      const pidPath = join(run.home!, DEMO_PID_FILE_BASENAME);
      const pidFile = await readModeAndText(pidPath);
      expect(pidFile.mode).toBe(OPERATOR_TOKEN_FILE_MODE);
      expect(pidFile.text.trim()).toBe(String(run.child.pid));
      const tokenPath = run.stdout.match(/^Operator token file: (.+)$/m)![1];
      const token = (await readFile(tokenPath, "utf8")).trim();
      const refused = await spawnCli(["--teardown", run.home!]);
      expect((await waitForExit(refused)).code).toBe(1);
      expect(refused.stderr.trim().split("\n")).toEqual([`refusing to teardown live demo pid ${run.child.pid}: ${run.home}`]);
      assertNoTokenOutput(token, refused, false);
      expect(await pathExists(run.home!)).toBe(true);
      run.child.kill("SIGINT");
      expect(await waitForExit(run)).toEqual({ code: 0, signal: null });
      expect(await pathExists(run.home!)).toBe(true);
      const removed = await spawnCli(["--teardown", run.home!]);
      expect(await waitForExit(removed)).toEqual({ code: 0, signal: null });
      expect(await pathExists(run.home!)).toBe(false);
    } finally {
      await cleanupOwned();
    }
    expect(await pathExists(run.home!)).toBe(false);
  });

  it("permits teardown of a stopped root without a pid file", async () => {
    const home = ownedDemoRoot();
    try {
      const run = await spawnCli(["--teardown", home]);
      expect(await waitForExit(run)).toEqual({ code: 0, signal: null });
      expect(await pathExists(home)).toBe(false);
    } finally {
      await cleanupOwned();
    }
    expect(await pathExists(home)).toBe(false);
  });

  it("refuses teardown of a root whose pid file is not a pid and leaves it intact", async () => {
    const home = ownedDemoRoot();
    await writeFile(join(home, DEMO_PID_FILE_BASENAME), "not-a-pid\n");
    try {
      const run = await spawnCli(["--teardown", home]);
      expect(await waitForExit(run)).toEqual({ code: 1, signal: null });
      expect(run.stderr).toContain("refusing to teardown demo root with invalid pid: ");
      expect(await pathExists(join(home, DEMO_PID_FILE_BASENAME))).toBe(true);
    } finally {
      await cleanupOwned();
    }
    expect(await pathExists(home)).toBe(false);
  });

  it("refuses teardown of a temp directory the seeder did not name", async () => {
    const foreign = await mkdtemp(join(demoTempParent(), "sanctuary-demo-foreign-"));
    roots.add(foreign);
    try {
      const run = await spawnCli(["--teardown", foreign]);
      expect(await waitForExit(run)).toEqual({ code: 1, signal: null });
      expect(run.stderr.trim()).toBe("refusing to teardown a path not created by the demo seeder");
      expect(await pathExists(foreign)).toBe(true);
    } finally {
      await cleanupOwned();
    }
    expect(await pathExists(foreign)).toBe(false);
  });

  it("refuses teardown of a demo-named directory nested inside a demo root", async () => {
    const home = ownedDemoRoot();
    const nested = join(home, "sdf-nested");
    await mkdir(nested);
    try {
      const run = await spawnCli(["--teardown", nested]);
      expect(await waitForExit(run)).toEqual({ code: 1, signal: null });
      expect(run.stderr.trim()).toBe("refusing to teardown a path not created by the demo seeder");
      expect(await pathExists(nested)).toBe(true);
    } finally {
      await cleanupOwned();
    }
    expect(await pathExists(home)).toBe(false);
  });

  it.each([[["--teardown"]], [["--teardown", "--keep"]]])("refuses %j without a path and starts no demo", async (args) => {
    const run = await spawnCli(args);
    try {
      expect(await waitForExit(run)).toEqual({ code: 1, signal: null });
      expect(run.stderr).toContain("--teardown needs the demo root path.");
      expect(run.stdout).not.toContain("Demo HOME:");
      expect(run.home).toBeUndefined();
    } finally {
      await cleanupOwned();
    }
  });

  it.each([false, true])("owns root cleanup on dashboard startup error (keep=%s)", async (keep) => {
    const port = await occupyEphemeralPort();
    const run = await spawnCli(["--port", String(port), ...(keep ? ["--keep"] : [])]);
    try {
      await waitForOutput(run, /^Demo HOME: /m);
      expect(await waitForExit(run)).toEqual({ code: 1, signal: null });
      expect(run.stdout).not.toContain("Dashboard URL:");
      expect(await pathExists(run.home!)).toBe(keep);
    } finally {
      await cleanupOwned();
    }
    expect(await pathExists(run.home!)).toBe(false);
  });
});
