/**
 * v1.1.5 (Finding Z) — wrap persists a hub `LocalAgentRecord` so the
 * v1.1 dashboard's Agents view reflects what wrap registered.
 *
 * v1.1.1 shipped the hub API surface (`/api/hub/agents`) backed by an
 * in-memory `InMemoryLocalAgentRegistry` that was constructed empty on
 * every boot (`server/src/dashboard/v1_1/wiring.ts:12-15` documented the
 * deferral). The 2026-04-27 acceptance drill arrested at Phase 1.3
 * because wrap reported success while the v1.1 dashboard's Agents view
 * stayed empty: wrap had no write-side path into the registry, and the
 * registry had no read-side path off disk.
 *
 * v1.1.5 closes the gap with a single hub-layer file at
 * `<storagePath>/state/_hub/local-agents.json`. These tests pin three
 * surfaces:
 *
 *   1. The persistence module's atomic write + best-effort read +
 *      upsert-by-agent_id behavior.
 *   2. `runWrap` end-to-end: a fresh wrap creates the file with mode
 *      0600 and the correct record; a second wrap of a different harness
 *      against the same fortress appends; re-wrapping the same harness
 *      updates rather than duplicates.
 *   3. `buildV11Bindings()` rehydrates the registry from the file when
 *      `storagePath` is passed, so the wrap-auto dashboard and the
 *      standalone dashboard both surface the persisted records.
 *
 * The L1 cognitive identity layer is intentionally left at lazy-init
 * (created on first fortress-unlock; see `cli.ts:588-593`). The hub
 * registry and L1 identities track different concerns and stay
 * decoupled in this hotfix.
 */

import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { mkdirSync, statSync, writeFileSync } from "node:fs";
import {
  cp,
  mkdir,
  readFile,
  rm,
  stat,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  localAgentsFilePath,
  readPersistedLocalAgents,
  upsertPersistedLocalAgent,
  writePersistedLocalAgents,
} from "../../src/hub/agent-registry-persistence.js";
import {
  buildV11Bindings,
  fortressIdFromStoragePath,
} from "../../src/dashboard/v1_1/wiring.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import {
  runWrap,
  type DashboardStarter,
  type RunWrapDeps,
  type WrapOptions,
} from "../../src/wrap/cli.js";
import { establishWrapCustody } from "../../src/wrap/custody-flow.js";
import {
  WORKLOAD_LIFECYCLE_OPS,
  WorkloadRegistry,
} from "../../src/workload-lifecycle/index.js";
import type { DashboardHandle } from "../../src/dashboard/index.js";
import type { LocalAgentRecord } from "../../src/contracts/v1.1/local-agent-records.js";
import { randomBytes } from "node:crypto";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const fixturesDir = join(__dirname, "..", "harness", "fixtures");

function makeRecord(partial: Partial<LocalAgentRecord> = {}): LocalAgentRecord {
  const nowIso = new Date().toISOString();
  return {
    version: "1.1",
    agent_id: "agent:claude_code:test-fortress-id",
    identity_id: "fortress:/tmp/test",
    harness: "claude_code",
    model_provider: {
      vendor: "unknown",
      model_id: "unknown",
      runs_locally: false,
    },
    policy_id: "unbound",
    status: "active",
    budget_summary: { last_refreshed_at: nowIso },
    last_activity_at: nowIso,
    wrapped_at: nowIso,
    capabilities: {
      can_pause: false,
      can_resume: false,
      can_restart: false,
      can_unwrap: true,
      can_lockdown: false,
      can_chat: false,
      can_change_template: false,
    },
    ...partial,
  };
}

describe("agent-registry-persistence module", () => {
  let tmpFortress: string;

  beforeEach(async () => {
    tmpFortress = join(
      tmpdir(),
      `sanctuary-z-persist-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
    await mkdir(tmpFortress, { recursive: true, mode: 0o700 });
  });

  afterEach(async () => {
    await rm(tmpFortress, { recursive: true, force: true });
  });

  it("localAgentsFilePath returns the canonical hub-layer path", () => {
    const path = localAgentsFilePath(tmpFortress);
    expect(path).toBe(
      join(tmpFortress, "state", "_hub", "local-agents.json"),
    );
  });

  it("readPersistedLocalAgents returns [] when the file does not exist", () => {
    expect(readPersistedLocalAgents(tmpFortress)).toEqual([]);
  });

  it("readPersistedLocalAgents returns [] on JSON parse error (best-effort)", async () => {
    const path = localAgentsFilePath(tmpFortress);
    await mkdir(dirname(path), { recursive: true });
    writeFileSync(path, "not valid json{{{", { mode: 0o600 });
    expect(readPersistedLocalAgents(tmpFortress)).toEqual([]);
  });

  it("readPersistedLocalAgents returns [] when payload lacks agents array", async () => {
    const path = localAgentsFilePath(tmpFortress);
    await mkdir(dirname(path), { recursive: true });
    writeFileSync(
      path,
      JSON.stringify({ version: "1.1", wrong_field: 42 }),
      { mode: 0o600 },
    );
    expect(readPersistedLocalAgents(tmpFortress)).toEqual([]);
  });

  it("writePersistedLocalAgents creates the file with mode 0600", async () => {
    const record = makeRecord();
    writePersistedLocalAgents(tmpFortress, [record]);
    const path = localAgentsFilePath(tmpFortress);
    const s = await stat(path);
    // Mask off the file-type bits; only the permission bits should be 0o600.
    expect((s.mode & 0o777).toString(8)).toBe("600");
  });

  it("writePersistedLocalAgents creates the parent directory chain with mode 0700", async () => {
    const record = makeRecord();
    writePersistedLocalAgents(tmpFortress, [record]);
    const hubDir = join(tmpFortress, "state", "_hub");
    const s = await stat(hubDir);
    expect((s.mode & 0o777).toString(8)).toBe("700");
  });

  it("write + read round-trip preserves all fields (single record)", () => {
    const record = makeRecord({
      agent_id: "agent:claude_code:abc123",
      harness_version: "1.0.40",
    });
    writePersistedLocalAgents(tmpFortress, [record]);
    const read = readPersistedLocalAgents(tmpFortress);
    expect(read).toHaveLength(1);
    expect(read[0]).toEqual(record);
  });

  it("write + read round-trip preserves multiple records in order", () => {
    const a = makeRecord({ agent_id: "a", harness: "claude_code" });
    const b = makeRecord({ agent_id: "b", harness: "openclaw" });
    const c = makeRecord({ agent_id: "c", harness: "cursor" });
    writePersistedLocalAgents(tmpFortress, [a, b, c]);
    const read = readPersistedLocalAgents(tmpFortress);
    expect(read.map((r) => r.agent_id)).toEqual(["a", "b", "c"]);
  });

  it("upsertPersistedLocalAgent appends a new record when agent_id is novel", () => {
    const a = makeRecord({ agent_id: "a" });
    const b = makeRecord({ agent_id: "b", harness: "openclaw" });
    upsertPersistedLocalAgent(tmpFortress, a);
    upsertPersistedLocalAgent(tmpFortress, b);
    const read = readPersistedLocalAgents(tmpFortress);
    expect(read).toHaveLength(2);
    expect(read.map((r) => r.agent_id).sort()).toEqual(["a", "b"]);
  });

  it("upsertPersistedLocalAgent preserves wrapped_at and bumps last_activity_at on update", async () => {
    const original = makeRecord({
      agent_id: "agent:claude_code:fixed",
      wrapped_at: "2026-01-01T00:00:00.000Z",
      last_activity_at: "2026-01-01T00:00:00.000Z",
    });
    upsertPersistedLocalAgent(tmpFortress, original);
    // Wait a tick so the new last_activity_at is observably later.
    await new Promise((r) => setTimeout(r, 5));
    const updated = makeRecord({
      agent_id: "agent:claude_code:fixed",
      wrapped_at: "2099-12-31T23:59:59.999Z",
      last_activity_at: "2099-12-31T23:59:59.999Z",
      harness_version: "1.1.0",
    });
    upsertPersistedLocalAgent(tmpFortress, updated);
    const read = readPersistedLocalAgents(tmpFortress);
    expect(read).toHaveLength(1);
    expect(read[0]!.wrapped_at).toBe("2026-01-01T00:00:00.000Z");
    expect(read[0]!.last_activity_at).not.toBe("2026-01-01T00:00:00.000Z");
    expect(read[0]!.harness_version).toBe("1.1.0");
  });

  it("upsertPersistedLocalAgent returns the next list (avoids re-read race)", () => {
    const a = makeRecord({ agent_id: "a" });
    const result = upsertPersistedLocalAgent(tmpFortress, a);
    expect(result).toHaveLength(1);
    expect(result[0]!.agent_id).toBe("a");
  });
});

describe("buildV11Bindings rehydrates from local-agents.json", () => {
  let tmpFortress: string;

  beforeEach(async () => {
    tmpFortress = join(
      tmpdir(),
      `sanctuary-z-rehydrate-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
    await mkdir(tmpFortress, { recursive: true, mode: 0o700 });
  });

  afterEach(async () => {
    await rm(tmpFortress, { recursive: true, force: true });
  });

  it("seeds an empty registry when no storagePath is passed (legacy behavior)", () => {
    const auditLog = new AuditLog(new MemoryStorage(), randomBytes(32));
    const { hubService } = buildV11Bindings({
      identityId: "id-1",
      fortressId: fortressIdFromStoragePath(tmpFortress),
      auditLog,
    });
    expect(hubService.listAgents()).toEqual([]);
  });

  it("seeds an empty registry when storagePath has no persisted file (first boot)", () => {
    const auditLog = new AuditLog(new MemoryStorage(), randomBytes(32));
    const { hubService } = buildV11Bindings({
      identityId: "id-1",
      fortressId: fortressIdFromStoragePath(tmpFortress),
      auditLog,
      storagePath: tmpFortress,
    });
    expect(hubService.listAgents()).toEqual([]);
  });

  it("rehydrates the registry from the persisted file", () => {
    // hub-service filters listAgents by identity_id, so seeded records
    // must declare the same identity the bindings are constructed with.
    // This mirrors the production shape: wrap and the standalone
    // dashboard both bind `identityId: fortress:${storagePath}` and
    // wrap writes records with the same value.
    const operatorIdentity = `fortress:${tmpFortress}`;
    const a = makeRecord({
      agent_id: "agent:claude_code:x",
      harness: "claude_code",
      identity_id: operatorIdentity,
    });
    const b = makeRecord({
      agent_id: "agent:openclaw:x",
      harness: "openclaw",
      identity_id: operatorIdentity,
    });
    writePersistedLocalAgents(tmpFortress, [a, b]);
    const auditLog = new AuditLog(new MemoryStorage(), randomBytes(32));
    const { hubService } = buildV11Bindings({
      identityId: operatorIdentity,
      fortressId: fortressIdFromStoragePath(tmpFortress),
      auditLog,
      storagePath: tmpFortress,
    });
    const agents = hubService.listAgents();
    expect(agents.map((r) => r.agent_id).sort()).toEqual([
      "agent:claude_code:x",
      "agent:openclaw:x",
    ]);
  });

  it("degrades to empty registry when the file is corrupted (best-effort)", () => {
    const path = localAgentsFilePath(tmpFortress);
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    writeFileSync(path, "{ not valid json", { mode: 0o600 });
    const auditLog = new AuditLog(new MemoryStorage(), randomBytes(32));
    const { hubService } = buildV11Bindings({
      identityId: "id-1",
      fortressId: fortressIdFromStoragePath(tmpFortress),
      auditLog,
      storagePath: tmpFortress,
    });
    expect(hubService.listAgents()).toEqual([]);
  });
});

describe("runWrap persists a LocalAgentRecord (Finding Z)", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;
  let originalPassphrase: string | undefined;
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    tmpHome = join(
      tmpdir(),
      `sanctuary-z-runwrap-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
    await mkdir(tmpHome, { recursive: true });
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    originalPassphrase = process.env.SANCTUARY_PASSPHRASE;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
    process.env.SANCTUARY_PASSPHRASE = "fixture-passphrase-z";
    stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(async () => {
    stderrSpy.mockRestore();
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalStoragePath === undefined) {
      delete process.env.SANCTUARY_STORAGE_PATH;
    } else {
      process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    }
    if (originalPassphrase === undefined) delete process.env.SANCTUARY_PASSPHRASE;
    else process.env.SANCTUARY_PASSPHRASE = originalPassphrase;
    vi.restoreAllMocks();
    await rm(tmpHome, { recursive: true, force: true });
  });

  function deps(): RunWrapDeps {
    const startDashboard: DashboardStarter = async (startOpts) => {
      return {
        url: `http://127.0.0.1:${startOpts.port}`,
        port: startOpts.port,
        host: "127.0.0.1",
        mode: "co-located",
        stop: async () => {},
        setV11Bindings: () => {},
        setV11LoopbackAutoAuth: () => {},
      } as unknown as DashboardHandle;
    };
    return {
      startDashboard,
      openBrowser: async () => {},
      resolvePassphrase: async () => ({
        value: "fixture-passphrase-z",
        location: "fixture-keychain",
        source: "generated" as const,
      }),
    };
  }

  async function installFixture(
    relPath: string,
    fixtureName: string,
  ): Promise<string> {
    const target = join(tmpHome, relPath);
    await mkdir(dirname(target), { recursive: true });
    await cp(join(fixturesDir, fixtureName), target);
    return target;
  }

  function storagePath(): string {
    return process.env.SANCTUARY_STORAGE_PATH!;
  }

  function options(extra: WrapOptions = {}): WrapOptions {
    return { claudeCode: true, noOpen: true, ...extra };
  }

  async function workloadAuditLog(): Promise<AuditLog> {
    const custody = await establishWrapCustody({
      storagePath: storagePath(),
      passphrase: "fixture-passphrase-z",
      interactive: false,
    });
    return new AuditLog(
      new FilesystemStorage(join(storagePath(), "state")),
      custody.masterKey,
    );
  }

  async function expectRecordedWorkloadRegistration(
    persisted: LocalAgentRecord,
  ): Promise<void> {
    const auditLog = await workloadAuditLog();
    const registered = await auditLog.query({
      operation_type: WORKLOAD_LIFECYCLE_OPS.REGISTERED,
    });
    expect(registered.entries).toHaveLength(1);
    expect(registered.entries[0]!.identity_id).toBe(
      fortressIdFromStoragePath(storagePath()),
    );
    expect(registered.entries[0]!.details).toMatchObject({
      workload_id: persisted.agent_id,
      instance_id: persisted.agent_id,
      workload_class: "wrapped-agent-harness",
      consent_ref: null,
      consent_status: "absent",
      state_disposition: "running",
      manufactured_preference_caveat: true,
    });

    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    expect(registry.get(persisted.agent_id)).toMatchObject({
      workload_id: persisted.agent_id,
      state: "registered",
      consent_status: "absent",
      consent_ref: null,
    });
  }

  it("first wrap creates state/_hub/local-agents.json and records a lifecycle declaration", async () => {
    await installFixture(".claude.json", "flat-mcp.json");
    await runWrap(options(), deps());

    const filePath = localAgentsFilePath(storagePath());
    const s = statSync(filePath);
    expect((s.mode & 0o777).toString(8)).toBe("600");

    const persisted = readPersistedLocalAgents(storagePath());
    expect(persisted).toHaveLength(1);
    expect(persisted[0]!.harness).toBe("claude_code");
    expect(persisted[0]!.identity_id).toBe(`fortress:${storagePath()}`);
    expect(persisted[0]!.policy_id).toBe("unbound");
    expect(persisted[0]!.model_provider.vendor).toBe("unknown");
    expect(persisted[0]!.status).toBe("active");
    expect(persisted[0]!.capabilities.can_unwrap).toBe(true);
    expect(persisted[0]!.capabilities.can_pause).toBe(false);
    await expectRecordedWorkloadRegistration(persisted[0]!);
  });

  it("no-dashboard wrap records the harness as a declared workload in the audit chain", async () => {
    await installFixture(".claude.json", "flat-mcp.json");
    await runWrap(options({ noDashboard: true }), deps());

    const [persisted] = readPersistedLocalAgents(storagePath());
    expect(persisted).toBeDefined();
    await expectRecordedWorkloadRegistration(persisted!);
  });

  it("second wrap of a different harness against the same fortress appends a second record", async () => {
    await installFixture(".claude.json", "flat-mcp.json");
    await runWrap(options({ claudeCode: true }), deps());

    await installFixture(".cursor/mcp.json", "flat-mcp.json");
    await runWrap(options({ claudeCode: false, cursor: true }), deps());

    const persisted = readPersistedLocalAgents(storagePath());
    expect(persisted).toHaveLength(2);
    expect(persisted.map((r) => r.harness).sort()).toEqual([
      "claude_code",
      "cursor",
    ]);
  });

  it("re-wrapping the same harness updates the existing record (no duplicate)", async () => {
    await installFixture(".claude.json", "flat-mcp.json");
    await runWrap(options(), deps());

    const firstPersisted = readPersistedLocalAgents(storagePath());
    expect(firstPersisted).toHaveLength(1);
    const firstWrappedAt = firstPersisted[0]!.wrapped_at;

    await new Promise((r) => setTimeout(r, 5));
    await runWrap(options(), deps());

    const secondPersisted = readPersistedLocalAgents(storagePath());
    expect(secondPersisted).toHaveLength(1);
    // wrapped_at preserved across re-wrap
    expect(secondPersisted[0]!.wrapped_at).toBe(firstWrappedAt);
    // last_activity_at bumped past the original
    expect(secondPersisted[0]!.last_activity_at >= firstWrappedAt).toBe(true);
  });

  it("a wrap-flow error in persistence is surfaced on stderr but does not fail wrap", async () => {
    // Pre-create the _hub directory as a regular FILE so the mkdir-recursive
    // call inside writePersistedLocalAgents fails. wrap should still
    // complete (the harness config rewrite is the security-bearing path);
    // the dashboard surface degrades to empty.
    const blockerPath = join(storagePath(), "state", "_hub");
    await mkdir(dirname(blockerPath), { recursive: true });
    writeFileSync(blockerPath, "i am a file blocking the dir", {
      mode: 0o600,
    });
    await installFixture(".claude.json", "flat-mcp.json");

    // Wrap completes (no throw).
    await runWrap(options(), deps());

    // The harness config was still rewritten (the mainline wrap path).
    const configRaw = await readFile(join(tmpHome, ".claude.json"), "utf-8");
    const parsed = JSON.parse(configRaw) as { mcpServers?: Record<string, unknown> };
    expect(parsed.mcpServers?.sanctuary).toBeDefined();

    // The persistence note is on stderr.
    const stderr = (
      console.error as unknown as { mock: { calls: unknown[][] } }
    ).mock.calls
      .map((call) => call.join(" "))
      .join("\n");
    expect(stderr).toContain("v1.1 hub agent record not persisted");
  });
});
