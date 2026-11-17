/**
 * Contracts the Hermes owner verbs share with the bridge: one id grammar, one
 * audit principal string, one adapter composition used by both the bridge and
 * the owner verbs, the frozen tool catalog as a full set, and the bridge-mode
 * adapter's refusal of every content mutator the owner delete relies on.
 */
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";

import * as compositionModule from "../../src/hermes-memory-bridge/memory-adapter-composition.js";
import {
  HERMES_MEMORY_TOOL_NAMES, ID_GRAMMAR, hermesBridgeAuditPrincipal,
} from "../../src/hermes-memory-bridge/index.js";
import { createSdwMemoryAdapter } from "../../src/index.js";
import { SdwValidationError } from "../../src/sdw/errors.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import {
  ownerFortress, runCleanups, runVerb, seedPassage, startBridge, type Cleanup,
} from "../helpers/hermes-owner-fortress.js";

const stack: Cleanup[] = [];
const dirs: string[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  await runCleanups(stack);
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

const read = (path: string) => readFile(fileURLToPath(new URL(path, import.meta.url)), "utf8");

describe("owner verbs share the bridge's sources", () => {
  it("exports the id grammar from process-shell and the owner verbs import it rather than copying it", async () => {
    expect(ID_GRAMMAR.test("agent-owner")).toBe(true);
    expect(ID_GRAMMAR.test("Agent")).toBe(false);
    expect(ID_GRAMMAR.test("a".repeat(64))).toBe(false);
    const owner = await read("../../src/cli/hermes-memory.ts");
    expect(owner).toMatch(/import \{[^}]*\bID_GRAMMAR\b[^}]*\} from "\.\.\/hermes-memory-bridge\/index\.js"/u);
    expect(owner).not.toContain("[a-z0-9][a-z0-9-]{0,62}");
  });

  it("builds the bridge's agent principal from one helper used by bridge-core and the report", async () => {
    expect(hermesBridgeAuditPrincipal("agent-owner")).toBe("agent:agent-owner");
    const core = await read("../../src/hermes-memory-bridge/bridge-core.ts");
    expect(core).toContain("agent_id: hermesBridgeAuditPrincipal(this.ports.agentId)");
    expect(core.match(/`agent:\$\{/gu)).toHaveLength(1);
    const owner = await read("../../src/cli/hermes-memory.ts");
    expect(owner).toContain("hermesBridgeAuditPrincipal(args.agentId)");
    expect(owner).not.toContain("`agent:${");
  });

  it("composes the bridge's adapter and the owner verbs' adapter from the same shared function", async () => {
    const f = await ownerFortress(stack);
    await seedPassage(f, "p1", "composition passage");
    const spy = vi.spyOn(compositionModule, "composeHermesMemoryAdapterOptions");
    const bridge = startBridge(f, stack);
    expect(await bridge.next()).toEqual({ type: "ready" });
    await bridge.stop();
    // The bridge runs in its own process; its use of the shared function is pinned at the source.
    const shell = await read("../../src/hermes-memory-bridge/process-shell.ts");
    expect(shell).toContain("await composeHermesMemoryAdapterOptions({");
    expect(shell).not.toContain("new KnownSignersStore(");
    expect(shell).not.toContain("new MemoryProvenanceBadSignerStore(");
    const run = await runVerb(f, ["memory-show", "--passage", "p1"]);
    expect(run.code, run.err).toBe(0);
    expect(spy).toHaveBeenCalledOnce();
    expect(spy.mock.calls[0]![0]).toMatchObject({ ownerRef: "agent-owner", fortressId: f.fortressId });
  });
});

describe("the agent's reach is unchanged", () => {
  it("keeps the frozen seven-tool catalog as a full set", () => {
    expect([...HERMES_MEMORY_TOOL_NAMES].sort()).toEqual([
      "export_memory", "memory_get", "memory_insert", "memory_recall", "memory_search", "protection_rules", "sign_statement",
    ]);
    expect(new Set(HERMES_MEMORY_TOOL_NAMES).size).toBe(HERMES_MEMORY_TOOL_NAMES.length);
  });

  it("refuses putPassages, putPassagesIfAbsent and deletePassage in bridge mode with operation_refused", async () => {
    const dir = await mkdtemp(join(tmpdir(), "bridge-mode-refusal-"));
    dirs.push(dir);
    const adapter = createSdwMemoryAdapter({
      mode: "hermes-bridge",
      storage: new FilesystemStorage(join(dir, "state")),
      masterKey: new Uint8Array(32).fill(1),
      fortressId: "fortress-refusal",
      ownerRef: "agent-refusal",
      resolvePrimarySigningHandle: () => { throw new Error("never signs"); },
      resolveSignerPublicKey: () => undefined,
      resolveMemoryIntegrityState: async () => "state_COMPLETE",
      commitCheck: { assertAllowedToCommit: async () => undefined },
      badSignerAuthority: { isMarked: async () => false },
    });
    const refusals = [
      () => adapter.putPassages([], "user_content"),
      () => adapter.putPassagesIfAbsent([], "user_content"),
      () => adapter.deletePassage("p1"),
    ];
    for (const attempt of refusals) {
      const error = await attempt().then(() => undefined, cause => cause);
      expect(error).toBeInstanceOf(SdwValidationError);
      expect((error as SdwValidationError).category).toBe("operation_refused");
    }
  });
});
