/**
 * Every state write names its origin. StateStore.write takes no default
 * origin, every production caller passes one, and no tool schema lets an agent
 * supply one.
 */
import { afterEach, describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { createSanctuaryServer } from "../../src/index.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { StateStore, type WriteOptions } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { createTempHome, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";

const SRC_DIR = join(import.meta.dirname, "../../src");

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sourceFiles(path);
    return name.endsWith(".ts") ? [path] : [];
  });
}

/** The text of a call from its opening parenthesis to the balanced close. */
function callText(text: string, open: number): string {
  let depth = 0;
  for (let i = open; i < text.length; i += 1) {
    const c = text[i];
    if (c === "(") depth += 1;
    else if (c === ")") {
      depth -= 1;
      if (depth === 0) return text.slice(open, i + 1);
    }
  }
  throw new Error("unbalanced call");
}

let cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  try {
    for (const cleanup of cleanups.reverse()) await cleanup();
  } finally {
    cleanups = [];
  }
});

describe("state write provenance", () => {
  it("every StateStore.write call site in src passes an explicit origin_actor", () => {
    const counts: Record<string, number> = {};
    for (const file of sourceFiles(SRC_DIR)) {
      const path = relative(SRC_DIR, file);
      if (path === join("cognitive", "state-store.ts")) continue;
      const text = readFileSync(file, "utf8");
      for (const match of text.matchAll(/\b(?:this\.(?:deps\.)?)?stateStore\.write\(/g)) {
        const call = callText(text, match.index + match[0].length - 1);
        expect(call, path).toMatch(/\borigin_actor:/);
        counts[path] = (counts[path] ?? 0) + 1;
      }
    }
    expect(counts).toEqual({
      [join("castle-wall", "observe", "store.ts")]: 1,
      [join("cognitive", "tools.ts")]: 2,
      [join("exit", "bundle.ts")]: 1,
      [join("file-grant", "store.ts")]: 1,
      [join("operational", "task-coordination", "task-service.ts")]: 1,
    });
    // The type requires provenance; this line is checked by typecheck:tests, never run.
    const typeOnly = (store: StateStore, options: Omit<WriteOptions, "provenance">) =>
      // @ts-expect-error a write without provenance does not typecheck
      store.write("ns", "k", "v", "id", { v: 1, alg: "aes-256-gcm", iv: "", ct: "", ts: "" }, new Uint8Array(), options);
    expect(typeof typeOnly).toBe("function");
  });

  it("state_write's input schema has no provenance field", async () => {
    const home = await createTempHome("state-write-provenance");
    cleanups.push(home.cleanup);
    const app = await createSanctuaryServer({ storage: new MemoryStorage(), passphrase: TEST_PASSPHRASE });
    cleanups.push(app.cleanup);
    const handler = (app.server as unknown as { _requestHandlers: Map<string, Function> })._requestHandlers.get("tools/list")!;
    const { tools } = (await handler({ method: "tools/list", params: {} }, {})) as {
      tools: Array<{ name: string; inputSchema: unknown }>;
    };
    const propertyNames = (schema: unknown): string[] => {
      if (schema === null || typeof schema !== "object") return [];
      if (Array.isArray(schema)) return schema.flatMap(propertyNames);
      const record = schema as Record<string, unknown>;
      const own = record.properties !== null && typeof record.properties === "object"
        ? Object.keys(record.properties as object)
        : [];
      return [...own, ...Object.values(record).flatMap(propertyNames)];
    };
    const stateWrite = tools.find((tool) => tool.name === "state_write");
    expect(stateWrite).toBeDefined();
    const names = propertyNames(stateWrite!.inputSchema);
    for (const forbidden of ["provenance", "origin", "origin_actor", "origin_ref"]) {
      expect(names).not.toContain(forbidden);
    }
    for (const tool of tools) expect(propertyNames(tool.inputSchema), tool.name).not.toContain("origin_actor");

    const source = readFileSync(join(SRC_DIR, "cognitive", "tools.ts"), "utf8");
    const start = source.indexOf('name: "state_write",');
    const end = source.indexOf('name: "state_read",', start);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    expect(source.slice(start, end).match(/provenance:/g)).toHaveLength(1);
  });

  it("a write with no origin throws and stores nothing", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const { tools, identityManager } = createL1Tools(new StateStore(storage, masterKey), storage, masterKey, "passphrase");
    await identityManager.load();
    const created = JSON.parse((await tools.find((tool) => tool.name === "identity_create")!.handler({ label: "no-origin" })).content[0]!.text);
    const identity = identityManager.get(created.identity_id as string)!;
    const store = new StateStore(storage, masterKey);
    for (const [key, options] of [
      ["absent", {}],
      ["empty", { provenance: {} }],
      ["unknown", { provenance: { origin_actor: "intruder" } }],
    ] as const) {
      await expect(store.write(
        "notes", key, "v", identity.identity_id, identity.encrypted_private_key,
        derivePurposeKey(masterKey, "identity-encryption"),
        options as unknown as WriteOptions,
      )).rejects.toThrow();
      expect(await storage.read("notes", key)).toBeNull();
    }
  });
});
