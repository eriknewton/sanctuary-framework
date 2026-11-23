/**
 * Every state write names its origin. StateStore.write takes no default
 * origin, every production caller passes one, and no tool schema lets an agent
 * supply one.
 */
import { afterEach, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import ts from "typescript";
import { createSanctuaryServer } from "../../src/index.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { StateStore, type WriteOptions } from "../../src/cognitive/state-store.js";
import { MemoryClassError } from "../../src/exit/memory-class.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { createTempHome, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";

const SERVER_DIR = join(import.meta.dirname, "../..");
const SRC_DIR = join(SERVER_DIR, "src");
const STATE_STORE_FILE = join(SRC_DIR, "cognitive", "state-store.ts");
// Two minutes: a whole-src program build measured at about a second, with headroom for a loaded machine.
const PROGRAM_BUILD_TIMEOUT_MS = 2 * 60 * 1000;

/** A named property's initializer in an object literal, or undefined when it is absent or not a plain assignment. */
function propertyInitializer(literal: ts.ObjectLiteralExpression, name: string): ts.Expression | undefined {
  for (const property of literal.properties) {
    if (ts.isPropertyAssignment(property) && property.name.getText() === name) return property.initializer;
  }
  return undefined;
}

/** Whether a write call's options literal carries provenance with an explicit origin_actor. */
function namesOrigin(call: ts.CallExpression, optionsIndex: number): boolean {
  const options = call.arguments[optionsIndex];
  if (options === undefined || !ts.isObjectLiteralExpression(options)) return false;
  const provenance = propertyInitializer(options, "provenance");
  return provenance !== undefined && ts.isObjectLiteralExpression(provenance)
    && propertyInitializer(provenance, "origin_actor") !== undefined;
}

/**
 * Every dot property access `<receiver>.write` in src whose symbol is StateStore.write, or whose receiver is typed
 * StateStore, found through the type checker: a receiver of any name (or a Pick of the class) is matched, and a
 * match inside a comment or string is impossible. A matched access that is the callee of a call is a call site; any
 * other matched access (for example `const w = store.write`) is reported as a non-call. Bracket access and
 * destructuring are not visited; the required options parameter and StateStore.write's own provenance check cover
 * those shapes. Program build cost is the same as the other ts.createProgram structure tests in this directory.
 */
function stateStoreWriteReferences(): { calls: Array<{ path: string; namesOrigin: boolean }>; nonCalls: string[] } {
  const configFile = ts.readConfigFile(join(SERVER_DIR, "tsconfig.json"), ts.sys.readFile);
  const parsed = ts.parseJsonConfigFileContent(configFile.config, ts.sys, SERVER_DIR);
  const program = ts.createProgram(parsed.fileNames, { ...parsed.options, noEmit: true });
  const checker = program.getTypeChecker();
  const storeSource = program.getSourceFile(STATE_STORE_FILE);
  expect(storeSource, "program does not contain cognitive/state-store.ts").toBeDefined();
  let writeDeclaration: ts.MethodDeclaration | undefined;
  let classSymbol: ts.Symbol | undefined;
  for (const statement of storeSource!.statements) {
    if (!ts.isClassDeclaration(statement) || statement.name?.text !== "StateStore") continue;
    classSymbol = checker.getSymbolAtLocation(statement.name);
    writeDeclaration = statement.members.find((member): member is ts.MethodDeclaration =>
      ts.isMethodDeclaration(member) && member.name.getText() === "write");
  }
  expect(writeDeclaration, "StateStore.write not found").toBeDefined();
  // The options argument's position is read from the declaration itself, so the check follows any parameter change.
  const optionsIndex = writeDeclaration!.parameters.findIndex((parameter) => parameter.name.getText() === "options");
  expect(optionsIndex, "StateStore.write has no options parameter").toBeGreaterThanOrEqual(0);
  const calls: Array<{ path: string; namesOrigin: boolean }> = [];
  const nonCalls: string[] = [];
  for (const sourceFile of program.getSourceFiles()) {
    if (sourceFile.isDeclarationFile || !sourceFile.fileName.startsWith(SRC_DIR + sep) || sourceFile === storeSource) continue;
    const path = relative(SRC_DIR, sourceFile.fileName);
    const visit = (node: ts.Node): void => {
      if (ts.isPropertyAccessExpression(node) && node.name.text === "write") {
        const symbol = checker.getSymbolAtLocation(node.name);
        const receiver = checker.getTypeAtLocation(node.expression);
        const isStoreWrite = symbol?.declarations?.includes(writeDeclaration!) === true
          || (classSymbol !== undefined && (receiver.getSymbol() === classSymbol
            || (receiver.isUnion() && receiver.types.some((type) => type.getSymbol() === classSymbol))));
        if (isStoreWrite) {
          const parent = node.parent;
          if (ts.isCallExpression(parent) && parent.expression === node) calls.push({ path, namesOrigin: namesOrigin(parent, optionsIndex) });
          else nonCalls.push(`${path}:${sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1}`);
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sourceFile);
  }
  return { calls, nonCalls };
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
    const { calls, nonCalls } = stateStoreWriteReferences();
    // Every matched dot access is a direct call, so no aliased reference taken through one can drop the options argument.
    expect(nonCalls).toEqual([]);
    const counts: Record<string, number> = {};
    for (const call of calls) {
      expect(call.namesOrigin, call.path).toBe(true);
      counts[call.path] = (counts[call.path] ?? 0) + 1;
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
  }, PROGRAM_BUILD_TIMEOUT_MS);

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

  it("a write with no options or no provenance is refused with the typed origin refusal and stores nothing", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const { tools, identityManager } = createL1Tools(new StateStore(storage, masterKey), storage, masterKey, "passphrase");
    await identityManager.load();
    const created = JSON.parse((await tools.find((tool) => tool.name === "identity_create")!.handler({ label: "no-provenance" })).content[0]!.text);
    const identity = identityManager.get(created.identity_id as string)!;
    const encKey = derivePurposeKey(masterKey, "identity-encryption");
    const store = new StateStore(storage, masterKey);
    /** Every namespace, key and byte the backend holds, so an untouched store is compared whole. */
    const snapshot = async () => {
      const all: Record<string, string> = {};
      for (const namespace of await storage.listNamespaces()) {
        for (const key of await storage.listKeys(namespace)) {
          all[`${namespace}/${key}`] = Buffer.from((await storage.read(namespace, key))!).toString("base64");
        }
      }
      return all;
    };
    const before = await snapshot();
    // Each call bypasses the type the way a JS caller or a cast can.
    const write = store.write.bind(store) as unknown as (...args: unknown[]) => Promise<unknown>;
    const fixed = ["notes", "k", "v", identity.identity_id, identity.encrypted_private_key, encKey] as const;
    for (const [name, call] of [
      ["six arguments", () => write(...fixed)],
      ["undefined options", () => write(...fixed, undefined)],
      ["empty options", () => write(...fixed, {})],
    ] as const) {
      let thrown: unknown;
      try {
        await call();
      } catch (error) {
        thrown = error;
      }
      expect(thrown, name).toBeInstanceOf(MemoryClassError);
      expect((thrown as MemoryClassError).code, name).toBe("invalid_origin_actor");
      expect(await snapshot(), name).toEqual(before);
    }
  });
});
