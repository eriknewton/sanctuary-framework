/** Help guidance and declared input bounds are wired through the production tool router. */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { createSanctuaryServer } from "../../src/index.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { createTempHome, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";

let home: Awaited<ReturnType<typeof createTempHome>>;
let originalSession: string | undefined;
let cleanups: Array<() => Promise<void>>;
beforeEach(async () => {
  originalSession = process.env.SANCTUARY_SESSION_IDENTITY_ID;
  delete process.env.SANCTUARY_SESSION_IDENTITY_ID;
  cleanups = [];
  home = await createTempHome("sanctuary-help-wiring");
});
afterEach(async () => {
  try {
    for (const cleanup of cleanups.reverse()) await cleanup();
  } finally {
    if (originalSession === undefined) delete process.env.SANCTUARY_SESSION_IDENTITY_ID;
    else process.env.SANCTUARY_SESSION_IDENTITY_ID = originalSession;
    await home.cleanup();
  }
});
async function boot() {
  const app = await createSanctuaryServer({ storage: new MemoryStorage(), passphrase: TEST_PASSPHRASE });
  cleanups.push(() => app.cleanup());
  const handler = (app.server as unknown as { _requestHandlers: Map<string, Function> })._requestHandlers.get("tools/call");
  if (!handler) throw new Error("tools/call handler not registered");
  return async (name: string, args: Record<string, unknown>) => {
    const result = await handler({ method: "tools/call", params: { name, arguments: args } }, {});
    return JSON.parse(result.content[0].text) as Record<string, unknown>;
  };
}
const intent = "leave a short note for the next coordinator session to read when it starts";
describe("help through the production router", () => {
  it("returns a write template in a bound session", async () => {
    const call = await boot();
    const identity = await call("identity_create", { label: "help-owner" });
    expect(identity.identity_id).toEqual(expect.any(String));
    process.env.SANCTUARY_SESSION_IDENTITY_ID = identity.identity_id as string;
    const result = await call("sanctuary_help", { intent });
    expect(result).toMatchObject({ safety_class: "ordinary", tool: "sanctuary_remember", example: { key: "<key>", value: "<value>" } });
    expect(result).not.toHaveProperty("session_bound");
    expect(result).not.toHaveProperty("probe_key");
  });
  it("preserves the production schema's length registration through tool wrapping", async () => {
    const call = await boot();
    const longIntent = "lorem ".repeat(682) + "ipsum";
    expect(longIntent).toHaveLength(4097);
    expect(await call("sanctuary_help", { intent: longIntent })).toEqual({
      error: "validation_failed", message: "Tool arguments failed schema validation",
      violations: [{ field: "intent", message: 'Field "intent" exceeds maximum length (4097 code points > 4096 code points)' }],
    });
  });
  it("returns classified guidance and binding availability without a session identity", async () => {
    const call = await boot();
    const gated = await call("sanctuary_help", { intent: "export the note" });
    expect(gated).toMatchObject({ safety_class: "gated", tool: null, example: { args: "<operator-approved placeholders only>" } });
    const ordinary = await call("sanctuary_help", { intent });
    expect(ordinary).toMatchObject({ tool: "sanctuary_remember", session_bound: false });
    for (const result of [gated, ordinary]) {
      for (const field of ["error", "denied", "status", "probe_key"]) expect(result).not.toHaveProperty(field);
    }
  });
  it("uses the extracted classifier as the cooperative surface's sole classifier", async () => {
    const source = await readFile(new URL("../../src/agent-native/cooperative-surface.ts", import.meta.url), "utf8");
    expect(source).toMatch(/import\s*\{[^}]*\bclassifyIntent\b[^}]*\}\s*from\s*["']\.\/intent-classifier\.js["']/);
    expect(source).toMatch(/classifyIntent\(args\.intent as string\)/);
    expect(source).not.toMatch(/function\s+classifyIntent|const\s+(?:gated|MEMORY_VERBS|HELP_WRITE_CUES|HELP_STRONG_READ_CUES)\s*=/);
    expect(source).not.toContain('"removepermanently"');
  });
});
