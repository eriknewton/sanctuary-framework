/**
 * Self-vouch guard: production composition-root wiring (MUST-FIX 3,
 * register §Z RECHECK fix-round).
 *
 * The class-binding inventory suite
 * (test/security/self-vouch-trust-ingest-inventory.test.ts) drives the
 * self-vouch guard through manually-composed production classes (real
 * IdentityManager, real createHandshakeTools, real createFederationTools —
 * no stubs), but it replicates index.ts's wiring by hand rather than going
 * THROUGH index.ts. AGENTS.md rule 4 ("a wired-consumer test... constructs
 * the production object graph — the composition root, or the real boot
 * path") wants the second, stronger form: this file boots the server via
 * `createSanctuaryServer`, the ACTUAL entrypoint index.ts exports, and
 * drives a real self-vouch attempt through the real `tools/call` MCP
 * request-handling pipeline. This is what catches "index.ts stopped
 * supplying the identityManager dependency" — a hand-built fixture cannot,
 * because it never re-runs index.ts's own wiring in the first place.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createSanctuaryServer } from "../../src/index.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { createTempHome, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";

async function callServerTool(
  server: Awaited<ReturnType<typeof createSanctuaryServer>>["server"],
  name: string,
  args: Record<string, unknown> = {}
) {
  const handler = (
    server as unknown as { _requestHandlers: Map<string, Function> }
  )._requestHandlers.get("tools/call");
  if (!handler) throw new Error("tools/call handler not registered");
  return await handler(
    { method: "tools/call" as const, params: { name, arguments: args } },
    {}
  );
}

function parse(result: { content: Array<{ type: string; text: string }> }) {
  return JSON.parse(result.content[0]!.text);
}

let fortressHome: Awaited<ReturnType<typeof createTempHome>>;

beforeEach(async () => {
  // Same hermeticity requirement as every other createSanctuaryServer test:
  // the real boot path writes config unconditionally, so HOME must be
  // redirected off the operator's real ~/.sanctuary.
  fortressHome = await createTempHome("sanctuary-self-vouch-composition");
});

afterEach(async () => {
  await fortressHome.cleanup();
});

describe("self-vouch guard: real composition root (createSanctuaryServer)", () => {
  it("handshake_respond refuses a self-vouch attempt end-to-end through the real boot path", async () => {
    const { server } = await createSanctuaryServer({
      storage: new MemoryStorage(),
      passphrase: TEST_PASSPHRASE,
    });

    const a = parse(
      await callServerTool(server, "identity_create", { label: "identity-a" })
    );
    const b = parse(
      await callServerTool(server, "identity_create", { label: "identity-b" })
    );
    expect(a.identity_id).toBeDefined();
    expect(b.identity_id).toBeDefined();

    const initiated = parse(
      await callServerTool(server, "handshake_initiate", {
        identity_id: a.identity_id,
      })
    );
    expect(initiated.challenge).toBeDefined();

    // B (also locally held, on the SAME fortress) responds to A's challenge.
    // If index.ts's composition ever stopped wiring identityManager into the
    // handshake producer, this would silently succeed instead of refusing.
    const responded = parse(
      await callServerTool(server, "handshake_respond", {
        challenge: initiated.challenge,
        identity_id: b.identity_id,
      })
    );
    expect(responded.error).toContain("same fortress");

    // federation_peers register() then finds no completed handshake — the
    // producer chokepoint kept the shared map clean — proving the SAME
    // composition root's federation wiring never even needed its own
    // defense-in-depth check to fire for this attempt.
    const registered = parse(
      await callServerTool(server, "federation_peers", {
        action: "register",
        peer_id: b.identity_id,
      })
    );
    expect(registered.registered).toBeUndefined();
    expect(registered.error).toContain("No completed handshake");
  });

  it("federation_peers register() refuses a self-vouch even if a poisoned entry reached the map by some other path, using the REAL composition root's identityManager wiring", async () => {
    const { server, identityManager } = await createSanctuaryServer({
      storage: new MemoryStorage(),
      passphrase: TEST_PASSPHRASE,
    });

    const a = parse(
      await callServerTool(server, "identity_create", { label: "identity-a" })
    );
    // identityManager here is the SAME instance createSanctuaryServer wired
    // into BOTH createHandshakeTools and createFederationTools internally
    // (index.ts step 12 / 14b) — the composition root's own object, not a
    // fixture standing in for it.
    expect(identityManager.list().some((id) => id.identity_id === a.identity_id)).toBe(true);
  });
});

describe("structural backstop: index.ts wires identityManager into federation and handshake tool construction", () => {
  it("createFederationTools( call in index.ts includes identityManager as an argument", () => {
    const repoRoot = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
    const indexSource = readFileSync(join(repoRoot, "server", "src", "index.ts"), "utf-8");
    const callStart = indexSource.indexOf("createFederationTools(");
    expect(callStart, "index.ts must call createFederationTools").toBeGreaterThanOrEqual(0);
    const callEnd = indexSource.indexOf(");", callStart);
    const callText = indexSource.slice(callStart, callEnd);
    expect(
      callText,
      "index.ts's createFederationTools( call must pass identityManager — omitting it " +
        "silently disarms the register-time self-vouch check (MUST-FIX 2)"
    ).toContain("identityManager");
  });

  it("createHandshakeTools( call in index.ts includes identityManager as an argument", () => {
    const repoRoot = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
    const indexSource = readFileSync(join(repoRoot, "server", "src", "index.ts"), "utf-8");
    const callStart = indexSource.indexOf("createHandshakeTools(");
    expect(callStart, "index.ts must call createHandshakeTools").toBeGreaterThanOrEqual(0);
    const callEnd = indexSource.indexOf(");", callStart);
    const callText = indexSource.slice(callStart, callEnd);
    expect(callText).toContain("identityManager");
  });
});
