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
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createSanctuaryServer } from "../../src/index.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateDefaultPolicyYaml } from "../../src/principal-policy/loader.js";
import type { ApprovalResponse } from "../../src/principal-policy/types.js";
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

  it("federation_peers register() refuses a self-vouch even if a poisoned entry reached the map by some other path, using the REAL composition root's identityManager wiring (MUST-FIX 2, register §Z RECHECK fix-round-2)", async () => {
    // This is the AGENTS.md rule-4 wired-consumer proof: it does not stop at
    // "identityManager has an entry" (that shallow check would stay green
    // even if index.ts stopped wiring identityManager into
    // createFederationTools, since it never calls federation_peers at all).
    // It drives an ACTUAL poisoned entry to the federation registration
    // boundary and asserts the specific defense-in-depth refusal fires.
    //
    // The "poisoned entry reached the map by some other path" scenario from
    // LD2-02 is reproduced without reaching into internal maps (the real
    // composition root does not expose handshakeResults) by using the two
    // real fortresses' own tool surfaces: FED completes a GENUINE (non-self)
    // handshake with a peer identity C, so FED's real handshakeResults gets
    // a legitimately verified entry for C. FED then separately gains LOCAL
    // custody of a public key matching C — as if a key-recovery import or a
    // merge brought the same key in through the identity_import tool rather
    // than through the handshake producer. Federation's OWN register-time
    // check (identityManager.list(), independent of the producer
    // chokepoint) must refuse to promote that peer to federation, because
    // it is now, by public-key bytes, an identity this fortress holds.
    //
    // Both fortresses below need a real, completed `handshake_complete` to
    // go through — the injection detector's blanket pre-check (gate.ts) can
    // flag genuine SHR/signature bytes and escalate to Tier 1 regardless of
    // the operation's configured tier, and the default `stderr` approval
    // channel cannot answer a non-interactive escalation, which denies the
    // handshake outright. `approval_channel: callback` + `approvalCallback`
    // is the documented embedding-host bypass for exactly this (see
    // `approvalCallback`'s doc in index.ts) — auto-approving here tests the
    // self-vouch guard, not the approval gate, which is orthogonal to
    // MUST-FIX 2 and out of scope for this fix.
    const approvalHome = await createTempHome(
      "sanctuary-self-vouch-composition-poisoned"
    );
    const originalHome = process.env.HOME;
    try {
      await mkdir(approvalHome.defaultFortressPath, {
        recursive: true,
        mode: 0o700,
      });
      const callbackPolicyYaml = generateDefaultPolicyYaml().replace(
        /approval_channel:\n  type: \w+/,
        "approval_channel:\n  type: callback"
      );
      await writeFile(
        join(approvalHome.defaultFortressPath, "principal-policy.yaml"),
        callbackPolicyYaml,
        { mode: 0o600 }
      );
      process.env.HOME = approvalHome.home;

      const autoApprove = async (): Promise<ApprovalResponse> => ({
        decision: "approve",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      });

      const fedFortress = await createSanctuaryServer({
        storage: new MemoryStorage(),
        passphrase: TEST_PASSPHRASE,
        approvalCallback: autoApprove,
      });
      const peerFortress = await createSanctuaryServer({
        storage: new MemoryStorage(),
        passphrase: TEST_PASSPHRASE,
        approvalCallback: autoApprove,
      });

      await runPoisonedFederationRegistration(fedFortress, peerFortress);
    } finally {
      if (originalHome === undefined) delete process.env.HOME;
      else process.env.HOME = originalHome;
      await approvalHome.cleanup();
    }
  });
});

async function runPoisonedFederationRegistration(
  fedFortress: Awaited<ReturnType<typeof createSanctuaryServer>>,
  peerFortress: Awaited<ReturnType<typeof createSanctuaryServer>>
): Promise<void> {
  const a = parse(
    await callServerTool(fedFortress.server, "identity_create", {
      label: "identity-a",
    })
  );
  const c = parse(
    await callServerTool(peerFortress.server, "identity_create", {
      label: "identity-c",
    })
  );

  // A genuine two-party handshake, driven entirely through each fortress's
  // own MCP tool surface (no shared in-process helper) — FED initiates, the
  // SEPARATE peer fortress responds with C's real key, FED completes and
  // records a verified entry for C.
  const initiated = parse(
    await callServerTool(fedFortress.server, "handshake_initiate", {
      identity_id: a.identity_id,
    })
  );
  const responded = parse(
    await callServerTool(peerFortress.server, "handshake_respond", {
      challenge: initiated.challenge,
      identity_id: c.identity_id,
    })
  );
  expect(responded.error).toBeUndefined();
  const completed = parse(
    await callServerTool(fedFortress.server, "handshake_complete", {
      session_id: initiated.session_id,
      response: responded.response,
    })
  );
  expect(completed.result.verified).toBe(true);

  // FED separately gains local custody of a public key matching C's, not
  // through the handshake producer, so the producer chokepoint
  // (recordHandshakeResult) is not exercised here. The test supplies a
  // placeholder encrypted-private-key payload because this path exercises
  // federation's OWN local-custody refusal, which is independent of
  // private-key control; ingest validation (MUST-FIX 1) checks only that
  // the public_key is a well-formed Ed25519 key.
  const poisonedImport = parse(
    await callServerTool(fedFortress.server, "identity_import", {
      identity: {
        identity_id: c.identity_id,
        label: "recovered-peer-c-key",
        public_key: c.public_key,
        did: c.did,
        created_at: c.created_at,
        key_type: "ed25519",
        key_protection: "recovery-key",
        encrypted_private_key: {
          v: 1,
          alg: "aes-256-gcm",
          iv: "cGxhY2Vob2xkZXItaXY",
          ct: "cGxhY2Vob2xkZXItY2lwaGVydGV4dA",
          ts: new Date().toISOString(),
        },
        rotation_history: [],
      },
    })
  );
  expect(poisonedImport.error).toBeUndefined();
  expect(poisonedImport.identity_id).toBe(c.identity_id);

  const registered = parse(
    await callServerTool(fedFortress.server, "federation_peers", {
      action: "register",
      peer_id: c.identity_id,
    })
  );

  expect(registered.registered).toBeUndefined();
  expect(registered.error).toContain("holds keys for");
}

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
