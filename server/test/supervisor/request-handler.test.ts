/**
 * Phase S1 — Supervisor request handler: config-path confinement + key decode.
 *
 * The handler is the seam where the (MAC-verified) protect frame's transient
 * key is decoded and the config_path is confined before any launch (H1/L2
 * blast-radius: never launch an API-pointed arbitrary path).
 */

import { describe, expect, it } from "vitest";
import { makeSupervisorHandler } from "../../src/supervisor/request-handler.js";
import { Supervisor, type AgentLauncher, type LaunchedChild } from "../../src/supervisor/supervisor.js";
import { toBase64url } from "../../src/core/encoding.js";

class NoopChild implements LaunchedChild {
  onExit(): void {}
  async stop(): Promise<void> {}
}
class NoopLauncher implements AgentLauncher {
  launches = 0;
  async launch(): Promise<LaunchedChild> {
    this.launches++;
    return new NoopChild();
  }
}

function makeHandler(over?: { allowPath?: (p: string) => boolean; launcher?: NoopLauncher }) {
  const launcher = over?.launcher ?? new NoopLauncher();
  const supervisor = new Supervisor({
    launcher,
    isRotationInProgress: async () => false,
    latestEnforcementAt: () => null,
  });
  const handle = makeSupervisorHandler({
    supervisor,
    isConfigPathAllowed: over?.allowPath ?? (() => true),
  });
  return { handle, launcher };
}

describe("supervisor request handler", () => {
  it("launches a protect with a valid key + allowed path", async () => {
    const { handle, launcher } = makeHandler();
    const resp = await handle({
      kind: "protect",
      agent_id: "a1",
      harness: "claude_code",
      config_path: "/allowed/a.json",
      transient_key_b64: toBase64url(new Uint8Array([1, 2, 3, 4])),
    });
    expect(resp.ok).toBe(true);
    expect(launcher.launches).toBe(1);
  });

  it("REJECTS a config_path outside the allowed root WITHOUT launching (H1/L2)", async () => {
    const launcher = new NoopLauncher();
    const { handle } = makeHandler({ launcher, allowPath: (p) => p.startsWith("/allowed/") });
    const resp = await handle({
      kind: "protect",
      agent_id: "a1",
      harness: "claude_code",
      config_path: "/etc/passwd",
      transient_key_b64: toBase64url(new Uint8Array([1, 2, 3, 4])),
    });
    expect(resp.ok).toBe(false);
    if (!resp.ok) expect(resp.reason).toBe("bad_request");
    expect(launcher.launches).toBe(0); // never reached the launcher
  });

  it("rejects a malformed transient key with bad_request", async () => {
    const { handle, launcher } = makeHandler();
    const resp = await handle({
      kind: "protect",
      agent_id: "a1",
      harness: "claude_code",
      config_path: "/allowed/a.json",
      transient_key_b64: "!!!not-base64url!!!",
    });
    expect(resp.ok).toBe(false);
    expect(launcher.launches).toBe(0);
  });

  it("status returns the live roster", async () => {
    const { handle } = makeHandler();
    await handle({
      kind: "protect",
      agent_id: "a1",
      harness: "claude_code",
      config_path: "/allowed/a.json",
      transient_key_b64: toBase64url(new Uint8Array([1, 2, 3, 4])),
    });
    const resp = await handle({ kind: "status" });
    expect(resp.ok).toBe(true);
    if (resp.ok && resp.kind === "status") {
      expect(resp.agents.map((a) => a.agent_id)).toEqual(["a1"]);
    }
  });

  it("unprotect on an unknown agent is not_found", async () => {
    const { handle } = makeHandler();
    const resp = await handle({ kind: "unprotect", agent_id: "ghost" });
    expect(resp.ok).toBe(false);
    if (!resp.ok) expect(resp.reason).toBe("not_found");
  });
});
