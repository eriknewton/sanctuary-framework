/**
 * SIM manifest honesty regression (audit S3, 2026-06-17 second-angle).
 *
 * The `manifest` tool emits the machine-readable Sanctuary Interface Manifest
 * (SIM) a peer agent or integrator reads to learn what this server delivers.
 * The honesty wave walked back two capability claims everywhere it found them:
 *   - secure deletion is best-effort overwrite, confidentiality rests on
 *     encryption (NOT a fully-realized right-to-deletion), and
 *   - reputation / SHR / attestation surfaces report "unknown" when telemetry
 *     is unavailable.
 * The manifest was not in the first audit's scope and still self-graded
 * S1.6_deletion_rights, S4.1_earned_reputation, and S4.7_trust_bootstrapping as
 * "full", with no backing "proven" ASSURANCE_MATRIX row. This guards that those
 * three grades are no longer the unqualified "full" the live tools were
 * corrected to stop claiming.
 */

import { describe, it, expect } from "vitest";
import { createSanctuaryServer } from "../src/index.js";
import { MemoryStorage } from "../src/storage/memory.js";

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

describe("manifest honest grades (audit S3)", () => {
  it("does NOT self-grade walked-back capabilities as 'full'", async () => {
    const { server } = await createSanctuaryServer({
      storage: new MemoryStorage(),
      passphrase: "manifest-honest-grades-test",
    });
    const manifest = parse(await callServerTool(server, "manifest"));

    const l1 = manifest.layers.l1.properties;
    const l4 = manifest.layers.l4.properties;

    // The three walked-back grades must no longer be the unqualified "full".
    expect(l1["S1.6_deletion_rights"]).not.toBe("full");
    expect(l4["S4.1_earned_reputation"]).not.toBe("full");
    expect(l4["S4.7_trust_bootstrapping"]).not.toBe("full");

    // They are downgraded to an honest existing level ("partial") that matches
    // the live delete/reputation surfaces.
    expect(l1["S1.6_deletion_rights"]).toBe("partial");
    expect(l4["S4.1_earned_reputation"]).toBe("partial");
    expect(l4["S4.7_trust_bootstrapping"]).toBe("partial");

    // Genuinely-full capabilities are untouched (no over-correction).
    expect(l1["S1.2_encryption_at_rest"]).toBe("full");
    expect(l1["S1.3_integrity_verification"]).toBe("full");
    expect(l4["S4.2_participant_owned"]).toBe("full");
  });
});
