import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");

function read(relativeToRepoRoot: string): string {
  return readFileSync(join(REPO_ROOT, relativeToRepoRoot), "utf8");
}

function around(source: string, anchor: string): string {
  const index = source.indexOf(anchor);
  expect(index, `missing source anchor: ${anchor}`).toBeGreaterThanOrEqual(0);
  return source.slice(Math.max(0, index - 700), index + anchor.length + 700);
}

function expectNear(
  source: string,
  anchor: string,
  snippets: readonly string[]
): void {
  const window = around(source, anchor);
  for (const snippet of snippets) {
    expect(window).toContain(snippet);
  }
}

describe("Mesh node-revoke invariant comments", () => {
  it("keeps the revoke authority invariant at the direct producer", () => {
    const source = read("server/src/mesh/lifecycle/mesh-node.ts");

    expectNear(source, "async revokePeer(params:", [
      "Node-revoke authority invariant",
      "node signature only proves which node",
      "operator principal signature or a verified guardian quorum",
      "before anything",
      "broadcast",
    ]);
  });

  it("keeps quorum revokes gated before lifecycle emission with no trusted-caller bypass", () => {
    const source = read("server/src/mesh/lifecycle/mesh-node.ts");

    expectNear(source, "this.assertNodeRevokePayloadQuorumAuthorized(payload);", [
      "Pre-broadcast guardian invariant",
      "before emitLifecycleEvent",
      "no trusted-caller bypass",
      "never examined",
      "this node_revoke payload",
      "receivers independently",
      "re-check node_revoke authority",
    ]);
  });

  it("keeps the ceremony bypass flag removed everywhere (C12)", () => {
    // The C12 defect was a bare trusted boolean crossing the module boundary:
    // a recovery ceremony could skip both revoke-quorum checks by asserting it
    // had verified a quorum over a DIFFERENT payload. The flag must not
    // reappear in the producer, any ceremony, or the payload types.
    for (const file of [
      "server/src/mesh/lifecycle/mesh-node.ts",
      "server/src/mesh/lifecycle/types.ts",
      "server/src/mesh/recovery-flows/device-recovery.ts",
      "server/src/mesh/recovery-flows/node-revoke.ts",
      "server/src/mesh/types.ts",
    ]) {
      expect(
        read(file).includes("guardian_quorum_verified_by_ceremony"),
        `trusted bypass flag reintroduced in ${file}`
      ).toBe(false);
    }
  });

  it("keeps the device-recovery ceremony verifying a dedicated revoke quorum", () => {
    const source = read(
      "server/src/mesh/recovery-flows/device-recovery.ts"
    );

    expectNear(source, "deviceRecoveryRevokeQuorumInput(", [
      "REVOCATION",
      "not the node_revoke payload",
      "trusted-bypass defect",
    ]);
    expectNear(source, "revoke_guardian_signatures.map", [
      "REVOKE quorum",
      "never the recovery",
      "re-verifies these signatures before anything is",
    ]);
  });

  it("keeps the receive-path authority reducer tied to verified envelopes", () => {
    const source = read("server/src/mesh/lifecycle/mesh-node.ts");

    expectNear(source, "private assertNodeRevokeAuthorized", [
      "Receive-path invariant",
      "verifyOrThrow",
      "packSignedEvent",
      "same guardian quorum",
    ]);
  });
});
