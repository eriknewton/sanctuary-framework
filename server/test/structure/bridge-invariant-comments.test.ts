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
  return source.slice(Math.max(0, index - 1_200), index + anchor.length + 700);
}

function expectNear(source: string, anchor: string, snippets: readonly string[]): void {
  const window = around(source, anchor);
  for (const snippet of snippets) {
    expect(window).toContain(snippet);
  }
}

describe("Bridge invariant comment hygiene", () => {
  it("keeps the caller-supplied public-key trust boundary at the signature verifier", () => {
    const source = read("server/src/bridge/bridge.ts");

    expectNear(source, "const signatureValid = verify(payloadBytes, sigBytes, committerPublicKey);", [
      "`committerPublicKey` is supplied by the caller",
      "proves only \"this key signed this commitment payload\"",
      "must first bind the key to",
    ]);
  });

  it("keeps the external-key DID binding rationale in bridge_verify", () => {
    const source = read("server/src/bridge/tools.ts");

    expectNear(source, "const derivedDid = publicKeyToDid(publicKey);", [
      "operator-supplied key is still",
      "must derive back to the DID stored",
      "claim from its signature result",
    ]);
  });

  it("keeps bridge_attest local-key-only before writing reputation", () => {
    const source = read("server/src/bridge/tools.ts");

    expectNear(
      source,
      "const committerPublicKey = localPublicKeyForDid(commitment.committer_did);",
      [
        "bridge_attest writes L4 reputation",
        "refuses the external-key",
        "attestation can amplify the bridge result",
      ]
    );
  });
});
