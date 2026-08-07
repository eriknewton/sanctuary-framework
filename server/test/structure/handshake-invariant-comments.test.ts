import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");

function read(relativeToRepoRoot: string): string {
  return readFileSync(join(REPO_ROOT, relativeToRepoRoot), "utf8");
}

function nthIndexOf(source: string, needle: string, occurrence: number): number {
  let from = 0;
  for (let i = 0; i <= occurrence; i += 1) {
    const found = source.indexOf(needle, from);
    if (found === -1) return -1;
    if (i === occurrence) return found;
    from = found + needle.length;
  }
  return -1;
}

function around(source: string, anchor: string, occurrence = 0): string {
  const index = nthIndexOf(source, anchor, occurrence);
  expect(index, `missing source anchor: ${anchor}`).toBeGreaterThanOrEqual(0);
  return source.slice(Math.max(0, index - 700), index + anchor.length + 700);
}

function expectNear(
  source: string,
  anchor: string,
  snippets: readonly string[],
  occurrence = 0
): void {
  const window = around(source, anchor, occurrence);
  for (const snippet of snippets) {
    expect(window).toContain(snippet);
  }
}

describe("Handshake invariant comment hygiene", () => {
  it("keeps the HS-3 liveness boundary comments at both nonce-signature gates", () => {
    const source = read("server/src/handshake/protocol.ts");

    expectNear(source, "const nonceSignatureValid = verify(", [
      "HS-3 liveness gate",
      "verified:true / liveness_proven:true only after signing OUR session",
      "Do not move either",
      "trust flag above this check",
    ]);
    expectNear(
      source,
      "const nonceSignatureValid = verify(",
      [
        "HS-3 responder-side mirror",
        "Do not derive `verified`,",
        "trust_tier, or liveness_proven from SHR validity alone",
      ],
      1
    );
  });

  it("keeps handshake_exchange marked as structural preview only at its write", () => {
    const source = read("server/src/handshake/tools.ts");

    expectNear(
      source,
      "if (verificationResult.valid) {",
      [
        "handshake_exchange is a STRUCTURAL PREVIEW ONLY",
        "must NEVER write a `verified:true` result",
        "nonce-bearing 4-step protocol",
      ]
    );
    expectNear(
      source,
      "if (!existing || (!existing.verified && !existing.liveness_proven))",
      [
        "structural preview must never DOWNGRADE an already",
        "would silently demote a live peer",
      ]
    );
  });

  it("keeps attestation trust-tier derivation capped by liveness", () => {
    const source = read("server/src/handshake/attestation.ts");

    expectNear(source, "const trustTier: TrustTier = livenessProven", [
      "A verified trust tier requires proven liveness",
      "sovereignty level is still reported honestly",
      "tier is capped at",
    ]);
  });
});
