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
  for (let i = 0; i <= occurrence; i++) {
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

describe("Core invariant comment hygiene", () => {
  it("keeps the identity Ed25519 verification funnel rationale at the verifier", () => {
    const source = read("server/src/core/identity.ts");

    expectNear(
      source,
      "return ed25519.verify(signature, payload, publicKey, { zip215: false });",
      [
        "Generic Ed25519 verification funnel",
        "Malformed signature or public-key bytes must return `false`",
        // The strictness profile is part of the invariant, not decoration: the
        // Rust daemon verifies the same bytes with `verify_strict`, so a TS
        // funnel that quietly relaxed to zip215 semantics would accept
        // signatures the daemon rejects and the two sides would disagree about
        // the same authority key.
        "zip215: false",
      ]
    );

    // The gate is only auditable if the site says which profile it implements
    // and what that profile rejects that a plain RFC 8032 verifier would not.
    expectNear(source, "!isStrictEd25519PointEncoding(publicKey) ||", [
      "RFC 8032 section 5.1.7",
      "COFACTORLESS STRICT",
      "verify_strict",
      "small-order",
      "torsion-bearing",
    ]);
  });

  it("keeps signature-suite algorithm-confusion rationale at each gate", () => {
    const source = read("server/src/core/crypto-suite-registry.ts");

    expectNear(
      source,
      "if (bundle.signature_suite !== descriptor.signature_suite) return false;",
      [
        "descriptor names the suite the caller asked to verify",
        "check the second copy inside",
      ]
    );
    expectNear(source, "if (!bundleMatchesSuitePolicy(bundle, this)) return false;", [
      "full suite policy must pass before reading components[0]",
    ]);
    expectNear(
      source,
      "if (!bundleMatchesSuitePolicy(bundle, this)) return false;",
      ["hybrid suite is an AND over two ordered components"],
      1
    );
    expectNear(source, "if (component.alg !== expectedAlg) return false;", [
      "Ordered `alg` equality is the suite policy",
    ]);
    expectNear(source, "if (toBase64url(decoded) !== value) return null;", [
      "Canonical round-trip closes that gap",
    ]);
  });

  it("keeps AES-GCM AAD swap-detection rationale on both cipher calls", () => {
    const source = read("server/src/core/encryption.ts");

    expectNear(source, "const cipher = gcm(key, iv, aad);", [
      "AAD binds caller-owned context",
      "ciphertext moved to a different",
    ]);
    expectNear(
      source,
      "const cipher = gcm(key, iv, aad);",
      ["same AAD must be supplied on decrypt", "GCM tag is the swap detector"],
      1
    );
  });
});
