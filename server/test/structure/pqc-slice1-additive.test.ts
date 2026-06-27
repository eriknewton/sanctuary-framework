import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");

function readRepoFile(path: string): string {
  return readFileSync(join(REPO_ROOT, path), "utf-8");
}

describe("PQC additive guard", () => {
  it("declares ML-DSA-65 as a pinned runtime dependency (slice 2), not hidden as optional", () => {
    const pkg = JSON.parse(readRepoFile("server/package.json")) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
    };

    // Slice 2 introduces the hybrid Ed25519+ML-DSA-65 suite, so the PQC library
    // is now a real runtime dependency: it is statically imported by a core
    // module and the server fails closed at boot if it is absent. It must be a
    // pinned exact version in `dependencies` — never hidden in
    // optionalDependencies (npm would silently ship a partial install that
    // crashes at boot) or in devDependencies.
    expect(pkg.dependencies?.["@noble/post-quantum"]).toBe("0.6.1");
    expect(pkg.devDependencies?.["@noble/post-quantum"]).toBeUndefined();
    expect(pkg.optionalDependencies?.["@noble/post-quantum"]).toBeUndefined();
  });

  it("keeps the suite registry out of legacy frozen serializers", () => {
    const legacyFrozenFiles = [
      "server/src/core/encryption.ts",
      "server/src/mesh/trust-root.ts",
      "server/src/mesh/envelope.ts",
      "server/src/mesh/audit-batch.ts",
      "server/src/transparency/checkpoint.ts",
      "server/src/v1/operator-signed.ts",
    ];

    for (const file of legacyFrozenFiles) {
      expect(readRepoFile(file), file).not.toContain("crypto-suite-registry");
      expect(readRepoFile(file), file).not.toContain("CryptoSuiteRegistry");
    }
  });
});
