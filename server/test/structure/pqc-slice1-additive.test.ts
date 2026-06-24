import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");

function readRepoFile(path: string): string {
  return readFileSync(join(REPO_ROOT, path), "utf-8");
}

describe("PQC slice 1 additive guard", () => {
  it("does not add a PQC dependency", () => {
    const pkg = JSON.parse(readRepoFile("server/package.json")) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };

    expect(pkg.dependencies).not.toHaveProperty("@noble/post-quantum");
    expect(pkg.devDependencies).not.toHaveProperty("@noble/post-quantum");
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
