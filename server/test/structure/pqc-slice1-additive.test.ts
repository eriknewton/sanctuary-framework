import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { transitivelyImports } from "../../scripts/check-import-cycles.lib.js";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const SERVER_SRC = resolve(REPO_ROOT, "server", "src");

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
    // This is an IMPORT-GRAPH check, not a text/substring scan, on purpose.
    // A `.not.toContain("crypto-suite-registry")` over the whole file text
    // (the original shape of this guard, per #1112 and the J5 register row)
    // both false-positives on a barred file that merely COMMENTS on the
    // registry's name (a pin comment or a derivation note referencing it by
    // name trips the same substring, with no import present) and
    // false-negatives on an aliased re-export or an indirect import chain
    // that never spells the literal string "crypto-suite-registry" in the
    // importing file at all. Following actual `import`/`export ... from`
    // edges (via the shared parser in `check-import-cycles.lib.ts`, reused
    // rather than re-implemented per AGENTS.md rule 5) tests what the guard
    // is actually meant to enforce: these serializers never reach the suite
    // registry module, directly or transitively.
    const legacyFrozenFiles = [
      "server/src/core/encryption.ts",
      "server/src/mesh/trust-root.ts",
      "server/src/mesh/envelope.ts",
      "server/src/mesh/audit-batch.ts",
      "server/src/transparency/checkpoint.ts",
      "server/src/v1/operator-signed.ts",
    ];
    const suiteRegistry = join(SERVER_SRC, "core", "crypto-suite-registry.ts");

    // Positive control: prove the machinery is live before trusting six
    // negatives. If the registry target path were ever mistyped (or the graph
    // went vacuously empty), transitivelyImports would return false for every
    // root and the six checks below would pass silently; a known genuine
    // importer (v1/federation.ts value-imports key-length constants from the
    // registry) must be reported as reaching it.
    expect(existsSync(suiteRegistry), "registry target must exist").toBe(true);
    expect(
      transitivelyImports(
        join(SERVER_SRC, "v1", "federation.ts"),
        suiteRegistry,
        SERVER_SRC,
      ),
      "positive control: v1/federation.ts is a known registry importer",
    ).toBe(true);

    for (const file of legacyFrozenFiles) {
      const abs = join(REPO_ROOT, file);
      expect(
        transitivelyImports(abs, suiteRegistry, SERVER_SRC),
        `${file} must not import the crypto-suite registry, directly or transitively`,
      ).toBe(false);
    }
  });
});
