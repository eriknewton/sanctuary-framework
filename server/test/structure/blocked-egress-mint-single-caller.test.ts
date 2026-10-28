/**
 * Blocked-egress attribution minting stays owned by the audit consumer.
 * S1
 */

import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SOURCE_ROOT = fileURLToPath(new URL("../../src/", import.meta.url));
const MINT_NAME = "mintConsumerBlockedEgress";
// Must match the mint invariant in castle-wall/runtime/blocked-egress-attribution.ts.
const ALLOWED_REFERENCES = new Set([
  "castle-wall/runtime/blocked-egress-attribution.ts",
  "castle-wall/runtime/audit-consumer.ts",
]);

interface SourceFile {
  path: string;
  contents: string;
}

function readSourceFiles(directory: string): SourceFile[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return readSourceFiles(path);
    if (!entry.isFile()) return [];
    return [{
      path: relative(SOURCE_ROOT, path).split("\\").join("/"),
      contents: readFileSync(path, "utf8"),
    }];
  });
}

function referencingFiles(files: SourceFile[]): Set<string> {
  return new Set(files.filter((file) => file.contents.includes(MINT_NAME)).map((file) => file.path));
}

function assertSingleCaller(files: SourceFile[]): void {
  // Exact membership catches an extra caller even when another reference disappears.
  expect(referencingFiles(files)).toEqual(ALLOWED_REFERENCES);
}

describe("blocked-egress mint single caller", () => {
  const files = readSourceFiles(SOURCE_ROOT);

  it("restricts all source references to the leaf and audit consumer", () => {
    assertSingleCaller(files);
  });

  it("rejects a second caller added as an in-memory source fixture", () => {
    const fixture: SourceFile = {
      path: "principal-policy/additional-caller.ts",
      contents: `import { mintConsumerBlockedEgress } from "../castle-wall/runtime/blocked-egress-attribution.js";
mintConsumerBlockedEgress(projection);`,
    };
    const withSecondCaller = [...files, fixture];
    expect(referencingFiles(withSecondCaller)).toEqual(new Set([...ALLOWED_REFERENCES, fixture.path]));
    expect(() => assertSingleCaller(withSecondCaller)).toThrow();
  });
});
