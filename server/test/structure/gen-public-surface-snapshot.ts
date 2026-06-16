/**
 * Generator for the PR-0 public-surface snapshot fixtures.
 *
 * Writes the four committed goldens under
 * test/structure/__fixtures__/public-surface/ from the CURRENT tree, using the
 * SAME extractors the snapshot test asserts against (public-surface-extract.ts),
 * so the fixtures and the live comparison can never drift.
 *
 * INTENTIONAL regeneration only: run this when a public-surface change is REAL
 * and REVIEWED (a tool added/removed, a deliberate API export change, an SHR /
 * audit shape change). A pure l1-l4 -> named-layer rename must NOT change any of
 * these — if running this after a rename produces a diff, the rename touched the
 * public surface and must be corrected, not re-baselined.
 *
 *   npx tsx test/structure/gen-public-surface-snapshot.ts
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  extractToolSurface,
  extractShrShape,
  extractSovereigntyAuditShape,
  extractExportedNames,
} from "./public-surface-extract.js";

const FIXTURES = join(
  fileURLToPath(import.meta.url),
  "..",
  "__fixtures__",
  "public-surface",
);

function writeJson(name: string, value: unknown): void {
  const path = join(FIXTURES, name);
  writeFileSync(path, JSON.stringify(value, null, 2) + "\n", "utf-8");
  console.log(`wrote ${path}`);
}

async function main(): Promise<void> {
  mkdirSync(FIXTURES, { recursive: true });
  writeJson("mcp-tool-surface.json", await extractToolSurface());
  writeJson("shr-shape.json", extractShrShape());
  writeJson("sovereignty-audit-shape.json", extractSovereigntyAuditShape());
  writeJson("exported-names.json", extractExportedNames());
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
