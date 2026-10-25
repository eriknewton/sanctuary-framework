import { readFile } from "node:fs/promises";
import { expect, it } from "vitest";

it("keeps the documented finding kinds equal to RecordFindingKind", async () => {
  const source = await readFile(new URL("../../src/cli/audit-chain-verify.ts", import.meta.url), "utf8");
  const doc = await readFile(new URL("../../docs/audit-chain-export-format.md", import.meta.url), "utf8");
  const union = source.match(/export type RecordFindingKind\s*=([\s\S]*?);/)?.[1];
  const kindList = doc.match(/"kind":\s*"([^"\n]+)"/)?.[1];
  expect(union).toBeDefined();
  expect(kindList).toBeDefined();
  const sourceKinds = new Set([...union!.matchAll(/"([^"\n]+)"/g)].map((match) => match[1]));
  const docKinds = new Set(kindList!.split("|").map((kind) => kind.trim()));
  expect(sourceKinds.size).toBeGreaterThan(0);
  expect(docKinds).toEqual(sourceKinds);
});
