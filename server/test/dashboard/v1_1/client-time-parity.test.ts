/** Dashboard freshness parsing stays in parity with the server strict-offset predicate. */
import { describe, expect, it } from "vitest";
import { createContext, runInContext } from "node:vm";

import { parseIsoInstantWithOffset } from "../../../src/core/time.js";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";

const CLIENT_PARSER = (() => {
  const script = getClientScript();
  const match = script.match(
    /(function parseEvidenceTimestamp\(value\) \{[\s\S]*?\n\})\n\n\/\/ .* Config/
  );
  if (!match) throw new Error("dashboard client parser not found");
  const context = createContext({ Date, input: undefined });
  runInContext(match[1], context);
  return (value: unknown): number | undefined => {
    (context as { input: unknown }).input = value;
    return runInContext("parseEvidenceTimestamp(input)", context) as number | undefined;
  };
})();

const VECTORS: ReadonlyArray<{ label: string; value: unknown }> = [
  { label: "valid Z", value: "2026-03-02T12:00:00Z" },
  { label: "valid positive offset", value: "2026-03-02T12:00:00+05:30" },
  { label: "valid negative offset", value: "2026-03-02T12:00:00-08:00" },
  { label: "fraction 1 digit", value: "2026-03-02T12:00:00.1Z" },
  { label: "fraction 3 digits", value: "2026-03-02T12:00:00.123Z" },
  { label: "fraction 9 digits", value: "2026-03-02T12:00:00.123456789Z" },
  { label: "missing offset", value: "2026-03-02T12:00:00" },
  { label: "lowercase z", value: "2026-03-02T12:00:00z" },
  { label: "space separator", value: "2026-03-02 12:00:00Z" },
  { label: "out-of-range month", value: "2026-13-02T12:00:00Z" },
  { label: "out-of-range day", value: "2026-02-30T12:00:00Z" },
  { label: "out-of-range hour", value: "2026-03-02T24:00:00Z" },
  { label: "out-of-range offset hour", value: "2026-03-02T12:00:00+24:00" },
  { label: "out-of-range offset minute", value: "2026-03-02T12:00:00+00:60" },
  { label: "empty", value: "" },
  { label: "non-string", value: 1772452800000 },
];

describe("dashboard timestamp parser parity", () => {
  it("matches parseIsoInstantWithOffset for every shared vector", () => {
    expect(new Set(VECTORS.map((vector) => vector.label)).size).toBe(VECTORS.length);
    const clientResults = VECTORS.map((vector) => [vector.label, CLIENT_PARSER(vector.value)]);
    const serverResults = VECTORS.map((vector) => [
      vector.label,
      parseIsoInstantWithOffset(vector.value as string),
    ]);
    expect(clientResults).toEqual(serverResults);
  });
});
