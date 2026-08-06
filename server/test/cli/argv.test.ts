import { describe, expect, it } from "vitest";

import { flagValue, flagValues, hasFlag } from "../../src/cli/argv.js";
import { parseExportArgs } from "../../src/cli/audit-chain-export.js";

describe("shared CLI argv flag parser", () => {
  it("reads split and equals value forms through one helper", () => {
    expect(flagValue(["--output", "chain.jsonl"], "--output")).toBe(
      "chain.jsonl",
    );
    expect(flagValue(["--output=chain.jsonl"], "--output")).toBe(
      "chain.jsonl",
    );
  });

  it("uses the first occurrence across split and equals forms", () => {
    expect(
      flagValue(["--output", "first.jsonl", "--output=second.jsonl"], "--output"),
    ).toBe("first.jsonl");
    expect(
      flagValue(["--output=first.jsonl", "--output", "second.jsonl"], "--output"),
    ).toBe("first.jsonl");
  });

  it("collects repeated split and equals values in argv order", () => {
    expect(
      flagValues(
        [
          "--destination",
          "api.example.test",
          "--destination=cdn.example.test",
        ],
        "--destination",
      ),
    ).toEqual(["api.example.test", "cdn.example.test"]);
  });

  it("treats equals-form value flags as present", () => {
    expect(hasFlag(["--fortress=/tmp/sanctuary"], "--fortress")).toBe(true);
    expect(hasFlag(["--fortress-path", "/tmp/sanctuary"], "--fortress")).toBe(
      false,
    );
  });

  it("keeps audit-chain export from silently dropping equals-form paths", () => {
    const parsed = parseExportArgs([
      "--output=/tmp/chain.jsonl",
      "--fortress=/tmp/fortress",
      "--storage-path=/tmp/storage",
      "--operator-only",
    ]);

    expect(parsed.output).toBe("/tmp/chain.jsonl");
    expect(parsed.fortressPath).toBe("/tmp/fortress");
    expect(parsed.storagePath).toBe("/tmp/storage");
    expect(parsed.operatorOnly).toBe(true);
  });
});
