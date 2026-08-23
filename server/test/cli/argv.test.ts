import { describe, expect, it } from "vitest";

import {
  consumeFlagValue,
  consumeFlagValues,
  flagValue,
  flagValues,
  hasFlag,
  unknownFlagWithPrefix,
} from "../../src/cli/argv.js";
import { parseExportArgs } from "../../src/cli/audit-chain-export.js";
import {
  parseSecretsAuditFlags,
  parseSecretsGrantFlags,
} from "../../src/cli/secrets.js";

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

  it("consumes split and equals value flags while preserving the rest", () => {
    expect(consumeFlagValue(["list", "--fortress", "/tmp/a", "--json"], "--fortress")).toEqual({
      argv: ["list", "--json"],
      value: "/tmp/a",
    });
    expect(consumeFlagValue(["list", "--fortress=/tmp/a", "--json"], "--fortress")).toEqual({
      argv: ["list", "--json"],
      value: "/tmp/a",
    });
  });

  it("returns loud errors for missing, empty, and duplicate values", () => {
    expect(consumeFlagValue(["--fortress"], "--fortress")).toEqual({
      argv: ["--fortress"],
      error: "--fortress requires a value",
    });
    expect(consumeFlagValue(["--fortress="], "--fortress")).toEqual({
      argv: ["--fortress="],
      error: "--fortress requires a value",
    });
    expect(consumeFlagValue(["--fortress=/tmp/a", "--fortress", "/tmp/b"], "--fortress")).toEqual({
      argv: ["--fortress=/tmp/a", "--fortress", "/tmp/b"],
      error: "--fortress may only be provided once",
    });
  });

  it("consumeFlagValues collects every occurrence, split and equals forms, in argv order", () => {
    expect(
      consumeFlagValues(
        ["ingest", "--allow-file", "a.md", "--allow-file=b.md", "--dir", "/tmp"],
        "--allow-file",
      ),
    ).toEqual({
      argv: ["ingest", "--dir", "/tmp"],
      values: ["a.md", "b.md"],
    });
  });

  it("consumeFlagValues returns no values (not an error) when the flag is absent", () => {
    expect(consumeFlagValues(["ingest", "--dir", "/tmp"], "--allow-file")).toEqual({
      argv: ["ingest", "--dir", "/tmp"],
      values: [],
    });
  });

  it("consumeFlagValues fails closed on a trailing bare flag instead of silently dropping the value", () => {
    expect(consumeFlagValues(["--allow-file"], "--allow-file")).toEqual({
      argv: ["--allow-file"],
      values: [],
      error: "--allow-file requires a value",
    });
  });

  it("consumeFlagValues fails closed on an empty or whitespace-only equals value", () => {
    expect(consumeFlagValues(["--allow-file="], "--allow-file")).toEqual({
      argv: ["--allow-file="],
      values: [],
      error: "--allow-file requires a value",
    });
    expect(consumeFlagValues(["--allow-file", "   "], "--allow-file")).toEqual({
      argv: ["--allow-file", "   "],
      values: [],
      error: "--allow-file requires a value",
    });
  });

  it("consumeFlagValues fails closed when the next token is itself flag-shaped, instead of consuming it as the value", () => {
    expect(consumeFlagValues(["--allow-file", "--dir", "/tmp"], "--allow-file")).toEqual({
      argv: ["--allow-file", "--dir", "/tmp"],
      values: [],
      error: "--allow-file requires a value",
    });
  });

  it("consumeFlagValues accepts a flag-shaped value in the equals form (unambiguous, operator-bound)", () => {
    expect(consumeFlagValues(["--allow-file=--dir"], "--allow-file")).toEqual({
      argv: [],
      values: ["--dir"],
    });
  });

  it("detects unknown or near-miss fortress flags while allowing known relatives", () => {
    expect(unknownFlagWithPrefix(["--fortress-path=/tmp/a"], "--fortress")).toBe(
      "--fortress-path",
    );
    expect(unknownFlagWithPrefix(["--fortressx=/tmp/a"], "--fortress")).toBe(
      "--fortressx",
    );
    expect(unknownFlagWithPrefix(["--fortres=/tmp/a"], "--fortress")).toBe(
      "--fortres",
    );
    expect(unknownFlagWithPrefix(["--fortrss=/tmp/a"], "--fortress")).toBe(
      "--fortrss",
    );
    expect(unknownFlagWithPrefix(["--forterss=/tmp/a"], "--fortress")).toBe(
      "--forterss",
    );
    expect(
      unknownFlagWithPrefix(["--fortress-url=http://127.0.0.1:9"], "--fortress", [
        "--fortress-url",
      ]),
    ).toBeUndefined();
    expect(unknownFlagWithPrefix(["--format=json"], "--fortress")).toBeUndefined();
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

  it("keeps secrets equals-form value flags on the keychain-free parser path", () => {
    expect(parseSecretsGrantFlags(["skill", "secret", "--scope=rotate", "--ttl=600"])).toEqual({
      scope: "rotate",
      ttl: 600,
    });
    expect(parseSecretsAuditFlags(["--since=2026-08-08T00:00:00.000Z", "--limit=25"])).toEqual({
      since: "2026-08-08T00:00:00.000Z",
      limit: 25,
    });
  });
});
