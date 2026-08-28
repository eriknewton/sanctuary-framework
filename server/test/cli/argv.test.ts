import { describe, expect, it } from "vitest";

import {
  consumeFlagValue,
  consumeFlagValues,
  flagValue,
  flagValues,
  hasFlag,
  shellQuoteSingleArg,
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

  it("IC-30 fix round: rejects ANY dash-leading split-form value, not only a `--`-prefixed one", () => {
    // Pre-fix, only a `--`-prefixed next token was rejected, so a
    // single-dash short flag like `-h` was silently consumed as the value:
    // `sanctuary identity show --fortress -h` ran against a fortress
    // literally named "-h" instead of printing help.
    expect(consumeFlagValue(["--fortress", "-h"], "--fortress")).toEqual({
      argv: ["--fortress", "-h"],
      error: "--fortress requires a value",
    });
    expect(consumeFlagValue(["--fortress", "-x"], "--fortress")).toEqual({
      argv: ["--fortress", "-x"],
      error: "--fortress requires a value",
    });
    // A `--`-prefixed next token (the original, narrower check) still
    // refuses too.
    expect(consumeFlagValue(["--fortress", "--json"], "--fortress")).toEqual({
      argv: ["--fortress", "--json"],
      error: "--fortress requires a value",
    });
    // The documented escape hatch: a dash-leading value stays expressible
    // through the unambiguous `--fortress=<path>` equals form.
    expect(consumeFlagValue(["--fortress=-weird-but-explicit"], "--fortress")).toEqual({
      argv: [],
      value: "-weird-but-explicit",
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

describe("shellQuoteSingleArg (round-4 fix, independent gate on #1304, P2)", () => {
  it("wraps a plain path in single quotes", () => {
    expect(shellQuoteSingleArg("/tmp/fortress")).toBe("'/tmp/fortress'");
  });

  it("wraps a path containing a space so it survives as ONE shell argument", () => {
    expect(shellQuoteSingleArg("/tmp/My Fortress")).toBe("'/tmp/My Fortress'");
  });

  it("escapes an embedded single quote (close-quote, escaped quote, reopen-quote)", () => {
    expect(shellQuoteSingleArg("/tmp/O'Brien's Fortress")).toBe(
      "'/tmp/O'\\''Brien'\\''s Fortress'",
    );
  });

  it("round-trips through a real shell: the quoted form evaluates back to the original string", async () => {
    const { execFileSync } = await import("node:child_process");
    const tricky = '/tmp/My Fortress\'s Data "quoted" $HOME `cmd`';
    const quoted = shellQuoteSingleArg(tricky);
    const output = execFileSync("/bin/sh", ["-c", `printf '%s' ${quoted}`], {
      encoding: "utf8",
    });
    expect(output).toBe(tricky);
  });
});
