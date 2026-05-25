/**
 * v1.2.1 (Finding EEE): strict argv parsing on sanctuary wrap.
 * Unknown positionals and unknown flags must be rejected.
 */
import { describe, it, expect } from "vitest";
import { parseWrapArgs } from "../../src/wrap/cli.js";

describe("sanctuary wrap strict argv parsing (Finding EEE)", () => {
  it("rejects unknown positional argument with suggestion", () => {
    expect(() => parseWrapArgs(["claude-code"])).toThrow(
      /Unrecognized argument 'claude-code'.*Did you mean --claude-code/,
    );
  });

  it("rejects unknown flag", () => {
    expect(() => parseWrapArgs(["--name", "x"])).toThrow(
      /Unrecognized flag '--name'/,
    );
  });

  it("accepts valid flags without error", () => {
    const opts = parseWrapArgs(["--claude-code", "--no-open"]);
    expect(opts.claudeCode).toBe(true);
    expect(opts.noOpen).toBe(true);
  });

  it("accepts bare invocation (auto-detect)", () => {
    const opts = parseWrapArgs([]);
    expect(opts).toEqual({});
  });
});
