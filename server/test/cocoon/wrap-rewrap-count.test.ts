/**
 * Re-wrap "MCP servers found" reporting (Finding B)
 *
 * v1.1.0 reported "MCP servers found: 0" when re-wrap found Sanctuary
 * already wrapped, because the filtered server list excludes Sanctuary's
 * own canonical entry to avoid double-wrapping. Operators saw a "0"
 * count next to a clearly-wrapped fortress and concluded wrap had
 * nothing to do.
 *
 * The fix splits the count: 1 Sanctuary entry (existing), N other
 * servers, properly pluralized.
 */

import { describe, it, expect } from "vitest";
import { formatMcpServerCount } from "../../src/cocoon/cli.js";

describe("formatMcpServerCount", () => {
  it("first wrap against an empty config: 0 servers, no Sanctuary entry", () => {
    expect(formatMcpServerCount(0, false)).toBe("MCP servers found: 0");
  });

  it("first wrap against a config with one upstream: 1 server, no Sanctuary entry", () => {
    expect(formatMcpServerCount(1, false)).toBe("MCP servers found: 1");
  });

  it("first wrap against a config with multiple upstreams: N servers, no Sanctuary entry", () => {
    expect(formatMcpServerCount(3, false)).toBe("MCP servers found: 3");
  });

  it("re-wrap against a config with only Sanctuary: 0 other servers, Sanctuary entry present", () => {
    // This is the Finding B scenario. Pre-fix this read "0".
    expect(formatMcpServerCount(0, true)).toBe(
      "MCP servers found: 1 Sanctuary entry (existing), 0 other servers",
    );
  });

  it("re-wrap with Sanctuary plus one other upstream: 1 other (singular)", () => {
    expect(formatMcpServerCount(1, true)).toBe(
      "MCP servers found: 1 Sanctuary entry (existing), 1 other server",
    );
  });

  it("re-wrap with Sanctuary plus multiple other upstreams: N others (plural)", () => {
    expect(formatMcpServerCount(5, true)).toBe(
      "MCP servers found: 1 Sanctuary entry (existing), 5 other servers",
    );
  });
});
