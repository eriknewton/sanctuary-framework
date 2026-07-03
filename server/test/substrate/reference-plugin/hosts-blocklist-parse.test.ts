/**
 * Pi-hole / hosts-format parse test for the SECOND bundled reference plugin
 * (ai.sanctuary.hosts-blocklist, slice S5).
 *
 * The second bundled plugin's one deliberate difference from the first is its on-disk
 * rule FORMAT: it parses a Pi-hole gravity / /etc/hosts adblock list ("<sink-ip>
 * <domain>") instead of a bare-domain-per-line list. This suite pins that parser's
 * behavior against the shipped fixture and against hand-crafted edge cases, so the
 * "the host runs a genuinely different second bundled plugin" claim is backed by a
 * parse-parity test, not just a file that happens to exist.
 *
 * The parser is imported DIRECTLY from the plugin entry binary (an import-guard keeps
 * the wire loop from starting on import), so this exercises the SAME code the plugin
 * runs - no re-implementation.
 */

import { describe, expect, it } from "vitest";
import { promises as fs } from "node:fs";
import path from "node:path";

import { BUNDLED_PLUGINS, bundledPluginDir } from "../../../src/substrate/index.js";
// The plugin binary is contract-only ESM; importing it runs no wire loop (guarded).
import { parseHostsBlocklist } from "../../../src/substrate/reference-plugin/hosts-blocklist/bin/hosts-blocklist.mjs";

function hostsBundleDir(): string {
  const spec = BUNDLED_PLUGINS.find((p) => p.plugin_id === "ai.sanctuary.hosts-blocklist");
  if (!spec) throw new Error("hosts-blocklist not registered");
  return bundledPluginDir(spec);
}

describe("hosts-blocklist plugin - Pi-hole / hosts-format parser", () => {
  it("parses the SHIPPED fixture into the expected blocked-domain set", async () => {
    const rulesPath = path.join(hostsBundleDir(), "rules", "hosts-blocklist.hosts");
    const text = await fs.readFile(rulesPath, "utf8");
    const set = parseHostsBlocklist(text);

    // Every non-comment rule line in the fixture, whatever its sink IP form.
    expect(set).toContain("ads.tracker-network.example"); // 0.0.0.0
    expect(set).toContain("telemetry.creepy-analytics.example"); // 0.0.0.0
    expect(set).toContain("beacon.ad-exchange.example"); // 0.0.0.0
    expect(set).toContain("malvertising.example.net"); // 127.0.0.1
    expect(set).toContain("fingerprint.data-broker.example"); // 0.0.0.0 + trailing comment
    expect(set).toContain("ipv6-sink.tracker.example"); // :: sink
    expect(set).toContain("coin-miner.example.org"); // bare-domain line
  });

  it("recognizes every hosts sink IP (0.0.0.0, 127.0.0.1, ::, ::1) as a block rule", () => {
    const set = parseHostsBlocklist(
      [
        "0.0.0.0 a.example",
        "127.0.0.1 b.example",
        ":: c.example",
        "::1 d.example",
      ].join("\n"),
    );
    expect([...set].sort()).toEqual(["a.example", "b.example", "c.example", "d.example"]);
  });

  it("ignores comments (whole-line + trailing), blank lines, and lowercases", () => {
    const set = parseHostsBlocklist(
      [
        "# whole-line comment",
        "",
        "   ",
        "0.0.0.0 Mixed.CASE.Example   # trailing comment",
        "# 0.0.0.0 commented-rule.example",
      ].join("\n"),
    );
    expect(set).toContain("mixed.case.example");
    expect(set).not.toContain("commented-rule.example");
    expect(set.size).toBe(1);
  });

  it("IGNORES lines whose leading token is NOT a recognized sink IP (a blocklist only adds objections)", () => {
    // A real routable-IP hosts entry (e.g. a legit host mapping) must not be read as a
    // block rule - an unrecognized line can only make the plugin object LESS.
    const set = parseHostsBlocklist(
      ["1.2.3.4 not-a-block.example", "0.0.0.0 real-block.example"].join("\n"),
    );
    expect(set).not.toContain("not-a-block.example");
    expect(set).toContain("real-block.example");
    expect(set.size).toBe(1);
  });

  it("accepts a bare-domain line (no sink IP) for lists that omit the IP", () => {
    const set = parseHostsBlocklist("bare-domain-list.example\n");
    expect(set).toContain("bare-domain-list.example");
  });

  it("rejects malformed / single-label / non-hostname tokens (no wildcard from `localhost` etc.)", () => {
    const set = parseHostsBlocklist(
      [
        "0.0.0.0 localhost", // single label - never a useful block entry
        "0.0.0.0 has space.example", // whitespace handled by field split, this is 3 fields
        "0.0.0.0 http://scheme.example", // embedded scheme
        "0.0.0.0 bad_underscore.example", // underscore not allowed in a label
        "0.0.0.0 -leading-hyphen.example", // label may not start with hyphen
      ].join("\n"),
    );
    expect(set.has("localhost")).toBe(false);
    // "0.0.0.0 has space.example" splits to fields [0.0.0.0, has, space.example];
    // domainField = "has" (single label) -> rejected.
    expect(set.has("has")).toBe(false);
    expect(set.has("space.example")).toBe(false);
    expect(set.has("http://scheme.example")).toBe(false);
    expect(set.has("bad_underscore.example")).toBe(false);
    expect(set.has("-leading-hyphen.example")).toBe(false);
    expect(set.size).toBe(0);
  });

  it("is a pure function: same input, same output, no I/O", () => {
    const input = "0.0.0.0 stable.example\n";
    const a = parseHostsBlocklist(input);
    const b = parseHostsBlocklist(input);
    expect([...a]).toEqual([...b]);
  });
});
