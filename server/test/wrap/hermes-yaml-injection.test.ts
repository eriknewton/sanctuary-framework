/**
 * Hermes config.yaml MCP injection — D4 Hermes drill staging, Bug 2
 *
 * Hermes v0.16.0 loads MCP servers from ~/.hermes/config.yaml under the
 * top-level `mcp_servers:` key (upstream hermes_cli/mcp_config.py and
 * mcp_startup.py). Pre-fix, wrap only rewrote the JSON cli-config.json,
 * so the agent was recorded but Hermes MCP traffic silently bypassed the
 * Sanctuary proxy.
 *
 * Unit tests pin the pure plan function (parse-modify-serialize with
 * byte-for-byte preservation of everything outside the sanctuary entry);
 * integration tests pin the wrap CLI end-to-end: both surfaces written,
 * both backed up, both restored on unwrap.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { writeFile, mkdir, mkdtemp, readFile, rm, access, symlink } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  planHermesYamlInjection,
  extractSanctuaryEntryEnv,
  yamlContainsSanctuaryEntry,
  HermesYamlUnsupportedError,
} from "../../src/wrap/hermes-yaml.js";
import { runWrap } from "../../src/wrap/cli.js";
import { SANCTUARY_VERSION } from "../../src/config.js";
import { findLatestBackup } from "../../src/wrap/config-reader.js";
import type { DashboardHandle } from "../../src/dashboard/index.js";

const ENTRY = {
  command: "npx",
  args: ["@sanctuary-framework/mcp-server"],
};

describe("planHermesYamlInjection (pure)", () => {
  it("creates a fresh file when config.yaml is absent", () => {
    const plan = planHermesYamlInjection(null, ENTRY);
    expect(plan.action).toBe("create-file");
    expect(plan.preservedEntryNames).toEqual([]);
    expect(plan.content).toBe(
      [
        "mcp_servers:",
        "  sanctuary:",
        '    command: "npx"',
        "    args:",
        '      - "@sanctuary-framework/mcp-server"',
        "",
      ].join("\n")
    );
    expect(yamlContainsSanctuaryEntry(plan.content)).toBe(true);
  });

  it("adds the mcp_servers key to an empty file", () => {
    const plan = planHermesYamlInjection("", ENTRY);
    expect(plan.action).toBe("add-key");
    expect(plan.content.startsWith("mcp_servers:\n  sanctuary:\n")).toBe(true);
    expect(yamlContainsSanctuaryEntry(plan.content)).toBe(true);
  });

  it("appends the mcp_servers key to a file without one, preserving bytes and fixing a missing trailing newline", () => {
    const existing = "# Hermes CLI configuration\nmodel: Hermes-4-405B";
    const plan = planHermesYamlInjection(existing, ENTRY);
    expect(plan.action).toBe("add-key");
    expect(
      plan.content.startsWith("# Hermes CLI configuration\nmodel: Hermes-4-405B\nmcp_servers:\n")
    ).toBe(true);
    expect(plan.content.endsWith("\n")).toBe(true);
  });

  it("appends the sanctuary entry after existing entries, preserving them and surrounding keys verbatim", () => {
    const existing = [
      "# Hermes CLI configuration",
      "model: Hermes-4-405B",
      "",
      "mcp_servers:",
      "  weather:",
      '    command: "uvx"',
      "    args:",
      '      - "mcp-weather"',
      "  search:",
      '    command: "npx"',
      "    args:",
      '      - "mcp-search"',
      "",
      "logging:",
      "  level: info",
      "",
    ].join("\n");

    const plan = planHermesYamlInjection(existing, ENTRY);
    expect(plan.action).toBe("append-entry");
    expect(plan.preservedEntryNames).toEqual(["weather", "search"]);
    // Everything outside the inserted entry is byte-identical: removing
    // the sanctuary lines from the output reproduces the input.
    const sanctuaryLines = [
      "  sanctuary:",
      '    command: "npx"',
      "    args:",
      '      - "@sanctuary-framework/mcp-server"',
    ].join("\n");
    expect(plan.content).toContain(sanctuaryLines);
    expect(plan.content.replace(`${sanctuaryLines}\n`, "")).toBe(existing);
    // Inserted inside the block: after search's args, before the blank
    // line that precedes the logging key.
    expect(plan.content.indexOf("  sanctuary:")).toBeGreaterThan(
      plan.content.indexOf('- "mcp-search"')
    );
    expect(plan.content.indexOf("  sanctuary:")).toBeLessThan(
      plan.content.indexOf("logging:")
    );
  });

  it("replaces an existing sanctuary entry in place (idempotent re-wrap)", () => {
    const existing = [
      "mcp_servers:",
      "  sanctuary:",
      '    command: "node"',
      "    args:",
      '      - "/old/dist/cli.js"',
      "  weather:",
      '    command: "uvx"',
      "",
    ].join("\n");

    const plan = planHermesYamlInjection(existing, ENTRY);
    expect(plan.action).toBe("replace-entry");
    expect(plan.preservedEntryNames).toEqual(["weather"]);
    expect(plan.content).not.toContain("/old/dist/cli.js");
    expect(plan.content).toContain('command: "npx"');
    expect(plan.content).toContain('command: "uvx"');
    // Exactly one sanctuary entry after replacement.
    expect(plan.content.match(/^ {2}sanctuary:/gm)?.length).toBe(1);
    // Re-running the plan on its own output is a no-op.
    const again = planHermesYamlInjection(plan.content, ENTRY);
    expect(again.action).toBe("replace-entry");
    expect(again.content).toBe(plan.content);
  });

  it("rewrites the empty flow form `mcp_servers: {}` to block form", () => {
    const existing = "model: Hermes-4-405B\nmcp_servers: {}\n";
    const plan = planHermesYamlInjection(existing, ENTRY);
    expect(plan.action).toBe("append-entry");
    expect(plan.content).toContain("mcp_servers:\n  sanctuary:");
    expect(plan.content).not.toContain("{}");
    expect(plan.content).toContain("model: Hermes-4-405B");
  });

  it("respects a non-default entry indent", () => {
    const existing = [
      "mcp_servers:",
      "    weather:",
      '        command: "uvx"',
      "",
    ].join("\n");
    const plan = planHermesYamlInjection(existing, ENTRY);
    expect(plan.content).toContain("    sanctuary:");
    expect(plan.content).toContain('      command: "npx"');
  });

  it("serializes env vars when provided", () => {
    const plan = planHermesYamlInjection(null, {
      ...ENTRY,
      env: { SANCTUARY_FORTRESS_PATH: "/tmp/fortress" },
    });
    expect(plan.content).toContain("    env:");
    expect(plan.content).toContain(
      '      SANCTUARY_FORTRESS_PATH: "/tmp/fortress"'
    );
  });

  it("refuses the block-sequence form (`- name: ...`) instead of emitting mixed YAML (D4 P2-1)", () => {
    const existing = [
      "mcp_servers:",
      "  - name: weather",
      '    command: "uvx"',
      "",
    ].join("\n");
    expect(() => planHermesYamlInjection(existing, ENTRY)).toThrow(
      HermesYamlUnsupportedError
    );
    expect(() => planHermesYamlInjection(existing, ENTRY)).toThrow(
      /block-sequence/
    );
  });

  it("refuses the block-sequence form even when comments precede the first item (D4 P2-1)", () => {
    const existing = [
      "mcp_servers:",
      "  # installed by hermes setup",
      "",
      "  - name: weather",
      '    command: "uvx"',
      "",
    ].join("\n");
    expect(() => planHermesYamlInjection(existing, ENTRY)).toThrow(
      HermesYamlUnsupportedError
    );
  });

  it("carries the trailing comment on `mcp_servers: {}` onto the rewritten key line (D4 P2-4)", () => {
    const existing = "mcp_servers: {} # managed by installer\n";
    const plan = planHermesYamlInjection(existing, ENTRY);
    expect(plan.action).toBe("append-entry");
    expect(plan.content).toContain("mcp_servers: # managed by installer");
    expect(plan.content).not.toContain("{}");
    expect(yamlContainsSanctuaryEntry(plan.content)).toBe(true);
  });

  it("refuses a non-empty inline flow mapping (fails loudly, never corrupts)", () => {
    const existing = 'mcp_servers: {weather: {command: "uvx"}}\n';
    expect(() => planHermesYamlInjection(existing, ENTRY)).toThrow(
      HermesYamlUnsupportedError
    );
  });

  it("refuses to replace a sanctuary entry carrying an inline env value the extractor cannot inherit", () => {
    const existing = [
      "mcp_servers:",
      "  sanctuary:",
      '    command: "npx"',
      "    env: {SANCTUARY_DASHBOARD_AUTH_TOKEN: tok, SANCTUARY_FORTRESS_PATH: /x}",
      "",
    ].join("\n");
    expect(() => planHermesYamlInjection(existing, ENTRY)).toThrow(
      HermesYamlUnsupportedError
    );
  });

  it("refuses a sanctuary entry with duplicate env fields (block form first, inline second) instead of dropping the vars PyYAML last-wins fed Hermes", () => {
    const existing = [
      "mcp_servers:",
      "  sanctuary:",
      '    command: "npx"',
      "    env:",
      '      SANCTUARY_STORAGE_PATH: "/tmp/tenant"',
      "    env: {SANCTUARY_DASHBOARD_AUTH_TOKEN: tok}",
      "",
    ].join("\n");
    expect(() => planHermesYamlInjection(existing, ENTRY)).toThrow(
      HermesYamlUnsupportedError
    );
  });

  it("refuses a sanctuary entry with duplicate BLOCK-form env fields (the extractor cannot know which set Hermes used)", () => {
    const existing = [
      "mcp_servers:",
      "  sanctuary:",
      '    command: "npx"',
      "    env:",
      '      SANCTUARY_STORAGE_PATH: "/old"',
      "    env:",
      '      SANCTUARY_DASHBOARD_AUTH_TOKEN: "tok"',
      "",
    ].join("\n");
    expect(() => planHermesYamlInjection(existing, ENTRY)).toThrow(
      HermesYamlUnsupportedError
    );
  });

  it("refuses a one-line flow-form sanctuary entry instead of silently dropping the env buried inside it", () => {
    // Valid PyYAML that Hermes loads; the entry spans a single line, so
    // the field-by-field env screen never sees the inline env. The entry
    // line itself must refuse.
    const existing = [
      "mcp_servers:",
      '  sanctuary: {command: "npx", env: {SANCTUARY_DASHBOARD_AUTH_TOKEN: tok, SANCTUARY_FORTRESS_PATH: /x}}',
      "",
    ].join("\n");
    expect(() => planHermesYamlInjection(existing, ENTRY)).toThrow(
      HermesYamlUnsupportedError
    );
    // Env-free flow form still refuses (conservative: this scanner cannot
    // prove the flow value carries no env without parsing flow YAML).
    const envFree = ["mcp_servers:", '  sanctuary: {command: "npx"}', ""].join("\n");
    expect(() => planHermesYamlInjection(envFree, ENTRY)).toThrow(
      HermesYamlUnsupportedError
    );
    // The empty flow mapping carries nothing to drop and stays editable,
    // as does a trailing comment on the entry line.
    const emptyFlow = ["mcp_servers:", "  sanctuary: {}", ""].join("\n");
    expect(planHermesYamlInjection(emptyFlow, ENTRY).action).toBe("replace-entry");
    const comment = [
      "mcp_servers:",
      "  sanctuary: # managed by wrap",
      '    command: "npx"',
      "",
    ].join("\n");
    expect(planHermesYamlInjection(comment, ENTRY).action).toBe("replace-entry");
  });

  it("refuses a block-form env whose value is a flow mapping opening on the NEXT line (valid PyYAML the var scan would misread)", () => {
    // PyYAML loads env.SECRET_TOKEN = "real-value"; the line-per-var
    // extractor would flatten it into a phantom `{SECRET_TOKEN` var.
    const flowMapping = [
      "mcp_servers:",
      "  sanctuary:",
      '    command: "npx"',
      "    env:",
      "      {SECRET_TOKEN: real-value}",
      "",
    ].join("\n");
    expect(() => planHermesYamlInjection(flowMapping, ENTRY)).toThrow(
      HermesYamlUnsupportedError
    );
    // A flow sequence opener under env: is equally unreadable.
    const flowSequence = [
      "mcp_servers:",
      "  sanctuary:",
      '    command: "npx"',
      "    env:",
      "      [SECRET_TOKEN]",
      "",
    ].join("\n");
    expect(() => planHermesYamlInjection(flowSequence, ENTRY)).toThrow(
      HermesYamlUnsupportedError
    );
    // Blank and comment lines between `env:` and its block vars are fine.
    const commented = [
      "mcp_servers:",
      "  sanctuary:",
      '    command: "npx"',
      "    env:",
      "",
      "      # dashboard token",
      '      SANCTUARY_DASHBOARD_AUTH_TOKEN: "tok"',
      "",
    ].join("\n");
    expect(planHermesYamlInjection(commented, ENTRY).action).toBe("replace-entry");
  });

  it("refuses a sanctuary entry carrying a YAML merge key (PyYAML folds the anchor's fields, possibly env, into the entry)", () => {
    const merged = [
      "defaults: &defaults",
      "  env:",
      '    SANCTUARY_DASHBOARD_AUTH_TOKEN: "tok"',
      "mcp_servers:",
      "  sanctuary:",
      "    <<: *defaults",
      '    command: "npx"',
      "",
    ].join("\n");
    expect(() => planHermesYamlInjection(merged, ENTRY)).toThrow(
      HermesYamlUnsupportedError
    );
    // A QUOTED "<<" is a literal string key under PyYAML, not a merge, so
    // it must NOT refuse (nothing is folded in that the scan cannot see).
    const quoted = [
      "mcp_servers:",
      "  sanctuary:",
      '    "<<": literal',
      '    command: "npx"',
      "",
    ].join("\n");
    expect(planHermesYamlInjection(quoted, ENTRY).action).toBe("replace-entry");
    // Merge keys on OTHER entries are untouched surface; only the
    // sanctuary entry is replaced wholesale.
    const otherEntry = [
      "defaults: &defaults",
      "  env:",
      '    WEATHER_KEY: "k"',
      "mcp_servers:",
      "  weather:",
      "    <<: *defaults",
      '    command: "uvx"',
      "  sanctuary:",
      '    command: "npx"',
      "",
    ].join("\n");
    expect(planHermesYamlInjection(otherEntry, ENTRY).action).toBe("replace-entry");
  });

  it('refuses an inline sanctuary env behind a QUOTED field key (PyYAML reads `"env":` as the same key)', () => {
    const existing = [
      "mcp_servers:",
      "  sanctuary:",
      '    command: "npx"',
      '    "env": {SANCTUARY_DASHBOARD_AUTH_TOKEN: tok}',
      "",
    ].join("\n");
    expect(() => planHermesYamlInjection(existing, ENTRY)).toThrow(
      HermesYamlUnsupportedError
    );
  });

  it("still replaces a sanctuary entry whose env is block-form or the empty flow `{}`, and ignores inline env on OTHER entries", () => {
    const blockForm = [
      "mcp_servers:",
      "  weather:",
      '    command: "uvx"',
      "    env: {WEATHER_KEY: k}",
      "  sanctuary:",
      '    command: "npx"',
      "    env: # inherited below",
      '      SANCTUARY_DASHBOARD_AUTH_TOKEN: "tok"',
      "",
    ].join("\n");
    expect(planHermesYamlInjection(blockForm, ENTRY).action).toBe("replace-entry");

    const emptyFlow = [
      "mcp_servers:",
      "  sanctuary:",
      '    command: "npx"',
      "    env: {}",
      "",
    ].join("\n");
    expect(planHermesYamlInjection(emptyFlow, ENTRY).action).toBe("replace-entry");
  });

  it("refuses duplicate top-level mcp_servers keys", () => {
    const existing = "mcp_servers:\n  a:\n    command: \"x\"\nmcp_servers:\n  b:\n    command: \"y\"\n";
    expect(() => planHermesYamlInjection(existing, ENTRY)).toThrow(
      HermesYamlUnsupportedError
    );
  });

  it("yamlContainsSanctuaryEntry is false for configs without the entry", () => {
    expect(yamlContainsSanctuaryEntry("")).toBe(false);
    expect(yamlContainsSanctuaryEntry("mcp_servers:\n  weather:\n    command: \"uvx\"\n")).toBe(false);
    expect(yamlContainsSanctuaryEntry("model: Hermes-4-405B\n")).toBe(false);
  });
});

describe("extractSanctuaryEntryEnv (pure)", () => {
  it("reads back the env block this module itself serializes", () => {
    const plan = planHermesYamlInjection(null, {
      ...ENTRY,
      env: {
        SANCTUARY_DASHBOARD_AUTH_TOKEN: "tok-123",
        SANCTUARY_STORAGE_PATH: "/tmp/tenant",
      },
    });
    expect(extractSanctuaryEntryEnv(plan.content)).toEqual({
      SANCTUARY_DASHBOARD_AUTH_TOKEN: "tok-123",
      SANCTUARY_STORAGE_PATH: "/tmp/tenant",
    });
  });

  it("parses hand-authored plain and single-quoted scalars with trailing comments", () => {
    const yaml = [
      "mcp_servers:",
      "  sanctuary:",
      '    command: "npx"',
      "    args:",
      '      - "@sanctuary-framework/mcp-server"',
      "    env:",
      "      SANCTUARY_DASHBOARD_AUTH_TOKEN: plain-tok # operator note",
      "      SANCTUARY_PASSPHRASE: 'it''s quoted'",
      "",
    ].join("\n");
    expect(extractSanctuaryEntryEnv(yaml)).toEqual({
      SANCTUARY_DASHBOARD_AUTH_TOKEN: "plain-tok",
      SANCTUARY_PASSPHRASE: "it's quoted",
    });
  });

  it('reads a block env behind a QUOTED field key (`"env":`), matching how PyYAML resolves it', () => {
    const yaml = [
      "mcp_servers:",
      "  sanctuary:",
      '    command: "npx"',
      '    "env":',
      '      SANCTUARY_DASHBOARD_AUTH_TOKEN: "tok"',
      "",
    ].join("\n");
    expect(extractSanctuaryEntryEnv(yaml)).toEqual({
      SANCTUARY_DASHBOARD_AUTH_TOKEN: "tok",
    });
  });

  it("skips nested mappings under env: instead of flattening their children into phantom vars", () => {
    const yaml = [
      "mcp_servers:",
      "  sanctuary:",
      '    command: "npx"',
      "    env:",
      "      GOOD: val",
      "      NESTED:",
      "        inner: oops",
      "      ALSO_GOOD: kept",
      "",
    ].join("\n");
    expect(extractSanctuaryEntryEnv(yaml)).toEqual({
      GOOD: "val",
      ALSO_GOOD: "kept",
    });
  });

  it("resolves null for a flow mapping opening on the line AFTER `env:` instead of flattening it into a phantom corrupted var", () => {
    // PyYAML loads env.SECRET_TOKEN = "real-value"; the line-per-var read
    // must not inherit a phantom `{SECRET_TOKEN: "real-value}"` pair. The
    // consuming injection refuses this shape, so null never masks a write.
    const flowMapping = [
      "mcp_servers:",
      "  sanctuary:",
      '    command: "npx"',
      "    env:",
      "      {SECRET_TOKEN: real-value}",
      "",
    ].join("\n");
    expect(extractSanctuaryEntryEnv(flowMapping)).toBeNull();
    const flowSequence = [
      "mcp_servers:",
      "  sanctuary:",
      '    command: "npx"',
      "    env:",
      "      [SECRET_TOKEN]",
      "",
    ].join("\n");
    expect(extractSanctuaryEntryEnv(flowSequence)).toBeNull();
  });

  it("skips block-scalar, anchored, aliased, tagged, and flow values instead of inheriting corrupted literals", () => {
    const yaml = [
      "mcp_servers:",
      "  sanctuary:",
      '    command: "npx"',
      "    env:",
      "      BLOCK_TOK: |",
      "        secret-line",
      "      FOLDED_TOK: >",
      "        folded-line",
      "      ANCHORED: &a val",
      "      ALIASED: *a",
      "      TAGGED: !!str hello",
      "      FLOW_SEQ: [a, b]",
      "      FLOW_MAP: {k: v}",
      '      GOOD: "kept"',
      "",
    ].join("\n");
    // PyYAML (which Hermes actually uses) gives every skipped value a
    // structural meaning; a single-line raw read would corrupt it.
    expect(extractSanctuaryEntryEnv(yaml)).toEqual({ GOOD: "kept" });
  });

  it("names every skipped var in the optional skippedKeys collector so wrap can warn instead of dropping silently", () => {
    const yaml = [
      "mcp_servers:",
      "  sanctuary:",
      '    command: "npx"',
      "    env:",
      "      BLOCK_TOK: |",
      "        secret-line",
      "      ANCHORED: &a val",
      "      MULTI_TOK: first line",
      "        continued here",
      '      GOOD: "kept"',
      "",
    ].join("\n");
    const skippedKeys: string[] = [];
    expect(extractSanctuaryEntryEnv(yaml, skippedKeys)).toEqual({
      GOOD: "kept",
    });
    expect(skippedKeys.sort()).toEqual(["ANCHORED", "BLOCK_TOK", "MULTI_TOK"]);
  });

  it("does not name a duplicate key that still inherited a readable value", () => {
    const yaml = [
      "mcp_servers:",
      "  sanctuary:",
      '    command: "npx"',
      "    env:",
      "      TOK: |",
      "        unreadable",
      '      TOK: "readable"',
      "",
    ].join("\n");
    const skippedKeys: string[] = [];
    expect(extractSanctuaryEntryEnv(yaml, skippedKeys)).toEqual({
      TOK: "readable",
    });
    expect(skippedKeys).toEqual([]);
  });

  it("un-inherits a duplicate key whose LAST occurrence is unreadable (PyYAML last-wins) and names it, instead of reverting to the stale first value", () => {
    const yaml = [
      "mcp_servers:",
      "  sanctuary:",
      '    command: "npx"',
      "    env:",
      '      TOK: "stale-readable"',
      "      TOK: |",
      "        the-secret-hermes-actually-used",
      '      GOOD: "kept"',
      "",
    ].join("\n");
    const skippedKeys: string[] = [];
    expect(extractSanctuaryEntryEnv(yaml, skippedKeys)).toEqual({
      GOOD: "kept",
    });
    expect(skippedKeys).toEqual(["TOK"]);
  });

  it("un-inherits a var whose plain scalar continues on a deeper-indented line instead of truncating it", () => {
    const yaml = [
      "mcp_servers:",
      "  sanctuary:",
      '    command: "npx"',
      "    env:",
      "      MULTI_TOK: first line",
      "        continued here",
      '      GOOD: "kept"',
      "",
    ].join("\n");
    expect(extractSanctuaryEntryEnv(yaml)).toEqual({ GOOD: "kept" });
  });

  it("resolves null for absent files, missing entries, missing env, and unsupported shapes", () => {
    expect(extractSanctuaryEntryEnv(null)).toBeNull();
    expect(extractSanctuaryEntryEnv("model: Hermes-4-405B\n")).toBeNull();
    expect(
      extractSanctuaryEntryEnv('mcp_servers:\n  weather:\n    command: "uvx"\n')
    ).toBeNull();
    expect(
      extractSanctuaryEntryEnv('mcp_servers:\n  sanctuary:\n    command: "npx"\n')
    ).toBeNull();
    // Flow-form env and unsupported mcp_servers shapes are skipped, not
    // guessed at.
    expect(
      extractSanctuaryEntryEnv(
        'mcp_servers:\n  sanctuary:\n    command: "npx"\n    env: {A: b}\n'
      )
    ).toBeNull();
    expect(extractSanctuaryEntryEnv("mcp_servers: [1, 2]\n")).toBeNull();
  });
});

describe("Wrap --hermes writes config.yaml end-to-end (D4 Bug 2)", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;

  beforeEach(async () => {
    // mkdtemp: atomic fresh 0o700 dir (CodeQL js/insecure-temporary-file).
    tmpHome = await mkdtemp(join(tmpdir(), "sanctuary-hermes-yaml-"));
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
  });

  afterEach(async () => {
    if (originalHome !== undefined) process.env.HOME = originalHome;
    else delete process.env.HOME;
    if (originalStoragePath !== undefined)
      process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    else delete process.env.SANCTUARY_STORAGE_PATH;
    try {
      await rm(tmpHome, { recursive: true, force: true });
    } catch {}
  });

  function makeDeps() {
    const fakeHandle: DashboardHandle = {
      url: "http://127.0.0.1:0",
      port: 0,
      host: "127.0.0.1",
      mode: "co-located",
      stop: async () => {},
    } as unknown as DashboardHandle;
    return {
      startDashboard: async () => fakeHandle,
      openBrowser: async () => {},
      resolvePassphrase: async () => ({
        value: "test-passphrase",
        location: "test-keychain",
        source: "generated",
      }),
    };
  }

  it("injects sanctuary into an existing config.yaml, preserving user entries, and records both surfaces in wrap meta", async () => {
    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    const jsonPath = join(hermesDir, "cli-config.json");
    const yamlPath = join(hermesDir, "config.yaml");
    await writeFile(
      jsonPath,
      JSON.stringify(
        { mcp_servers: { weather: { command: "uvx", args: ["mcp-weather"] } } },
        null,
        2
      )
    );
    await writeFile(
      yamlPath,
      [
        "# user notes",
        "mcp_servers:",
        "  weather:",
        '    command: "uvx"',
        "",
      ].join("\n")
    );

    await runWrap({ hermes: true, noOpen: true }, makeDeps());

    // YAML surface: sanctuary injected, user entry and comment preserved.
    const yaml = await readFile(yamlPath, "utf-8");
    expect(yamlContainsSanctuaryEntry(yaml)).toBe(true);
    expect(yaml).toContain("# user notes");
    expect(yaml).toContain("  weather:");
    expect(yaml).toContain(
      `- "@sanctuary-framework/mcp-server@${SANCTUARY_VERSION}"`
    );
    expect(yaml).toContain('- "sanctuary"');

    // JSON surface kept for forward-compat.
    const json = JSON.parse(await readFile(jsonPath, "utf-8"));
    expect(json.mcp_servers.sanctuary).toBeDefined();
    expect(json.mcp_servers.weather).toBeDefined();

    // Wrap meta records the auxiliary YAML backup for unwrap.
    const meta = await findLatestBackup();
    expect(meta).not.toBeNull();
    expect(meta!.auxiliary).toHaveLength(1);
    expect(meta!.auxiliary![0]!.originalPath).toBe(yamlPath);
    expect(meta!.auxiliary![0]!.backupPath).not.toBeNull();
    expect(meta!.auxiliary![0]!.backupPath!.endsWith(".yaml")).toBe(true);
    await expect(access(meta!.auxiliary![0]!.backupPath!)).resolves.toBeUndefined();
  });

  it("creates config.yaml when absent and unwrap removes it again", async () => {
    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    const jsonPath = join(hermesDir, "cli-config.json");
    const yamlPath = join(hermesDir, "config.yaml");
    await writeFile(jsonPath, JSON.stringify({ mcp_servers: {} }, null, 2));

    await runWrap({ hermes: true, noOpen: true }, makeDeps());

    const yaml = await readFile(yamlPath, "utf-8");
    expect(yamlContainsSanctuaryEntry(yaml)).toBe(true);

    const meta = await findLatestBackup();
    expect(meta!.auxiliary![0]!.backupPath).toBeNull();

    // Unwrap restores the pre-wrap state: no config.yaml.
    await runWrap({ unwrap: true }, makeDeps());
    await expect(access(yamlPath)).rejects.toThrow();
    const restoredJson = JSON.parse(await readFile(jsonPath, "utf-8"));
    expect(restoredJson.mcp_servers.sanctuary).toBeUndefined();
  });

  it("unwrap restores the original config.yaml content", async () => {
    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    const jsonPath = join(hermesDir, "cli-config.json");
    const yamlPath = join(hermesDir, "config.yaml");
    const originalYaml = "mcp_servers:\n  weather:\n    command: \"uvx\"\n";
    await writeFile(jsonPath, "{}");
    await writeFile(yamlPath, originalYaml);

    await runWrap({ hermes: true, noOpen: true }, makeDeps());
    expect(yamlContainsSanctuaryEntry(await readFile(yamlPath, "utf-8"))).toBe(
      true
    );

    await runWrap({ unwrap: true }, makeDeps());
    expect(await readFile(yamlPath, "utf-8")).toBe(originalYaml);
  });

  it("re-wrap inherits entry-persisted env on the authoritative YAML surface (no JSON/YAML split-brain), never the plaintext-remote flag", async () => {
    // Regression (harden round): the YAML replace-entry write got its env
    // ONLY from buildSanctuaryEnv, so a re-wrap from a tenancy-only shell
    // (this suite sets SANCTUARY_STORAGE_PATH — the upgrade flow the
    // wrapped-install update advice recommends) dropped entry-persisted
    // vars like SANCTUARY_DASHBOARD_AUTH_TOKEN from config.yaml — the
    // surface Hermes actually loads — while the JSON surface kept them.
    // Both surfaces now resolve through resolveWrapEntryEnv, which also
    // screens the plaintext-remote downgrade flag from inheritance.
    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    const yamlPath = join(hermesDir, "config.yaml");
    await writeFile(join(hermesDir, "cli-config.json"), "{}");
    await writeFile(
      yamlPath,
      [
        "mcp_servers:",
        "  sanctuary:",
        '    command: "npx"',
        "    args:",
        '      - "@sanctuary-framework/mcp-server"',
        "    env:",
        '      SANCTUARY_DASHBOARD_AUTH_TOKEN: "persisted-tok"',
        '      SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE: "true"',
        "",
      ].join("\n")
    );

    await runWrap({ hermes: true, noOpen: true }, makeDeps());

    const yaml = await readFile(yamlPath, "utf-8");
    const yamlEnv = extractSanctuaryEntryEnv(yaml);
    expect(yamlEnv).not.toBeNull();
    // Entry-persisted token survives on the surface Hermes actually loads.
    expect(yamlEnv!.SANCTUARY_DASHBOARD_AUTH_TOKEN).toBe("persisted-tok");
    // The transport downgrade is never inherited; it must be re-asserted.
    expect(yamlEnv!.SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE).toBeUndefined();
    // The tenancy var from this run's shell is caller-authoritative.
    expect(yamlEnv!.SANCTUARY_STORAGE_PATH).toBe(join(tmpHome, ".sanctuary"));
  });

  it("re-wrap prints a notice naming env vars it cannot inherit instead of dropping them silently", async () => {
    // Harden-review round: skip-not-guess is the documented tradeoff for
    // unreadable YAML value shapes (block scalars, anchors, multi-line
    // plain scalars), but the skip must be LOUD at the operator surface:
    // a one-line stderr notice names each un-inherited var so the
    // operator can re-add it by hand.
    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    const yamlPath = join(hermesDir, "config.yaml");
    await writeFile(join(hermesDir, "cli-config.json"), "{}");
    await writeFile(
      yamlPath,
      [
        "mcp_servers:",
        "  sanctuary:",
        '    command: "npx"',
        "    args:",
        '      - "@sanctuary-framework/mcp-server"',
        "    env:",
        "      OPERATOR_BLOCK_TOK: |",
        "        multi-line secret",
        '      READABLE_TOK: "kept"',
        "",
      ].join("\n")
    );

    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await runWrap({ hermes: true, noOpen: true }, makeDeps());
      const out = stderrSpy.mock.calls
        .map((call) => call.map(String).join(" "))
        .join("\n");
      expect(out).toContain("NOT inheriting 1 env var(s)");
      expect(out).toContain("OPERATOR_BLOCK_TOK");
      // The readable sibling inherited fine, so it is not named anywhere in
      // the notice (position-independent: a trailing-list entry would render
      // as "READABLE_TOK)" and dodge a comma-suffixed substring check).
      expect(out).not.toContain("READABLE_TOK");
    } finally {
      stderrSpy.mockRestore();
    }
    const yamlEnv = extractSanctuaryEntryEnv(await readFile(yamlPath, "utf-8"));
    expect(yamlEnv!.READABLE_TOK).toBe("kept");
    expect(yamlEnv!.OPERATOR_BLOCK_TOK).toBeUndefined();
  });

  it("re-wrap updates the existing sanctuary entry instead of stacking a second one", async () => {
    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    await writeFile(join(hermesDir, "cli-config.json"), "{}");

    await runWrap({ hermes: true, noOpen: true }, makeDeps());
    await runWrap({ hermes: true, noOpen: true }, makeDeps());

    const yaml = await readFile(join(hermesDir, "config.yaml"), "utf-8");
    expect(yaml.match(/^ {2}sanctuary:/gm)?.length).toBe(1);
  });

  // F7 (v1.6.1 first-run honesty): the empty legacy cli-config.json surface
  // (which Hermes does not consult for MCP routing) must not make the
  // first-run output claim "installed as the only MCP server" or "0 tools
  // registered across 0 upstream servers" moments after the (correct)
  // config.yaml preservation message.
  it("first-run output never contradicts the config.yaml preservation message (F7)", async () => {
    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    await writeFile(join(hermesDir, "cli-config.json"), "{}");
    await writeFile(
      join(hermesDir, "config.yaml"),
      'mcp_servers:\n  weather:\n    command: "uvx"\n'
    );

    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await runWrap({ hermes: true, noOpen: true }, makeDeps());
      const out = stderrSpy.mock.calls
        .map((call) => call.map(String).join(" "))
        .join("\n");
      expect(out).not.toContain("only MCP server");
      expect(out).not.toContain(
        "0 tools registered across 0 upstream servers"
      );
      // The honest pointer at the authoritative YAML surface is present.
      expect(out).toContain("config.yaml");
    } finally {
      stderrSpy.mockRestore();
    }
  });
});

describe("Wrap --hermes config.yaml atomicity + symlink refusal (D4 P1-1, P2-3)", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;
  let errSpy: ReturnType<typeof vi.spyOn>;
  let exitSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    // mkdtemp: atomic fresh 0o700 dir (CodeQL js/insecure-temporary-file).
    tmpHome = await mkdtemp(join(tmpdir(), "sanctuary-hermes-atomic-"));
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
    errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    exitSpy = vi
      .spyOn(process, "exit")
      .mockImplementation((code?: string | number | null) => {
        throw new Error(`process.exit:${code}`);
      });
  });

  afterEach(async () => {
    errSpy.mockRestore();
    exitSpy.mockRestore();
    vi.restoreAllMocks();
    if (originalHome !== undefined) process.env.HOME = originalHome;
    else delete process.env.HOME;
    if (originalStoragePath !== undefined)
      process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    else delete process.env.SANCTUARY_STORAGE_PATH;
    try {
      await rm(tmpHome, { recursive: true, force: true });
    } catch {}
  });

  function makeDeps() {
    const fakeHandle: DashboardHandle = {
      url: "http://127.0.0.1:0",
      port: 0,
      host: "127.0.0.1",
      mode: "co-located",
      stop: async () => {},
    } as unknown as DashboardHandle;
    return {
      startDashboard: async () => fakeHandle,
      openBrowser: async () => {},
      resolvePassphrase: async () => ({
        value: "test-passphrase",
        location: "test-keychain",
        source: "generated",
      }),
    };
  }

  function stderrOutput(): string {
    return errSpy.mock.calls.map((c) => c.join(" ")).join("\n");
  }

  it("rolls the JSON config back when the config.yaml write throws — wrap is atomic (P1-1)", async () => {
    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    const jsonPath = join(hermesDir, "cli-config.json");
    const originalJson = JSON.stringify(
      { mcp_servers: { weather: { command: "uvx", args: ["mcp-weather"] } } },
      null,
      2
    );
    await writeFile(jsonPath, originalJson);
    // A directory at the config.yaml path makes writeFile throw EISDIR
    // AFTER the JSON surface has been rewritten and verified — the exact
    // partially-applied window P1-1 closes.
    await mkdir(join(hermesDir, "config.yaml"));

    await expect(
      runWrap({ hermes: true, noOpen: true }, makeDeps())
    ).rejects.toThrow("process.exit:1");

    // Loud failure + full rollback: the JSON config is byte-identical to
    // the pre-wrap original (no sanctuary entry left behind).
    expect(stderrOutput()).toContain("Hermes config.yaml write FAILED");
    expect(await readFile(jsonPath, "utf-8")).toBe(originalJson);
  });

  it("refuses to wrap through a symlinked config.yaml, leaving every surface untouched (P2-3)", async () => {
    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    const jsonPath = join(hermesDir, "cli-config.json");
    const originalJson = JSON.stringify({ mcp_servers: {} }, null, 2);
    await writeFile(jsonPath, originalJson);
    const victimPath = join(tmpHome, "victim.yaml");
    const victimContent = "do-not-touch: true\n";
    await writeFile(victimPath, victimContent);
    await symlink(victimPath, join(hermesDir, "config.yaml"));

    await expect(
      runWrap({ hermes: true, noOpen: true }, makeDeps())
    ).rejects.toThrow("process.exit:1");

    expect(stderrOutput()).toContain("symlink");
    // The write never followed the link, and the refusal fired before any
    // backup or JSON rewrite.
    expect(await readFile(victimPath, "utf-8")).toBe(victimContent);
    expect(await readFile(jsonPath, "utf-8")).toBe(originalJson);
  });
});
