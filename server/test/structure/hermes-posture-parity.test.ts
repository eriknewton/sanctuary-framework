import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { HERMES_MEMORY_PROVIDER_NAME, HERMES_PLUGIN_FILES, HERMES_SOUL_BLOCK, HERMES_SKILL, HERMES_TOOLS_PLUGIN_NAME } from "../../src/wrap/hermes-posture.js";
import { SEALED_CLI_RUNTIME_DIST_ENTRIES } from "../../scripts/sealed-cli-runtime-entries.mjs";

describe("Hermes posture complete manifest parity", () => {
  it("uses the plugin manifest names and directories", () => {
    for (const name of [HERMES_MEMORY_PROVIDER_NAME, HERMES_TOOLS_PLUGIN_NAME]) {
      expect(readFileSync(resolve("../hermes-plugin", name, "plugin.yaml"), "utf8").split("\n")[0]).toBe(`name: ${name}`);
    }
    expect(HERMES_MEMORY_PROVIDER_NAME).toBe("sanctuary_memory");
    expect(HERMES_TOOLS_PLUGIN_NAME).toBe("sanctuary");
  });
  it("copies the entire tracked plugin pair and seals exactly that directory", () => {
    const files = execFileSync("git", ["ls-files", "hermes-plugin/sanctuary", "hermes-plugin/sanctuary_memory"], { cwd: resolve(".."), encoding: "utf8" }).trim().split("\n").map(path => path.replace("hermes-plugin/", ""));
    expect([...HERMES_PLUGIN_FILES].sort()).toEqual(files.sort());
    const copy = readFileSync("scripts/copy-templates.js", "utf8");
    expect(copy).toContain('"dist", "hermes-plugin"');
    expect(copy).toContain("HERMES_PLUGIN_FILES");
    expect(SEALED_CLI_RUNTIME_DIST_ENTRIES.filter(entry => entry.path === "hermes-plugin")).toEqual([
      { path: "hermes-plugin", kind: "dir", source: "copy-templates.js", sentinel: "sanctuary/sanctuary_client.py" },
    ]);
  });
  it("keeps skill and identity instructions in ordinary user language", () => {
    for (const text of [HERMES_SKILL, HERMES_SOUL_BLOCK]) {
      expect(text).not.toMatch(/\btier\b|tier[_ -]?[0-9]|principal[_-]?policy|approval|allowlist|blocklist/i);
      expect(text).toContain("never by writing memories to a file");
      expect(text).toContain("do not retry");
    }
    for (const marker of HERMES_SOUL_BLOCK.match(/<!--[\s\S]*?-->/g)!) expect(marker).not.toMatch(/ignore|override|system|secret|hidden/i);
  });
  it("tells every session the same automatic-save and honesty wording the memory provider uses", () => {
    // Python joins adjacent string literals, so the provider's prompts are read with those joins removed.
    const provider = readFileSync(resolve("../hermes-plugin/sanctuary_memory/__init__.py"), "utf8").replace(/"\s*\n\s*"/g, "");
    const automatic = "plain messages from the user may be saved to memory automatically after the turn ends";
    const honesty = "Never say something was saved unless remember returned saved in this turn.";
    expect(provider).toContain("Plain " + automatic.slice("plain ".length));
    expect(provider.split(honesty)).toHaveLength(3); // Once in the capturing prompt and once in the remember-only prompt.
    for (const text of [HERMES_SKILL, HERMES_SOUL_BLOCK]) {
      // Hermes shows these to every platform, and only Telegram captures, so the sentence names Telegram.
      expect(text).toContain("In a Telegram chat, " + automatic + "; save anything else with remember.");
      expect(text).toContain(honesty);
      expect(text).not.toContain("Save with remember.");
    }
  });
});
