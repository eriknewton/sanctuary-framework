// fail-before-exempt: isolate custody locks in a short per-test temporary root and remove it after fixture teardown; assertions are unchanged.
// After one install command, a fresh Hermes process saves the board-meeting memory
// and another recalls it through Sanctuary, without an MCP entry or a human step.
// Uninstall restores the original bytes and retains the Sanctuary passage.
// These checks require SANCTUARY_HERMES_PYTHON and temporary HOME/HERMES_HOME.
// The macOS relay, production shim entry and model's tool choice are witnessed
// only by the attended platform drill; this fixture supplies the tool choice.
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { __hermesParityTestHook, __hermesPostureTestHook, parseWrapArgs, runWrap } from "../../src/wrap/cli.js";
import { HERMES_PLUGIN_FILES, HERMES_SOUL_BLOCK } from "../../src/wrap/hermes-posture.js";
import { startFixture } from "./harness/fixture.js";

// Darwin root /private/tmp/hplock-XXXXXX is 26 bytes; 26 + 1 + 47 = 74 <= 100
// (separator plus a 40-character custody digest and the longest suffix, .reaper).
const SHORT_SOCKET_TMP_PARENT = process.platform === "darwin" ? "/private/tmp" : tmpdir();
let custodyRoot: string;
const before = `# My Hermes settings
model:
  default: offline-fixture
mcp_servers:
  weather:
    command: weather
  sanctuary:
    command: old-sanctuary
memory:
  memory_char_limit: 3000 # keep this limit
plugins:
  enabled:
    - other_plugin
`;
const after = `# My Hermes settings
model:
  default: offline-fixture
mcp_servers:
  weather:
    command: weather
memory:
  memory_char_limit: 3000 # keep this limit
  provider: sanctuary_memory
  memory_enabled: false
  user_profile_enabled: false
plugins:
  enabled:
    - other_plugin
    - sanctuary
`;
const soul = "# My identity\nBe clear and kind.\n";
const memory = "Keep my original memories.\n";
const hash = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
async function snapshot(root: string): Promise<Record<string, string>> {
  const result: Record<string, string> = {};
  for (const entry of await readdir(root, { recursive: true, withFileTypes: true })) {
    if (entry.isFile()) {
      const path = join(entry.parentPath, entry.name);
      result[path.slice(root.length)] = (await readFile(path)).toString("base64");
    }
  }
  return result;
}

describe.skipIf(!process.env.SANCTUARY_HERMES_PYTHON)("Hermes installer acceptance", () => {
  beforeEach(async () => {
    custodyRoot = await mkdtemp(join(SHORT_SOCKET_TMP_PARENT, "hplock-"));
    vi.stubEnv("SANCTUARY_CUSTODY_LOCK_ROOT", custodyRoot);
  });
  afterEach(async () => {
    __hermesParityTestHook.parity = undefined;
    delete __hermesPostureTestHook.relaySocketPath;
    delete __hermesPostureTestHook.shimCommand;
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
    if (custodyRoot) await rm(custodyRoot, { recursive: true, force: true });
  });
  it("installs once, saves and recalls in fresh processes, then restores bytes and retains the passage", async () => {
    const fixture = await startFixture();
    const home = await mkdtemp(join(tmpdir(), "hermes-installer-"));
    const root = join(home, "hermes");
    try {
      await mkdir(join(root, "memories"), { recursive: true });
      await writeFile(join(root, "config.yaml"), before);
      await writeFile(join(root, "SOUL.md"), soul);
      await writeFile(join(root, "memories/MEMORY.md"), memory);
      vi.stubEnv("HOME", home);
      vi.stubEnv("HERMES_HOME", root);
      __hermesParityTestHook.parity = { pythonPath: process.env.SANCTUARY_HERMES_PYTHON! };
      __hermesPostureTestHook.relaySocketPath = fixture.socket;
      const argv = fixture.shimCommand(home);
      __hermesPostureTestHook.shimCommand = argv;
      const output = vi.spyOn(console, "log").mockImplementation(() => {});
      const install = () => runWrap(parseWrapArgs(["--hermes-memory"]));
      const uninstall = () => runWrap(parseWrapArgs(["--hermes-memory", "--unwrap"]));
      await install();
      expect(await readFile(join(root, "config.yaml"), "utf8")).toBe(after);
      for (const file of HERMES_PLUGIN_FILES) {
        expect(await readFile(join(root, "plugins", file))).toEqual(await readFile(resolve("../hermes-plugin", file)));
      }
      expect(JSON.parse(await readFile(join(root, "plugins/sanctuary/shim-command.json"), "utf8"))).toEqual(argv);
      expect(await readFile(join(root, "SOUL.md"), "utf8")).toBe(soul + "\n" + HERMES_SOUL_BLOCK + "\n");
      expect(await readFile(join(root, "skills/sanctuary/SKILL.md"), "utf8")).toContain("name: sanctuary");
      expect(hash(await readFile(join(root, "memories/MEMORY.md")))).toBe(hash(memory));
      const installed = await snapshot(root);
      await install();
      expect(await snapshot(root)).toEqual(installed);
      expect(output.mock.calls.flat().join("\n")).toContain("already installed");
      const evidence = process.env.SANCTUARY_PLUGIN_EVIDENCE_DIR;
      if (evidence) {
        const target = join(evidence, "installed");
        await mkdir(target, { recursive: true });
        for (const [name, path] of Object.entries({ "SKILL.md": "skills/sanctuary/SKILL.md", "shim-command.json": "plugins/sanctuary/shim-command.json", "record.json": "sanctuary-install/record.json", "config.before.yaml": "sanctuary-install/config.yaml.before", "config.after.yaml": "config.yaml" })) {
          await writeFile(join(target, name), await readFile(join(root, path)));
        }
        await writeFile(join(target, "SOUL-block.md"), HERMES_SOUL_BLOCK);
      }
      let documentId = "";
      for (const python of [process.env.SANCTUARY_HERMES_PYTHON!, process.env.SANCTUARY_HERMES_PYTHON_019].filter((p): p is string => Boolean(p))) {
        const prior = (await fixture.audit()).filter(row => row.details?.kind === "insert_admitted").length;
        const saved = await fixture.preinstalledSession(python, "save", home);
        expect(saved.provider).toBe("sanctuary_memory");
        expect(saved.plugin_loaded).toBe(true);
        expect(saved.memory_store_none).toBe(true);
        expect(saved.mcp_names).not.toContain("sanctuary");
        expect(saved.soul).toContain(HERMES_SOUL_BLOCK);
        expect(saved.soul).not.toContain("[BLOCKED");
        expect(saved.skills).toContain("sanctuary");
        expect(saved.results).toEqual([{ outcome: "saved", message: "Saved." }]);
        const rows = (await fixture.audit()).filter(row => row.details?.kind === "insert_admitted");
        expect(rows.length - prior).toBe(1);
        documentId = String(rows.at(-1)!.details!.document_id);
        const offset = fixture.responses.length;
        const recalled = await fixture.preinstalledSession(python, "recall", home);
        expect(recalled.context).toContain("Thursday 3pm");
        expect(recalled.provider_sha256).toBe(hash(String(fixture.responses.slice(offset).find(row => row.outcome === "recalled")!.context)));
        expect(recalled.executed_tools).not.toContain("session_search");
        const refused = await fixture.preinstalledSession(python, "refusals", home);
        expect(refused.results.slice(1)).toEqual([{ outcome: "denied", message: "Request denied." }, { outcome: "unavailable", message: "This is not available yet; nothing was done." }]);
      }
      await uninstall();
      const remaining = await snapshot(root);
      const measured = {
        config_byte_identical: (await readFile(join(root, "config.yaml"), "utf8")) === before,
        soul_byte_identical: (await readFile(join(root, "SOUL.md"), "utf8")) === soul,
        plugin_dirs_removed: !(await readdir(join(root, "plugins"))).some(name => ["sanctuary", "sanctuary_memory"].includes(name)),
        memory_md_untouched: hash(await readFile(join(root, "memories/MEMORY.md"))) === hash(memory),
        passage_kept: (await fixture.document(documentId)).includes("The board meeting moved to Thursday 3pm."),
      };
      expect(measured).toEqual({ config_byte_identical: true, soul_byte_identical: true, plugin_dirs_removed: true, memory_md_untouched: true, passage_kept: true });
      expect(Object.keys(remaining).some(path => /sanctuary-install|skills\/sanctuary/.test(path))).toBe(false);
      if (evidence) await writeFile(join(evidence, "uninstall.json"), JSON.stringify(measured));
      const restored = await fixture.preinstalledSession(process.env.SANCTUARY_HERMES_PYTHON!, "uninstalled", home);
      expect(restored.memory_store_none).toBe(false);
      expect(restored.provider).not.toBe("sanctuary_memory");
      await install();
      await writeFile(join(root, "config.yaml"), after + "unrelated: kept\n");
      await uninstall();
      const changed = await readFile(join(root, "config.yaml"), "utf8");
      expect(changed).toContain("unrelated: kept\n");
      expect(changed).not.toContain("provider:");
      expect(changed).not.toContain("memory_enabled:");
      expect(changed).not.toContain("user_profile_enabled:");
      expect(changed).not.toContain("old-sanctuary");
      expect(output.mock.calls.flat().join("\n")).toContain(join(root, "sanctuary-install/config.yaml.before"));
    } finally {
      try { await fixture.close(); }
      finally { await rm(home, { recursive: true, force: true }); }
    }
  }, 240_000); // Four minutes covers both versions and fresh process teardown.
});
