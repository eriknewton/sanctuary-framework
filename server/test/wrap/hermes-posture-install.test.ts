// Real-parser continuing and changed-removal rows require SANCTUARY_HERMES_PYTHON.
// Refusal, write order, rollback, and dispatcher rows use a controlled parser executor
// and always run. All files and the relay socket live under a temporary HOME.
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import net from "node:net";
import { execFileSync } from "node:child_process";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { __hermesParityTestHook, __hermesPostureTestHook, parseWrapArgs, runWrap } from "../../src/wrap/cli.js";
import { assertHermesPostureParseParity } from "../../src/wrap/hermes-yaml-parse-parity.js";
import { scanHermesPosture } from "../../src/wrap/hermes-yaml.js";
import { HERMES_PLUGIN_FILES } from "../../src/wrap/hermes-posture.js";
vi.mock("node:fs/promises", async original => ({ ...await original<typeof import("node:fs/promises")>() }));
const python = process.env.SANCTUARY_HERMES_PYTHON;
const fresh = "memory:\n  provider: sanctuary_memory\n  memory_enabled: false\n  user_profile_enabled: false\nplugins:\n  enabled: [sanctuary]\n";
let home: string;
let root: string;
let relay: net.Server;
let output: ReturnType<typeof vi.spyOn>;
const install = () => runWrap(parseWrapArgs(["--hermes-memory"]));
const uninstall = () => runWrap(parseWrapArgs(["--hermes-memory", "--unwrap"]));
const successfulParser = vi.fn(async () => ({ stdout: '{"ok": true}', stderr: "", code: 0 }));
async function seed(text: string) { await fs.writeFile(join(root, "config.yaml"), text); }
async function snapshot(): Promise<Record<string, string>> {
  const result: Record<string, string> = {};
  async function walk(dir: string) {
    for (const name of await fs.readdir(dir)) {
      const path = join(dir, name);
      const stat = await fs.lstat(path);
      if (stat.isSymbolicLink()) result[path.slice(home.length)] = "link:" + await fs.readlink(path);
      else if (stat.isDirectory()) { result[path.slice(home.length)] = "directory"; await walk(path); }
      else if (stat.isFile()) result[path.slice(home.length)] = (await fs.readFile(path)).toString("base64");
    }
  }
  await walk(home);
  // Run-lock scaffolds use 32 hex characters (128 digest bits); preserve every other path in HOME.
  for (const path of Object.keys(result)) {
    if (["/.sanctuary", "/.sanctuary/locks", "/.sanctuary/locks/hermes-posture"].includes(path) ||
        /^\/\.sanctuary\/locks\/hermes-posture\/[a-f0-9]{32}\.lock$/.test(path)) delete result[path];
  }
  return result;
}
async function refuses(pattern?: string | RegExp) {
  const before = await snapshot();
  if (pattern) await expect(install()).rejects.toThrow(pattern);
  else await expect(install()).rejects.toThrow();
  expect(await snapshot()).toEqual(before);
}
beforeEach(async () => {
  home = await fs.mkdtemp(join(tmpdir(), "hpost-"));
  root = join(home, "hermes");
  await fs.mkdir(root);
  vi.stubEnv("HOME", home);
  vi.stubEnv("HERMES_HOME", root);
  output = vi.spyOn(console, "log").mockImplementation(() => {});
  successfulParser.mockClear();
  __hermesParityTestHook.parity = { exec: successfulParser, pythonPath: "/fixture/python" };
  __hermesPostureTestHook.shimCommand = [process.execPath, "fixture"];
  __hermesPostureTestHook.relaySocketPath = join(home, "relay");
  relay = net.createServer();
  await new Promise<void>(resolveListen => {
    // port-discipline: ignore - temporary Unix socket, no TCP listener.
    relay.listen(__hermesPostureTestHook.relaySocketPath, resolveListen);
  });
});
afterEach(async () => {
  delete __hermesPostureTestHook.shimCommand;
  delete __hermesPostureTestHook.relaySocketPath;
  delete __hermesPostureTestHook.failAfterStep;
  delete (__hermesPostureTestHook as { interruptAfterStep?: string }).interruptAfterStep;
  __hermesParityTestHook.parity = undefined;
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  await new Promise<void>(done => relay.close(() => done()));
  await fs.rm(home, { recursive: true, force: true });
});

describe("Hermes installer controlled-parser paths", () => {
  it("uninstall without record", async () => {
    const before = await snapshot();
    await uninstall();
    expect(await snapshot()).toEqual(before);
    expect(await fs.readdir(join(home, ".sanctuary/locks/hermes-posture"))).toHaveLength(1);
    expect(output.mock.calls.flat().join()).toContain("nothing to remove");
  });
  it("dry run makes no write and reports the planned posture", async () => {
    const before = await snapshot();
    await runWrap(parseWrapArgs(["--hermes-memory", "--dry-run"]));
    expect(await snapshot()).toEqual(before);
    expect(output.mock.calls.flat().join()).toContain("running state is not checked");
    expect(output.mock.calls.flat().join()).toContain("Memory provider: builtin");
    expect(output.mock.calls.flat().join()).toContain("memory_enabled=true (default)");
    expect(output.mock.calls.flat().join()).toContain("Planned: select sanctuary_memory");
    expect(successfulParser).toHaveBeenCalledTimes(1);
  });
  it("already installed makes no write", async () => {
    await install();
    const before = await snapshot();
    const writer = vi.spyOn(fs, "open");
    await install();
    // Lock acquisition opens its external directory and scaffold even for an unchanged install.
    expect(writer.mock.calls.filter(([path]) => String(path).startsWith(root))).toEqual([]);
    expect(await snapshot()).toEqual(before);
    expect(output.mock.calls.flat().join()).toContain("already installed");
  });
  it("recorded older plugin bytes refresh and retain the first backup", async () => {
    await seed("model: old\n");
    await install();
    const file = join(root, "plugins/sanctuary/__init__.py");
    const { createHash } = await import("node:crypto");
    const old = "# previous installed version\n";
    await fs.writeFile(file, old);
    const recordPath = join(root, "sanctuary-install/record.json");
    const record = JSON.parse(await fs.readFile(recordPath, "utf8"));
    record.files["plugins/sanctuary/__init__.py"] = createHash("sha256").update(old).digest("hex");
    await fs.writeFile(recordPath, JSON.stringify(record));
    await install();
    expect(await fs.readFile(file)).toEqual(await fs.readFile(resolve("../hermes-plugin/sanctuary/__init__.py")));
    expect(await fs.readFile(join(root, "sanctuary-install/config.yaml.before"), "utf8")).toBe("model: old\n");
  });
  it("removes an earlier record after refreshing its installed files", async () => {
    await seed("model: original\n");
    await fs.writeFile(join(root, "SOUL.md"), "Identity.\n");
    await install();
    const path = join(root, "sanctuary-install/record.json");
    const record = JSON.parse(await fs.readFile(path, "utf8"));
    delete record.state;
    delete record.originals;
    await fs.writeFile(path, JSON.stringify(record));
    await install();
    await uninstall();
    expect(await fs.readFile(join(root, "config.yaml"), "utf8")).toBe("model: original\n");
    expect(await fs.readFile(join(root, "SOUL.md"), "utf8")).toBe("Identity.\n");
    expect(await fs.stat(join(root, "plugins/sanctuary")).catch(() => null)).toBeNull();
    expect(await fs.stat(join(root, "sanctuary-install")).catch(() => null)).toBeNull();
  });
  it("publishes complete config bytes and mode through rename", async () => {
    await seed("model: original\n");
    await fs.chmod(join(root, "config.yaml"), 0o644);
    const rename = fs.rename;
    let published = false;
    vi.spyOn(fs, "rename").mockImplementation(async (...args) => {
      if (String(args[1]) === join(root, "config.yaml")) {
        expect(await fs.readFile(join(root, "config.yaml"), "utf8")).toBe("model: original\n");
        expect(await fs.readFile(String(args[0]), "utf8")).toBe("model: original\n" + fresh);
        expect((await fs.stat(String(args[0]))).mode & 0o777).toBe(0o644);
        const record = JSON.parse(await fs.readFile(join(root, "sanctuary-install/record.json"), "utf8"));
        expect(record.state).toBe("intent");
        expect(record.originals["config.yaml"]).toEqual({ bytes: Buffer.from("model: original\n").toString("base64"), mode: 0o644 });
        published = true;
      }
      return rename(...args);
    });
    await install();
    expect(published).toBe(true);
  });
  it("writes provider files before the selected configuration", async () => {
    await fs.writeFile(join(root, "SOUL.md"), "Identity.\n");
    const paths: string[] = [];
    const rename = fs.rename;
    vi.spyOn(fs, "rename").mockImplementation(async (...args) => { paths.push(String(args[1])); return rename(...args); });
    await install();
    const writes = paths.filter(path => path.startsWith(root));
    expect(writes[0]).toBe(join(root, "sanctuary-install/record.json"));
    expect(writes.at(-2)).toBe(join(root, "config.yaml"));
    expect(writes.at(-1)).toBe(join(root, "sanctuary-install/record.json"));
    expect(writes.indexOf(join(root, "plugins/sanctuary/shim-command.json"))).toBeLessThan(writes.indexOf(join(root, "skills/sanctuary/SKILL.md")));
    expect(writes.indexOf(join(root, "skills/sanctuary/SKILL.md"))).toBeLessThan(writes.indexOf(join(root, "SOUL.md")));
  });
  it.each(["plugins", "skill", "soul", "record", "config"])("rolls back failure after %s", async step => {
    await seed("model: original\n");
    await fs.writeFile(join(root, "SOUL.md"), "Identity.\n");
    __hermesPostureTestHook.failAfterStep = step;
    await refuses("Injected write failure");
  });
  it("restores removal when directory cleanup fails", async () => {
    await seed("model: original\n");
    await fs.writeFile(join(root, "SOUL.md"), "Identity.\n");
    await install();
    const before = await snapshot();
    const remove = fs.rmdir;
    let injected = false;
    vi.spyOn(fs, "rmdir").mockImplementation(async (...args) => {
      if (!injected && String(args[0]).endsWith("plugins/sanctuary_memory")) {
        injected = true;
        throw new Error("directory removal stopped");
      }
      return remove(...args);
    });
    await expect(uninstall()).rejects.toThrow("directory removal stopped");
    expect(await snapshot()).toEqual(before);
  });
  it("removes only Python caches for manifest modules", async () => {
    await install();
    const cache = join(root, "plugins/sanctuary_memory/__pycache__");
    await fs.mkdir(cache);
    await fs.writeFile(join(cache, "__init__.cpython-312.pyc"), "own cache");
    await fs.writeFile(join(cache, "sanctuary_client.cpython-312.pyc"), "unrelated cache");
    await install();
    await uninstall();
    expect(await fs.readdir(cache)).toEqual(["sanctuary_client.cpython-312.pyc"]);
    expect(await fs.readFile(join(cache, "sanctuary_client.cpython-312.pyc"), "utf8")).toBe("unrelated cache");
  });
  it("refuses euid zero", async () => {
    vi.spyOn(process, "geteuid").mockReturnValue(0);
    await refuses("run this as the account that runs Hermes");
  });
  it.each(["relative", "/outside/home"])("refuses bad HERMES_HOME %s", async path => {
    vi.stubEnv("HERMES_HOME", path);
    await refuses("HERMES_HOME");
  });
  it("refuses active profile", async () => {
    await fs.mkdir(join(home, ".hermes"));
    await fs.writeFile(join(home, ".hermes/active_profile"), "work\n");
    vi.stubEnv("HERMES_HOME", "");
    await refuses("default Hermes profile");
  });
  it.each(["config.yaml", "plugins", "skills", "ancestor"])("refuses symlinked %s", async target => {
    const destination = join(home, "destination");
    await fs.mkdir(destination);
    if (target === "ancestor") {
      await fs.symlink(root, join(home, "linked"));
      vi.stubEnv("HERMES_HOME", join(home, "linked/nested"));
    } else await fs.symlink(destination, join(root, target));
    await refuses("symlink");
  });
  it.each([
    ["duplicate top-level", "model: one\nmodel: two\n"],
    ["memory flow", "memory: {provider: old}\n"],
    ["plugins flow", "plugins: {enabled: []}\n"],
    ["memory scalar", "memory: text\n"],
    ["plugins scalar", "plugins: text\n"],
    ["nested managed", "memory:\n  provider:\n    value: old\n"],
    ["multiline managed", "memory:\n  provider: |\n    old\n"],
    ["anchor", "memory:\n  provider: &old text\n"],
    ["alias", "memory:\n  provider: *old\n"],
    ["tag", "memory:\n  provider: !!str old\n"],
    ["enabled scalar", "plugins:\n  enabled: other\n"],
    ["enabled mapping", "plugins:\n  enabled:\n    other: true\n"],
    ["disabled sanctuary", "plugins:\n  disabled: [sanctuary]\n"],
    ["hard stop enabled", "tool_loop_guardrails:\n  hard_stop_enabled: true\n"],
  ])("refuses shape %s", async (_name, yaml) => { await seed(yaml); await refuses(); });
  it("refuses PyYAML unavailable", async () => {
    __hermesParityTestHook.parity = { exec: async () => ({ code: 20, stdout: "", stderr: "" }) };
    await refuses("PyYAML is unavailable");
  });
  it("refuses parser disagreement", async () => {
    __hermesParityTestHook.parity = { exec: async () => ({ code: 21, stdout: "", stderr: "disagreement" }) };
    await refuses("planned bytes");
  });
  it("refuses planned-bytes check failure", async () => {
    __hermesParityTestHook.parity = { exec: async () => ({ code: 0, stdout: '{"ok": false}', stderr: "" }) };
    await refuses("planned bytes");
  });
  it("refuses foreign plugin directory", async () => {
    await fs.mkdir(join(root, "plugins/sanctuary"), { recursive: true });
    await fs.writeFile(join(root, "plugins/sanctuary/foreign.py"), "mine\n");
    await refuses("Foreign plugin");
  });
  it("refuses changed installed plugin bytes", async () => {
    await install();
    await fs.appendFile(join(root, "plugins/sanctuary/__init__.py"), "# changed\n");
    await refuses("Modified plugin");
  });
  it("refuses incomplete plugin source", async () => {
    const read = fs.readFile;
    vi.spyOn(fs, "readFile").mockImplementation((...args: Parameters<typeof fs.readFile>) => {
      if (String(args[0]).endsWith("hermes-plugin/sanctuary/plugin.yaml")) return Promise.reject(Object.assign(new Error("missing"), { code: "ENOENT" }));
      return read(...args);
    });
    await refuses("Incomplete Hermes plugin source");
  });
  it("requires packaged plugin assets in the package", async () => {
    const before = await snapshot();
    const reads: string[] = [];
    const read = fs.readFile;
    vi.spyOn(fs, "readFile").mockImplementation((...args: Parameters<typeof fs.readFile>) => {
      reads.push(String(args[0]));
      return read(...args);
    });
    vi.doMock("node:url", async original => {
      const url = await original<typeof import("node:url")>();
      return { ...url, fileURLToPath: (value: string | URL, options?: Parameters<typeof url.fileURLToPath>[1]) =>
        String(value).endsWith("/wrap/hermes-posture.ts") ? join(home, "package/dist/cli.js") : url.fileURLToPath(value, options) };
    });
    vi.resetModules();
    try {
      const dispatcher = await import("../../src/wrap/cli.js");
      dispatcher.__hermesParityTestHook.parity = { exec: successfulParser };
      dispatcher.__hermesPostureTestHook.shimCommand = [process.execPath, "fixture"];
      dispatcher.__hermesPostureTestHook.relaySocketPath = join(home, "relay");
      await expect(dispatcher.runWrap(dispatcher.parseWrapArgs(["--hermes-memory"])))
        .rejects.toThrow("packaged Hermes plugin directory is missing");
      expect(reads.some(path => path.includes("/hermes-plugin/"))).toBe(false);
      expect(await snapshot()).toEqual(before);
    } finally {
      vi.doUnmock("node:url");
      vi.resetModules();
    }
  });
  it.each(["missing", "_npx"])("refuses %s CLI", async kind => {
    delete __hermesPostureTestHook.shimCommand;
    const real = fs.realpath;
    vi.spyOn(fs, "realpath").mockImplementation((...args: Parameters<typeof fs.realpath>) => {
      if (String(args[0]).endsWith("/dist/cli.js")) {
        return kind === "missing" ? Promise.reject(new Error("missing")) : Promise.resolve("/npm/_npx/package/dist/cli.js");
      }
      return real(...args);
    });
    await refuses(kind === "missing" ? "cli.js is missing" : "_npx cache");
  });
  it("refuses no relay socket", async () => {
    __hermesPostureTestHook.relaySocketPath = join(home, "missing");
    await refuses("Relay socket is missing");
  });
  it("refuses protect hermes with a memory record", async () => {
    await install();
    const before = await snapshot();
    await expect(runWrap(parseWrapArgs(["--hermes"]))).rejects.toThrow("memory is installed");
    expect(await snapshot()).toEqual(before);
  });
  it("refuses production use of the test hooks", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VITEST", undefined);
    await refuses("test-only");
  });
});

describe.skipIf(!python)("Hermes installer real-parser continuing paths", () => {
  beforeEach(() => { __hermesParityTestHook.parity = { pythonPath: python! }; });
  it.each([
    ["config absent", null],
    ["blocks absent", "model: fixture\n"],
    ["values replaced", "memory:\n  provider: old\n  memory_enabled: true # retain\nplugins:\n  enabled: [other_plugin]\n"],
  ])("%s and uninstall unchanged", async (_name, original) => {
    if (original !== null) await seed(original);
    await fs.writeFile(join(root, "SOUL.md"), "Original identity.\n");
    await install();
    const config = await fs.readFile(join(root, "config.yaml"), "utf8");
    expect(config).toContain("provider: sanctuary_memory");
    expect(config).toContain("memory_enabled: false");
    expect(config).toContain("user_profile_enabled: false");
    for (const file of HERMES_PLUGIN_FILES) {
      expect((await fs.stat(join(root, "plugins", file))).mode & 0o777).toBe(0o600); // Owner-only file permissions.
    }
    expect(await fs.readFile(join(root, "memories/MEMORY.md")).catch(() => null)).toBeNull();
    await uninstall();
    expect(await fs.readFile(join(root, "config.yaml"), "utf8").catch(() => null)).toBe(original);
    expect(await fs.readFile(join(root, "SOUL.md"), "utf8")).toBe("Original identity.\n");
  });
  it("uninstall changed preserves subsequent keys and reports backup", async () => {
    await install();
    await fs.appendFile(join(root, "config.yaml"), "unrelated: kept\n");
    await uninstall();
    expect(await fs.readFile(join(root, "config.yaml"), "utf8")).toBe("unrelated: kept\n");
    expect(output.mock.calls.flat().join()).toContain(join(root, "sanctuary-install/config.yaml.before"));
  });
  it("uninstall changed restores a value after a comment-only edit", async () => {
    await seed("memory:\n  memory_enabled: true # original\n");
    await install();
    const config = await fs.readFile(join(root, "config.yaml"), "utf8");
    await seed(config.replace("false # original", "false # edited"));
    await uninstall();
    expect(await fs.readFile(join(root, "config.yaml"), "utf8"))
      .toBe("memory:\n  memory_enabled: true # edited\n");
  });
  it("reinstall and removal retain operator comments and unrelated keys", async () => {
    const original = "model: fixture\nmemory:\n  memory_enabled: true\nplugins:\n  enabled: [other]\n";
    await seed(original);
    await install();
    await fs.appendFile(join(root, "config.yaml"), "# operator note\nunrelated: kept\n");
    await install();
    output.mockClear();
    await uninstall();
    expect(await fs.readFile(join(root, "config.yaml"), "utf8"))
      .toBe(original + "# operator note\nunrelated: kept\n");
    expect(output.mock.calls.flat().join()).toContain("kept subsequent edits");
    expect(output.mock.calls.flat().join()).not.toContain("original files restored");
  });
  it("removal of a created memory block restores Hermes default memory", async () => {
    await seed("model:\n  default: fixture\n");
    await install();
    await seed((await fs.readFile(join(root, "config.yaml"), "utf8")).replace("fixture", "chosen"));
    await uninstall();
    expect(await fs.readFile(join(root, "config.yaml"), "utf8")).toBe("model:\n  default: chosen\n");
    const result = JSON.parse(execFileSync(python!, ["-c", `
import json, yaml
from hermes_cli.config import load_config, DEFAULT_CONFIG
from hermes_constants import get_hermes_home
from pathlib import Path
raw = yaml.safe_load((Path(get_hermes_home()) / 'config.yaml').read_text())
memory = load_config()['memory']
print(json.dumps({'has_memory': 'memory' in raw, 'defaults': memory == DEFAULT_CONFIG['memory'],
                  'memory_enabled': memory['memory_enabled'], 'user_profile_enabled': memory['user_profile_enabled']}))
`], { env: { ...process.env, HOME: home, HERMES_HOME: root }, encoding: "utf8" }));
    expect(result).toEqual({ has_memory: false, defaults: true, memory_enabled: true, user_profile_enabled: true });
  });
  it.each(["memory:\n", "memory: {}\n"])("real parser requires an absent created block for %s", async empty => {
    await expect(assertHermesPostureParseParity(fresh, empty, scanHermesPosture(fresh),
      scanHermesPosture(empty), false, null, { pythonPath: python! })).rejects.toThrow("planned bytes");
    await expect(assertHermesPostureParseParity(fresh, "", scanHermesPosture(fresh),
      scanHermesPosture(""), false, null, { pythonPath: python! })).resolves.toBeUndefined();
  });
  it("install and removal preserve existing config and identity modes", async () => {
    await seed("model: fixture\n");
    await fs.writeFile(join(root, "SOUL.md"), "Identity.\n");
    await fs.chmod(join(root, "config.yaml"), 0o644); // Owner write, public read.
    await fs.chmod(join(root, "SOUL.md"), 0o640); // Owner write, group read.
    for (const action of [install, uninstall]) {
      await action();
      expect((await fs.stat(join(root, "config.yaml"))).mode & 0o777).toBe(0o644);
      expect((await fs.stat(join(root, "SOUL.md"))).mode & 0o777).toBe(0o640);
    }
  });
  const writeSteps = ["intent", "backup", ...HERMES_PLUGIN_FILES.map(file => "plugins/" + file),
    "plugins/sanctuary/shim-command.json", "skill", "soul", "config", "complete"];
  async function fileState() {
    const files: Record<string, { bytes: string; mode: number }> = {};
    for (const path of Object.keys(await snapshot()).filter(path => path.startsWith("/hermes/"))) {
      const stat = await fs.lstat(home + path);
      if (stat.isFile()) files[path] = { bytes: (await fs.readFile(home + path)).toString("base64"), mode: stat.mode };
    }
    return files;
  }
  async function interrupt(step: string) {
    // The guarded hook models process exit after a completed write, without cleanup.
    (__hermesPostureTestHook as { interruptAfterStep?: string }).interruptAfterStep = step;
    await expect(install()).rejects.toThrow("Interrupted install");
    delete (__hermesPostureTestHook as { interruptAfterStep?: string }).interruptAfterStep;
  }
  it("install after an unpublished intent matches a clean install", async () => {
    await seed("model: fixture\n");
    await fs.writeFile(join(root, "SOUL.md"), "Identity.\n");
    await install();
    const clean = await fileState();
    const cleanOutput = output.mock.calls.flat();
    await uninstall();
    await fs.mkdir(join(root, "sanctuary-install"));
    await fs.writeFile(join(root, "sanctuary-install/record.json.sanctuary-install-tmp"), "partial intent");
    output.mockClear();
    await install();
    expect(await fileState()).toEqual(clean);
    expect(output.mock.calls.flat()).toEqual(cleanOutput);
    expect(await fs.readdir(join(root, "sanctuary-install"))).toEqual(["config.yaml.before", "record.json"]);
  });
  it("removal of an unpublished intent leaves Hermes files unchanged", async () => {
    await seed("model: fixture\n");
    await fs.writeFile(join(root, "SOUL.md"), "Identity.\n");
    await fs.mkdir(join(root, "memories"));
    await fs.writeFile(join(root, "memories/MEMORY.md"), "Remembered.\n");
    const before = await snapshot();
    await fs.mkdir(join(root, "sanctuary-install"));
    const staging = join(root, "sanctuary-install/record.json.sanctuary-install-tmp");
    await fs.writeFile(staging, "partial intent");
    await uninstall();
    expect(await fs.lstat(staging).catch(() => null)).toBeNull();
    expect(await fs.lstat(join(root, "sanctuary-install")).catch(() => null)).toBeNull();
    expect(await snapshot()).toEqual(before);
    expect(output.mock.calls.flat().join()).toContain("nothing to remove");
  });
  it("unpublished intent cleanup uses only the exact suffix in the record folder", async () => {
    const folder = join(root, "sanctuary-install");
    await fs.mkdir(join(folder, "nested"), { recursive: true });
    for (const path of ["record.json.tmp", "record.json.sanctuary-install-tmp.saved",
      "nested/record.json.sanctuary-install-tmp"]) await fs.writeFile(join(folder, path), "kept");
    await fs.writeFile(join(root, "SOUL.md.sanctuary-install-tmp"), "kept");
    const before = await snapshot();
    await fs.writeFile(join(folder, "record.json.sanctuary-install-tmp"), "partial intent");
    await fs.writeFile(join(folder, "config.yaml.before.sanctuary-install-tmp"), "partial backup");
    await uninstall();
    expect(await snapshot()).toEqual(before);
  });
  it.each(["install", "unwrap"])("%s preserves operator files beside unpublished intent staging", async action => {
    await seed("model: fixture\n");
    const folder = join(root, "sanctuary-install");
    await fs.mkdir(folder);
    const notes = join(folder, "notes.sanctuary-install-tmp");
    const contents = Buffer.from("Operator notes.\n");
    const notesMode = 0o640; // Owner read and write, group read.
    const permissionMask = 0o7777; // Permission and special mode bits.
    await fs.writeFile(notes, contents);
    await fs.chmod(notes, notesMode);
    const before = await snapshot();
    const staging = join(folder, "record.json.sanctuary-install-tmp");
    await fs.writeFile(staging, "partial intent");
    if (action === "install") await install();
    else await uninstall();
    expect(await fs.readFile(notes)).toEqual(contents);
    expect((await fs.stat(notes)).mode & permissionMask).toBe(notesMode);
    expect(await fs.lstat(staging).catch(() => null)).toBeNull();
    expect((await fs.stat(folder)).isDirectory()).toBe(true);
    if (action === "install") {
      expect(JSON.parse(await fs.readFile(join(folder, "record.json"), "utf8")).state).toBe("complete");
      expect(output.mock.calls.flat().join()).toContain("Sanctuary memory installed");
    } else {
      expect(await snapshot()).toEqual(before);
      expect(output.mock.calls.flat().join()).toContain("nothing to remove");
    }
  });
  it("removal rollback keeps metadata and its staging copies owner-only", async () => {
    await seed("model: fixture\n");
    const configMode = 0o644; // Owner read and write, public read.
    const permissionMask = 0o7777; // Permission and special mode bits.
    await fs.chmod(join(root, "config.yaml"), configMode);
    await interrupt("config");
    const folder = join(root, "sanctuary-install");
    const metadata = ["record.json", "config.yaml.before", "config.yaml.before.sanctuary-install-tmp"];
    expect(JSON.parse(await fs.readFile(join(folder, "record.json"), "utf8")).state).toBe("intent");
    const staging = join(folder, "config.yaml.before.sanctuary-install-tmp");
    await fs.writeFile(staging, "partial backup");
    await fs.chmod(staging, configMode);
    await fs.chmod(folder, 0o755); // Owner write, public read and traversal.
    const before = await snapshot();
    __hermesPostureTestHook.failAfterStep = "config";
    await expect(uninstall()).rejects.toThrow("Injected write failure after config");
    expect(await snapshot()).toEqual(before);
    expect((await fs.stat(folder)).mode & permissionMask).toBe(0o700); // Owner only.
    expect((await fs.readdir(folder)).sort()).toEqual([...metadata].sort());
    for (const path of metadata) {
      expect((await fs.stat(join(folder, path))).mode & permissionMask).toBe(0o600); // Owner read and write.
    }
    expect((await fs.stat(join(root, "config.yaml"))).mode & permissionMask).toBe(configMode);
  });
  it("install metadata stays owner-only across install, reinstall and interruption", async () => {
    const original = "model: fixture\n";
    await seed(original);
    await fs.writeFile(join(root, "SOUL.md"), "Identity.\n");
    await install();
    const folder = join(root, "sanctuary-install");
    const recordPath = join(folder, "record.json");
    const backupPath = join(folder, "config.yaml.before");
    const record = await fs.readFile(recordPath);
    await uninstall();
    await fs.mkdir(folder);
    await fs.writeFile(recordPath, record);
    await fs.writeFile(backupPath, original);
    const publicFileMode = 0o644; // Owner write, public read.
    const publicDirMode = 0o755; // Owner write, public read and traversal.
    const permissionMask = 0o7777; // Permission and special mode bits.
    async function ownerOnly() {
      expect((await fs.stat(folder)).mode & permissionMask).toBe(0o700); // Owner only.
      for (const path of [recordPath, backupPath]) {
        expect((await fs.stat(path)).mode & permissionMask).toBe(0o600); // Owner read and write.
      }
    }
    const rename = fs.rename;
    vi.spyOn(fs, "rename").mockImplementation(async (...args) => {
      if ([recordPath, backupPath].includes(String(args[1]))) {
        expect((await fs.stat(String(args[0]))).mode & permissionMask).toBe(0o600);
        expect((await fs.stat(folder)).mode & permissionMask).toBe(0o700);
      }
      return rename(...args);
    });
    for (const action of [install, install, () => interrupt("intent")]) {
      await fs.chmod(folder, publicDirMode);
      await fs.chmod(recordPath, publicFileMode);
      await fs.chmod(backupPath, publicFileMode);
      if (action !== install) await seed(original);
      await action();
      await ownerOnly();
    }
    expect(JSON.parse(await fs.readFile(recordPath, "utf8")).state).toBe("intent");
    await uninstall();
    await fs.mkdir(folder);
    await fs.writeFile(backupPath, "prior backup", { mode: publicFileMode });
    await interrupt("backup");
    await ownerOnly();
  });
  it.each(writeSteps)("removal restores bytes and modes after interruption at %s", async step => {
    await seed("model: fixture\n");
    await fs.chmod(join(root, "config.yaml"), 0o644);
    await fs.writeFile(join(root, "SOUL.md"), "Identity.\n", { mode: 0o640 });
    const before = await fileState();
    await interrupt(step);
    expect(await fs.stat(join(root, "sanctuary-install/record.json"))).toBeDefined();
    await uninstall();
    expect(await fileState()).toEqual(before);
    await install();
    expect(await fs.readFile(join(root, "config.yaml"), "utf8")).toContain("provider: sanctuary_memory");
  });
  it.each(writeSteps)("reinstall accounts for files after interruption at %s", async step => {
    await seed("model: fixture\n");
    await fs.writeFile(join(root, "SOUL.md"), "Identity.\n");
    const before = await fileState();
    await interrupt(step);
    const interrupted = await snapshot();
    try { await install(); }
    catch (error) {
      expect((error as Error).message).toBe("Hermes installation is incomplete; unwrap it before installing again.");
      expect(await snapshot()).toEqual(interrupted);
    }
    await uninstall();
    expect(await fileState()).toEqual(before);
  });
  it("removal clears partial staged bytes using the intent", async () => {
    await seed("model: fixture\n");
    await fs.writeFile(join(root, "SOUL.md"), "Identity.\n", { mode: 0o640 });
    const before = await fileState();
    await interrupt("intent");
    for (const path of ["config.yaml", "SOUL.md", "plugins/sanctuary/__init__.py", "sanctuary-install/record.json"]) {
      await fs.mkdir(join(root, path, ".."), { recursive: true });
      await fs.writeFile(join(root, path + ".sanctuary-install-tmp"), "partial bytes");
    }
    await uninstall();
    expect(await fileState()).toEqual(before);
    await install();
  });
  it("removal after an interrupted refresh retains operator edits", async () => {
    await seed("model: fixture\n");
    await fs.writeFile(join(root, "SOUL.md"), "Identity.\n", { mode: 0o640 });
    await install();
    await fs.appendFile(join(root, "config.yaml"), "# operator note\nunrelated: kept\n");
    const path = join(root, "plugins/sanctuary/__init__.py");
    const old = "# previous version\n";
    await fs.writeFile(path, old);
    const recordPath = join(root, "sanctuary-install/record.json");
    const record = JSON.parse(await fs.readFile(recordPath, "utf8"));
    const { createHash } = await import("node:crypto");
    record.files["plugins/sanctuary/__init__.py"] = createHash("sha256").update(old).digest("hex");
    await fs.writeFile(recordPath, JSON.stringify(record));
    await interrupt("intent");
    await uninstall();
    expect(await fs.readFile(join(root, "config.yaml"), "utf8")).toBe("model: fixture\n# operator note\nunrelated: kept\n");
    expect(await fs.readFile(join(root, "SOUL.md"), "utf8")).toBe("Identity.\n");
  });
  it("uses a home beneath a symlinked temporary root", async () => {
    const actual = join(home, "actual-root");
    const linked = join(home, "linked-root");
    await fs.mkdir(join(actual, "account/hermes"), { recursive: true });
    await fs.symlink(actual, linked);
    vi.stubEnv("HOME", join(linked, "account"));
    vi.stubEnv("HERMES_HOME", join(linked, "account/hermes"));
    await install();
    expect(await fs.readFile(join(actual, "account/hermes/config.yaml"), "utf8")).toBe(fresh);
    await uninstall();
    expect(await fs.stat(join(actual, "account/hermes/config.yaml")).catch(() => null)).toBeNull();
  });
  it("default HOME resolution and absent SOUL leave identity creation to Hermes", async () => {
    vi.stubEnv("HERMES_HOME", "");
    await install();
    expect(await fs.readFile(join(home, ".hermes/config.yaml"), "utf8")).toBe(fresh);
    expect(await fs.stat(join(home, ".hermes/SOUL.md")).catch(() => null)).toBeNull();
  });
});
