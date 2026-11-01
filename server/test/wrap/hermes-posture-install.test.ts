// Real-parser continuing and changed-removal rows require SANCTUARY_HERMES_PYTHON.
// Refusal, write order, rollback, and dispatcher rows use a controlled parser executor
// and always run. All files and the relay socket live under a temporary HOME.
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import net from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { __hermesParityTestHook, __hermesPostureTestHook, parseWrapArgs, runWrap } from "../../src/wrap/cli.js";
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
    expect(writer).not.toHaveBeenCalled();
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
  it("writes provider files before the selected configuration", async () => {
    await fs.writeFile(join(root, "SOUL.md"), "Identity.\n");
    const paths: string[] = [];
    const open = fs.open;
    vi.spyOn(fs, "open").mockImplementation(async (...args) => { paths.push(String(args[0])); return open(...args); });
    await install();
    const writes = paths.filter(path => path.startsWith(root));
    expect(writes.at(-1)).toBe(join(root, "config.yaml"));
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
    expect(await fs.readFile(join(root, "config.yaml"), "utf8")).toBe("memory:\nplugins:\nunrelated: kept\n");
    expect(output.mock.calls.flat().join()).toContain(join(root, "sanctuary-install/config.yaml.before"));
  });
  it("uninstall changed restores a value after a comment-only edit", async () => {
    await seed("memory:\n  memory_enabled: true # original\n");
    await install();
    const config = await fs.readFile(join(root, "config.yaml"), "utf8");
    await seed(config.replace("false # original", "false # edited"));
    await uninstall();
    expect(await fs.readFile(join(root, "config.yaml"), "utf8"))
      .toBe("memory:\n  memory_enabled: true # edited\nplugins:\n");
  });
  it("default HOME resolution and absent SOUL leave identity creation to Hermes", async () => {
    vi.stubEnv("HERMES_HOME", "");
    await install();
    expect(await fs.readFile(join(home, ".hermes/config.yaml"), "utf8")).toBe(fresh);
    expect(await fs.stat(join(home, ".hermes/SOUL.md")).catch(() => null)).toBeNull();
  });
});
