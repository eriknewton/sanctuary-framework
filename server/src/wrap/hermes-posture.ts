/** Install the Hermes plugin pair in the account that runs Hermes, with reversible file edits. */
import { createHash } from "node:crypto";
import { lstat, readFile, readdir, realpath, rmdir, chmod, mkdir } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { FIXED_SOCKET_PATH } from "../hermes-memory-client/protocol.js";
import { writeFileSafeUnderRoot, unlinkSafeUnderRoot } from "./config-reader.js";
import { planHermesMemoryPosture, planHermesMemoryRevert, scanHermesPosture } from "./hermes-yaml.js";
import { assertHermesPostureParseParity, type ParseParityOptions } from "./hermes-yaml-parse-parity.js";

export const HERMES_MEMORY_PROVIDER_NAME = "sanctuary_memory";
export const HERMES_POSTURE_SETTINGS = [
  { block: "memory", key: "provider", value: HERMES_MEMORY_PROVIDER_NAME },
  { block: "memory", key: "memory_enabled", value: "false" },
  { block: "memory", key: "user_profile_enabled", value: "false" },
] as const;
// Must match the manifest read by server/scripts/copy-templates.js and the complete plugin tree.
export const HERMES_PLUGIN_FILES = ["sanctuary/__init__.py", "sanctuary/plugin.yaml", "sanctuary/sanctuary_client.py", "sanctuary_memory/__init__.py", "sanctuary_memory/plugin.yaml"] as const;
export const HERMES_TOOLS_PLUGIN_NAME = "sanctuary";
const INSTRUCTIONS = "Memory is persistent and kept by Sanctuary. Save with remember. Export with export_memory, never by writing memories to a file. Sign with sign_statement. For rules, protections or security settings call protection_rules. If a Sanctuary tool says a request was not done, say so in one sentence and do not retry.";
export const HERMES_SKILL = `---\nname: sanctuary\ndescription: Use when the user asks you to remember something, to export what you know, to sign a statement, or asks about your rules or protections.\n---\n\n${INSTRUCTIONS}\n`;
export const HERMES_SOUL_BLOCK = `<!-- sanctuary memory begin -->\n${INSTRUCTIONS}\n<!-- sanctuary memory end -->`;
const FILE_MODE = 0o600; // Owner read and write only.
const DIR_MODE = 0o700; // Owner traversal, read and write only.
const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const CONFIG = "config.yaml";
const SOUL = "SOUL.md";
const SKILL = "skills/sanctuary/SKILL.md";
const SHIM = "plugins/sanctuary/shim-command.json";
const RECORD = "sanctuary-install/record.json";
const BACKUP = "sanctuary-install/config.yaml.before";
const pluginPaths = HERMES_PLUGIN_FILES.map(file => "plugins/" + file);
const recordedPaths = [...pluginPaths, SHIM, SKILL];

/** Test-only values reach this function only through the guarded dispatcher hook. */
export interface HermesPostureHooks { relaySocketPath?: string; shimCommand?: string[]; failAfterStep?: string }
interface InstallRecord {
  version: 1;
  originalConfig: string | null;
  installedConfig: string;
  files: Record<string, string>;
  priorRaw: Record<string, string | null>;
  removedMcp: string | null;
  soulInsertion: string;
  originalSoul: string | null;
  installedSoul: string | null;
}
const hash = (bytes: string | Buffer) => createHash("sha256").update(bytes).digest("hex");
const missing = (error: unknown) => (error as NodeJS.ErrnoException).code === "ENOENT";
async function statOptional(path: string) {
  try { return await lstat(path); } catch (error) { if (missing(error)) return null; throw error; }
}
async function readOptional(path: string): Promise<Buffer | null> {
  try { return await readFile(path); } catch (error) { if (missing(error)) return null; throw error; }
}
async function safePath(path: string): Promise<void> {
  const parent = dirname(path);
  if (parent !== path) await safePath(parent);
  const stat = await statOptional(path);
  if (stat?.isSymbolicLink()) throw new Error(`Refusing symlinked path: ${path}`);
}

/** Match Hermes's explicit home selection, while keeping all writes under HOME. */
export async function hermesPostureHome(): Promise<string> {
  const home = process.env.HOME;
  if (!home || !isAbsolute(home)) throw new Error("HOME must be an absolute path.");
  const explicit = process.env.HERMES_HOME?.trim();
  const root = explicit || join(home, ".hermes");
  if (!isAbsolute(root) || !resolve(root).startsWith(resolve(home) + sep)) throw new Error("HERMES_HOME must be absolute and under HOME.");
  await safePath(resolve(root));
  if (!explicit) {
    const profilePath = join(home, ".hermes/active_profile");
    await safePath(profilePath);
    const profile = (await readOptional(profilePath))?.toString().trim();
    if (profile && profile !== "default") throw new Error("Select the default Hermes profile or set HERMES_HOME explicitly.");
  }
  return resolve(root);
}

/** The older MCP setup must not coexist with a recorded memory-provider install. */
export async function refuseHermesMcpWithPosture(): Promise<void> {
  const root = await hermesPostureHome();
  if (await statOptional(join(root, RECORD))) throw new Error("Hermes memory is installed; use protect --hermes-memory --unwrap first.");
}
async function treeFiles(root: string, relative = ""): Promise<string[]> {
  const path = join(root, relative);
  await safePath(path);
  const stat = await statOptional(path);
  if (!stat) return [];
  if (!stat.isDirectory()) throw new Error(`Expected a directory: ${path}`);
  const files: string[] = [];
  for (const name of await readdir(path)) {
    const child = join(relative, name);
    await safePath(join(root, child));
    const info = await lstat(join(root, child));
    if (info.isDirectory()) files.push(...await treeFiles(root, child));
    else if (info.isFile()) files.push(child);
    else throw new Error(`Expected a regular file: ${child}`);
  }
  return files;
}
function moduleCache(path: string): boolean {
  const match = /^plugins\/([^/]+)\/__pycache__\/([^.]+)\.[A-Za-z0-9_.-]+\.pyc$/.exec(path);
  return Boolean(match && HERMES_PLUGIN_FILES.some(file => file === `${match[1]}/${match[2]}.py`));
}
function inPythonCache(path: string): boolean {
  return path.split(sep).includes("__pycache__");
}
async function pluginSource(): Promise<Map<string, Buffer>> {
  const bundled = join(MODULE_DIR, "hermes-plugin");
  const source = await statOptional(bundled) ? bundled : resolve(MODULE_DIR, "../../../hermes-plugin");
  const files = new Map<string, Buffer>();
  for (const file of HERMES_PLUGIN_FILES) {
    await safePath(join(source, file));
    const bytes = await readOptional(join(source, file));
    if (!bytes) throw new Error(`Incomplete Hermes plugin source: ${file}`);
    files.set("plugins/" + file, bytes);
  }
  return files;
}
async function shimCommand(hooks: HermesPostureHooks): Promise<string[]> {
  if (hooks.shimCommand) return hooks.shimCommand;
  const path = MODULE_DIR.endsWith(`${sep}wrap`) ? resolve(MODULE_DIR, "../../dist/cli.js") : join(MODULE_DIR, "cli.js");
  let cli: string;
  try { cli = await realpath(path); } catch { throw new Error("Installed cli.js is missing; use a persistent Sanctuary installation."); }
  if (cli.split(sep).includes("_npx")) throw new Error("The CLI is inside an npm _npx cache; use a persistent Sanctuary installation.");
  if (!(await statOptional(cli))?.isFile()) throw new Error("Installed cli.js is missing; use a persistent Sanctuary installation.");
  return [await realpath(process.execPath), cli, "hermes-memory-client"];
}
function parseRecord(bytes: Buffer): InstallRecord {
  const record = JSON.parse(bytes.toString()) as InstallRecord;
  if (record.version !== 1 || typeof record.installedConfig !== "string" ||
      !(record.originalConfig === null || typeof record.originalConfig === "string") ||
      !(record.originalSoul === null || typeof record.originalSoul === "string") ||
      !(record.installedSoul === null || typeof record.installedSoul === "string") ||
      typeof record.soulInsertion !== "string" || !record.files ||
      Object.keys(record.files).sort().join() !== [...recordedPaths].sort().join() ||
      // SHA-256 is 32 bytes, represented by 64 hexadecimal characters.
      Object.values(record.files).some(value => typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value))) {
    throw new Error("The Hermes install record is not recognized.");
  }
  return record;
}

/** Plan all reads and checks first; apply a reversible ordered set of file changes. */
export async function runHermesPosture(
  options: { unwrap?: boolean; dryRun?: boolean },
  hooks: HermesPostureHooks,
  parity?: ParseParityOptions,
): Promise<void> {
  // Root would place this configuration in a different account from the running Hermes process.
  if (process.geteuid?.() === 0) throw new Error("run this as the account that runs Hermes");
  const root = await hermesPostureHome();
  for (const path of [CONFIG, SOUL, "plugins", "skills", RECORD, BACKUP, ...recordedPaths]) await safePath(join(root, path));
  const recordBytes = await readOptional(join(root, RECORD));
  if (options.unwrap && !recordBytes) { console.log("nothing to remove"); return; }
  const record = recordBytes ? parseRecord(recordBytes) : null;
  const configBytes = await readOptional(join(root, CONFIG));
  const config = configBytes?.toString() ?? null;
  const soulBytes = await readOptional(join(root, SOUL));
  const soul = soulBytes?.toString() ?? null;
  for (const bytes of [configBytes, soulBytes]) {
    if (bytes && !Buffer.from(bytes.toString()).equals(bytes)) throw new Error("Hermes configuration and identity must be valid UTF-8.");
  }
  const backup = await readOptional(join(root, BACKUP));
  if (record && backup?.toString() !== (record.originalConfig ?? "")) throw new Error("The original Hermes config backup does not match the record.");
  const existingPlugins = [...await treeFiles(root, "plugins/sanctuary"), ...await treeFiles(root, "plugins/sanctuary_memory")];
  for (const dir of ["plugins/sanctuary", "plugins/sanctuary_memory", "skills/sanctuary"]) {
    if (!record && await statOptional(join(root, dir))) throw new Error(`Foreign plugin or skill directory: ${join(root, dir)}`);
  }
  for (const path of existingPlugins.filter(path => !inPythonCache(path))) {
    if (!record?.files[path] || hash((await readOptional(join(root, path)))!) !== record.files[path]) throw new Error(`Modified plugin file: ${path}`);
  }
  if (record) {
    for (const path of recordedPaths) {
      const bytes = await readOptional(join(root, path));
      if (bytes && hash(bytes) !== record.files[path]) throw new Error(`Modified installed file: ${path}`);
    }
  }
  const changes = new Map<string, Buffer | null>();
  const steps = new Map<string, string>();
  const put = (path: string, value: string | Buffer | null, step: string) => { changes.set(path, value === null ? null : Buffer.from(value)); steps.set(path, step); };
  let changedRemoval = false;
  let reportPosture: ((installed: boolean) => void) | undefined;
  if (options.unwrap && record) {
    // Exact recorded bytes get the original file; subsequent operator edits retain their own values.
    const unchanged = config === record.installedConfig;
    changedRemoval = !unchanged;
    const next = unchanged ? record.originalConfig : planHermesMemoryRevert(config ?? "", record.originalConfig, record.installedConfig).content;
    await assertHermesPostureParseParity(config, next, scanHermesPosture(config), scanHermesPosture(next), false, parity);
    put(CONFIG, next, "config");
    if (record.soulInsertion && soul !== null) {
      const nextSoul = soul === record.installedSoul ? record.originalSoul : soul.replace(record.soulInsertion, "");
      put(SOUL, nextSoul, "soul");
    }
    for (const path of [...recordedPaths, ...existingPlugins.filter(moduleCache)]) put(path, null, "plugins");
    put(RECORD, null, "record");
    if (!changedRemoval) put(BACKUP, null, "record");
  } else {
    const source = await pluginSource();
    const command = await shimCommand(hooks);
    const socket = hooks.relaySocketPath ?? FIXED_SOCKET_PATH;
    // Turning off built-in memory requires the relay to exist so saved memories have a destination.
    if (!(await statOptional(socket))?.isSocket()) throw new Error(`Relay socket is missing: ${socket}`);
    const plan = planHermesMemoryPosture(config, HERMES_POSTURE_SETTINGS);
    await assertHermesPostureParseParity(config, plan.content, plan.before, plan.after, true, parity);
    let insertion = record?.soulInsertion ?? "";
    let installedSoul = soul;
    if (!record && soul !== null) {
      if (soul.includes("<!-- sanctuary memory")) throw new Error("SOUL.md already has Sanctuary memory markers without a record.");
      insertion = (soul.endsWith("\n\n") ? "" : soul.endsWith("\n") ? "\n" : "\n\n") + HERMES_SOUL_BLOCK + "\n";
      installedSoul = soul + insertion;
    }
    // Copies keep the installed provider independent from package updates and source-tree moves.
    for (const [path, bytes] of source) put(path, bytes, "plugins");
    put(SHIM, JSON.stringify(command) + "\n", "plugins");
    put(SKILL, HERMES_SKILL, "skill");
    if (installedSoul !== soul) put(SOUL, installedSoul, "soul");
    const hashes = Object.fromEntries(recordedPaths.map(path => [path, hash(changes.get(path)!)]));
    const nextRecord: InstallRecord = { version: 1, originalConfig: record ? record.originalConfig : config, installedConfig: plan.content,
      files: hashes, priorRaw: record?.priorRaw ?? plan.before.raw, removedMcp: record?.removedMcp ?? plan.removedMcp,
      soulInsertion: insertion, originalSoul: record ? record.originalSoul : soul, installedSoul: record?.installedSoul ?? installedSoul };
    if (!record) put(BACKUP, config ?? "", "record");
    put(RECORD, JSON.stringify(nextRecord, null, 2) + "\n", "record");
    // Provider files, command, skill and identity instructions must exist before config selects the provider.
    put(CONFIG, plan.content, "config");
    reportPosture = installed => {
      const view = installed ? plan.after : plan.before;
      const field = (key: string, fallback: string) => view.raw[key]?.trim().replace(/^[^:]+:\s*/, "") ?? fallback;
      console.log(`Read from Hermes's files in ${root}; Hermes's running state is not checked.`);
      console.log(`Memory provider: ${field("memory.provider", "builtin")}${installed && plan.before.raw["memory.provider"] && plan.before.raw["memory.provider"] !== plan.after.raw["memory.provider"] ? " (replaces another provider)" : ""}`);
      console.log(`Built-in memory: memory_enabled=${field("memory.memory_enabled", "true (default)")}, user_profile_enabled=${field("memory.user_profile_enabled", "true (default)")}`);
      console.log(`Tools plugin: sanctuary ${view.enabled.includes(HERMES_TOOLS_PLUGIN_NAME) ? "enabled" : "not enabled"}`);
      console.log(`MCP entry: sanctuary ${view.mcp.includes("sanctuary") ? "present" : "absent"}`);
      console.log(`Plugin files: ${installed || [...pluginPaths, SHIM].every(path => existingPlugins.includes(path)) ? "installed" : "missing"}`);
      console.log(`Relay socket: ${socket} (present)`);
      const others = view.enabled.filter(name => name !== HERMES_TOOLS_PLUGIN_NAME);
      if (others.length) console.log(`Other enabled plugins: ${others.join(", ")}; on Hermes 0.19 another enabled plugin can approve a call before the Sanctuary guard sees it, and the guard is not the lock.`);
      if (!installed) console.log("Planned: select sanctuary_memory, turn built-in memory off, enable sanctuary, install plugin files and remove the Sanctuary MCP entry.");
      console.log("MEMORY.md and USER.md stay on disk unread while this is installed. Restart Hermes.");
      if (soul === null) console.log("SOUL.md is absent; Hermes will seed its default identity. No SOUL.md was created.");
    };
  }
  const prior = new Map<string, Buffer | null>();
  const modes = new Map<string, number>();
  for (const [path, bytes] of changes) {
    await safePath(join(root, path));
    const old = await readOptional(join(root, path));
    if (old === null && bytes === null || old && bytes && old.equals(bytes)) { changes.delete(path); continue; }
    prior.set(path, old);
    const stat = await statOptional(join(root, path));
    if (stat) modes.set(path, stat.mode);
  }
  if (!changes.size) { reportPosture?.(true); console.log("already installed"); return; }
  if (options.dryRun) { reportPosture?.(false); console.log("Dry run: no files written."); return; }
  const createdDirs = new Set<string>();
  for (const path of changes.keys()) {
    let dir = dirname(join(root, path));
    while (dir.startsWith(root) && !(await statOptional(dir))) { createdDirs.add(dir); dir = dirname(dir); }
  }
  const touched: string[] = [];
  const removedDirs = new Map<string, number>();
  try {
    for (const [path, bytes] of changes) {
      touched.push(path);
      if (bytes === null) await unlinkSafeUnderRoot(join(root, path));
      else {
        await writeFileSafeUnderRoot(join(root, path), bytes, { mode: FILE_MODE });
        await chmod(join(root, path), FILE_MODE);
      }
      const next = [...changes.keys()][touched.length];
      if ((!next || steps.get(next) !== steps.get(path)) && hooks.failAfterStep === steps.get(path)) throw new Error(`Injected write failure after ${steps.get(path)}`);
    }
    for (const dir of createdDirs) await chmod(dir, DIR_MODE);
    if (options.unwrap) {
      for (const path of ["plugins/sanctuary/__pycache__", "plugins/sanctuary_memory/__pycache__", "plugins/sanctuary", "plugins/sanctuary_memory", "skills/sanctuary", "sanctuary-install"]) {
        const dir = join(root, path);
        await safePath(dir);
        const stat = await statOptional(dir);
        if (stat?.isDirectory() && !(await readdir(dir)).length) {
          await rmdir(dir);
          removedDirs.set(dir, stat.mode);
        }
      }
    }
  } catch (error) {
    for (const [dir, mode] of [...removedDirs].sort(([a], [b]) => a.length - b.length)) {
      await safePath(dir);
      await mkdir(dir, { mode });
    }
    for (const path of touched.reverse()) {
      const old = prior.get(path)!;
      if (old === null) { if (await statOptional(join(root, path))) await unlinkSafeUnderRoot(join(root, path)); }
      else { await writeFileSafeUnderRoot(join(root, path), old); await chmod(join(root, path), modes.get(path)!); }
    }
    for (const dir of [...createdDirs].sort((a, b) => b.length - a.length)) {
      if (await statOptional(dir)) await rmdir(dir);
    }
    throw error;
  }
  if (options.unwrap) {
    console.log(changedRemoval ? `Removed recorded files; kept subsequent edits. Original config backup: ${join(root, BACKUP)}` : "Removed Sanctuary memory configuration; original files restored.");
  } else { reportPosture?.(true); console.log("Sanctuary memory installed. Restart Hermes."); }
}
