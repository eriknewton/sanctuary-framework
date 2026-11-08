/** Read-only recipient isolation and same-instance synthetic drill isolation. */
import fs from "node:fs";
import fsp from "node:fs/promises";
import child from "node:child_process";
import net from "node:net";
import tls from "node:tls";
import http from "node:http";
import https from "node:https";
import http2 from "node:http2";
import inspector from "node:inspector";
import workers from "node:worker_threads";
import dns from "node:dns";
import dgram from "node:dgram";
import { promisify } from "node:util";
import { syncBuiltinESMExports } from "node:module";
import { resolve, sep, dirname, basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { installInMemoryKeychainStore } from "../test/setup/keychain-memory-store.js";
import { execKeychain } from "../src/wrap/keychain-exec.js";
import { LINUX_METADATA_PROGRAM, METADATA_TIMEOUT_MS, METADATA_OUTPUT_LIMIT } from "../src/evidence-pack/snapshot-metadata.js";
import { OS_ATTACHED_METADATA } from "../src/evidence-pack/snapshot-contract.js";
const NORMAL_EXIT = 0, DENIED_EXIT = 1;
let installed = false;
export async function installDrillCredentials(): Promise<void> {
  // Explicit synthetic mode avoids ambient package-marker probes; the credential round trip still requires the injected store.
  process.env.NODE_ENV = "test";
  installInMemoryKeychainStore();
  // This probe reaches the exact chokepoint used by the bundled exporter, so a second fake module cannot masquerade as isolation.
  const service = "synthetic-evidence-drill", account = "synthetic", sentinel = "synthetic-isolation-proof";
  const added = await execKeychain("security", ["add-generic-password", "-U", "-s", service, "-a", account, "-w", sentinel]);
  const found = await execKeychain("security", ["find-generic-password", "-s", service, "-a", account, "-w"]);
  const removed = await execKeychain("security", ["delete-generic-password", "-s", service, "-a", account]);
  if (added.code !== NORMAL_EXIT || found.code !== NORMAL_EXIT || found.stdout.trimEnd() !== sentinel || removed.code !== NORMAL_EXIT) throw new Error("Synthetic credential round trip required");
  installed = true;
}
export function requireDrillCredentials(): void { if (!installed) throw new Error("Drill isolation is required"); }
export function installIsolation(rootPath: string, bundlePath: string, writable = false): void {
  const realpath = fs.realpathSync.bind(fs), lstat = fs.lstatSync.bind(fs);
  const root = realpath(rootPath), bundle = realpath(bundlePath);
  function resolved(path: string): string {
    try { return realpath(path); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT" || dirname(path) === path) throw error;
      return join(resolved(dirname(path)), basename(path));
    }
  }
  const home = process.env.HOME ? resolved(resolve(process.env.HOME)) : undefined;
  let denied = 0, enumerations = 0;
  const deny = (): never => { denied++; throw new Error("Evidence drill isolation denied I/O"); };
  const inside = (path: string) => path === root || path.startsWith(root + sep);
  const pathOf = (value: unknown) => value instanceof URL ? fileURLToPath(value) : Buffer.isBuffer(value) ? value.toString() : typeof value === "string" ? value : undefined;
  const check = (value: unknown, write = false) => {
    if (typeof value === "number") return deny();
    const text = pathOf(value); if (!text) return deny();
    // Canonical ancestors and a non-link final component keep admitted paths inside the actual disposable root.
    const lexical = resolve(text);
    let link = false;
    try { link = lstat(lexical).isSymbolicLink(); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") return deny(); }
    if (link) return deny();
    const path = resolved(lexical);
    if (!writable && ((home && (path === home || path.startsWith(home + sep))) || path.split(sep).includes(".sanctuary"))) return deny();
    if (write && !writable) return deny();
    if (!inside(path) && path !== bundle) return deny();
  };
  function wrap(object: object, key: string, fn: (original: (...args: unknown[]) => unknown, args: unknown[]) => unknown) {
    const record = object as Record<string, unknown>; const original = record[key];
    if (typeof original === "function") {
      const wrapper = function (...args: unknown[]) { return fn(original.bind(object), args); };
      if (object === child && key === "execFile") Object.defineProperty(wrapper, promisify.custom, { value: (...args: unknown[]) => new Promise((resolve, reject) => wrapper(...args, (error: Error | null, stdout: string, stderr: string) => error ? reject(error) : resolve({ stdout, stderr }))) });
      record[key] = wrapper;
    }
  }
  // Only explicit fixture paths can be accessed, so HOME and operator storage cannot become implicit inputs.
  const reads = ["readFile", "open", "opendir", "readdir", "stat", "lstat", "realpath", "readlink", "access", "exists", "createReadStream"];
  const writes = ["writeFile", "appendFile", "mkdir", "mkdtemp", "rm", "rmdir", "unlink", "rename", "copyFile", "cp", "symlink", "link", "chmod", "chown", "truncate", "createWriteStream"];
  for (const object of [fs, fsp]) for (const key of reads) for (const suffix of ["", "Sync"]) wrap(object, key + suffix, (original, args) => { check(args[0]); if (key === "open" && !writable) { const flags = args[1]; if (typeof flags === "string" ? flags !== "r" : typeof flags === "number" && (flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_TRUNC)) !== 0) deny(); } return original(...args); });
  for (const object of [fs, fsp]) for (const key of writes) for (const suffix of ["", "Sync"]) wrap(object, key + suffix, (original, args) => { check(args[0], true); if (["rename", "copyFile", "cp", "symlink", "link"].includes(key)) check(args[1], true); return original(...args); });
  for (const key of ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"]) wrap(child, key, (original, args) => {
    const [command, argv, options] = args as [string, string[], Record<string, unknown>];
    if (!Array.isArray(argv) || !options) return deny();
    const file = argv.at(-1); check(file);
    const linux = command === "/usr/bin/python3" && JSON.stringify(argv.slice(0, -1)) === JSON.stringify(["-I", "-S", "-c", LINUX_METADATA_PROGRAM]);
    const darwin = command === "/usr/bin/xattr" && argv[0] === "-s" && (argv.length === 2 || (argv.length === 4 && argv[1] === "-p" && OS_ATTACHED_METADATA.includes(argv[2])));
    const exact = linux || darwin;
    const stdio = options.stdio;
    // Value lookups discard stdout because only attribute names may reach the verifier.
    const safeStdio = darwin && argv[1] === "-p" ? stdio === "ignore" : JSON.stringify(stdio) === JSON.stringify(["ignore", "pipe", "ignore"]);
    const closed = options.shell === false && JSON.stringify(options.env) === JSON.stringify({ LC_ALL: "C" }) && options.timeout === METADATA_TIMEOUT_MS && options.maxBuffer === METADATA_OUTPUT_LIMIT && safeStdio;
    // Must match snapshot-metadata.ts: every writable and read-only path admits only bounded no-follow enumeration with closed execution.
    if (!exact || !closed || !["execFileSync", "spawnSync"].includes(key)) return deny();
    enumerations++; return original(...args);
  });
  // Must match the forbidden bundle import set in test/evidence-pack/snapshot-packed.test.ts.
  // Every network and alternate execution entry is denied so non-PASS paths have the same isolation boundary.
  for (const [object, keys] of [[net, ["connect", "createConnection", "createServer"]], [net.Socket.prototype, ["connect"]], [tls, ["connect", "createServer"]], [http, ["request", "get", "createServer"]], [https, ["request", "get", "createServer"]], [dns, ["lookup", "resolve"]], [dns.promises, ["lookup", "resolve"]], [dgram, ["createSocket"]], [http2, ["connect", "createServer", "createSecureServer"]], [inspector, ["open", "Session"]], [workers, ["Worker"]]] as [object, string[]][]) for (const key of keys) wrap(object, key, () => deny());
  for (const object of [dns, dns.promises]) for (const key of Object.keys(object)) if (typeof (object as unknown as Record<string, unknown>)[key] === "function") wrap(object, key, () => deny());
  globalThis.fetch = async () => deny();
  syncBuiltinESMExports();
  process.on("exit", () => { process.stderr.write(JSON.stringify({ isolation: true, denied, enumerations }) + "\n"); if (denied) process.exitCode = DENIED_EXIT; });
}
// The preload is opt-in and the production verifier never imports this harness.
if (process.env.EVIDENCE_PACK_ISOLATION_ROOT && process.env.EVIDENCE_PACK_ISOLATION_BUNDLE) installIsolation(process.env.EVIDENCE_PACK_ISOLATION_ROOT, process.env.EVIDENCE_PACK_ISOLATION_BUNDLE);
