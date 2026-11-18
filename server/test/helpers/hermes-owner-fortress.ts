/**
 * Temporary Hermes fortresses for the owner-verb tests: a real filesystem
 * fortress under a temporary HOME, custody from a stored fixture passphrase
 * (the in-memory keychain store installed by the suite setup), a primary
 * identity, and helpers that seed passages and bridge audit rows exactly as
 * the bridge writes them. Never touches a real keychain or a real ~/.sanctuary.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, mkdtemp, mkdir, readdir, readFile, readlink, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough, type Duplex } from "node:stream";

import { IdentityManager } from "../../src/cognitive/tools.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { fromBase64url } from "../../src/core/encoding.js";
import {
  CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME, establishMaster, unlockExistingMasterReadOnly, withCustodyWriteLock,
} from "../../src/core/master-custody.js";
import { fortressIdFromStoragePath } from "../../src/dashboard/v1_1/wiring.js";
import {
  PrivateFrameDecoder, composeHermesMemoryAdapterOptions, encodePrivateFrame, hermesBridgeAuditPrincipal,
  type HermesBridgeAuditRecord,
} from "../../src/hermes-memory-bridge/index.js";
import { createSdwMemoryAdapter } from "../../src/index.js";
import { AuditLog, type AuditEntry } from "../../src/operational/audit-log.js";
import { hermesBridgePassageTextDigest } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { memoryProvenancePublicKeyFingerprint } from "../../src/sdw/memory-provenance-bad-signers.js";
import { memoryInsertIngress } from "../../src/sdw/memory-provenance-ingress.js";
import { withExclusiveMasterRotationBarrier } from "../../src/storage/cross-process-lock.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { ReadOnlyStorageGuard } from "../../src/storage/read-only-guard.js";
import { persistUserProvidedPassphrase } from "../../src/wrap/passphrase.js";
import { runHermesMemory, type HermesMemoryOptions } from "../../src/cli/hermes-memory.js";

export const FIXTURE_PASSPHRASE = "hermes owner verb fixture passphrase";
export const FIXTURE_AGENT_ID = "agent-owner";
export const FIXTURE_FORTRESS_ID = "fortress-owner";

export type Cleanup = () => Promise<unknown>;

export async function runCleanups(stack: Cleanup[]): Promise<void> {
  const failures: unknown[] = [];
  while (stack.length) {
    try { await stack.pop()!(); } catch (cause) { failures.push(cause); }
  }
  if (failures.length) throw new AggregateError(failures, `Owner fixture cleanup failed: ${failures.map(String).join("; ")}`);
}

export interface OwnerFortress {
  readonly root: string;
  readonly home: string;
  readonly fortress: string;
  readonly storage: FilesystemStorage;
  readonly fortressId: string;
  /** ISO time after fixture setup and its first audit row, before any seeded row. */
  readonly since: string;
  readonly bridgeEnv: Record<string, string>;
}

/** Build a fortress shaped like the bridge's: HOME/Library/.../Fortresses/<id>, mode 0700 throughout. */
export async function ownerFortress(stack: Cleanup[]): Promise<OwnerFortress> {
  const root = await realpath(await mkdtemp(join(tmpdir(), "hermes-owner-")));
  stack.push(async () => {
    // Drain both custody holders before removal so no live lease outlives its namespace.
    await withExclusiveMasterRotationBarrier(storage, CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME, async () => undefined)
      .catch(() => undefined);
    await withCustodyWriteLock(storage, async () => undefined).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
  });
  const home = join(root, "home");
  await mkdir(home, { mode: 0o700 });
  const fortress = join(home, "Library", "Application Support", "Sanctuary", "Fortresses", FIXTURE_FORTRESS_ID);
  let dir = home;
  for (const part of ["Library", "Application Support", "Sanctuary", "Fortresses", FIXTURE_FORTRESS_ID, "state"]) {
    dir = join(dir, part);
    await mkdir(dir, { mode: 0o700 });
  }
  const storage = new FilesystemStorage(join(fortress, "state"));
  await mkdir(storage.namespacePath(CUSTODY_WRITE_LOCK_NAMESPACE), { mode: 0o700 });
  await persistUserProvidedPassphrase(FIXTURE_PASSPHRASE, { home, storagePath: fortress, platformOverride: "freebsd" });
  const custody = await establishMaster({ storage, passphrase: FIXTURE_PASSPHRASE,
    firstRun: { installMode: "headless", mintRecoveryKey: false } });
  let fingerprint: string;
  try {
    const identities = new IdentityManager(storage, custody.masterKey);
    await identities.load();
    const { storedIdentity } = createIdentity("owner fixture", derivePurposeKey(custody.masterKey, "identity-encryption"), "passphrase");
    await identities.save(storedIdentity);
    fingerprint = memoryProvenancePublicKeyFingerprint(fromBase64url(storedIdentity.public_key));
    // One retained row before the window start, so a window starting at `since` is fully retained.
    await new AuditLog(storage, custody.masterKey).appendCritical({ layer: "l1", operation: "owner_fixture_ready",
      identity_id: "operator", result: "success" });
  } finally { await custody.masterWriteBarrier?.release(); custody.masterKey.fill(0); }
  await new Promise(resolve => setTimeout(resolve, 5));
  const since = new Date().toISOString();
  await new Promise(resolve => setTimeout(resolve, 5));
  return {
    root, home, fortress, storage, fortressId: fortressIdFromStoragePath(await realpath(fortress)), since,
    bridgeEnv: { HOME: home, LANG: "C", TMPDIR: tmpdir(), HERMES_MEMORY_BRIDGE_IDENTITY: fingerprint,
      HERMES_MEMORY_AGENT_ID: FIXTURE_AGENT_ID, HERMES_MEMORY_FORTRESS_ID: FIXTURE_FORTRESS_ID },
  };
}

/** Run writes under an ordinary custody session, then release it so the owner verbs can take the exclusive side. */
export async function withSeedSession<T>(f: OwnerFortress, run: (session: {
  readonly masterKey: Uint8Array;
  readonly audit: AuditLog;
  readonly adapter: ReturnType<typeof createSdwMemoryAdapter>;
}) => Promise<T>, ownerRef = FIXTURE_AGENT_ID): Promise<T> {
  const custody = await establishMaster({ storage: f.storage, passphrase: FIXTURE_PASSPHRASE });
  try {
    const identities = new IdentityManager(f.storage, custody.masterKey);
    await identities.load();
    let adapter: ReturnType<typeof createSdwMemoryAdapter> | undefined;
    const composed = await composeHermesMemoryAdapterOptions({ storage: f.storage, masterKey: custody.masterKey,
      fortressId: f.fortressId, ownerRef, identityManager: identities,
      scanForeignDependencies: (did, fp) => adapter!.scanForeignSignerDependencies(did, fp) });
    adapter = createSdwMemoryAdapter({ mode: "standard", ...composed.options });
    return await run({ masterKey: custody.masterKey, audit: new AuditLog(f.storage, custody.masterKey), adapter });
  } finally { await custody.masterWriteBarrier?.release(); custody.masterKey.fill(0); }
}

/** Save one passage the way the bridge does: own scope, user_content taint, memory_insert ingress. */
export async function seedPassage(f: OwnerFortress, passageId: string, text: string, options: { tags?: string[]; createdAt?: string } = {}) {
  return withSeedSession(f, ({ adapter }) => adapter.insertPassage({
    passage_id: passageId, text, ...(options.tags ? { tags: options.tags } : {}),
    ...(options.createdAt ? { created_at: options.createdAt } : {}),
    provenanceContext: memoryInsertIngress(() => undefined, "user_content"),
  }, "user_content"));
}

/** Append bridge rows with the AuditForwarder's exact envelope (operation, layer, identity, success). */
export async function seedBridgeRows(f: OwnerFortress, records: readonly HermesBridgeAuditRecord[]): Promise<void> {
  await withSeedSession(f, async ({ audit }) => {
    for (const record of records) {
      await audit.appendCritical({ layer: "l1", operation: "hermes_memory_bridge", identity_id: "hermes-memory-bridge",
        result: "success", details: { ...record } });
    }
  });
}

/** An insert_admitted row as bridge-core writes it for this fixture's agent. */
export function admittedRow(passageId: string, text: string, entryId: string, agentId = FIXTURE_AGENT_ID): HermesBridgeAuditRecord {
  return { kind: "insert_admitted", entryId, operation: "memory_insert", tier: 3,
    agent_id: hermesBridgeAuditPrincipal(agentId), requester_verified: false, passage_id: passageId,
    document_id: `mem.${agentId}.${passageId}`, text_sha256: hermesBridgePassageTextDigest(text),
    bytes: Buffer.byteLength(text, "utf8") };
}

export async function auditEntries(f: OwnerFortress, operation?: string): Promise<AuditEntry[]> {
  const storage = new ReadOnlyStorageGuard(f.storage);
  const master = await unlockExistingMasterReadOnly(storage, { passphrase: FIXTURE_PASSPHRASE });
  try {
    return (await new AuditLog(storage, master, { readOnly: true }).query({ limit: Number.MAX_SAFE_INTEGER,
      ...(operation ? { operation_type: operation } : {}) })).entries;
  } finally { master.fill(0); }
}

/** Content hash of every file and directory below a root, for byte-identity assertions. */
export async function treeHashes(root: string): Promise<Record<string, string>> {
  const result: Record<string, string> = {};
  // A missing root is recorded as absent, so it appearing later is a difference; an unreadable one throws.
  if (await lstat(root).then(() => false, (cause: NodeJS.ErrnoException) => { if (cause.code === "ENOENT") return true; throw cause; })) {
    return { "": "absent" };
  }
  async function visit(dir: string, prefix: string) {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const name = prefix + entry.name;
      if (entry.isDirectory()) {
        result[name + "/"] = "directory";
        await visit(join(dir, entry.name), name + "/");
      } else if (entry.isFile()) result[name] = createHash("sha256").update(await readFile(join(dir, entry.name))).digest("hex");
      // A symlink is recorded by its target, so retargeting it is a change.
      else if (entry.isSymbolicLink()) result[name] = `symlink:${await readlink(join(dir, entry.name))}`;
      else result[name] = "other";
    }
  }
  await visit(root, "");
  return result;
}

export class TerminalSink extends PassThrough {
  isTTY = true;
  text = "";
  constructor() {
    super();
    this.on("data", chunk => { this.text += String(chunk); });
  }
}

export class TerminalInput extends PassThrough {
  isTTY = true;
  rawMode = false;
  setRawMode(mode: boolean): this { this.rawMode = mode; return this; }
}

export interface VerbRun {
  readonly code: number;
  readonly out: string;
  readonly err: string;
}

/** Package version the in-process runs pass, so the report header can be asserted exactly. */
export const FIXTURE_PACKAGE_VERSION = "0.0.0-owner-fixture";

/** Package identity for an in-process run: a kit-shaped B/B_RUNTIME/pkg path under the fortress's temporary root. */
export function fixturePackage(f: OwnerFortress): Pick<HermesMemoryOptions, "packageVersion" | "packageRoot" | "invokedEntry"> {
  const packageRoot = join(f.root, "kit", "B_RUNTIME", "pkg");
  return { packageVersion: FIXTURE_PACKAGE_VERSION, packageRoot, invokedEntry: join(packageRoot, "dist", "cli.js") };
}

/** Run an owner verb in-process with terminal-like streams; `answer` is typed after the first prompt appears. */
export async function runVerb(f: OwnerFortress, argv: string[], options: Partial<HermesMemoryOptions> & {
  readonly answer?: string;
  readonly env?: NodeJS.ProcessEnv;
} = {}): Promise<VerbRun> {
  const stdout = (options.stdout as TerminalSink | undefined) ?? new TerminalSink();
  const stderr = (options.stderr as TerminalSink | undefined) ?? new TerminalSink();
  const stdin = (options.stdin as TerminalInput | undefined) ?? new TerminalInput();
  if (options.answer !== undefined) {
    const answer = options.answer;
    const onData = () => {
      if (stdout.text.includes("Type DELETE")) {
        stdout.off("data", onData);
        setImmediate(() => stdin.write(answer));
      }
    };
    stdout.on("data", onData);
  }
  const code = await runHermesMemory({
    uid: process.getuid!(),
    signals: { on: () => undefined, off: () => undefined },
    ...fixturePackage(f),
    ...options,
    argv: [argv[0]!, "--fortress", f.fortress, "--agent-id", FIXTURE_AGENT_ID, ...argv.slice(1)],
    env: options.env ?? { HOME: f.home },
    stdout, stderr, stdin,
  });
  return { code, out: stdout.text, err: stderr.text };
}

const source = (path: string) => new URL(path, import.meta.url).href;
export const CLI_ENTRY = source("../../src/cli.ts");
const KEYCHAIN_STORE = source("../setup/keychain-memory-store.ts");
// Each child installs the injected credential store before importing anything that could reach a keychain.
export const CHILD_PREAMBLE = `const { installInMemoryKeychainStore } = await import(${JSON.stringify(KEYCHAIN_STORE)}); installInMemoryKeychainStore();`;
// Two seconds lets an exited child's pipes settle before the group is force-killed.
const CHILD_SETTLE_MS = 2_000;

export interface ObservedChild {
  readonly child: ChildProcess;
  readonly exit: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
  stdout(): string;
  stderr(): string;
}

/** Observe a detached child and register a teardown that always reaps its whole process group. */
export function observeChild(child: ChildProcess, stack: Cleanup[]): ObservedChild {
  let stdout = "";
  let stderr = "";
  child.stdout?.on("data", bytes => { stdout += String(bytes); });
  child.stderr?.on("data", bytes => { stderr += String(bytes); });
  const exit = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });
  void exit.catch(() => undefined);
  stack.push(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      try { process.kill(-child.pid!, "SIGCONT"); } catch { /* already gone */ }
      try { process.kill(-child.pid!, "SIGKILL"); } catch { /* already gone */ }
    }
    await Promise.race([exit, new Promise(resolve => setTimeout(resolve, CHILD_SETTLE_MS))]);
    try { process.kill(-child.pid!, "SIGKILL"); } catch { /* group already gone */ }
    for (const stream of child.stdio) stream?.destroy();
  });
  return { child, exit, stdout: () => stdout, stderr: () => stderr };
}

/** Run the real CLI dispatcher in a child with the injected credential store. */
export async function runCli(f: OwnerFortress, argv: string[], stack: Cleanup[]): Promise<{ code: number | null; out: string; err: string }> {
  const script = `${CHILD_PREAMBLE} process.argv = [process.execPath, ${JSON.stringify(CLI_ENTRY)}, ...${JSON.stringify(argv)}]; await import(${JSON.stringify(CLI_ENTRY)});`;
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: f.home, VITEST: "true", SANCTUARY_SKIP_UPDATE_CHECK: "1" };
  for (const name of ["SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY", "SANCTUARY_PASSPHRASE", "SANCTUARY_RECOVERY_KEY"]) delete env[name];
  const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script],
    { detached: true, stdio: ["ignore", "pipe", "pipe"], env });
  const observed = observeChild(child, stack);
  const { code } = await observed.exit;
  return { code, out: observed.stdout(), err: observed.stderr() };
}

/** Start the real bridge child on an inherited socket pair, as the relay does. */
export function startBridge(f: OwnerFortress, stack: Cleanup[]) {
  const script = `${CHILD_PREAMBLE}
    process.env = ${JSON.stringify(f.bridgeEnv)};
    process.argv = [process.execPath, ${JSON.stringify(CLI_ENTRY)}, 'hermes-memory-bridge', 'run', '--relay-fd', '3'];
    await import(${JSON.stringify(CLI_ENTRY)});`;
  const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script],
    { detached: true, stdio: ["ignore", "pipe", "pipe", "pipe"], env: { ...process.env, VITEST: "true" } });
  const observed = observeChild(child, stack);
  const socket = child.stdio[3] as Duplex;
  const decoder = new PrivateFrameDecoder();
  const frames: Record<string, unknown>[] = [];
  let wake: (() => void) | undefined;
  socket.on("data", (bytes: Buffer) => {
    decoder.push(bytes);
    for (;;) {
      const frame = decoder.next();
      if (frame.kind === "need_more") break;
      if (frame.kind === "fatal") throw frame.error;
      frames.push(JSON.parse(Buffer.from(frame.body).toString("utf8")) as Record<string, unknown>);
    }
    wake?.();
  });
  socket.on("error", () => undefined);
  const next = async () => {
    if (frames.length === 0) await Promise.race([
      new Promise<void>(resolve => { wake = resolve; }),
      observed.exit.then(() => { throw new Error(`bridge exited: ${observed.stderr()}`); }),
    ]);
    const frame = frames.shift();
    if (frame === undefined) throw new Error("missing bridge frame");
    return frame;
  };
  const send = (value: Record<string, unknown>) => socket.write(encodePrivateFrame(Buffer.from(JSON.stringify(value))));
  let requests = 0;
  const call = async (name: string, args: Record<string, unknown>) => {
    const connection = `c${++requests}`;
    send({ type: "accepted", connection_id: connection });
    send({ type: "frame", connection_id: connection, frame_b64: Buffer.from(JSON.stringify({ type: "tools_call", request_id: `request-${requests}`, name, arguments: args })).toString("base64") });
    for (;;) {
      const frame = await next();
      if (frame.type === "probe") send({ type: "probe_reply", connection_id: connection, nonce: frame.nonce });
      if (frame.type === "response") {
        const response = JSON.parse(Buffer.from(String(frame.result_b64), "base64").toString("utf8"));
        send({ type: "closed", connection_id: connection });
        return JSON.parse(response.payload.content[0].text) as Record<string, unknown>;
      }
    }
  };
  const stop = async () => {
    send({ type: "relay_shutdown" });
    const { code } = await observed.exit;
    if (code !== 0) throw new Error(`bridge stop exit ${String(code)}: ${observed.stderr()}`);
  };
  return { ...observed, next, call, stop };
}
