/** Synthetic records only; this harness never opens an operator fortress. */
import { mkdir, writeFile, readFile, realpath, lstat } from "node:fs/promises";
import { join, resolve, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { createIdentity, sign, type StoredIdentity } from "../src/core/identity.js";
import { derivePurposeKey } from "../src/core/key-derivation.js";
import { checkpointSigningBytes } from "../src/audit/chain.js";
import { snapshotJSON } from "../src/evidence-pack/snapshot-generate.js";
import { installDrillCredentials, requireDrillCredentials, installIsolation } from "./evidence-pack-drill-isolation.js";
import * as C from "../src/evidence-pack/snapshot-contract.js";
declare const __SANCTUARY_SOURCE_SHA__: string;
// Must match the disposable root and checkpoint-prefix procedure in docs/audit/evidence-pack-v0-drill.md.
const MODE_DIRECTORY = 0o700, MODE_FILE = 0o600, INITIAL_CHECKPOINTS = 2, ENTRIES_PER_CHECKPOINT = 2;
interface FixtureState { synthetic: true; master: string; who: StoredIdentity; wrong: Pick<StoredIdentity, "identity_id" | "public_key" | "rotation_history">; rows: { namespace: string; key: string; data: string }[] }
export async function rootPath(path: string, allowedPath = "/tmp/v70"): Promise<string> {
  const root = resolve(path);
  const modeMask = 0o777; // Permission bits exclude the inode type.
  for (const directory of [allowedPath, root]) {
    const stat = await lstat(directory);
    // Only existing private directories owned by this uid may receive synthetic secret state.
    C.requireSnapshot(stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === process.getuid?.() && (stat.mode & modeMask) === MODE_DIRECTORY, C.HARD.unsafe_path);
  }
  const allowed = await realpath(allowedPath), parent = await realpath(dirname(root));
  // The explicit root must be a direct child of the checked disposable parent.
  C.requireSnapshot(parent === allowed, C.HARD.unsafe_path);
  return join(parent, basename(root));
}
async function storageFor(state: FixtureState) {
  const { MemoryStorage } = await import("../src/storage/memory.js");
  const storage = new MemoryStorage();
  for (const row of state.rows) await storage.write(row.namespace, row.key, Buffer.from(row.data, "base64url"));
  return storage;
}
async function append(root: string, state: FixtureState): Promise<void> {
  requireDrillCredentials();
  // Import production writers after isolation so their adapters use the same guarded builtins and credential module.
  const { AuditLog } = await import("../src/operational/audit-log.js");
  const { emitEnforcementCheckpoint } = await import("../src/transparency/emitter.js");
  const { TRANSPARENCY_NEVER_ABORTED } = await import("../src/transparency/scheduler.js");
  const fortress = join(root, "fortress"), who = state.who, master = Buffer.from(state.master, "base64url"), key = derivePurposeKey(master, "identity-encryption");
  const storage = await storageFor(state);
  const signBytes = (bytes: Uint8Array) => sign(bytes, who.encrypted_private_key, key);
  const auditLog = new AuditLog(storage, master, { checkpointInterval: ENTRIES_PER_CHECKPOINT, checkpointSigner: async payload => ({ signer_kid: who.identity_id, signature: Buffer.from(signBytes(checkpointSigningBytes(payload))).toString("base64url"), public_key: who.public_key }), checkpointPublicKeyResolver: () => who.public_key });
  try {
    for (let i = 0; i < ENTRIES_PER_CHECKPOINT; i++) await auditLog.appendCritical({ layer: "l2", operation: "synthetic_fixture_record", identity_id: who.identity_id, result: "success", details: { synthetic: true, purpose: "evidence snapshot copy drill" } });
    await auditLog.flushDurable();
    await emitEnforcementCheckpoint({ storage, auditLog, fortressId: who.identity_id, fortressPath: fortress, masterKey: master, signer: { signer_kid: who.identity_id, publicKey: C.publicKey(who.public_key), sign: async bytes => signBytes(bytes) }, binaryPath: join(fortress, "synthetic-binary"), version: "synthetic-fixture", abortState: TRANSPARENCY_NEVER_ABORTED });
    // Only encrypted synthetic storage records are persisted, under the explicitly created private fixture root.
    state.rows = [];
    for (const namespace of await storage.listNamespaces()) for (const row of await storage.list(namespace)) state.rows.push({ namespace, key: row.key, data: Buffer.from((await storage.read(namespace, row.key))!).toString("base64url") });
  } finally { key.fill(0); master.fill(0); }
}
export async function runDrillFixture(argv: string[]): Promise<number> {
  try {
    if (argv.length < 3 || argv[1] !== "--root" || !["create", "advance", "export"].includes(argv[0])) return C.EXIT_USAGE;
    if (argv.length !== (argv[0] === "export" ? 5 : 3) || (argv[0] === "export" && argv[3] !== "--name")) return C.EXIT_USAGE;
    const root = await rootPath(argv[2]); installIsolation(root, fileURLToPath(import.meta.url), true); await installDrillCredentials(); requireDrillCredentials();
    const fortress = join(root, "fortress"), statePath = join(fortress, "synthetic-state.json"); let state: FixtureState;
    if (argv[0] === "create") {
      await mkdir(fortress, { mode: MODE_DIRECTORY });
      const master = randomBytes(C.KEY_BYTES), key = derivePurposeKey(master, "identity-encryption");
      const who = createIdentity("synthetic evidence drill", key, "passphrase").storedIdentity;
      const wrong = createIdentity("synthetic unrelated pin", key, "passphrase").storedIdentity;
      state = { synthetic: true, master: master.toString("base64url"), who, wrong: { identity_id: wrong.identity_id, public_key: wrong.public_key, rotation_history: wrong.rotation_history }, rows: [] }; key.fill(0);
      await mkdir(join(fortress, "policy/egress/rules"), { recursive: true, mode: MODE_DIRECTORY });
      await writeFile(join(fortress, "synthetic-binary"), "Synthetic fixture only.\n", { flag: "wx", mode: MODE_FILE });
      await writeFile(join(fortress, "castle-pinned-pubkey.bin"), C.publicKey(who.public_key), { flag: "wx", mode: MODE_FILE });
      for (let i = 0; i < INITIAL_CHECKPOINTS; i++) await append(root, state);
      await writeFile(join(root, "pack-key.txt"), who.public_key + C.LF, { flag: "wx", mode: MODE_FILE });
      await writeFile(join(root, "wrong-key.txt"), wrong.public_key + C.LF, { flag: "wx", mode: MODE_FILE });
      await writeFile(statePath, snapshotJSON(state), { flag: "wx", mode: MODE_FILE }); master.fill(0);
    } else {
      C.requireSnapshot((await lstat(root)).isDirectory() && !(await lstat(fortress)).isSymbolicLink() && !(await lstat(statePath)).isSymbolicLink(), C.HARD.unsafe_path);
      state = JSON.parse(await readFile(statePath, "utf8")) as FixtureState; C.requireSnapshot(state.synthetic === true);
      if (argv[0] === "advance") { await append(root, state); await writeFile(statePath, snapshotJSON(state), { mode: MODE_FILE }); }
      else {
        C.safeName(argv[4]); const output = join(root, argv[4]);
        const { exportSnapshot } = await import("../src/evidence-pack/snapshot-export-cli.js");
        const { gatherSnapshot } = await import("../src/evidence-pack/snapshot-gather.js");
        const { FilesystemStorage } = await import("../src/storage/filesystem.js");
        const storage = new FilesystemStorage(join(fortress, "state"));
        // The real gather reads a disposable filesystem projection of records made by the in-memory production writers.
        for (const row of state.rows) await storage.write(row.namespace, row.key, Buffer.from(row.data, "base64url"));
              const masterKey = Buffer.from(state.master, "base64url");
        const boot = async () => ({ config: { storage_path: fortress }, identityManager: { getDefault: () => state.who, list: () => [state.who], get: () => state.who }, masterKey, cleanup: async () => {} });
        try {
          const result = await exportSnapshot({ fortress, output, receipt: join(root, argv[4] + "-receipt.json"), publicKeyFile: join(root, argv[4] + "-export-key.txt") }, { boot: boot as unknown as import("../src/evidence-pack/snapshot-export-cli.js").ExportDependencies["boot"], gather: async () => gatherSnapshot({ storage, masterKey, fortress, generatedAt: new Date().toISOString(), localSign: true, globalPinPath: join(fortress, "synthetic-absent-global-pin") }), buildRevision: __SANCTUARY_SOURCE_SHA__, runtimeRevision: __SANCTUARY_SOURCE_SHA__, phase: async () => { requireDrillCredentials(); }, io: { stdout: text => { process.stdout.write(text); }, stderr: text => { process.stderr.write(text); } } });
          C.requireSnapshot(result === C.EXIT_PASS, C.HARD.nested_invalid);
          const descriptorBytes = await readFile(join(output, C.TRUST_FILENAME));
          await writeFile(join(root, argv[4] + "-trust.json"), descriptorBytes, { flag: "wx", mode: MODE_FILE });
          const descriptor = C.parseSnapshotJSON(descriptorBytes, C.MAX_TRUST_BYTES) as { format: string; keys: C.TrustKey[] };
          const wrong = state.wrong, fingerprint = C.manifestDigest(C.publicKey(wrong.public_key));
          // The unrelated public role is an explicit synthetic signature control, never an acceptance pin.
          descriptor.keys = descriptor.keys.map(row => row.role !== C.PIN_ROLE.pack ? row : { ...row, key_id: fingerprint, fingerprint, public_key_base64url: wrong.public_key, rotation_evidence: { kind: C.ROTATION.history, identity_id: wrong.identity_id, current_public_key: wrong.public_key, history: [] } });
          // Must match the independently transferred control pins in docs/audit/evidence-pack-v0-drill.md.
          await writeFile(join(root, argv[4] + "-wrong-trust.json"), snapshotJSON(descriptor), { flag: "wx", mode: MODE_FILE });
        } finally { masterKey.fill(0); }
      }
    }
    process.stdout.write("Synthetic fixture step completed.\n"); return C.EXIT_PASS;
  } catch { process.stderr.write("Synthetic fixture step refused.\n"); return C.EXIT_FAIL; }
}
