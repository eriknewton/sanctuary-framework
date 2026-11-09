/** Offline filesystem boundary; authority is supplied only through explicit public pin files. */
import { constants, type BigIntStats } from "node:fs";
import { lstat, open, opendir, realpath, type FileHandle } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { verify } from "../core/identity.js";
import { verifySnapshot } from "./snapshot-verify.js";
import { validateSnapshotPins } from "./snapshot-trust.js";
import * as C from "./snapshot-contract.js";
declare const __SANCTUARY_SOURCE_SHA__: string;
declare const __EVIDENCE_PACK_VERSION__: string;
// Must match definitions in tsup.evidence-pack.config.ts and the package version read by build-evidence-pack.mjs.
export const OFFLINE_REVISION = typeof __SANCTUARY_SOURCE_SHA__ === "string" ? __SANCTUARY_SOURCE_SHA__ : "";
export const OFFLINE_VERSION = typeof __EVIDENCE_PACK_VERSION__ === "string" ? __EVIDENCE_PACK_VERSION__ : "0.1.0";
// Must match the shared held-inode contract in snapshot-metadata.ts so capture cannot consume names from a replacement.
import { metadataNames } from "./snapshot-metadata.js";
export { metadataNames, METADATA_OUTPUT_LIMIT, METADATA_TIMEOUT_MS, LINUX_METADATA_PROGRAM } from "./snapshot-metadata.js";
function observation(stat: BigIntStats): C.CapturedStat {
  return { type: stat.isFile() ? C.FILE_TYPE.file : stat.isDirectory() ? C.FILE_TYPE.directory : "invalid", size: Number(stat.size), nlink: Number(stat.nlink), dev: String(stat.dev), ino: String(stat.ino), mtime: String(stat.mtimeNs), ctime: String(stat.ctimeNs) };
}
export async function readPublicFile(path: string, maxBytes: number): Promise<Uint8Array> {
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = observation(await fd.stat({ bigint: true }));
    C.requireSnapshot(before.type === C.FILE_TYPE.file && before.nlink === 1, C.HARD.file_type_invalid); C.cap(before.size, maxBytes);
    const buffer = Buffer.alloc(maxBytes + 1); const { bytesRead } = await fd.read(buffer, 0, buffer.length, 0);
    C.cap(bytesRead, maxBytes);
    C.requireSnapshot(C.canonicalSnapshotJSON(before) === C.canonicalSnapshotJSON(observation(await fd.stat({ bigint: true }))), C.HARD.snapshot_changed);
    return buffer.subarray(0, bytesRead);
  } finally { await fd.close(); }
}
async function directoryNames(path: string): Promise<Buffer[]> {
  const names: Buffer[] = [];
  // Node supports raw buffer names here although its directory encoding declaration omits that mode.
  const directory = await opendir(path, { encoding: "buffer" as BufferEncoding });
  // Bound inventory while enumerating so an oversized hostile directory cannot allocate an unbounded name list.
  for await (const entry of directory) {
    C.cap(names.length + 1, C.MAX_FILES);
    const name = entry.name as unknown as Buffer;
    C.requireSnapshot(Buffer.isBuffer(name), C.HARD.unsafe_path); C.cap(name.length, C.MAX_NAME_BYTES);
    names.push(name);
  }
  return names;
}
export async function captureOfflineSnapshot(path: string, packKey: string, expectedDigest: string, phase: (state: C.ProtocolState) => void = () => {}): Promise<C.CapturedSnapshot> {
  phase(C.STATES.MANIFEST_BYTES);
  const root = join(await realpath(dirname(resolve(path))), basename(resolve(path))); const held: { fd: FileHandle; file: C.CapturedFile; path: string }[] = [];
  const before = observation(await lstat(root, { bigint: true }));
  C.requireSnapshot(before.type === C.FILE_TYPE.directory, C.HARD.file_type_invalid);
  const rootFd = await open(root, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY);
  try {
    C.requireSnapshot(C.canonicalSnapshotJSON(before) === C.canonicalSnapshotJSON(observation(await rootFd.stat({ bigint: true }))), C.HARD.snapshot_changed);
    const names = await directoryNames(root); C.cap(names.length, C.MAX_FILES);
    const rootMetadata = metadataNames(root, process.platform, await rootFd.stat({ bigint: true }));
    async function capture(name: Buffer, maximum: number): Promise<C.CapturedFile> {
      const decoded = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(name); C.safeName(decoded);
      const filePath = join(root, decoded); const lst = observation(await lstat(filePath, { bigint: true }));
      C.requireSnapshot(lst.type === C.FILE_TYPE.file && lst.nlink === 1, C.HARD.file_type_invalid); C.cap(lst.size, maximum);
      const fd = await open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      const file: C.CapturedFile = { name, bytes: new Uint8Array(), before: lst, after: lst, metadata: [] };
      // Register the handle before any fallible observation so the outer finally closes every opened file.
      held.push({ fd, file, path: filePath });
      file.before = observation(await fd.stat({ bigint: true }));
      C.requireSnapshot(C.canonicalSnapshotJSON(lst) === C.canonicalSnapshotJSON(file.before), C.HARD.snapshot_changed);
      const buffer = Buffer.alloc(lst.size + 1); const { bytesRead } = await fd.read(buffer, 0, buffer.length, 0);
      C.requireSnapshot(bytesRead === lst.size, C.HARD.snapshot_changed); file.bytes = buffer.subarray(0, bytesRead); file.metadata = metadataNames(filePath, process.platform, await fd.stat({ bigint: true })); return file;
    }
    const manifestName = names.find(n => n.equals(Buffer.from(C.MANIFEST_FILENAME))); C.requireSnapshot(manifestName, C.HARD.file_set_mismatch);
    const mf = await capture(manifestName, C.MAX_MANIFEST_BYTES); const raw = C.parseManifestEnvelope(mf.bytes);
    // Authenticate names and exact snapshot selection before resolving any manifest-listed file.
    phase(C.STATES.MANIFEST_AUTHENTICATED);
    C.requireSnapshot(verify(C.manifestSigningBytes(raw), C.base64(raw.manifest_signature, C.SIGNATURE_BYTES), C.publicKey(packKey)), C.HARD.manifest_signature_invalid);
    phase(C.STATES.EXPECTED_SNAPSHOT);
    C.requireSnapshot(C.manifestDigest(mf.bytes) === expectedDigest, C.HARD.manifest_digest_mismatch);
    phase(C.STATES.FILE_SET_AUTHENTICATED);
    const manifest = C.parseManifest(raw);
    C.cap(mf.bytes.length + manifest.files.reduce((sum, row) => sum + row.size_bytes, 0), C.MAX_PACK_BYTES);
    const expected = [C.MANIFEST_FILENAME, ...manifest.files.map(f => f.filename)].map(n => Buffer.from(n).toString("hex")).sort();
    C.requireSnapshot(JSON.stringify(names.map(n => n.toString("hex")).sort()) === JSON.stringify(expected), names.some(n => C.OS_METADATA.test(n.toString())) ? C.HARD.unlisted_os_metadata : C.HARD.file_set_mismatch);
    // Signed row sizes bound allocation before reading, so false small sizes cannot conceal excessive actual bytes.
    for (const name of names) if (!name.equals(manifestName)) {
      const row = manifest.files.find(file => Buffer.from(file.filename).equals(name))!;
      await capture(name, row.size_bytes);
    }
    phase(C.STATES.FINAL_RECHECK);
    for (const h of held) {
      h.file.after = observation(await h.fd.stat({ bigint: true }));
      C.requireSnapshot(C.canonicalSnapshotJSON(h.file.after) === C.canonicalSnapshotJSON(observation(await lstat(h.path, { bigint: true }))), C.HARD.snapshot_changed);
    }
    const after = observation(await rootFd.stat({ bigint: true }));
    C.requireSnapshot(C.canonicalSnapshotJSON(after) === C.canonicalSnapshotJSON(observation(await lstat(root, { bigint: true }))), C.HARD.snapshot_changed);
    return { files: held.map(h => h.file), rootBefore: before, rootAfter: after, rootMetadata, finalNames: await directoryNames(root) };
  } finally { await Promise.all(held.map(h => h.fd.close())); await rootFd.close(); }
}

export interface OfflineIO { stdout: (text: string) => void | Promise<void>; stderr: (text: string) => void | Promise<void> }
export const offlineIO: OfflineIO = {
  stdout: text => new Promise<void>((resolve, reject) => process.stdout.write(text, error => error ? reject(error) : resolve())),
  stderr: text => new Promise<void>((resolve, reject) => process.stderr.write(text, error => error ? reject(error) : resolve())),
};
// Must match the command grammar in docs/evidence-pack-recipient-v0.md and the companion package README.
export const OFFLINE_FLAGS = ["--pack", "--public-key-file", "--trust-descriptor-file", "--expect-manifest-digest"] as const;
const HELP = "Usage: verify-evidence-pack --pack <directory> --public-key-file <file> --trust-descriptor-file <file> --expect-manifest-digest <sha256:hex> [--json]\nverify-evidence-pack --help\nverify-evidence-pack --version\n";
export function parseOfflineArguments(args: string[]): { flags: Record<string, string>; json: boolean } {
  const flags: Record<string, string> = {}; let json = false;
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    if (flag === "--json" && !json) { json = true; continue; }
    // Every pin has one explicit value, so neither ordering nor an environment variable can replace recipient authority.
    if (!(OFFLINE_FLAGS as readonly string[]).includes(flag) || Object.hasOwn(flags, flag)) throw new Error("usage");
    const value = args[++i]; if (!value || value.startsWith("--")) throw new Error("usage"); flags[flag] = value;
  }
  if (!OFFLINE_FLAGS.every(flag => flags[flag]) || !C.DIGEST.test(flags["--expect-manifest-digest"])) throw new Error("usage");
  return { flags, json };
}
export function parseOfflineKey(bytes: Uint8Array): string {
  try {
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    // One optional final LF admits a text file without normalizing any part of the authenticated key grammar.
    const key = text.endsWith(C.LF) ? text.slice(0, -C.LF.length) : text;
    C.publicKey(key); return key;
  } catch {
    // Key grammar failures describe the supplied pin regardless of the decoder that rejects it.
    throw new C.SnapshotError(C.HARD.pin_invalid);
  }
}
function captureFailure(error: unknown, state: C.ProtocolState): C.VerificationResult {
  return { format: C.RESULT_FORMAT, status: C.STATUS.FAIL, exit_code: C.EXIT_FAIL, accepted: false, snapshot_integrity: C.INTEGRITY.unverified, export_id: null, manifest_digest: null, verifier_source_revision: OFFLINE_REVISION, findings: [{ code: error instanceof C.SnapshotError ? error.code : C.HARD.io_error, state, filename: null }], partial_reasons: [], nested: { audit: null, transparency: null }, not_checked: C.NOT_CHECKED };
}
export async function runOfflineCommand(argv: string[], io: OfflineIO = offlineIO): Promise<number> {
  // Output is part of completion, so a broken stdout cannot leave an acceptance exit behind.
  try {
    if (argv.length === 1 && argv[0] === "--help") { await io.stdout(HELP); return C.EXIT_PASS; }
    if (argv.length === 1 && argv[0] === "--version") { await io.stdout(`verify-evidence-pack ${OFFLINE_VERSION} source_revision=${OFFLINE_REVISION}\n`); return C.EXIT_PASS; }
    let parsed: ReturnType<typeof parseOfflineArguments>;
    try { parsed = parseOfflineArguments(argv); } catch { await io.stderr(C.HUMAN.USAGE_ERROR + C.LF + HELP); return C.EXIT_USAGE; }
    const { flags, json } = parsed; let state: C.ProtocolState = C.STATES.PIN_INPUTS;
    let result: C.VerificationResult;
    try {
      const pins = { packKey: parseOfflineKey(await readPublicFile(flags["--public-key-file"], C.MAX_TRUST_BYTES)), descriptorBytes: await readPublicFile(flags["--trust-descriptor-file"], C.MAX_TRUST_BYTES), expectedManifestDigest: flags["--expect-manifest-digest"] };
      validateSnapshotPins(pins);
      state = C.STATES.MANIFEST_BYTES;
      result = verifySnapshot(await captureOfflineSnapshot(flags["--pack"], pins.packKey, pins.expectedManifestDigest, next => { state = next; }), pins, OFFLINE_REVISION);
    } catch (error) { result = captureFailure(error, state); }
    await io.stdout(json ? JSON.stringify(result) + C.LF : C.HUMAN[result.status] + C.LF + [...result.findings.map(finding => finding.code), ...result.partial_reasons].join(C.LF) + C.LF);
    return result.exit_code;
  } catch { return C.EXIT_FAIL; }
}
