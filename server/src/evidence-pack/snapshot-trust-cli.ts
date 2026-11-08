/** Filesystem capture and public descriptor export; this entry never boots a fortress. */
import { constants, type BigIntStats } from "node:fs";
import { lstat, open, opendir, realpath, writeFile, type FileHandle } from "node:fs/promises";
import { basename, dirname, join, resolve, relative, isAbsolute } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { authenticateSnapshotBytes } from "./snapshot-verify.js";
import { verify } from "../core/identity.js";
import * as C from "./snapshot-contract.js";
const execute = promisify(execFile);
export const PRIVATE_DIRECTORY_MODE = 0o700;
export const PRIVATE_FILE_MODE = 0o600;
const METADATA_OUTPUT_LIMIT = C.MAX_NAME_BYTES * C.MAX_FILES;
const METADATA_TIMEOUT_MS = 10_000;
function observation(stat: BigIntStats): C.CapturedStat {
  return { type: stat.isFile() ? C.FILE_TYPE.file : stat.isDirectory() ? C.FILE_TYPE.directory : "invalid", size: Number(stat.size), nlink: Number(stat.nlink), dev: String(stat.dev), ino: String(stat.ino), mtime: String(stat.mtimeNs), ctime: String(stat.ctimeNs) };
}
async function metadata(path: string): Promise<string[]> {
  // Metadata is excluded from signed evidence, so inability to enumerate it must refuse capture.
  const command = process.platform === "darwin" ? "/usr/bin/xattr" : "python3";
  const args = process.platform === "darwin" ? [path] : ["-c", "import os,sys,json; print(json.dumps(os.listxattr(sys.argv[1], follow_symlinks=False)))", path];
  const { stdout } = await execute(command, args, { maxBuffer: METADATA_OUTPUT_LIMIT, timeout: METADATA_TIMEOUT_MS });
  return process.platform === "darwin" ? stdout.trim().split("\n").filter(Boolean) : JSON.parse(stdout) as string[];
}
export async function canonicalOutput(path: string): Promise<string> { return join(await realpath(dirname(resolve(path))), basename(resolve(path))); }
export function requireOutside(pack: string, path: string): void {
  const rel = relative(pack, path);
  // Pins and receipts must survive independently of the delivered directory and cannot be sourced from it.
  C.requireSnapshot(rel !== "" && (rel === ".." || rel.startsWith("../") || isAbsolute(rel)), C.HARD.unsafe_path);
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
export async function captureSnapshotDirectory(path: string, packKey: string, expectedDigest: string): Promise<C.CapturedSnapshot> {
  const root = await canonicalOutput(path); const held: { fd: FileHandle; file: C.CapturedFile; path: string }[] = [];
  const before = observation(await lstat(root, { bigint: true }));
  C.requireSnapshot(before.type === C.FILE_TYPE.directory, C.HARD.file_type_invalid);
  const rootFd = await open(root, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY);
  try {
    C.requireSnapshot(C.canonicalSnapshotJSON(before) === C.canonicalSnapshotJSON(observation(await rootFd.stat({ bigint: true }))), C.HARD.snapshot_changed);
    const names = await directoryNames(root); C.cap(names.length, C.MAX_FILES);
    const rootMetadata = await metadata(root);
    async function capture(name: Buffer, maximum: number): Promise<C.CapturedFile> {
      const decoded = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(name); C.safeName(decoded);
      const filePath = join(root, decoded); const lst = observation(await lstat(filePath, { bigint: true }));
      C.requireSnapshot(lst.type === C.FILE_TYPE.file && lst.nlink === 1, C.HARD.file_type_invalid); C.cap(lst.size, maximum);
      const fd = await open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      const file: C.CapturedFile = { name, bytes: new Uint8Array(), before: observation(await fd.stat({ bigint: true })), after: lst, metadata: [] };
      held.push({ fd, file, path: filePath });
      C.requireSnapshot(C.canonicalSnapshotJSON(lst) === C.canonicalSnapshotJSON(file.before), C.HARD.snapshot_changed);
      const buffer = Buffer.alloc(lst.size + 1); const { bytesRead } = await fd.read(buffer, 0, buffer.length, 0);
      C.requireSnapshot(bytesRead === lst.size, C.HARD.snapshot_changed); file.bytes = buffer.subarray(0, bytesRead); file.metadata = await metadata(filePath); return file;
    }
    const manifestName = names.find(n => n.equals(Buffer.from(C.MANIFEST_FILENAME))); C.requireSnapshot(manifestName, C.HARD.file_set_mismatch);
    const mf = await capture(manifestName, C.MAX_MANIFEST_BYTES); const raw = C.parseManifestEnvelope(mf.bytes);
    // Authenticate names and exact snapshot selection before resolving any manifest-listed file.
    C.requireSnapshot(verify(C.manifestSigningBytes(raw), C.base64(raw.manifest_signature, C.SIGNATURE_BYTES), C.publicKey(packKey)), C.HARD.manifest_signature_invalid);
    C.requireSnapshot(C.manifestDigest(mf.bytes) === expectedDigest, C.HARD.manifest_digest_mismatch);
    const manifest = C.parseManifest(raw);
    const expected = [C.MANIFEST_FILENAME, ...manifest.files.map(f => f.filename)].map(n => Buffer.from(n).toString("hex")).sort();
    C.requireSnapshot(JSON.stringify(names.map(n => n.toString("hex")).sort()) === JSON.stringify(expected), C.HARD.file_set_mismatch);
    // Signed row sizes bound allocation before reading, so false small sizes cannot conceal excessive actual bytes.
    for (const name of names) if (!name.equals(manifestName)) {
      const row = manifest.files.find(file => Buffer.from(file.filename).equals(name))!;
      await capture(name, row.size_bytes);
    }
    for (const h of held) {
      h.file.after = observation(await h.fd.stat({ bigint: true }));
      C.requireSnapshot(C.canonicalSnapshotJSON(h.file.after) === C.canonicalSnapshotJSON(observation(await lstat(h.path, { bigint: true }))), C.HARD.snapshot_changed);
    }
    const after = observation(await rootFd.stat({ bigint: true }));
    C.requireSnapshot(C.canonicalSnapshotJSON(after) === C.canonicalSnapshotJSON(observation(await lstat(root, { bigint: true }))), C.HARD.snapshot_changed);
    return { files: held.map(h => h.file), rootBefore: before, rootAfter: after, rootMetadata, finalNames: await directoryNames(root) };
  } finally { await Promise.all(held.map(h => h.fd.close())); await rootFd.close(); }
}
export interface CommandIO { stdout: (text: string) => void | Promise<void>; stderr: (text: string) => void | Promise<void> }
export const commandIO: CommandIO = {
  stdout: text => new Promise<void>((resolve, reject) => process.stdout.write(text, error => error ? reject(error) : resolve())),
  stderr: text => new Promise<void>((resolve, reject) => process.stderr.write(text, error => error ? reject(error) : resolve())),
};
export function parseSnapshotFlags(args: string[], flags: readonly string[]): Record<string, string> {
  const result: Record<string, string> = {};
  for (let i = 0; i < args.length; i += 2) {
    const flag = args[i]; const value = args[i + 1];
    if (!flags.includes(flag) || Object.hasOwn(result, flag) || !value || value.startsWith("--")) throw new Error("usage");
    result[flag] = value;
  }
  for (const flag of flags) if (!result[flag]) throw new Error("usage");
  return result;
}
export async function runSnapshotTrustCommand(argv: string[], io: CommandIO = commandIO): Promise<number> {
  const help = "Usage: sanctuary export-evidence-trust --pack <dir> --public-key-file <file> --expect-manifest-digest <sha256:hex> --output <file>\nExporting this descriptor does not authenticate its keys to a recipient.\n";
  if (argv.length === 1 && argv[0] === "--help") { await io.stdout(help); return C.EXIT_PASS; }
  let flags: Record<string, string>;
  try { flags = parseSnapshotFlags(argv, ["--pack", "--public-key-file", "--expect-manifest-digest", "--output"]); C.text(flags["--expect-manifest-digest"], C.DIGEST); }
  catch { await io.stderr(help); return C.EXIT_USAGE; }
  try {
    const pack = await canonicalOutput(flags["--pack"]), output = await canonicalOutput(flags["--output"]);
    const pinPath = await canonicalOutput(flags["--public-key-file"]); requireOutside(pack, output); requireOutside(pack, pinPath); C.requireSnapshot(output !== pinPath, C.HARD.unsafe_path);
    const packKey = new TextDecoder().decode(await readPublicFile(pinPath, C.MAX_TRUST_BYTES)).trim(); C.publicKey(packKey);
    const capture = await captureSnapshotDirectory(pack, packKey, flags["--expect-manifest-digest"]);
    const raw = C.parseManifestEnvelope(capture.files.find(f => Buffer.from(f.name).toString() === C.MANIFEST_FILENAME)!.bytes);
    const candidate = authenticateSnapshotBytes(capture, packKey, flags["--expect-manifest-digest"], raw.source_revision as string);
    await writeFile(output, candidate.candidateDescriptorBytes, { flag: "wx", mode: PRIVATE_FILE_MODE });
    await io.stdout(`TRUST_DESCRIPTOR_SHA256=${C.manifestDigest(candidate.candidateDescriptorBytes)}\n`); return C.EXIT_PASS;
  } catch { await io.stderr("Trust descriptor export failed.\n"); return C.EXIT_FAIL; }
}
