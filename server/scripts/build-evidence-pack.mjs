// Failure bound: publication into the checkout is not transactional. Each removal is permanent before the next check runs, and the first output is
// published before work on the second finishes, so a refusal partway through can leave one output holding the new build while the other is partly
// cleared or still holds the old one. No refusal deletes anything: a refused destination is left as found and must not be used, and the operator
// rebuilds into a clean checkout. After any nonzero exit neither output is trusted until a later build exits zero.
// Failure mode: after a refused build an output directory can still look complete from the outside; only the exit status says whether it is trusted.
// Race bound: Post-publication verification is a sequence of observations, not an atomic snapshot. It detects mismatches present when the relevant
// identities, entries and bytes are checked. Concurrent changes after a relevant check, including changes during verification, can remain undetected
// and the build can exit zero. It neither prevents redirected operations nor authenticates subsequent checkout contents.
// Trust bound: the checkout copies are build convenience outputs, not the trust authority; release acceptance rests on the packed artifact and its verifier.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, chmodSync, mkdirSync, mkdtempSync, cpSync, symlinkSync, readdirSync, unlinkSync, lstatSync, realpathSync, opendirSync, openSync, fstatSync, readSync, closeSync, constants } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
const TIMEOUT_MS = 120_000;
const PRIVATE_ARCHIVE_MODE = 0o600;
// Must match the source metadata fields in .github/workflows/evidence-pack-candidate.yml and snapshot-provenance.test.ts.
const SOURCE_FORMAT = "SANCTUARY_RELEASE_SOURCE_V1";
// Must match the installed provenance consumer in snapshot-provenance.test.ts.
const BUILD_FORMAT = "SANCTUARY_VERIFIER_BUILD_V1";
// Must match the installed non-release marker consumer in snapshot-provenance.test.ts and the packed file list in snapshot-packed.test.ts.
export const NON_RELEASE_MARKER = "NON_RELEASE";
export const NON_RELEASE_TEXT = "Synthetic archive metadata is not release authentication.\n";
const SHA = /^[0-9a-f]{40}$/;
const HASH = /^[0-9a-f]{64}$/;
export const digest = bytes => createHash("sha256").update(bytes).digest("hex");
export function validateSource(metadata, archive, revision, head) {
  // Exact metadata and full revisions prevent a basename or short hash from becoming build provenance.
  if (Object.keys(metadata).sort().join() !== "format,source_archive_sha256,source_revision" || metadata.format !== SOURCE_FORMAT || !SHA.test(metadata.source_revision) || !HASH.test(metadata.source_archive_sha256) || revision !== metadata.source_revision || (head !== undefined && head !== revision) || digest(archive) !== metadata.source_archive_sha256) throw new Error("Source provenance refused");
  return metadata;
}
export function extractSourceArchive(archive, staged) {
  // Validation and extraction share one archive handle so only checked members reach the empty staging tree.
  execFileSync("/usr/bin/python3", ["-I", "-S", "-c", `import pathlib,tarfile,sys
with tarfile.open(sys.argv[1]) as archive:
    members = archive.getmembers()
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if not (member.isfile() or member.isdir()) or path.is_absolute() or '..' in path.parts:
            raise ValueError('Unsafe source archive')
    for member in members:
        target = pathlib.Path(sys.argv[2]) / member.name
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as output, archive.extractfile(member) as source:
                import shutil
                shutil.copyfileobj(source, output)
`, archive, staged], { timeout: TIMEOUT_MS });
}
export async function buildCandidate(args, root = resolve(dirname(fileURLToPath(import.meta.url)), "../.."), revision = process.env.SANCTUARY_SOURCE_SHA, { nonRelease = false, outputsChecked, beforeCopy, afterCopy, beforeHash } = {}) {
  if (args.length !== 4 || args[0] !== "--source-metadata" || args[2] !== "--source-archive") throw new Error("Expected source metadata and source archive");
  const metadata = JSON.parse(readFileSync(args[1], "utf8"));
  const head = existsSync(join(root, ".git")) ? execFileSync("/usr/bin/git", ["-C", root, "rev-parse", "HEAD"], { encoding: "utf8" }).trim() : undefined;
  const archiveBytes = readFileSync(args[3]);
  validateSource(metadata, archiveBytes, revision, head);
  // Hash validation precedes extraction, and only the validated archive supplies compiled source bytes.
  const staged = mkdtempSync(join(tmpdir(), "pack-source-"));
  // Extract the validated bytes from a private copy so the caller cannot swap the archive between hash and use.
  const archivePath = join(mkdtempSync(join(tmpdir(), "pack-archive-")), "source.tar");
  writeFileSync(archivePath, archiveBytes, { flag: "wx", mode: PRIVATE_ARCHIVE_MODE });
  // Only regular files and directories can supply archived source without reaching outside the private staging tree.
  extractSourceArchive(archivePath, staged);
  symlinkSync(join(root, "server/node_modules"), join(staged, "server/node_modules"), "dir");
  const packageRoot = join(staged, "packages/evidence-pack-verifier");
  const pkg = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8"));
  // The candidate stays private because publication and attribution require owner-controlled release intent.
  if (pkg.private !== true || pkg.author !== "Erik Newton" || pkg.license !== "Apache-2.0" || pkg.scripts || pkg.dependencies || pkg.type !== "module" || pkg.engines.node !== ">=22.0.0" || JSON.stringify(pkg.files) !== JSON.stringify(["dist", "README.md", "LICENSE", "THIRD_PARTY_NOTICES.md"]) || JSON.stringify(pkg.bin) !== JSON.stringify({ "verify-evidence-pack": "dist/verify-evidence-pack.js" })) throw new Error("Candidate package contract refused");
  // Must match the definition consumed by tsup.evidence-pack.config.ts and snapshot-offline-cli.ts.
  execFileSync(process.execPath, [join(root, "server/node_modules/tsup/dist/cli-default.js"), "--config", "tsup.evidence-pack.config.ts"], { cwd: join(staged, "server"), stdio: "inherit", timeout: TIMEOUT_MS, env: { ...process.env, SANCTUARY_SOURCE_SHA: revision } });
  const bundle = join(packageRoot, "dist/verify-evidence-pack.js");
  chmodSync(bundle, 0o755);
  writeFileSync(join(packageRoot, "dist/provenance.json"), JSON.stringify({ format: BUILD_FORMAT, package_version: pkg.version, source_revision: metadata.source_revision, source_archive_sha256: metadata.source_archive_sha256, verifier_sha256: digest(readFileSync(bundle)), dependency_lock_sha256: digest(readFileSync(join(root, "server/package-lock.json"))) }, null, 2) + "\n");
  // The marker lives inside the packed directory so a fixture tarball stays marked non-release after it leaves its build root.
  if (nonRelease) writeFileSync(join(packageRoot, "dist", NON_RELEASE_MARKER), NON_RELEASE_TEXT, { flag: "wx" });
  if (readdirSync(join(packageRoot, "dist")).sort().join() !== ["provenance.json", "verify-evidence-pack.js", ...(nonRelease ? [NON_RELEASE_MARKER] : [])].sort().join()) throw new Error("Unexpected verifier artifact");
  // The repository root is resolved once, so every output component below it is judged against one real anchor.
  const base = realpathSync(root);
  const outputs = OUTPUT_DIRECTORIES.map(relative => checkOutput(base, relative));
  // Test-only seam: it runs after both outputs pass validation and before any removal, so a hardening test can change an output in that window.
  outputsChecked?.(outputs.map(output => output.destination));
  // Both flat output directories are cleared in place so stale files cannot travel into rebuilt artifacts across volumes.
  for (const output of outputs) {
    for (const entry of output.entries) { recheckOutputs(outputs); unlinkSync(join(output.destination, entry.name)); }
    recheckOutputs(outputs);
    // Test-only seam: it runs after the final recheck and before the copy, a window only post-publication verification can observe.
    beforeCopy?.(output.destination);
    cpSync(join(staged, output.relative), output.destination, { recursive: true });
    if (!output.present) { output.held.push(directoryIdentity(output.destination) ?? refuseOutputPath()); output.present = true; }
    // Test-only seam: it runs after this output's copy and before verification, so a hardening test can change a published output.
    afterCopy?.(output.destination);
  }
  verifyPublished(outputs, staged, nonRelease, beforeHash);
}
// Must match the output-directory witnesses in snapshot-provenance.test.ts.
const OUTPUT_DIRECTORIES = ["packages/evidence-pack-verifier/dist", "server/evidence-pack-dist"];
const refuseOutputPath = () => { throw new Error("Unexpected output path"); };
function directoryIdentity(path) {
  const stat = lstatSync(path, { bigint: true, throwIfNoEntry: false });
  if (!stat) return undefined;
  // A link or non-directory anywhere on an output chain would redirect in-place clearing or the copy to another tree.
  if (stat.isSymbolicLink() || !stat.isDirectory()) refuseOutputPath();
  return { path, dev: stat.dev, ino: stat.ino };
}
// Must match the output-chain and identity witnesses in snapshot-provenance.test.ts.
function checkOutput(base, relative) {
  const parts = relative.split("/"), held = [directoryIdentity(base) ?? refuseOutputPath()];
  // Every component from the repository root down is examined, and only the final one may be absent, so no linked ancestor can carry the clear or the copy elsewhere.
  for (let depth = 1; depth <= parts.length; depth++) {
    const component = directoryIdentity(join(base, ...parts.slice(0, depth)));
    if (component) held.push(component); else if (depth < parts.length) refuseOutputPath(); else break;
  }
  const deepest = held.at(-1).path, destination = join(base, relative), present = deepest === destination;
  // The resolved deepest existing component must be its own lexical path, so a link the component walk could miss still refuses.
  if (realpathSync(deepest) !== deepest) refuseOutputPath();
  const entries = present ? readdirSync(destination, { withFileTypes: true }) : [];
  // Unexpected directories refuse cleanup because build outputs are flat and recursive deletion is not authorized.
  if (entries.some(entry => entry.isDirectory())) throw new Error("Unexpected output directory");
  return { relative, destination, held, present, entries };
}
function identityChange(outputs) {
  for (const { held, present, destination } of outputs) {
    // Each held directory must still be the same real directory before every removal and copy; a replacement in the window after this check can only be observed later, never prevented, since Node offers no descriptor-relative unlink or copy.
    for (const { path, dev, ino } of held) { const stat = lstatSync(path, { bigint: true, throwIfNoEntry: false }); if (!stat || stat.isSymbolicLink() || !stat.isDirectory() || stat.dev !== dev || stat.ino !== ino) return "output identity changed"; }
    // An output that was absent at the check must stay absent until its own copy creates it.
    if (!present && lstatSync(destination, { throwIfNoEntry: false })) return "output identity changed";
  }
  return undefined;
}
function recheckOutputs(outputs) { if (identityChange(outputs) !== undefined) throw new Error("Output path changed"); }
// Must match the post-publication witnesses in snapshot-provenance.test.ts.
function verifyPublished(outputs, staged, nonRelease, beforeHash) {
  const expected = outputs.map(output => inventory(join(staged, output.relative), Number.POSITIVE_INFINITY));
  let reason;
  // Any error while reading a published output is itself a refusal, so a vanished or unreadable entry can never count as verified.
  try {
    reason = identityChange(outputs);
    const first = [];
    for (const [index, output] of outputs.entries()) {
      if (reason !== undefined) break;
      const compared = publishedMismatch(output, join(staged, output.relative), expected[index], nonRelease, beforeHash);
      reason = compared.reason; first.push(compared.found);
    }
    // A change made while the comparison ran shows up in this second pass as a moved directory or an inventory unlike the one just compared.
    reason ??= identityChange(outputs) ?? outputs.map((output, index) => changedSince(output, first[index], nonRelease)).find(found => found !== undefined);
  } catch { reason = "published output unreadable"; }
  if (reason === undefined) return;
  // Nothing is deleted on refusal: the build cannot prove it owns any entry it finds now, so every file stays for the operator to inspect.
  throw new Error(`Published output refused: ${reason}; the destination is not trusted and must be rebuilt`);
}
// Entries are classified by lstat and never followed, and the walk stops one entry past the limit, so a planted link, special file or flood costs bounded work.
function inventory(directory, limit, prefix = "", rows = []) {
  const handle = opendirSync(directory);
  try {
    for (let entry = handle.readSync(); entry !== null && rows.length < limit; entry = handle.readSync()) {
      const name = prefix + entry.name, stat = lstatSync(join(directory, entry.name), { throwIfNoEntry: false });
      const type = !stat ? "vanished" : stat.isSymbolicLink() ? "link" : stat.isDirectory() ? "directory" : stat.isFile() ? "file" : "special";
      rows.push({ name, type, size: stat?.size });
      if (type === "directory") inventory(join(directory, entry.name), limit, name + "/", rows);
    }
  } finally { handle.closeSync(); }
  return rows;
}
const carriesMarker = rows => rows.some(row => row.name.split("/").at(-1) === NON_RELEASE_MARKER);
const inventoryKey = rows => JSON.stringify(rows.map(({ name, type, size }) => [name, type, size]).sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
function publishedMismatch(output, stagedOutput, expected, nonRelease, beforeHash) {
  // The limit is one entry more than the staged package holds, which is the least work that still proves an extra entry exists.
  const found = inventory(output.destination, expected.length + 1), wanted = new Map(expected.map(row => [row.name, row]));
  const refuse = reason => ({ reason: `${reason} in ${output.relative}`, found });
  // A release build refuses the fixture marker at any depth, so a marker planted in the checkout can never ride a release output into packaging.
  if (!nonRelease && carriesMarker(found)) return refuse("non-release marker");
  // The published tree must hold exactly the staged names, so an entry merged in by the copy or planted afterwards refuses.
  if (found.some(row => !wanted.has(row.name))) return refuse("unexpected entry");
  if (found.length !== expected.length) return refuse("missing entry");
  if (found.some(row => row.type !== wanted.get(row.name).type)) return refuse("entry type changed");
  for (const row of expected) {
    if (row.type !== "file") continue;
    // Test-only seam: it runs before each published file is opened, so a hardening test can change an output while verification is under way.
    beforeHash?.(join(output.destination, row.name));
    if (!sameBytes(join(output.destination, row.name), join(stagedOutput, row.name), row.size)) return refuse("content changed");
  }
  return { reason: undefined, found };
}
// Must match the mid-verification witnesses in snapshot-provenance.test.ts.
function changedSince(output, first, nonRelease) {
  // The same one-past limit applies, so the second pass costs no more than the first.
  const again = inventory(output.destination, first.length + 1);
  if (!nonRelease && carriesMarker(again)) return `non-release marker in ${output.relative}`;
  return inventoryKey(again) === inventoryKey(first) ? undefined : `output changed during verification in ${output.relative}`;
}
// The published file is opened without following a link and without blocking on a fifo, and at most one byte past the staged size is read, so a swapped entry can neither redirect nor stall nor inflate the comparison.
function sameBytes(published, staged, size) {
  if (constants.O_NOFOLLOW === undefined || constants.O_NONBLOCK === undefined) return false;
  const descriptor = openSync(published, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    if (!fstatSync(descriptor).isFile()) return false;
    // One byte past the staged size is enough to detect a file that grew after it was listed.
    const buffer = Buffer.alloc(size + 1);
    let length = 0, read;
    do { read = readSync(descriptor, buffer, length, buffer.length - length, null); length += read; } while (read > 0 && length < buffer.length);
    return length === size && digest(buffer.subarray(0, size)) === digest(readFileSync(staged));
  } finally { closeSync(descriptor); }
}
// Test archives live outside git and are explicitly marked non-release; no fixture metadata authenticates a release.
export async function prepareFixtureCandidate(sourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..")) {
  const root = mkdtempSync(join(tmpdir(), "pack-artifact-"));
  const tree = join(root, "tree"); mkdirSync(join(tree, "server"), { recursive: true });
  for (const name of ["src", "scripts", "test/setup"]) cpSync(join(sourceRoot, "server", name), join(tree, "server", name), { recursive: true });
  for (const name of ["tsconfig.json", "tsup.evidence-pack.config.ts", "package.json", "package-lock.json"]) cpSync(join(sourceRoot, "server", name), join(tree, "server", name));
  cpSync(join(sourceRoot, "packages/evidence-pack-verifier"), join(tree, "packages/evidence-pack-verifier"), { recursive: true, filter: p => !p.split("/").includes("dist") });
  const archive = join(root, "fixture-source.tar");
  execFileSync("tar", ["-cf", archive, "-C", tree, "."], { timeout: TIMEOUT_MS });
  const metadata = join(root, "release-source.json");
  const revision = execFileSync("/usr/bin/git", ["-C", sourceRoot, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  writeFileSync(metadata, JSON.stringify({ format: SOURCE_FORMAT, source_revision: revision, source_archive_sha256: digest(readFileSync(archive)) }));
  writeFileSync(join(root, "NON_RELEASE_FIXTURE"), NON_RELEASE_TEXT);
  symlinkSync(join(sourceRoot, "server/node_modules"), join(tree, "server/node_modules"), "dir");
  await buildCandidate(["--source-metadata", metadata, "--source-archive", archive], tree, revision, { nonRelease: true });
  const packed = JSON.parse(execFileSync("npm", ["pack", "--json", "--ignore-scripts", "--offline", "--pack-destination", root], { cwd: join(tree, "packages/evidence-pack-verifier"), encoding: "utf8", timeout: TIMEOUT_MS }))[0];
  const tarball = join(root, packed.filename), prefix = join(root, "installed");
  execFileSync("npm", ["install", "--prefix", prefix, "--ignore-scripts", "--no-audit", "--no-fund", "--offline", tarball], { encoding: "utf8", timeout: TIMEOUT_MS });
  const command = join(prefix, "node_modules/.bin/verify-evidence-pack");
  writeFileSync(join(root, "packed-consumer.json"), JSON.stringify({ non_release: true, tarball_sha256: digest(readFileSync(tarball)), integrity: packed.integrity, files: packed.files, command }, null, 2));
  return { root, tree, command, tarball, packed, metadata, archive, non_release: true, fixture: true };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { await buildCandidate(process.argv.slice(2)); }
  catch (error) { process.stderr.write(String(error) + "\n"); process.exitCode = 1; }
}
let fixtureCandidate;
export async function candidateForTests() {
  // Must match the installed descriptor written in .github/workflows/evidence-pack-candidate.yml.
  if (process.env.EVIDENCE_PACK_TEST_CANDIDATE) return JSON.parse(readFileSync(process.env.EVIDENCE_PACK_TEST_CANDIDATE, "utf8"));
  fixtureCandidate ??= prepareFixtureCandidate();
  return fixtureCandidate;
}
