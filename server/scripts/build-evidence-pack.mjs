// Failure bound: publication into the checkout is not transactional. Each removal is permanent before the next check runs, and the first output is
// published before work on the second finishes, so a refusal partway through can leave one output holding the new build while the other is partly
// cleared or still holds the old one. No refusal deletes anything: a refused destination is left as found and must not be used, and the operator
// rebuilds into a clean checkout. After any nonzero exit neither output is trusted until a later build exits zero.
// Failure mode: after a refused build an output directory can still look complete from the outside; only the exit status says whether it is trusted.
// Race bound: Post-publication verification is a sequence of observations, not an atomic snapshot. It detects mismatches present when the relevant
// identities, entries and bytes are checked. Concurrent changes after a relevant check, including changes during verification, can remain undetected
// and the build can exit zero. It neither prevents redirected operations nor authenticates subsequent checkout contents.
// Trust bound: the checkout copies are build convenience outputs, not the trust authority; content acceptance uses check-evidence-pack-artifact and the SANCTUARY_EVIDENCE_CANDIDATE_V1 receipt.
import { ARTIFACT_FORMAT, CANDIDATE_FORMAT, ARTIFACT_FILES, BIN, MAX_ARTIFACT_BYTES, MAX_MANIFEST_BYTES, NON_RELEASE_MARKER, NON_RELEASE_TEXT, digest, registry, memberMode, parsePackage, parseCandidate, parseManifest, parseJson, checkArtifact, requireValid, readBounded, artifactSuccess } from "../src/evidence-pack/artifact-policy.mjs";
export { digest, NON_RELEASE_MARKER, NON_RELEASE_TEXT };
import { readFileSync, writeFileSync, existsSync, chmodSync, mkdirSync, mkdtempSync, cpSync, symlinkSync, readdirSync, unlinkSync, lstatSync, realpathSync, opendirSync, openSync, fstatSync, readSync, closeSync, constants } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join, resolve, isAbsolute, basename } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
const TIMEOUT_MS = 120_000;
const PRIVATE_ARCHIVE_MODE = 0o600;
// Must match the source metadata fields in .github/workflows/evidence-pack-candidate.yml and snapshot-provenance.test.ts.
const SOURCE_FORMAT = "SANCTUARY_RELEASE_SOURCE_V1";
// Must match the installed provenance consumer in snapshot-provenance.test.ts.
const BUILD_FORMAT = "SANCTUARY_VERIFIER_BUILD_V1";
// Must match the installed non-release marker consumer in snapshot-provenance.test.ts and the packed file list in snapshot-packed.test.ts.
const SHA = /^[0-9a-f]{40}$/;
const HASH = /^[0-9a-f]{64}$/;
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
export async function buildCandidate(args, root = resolve(dirname(fileURLToPath(import.meta.url)), "../.."), revision = process.env.SANCTUARY_SOURCE_SHA, { outputsChecked, beforeCopy, afterCopy, beforeHash, packedBytes, copiesObserved, artifactWritten } = {}) {
  // INPUTS_VALIDATED: artifact policy is required in the core entry, never defaulted from an option.
  if (args.length !== 8 || args[0] !== "--source-metadata" || args[2] !== "--source-archive" || args[4] !== "--artifact-dir" || args[6] !== "--artifact-mode" || !["release", "fixture"].includes(args[7])) throw new Error("Expected source metadata, source archive, artifact directory and explicit mode");
  const mode = args[7], nonRelease = mode === "fixture";
  const metadata = JSON.parse(readFileSync(args[1], "utf8"));
  const head = existsSync(join(root, ".git")) ? execFileSync("/usr/bin/git", ["-C", root, "rev-parse", "HEAD"], { encoding: "utf8" }).trim() : undefined;
  const archiveBytes = readFileSync(args[3]);
  validateSource(metadata, archiveBytes, revision, head);
  const destination = args[5], component = destination.split("/").at(-1);
  if (!isAbsolute(destination) || resolve(destination) !== destination || !component || component === "." || component === "..") throw new Error("Artifact destination refused");
  // Ancestors may relocate the whole artifact; anchor the parent once and create only a plain final component.
  const parent = realpathSync(dirname(destination)), artifactDir = join(parent, basename(destination));
  if (OUTPUT_DIRECTORIES.some(path => artifactDir === join(realpathSync(root), path) || artifactDir.startsWith(join(realpathSync(root), path) + "/"))) throw new Error("Artifact destination refused");
  mkdirSync(artifactDir, { mode: 0o700 }); // Exclusive creation refuses existing files, directories and links.
  // Hash validation precedes extraction, and only the validated archive supplies compiled source bytes.
  const staged = mkdtempSync(join(tmpdir(), "pack-source-"));
  // Extract the validated bytes from a private copy so the caller cannot swap the archive between hash and use.
  const archivePath = join(mkdtempSync(join(tmpdir(), "pack-archive-")), "source.tar");
  writeFileSync(archivePath, archiveBytes, { flag: "wx", mode: PRIVATE_ARCHIVE_MODE });
  // Only regular files and directories can supply archived source without reaching outside the private staging tree.
  extractSourceArchive(archivePath, staged);
  symlinkSync(join(root, "server/node_modules"), join(staged, "server/node_modules"), "dir");
  const packageRoot = join(staged, "packages/evidence-pack-verifier");
  // STAGED: the package semantics are the same contract the shipped checker consumes.
  const pkg = parsePackage(readBounded(join(packageRoot, "package.json"), MAX_MANIFEST_BYTES));
  // The candidate stays private because publication and attribution require owner-controlled release intent.
  // Must match the definition consumed by tsup.evidence-pack.config.ts and snapshot-offline-cli.ts.
  execFileSync(process.execPath, [join(root, "server/node_modules/tsup/dist/cli-default.js"), "--config", "tsup.evidence-pack.config.ts"], { cwd: join(staged, "server"), stdio: "inherit", timeout: TIMEOUT_MS, env: { ...process.env, SANCTUARY_SOURCE_SHA: revision, SANCTUARY_ARTIFACT_MODE: mode } });
  const bundle = join(packageRoot, "dist/verify-evidence-pack.js");
  // A compiler surprise is a STOP, never an implicit registry extension.
  if (readdirSync(join(packageRoot, "dist")).sort().join() !== Object.values(BIN).map(path => basename(path)).sort().join()) throw new Error("Unexpected verifier artifact");
  for (const bin of Object.values(BIN)) chmodSync(join(packageRoot, bin), 0o755);
  writeFileSync(join(packageRoot, "dist/provenance.json"), JSON.stringify({ format: BUILD_FORMAT, package_version: pkg.version, source_revision: metadata.source_revision, source_archive_sha256: metadata.source_archive_sha256, verifier_sha256: digest(readFileSync(bundle)), dependency_lock_sha256: digest(readFileSync(join(root, "server/package-lock.json"))) }, null, 2) + "\n");
  // The marker lives inside the packed directory so a fixture tarball stays marked non-release after it leaves its build root.
  if (nonRelease) writeFileSync(join(packageRoot, "dist", NON_RELEASE_MARKER), NON_RELEASE_TEXT, { flag: "wx" });
  if (readdirSync(join(packageRoot, "dist")).sort().join() !== registry(mode).filter(path => path.startsWith("package/dist/")).map(path => basename(path)).sort().join()) throw new Error("Unexpected verifier artifact");
  // Expected digests come only from the exact staged registry, before npm runs. No normalization was observed.
  const members = registry(mode).map(path => {
    const file = join(packageRoot, path.slice("package/".length));
    chmodSync(file, memberMode(path));
    const bytes = readBounded(file, MAX_ARTIFACT_BYTES);
    return { path, type: "file", size_bytes: bytes.length, sha256: digest(bytes) };
  });
  // PACKED: npm's report locates a single file; it supplies no accepted content metadata.
  const packDir = mkdtempSync(join(tmpdir(), "pack-compressed-"));
  const report = JSON.parse(execFileSync("npm", ["pack", "--json", "--ignore-scripts", "--offline", "--pack-destination", packDir], { cwd: packageRoot, encoding: "utf8", timeout: TIMEOUT_MS }));
  if (!Array.isArray(report) || report.length !== 1 || typeof report[0].filename !== "string" || basename(report[0].filename) !== report[0].filename) throw new Error("Pack report refused");
  let tarballBytes = readBounded(join(packDir, report[0].filename), MAX_ARTIFACT_BYTES);
  // Fault injection is callable only from tests, never from arguments or environment.
  if (packedBytes) tarballBytes = packedBytes(tarballBytes, { packageRoot, packDir });
  const manifestBytes = Buffer.from(JSON.stringify({ format: ARTIFACT_FORMAT, mode, package_name: pkg.name, package_version: pkg.version, source_revision: revision, source_archive_sha256: metadata.source_archive_sha256, tarball_sha256: digest(tarballBytes), members }, null, 2) + "\n");
  const receipt = requireValid(parseCandidate(Buffer.from(JSON.stringify({ format: CANDIDATE_FORMAT, mode, source_revision: revision, tarball: ARTIFACT_FILES.tarball, manifest: ARTIFACT_FILES.manifest, tarball_sha256: digest(tarballBytes), manifest_sha256: digest(manifestBytes) }))));
  const pins = { ...receipt, dependency_lock_sha256: digest(readFileSync(join(root, "server/package-lock.json"))) };
  // ARTIFACT_CHECKED: package.json is included in the fixed pre-pack hash comparison too.
  requireValid(parseManifest(manifestBytes));
  requireValid(checkArtifact(tarballBytes, manifestBytes, pins));
  writeFileSync(join(artifactDir, receipt.tarball), tarballBytes, { flag: "wx", mode: PRIVATE_ARCHIVE_MODE });
  writeFileSync(join(artifactDir, receipt.manifest), manifestBytes, { flag: "wx", mode: PRIVATE_ARCHIVE_MODE });
  artifactWritten?.(artifactDir);
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
  // COPIES_OBSERVED: these observations neither authenticate later checkout bytes nor authorize repacking.
  copiesObserved?.(outputs.map(output => output.destination));
  const finalTarball = readBounded(join(artifactDir, receipt.tarball), MAX_ARTIFACT_BYTES);
  const finalManifest = readBounded(join(artifactDir, receipt.manifest), MAX_MANIFEST_BYTES);
  requireValid(checkArtifact(finalTarball, finalManifest, pins));
  // The archive-built checker must accept too, even when the checkout's policy differs from the source archive.
  const checked = execFileSync(process.execPath, [join(packageRoot, BIN["check-evidence-pack-artifact"]), ...checkerArgs(artifactDir, receipt)], { encoding: "utf8", timeout: TIMEOUT_MS });
  if (checked !== artifactSuccess(mode)) throw new Error("Shipped checker refused");
  // READY is written last. Refusal never deletes outputs, including a partially completed first copy.
  writeFileSync(join(artifactDir, ARTIFACT_FILES.receipt), JSON.stringify(receipt, null, 2) + "\n", { flag: "wx", mode: PRIVATE_ARCHIVE_MODE });
  return receipt;
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
  const artifactDir = join(root, "artifact");
  await buildCandidate(["--source-metadata", metadata, "--source-archive", archive, "--artifact-dir", artifactDir, "--artifact-mode", "fixture"], tree, revision);
  const checked = checkDescriptor(artifactDir);
  const installed = installCandidate(artifactDir);
  return { root, tree, ...installed, tarball: join(artifactDir, ARTIFACT_FILES.tarball), artifactDir, receipt: checked.receipt, packed: { files: checked.members.map(row => ({ path: row.path.slice("package/".length), size: row.size_bytes, mode: memberMode(row.path) })) }, metadata, archive, non_release: true, fixture: true };
}
/** Fixed-path descriptor consumer used before install and upload; a receipt supplies data, never a command. */
export function checkDescriptor(artifactDir) {
  if (!isAbsolute(artifactDir) || !lstatSync(artifactDir).isDirectory()) throw new Error("Artifact directory refused");
  artifactDir = realpathSync(artifactDir);
  const receipt = requireValid(parseCandidate(readBounded(join(artifactDir, ARTIFACT_FILES.receipt), MAX_MANIFEST_BYTES)));
  const checked = requireValid(checkArtifact(readBounded(join(artifactDir, receipt.tarball), MAX_ARTIFACT_BYTES), readBounded(join(artifactDir, receipt.manifest), MAX_MANIFEST_BYTES), receipt));
  // Uploaded source sidecars describe the same input bytes and revision as the accepted artifact.
  const sourceArchive = join(artifactDir, "source.tar"), sourceMetadata = join(artifactDir, "release-source.json");
  if (lstatSync(sourceArchive, { throwIfNoEntry: false }) && digest(readBounded(sourceArchive, Number.MAX_SAFE_INTEGER)) !== checked.manifest.source_archive_sha256) throw new Error("Source archive refused");
  if (lstatSync(sourceMetadata, { throwIfNoEntry: false })) {
    try {
      const source = parseJson(readBounded(sourceMetadata, MAX_MANIFEST_BYTES));
      const keys = ["format", "source_revision", "source_archive_sha256"];
      if (source === null || typeof source !== "object" || Array.isArray(source) || Object.keys(source).length !== keys.length || !keys.every(key => Object.hasOwn(source, key)) || source.format !== SOURCE_FORMAT || source.source_revision !== checked.manifest.source_revision || source.source_archive_sha256 !== checked.manifest.source_archive_sha256) throw new Error("Source metadata refused");
    } catch { throw new Error("Source metadata refused"); }
  }
  return { receipt, ...checked };
}
export function checkerArgs(artifactDir, receipt) {
  return ["--tarball", join(artifactDir, receipt.tarball), "--manifest", join(artifactDir, receipt.manifest), "--expect-tarball-sha256", receipt.tarball_sha256, "--expect-manifest-sha256", receipt.manifest_sha256, "--expect-source-revision", receipt.source_revision, "--expect-mode", receipt.mode];
}
/** Install only the checked fixed artifact; executable paths are derived from this owned prefix. */
export function installCandidate(artifactDir) {
  const { receipt } = checkDescriptor(artifactDir), prefix = join(artifactDir, "installed");
  execFileSync("npm", ["install", "--prefix", prefix, "--ignore-scripts", "--no-audit", "--no-fund", "--offline", join(artifactDir, receipt.tarball)], { encoding: "utf8", timeout: TIMEOUT_MS });
  return { command: join(prefix, "node_modules/.bin/verify-evidence-pack"), checker: join(prefix, "node_modules/.bin/check-evidence-pack-artifact") };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    if (args.length === 2 && args[0] === "--check-descriptor") checkDescriptor(args[1]);
    else if (args.length === 2 && args[0] === "--install-candidate") {
      installCandidate(args[1]);
      const { receipt } = checkDescriptor(args[1]);
      writeFileSync(join(args[1], "test-candidate.json"), JSON.stringify(receipt), { flag: "wx", mode: PRIVATE_ARCHIVE_MODE });
      if (receipt.mode === "fixture") writeFileSync(join(args[1], "NON_RELEASE_FIXTURE"), NON_RELEASE_TEXT, { flag: "wx", mode: PRIVATE_ARCHIVE_MODE });
    } else await buildCandidate(args);
  }
  catch (error) { process.stderr.write(String(error) + "\n"); process.exitCode = 1; }
}
let fixtureCandidate;
export async function candidateForTests() {
  // Must match the installed descriptor written in .github/workflows/evidence-pack-candidate.yml.
  if (process.env.EVIDENCE_PACK_TEST_CANDIDATE) {
    const descriptor = process.env.EVIDENCE_PACK_TEST_CANDIDATE, artifactDir = dirname(descriptor);
    const receipt = requireValid(parseCandidate(readBounded(descriptor, MAX_MANIFEST_BYTES)));
    const checked = checkDescriptor(artifactDir);
    if (JSON.stringify(receipt) !== JSON.stringify(checked.receipt)) throw new Error("Test receipt mismatch");
    return { root: artifactDir, tree: resolve(dirname(fileURLToPath(import.meta.url)), "../.."), artifactDir, receipt, command: join(artifactDir, "installed/node_modules/.bin/verify-evidence-pack"), checker: join(artifactDir, "installed/node_modules/.bin/check-evidence-pack-artifact"), tarball: join(artifactDir, receipt.tarball), archive: join(artifactDir, "source.tar"), metadata: join(artifactDir, "release-source.json"), packed: { files: checked.members.map(row => ({ path: row.path.slice("package/".length), size: row.size_bytes, mode: memberMode(row.path) })) }, fixture: receipt.mode === "fixture", non_release: receipt.mode === "fixture" };
  }
  fixtureCandidate ??= prepareFixtureCandidate();
  return fixtureCandidate;
}
