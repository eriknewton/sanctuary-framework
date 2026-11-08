import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, chmodSync, mkdirSync, mkdtempSync, cpSync, symlinkSync, readdirSync, renameSync } from "node:fs";
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
export async function buildCandidate(args, root = resolve(dirname(fileURLToPath(import.meta.url)), "../.."), revision = process.env.SANCTUARY_SOURCE_SHA) {
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
  if (readdirSync(join(packageRoot, "dist")).sort().join() !== "provenance.json,verify-evidence-pack.js") throw new Error("Unexpected verifier artifact");
  // A fresh destination prevents earlier local artifacts from entering the candidate file set.
  const destination = join(root, "packages/evidence-pack-verifier/dist");
  if (existsSync(destination)) renameSync(destination, join(mkdtempSync(join(tmpdir(), "pack-previous-")), "dist"));
  cpSync(join(packageRoot, "dist"), join(root, "packages/evidence-pack-verifier/dist"), { recursive: true });
  cpSync(join(staged, "server/evidence-pack-dist"), join(root, "server/evidence-pack-dist"), { recursive: true });
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
  writeFileSync(join(root, "NON_RELEASE_FIXTURE"), "Synthetic archive metadata is not release authentication.\n");
  symlinkSync(join(sourceRoot, "server/node_modules"), join(tree, "server/node_modules"), "dir");
  await buildCandidate(["--source-metadata", metadata, "--source-archive", archive], tree, revision);
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
