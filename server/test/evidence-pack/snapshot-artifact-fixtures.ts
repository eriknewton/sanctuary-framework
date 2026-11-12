/** Helpers only: archive mutations preserve unrelated outer pins so each witness reaches its intended boundary. */
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, cpSync, symlinkSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { gzipSync, gunzipSync } from "node:zlib";
import { spawnSync } from "node:child_process";
import { digest, ARTIFACT_FILES, MAX_MANIFEST_BYTES, parseManifest, requireValid, memberRows, parseArchive, type ArtifactMode, type Candidate, type ArtifactManifest } from "../../src/evidence-pack/artifact-policy.mjs";
// @ts-expect-error Node build script deliberately has no TypeScript wrapper.
import { prepareFixtureCandidate, candidateForTests, buildCandidate, checkerArgs, installCandidate } from "../../scripts/build-evidence-pack.mjs";
export const ROOT = resolve("..");
const tempParent = mkdtempSync(join(tmpdir(), "artifact-witness-"));
export const scratch = () => mkdtempSync(join(tempParent, "case-"));
export interface Sample { dir: string; tar: Buffer; manifest: Buffer; receipt: Candidate; checker: string; tree: string; archive: string; metadata: string; command: string }
export function sample(dir: string, checker: string, tree: string, archive: string, metadata: string, command: string): Sample { return { dir, tar: readFileSync(join(dir, ARTIFACT_FILES.tarball)), manifest: readFileSync(join(dir, ARTIFACT_FILES.manifest)), receipt: JSON.parse(readFileSync(join(dir, ARTIFACT_FILES.receipt), "utf8")), checker, tree, archive, metadata, command }; }
export async function samples() {
  const c = process.env.EVIDENCE_PACK_TEST_CANDIDATE ? await prepareFixtureCandidate(ROOT) : await candidateForTests();
  const fixture = sample(c.artifactDir, c.checker, c.tree, c.archive, c.metadata, c.command);
  const releaseDir = join(scratch(), "artifact");
  await buildCandidate(buildArgs(fixture, releaseDir, "release"), fixture.tree, fixture.receipt.source_revision);
  const installed = installCandidate(releaseDir);
  const release = sample(releaseDir, installed.checker, c.tree, c.archive, c.metadata, installed.command);
  return { fixture, release };
}
export const buildArgs = (s: Sample, dir: string, mode: ArtifactMode) => ["--source-metadata", s.metadata, "--source-archive", s.archive, "--artifact-dir", dir, "--artifact-mode", mode];
export function buildRoot(s: Sample) {
  const root = scratch(); mkdirSync(join(root, "server"));
  symlinkSync(join(ROOT, "server/node_modules"), join(root, "server/node_modules"), "dir");
  cpSync(join(ROOT, "server/package-lock.json"), join(root, "server/package-lock.json"));
  cpSync(join(s.tree, "packages"), join(root, "packages"), { recursive: true });
  cpSync(join(s.tree, "server/evidence-pack-dist"), join(root, "server/evidence-pack-dist"), { recursive: true });
  return root;
}
export interface Entry { header: Buffer; bytes: Buffer }
const BLOCK = 512;
export function entries(tarball: Buffer): Entry[] {
  const tar = gunzipSync(tarball), out: Entry[] = [];
  for (let offset = 0; offset + BLOCK <= tar.length && tar[offset] !== 0;) {
    const header = Buffer.from(tar.subarray(offset, offset + BLOCK));
    const size = parseInt(header.subarray(124, 136).toString(), 8); offset += BLOCK;
    out.push({ header, bytes: Buffer.from(tar.subarray(offset, offset + size)) }); offset += Math.ceil(size / BLOCK) * BLOCK;
  }
  return out;
}
export const name = (e: Entry) => e.header.subarray(0, 100).toString().split("\0")[0]!;
export function setName(e: Entry, path: string) { e.header.fill(0, 0, 100); e.header.write(path, 0, "ascii"); }
export function checksum(header: Buffer) { header.fill(0x20, 148, 156); const sum = header.reduce((n, b) => n + b, 0); header.write(sum.toString(8).padStart(6, "0") + " \0", 148, "ascii"); }
export function tarBytes(rows: Entry[]) {
  return Buffer.concat([...rows.flatMap(row => {
    const h = Buffer.from(row.header); h.fill(0, 124, 136); h.write(row.bytes.length.toString(8).padStart(10, "0") + " \0", 124, "ascii"); checksum(h);
    return [h, row.bytes, Buffer.alloc((BLOCK - row.bytes.length % BLOCK) % BLOCK)];
  }), Buffer.alloc(BLOCK * 2)]);
}
export const pack = (rows: Entry[]) => gzipSync(tarBytes(rows));
export function changed(s: Sample, mutate: (rows: Entry[]) => void) { const rows = entries(s.tar); mutate(rows); return pack(rows); }
export function coherent(s: Sample, tar: Buffer): Buffer {
  const m = requireValid(parseManifest(s.manifest));
  m.tarball_sha256 = digest(tar);
  m.members = entries(tar).map(row => ({ path: name(row), type: "file" as const, size_bytes: row.bytes.length, sha256: digest(row.bytes) })).sort((a, b) => a.path.localeCompare(b.path, "en"));
  // Bytewise ordering is the runtime schema's ordering, not locale ordering.
  m.members.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  return Buffer.from(JSON.stringify(m));
}
export const pins = (s: Sample, tar = s.tar, manifest = s.manifest) => ({ ...s.receipt, tarball_sha256: digest(tar), manifest_sha256: digest(manifest) });
export function retained(s: Sample, tar: Buffer) { const m = JSON.parse(s.manifest.toString()) as ArtifactManifest; m.tarball_sha256 = digest(tar); return Buffer.from(JSON.stringify(m)); }
export function installed(s: Sample, tar = s.tar, manifest = s.manifest, extra: string[] = []) {
  const dir = scratch(); writeFileSync(join(dir, ARTIFACT_FILES.tarball), tar); writeFileSync(join(dir, ARTIFACT_FILES.manifest), manifest);
  return spawnSync(process.execPath, [s.checker, ...checkerArgs(dir, pins(s, tar, manifest)), ...extra], { encoding: "utf8", timeout: 30_000, maxBuffer: MAX_MANIFEST_BYTES });
}
export function parsedRows(s: Sample) { return memberRows(requireValid(parseArchive(s.tar, s.receipt.mode)).members); }
export function malformed(s: Sample): Buffer[] {
  const base = JSON.parse(s.manifest.toString()) as ArtifactManifest;
  const variants: unknown[] = [null, { ...base, extra: true }, { ...base, members: [null] }, { ...base, members: [{ ...base.members[0], sha256: undefined }] }, { ...base, members: [base.members[0], ...base.members] }, { ...base, members: base.members.map((row, i) => i ? row : { ...row, size_bytes: Number.MAX_SAFE_INTEGER + 1 }) }, { ...base, members: base.members.map((row, i) => i ? row : { ...row, type: 7 }) }, { ...base, mode: false }];
  return [...variants.map(v => Buffer.from(JSON.stringify(v))), Buffer.from(s.manifest.toString().replace('"format":', '"format":"duplicate","format":'))];
}
