// Internal non-barrel boundary shared by build-evidence-pack.mjs and snapshot-artifact-cli.ts.
import { createHash } from "node:crypto";
import { inflateRawSync } from "node:zlib";
import { openSync, fstatSync, readSync, closeSync, constants } from "node:fs";
const KiB = 1024, MiB = KiB * KiB;
export const MAX_ARTIFACT_BYTES = 8 * MiB;
export const MAX_TAR_BYTES = 16 * MiB;
export const MAX_MANIFEST_BYTES = 64 * KiB;
export const MAX_MEMBERS = 8; // Seven release files plus the fixture marker.
const BLOCK = 512, GZIP_HEADER = 10, GZIP_TRAILER = 8;
const MAX_JSON_DEPTH = 16; // The schemas need at most three composite levels.
export const NON_RELEASE_MARKER = "NON_RELEASE";
export const NON_RELEASE_TEXT = "Synthetic archive metadata is not release authentication.\n";
export const ARTIFACT_FORMAT = "SANCTUARY_EVIDENCE_ARTIFACT_V1";
export const CANDIDATE_FORMAT = "SANCTUARY_EVIDENCE_CANDIDATE_V1";
export const BIN = Object.freeze({ "verify-evidence-pack": "dist/verify-evidence-pack.js", "check-evidence-pack-artifact": "dist/check-evidence-pack-artifact.js" });
export const ARTIFACT_FILES = Object.freeze({ tarball: "candidate.tgz", manifest: "artifact-manifest.json", receipt: "candidate.json" });
export const CHECK_FLAGS = Object.freeze(["--tarball", "--manifest", "--expect-tarball-sha256", "--expect-manifest-sha256", "--expect-source-revision", "--expect-mode"]);
// Must match the frozen surface inventory and the installed checker tests.
export const ARTIFACT_HELP = "Usage: check-evidence-pack-artifact --tarball <file> --manifest <file> --expect-tarball-sha256 <64hex> --expect-manifest-sha256 <64hex> --expect-source-revision <40hex> --expect-mode <release|fixture>\n";
export const ARTIFACT_REFUSED = "ARTIFACT_REFUSED: artifact contents could not be verified.\n";
export const ARTIFACT_USAGE = "ARTIFACT_USAGE_ERROR: invalid command arguments.\n";
export const artifactSuccess = mode => mode === "release" ? "ARTIFACT_OK: release-policy contents matched; this does not authenticate the publisher.\n" : "ARTIFACT_OK: fixture-policy contents matched; non-release.\n";
export const digest = bytes => createHash("sha256").update(bytes).digest("hex");
const fail = code => { throw new Error(code); };
const need = (condition, code) => { if (!condition) fail(code); };
const result = fn => { try { return { ok: true, value: fn() }; } catch (error) { return { ok: false, error: error instanceof Error ? error.message : "invalid" }; } };
export function requireValid(parsed) { if (!parsed.ok) fail(parsed.error); return parsed.value; }
const exact = (value, keys) => value !== null && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join() === [...keys].sort().join();
const hash = value => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
const revision = value => typeof value === "string" && /^[0-9a-f]{40}$/.test(value);
const modeValid = mode => mode === "release" || mode === "fixture";
const version = value => typeof value === "string" && value.length <= 64 && /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$/.test(value);
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
/** Return the complete member contract for an explicit content policy, never a trust level. */
export function registry(mode) {
  need(modeValid(mode), "mode");
  return ["LICENSE", "README.md", "THIRD_PARTY_NOTICES.md", "package.json", "dist/provenance.json", ...Object.values(BIN), ...(mode === "fixture" ? ["dist/" + NON_RELEASE_MARKER] : [])].map(path => "package/" + path).sort();
}
export const memberMode = path => Object.values(BIN).some(bin => path === "package/" + bin) ? 0o755 : 0o644;
/** Bounded, no-follow, regular-file read; short reads and growth cannot bypass the byte budget. */
export function readBounded(path, limit) {
  need(Number.isSafeInteger(limit) && limit > 0, "read limit");
  need(constants.O_NOFOLLOW !== undefined && constants.O_NONBLOCK !== undefined, "read flags");
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd); need(stat.isFile() && stat.size <= limit, "read size/type");
    const bytes = Buffer.alloc(Math.min(stat.size + 1, limit + 1)); let length = 0;
    while (length < bytes.length) { const count = readSync(fd, bytes, length, bytes.length - length, null); if (!count) break; length += count; }
    need(length === stat.size, "read changed"); return bytes.subarray(0, length);
  } finally { closeSync(fd); }
}
/** Parse once for every JSON boundary, rejecting duplicate decoded keys before schema validation. */
export function parseJson(bytes) {
  need(bytes.byteLength <= MAX_MANIFEST_BYTES, "json cap");
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); let offset = 0;
  const space = () => { while (/[\t\r\n ]/.test(text[offset] ?? "x")) offset++; };
  const string = () => {
    const start = offset++; let escaped = false;
    while (offset < text.length) { const c = text[offset++]; if (c === '"' && !escaped) return JSON.parse(text.slice(start, offset)); if (c === "\\" && !escaped) escaped = true; else escaped = false; }
    fail("json string");
  };
  const value = depth => {
    need(depth <= MAX_JSON_DEPTH, "json depth"); space(); const c = text[offset];
    if (c === '"') return string();
    if (c === "{" || c === "[") {
      offset++; space(); const object = c === "{", end = object ? "}" : "]", out = object ? Object.create(null) : [], keys = new Set();
      if (text[offset] === end) { offset++; return out; }
      for (;;) {
        space(); let key;
        if (object) { need(text[offset] === '"', "json key"); key = string(); need(!keys.has(key), "duplicate key"); keys.add(key); space(); need(text[offset++] === ":", "json colon"); }
        const item = value(depth + 1); if (object) out[key] = item; else out.push(item);
        space(); const delimiter = text[offset++]; if (delimiter === end) return out; need(delimiter === ",", "json delimiter");
      }
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(offset));
    need(token, "json token"); offset += token[0].length; const parsed = JSON.parse(token[0]);
    need(typeof parsed !== "number" || (Number.isFinite(parsed) && Math.abs(parsed) <= Number.MAX_SAFE_INTEGER), "json number"); return parsed;
  };
  const parsed = value(0); space(); need(offset === text.length, "json trailing"); return parsed;
}
/** A manifest describes member bytes, not release authenticity. The checker supplies independent pins. */
export function parseManifest(bytes) { return result(() => {
  const m = parseJson(bytes);
  need(exact(m, ["format", "mode", "package_name", "package_version", "source_revision", "source_archive_sha256", "tarball_sha256", "members"]), "manifest keys");
  need(m.format === ARTIFACT_FORMAT && modeValid(m.mode) && m.package_name === "@sanctuary-framework/evidence-pack-verifier" && version(m.package_version) && revision(m.source_revision) && hash(m.source_archive_sha256) && hash(m.tarball_sha256), "manifest fields");
  need(Array.isArray(m.members) && m.members.length <= MAX_MEMBERS, "member cap");
  for (const row of m.members) need(exact(row, ["path", "type", "size_bytes", "sha256"]) && typeof row.path === "string" && row.path.length <= BLOCK && row.type === "file" && Number.isSafeInteger(row.size_bytes) && row.size_bytes >= 0 && row.size_bytes <= MAX_TAR_BYTES && hash(row.sha256), "member shape");
  need(same(m.members.map(row => row.path), registry(m.mode)), "manifest registry");
  return m;
}); }
/** Receipts use fixed relative names. No command, install path, or arbitrary artifact path is data authority. */
export function parseCandidate(bytes) { return result(() => {
  const c = parseJson(bytes);
  need(exact(c, ["format", "mode", "source_revision", "tarball", "manifest", "tarball_sha256", "manifest_sha256"]), "candidate keys");
  need(c.format === CANDIDATE_FORMAT && modeValid(c.mode) && revision(c.source_revision) && c.tarball === ARTIFACT_FILES.tarball && c.manifest === ARTIFACT_FILES.manifest && hash(c.tarball_sha256) && hash(c.manifest_sha256), "candidate fields"); return c;
}); }
/** Package semantics are shared by the pre-pack producer and actual archive consumer. */
export function parsePackage(bytes) {
  const p = parseJson(bytes);
  need(exact(p, ["name", "version", "private", "description", "author", "license", "type", "engines", "bin", "files"]) && p.name === "@sanctuary-framework/evidence-pack-verifier" && version(p.version) && p.private === true && p.author === "Erik Newton" && p.license === "Apache-2.0" && p.type === "module" && typeof p.description === "string" && exact(p.engines, ["node"]) && p.engines.node === ">=22.0.0" && exact(p.bin, Object.keys(BIN)) && Object.entries(BIN).every(([name, path]) => p.bin[name] === path) && same(p.files, ["dist", "README.md", "LICENSE", "THIRD_PARTY_NOTICES.md"]), "package semantics");
  return p;
}
// CRC32 is implemented locally to retain the existing Node >=22.0.0 package contract.
const CRC_TABLE = Array.from({ length: 256 }, (_, byte) => { let crc = byte; for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0); return crc >>> 0; });
const crc32 = bytes => { let crc = 0xffffffff; for (const byte of bytes) crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ byte) & 0xff]; return (crc ^ 0xffffffff) >>> 0; };
const zero = bytes => bytes.every(byte => byte === 0);
function field(bytes) { const end = bytes.indexOf(0); need(end < 0 || zero(bytes.subarray(end)), "tar nul"); const text = bytes.subarray(0, end < 0 ? bytes.length : end); need(text.every(byte => byte >= 0x20 && byte <= 0x7e), "tar ascii"); return text.toString("ascii"); }
function octal(bytes) { const text = bytes.toString("ascii"); need(/^[0-7]+(?:\0| )*$/.test(text), "tar octal"); const value = Number.parseInt(text, 8); need(Number.isSafeInteger(value), "tar integer"); return value; }
/** Inspect bounded compressed bytes without extraction; only the fixed regular ustar dialect is admitted. */
export function parseArchive(bytes, mode) { return result(() => {
  need(modeValid(mode), "mode");
  need(bytes.length <= MAX_ARTIFACT_BYTES && bytes.length >= GZIP_HEADER + GZIP_TRAILER, "compressed cap");
  // npm emits a fixed header without optional fields. A second deflate stream must never be ignored.
  need(bytes[0] === 0x1f && bytes[1] === 0x8b && bytes[2] === 8 && bytes[3] === 0, "gzip header");
  const compressed = bytes.subarray(GZIP_HEADER, -GZIP_TRAILER);
  const inflated = inflateRawSync(compressed, { maxOutputLength: MAX_TAR_BYTES, info: true });
  need(inflated.engine.bytesWritten === compressed.length, "gzip trailing");
  const tar = inflated.buffer;
  need(tar.length <= MAX_TAR_BYTES, "expanded cap");
  need(crc32(tar) === bytes.readUInt32LE(bytes.length - GZIP_TRAILER) && tar.length === bytes.readUInt32LE(bytes.length - 4), "gzip trailer");
  need(tar.length % BLOCK === 0, "tar alignment");
  const members = [], seen = new Set(); let offset = 0, ended = false;
  while (offset + BLOCK <= tar.length) {
    const h = tar.subarray(offset, offset + BLOCK); offset += BLOCK;
    if (zero(h)) { need(offset + BLOCK <= tar.length && zero(tar.subarray(offset)), "tar end"); ended = true; break; }
    need(members.length < MAX_MEMBERS, "archive member cap");
    const checksum = octal(h.subarray(148, 156));
    need(checksum === h.reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 0x20 : byte), 0), "tar checksum");
    need(h.subarray(257, 263).equals(Buffer.from("ustar\0")) && h.subarray(263, 265).equals(Buffer.from("00")), "tar dialect");
    need(h[156] === 0x30 || h[156] === 0, "tar type");
    need(zero(h.subarray(157, 257)) && zero(h.subarray(345)), "tar extensions");
    const path = field(h.subarray(0, 100));
    need(path.startsWith("package/") && !path.includes("\\") && path.split("/").every(part => part !== "" && part !== "." && part !== ".."), "tar path");
    need(mode !== "release" || !path.split("/").includes(NON_RELEASE_MARKER), "release marker");
    need(!seen.has(path), "duplicate member"); seen.add(path);
    const fileMode = octal(h.subarray(100, 108)), size = octal(h.subarray(124, 136));
    // npm deliberately omits uid/gid; freeze that zero-filled representation as zero.
    for (const [start, end] of [[108, 116], [116, 124]]) { const owner = h.subarray(start, end); if (!zero(owner)) octal(owner); }
    for (const [start, end] of [[136, 148], [329, 337], [337, 345]]) octal(h.subarray(start, end));
    field(h.subarray(265, 297)); field(h.subarray(297, 329));
    need(fileMode === memberMode(path), "tar mode");
    const padded = Math.ceil(size / BLOCK) * BLOCK;
    need(size <= MAX_TAR_BYTES && offset + padded <= tar.length, "tar payload");
    const payload = tar.subarray(offset, offset + size); need(zero(tar.subarray(offset + size, offset + padded)), "tar padding"); offset += padded;
    members.push({ path, type: "file", size_bytes: size, sha256: digest(payload), bytes: payload });
  }
  need(ended, "tar missing end"); members.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  need(same(members.map(row => row.path), registry(mode)), "archive registry");
  if (mode === "fixture") need(members.find(row => row.path === "package/dist/" + NON_RELEASE_MARKER).bytes.equals(Buffer.from(NON_RELEASE_TEXT)), "fixture marker");
  return { members, expanded_bytes: tar.length };
}); }
export const memberRows = members => members.map(({ path, type, size_bytes, sha256 }) => ({ path, type, size_bytes, sha256 }));
/** Compare all observed member bytes to pre-pack expectations; outer pins are supplied by the relying caller. */
export function checkArtifact(tarball, manifestBytes, pins) { return result(() => {
  need(pins && hash(pins.tarball_sha256) && hash(pins.manifest_sha256) && revision(pins.source_revision) && modeValid(pins.mode), "pins");
  need(digest(tarball) === pins.tarball_sha256 && digest(manifestBytes) === pins.manifest_sha256, "pin mismatch");
  const manifest = requireValid(parseManifest(manifestBytes));
  need(manifest.tarball_sha256 === pins.tarball_sha256 && manifest.source_revision === pins.source_revision && manifest.mode === pins.mode, "manifest pins");
  const archive = requireValid(parseArchive(tarball, pins.mode));
  // Subject: every actual tar payload; source: bounded parsing; verifier: staged/pinned manifest comparison.
  need(same(memberRows(archive.members), manifest.members), "member hashes");
  const get = path => archive.members.find(row => row.path === "package/" + path).bytes;
  const pkg = parsePackage(get("package.json")), p = parseJson(get("dist/provenance.json"));
  // Provenance describes input bytes and internal consistency, never publisher approval or reproducibility.
  need(pkg.version === manifest.package_version && pkg.name === manifest.package_name && exact(p, ["format", "package_version", "source_revision", "source_archive_sha256", "verifier_sha256", "dependency_lock_sha256"]) && p.format === "SANCTUARY_VERIFIER_BUILD_V1" && p.package_version === pkg.version && p.source_revision === manifest.source_revision && p.source_archive_sha256 === manifest.source_archive_sha256 && p.verifier_sha256 === digest(get(BIN["verify-evidence-pack"])) && hash(p.dependency_lock_sha256) && (pins.dependency_lock_sha256 === undefined || p.dependency_lock_sha256 === pins.dependency_lock_sha256), "provenance semantics");
  return { manifest, ...archive };
}); }
