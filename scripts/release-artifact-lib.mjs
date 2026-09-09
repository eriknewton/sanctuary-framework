import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { gunzipSync } from "node:zlib";

export const RELEASE_MANIFEST_DOMAIN = "sanctuary.release-manifest.v1";
export const RELEASE_VERSION_SHAPE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?$/;
// Both release bounds are anti-decompression-bomb ceilings for the signer and
// the verifier, not a policy about how large the package is allowed to be. Each
// is derived from a MEASURED `npm pack --dry-run --json` of this repository's
// own artifact plus roughly 50% headroom, so a legitimate release fits and an
// adversarial tarball still cannot make either script allocate without limit.
// Re-measure and re-derive both when the package grows; never remove them, and
// never widen the gzip validity check itself to get a large archive through.
//
// Compressed ceiling. Measured at 1.8.6-rc.1: 32,901,969 B packed.
// 64 MiB = 67,108,864 B, which is 2.04x the measured size.
export const MAX_RELEASE_TARBALL_BYTES = 64 * 1024 * 1024;

const PACKAGE_NAME = "@sanctuary-framework/mcp-server";
// Decompressed ceiling. Measured at 1.8.6-rc.1: 136,023,052 B unpacked across
// 81 entries, of which 100,429,174 B (73.8%) are `dist/**/*.map` debug source
// maps. 192 MiB = 201,326,592 B, which is 1.48x the measured size.
//
// The two ceilings are INDEPENDENT ABSOLUTE bounds; neither constrains the
// expansion RATIO between them, and reading the pair as a ratio limit is wrong:
// a small archive that decompresses to just under the output ceiling passes both
// at an expansion of many hundreds to one. The cost of this raise stated
// plainly: moving the output ceiling from 128 MiB to 192 MiB admits 64 MiB more
// decompressed output (a 50% increase), plus the decompression work and the
// transient allocation that output implies, and the verifier does this
// decompression BEFORE it verifies any signature. Bounded, but weaker by exactly
// that amount.
// Failure mode when this is too small, stated as the operator sees it: signing
// or verifying a HEALTHY release refuses with "tarball is not a bounded valid
// gzip archive", which reads like a corrupt or hostile archive rather than a
// ceiling the package outgrew.
const MAX_UNPACKED_BYTES = 192 * 1024 * 1024;

/** Open once and read a bounded regular-file snapshot from that descriptor. */
export function readBoundedRegularFile(path, maxBytes, label) {
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    if (!fstatSync(fd).isFile()) throw new Error(`${label} is not a regular file`);
    const snapshot = Buffer.allocUnsafe(maxBytes + 1);
    let length = 0;
    while (length < snapshot.length) {
      const count = readSync(fd, snapshot, length, snapshot.length - length, null);
      if (count === 0) break;
      length += count;
    }
    if (length > maxBytes) throw new Error(`${label} exceeds its release size limit`);
    return snapshot.subarray(0, length);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith(`${label} `)) throw error;
    throw new Error(`${label} is not a readable regular file`);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

export function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

/** Validate npm's tarball name and the sole package/package.json identity. */
export function validatePackageIdentity(tarball, tarballName, version) {
  const expectedName = `sanctuary-framework-mcp-server-${version}.tgz`;
  if (tarballName !== expectedName) throw new Error(`tarball name must be ${expectedName}`);
  let archive;
  try {
    // Enforcement site for the decompressed ceiling: `maxOutputLength` is what
    // makes a decompression bomb fail here instead of exhausting the signer's
    // memory. The bound must stay an explicit argument; gunzipSync defaults to
    // unbounded output.
    archive = gunzipSync(tarball, { maxOutputLength: MAX_UNPACKED_BYTES });
  } catch {
    throw new Error("tarball is not a bounded valid gzip archive");
  }
  const packageJsons = [];
  // npm's current pack format stores package/package.json as a regular ustar
  // entry. We intentionally do not interpret pax path overrides: if npm ever
  // changes that format, this parser finds no canonical package.json and the
  // release fails closed. The real `npm pack` integration test is the upgrade
  // alarm; extend this parser deliberately before accepting a new format.
  for (let offset = 0; offset + 512 <= archive.length;) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const text = (start, length) => header.subarray(start, start + length).toString("utf8").replace(/\0.*$/s, "");
    const prefix = text(345, 155);
    const name = `${prefix}${prefix ? "/" : ""}${text(0, 100)}`;
    const sizeText = text(124, 12).trim();
    if (!/^[0-7]+$/.test(sizeText)) throw new Error("tar entry has invalid size metadata");
    const size = Number.parseInt(sizeText, 8);
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    if (!Number.isSafeInteger(size) || dataEnd > archive.length) throw new Error("tar entry exceeds archive bounds");
    if (name === "package/package.json") {
      const type = header[156];
      if (type !== 0 && type !== 48) throw new Error("package.json is not a regular tar entry");
      packageJsons.push(archive.subarray(dataStart, dataEnd));
    }
    offset = dataStart + Math.ceil(size / 512) * 512;
  }
  if (packageJsons.length !== 1) throw new Error("tarball must contain exactly one package/package.json");
  let packageJson;
  try {
    packageJson = JSON.parse(packageJsons[0].toString("utf8"));
  } catch {
    throw new Error("package/package.json is invalid JSON");
  }
  if (packageJson.name !== PACKAGE_NAME || packageJson.version !== version) {
    throw new Error(`tarball package identity must be ${PACKAGE_NAME}@${version}`);
  }
}
