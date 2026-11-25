/**
 * The complete refusal vocabulary of `sanctuary verify-release`, and the
 * escaping every printed detail goes through.
 *
 * | Reason | Trigger |
 * |---|---|
 * | `runtime-unsupported` | Node is outside the pinned `@sigstore/verify` engine range |
 * | `target-unreadable` | the target, or its `package.json`, cannot be resolved or opened as a regular file |
 * | `target-package-json-invalid` | the target `package.json` is not JSON with string `name` and `version` |
 * | `target-package-mismatch` | the target `package.json` names another package |
 * | `self-version-mismatch` | self mode: the install's version differs from the running verifier's |
 * | `version-mismatch` | `--version` differs from the target's version |
 * | `version-malformed` | the version is not strict semver without build metadata |
 * | `fetch-failed:<resource>` | transport error, non-200 status, stall, bad Content-Length, or a document that is not JSON |
 * | `fetch-oversize:<resource>` | Content-Length or body over the resource's byte cap |
 * | `fetch-redirect-refused:<resource>` | a redirect the resource's policy does not allow |
 * | `deadline-exceeded` | the whole-run deadline passed before evidence was accepted |
 * | `tarball-url-mismatch` | the version document's `dist.tarball` is not the composed registry URL |
 * | `provenance-absent` | no attestation whose SIGNED predicateType is SLSA provenance v1 |
 * | `provenance-ambiguous` | more than one such attestation |
 * | `sigstore-invalid:<code>` | the bundle failed parsing, the local proof-and-SET guard, or the library verifier |
 * | `trusted-root-stale` | the library refused and no Fulcio CA and no log key in the committed root covers the entry's time |
 * | `identity-extension-absent:<name>` | a pinned certificate extension, or the SAN URI, is missing |
 * | `identity-mismatch:<name>` | a pinned certificate value differs, is duplicated or is not a DER UTF8String, or the statement disagrees with the certificate |
 * | `provenance-field-absent:<field>` | a pinned statement field is missing or has the wrong JSON type |
 * | `provenance-pin-mismatch:<field>` | a pinned statement field has another value |
 * | `subject-invalid` | not exactly one subject, or the subject names another package or version |
 * | `subject-digest-mismatch` | the subject sha512 differs from the fetched tarball's |
 * | `packument-integrity-mismatch` | the version document's `dist.integrity` differs from the fetched tarball's sha512 |
 * | `digest-malformed` | a digest is not exactly 128 lowercase hex, or the SRI is not exactly one `sha512-` token of 64 bytes |
 * | `manifest-invalid` | the manifest does not verify under the pinned release key, or does not list exactly the one tarball artifact |
 * | `manifest-version-mismatch` | the signed manifest names another version |
 * | `manifest-digest-mismatch` | the signed artifact SHA-256 differs from the fetched tarball's |
 * | `archive-entry-type:<path>` | an archive entry that is not a regular file or a directory |
 * | `archive-invalid:<reason>` | gzip or tar error, truncation, a path outside `package/`, absolute, with `..`, empty or `.` segments, a duplicate, a file/directory conflict, or a case-fold collision |
 * | `archive-oversize:<cap>` | an archive cap is exceeded |
 * | `installed-object-type:<path>` | a symlink, special file, hardlinked file, or a root `node_modules` that is not a directory |
 * | `installed-name-collision:<path>` | two installed names that differ only by case folding |
 * | `installed-file-missing:<path>` | an archive file or directory absent from the target |
 * | `installed-file-extra:<path>` | a regular file in the target that the archive does not list |
 * | `installed-dir-extra:<path>` | a directory in the target that the archive does not imply |
 * | `installed-file-differs:<path>` | an installed file's bytes differ from the archive's |
 */

export type RefusalReason =
  | "runtime-unsupported"
  | "target-unreadable"
  | "target-package-json-invalid"
  | "target-package-mismatch"
  | "self-version-mismatch"
  | "version-mismatch"
  | "version-malformed"
  | `fetch-failed:${FetchResource}`
  | `fetch-oversize:${FetchResource}`
  | `fetch-redirect-refused:${FetchResource}`
  | "deadline-exceeded"
  | "tarball-url-mismatch"
  | "provenance-absent"
  | "provenance-ambiguous"
  | `sigstore-invalid:${string}`
  | "trusted-root-stale"
  | `identity-extension-absent:${string}`
  | `identity-mismatch:${string}`
  | `provenance-field-absent:${string}`
  | `provenance-pin-mismatch:${string}`
  | "subject-invalid"
  | "subject-digest-mismatch"
  | "packument-integrity-mismatch"
  | "digest-malformed"
  | "manifest-invalid"
  | "manifest-version-mismatch"
  | "manifest-digest-mismatch"
  | `archive-entry-type:${string}`
  | `archive-invalid:${string}`
  | `archive-oversize:${ArchiveCap}`
  | `installed-object-type:${string}`
  | `installed-name-collision:${string}`
  | `installed-file-missing:${string}`
  | `installed-file-extra:${string}`
  | `installed-dir-extra:${string}`
  | `installed-file-differs:${string}`;

export type FetchResource = "version-document" | "attestations" | "tarball" | "manifest";
export type ArchiveCap = "expanded-bytes" | "entry-count" | "file-size" | "path-length";

/** The base names of every reason, for the output contract test. */
export const REFUSAL_REASON_BASES: readonly string[] = [
  "runtime-unsupported", "target-unreadable", "target-package-json-invalid", "target-package-mismatch",
  "self-version-mismatch", "version-mismatch", "version-malformed", "fetch-failed", "fetch-oversize",
  "fetch-redirect-refused", "deadline-exceeded", "tarball-url-mismatch", "provenance-absent",
  "provenance-ambiguous", "sigstore-invalid", "trusted-root-stale", "identity-extension-absent",
  "identity-mismatch", "provenance-field-absent", "provenance-pin-mismatch", "subject-invalid",
  "subject-digest-mismatch", "packument-integrity-mismatch", "digest-malformed", "manifest-invalid",
  "manifest-version-mismatch", "manifest-digest-mismatch", "archive-entry-type", "archive-invalid",
  "archive-oversize", "installed-object-type", "installed-name-collision", "installed-file-missing",
  "installed-file-extra", "installed-dir-extra", "installed-file-differs",
];

/** A step's outcome: typed evidence, or one refusal. */
export type StepOutcome<E> = { ok: true; evidence: E } | { ok: false; reason: RefusalReason };

export function refuse(reason: RefusalReason): { ok: false; reason: RefusalReason } {
  return { ok: false, reason };
}

/** Longest printed detail, in characters after escaping. */
export const MAX_DETAIL_CHARS = 256;
const PRINTABLE_MIN = 0x20;
const PRINTABLE_MAX = 0x7e;
const BACKSLASH = 0x5c;

/**
 * Escape a path or field for printing: printable ASCII stays, a backslash
 * doubles, and every other UTF-8 byte becomes `\xHH`. A filename therefore
 * cannot carry a newline, a control sequence or a look-alike character onto
 * the terminal, so it cannot forge a step line or a verdict line. A result
 * longer than MAX_DETAIL_CHARS is cut on an escape boundary and ends with
 * TRUNCATION_MARK, still within MAX_DETAIL_CHARS.
 */
export function escapeDetail(value: string): string {
  const pieces: string[] = [];
  let length = 0;
  for (const byte of Buffer.from(value, "utf8")) {
    const piece = byte === BACKSLASH ? "\\\\"
      : byte >= PRINTABLE_MIN && byte <= PRINTABLE_MAX ? String.fromCharCode(byte)
        : `\\x${byte.toString(16).padStart(2, "0")}`;
    pieces.push(piece);
    length += piece.length;
  }
  if (length <= MAX_DETAIL_CHARS) return pieces.join("");
  let out = "";
  for (const piece of pieces) {
    if (out.length + piece.length > MAX_DETAIL_CHARS - TRUNCATION_MARK.length) break;
    out += piece;
  }
  return out + TRUNCATION_MARK;
}

const TRUNCATION_MARK = "...";

/** `<base>:<escaped detail>`, the shape every path-bearing reason takes. */
export function withPath<B extends string>(base: B, path: string): `${B}:${string}` {
  return `${base}:${escapeDetail(path)}`;
}
