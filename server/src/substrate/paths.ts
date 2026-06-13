/**
 * Plugin substrate — bundle path validation (design §3.1a, §5; RFC §5/§3.1a).
 *
 * Every path in a BundleDescriptor and every reverse-DNS id used to build a path is
 * validated BEFORE it is ever joined onto a filesystem location. A path that escapes
 * the bundle root (`..`), is absolute, has a leading slash, or contains a NUL is a
 * named rejection — never sanitized-and-continued (CLAUDE.md "never silently degrade").
 *
 * This module is pure string validation: it does not touch the filesystem. The launcher
 * (S3) performs the no-follow resolution; the contract surface (S1) fixes the rules and
 * proves them with the hostile-fixture suite.
 */

import { reject } from "./errors.js";

/** Charset for a reverse-DNS plugin/signer id: lowercase, dots, dashes, digits. */
const ID_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;

/**
 * Validate a reverse-DNS id (plugin_id, signer_id) before any path or trust use.
 * Rejects empty, leading/trailing dots, uppercase, underscores, and anything that
 * could be path-meaningful.
 */
export function validateId(id: string, kind: "plugin" | "signer"): void {
  if (typeof id !== "string" || id.length === 0 || id.length > 253) {
    reject("invalid_plugin_id", `${kind} id must be a non-empty reverse-DNS string ≤253 chars`);
  }
  if (!ID_RE.test(id)) {
    reject(
      "invalid_plugin_id",
      `${kind} id "${id}" is not a valid reverse-DNS id (lowercase, dot-separated, no "..", no "/")`,
    );
  }
}

/**
 * Validate a canonical relative POSIX path inside the bundle.
 * Fail-closed on: NUL bytes, absolute paths, leading slash, "." or ".." segments,
 * empty segments (//), backslashes, and Windows drive prefixes.
 */
export function validateBundlePath(p: string): void {
  if (typeof p !== "string" || p.length === 0) {
    reject("bundle_path_traversal", "bundle path must be a non-empty string");
  }
  if (p.includes("\0")) {
    reject("bundle_path_traversal", "bundle path contains a NUL byte");
  }
  if (p.includes("\\")) {
    reject("bundle_path_traversal", `bundle path "${p}" contains a backslash`);
  }
  if (/^[a-zA-Z]:/.test(p)) {
    reject("bundle_absolute_path", `bundle path "${p}" looks like a Windows drive path`);
  }
  if (p.startsWith("/")) {
    reject("bundle_leading_slash", `bundle path "${p}" has a leading slash`);
  }
  if (/^[a-zA-Z]+:\/\//.test(p) || p.startsWith("//")) {
    reject("bundle_absolute_path", `bundle path "${p}" is absolute or a URL`);
  }

  const segments = p.split("/");
  for (const seg of segments) {
    if (seg === "" ) {
      reject("bundle_path_traversal", `bundle path "${p}" has an empty segment ("//")`);
    }
    if (seg === ".") {
      reject("bundle_path_traversal", `bundle path "${p}" has a "." segment`);
    }
    if (seg === "..") {
      reject("bundle_path_traversal", `bundle path "${p}" has a ".." segment (traversal)`);
    }
  }
}
