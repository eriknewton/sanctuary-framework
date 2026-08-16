/**
 * Small shared ASCII token grammars.
 *
 * ASCII labels and base64url tokens intentionally share the same alphabet but
 * they are different semantic domains: labels are human-chosen identifiers
 * embedded in tool namespaces and did:web paths; base64url tokens are encoded
 * cryptographic material. Keep the named exports separate so callers do not
 * "dedupe" the regexes into one misleading domain.
 */

export const ASCII_LABEL_RE_SOURCE = "^[A-Za-z0-9_-]+$";
export const BASE64URL_TOKEN_RE_SOURCE = "^[A-Za-z0-9_-]+$";

export const ASCII_LABEL_RE = new RegExp(ASCII_LABEL_RE_SOURCE);
export const BASE64URL_TOKEN_RE = new RegExp(BASE64URL_TOKEN_RE_SOURCE);

export function isAsciiLabel(
  value: unknown,
  options: { minLength?: number; maxLength?: number } = {},
): value is string {
  if (typeof value !== "string") return false;

  const minLength = options.minLength ?? 1;
  const maxLength = options.maxLength ?? Number.MAX_SAFE_INTEGER;
  return value.length >= minLength && value.length <= maxLength && ASCII_LABEL_RE.test(value);
}

export function isBase64urlToken(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && BASE64URL_TOKEN_RE.test(value);
}
