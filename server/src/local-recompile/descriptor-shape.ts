/**
 * The one shape rule for a local binding descriptor, applied on both sides of
 * the worker IPC boundary: the server's describeVerifiedLocalBinding
 * (intelligence/selector.ts) refuses a binding outside it, and the worker's
 * parseBindingDescriptor (binding.ts) refuses a message outside it, so the two
 * sides can never disagree about what a valid descriptor is.
 */
import { resolveLoopbackConnectTarget } from "../intelligence/loopback-endpoint.js";

// The runtime tag is namespace/model:tag, three components of at most 64 characters with two separators.
export const RUNTIME_TAG_MAX_CHARS = 3 * 64 + 2;
// SHA-256 is 256 bits: 64 lowercase hex digits.
const MANIFEST_DIGEST = /^[0-9a-f]{64}$/;
// An IPv6 literal is at most 45 characters.
export const ADDRESS_MAX_CHARS = 45;
// TCP carries an unsigned 16-bit port.
const MAX_TCP_PORT = 2 ** 16 - 1;

/**
 * True exactly when the fields form a descriptor a job may generate against: a non-empty bounded tag,
 * a SHA-256 digest in lowercase hex, and a loopback IP literal with a TCP port. A hostname, even
 * `localhost`, is refused: only a literal crosses the boundary, so no side ever resolves a name.
 */
export function isLocalBindingDescriptorShape(runtimeTag: unknown, manifestDigest: unknown, address: unknown, port: unknown): boolean {
  if (typeof runtimeTag !== "string" || runtimeTag.length === 0 || runtimeTag.length > RUNTIME_TAG_MAX_CHARS) return false;
  if (typeof manifestDigest !== "string" || !MANIFEST_DIGEST.test(manifestDigest)) return false;
  if (typeof address !== "string" || address.length === 0 || address.length > ADDRESS_MAX_CHARS) return false;
  if (typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > MAX_TCP_PORT) return false;
  const host = address.includes(":") ? `[${address}]` : address;
  const resolved = resolveLoopbackConnectTarget(`http://${host}:${port}/`);
  return resolved.ok && resolved.target.address === address && resolved.target.port === port;
}
