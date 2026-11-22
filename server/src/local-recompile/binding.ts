/**
 * The verified local binding as the local job needs it: the surface it reads,
 * the narrow source interface the server passes in, and the one shape check
 * both IPC sides apply to a descriptor.
 */
import type { LocalBindingDescription, LocalBindingDescriptor } from "../intelligence/selector.js";
import type { Surface } from "../intelligence/surfaces.js";

export type { LocalBindingDescription, LocalBindingDescriptor, LocalBindingRefusal } from "../intelligence/selector.js";

/** The surface whose binding the summary task generates against. */
export const LOCAL_TASK_SURFACE: Surface = "concierge";

/** Must match `SubstrateSelector.describeVerifiedLocalBinding` in intelligence/selector.ts. */
export interface LocalBindingSource {
  describeVerifiedLocalBinding(surface: Surface, expectedEpoch?: number): LocalBindingDescription;
}

// The runtime tag is namespace/model:tag, three components of at most 64 characters with two separators.
const RUNTIME_TAG_MAX_CHARS = 3 * 64 + 2;
// SHA-256 is 256 bits: 64 lowercase hex digits.
const MANIFEST_DIGEST = /^[0-9a-f]{64}$/;
// An IPv6 literal is at most 45 characters.
const ADDRESS_MAX_CHARS = 45;
// TCP carries an unsigned 16-bit port.
const MAX_TCP_PORT = 2 ** 16 - 1;

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

/** A descriptor as it crosses the IPC channel; null for anything outside the shape. */
export function parseBindingDescriptor(value: unknown): LocalBindingDescriptor | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (!exactKeys(record, ["runtime_tag", "manifest_digest", "endpoint"])) return null;
  const endpoint = record.endpoint;
  if (endpoint === null || typeof endpoint !== "object" || Array.isArray(endpoint)) return null;
  const target = endpoint as Record<string, unknown>;
  if (
    !exactKeys(target, ["address", "port"]) ||
    typeof target.address !== "string" ||
    target.address.length === 0 ||
    target.address.length > ADDRESS_MAX_CHARS ||
    typeof target.port !== "number" ||
    !Number.isInteger(target.port) ||
    target.port < 1 ||
    target.port > MAX_TCP_PORT ||
    typeof record.runtime_tag !== "string" ||
    record.runtime_tag.length === 0 ||
    record.runtime_tag.length > RUNTIME_TAG_MAX_CHARS ||
    typeof record.manifest_digest !== "string" ||
    !MANIFEST_DIGEST.test(record.manifest_digest)
  ) {
    return null;
  }
  return Object.freeze({
    runtime_tag: record.runtime_tag,
    manifest_digest: record.manifest_digest,
    endpoint: Object.freeze({ address: target.address, port: target.port }),
  });
}
