/**
 * The verified local binding as the local job needs it: the surface it reads,
 * the narrow source interface the server passes in, and the worker-side parse
 * of a descriptor under the shared shape rule in descriptor-shape.ts.
 */
import type { LocalBindingDescription, LocalBindingDescriptor } from "../intelligence/selector.js";
import type { Surface } from "../intelligence/surfaces.js";
import { isLocalBindingDescriptorShape } from "./descriptor-shape.js";

export type { LocalBindingDescription, LocalBindingDescriptor, LocalBindingRefusal } from "../intelligence/selector.js";

/** The surface whose binding the summary task generates against. */
export const LOCAL_TASK_SURFACE: Surface = "concierge";

/** Must match `SubstrateSelector.describeVerifiedLocalBinding` in intelligence/selector.ts. */
export interface LocalBindingSource {
  describeVerifiedLocalBinding(surface: Surface, expectedEpoch?: number): LocalBindingDescription;
}

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
  // The same shape rule the server applied when it described the binding (descriptor-shape.ts).
  if (
    !exactKeys(target, ["address", "port"]) ||
    !isLocalBindingDescriptorShape(record.runtime_tag, record.manifest_digest, target.address, target.port)
  ) {
    return null;
  }
  const runtimeTag = record.runtime_tag as string;
  const manifestDigest = record.manifest_digest as string;
  const address = target.address as string;
  const port = target.port as number;
  return Object.freeze({
    runtime_tag: runtimeTag,
    manifest_digest: manifestDigest,
    endpoint: Object.freeze({ address, port }),
  });
}
