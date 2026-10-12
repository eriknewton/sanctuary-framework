import { isAbsolute, join, relative, resolve, sep } from "node:path";
import {
  decodeFilesystemStorageName,
  encodeFilesystemStorageName,
} from "./filesystem-name-codec.js";

// Must match filesystem-name-codec.ts: namespace components and storage keys
// share one on-disk encoder so P13 cannot drift from raw storage enumeration.
export const encodeStoragePathComponent = encodeFilesystemStorageName;
export const decodeStoragePathComponent = decodeFilesystemStorageName;

export class InvalidStorageNamespaceError extends Error {
  readonly code = "INVALID_STORAGE_NAMESPACE";

  constructor(namespace: string) {
    super(
      `storage namespace must resolve to exactly one directory under the storage root: ${JSON.stringify(namespace)}`
    );
    this.name = "InvalidStorageNamespaceError";
  }
}

function isSingleEncodedComponent(component: string): boolean {
  return (
    component !== "" &&
    component !== "." &&
    component !== ".." &&
    !component.includes("/") &&
    !component.includes("\\")
  );
}

export function storageNamespacePathComponent(namespace: string): string {
  // NUL is reserved for private worker control markers; caller namespaces must
  // never collide with out-of-band storage authority.
  if (namespace.includes("\0")) {
    throw new InvalidStorageNamespaceError(namespace);
  }
  const encoded = encodeStoragePathComponent(namespace);
  // Namespace directory names must be re-addressable by this build; otherwise
  // discovery could decode bytes that later resolve to a different directory.
  if (decodeStoragePathComponent(encoded) !== namespace) {
    throw new InvalidStorageNamespaceError(namespace);
  }
  if (!isSingleEncodedComponent(encoded)) {
    throw new InvalidStorageNamespaceError(namespace);
  }
  return encoded;
}

export function assertStorageNamespacePathComponent(namespace: string): void {
  storageNamespacePathComponent(namespace);
}

export function isStorageNamespacePathComponent(namespace: string): boolean {
  try {
    assertStorageNamespacePathComponent(namespace);
    return true;
  } catch {
    return false;
  }
}

export function resolveStorageNamespacePath(
  basePath: string,
  namespace: string
): string {
  const component = storageNamespacePathComponent(namespace);
  const resolvedBase = resolve(basePath);
  const resolved = resolve(join(resolvedBase, component));
  const baseRelative = relative(resolvedBase, resolved);
  // A namespace is a single directory under the storage base; any other shape would let a caller address files outside the namespace tree.
  if (
    baseRelative === "" ||
    baseRelative === ".." ||
    isAbsolute(baseRelative) ||
    baseRelative.includes(sep)
  ) {
    throw new InvalidStorageNamespaceError(namespace);
  }
  return join(basePath, component);
}

export function resolveEncodedStorageNamespacePath(
  basePath: string,
  encodedComponent: string
): string {
  const namespace = decodeStoragePathComponent(encodedComponent);
  if (storageNamespacePathComponent(namespace) !== encodedComponent) {
    throw new InvalidStorageNamespaceError(namespace);
  }
  return resolveStorageNamespacePath(basePath, namespace);
}
