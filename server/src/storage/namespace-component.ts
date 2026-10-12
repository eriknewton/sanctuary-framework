import { isAbsolute, join, relative, resolve, sep } from "node:path";

const SAFE_PATH_COMPONENT_CHARS = /[^A-Za-z0-9_.-]/g;
const HEX_RADIX = 16;
const HEX_BYTE_WIDTH = 2;
const FIRST_CODE_UNIT_INDEX = 0;

export class InvalidStorageNamespaceError extends Error {
  readonly code = "INVALID_STORAGE_NAMESPACE";

  constructor(namespace: string) {
    super(
      `storage namespace must resolve to exactly one directory under the storage root: ${JSON.stringify(namespace)}`
    );
    this.name = "InvalidStorageNamespaceError";
  }
}

export function encodeStoragePathComponent(name: string): string {
  return name.replace(SAFE_PATH_COMPONENT_CHARS, (ch) =>
    "!" +
    ch
      .charCodeAt(FIRST_CODE_UNIT_INDEX)
      .toString(HEX_RADIX)
      .padStart(HEX_BYTE_WIDTH, "0")
      .toUpperCase()
  );
}

export function decodeStoragePathComponent(encoded: string): string {
  return encoded.replace(/!([0-9A-Fa-f]{2})/g, (_match, hex) =>
    String.fromCharCode(parseInt(hex, HEX_RADIX))
  );
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
  const encoded = encodeStoragePathComponent(namespace);
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
