const SAFE_CHARS = /[^A-Za-z0-9_.-]/g;
// Two hex digits encode the legacy byte-sized escape, and radix 16 is the
// numeric base for that on-disk hex contract.
const LEGACY_ESCAPE_HEX_DIGITS = 2;
const HEX_RADIX = 16;

export type FilesystemStorageNameKind = "namespace" | "key";

export const FILESYSTEM_STORAGE_NAME_REMEDIATION =
  "the fortress holds a stored name this version cannot address; export the affected data with the previous version or contact support";

export class FilesystemStorageNameError extends Error {
  readonly code = "FILESYSTEM_STORAGE_NAME_UNADDRESSABLE";

  constructor(readonly kind: FilesystemStorageNameKind) {
    super(`Storage refused: ${FILESYSTEM_STORAGE_NAME_REMEDIATION}.`);
    this.name = "FilesystemStorageNameError";
  }
}

export function isFilesystemStorageNameError(
  error: unknown,
): error is FilesystemStorageNameError {
  return (
    error instanceof FilesystemStorageNameError ||
    (error instanceof Error &&
      "code" in error &&
      (error as { code?: unknown }).code === "FILESYSTEM_STORAGE_NAME_UNADDRESSABLE")
  );
}

export function encodeFilesystemStorageName(name: string): string {
  return name.replace(SAFE_CHARS, (ch) =>
    "!" +
    ch
      .charCodeAt(0)
      .toString(HEX_RADIX)
      .padStart(LEGACY_ESCAPE_HEX_DIGITS, "0")
      .toUpperCase()
  );
}

export function decodeFilesystemStorageName(encoded: string): string {
  return encoded.replace(/!([0-9A-Fa-f]{2})/g, (_match, hex) =>
    String.fromCharCode(parseInt(hex, HEX_RADIX))
  );
}

export function filesystemStorageNameRoundTrips(name: string): boolean {
  return decodeFilesystemStorageName(encodeFilesystemStorageName(name)) === name;
}

export function assertFilesystemStorageNameAddressable(
  name: string,
  kind: FilesystemStorageNameKind,
): void {
  if (!filesystemStorageNameRoundTrips(name)) {
    throw new FilesystemStorageNameError(kind);
  }
}

export function decodeRawFilesystemStorageName(
  rawName: string,
  kind: FilesystemStorageNameKind,
): string {
  const decoded = decodeFilesystemStorageName(rawName);
  // Enumeration must refuse a raw segment it cannot re-address exactly; a
  // partial logical set would let custody operations report complete coverage
  // while leaving a stored entry outside the operation.
  if (encodeFilesystemStorageName(decoded) !== rawName) {
    throw new FilesystemStorageNameError(kind);
  }
  return decoded;
}
