const SAFE_CHARS = /[^A-Za-z0-9_.-]/g;
// Two hex digits encode the legacy byte-sized escape, and radix 16 is the
// numeric base for that on-disk hex contract.
const LEGACY_ESCAPE_HEX_DIGITS = 2;
const HEX_RADIX = 16;

export type FilesystemStorageNameKind = "namespace" | "key";

export const FILESYSTEM_STORAGE_NAME_REMEDIATION =
  "storage name this version cannot address";

export class FilesystemStorageNameError extends Error {
  readonly code = "FILESYSTEM_STORAGE_NAME_UNADDRESSABLE";
  readonly rawName?: string;
  readonly rawNamespace?: string;
  readonly requestedName?: string;

  constructor(
    readonly kind: FilesystemStorageNameKind,
    options: { rawName?: string; rawNamespace?: string; requestedName?: string } = {},
  ) {
    const detail = options.rawName === undefined
      ? `requested ${kind} ${FILESYSTEM_STORAGE_NAME_REMEDIATION}`
      : `stored ${kind} raw entry ${JSON.stringify(options.rawName)}${
          options.rawNamespace === undefined
            ? ""
            : ` in namespace directory ${JSON.stringify(options.rawNamespace)}`
        } ${FILESYSTEM_STORAGE_NAME_REMEDIATION}`;
    const recovery = options.rawName === undefined
      ? "choose a supported storage name"
      : "if the original logical name is known, use an older build to read the entry, write it under a supported storage name, then delete the original with the older build; if it is not known, move the raw entry out of the storage directory, accepting that this entry will be unavailable";
    super(`Storage refused: ${detail}; ${recovery}.`);
    this.name = "FilesystemStorageNameError";
    this.rawName = options.rawName;
    this.rawNamespace = options.rawNamespace;
    this.requestedName = options.requestedName;
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
  // namespace-component.ts re-exports this implementation; changing this
  // changes both namespace directories and key file names.
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
    throw new FilesystemStorageNameError(kind, { requestedName: name });
  }
}

export function decodeRawFilesystemStorageName(
  rawName: string,
  kind: FilesystemStorageNameKind,
): string {
  const decoded = decodeFilesystemStorageName(rawName);
  // Enumeration must refuse a raw segment it cannot re-address to the same
  // bytes; names outside the supported range are refused on write and may not
  // round-trip when read from older storage.
  if (encodeFilesystemStorageName(decoded) !== rawName) {
    throw new FilesystemStorageNameError(kind, { rawName });
  }
  return decoded;
}
