// Type surface for sealed-cli-runtime-entries.mjs so TypeScript (install.ts and
// the structure tests) can import the same list the build tooling runs. Must
// match the exports in that file.
export interface SealedCliRuntimeDistEntry {
  readonly path: string;
  readonly kind: "file" | "dir";
  readonly source: string;
  /** Present on `kind: "dir"` entries: a file inside the directory that must exist. */
  readonly sentinel?: string;
  /** PR whose merge brings the producer script; the entry is pending until then. */
  readonly landsWith?: string;
}

export const SEALED_CLI_RUNTIME_DIST_ENTRIES: readonly SealedCliRuntimeDistEntry[];
export const SEALED_CLI_RUNTIME_DIST_DENY: readonly string[];
export function sealedCliRuntimeDenyMatch(distRelativePath: string): string | null;
export function isPendingSealedCliRuntimeEntry(entry: SealedCliRuntimeDistEntry): boolean;
export function enforcedSealedCliRuntimeDistEntries(): SealedCliRuntimeDistEntry[];
export function installerRequiredSealedCliRuntimeEntries(): SealedCliRuntimeDistEntry[];
export function sealedCliRuntimeManifestPath(entry: SealedCliRuntimeDistEntry): string;
export function missingSealedCliRuntimeEntries(distDir: string): string[];
export function missingSealedCliRuntimeManifestEntries(
  manifestFilePaths: Iterable<string>,
): string[];
export function deniedSealedCliRuntimeManifestPaths(
  manifestFilePaths: Iterable<string>,
): Array<[string, string]>;
