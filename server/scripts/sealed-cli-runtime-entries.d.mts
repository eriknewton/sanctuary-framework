// Type surface for sealed-cli-runtime-entries.mjs so TypeScript tests can import
// the same list the build tooling runs. Must match the exports in that file.
export interface SealedCliRuntimeDistEntry {
  readonly path: string;
  readonly kind: "file" | "dir";
  readonly source: string;
}

export const SEALED_CLI_RUNTIME_DIST_ENTRIES: readonly SealedCliRuntimeDistEntry[];
export const SEALED_CLI_RUNTIME_MANIFEST_FILE_PATHS: readonly string[];
export function missingSealedCliRuntimeEntries(distDir: string): string[];
export function missingSealedCliRuntimeManifestEntries(
  manifestFilePaths: Iterable<string>,
): string[];
