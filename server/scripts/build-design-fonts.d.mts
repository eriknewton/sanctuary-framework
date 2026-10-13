// Type surface for build-design-fonts.mjs so the structure test can import the
// same face table and renderer the generator runs. Must match the exports in
// that file (UNICODE_RANGE, FACES, renderModule); the .mjs carries the matching
// pin naming this file.
export interface ConsoleFontFace {
  readonly family: string;
  readonly file: string;
  readonly license: string;
  readonly weight: string;
  readonly upstream: string;
  readonly ref: string;
  readonly sourcePath: string;
  readonly sourceSha256: string;
  readonly subsetSha256: string;
}

export const UNICODE_RANGE: string;
export const FACES: readonly ConsoleFontFace[];
export function renderModule(): string;
