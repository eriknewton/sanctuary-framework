import { createHash } from 'node:crypto';

export const digest = value => createHash('sha256').update(value).digest('hex');
export const SOURCE_PREFIX = 'server/src/';
export const BASELINE_PATH = 'server/scripts/promise-hygiene/baseline.json';
export const CONFIG_PATH = 'server/tsconfig.promise-hygiene.json';
export const EXTENSIONS = ['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs'];
export const MAX_GIT_BYTES = 32 * 1024 * 1024; // 32 MiB bounds each manifest/history response.
export const MAX_SOURCE_BYTES = 4 * 1024 * 1024; // 4 MiB per reviewed source file.
export const MAX_SOURCE_FILES = 4096; // Explicit ceiling above the reviewed source inventory, not a coverage floor.
export const MAX_BASELINE_ENTRIES = 16384; // Bound identity maps and transition work independently of source count.
export const MAX_METADATA_BYTES = 32 * 1024 * 1024; // Bound baseline, event and lockfile inputs to 32 MiB.
export const MODES = { TRANSITION: 'TRANSITION', VERIFY: 'VERIFY', LOCAL: 'LOCAL' };
export const STATES = { INITIAL_SEED: 'INITIAL_SEED', RETAINED: 'RETAINED', REANCHORED: 'REANCHORED', VERIFIED: 'VERIFIED', ADVISORY: 'ADVISORY' };
export const REANCHOR_LABEL = 'promise-hygiene-reanchor';
export const POLICY = {
  schema: 'promise-hygiene-v2',
  // Must match the pinned devDependencies in ../../package.json and its npm lockfile.
  versions: { eslint: '10.14.0', typescript: '5.9.3', 'typescript-eslint': '8.72.1', '@eslint/js': '10.0.1' },
  extensions: EXTENSIONS,
  manifest: 'git-index-source-prefix-no-links-full-program-parity',
  fingerprint: 'typescript-token-names-clause-call-head-context-v2',
  noInlineConfig: true,
  rules: {
    '@typescript-eslint/no-floating-promises': ['error', {
      ignoreVoid: false, ignoreIIFE: false, checkThenables: true,
    }],
    '@typescript-eslint/no-misused-promises': ['error', {
      checksConditionals: true, checksSpreads: true,
      checksVoidReturn: {
        arguments: true, attributes: true, inheritedMethods: true,
        properties: true, returns: true, variables: true,
      },
    }],
  },
};
// Must match compilerOptions in ../../tsconfig.promise-hygiene.json.
export const CONFIG = {
  extends: './tsconfig.json',
  compilerOptions: { allowJs: true, checkJs: false, noEmit: true, declaration: false, declarationMap: false },
  include: ['src/**/*'],
  exclude: ['node_modules', 'dist', 'test'],
};
// Effective compiler options are hashed by exclusion, so newly introduced type options count.
// Must match the complete denylist witness in promise-hygiene-baseline.test.ts.
export const EMIT_ONLY_OPTIONS = [
  'outDir', 'declaration', 'declarationMap', 'declarationDir', 'sourceMap',
  'inlineSourceMap', 'inlineSources', 'removeComments', 'noEmit', 'emitDeclarationOnly',
  'incremental', 'tsBuildInfoFile', 'composite', 'pretty', 'preserveWatchOutput',
  'listFiles', 'listEmittedFiles', 'traceResolution', 'diagnostics', 'extendedDiagnostics',
];
