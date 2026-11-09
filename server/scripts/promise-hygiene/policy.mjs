import { createHash } from 'node:crypto';

export const digest = value => createHash('sha256').update(value).digest('hex');
export const SOURCE_PREFIX = 'server/src/';
export const BASELINE_PATH = 'server/scripts/promise-hygiene/baseline.json';
export const CONFIG_PATH = 'server/tsconfig.promise-hygiene.json';
export const EXTENSIONS = ['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs'];
export const MAX_GIT_BYTES = 32 * 1024 * 1024; // 32 MiB bounds each manifest/history response.
export const MAX_SOURCE_BYTES = 4 * 1024 * 1024; // 4 MiB per reviewed source file.
export const MAX_SOURCE_FILES = 4096; // Four times the initial source inventory, rounded to a power of two.
export const MAX_HISTORY_COMMITS = 4096; // Refuse oversized history rather than silently dropping ancestry.
export const POLICY = {
  schema: 'promise-hygiene-v1',
  // Must match the pinned devDependencies in ../../package.json and its npm lockfile.
  versions: { eslint: '10.14.0', typescript: '5.9.3', typescriptEslint: '8.72.1' },
  extensions: EXTENSIONS,
  manifest: 'git-index-source-prefix-no-links-full-program-parity',
  fingerprint: 'typescript-ast-tokens-statement-named-call-branch-context-token-offset-v1',
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
export const POLICY_DIGEST = digest(JSON.stringify({ policy: POLICY, config: CONFIG }));
// Must match the reviewed seed in baseline.json; no initialization command is exposed.
export const SEED_DIGEST = '992f51885a6d557e066bea433c38138bf6389b651897206b4aa6bf5e8e413f44';
export const SEED_SOURCE_DIGEST = 'e5c169f135dc2427c5c26d9b8f34f96d55b612e059a815b306e19f69d4be009c';
