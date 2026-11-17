/**
 * Test isolation: no test process may inherit a git variable that redirects
 * repository discovery or state.
 *
 * Why this exists. When git runs a hook (the pre-commit fast tier runs
 * `vitest related`), it exports `GIT_DIR` and often `GIT_INDEX_FILE` and
 * `GIT_WORK_TREE`, all pointing at the REAL repository. A test that spawns
 * `git` in its own fixture folder without clearing them then acts on the real
 * repository instead of the fixture. Seen from outside: a related-test run set
 * `core.bare=true` in the shared `Sanctuary/.git/config`, after which git
 * failed in every worktree of the checkout, with no test failing.
 *
 * Invariant: this runs first in `setupFiles` (vitest.config.ts), so every
 * test file, and every child it spawns with an inherited environment, starts
 * with these variables absent. `GIT_CEILING_DIRECTORIES` is deliberately NOT in
 * the list: it only limits upward discovery and protects fixtures.
 *
 * Must match the `GIT_REDIRECT_ENV_KEYS` consumers: test/scripts/prepush-floor-rules.test.ts
 * imports the constant rather than restating it, and .githooks/pre-commit
 * unsets the same names before it runs vitest (keep both lists equal to this
 * one; test/structure/git-env-scrub.test.ts pins the hook copy).
 */
export const GIT_REDIRECT_ENV_KEYS: readonly string[] = [
  "GIT_DIR",
  "GIT_COMMON_DIR",
  "GIT_WORK_TREE",
  "GIT_INDEX_FILE",
  "GIT_OBJECT_DIRECTORY",
  "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_NAMESPACE",
  "GIT_PREFIX",
];

export function scrubGitRedirectEnv(env: NodeJS.ProcessEnv = process.env): void {
  for (const key of GIT_REDIRECT_ENV_KEYS) delete env[key];
}

scrubGitRedirectEnv();
