/**
 * Test isolation: no test process may inherit a git variable that redirects
 * which repository, config file, or object graph git acts on.
 *
 * Why this exists. When git runs a hook (the pre-commit fast tier runs
 * `vitest related`), it exports `GIT_DIR` and often `GIT_INDEX_FILE` and
 * `GIT_WORK_TREE`, all pointing at the REAL repository; a developer shell can
 * add `GIT_CONFIG` (a config file to write), `GIT_CONFIG_PARAMETERS` or
 * `GIT_CONFIG_COUNT` with numbered `GIT_CONFIG_KEY_<n>`/`GIT_CONFIG_VALUE_<n>`
 * pairs (runtime config such as remote or push destinations), or
 * `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM` (where global and system writes go).
 * A test that spawns `git` in its own fixture folder without clearing them
 * then acts on the real repository or the real config instead of the
 * fixture. Seen from outside: a related-test run set `core.bare=true` in the
 * shared `Sanctuary/.git/config`, after which git failed in every worktree of
 * the checkout, with no test failing.
 *
 * Invariant: this runs first in `setupFiles` (vitest.config.ts), so every
 * test file, and every child it spawns with an inherited environment, starts
 * with these variables absent. Deleting (not pointing at /dev/null) reverts to
 * the normal shell defaults, because many tests rely on the developer's usual
 * git identity and config; a test that needs no user config sets
 * `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM` for its own children after this runs.
 * `GIT_CEILING_DIRECTORIES` is deliberately NOT cleared: it only restricts
 * upward discovery and protects fixtures.
 *
 * Accepted consequence under pre-commit: with `GIT_INDEX_FILE` cleared, a test
 * that reads this repository's index reads `.git/index`, not the temporary
 * index git prepared for the commit being made (which differs only for a
 * partial commit such as `git commit <path>`). No test asserts on the
 * in-flight commit's index, so this is accepted rather than special-cased.
 *
 * One source (AGENTS.md rule 5): the list lives in
 * `scripts/git-redirect-env-keys.json`. Consumers: this file (and, through
 * `scrubGitRedirectEnv`, test/scripts/prepush-floor-rules.test.ts,
 * test/scripts/install-hooks.test.ts and test/structure/git-env-scrub.test.ts),
 * scripts/install-hooks.js (loads the JSON directly), and two bash copies that
 * must match it exactly: `.githooks/pre-commit` (`scrub_git_redirect_env`
 * before its one vitest call) and `scripts/verify-fail-before-self-test.sh`.
 * test/structure/git-env-scrub.test.ts pins both bash copies by full-set
 * equality and by running them.
 */
import { readFileSync } from "node:fs";

interface GitRedirectEnvSpec {
  keys: string[];
  numberedKeyPattern: string;
}

const spec = JSON.parse(
  readFileSync(new URL("../../scripts/git-redirect-env-keys.json", import.meta.url), "utf8"),
) as GitRedirectEnvSpec;

/** Fixed names from scripts/git-redirect-env-keys.json `keys`. */
export const GIT_REDIRECT_ENV_KEYS: readonly string[] = Object.freeze([...spec.keys]);

/** Numbered names (GIT_CONFIG_KEY_<n>/GIT_CONFIG_VALUE_<n>) from `numberedKeyPattern`; pattern-matched because <n> is unbounded. */
export const GIT_REDIRECT_NUMBERED_KEY_RE = new RegExp(spec.numberedKeyPattern, "u");

/** True for every name the scrub removes: a fixed key or a numbered config pair. */
export function isGitRedirectEnvKey(name: string): boolean {
  return GIT_REDIRECT_ENV_KEYS.includes(name) || GIT_REDIRECT_NUMBERED_KEY_RE.test(name);
}

export function scrubGitRedirectEnv(env: NodeJS.ProcessEnv = process.env): void {
  for (const key of Object.keys(env)) {
    if (isGitRedirectEnvKey(key)) delete env[key];
  }
}

scrubGitRedirectEnv();
