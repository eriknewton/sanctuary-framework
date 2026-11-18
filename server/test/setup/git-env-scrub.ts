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
 * Invariant: this file is the FIRST entry of both `globalSetup` and
 * `setupFiles` in vitest.config.ts. As the first globalSetup entry it clears
 * the vitest main process before any other globalSetup `setup` callback runs
 * and before workers start (vitest may import the globalSetup modules
 * concurrently, so another module's top-level code is not ordered after this;
 * none of them runs git at import); as the first setupFiles entry it clears every worker (a
 * setup file runs in workers only, so neither entry alone covers both). Every
 * child a test spawns with an inherited environment then starts with these
 * variables absent. Bound: vitest loads its config file before globalSetup,
 * so only config evaluation itself still sees them; the config runs no git.
 * Deleting (not pointing at /dev/null) reverts to
 * the normal shell defaults, because many tests rely on the developer's usual
 * git identity and config. Scope of the guarantee: the scrub stops a test
 * being redirected into a repository or a config file it did not choose; it
 * does NOT stop writes to the developer's own global config, because deleting
 * `GIT_CONFIG_GLOBAL` falls back to `$HOME/.gitconfig`. A test that writes
 * global (or system) git config must point `GIT_CONFIG_GLOBAL` /
 * `GIT_CONFIG_SYSTEM` at /dev/null or a temp file for its own children itself.
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
 * `scripts/git-redirect-env-keys.json`; this file clears BOTH its groups
 * (`repositoryKeys`, then `configKeys` and the numbered pattern). Consumers:
 * this file (and, through `scrubGitRedirectEnv`,
 * test/scripts/prepush-floor-rules.test.ts, test/scripts/install-hooks.test.ts
 * and test/structure/git-env-scrub.test.ts), scripts/install-hooks.js (loads
 * the JSON directly and deliberately clears only `repositoryKeys` plus
 * GIT_CONFIG_PARAMETERS, see there), and two bash copies that must match the
 * full set exactly: `.githooks/pre-commit` (`scrub_git_redirect_env` before
 * its one vitest call) and `scripts/verify-fail-before-self-test.sh`.
 * test/structure/git-env-scrub.test.ts pins both bash copies statically and
 * by running them (the hook end to end).
 */
import { readFileSync } from "node:fs";

interface GitRedirectEnvSpec {
  repositoryKeys: string[];
  configKeys: string[];
  numberedConfigKeyPattern: string;
}

const spec = JSON.parse(
  readFileSync(new URL("../../scripts/git-redirect-env-keys.json", import.meta.url), "utf8"),
) as GitRedirectEnvSpec;

/** Fixed names: `repositoryKeys` then `configKeys` from scripts/git-redirect-env-keys.json (the bash copies use this order). */
export const GIT_REDIRECT_ENV_KEYS: readonly string[] = Object.freeze([...spec.repositoryKeys, ...spec.configKeys]);

/** Numbered names (GIT_CONFIG_KEY_<n>/GIT_CONFIG_VALUE_<n>) from `numberedConfigKeyPattern`; pattern-matched because <n> is unbounded. */
export const GIT_REDIRECT_NUMBERED_KEY_RE = new RegExp(spec.numberedConfigKeyPattern, "u");

/** True for every name the scrub removes: a fixed key or a numbered config pair. */
export function isGitRedirectEnvKey(name: string): boolean {
  return GIT_REDIRECT_ENV_KEYS.includes(name) || GIT_REDIRECT_NUMBERED_KEY_RE.test(name);
}

export function scrubGitRedirectEnv(env: NodeJS.ProcessEnv = process.env): void {
  for (const key of Object.keys(env)) {
    if (isGitRedirectEnvKey(key)) delete env[key];
  }
}

/** globalSetup entry point: clears the vitest main process (the import below already did; this keeps the module a valid globalSetup). */
export function setup(): void {
  scrubGitRedirectEnv();
}

// Runs on import in both roles, so the scrub precedes anything a later setup
// module or test file does in this process.
scrubGitRedirectEnv();
