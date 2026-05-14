# Releasing `@sanctuary-framework/mcp-server`

Publish intent is separate from tag intent. Tag pushes do not publish; manual workflow dispatch does.

## Procedure

1. Land the release commit on `main`. `server/package.json` must be at the exact version string being published (example `1.0.0-rc.3` or `1.0.1`).
2. Tag the SHA locally and push the tag, for example `git tag v1.0.1 && git push origin v1.0.1`. The tag is for git history; it does not trigger publish.
3. Open the repo on GitHub, go to Actions, select the "Publish (manual)" workflow, click "Run workflow".
4. Type the version string from `server/package.json` into the `version` input (do not prefix with `v`). Optionally set `ref` to the tag you just pushed; leave blank to publish from the selected branch.
5. Click "Run workflow". The job verifies the input matches `server/package.json` at the checked-out ref, runs typecheck and tests, builds, and publishes. Pre-release versions (containing a hyphen) publish under the `next` dist-tag; plain versions publish under `latest`.

## Required repo secret

`NPM_TOKEN` (automation token with publish access to the `@sanctuary-framework` scope). Add at Settings, Secrets and variables, Actions.

## Failure modes and what to do

- Input version empty or does not match `server/package.json` at ref: job fails at the verify step. Fix the input or the ref, rerun.
- `NPM_TOKEN` missing or expired: `npm publish` step fails. Rotate the token and rerun.
- Tests or typecheck fail: treat as a real failure, do not bypass. Fix on a branch, merge, rerun dispatch.
- Release dependency pin check fails: a direct release-critical dependency uses a range or its lockfile root does not match the manifest. Pin the direct dependency to the exact version being released, regenerate the relevant lockfile, and rerun `npm run check:release-dependency-pins`.

## Dependency refresh procedure

Release-critical dependency updates are intentional release inputs, not incidental installer behavior.

1. Refresh only the dependency being updated. Do not run broad upgrades for a release-candidate fix.
2. For the server package, update `server/package.json` direct `dependencies` and `devDependencies` to exact versions, then run `npm install --package-lock-only` from `server/`.
3. For the menubar approval surface, update `menubar/package.json` direct Tauri/Vite/TypeScript dependencies to exact versions, then run `npm install --package-lock-only` from `menubar/`.
4. For Rust-side menubar dependencies, update `menubar/src-tauri/Cargo.toml` direct release-critical crates with exact `=` requirements and refresh `menubar/src-tauri/Cargo.lock` only when the resolved version changes.
5. Run `npm run check:release-dependency-pins`, `cd server && npm test`, and the menubar build checks available without release signing before opening the release PR.

## Rollback

If a published version needs to be pulled, use `npm dist-tag rm` or `npm deprecate` from a trusted maintainer shell. The workflow does not handle unpublish.
