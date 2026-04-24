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

## Rollback

If a published version needs to be pulled, use `npm dist-tag rm` or `npm deprecate` from a trusted maintainer shell. The workflow does not handle unpublish.
