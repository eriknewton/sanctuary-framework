# Sanctuary release notes

## Required repository secrets

### `NPM_TOKEN`

Starting with `v1.0.0-rc.2`, the release workflow publishes to npm automatically on tag push. The workflow authenticates via a repository secret named `NPM_TOKEN`. Without it the publish step fails.

**Create once per repo:**

1. On [npmjs.com](https://www.npmjs.com/), open `Access Tokens` from the account menu.
2. Click `Generate New Token`. Choose type `Automation` (not `Publish`, which is interactive-only and breaks headless CI).
3. Scope the token to the `@sanctuary-framework` org if prompted.
4. Copy the token value. npm shows it only once.
5. In the GitHub repo, open `Settings` > `Secrets and variables` > `Actions`.
6. Click `New repository secret`. Name: `NPM_TOKEN`. Value: the token copied in step 4. Save.

**Rotation:** rotate the token after any suspected exposure and at least yearly. The rotation is two steps: generate the new token on npm, replace the value of the `NPM_TOKEN` secret on GitHub. No code change required.

**Scope boundaries:** the Automation token type has publish-only permission on packages the account owns. It cannot read other users' private data or modify billing. It does not grant write access to the GitHub repo itself.

## Dist-tag policy

| Version shape | npm dist-tag at publish | Promotion trigger |
|---|---|---|
| `v1.0.0-rc.N` (release candidate) | `next` | Acceptance drill clears on the candidate |
| `v1.0.0` (final) | `latest` | Drill-pass + Erik sign-off |
| `v1.0.1+` (patch / minor) | `latest` | Standard release flow |
| `v2.0.0-rc.N` (future major RC) | `next` | Same as rc above |

`next` is a staging lane. Consumers opt in with `npm install @sanctuary-framework/mcp-server@next`. Default `npm install @sanctuary-framework/mcp-server` always resolves to `latest`.

## Tag push checklist

Before pushing a release tag:

1. `.test-baseline` reflects the current Linux CI floor (see `docs/audit/test-baseline-hardening-plan.md`).
2. CHANGELOG has an entry for the tag with `### Removed`, `### Changed`, `### Housekeeping`, `### Not changed` sections populated.
3. `server/package.json` `version` field matches the tag exactly (minus the leading `v`).
4. `npm run typecheck && npm test` pass on a clean worktree.
5. Gate 4 em-dash sweep on outward-facing surfaces (`README.md`, `CHANGELOG.md`) passes.
6. Gate 3 naming-discipline check on outward-facing surfaces passes.

The release workflow picks up from the tag push. Watch the Actions tab for the publish step; the full flow typically finishes in under two minutes.
