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

## Castle Wall macOS signed release

Publishing the npm package does NOT ship the enforcement surface. The wall is enforced by the signed macOS app and its system extension, built by the separate `Castle Wall macOS Release Build` workflow (`.github/workflows/castle-wall-macos-release.yml`). An npm release without a corresponding signed macOS build ships the cooperative surface only.

Its first run (2026-06-16) failed at "Import signing certificate" because none of the five Apple credentials below had ever been added to the repository. The error surfaced as an opaque Keychain parameter fault; a preflight step now names the missing inputs directly.

The second run (2026-07-25) got through preflight, certificate import and signing, and exposed two further defects that only a real run could surface:

- `build-signed.sh --wrapped` refuses to finish when it has assembled a `.systemextension` and `NOTARYTOOL_PROFILE` is unset, because a signed-but-unnotarized system extension is silently uninstalled by Tahoe `sysextd` at validation (drill 2026-06-11c, finding W6-N1). This job holds the raw Apple ID and app-specific password rather than a stored notarytool profile, and notarizes in its own step, so it now passes `--allow-unnotarized` to mean "this step is not the notarizing step". **That flag is only safe on a path where a mandatory notarization follows.**
- The uploaded artifact was a zip taken **before** `stapler staple`, so Apple held the ticket while the shipped bundle did not carry it. Such a bundle passes `spctl` on a networked machine and fails Gatekeeper offline. The submission zip is now transient, the artifact zip is produced from the stapled bundle, and `stapler validate` proves the ticket is attached (`spctl` alone cannot, since it can satisfy itself with an online lookup).

### Required repository secrets

All five are required. The job now fails closed and lists every one that is absent.

| Secret | What it holds |
|---|---|
| `APPLE_DEVELOPER_ID_P12` | Base64 of the exported Developer ID Application `.p12` |
| `APPLE_DEVELOPER_ID_P12_PASSWORD` | The password chosen when exporting that `.p12` |
| `APPLE_NOTARY_APPLE_ID` | Apple ID used for `notarytool` submission |
| `APPLE_NOTARY_PASSWORD` | App-specific password for that Apple ID, not the account password |
| `APPLE_TEAM_ID` | Developer Team ID, which must match the team in `SIGNING_IDENTITY` |

### Export procedure

Run on a machine whose login keychain already holds the Developer ID Application identity. Confirm it is present first:

```
security find-identity -v -p codesigning
```

Expect a line naming `Developer ID Application`. If none appears, the certificate must be created or installed from the Apple Developer account before continuing.

1. In Keychain Access, select the `Developer ID Application` certificate together with its private key, right click, Export 2 items, and save as `.p12`. Choose a strong export password; that password is the value of `APPLE_DEVELOPER_ID_P12_PASSWORD`.
2. Base64-encode it as a single line: `base64 -i cert.p12 | tr -d '\n' | pbcopy`.
3. Add each secret at Settings, Secrets and variables, Actions. Paste the clipboard contents as `APPLE_DEVELOPER_ID_P12`.
4. Generate the app-specific password at appleid.apple.com, Sign-In and Security, App-Specific Passwords. It is used for notarization only.
5. Delete the local `.p12` once the secrets are set: `rm -P cert.p12`.

The exported `.p12` contains the signing private key. Do not commit it, do not place it in the repository tree, and do not paste it into an issue, a pull request, or a chat transcript.

### Verifying

Dispatch the workflow with a version tag. The preflight reports either which credentials are missing or that all five are present and the `.p12` parses. A wrong export password is deliberately not distinguished by the preflight and will fail at the import step instead, so that a public log cannot be used to probe the password.
