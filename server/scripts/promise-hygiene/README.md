# Promise hygiene ratchet

The original ESLint pass runs first. A separate type-aware pass pins floating and
misused promise diagnostics by rule, repository path, message kind and fingerprint.
The tracked eight-extension manifest determines coverage on every run;
`baseline.sources` is measurement metadata, never a floor.

## Modes and continuing paths

| Mode | Continuing evidence | State |
| --- | --- | --- |
| TRANSITION | PR event, two-parent synthetic merge, first parent equal to event base SHA | INITIAL_SEED, RETAINED or REANCHORED |
| VERIFY | Every other Actions event; exact measured identities, multiplicities and computed digests | VERIFIED |
| LOCAL | Worktree compared to HEAD's baseline using transition rules | ADVISORY; advisory, CI is the gate |

The lint checkouts in `ci.yml` and `evidence-pack-candidate.yml` must match the
`fetch-depth: 2`, no-`ref` contract in `run.mjs` and
`promise-hygiene-workflows.test.ts`. Test jobs do not depend on repository ancestry.
A missing commit, corrupt baseline or unproven merge refuses. Only proven baseline
path absence at the PR base permits initialization, with the external label and an
exact measurement.

Without drift, entries may shrink with fixes, disappear with deleted files, or move
one-to-one to paths absent from the entire base tree. Each donor path must disappear
from the tested tree, and each donor key may be consumed once. A byte- and
context-identical delete-plus-add meeting these conditions is a conserved move by
design. Only final trees matter. Every continuing path requires exact measurement;
stale entries and new diagnostics refuse.

Every non-dependency Program file is compared to the manifest. Outside-manifest
`.d.ts`, `.d.mts` and `.d.cts` files are permitted only when tracked with mode 100644
and no symlink component. They are never lint targets because declarations contain
no executable statements. The accepted set is computed afresh, not maintained as an
allowlist. A runtime file behind an accepted declaration is not measured.
Executable modules outside the manifest still refuse.

## Re-anchor and seed procedure

1. Use the reviewed landing tree, install the lockfile with `npm ci`, and build.
   A stale installation causes a version refusal rather than an automatic refresh.
2. Outside package scripts and CI, capture a measurement from the repository root:

   ```sh
   node --input-type=module -e 'import {measure} from "./server/scripts/promise-hygiene/run.mjs"; console.log(JSON.stringify(await measure(process.cwd()), null, 2));' > /tmp/promise-hygiene-measurement.json
   ```

   Use the host's approved memory limits. A collision stops the operation; never
   add line numbers, drop a diagnostic or disambiguate identical keys.
3. Compare every old and new key and explain each addition and removal. Copy
   `compilerDigest`, `driftDigest`, `sources` and `entries` into `baseline.json`.
   There is no regeneration command in the driver or package scripts. Stale
   digests or omitted entries refuse on the next check.
4. For initialization or a re-anchor with changed identities, have a maintainer
   apply `promise-hygiene-reanchor`, then push a commit or re-open the PR. A re-run
   reuses the original event payload and cannot see a subsequently applied label.
5. Run typecheck, lint, the hygiene and workflow tests, and the full isolated suite.
   The coordinator sets `.test-baseline` from CI's printed passing count in the
   same PR. The builder leaves it unchanged.

The drift digest covers installed pinned tool versions, exact lockfile bytes, and
all effective compiler options except the tested emit-only denylist. Paths are
repository-relative and cannot escape the repository; enum values use names,
object keys are sorted and array order is preserved. Fixed rule options and
coverage cannot be weakened by a label; that requires a separate design change.

Drift with unchanged identities may update the digest. Drift with changed identities
requires the external label, an exact measurement and no changes of any kind under
`server/src/`. Ordinary remediation shrinks without drift. LOCAL has no label
authority, so a pending re-anchor can refuse until its reviewed baseline is
committed. The PR TRANSITION gate supplies the authorization boundary.

## Trust, limits and cost

Branch protection and reviewed PRs are the merge boundary. VERIFY checks the current
snapshot, not history; a direct push accepts an enlarged or restored baseline when
its entries and digests exactly match the current measurement. Protect main against
direct and force pushes. The label plus owner review authorizes re-anchors.
Checker/source co-changes require the label, but this is defense in depth: a
self-edited checker cannot prove its own integrity. Owner review of checker and
workflow changes remains necessary, including changes spread across PRs. No
CODEOWNERS change is included here.

ESLint 10 uses `overrideConfigFile: true` to disable config lookup. Project ESLint
configuration cannot execute in the hygiene pass, and inline disables cannot hide
diagnostics. The original ESLint pass retains its existing policy. Project lint
configuration and pre-lint scripts run before the driver and are reviewed as source.

These rules do not prove complete asynchronous ownership. Casts to `any`, unused
bindings and inaccurate void-return declarations are limitations of the rules.
In pull-request TRANSITION mode, restoring a removed diagnostic, including by
reverting a remediation, is refused.
Existing pinned diagnostics need separately reviewed remediation.

The second type-aware pass adds cost to ordinary lint. The round-one review
measured about 13 seconds and 2.8 GB peak RSS on its Mac; host measurements differ.
File counts, source bytes, metadata bytes, Git output and baseline identities have
explicit caps. There is no historical replay or persistent request queue, and no
timeout releases work into a detached background writer.
