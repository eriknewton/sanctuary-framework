# Credential surrogacy slice 1a: progress ledger

Branch `feat/credential-surrogate-1a-2026-09-30`, base `origin/main` at `94bc9d41`.
Design: `Review/Sanctuary/Credential_Surrogacy_Design_v2.1_2026-09-30.md` (coordinator repo).
Dispositions: `Review/Sanctuary/Credential_Surrogacy_Design_Gate_2026-09-30/ROUND2_DISPOSITIONS.md`.
This ledger is the resume point for the next job in the chain. Read the "next" line first.

## Read this before you do anything (host facts job 1 learned the hard way)

1. **A pre-commit hook IS installed here**, at `Sanctuary/.git/hooks/pre-commit`
   (the baseline guard, file dated 2026-09-02). It runs `npm run typecheck` AND THE
   WHOLE VITEST SUITE on every commit, about 7.5 minutes, and it BLOCKS the commit on
   any failure. The spawn prompt says no hooks are installed; that is wrong for this
   host. Note the installed hook is the PRE-SPLIT version: `AGENTS.md` (2026-09-26)
   says pre-commit should run only `vitest related --run` scoped to staged files and
   that the full suite belongs to pre-push. The installed copy predates that split,
   and no `pre-push` hook is installed at all (only `pre-push.sample`), so the cost
   landed on commit instead of push. Re-running `cd server && npm run install-hooks`
   would fix the split, but that mutates the shared checkout's hooks, so job 1 left it
   alone and reported it instead.
2. **The suite cannot pass on this host**, so every commit needs `--no-verify` with
   the reason in the commit message. The blocker is
   `test/castle-wall/runtime/linux-producer-signed-activation.test.ts`, which shells
   `cargo` (`spawnSync cargo ENOENT`; `cargo` is absent here). The spawn prompt names
   Rust-toolchain failures as expected environmental failures on this host and tells
   the worker not to chase them. Linux CI is the gate for that suite.
3. **No `pre-push` hook fired**: `git push` is plain and fast here.
4. **No `timeout(1)` binary** exists on this host (no coreutils, no `gtimeout`). Use
   the tool call's own timeout instead of `timeout <secs> bash -c ...`.
5. **Budget the full suite.** The rule is one vitest full suite per job, and the
   pre-commit hook spends it. Plan on ONE verified commit per job plus cheap
   `--no-verify` checkpoints, and use targeted `npx vitest run <path>` while working.
6. The Concordia sidecar venv DID build here (hash-pinned install succeeded), so
   `test/composition` passes: 7 files, 149 tests, verified job 1. Composition and
   catalog parity are NOT environmental failures on this host.

## Job 1 (2026-09-30, about 50 minutes)

### done

- Step 0 worktree setup: `npm install` plus a fresh hash-pinned Concordia sidecar venv,
  both succeeded.
- Read design v2.1 sections 1 through 5 and `ROUND2_DISPOSITIONS.md` in full.
- **Scope item 8 complete**: new module `server/src/credential-surrogate/` with a barrel.
  - `constants.ts`: the design 3.5 bound table, each bound carrying its derivation and
    its enforcement site. Imports NOTHING on purpose (the root helper, root arming and
    the broker all load it); each derived bound is pinned equal to its source constant
    by a test instead of by an import chain.
  - `placeholder.ts`: grammar (`sanctuary_surrogate_` plus 32 lowercase hex from
    `randomBytes(16)`), anchored matcher, fresh-per-call global scan regex,
    `mintSurrogatePlaceholder`.
  - `binding.ts`: `SurrogateBinding` and `MintedSurrogateBinding`, plus the shared
    element-level validators (env name, bound header, destination host, port, agent id,
    secret name) and `isLegalHttpFieldValue`, the header-splitting guard. Reserved env
    names duplicated from `HARNESS_FORBIDDEN_PLIST_ENV` and pinned equal by test
    (`harness-daemon.ts` is do-not-touch, so a comment on both sides was not available;
    the test is the stronger pin and matches the precedent that list already uses).
  - `wire.ts`: shared version, correlation-id grammar, frame encode, and the
    before-`JSON.parse` size check.
  - `query-codec.ts` and `unlock-codec.ts`: the two one-shot codecs, strict shapes,
    unknown keys refused, each socket bound to exactly one codec.
  - `redaction.ts`: sink-level placeholder redaction, cycle-safe, non-mutating.
- **Scope item 10, partial**: `server/src/README.md` gained the `credential-surrogate`
  row, and its module and barrel counts moved 62 to 63 and 54-of-62 to 55-of-63.
- Commit `2fc17dd5`, pushed to `origin/feat/credential-surrogate-1a-2026-09-30`.
- **Scope item 1, the parser and the file seam** (the `openBroker` wiring is still
  owed, see next step 1):
  - `parseSurrogatePolicyDocument` in `disclosure/broker/policy.ts`: strict, unknown
    keys refused at every level, unknown version refused, element grammar taken from
    `credential-surrogate/binding.ts` rather than re-implemented, 1 to
    `MAX_SURROGATE_DESTINATIONS_PER_BINDING` destinations on port 443 only, the
    per-agent cap enforced at parse, a repeated host inside one binding refused, and
    two bindings naming one secret refused as `duplicate_binding`.
  - `SurrogatePolicyError` carrying only a fixed `failureClass` from the closed set
    (`read_error`, `json_error`, `schema_error`, `conflict`, `duplicate_binding`,
    `bad_version`), never parser message text.
  - `findSurrogateGrantConflicts` (the conflict check against `read` and `rotate`
    grants, sorted and deduped so an audit line is stable) and
    `surrogateBoundSecretNames` (the required set the token issuer will refuse
    against).
  - `surrogatePolicyPath`, `saveSurrogatePolicy` (0600 via `writeFileCustody`, and it
    re-parses before writing so a caller cannot persist what the loader would refuse)
    and `loadSurrogatePolicyDocument` in `open.ts`, returning the three-way
    `absent` / `loaded` / `failed` result that IS the ENOENT split.
- **Scope item 3, partial**: the pin comments on `SecretScope`
  (`backend-interface.ts`) and `SCOPE_RANK` (`token-issuer.ts`), each naming the
  other side and stating that `surrogate` must never be added.
- **Scope item 4, partial**: the five additive `BROKER_OPS` entries in
  `operational/audit-log.ts` (`SURROGATE_UNLOCKED`, `SURROGATE_TOKEN_REFUSED`,
  `SURROGATE_BOUND`, `SURROGATE_REMOVED`, `POLICY_LOAD_FAILED`), each commented with
  whether it is `append` or `appendCritical`.

### next (do these in this order)

1. **Finish scope item 1's wiring.** The PARSER and the FILE seam are built (see done
   below). What remains is threading them through `openBroker`:
   - call `loadSurrogatePolicyDocument` beside `loadBrokerGrants` (`open.ts:80`);
   - on `failed`, write `BROKER_OPS.POLICY_LOAD_FAILED` via `append` (not
     `appendCritical`) carrying the file (`broker` or `surrogate`) and the
     `failureClass`, and yield ZERO grants and zero bindings;
   - on `absent`, stay silent with zero bindings;
   - run `findSurrogateGrantConflicts` against the parsed broker grants; on a
     conflict, yield ZERO grants and audit `POLICY_LOAD_FAILED` with class
     `conflict`;
   - apply the SAME ENOENT-versus-broken split to `loadBrokerGrants`'s own bare
     `catch` at `open.ts:116-125`, which still collapses both causes.
   Note `loadBrokerGrants` has no `auditLog` today, so the split needs the audit log
   threaded in or the load moved after the `AuditLog` construction at `open.ts:73`.
   The `AuditLog` is already built before grants load, so moving the call is enough.
2. **Scope item 2**, `disclosure/broker/surrogate-store.ts`. Confirmed seams:
   `KeychainBackend` takes a `service` override (option declared in
   `KeychainBackendOptions`, applied in the constructor), the broker's own derivation
   is `legacyBrokerKeychainIdentity` plus `brokerKeychainIdentityFor` with
   `storagePathDigest` (`keychain-backend.ts:349-386`), and `SERVICE` is the literal
   `sanctuary-broker` at `:36`. NOTE: `storagePathDigest` is NOT exported, so the
   surrogate derivation either exports it or derives its identity by calling
   `brokerKeychainIdentityFor` and replacing the service prefix. Keep the same
   keychain FILE (one passphrase unlock) and change only the service prefix, per
   design 3.3. `openSurrogateStore` shares steps 1 to 4 of `openBroker`
   (`open.ts:51-73`). Add the structural test that the surrogate service literal is
   declared only in `surrogate-store.ts` and that `openBroker` never passes a service
   override.
3. **Scope item 3**, broker refusal. The pin comments are already in place. What
   remains: required `surrogateBoundSecrets: ReadonlySet<string>` on
   `TokenIssuerOptions`, refusal in `issueToken` and `readViaToken` with the generic
   denial plus `appendCritical BROKER_OPS.SURROGATE_TOKEN_REFUSED`, `Broker.grant`
   refusal (`broker.ts:198`), and the set threaded from `BrokerOptions`
   (`broker.ts:29`) through the `new TokenIssuer` call (`broker.ts:94`). Use
   `surrogateBoundSecretNames` from `policy.ts`, already built and tested.
4. Then scope items 4 through 7 and 9, then the rest of item 10.

### open questions

- None blocking. The design and the tree agreed at every seam job 1 read.
- One deliberate deviation from the design's letter, recorded for the code gate: design
  3.3 and 4 say the parser pins its env-name refusal to `HARNESS_FORBIDDEN_PLIST_ENV`
  "with a must-match comment on both sides". `harness-daemon.ts` is in the spawn
  prompt's do-not-touch list, so only one side carries the comment; the other side of
  the pin is a test that imports both lists and asserts set equality. That is the same
  mechanism `harness-daemon.ts` itself uses for its lockstep with
  `cli/castle-wall-boot.ts`.

### deferred on purpose

- The `egress-gate` row update in `server/src/README.md` (naming the helper daemon,
  with the "drill-owed; no capability claim advances" bound) waits for the job that
  actually adds `surrogate-helper-daemon.ts`. A row naming a file that does not exist
  would be a false claim in the module map.

### test results so far

- `npx vitest run test/credential-surrogate/`: 5 files, **79 passed**, 0 failed.
- `npx vitest run test/disclosure/broker/surrogate-policy.test.ts`: **28 passed**.
- `npx vitest run test/disclosure/broker/surrogate-policy-file.test.ts`: **14 passed**.
- `npx vitest run test/disclosure/broker test/broker-mcp test/audit`: 28 files,
  **336 passed**, 0 failed. This is the no-regression check for the additive parser,
  the two pin comments and the five new audit ops.
- `npm run check-import-cycles`: exit 0, 10 cycles (all pre-existing baseline
  cycles), **zero involving `credential-surrogate`**.
- `git diff origin/main -- server/src/broker-mcp/broker-server.ts`: **empty, 0 bytes**.
- `scripts/check-ai-tells.sh server/src/README.md`: clean, no tells.
- Zero em-dashes on any line job 1 added (`git diff -U0 | grep '^+' | grep -c` is 0).
- `npx vitest run test/structure/codebase-conventions.test.ts`: 2 passed (the module
  map row).
- `npx vitest run test/composition`: 7 files, 149 passed.
- `npm run typecheck`: green. Tests/scripts typecheck baseline unchanged (979
  diagnostics).
- Full suite via the pre-commit hook, on the tree BEFORE the README row landed:
  1154 files, 16603 passed, 9 skipped, **3 failed**. Two are accounted for: the module
  map row (fixed in `2fc17dd5`) and the `cargo ENOENT` suite above. **The third failing
  file was not captured**: the hook keeps no test log and its output scrolled past the
  `tail`, and the one-full-suite-per-job rule stopped job 1 from re-running to name it.
  **Owed to the next job**: name it from that job's own pre-commit run, and say whether
  it reproduces on the base tree.

### gates still owed for the final job

- Gate 2: targeted vitest for everything touched, with the exact commands in the report.
- Gate 3: `test/security` and `test/wrap` whole, `test/structure` whole, and
  `node scripts/check-assurance-matrix.mjs`.
- Gate 4: `npm run check-import-cycles`, and confirm
  `git diff origin/main -- server/src/broker-mcp/broker-server.ts` is empty.
- Gate 5: `.test-baseline` recomputed from the LINUX count. Current value `16496`;
  a macOS count is not the floor, so this must come from CI, not from this host.
