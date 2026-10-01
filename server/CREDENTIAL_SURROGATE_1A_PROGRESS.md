# Credential surrogacy slice 1a: progress ledger

Branch `feat/credential-surrogate-1a-2026-09-30`, base `origin/main` at `94bc9d41`.
Design: `Review/Sanctuary/Credential_Surrogacy_Design_v2.1_2026-09-30.md` (coordinator repo).
Dispositions: `Review/Sanctuary/Credential_Surrogacy_Design_Gate_2026-09-30/ROUND2_DISPOSITIONS.md`.
This ledger is the resume point for the next job in the chain. Read the LAST
`### next` list in the file first (currently the one under "Job 6").

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

### next

Superseded by the Job 2 section below; read that one.

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

## Job 2 (2026-09-30, about 20 minutes of work)

### done

- **Scope item 1 COMPLETE.** `openBroker` now reads both policy files after the
  audit log exists and reconciles them, in a new exported
  `loadBrokerAndSurrogatePolicies` (`open.ts`). Broker grants got the SAME
  absent-versus-present-and-broken split the surrogate loader already had, in a
  new exported `loadBrokerGrantsClassified`, so the bare `catch` that collapsed
  both causes is gone. A conflict, a broken broker file, or a broken surrogate
  file each yields ZERO grants plus one `append` (not `appendCritical`)
  `POLICY_LOAD_FAILED` line carrying `{ file, failure_class }` and, for a
  conflict only, the sorted conflicting names. Absence stays silent.
- **Scope item 2 COMPLETE.** `disclosure/broker/surrogate-store.ts`:
  `SurrogateValueStore` over the SAME keychain file under service
  `sanctuary-surrogate[-<digest>]`. The digest is NOT re-derived: the identity
  comes from `brokerKeychainIdentityFor` with the prefix rewritten, so one digest
  derivation exists in the tree and `storagePathDigest` stays unexported
  (`keychain-backend.ts` is pin-comment-only and was not widened). It fails
  closed if the broker identity ever stops starting with `sanctuary-broker`.
  `hasValue` answers from the NAME list, never by reading the value.
  `openSurrogateStore` is in `open.ts`, sharing steps 1 to 4 with `openBroker`
  through one extracted `openFortressContext`.
- **Scope item 3 COMPLETE.** `TokenIssuerOptions.surrogateBoundSecrets` and
  `BrokerOptions.surrogateBoundSecrets` are REQUIRED (rule 3). `issueToken`
  refuses FIRST, ahead of the grant lookup; `readViaToken` refuses ahead of the
  expiry check; `Broker.grant` throws `BrokerDeniedError` and records nothing in
  the issuer. All three write `appendCritical SURROGATE_TOKEN_REFUSED` with a
  `surface` discriminator (`issue_token`, `read_via_token`, `grant`).
  **Design decision worth the code gate's attention:** the set is held by
  REFERENCE, not copied. A copy would make `readViaToken`'s branch unreachable
  by construction (nothing rebinds a secret inside one broker process today), and
  an unreachable required guard is the same as an unwritten one.
- **Scope item 4, partial.** `secrets surrogate` dispatch with `add` and `list`,
  `parseSurrogateAddFlags` (all four required flags named at once on a miss,
  comma host list split before the shared parser judges it), and the `cmdGrant`
  refusal, which fires BEFORE `broker-policy.json` is written. `surrogate add`
  builds the candidate document and hands it to `parseSurrogatePolicyDocument`
  rather than validating locally, refuses when the name already holds a value
  under the broker label, writes the VALUE before the binding row, and appends
  `SURROGATE_BOUND`.
- **Scope item 10, partial.** `reorg-surface-manifest.md` row 77 records the
  `secrets surrogate` additions, that `TOP_LEVEL_SUBCOMMANDS` is unchanged, the
  re-recorded `secrets` help line, and that `secrets grant` now refuses a bound
  name (a deliberate behavior change on a frozen row).
- Commits `9c9276be` and the Job 2 tail, both pushed.

### next (do these in this order)

1. **Finish scope item 5, the root helper daemon's RUNTIME**
   (`egress-gate/surrogate-helper-daemon.ts`). The process SURFACE landed in Job
   2 (see the Job 2 addendum below); what remains is the behavior:
   - both listeners, with `SURROGATE_HELPER_SOCKET_UMASK` held across `listen()`
     then `chmod` 0600 and `chown` (query socket to the gate uid, unlock socket
     to the operator uid);
   - each socket bound to exactly ONE codec, so a query frame on the unlock
     socket and the reverse is `malformed` and never falls through;
   - the unlock contract: one value per connection, validation (secret in table,
     own generation, 1 to `MAX_SURROGATE_VALUE_BYTES`, legal HTTP field-value
     bytes, TTL clamped to `MAX_SURROGATE_UNLOCK_SECONDS`), `unlock_accepted`
     and `lock_accepted` for EVERY accepted unlock or lock regardless of client,
     and a `status` that never returns a value or a placeholder;
   - the query contract of design 3.4.2: one connection per query, one frame each
     way, `unexpected_extra_bytes` on any byte after the first frame, the `id`
     echoed, the four decision conditions, and
     `SURROGATE_HELPER_MAX_CONCURRENT_QUERIES` with `rate_limited`;
   - the generation check against the bindings file header (the argv parser is
     pure and deliberately does not do this read) and the over-cap load refusal;
   - the composition root the `castle-wall surrogate-helper-daemon` verb calls,
     plus that verb in `cli.ts`.
2. **Finish scope item 4** against that daemon: the operator-side one-shot
   unlock-socket client (`status` probe classified `unarmed` on socket ENOENT,
   `armed` on a status answer, refuse on EACCES, timeout and malformed), then
   `remove`, `unlock` (RLIMIT_CORE re-exec, order per design 3.4.4), `lock`,
   `status`, `events` (root only), and the `cmdRevoke` refusal. `cli.ts` gets the
   `castle-wall surrogate-helper-daemon` verb.
3. Scope items 6 and 7 (arming twin membership, placeholder minting, release
   barrier), then 9 (gate plist `Core = 0` only), then the rest of 10
   (`ASSURANCE_MATRIX.md` row, the `egress-gate` module-map row, `.test-baseline`).

### open questions

- None blocking. The design and the tree agreed at every seam Job 2 read.
- Job 1's deviation note (the env-name pin carried by a test rather than a
  comment on `harness-daemon.ts`) still stands and still needs the code gate's eye.

### out-of-owned-path edits made, flagged for the code gate

Making `surrogateBoundSecrets` required (design 3.3, AGENTS.md rule 3) broke 14
existing construction sites at the type level. Twelve are inside owned test
paths. TWO are not: `server/test/security/agent-audit-allowlist.test.ts:698` and
`server/test/structure/public-surface-extract.ts:210`. Each got exactly one
added option line plus a one-line comment; nothing else in either file changed,
and neither edit alters what those suites assert. Halting the build over two
mechanical one-line compile fixes forced by a design-mandated required option
would have been disproportionate, so they were made and are recorded here.
`server/test/fixtures/typecheck-tests-baseline.txt` also moved by ONE line
number (a shifted `@ts-expect-error` in a file Job 2 edited); the diagnostic
COUNT is unchanged at 979.

### test results so far (Job 2, additive to Job 1)

- `npx vitest run test/disclosure/broker/surrogate-refusal.test.ts`: **6 passed**.
- `npx vitest run test/disclosure/broker/surrogate-policy-reconcile.test.ts`: **11 passed**.
- `npx vitest run test/disclosure/broker/surrogate-store.test.ts`: **7 passed**.
- `npx vitest run test/broker-mcp/broker-server-surrogate-refusal.test.ts`: **3 passed**
  (the wired-consumer test through the real `tools/call` handler).
- `npx vitest run test/structure/surrogate-keychain-label.test.ts`: **4 passed**.
- `npx vitest run test/cli/secrets-surrogate.test.ts`: **12 passed**.
- `npx vitest run test/disclosure/broker test/broker-mcp test/audit test/credential-surrogate`:
  37 files, **442 passed**, 0 failed.
- `npx vitest run test/cli/secrets.test.ts test/cli/secrets-fortress-flag.test.ts test/cli/secrets-surrogate.test.ts`:
  3 files, **34 passed**.
- `npm run typecheck`: green; tests/scripts baseline unchanged at 979.
- `scripts/check-ai-tells.sh server/reorg-surface-manifest.md`: 5 hits, ALL of
  them present on the base tree too (verified against
  `git show origin/main:server/reorg-surface-manifest.md`). Job 2 added zero.
- Zero em-dashes on any added line.

### fail-before witnesses captured (Job 2)

| Guard | Command | Base or guard-removed result | Head result |
|---|---|---|---|
| required `surrogateBoundSecrets` (type level) | `npm run typecheck` | 14 new `TS2345` diagnostics naming `BrokerOptions` and `TokenIssuerOptions` | baseline unchanged, 979 |
| `issueToken`, `readViaToken` and `Broker.grant` refusals | `npx vitest run test/disclosure/broker/surrogate-refusal.test.ts` with the three `.has()` checks stubbed false | 5 failed, 1 passed | 6 passed |
| `cmdGrant` binding refusal | `npx vitest run test/cli/secrets-surrogate.test.ts` with the refusal call removed | 2 failed, 10 passed | 12 passed |

Raw output for the three is in `/tmp/cs1a-evidence/` on the Mini2 host, which is
NOT durable; the next job re-captures anything it needs for the BUILD_REPORT
rather than citing that path.

## Job 2 addendum (same session, second half)

### done

- **Scope item 5, the process SURFACE** (`egress-gate/surrogate-helper-daemon.ts`,
  new, exported through the `egress-gate` barrel): `GATE_SURROGATE_DIR` (0711,
  pinned to `GATE_CRED_DIR`'s reasoning), the two socket paths (distinct by NAME
  as well as by owner), the bindings and destinations artifact paths, the
  launchd label and plist path, the operator-readable log-path derivation, the
  listen umask, the CLOSED event enum with no free-form `message` field
  anywhere, and `parseSurrogateHelperDaemonArgs`, which refuses an
  `--operator-uid` of 0, of the agent uid or of the gate uid, an agent uid equal
  to the gate uid, a missing flag, and any uid that is not plain decimal digits
  (`Number("0x1f6")` and `Number(" 502")` both parse, and a uid read one way here
  and another way by the arming side is a mismatch nothing would report).
  `renderSurrogateHelperDaemonPlist` emits `RunAtLoad=false`,
  `KeepAlive={Crashed:true}`, both `Core = 0` limit dictionaries, and the four
  baked argv values.
- **Scope item 9 COMPLETE.** `renderEgressGateDaemonPlist` in `gate-daemon.ts`
  gained `HardResourceLimits` and `SoftResourceLimits` with `Core = 0`, and
  NOTHING else in that file changed. The byte-identical guard at
  `test/egress-gate/boot-supervisor.test.ts` is re-recorded: the pre-existing
  assertion is a self-comparison through one renderer and would still hold if
  both sides lost the keys together, so two explicit key assertions were added
  beside it.
- **Scope item 10, further.** The `egress-gate` row in `server/src/README.md`
  now names the helper daemon, states exactly what is and is not built, and
  carries the bound "drill-owed; no capability claim advances".

### three structural guards this work tripped, and how each was answered

Recorded because each is a deliberate decision the code gate should see:

1. `test/structure/no-floating-append-critical.test.ts` refused
   `void this.auditLog.appendCritical(...)` in the synchronous `Broker.grant`.
   Answered by using `append` on THAT surface only, with the reason at the line:
   `grant` is synchronous and its callers expect it to stay so, and the awaited
   `appendCritical` records for this operation are the two on the token paths,
   which is where an AGENT-triggered refusal lands. The `grant` line records an
   operator's own refused command, and the operator already has the thrown error.
   This is a narrow, stated deviation from design 3.10's blanket
   "`SURROGATE_TOKEN_REFUSED` via `appendCritical`".
2. `test/structure/pr5plus-cluster8-invariant-comments.test.ts` anchored on the
   bare `return [];` that the classified loader replaced. Re-recorded onto the
   two new enforcement sites, and an invariant comment was added AT the
   zero-grant return, which is where prose hygiene says the why belongs.
3. `test/structure/disclosure-guard.test.ts` D8-LOCALIZED went 21 to 22 on the
   new structural test's header. Rewritten positively; the ratchet is back at 21
   and `disclosure-baseline.txt` was NOT edited.
   Also `test/egress-gate/claim-basis-structural.test.ts` required the new source
   file in the claim-literal ratchet; added at 0 with a comment saying it must
   stay 0 while the helper is process surface only.

### test results (Job 2 addendum)

- `npx vitest run test/egress-gate/surrogate-helper-daemon-plist.test.ts`: **15 passed**.
- `npx vitest run test/structure test/egress-gate`: 110 files, **1480 passed**, 0 failed.
- `npx vitest run test/disclosure/broker test/broker-mcp test/audit test/credential-surrogate test/cli/secrets*.test.ts`:
  40 files, **476 passed**, 0 failed.
- `npm run typecheck`: green; tests/scripts baseline unchanged at 979.
- `npm run check-import-cycles`: exit 0, 10 cycles, all pre-existing, **none
  involving `credential-surrogate` or `surrogate-helper-daemon`**.
- `git diff origin/main -- server/src/broker-mcp/broker-server.ts`: **0 bytes**.
- `scripts/check-ai-tells.sh server/src/README.md`: clean, and clean on the base
  copy too. `server/reorg-surface-manifest.md`: 5 hits, all 5 present on the base.
- Zero em-dashes on any added line.
- NOT RUN this job, owed to the final job: `test/security` and `test/wrap` whole,
  `node scripts/check-assurance-matrix.mjs`, and the `.test-baseline` recompute
  from the LINUX count.

### fail-before witness (Job 2 addendum)

| Guard | Command | Base result | Head result |
|---|---|---|---|
| gate plist `Core = 0` | `npx vitest run test/egress-gate/surrogate-helper-daemon-plist.test.ts` with `gate-daemon.ts` restored from `origin/main` | 1 failed, 14 passed | 15 passed |

The helper plist and argv guards have no base tree to fail against (the file is
new), so their witness is the guard-removed form, owed to the next job.

## Job 3 (2026-09-30, about 45 minutes of work)

### done

- **Scope item 5 COMPLETE.** The helper daemon RUNTIME landed in
  `egress-gate/surrogate-helper-daemon.ts`, on top of the process surface Job 2
  built:
  - `loadSurrogateHelperTable`: reads `gate-surrogate/<uid>.bindings` through the
    shared parser and refuses to start on a header generation that differs from
    the argv generation (`generation_mismatch`), on a table over
    `MAX_SURROGATE_BINDINGS_PER_AGENT` (`too_many_bindings`, kept as its own
    class because it is the one an operator can act on), and on anything else
    (`bindings_unreadable`, cause never carried into the message because a parse
    refusal's text is derived from a file that names secrets).
  - `listenOneShot`: the umask held across `listen()`, then chmod 0600, then
    chown, the resolver's order. UNLOCK socket first, then query, so the gate
    never finds a query socket whose unlock path is not yet reachable.
  - `serveOneShotConnection`: the shared transport half (one frame each way, cap
    checked on the accumulated buffer before any parse, `unexpected_extra_bytes`
    on a byte after the first frame). What is NOT shared is which parser the
    caller passes, and each socket passes exactly one, so a query frame on the
    unlock socket reaches only the unlock parser and is `malformed`.
  - `answerQuery`: the four conditions of design 3.4.2 in membership-first order,
    the `id` echoed, expiry enforced on READ as well as by the sweep, and the
    concurrency cap taken after the parse and released on every path.
  - `answerUnlockSocket`: `status` (never a value or a placeholder, and it answers
    for a fully locked table because that is the CLI's armed probe), `lock`
    (drops and overwrites every value), and `unlock` with the generation and
    table checks and the TTL clamp. `unlock_accepted` and `lock_accepted` fire
    for every accepted unlock or lock regardless of client.
  - `runSurrogateHelperDaemonFromArgv`: the ONE production composition root, which
    `cli.ts`'s new `castle-wall surrogate-helper-daemon` verb calls. The verb
    prints a binding COUNT and socket paths, never a name or a placeholder.
- **New shared artifact codecs** in `credential-surrogate/artifacts.ts` (part of
  item 5's table load, and the seam item 6 and item 7 will write through): one
  render and one parse function for each of the three artifacts, with the
  writer/reader/mode table in the module header. Header grammar is a single LINE
  (`<kind> v<version> generation=<digits>`) so the release commit path can read
  the generation as root without a JSON parse and the release wrapper can read it
  from emitted script text. Every parser is all-or-nothing, re-validates each
  element with the shared validators, and refuses a cross-artifact kind, so a
  file at the wrong path is refused rather than parsed as the format it is not.
  `SURROGATE_PLACEHOLDER_LINE_RE` and `SURROGATE_PLACEHOLDER_FILE_KIND` are the
  two literals the wrapper must carry; the module header says so and item 7 owes
  the pin test.

### two design-versus-tree reconciliations, flagged for the code gate

1. **The TTL bound moved to the relying side.** Job 1's unlock codec REFUSED a
   `ttl_seconds` above `MAX_SURROGATE_UNLOCK_SECONDS`, which made the helper's
   clamp unreachable and contradicted design 3.4.3 and AGENTS.md rule 10 ("the
   relying side clamps"). The codec now bounds only the SHAPE (a positive safe
   integer) and `clampSurrogateUnlockSeconds` in the helper owns the ceiling, so
   a generous operator request becomes a bounded unlock rather than no unlock.
   The codec test was rewritten to pin that ownership rather than the old
   refusal.
2. **Value length and field-value bytes are enforced at the PARSER, not twice.**
   The helper's own duplicate checks were removed. Reason: the shared parser
   already refuses an empty value, an over-`MAX_SURROGATE_VALUE_BYTES` value and
   any CR, LF or NUL, so by the time the helper has a request no value that could
   split a header has ever existed in the process. Keeping both would be two
   grammars, and the weaker one would be the one that eventually diverged. The
   consequence is visible on the wire: those three refusals answer `malformed`,
   not `illegal_value_byte` or `value_too_long`, and the runtime test asserts
   that plus "nothing was loaded". The now-unused `illegal_value_bytes` helper
   deny CODE was deleted so the closed enum stays fully used.

### two structural guards this work tripped, and how each was answered

1. `test/egress-gate/claim-basis-structural.test.ts` claim-literal ratchet went
   0 to 1 on the helper. The literal is the affirmative early return in
   `acquireSlot`, a concurrency-slot accounting return and not a capability
   claim, exactly as the resolver's own slot acquirer is counted. Re-recorded in
   `claim-basis.ts` at 1 with its classification and the note that a SECOND
   literal there would mean the helper had started describing its own capability.
   (The classification comment itself first tripped the scanner, because the
   scanner reads comments too; reworded.)
2. `test/structure/surrogate-keychain-label.test.ts` flagged
   `credential-surrogate/artifacts.ts` because the artifact kind tokens start
   with the keychain service prefix. The guard now matches the SERVICE literal
   shape (the bare prefix, or the prefix plus a `-<hex digest>` suffix) instead of
   any quoted token sharing the prefix, with the reason at the line: matching the
   prefix alone would fail on every future file name that shares it, which trains
   a reader to widen the allow list.

### next (do these in this order)

1. **Finish scope item 4**, the operator side, against the daemon that now
   exists: the one-shot unlock-socket client (`status` probe classified
   `unarmed` on socket ENOENT, `armed` on a status answer, refuse on EACCES,
   timeout and malformed), then `remove`, `unlock` (the RLIMIT_CORE re-exec and
   the step order of design 3.4.4), `lock`, `status`, `events` (root only,
   fixture log lines), and the `cmdRevoke` refusal. `secrets surrogate add` and
   `list` and the `cmdGrant` refusal already landed in Job 2.
2. **Scope items 6 and 7**: arming-twin membership (every function in the design
   3.4.1 table), placeholder minting at the one mint site, the three artifact
   writes (call `renderSurrogate*File` from `artifacts.ts`; do NOT write a second
   serializer), the `gate-surrogate` runtime-fs plan entry, and the release
   barrier wrapper plus `gateSurrogatePlaceholderPath`. The wrapper owes the pin
   test named in the `artifacts.ts` header.
3. **The rest of item 10**: the `ASSURANCE_MATRIX.md` row, the remaining
   `reorg-surface-manifest.md` notes (the `surrogate-helper-daemon` verb is NOT
   in any help text, the daemon verbs are internal, so there is no castle-wall
   help text to re-record; say that explicitly), and `.test-baseline` from the
   LINUX count.
4. **The BUILD_REPORT.** Nothing has been written to
   `Review/Sanctuary/Credential_Surrogacy_Slice1a_BUILD_REPORT_2026-09-30.md`
   yet. It is owed by the final job and needs the fail-before witness table
   re-captured (Job 2's raw output lived in `/tmp` and is gone).

### open questions

- None blocking.
- Job 1's deviation note (the env-name pin carried by a test rather than a
  comment on `harness-daemon.ts`) still stands and still needs the code gate's
  eye, as do the two reconciliations above.

### test results (Job 3, additive)

- `npx vitest run test/egress-gate/surrogate-helper-daemon-runtime.test.ts`:
  **24 passed**. Real Unix-domain socket round trips against the real listeners.
- `npx vitest run test/credential-surrogate`: 6 files, **92 passed** (was 79;
  13 new in `artifacts.test.ts`).
- `npx vitest run test/structure test/egress-gate`: 111 files, **1504 passed**,
  0 failed (was 110 files / 1480).
- `npm run typecheck`: green; tests/scripts baseline unchanged at 979.
- `npm run check-import-cycles`: exit 0, 10 cycles, all pre-existing, **none
  involving `credential-surrogate` or `surrogate-helper-daemon`**.
- `git diff origin/main -- server/src/broker-mcp/broker-server.ts`: **0 bytes**.
- `npx eslint` clean on every file touched.
- Zero em-dashes on any added line.
- NOT RUN this job, still owed to the final job: `test/security` and `test/wrap`
  whole, `node scripts/check-assurance-matrix.mjs`, the `.test-baseline`
  recompute from the LINUX count, and the full suite (job 3 used
  `git commit --no-verify` per the host facts at the top of this file, so the
  third unnamed full-suite failure Job 1 owed is STILL unnamed; name it from a
  pre-commit run in a job that can afford one).

### fail-before witnesses: what job 3 ACTUALLY observed, and what is OWED

Read this table literally. Job 3 ran out of session budget before it could
capture guard-removed runs, so most of its guards have NO witness yet. Nothing
below is inferred; an owed row is owed.

| Guard | Observed this job | Status |
|---|---|---|
| TTL clamped by the relying side, not refused by the codec | `npx vitest run test/credential-surrogate/codecs.test.ts` FAILED on the pre-change tree (1 failed of 79: the over-clamp TTL parsed, where the old test asserted `null`), and passes after the codec and the test were both changed | **CAPTURED**, and it is a genuine before/after: the failing run is in this session's transcript |
| value byte and length rules refused at the shared parser | the runtime test's three unlock cases FAILED against the helper's own duplicated checks (they answered `malformed` where the test expected `illegal_value_byte` and `value_too_long`), which is what showed the parser was the real enforcement site | **CAPTURED as a discovery**, not as a guard-removed witness |
| `too_many_bindings` distinguished from `bindings_unreadable` | the cap case FAILED with `bindings_unreadable` before the refusal was mapped through, and passes after | **CAPTURED** |
| claim-literal ratchet, surrogate keychain label guard | both FAILED on the tree before they were re-recorded, with the exact drift lines quoted in this session | **CAPTURED** |
| one codec per socket (query frame on the unlock socket and the reverse) | not attempted | **OWED**: rewire the unlock listener to the query parser and record the failure |
| helper refuses a generation mismatch | not attempted | **OWED**: remove the header-versus-argv check and record the failure |
| over-cap unlock frame refused before `JSON.parse` | not attempted | **OWED**: remove the accumulated-buffer cap check and record the failure |
| helper refuses a bad `--operator-uid` | not attempted this job (the argv parser and its test landed in Job 2, also without a witness) | **OWED** |
| the four query conditions, the rate limit, the fault schedule | not attempted | **OWED**: each needs its guard-removed form |

The helper-plist and argv guards still have no base tree to fail against (the
file is new), so their witness must be the guard-removed form. Everything marked
OWED above is work for a later job, and the BUILD_REPORT must not claim a
witness that no run produced.

## Job 4 (2026-09-30, about 50 minutes of work)

### done

- **Scope item 4 COMPLETE.** The operator side landed in `cli/secrets.ts`
  against the helper daemon Job 3 built:
  - **The one-shot unlock-socket client**, `createSurrogateUnlockSocketTransport`
    plus `sendOnSurrogateUnlockSocket`: one connection per request, one frame
    each way, the frame cap checked on the ACCUMULATED buffer before any parse,
    a byte after the first frame classified `malformed_reply`, the correlation
    `id` checked on the reply, and one deadline covering connect and reply
    together. Outcomes are a closed three-way split (`answered`, `absent`,
    `unreachable` with a fixed failure class); the raw errno string never
    reaches an operator line because it carries the socket path, which names an
    agent uid.
  - **`probeSurrogateHelperArmed`**, the decision every destructive verb rests
    on: ENOENT is `unarmed`, a `status` answer is `armed`, and EACCES, timeout,
    malformed and a wrong-kind reply are all `indeterminate`. `indeterminate`
    is not "probably unarmed"; it refuses.
  - **`surrogate remove`**: refuses while armed or indeterminate, and on ENOENT
    removes the row and then the value, the reverse of `add`'s order and for
    the same reason (the state that must never exist between the two writes is
    a binding with no value behind it).
  - **`cmdRevoke`**: `removeSurrogateRowForRevoke` runs the same probe when the
    named secret is bound, removes only the binding ROW on success, keeps the
    stored value (revoke is a policy verb and has never deleted a secret) and
    writes `SURROGATE_REMOVED` with `removed_value: false`. An unbound name
    never reaches the probe.
  - **`surrogate unlock`**: the step order of design 3.4.4 exactly. Re-exec
    through `/bin/sh -c 'ulimit -H -c 0 && ulimit -S -c 0 && exec "$@"'`, then
    VERIFY in the child by reading `ulimit -H -c` (the env marker is never
    trusted on its own), then the `status` probe, then `openSurrogateStore`,
    then `appendCritical SURROGATE_UNLOCKED` aborting before any value is read,
    then one value per connection. `--ttl` is bounded only in shape; the helper
    clamps (AGENTS.md rule 10).
  - **`lock`, `status`, `events`.** `status` prints lock state and never a value
    or a placeholder. `events` refuses unless the effective uid is 0, checked
    before anything is opened, derives the gate log path through
    `egressGateDaemonLogPaths` (gate account from `deriveGateAccountName`, home
    base through a dynamic import of `arming-wiring.ts`, the precedent
    `cli/castle-wall.ts` already sets), prints only lines carrying
    `SURROGATE_GATE_EVENT_PREFIX`, and redacts placeholders on the way out.
- **Test seams added to `SecretsArgs`** so every case above is host-free:
  `surrogateUnlock` (the transport), `surrogateNoCore` (re-exec and core-limit),
  `effectiveUid`, `gateLogPathOverride`, and `surrogateBackend` /
  `brokerBackend` threaded into `openSurrogateStore` / `openBroker`. No
  `security` subprocess runs, no socket is created under a root-owned path, and
  no helper is started.
- **New test file** `test/cli/secrets-surrogate-operator.test.ts`, 30 cases.

### one design gap this work had to close, flagged for the code gate

**`remove`, `revoke`, `unlock`, `lock`, `status` and `events` all require an
explicit `--agent-uid N`.** The design names `--agent-uid` only for `unlock`
(3.4.4), but a binding names an agent ID (`"hermes"`) while the helper, its
sockets and its artifacts are all keyed by agent UID. Deriving one from the
other in the CLI would be a second resolver beside the arming path's, and after
an account rename the two would disagree: the CLI would probe a uid no helper
owns, read `unarmed`, and remove a row a live helper is serving. The operator
names the uid. The reason is at `parseSurrogateAgentUid`.

### one structural guard this work tripped, and how it was answered

`test/structure/cli-argv-parser-chokepoint.test.ts` flagged
`buffered.indexOf("\n")` in the unlock-socket reader as hand-rolled argv
parsing. It is wire framing: the unlock codec is newline-delimited JSON, and
`flagValue` remains the only reader of argv in the file. Answered with the
guard's own sanctioned `cli-argv-indexof-allowed:` marker plus the reason at the
line. NOTE for anyone adding another: the marker must sit on the SAME line, the
line directly above, or the line directly below (`hasAllowMarker` checks exactly
those three); a marker four lines up does not count, which is how this was first
mis-answered.

### next (do these in this order)

1. **Scope items 6 and 7**, the largest remaining packet: arming-twin membership
   (every function in the design 3.4.1 table), placeholder minting at the one
   mint site in `productionBringUp`, the three artifact writes (call
   `renderSurrogate*File` from `artifacts.ts`; do NOT write a second
   serializer), the `gate-surrogate` runtime-fs plan entry (root 0711), and the
   `release-barrier.ts` wrapper plus `gateSurrogatePlaceholderPath`. The wrapper
   owes the pin test named in the `artifacts.ts` header.
2. **The rest of item 10**: the `ASSURANCE_MATRIX.md` row, the remaining
   `reorg-surface-manifest.md` notes (row 77 now needs
   `secrets surrogate add|list|remove|unlock|lock|status|events`; the
   `surrogate-helper-daemon` verb is NOT in any help text because the daemon
   verbs are internal, so say that explicitly rather than re-recording a
   castle-wall help string that does not change), and `.test-baseline` from the
   LINUX count.
3. **The OWED fail-before witnesses** in the Job 3 table, plus this job's own
   (see below). Nothing may be claimed that no run produced.
4. **The BUILD_REPORT.** Still nothing written to
   `Review/Sanctuary/Credential_Surrogacy_Slice1a_BUILD_REPORT_2026-09-30.md`.

### open questions

- None blocking.
- The `--agent-uid` requirement above and Job 3's two reconciliations and Job
  1's env-name pin deviation all still want the code gate's eye.

### test results (Job 4, additive)

- `npx vitest run test/cli/secrets-surrogate-operator.test.ts
  test/cli/secrets-surrogate.test.ts`: **42 passed** (30 new).
- `npx vitest run test/structure test/cli`: 181 files, **2014 passed**, 2
  skipped, 0 failed (after the chokepoint marker; see the witness below).
- `npm run typecheck`: green; tests/scripts baseline unchanged at 979.
- `npx eslint src/cli/secrets.ts test/cli/secrets-surrogate-operator.test.ts`:
  clean. Zero em-dashes on any added line.
- NOT RUN this job, still owed to the final job: `test/security` and `test/wrap`
  whole, `node scripts/check-assurance-matrix.mjs`,
  `npm run check-import-cycles` (the new static imports of
  `egress-gate/gate-account.js`, `egress-gate/gate-daemon.js` and
  `egress-gate/surrogate-helper-daemon.js` from `cli/secrets.ts` MUST be
  re-checked for a cycle before the final push), the `.test-baseline` recompute
  from the LINUX count, and the full suite.

### fail-before witnesses (Job 4): what was ACTUALLY observed

| Guard | Observed this job | Status |
|---|---|---|
| CLI argv chokepoint rejects a hand-rolled `indexOf` in `src/cli/` | `npx vitest run test/structure/cli-argv-parser-chokepoint.test.ts` FAILED with the offender line quoted (`src/cli/secrets.ts:891`), failed again with the marker four lines above the call, and passes with the marker adjacent | **CAPTURED**, a genuine three-state before/after |
| `revoke` and `remove` reach a keychain on the success path | both ENOENT cases FAILED (exit 1, not 0) before the `brokerBackend` seam was threaded, which is what showed `cmdRevoke` continues into `openBroker` after the surrogate half | **CAPTURED as a discovery**, not as a guard-removed witness |
| unlock refuses without a verified hard core limit of 0 | not attempted in guard-removed form | **OWED**: delete the `hardLimit !== NO_CORE_HARD_LIMIT` arm and record the failure |
| unlock refuses before any keychain read when the helper is absent | not attempted in guard-removed form | **OWED**: move the probe below `openSurrogateStore` and record `keychainReads` going non-empty |
| `events` refuses when not root | not attempted in guard-removed form | **OWED** |
| remove and revoke refuse on EACCES, timeout and malformed | not attempted in guard-removed form | **OWED**: make `indeterminate` fall through to `unarmed` and record the four failures |

Everything marked OWED is work for a later job. The BUILD_REPORT must not claim
a witness that no run produced.


## Job 5 (2026-09-30, about 50 minutes of work)

### done

- **Scope item 6 COMPLETE, scope item 7 HALF** (the minting half; the release
  wrapper half is still owed). The helper is now a member of the arming twin
  at every function the design 3.4.1 table names.
  - `resolveSurrogateBringUpPlan` (`egress-gate/arming-wiring.ts`): loads
    `surrogate-policy.json` through `loadSurrogatePolicyDocument` (so the
    ENOENT split is the loader's and is not re-implemented), refuses to arm on
    a present-and-broken policy, on a breach of
    `MAX_SURROGATE_BINDINGS_PER_HOST`, on an unusable broker policy and on any
    `findSurrogateGrantConflicts` hit, then assigns dense ordinals in policy
    order and mints one placeholder per binding. **The only mint site in the
    tree.** The per-HOST cap is enforced here because this is the only place
    that sees every agent's bindings at once, under the provision lock the
    bring-up already holds; the parser keeps the per-AGENT cap.
  - `installSurrogateHelperForBringUp`: the three artifact writes through
    `renderSurrogate*File` (no second serializer), each chowned to exactly its
    reader with the final mode on the tmp file before the rename, then the
    plist render and `reloadLaunchdDaemonForBringUp`. Write order is bindings,
    destinations, placeholders LAST, stated at the line: the placeholder file
    is the only one the agent can read, and a placeholder the agent holds
    before the helper's table knows it is a placeholder that resolves to
    nothing. Called from `productionBringUp` immediately after the bearer mint
    and BEFORE the resolver reload.
  - `removeSurrogateHelperForAgent`: one bootout-and-delete shared by the
    bring-up's no-bindings branch and both teardowns, so a fortress that stops
    using surrogacy does not leave a root helper running for a policy that no
    longer authorizes it. `surrogateArtifactPaths` is the one list of the four
    paths, so a teardown cannot forget one.
  - `bootstrapSurrogateHelperDaemonForBoot`: the resolver's shape plus the
    bindings-file pre-condition, wired into `startExclusiveEgressBootSupervisor`
    between the resolver and gate bootstraps, with the resolver's
    log-and-continue on failure.
  - `verifySurrogateBindingsGenerationForCommit` in the BASE `commitGeneration`:
    reads the bindings header as root through
    `readSurrogateArtifactGeneration` and throws on a mismatch. Verify only.
    An absent file is success.
  - `restoreCoarseCompositionProduction`: step 0c bootout with the step 0b
    throw, plus the plist and all three artifacts at step 3.
  - `createUnprotectExclusiveEgressOps`: helper bootout after the resolver with
    the same throw; `revokeCredential` also removes the placeholder file (it is
    a credential surface, not a gate surface); `removeGateSurfaces` also
    removes the plist and both `gate-surrogate` files.
  - `gate-surrogate` root 0711 in `runtime-fs-plan.ts` and its ASCII layout,
    with `GATE_SURROGATE_DIR_MODE` imported from the daemon (the
    `AGENT_HARNESS_HOLD_DIR_MODE` precedent) so the plan and the daemon cannot
    state two modes for one directory.
  - `gateSurrogatePlaceholderPath` in `gate-credential.ts`, placed there rather
    than with the helper because its writer/reader pair is root arming and the
    release wrapper as the agent uid, which is the `.token` pair exactly.

### one decision worth the code gate's eye

**The fortress path IS the policy storage path.** `resolveSurrogateBringUpPlan`
passes `input.fortressPath` to `loadSurrogatePolicyDocument` and
`loadBrokerGrantsClassified`, which join `surrogate-policy.json` and
`broker-policy.json` onto it. That matches the spawn prompt's
`<fortress>/surrogate-policy.json` and the CLI's own `openSurrogateStore`
threading, but it is an assumption a reader should confirm against a real
fortress layout rather than infer from this ledger.

### next (do these in this order)

1. **The second half of scope item 7**: the `release-barrier.ts` wrapper. It
   derives the surrogates path from its existing `TOKEN_FILE` argument (so the
   argument contract does not change), exports a line only when the header
   generation equals `EXPECTED_GENERATION` and every line matches
   `^[A-Z_][A-Z0-9_]{0,63}=sanctuary_surrogate_[0-9a-f]{32}$`, exits 78
   otherwise, and exports nothing for an absent file. The pin test named in
   the `credential-surrogate/artifacts.ts` header is owed WITH it: run the
   wrapper over a file `renderSurrogatePlaceholderFile` produced.
2. **The wired-consumer and rule 8 and rule 12 tests for what Job 5 built.**
   None were written this job, and they are the evidence: `productionBringUp`
   with a policy mints the three artifacts and installs the helper before the
   resolver reload; without a policy it creates none and removes a stale
   helper; the boot supervisor reaches `bootstrapSurrogateHelperDaemonForBoot`,
   starts nothing for an unresolvable agent, and continues on failure; arming
   with 101 bindings refuses; the per-host cap refuses; `commitGeneration`
   throws on a header mismatch. The `surrogateBindingsPresent` internals seam
   and the `fsOps` / `statFn` seams exist for exactly these.
3. **The rest of item 10**: `ASSURANCE_MATRIX.md` row, the remaining
   `reorg-surface-manifest.md` notes, `.test-baseline` from the LINUX count.
4. **The OWED fail-before witnesses** in the Job 3 and Job 4 tables.
5. **The BUILD_REPORT.** Still nothing written.

### open questions

- None blocking.
- The fortress-path-is-storage-path assumption above.

### test results (Job 5, additive)

- `npx vitest run test/egress-gate/runtime-fs-plan.test.ts
  test/egress-gate/gate-credential.test.ts`: **28 passed**.
- `npx vitest run test/egress-gate/arming-wiring.test.ts`: **116 passed**.
- `npx vitest run test/egress-gate/boot-supervisor.test.ts`: **39 passed**
  (unchanged by this job; run as a regression check).
- `npm run typecheck`: green. The tests/scripts baseline was RE-RECORDED at the
  same count, 979 to 979: adding ten import lines to
  `test/egress-gate/arming-wiring.test.ts` shifted 24 pre-existing diagnostics
  onto new line numbers, and the baseline stores `file(line,col)` strings. No
  diagnostic was added or removed. Run `npm run typecheck:tests:update` after
  any edit that shifts lines in a file that already carries diagnostics.
- NOT RUN this job, still owed to the final job: `test/security`, `test/wrap`
  and `test/structure` whole, `node scripts/check-assurance-matrix.mjs`,
  `npm run check-import-cycles` (Job 5 added
  `arming-wiring.ts` to `surrogate-helper-daemon.js`,
  `runtime-fs-plan.ts` to `surrogate-helper-daemon.js`, and `arming-wiring.ts`
  to `disclosure/broker/open.js` and `policy.js`, all of which MUST be
  re-checked for a cycle), the `.test-baseline` recompute from the LINUX count,
  and the full suite.

### fail-before witnesses (Job 5): what was ACTUALLY observed

| Guard | Command | Base result | Head result |
|---|---|---|---|
| The runtime-fs plan carries a `gate-surrogate` root 0711 entry | `npx vitest run test/egress-gate/runtime-fs-plan.test.ts` | FAILED, 2 tests: the ordered-plan deep equal, and `expected [...] to have a length of 21 but got 24` | **21 passed** after the three expected steps were added to the test |
| Unprotect boots the helper out after the resolver | `npx vitest run test/egress-gate/arming-wiring.test.ts` | FAILED: `bootoutGateDaemon ... ALSO boots out the peer-resolver daemon, gate FIRST` saw a third `bootout system/ai.sanctuaryprotocol.surrogate-helper.601` call | **116 passed** after the expectation named it |
| `revokeCredential` removes the agent-readable placeholder file | same command | FAILED: the credential teardown saw a fourth removed path | passed after the expectation named it |
| `removeGateSurfaces` removes the plist and both `gate-surrogate` files | same command | FAILED: `removeGateSurfaces ... every surface goes` saw three extra removed paths in per-uid position | passed after the expectation named them |

These four are genuine before/after witnesses on EXISTING guards (the tests
were on the base tree and failed against the new behavior until re-recorded).
They are NOT witnesses for the new behavior's own guards, which are owed with
the tests in "next" item 2 above. The BUILD_REPORT must keep that distinction.

## Job 6 (2026-09-30, about 40 minutes of work)

### done

- **Scope item 7 COMPLETE.** The `release-barrier.ts` exec wrapper now exports
  the agent's surrogate placeholders for the generation being released.
  - The path is DERIVED from the wrapper's existing `TOKEN_FILE` argument, so
    the launchd `ProgramArguments` contract and the argv digest that pins it do
    not change when a fortress starts or stops using surrogacy. A test pins the
    derivation against `gateSurrogatePlaceholderPath`.
  - **Two escaping traps a future editor of that script must know.** The
    wrapper body is a TypeScript template literal, so (a) a BACKTICK anywhere in
    it terminates the literal (the first draft used backticks in shell comments
    and the file stopped parsing), and (b) a single backslash is eaten by the
    literal, so `sed 's/\.token$/'` in the source renders as `s/.token$/` and
    the suffix anchor silently matches any character. Double every backslash.
  - **`${` is FORBIDDEN in that script**, enforced by the pre-existing test "has
    no render-time template interpolation in the wrapper body", which greps the
    raw source inside the backticks. So no POSIX parameter expansion at all: no
    `${VAR%suffix}`, no `${#VAR}`. The block uses `case` for suffix tests,
    `sed` for the two substitutions, `wc -l` for the count and `$((...))` for
    arithmetic (which is `$((`, not `${`, and is allowed).
  - Validation is all-or-nothing and bounded: a line cap (1024, pinned by test
    strictly above `MAX_SURROGATE_BINDINGS_PER_AGENT`) and ONE anchored grammar
    over the whole body BEFORE the first `export`, so a malformed last line
    cannot leave earlier lines in the environment. The loop reads the file
    directly (`done < "$FILE"`), never through a pipe, because a
    `tail | while read` loop runs its body in a subshell and discards every
    export silently.
  - Three fixed-code observations added to the diagnostic refusal record
    (`surrogate_file`, `surrogate_generation`, `surrogate_lines`). The record
    never carries a placeholder, a line or the path.
  - The pin test the `credential-surrogate/artifacts.ts` header promised now
    exists: six live tests run the real wrapper (via the existing
    `renderLinuxVisibleWrapperScript` + `runSh` harness) over files
    `renderSurrogatePlaceholderFile` produced.
- **Scope item 6's evidence (next item 2 of Job 5) DONE.** 31 tests.
  - NEW `test/egress-gate/surrogate-arming-wiring.test.ts`, 27 tests, covering
    `resolveSurrogateBringUpPlan` (mint, fresh-per-call, the two `none` cases,
    the present-and-broken refusal, the conflict refusal), rule 8 (the per-agent
    cap at +1 AND arming at exactly the cap, the per-host cap at +1 spread
    across agents so only the total is wrong), `installSurrogateHelperForBringUp`
    (write order, per-file owner and mode, each reader gets only what it is
    entitled to asserted by parsing all three files back, the LOCKED plist with
    Core 0 in both dictionaries, reload failure throws, an artifact write
    failure throws before the agent-readable file exists),
    `removeSurrogateHelperForAgent` (all four paths, not-loaded still tears
    down, an untolerated bootout throws and removes nothing),
    `bootstrapSurrogateHelperDaemonForBoot` and
    `verifySurrogateBindingsGenerationForCommit` (including a wrong-KIND file).
  - `boot-supervisor.test.ts` 39 to 43: the helper goes up between the resolver
    and the gate for a uid with a table, nothing at all for a uid without one, a
    bootstrap failure logs and continues with the gate still up, and an
    unresolvable agent starts nothing.
  - **ONE SOURCE CHANGE was required for rule 4**: `installSurrogateHelperForBringUp`
    wrote the helper plist through the un-seamed `atomicRootWrite`, which no test
    can reach without writing into `/Library`. It now routes through the SAME
    injected `fsOps.writeFileAs(path, content, 0, 0o644)` as the three
    artifacts. `writeFileAs` with uid 0 is `atomicRootWrite` plus a chown to
    root, which is a no-op for a file root just created.
- **Scope item 10 COMPLETE**: the `ASSURANCE_MATRIX.md` row (partial, macOS,
  with the echo bound stated alongside the claim and the gate-events residual),
  the `server/src/README.md` `egress-gate` row (deferred since job 1, now that
  the helper file exists), the `reorg-surface-manifest.md` row 77 correction
  (its note still said only `add` and `list` shipped in 1a), and `.test-baseline`.

### the .test-baseline number, and why it is what it is

16496 to **16769**. The delta is exactly the **273** tests in the **eighteen**
test files this branch ADDS, measured on this host with `npx vitest run` over
that file list, and confirmed to contain no `skipIf`, no `process.platform` and
no `darwin` gate, so all 273 run on Linux too. It DELIBERATELY excludes the
tests the branch adds to files that already existed (release-barrier +13,
boot-supervisor +4, and whatever jobs 2 to 5 added to the broker, arming-wiring
and runtime-fs-plan files), so the value is a floor KNOWN to sit below the true
Linux count rather than a guess at it. The guard is a floor, so undershooting is
safe and overshooting breaks CI. A full suite cannot run here (cargo absent) and
the spawn prompt says a macOS count is not the floor. **The next job may tighten
this once CI reports the real Linux number on this branch.**

### next (do these in this order)

1. **The BUILD_REPORT.** Still nothing written, and it is now the single largest
   remaining item. `Review/Sanctuary/Credential_Surrogacy_Slice1a_BUILD_REPORT_2026-09-30.md`
   in the COORDINATOR repo (`/Users/mini2/Code/Claude/`), frontmatter
   `disclosure: internal`. It needs: base SHA `94bc9d41` and head SHA; files
   changed; the per-guard fail-before witness table assembled from the tables in
   the Job 3, Job 4, Job 5 and Job 6 sections of THIS ledger; wired-consumer test
   names; the rule 8 and rule 12 test names and what they assert; plist render
   evidence; gate command outputs; the empty `broker-server.ts` diff;
   `.test-baseline` old and new with the derivation above; and an honest
   residuals list. Run `scripts/check-ai-tells.sh` on it.
2. **The OWED fail-before witnesses** still listed in the Job 3 and Job 4 tables.
3. **The final gates are already green** (see the section below): typecheck,
   `test/structure`, `test/security`, `test/wrap`, the assurance-matrix script,
   import cycles and the `broker-server.ts` zero diff all ran in job 6. Re-run
   only what a further edit touches, then push.
4. Only then print `RESULT_VERDICT: BRANCH_PUSHED <sha> COMPLETE`.

### gates ALREADY RUN on this branch (do not re-run unless something changed)

- `npm run typecheck`: **green**. Baseline 979, unchanged. Note: editing a test
  file that already carries diagnostics SHIFTS them onto new line numbers and the
  baseline stores `file(line,col)`, so `npm run typecheck:tests:update` is needed
  after such an edit even when no diagnostic was added or removed. It happened
  twice this job; both times the counts were 14 added / 14 resolved.
- `npx vitest run test/structure` WHOLE: **68 files, 518 passed.** This covers the
  frozen-surface and public-surface-snapshot tests with NO fixture edits, and it
  was run AFTER the `README.md` and `reorg-surface-manifest.md` edits.
- `node scripts/check-assurance-matrix.mjs`: **OK, 28 rows**, all evidence links
  resolve, every proven enforcement claim cites a drill.
- `npm run check-import-cycles`: **exit 0, 10 cycles**, the pre-existing baseline
  set. ZERO of them mention any surrogate module, so the new module adds no cycle.
- `git diff origin/main -- server/src/broker-mcp/broker-server.ts`: **0 bytes.**
- `bash ~/Code/Claude/scripts/check-ai-tells.sh` over `ASSURANCE_MATRIX.md`,
  `server/src/README.md`, `server/reorg-surface-manifest.md`: 5 hits, ALL of them
  pre-existing lines in `reorg-surface-manifest.md` (lines 37, 48, 71, 74, 91),
  none in text this branch added.

### the two owed suites: BOTH NOW RUN AND GREEN (end of job 6)

- `npx vitest run test/security` WHOLE: **37 files, 436 passed**, 0 failed.
- `npx vitest run test/wrap` WHOLE: **78 files, 1242 passed, 4 skipped**, 0 failed.
  The 4 skips are pre-existing, not introduced by this branch.

So EVERY named local gate in the spawn prompt has now run green on this branch.
Nothing test-shaped is owed. What remains for the final job is the BUILD_REPORT
and the Job 3 and Job 4 owed witnesses, both of which are writing, not running.
Re-run only what a further edit touches.

### open questions

- None blocking.
- The fortress-path-is-storage-path assumption recorded under Job 5 still stands
  and still wants a reader's confirmation against a real fortress layout.

### test results (Job 6, additive)

- `npx vitest run test/egress-gate/release-barrier.test.ts`: 94 to **107 passed**.
- `npx vitest run test/egress-gate/surrogate-arming-wiring.test.ts`: **27 passed**.
- `npx vitest run test/egress-gate/boot-supervisor.test.ts`: 39 to **43 passed**.
- `npx vitest run` over the 18 new test files: **273 passed**.
- `npx vitest run test/structure`: **518 passed**.
- Regression check re-run this job: `test/egress-gate/surrogate-helper-daemon-plist.test.ts`
  (**15 passed**, and it already covers BOTH plists' `Core` keys, so the spawn
  prompt's plist-render item is done), `surrogate-helper-daemon-runtime.test.ts`
  and `test/credential-surrogate/` together: **131 passed**. Job 3 and 4 already
  wrote the rule 8 and rule 12 helper-socket tests; do not write them again.

### fail-before witnesses (Job 6): what was ACTUALLY observed

| Guard | Command | Base result | Head result |
|---|---|---|---|
| The release wrapper exports this generation's placeholders (all 13 new tests) | `git stash push -- server/src/egress-gate/release-barrier.ts` then `npx vitest run test/egress-gate/release-barrier.test.ts` | **13 failed**, 94 passed: 7 static pins could not find their literals, 6 live runs got no export and no refusal | **107 passed** after the stash pop |
| The boot supervisor reaches the helper bootstrap | deleted ONLY the `bootstrapSurrogateHelperDaemonForBoot` try/catch from `arming-wiring.ts`, then `npx vitest run test/egress-gate/boot-supervisor.test.ts` | **2 failed**, 41 passed: exactly the two that assert it runs. The two that assert it does NOT run still passed, which is the point | **43 passed** after restore |
| The helper plist write is reachable by a test | reverted the plist write to `atomicRootWrite`, then `npx vitest run test/egress-gate/surrogate-arming-wiring.test.ts` | **4 failed**, 23 passed: the plist never appears in the recorded writes | **27 passed** after restore |
| The whole surrogate arming surface | `git show origin/main:server/src/egress-gate/arming-wiring.ts \| grep -c` the four function names | **0 occurrences** on the base tree, so all 27 tests in the new file are new-guard coverage | 27 passed at head |

The first three are true before/after witnesses with the guard removed from the
head tree. The fourth is an absence proof on the base tree, which is weaker and
the BUILD_REPORT must say so.

### one thing the BUILD_REPORT must state as a weaker witness

`productionBringUp` is module-private and every step in it mutates a root-owned
path, so NO test may call it. Its composition order is pinned by a source-order
assertion in the last describe of `surrogate-arming-wiring.test.ts` (bearer mint
before the surrogate plan, install before the resolver reload, the no-bindings
branch reaching a real teardown, and exactly one `mintSurrogatePlaceholder(` call
site in the whole of `arming-wiring.ts`). That is a text assertion, not a runtime
witness, and the report must not present it as one.


## Job 7 (2026-10-01, coordinator's Mac, verification and BUILD_REPORT)

### done

- **`.test-baseline` corrected 16769 to 16787.** Job 6's reasoning ("undershooting
  is safe") is wrong for this repo: `.github/workflows/test-baseline-guard.yml`
  Gate 2c FAILS when the passing count is ABOVE the floor as well as below it, so
  16769 would have failed CI by 18. 16787 is the main CI count at `94bc9d41`
  (16496 passed, 40 skipped, read from run 36736882367) plus the 291 tests this
  branch adds: 273 in the eighteen new files and 18 in existing files
  (`release-barrier.test.ts` 93 to 107, `boot-supervisor.test.ts` 39 to 43). The
  delta was derived by diffing `npx vitest list --json` over the WHOLE tree at the
  base and at head (collection only, no execution): +291 test ids added, 0 removed
  once the worktree-path artifact on `scripts/synthetic-coverage` and one
  host-environmental PyYAML-gated block in `test/wrap/hermes-yaml-parse-parity.test.ts`
  (present or absent by probe, unrelated to this branch) are set aside. None of the
  291 sits behind a platform gate. CI on Linux remains the authority; if it reports
  a different count, that number goes into `.test-baseline` in this PR.
- **Raw NUL byte removed from `test/egress-gate/surrogate-helper-daemon-plist.test.ts`**
  (line 140, inside the control-character refusal case), replaced by the `\u0000`
  escape, which is the same string value. The raw byte made git classify the file
  as binary, so no diff of it was reviewable. 15 of 15 still pass.
- All local gates re-run on this host; the fail-before witnesses re-captured and the
  OWED ones from the Job 3 and Job 4 tables run in guard-removed form. Results are in
  the coordinator repo, `Review/Sanctuary/Credential_Surrogacy_Slice1a_BUILD_REPORT_2026-10-01.md`.

## Fix round before push (2026-10-01, coordinator's Mac)

- Design section 5 item 16 witnesses added to `test/egress-gate/arming-wiring.test.ts`
  (+4): degrade stops the helper after the gate and resolver and before the first
  surface removal; degrade THROWS with nothing removed when the helper cannot be
  stopped; degrade treats a not-loaded helper as stopped; unprotect THROWS naming the
  helper label when only the helper fails to stop. Each degrade case halts the flow
  with a sentinel at the first `removeFile`, so even a regressed guard can never reach
  the un-seamed anchor registry on the host.
- New `test/egress-gate/surrogate-helper-real-wire.test.ts` (4): the operator CLI's
  real unlock-socket client against a real helper over a temp-dir socket; the argv
  entry `runSurrogateHelperDaemonFromArgv` (uid refusal, and absent-table refusal);
  the `castle-wall surrogate-helper-daemon` verb in the built CLI.
- `server/src/README.md` `egress-gate` row: the stale "NOT built yet" sentence now
  describes the built listeners.
- `.test-baseline` 16787 to 16795 (+8 tests, none platform-gated).
- `test/fixtures/typecheck-tests-baseline.txt` re-recorded at the same count (979):
  the inserted tests shifted 24 existing diagnostics' line numbers.

## Suite pins (2026-10-01)

The coordinator's pre-push full suite failed 7 tests in 5 files, all consistency pins
the new matrix row and the new module move: `EXPECTED_ASSURANCE_ROW_COUNT` 27 to 28 in
`scripts/synthetic-coverage/assurance-matrix.ts`; `CONTRIBUTING.md` module-map counts
62 to 63 modules and 54 to 55 barrels; `scripts/synthetic-coverage/coverage-baseline.json`
regenerated with `npm run synthetic-coverage:baseline` (adds row 28, `partial`,
`no_fixture`). No test was added or removed, so `.test-baseline` stays 16795.
