/**
 * Shared analyzer: which MCP tools classified `read` can reach a durable-state
 * MUTATION, or a subprocess, from inside their own handler.
 *
 * This module is the mechanism. `read-tool-mutation-reachability.test.ts` is the
 * assertion layer and carries the property statement, the scope bound, and the
 * justified residual. Both live off one analyzer so the guard and any future
 * report can never disagree about what was measured (same lesson as
 * `public-surface-extract.ts` / `public-surface-snapshot.test.ts`).
 *
 * HOW IT WORKS
 *
 *   1. Build a `ts.Program` over `server/src` from the shipping `tsconfig.json`,
 *      so the file set analyzed is exactly the file set compiled.
 *   2. Read the classification tables out of `src/index.ts` BY AST. Nothing here
 *      restates a tool name: the target list is derived from the same literal
 *      the server classifies from, because a guard that hand-lists its own
 *      targets only ever checks the entries its author happened to remember.
 *   3. Find every `ToolDefinition` object literal in `src` (a literal with both
 *      a resolvable `name` and a `handler`) and take the handler function node.
 *      A `handler` holding a REFERENCE rather than a function literal is
 *      resolved to the declarations behind it; one that resolves to no walkable
 *      body is reported, never analyzed as reaching nothing.
 *   4. From each handler, walk the call graph with the type checker, following
 *      calls into any function declared under `src`, and report the sites that
 *      reach a durable-state mutation primitive or a subprocess.
 *
 * SINKS (what counts as an escape from the read claim)
 *
 *   - Anything under `src/storage/**` that is not on `STORAGE_READ_ONLY`. This
 *     rule is INVERTED deliberately: see the boundary note below.
 *   - The mutating `node:fs` entry points, for a path that skips the storage
 *     backend. Matched against the `@types/node` `fs` / `fs/promises`
 *     declaration files specifically, so an unrelated library's same-named
 *     `.d.ts` export (`write`, `link`, `cp`) is not mistaken for the primitive.
 *   - The `node:child_process` spawn entry points. A subprocess leaves the
 *     process entirely, so nothing downstream of this analyzer can bound what
 *     it does; keychain mutation reaches the `security` binary this way.
 *   - A `callPrimitive("<tool>", ...)` dispatch naming a write-classified tool.
 *
 * WHY THE STORAGE BOUNDARY RULE IS INVERTED. An earlier revision stopped at
 * every declaration under `src/storage/**` and treated only `write` and
 * `delete` as sinks, so any OTHER durable primitive in that directory was
 * walked into, dropped, and never reported: `writeDurable`, `writeFileCustody`,
 * `chownCreatedDirChain` and `tightenStoragePermissions` were all invisible,
 * and the next primitive added there would have been invisible too. The rule is
 * now the other way round — a storage declaration is a sink UNLESS it is named
 * on the read-only allowlist — so an unrecognized primitive fails closed as a
 * reported sink rather than vanishing into a clean result.
 *
 * AUDIT-CHAIN APPENDS ARE DELIBERATELY NOT SINKS. Every read tool in this tree
 * records the read it performed, and the router routes read tools through
 * `runAllowingIntegrityFindings` precisely so that record still lands when the
 * chain has findings. An append is therefore the expected behavior of a correct
 * read tool and cannot discriminate one classification from the other. The
 * analyzer still CLASSIFIES appends (`audit_append`) so a caller can report
 * them; the test asserts only on mutations and subprocesses.
 *
 * SOUNDNESS BOUND, STATED SO THE CLAIM DOES NOT EXCEED THE REACH. This is a
 * static, checker-resolved call graph. It is an UNDER-approximation of what a
 * handler can reach, and, in ONE respect stated first because it is the newer
 * direction and the easier one to be surprised by, an OVER-approximation:
 *
 *   - A FUNCTION HANDED OVER AS A VALUE IS TREATED AS REACHED, WHETHER OR NOT
 *     THE CALLEE EVER INVOKES IT. Resolving a callable argument is what catches
 *     a primitive that is passed rather than called, and deciding whether the
 *     receiving function actually calls its parameter is a dataflow question
 *     this analyzer does not answer. So `keep(execSync)`, for a `keep` that
 *     drops its argument, is reported as reaching a subprocess and is a FALSE
 *     POSITIVE by construction. That is the right side to err on for a
 *     must-not-reach guard: an over-approximation costs a review of a hit that
 *     turns out to be inert, and the reviewer has the code in front of them,
 *     while an under-approximation costs a mutation that no one ever sees. The
 *     failure that this whole file exists to prevent is absent reading as
 *     passing, and a guard tuned to avoid false alarms is tuned toward exactly
 *     that. No instance exists on the real tree today. When one appears, the
 *     answer is to stop handing the primitive over, never to pin it: see the
 *     residual-pin bullet below.
 *
 * Everything else below is the under-approximating half:
 *
 *   - A call made through a value the checker cannot resolve to a declaration
 *     (a dynamically indexed method, an `unknown`-typed dispatch) is not
 *     followed. The one runtime dispatch that IS followed is `callPrimitive`,
 *     because its first argument is a string literal at every call site; see
 *     `PRIMITIVE_DISPATCH_FUNCTIONS`.
 *   - THE LARGEST REMAINING GAP, MEASURED RATHER THAN GUESSED: a call through an
 *     INJECTED function-typed dependency is not followed, because resolving it
 *     needs dataflow (which object literal supplied that property, at which
 *     construction site, reaching this call), not a syntactic lookup. Tracked as
 *     a separate build under ABC-READCLASS-01; it is NOT closed here and no
 *     result below should be read as covering it. Neither the mechanism that
 *     defeats the lookup nor a spelling of it is written out here, because the
 *     class is open and this file ships in a public repository; the register
 *     entry carries the detail.
 *
 *     THE COUNT IS STATED WITH ITS METHOD, because it moves by a factor of four
 *     with the method and a bare number here was wrong twice. Counting UNIQUE
 *     `path:line` call sites, on a walk over the read tools only, where the
 *     walk finds no `src` declaration carrying a body and the callee's resolved
 *     declaration is a property signature or parameter whose declared TYPE NODE
 *     is a function type or type literal: 18 sites, being 17 function-typed
 *     property signatures on options/deps interfaces (`currentSessionBinding`,
 *     `getProfile`, `verifyIdentity`, `getRuntimeSignals`, the
 *     `ToolDefinition.handler` member itself) and 1 callback parameter. The
 *     same tree gives 52 counting per walk VISIT rather than per location, and
 *     13 taking "function-typed" to mean "the checker's type of the member is
 *     callable", which drops the optional `f?: () => void` members. Whichever
 *     is used, the number is unchanged by the laundering closure below: it is a
 *     different class and closing one does not touch the other.
 *   - An interface member call IS followed into the classes that syntactically
 *     `implements` that interface in `src`, for both method signatures
 *     (`save(x): void`) and function-typed property signatures
 *     (`save: (x) => void`). THE PROPERTY-SIGNATURE SPELLING IS INERT TODAY and
 *     is not claimed otherwise: of 685 function-typed property-signature
 *     members across 363 interfaces in `src`, the implements-index resolves 0,
 *     so that branch fixes no call site. It is wired so that adding such an
 *     implementation fails closed rather than going silently unwalked. It does
 *     not touch the injected-dependency gap above, because an injected property
 *     is supplied by an object literal rather than by a class declaring
 *     `implements`.
 *   - A `new X()` IS followed into `X`'s own constructor. A base-class
 *     constructor reached only through an implicit `super()` is not followed.
 *   - AN INTERPOSED SOURCE-LOCAL BINDING NO LONGER LAUNDERS A BUILTIN SINK.
 *     Classification and the walk resolve the callee ONCE, through the same
 *     chokepoint (`createCalleeResolver`), from four sources of the same
 *     target: the callee's own declarations, the expansion of those, the callee
 *     type's call signatures, and the indirect targets a reflective or
 *     type-wrapped call site puts somewhere other than the callee.
 *
 *     WHAT IS CLOSED IS AN ENUMERATION, NOT A CATEGORY. This paragraph twice
 *     carried a category claim ("this is where syntax runs out"), and twice a
 *     later attack found a syntactic shape outside it. A category is not
 *     something this analyzer can establish, so it no longer claims one. The
 *     shapes closed, each pinned as a must-fail fixture in the test file, are
 *     exactly: a destructured namespace import; a bare aliased `const`; an
 *     annotated `const` whose annotation erases the target; an object-literal
 *     property; a getter handing the function back; a getter returning it
 *     behind a cast; a class field; a default parameter; a default parameter
 *     carrying a cast; a destructure out of an array; a destructured dynamic
 *     `import`; a destructure of a cast namespace; a re-export chain; a
 *     wildcard re-export; a `.bind()`; a conditional selecting between two
 *     functions; a factory return; a generic identity function; an `await`ed
 *     promise; a `Map` lookup; an object spread of a namespace import; an
 *     `Object.assign` target; a computed key on an object literal; an indexed
 *     access on a namespace import; a callee the call site does not name at
 *     all; an optional call; the five type-only wrappers (`as`, `satisfies`,
 *     parentheses, `!`, and the angle-bracket assertion) on an initializer AND
 *     at the call site; `.call`; `.apply`; `Reflect.apply`; a function handed
 *     over as a VALUE at a call site rather than called at it; and those
 *     composed with any receiver shape above.
 *
 *     TWO MORE INVOCATION SITES ARE NOW VISITED, and they are reach rather than
 *     resolution, so they are not fixture-pinnable in the corpus (which
 *     resolves call sites without walking bodies): a tagged template, whose tag
 *     is a callee like any other, and a `handler:` property holding a reference
 *     rather than a function literal. Both are verified by planting the shape
 *     into a real read handler and confirming the guard reds.
 *
 *     WHAT REMAINS OPEN IS NOT ENUMERATED HERE and is deliberately not pinned
 *     as a fixture: a fixture is a copy-pasteable spelling, so a fixture for an
 *     unclosed shape is a working evasion published against a live guard, and
 *     an enumeration in prose is most of the way to the same thing. Spellings
 *     that put the target somewhere this resolver does not look remain, they
 *     resolve only in the private register under ABC-READCLASS-01, and no count
 *     is given: the count in this paragraph has been wrong at every previous
 *     revision, and a wrong count reads as an assurance. THE SAME RULE IS
 *     APPLIED TO THE WALK-LEVEL BOUNDS FURTHER DOWN, so both halves of this
 *     file's open surface are described the same way. An earlier revision made
 *     this trade for the resolver and declined it for the walk, which was an
 *     accident rather than a judgement; that they now match is a decision.
 *
 *     THE VALUE PATH INHERITS THE CALLEE PATH'S BOUND, stated because closing
 *     one is easily read as closing more than it does. An argument is resolved
 *     by exactly the same chokepoint as a callee, so it reaches what a callee
 *     reaches and stops where a callee stops. Where a target is hidden from
 *     that resolution, moving it into an argument position does not reveal it.
 *     That residue shares the MECHANISM of the measured dataflow gap above (a
 *     declared type standing where a declaration would be, so there is nothing
 *     with a body to resolve to), but THE 18-SITE COUNT DOES NOT BOUND IT: that
 *     count's stated method admits only a property signature or a parameter,
 *     and the value path's residue includes declarations the method excludes by
 *     construction. Carrying the number across would be quoting a measurement
 *     outside the class it measured, which is the same defect as a count with
 *     no method. No count is given for the value path; the register entry under
 *     ABC-READCLASS-01 carries the detail.
 *   - Traversal stops AT the storage and audit-log module boundaries: a call
 *     into one of those is classified (sink, append, or read-only) and its body
 *     is not walked, because the question this guard answers is which primitive
 *     a tool reaches, not how that primitive is implemented. Both boundaries
 *     use the INVERTED rule, so an unrecognized entry point is a reported sink
 *     rather than a silent pass. What the audit-log boundary DOES hide, and
 *     this is a real gap rather than a tidy one: chain maintenance below a
 *     read-only entry point, which includes a head-anchor self-heal, a legacy
 *     checkpoint record, an integrity-alert record, write-lock files, and a
 *     cached `sysctl` subprocess for the boot id. Those are uniform across
 *     every caller of a given entry point, so they cannot discriminate one
 *     tool's classification from another's, but a `verify*` entry point on this
 *     module can and does write inside the boundary.
 *   - The residual pin is per primitive, per enclosing function, per immediate
 *     caller. A SECOND call to the SAME primitive inside an ALREADY-pinned
 *     function reached from the SAME caller is not distinguished from the first
 *     one. Closing that needs a statement-level (line-numbered) pin, which
 *     would churn on every edit above it. A COROLLARY THAT FOLLOWS FROM THAT
 *     COARSENESS: a hit whose argument is never invoked must not be pinned as a
 *     reviewed residual, however obviously inert it is. Pinning it blesses the
 *     whole triple, after which a REAL call to that primitive from that
 *     function through that caller passes silently — a false positive would
 *     have been converted into a blind spot by the review itself. Remove the
 *     handover instead.
 *   - `proxy/*` tools are named at runtime from an upstream catalog and are
 *     forced `write` at classification time, so they are outside this analysis.
 *   - THE WALK IS NOT TOTAL OVER INVOCATION OR OVER DISPATCH, and this is the
 *     bound rather than an oversight. It visits some invocation forms and not
 *     others, and it follows some ways one declaration stands in for another
 *     and not others, so a body can run without this analyzer reaching it. A
 *     bounded number of syntactic and dataflow shapes remain open on both
 *     counts. WHICH ONES IS NOT WRITTEN DOWN HERE, and neither is a count of
 *     them: this file ships in a public repository, an open shape named in
 *     prose is most of the way to a working evasion of a live guard, and a
 *     count of open shapes reads as an assurance that the rest are closed. They
 *     resolve in the private register under ABC-READCLASS-01. The corresponding
 *     honesty obligation is discharged by stating plainly that the coverage is
 *     partial, which is what this bullet does; softening it further would not
 *     be permitted, and describing the shapes is not required to state it.
 *     Read the laundering corpus narrowly for the same reason: a fixture there
 *     pins exactly the shape it spells and nothing adjacent to it.
 *   - THE FOUR TRAVERSAL CAPS FAIL OPEN, THOUGH NO LONGER SILENTLY BEYOND
 *     THEMSELVES. Call depth, alias hops, cast hops, and reflective hops each
 *     stop on exhaustion with nothing recorded, so exhausting one is
 *     indistinguishable from finding nothing ALONG THAT PATH. It can no longer
 *     do worse than that: a descent refused by the depth ceiling leaves the
 *     walk's memo untouched (`admitDescent`), so exhaustion cannot suppress a
 *     sink on a shorter, unrelated path that reaches the same pair. It could,
 *     until this revision. This remains the file's own exception to its thesis,
 *     which is why it is stated at the claim rather than left to a reader of
 *     the constants. Recording a truncation and asserting there are none is the
 *     remaining fix; it is not built here.
 *   - THE LAUNDERING CLOSURE HAS NO REAL-TREE WITNESS. With the expanded-set
 *     classification disabled, every real-tree assertion in the test still
 *     passes and only the synthetic corpus reds. The corpus is that closure's
 *     ONLY evidence. That is defensible for a class the tree does not currently
 *     contain, and it is stated so a green real-tree result is not read as
 *     evidence for the closure.
 *
 * A clean result therefore means "no mutation is reachable along a
 * statically resolvable path", not "no mutation is possible".
 */

import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const HERE = resolve(fileURLToPath(import.meta.url), "..");
/** test/structure -> test -> server */
const SERVER_DIR = resolve(HERE, "..", "..");
const SRC_DIR = join(SERVER_DIR, "src");
const INDEX_FILE = join(SRC_DIR, "index.ts");
const STORAGE_DIR = join(SRC_DIR, "storage");
const AUDIT_LOG_FILE = join(SRC_DIR, "operational", "audit-log.ts");

/**
 * Declarations under `src/storage/**` that read, compute, or verify and never
 * mutate durable state. THIS LIST IS THE EXCEPTION, NOT THE RULE: anything
 * declared in that directory and absent from this set is reported as a mutation
 * sink. Adding a primitive there and forgetting this file therefore reds the
 * guard instead of silently widening what a read tool may reach.
 *
 * Deliberately ABSENT (i.e. treated as sinks), so the reasoning is on the
 * record: `write`, `writeDurable`, `delete`, `deleteAtPath`, `writeFileCustody`,
 * `atomicWriteFile`, `prepareTemp`, `fsyncDirectory`, `chownCreatedDirChain`,
 * `tightenStoragePermissions`, `tightenEntry`, `tightenMode`, `clear`, and the
 * two lock helpers `withCrossProcessLock` / `withPathLock` (a lock acquisition
 * creates a file, so a read path taking one is a reviewable event, not a
 * silent one).
 */
const STORAGE_READ_ONLY: ReadonlySet<string> = new Set([
  // reads
  "read",
  "readAtPath",
  "readFileCustody",
  "readFileCustodyWithStats",
  "list",
  "listNamespaces",
  "exists",
  "totalSize",
  // read-only handle lifecycle
  "openDirectoryCustodyWithinBase",
  "openExistingDirectoryNoFollow",
  "openNoFollowPathWithinBase",
  "openReadHandle",
  "revalidate",
  "close",
  // verification (throws on mismatch; writes nothing)
  "verifyDirectoryCustodyWithinBase",
  "verifyDirectoryGuardStats",
  "verifyDirectoryStats",
  "verifyParentCustody",
  "sameFile",
  // pure path / name computation
  "namespacePath",
  "encodedNamespacePath",
  "entryPath",
  "legacyEntryPath",
  "storageKey",
  "legacyKeySanitize",
  "legacyNamespaceSanitize",
  "bijectiveEncode",
  "bijectiveDecode",
  // pure predicates, error shaping, capability probing
  "asFilesystemCapabilities",
  "errorMessage",
  "fileMode",
  "isBenignMissing",
  "isCustodyFsError",
  "modeRejected",
  "readTransientError",
  "throwModeRejected",
  "sleep",
  // Caller-supplied observation hooks. Treating the hook itself as a sink would
  // misattribute the site: the callback is what runs, and the callback IS
  // walked, whether it is written inline at the call site or passed by name.
  // The by-name half of that was an assumption until the resolver started
  // resolving function-valued arguments; before that this justification held
  // only for an inline arrow, which is what every call site happened to use.
  "onContended",
  "onDescriptorVerified",
  // Runs a caller-supplied callback under a different effective identity. Not a
  // durable-state write in itself; same justification as the two hooks above.
  "withOwnerEffectiveIdentity",
]);

/**
 * Append entry points on `AuditLog` (`src/operational/audit-log.ts`).
 * Classified for reporting only — see the header on why these are not sinks.
 */
const AUDIT_APPENDERS: ReadonlySet<string> = new Set([
  "append",
  "appendCritical",
  "appendVisible",
  "enqueueAppend",
]);

/**
 * Audit-log ENTRY POINTS (members called from outside `audit-log.ts`) that read,
 * verify, derive, or fold and do not create a new durable record of their own.
 * Inverted the same way as `STORAGE_READ_ONLY`: an entry point in that file
 * absent from this set and from `AUDIT_APPENDERS` is reported as a sink, so a
 * new public mutating entry point there fails closed. The three that are
 * deliberately ABSENT today are `writeAuditEpochRecord`,
 * `writeAuditStoreSplitBoundary` and `writeAuditStoreSplitEstablishedMarker`.
 *
 * The boundary is at the entry point, not the whole file: chain internals below
 * it (lock acquisition, head-anchor self-heal, checkpoint and integrity-alert
 * records, the cached boot-id probe) are uniform across every caller of a given
 * entry point and so cannot discriminate one tool's classification from
 * another's. That is a real bound and it is stated in the header, because a
 * `verify*` entry point on this module CAN write inside the boundary.
 */
const AUDIT_LOG_READ_ONLY: ReadonlySet<string> = new Set([
  "auditChainVerdictClaimsClean",
  "auditChainVerdictSealedUnverifiedAtPrivilege",
  "auditChainVerdictUntampered",
  "auditStoreSplitBoundaryPath",
  "authenticatedRotationFloor",
  "deriveAuditEpochKeys",
  "deriveAuditStoreSplitBoundaryMacKey",
  "foldAuditChainVerdict",
  "getAuditChainVerdict",
  "getChainHead",
  "getIntegrityFindings",
  "getRetentionConfig",
  "getRetentionUsage",
  "getWriteLockRecoveryCount",
  "isHardIntegrityFinding",
  "onWriteLockRecovery",
  "probeAuditHeadAnchor",
  "query",
  "queryEager",
  "readAuditEpochEntries",
  "readAuditEpochKeys",
  "readAuditStoreSplitBoundary",
  "readAuditStoreSplitEstablishedMarker",
  "readCustodyEpochCount",
  "runEagerReads",
  "streamVerifiedChain",
  "verifySealedRegion",
  "verifySealedRegionAt",
  // Drains writes that `append` already queued; it creates no record of its
  // own, and appends are not sinks by the rule above.
  "flush",
  // Runs a caller-supplied callback; the callback is walked whether it is
  // written inline or passed by name, so treating the wrapper as a sink would
  // misattribute the site. Same note as the storage hooks: the by-name half of
  // this justification became true when the resolver started resolving
  // function-valued arguments, and was an assumption before that.
  "runAllowingIntegrityFindings",
]);

/**
 * Mutating `node:fs` entry points. Covers the callback and sync spellings from
 * `fs.d.ts` and the promise spellings from `fs/promises.d.ts`, which share
 * these names, so one entry per name serves both.
 *
 * This set is matched ONLY against the `@types/node` fs declaration files (see
 * `FS_DECL_FILE`), never against any declaration file, because names like
 * `write`, `link`, `cp` and `rename` are common enough to collide with an
 * unrelated library's typings.
 *
 * NOT included, and deliberately: `open`/`openSync` (the mutating intent lives
 * in the flags argument, which this analyzer does not evaluate) and the
 * `FileHandle` methods reached from an already-open handle. Both are named in
 * the soundness bound rather than guessed at.
 */
const FS_MUTATORS: ReadonlySet<string> = new Set([
  "writeFile",
  "writeFileSync",
  "write",
  "writeSync",
  "writev",
  "writevSync",
  "appendFile",
  "appendFileSync",
  "mkdir",
  "mkdirSync",
  "mkdtemp",
  "mkdtempSync",
  "rm",
  "rmSync",
  "rmdir",
  "rmdirSync",
  "unlink",
  "unlinkSync",
  "rename",
  "renameSync",
  "copyFile",
  "copyFileSync",
  "cp",
  "cpSync",
  "symlink",
  "symlinkSync",
  "link",
  "linkSync",
  "truncate",
  "truncateSync",
  "ftruncate",
  "ftruncateSync",
  "chmod",
  "chmodSync",
  "fchmod",
  "fchmodSync",
  "lchmod",
  "lchmodSync",
  "chown",
  "chownSync",
  "fchown",
  "fchownSync",
  "lchown",
  "lchownSync",
  "utimes",
  "utimesSync",
  "futimes",
  "futimesSync",
  "lutimes",
  "lutimesSync",
  "createWriteStream",
]);

/**
 * `node:child_process` entry points that start a process. A subprocess leaves
 * this process entirely, so no analysis downstream of here can bound what it
 * writes — keychain mutation, for one, leaves through the `security` binary.
 * Reported as its own kind so a residual can say "this is a probe" without the
 * report having to call a subprocess a storage write.
 */
const CHILD_PROCESS_SPAWNERS: ReadonlySet<string> = new Set([
  "exec",
  "execSync",
  "execFile",
  "execFileSync",
  "spawn",
  "spawnSync",
  "fork",
]);

/**
 * Runtime dispatchers whose first argument is a string-literal tool name at
 * every call site, so the edge IS statically resolvable even though the call is
 * dynamic. `callPrimitive` (`src/agent-native/cooperative-surface.ts`) looks a
 * primitive tool up by name and invokes its handler; without this the one
 * module that mixes read and write tools in a single factory would report a
 * clean graph for a handler that reaches a write through the lookup.
 */
const PRIMITIVE_DISPATCH_FUNCTIONS: ReadonlySet<string> = new Set(["callPrimitive"]);

/**
 * Depth ceiling for the call-graph walk. Not a semantic limit: the walk already
 * memoizes each function body per tool, so it terminates on its own. This only
 * bounds a pathological chain.
 *
 * IT FAILS OPEN, and an earlier version of this comment claimed the opposite —
 * that it "keeps a stack overflow from reading as a pass". Exhausting it IS a
 * pass: the walk returns with nothing recorded and the result is
 * indistinguishable from a clean one. The same is true of the three hop
 * ceilings below. The bound is stated in the header rather than only here,
 * because a cap that fails open in a file whose thesis is that absent must not
 * read as passing is the file's own exception and has to be visible from the
 * claim, not just from the constant.
 */
const MAX_CALL_DEPTH = 60;

/**
 * Hop ceiling for following `const a = b` initializer REFERENCES. Small on
 * purpose: this is alias chasing, not a call graph, and a chain longer than
 * this in real code is a finding of its own. The cap is also what terminates a
 * mutually-referential pair (`let a = b; let b = a`).
 */
const MAX_ALIAS_HOPS = 4;

/**
 * Hop ceiling for stripping type-only wrappers off an initializer. Five is the
 * count of wrapper node kinds stripped (`as`, `satisfies`, parentheses, `!`,
 * and the angle-bracket assertion), doubled, because a hand-written chain
 * alternates them (`(x as unknown) as F`) rather than repeating one. A cap
 * rather than plain recursion so a synthesized cycle cannot hang the guard.
 */
const MAX_CAST_HOPS = 10;

/**
 * Hop ceiling for following a reflective invocation to its real target. Bounds
 * the pathological `f.call.call.call(...)` spelling; two hops is already beyond
 * anything that appears in this tree.
 */
const MAX_REFLECTIVE_HOPS = 4;

export type SinkKind = "mutation" | "subprocess" | "audit_append";

export interface SinkHit {
  /** "mutation"/"subprocess" gate the guard; "audit_append" is only reported. */
  kind: SinkKind;
  /** e.g. `storage.write`, `fs.writeFileSync`, `child_process.execSync`. */
  primitive: string;
  /** `<enclosingFunction>@<path relative to server/>` — stable across edits. */
  site: string;
  /**
   * The frame that called into `site`, same shape, or undefined when the sink
   * sits directly in the handler. This is what lets a residual pin a specific
   * caller of a shared helper instead of pre-approving every future caller of
   * it — see `REVIEWED_READ_PATH_MAINTENANCE` in the test.
   */
  caller: string | undefined;
  /** Call chain from the handler, for a failure message that names the path. */
  via: string[];
}

export interface ToolClassification {
  /** Names in `READ_MCP_TOOLS` in `src/index.ts`. */
  readTable: string[];
  /** Names in `WRITE_MCP_TOOLS` in `src/index.ts`. */
  writeTable: string[];
  /** Names in `OPERATOR_TERMINAL_ONLY_MCP_TOOLS` in `src/index.ts`. */
  operatorTable: string[];
  /** Tool literals carrying an inline `tool_class: "read"`. */
  inlineRead: string[];
  /** Tool literals carrying an inline `tool_class: "write"`. */
  inlineWrite: string[];
  /**
   * Anti-vacuity for the TABLE half of the target set, and the counterpart of
   * `inlineAntiVacuity` below. One entry per element of a classification table
   * that this parser could not read as a string literal. The shipping router
   * builds the same `Set` at runtime and classifies from it either way, so a
   * skipped element removes a tool from this analysis while leaving it fully
   * classified in production. Asserted empty by the test.
   */
  unparsableTableElements: string[];
}

export interface ReachabilityReport {
  classification: ToolClassification;
  /** Every tool the server can classify `read`: the table plus the inline set. */
  readTools: string[];
  /** tool name -> `<path>:<line>` of its handler, for coverage assertions. */
  handlerLocations: Map<string, string>;
  /**
   * Read-classified tools this analyzer could not start a walk from: no tool
   * literal was found for the name, or a literal was found whose `handler`
   * could not be resolved to a function body under `src`. Both cases would
   * otherwise report zero sinks and read exactly like a clean tool, and eight
   * read tools legitimately report zero sinks today, so a newly-zeroed one
   * would be invisible. The entry names which of the two it was.
   */
  unresolvedHandlers: string[];
  /**
   * Every tool-literal name the analyzer resolved, across the whole tree and in
   * source order, duplicates PRESERVED. The handler map is first-wins, so two
   * literals sharing a name means the second was analyzed as if it did not
   * exist. This is the full set rather than the inline-classified subset,
   * because the table-classified tools are the majority and had no duplicate
   * check at all.
   */
  resolvedToolLiteralNames: string[];
  /**
   * Anti-vacuity for the INLINE half of the target set, and the third of the
   * three backstops rather than the second of two. A table ELEMENT this parser
   * cannot read lands in `classification.unparsableTableElements`; a parsed
   * table NAME with nothing behind it lands in `unresolvedHandlers`; an inline
   * tool literal whose `tool_class` or `name` cannot be parsed would drop out
   * of the analyzed set with no signal at all while the shipping router still
   * classifies it and still grants the bypass. These three fields are what make
   * that last drop loud.
   */
  inlineAntiVacuity: {
    /**
     * One entry per object literal carrying `tool_class: "read"`, a `handler`,
     * AND a name the analyzer resolved. Duplicates are preserved on purpose:
     * two literals sharing a name means the handler map silently kept only the
     * first, so the test asserts this list is duplicate-free as well as
     * equal to the parsed inline set.
     */
    resolvedReadLiteralNames: string[];
    /** Same, for `tool_class: "write"`. */
    resolvedWriteLiteralNames: string[];
    /**
     * Files with a tool literal whose `tool_class` is present but is NOT a
     * string literal, so this extractor cannot read it. The SHIPPING router
     * compares the runtime value, so `("re" + "ad")` classifies read and grants
     * the bypass while this analyzer drops the tool from its target set — a
     * silent hole rather than a loud one. Reported so it reds instead.
     */
    unparsableToolClassLiterals: string[];
    /**
     * Files holding tool-shaped object literals whose `name` did not resolve,
     * so they were never analyzed. Deduplicated paths, no line numbers. The
     * runtime-named families are dispositioned in the test rather than skipped
     * here, so this list is the raw measurement.
     */
    unresolvableToolLiterals: string[];
  };
  /** tool name -> sink hits, for every read-classified tool that has any. */
  hits: Map<string, SinkHit[]>;
}

interface Analyzer {
  program: ts.Program;
  checker: ts.TypeChecker;
  handlers: Map<string, { node: ts.Node; location: string }>;
  classification: ToolClassification;
  inlineAntiVacuity: ReachabilityReport["inlineAntiVacuity"];
  resolvedToolLiteralNames: string[];
  /** False when the handler literal exists but resolves to no walkable body. */
  handlerWalkable(tool: string): boolean;
  sinksFor(tool: string): SinkHit[];
}

let cached: Analyzer | undefined;

function relPath(fileName: string): string {
  return relative(SERVER_DIR, fileName);
}

function lineOf(node: ts.Node): number {
  const sf = node.getSourceFile();
  return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
}

function locate(node: ts.Node): string {
  return `${relPath(node.getSourceFile().fileName)}:${lineOf(node)}`;
}

/** True for the `@types/node` fs typings, so `FS_MUTATORS` cannot cross-match. */
function isFsDeclarationFile(fileName: string): boolean {
  return (
    fileName.endsWith("/@types/node/fs.d.ts") ||
    fileName.endsWith("/@types/node/fs/promises.d.ts")
  );
}

/** True for the `@types/node` child_process typings, same reason. */
function isChildProcessDeclarationFile(fileName: string): boolean {
  return fileName.endsWith("/@types/node/child_process.d.ts");
}

function propertyKey(prop: ts.ObjectLiteralElementLike): string | undefined {
  if (!ts.isPropertyAssignment(prop) && !ts.isMethodDeclaration(prop)) return undefined;
  const name = prop.name;
  if (ts.isIdentifier(name) || ts.isStringLiteral(name)) return name.text;
  return undefined;
}

/**
 * Resolve a tool literal's `name` to a string. Handles a direct literal and a
 * reference into an as-const name table (`COOPERATIVE_TOOL_NAMES.recall` in
 * `src/agent-native/tool-names.ts`), which is how the cooperative surface names
 * its tools. Returns undefined for a name computed at runtime (`proxy/*`),
 * which is out of scope by construction — see the header.
 */
function resolveToolName(
  expr: ts.Expression,
  checker: ts.TypeChecker
): string | undefined {
  if (ts.isStringLiteralLike(expr)) return expr.text;
  if (!ts.isPropertyAccessExpression(expr) && !ts.isIdentifier(expr)) return undefined;
  const symbol = checker.getSymbolAtLocation(
    ts.isPropertyAccessExpression(expr) ? expr.name : expr
  );
  for (const decl of symbol?.getDeclarations() ?? []) {
    if (ts.isPropertyAssignment(decl) && ts.isStringLiteralLike(decl.initializer)) {
      return decl.initializer.text;
    }
    if (
      ts.isVariableDeclaration(decl) &&
      decl.initializer !== undefined &&
      ts.isStringLiteralLike(decl.initializer)
    ) {
      return decl.initializer.text;
    }
  }
  return undefined;
}

/**
 * Read a `const X: ReadonlySet<string> = new Set([...] as const)` table.
 *
 * Returns the names AND the elements it could not read, because those two are
 * the same measurement: the shipping `classifyMcpTools` builds this `Set` at
 * RUNTIME, so an element this parser drops (a spread, a template with a
 * substitution, an identifier) is still classified `read` by the router and
 * still granted the audit-integrity bypass, while silently leaving the analyzed
 * target set. A dropped element used to be indistinguishable from a shorter
 * table; the `toBeGreaterThan` floor on the table length cannot see one tool
 * go missing. Absent must not read as passing, so the skips are reported and
 * the test asserts there are none.
 */
function readNameTable(
  source: ts.SourceFile,
  tableName: string
): { names: string[]; skipped: string[] } {
  const names: string[] = [];
  const skipped: string[] = [];
  const arrayOf = (expr: ts.Expression | undefined): ts.ArrayLiteralExpression | undefined => {
    if (expr === undefined) return undefined;
    if (ts.isArrayLiteralExpression(expr)) return expr;
    // `[...] as const` and `<const>[...]` both wrap the array in an assertion.
    if (ts.isAsExpression(expr) || ts.isTypeAssertionExpression(expr)) {
      return arrayOf(expr.expression);
    }
    return undefined;
  };
  const visit = (node: ts.Node): void => {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.name.text === tableName &&
      node.initializer !== undefined &&
      ts.isNewExpression(node.initializer)
    ) {
      const argument = node.initializer.arguments?.[0];
      const array = arrayOf(argument);
      if (array === undefined && argument !== undefined) {
        // The whole table is unreadable, which is worse than one element.
        skipped.push(`${tableName}: whole initializer at ${locate(argument)}`);
      }
      for (const element of array?.elements ?? []) {
        if (ts.isStringLiteralLike(element)) {
          names.push(element.text);
          continue;
        }
        skipped.push(
          `${tableName}: <${ts.SyntaxKind[element.kind]}> element at ${locate(element)}`
        );
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return { names, skipped };
}

function enclosingFunctionName(node: ts.Node): string {
  for (let cursor: ts.Node | undefined = node; cursor; cursor = cursor.parent) {
    if (ts.isMethodDeclaration(cursor) || ts.isFunctionDeclaration(cursor)) {
      return cursor.name && ts.isIdentifier(cursor.name) ? cursor.name.text : "<anonymous>";
    }
    if (ts.isConstructorDeclaration(cursor)) {
      const cls = cursor.parent;
      const owner = ts.isClassDeclaration(cls) && cls.name ? cls.name.text : "<anonymous>";
      return `${owner}.constructor`;
    }
    if (ts.isArrowFunction(cursor) || ts.isFunctionExpression(cursor)) {
      const parent = cursor.parent;
      if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) return parent.name.text;
      if (ts.isPropertyAssignment(parent) && ts.isIdentifier(parent.name)) return parent.name.text;
      if (ts.isPropertyDeclaration(parent) && ts.isIdentifier(parent.name)) return parent.name.text;
    }
  }
  return "<module>";
}

/** `<enclosingFunction>@<path>` for a node — the stable frame identifier. */
function frameOf(node: ts.Node): string {
  return `${enclosingFunctionName(node)}@${relPath(node.getSourceFile().fileName)}`;
}

/**
 * The frame identifier for a declaration we are about to WALK INTO. Distinct
 * from `frameOf`, which reads the frame a node sits INSIDE: a declaration's own
 * name is the frame it establishes, and `enclosingFunctionName` would walk past
 * an arrow-initialized `const` to the module and lose it.
 */
function declarationFrame(decl: ts.Declaration): string {
  const file = relPath(decl.getSourceFile().fileName);
  if (ts.isConstructorDeclaration(decl)) {
    const owner =
      ts.isClassDeclaration(decl.parent) && decl.parent.name
        ? decl.parent.name.text
        : "<anonymous>";
    return `${owner}.constructor@${file}`;
  }
  const name = (decl as ts.NamedDeclaration).name;
  if (name !== undefined && (ts.isIdentifier(name) || ts.isStringLiteral(name))) {
    return `${name.text}@${file}`;
  }
  return frameOf(decl);
}

function functionBody(decl: ts.Declaration): ts.Node | undefined {
  if (
    ts.isFunctionDeclaration(decl) ||
    ts.isMethodDeclaration(decl) ||
    ts.isConstructorDeclaration(decl) ||
    ts.isGetAccessorDeclaration(decl)
  ) {
    return decl.body;
  }
  if (ts.isArrowFunction(decl) || ts.isFunctionExpression(decl)) return decl.body;
  if (
    ts.isVariableDeclaration(decl) ||
    ts.isPropertyDeclaration(decl) ||
    ts.isPropertyAssignment(decl)
  ) {
    const init = decl.initializer;
    if (init && (ts.isArrowFunction(init) || ts.isFunctionExpression(init))) return init.body;
  }
  return undefined;
}

/** A declaration that could carry a body, for the storage sink/opaque split. */
function isFunctionLike(decl: ts.Declaration): boolean {
  return (
    ts.isFunctionDeclaration(decl) ||
    ts.isMethodDeclaration(decl) ||
    ts.isMethodSignature(decl) ||
    ts.isConstructorDeclaration(decl) ||
    ts.isGetAccessorDeclaration(decl) ||
    ts.isArrowFunction(decl) ||
    ts.isFunctionExpression(decl) ||
    ((ts.isPropertySignature(decl) ||
      ts.isPropertyDeclaration(decl) ||
      ts.isVariableDeclaration(decl) ||
      ts.isPropertyAssignment(decl) ||
      ts.isBindingElement(decl)) &&
      true)
  );
}

/**
 * Strip the type-only wrappers off an expression, so the value underneath is
 * what gets resolved.
 *
 * These five node kinds all erase the target for symbol resolution while
 * changing nothing at runtime: `x as T`, `x satisfies T`, `(x)`, `x!`, and the
 * angle-bracket `<T>x`. A cast is therefore a one-token way to hide a primitive
 * behind an unrelated function type, which is exactly the laundering shape this
 * analyzer exists to refuse. Stripping is safe here because none of the five
 * can change WHICH function is called.
 */
function unwrapTypeOnly(expr: ts.Expression): ts.Expression {
  let current = expr;
  for (let hop = 0; hop < MAX_CAST_HOPS; hop += 1) {
    if (
      ts.isAsExpression(current) ||
      ts.isSatisfiesExpression(current) ||
      ts.isParenthesizedExpression(current) ||
      ts.isNonNullExpression(current) ||
      ts.isTypeAssertionExpression(current)
    ) {
      current = current.expression;
      continue;
    }
    return current;
  }
  return current;
}

/**
 * Further expressions that hold the same call's REAL target, when the callee
 * as written does not.
 *
 * Two shapes, both of which resolve to nothing useful from the callee alone:
 *
 *   1. A TYPE-ONLY WRAPPER at the call site. `(execSync as unknown as F)(cmd)`
 *      has no symbol on the parenthesized expression and a callee type that is
 *      the asserted `F`, so neither route reaches `execSync`. The stripped form
 *      does. It is returned ALONGSIDE the original rather than replacing it,
 *      because stripping is not always an improvement: `m.get("run")!(cmd)`
 *      resolves only WITH the `!`, since the unasserted type is
 *      `typeof execSync | undefined` and a union with `undefined` has no call
 *      signatures. Resolving both forms is what makes the strip monotone.
 *   2. A REFLECTIVE INVOCATION. `f.call(thisArg, …)`, `f.apply(thisArg, args)`
 *      and `Reflect.apply(f, thisArg, args)` all invoke `f` while naming
 *      `call`, `apply`, or `Reflect.apply` at the call site. Resolving only the
 *      callee finds `CallableFunction.call` in the standard library, which is
 *      in no sink set and lives outside `src`, so the primitive underneath goes
 *      unclassified AND unwalked: `execSync.call(null, "id")` spawns a
 *      subprocess and reports nothing at all. The receiver, or for
 *      `Reflect.apply` the first argument, is where the target survives.
 *
 * The receiver is passed on AS WRITTEN. Its own wrappers are stripped by rule 1
 * when this function runs again on it, which is also what keeps the `!` case
 * above working.
 */
function indirectTargets(
  callee: ts.Expression,
  args: readonly ts.Expression[]
): ts.Expression[] {
  const out: ts.Expression[] = [];
  const stripped = unwrapTypeOnly(callee);
  if (stripped !== callee) out.push(stripped);
  if (ts.isPropertyAccessExpression(callee) || ts.isPropertyAccessChain(callee)) {
    const member = callee.name.text;
    const receiver = unwrapTypeOnly(callee.expression);
    const isReflect = ts.isIdentifier(receiver) && receiver.text === "Reflect";
    if (member === "apply" && isReflect) {
      const first = args[0];
      if (first !== undefined) out.push(first);
    } else if (member === "call" || member === "apply") {
      out.push(callee.expression);
    }
  }
  return out;
}

/**
 * The name a call site spells for its callee, when it spells one at all. Shared
 * by the walk and by the resolver's own nested resolutions so both classify a
 * given expression under the same name; two copies of this three-line rule are
 * how a call-site name and a declaration name drift apart.
 */
function calleeName(expr: ts.Expression): string | undefined {
  if (ts.isPropertyAccessExpression(expr) || ts.isPropertyAccessChain(expr)) return expr.name.text;
  if (ts.isIdentifier(expr)) return expr.text;
  return undefined;
}

/** A function-typed property signature is a callable member, not a value. */
function isCallablePropertySignature(decl: ts.Declaration): decl is ts.PropertySignature {
  if (!ts.isPropertySignature(decl)) return false;
  const type = decl.type;
  return type !== undefined && (ts.isFunctionTypeNode(type) || ts.isTypeLiteralNode(type));
}

type Classified =
  | { kind: "sink"; primitive: string; sinkKind: SinkKind }
  /** Recognized and deliberately not walked (the storage/append boundary). */
  | { kind: "opaque" }
  | undefined;

/** What one call expression resolves to: sinks to record, and where to walk. */
export interface CalleeResolution {
  /** Sinks to record at this call site, in declaration order. */
  readonly sinks: readonly { readonly primitive: string; readonly sinkKind: SinkKind }[];
  /**
   * True when SOME declaration behind this callee was recognized, as a sink or
   * as a deliberately-not-walked boundary. A recognized callee is not walked.
   */
  readonly classified: boolean;
  /** Declarations to walk into, used only when nothing was recognized. */
  readonly walkTargets: readonly ts.Declaration[];
  /**
   * Declarations reached because a function was passed as a VALUE at this call
   * site rather than called at it (`["id"].forEach(execSync)`,
   * `setTimeout(execSync, 0, "id")`, `Function.prototype.call.call(execSync,
   * …)`). Kept separate from `walkTargets`, and walked UNCONDITIONALLY rather
   * than only when the callee came back unrecognized: the callee of such a call
   * is frequently a recognized boundary or a builtin, and gating the argument
   * on the callee's verdict would drop precisely the case this exists for.
   */
  readonly valueTargets: readonly ts.Declaration[];
}

/**
 * THE CALLEE CHOKEPOINT. The one place a call expression is turned into
 * declarations, classified against the sink sets, and expanded into walk
 * targets. It is a module-level factory rather than a closure inside
 * `buildAnalyzer` for one reason: the laundering fixtures in the test file
 * drive THIS resolver over a synthetic program, so the must-fail corpus
 * exercises the shipping resolution path instead of a copy of it that could
 * drift from it.
 *
 * `implementationsOf` is injected because it needs the interface-to-class index
 * built from the analyzed program; a fixture program supplies an empty one.
 *
 * `args` is REQUIRED rather than optional on `resolve`, because the reflective
 * spellings need them: `Reflect.apply(execSync, null, [cmd])` carries its
 * target in argument zero and nowhere else. An optional parameter every call
 * site was free to omit is the shape that ships a security check no production
 * caller supplies, so the type does not allow omitting it. A caller with no
 * arguments to offer passes an empty list and says so.
 */
export function createCalleeResolver(
  checker: ts.TypeChecker,
  implementationsOf: (
    signature: ts.MethodSignature | ts.PropertySignature
  ) => readonly ts.Declaration[]
): {
  resolve(
    callee: ts.Expression,
    callSiteName: string | undefined,
    args: readonly ts.Expression[]
  ): CalleeResolution;
} {
  function calleeDeclarations(callee: ts.Expression): ts.Declaration[] {
    let symbol = checker.getSymbolAtLocation(callee);
    if (
      symbol === undefined &&
      (ts.isPropertyAccessExpression(callee) || ts.isPropertyAccessChain(callee))
    ) {
      symbol = checker.getSymbolAtLocation(callee.name);
    }
    if (symbol === undefined) return [];
    if ((symbol.flags & ts.SymbolFlags.Alias) !== 0) {
      const aliased = checker.getAliasedSymbol(symbol);
      if (aliased.getDeclarations() !== undefined) symbol = aliased;
    }
    return symbol.getDeclarations() ?? [];
  }

  /**
   * The declaration set after expanding the three shapes whose own symbol
   * declaration carries no body:
   *
   *   1. an interface member  -> the implementing class members in `src`;
   *   2. `new X()`            -> `X`'s own constructor (the symbol resolves to
   *      the class, whose `functionBody` is undefined, so without this the
   *      constructor branch below could never fire at all);
   *   3. `const { f } = await import(...)` -> the imported function itself. The
   *      non-destructured `(await import(...)).f()` already resolved; the
   *      destructured binding did not, which is why two read tools whose
   *      primary path is written that way reported zero sinks of any kind.
   *      Handled generically by falling back to the call signatures of the
   *      callee's TYPE, which also covers an aliased const, an object-literal
   *      property holding a function, and a callback whose type has exactly one
   *      declared signature.
   */
  /**
   * Hops along `const a = b` / `{ p: b }` / `field = b` / `f(p = b)` initializer
   * REFERENCES, and along `get p() { return b; }` return references.
   *
   * Needed because a TYPE ANNOTATION erases the target: in
   * `const f: (c: string) => unknown = execSync`, the callee's type is the
   * annotation, whose only call signature is declared by the annotation's own
   * function-type node in the caller's file, so the type-signature fallback
   * resolves to the annotation and never to `execSync`. The initializer is the
   * only place the real target survives. An initializer that IS a function
   * (an arrow or function expression) is not a reference and is left alone;
   * `functionBody` already walks into it.
   *
   * The initializer is read through `unwrapTypeOnly` first, because a cast
   * defeats this hop the same way an annotation defeats the type-signature
   * fallback: in `const f = execSync as unknown as (c: string) => unknown` the
   * bare-identifier check below sees an `AsExpression`, bails, and the
   * annotation-erased type has no path back to `execSync` either, so both
   * routes miss and a subprocess reports clean.
   *
   * A PARAMETER DEFAULT and a GETTER RETURN are the same hop wearing different
   * syntax, and both were reachable once the cast strip existed: an annotated
   * `run: F = execSync as unknown as F` default, and a
   * `get run(): F { return execSync as unknown as F; }` accessor, each put the
   * real target one cast behind an annotation that erases it.
   */
  function referenceExpressions(decl: ts.Declaration): ts.Expression[] {
    if (
      ts.isVariableDeclaration(decl) ||
      ts.isPropertyAssignment(decl) ||
      ts.isPropertyDeclaration(decl) ||
      ts.isParameter(decl)
    ) {
      return decl.initializer === undefined ? [] : [decl.initializer];
    }
    if (ts.isGetAccessorDeclaration(decl) && decl.body !== undefined) {
      const out: ts.Expression[] = [];
      const visit = (node: ts.Node): void => {
        if (ts.isReturnStatement(node) && node.expression !== undefined) {
          out.push(node.expression);
        }
        // A nested function inside the getter has its own returns, which are
        // not this accessor's value; `functionBody` walks those where they are
        // written.
        if (isFunctionLike(node as ts.Declaration) && node !== decl) return;
        ts.forEachChild(node, visit);
      };
      ts.forEachChild(decl.body, visit);
      return out;
    }
    return [];
  }

  function initializerReferences(decl: ts.Declaration, depth: number): ts.Declaration[] {
    if (depth > MAX_ALIAS_HOPS) return [];
    const out: ts.Declaration[] = [];
    for (const expression of referenceExpressions(decl)) {
      const init = unwrapTypeOnly(expression);
      if (!ts.isIdentifier(init) && !ts.isPropertyAccessExpression(init)) continue;
      for (const target of calleeDeclarations(init)) {
        if (target === decl) continue;
        out.push(target, ...initializerReferences(target, depth + 1));
      }
    }
    return out;
  }

  function expandedDeclarations(
    callee: ts.Expression,
    declarations: readonly ts.Declaration[]
  ): ts.Declaration[] {
    const expanded: ts.Declaration[] = [];
    for (const decl of declarations) {
      expanded.push(decl);
      if (ts.isMethodSignature(decl) || isCallablePropertySignature(decl)) {
        expanded.push(...implementationsOf(decl));
      }
      if (ts.isClassDeclaration(decl)) {
        for (const member of decl.members) {
          if (ts.isConstructorDeclaration(member) && member.body !== undefined) {
            expanded.push(member);
          }
        }
      }
      expanded.push(...initializerReferences(decl, 0));
    }
    if (!expanded.some((decl) => functionBody(decl) !== undefined)) {
      expanded.push(...typeCallSignatureDeclarations(callee));
    }
    return expanded;
  }

  /** The declarations behind the callee TYPE's call signatures. */
  function typeCallSignatureDeclarations(callee: ts.Expression): ts.Declaration[] {
    const out: ts.Declaration[] = [];
    for (const signature of checker.getTypeAtLocation(callee).getCallSignatures()) {
      const decl = signature.getDeclaration() as ts.Declaration | undefined;
      if (decl !== undefined) out.push(decl);
    }
    return out;
  }

  function classifyCallee(decl: ts.Declaration, callSiteName: string | undefined): Classified {
    const file = decl.getSourceFile().fileName;

    // Classify on the DECLARATION's own name, not the identifier at the call
    // site. `import { cpSync as c } from "node:fs"` writes `c(...)`, and a set
    // matched against the call-site spelling would miss it — an alias is a
    // one-line evasion of every name-keyed sink below. The call-site name is
    // still what appears in `via`, because that is what the code reads like.
    //
    // A callee with NO call-site name (`fns[0](...)`, `(cond ? a : b)(...)`) is
    // still classifiable whenever the resolved declaration carries its own
    // name, which is why the call-site name is optional here rather than a
    // precondition. Requiring it made every non-identifier callee unclassifiable
    // by construction, which is a one-character evasion.
    const declared = (decl as ts.NamedDeclaration).name;
    const memberName =
      declared !== undefined && (ts.isIdentifier(declared) || ts.isStringLiteral(declared))
        ? declared.text
        : callSiteName;
    // Neither the declaration nor the call site names this callee, so there is
    // nothing to match against any sink set. Return unrecognized so it is
    // WALKED rather than reported under a made-up name.
    if (memberName === undefined) return undefined;

    if (file.startsWith(STORAGE_DIR)) {
      // A class or error constructor under storage is not a primitive; treat it
      // as recognized-and-not-walked rather than inventing a sink for it.
      if (!isFunctionLike(decl)) return { kind: "opaque" };
      if (STORAGE_READ_ONLY.has(memberName)) return { kind: "opaque" };
      return { kind: "sink", primitive: `storage.${memberName}`, sinkKind: "mutation" };
    }

    if (file === AUDIT_LOG_FILE) {
      // The `AuditLog` class itself (`new AuditLog(...)`) is not a primitive.
      if (!isFunctionLike(decl)) return { kind: "opaque" };
      if (AUDIT_APPENDERS.has(memberName)) {
        return { kind: "sink", primitive: `auditLog.${memberName}`, sinkKind: "audit_append" };
      }
      if (AUDIT_LOG_READ_ONLY.has(memberName)) return { kind: "opaque" };
      return { kind: "sink", primitive: `auditLog.${memberName}`, sinkKind: "mutation" };
    }

    if (isFsDeclarationFile(file) && FS_MUTATORS.has(memberName)) {
      return { kind: "sink", primitive: `fs.${memberName}`, sinkKind: "mutation" };
    }

    if (isChildProcessDeclarationFile(file) && CHILD_PROCESS_SPAWNERS.has(memberName)) {
      return {
        kind: "sink",
        primitive: `child_process.${memberName}`,
        sinkKind: "subprocess",
      };
    }

    return undefined;
  }

  /**
   * The arguments at this call site that are functions handed over as VALUES.
   *
   * A primitive passed rather than called is invoked by the callee, so no
   * `CallExpression` in this file names it and neither the callee's
   * declarations nor its type ever mention it: `["id"].forEach(execSync)` and
   * `setTimeout(execSync, 0, "id")` each spawn a subprocess while the resolved
   * callee is a standard-library method in no sink set. Classifying and walking
   * the argument is what closes that, and it is the same move that reaches a
   * named callback handed to a wrapper (an inline arrow was already walked as
   * part of the enclosing body; a named one was not).
   *
   * The test is the argument's TYPE, not its spelling: an earlier draft
   * accepted only an identifier or a property access, which is an enumeration
   * of spellings and reopens whichever one it forgot. A string, an object
   * literal, or a number has no call signature and costs one type lookup to
   * skip. A function LITERAL is excluded because it is already inside the
   * enclosing body the walk is traversing, so resolving it here would only
   * re-walk it.
   *
   * THIS SELECTS CANDIDATES; IT DOES NOT PROMISE THEY RESOLVE. Reaching the
   * primitive behind a selected argument is the callee resolver's job and
   * inherits its bound exactly, so an argument whose type is callable can still
   * resolve to nothing. Read no coverage claim into the selection test, and see
   * the value-path bound in the header for the residue.
   */
  function functionValuedArguments(args: readonly ts.Expression[]): ts.Expression[] {
    const out: ts.Expression[] = [];
    for (const arg of args) {
      const value = unwrapTypeOnly(arg);
      if (ts.isArrowFunction(value) || ts.isFunctionExpression(value)) continue;
      if (checker.getTypeAtLocation(value).getCallSignatures().length === 0) continue;
      out.push(value);
    }
    return out;
  }

  function resolveAt(
    callee: ts.Expression,
    callSiteName: string | undefined,
    args: readonly ts.Expression[],
    hop: number
  ): CalleeResolution {
    const direct = calleeDeclarations(callee);
    const expanded = expandedDeclarations(callee, direct);
    const sinks: { primitive: string; sinkKind: SinkKind }[] = [];
    let classified = false;

    const classifyOver = (decls: readonly ts.Declaration[]): void => {
      for (const decl of decls) {
        const verdict = classifyCallee(decl, callSiteName);
        if (verdict === undefined) continue;
        if (verdict.kind === "sink") {
          sinks.push({ primitive: verdict.primitive, sinkKind: verdict.sinkKind });
        }
        classified = true;
      }
    };

    // Direct declarations keep precedence, for two reasons. A decorator class
    // implementing the storage interface would otherwise report its own
    // forwarding call as a second, distinct site for the same primitive; and
    // `new AuditLog(...)` resolves to the class (opaque) whose constructor,
    // classified on the call-site name, would read as an `auditLog.AuditLog`
    // mutation.
    classifyOver(direct);

    // THE LAUNDERING FIX, AND WHY IT IS HERE RATHER THAN IN THE SINK NAME SETS.
    // Any indirection that interposes a source-local declaration between the
    // call site and a builtin primitive leaves the DIRECT declaration
    // unclassifiable (a destructured namespace import, an aliased `const`, an
    // object-literal property, a destructured dynamic `import`), while the
    // expansion above has already resolved the true target through the callee
    // type's call signatures. Classifying only the direct set therefore
    // launders every such one-liner past the guard while the walk knows exactly
    // where it went. Classification and walking must see the SAME resolved set,
    // which is what this second pass makes true. Adding the evading spellings
    // to the name sets instead would close the instances and leave the class:
    // that was tried once here, and the class survived one indirection away.
    if (!classified) {
      classifyOver(expanded.filter((decl) => !direct.includes(decl)));
    }

    // The expansion above computes type call signatures only when nothing in
    // the direct set has a BODY, because that condition is about where to walk.
    // Classification needs them unconditionally: a body-bearing intermediary
    // that merely HANDS BACK the primitive (an object getter returning it) is
    // walked into, and its body holds a reference rather than a call, so the
    // walk terminates clean while the callee's type names the primitive
    // exactly. Same chokepoint, third and last source of the SAME resolved
    // target.
    if (!classified) {
      classifyOver(typeCallSignatureDeclarations(callee).filter((decl) => !expanded.includes(decl)));
    }

    // REFLECTIVE INVOCATION, resolved through the expression that holds the
    // real target rather than through the callee. Merged unconditionally rather
    // than only when the callee itself came back unclassified: `f.call(...)`
    // resolves to the standard library's `CallableFunction.call`, which is
    // recognized by nothing, so "unclassified" is the normal case here and
    // gating on it would only skip the merge in the one situation where the
    // callee happened to be a sink named `call` or `apply` in its own right.
    // The walk targets are merged too, so a `.call` onto a `src`-local helper
    // is descended into instead of terminating at a standard-library
    // declaration outside `src`.
    const walkTargets = [...expanded];
    const valueTargets: ts.Declaration[] = [];
    if (hop < MAX_REFLECTIVE_HOPS) {
      for (const target of indirectTargets(callee, args)) {
        // An indirect target is the FUNCTION being invoked, not another call
        // expression, so it carries no arguments of its own to pass down.
        const nested = resolveAt(target, calleeName(target), [], hop + 1);
        sinks.push(...nested.sinks);
        if (nested.classified) classified = true;
        walkTargets.push(...nested.walkTargets.filter((decl) => !walkTargets.includes(decl)));
        valueTargets.push(...nested.valueTargets.filter((decl) => !valueTargets.includes(decl)));
      }

      // FUNCTION-VALUED ARGUMENTS, resolved as targets in their own right.
      // `classified` is deliberately NOT set from one: an argument says nothing
      // about whether the CALLEE was recognized, and setting it here would stop
      // the walk from descending into a `src`-local higher-order helper that
      // happened to be handed a function.
      for (const argument of functionValuedArguments(args)) {
        const nested = resolveAt(argument, calleeName(argument), [], hop + 1);
        sinks.push(...nested.sinks);
        for (const decl of [...nested.walkTargets, ...nested.valueTargets]) {
          if (!valueTargets.includes(decl)) valueTargets.push(decl);
        }
      }
    }

    return { sinks, classified, walkTargets, valueTargets };
  }

  return {
    resolve: (callee, callSiteName, args) => resolveAt(callee, callSiteName, args, 0),
  };
}

/**
 * Admission for ONE descent edge of the call-graph walk, and the single place
 * the depth ceiling and the per-edge memo are decided together.
 *
 * THE ORDER IS THE WHOLE POINT: the ceiling is tested BEFORE the memo is
 * written, because a descent the ceiling refuses entered nothing and therefore
 * knows nothing about that `(body, caller frame, callee frame)` triple. An
 * earlier revision inserted the key first and let `walk` discover the ceiling
 * after the call, so a truncated descent CLAIMED the triple: any later route to
 * the same pair — including a two-hop route straight from the handler — was
 * then skipped as already-walked, and a sink that the walk would otherwise have
 * found went unreported. That turns a cap which fails open locally into one
 * that suppresses results on unrelated shorter paths, which is the failure this
 * whole file exists to prevent. Pinned by "a descent refused by the depth
 * ceiling does not claim the memo" in the test file.
 *
 * Both descent sites in `sinksFor` (the `callPrimitive` dispatch and the
 * ordinary callee/value descent) go through here rather than repeating the
 * two-step, so the sites cannot drift apart.
 *
 * Refusing without memoizing cannot loop: a refusal recurses nowhere, and the
 * walk terminates on the finite triple space that the memo enumerates.
 *
 * @param childDepth depth the callee WOULD be walked at, i.e. the caller's
 *                   depth plus one.
 * @returns whether to descend. Writes the memo only when it returns true.
 */
export function admitDescent(
  walked: Set<string>,
  key: string,
  childDepth: number
): boolean {
  // Truncation leaves the memo untouched: nothing was entered, so nothing is
  // known. Exhausting the ceiling still fails open for THIS path (see the
  // bound stated in the header); it must not also blank another one.
  if (childDepth > MAX_CALL_DEPTH) return false;
  if (walked.has(key)) return false;
  walked.add(key);
  return true;
}

function buildAnalyzer(): Analyzer {
  const configFile = ts.readConfigFile(join(SERVER_DIR, "tsconfig.json"), ts.sys.readFile);
  const parsed = ts.parseJsonConfigFileContent(configFile.config, ts.sys, SERVER_DIR);
  const program = ts.createProgram(parsed.fileNames, { ...parsed.options, noEmit: true });
  const checker = program.getTypeChecker();
  const sources = program
    .getSourceFiles()
    .filter((sf) => !sf.isDeclarationFile && sf.fileName.startsWith(SRC_DIR));

  // ---- tool literals + inline classification -----------------------------
  const handlers = new Map<string, { node: ts.Node; location: string }>();
  const inlineRead: string[] = [];
  const inlineWrite: string[] = [];
  const resolvedReadLiteralNames: string[] = [];
  const resolvedWriteLiteralNames: string[] = [];
  const resolvedToolLiteralNames: string[] = [];
  const unresolvableToolLiterals: string[] = [];
  const unparsableToolClassLiterals: string[] = [];

  for (const sf of sources) {
    const visit = (node: ts.Node): void => {
      if (ts.isObjectLiteralExpression(node)) {
        let name: string | undefined;
        let handler: ts.Node | undefined;
        let inlineClass: string | undefined;
        let opaqueToolClass = false;
        let hasToolShape = false;
        for (const prop of node.properties) {
          const key = propertyKey(prop);
          if (key === "name" && ts.isPropertyAssignment(prop)) {
            name = resolveToolName(prop.initializer, checker);
          } else if (key === "tool_class" && ts.isPropertyAssignment(prop)) {
            if (ts.isStringLiteralLike(prop.initializer)) {
              inlineClass = prop.initializer.text;
            } else {
              opaqueToolClass = true;
            }
          } else if (key === "handler") {
            handler = ts.isMethodDeclaration(prop) ? prop : (prop as ts.PropertyAssignment).initializer;
          } else if (key === "inputSchema" || key === "description") {
            hasToolShape = true;
          }
        }
        if (opaqueToolClass && handler !== undefined) {
          unparsableToolClassLiterals.push(relPath(sf.fileName));
        }
        if (name !== undefined && handler !== undefined) {
          resolvedToolLiteralNames.push(name);
          if (!handlers.has(name)) handlers.set(name, { node: handler, location: locate(node) });
          if (inlineClass === "read") {
            inlineRead.push(name);
            resolvedReadLiteralNames.push(name);
          }
          if (inlineClass === "write") {
            inlineWrite.push(name);
            resolvedWriteLiteralNames.push(name);
          }
        } else if (
          name === undefined &&
          handler !== undefined &&
          (hasToolShape || inlineClass !== undefined)
        ) {
          // Reported with the FILE only, no line, so an edit above one does not
          // churn the disposition list. The two runtime-named tool families are
          // dispositioned in the test, not silently skipped here, so a third
          // one appearing anywhere is a review event.
          unresolvableToolLiterals.push(relPath(sf.fileName));
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }

  // ---- classification tables, read from the shipping source --------------
  const indexSource = program.getSourceFile(INDEX_FILE);
  if (indexSource === undefined) {
    throw new Error(`read-tool guard could not load ${relPath(INDEX_FILE)}`);
  }
  const readTableParse = readNameTable(indexSource, "READ_MCP_TOOLS");
  const writeTableParse = readNameTable(indexSource, "WRITE_MCP_TOOLS");
  const operatorTableParse = readNameTable(indexSource, "OPERATOR_TERMINAL_ONLY_MCP_TOOLS");
  const classification: ToolClassification = {
    readTable: readTableParse.names,
    writeTable: writeTableParse.names,
    operatorTable: operatorTableParse.names,
    inlineRead: [...new Set(inlineRead)].sort(),
    inlineWrite: [...new Set(inlineWrite)].sort(),
    unparsableTableElements: [
      ...readTableParse.skipped,
      ...writeTableParse.skipped,
      ...operatorTableParse.skipped,
    ],
  };

  /** Every name the server treats as state-changing, for dispatch edges. */
  const writeClassified = new Set([
    ...classification.writeTable,
    ...classification.operatorTable,
    ...classification.inlineWrite,
  ]);

  // ---- interface -> implementing classes ---------------------------------
  // A call on an interface-typed value resolves to a signature with no body.
  // Without this index the walk would stop at every injected adapter and report
  // a clean graph for a handler that in fact reaches a mutation through one.
  const implementers = new Map<string, ts.ClassDeclaration[]>();
  for (const sf of sources) {
    const visit = (node: ts.Node): void => {
      if (ts.isClassDeclaration(node)) {
        for (const clause of node.heritageClauses ?? []) {
          for (const type of clause.types) {
            if (!ts.isIdentifier(type.expression)) continue;
            const key = type.expression.text;
            implementers.set(key, [...(implementers.get(key) ?? []), node]);
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }

  /**
   * Members of `src` classes that implement an interface member. Covers BOTH
   * spellings an interface can use for a function member: a method signature
   * (`save(x): void`) and a function-typed property signature
   * (`save: (x) => void`).
   *
   * THE PROPERTY-SIGNATURE BRANCH IS WIRED AND CURRENTLY INERT, stated plainly
   * because a branch carrying an unearned claim is worse than an absent one. It
   * resolves nothing in this tree as it stands: of the 685 function-typed
   * property-signature members across 363 interfaces, not one is implemented by
   * a class that syntactically `implements` its interface, so this branch's own
   * resolution count is zero. It exists so that adding such an implementation
   * fails closed rather than going silently unwalked. It fixes no call site
   * today and none should be attributed to it. The real unresolved gap is the
   * injected-dependency class measured in the header, which this branch does
   * not touch, because an injected function-typed property is supplied by an
   * object literal at a construction site rather than by a class that declares
   * `implements`.
   */
  function implementationsOf(
    signature: ts.MethodSignature | ts.PropertySignature
  ): ts.Declaration[] {
    const iface = signature.parent;
    if (!ts.isInterfaceDeclaration(iface)) return [];
    const memberName =
      ts.isIdentifier(signature.name) || ts.isStringLiteral(signature.name)
        ? signature.name.text
        : undefined;
    if (memberName === undefined) return [];
    const out: ts.Declaration[] = [];
    for (const cls of implementers.get(iface.name.text) ?? []) {
      for (const member of cls.members) {
        if (!ts.isMethodDeclaration(member) && !ts.isPropertyDeclaration(member)) continue;
        if (!ts.isIdentifier(member.name) && !ts.isStringLiteral(member.name)) continue;
        if (member.name.text !== memberName) continue;
        out.push(member);
      }
    }
    return out;
  }

  const resolver = createCalleeResolver(checker, implementationsOf);

  /**
   * Where a handler walk STARTS, and why that is not simply the `handler`
   * property's initializer.
   *
   * `handler: async (args) => { … }` is a function literal and is walked as
   * written. `handler: sovereigntyAuditHandler` is an IDENTIFIER: it contains
   * no call expression at all, so a walk starting there terminates immediately
   * and reports zero sinks while the function behind the name can spawn a
   * subprocess. Hoisting a handler out of its literal is an ordinary refactor,
   * not an exotic shape, and eight read tools legitimately report zero sinks
   * today, so a newly-zeroed tool would be indistinguishable from them. The
   * identifier is therefore resolved through the SAME callee chokepoint the
   * walk uses, and the declarations behind it are what get walked.
   *
   * An EMPTY result is the loud case, never a quiet one: the caller records the
   * tool in `unresolvedHandlers`, so a handler this analyzer cannot walk reds
   * the guard instead of reading as clean.
   */
  interface HandlerEntry {
    /** Nodes to walk. Empty means the handler did not resolve to a body. */
    readonly walkFrom: readonly ts.Node[];
    /** Sinks named by the handler position itself (`handler: execSync`). */
    readonly sinks: readonly { readonly primitive: string; readonly sinkKind: SinkKind }[];
  }

  const handlerEntries = new Map<string, HandlerEntry>();

  function handlerEntry(tool: string): HandlerEntry {
    const memo = handlerEntries.get(tool);
    if (memo !== undefined) return memo;
    const entry = handlers.get(tool);
    let resolved: HandlerEntry = { walkFrom: [], sinks: [] };
    if (entry !== undefined) {
      const node = entry.node;
      if (
        ts.isMethodDeclaration(node) ||
        ts.isArrowFunction(node) ||
        ts.isFunctionExpression(node)
      ) {
        // Walk the function node itself rather than its body, so a parameter
        // default carrying a call is inside the walk.
        resolved = { walkFrom: [node], sinks: [] };
      } else {
        // Everything else a `handler:` property can hold is an expression.
        const expression = unwrapTypeOnly(node as ts.Expression);
        const resolution = resolver.resolve(expression, calleeName(expression), []);
        const walkFrom: ts.Node[] = [];
        for (const decl of [...resolution.walkTargets, ...resolution.valueTargets]) {
          if (!decl.getSourceFile().fileName.startsWith(SRC_DIR)) continue;
          if (functionBody(decl) === undefined) continue;
          if (!walkFrom.includes(decl)) walkFrom.push(decl);
        }
        resolved = { walkFrom, sinks: resolution.sinks };
      }
    }
    handlerEntries.set(tool, resolved);
    return resolved;
  }

  function sinksFor(tool: string): SinkHit[] {
    const entry = handlers.get(tool);
    if (entry === undefined) return [];
    const found: SinkHit[] = [];
    // Memoized per (body, immediate caller). Keying on the body alone would let
    // the FIRST path to a shared helper claim it and drop every later caller,
    // which is exactly the distinction a per-caller residual pin depends on.
    const walked = new Set<string>();

    const walk = (node: ts.Node, chain: string[], frames: string[], depth: number): void => {
      // Backstop only: every descent edge is admitted by `admitDescent`, which
      // is the authoritative ceiling test. Kept so a future descent site that
      // forgets the admission gate still stops rather than recursing forever,
      // and the two must not diverge — both read `MAX_CALL_DEPTH`.
      if (depth > MAX_CALL_DEPTH) return;
      const currentFrame = frames[frames.length - 1];
      const callerFrame = frames[frames.length - 2];

      const record = (
        current: ts.Node,
        primitive: string,
        sinkKind: SinkKind,
        memberName: string | undefined
      ): void => {
        const site = frameOf(current);
        found.push({
          kind: sinkKind,
          primitive,
          site,
          // `site` is the function the sink call sits in. When that is the frame
          // we are currently inside, the caller is one frame further up.
          caller: site === currentFrame ? callerFrame : currentFrame,
          via: [...chain, `${memberName ?? "?"}@${locate(current)}`],
        });
      };

      const visit = (current: ts.Node): void => {
        // A TAGGED TEMPLATE is an invocation, and the walk used to skip it.
        // `Tpl.run\`id\`` calls `Tpl.run` with the template's parts, so a
        // `src`-local tag function is reached exactly like any other callee and
        // can do anything its body does. An earlier revision argued the shape
        // was harmless because no sink in the sets above accepts a
        // `TemplateStringsArray`; that argument only covers a BUILTIN used as
        // the tag, and the reachable case is the source-local one.
        const isCall = ts.isCallExpression(current) || ts.isNewExpression(current);
        if (isCall || ts.isTaggedTemplateExpression(current)) {
          const callee = ts.isTaggedTemplateExpression(current)
            ? current.tag
            : current.expression;
          const callArguments = isCall
            ? ((current as ts.CallExpression | ts.NewExpression).arguments ?? [])
            : [];
          const memberName = calleeName(callee);
          // One resolution per call site, shared by classification and the
          // walk. They must not resolve the callee separately: that split is
          // what let an interposed source-local declaration launder a builtin
          // sink past classification while the walk still knew the true target.
          // The arguments go with it because a reflective invocation
          // (`Reflect.apply(fn, …)`) names its target there and not in the
          // callee.
          const resolution = resolver.resolve(callee, memberName, callArguments);

          // --- runtime primitive dispatch, resolved through its literal ------
          // `callPrimitive("state_write", ...)`: name a mutation edge when the
          // target is write-classified, and walk the target's handler either
          // way so a read-classified target contributes its own sinks to this
          // tool (which is how `sanctuary_recall` inherits `state_read`'s set).
          if (
            memberName !== undefined &&
            PRIMITIVE_DISPATCH_FUNCTIONS.has(memberName) &&
            ts.isCallExpression(current)
          ) {
            const first = current.arguments[0];
            if (first !== undefined && ts.isStringLiteralLike(first)) {
              const target = first.text;
              if (writeClassified.has(target)) {
                record(current, `callPrimitive:${target}`, "mutation", memberName);
              }
              const targetHandler = handlers.get(target);
              if (targetHandler !== undefined) {
                const frame = `${target} handler@${relPath(
                  targetHandler.node.getSourceFile().fileName
                )}`;
                const key = `${targetHandler.node.pos}|${currentFrame ?? ""}|${frame}`;
                if (admitDescent(walked, key, depth + 1)) {
                  walk(
                    targetHandler.node,
                    [...chain, `callPrimitive("${target}")@${locate(current)}`],
                    [...frames, frame],
                    depth + 1
                  );
                }
              }
            }
          }

          for (const sink of resolution.sinks) {
            record(current, sink.primitive, sink.sinkKind, memberName);
          }

          // A recognized callee is not walked (that is the storage/audit
          // boundary rule), but a function handed to it as a VALUE is walked
          // either way: the callee's verdict is about the callee, and the
          // argument is a separate target that this call site reaches.
          const descendInto = [
            ...(resolution.classified ? [] : resolution.walkTargets),
            ...resolution.valueTargets,
          ];
          for (const decl of descendInto) {
            if (!decl.getSourceFile().fileName.startsWith(SRC_DIR)) continue;
            const body = functionBody(decl);
            if (body === undefined) continue;
            const frame = declarationFrame(decl);
            const key = `${body.pos}|${currentFrame ?? ""}|${frame}`;
            if (!admitDescent(walked, key, depth + 1)) continue;
            walk(
              body,
              [...chain, `${memberName ?? "?"}@${locate(decl)}`],
              [...frames, frame],
              depth + 1
            );
          }
        }
        ts.forEachChild(current, visit);
      };
      visit(node);
    };

    const start = handlerEntry(tool);
    for (const sink of start.sinks) {
      // The handler property IS the primitive (`handler: execSync`). Recorded
      // at the literal so it cannot pass for want of a call expression.
      found.push({
        kind: sink.sinkKind,
        primitive: sink.primitive,
        site: `${tool} handler@${relPath(entry.node.getSourceFile().fileName)}`,
        caller: undefined,
        via: [`${tool}@${entry.location}`],
      });
    }
    for (const node of start.walkFrom) {
      walk(
        node,
        [`${tool}@${entry.location}`],
        [`${tool} handler@${relPath(node.getSourceFile().fileName)}`],
        0
      );
    }

    const unique = new Map<string, SinkHit>();
    for (const hit of found) {
      const key = `${hit.kind}|${hit.primitive}|${hit.site}|${hit.caller ?? ""}`;
      if (!unique.has(key)) unique.set(key, hit);
    }
    return [...unique.values()];
  }

  return {
    program,
    checker,
    handlers,
    classification,
    inlineAntiVacuity: {
      resolvedReadLiteralNames,
      resolvedWriteLiteralNames,
      unresolvableToolLiterals: [...new Set(unresolvableToolLiterals)].sort(),
      unparsableToolClassLiterals: [...new Set(unparsableToolClassLiterals)].sort(),
    },
    resolvedToolLiteralNames,
    handlerWalkable: (tool) => handlerEntry(tool).walkFrom.length > 0,
    sinksFor,
  };
}

function analyzer(): Analyzer {
  cached ??= buildAnalyzer();
  return cached;
}

/**
 * Sink hits for one tool, whatever its classification. Used by the guard for
 * its read set and by the positive control for a known write tool.
 */
export function sinksForTool(tool: string): SinkHit[] {
  return analyzer().sinksFor(tool);
}

/** Whether a tool literal with a discoverable handler exists for this name. */
export function hasHandler(tool: string): boolean {
  return analyzer().handlers.has(tool);
}

export function analyzeReadToolMutationReachability(): ReachabilityReport {
  const {
    classification,
    handlers,
    inlineAntiVacuity,
    resolvedToolLiteralNames,
    handlerWalkable,
    sinksFor,
  } = analyzer();
  const readTools = [
    ...new Set([...classification.readTable, ...classification.inlineRead]),
  ].sort();

  const handlerLocations = new Map<string, string>();
  const unresolvedHandlers: string[] = [];
  const hits = new Map<string, SinkHit[]>();

  for (const tool of readTools) {
    const entry = handlers.get(tool);
    if (entry === undefined) {
      unresolvedHandlers.push(`${tool}: no tool literal`);
      continue;
    }
    // A literal whose handler resolves to no walkable body is the same failure
    // as an absent literal, and it used to be silent: the tool stayed in
    // `handlers`, so nothing here saw it, and the walk reported nothing.
    if (!handlerWalkable(tool)) {
      unresolvedHandlers.push(`${tool}: handler at ${entry.location} has no walkable body`);
      continue;
    }
    handlerLocations.set(tool, entry.location);
    const sinks = sinksFor(tool);
    if (sinks.length > 0) hits.set(tool, sinks);
  }

  return {
    classification,
    readTools,
    handlerLocations,
    unresolvedHandlers,
    resolvedToolLiteralNames,
    inlineAntiVacuity,
    hits,
  };
}
