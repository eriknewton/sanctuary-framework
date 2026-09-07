// fail-before-exempt: reconciliation-only for this PR — the full suite exposed that the new runtime-named signer-prune tool file needed an entry in REVIEWED_RUNTIME_NAMED_TOOL_FILES. That allowlist entry correctly still passes against pre-fix source because the new tool file is absent there; the actual signer-prune behavior and authority changes fail before in memory-provenance-signer-prune, Exit journal, CLI, principal-policy, migration-contract, and frozen-surface tests.
/**
 * CAPABILITY: an MCP tool classified `read` runs even when the audit chain
 * reports integrity findings, so an operator can still introspect a fortress in
 * trouble. This test reconciles that classification against what each read
 * handler can actually reach: it derives the read set from the shipping
 * classification tables and walks every handler's call graph, and it fails when
 * a read-classified handler can reach a durable-state mutation or a subprocess
 * that is not on the reviewed residual list below (ABC-READCLASS-01).
 *
 * SCOPE, WHICH IS PART OF THE CLAIM. Three separate bounds, all deliberate:
 *
 *   1. TARGET SET. Derived, never hand-listed: `READ_MCP_TOOLS` in
 *      `src/index.ts` read by AST, unioned with every tool literal carrying an
 *      inline `tool_class: "read"`. Both are live classification inputs to
 *      `classifyMcpTools`. BOTH HALVES have an anti-vacuity backstop, and they
 *      are three distinct backstops rather than one, because there are three
 *      distinct ways a tool can leave this analysis while the shipping router
 *      still classifies it read and still grants the bypass:
 *        - a table element this parser cannot read as a string literal, which
 *          the runtime `Set` still contains (`unparsableTableElements`);
 *        - a parsed table name with no tool literal behind it, or a literal
 *          whose handler resolves to no walkable body (`unresolvedHandlers`);
 *        - an inline literal whose `tool_class` or `name` this extractor cannot
 *          parse (`inlineAntiVacuity`).
 *      An earlier revision of this comment claimed the first case landed in
 *      `unresolvedHandlers`. It did not: it landed nowhere, and the
 *      order-of-magnitude floor on table length cannot see one tool go missing.
 *      All three are asserted empty below.
 *   2. SINKS. Durable-state mutation and subprocess: the storage boundary under
 *      an inverted allowlist, the mutating `node:fs` entry points, the
 *      `node:child_process` spawn entry points, and a `callPrimitive` dispatch
 *      naming a write-classified tool. Audit-chain appends are NOT sinks, and
 *      that is not an oversight: every read tool in this tree records the read
 *      it performed, so an append is the expected behavior of a correct read
 *      tool and cannot discriminate one classification from the other. Appends
 *      are still measured and are reported by the analyzer. A sink is matched
 *      on the DECLARATION the callee resolves to, never on the spelling at the
 *      call site, so interposing a local binding does not launder it; the
 *      laundering corpus below is the must-fail proof of that. The corpus pins
 *      CLOSED shapes only. It does not exhibit what it fails to catch, and a
 *      reader must not take its extent for the closure's extent: the bound is
 *      stated in prose on the analyzer and resolves in the private register.
 *   3. SOUNDNESS. The walk is a static, checker-resolved UNDER-approximation,
 *      with one deliberate over-approximating exception: a function handed over
 *      as a value counts as reached whether or not the receiving function
 *      invokes it. The full bound, in both directions, including the measured
 *      call sites through injected function-typed dependencies that it does NOT
 *      resolve, is stated with its counting method on
 *      `read-tool-mutation-reachability.ts`. A green here means "no mutation is
 *      reachable along a statically resolvable path", never "no mutation is
 *      possible", and a red means a path exists, not that it necessarily runs.
 *
 * WHY THE MECHANISM IS ASSERTED FIRST. Several assertions below check that the
 * analyzer still works at all — that the tables parsed non-empty, that every
 * read tool resolved to a handler, that no inline tool literal silently
 * dropped, and that known state-creating tools are still reported as reaching a
 * mutation. Without those, an extractor that silently stopped matching would
 * report an empty offender set and read as a pass, which is the failure this
 * whole file exists to avoid.
 */

import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";
import { beforeAll, describe, expect, it } from "vitest";

import {
  admitDescent,
  analyzeReadToolMutationReachability,
  createCalleeResolver,
  createImplementationLookup,
  deduplicateTraversalTruncations,
  sinksForTool,
  walkForSinks,
} from "./read-tool-mutation-reachability.js";
import type {
  SinkHit,
  TraversalTruncation,
  TraversalTruncationKind,
} from "./read-tool-mutation-reachability.js";

interface ReviewedSite {
  /** Must equal `SinkHit.primitive` exactly. */
  readonly primitive: string;
  /** `<enclosingFunction>@<path>`; must equal `SinkHit.site` exactly. */
  readonly site: string;
  /**
   * The immediate caller frame, which must equal `SinkHit.caller`. This is what
   * stops a pin on a SHARED helper from pre-approving every future caller of
   * it: `saveJsonRecord` is the generic `_meta` writer, so it is pinned only as
   * reached from `rememberWriterPublicKey`, and a new read path that writes
   * `_meta` through the same helper reds instead of inheriting the exemption.
   */
  readonly through: string | undefined;
}

/**
 * The two L2 posture probes read kernel and platform state that has no Node
 * API, so they shell out. Shared between both tools because they call the same
 * assessment function.
 */
function l2ProbeSites(): readonly ReviewedSite[] {
  const p = (site: string, through: string): ReviewedSite => ({
    primitive: "child_process.execSync",
    site: `${site}@src/operational/hardening.ts`,
    through: `${through}@src/operational/hardening.ts`,
  });
  return [
    p("checkASLR", "checkMemoryProtection"),
    p("detectContainer", "checkProcessIsolation"),
    p("detectVM", "checkProcessIsolation"),
    p("detectSandbox", "checkProcessIsolation"),
  ];
}

const L2_PROBE_WHY =
  "Both tools answer 'is this fortress actually isolated', which is precisely " +
  "the question an operator needs answered while the audit chain has findings, " +
  "so reclassifying them to `write` would remove the introspection the " +
  "audit-integrity bypass exists to preserve. Every command is a fixed string " +
  "literal with no caller-derived component (ASLR from " +
  "/proc/sys/kernel/randomize_va_space; container, VM and sandbox signals from " +
  "cgroup, dmidecode, cpuinfo, nvram, pledge and getenforce), each reads and " +
  "writes nothing, and the output is summarized rather than returned raw. The " +
  "bound this accepts, stated rather than assumed: a subprocess leaves this " +
  "process, so no analysis here can prove what it did — the justification rests " +
  "on the commands being fixed literals, which is why they are enumerated above " +
  "and why a new one at a new site reds this test.";

const SDW_QUARANTINE_WHY =
  "These read tools may discover an invalid provenance companion while the " +
  "fortress is already in an integrity incident, so making them write-classed " +
  "would remove the operator's ability to inspect the affected memory. The " +
  "maintenance is denial/quarantine only: it can neither admit a passage nor " +
  "make one visible. It replaces one bounded status row for an already-present, " +
  "already-counted candidate; the reason, document-content hash and provenance-" +
  "ciphertext digest come from verified stored bytes rather than caller input, " +
  "and the exact document plus companion are rechecked under the corpus lock " +
  "before the digest-bound status is written. The storage write is pinned only " +
  "through putProvenanceStatus and the lock only through getPassageProvenance, " +
  "for each named tool, so a new primitive, site or immediate caller remains " +
  "unreviewed and reds this test.";

/**
 * Read-path maintenance that is reviewed and allowed to stay in the read set.
 *
 * The entries here are not exemptions from the property; they are the cases
 * where the mutation is upkeep on data already present rather than new state
 * created from a caller's input, AND where moving the tool to `write` would
 * take away the operator's ability to read their own fortress during exactly
 * the incident the audit-integrity gate exists for.
 *
 * Each entry pins a PRIMITIVE at a SITE reached from a named CALLER. All three
 * parts matter: keying on the site alone (the earlier shape) meant a new
 * mutation of a DIFFERENT primitive inside an already-listed function was
 * allowed, and a new CALLER of an already-listed shared helper was allowed too.
 *
 * WHAT THE TRIPLE DOES NOT CATCH, since a pin's granularity is part of its
 * claim: it distinguishes primitive, enclosing function, and immediate caller,
 * and nothing finer. A SECOND call to the SAME primitive added inside an
 * already-pinned function and reached from the SAME caller is indistinguishable
 * from the first and stays GREEN. So a new mutation inside an already-listed
 * tool reds this test only when it differs from every reviewed entry in at
 * least one of those three, which is a weaker statement than "any new mutation
 * reds". Closing it needs a statement-level (line-numbered) pin, which would
 * churn on every edit above it. The analyzer header states the same bound.
 *
 * Sites and callers are `<enclosingFunction>@<path>`; no line numbers, so
 * ordinary edits above them do not churn this list.
 */
const REVIEWED_READ_PATH_MAINTENANCE: ReadonlyMap<
  string,
  { readonly sites: readonly ReviewedSite[]; readonly why: string }
> = new Map([
  [
    "state_read",
    {
      sites: [
        {
          primitive: "storage.write",
          site: "migrateLegacyEntryToSchema2@src/cognitive/state-store.ts",
          through: "readInternal@src/cognitive/state-store.ts",
        },
        {
          primitive: "storage.write",
          site: "saveJsonRecord@src/cognitive/state-store.ts",
          through: "rememberWriterPublicKey@src/cognitive/state-store.ts",
        },
        {
          primitive: "storage.write",
          site: "saveVersionAnchors@src/cognitive/state-store.ts",
          through: "observeVersion@src/cognitive/state-store.ts",
        },
      ],
      why:
        "Reading a v1 entry rewrites it into the current signed envelope and " +
        "records the writer key and the version anchor the anti-rollback check " +
        "reads. All three act on an entry the caller already had. The anchor " +
        "write is NOT an unqualified integrity gain and is not claimed as one: " +
        "the floor it records is adopted from whatever entry was just read, so " +
        "during an incident it takes its value from the least trustworthy " +
        "source available, and a deleted anchor plus an older validly-signed " +
        "entry resets it. It raises a rollback floor that would otherwise not " +
        "exist at all, which is why it stays on the read path; it does not " +
        "make rollback detectable on its own (STATE-READ-MIGRATE-01, " +
        "STATE-READ-ANCHOR-01). The generic `_meta` writer is pinned only as " +
        "reached from the writer-key remembrance function, so it does not " +
        "pre-approve future `_meta` writes through the same helper.",
    },
  ],
  [
    "sanctuary_recall",
    {
      sites: [
        {
          primitive: "storage.delete",
          site: "deleteHiddenMarker@src/agent-native/cooperative-surface.ts",
          through: "garbageCollectExpiredHiddenMarker@src/agent-native/cooperative-surface.ts",
        },
        // Recall reads through `callPrimitive("state_read", ...)`, so it
        // inherits that tool's residual write set in full. Listing only the
        // marker delete (the earlier shape) presented an incomplete account of
        // what recall can reach.
        {
          primitive: "storage.write",
          site: "migrateLegacyEntryToSchema2@src/cognitive/state-store.ts",
          through: "readInternal@src/cognitive/state-store.ts",
        },
        {
          primitive: "storage.write",
          site: "saveJsonRecord@src/cognitive/state-store.ts",
          through: "rememberWriterPublicKey@src/cognitive/state-store.ts",
        },
        {
          primitive: "storage.write",
          site: "saveVersionAnchors@src/cognitive/state-store.ts",
          through: "observeVersion@src/cognitive/state-store.ts",
        },
      ],
      why:
        "Recall drops the hide marker for the key it was asked about once that " +
        "marker's own TTL has passed. The delete is bounded to that one expired " +
        "marker, its expiry is set when the marker is created rather than by the " +
        "recalling caller, and it removes bookkeeping rather than stored content. " +
        "Recall then reads through the state-read primitive by runtime dispatch, " +
        "so everything reviewed for `state_read` above is reachable from here " +
        "too and is listed rather than left implicit.",
    },
  ],
  [
    "memory_get",
    {
      sites: [
        {
          primitive: "storage.write",
          site: "sdwBackendWrite@src/sdw/write-gate.ts",
          through: "putProvenanceStatus@src/sdw/document-corpus-store.ts",
        },
        {
          primitive: "storage.withCrossProcessLock",
          site: "quarantine@src/sdw/adapters/sdw-memory-backend.ts",
          through: "getPassageProvenance@src/sdw/adapters/sdw-memory-backend.ts",
        },
      ],
      why: SDW_QUARANTINE_WHY,
    },
  ],
  [
    "memory_list",
    {
      sites: [
        {
          primitive: "storage.write",
          site: "sdwBackendWrite@src/sdw/write-gate.ts",
          through: "putProvenanceStatus@src/sdw/document-corpus-store.ts",
        },
        {
          primitive: "storage.withCrossProcessLock",
          site: "quarantine@src/sdw/adapters/sdw-memory-backend.ts",
          through: "getPassageProvenance@src/sdw/adapters/sdw-memory-backend.ts",
        },
      ],
      why: SDW_QUARANTINE_WHY,
    },
  ],
  [
    "memory_search",
    {
      sites: [
        {
          primitive: "storage.write",
          site: "sdwBackendWrite@src/sdw/write-gate.ts",
          through: "putProvenanceStatus@src/sdw/document-corpus-store.ts",
        },
        {
          primitive: "storage.withCrossProcessLock",
          site: "quarantine@src/sdw/adapters/sdw-memory-backend.ts",
          through: "getPassageProvenance@src/sdw/adapters/sdw-memory-backend.ts",
        },
      ],
      why: SDW_QUARANTINE_WHY,
    },
  ],
  [
    "sdw_memory_provenance",
    {
      sites: [
        {
          primitive: "storage.write",
          site: "sdwBackendWrite@src/sdw/write-gate.ts",
          through: "putProvenanceStatus@src/sdw/document-corpus-store.ts",
        },
        {
          primitive: "storage.withCrossProcessLock",
          site: "quarantine@src/sdw/adapters/sdw-memory-backend.ts",
          through: "getPassageProvenance@src/sdw/adapters/sdw-memory-backend.ts",
        },
      ],
      why: SDW_QUARANTINE_WHY,
    },
  ],
  [
    "l2_hardening_status",
    {
      sites: l2ProbeSites(),
      why: L2_PROBE_WHY,
    },
  ],
  [
    "l2_verify_isolation",
    {
      sites: l2ProbeSites(),
      why: L2_PROBE_WHY,
    },
  ],
]);

function isReviewedReadPathMaintenance(tool: string, hit: SinkHit): boolean {
  return (
    REVIEWED_READ_PATH_MAINTENANCE.get(tool)?.sites.some(
      (entry) =>
        entry.primitive === hit.primitive &&
        entry.site === hit.site &&
        entry.through === hit.caller
    ) === true
  );
}


/**
 * Files whose tool-shaped object literals are named at runtime, so the analyzer
 * cannot resolve them. Each is reviewed and cannot receive the read bypass.
 */
const REVIEWED_RUNTIME_NAMED_TOOL_FILES: ReadonlyMap<string, string> = new Map([
  [
    "src/proxy/proxy-router.ts",
    "Upstream tools are re-namespaced as `proxy/{server}/{tool}` from a catalog " +
      "fetched at runtime, and `classifyMcpTools` forces every `proxy/` name to " +
      "`write` before any other rule runs, so none of them can reach the read " +
      "bypass regardless of what the handler does.",
  ],
  [
    "src/honeypot/tool-call-trap-runtime.ts",
    "Decoy tool literals built by `listCatalogTools` from the trap registry. " +
      "They are appended to the ListTools response only; they never pass through " +
      "`classifyMcpTools`, are never registered as executable handlers (a trap " +
      "call is dispatched by `invokeIfTrap`), and the literal's own handler is " +
      "an inert `async () => ({ content: [] })`. So they cannot be classified " +
      "read and cannot reach the bypass.",
  ],
  [
    "src/sdw/memory-provenance-signer-prune-tools.ts",
    "The tool name is the imported frozen `memory_provenance_prune_signers` " +
      "operation constant. The literal declares `tool_class: write`, the " +
      "composition root includes the exact name in `WRITE_MCP_TOOLS`, and the " +
      "principal-policy loader force-pins it to Tier 1, so it cannot receive " +
      "the read bypass.",
  ],
]);

/**
 * Tools that create persisted state and are classified `write`. They are the
 * must-pass corpus: if the analyzer stops reporting a mutation for these, its
 * clean result on the read set means nothing.
 */
const KNOWN_STATE_CREATING_TOOLS = [
  "state_write",
  "identity_create",
  "reputation_record",
  "memory_ingest",
] as const;

/** A sink the guard asserts on. Appends are measured but never gated. */
const GATED_KINDS = new Set(["mutation", "subprocess"]);

// ---------------------------------------------------------------------------
// LAUNDERING CORPUS: the permanent must-fail fixtures for the callee resolver.
//
// Every must-fail shape below hides a `node:fs` or `node:child_process`
// primitive from the sink sets, either by interposing a source-local
// declaration between the call site and the primitive, or by naming the
// primitive somewhere other than the callee. Each is a typecheck-clean
// one-liner. They are fixtures rather than one-off mutations because this class
// has been half-closed three times now — first by adding the then-current
// spelling to the name sets, then by classifying over the expanded declaration
// set, then by resolving the callee once through a single chokepoint — and each
// time it survived one indirection further out. A fixture that stops reporting
// its primitive is the class reopening.
//
// PROVENANCE, STATED WITH ITS METHOD, because a count without one is not a
// measurement and this corpus's count has been restated twice. Method: run the
// corpus against a resolver with the expanded-set classification pass disabled,
// and count the must-fail fixtures (those with a non-empty `expect`) whose
// resolved primitive set becomes empty. Re-measured after the nested
// reflective-argument repair, on the corpus as it stands: 40 of 53 must-fail
// fixtures flip; all 9 must-stay-clean fixtures remain clean. Survivors resolve
// through another independent route to the same primitive and remain useful
// pins: a shape closed by one mechanism is exactly the shape a refactor of
// another mechanism can reopen.
//
// They drive the SHIPPING resolver (`createCalleeResolver`) over a synthetic
// program, not a copy of it, so a resolver change cannot pass here and regress
// in the analyzer.
//
// ONLY CLOSED SHAPES ARE PINNED HERE, with no exception. A fixture for a shape
// that still evades is a working evasion of a live guard, published in a public
// repository, and this corpus shipped one such fixture as a drift tripwire
// while stating the rule against it twice. Shapes found open by the attack
// rounds are recorded in the private register under ABC-READCLASS-01 and are
// bounded in prose on the analyzer, never spelled out here.
//
// EVERY MUST-STAY-CLEAN FIXTURE BELOW IS A NEGATIVE CONTROL, not a declared
// gap: each one is an indirection the resolver DOES follow, over a primitive
// that is deliberately absent from the sink sets. They prove the resolver still
// discriminates after each widening, which is the failure a corpus of must-fail
// shapes alone cannot detect.
// ---------------------------------------------------------------------------

interface LaunderingFixture {
  /** The indirection under test, as a reviewer would describe it. */
  readonly what: string;
  /** Sink primitives the resolver must report, as a sorted set. */
  readonly expect: readonly string[];
  /** The module holding the call. Its calls are the ones resolved. */
  readonly code: string;
  /**
   * Sibling modules, keyed by bare name, importable as `./<name>.js`. Only a
   * re-export chain needs these; a chain is a laundering shape in its own right
   * and cannot be written in one file.
   */
  readonly siblings?: Readonly<Record<string, string>>;
}

const LAUNDERING_FIXTURES: readonly LaunderingFixture[] = [
  {
    what: "a namespace import, then a destructure",
    expect: ["fs.writeFileSync"],
    code: `
import * as nodeFs from "node:fs";
const { writeFileSync } = nodeFs;
export function launder(path: string): void {
  writeFileSync(path, "x");
}
`,
  },
  {
    what: "a bare const bound to the imported function",
    expect: ["fs.rmSync"],
    code: `
import { rmSync } from "node:fs";
const drop = rmSync;
export function launder(path: string): void {
  drop(path);
}
`,
  },
  {
    what: "an object literal holding the function, called through the property",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
const shell = { run: execSync };
export function launder(command: string): void {
  shell.run(command);
}
`,
  },
  {
    what: "an interface-typed inline object property",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
interface Shell { run: (command: string) => unknown }
const shell: Shell = { run: execSync };
export function launder(command: string): void {
  void shell.run(command);
}
`,
  },
  {
    // Exact member selection is the false-positive boundary. The mutating
    // sibling must not contaminate the safe property that is actually called.
    // A later reassignment of `shell.run` remains deliberately untracked: this
    // bounded syntactic recovery reads the initializer and does no dataflow.
    what: "a safe interface property beside an unrelated mutating sibling (must stay clean)",
    expect: [],
    code: `
import { execSync } from "node:child_process";
type Fn = (command: string) => unknown;
interface Shell { run: Fn; dangerous: Fn }
function safe(command: string): string { return command; }
const shell: Shell = { run: safe, dangerous: execSync };
export function launder(command: string): void {
  void shell.run(command);
}
`,
  },
  {
    what: "a Record string-literal lookup into an inline object",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
type Fn = (command: string) => unknown;
const shell: Record<string, Fn> = { run: execSync };
export function launder(command: string): void {
  void shell["run"](command);
}
`,
  },
  {
    // As above, selecting every property would manufacture a subprocess hit.
    what: "a safe Record key beside an unrelated mutating key (must stay clean)",
    expect: [],
    code: `
import { execSync } from "node:child_process";
type Fn = (command: string) => unknown;
function safe(command: string): string { return command; }
const shell: Record<string, Fn> = { run: safe, dangerous: execSync };
export function launder(command: string): void {
  void shell["run"](command);
}
`,
  },
  {
    what: "a parenthesized receiver with an interface-erased property",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
interface Shell { run: (command: string) => unknown }
const shell: Shell = { run: execSync };
export function launder(command: string): void {
  void (shell).run(command);
}
`,
  },
  {
    what: "a parenthesized exact element key on an annotated Record",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
type Fn = (command: string) => unknown;
const shell: Record<string, Fn> = { run: execSync };
export function launder(command: string): void {
  void shell[("run")](command);
}
`,
  },
  {
    what: "a parenthesized inline-object initializer behind an interface",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
interface Shell { run: (command: string) => unknown }
const shell: Shell = ({ run: execSync });
export function launder(command: string): void {
  void shell.run(command);
}
`,
  },
  {
    what: "an as-wrapped inline-object initializer behind an interface",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
interface Shell { run: (command: string) => unknown }
const shell: Shell = ({ run: execSync } as Shell);
export function launder(command: string): void {
  void shell.run(command);
}
`,
  },
  {
    what: "a satisfies-wrapped inline-object initializer behind an interface",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
interface Shell { run: (command: string) => unknown }
const shell: Shell = ({ run: execSync } satisfies Shell);
export function launder(command: string): void {
  void shell.run(command);
}
`,
  },
  {
    what: "an exact numeric element key on an annotated Record",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
type Fn = (command: string) => unknown;
const shell: Record<number, Fn> = { 1: execSync };
export function launder(command: string): void {
  void shell[1](command);
}
`,
  },
  {
    what: "a safe numeric Record key beside an unrelated mutating key (must stay clean)",
    expect: [],
    code: `
import { execSync } from "node:child_process";
type Fn = (command: string) => unknown;
function safe(command: string): string { return command; }
const shell: Record<number, Fn> = { 1: safe, 2: execSync };
export function launder(command: string): void {
  void shell[1](command);
}
`,
  },
  {
    what: "a bare const bound to the imported function, subprocess family",
    expect: ["child_process.spawnSync"],
    code: `
import { spawnSync } from "node:child_process";
const go = spawnSync;
export function launder(command: string): void {
  go(command);
}
`,
  },
  {
    what: "a destructured dynamic import",
    expect: ["child_process.execSync"],
    code: `
export async function launder(command: string): Promise<void> {
  const { execSync: dyn } = await import("node:child_process");
  dyn(command);
}
`,
  },
  // The three below were found by attacking the fix for the five above rather
  // than by review, and all three evaded it on the first attempt. They are the
  // reason the fix is three sources of ONE resolved target instead of one.
  {
    what: "a getter handing back the function",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
const box = { get run() { return execSync; } };
export function launder(command: string): void {
  box.run(command);
}
`,
  },
  {
    what: "a callee the call site does not name (array element)",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
const fns = [execSync];
export function launder(command: string): void {
  fns[0]!(command);
}
`,
  },
  {
    what: "a type annotation erasing the initializer's type",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
const run: (command: string) => unknown = execSync;
export function launder(command: string): void {
  run(command);
}
`,
  },
  // The rest are the second attack round on the same fix. None of these evaded
  // it, and they are kept because a shape that is closed today is exactly the
  // shape a later refactor of the resolver reopens without noticing.
  {
    what: "a re-export chain through two hops",
    siblings: {
      "hop-a": `export { execSync } from "node:child_process";`,
      "hop-b": `export { execSync } from "./hop-a.js";`,
    },
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "./hop-b.js";
export function launder(command: string): void {
  execSync(command);
}
`,
  },
  {
    what: "a wildcard re-export",
    siblings: { "hop-star": `export * from "node:child_process";` },
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "./hop-star.js";
export function launder(command: string): void {
  execSync(command);
}
`,
  },
  {
    what: "a bound function",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
const bound = execSync.bind(null);
export function launder(command: string): void {
  bound(command);
}
`,
  },
  {
    what: "a conditional expression selecting between two primitives",
    expect: ["child_process.execSync", "child_process.spawnSync"],
    code: `
import { execSync, spawnSync } from "node:child_process";
const pick = process.env.MODE === "x" ? execSync : spawnSync;
export function launder(command: string): void {
  pick(command);
}
`,
  },
  {
    what: "a function returned from a factory",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
function make() {
  return execSync;
}
const made = make();
export function launder(command: string): void {
  made(command);
}
`,
  },
  {
    what: "a class field holding the function",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
class Box {
  run = execSync;
}
export function launder(command: string): void {
  new Box().run(command);
}
`,
  },
  {
    what: "a default parameter value",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
export function launder(command: string, run = execSync): void {
  run(command);
}
`,
  },
  {
    what: "an array destructure",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
const [taken] = [execSync];
export function launder(command: string): void {
  taken!(command);
}
`,
  },
  {
    what: "a Map lookup",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
const registry = new Map([["run", execSync]]);
export function launder(command: string): void {
  registry.get("run")!(command);
}
`,
  },
  {
    what: "an object spread of a namespace import",
    expect: ["child_process.execSync"],
    code: `
import * as childProcess from "node:child_process";
const spread = { ...childProcess };
export function launder(command: string): void {
  spread.execSync(command);
}
`,
  },
  {
    what: "a computed key on an object literal",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
const table = { run: execSync };
const key = "run" as const;
export function launder(command: string): void {
  table[key](command);
}
`,
  },
  // ---- the reflective invocations -----------------------------------------
  // `.call` was found by attacking the fix for everything above it, and it was
  // the worst of the corpus: it needs no local binding at all, so it defeated
  // the whole laundering closure with one property access on the primitive
  // itself. `.apply` and `Reflect.apply` are the same hole spelled differently.
  {
    what: "the primitive invoked through .call",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
export function launder(command: string): void {
  execSync.call(null, command);
}
`,
  },
  {
    what: "the primitive invoked through .apply",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
export function launder(command: string): void {
  execSync.apply(null, [command]);
}
`,
  },
  {
    what: "the primitive invoked through Reflect.apply",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
export function launder(command: string): void {
  Reflect.apply(execSync, null, [command]);
}
`,
  },
  {
    what: "an aliased const invoked through .call",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
const run = execSync;
export function launder(command: string): void {
  run.call(null, command);
}
`,
  },
  {
    what: "an object-literal property invoked through .call",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
const shell = { run: execSync };
export function launder(command: string): void {
  shell.run.call(null, command);
}
`,
  },
  {
    what: "a getter's result invoked through .call",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
const box = { get run() { return execSync; } };
export function launder(command: string): void {
  box.run.call(null, command);
}
`,
  },
  {
    // Keeps the `!` from being stripped on the way to the receiver. Without the
    // receiver being resolved AS WRITTEN, the unasserted type is
    // `typeof execSync | undefined`, a union with no call signatures, and this
    // shape silently reopens while every other `.call` fixture stays green.
    what: "a Map lookup invoked through .call",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
const registry = new Map([["run", execSync]]);
export function launder(command: string): void {
  registry.get("run")!.call(null, command);
}
`,
  },
  {
    what: "a class field invoked through .apply",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
class Box {
  run = execSync;
}
export function launder(command: string): void {
  new Box().run.apply(null, [command]);
}
`,
  },
  {
    what: "an object-literal property invoked through Reflect.apply",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
const shell = { run: execSync };
export function launder(command: string): void {
  Reflect.apply(shell.run, null, [command]);
}
`,
  },
  {
    what: "a bound function invoked through .call",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
const bound = execSync.bind(null);
export function launder(command: string): void {
  bound.call(null, command);
}
`,
  },
  // ---- the type-only wrappers ----------------------------------------------
  // A cast is the cheapest laundering shape in the corpus: one token, no new
  // binding, and it erases the target for both the symbol lookup and the type
  // fallback at once. All five wrapper spellings are pinned in both positions
  // they can occupy, on the initializer and at the call site, because closing
  // one position and not the other is the same half-fix this corpus exists to
  // catch.
  {
    what: "an as-cast on the initializer",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
const run = execSync as unknown as (command: string) => unknown;
export function launder(command: string): void {
  run(command);
}
`,
  },
  {
    what: "an angle-bracket assertion on the initializer",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
const run = <(command: string) => unknown>(execSync as unknown);
export function launder(command: string): void {
  run(command);
}
`,
  },
  {
    what: "an annotated const whose initializer is cast",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
const run: (command: string) => unknown = execSync as unknown as (c: string) => unknown;
export function launder(command: string): void {
  run(command);
}
`,
  },
  {
    what: "a cast at the call site rather than on a binding",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
export function launder(command: string): void {
  (execSync as unknown as (c: string) => unknown)(command);
}
`,
  },
  {
    what: "a satisfies wrapper on the initializer",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
const run = execSync satisfies (command: string, ...rest: never[]) => unknown;
export function launder(command: string): void {
  run(command);
}
`,
  },
  {
    what: "a non-null assertion on the initializer",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
const maybe: typeof execSync | undefined = execSync;
const run = maybe!;
export function launder(command: string): void {
  run(command);
}
`,
  },
  {
    what: "a cast composed with .call",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
const run = execSync as unknown as (command: string) => unknown;
export function launder(command: string): void {
  run.call(null, command);
}
`,
  },
  {
    what: "a getter returning the primitive behind a cast",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
const box = { get run(): (c: string) => unknown { return execSync as unknown as (c: string) => unknown; } };
export function launder(command: string): void {
  box.run(command);
}
`,
  },
  {
    what: "a default parameter whose value is cast",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
export function launder(
  command: string,
  run: (c: string) => unknown = execSync as unknown as (c: string) => unknown
): void {
  run(command);
}
`,
  },
  {
    what: "an indexed access on a namespace import",
    expect: ["child_process.execSync"],
    code: `
import * as childProcess from "node:child_process";
const key = "execSync" as const;
export function launder(command: string): void {
  childProcess[key](command);
}
`,
  },
  {
    what: "an await of a promise resolving to the primitive",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
export async function launder(command: string): Promise<void> {
  const run = await Promise.resolve(execSync);
  run(command);
}
`,
  },
  {
    what: "a generic identity function returning the primitive",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
function id<T>(value: T): T {
  return value;
}
const run = id(execSync);
export function launder(command: string): void {
  run(command);
}
`,
  },
  // The fourth attack round: a primitive handed over as a VALUE rather than
  // called. Nothing in this file's own text names it as a callee, so before the
  // resolver looked at arguments these reported nothing at all while spawning a
  // real subprocess. The tagged-template form of the same round is closed in
  // the analyzer's walk rather than in the resolver, so it has no fixture here:
  // its sink is found by descending into a source-local tag function, and this
  // corpus resolves call sites without walking bodies.
  {
    what: "a primitive passed as a function value to a builtin higher-order call",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
export function launder(): void {
  ["id"].forEach(execSync);
}
`,
  },
  {
    what: "a primitive passed as a function value to a deferred call",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
export function launder(): void {
  setTimeout(execSync, 0, "id");
}
`,
  },
  {
    what: "a reflective call one level out, target in argument zero",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
type Invoke = (target: unknown, thisArg: unknown, command: unknown) => unknown;
export function launder(command: string): void {
  (Function.prototype.call as unknown as Invoke)(execSync, null, command);
}
`,
  },
  {
    what: "a nested reflective call with a literal invoked-argument vector",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
export function launder(command: string): void {
  Reflect.apply(
    Function.prototype.call,
    Function.prototype.call,
    ([execSync, null, command] as const),
  );
}
`,
  },
  {
    what: "a nested reflective call over a read-only primitive (must stay clean)",
    expect: [],
    code: `
import { readFileSync } from "node:fs";
export function launder(path: string): void {
  Reflect.apply(
    Function.prototype.call,
    Function.prototype.call,
    ([readFileSync, null, path, "utf8"] as const),
  );
}
`,
  },
  // NO FIXTURE FOR AN OPEN SHAPE, INCLUDING THE MEASURED ONE. A fixture is a
  // typecheck-clean, copy-pasteable spelling; a fixture for a shape the guard
  // does not catch is a working evasion of a live guard, published in a public
  // repository. This corpus carried one anyway — the measured dependency-call
  // gap, pinned as an `expect: []` drift tripwire — while the file stated the
  // rule against exactly that twice. The rule wins and the fixture is gone. The
  // bound itself is not softened: it is stated in prose on the analyzer, and
  // the shapes resolve only in the private register under ABC-READCLASS-01.
  {
    // The negative control. Without it a resolver that reported a sink for
    // every resolved builtin would satisfy every fixture above, so the corpus
    // would prove the resolver reaches the declaration but not that it still
    // discriminates. `readFileSync` is a `node:fs` entry point that is
    // deliberately absent from the mutator set.
    what: "the same indirection over a read-only primitive (must stay clean)",
    expect: [],
    code: `
import * as nodeFs from "node:fs";
const { readFileSync } = nodeFs;
export function launder(path: string): string {
  return readFileSync(path, "utf8");
}
`,
  },
  // Three more controls, one per closure added above. Each closure widens what
  // the resolver reaches, and a widening that stops discriminating is a
  // regression that every must-fail fixture would happily pass.
  {
    what: "a read-only primitive through .call (must stay clean)",
    expect: [],
    // The encoding argument is `{ encoding: "utf8" }`, not the bare string
    // `"utf8"`, because `readFileSync.call(...)` routes TypeScript's overload
    // resolution through the LAST declared `readFileSync` overload only (an
    // engine quirk for a generic call target, not specific to this fixture).
    // @types/node 26.4.1 (#1363) reordered that overload set and narrowed the
    // last signature's options parameter to the object-only `ReadFileSyncOptions`
    // interface, so the bare string, which the prior last overload accepted
    // via its `| BufferEncoding` arm, no longer typechecks there. The object
    // form is accepted by every declared overload in both @types/node
    // versions, so it exercises the same read-only call shape without
    // depending on which overload the compiler's last-signature fallback picks.
    code: `
import { readFileSync } from "node:fs";
export function launder(path: string): string {
  return readFileSync.call(null, path, { encoding: "utf8" }) as string;
}
`,
  },
  {
    what: "a read-only primitive through Reflect.apply (must stay clean)",
    expect: [],
    code: `
import { readFileSync } from "node:fs";
export function launder(path: string): unknown {
  return Reflect.apply(readFileSync, null, [path]);
}
`,
  },
  {
    // `.call` on an ordinary local function must not manufacture a sink out of
    // the standard library's `CallableFunction.call`.
    what: "a plain local function through .call (must stay clean)",
    expect: [],
    code: `
function local(value: string): string {
  return value;
}
export function launder(value: string): string {
  return local.call(null, value);
}
`,
  },
  {
    // The control for the function-valued-argument closure. Resolving every
    // callable argument is the widest of these widenings, so it needs the
    // sharpest control: the same shape over a read-only primitive.
    what: "a read-only primitive passed as a function value (must stay clean)",
    expect: [],
    code: `
import { readFileSync } from "node:fs";
function acceptReader(reader: typeof readFileSync): void {
  void reader;
}
export function launder(): void {
  acceptReader(readFileSync);
}
`,
  },
];

/** test/structure -> test -> server */
const TEST_STRUCTURE_DIR = resolve(fileURLToPath(import.meta.url), "..");
const FIXTURE_SERVER_DIR = resolve(TEST_STRUCTURE_DIR, "..", "..");

/**
 * Resolve every call in each fixture with the shipping resolver.
 *
 * The fixtures are overlaid on the real compiler host rather than written to
 * disk, so `node:fs` and `node:child_process` resolve to the SAME `@types/node`
 * declaration files the analyzer matches against. A hand-written stub of those
 * modules would make the fixtures pass while proving nothing about the real
 * declaration-file match, which is the failure mode this whole file is about.
 */
function resolveLaunderingFixtures(): Map<string, string[]> {
  const options: ts.CompilerOptions = {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Bundler,
    lib: ["lib.es2022.d.ts"],
    strict: true,
    noEmit: true,
    skipLibCheck: true,
  };
  const virtual = new Map<string, string>();
  const fileNames: string[] = [];
  LAUNDERING_FIXTURES.forEach((fixture, index) => {
    // Sibling names are namespaced per fixture, so two fixtures cannot resolve
    // each other's hops and pass on the wrong module.
    const scope = (bare: string): string =>
      join(TEST_STRUCTURE_DIR, `laundering-${index}-${bare}.virtual.ts`);
    for (const [bare, text] of Object.entries(fixture.siblings ?? {})) {
      virtual.set(scope(bare), text.replace(/"\.\/([\w-]+)\.js"/g, `"./laundering-${index}-$1.virtual.js"`));
    }
    const fileName = scope("main");
    virtual.set(
      fileName,
      fixture.code.replace(/"\.\/([\w-]+)\.js"/g, `"./laundering-${index}-$1.virtual.js"`)
    );
    fileNames.push(fileName);
  });

  const host = ts.createCompilerHost(options, true);
  const baseGetSourceFile = host.getSourceFile.bind(host);
  const baseFileExists = host.fileExists.bind(host);
  const baseReadFile = host.readFile.bind(host);
  host.getSourceFile = (fileName, languageVersion, onError, shouldCreate) => {
    const text = virtual.get(fileName);
    if (text !== undefined) {
      return ts.createSourceFile(fileName, text, languageVersion, true, ts.ScriptKind.TS);
    }
    return baseGetSourceFile(fileName, languageVersion, onError, shouldCreate);
  };
  host.fileExists = (fileName) => virtual.has(fileName) || baseFileExists(fileName);
  host.readFile = (fileName) => virtual.get(fileName) ?? baseReadFile(fileName);
  host.getCurrentDirectory = () => FIXTURE_SERVER_DIR;

  const program = ts.createProgram(fileNames, options, host);
  const diagnostics = [
    ...program.getSyntacticDiagnostics(),
    ...program.getSemanticDiagnostics(),
  ].filter((diagnostic) => diagnostic.file !== undefined && virtual.has(diagnostic.file.fileName));
  if (diagnostics.length > 0) {
    throw new Error(
      `invalid laundering fixture:\n${diagnostics
        .map((diagnostic) => ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n"))
        .join("\n")}`
    );
  }
  const checker = program.getTypeChecker();
  // No interface-to-class index: none of these shapes goes through one, and
  // supplying an empty one keeps the fixture's resolution path honest.
  const resolver = createCalleeResolver(checker, () => []);

  const byDescription = new Map<string, string[]>();
  for (const [index, fileName] of fileNames.entries()) {
    const source = program.getSourceFile(fileName);
    if (source === undefined) throw new Error(`fixture did not load: ${fileName}`);
    const found: string[] = [];
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node)) {
        const callee = node.expression;
        const callSiteName =
          ts.isPropertyAccessExpression(callee) || ts.isPropertyAccessChain(callee)
            ? callee.name.text
            : ts.isIdentifier(callee)
              ? callee.text
              : undefined;
        for (const sink of resolver.resolve(callee, callSiteName, node.arguments).sinks) {
          found.push(sink.primitive);
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
    const fixture = LAUNDERING_FIXTURES[index];
    if (fixture === undefined) throw new Error(`fixture ${index} disappeared`);
    byDescription.set(fixture.what, [...new Set(found)].sort());
  }
  return byDescription;
}

// ---------------------------------------------------------------------------
// IMPLICIT-INVOCATION FIXTURES: the permanent regression and negative-control
// corpus for the three implicit invocation forms closed by GATE-A-R5.
//
// Each fixture is a self-contained TypeScript module whose `handler` function
// contains one of three implicit invocation forms — getter read, setter
// assignment, for-of iteration — over a source-local declaration whose body
// calls a `node:child_process` or `node:fs` entry point. The test walks the
// `handler` body using the same chokepoint the analyzer uses, descending into
// implicitly-invoked bodies and classifying calls inside them through the
// shipping resolver. The fixture proves the form IS walked (regressions) or IS
// NOT falsely walked (negative controls).
//
// WHAT IS CLOSED IS EXACTLY THREE FORMS: getter read, simple setter
// assignment, and synchronous source-local for-of. Implicit-invocation
// coverage remains partial; remaining bounds resolve privately under
// ABC-READCLASS-01 / GATE-A-R5.
// ---------------------------------------------------------------------------

interface ImplicitInvocationFixture {
  /** The implicit invocation form under test. */
  readonly what: string;
  /** Sink primitives the walk must report, as a sorted set. */
  readonly expect: readonly string[];
  /** The module containing a `handler` function with the implicit form. */
  readonly code: string;
}

const IMPLICIT_INVOCATION_FIXTURES: readonly ImplicitInvocationFixture[] = [
  // ---- regressions: each must report child_process.execSync ----------------
  {
    what: "a getter whose body spawns a subprocess (GATE-A-R5 form 1)",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
class Probe {
  get status(): string { execSync("id"); return "ok"; }
}
export function handler(): string {
  return new Probe().status;
}
`,
  },
  {
    what: "a setter whose body spawns a subprocess (GATE-A-R5 form 2)",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
class Target {
  set value(v: string) { execSync(v); }
}
export function handler(v: string): void {
  new Target().value = v;
}
`,
  },
  {
    what: "a for-of loop invoking a source-local [Symbol.iterator] that spawns a subprocess (GATE-A-R5 form 3)",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
class Items {
  *[Symbol.iterator](): Generator<string> {
    execSync("id");
    yield "done";
  }
}
export function handler(): void {
  for (const item of new Items()) { void item; }
}
`,
  },
  // ---- negative controls: must stay clean -----------------------------------
  //
  // These fixtures prove that the resolver does NOT manufacture a mutation sink
  // for the form under test. They do NOT prove the form is reached at all —
  // that proof comes from the positive controls (the regression fixtures above),
  // which must report their primitive. Both directions are required: a resolver
  // that reported nothing for everything would satisfy every negative control
  // while being entirely inert; a resolver that reported everything would
  // satisfy every positive control while being entirely wrong.
  {
    what: "a getter that reads only (must stay clean)",
    expect: [],
    code: `
import { readFileSync } from "node:fs";
class Reader {
  get content(): string { return readFileSync("/dev/null", "utf8"); }
}
export function handler(): string {
  return new Reader().content;
}
`,
  },
  {
    what: "a setter that reads only (must stay clean)",
    expect: [],
    code: `
import { readFileSync } from "node:fs";
class Writer {
  private _data = "";
  set data(v: string) { this._data = readFileSync("/dev/null", "utf8"); }
}
export function handler(): void {
  new Writer().data = "x";
}
`,
  },
  {
    what: "a for-of loop over a source-local iterator that reads only (must stay clean)",
    expect: [],
    code: `
import { readFileSync } from "node:fs";
class SafeItems {
  *[Symbol.iterator](): Generator<string> {
    yield readFileSync("/dev/null", "utf8");
  }
}
export function handler(): void {
  for (const item of new SafeItems()) { void item; }
}
`,
  },
  {
    what: "an ordinary property read, not a getter (must stay clean)",
    expect: [],
    code: `
class Plain {
  status = "ok";
}
export function handler(): string {
  return new Plain().status;
}
`,
  },
  {
    what: "an ordinary property write, not a setter (must stay clean)",
    expect: [],
    code: `
class Plain {
  value = "";
}
export function handler(): void {
  new Plain().value = "x";
}
`,
  },
  {
    // Paired getter/setter: simple assignment invokes the setter only, not the getter.
    // Verifies that `resolveImplicitInvocations` correctly excludes getter lookup
    // when the property access is the assignment target.
    what: "a paired getter (calls execSync) with read-only setter — simple assignment must stay clean",
    expect: [],
    code: `
import { execSync } from "node:child_process";
class Accessor {
  private _v = "";
  get value(): string { execSync("id"); return this._v; }
  set value(v: string) { this._v = v; }
}
export function handler(v: string): void {
  new Accessor().value = v;
}
`,
  },
];

/**
 * Walk each implicit-invocation fixture's `handler` function, descending into
 * implicitly-invoked bodies through the same chokepoint the analyzer uses and
 * classifying calls inside them through the shipping resolver.
 *
 * The fixtures use the same overlay-on-real-host technique as the laundering
 * corpus, so `node:child_process` and `node:fs` resolve to the real
 * `@types/node` declaration files.
 */
function resolveImplicitInvocationFixtures(): Map<string, string[]> {
  const options: ts.CompilerOptions = {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Bundler,
    lib: ["lib.es2022.d.ts"],
    strict: true,
    noEmit: true,
    skipLibCheck: true,
  };
  const virtual = new Map<string, string>();
  const fileNames: string[] = [];
  // Associate each virtual file name directly with its fixture's `what` string
  // so callers can key results by `what` and not by Map-insertion position.
  const fileToWhat = new Map<string, string>();
  IMPLICIT_INVOCATION_FIXTURES.forEach((fixture, index) => {
    const fileName = join(TEST_STRUCTURE_DIR, `implicit-${index}-main.virtual.ts`);
    virtual.set(fileName, fixture.code);
    fileNames.push(fileName);
    fileToWhat.set(fileName, fixture.what);
  });

  const host = ts.createCompilerHost(options, true);
  const baseGetSourceFile = host.getSourceFile.bind(host);
  const baseFileExists = host.fileExists.bind(host);
  const baseReadFile = host.readFile.bind(host);
  host.getSourceFile = (fileName, languageVersion, onError, shouldCreate) => {
    const text = virtual.get(fileName);
    if (text !== undefined) {
      return ts.createSourceFile(fileName, text, languageVersion, true, ts.ScriptKind.TS);
    }
    return baseGetSourceFile(fileName, languageVersion, onError, shouldCreate);
  };
  host.fileExists = (fileName) => virtual.has(fileName) || baseFileExists(fileName);
  host.readFile = (fileName) => virtual.get(fileName) ?? baseReadFile(fileName);
  host.getCurrentDirectory = () => FIXTURE_SERVER_DIR;

  const program = ts.createProgram(fileNames, options, host);
  const checker = program.getTypeChecker();
  const resolver = createCalleeResolver(checker, () => []);

  const byFile = new Map<string, string[]>();
  for (const fileName of fileNames) {
    const source = program.getSourceFile(fileName);
    if (source === undefined) throw new Error(`fixture did not load: ${fileName}`);

    // Find the `handler` function — the entry point the production walk starts
    // from. Walking it through `walkForSinks` (the same primitive `sinksFor`
    // uses) means the test cannot stay green if the production walk changes
    // how it descends into implicit invocation bodies or integrates them.
    let handlerNode: ts.Node | undefined;
    const findHandler = (node: ts.Node): void => {
      if (
        ts.isFunctionDeclaration(node) &&
        node.name?.text === "handler" &&
        node.body !== undefined
      ) {
        handlerNode = node;
        return;
      }
      ts.forEachChild(node, findHandler);
    };
    findHandler(source);
    if (handlerNode === undefined) throw new Error(`fixture has no handler function: ${fileName}`);

    const found: string[] = [];
    const walked = new Set<string>();
    walkForSinks(
      handlerNode,
      checker,
      resolver,
      TEST_STRUCTURE_DIR,
      (_node, primitive) => { found.push(primitive); },
      walked,
      0,
      ["handler"],
      [],
    );
    const what = fileToWhat.get(fileName);
    if (what === undefined) throw new Error(`no fixture registered for: ${fileName}`);
    byFile.set(what, [...new Set(found)].sort());
  }
  return byFile;
}

interface ClassDispatchFixture {
  readonly what: string;
  readonly expect: readonly string[];
  readonly code: string;
  readonly siblings?: Readonly<Record<string, string>>;
}

const CLASS_DISPATCH_FIXTURES: readonly ClassDispatchFixture[] = [
  {
    what: "an abstract base method dispatches to its concrete override",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
abstract class Runner { abstract run(command: string): void; }
class ShellRunner extends Runner { run(command: string): void { execSync(command); } }
export function handler(runner: Runner): void { runner.run("id"); }
`,
  },
  {
    what: "unrelated same-named base classes do not collide",
    expect: [],
    siblings: {
      clean: `
export abstract class Base { abstract run(): void; }
export class Reader extends Base { run(): void {} }
`,
      other: `
import { execSync } from "node:child_process";
abstract class Base { abstract run(): void; }
export class Writer extends Base { run(): void { execSync("id"); } }
`,
    },
    code: `
import { Base } from "./clean.js";
import "./other.js";
export function handler(value: Base): void { value.run(); }
`,
  },
  {
    what: "a base method expands across multiple subclasses",
    expect: ["child_process.execSync", "fs.rmSync"],
    code: `
import { execSync } from "node:child_process";
import { rmSync } from "node:fs";
abstract class Action { abstract apply(value: string): void; }
class ShellAction extends Action { apply(value: string): void { execSync(value); } }
class DeleteAction extends Action { apply(value: string): void { rmSync(value); } }
export function handler(action: Action): void { action.apply("target"); }
`,
  },
  {
    what: "an abstract method expands through transitive inheritance",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
abstract class Root { abstract run(): void; }
abstract class Middle extends Root {}
class Leaf extends Middle { run(): void { execSync("id"); } }
export function handler(value: Root): void { value.run(); }
`,
  },
  {
    what: "interface dispatch keeps resolving implementing class members",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
interface Runner { run(): void; }
class ConcreteRunner implements Runner { run(): void { execSync("id"); } }
export function handler(value: Runner): void { value.run(); }
`,
  },
  {
    what: "a direct type alias preserves interface dispatch",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
interface Runner { run(): void; }
type Alias = Runner;
class ConcreteRunner implements Alias { run(): void { execSync("id"); } }
export function handler(value: Runner): void { value.run(); }
`,
  },
  {
    what: "a chained type alias preserves interface dispatch",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
interface Runner { run(): void; }
type FirstAlias = Runner;
type SecondAlias = FirstAlias;
class ConcreteRunner implements SecondAlias { run(): void { execSync("id"); } }
export function handler(value: Runner): void { value.run(); }
`,
  },
  {
    what: "an intersection alias indexes each named interface constituent",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
interface Runner { run(): void; }
interface Labelled { readonly label: string; }
type Alias = Runner & Labelled;
class ConcreteRunner implements Alias {
  readonly label = "concrete";
  run(): void { execSync("id"); }
}
export function handler(value: Runner): void { value.run(); }
`,
  },
  {
    what: "a renamed imported type alias preserves interface dispatch",
    expect: ["child_process.execSync"],
    siblings: {
      model: `
export interface Runner { run(): void; }
export type Alias = Runner;
`,
    },
    code: `
import { execSync } from "node:child_process";
import { Alias as ImportedAlias, Runner } from "./model.js";
class ConcreteRunner implements ImportedAlias { run(): void { execSync("id"); } }
export function handler(value: Runner): void { value.run(); }
`,
  },
  {
    what: "a namespace-qualified type alias preserves interface dispatch",
    expect: ["child_process.execSync"],
    siblings: {
      model: `
export interface Runner { run(): void; }
export type Alias = Runner;
`,
    },
    code: `
import { execSync } from "node:child_process";
import * as model from "./model.js";
class ConcreteRunner implements model.Alias { run(): void { execSync("id"); } }
export function handler(value: model.Runner): void { value.run(); }
`,
  },
  {
    what: "a static base member does not match a subclass instance member",
    expect: [],
    code: `
import { execSync } from "node:child_process";
class Base { static run(): void {} }
class Child extends Base { run(): void { execSync("id"); } }
export function handler(): void { Base.run(); }
`,
  },
  {
    what: "an instance base member does not match a subclass static member",
    expect: [],
    code: `
import { execSync } from "node:child_process";
class Base { run(): void {} }
class Child extends Base { static run(): void { execSync("id"); } }
export function handler(value: Base): void { value.run(); }
`,
  },
  {
    what: "a static member dispatches to a static subclass override",
    expect: ["child_process.execSync"],
    code: `
import { execSync } from "node:child_process";
class Base { static run(): void {} }
class Child extends Base { static override run(): void { execSync("id"); } }
export function handler(value: typeof Base): void { value.run(); }
`,
  },
];

function resolveClassDispatchFixtures(): Map<string, string[]> {
  const options: ts.CompilerOptions = {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Bundler,
    lib: ["lib.es2022.d.ts"],
    strict: true,
    noEmit: true,
    skipLibCheck: true,
  };
  const virtual = new Map<string, string>();
  const mainFiles: string[] = [];
  CLASS_DISPATCH_FIXTURES.forEach((fixture, index) => {
    const scope = (bare: string): string =>
      join(TEST_STRUCTURE_DIR, `class-dispatch-${index}-${bare}.virtual.ts`);
    for (const [bare, text] of Object.entries(fixture.siblings ?? {})) {
      virtual.set(scope(bare), text);
    }
    const main = scope("main");
    virtual.set(
      main,
      fixture.code.replace(/"\.\/([\w-]+)\.js"/g, `"./class-dispatch-${index}-$1.virtual.js"`)
    );
    mainFiles.push(main);
  });

  const host = ts.createCompilerHost(options, true);
  const baseGetSourceFile = host.getSourceFile.bind(host);
  const baseFileExists = host.fileExists.bind(host);
  const baseReadFile = host.readFile.bind(host);
  host.getSourceFile = (fileName, languageVersion, onError, shouldCreate) => {
    const source = virtual.get(fileName);
    return source === undefined
      ? baseGetSourceFile(fileName, languageVersion, onError, shouldCreate)
      : ts.createSourceFile(fileName, source, languageVersion, true, ts.ScriptKind.TS);
  };
  host.fileExists = (fileName) => virtual.has(fileName) || baseFileExists(fileName);
  host.readFile = (fileName) => virtual.get(fileName) ?? baseReadFile(fileName);
  host.getCurrentDirectory = () => FIXTURE_SERVER_DIR;

  const program = ts.createProgram([...virtual.keys()], options, host);
  const checker = program.getTypeChecker();
  const diagnostics = [
    ...program.getSyntacticDiagnostics(),
    ...program.getSemanticDiagnostics(),
  ].filter((diagnostic) => diagnostic.file !== undefined && virtual.has(diagnostic.file.fileName));
  if (diagnostics.length > 0) {
    throw new Error(
      `invalid class-dispatch fixture:\n${diagnostics
        .map((diagnostic) => ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n"))
        .join("\n")}`
    );
  }
  const sources = program.getSourceFiles().filter((source) => virtual.has(source.fileName));
  const resolver = createCalleeResolver(checker, createImplementationLookup(checker, sources));
  const resolved = new Map<string, string[]>();

  mainFiles.forEach((fileName, index) => {
    const source = program.getSourceFile(fileName);
    if (source === undefined) throw new Error(`fixture did not load: ${fileName}`);
    let handler: ts.FunctionDeclaration | undefined;
    const findHandler = (node: ts.Node): void => {
      if (ts.isFunctionDeclaration(node) && node.name?.text === "handler") handler = node;
      ts.forEachChild(node, findHandler);
    };
    findHandler(source);
    if (handler === undefined) throw new Error(`fixture has no handler: ${fileName}`);

    const found: string[] = [];
    walkForSinks(
      handler,
      checker,
      resolver,
      TEST_STRUCTURE_DIR,
      (_node, primitive) => { found.push(primitive); },
      new Set<string>(),
      0,
      ["handler"],
      [],
    );
    const fixture = CLASS_DISPATCH_FIXTURES[index];
    if (fixture === undefined) throw new Error(`fixture ${index} disappeared`);
    resolved.set(fixture.what, [...new Set(found)].sort());
  });
  return resolved;
}

interface TraversalFixtureResult {
  readonly sinks: readonly string[];
  readonly truncations: readonly TraversalTruncationKind[];
}

function resolveTraversalFixture(code: string): TraversalFixtureResult {
  const options: ts.CompilerOptions = {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Bundler,
    lib: ["lib.es2022.d.ts"],
    strict: true,
    noEmit: true,
    skipLibCheck: true,
  };
  const fileName = join(TEST_STRUCTURE_DIR, "traversal-cap.virtual.ts");
  const host = ts.createCompilerHost(options, true);
  const baseGetSourceFile = host.getSourceFile.bind(host);
  const baseFileExists = host.fileExists.bind(host);
  const baseReadFile = host.readFile.bind(host);
  host.getSourceFile = (candidate, languageVersion, onError, shouldCreate) =>
    candidate === fileName
      ? ts.createSourceFile(candidate, code, languageVersion, true, ts.ScriptKind.TS)
      : baseGetSourceFile(candidate, languageVersion, onError, shouldCreate);
  host.fileExists = (candidate) => candidate === fileName || baseFileExists(candidate);
  host.readFile = (candidate) => candidate === fileName ? code : baseReadFile(candidate);
  host.getCurrentDirectory = () => FIXTURE_SERVER_DIR;

  const program = ts.createProgram([fileName], options, host);
  const diagnostics = [
    ...program.getSyntacticDiagnostics(),
    ...program.getSemanticDiagnostics(),
  ].filter((diagnostic) => diagnostic.file?.fileName === fileName);
  if (diagnostics.length > 0) {
    throw new Error(
      `invalid traversal fixture:\n${diagnostics
        .map((diagnostic) => ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n"))
        .join("\n")}`
    );
  }

  const source = program.getSourceFile(fileName);
  if (source === undefined) throw new Error("traversal fixture did not load");
  let handler: ts.FunctionDeclaration | undefined;
  const findHandler = (node: ts.Node): void => {
    if (ts.isFunctionDeclaration(node) && node.name?.text === "handler") handler = node;
    ts.forEachChild(node, findHandler);
  };
  findHandler(source);
  if (handler === undefined) throw new Error("traversal fixture has no handler");

  const rawTruncations: TraversalTruncation[] = [];
  const record = (kind: TraversalTruncationKind, node: ts.Node): void => {
    const line = node.getSourceFile().getLineAndCharacterOfPosition(node.getStart()).line + 1;
    rawTruncations.push({ kind, tool: "fixture", site: `traversal-cap.virtual.ts:${line}` });
  };
  const checker = program.getTypeChecker();
  const resolver = createCalleeResolver(checker, () => [], record);
  const sinks: string[] = [];
  walkForSinks(
    handler,
    checker,
    resolver,
    TEST_STRUCTURE_DIR,
    (_node, primitive) => { sinks.push(primitive); },
    new Set<string>(),
    0,
    ["handler"],
    [],
    undefined,
    record,
  );
  return {
    sinks: [...new Set(sinks)].sort(),
    truncations: deduplicateTraversalTruncations(rawTruncations).map(({ kind }) => kind),
  };
}

function callDepthFixture(depth: number): string {
  const functions = Array.from({ length: depth }, (_, index) => {
    const name = `f${index + 1}`;
    const body = index + 1 === depth ? `execSync("id");` : `f${index + 2}();`;
    return `function ${name}(): void { ${body} }`;
  }).join("\n");
  return `
import { execSync } from "node:child_process";
${functions}
export function handler(): void { f1(); }
`;
}

function aliasFixture(aliases: number): string {
  const declarations: string[] = [];
  for (let index = aliases - 1; index >= 0; index -= 1) {
    const target = index === aliases - 1 ? "execSync" : `a${index + 1}`;
    declarations.push(`const a${index}: (command: string) => unknown = ${target};`);
  }
  return `
import { execSync } from "node:child_process";
${declarations.join("\n")}
export function handler(): void { void a0("id"); }
`;
}

function castFixture(wrappers: number): string {
  return `
import { execSync } from "node:child_process";
const f: (command: string) => unknown = execSync${"!".repeat(wrappers)};
export function handler(): void { void f("id"); }
`;
}

function reflectiveFixture(hops: number): string {
  return `
import { execSync } from "node:child_process";
function noop(): void {}
export function handler(): void { void execSync${".call".repeat(hops)}(noop, null, "id"); }
`;
}

describe("read-classified MCP tools and durable-state mutation", () => {
  const report = analyzeReadToolMutationReachability();
  let resolvedLaunderingFixtures: Map<string, string[]>;
  let resolvedClassDispatchFixtures: Map<string, string[]>;

  beforeAll(() => {
    // Resolve the synthetic program once so splitting the corpus into
    // independently counted tests does not multiply the compiler work. These
    // assertions keep duplicate descriptions or a partial result map from
    // laundering a missing case into a green parameterized run.
    resolvedLaunderingFixtures = resolveLaunderingFixtures();
    expect(new Set(LAUNDERING_FIXTURES.map((fixture) => fixture.what))).toHaveLength(
      LAUNDERING_FIXTURES.length
    );
    expect(resolvedLaunderingFixtures.size).toBe(LAUNDERING_FIXTURES.length);
    resolvedClassDispatchFixtures = resolveClassDispatchFixtures();
    expect(new Set(CLASS_DISPATCH_FIXTURES.map((fixture) => fixture.what))).toHaveLength(
      CLASS_DISPATCH_FIXTURES.length
    );
    expect(resolvedClassDispatchFixtures.size).toBe(CLASS_DISPATCH_FIXTURES.length);
  });

  it("parsed the shipping classification tables", () => {
    // A parser that matched nothing would produce an empty target set and pass
    // every later assertion vacuously. These floors are order-of-magnitude
    // sanity, not exact counts, so adding or removing a tool never edits them.
    expect(report.classification.readTable.length).toBeGreaterThan(25);
    expect(report.classification.writeTable.length).toBeGreaterThan(25);
    expect(report.classification.inlineRead.length).toBeGreaterThan(5);
    expect(report.readTools.length).toBeGreaterThanOrEqual(
      report.classification.readTable.length
    );
  });

  it("read every element of the shipping classification tables", () => {
    // The anti-vacuity backstop for the TABLE half of the target set, and the
    // counterpart of the inline one below. `classifyMcpTools` builds the same
    // `Set` at RUNTIME, so an element this parser drops (a spread, an
    // identifier, a template with a substitution) is still classified `read`
    // and still granted the audit-integrity bypass while quietly leaving this
    // analysis. The length floor above is order-of-magnitude and cannot see one
    // tool go missing; this can.
    expect(report.classification.unparsableTableElements).toEqual([]);
  });

  it("classifies each tool exactly once", () => {
    // `classifyMcpTools` in src/index.ts checks the write table, then the
    // operator table, then the read table, then any inline tool_class. That
    // precedence only matters if the sets overlap; asserting they do not is
    // what lets this guard treat the read set as simply "the read tools"
    // instead of restating the precedence and drifting from it.
    const write = new Set([
      ...report.classification.writeTable,
      ...report.classification.operatorTable,
      ...report.classification.inlineWrite,
    ]);
    const bothWays = report.readTools.filter((name) => write.has(name));
    expect(bothWays).toEqual([]);
  });

  it("resolves a handler for every read-classified tool", () => {
    // An unresolved handler is analyzed as reaching nothing, so it would read
    // as clean. Absent must not read as passing: it fails here instead.
    expect(report.unresolvedHandlers).toEqual([]);
    expect(report.handlerLocations.size).toBe(report.readTools.length);
  });

  it("completes the shipping-tree analysis without traversal truncation", () => {
    expect(report.truncations).toEqual([]);
  });

  it.each([
    ["call depth boundary", callDepthFixture(60), ["child_process.execSync"], []],
    ["call depth boundary plus one", callDepthFixture(61), [], ["call_depth"]],
    ["explicit depth 65", callDepthFixture(65), [], ["call_depth"]],
    ["four alias hops", aliasFixture(4), ["child_process.execSync"], []],
    ["five alias hops", aliasFixture(5), [], ["alias_hops"]],
    ["explicit seven alias hops", aliasFixture(7), [], ["alias_hops"]],
    ["ten cast wrappers", castFixture(10), ["child_process.execSync"], []],
    ["eleven cast wrappers", castFixture(11), [], ["cast_hops"]],
    ["four reflective hops", reflectiveFixture(4), ["child_process.execSync"], []],
    ["five reflective hops", reflectiveFixture(5), [], ["reflective_hops"]],
  ] as const)("fails loud at traversal cap: %s", (_what, code, sinks, truncations) => {
    expect(resolveTraversalFixture(code)).toEqual({ sinks, truncations });
  });

  it("deduplicates stable truncation records", () => {
    const record: TraversalTruncation = {
      kind: "alias_hops",
      tool: "fixture",
      site: "test/structure/traversal-cap.virtual.ts:1",
    };
    expect(deduplicateTraversalTruncations([record, record])).toEqual([record]);
  });

  it("analyzed every inline tool literal it found", () => {
    // The anti-vacuity backstop for the INLINE half of the target set. The
    // table half reds through `unresolvedHandlers` above; an inline literal the
    // extractor cannot parse would instead vanish from the analyzed set while
    // the router still classified it and still granted the bypass. Comparing
    // the count of literals CARRYING a `tool_class` against the count the
    // analyzer actually RESOLVED is what closes that asymmetry.
    const {
      resolvedReadLiteralNames,
      resolvedWriteLiteralNames,
      unresolvableToolLiterals,
      unparsableToolClassLiterals,
    } = report.inlineAntiVacuity;

    // A `tool_class` this extractor cannot read is worse than an absent one:
    // the router compares the RUNTIME value, so the tool is still classified
    // and still gets the bypass while dropping out of the analyzed set.
    expect(unparsableToolClassLiterals).toEqual([]);

    // Two literals sharing a name means the handler map kept only the first and
    // the second was analyzed as if it did not exist. Checked over EVERY
    // resolved tool literal, not just the inline-classified ones: the majority
    // of read tools are classified by the `READ_MCP_TOOLS` table and carry no
    // inline `tool_class`, so scoping this to the inline set (the earlier
    // shape) left the larger half of the target set unguarded.
    const duplicates = (names: readonly string[]): string[] =>
      names.filter((name, index) => names.indexOf(name) !== index);
    expect(duplicates(resolvedReadLiteralNames)).toEqual([]);
    expect(duplicates(resolvedWriteLiteralNames)).toEqual([]);
    expect(duplicates(report.resolvedToolLiteralNames)).toEqual([]);

    // Every literal the extractor RESOLVED has to appear in the parsed set it
    // feeds the analysis. Full-set equality, not a count: a count can match
    // while the membership differs.
    expect([...new Set(resolvedReadLiteralNames)].sort()).toEqual(
      report.classification.inlineRead
    );
    expect([...new Set(resolvedWriteLiteralNames)].sort()).toEqual(
      report.classification.inlineWrite
    );

    // Any OTHER file growing an unresolvable tool literal is a review event,
    // not a silent drop out of the analyzed set.
    const undocumented = unresolvableToolLiterals.filter(
      (file) => !REVIEWED_RUNTIME_NAMED_TOOL_FILES.has(file)
    );
    expect(undocumented).toEqual([]);
    for (const [, why] of REVIEWED_RUNTIME_NAMED_TOOL_FILES) {
      expect(why.length).toBeGreaterThan(0);
    }
  });

  it("still detects mutation in tools known to create persisted state", () => {
    const undetected = KNOWN_STATE_CREATING_TOOLS.filter(
      (tool) => !sinksForTool(tool).some((hit) => GATED_KINDS.has(hit.kind))
    );
    expect(undetected).toEqual([]);
  });

  it("reaches no durable-state mutation outside the reviewed read-path maintenance", () => {
    const unreviewed: string[] = [];
    for (const [tool, hits] of report.hits) {
      const gated = hits.filter((hit) => GATED_KINDS.has(hit.kind));
      if (gated.length === 0) continue;
      for (const hit of gated) {
        if (isReviewedReadPathMaintenance(tool, hit)) continue;
        unreviewed.push(
          `${tool}: ${hit.primitive} at ${hit.site} (via ${hit.caller ?? "<handler>"})\n` +
            `    via ${hit.via.join(" -> ")}`
        );
      }
    }
    expect(unreviewed).toEqual([]);
  });

  it("keeps each reviewed quarantine triple exact across primitive, site, and caller", () => {
    const reviewedHit = (report.hits.get("sdw_memory_provenance") ?? []).find(
      (hit) =>
        hit.primitive === "storage.write" &&
        hit.site === "sdwBackendWrite@src/sdw/write-gate.ts" &&
        hit.caller === "putProvenanceStatus@src/sdw/document-corpus-store.ts"
    );
    if (reviewedHit === undefined) throw new Error("reviewed quarantine write disappeared");
    expect(isReviewedReadPathMaintenance("sdw_memory_provenance", reviewedHit)).toBe(true);

    const unreviewedVariants: readonly SinkHit[] = [
      { ...reviewedHit, primitive: "storage.delete" },
      { ...reviewedHit, site: "anotherSite@src/sdw/write-gate.ts" },
      { ...reviewedHit, caller: "anotherCaller@src/sdw/document-corpus-store.ts" },
    ];
    // These are the three dimensions used by the shipping assertion above: a
    // new primitive, site, or immediate caller must remain an unreviewed red.
    expect(
      unreviewedVariants.map((hit) =>
        isReviewedReadPathMaintenance("sdw_memory_provenance", hit)
      )
    ).toEqual([false, false, false]);
  });

  it("keeps the reviewed list free of entries that no longer apply", () => {
    // A residual that has been fixed but left listed turns this guard back into
    // a hand-maintained table of names, which is the shape it was built to
    // replace. Both directions are checked so the list can only shrink by being
    // reconciled.
    const stale: string[] = [];
    for (const [tool, reviewed] of REVIEWED_READ_PATH_MAINTENANCE) {
      const live = (report.hits.get(tool) ?? []).filter((hit) =>
        GATED_KINDS.has(hit.kind)
      );
      for (const entry of reviewed.sites) {
        const matched = live.some(
          (hit) =>
            hit.primitive === entry.primitive &&
            hit.site === entry.site &&
            hit.caller === entry.through
        );
        if (!matched) {
          stale.push(`${tool}: ${entry.primitive} at ${entry.site} via ${entry.through}`);
        }
      }
      expect(reviewed.why.length).toBeGreaterThan(0);
    }
    expect(stale).toEqual([]);
  });

  it.each(LAUNDERING_FIXTURES)(
    "classifies a laundered sink: $what",
    (fixture) => {
      // One program for the whole corpus, so a fixture cannot pass by loading a
      // different `@types/node` than its neighbours.
      //
      // Every corpus entry is a distinct Vitest case, so removing or breaking one
      // changes the repository-wide passing-test floor by one. The shared
      // beforeAll keeps the compiler cost constant while its cardinality checks
      // retain the former whole-map anti-vacuity guarantee.
      const actual = resolvedLaunderingFixtures.get(fixture.what);
      expect(actual, `fixture disappeared: ${fixture.what}`).toBeDefined();
      expect(actual).toEqual([...fixture.expect].sort());
    }
  );

  it("walks implicit invocations: getter reads, setter assignments, and iterator protocol", () => {
    // GATE-A-R5 regression and negative-control corpus. Three implicit
    // invocation forms can reach a subprocess while a call-expression-only
    // walk reports nothing: (1) reading a property whose declaration is a
    // getter, (2) assigning a property whose declaration is a setter, (3)
    // consuming an iterable whose source-local [Symbol.iterator] is invoked
    // by the iterator protocol.
    //
    // Each regression fixture contains a source-local accessor or iterator
    // whose body calls `child_process.execSync` and a `handler` function
    // that triggers the implicit invocation. Each negative control contains
    // the same form over a read-only primitive or an ordinary (non-accessor)
    // property and must report no sinks.
    //
    // WHAT IS CLOSED IS EXACTLY THREE FORMS: getter read, simple setter
    // assignment, and synchronous source-local for-of. Implicit-invocation
    // coverage remains partial; remaining bounds resolve privately under
    // ABC-READCLASS-01 / GATE-A-R5.
    // Results are keyed by `fixture.what` — no insertion-order coupling.
    const resolved = resolveImplicitInvocationFixtures();
    const actual: Record<string, readonly string[]> = {};
    const expected: Record<string, readonly string[]> = {};
    for (const [what, primitives] of resolved) {
      actual[what] = primitives;
    }
    for (const fixture of IMPLICIT_INVOCATION_FIXTURES) {
      expected[fixture.what] = [...fixture.expect].sort();
    }
    expect(actual).toEqual(expected);
    expect(Object.keys(actual)).toHaveLength(IMPLICIT_INVOCATION_FIXTURES.length);
  });

  it.each(CLASS_DISPATCH_FIXTURES)("walks class dispatch: $what", (fixture) => {
    const actual = resolvedClassDispatchFixtures.get(fixture.what);
    expect(actual, `fixture disappeared: ${fixture.what}`).toBeDefined();
    expect(actual).toEqual([...fixture.expect].sort());
  });

  it("a descent refused by the depth ceiling does not claim the memo", () => {
    // PROOF OF CLOSURE for a reach regression that was real and is now closed,
    // pinned because the shape is CLOSED: it exhibits nothing an attacker can
    // spell, only the analyzer's own admission order.
    //
    // The walk memoizes each descent edge as `(body, caller frame, callee
    // frame)` so a shared helper is not re-walked per route. When the memo was
    // written BEFORE the depth ceiling was tested, a descent the ceiling
    // refused still claimed its triple, and a later SHORTER route to the same
    // pair was skipped as already-walked. The observable effect was a sink two
    // hops from a handler going unreported because an unrelated deep traversal
    // touched the same pair first: a truncated deep path silently blanking an
    // unrelated shallow path. Exhaustion now records a separate loud finding.
    //
    // The ceiling is `MAX_CALL_DEPTH`, so a childDepth of `Number.MAX_SAFE_INTEGER`
    // is refused under any value of it and this case never needs editing when
    // the constant moves.
    const walked = new Set<string>();
    const key = "body|caller|callee";

    // Refused by the ceiling: descends nothing, so it must learn nothing.
    expect(admitDescent(walked, key, Number.MAX_SAFE_INTEGER)).toBe(false);
    expect(walked.has(key)).toBe(false);

    // The shorter route to the same pair is therefore still walked...
    expect(admitDescent(walked, key, 1)).toBe(true);
    // ...and only then is the triple claimed, so it is walked exactly once.
    expect(admitDescent(walked, key, 1)).toBe(false);
    expect([...walked]).toEqual([key]);
  });

  it("classifies the commitment-minting verbs together", () => {
    // proof_commitment persists a new commitment record, the same as the zk
    // verbs it sits beside in the disclosure tool module. Pinned here because
    // the four are easy to edit apart, and the split is invisible in the tool
    // catalog an agent sees. This assertion is also the compensating control
    // named in the frozen-surface declaration for this PR: it freezes the
    // classification of all six commitment/verifier verbs, not just the one
    // that moved.
    const write = new Set(report.classification.writeTable);
    for (const tool of ["proof_commitment", "zk_commit", "zk_prove", "zk_range_prove"]) {
      expect({ tool, write: write.has(tool) }).toEqual({ tool, write: true });
    }
    const read = new Set(report.readTools);
    for (const tool of ["zk_verify", "zk_range_verify"]) {
      expect({ tool, read: read.has(tool) }).toEqual({ tool, read: true });
    }
  });
});
