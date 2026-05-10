# Sanctuary server log-discipline framework

## What this is

The Sanctuary MCP server is a privileged operator-facing process. Raw
`console.log`/`console.warn`/`console.error` writes produce unstructured
output that bypasses any log-level filtering, breaks log-aggregator
parsing, and makes operational grep harder. This document defines the
log-discipline framework: every `console.*` call in non-test TypeScript
source files inside `server/src/` must either

1. live inside a template literal (browser-side JS embedded in HTML
   strings, which the server cannot route through a logger), or
2. carry an immediately preceding `// SAFETY:` comment naming why raw
   stdout/stderr is the contract at that site.

Test code is exempt: `console.*` is idiomatic in tests for assertion
debug, and routing it through a logger is not the job of this gate.

The framework is enforced by `server/scripts/check-no-raw-console.ts`,
which the Sanctuary CI workflow (`.github/workflows/ci.yml`) runs on
every PR and every push to `main`.

## Why no `logger.*` migration in this sweep

The Sanctuary server does not yet ship a structured logger module
(`pino`, `winston`, `debug`, custom). Introducing one is a coordinator-
scope decision that touches the configuration surface, the dashboard
surface (where logs flow into the operator UI), and the audit-log
contract (where signed audit entries are the durable record). The
Sigma-5 sweep therefore lands the discipline first and does the
mechanical migration later, when a logger module is chosen.

Until then, every server-side `console.*` site is annotated with a
`// SAFETY:` comment naming the channel role. This is the same shape as
the Sigma-3 sweep on `castle-wall-daemon` (Rust `println!`/`eprintln!`,
finding #98), which also operates without a structured logger today and
relies on annotation discipline.

## Classification framework

For every production-code `console.*` call site, classify it before
merging:

### Category A. CLI subcommand stdout/stderr is the contract

`console.log` of structured output (JSON, version strings, --help text)
or `console.error` of operator-facing diagnostic output from a CLI
entrypoint. stdout/stderr is the operator interface here, not a log
sink. CLI code lives under `server/src/cli/`, `server/src/cocoon/cli.ts`,
`server/src/cocoon/init.ts`,
`server/src/compliance/eu_ai_act/cli.ts`, and
`server/src/dashboard-standalone.ts`. Annotate with:

```ts
// SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
console.error(`...`);
```

### Category B. Server-runtime warning to stderr

A long-running process emits a warning to stderr because no logger is
wired yet. Sites: `server/src/index.ts` startup errors, the MCP-server
entrypoint, `server/src/storage/permissions.ts` chmod warnings,
`server/src/principal-policy/loader.ts` policy-load warnings,
`server/src/update-check.ts` update notifications,
`server/src/mesh/libp2p-transport/transport.ts` libp2p debug under
`SANCTUARY_LIBP2P_DEBUG=1`. Annotate with:

```ts
// SAFETY: no structured logger module is wired in server/src/ yet; until one lands, raw stderr is the runtime warning channel for this site.
console.error(`...`);
```

### Category C. Browser-side embedded JS

`console.*` calls inside template literals that generate browser HTML.
These run in the browser, not the server. The gate's lexer strips
template-literal contents before scanning, so these sites are
automatically excluded. No annotation needed. Files affected today:
`server/src/principal-policy/dashboard-html.ts` (10 calls in HTML
template),`server/src/cocoon/fortress-view.ts` (1 call in HTML
template).

### Category D. Residual debug

A debug print that should not have shipped. Remove the call. Do not
annotate. The gate exists to keep this category at zero.

## The SAFETY annotation contract

Format requirements:

* The comment block must begin with a line whose stripped form starts
  with `// SAFETY:` (capital SAFETY, colon, exact spelling). Doc
  comments (`///`, `//!`) are not honored.
* The comment block may be one line or many; the gate looks for the
  `SAFETY:` token within 20 lines of the call site, stopping at any
  blank line or any earlier non-`console.*`, non-comment code.
* The annotation must name the channel-contract reason in plain
  English. References to where the line is read (operator terminal,
  CI smoke harness scrape line, etc.) are encouraged.

The gate is intentionally permissive about formatting. The substantive
review work is the channel-contract proof, not the comment shape.

## Annotation walk-back

The gate is more permissive than per-call annotation in one specific
way: the walk-back from a `console.*` site traverses contiguous earlier
`console.*` calls and `//` line comments, so a single `// SAFETY:`
annotation can cover an entire structural output block (a multi-line
banner, a sequence of error-message lines, etc.). The walk-back stops
at blank lines and at any other code (a `let` statement, an `if (...)`
condition, etc.), so a residual debug `console.*` separated from a
legitimate banner by structural code remains unannotated and fails the
gate.

Multi-line `console.*` continuations (a `console.error(\n ... );` whose
arguments span several lines) are treated as part of the same call site
for walk-back purposes; the `;`-bearing closing line bounds the call,
and lines containing structural keywords (`let`, `const`, `if`, `for`,
`function`, etc.) break the walk so escape routes for residual debug
stay shut.

## Marker convention vs. panic-discipline

The Castle Wall daemon's panic-discipline gate
(`castle-wall-daemon/scripts/check-panic-discipline.py`) uses
mixed-case `// Safety:` to mark `unwrap`/`expect` invariants in Rust
production code. The console-discipline gate here uses capital
`// SAFETY:` to mark stdout/stderr channel contracts in TS production
code. The two markers are intentionally distinct so each gate operates
on a disjoint annotation set; a comment with the wrong case will not
satisfy the other gate.

The Sigma-3 sweep on the daemon used capital `// SAFETY:` for the same
log-discipline role, so the two gates use the same marker for the same
purpose across languages.

## Running the gate locally

```bash
# Pass / fail check
cd server
npx vite-node scripts/check-no-raw-console.ts

# Self-tests for the gate logic itself
npx vitest run test/scripts/check-no-raw-console.test.ts
```

Pass output:

```
Sanctuary server console-discipline gate PASS: 165 annotated production-code site(s), 0 unannotated.
```

Fail output lists each unannotated site with file path, line number,
and the offending source line.

## What the gate does NOT do

* It does not parse TypeScript. It uses a single-pass lexer that
  tracks string, template-literal, and block-comment state. Regex
  literals are not parsed; in production code today none contain
  apparent `console.*` substrings, so this is not a current source of
  false positives. If a regex literal in a future commit triggers a
  false hit, the operator can resolve with a `// SAFETY:` annotation
  or by extracting the regex.
* It does not run on `server/test/`, `server/scripts/`, `server/dist/`,
  or `server/node_modules/`. Test code is idiomatic with `console.*`,
  scripts are out-of-band tooling, and `dist/` plus `node_modules/`
  are non-source artifacts.
* It does not enforce Categories A vs. B vs. D. If a residual debug
  print at runtime is the wrong semantic and a `SAFETY:` annotation
  papers over the design defect, only human review catches it. The
  gate is a structural floor, not a ceiling.

## How this closes full-sweep #97

The Sigma-5 sweep classified the 165 production-code `console.*` sites
in `server/src/` (CLI surfaces and server-runtime warning sites) and
annotated each with a `// SAFETY:` comment. 11 additional sites
inside template literals (browser-side JS in HTML strings) are
excluded by the gate's lexer rather than annotated. The new gate is
the structural floor that prevents future commits from re-introducing
unannotated sites. Together, the sweep and the gate close finding #97.

## How this fits the Castle Architecture

Castle Layer 1 enforcement is the load-bearing security promise. Log
discipline preserves the operator's ability to audit and debug the
server's behavior under stress. A residual debug `console.log` in a
hot path is a noise-floor source that obscures real signal during an
incident; a structural gate prevents that drift. The discipline is
not itself enforcement, but it preserves the conditions under which
operators can trust what they see.

This document is canonical for the framework. Future scope expansions
(introducing a structured logger module, migrating annotated sites
through it, extending the gate to other directories or to
non-`console.*` patterns) are coordinator-level decisions and ship as
follow-on PRs, not as scope creep on this file.
