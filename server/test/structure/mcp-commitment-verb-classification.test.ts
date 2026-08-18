/**
 * CAPABILITY: the router lets an MCP tool classified `read` run even when the
 * audit chain reports integrity findings, so an operator can still introspect a
 * fortress in trouble, and refuses a tool classified `write`. Membership of the
 * two classification tables is therefore a security decision, and this test
 * freezes it for the six commitment and verifier verbs, which are the set where
 * minting and checking are easiest to confuse for one another
 * (ABC-READCLASS-01).
 *
 * SCOPE, WHICH IS PART OF THE CLAIM, and it is narrow on purpose:
 *
 *   1. It reads the two tables out of the shipping source BY AST, so it pins
 *      what the server actually classifies from rather than a restatement. It
 *      does NOT boot the server, and it does not observe a call.
 *   2. It covers SIX NAMED TOOLS and nothing else. It is not a reconciliation
 *      of the read set against what each handler can reach; that is a separate
 *      change, and ABC-READCLASS-01 stays open until it lands. A green here
 *      says these six are on the tables this test expects, never that every
 *      other entry is right.
 *   3. It reads the table LITERALS. A name reaching a class some other way, in
 *      particular an inline `tool_class` on a tool literal, is outside what
 *      this file sees.
 *
 * WHY THE MECHANISM IS ASSERTED FIRST. If the table reader stopped matching,
 * every membership assertion below would be checking an empty set, and an empty
 * set satisfies nothing and reports nothing. The first assertion is therefore
 * that both tables parsed non-empty and that the reader found the names it is
 * about to judge, so a silently broken parse reds instead of reading as a pass.
 */

import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";
import { describe, expect, it } from "vitest";

/** test/structure -> test -> server */
const SERVER_DIR = resolve(fileURLToPath(import.meta.url), "..", "..", "..");
const INDEX_FILE = join(SERVER_DIR, "src", "index.ts");

/**
 * The verbs that MINT a commitment and persist it, so they create durable state
 * and must not run while the audit chain has findings.
 */
const MINTING_VERBS = ["proof_commitment", "zk_commit", "zk_prove", "zk_range_prove"] as const;

/**
 * The verbs that CHECK an existing commitment. They create nothing, and an
 * operator needs them precisely while the chain has findings, so they stay
 * readable.
 */
const VERIFYING_VERBS = ["zk_verify", "zk_range_verify"] as const;

/**
 * Read the string members of a top-level `const <name>: ReadonlySet<string> =
 * new Set([...])` in the shipping source.
 *
 * Reading the literal rather than importing the constant is deliberate: these
 * tables are module-private, and exporting them so a test could see them would
 * widen a security-relevant surface for the test's convenience. The failure
 * mode to watch for is silent: a table renamed or re-spelled makes this return
 * an empty list, which is why the anti-vacuity assertion below exists.
 */
function readNameTable(source: ts.SourceFile, tableName: string): string[] {
  const found: string[] = [];
  const visit = (node: ts.Node): void => {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.name.text === tableName &&
      node.initializer !== undefined
    ) {
      const literals: ts.Node[] = [];
      const collect = (inner: ts.Node): void => {
        if (ts.isStringLiteralLike(inner)) literals.push(inner);
        ts.forEachChild(inner, collect);
      };
      collect(node.initializer);
      for (const literal of literals) found.push((literal as ts.StringLiteralLike).text);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return found;
}

describe("MCP commitment and verifier classification", () => {
  const source = ts.createSourceFile(
    INDEX_FILE,
    readFileSync(INDEX_FILE, "utf8"),
    ts.ScriptTarget.ES2022,
    true,
    ts.ScriptKind.TS
  );
  const writeTable = readNameTable(source, "WRITE_MCP_TOOLS");
  const readTable = readNameTable(source, "READ_MCP_TOOLS");

  it("parsed both shipping classification tables", () => {
    // Lower bounds, not exact counts, so ordinary additions to either table do
    // not churn this file. A parser that matched nothing produces zero and is
    // what this assertion is for.
    expect({
      write: writeTable.length > 10,
      read: readTable.length > 10,
      overlap: writeTable.filter((name) => readTable.includes(name)),
    }).toEqual({ write: true, read: true, overlap: [] });
  });

  it("classifies every commitment-minting verb as write", () => {
    // Asserted as a whole map rather than in a loop: a loop that stopped
    // iterating would pass on the entries it never reached.
    const actual = Object.fromEntries(
      MINTING_VERBS.map((verb) => [verb, writeTable.includes(verb)])
    );
    const expected = Object.fromEntries(MINTING_VERBS.map((verb) => [verb, true]));
    expect(actual).toEqual(expected);
  });

  it("classifies every verifier verb as read, and no minting verb with them", () => {
    const actual = {
      verifiersRead: Object.fromEntries(
        VERIFYING_VERBS.map((verb) => [verb, readTable.includes(verb)])
      ),
      mintingVerbsInReadTable: MINTING_VERBS.filter((verb) => readTable.includes(verb)),
    };
    expect(actual).toEqual({
      verifiersRead: Object.fromEntries(VERIFYING_VERBS.map((verb) => [verb, true])),
      mintingVerbsInReadTable: [],
    });
  });
});
