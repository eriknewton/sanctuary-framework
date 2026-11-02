import { readFileSync } from "node:fs";
import ts from "typescript";
import { expect, it } from "vitest";

const source = readFileSync(new URL("../../src/operational/audit-log.ts", import.meta.url), "utf8");
// Replace comments with spaces to preserve AST positions while excluding prose.
const code = source.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, (comment) => comment.replace(/[^\n]/g, " "));
const fallbacks = [
  `typeof this.storage.listKeys === "function"
      ? await this.storage.listKeys(AUDIT_NAMESPACE)
      : (await this.storage.list(AUDIT_NAMESPACE, "entry-")).map((meta) => meta.key)`,
  `typeof this.storage.listKeys === "function"
      ? await this.storage.listKeys(AUDIT_CHECKPOINT_NAMESPACE, "audit-checkpoint-")
      : (await this.storage.list(AUDIT_CHECKPOINT_NAMESPACE, "audit-checkpoint-")).map((meta) => meta.key)`,
];

it("pins every sized listing by enclosing function, with only exact capability fallbacks excluded", () => {
  const parsed = ts.createSourceFile("audit-log.ts", source, ts.ScriptTarget.Latest, true);
  function owner(position: number): string {
    let found = "<module>";
    function visit(node: ts.Node): void {
      if (position < node.pos || position >= node.end) return;
      if ((ts.isMethodDeclaration(node) || ts.isFunctionDeclaration(node)) && node.name) found = node.name.getText(parsed);
      ts.forEachChild(node, visit);
    }
    visit(parsed); return found;
  }
  let remaining = code;
  for (const fallback of fallbacks) {
    expect(remaining.split(fallback)).toHaveLength(2);
    remaining = remaining.replace(fallback, " ".repeat(fallback.length));
  }
  const classes = [...remaining.matchAll(/this\.storage\s*\.list\(/g)];
  const modules = [...remaining.matchAll(/\bstorage\s*\.list\(/g)]
    .filter((match) => !classes.some((entry) => match.index === entry.index! + "this.".length));
  expect(classes.map((match) => owner(match.index!)).sort()).toEqual([
    "sealedRegionFingerprint", "maybeRotate", "daemonMigrationMarkerExists",
    "isEstablishedAuditStore", "getRetentionUsage", "auditStoreFingerprint",
    "auditEntryListingSignature", "loadPersistedEntries", "readCheckpointsWithCompleteness",
  ].sort());
  expect(modules.map((match) => owner(match.index!)).sort()).toEqual([
    "probeAuditHeadAnchor", "probeAuditHeadAnchor", "verifySealedRegionAt",
  ].sort());
  // Nine class sites, three module sites, and two exact fallbacks make fourteen.
  expect([...code.matchAll(/\bstorage\s*\.list\(/g)]).toHaveLength(14);
});
