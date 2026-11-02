// fail-before-exempt: A1b extends the existing provenance guard to confine recovery clocks, roots and sweep resets to declaring modules and tests.
import { readdirSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { createRequire } from "node:module";
import type * as Ts from "typescript";
const ts: typeof Ts = createRequire(import.meta.url)("typescript");

const src = fileURLToPath(new URL("../../src/", import.meta.url));
function files(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => entry.isDirectory()
    ? files(join(dir, entry.name)) : entry.name.endsWith(".ts") ? [join(dir, entry.name)] : []);
}
const declaringModule = "operational/audit-log.ts";
const read = (path: string) => readFileSync(join(src, path), "utf8");

describe("audit writer role provenance", () => {
  it("pins the full set of trusted role literals and confines test identity seams", () => {
    const roles: string[] = [];
    for (const path of files(src)) {
      const name = relative(src, path);
      if (name !== declaringModule && name !== "storage/cross-process-lock.ts") {
        expect(readFileSync(path, "utf8"), name).not.toMatch(/__testMonotonicNow/);
      }
      if (name === declaringModule) continue;
      const text = readFileSync(path, "utf8");
      expect(text, name).not.toMatch(/__testAuditAuthorityUid|__testSetAuditWriterUidForRole|__testAuditGuardLockRoot|__testResetAuditLockTempSweepBudget/);
      const occurrences = text.match(/chainWriterRole/g) ?? [];
      let literals = 0;
      const tree = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true);
      function visit(node: Ts.Node): void {
        if (ts.isPropertyAssignment(node) && node.name.getText(tree) === "chainWriterRole") {
          expect(ts.isStringLiteral(node.initializer), name).toBe(true);
          if (ts.isStringLiteral(node.initializer)) {
            let parent: Ts.Node | undefined = node.parent;
            while (parent && !ts.isFunctionDeclaration(parent)) parent = parent.parent;
            roles.push(`${name}:${parent && ts.isFunctionDeclaration(parent) ? parent.name?.text : "unknown"}:${node.initializer.text}`);
          }
          literals++;
        }
        ts.forEachChild(node, visit);
      }
      visit(tree);
      expect(occurrences.length, name).toBe(literals);
    }
    expect(roles.sort()).toEqual([
      "cli/castle-wall-boot.ts:auditBootTokenEvent:boot_token", "cli/castle-wall-observe.ts:resolveObserveAuditSources:boot_token",
      "cli/castle-wall.ts:runSafeModeDaemon:boot_token", "operational/audit-store-split.ts:createDaemonAuditLog:root_daemon",
    ].sort());
    const implementation = read(declaringModule);
    expect(implementation).toContain('chainWriterRole?: "operator" | "root_daemon" | "boot_token";');
    expect(implementation).toContain('this.chainWriterRole = config?.chainWriterRole ?? "operator";');
    expect(implementation.match(/this\.chainWriterRole\s*=(?!=)/g)).toHaveLength(1);
    expect(implementation.match(/config\?\.chainWriterRole/g)).toHaveLength(1);
    expect(implementation).toContain('this.chainWriterRole !== "operator" ? auditWriterRoleTestUids.get(this.chainWriterRole) : undefined');
    expect(read("index.ts")).toContain('export { AuditLog } from "./operational/audit-log.js"');
  });

  it("confines recovery seams across the repository to declaring files and server tests", () => {
    const root = fileURLToPath(new URL("../../../", import.meta.url));
    // Git's tracked and untracked source inventory includes scripts without traversing dependency/build trees.
    const paths = execFileSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"], { cwd: root, encoding: "utf8" }).split("\0").filter(Boolean);
    for (const path of new Set(paths)) {
      if (!/\.(?:[cm]?[jt]sx?)$/.test(path) || path.startsWith("server/test/")) continue;
      const text = readFileSync(join(root, path), "utf8");
      if (path !== "server/src/operational/audit-log.ts") expect(text, path).not.toMatch(/__testAuditGuardLockRoot|__testResetAuditLockTempSweepBudget/);
      if (path !== "server/src/operational/audit-log.ts" && path !== "server/src/storage/cross-process-lock.ts") expect(text, path).not.toMatch(/__testMonotonicNow/);
    }
  });

  it("pins each diagnostic construction as read-only", () => {
    const expectations = [
      ["operational/audit-store-split.ts", /const probe = new AuditLog\(storage, masterKey, \{\s*readOnly: true/],
      ["operational/audit-store-split.ts", /const daemonAuditLog = createDaemonAuditLog\(storage, masterKey, \{\s*readOnly: true/],
      ["wrap/cli.ts", /const daemonLog = createDaemonAuditLog\(auditStorage, masterKey, \{\s*readOnly: true/],
      ["cli/castle-wall.ts", /const daemonLog = createDaemonAuditLog\(storage, masterKey, \{\s*readOnly: true/],
      ["evidence-pack/cli.ts", /const daemonLog = createDaemonAuditLog\(storage, masterKey, \{ readOnly: true \}/],
    ] as const;
    for (const [path, pattern] of expectations) expect(read(path), path).toMatch(pattern);
    expect(read("cli/castle-wall-observe.ts")).toMatch(/chainWriterRole: "boot_token",\s*readOnly: true/);
    const refresh = read("castle-wall/observe/refresh.ts");
    expect(refresh).toContain("source.auditLog.streamVerifiedChain(");
    expect(refresh).not.toMatch(/source\.auditLog\.(append|flush|write)/);
  });
});
