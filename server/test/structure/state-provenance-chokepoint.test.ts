import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const SERVER_SRC = join(REPO_ROOT, "server", "src");

interface WriteCall {
  relativePath: string;
  firstArg: string;
  callArgs: string;
}

interface AuditedDynamicWrite {
  path: string;
  callArgs: string;
  reason: string;
}

const AUDITED_DYNAMIC_WRITES: AuditedDynamicWrite[] = [
  {
    path: "server/src/exit/bundle.ts",
    callArgs: "namespace, key, jsonBytes(value)",
    reason: "exit import stages only internal _exit_* artifact namespaces",
  },
  {
    path: "server/src/exit/bundle.ts",
    callArgs: "snapshot.namespace, snapshot.key, snapshot.data",
    reason:
      "exit activation rollback (restoreStorageSnapshots) restores byte-identical pre-activation snapshots that already carry their original Slice-2 provenance; routing through StateStore.write would re-mint and corrupt the byte-for-byte rollback the atomicity guarantee requires. HIGH-1 (Codex gate, 2026-08-22): the write is now reached only after a post-image-confirmed divergence check (classifyRestoreSafety), not unconditionally.",
  },
  {
    path: "server/src/transparency/anchoring.ts",
    callArgs: "namespace, key, bytes",
    reason: "transparency checkpoint helper uses frozen internal namespaces",
  },
  {
    path: "server/src/transparency/emitter.ts",
    callArgs: "namespace, key, bytes",
    reason: "transparency emitter helper uses frozen internal namespaces",
  },
  {
    path: "server/src/mesh/lifecycle/durable-spent-set-store.ts",
    callArgs:
      "this.namespace, this.recordKey, stringToBytes(JSON.stringify(encrypted))",
    reason:
      "federation single-use NONCE replay-protection metadata (the spent set), written to the frozen internal _federation namespace under its own AES-GCM purpose key; not export-eligible user state, so it must not route through StateStore (mirrors federation-trust-root-store)",
  },
  {
    path: "server/src/mesh/lifecycle/durable-claim-set-store.ts",
    callArgs:
      "this.namespace, this.recordKey, stringToBytes(JSON.stringify(encrypted))",
    reason:
      "operator-cloud provision-claim single-use replay-protection metadata (the claim set), written to the frozen internal _federation namespace under its own AES-GCM purpose key; not export-eligible user state, so it must not route through StateStore (mirrors federation-trust-root-store)",
  },
  {
    path: "server/src/storage/directory-capability-worker.ts",
    callArgs: "namespace, String(args[0]), bytes(args[1])",
    reason:
      "the directory-capability worker is a narrow cwd-bound transport for an already-authorized FilesystemStorage.write call; export-eligible StateStore provenance is minted by the parent before bytes reach this backend, and the worker preserves the selected namespace/key rather than creating a second state-write API",
  },
  {
    path: "server/src/v1/federation-sync-state-store.ts",
    callArgs:
      "this.namespace, this.recordKey, stringToBytes(JSON.stringify(encrypted))",
    reason:
      "federation peer-sync security state (Federation 3/3b P0): per-sender accepted high-water + outbound high-water + folded revocation projection, written to the frozen internal _federation namespace under its own AES-GCM purpose key; derived anti-replay/revocation metadata, not export-eligible user state, so it must not route through StateStore (mirrors federation-trust-root-store)",
  },
];

function tsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...tsFiles(full));
    else if (entry.isFile() && entry.name.endsWith(".ts")) out.push(full);
  }
  return out;
}

function readBalancedCall(source: string, openParen: number): string {
  let depth = 0;
  let quote: '"' | "'" | "`" | null = null;
  let escaped = false;
  for (let i = openParen; i < source.length; i++) {
    const ch = source[i]!;
    if (quote !== null) {
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
      continue;
    }
    if (ch === "(") depth++;
    if (ch === ")") {
      depth--;
      if (depth === 0) return source.slice(openParen + 1, i);
    }
  }
  return source.slice(openParen + 1);
}

function firstArgument(callBody: string): string {
  let depth = 0;
  let quote: '"' | "'" | "`" | null = null;
  let escaped = false;
  for (let i = 0; i < callBody.length; i++) {
    const ch = callBody[i]!;
    if (quote !== null) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
      continue;
    }
    if (ch === "(" || ch === "{" || ch === "[") depth++;
    if (ch === ")" || ch === "}" || ch === "]") depth--;
    if (ch === "," && depth === 0) return callBody.slice(0, i).trim();
  }
  return callBody.trim();
}

function normalizeCallText(text: string): string {
  return text.replace(/\s+/g, " ").trim().replace(/,$/, "").trim();
}

function storageWriteCalls(): WriteCall[] {
  const calls: WriteCall[] = [];
  for (const file of tsFiles(SERVER_SRC)) {
    const source = readFileSync(file, "utf8");
    calls.push(...storageWriteCallsFromSource(relative(REPO_ROOT, file), source));
  }
  return calls;
}

function storageWriteCallsFromSource(relativePath: string, source: string): WriteCall[] {
  const calls: WriteCall[] = [];
  const pattern = /(?:this\.|ctx\.|opts\.|options\.)?storage\.write\s*\(/g;
  for (const match of source.matchAll(pattern)) {
    const openParen = source.indexOf("(", match.index);
    const body = readBalancedCall(source, openParen);
    calls.push({
      relativePath,
      firstArg: normalizeCallText(firstArgument(body)),
      callArgs: normalizeCallText(body),
    });
  }
  return calls;
}

function isReservedLiteral(firstArg: string): boolean {
  const match = firstArg.match(/^["'`]([^"'`]+)["'`]$/);
  return match !== null && match[1]!.startsWith("_");
}

function isInternalConstant(firstArg: string): boolean {
  return /^[A-Z][A-Z0-9_]*$/.test(firstArg);
}

function isAllowedDynamicWrite(call: WriteCall): boolean {
  if (
    call.relativePath === "server/src/cognitive/state-store.ts" &&
    (call.firstArg === "namespace" || call.firstArg === "ns")
  ) {
    return true;
  }
  if (
    call.relativePath === "server/src/core/master-rotation.ts" &&
    call.firstArg === "namespace"
  ) {
    return true;
  }
  return AUDITED_DYNAMIC_WRITES.some(
    (item) => call.relativePath === item.path && call.callArgs === item.callArgs,
  );
}

describe("state provenance write chokepoint", () => {
  it("ties audited dynamic write allowances to the matching call", () => {
    const fixture = `
      async function writeAllowed(storage, namespace, key, bytes) {
        await storage.write(namespace, key, bytes);
        await storage.write(userNamespace, key, bytes);
      }
    `;

    const unsafe = storageWriteCallsFromSource(
      "server/src/transparency/anchoring.ts",
      fixture,
    ).filter((call) => {
      if (isReservedLiteral(call.firstArg)) return false;
      if (isInternalConstant(call.firstArg)) return false;
      return !isAllowedDynamicWrite(call);
    });

    expect(unsafe.map((call) => call.firstArg)).toEqual(["userNamespace"]);
  });

  it("keeps every audited dynamic write allowance bound to one call site", () => {
    const calls = storageWriteCalls();
    const matchCounts = AUDITED_DYNAMIC_WRITES.map((item) => ({
      item,
      matches: calls.filter(
        (call) =>
          call.relativePath === item.path && call.callArgs === item.callArgs,
      ),
    }));

    expect(
      matchCounts.map(({ item, matches }) => ({
        path: item.path,
        callArgs: item.callArgs,
        count: matches.length,
        reason: item.reason,
      })),
    ).toEqual(
      AUDITED_DYNAMIC_WRITES.map((item) => ({
        path: item.path,
        callArgs: item.callArgs,
        count: 1,
        reason: item.reason,
      })),
    );
  });

  it("has no unaudited direct raw storage writes to variable namespaces", () => {
    const unsafe = storageWriteCalls().filter((call) => {
      if (isReservedLiteral(call.firstArg)) return false;
      if (isInternalConstant(call.firstArg)) return false;
      return !isAllowedDynamicWrite(call);
    });

    expect(
      unsafe.map((call) => `${call.relativePath}: storage.write(${call.firstArg}, ...)`),
      "Every direct raw storage write with a variable namespace must be audited. " +
        "Export-eligible user state should route through StateStore.write so " +
        "Slice-2 provenance is minted at the chokepoint.",
    ).toEqual([]);
  });
});
