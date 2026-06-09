import { readFile, readdir } from "node:fs/promises";
import { relative, join } from "node:path";
import { describe, expect, it } from "vitest";

describe("SDW architecture write gate", () => {
  it("does not expose raw write authority from the public SDW barrel", async () => {
    const barrel = await import("../../src/sdw/index.js");

    expect(barrel).not.toHaveProperty("runWithSdwWriteAuthority");
    expect(barrel).not.toHaveProperty("sdwBackendWriteAuthenticatedMeta");
  });

  it("keeps all source-wide SDW raw writes behind the gate", async () => {
    const root = join(process.cwd(), "src");
    const offenders: string[] = [];
    for (const file of await listTsFiles(root)) {
      const path = relative(root, file);
      const source = await readFile(file, "utf8");

      if (importsForbiddenRawWriteHelper(source)) {
        offenders.push(`${path}: imports a raw SDW write authority helper`);
      }
      if (importsLmdbBackendWrite(source)) {
        offenders.push(`${path}: imports LmdbStorageBackend.write directly`);
      }

      if (path === join("sdw", "write-gate.ts")) {
        offenders.push(...findWriteGateOffenders(source, path));
        continue;
      }
      if (path === join("sdw", "lmdb-backend.ts")) {
        offenders.push(...findLmdbWriteGateOffenders(source, path));
        continue;
      }

      const aliases = sdwNamespaceAliases(source);
      if (callsSdwRawWrite(source, aliases)) {
        offenders.push(`${path}: direct backend.write/SdwTxn.write to an SDW namespace`);
      }
      if (writesLmdbCompositeKey(source)) {
        offenders.push(`${path}: direct LMDB composite-key write outside the SDW backend`);
      }
      if (callsForbiddenSdwAuthority(source)) {
        offenders.push(`${path}: calls raw SDW write authority directly`);
      }
    }
    expect(offenders).toEqual([]);
  });
});

function callsSdwRawWrite(source: string, aliases = new Set<string>()): boolean {
  const namespaceTargets = [
    `["'\\\`]_sdw_`,
    String.raw`SDW_[A-Z_]+_NAMESPACE\b`,
    ...[...aliases].map(escapeRegExp).map((alias) => `${alias}\\b`),
  ];
  const namespacePattern = `(?:${namespaceTargets.join("|")})`;
  return [
    new RegExp(String.raw`\b(?:storage|backend|txn|this\.storage|this\.backend)\.write\s*\(\s*${namespacePattern}`),
    new RegExp(String.raw`\bwrite\s*\(\s*${namespacePattern}`),
  ].some((pattern) => pattern.test(source));
}

function writesLmdbCompositeKey(source: string): boolean {
  return /\bput(?:Sync)?\s*\(\s*compositeKey\s*\(/.test(source);
}

function importsForbiddenRawWriteHelper(source: string): boolean {
  return /import\s*\{[^}]*\b(?:runWithSdwWriteAuthority|sdwBackendWriteAuthenticatedMeta)\b[^}]*\}\s*from\s+["'](?:[^"']*\/sdw\/(?:write-gate|index)|\.{1,2}\/(?:write-gate|index))\.js["']/.test(source);
}

function importsLmdbBackendWrite(source: string): boolean {
  return /import\s*\{[^}]*\bwrite\b[^}]*\}\s*from\s+["'](?:[^"']*\/sdw\/lmdb-backend|\.{1,2}\/lmdb-backend)\.js["']/.test(source);
}

function callsForbiddenSdwAuthority(source: string): boolean {
  return /\b(?:runWithSdwWriteAuthority|sdwBackendWriteAuthenticatedMeta)\s*\(/.test(source);
}

function sdwNamespaceAliases(source: string): Set<string> {
  const aliases = new Set<string>();
  const declaration =
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:["'`]_sdw_[^"'`]+["'`]|SDW_[A-Z_]+_NAMESPACE)\b/g;
  for (const match of source.matchAll(declaration)) {
    aliases.add(match[1]!);
  }
  return aliases;
}

function findWriteGateOffenders(source: string, path: string): string[] {
  const offenders: string[] = [];
  if (/\bexport\s+(?:async\s+)?function\s+runWithSdwWriteAuthority\b/.test(source)) {
    offenders.push(`${path}: exports raw SDW write authority`);
  }
  if (/\bexport\s+(?:async\s+)?function\s+sdwBackendWriteAuthenticatedMeta\b/.test(source)) {
    offenders.push(`${path}: exports raw authenticated meta byte writer`);
  }
  return offenders;
}

function findLmdbWriteGateOffenders(source: string, path: string): string[] {
  const offenders: string[] = [];
  const publicWrite = extractBalancedBlock(
    source,
    /async\s+write\s*\(\s*namespace:\s*string,\s*key:\s*string,\s*data:\s*Uint8Array\s*\)/,
  );
  if (publicWrite === null) {
    offenders.push(`${path}: missing public backend write implementation`);
  } else if (!writeBlockChecksBeforeRawPut(publicWrite)) {
    offenders.push(`${path}: public backend write can reach LMDB without the raw SDW guard`);
  }

  const txnWrite = extractBalancedBlock(source, /write:\s*async\s*\(\s*namespace,\s*key,\s*data\s*\)\s*=>/);
  if (txnWrite === null) {
    offenders.push(`${path}: missing transactional raw write implementation`);
  } else if (!writeBlockChecksBeforeRawPut(txnWrite)) {
    offenders.push(`${path}: transactional raw write can reach LMDB without the raw SDW guard`);
  }

  const txnPersistable = extractBalancedBlock(
    source,
    /writePersistable:\s*async\s*\(\s*persistable,\s*encryptionKey,\s*fortressId\s*\)\s*=>/,
  );
  if (txnPersistable === null) {
    offenders.push(`${path}: missing transactional persistable write implementation`);
  } else if (!persistableBlockUsesPreparedAuthority(txnPersistable)) {
    offenders.push(`${path}: transactional persistable write does not use the SDW prepare/authority path`);
  }

  return offenders;
}

function writeBlockChecksBeforeRawPut(block: string): boolean {
  const guardIndex = block.indexOf("assertSdwRawWriteAuthorized(namespace, key, data)");
  const putIndex = block.search(/\bput(?:Sync)?\s*\(\s*compositeKey\s*\(\s*namespace\s*,\s*key\s*\)/);
  return guardIndex >= 0 && putIndex >= 0 && guardIndex < putIndex;
}

function persistableBlockUsesPreparedAuthority(block: string): boolean {
  const prepareIndex = block.indexOf("prepareSdwBackendWrite(persistable, encryptionKey, fortressId)");
  const guardIndex = block.indexOf(
    "assertSdwRawWriteAuthorized(prepared.namespace, prepared.storageKey, prepared.data)",
  );
  const putPreparedIndex = block.search(
    /\bputSync\s*\(\s*compositeKey\s*\(\s*prepared\.namespace\s*,\s*prepared\.storageKey\s*\)/,
  );
  return (
    prepareIndex >= 0 &&
    guardIndex > prepareIndex &&
    putPreparedIndex > guardIndex
  );
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function extractBalancedBlock(source: string, signature: RegExp): string | null {
  const match = signature.exec(source);
  if (match === null) return null;
  const openIndex = source.indexOf("{", match.index + match[0].length);
  if (openIndex < 0) return null;
  let depth = 0;
  for (let index = openIndex; index < source.length; index++) {
    const char = source[index];
    if (char === "{") depth++;
    if (char === "}") {
      depth--;
      if (depth === 0) return source.slice(openIndex, index + 1);
    }
  }
  return null;
}

async function listTsFiles(root: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) {
      out.push(...(await listTsFiles(path)));
    } else if (entry.isFile() && entry.name.endsWith(".ts")) {
      out.push(path);
    }
  }
  return out;
}
