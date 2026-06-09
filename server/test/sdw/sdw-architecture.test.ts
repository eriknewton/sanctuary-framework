import { readFile, readdir } from "node:fs/promises";
import { relative, join } from "node:path";
import { describe, expect, it } from "vitest";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { stateKey } from "../../src/sdw/grammar.js";
import {
  SDW_WORKING_STATE_HKDF_INFO,
  type SdwWorkingStateRecord,
} from "../../src/sdw/records.js";
import { SdwValidationError } from "../../src/sdw/errors.js";
import {
  mintPersistable,
  prepareSdwBackendWrite,
} from "../../src/sdw/write-gate.js";

const FORTRESS_ID = "fortress:test";
const MASTER_KEY = new Uint8Array(32).fill(7);

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
      }
      offenders.push(...findStorageBackendImplementationOffenders(source, path));
      offenders.push(...findSdwNamespacePathExposureOffenders(source, path));
      if (path === join("sdw", "lmdb-backend.ts")) continue;

      const aliases = sdwNamespaceAliases(source);
      if (callsSdwRawWrite(source, aliases)) {
        offenders.push(`${path}: direct backend.write/SdwTxn.write to an SDW namespace`);
      }
      if (callsSdwNamespacePathExposure(source, aliases)) {
        offenders.push(`${path}: exposes a filesystem path/dir/handle for an SDW namespace`);
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

  it("does not expose filesystem paths for SDW namespaces", () => {
    const storage = new FilesystemStorage("/tmp/sanctuary-sdw-path-exposure-test");

    expect(() => storage.namespacePath("_sdw_catalog")).toThrow(
      "Filesystem paths for SDW namespaces are not exposed",
    );
    expect(storage.namespacePath("_audit")).toContain("_audit");
  });

  it("rejects prepared SDW payloads mutated after authorization", async () => {
    const storage = new MemoryStorage();
    const record = workingStateRecord("state-mutable", "benign prepared content");
    const prepared = prepareSdwBackendWrite(
      mintPersistable(
        { value: record, taint: "user_content" },
        "_sdw_working_state",
        stateKey("task", record.state_id),
        FORTRESS_ID,
      ),
      derivePurposeKey(MASTER_KEY, SDW_WORKING_STATE_HKDF_INFO),
      FORTRESS_ID,
    );

    prepared.data.fill(0);
    await expect(
      storage.write(prepared.namespace, prepared.storageKey, prepared.data),
    ).rejects.toBeInstanceOf(SdwValidationError);
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

function callsSdwNamespacePathExposure(
  source: string,
  aliases = new Set<string>(),
): boolean {
  const namespaceTargets = [
    `["'\\\`]_sdw_`,
    String.raw`SDW_[A-Z_]+_NAMESPACE\b`,
    ...[...aliases].map(escapeRegExp).map((alias) => `${alias}\\b`),
  ];
  const namespacePattern = `(?:${namespaceTargets.join("|")})`;
  return new RegExp(
    String.raw`\b(?:namespace(?:Path|Dir|Directory|Handle)|pathForNamespace|dirForNamespace|handleForNamespace)\s*\(\s*${namespacePattern}`,
  ).test(source);
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
    /async\s+write\s*\(\s*namespace:\s*string\s*,\s*key:\s*string\s*,\s*data:\s*Uint8Array\s*\)/,
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

function findStorageBackendImplementationOffenders(source: string, path: string): string[] {
  const offenders: string[] = [];
  if (!/\bimplements\s+[^{]*\bStorageBackend\b/.test(source)) return offenders;

  const rawWriteBlocks = extractBalancedBlocks(
    source,
    /\basync\s+write\s*\([^)]*\)\s*(?::\s*Promise<void>)?/g,
  );
  for (const rawWrite of rawWriteBlocks) {
    if (!storageWriteBlockUsesSdwGuard(rawWrite)) {
      offenders.push(`${path}: StorageBackend.write does not enforce the SDW raw-write gate`);
    }
  }

  const durableWriteBlocks = extractBalancedBlocks(
    source,
    /\basync\s+writeDurable\s*\([^)]*\)\s*(?::\s*Promise<void>)?/g,
  );
  for (const durableWrite of durableWriteBlocks) {
    if (!storageWriteBlockUsesSdwGuard(durableWrite)) {
      offenders.push(`${path}: writeDurable does not enforce the SDW raw-write gate`);
    }
  }

  return offenders;
}

function findSdwNamespacePathExposureOffenders(source: string, path: string): string[] {
  if (path === join("sdw", "write-gate.ts")) return [];
  const offenders: string[] = [];
  const exposureBlocks = extractNamedBalancedBlocks(
    source,
    /(?:^|\n)\s*(?:export\s+)?(?:async\s+)?(?:function\s+)?(namespace(?:Path|Dir|Directory|Handle)|pathForNamespace|dirForNamespace|handleForNamespace)\s*\([^)]*\)\s*(?::[^{;]+)?(?=\s*\{)/g,
  );
  for (const { name, block } of exposureBlocks) {
    if (!namespaceExposureRejectsSdw(block)) {
      offenders.push(`${path}: ${name} does not reject SDW namespace path exposure`);
    }
  }
  return offenders;
}

function storageWriteBlockUsesSdwGuard(block: string): boolean {
  const assignment = /\b(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*assertSdwRawWriteAuthorized\s*\(/.exec(block);
  if (assignment === null) return false;
  const checkedBytesName = assignment[1]!;
  const afterGuard = block.slice((assignment.index ?? 0) + assignment[0].length);
  return new RegExp(String.raw`\b${escapeRegExp(checkedBytesName)}\b`).test(afterGuard);
}

function namespaceExposureRejectsSdw(block: string): boolean {
  return /\bif\s*\(\s*isSdwNamespace\s*\([^)]*\)\s*\)\s*\{\s*throw\b/s.test(block);
}

function writeBlockChecksBeforeRawPut(block: string): boolean {
  const guardIndex = block.indexOf("assertSdwRawWriteAuthorized(");
  const checkedDataIndex = block.indexOf("checkedData");
  const putIndex = block.search(/\bput(?:Sync)?\s*\(\s*compositeKey\s*\(\s*namespace\s*,\s*key\s*\)/);
  return guardIndex >= 0 && checkedDataIndex >= 0 && putIndex > guardIndex;
}

function persistableBlockUsesPreparedAuthority(block: string): boolean {
  const prepareIndex = block.indexOf("prepareSdwBackendWrite(persistable, encryptionKey, fortressId)");
  const guardIndex = block.indexOf("assertSdwRawWriteAuthorized(");
  const checkedDataIndex = block.indexOf("checkedData");
  const putPreparedIndex = block.search(
    /\bputSync\s*\(\s*compositeKey\s*\(\s*prepared\.namespace\s*,\s*prepared\.storageKey\s*\)/,
  );
  return (
    prepareIndex >= 0 &&
    guardIndex > prepareIndex &&
    checkedDataIndex >= 0 &&
    putPreparedIndex > guardIndex &&
    block.includes("asBinary(checkedData)")
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

function extractBalancedBlocks(source: string, signature: RegExp): string[] {
  const blocks: string[] = [];
  const flags = signature.flags.includes("g") ? signature.flags : `${signature.flags}g`;
  const globalSignature = new RegExp(signature.source, flags);
  for (const match of source.matchAll(globalSignature)) {
    const block = extractBalancedBlock(source.slice(match.index), globalSignatureWithoutGlobal(signature));
    if (block !== null) blocks.push(block);
  }
  return blocks;
}

function extractNamedBalancedBlocks(
  source: string,
  signature: RegExp,
): Array<{ name: string; block: string }> {
  const blocks: Array<{ name: string; block: string }> = [];
  for (const match of source.matchAll(signature)) {
    const block = extractBalancedBlock(source.slice(match.index), globalSignatureWithoutGlobal(signature));
    if (block !== null) blocks.push({ name: match[1]!, block });
  }
  return blocks;
}

function globalSignatureWithoutGlobal(signature: RegExp): RegExp {
  return new RegExp(signature.source, signature.flags.replace("g", ""));
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

function workingStateRecord(stateId: string, summary: string): SdwWorkingStateRecord {
  return {
    kind: "working_state",
    version: 1,
    state_id: stateId,
    scope: "task",
    owner_ref: "owner-1",
    status: "active",
    created_at: "2026-06-08T00:00:00.000Z",
    updated_at: "2026-06-08T00:00:00.000Z",
    content_type: "application/json",
    state: {
      kind: "task_checkpoint",
      task_ref: "task-1",
      summary,
    },
  };
}
