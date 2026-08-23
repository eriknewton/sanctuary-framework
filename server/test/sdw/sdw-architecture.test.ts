// fail-before-exempt: this file is the SDW architecture GATE (re-asserted 2026-08-22 for Rung-1 point 3, --allow-file classifier override), not a test of a
// behavior change. Widening it to recognize an additional compliant shape
// cannot fail against the base ref, because the base's source already passes
// the narrower rule; "fails before the fix" has no meaning for a gate
// widening. The widening is given its own teeth instead: the recognizer has
// direct unit tests below covering both directions, including the exact
// laundering case (a real write slipped in ahead of the refusal). This time
// the widening is the txnPersistable extraction regex and
// persistableBlockUsesPreparedAuthority accepting an optional trailing
// `options` argument on writePersistable/prepareSdwBackendWrite, proven both
// directions by the new "transactional persistable-write recognizer" describe
// block below (accepts 3-arg AND 4-arg compliant shapes, still rejects a
// bypass and a missing implementation).
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

  describe("unconditional-refusal recognizer", () => {
    // The gate accepts a write body that refuses EVERY write as satisfying the
    // no-unauthorized-SDW-write property, since there is no write to authorize.
    // That concession is only sound while the recognizer is strict, so it is
    // tested in both directions here rather than trusted from its own source.
    it("accepts a body that is nothing but a throw", () => {
      expect(
        writeBlockRefusesUnconditionally(
          '{\n  throw new ReadOnlyStorageViolationError("write", namespace, key);\n}',
        ),
      ).toBe(true);
    });

    it("accepts a throw-only body carrying comments", () => {
      expect(
        writeBlockRefusesUnconditionally(
          '{\n  // refuses every write, whatever the namespace\n  /* see the guard header */\n  throw new Error("no");\n}',
        ),
      ).toBe(true);
    });

    it("rejects a body that writes before it throws", () => {
      // The laundering case: a real write, then a refusal that makes the method
      // still look read-only from its last line.
      expect(
        writeBlockRefusesUnconditionally(
          '{\n  await this.inner.write(namespace, key, data);\n  throw new Error("no");\n}',
        ),
      ).toBe(false);
    });

    it("rejects a conditional refusal", () => {
      expect(
        writeBlockRefusesUnconditionally(
          '{\n  if (isSdwNamespace(namespace)) throw new Error("no");\n  await this.inner.write(namespace, key, data);\n}',
        ),
      ).toBe(false);
    });

    it("rejects an empty body", () => {
      // A silent no-op is the shape MUST-NEVER #5 forbids: the caller believes
      // the write landed. It must never read as a compliant refusal.
      expect(writeBlockRefusesUnconditionally("{\n}")).toBe(false);
    });

    it("rejects a throw whose ARGUMENT LIST nests the write (laundering inside the throw expression)", () => {
      // The one-statement rule alone does not close this: the body IS exactly
      // one throw statement, but the write executes while the constructor's
      // arguments are evaluated, before anything is thrown. Both mutating
      // spellings and a bare await are must-fail shapes.
      expect(
        writeBlockRefusesUnconditionally(
          '{\n  throw new Error(String(await this.inner.write(namespace, key, data)));\n}',
        ),
      ).toBe(false);
      expect(
        writeBlockRefusesUnconditionally(
          '{\n  throw new Error(String(await this.inner.writeDurable(namespace, key, data)));\n}',
        ),
      ).toBe(false);
      expect(
        writeBlockRefusesUnconditionally(
          '{\n  throw new Error(String(this.inner.delete(namespace, key)));\n}',
        ),
      ).toBe(false);
    });
  });

  describe("transactional persistable-write recognizer (Rung-1 point 3 widening)", () => {
    // Rung-1 point 3 (2026-08-22) added an optional trailing `options`
    // parameter to writePersistable/prepareSdwBackendWrite so ONE narrow,
    // per-passage classifier override can reach the LMDB transactional write
    // path. Widening the recognizer to accept it must not lose its ability to
    // reject a genuine bypass; both directions are proven here rather than
    // trusted from the recognizer's own source, same discipline as the
    // unconditional-refusal recognizer above.
    const VALID_PUBLIC_WRITE = `
  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    const checkedData = assertSdwRawWriteAuthorized(namespace, key, data);
    this.db.putSync(compositeKey(namespace, key), checkedData);
  }
`;
    const VALID_TXN_WRITE = `
        write: async (namespace, key, data) => {
          const checkedData = assertSdwRawWriteAuthorized(namespace, key, data);
          overlay.set(compositeKey(namespace, key), checkedData);
        },
`;
    const COMPLIANT_PERSISTABLE_BODY = `
          const prepared = prepareSdwBackendWrite(persistable, encryptionKey, fortressId, options);
          const checkedData = assertSdwRawWriteAuthorized(
            prepared.namespace,
            prepared.storageKey,
            prepared.data,
          );
          overlay.set(
            compositeKey(prepared.namespace, prepared.storageKey),
            new Uint8Array(checkedData),
          );
`;

    function sourceWithPersistableWriter(paramList: string, body: string): string {
      return `
class FakeLmdbBackend {
${VALID_PUBLIC_WRITE}
  async sdwTransaction<T>(fn: (txn: unknown) => Promise<T>): Promise<T> {
    const overlay = new Map();
    const txn = {
${VALID_TXN_WRITE}
      writePersistable: async (${paramList}) => {
${body}
      },
    };
    const result = await fn(txn);
    for (const [composite, value] of overlay) {
      this.db.putSync(composite, this.lmdb.asBinary(value));
    }
    return result;
  }
}
`;
    }

    it("accepts the widened 4-arg (options) compliant shape", () => {
      const offenders = findLmdbWriteGateOffenders(
        sourceWithPersistableWriter(
          "persistable, encryptionKey, fortressId, options",
          COMPLIANT_PERSISTABLE_BODY,
        ),
        "sdw/lmdb-backend.ts",
      );
      expect(offenders).toEqual([]);
    });

    it("still accepts the original 3-arg compliant shape (backward compatible)", () => {
      const offenders = findLmdbWriteGateOffenders(
        sourceWithPersistableWriter(
          "persistable, encryptionKey, fortressId",
          // The 3-arg body legitimately omits `options` from the call too.
          COMPLIANT_PERSISTABLE_BODY.replace(", options)", ")"),
        ),
        "sdw/lmdb-backend.ts",
      );
      expect(offenders).toEqual([]);
    });

    it("rejects a 4-arg shape that drops the guard (options did not smuggle in a bypass)", () => {
      const offenders = findLmdbWriteGateOffenders(
        sourceWithPersistableWriter(
          "persistable, encryptionKey, fortressId, options",
          // No prepareSdwBackendWrite/assertSdwRawWriteAuthorized at all: a
          // raw write straight from the caller-supplied persistable.
          `
          overlay.set(
            compositeKey(persistable.namespace, persistable.storageKey),
            options?.classifierOverride ? persistable.record : null,
          );
`,
        ),
        "sdw/lmdb-backend.ts",
      );
      expect(offenders).toContain(
        "sdw/lmdb-backend.ts: transactional persistable write does not use the SDW prepare/authority path",
      );
    });

    it("rejects a missing writePersistable implementation entirely", () => {
      const source = `
class FakeLmdbBackend {
${VALID_PUBLIC_WRITE}
  async sdwTransaction<T>(fn: (txn: unknown) => Promise<T>): Promise<T> {
    const overlay = new Map();
    const txn = {
${VALID_TXN_WRITE}
    };
    const result = await fn(txn);
    for (const [composite, value] of overlay) {
      this.db.putSync(composite, this.lmdb.asBinary(value));
    }
    return result;
  }
}
`;
      const offenders = findLmdbWriteGateOffenders(source, "sdw/lmdb-backend.ts");
      expect(offenders).toContain(
        "sdw/lmdb-backend.ts: missing transactional persistable write implementation",
      );
    });
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

  // Rung-1 point 3 (2026-08-22, memory-file ingest --allow-file override)
  // widened this to accept an optional trailing `options` parameter
  // (`MintPersistableOptions`, threaded through so ONE narrow, per-passage
  // classifier override can reach the LMDB transactional write path too).
  // The widening is proven both directions below rather than trusted from
  // its own source, same discipline as the unconditional-refusal recognizer
  // above: it still rejects a shape that drops the guard.
  const txnPersistable = extractBalancedBlock(
    source,
    /writePersistable:\s*async\s*\(\s*persistable,\s*encryptionKey,\s*fortressId(?:,\s*options)?\s*\)\s*=>/,
  );
  if (txnPersistable === null) {
    offenders.push(`${path}: missing transactional persistable write implementation`);
  } else if (!persistableBlockUsesPreparedAuthority(txnPersistable)) {
    offenders.push(`${path}: transactional persistable write does not use the SDW prepare/authority path`);
  }

  if (!sdwTransactionCommitsOnlyOverlayValues(source)) {
    offenders.push(
      `${path}: sdwTransaction commit loop must write only guarded overlay values`,
    );
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
    if (!storageWriteBlockUsesSdwGuard(rawWrite) && !writeBlockRefusesUnconditionally(rawWrite)) {
      offenders.push(`${path}: StorageBackend.write does not enforce the SDW raw-write gate`);
    }
  }

  const durableWriteBlocks = extractBalancedBlocks(
    source,
    /\basync\s+writeDurable\s*\([^)]*\)\s*(?::\s*Promise<void>)?/g,
  );
  for (const durableWrite of durableWriteBlocks) {
    if (
      !storageWriteBlockUsesSdwGuard(durableWrite) &&
      !writeBlockRefusesUnconditionally(durableWrite)
    ) {
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

/**
 * A write body that REFUSES every write, whatever the namespace, satisfies the
 * property this gate protects (no raw SDW write escapes authorization) more
 * strongly than calling the gate would: there is no write at all. Requiring the
 * gate call there would mean running an authorization check in front of an
 * unconditional refusal, which reads as though some write might proceed.
 *
 * Deliberately narrow, so it cannot launder a real write path. The body, with
 * comments removed, must be exactly one `throw new X(...)` statement and
 * nothing else; any assignment, call, or branch before the throw fails it.
 *
 * The one-statement rule is not sufficient on its own: the constructor's
 * ARGUMENT LIST is evaluated before the throw, so a write nested inside it
 * (`throw new E(String(await this.inner.write(…)))`) executes and still reads
 * as "exactly one throw statement". The argument text is therefore also
 * refused if it contains an `await` or a call to any of the storage
 * interface's mutating members — must match
 * `READ_ONLY_STORAGE_MUTATING_METHODS` in `src/storage/read-only-guard.ts`
 * (`write`/`writeDurable`/`delete`), the same full set the parity test pins.
 */
function writeBlockRefusesUnconditionally(block: string): boolean {
  const body = block
    .replace(/^\s*\{/, "")
    .replace(/\}\s*$/, "")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/[^\n]*/g, "")
    .trim();
  const throwOnly = /^throw\s+new\s+[A-Za-z_$][\w$]*\s*\(([\s\S]*)\)\s*;?$/.exec(
    body
  );
  if (throwOnly === null) return false;
  const argumentText = throwOnly[1]!;
  return !/(\bawait\b|\.\s*write\s*\(|\.\s*writeDurable\s*\(|\.\s*delete\s*\()/.test(
    argumentText
  );
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
  // Either form is acceptable: a direct guarded LMDB put, or — inside
  // sdwTransaction's staged-then-atomic-commit construction — a guarded
  // write into the staging overlay. The commit loop is separately checked
  // (sdwTransactionCommitsOnlyOverlayValues) to write ONLY overlay values.
  const putIndex = block.search(/\bput(?:Sync)?\s*\(\s*compositeKey\s*\(\s*namespace\s*,\s*key\s*\)/);
  const stagedIndex = block.search(
    /\boverlay\.set\s*\(\s*compositeKey\s*\(\s*namespace\s*,\s*key\s*\)/,
  );
  const sinkIndex = putIndex >= 0 ? putIndex : stagedIndex;
  return guardIndex >= 0 && checkedDataIndex >= 0 && sinkIndex > guardIndex;
}

function persistableBlockUsesPreparedAuthority(block: string): boolean {
  // Same optional-trailing-`options` widening as the txnPersistable extraction
  // regex above, and for the same reason: prepareSdwBackendWrite now takes an
  // optional 4th MintPersistableOptions argument. A regex search (not a fixed
  // indexOf) so both the 3-arg and 4-arg call shapes are recognized.
  const prepareMatch = block.match(
    /prepareSdwBackendWrite\(\s*persistable,\s*encryptionKey,\s*fortressId(?:,\s*options)?\s*\)/,
  );
  const prepareIndex = prepareMatch === null ? -1 : (prepareMatch.index ?? -1);
  const guardIndex = block.indexOf("assertSdwRawWriteAuthorized(");
  const checkedDataIndex = block.indexOf("checkedData");
  // Direct guarded LMDB put, or guarded write into the sdwTransaction
  // staging overlay (see writeBlockChecksBeforeRawPut).
  const putPreparedIndex = block.search(
    /\bputSync\s*\(\s*compositeKey\s*\(\s*prepared\.namespace\s*,\s*prepared\.storageKey\s*\)/,
  );
  const stagedPreparedIndex = block.search(
    /\boverlay\.set\s*\(\s*compositeKey\s*\(\s*prepared\.namespace\s*,\s*prepared\.storageKey\s*\)/,
  );
  const sinkIndex = putPreparedIndex >= 0 ? putPreparedIndex : stagedPreparedIndex;
  return (
    prepareIndex >= 0 &&
    guardIndex > prepareIndex &&
    checkedDataIndex >= 0 &&
    sinkIndex > guardIndex &&
    (block.includes("asBinary(checkedData)") ||
      block.includes("new Uint8Array(checkedData)"))
  );
}

/**
 * The staged-commit loop must move ONLY overlay values into LMDB: every
 * `putSync` inside `sdwTransaction` writes `asBinary(value)` where `value`
 * is the overlay entry (all overlay writes pass the raw-write guard at
 * staging time, per the block checks above).
 */
function sdwTransactionCommitsOnlyOverlayValues(source: string): boolean {
  const txnBlock = extractBalancedBlock(source, /async\s+sdwTransaction\s*</);
  if (txnBlock === null) return false;
  const putSyncCount = (txnBlock.match(/\bputSync\b/g) ?? []).length;
  const overlayPutCount = (
    txnBlock.match(
      /\bputSync\s*\(\s*composite\s*,\s*this\.lmdb\.asBinary\(value\)\s*\)/g,
    ) ?? []
  ).length;
  return putSyncCount > 0 && putSyncCount === overlayPutCount;
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
