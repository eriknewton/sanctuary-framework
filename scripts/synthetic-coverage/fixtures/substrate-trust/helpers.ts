import { AuditLog } from "../../../../server/src/operational/audit-log.js";
import { createL1Tools } from "../../../../server/src/cognitive/tools.js";
import { StateStore } from "../../../../server/src/cognitive/state-store.js";
import { generateRandomKey } from "../../../../server/src/core/random.js";
import { MemoryStorage } from "../../../../server/src/storage/memory.js";

export const ROW_AUDIT_CHAIN = "4";
export const ROW_AUDIT_CHAIN_LABEL = "Tamper-evident audit chain";
export const ROW_STATE_ENCRYPTION = "5";
export const ROW_STATE_ENCRYPTION_LABEL = "State encryption";
export const ROW_ATTESTATION = "8";
export const ROW_ATTESTATION_LABEL = "Health and attestation evidence-based";
export const ROW_DID_KEY = "19";
export const ROW_DID_KEY_LABEL = "did:key encoding (PR #268, base58btc compliant)";
export const ROW_IDENTITY_SIGNING = "20";
export const ROW_IDENTITY_SIGNING_LABEL =
  "Identity signing authority (PR #270, raw identity_sign Tier 1)";

export interface ToolCallResult {
  [key: string]: unknown;
}

export interface ToolDef {
  name: string;
  handler: (
    args: Record<string, unknown>,
  ) => Promise<{ content: Array<{ type: string; text: string }> }>;
}

export async function callTool(
  tools: ToolDef[],
  name: string,
  args: Record<string, unknown> = {},
): Promise<ToolCallResult> {
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) {
    throw new Error(`Tool not found: ${name}`);
  }
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text) as ToolCallResult;
}

export function makeL1Rig(): {
  storage: MemoryStorage;
  masterKey: Uint8Array;
  auditLog: AuditLog;
  tools: ToolDef[];
  identityManager: ReturnType<typeof createL1Tools>["identityManager"];
  internalSigning: ReturnType<typeof createL1Tools>["internalSigning"];
} {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  const l1 = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "recovery-key",
    auditLog,
  );

  return {
    storage,
    masterKey,
    auditLog,
    tools: l1.tools as ToolDef[],
    identityManager: l1.identityManager,
    internalSigning: l1.internalSigning,
  };
}

export function passedSince(start: number, message?: string): {
  passed: true;
  message?: string;
  durationMs: number;
} {
  return { passed: true, message, durationMs: performance.now() - start };
}

export function failedSince(start: number, error: unknown): {
  passed: false;
  message: string;
  durationMs: number;
} {
  return {
    passed: false,
    message: error instanceof Error ? error.message : String(error),
    durationMs: performance.now() - start,
  };
}

export async function outcome(
  start: number,
  fn: () => Promise<boolean> | boolean,
  message: string,
) {
  try {
    const passed = await fn();
    return {
      passed,
      message,
      durationMs: performance.now() - start,
    };
  } catch (error) {
    return failedSince(start, error);
  }
}
