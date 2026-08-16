import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import {
  resolveProducerCursorFromPersistedChainAnchor,
  type ChainAnchorSource,
} from "./audit-consumer.js";

export const MACOS_AUDIT_PRODUCER_CHAIN_STATE_PATH =
  "/var/root/Library/Application Support/Sanctuary/CastleWall/audit-producer-chain-state.json";

export interface AuditProducerCursorState {
  schema_version: 1;
  next_seq: number;
  prior_sha256_hex?: string | null;
}

export type AuditProducerCursorSeedResult =
  | { kind: "skipped"; reason: "no_state_path" | "no_anchor" }
  | {
      kind: "current";
      statePath: string;
      nextSeq: number;
      priorSha256Hex: string;
    }
  | {
      kind: "seeded";
      statePath: string;
      previousNextSeq: number | null;
      nextSeq: number;
      priorSha256Hex: string;
      replacedInvalidState: boolean;
    };

export function defaultMacOSAuditProducerChainStatePath(): string | null {
  if (process.platform !== "darwin" || process.getuid?.() !== 0) {
    return null;
  }
  return MACOS_AUDIT_PRODUCER_CHAIN_STATE_PATH;
}

export async function seedMacOSAuditProducerStateFromLocalAnchor(input: {
  chainAnchorSource: ChainAnchorSource;
  pinnedProducerKeyB64url: string;
  statePath?: string | null;
}): Promise<AuditProducerCursorSeedResult> {
  const statePath =
    input.statePath === undefined
      ? defaultMacOSAuditProducerChainStatePath()
      : input.statePath;
  if (statePath === null) {
    return { kind: "skipped", reason: "no_state_path" };
  }

  const anchor = await input.chainAnchorSource();
  if (anchor === null) {
    return { kind: "skipped", reason: "no_anchor" };
  }
  const resolved = resolveProducerCursorFromPersistedChainAnchor(
    anchor,
    input.pinnedProducerKeyB64url,
  );
  if (resolved.kind === "unavailable") {
    throw new Error(
      `audit producer cursor seed unavailable: ${resolved.reason}`,
    );
  }

  const existing = await readAuditProducerCursorState(statePath);
  if (existing.kind === "valid") {
    if (existing.state.next_seq > resolved.nextSeq) {
      return {
        kind: "current",
        statePath,
        nextSeq: existing.state.next_seq,
        priorSha256Hex: existing.state.prior_sha256_hex as string,
      };
    }
    if (existing.state.next_seq === resolved.nextSeq) {
      if (existing.state.prior_sha256_hex !== resolved.priorSha256Hex) {
        throw new Error(
          `audit producer cursor state conflict at next_seq=${resolved.nextSeq}`,
        );
      }
      return {
        kind: "current",
        statePath,
        nextSeq: resolved.nextSeq,
        priorSha256Hex: resolved.priorSha256Hex,
      };
    }
  }

  await writeAuditProducerCursorState(statePath, {
    next_seq: resolved.nextSeq,
    prior_sha256_hex: resolved.priorSha256Hex,
    schema_version: 1,
  });
  return {
    kind: "seeded",
    statePath,
    previousNextSeq: existing.kind === "valid" ? existing.state.next_seq : null,
    nextSeq: resolved.nextSeq,
    priorSha256Hex: resolved.priorSha256Hex,
    replacedInvalidState: existing.kind === "invalid",
  };
}

async function readAuditProducerCursorState(path: string): Promise<
  | { kind: "missing" }
  | { kind: "invalid" }
  | { kind: "valid"; state: AuditProducerCursorState }
> {
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (err) {
    if (isNodeErrno(err, "ENOENT")) return { kind: "missing" };
    throw err;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { kind: "invalid" };
  }
  if (!isValidAuditProducerCursorState(parsed)) {
    return { kind: "invalid" };
  }
  return { kind: "valid", state: parsed };
}

async function writeAuditProducerCursorState(
  path: string,
  state: AuditProducerCursorState,
): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
  await writeFile(tmp, JSON.stringify(state), { mode: 0o600 });
  await rename(tmp, path);
}

function isValidAuditProducerCursorState(
  value: unknown,
): value is AuditProducerCursorState {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const record = value as Record<string, unknown>;
  if (record.schema_version !== 1) return false;
  if (
    typeof record.next_seq !== "number" ||
    !Number.isSafeInteger(record.next_seq) ||
    record.next_seq < 0
  ) {
    return false;
  }
  const prior = record.prior_sha256_hex;
  if (record.next_seq === 0) {
    return prior === undefined || prior === null;
  }
  return (
    typeof prior === "string" &&
    /^[0-9a-fA-F]{64}$/.test(prior)
  );
}

function isNodeErrno(err: unknown, code: string): boolean {
  return (
    err !== null &&
    typeof err === "object" &&
    "code" in err &&
    (err as { code?: unknown }).code === code
  );
}
