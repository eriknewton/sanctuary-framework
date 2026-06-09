import type { StorageBackend } from "../storage/interface.js";
import { stringToBytes, bytesToString, toBase64url, constantTimeEqual } from "../core/encoding.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { hmacSha256 } from "../core/hashing.js";
import {
  SDW_META_NAMESPACE,
  SDW_REPLAY_ANCHOR_KEY,
  type ReplayAnchorCounter,
  type SdwReplayAnchorData,
  type SdwReplayAnchorRecord,
} from "./records.js";
import { SdwReplayAnchorError } from "./errors.js";
export { prepareReplayAnchorWrite, writeReplayAnchor } from "./write-gate.js";

const SDW_REPLAY_MAC_DOMAIN = "sanctuary.sdw-replay-anchor-mac.v1\n";
const SDW_REPLAY_MAC_MARKER = "__sanctuary_sdw_replay_anchor_mac_v1";
const SDW_REPLAY_MAC_INFO = "sdw-replay-anchor-mac";

interface ReplayAnchorEnvelope {
  readonly marker: typeof SDW_REPLAY_MAC_MARKER;
  readonly data: SdwReplayAnchorData;
  readonly mac: string;
}

export type ReplayAnchorStatus =
  | { readonly status: "valid"; readonly data: SdwReplayAnchorData }
  | { readonly status: "stripped" };

export function emptyReplayAnchorData(): SdwReplayAnchorData {
  return {
    catalog: 0,
    chain_head: [],
    manifests: [],
    tombstones: [],
    export_state: 0,
  };
}

export function createReplayAnchorRecord(
  fortressId: string,
  data: SdwReplayAnchorData,
  updatedAt = new Date().toISOString(),
): SdwReplayAnchorRecord {
  return {
    kind: "replay_anchor",
    version: 1,
    fortress_id: fortressId,
    data,
    updated_at: updatedAt,
  };
}

export async function readReplayAnchor(
  storage: Pick<StorageBackend, "read">,
  masterKey: Uint8Array,
): Promise<ReplayAnchorStatus> {
  const raw = await storage.read(SDW_META_NAMESPACE, SDW_REPLAY_ANCHOR_KEY);
  if (raw === null) return { status: "stripped" };
  let parsed: ReplayAnchorEnvelope;
  try {
    parsed = JSON.parse(bytesToString(raw)) as ReplayAnchorEnvelope;
  } catch {
    throw new SdwReplayAnchorError("malformed", "SDW replay anchor malformed");
  }
  if (parsed.marker !== SDW_REPLAY_MAC_MARKER) return { status: "stripped" };
  const expected = replayAnchorMac(masterKey, parsed.data);
  const actual = stringToBytes(parsed.mac);
  if (!constantTimeEqual(stringToBytes(expected), actual)) {
    throw new SdwReplayAnchorError("invalid_mac", "SDW replay anchor MAC invalid");
  }
  return { status: "valid", data: parsed.data };
}

export function assertCatalogNotRolledBack(
  recordSeq: number,
  anchor: ReplayAnchorStatus,
): void {
  if (anchor.status === "valid" && recordSeq < anchor.data.catalog) {
    throw new SdwReplayAnchorError("replay_detected", "SDW catalog rollback detected");
  }
}

export function assertReplayAnchorPresentForEstablishedStore(
  anchor: ReplayAnchorStatus,
  established: boolean,
  label: string,
): void {
  // First boot is legitimately anchorless. Once any SDW bytes exist, stripping
  // the replay anchor removes the only monotonic floor and must fail closed.
  if (established && anchor.status === "stripped") {
    throw new SdwReplayAnchorError(
      "replay_anchor_invalid",
      `SDW replay anchor missing for established ${label}`,
    );
  }
}

export function replayAnchorCounterSeq(
  counters: readonly ReplayAnchorCounter[],
  id: string,
): number {
  return counters.find((counter) => counter.id === id)?.seq ?? 0;
}

export function upsertReplayAnchorCounter(
  counters: readonly ReplayAnchorCounter[],
  id: string,
  seq: number,
): readonly ReplayAnchorCounter[] {
  let found = false;
  const next = counters.map((counter) => {
    if (counter.id !== id) return counter;
    found = true;
    return { id, seq };
  });
  return found ? next : [...next, { id, seq }];
}

function replayAnchorMac(masterKey: Uint8Array, data: SdwReplayAnchorData): string {
  const macKey = derivePurposeKey(masterKey, SDW_REPLAY_MAC_INFO);
  const payload = SDW_REPLAY_MAC_DOMAIN +
    SDW_REPLAY_ANCHOR_KEY +
    "\n" +
    canonicalJson(data);
  return toBase64url(hmacSha256(macKey, stringToBytes(payload)));
}

function canonicalize(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((item) => canonicalize(item));
  const object = value as { readonly [key: string]: unknown };
  const out: { [key: string]: unknown } = {};
  for (const key of Object.keys(object).sort()) {
    const item = object[key];
    if (item !== undefined) out[key] = canonicalize(item);
  }
  return out;
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}
