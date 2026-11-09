/**
 * The pure canary integrity checker. The CLI collector gathers the facts each
 * observer cycle; this function decides, so the decision is testable without a
 * root-owned file.
 */
import { createHash } from "node:crypto";
import {
  CANARY_PLIST_BYTES,
  CANARY_PROGRAM,
  CANARY_PROGRAM_ARGUMENTS,
  canaryAccountNameValid,
  canaryPlistSha256,
  type SystemJobPrint,
} from "./launchd-plists.js";

const ROOT_UID = 0;
const ROOT_GID = 0;
/** Permission bits only; the file-type bits of `st_mode` are checked through `isFile`. */
const PERMISSION_MASK = 0o7777;
/** Owner read and write, group and other read: the attended `install -m 0644`. */
const CANARY_PLIST_MODE = 0o644;

/** One child's outcome: ok with its value, or failed (refused, non-zero, over cap or past its deadline). */
export type CollectedFact<T> = { status: "ok"; value: T } | { status: "failed" };

export interface CanaryPlistStat {
  isFile: boolean;
  isSymbolicLink: boolean;
  uid: number;
  gid: number;
  mode: number;
  size: number;
}

export interface CanaryIntegrityFacts {
  /** `config.agent_uid` from a valid config, else null (no account to check). */
  agentUid: number | null;
  /** lstat of the installed plist; failed when absent or unreadable. */
  plistStat: CollectedFact<CanaryPlistStat>;
  /** Its bytes, read with O_NOFOLLOW and capped at CANARY_PLIST_BYTES. */
  plistBytes: CollectedFact<Uint8Array>;
  /** `id -un <agent_uid>` then `id -u <name>`, sequential under one shared deadline. */
  account: CollectedFact<{ name: string; reverseUid: number }>;
  /** `launchctl print system/<CANARY_LABEL>`, parsed. */
  print: CollectedFact<SystemJobPrint>;
}

export interface CanaryIntegrityResult { passed: boolean; checked_at_ms: number }

/**
 * Decide canary integrity for this cycle. `checkedAtMs` is this cycle's
 * collection time, never an earlier cycle's.
 */
export function checkCanaryIntegrity(facts: CanaryIntegrityFacts, checkedAtMs: number): CanaryIntegrityResult | null {
  if (facts.agentUid === null) return null;
  const fail = { passed: false, checked_at_ms: checkedAtMs };
  if (facts.plistStat.status !== "ok" || facts.plistBytes.status !== "ok" || facts.account.status !== "ok" || facts.print.status !== "ok") return fail;
  const stat = facts.plistStat.value;
  const bytes = facts.plistBytes.value;
  const { name, reverseUid } = facts.account.value;
  const print = facts.print.value;
  if (!canaryAccountNameValid(name)) return fail;
  // Every conjunct is required: an edited, unloaded or re-owned canary must read canary_unprovisioned even while some curl still produces drops.
  const passed =
    stat.isFile && !stat.isSymbolicLink && stat.uid === ROOT_UID && stat.gid === ROOT_GID &&
    (stat.mode & PERMISSION_MASK) === CANARY_PLIST_MODE && stat.size <= CANARY_PLIST_BYTES &&
    // The hashed bytes must be the whole file the stat described; a size disagreement means they were read from another file.
    bytes.byteLength === stat.size &&
    bytes.byteLength <= CANARY_PLIST_BYTES && createHash("sha256").update(bytes).digest("hex") === canaryPlistSha256(name) &&
    reverseUid === facts.agentUid &&
    print.valid && print.program === CANARY_PROGRAM && print.username === name &&
    print.arguments.length === CANARY_PROGRAM_ARGUMENTS.length && print.arguments.every((argument, i) => argument === CANARY_PROGRAM_ARGUMENTS[i]);
  return { passed, checked_at_ms: checkedAtMs };
}
