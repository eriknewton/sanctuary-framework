/**
 * CoS round-trip liveness prober, Telegram v1.
 *
 * Scope is deliberately narrow: `cos_liveness_verified` means exactly a
 * confined Telegram round trip. This module does NOT certify brain routing,
 * provider-chain health, model billing, or general Castle Wall enforcement.
 *
 * v1 is mock-proven only. The local mock Bot API can prove the state machine,
 * nonce discipline, reply attribution, timeout, stale-drain behavior, and the
 * "never poll the agent token" construction. It does NOT cover Telegram's live
 * privacy/Bot-to-Bot delivery semantics, real update-offset behavior under
 * stale queues, 429 backoff, group membership, webhook conflicts, chat
 * migration, or real confined egress. Those remain live-leg residuals.
 *
 * Config custody is bounded by the verified fortress custody base
 * (operator-owned, mode 0700, not root-owned) plus the descriptor-first
 * config-file read and immediate-parent check. POSIX mode bits alone do not
 * prove not-agent-writable under macOS ACLs; that is a disclosed bound, not a
 * stronger guarantee.
 */

import { createHash, randomUUID } from "node:crypto";
import { join } from "node:path";
import type { Stats } from "node:fs";

import {
  readFileCustodyWithStats,
  type ReadFileCustodyTextOptions,
} from "../../storage/custody-fs.js";
import {
  verifyFortressCustodyBase,
} from "./fortress-custody.js";
import type {
  AgentLivenessProbeResult,
  CosLivenessUnverifiedReason,
} from "./orchestrate.js";

export const TELEGRAM_LIVENESS_PROBE_CONFIG_RELATIVE_PATH = "config/liveness-probe/telegram.json";
export const TELEGRAM_LIVENESS_PROBE_AUDIT_OP = "cos_liveness_probe";
export const DEFAULT_TELEGRAM_LIVENESS_TIMEOUT_MS = 90_000;
export const DEFAULT_TELEGRAM_LIVENESS_POLL_INTERVAL_MS = 1_000;
export const DEFAULT_TELEGRAM_LIVENESS_MAX_DRAIN_BATCHES = 3;

const DEFAULT_TELEGRAM_API_BASE_URL = "https://api.telegram.org";
const TELEGRAM_MAX_GET_UPDATES_TIMEOUT_SECONDS = 0;

export type TelegramLivenessProbeFailureDetail =
  | "send_failed"
  | "send_ok_no_reply"
  | "reply_wrong_sender"
  | "reply_no_nonce"
  | "rate_limited"
  | "stale_update_backlog";

export interface TelegramLivenessProbeConfig {
  /** Probe bot token. The agent bot token is never accepted or read here. */
  botToken: string;
  /** Dedicated private probe group chat id. Stored as a string to avoid large-id precision loss. */
  chatId: string;
  /** The agent bot/user id expected to produce the correlated reply. */
  expectedSenderId: number;
  timeoutMs: number;
  pollIntervalMs: number;
  maxDrainBatches: number;
}

export type TelegramLivenessProbeConfigRead =
  | { kind: "absent"; path: string }
  | { kind: "configured"; path: string; config: TelegramLivenessProbeConfig };

export interface TelegramLivenessProbeConfigFs {
  verifyFortressCustodyBase?(path: string, expectedOwnerUid: number | undefined): Promise<void>;
  readFileCustodyWithStats(
    path: string,
    options: ReadFileCustodyTextOptions,
  ): Promise<{ data: string; stats: Pick<Stats, "mode" | "uid" | "isFile"> }>;
}

export interface TelegramLivenessProbeAuditSink {
  append(
    layer: "l2",
    operation: typeof TELEGRAM_LIVENESS_PROBE_AUDIT_OP,
    identityId: string,
    details: Record<string, unknown>,
    result?: "success" | "failure",
  ): Promise<void>;
}

export interface TelegramLivenessProbeOps {
  fetch: typeof fetch;
  nowMs: () => number;
  sleepMs: (ms: number) => Promise<void>;
  randomNonce: () => string;
}

export interface RunTelegramLivenessProbeOptions {
  config: TelegramLivenessProbeConfig;
  ops?: Partial<TelegramLivenessProbeOps>;
  /** Test-only override; production always uses api.telegram.org. */
  apiBaseUrl?: string;
  audit?: TelegramLivenessProbeAuditSink;
  auditIdentityId?: string;
}

export interface VerifyTelegramAgentLivenessFromFortressOptions {
  fortressPath: string;
  expectedOwnerUid?: number;
  configFs?: TelegramLivenessProbeConfigFs;
  ops?: Partial<TelegramLivenessProbeOps>;
  audit?: TelegramLivenessProbeAuditSink;
  auditIdentityId?: string;
}

interface TelegramMessage {
  message_id?: unknown;
  from?: { id?: unknown };
  chat?: { id?: unknown };
  text?: unknown;
  caption?: unknown;
  reply_to_message?: { message_id?: unknown };
}

interface TelegramUpdate {
  update_id?: unknown;
  message?: TelegramMessage;
}

interface TelegramCallOk {
  body: Record<string, unknown>;
  result: unknown;
}

export type TelegramLivenessProbeConfigErrorCode =
  | "config_unreadable"
  | "config_malformed";

class TelegramLivenessProbeConfigError extends Error {
  readonly path: string;

  constructor(
    readonly code: TelegramLivenessProbeConfigErrorCode,
    path: string,
    options: { cause?: unknown } = {},
  ) {
    super(code, options);
    this.name = "TelegramLivenessProbeConfigError";
    this.path = path;
    Object.defineProperty(this, "path", { value: path, enumerable: false });
  }
}

class TelegramLivenessProbeRequestError extends Error {
  constructor(
    message: string,
    readonly detail: TelegramLivenessProbeFailureDetail,
  ) {
    super(message);
    this.name = "TelegramLivenessProbeRequestError";
  }
}

export { TelegramLivenessProbeConfigError };

/**
 * Re-gate round 3: the cause chain is DROPPED, not merely non-enumerated. A raw
 * cause survives `JSON.stringify` sanitization but `util.inspect(error)` prints
 * `[cause]`, and the causes here are path-bearing `CustodyFsError`s — so any
 * default error dump of a config failure leaked the credential path. The code
 * IS the diagnostic; the path stays on the non-enumerable `path` field for
 * callers that deliberately ask for it.
 */
function configUnreadable(path: string): TelegramLivenessProbeConfigError {
  return new TelegramLivenessProbeConfigError("config_unreadable", path);
}

function configMalformed(path: string): TelegramLivenessProbeConfigError {
  return new TelegramLivenessProbeConfigError("config_malformed", path);
}

export function resolveTelegramLivenessProbeConfigPath(fortressPath: string): string {
  return join(fortressPath, TELEGRAM_LIVENESS_PROBE_CONFIG_RELATIVE_PATH);
}

export async function readTelegramLivenessProbeConfigFromFortress(input: {
  fortressPath: string;
  expectedOwnerUid?: number;
  fs?: TelegramLivenessProbeConfigFs;
}): Promise<TelegramLivenessProbeConfigRead> {
  const configPath = resolveTelegramLivenessProbeConfigPath(input.fortressPath);
  const fsOps = input.fs ?? {
    readFileCustodyWithStats,
    verifyFortressCustodyBase: verifyTelegramLivenessProbeFortressCustodyBase,
  };
  try {
    await (fsOps.verifyFortressCustodyBase ?? verifyTelegramLivenessProbeFortressCustodyBase)(
      input.fortressPath,
      input.expectedOwnerUid,
    );
  } catch {
    // Re-gate round 3: a MISSING FORTRESS is not "no probe channel configured".
    // Degrading it to `absent` made a nonexistent-or-vanished fortress read as
    // the benign unconfigured case, so a caller pointed at the wrong path (or a
    // fortress that disappeared under it) got a quiet `no_channel_configured`
    // instead of a refusal. An absent CONFIG FILE inside a VERIFIED fortress is
    // still the benign case — that is decided below, after this check passes.
    throw configUnreadable(configPath);
  }
  let raw: string;
  try {
    const read = await fsOps.readFileCustodyWithStats(configPath, {
      encoding: "utf8",
      ...(input.expectedOwnerUid !== undefined ? { uid: input.expectedOwnerUid } : {}),
      mode: { exact: 0o600 },
      parent: {
        ...(input.expectedOwnerUid !== undefined ? { uid: input.expectedOwnerUid } : {}),
        mode: { rejectGroupOrOtherWrite: true },
      },
      verifyPathIdentity: true,
    });
    raw = read.data;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return { kind: "absent", path: configPath };
    }
    throw configUnreadable(configPath);
  }
  return { kind: "configured", path: configPath, config: parseTelegramLivenessProbeConfig(raw, configPath) };
}

async function verifyTelegramLivenessProbeFortressCustodyBase(
  path: string,
  expectedOwnerUid: number | undefined,
): Promise<void> {
  await verifyFortressCustodyBase({ fortressPath: path, operatorUid: expectedOwnerUid });
}

export function parseTelegramLivenessProbeConfig(
  raw: string,
  source = TELEGRAM_LIVENESS_PROBE_CONFIG_RELATIVE_PATH,
): TelegramLivenessProbeConfig {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw configMalformed(source);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw configMalformed(source);
  }
  const record = parsed as Record<string, unknown>;
  const botToken = requiredNonEmptyString(record, "bot_token", source);
  const chatId = requiredChatId(record, source);
  const expectedSenderId = requiredSafeInteger(record, "expected_sender_id", source);
  const timeoutMs = optionalPositiveInteger(
    record,
    "timeout_ms",
    DEFAULT_TELEGRAM_LIVENESS_TIMEOUT_MS,
    source,
  );
  const pollIntervalMs = optionalPositiveInteger(
    record,
    "poll_interval_ms",
    DEFAULT_TELEGRAM_LIVENESS_POLL_INTERVAL_MS,
    source,
  );
  const maxDrainBatches = optionalPositiveInteger(
    record,
    "max_drain_batches",
    DEFAULT_TELEGRAM_LIVENESS_MAX_DRAIN_BATCHES,
    source,
  );
  return {
    botToken,
    chatId,
    expectedSenderId,
    timeoutMs,
    pollIntervalMs,
    maxDrainBatches,
  };
}

export async function verifyTelegramAgentLivenessFromFortress(
  options: VerifyTelegramAgentLivenessFromFortressOptions,
): Promise<AgentLivenessProbeResult | undefined> {
  const read = await readTelegramLivenessProbeConfigFromFortress({
    fortressPath: options.fortressPath,
    ...(options.expectedOwnerUid !== undefined ? { expectedOwnerUid: options.expectedOwnerUid } : {}),
    ...(options.configFs ? { fs: options.configFs } : {}),
  });
  if (read.kind === "absent") return undefined;
  return runTelegramLivenessProbe({
    config: read.config,
    ...(options.ops ? { ops: options.ops } : {}),
    ...(options.audit ? { audit: options.audit } : {}),
    ...(options.auditIdentityId !== undefined ? { auditIdentityId: options.auditIdentityId } : {}),
  });
}

export async function runTelegramLivenessProbe(
  options: RunTelegramLivenessProbeOptions,
): Promise<AgentLivenessProbeResult> {
  const ops = resolveProbeOps(options.ops);
  const nonce = ops.randomNonce();
  let result: AgentLivenessProbeResult | undefined;
  let requestId: string | undefined;
  let responseId: string | undefined;
  try {
    const drain = await drainStaleUpdates({
      config: options.config,
      apiBaseUrl: options.apiBaseUrl,
      ops,
    });
    if (drain.detail !== undefined) {
      result = unverified("provider_failed", drain.detail);
      return result;
    }
    const sent = await sendProbeMessage({
      config: options.config,
      apiBaseUrl: options.apiBaseUrl,
      ops,
      nonce,
    });
    if ("detail" in sent) {
      result = unverified(sent.reason, sent.detail);
      return result;
    }
    requestId = telegramRequestId(sent.messageId, nonce);
    const waited = await waitForReply({
      config: options.config,
      apiBaseUrl: options.apiBaseUrl,
      ops,
      nonce,
      requestMessageId: sent.messageId,
      initialOffset: drain.nextOffset,
    });
    if (waited.responseMessageId !== undefined) {
      responseId = `telegram:${String(waited.responseMessageId)}`;
      result = {
        kind: "round_trip",
        roundTrip: {
          channel: "telegram",
          requestId,
          responseId,
        },
      };
      return result;
    }
    result = unverified("provider_failed", waited.detail);
    return result;
  } finally {
    if (options.audit !== undefined) {
      await appendProbeAudit({
        audit: options.audit,
        identityId: options.auditIdentityId ?? "system",
        config: options.config,
        nonce,
        result: resultFromMaybeUndefined(result),
        requestId,
        responseId,
      });
    }
  }
}

function requiredNonEmptyString(
  record: Record<string, unknown>,
  key: string,
  source: string,
): string {
  const value = record[key];
  if (typeof value !== "string" || value.trim().length === 0) {
    throw configMalformed(source);
  }
  return value.trim();
}

function requiredChatId(record: Record<string, unknown>, source: string): string {
  const value = record.chat_id;
  if (typeof value === "string" && value.trim().length > 0) return value.trim();
  if (typeof value === "number" && Number.isSafeInteger(value)) return String(value);
  throw configMalformed(source);
}

function requiredSafeInteger(
  record: Record<string, unknown>,
  key: string,
  source: string,
): number {
  const value = record[key];
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  throw configMalformed(source);
}

function optionalPositiveInteger(
  record: Record<string, unknown>,
  key: string,
  fallback: number,
  source: string,
): number {
  const value = record[key];
  if (value === undefined) return fallback;
  if (typeof value === "number" && Number.isSafeInteger(value) && value > 0) return value;
  throw configMalformed(source);
}

function resolveProbeOps(partial: Partial<TelegramLivenessProbeOps> | undefined): TelegramLivenessProbeOps {
  return {
    fetch: partial?.fetch ?? fetch,
    nowMs: partial?.nowMs ?? Date.now,
    sleepMs: partial?.sleepMs ?? ((ms) => new Promise<void>((resolve) => setTimeout(resolve, ms))),
    randomNonce: partial?.randomNonce ?? randomUUID,
  };
}

function apiUrl(
  apiBaseUrl: string | undefined,
  token: string,
  method: "sendMessage" | "getUpdates",
): string {
  return `${(apiBaseUrl ?? DEFAULT_TELEGRAM_API_BASE_URL).replace(/\/+$/, "")}/bot${encodeURIComponent(token)}/${method}`;
}

async function telegramCall(input: {
  config: TelegramLivenessProbeConfig;
  apiBaseUrl: string | undefined;
  ops: TelegramLivenessProbeOps;
  method: "sendMessage" | "getUpdates";
  body: Record<string, unknown>;
  failureDetail: TelegramLivenessProbeFailureDetail;
}): Promise<TelegramCallOk> {
  let res: Response;
  try {
    res = await input.ops.fetch(apiUrl(input.apiBaseUrl, input.config.botToken, input.method), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(input.body),
    });
  } catch (err) {
    throw new TelegramLivenessProbeRequestError((err as Error).message, input.failureDetail);
  }
  let body: unknown;
  try {
    body = await res.json();
  } catch (err) {
    throw new TelegramLivenessProbeRequestError((err as Error).message, input.failureDetail);
  }
  const record = body && typeof body === "object" && !Array.isArray(body)
    ? body as Record<string, unknown>
    : {};
  if (res.status === 429 || record.error_code === 429) {
    throw new TelegramLivenessProbeRequestError("Telegram Bot API rate limited the probe", "rate_limited");
  }
  if (!res.ok || record.ok !== true) {
    throw new TelegramLivenessProbeRequestError(
      typeof record.description === "string" ? record.description : `Telegram Bot API ${input.method} failed`,
      input.failureDetail,
    );
  }
  return { body: record, result: record.result };
}

async function sendProbeMessage(input: {
  config: TelegramLivenessProbeConfig;
  apiBaseUrl: string | undefined;
  ops: TelegramLivenessProbeOps;
  nonce: string;
}): Promise<
  | { messageId: number }
  | { reason: CosLivenessUnverifiedReason; detail: TelegramLivenessProbeFailureDetail }
> {
  let call: TelegramCallOk;
  try {
    call = await telegramCall({
      config: input.config,
      apiBaseUrl: input.apiBaseUrl,
      ops: input.ops,
      method: "sendMessage",
      failureDetail: "send_failed",
      body: {
        chat_id: input.config.chatId,
        text: `/sanctuary_liveness_probe ${input.nonce}`,
        disable_notification: true,
      },
    });
  } catch (err) {
    return {
      reason: detailReason(errorDetail(err)),
      detail: errorDetail(err),
    };
  }
  const result = call.result;
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    return { reason: "network_unavailable", detail: "send_failed" };
  }
  const messageId = (result as Record<string, unknown>).message_id;
  if (typeof messageId !== "number" || !Number.isSafeInteger(messageId)) {
    return { reason: "network_unavailable", detail: "send_failed" };
  }
  return { messageId };
}

async function getUpdates(input: {
  config: TelegramLivenessProbeConfig;
  apiBaseUrl: string | undefined;
  ops: TelegramLivenessProbeOps;
  offset: number | undefined;
}): Promise<TelegramUpdate[]> {
  const body: Record<string, unknown> = {
    timeout: TELEGRAM_MAX_GET_UPDATES_TIMEOUT_SECONDS,
    allowed_updates: ["message"],
  };
  if (input.offset !== undefined) body.offset = input.offset;
  const call = await telegramCall({
    config: input.config,
    apiBaseUrl: input.apiBaseUrl,
    ops: input.ops,
    method: "getUpdates",
    failureDetail: "send_ok_no_reply",
    body,
  });
  if (!Array.isArray(call.result)) {
    throw new TelegramLivenessProbeRequestError("Telegram Bot API getUpdates returned a non-array result", "send_ok_no_reply");
  }
  return call.result.filter((item): item is TelegramUpdate =>
    item !== null && typeof item === "object" && !Array.isArray(item),
  );
}

async function drainStaleUpdates(input: {
  config: TelegramLivenessProbeConfig;
  apiBaseUrl: string | undefined;
  ops: TelegramLivenessProbeOps;
}): Promise<{ nextOffset: number | undefined; detail?: TelegramLivenessProbeFailureDetail }> {
  let offset: number | undefined;
  let nonEmptyBatches = 0;
  for (;;) {
    let updates: TelegramUpdate[];
    try {
      updates = await getUpdates({ ...input, offset });
    } catch (err) {
      return { nextOffset: offset, detail: errorDetail(err) };
    }
    if (updates.length === 0) return { nextOffset: offset };
    nonEmptyBatches += 1;
    if (nonEmptyBatches > input.config.maxDrainBatches) {
      return { nextOffset: offset, detail: "stale_update_backlog" };
    }
    offset = nextOffsetFromUpdates(updates, offset);
  }
}

async function waitForReply(input: {
  config: TelegramLivenessProbeConfig;
  apiBaseUrl: string | undefined;
  ops: TelegramLivenessProbeOps;
  nonce: string;
  requestMessageId: number;
  initialOffset: number | undefined;
}): Promise<{
  responseMessageId?: number;
  detail: TelegramLivenessProbeFailureDetail;
}> {
  const deadline = input.ops.nowMs() + input.config.timeoutMs;
  let offset = input.initialOffset;
  let bestFailure: TelegramLivenessProbeFailureDetail = "send_ok_no_reply";
  for (;;) {
    let updates: TelegramUpdate[];
    try {
      updates = await getUpdates({
        config: input.config,
        apiBaseUrl: input.apiBaseUrl,
        ops: input.ops,
        offset,
      });
    } catch (err) {
      return { detail: errorDetail(err) };
    }
    offset = nextOffsetFromUpdates(updates, offset);
    const classified = classifyUpdates({
      updates,
      config: input.config,
      nonce: input.nonce,
      requestMessageId: input.requestMessageId,
    });
    if (classified.responseMessageId !== undefined) {
      return { responseMessageId: classified.responseMessageId, detail: "send_ok_no_reply" };
    }
    if (classified.detail !== undefined) {
      bestFailure = strongerReplyFailure(bestFailure, classified.detail);
    }
    const remaining = deadline - input.ops.nowMs();
    if (remaining <= 0) return { detail: bestFailure };
    await input.ops.sleepMs(Math.min(input.config.pollIntervalMs, remaining));
  }
}

function classifyUpdates(input: {
  updates: TelegramUpdate[];
  config: TelegramLivenessProbeConfig;
  nonce: string;
  requestMessageId: number;
}): { responseMessageId?: number; detail?: TelegramLivenessProbeFailureDetail } {
  let detail: TelegramLivenessProbeFailureDetail | undefined;
  for (const update of input.updates) {
    const message = update.message;
    if (message === undefined) continue;
    if (!messageChatMatches(message, input.config.chatId)) continue;
    if (!messageRepliesToRequest(message, input.requestMessageId)) continue;
    if (!messageFromExpectedSender(message, input.config.expectedSenderId)) {
      detail = strongerReplyFailure(detail ?? "send_ok_no_reply", "reply_wrong_sender");
      continue;
    }
    if (!messageContainsNonce(message, input.nonce)) {
      detail = strongerReplyFailure(detail ?? "send_ok_no_reply", "reply_no_nonce");
      continue;
    }
    const responseMessageId = numericMessageId(message);
    if (responseMessageId !== undefined) return { responseMessageId };
  }
  return detail !== undefined ? { detail } : {};
}

function messageChatMatches(message: TelegramMessage, chatId: string): boolean {
  const id = message.chat?.id;
  return id !== undefined && String(id) === chatId;
}

function messageRepliesToRequest(message: TelegramMessage, requestMessageId: number): boolean {
  return message.reply_to_message?.message_id === requestMessageId;
}

function messageFromExpectedSender(message: TelegramMessage, expectedSenderId: number): boolean {
  return message.from?.id === expectedSenderId;
}

function messageContainsNonce(message: TelegramMessage, nonce: string): boolean {
  const text = typeof message.text === "string" ? message.text : "";
  const caption = typeof message.caption === "string" ? message.caption : "";
  return text.includes(nonce) || caption.includes(nonce);
}

function numericMessageId(message: TelegramMessage): number | undefined {
  return typeof message.message_id === "number" && Number.isSafeInteger(message.message_id)
    ? message.message_id
    : undefined;
}

function nextOffsetFromUpdates(
  updates: TelegramUpdate[],
  current: number | undefined,
): number | undefined {
  let max = current === undefined ? undefined : current - 1;
  for (const update of updates) {
    if (typeof update.update_id === "number" && Number.isSafeInteger(update.update_id)) {
      max = max === undefined ? update.update_id : Math.max(max, update.update_id);
    }
  }
  return max === undefined ? current : max + 1;
}

function strongerReplyFailure(
  current: TelegramLivenessProbeFailureDetail,
  candidate: TelegramLivenessProbeFailureDetail,
): TelegramLivenessProbeFailureDetail {
  const rank: Record<TelegramLivenessProbeFailureDetail, number> = {
    send_failed: 0,
    send_ok_no_reply: 1,
    reply_no_nonce: 2,
    reply_wrong_sender: 3,
    rate_limited: 4,
    stale_update_backlog: 5,
  };
  return rank[candidate] > rank[current] ? candidate : current;
}

function errorDetail(err: unknown): TelegramLivenessProbeFailureDetail {
  if (err instanceof TelegramLivenessProbeRequestError) return err.detail;
  return "send_failed";
}

function detailReason(detail: TelegramLivenessProbeFailureDetail): CosLivenessUnverifiedReason {
  if (detail === "send_failed") return "network_unavailable";
  return "provider_failed";
}

function unverified(
  reason: CosLivenessUnverifiedReason,
  detail: TelegramLivenessProbeFailureDetail,
): AgentLivenessProbeResult {
  return { kind: "unverified", reason, detail };
}

function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

function telegramRequestId(messageId: number, nonce: string): string {
  return `telegram:${String(messageId)}:nonce8:${sha256Hex(nonce).slice(0, 8)}`;
}

function redactedDigest(input: string): string {
  return `sha256:${sha256Hex(input)}`;
}

function resultFromMaybeUndefined(result: AgentLivenessProbeResult | undefined): AgentLivenessProbeResult {
  return result ?? { kind: "unverified", reason: "provider_failed", detail: "send_failed" };
}

async function appendProbeAudit(input: {
  audit: TelegramLivenessProbeAuditSink;
  identityId: string;
  config: TelegramLivenessProbeConfig;
  nonce: string;
  result: AgentLivenessProbeResult;
  requestId?: string;
  responseId?: string;
}): Promise<void> {
  const details: Record<string, unknown> = {
    channel: "telegram",
    outcome: input.result.kind === "round_trip" ? "verified" : "unverified",
    token_sha256: redactedDigest(input.config.botToken),
    chat_id_sha256: redactedDigest(input.config.chatId),
    expected_sender_id_sha256: redactedDigest(String(input.config.expectedSenderId)),
    nonce_sha256: redactedDigest(input.nonce),
    timeout_ms: input.config.timeoutMs,
  };
  if (input.result.kind === "unverified") {
    details.reason = input.result.reason;
    details.detail = input.result.detail;
  }
  if (input.requestId !== undefined) details.request_id_sha256 = redactedDigest(input.requestId);
  if (input.responseId !== undefined) details.response_id_sha256 = redactedDigest(input.responseId);
  await input.audit.append(
    "l2",
    TELEGRAM_LIVENESS_PROBE_AUDIT_OP,
    input.identityId,
    details,
    input.result.kind === "round_trip" ? "success" : "failure",
  );
}
