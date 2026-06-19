import type { ServerResponse } from "node:http";

export type PublicErrorCode =
  | "bad_request"
  | "invalid_json"
  | "payload_too_large"
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "service_unavailable"
  | "internal_error";

export interface CaughtErrorLogEntry {
  route?: string;
  operation?: string;
  status?: number;
  public_code?: PublicErrorCode;
  error_name: string;
  error_message: string;
  error_stack?: string;
}

export interface CaughtErrorContext {
  route?: string;
  operation?: string;
  log?: (entry: CaughtErrorLogEntry) => void | Promise<void>;
}

const BEARER_SECRET_PATTERN = /\bBearer\s+[A-Za-z0-9._~+/=-]+/gi;
const KEYED_SECRET_PATTERN =
  /\b(passphrase|password|secret|token|api[_-]?key|private[_-]?key|authorization)\b\s*[:=]\s*("[^"]*"|'[^']*'|[^\s,;]+)/gi;
const PRIVATE_KEY_PATTERN =
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g;

function redactSecrets(value: string): string {
  return value
    .replace(BEARER_SECRET_PATTERN, "Bearer <redacted>")
    .replace(KEYED_SECRET_PATTERN, (_match, key: string) => `${key}=<redacted>`)
    .replace(PRIVATE_KEY_PATTERN, "<redacted-private-key>");
}

function describeCaughtError(err: unknown): {
  error_name: string;
  error_message: string;
  error_stack?: string;
} {
  if (err instanceof Error) {
    return {
      error_name: err.name || "Error",
      error_message: redactSecrets(err.message),
      ...(err.stack !== undefined ? { error_stack: redactSecrets(err.stack) } : {}),
    };
  }
  return {
    error_name: typeof err,
    error_message: redactSecrets(String(err)),
  };
}

/** Map an HTTP status to the generic public code used for caught exceptions. */
export function publicCodeForStatus(status: number): PublicErrorCode {
  if (status === 400 || status === 422) return "bad_request";
  if (status === 401) return "unauthorized";
  if (status === 403) return "forbidden";
  if (status === 404) return "not_found";
  if (status === 409) return "conflict";
  if (status === 413) return "payload_too_large";
  if (status === 503) return "service_unavailable";
  return "internal_error";
}

/**
 * Record caught-exception diagnostics for operators without exposing known
 * secret-shaped values. This is server-side only; callers choose the sink.
 */
export function logCaughtError(
  err: unknown,
  ctx: CaughtErrorContext = {},
  meta: { status?: number; publicCode?: PublicErrorCode } = {},
): void {
  const entry: CaughtErrorLogEntry = {
    ...describeCaughtError(err),
    ...(ctx.route !== undefined ? { route: ctx.route } : {}),
    ...(ctx.operation !== undefined ? { operation: ctx.operation } : {}),
    ...(meta.status !== undefined ? { status: meta.status } : {}),
    ...(meta.publicCode !== undefined ? { public_code: meta.publicCode } : {}),
  };

  try {
    if (ctx.log) {
      void Promise.resolve(ctx.log(entry)).catch(() => undefined);
      return;
    }
    console.error("[sanctuary:http-error]", JSON.stringify(entry));
  } catch {
    // Error logging must never alter the HTTP response path.
  }
}

/**
 * Send the public caught-error envelope and log the redacted exception detail.
 * The response body intentionally contains no exception message or stack.
 */
export function sendCaughtError(
  res: ServerResponse,
  status: number,
  publicCode: PublicErrorCode,
  err: unknown,
  ctx: CaughtErrorContext = {},
): void {
  logCaughtError(err, ctx, { status, publicCode });
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify({ error: publicCode }));
}
