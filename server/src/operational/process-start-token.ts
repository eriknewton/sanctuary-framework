import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";

/** One second bounds the local identity command, independently of wall time. */
export const PROCESS_START_TOKEN_TIMEOUT_MS = 1000;
type Exec = (file: string, args: string[], options: { env: NodeJS.ProcessEnv; timeout: number }) => Promise<string>;
const execute: Exec = (file, args, options) => new Promise((resolve, reject) => {
  execFile(file, args, { ...options, encoding: "utf8" }, (error, stdout) => error ? reject(error) : resolve(stdout));
});

// Linux /proc stat field 22 is an unsigned decimal tick count, without a prefix.
const LINUX_START_TOKEN_PATTERN = /^\d+$/;
// C-locale ps lstart uses weekday(3), month(3), day(2), time(8), year(4) and four separators.
const DARWIN_START_TOKEN_PATTERN = /^(Sun|Mon|Tue|Wed|Thu|Fri|Sat) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ \d]\d \d{2}:\d{2}:\d{2} \d{4}$/;

/** Recognize only the platform's exact stored token shape before comparing process identities. */
export function isProcessStartToken(value: unknown, host: NodeJS.Platform = process.platform): value is string {
  // Unknown encodings cannot prove pid reuse; must match the parsers below and audit-log.ts's start_token reader.
  return typeof value === "string" && (host === "linux" ? LINUX_START_TOKEN_PATTERN.exec(value)?.[0] === value
    : host === "darwin" ? DARWIN_START_TOKEN_PATTERN.exec(value)?.[0] === value : false);
}

/** Preserve the kernel's exact start ticks even when comm contains spaces or parentheses. */
export function parseLinuxProcessStartToken(raw: string): string | undefined {
  // Field 3 follows the LAST ')'; field 22 is token 20, indexed at 19.
  const closing = raw.lastIndexOf(")");
  if (closing < 0) return undefined;
  const token = raw.slice(closing + 1).trim().split(/\s+/)[19];
  return isProcessStartToken(token, "linux") ? token : undefined;
}

/** Accept only the fixed C-locale, UTC ps shape; preserve interior day padding. */
export function parseDarwinProcessStartToken(raw: string): string | undefined {
  const token = raw.replace(/\n$/, "").replace(/ +$/, "");
  // 24 characters: weekday(3), month(3), day(2), time(8), year(4), four separators.
  return isProcessStartToken(token, "darwin")
    ? token : undefined;
}

/** Read process identity without interpreting wall-clock age; absence is never staleness evidence. */
export async function readProcessStartToken(pid: number, host: NodeJS.Platform = process.platform, exec: Exec = execute): Promise<string | undefined> {
  if (!Number.isSafeInteger(pid) || pid <= 0) return undefined;
  try {
    if (host === "linux") return parseLinuxProcessStartToken(await readFile(`/proc/${pid}/stat`, "utf8"));
    if (host === "darwin") {
      return parseDarwinProcessStartToken(await exec("/bin/ps", ["-p", String(pid), "-o", "lstart="], {
        env: { LC_ALL: "C", TZ: "UTC" }, timeout: PROCESS_START_TOKEN_TIMEOUT_MS,
      }));
    }
  } catch { /* Unreadable identities provide no permission to remove a lock. */ }
  return undefined;
}

let ownToken: Promise<string | undefined> | undefined;
/** Cache this process's identity, including an unreadable result, once per process. */
export function ownProcessStartToken(): Promise<string | undefined> {
  return ownToken ??= readProcessStartToken(process.pid);
}
