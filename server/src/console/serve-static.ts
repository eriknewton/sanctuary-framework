/**
 * Sanctuary Operator Console v1.0 -- Static File Server
 *
 * Serves server/public/console/* files with correct MIME types.
 * No external resource fetches: audit hook rejects URLs outside
 * the console asset root.
 */

import { readFile } from "node:fs/promises";
import { join, extname } from "node:path";
import type { ServerResponse } from "node:http";

const MIME_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

/**
 * Resolve the public directory. Works from both source (server/src)
 * and dist (server/dist) directories.
 */
export function resolvePublicDir(): string {
  // __dirname at runtime is either server/src/console or server/dist/console
  // The public directory is at server/public/console
  const srcDir = new URL(".", import.meta.url).pathname;
  // Walk up from src/console or dist/console to server/
  const serverDir = join(srcDir, "..", "..");
  return join(serverDir, "public", "console");
}

/**
 * Serve a static file from the console public directory.
 * Returns true if the file was served, false if not found.
 */
export async function serveStaticFile(
  res: ServerResponse,
  requestPath: string,
  publicDir?: string
): Promise<boolean> {
  const dir = publicDir ?? resolvePublicDir();

  // Normalize: strip /console/ prefix if present
  let filePath = requestPath;
  if (filePath.startsWith("/console/")) {
    filePath = filePath.slice("/console".length);
  }
  if (filePath === "/" || filePath === "") {
    filePath = "/index.html";
  }

  // Security: prevent directory traversal
  const resolved = join(dir, filePath);
  if (!resolved.startsWith(dir)) {
    res.writeHead(403, { "Content-Type": "text/plain" });
    res.end("Forbidden");
    return true;
  }

  try {
    const content = await readFile(resolved);
    const ext = extname(resolved);
    const mime = MIME_TYPES[ext] ?? "application/octet-stream";

    res.writeHead(200, {
      "Content-Type": mime,
      "Cache-Control": "no-cache",
    });
    res.end(content);
    return true;
  } catch {
    return false;
  }
}

/**
 * Audit hook: verify that HTML/JS/CSS contain no external URL references.
 * Returns an array of violations (empty = clean).
 */
export function auditNoExternalFetches(
  content: string,
  allowedPatterns: string[] = ["/api/console/"]
): string[] {
  const violations: string[] = [];

  // Match http:// and https:// URLs
  const urlPattern = /https?:\/\/[^\s"'<>)]+/g;
  let match: RegExpExecArray | null;
  while ((match = urlPattern.exec(content)) !== null) {
    const url = match[0];
    // Check if this URL is in the allowed list (SSE API path, etc.)
    const isAllowed = allowedPatterns.some((p) => url.includes(p));
    if (!isAllowed) {
      violations.push(url);
    }
  }

  return violations;
}
