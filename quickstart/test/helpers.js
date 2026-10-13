/**
 * Shared fixtures for the quickstart tests.
 *
 * Hermeticity: every test points the CLI at a throwaway HOME, so the identity
 * file lands in a temp directory and never in the operator's real
 * `~/.sanctuary`. The CLI resolves its identity path from `os.homedir()`,
 * which reads HOME on POSIX, so overriding HOME on the child process (or
 * passing `homeDir` to `run`) is the whole isolation.
 */

import http from "node:http";
import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const DIST_DIR = path.resolve(__dirname, "..", "dist");
export const CLI_PATH = path.join(DIST_DIR, "index.js");

/** Child-process ceiling; the whole flow is specified to finish in under 60s. */
export const RUN_TIMEOUT_MS = 60_000;

/** Start a mock Verascore that records every POST to /api/publish. */
export function startMockVerascore() {
  return new Promise((resolve) => {
    const received = [];
    const server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk;
      });
      req.on("end", () => {
        if (req.method === "POST" && req.url === "/api/publish") {
          let parsed = null;
          try {
            parsed = JSON.parse(body);
          } catch {
            parsed = null;
          }
          received.push({ url: req.url, body: parsed });
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: true }));
        } else {
          res.writeHead(404);
          res.end("not found");
        }
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      resolve({
        url: `http://127.0.0.1:${port}`,
        received,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

/** A fresh temp directory to stand in for HOME. */
export async function makeTempHome() {
  return fs.mkdtemp(path.join(os.tmpdir(), "sanctuary-quickstart-test-"));
}

export async function removeTempHome(dir) {
  await fs.rm(dir, { recursive: true, force: true });
}

export function identityPathIn(home) {
  return path.join(home, ".sanctuary", "quickstart-identity.json");
}

export async function readIdentity(home) {
  return JSON.parse(await fs.readFile(identityPathIn(home), "utf8"));
}

/**
 * Spawn the built CLI with stdin ignored, so neither stdin nor stdout is a
 * TTY: the non-interactive path.
 */
export function runCli(args, { home, verascoreUrl }) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI_PATH, ...args], {
      env: { ...process.env, HOME: home, VERASCORE_URL: verascoreUrl },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c) => (stdout += c.toString()));
    child.stderr.on("data", (c) => (stderr += c.toString()));
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`quickstart exceeded ${RUN_TIMEOUT_MS}ms`));
    }, RUN_TIMEOUT_MS);
    child.on("exit", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}
