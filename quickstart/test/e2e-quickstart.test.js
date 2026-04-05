/**
 * E2E Test: Fresh Quickstart Run
 *
 * Spawns the quickstart CLI against a local mock Verascore server,
 * verifies identity file is written, a profile URL is printed,
 * and the whole flow completes in under 60 seconds.
 *
 * Run:  node --test test/e2e-quickstart.test.js
 * (must be run after `npm run build`)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import http from "node:http";
import { promises as fs } from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CLI_PATH = path.resolve(__dirname, "..", "dist", "index.js");
const IDENTITY_PATH = path.join(os.homedir(), ".sanctuary", "quickstart-identity.json");

/** Start a mock Verascore HTTP server that accepts /api/publish. */
function startMockVerascore() {
  return new Promise((resolve) => {
    const received = [];
    const server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk;
      });
      req.on("end", () => {
        if (req.method === "POST" && req.url === "/api/publish") {
          try {
            const parsed = JSON.parse(body);
            received.push({ url: req.url, body: parsed });
          } catch {
            received.push({ url: req.url, body: null });
          }
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: true, received: true }));
        } else {
          res.writeHead(404);
          res.end("not found");
        }
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      resolve({ server, port, received });
    });
  });
}

test("quickstart CLI runs end-to-end in under 60s", async () => {
  // Back up any existing identity so we don't overwrite real user data.
  let backup = null;
  try {
    backup = await fs.readFile(IDENTITY_PATH);
  } catch {
    backup = null;
  }

  const { server, port, received } = await startMockVerascore();
  const mockUrl = `http://127.0.0.1:${port}`;

  const start = Date.now();
  try {
    const child = spawn(process.execPath, [CLI_PATH, "--name=TestAgent", "--yes"], {
      env: { ...process.env, VERASCORE_URL: mockUrl },
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c) => (stdout += c.toString()));
    child.stderr.on("data", (c) => (stderr += c.toString()));

    const exitCode = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        reject(new Error("Quickstart exceeded 60s"));
      }, 60000);
      child.on("exit", (code) => {
        clearTimeout(timer);
        resolve(code);
      });
      child.on("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });

    const elapsedMs = Date.now() - start;

    // 1. Exit 0
    assert.equal(exitCode, 0, `expected exit 0, got ${exitCode}. stderr: ${stderr}`);

    // 2. Profile URL printed
    assert.match(stdout, /Profile: http:\/\/127\.0\.0\.1:\d+\/agent\//, "profile URL not printed");

    // 3. Identity file written
    const raw = await fs.readFile(IDENTITY_PATH, "utf8");
    const parsed = JSON.parse(raw);
    assert.ok(parsed.did?.startsWith("did:key:z"), "DID missing or malformed");
    assert.ok(parsed.publicKey && parsed.privateKey, "keys missing");

    // 4. Mock server received publish
    assert.equal(received.length, 1, "expected 1 publish call");
    assert.equal(received[0].body.type, "shr");
    assert.equal(received[0].body.data.name, "TestAgent");
    assert.ok(received[0].body.signature, "signature missing");
    assert.ok(received[0].body.publicKey, "publicKey missing");

    // 5. Under 60s
    assert.ok(elapsedMs < 60000, `elapsed ${elapsedMs}ms exceeded 60s`);
  } finally {
    server.close();
    // Restore prior identity if present, otherwise remove the test one.
    if (backup !== null) {
      await fs.writeFile(IDENTITY_PATH, backup, { mode: 0o600 });
    }
  }
});
