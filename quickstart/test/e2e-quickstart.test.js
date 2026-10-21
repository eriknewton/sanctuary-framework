/**
 * E2E Test: Fresh Quickstart Run
 *
 * Spawns the quickstart CLI with `--publish` against a local mock Verascore
 * server, verifies the identity file is written, a profile URL is printed,
 * and the whole flow completes in under 60 seconds.
 *
 * HOME points at a throwaway directory, so the run never touches the
 * operator's real `~/.sanctuary`.
 *
 * Run:  node --test test/e2e-quickstart.test.js
 * (must be run after `npm run build`)
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  RUN_TIMEOUT_MS,
  makeTempHome,
  readIdentity,
  removeTempHome,
  runCli,
  startMockVerascore,
} from "./helpers.js";

test("quickstart CLI runs end-to-end in under 60s", async () => {
  const home = await makeTempHome();
  const mock = await startMockVerascore();

  const start = Date.now();
  try {
    const { code, stdout, stderr } = await runCli(
      ["--name=TestAgent", "--publish"],
      { home, verascoreUrl: mock.url },
    );
    const elapsedMs = Date.now() - start;

    // 1. Exit 0
    assert.equal(code, 0, `expected exit 0, got ${code}. stderr: ${stderr}`);

    // 2. Profile URL printed
    assert.match(stdout, /Profile: http:\/\/127\.0\.0\.1:\d+\/agent\//, "profile URL not printed");

    // 3. Identity file written
    const parsed = await readIdentity(home);
    assert.ok(parsed.did?.startsWith("did:key:z"), "DID missing or malformed");
    assert.ok(parsed.publicKey && parsed.privateKey, "keys missing");

    // 4. Mock server received publish
    assert.equal(mock.received.length, 1, "expected 1 publish call");
    assert.equal(mock.received[0].body.type, "shr");
    assert.equal(mock.received[0].body.data.name, "TestAgent");
    assert.ok(mock.received[0].body.signature, "signature missing");
    assert.ok(mock.received[0].body.publicKey, "publicKey missing");

    // 5. Under 60s
    assert.ok(elapsedMs < RUN_TIMEOUT_MS, `elapsed ${elapsedMs}ms exceeded 60s`);
  } finally {
    await mock.close();
    await removeTempHome(home);
  }
});
