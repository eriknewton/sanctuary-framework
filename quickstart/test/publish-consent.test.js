/**
 * Publish consent: quickstart sends nothing to Verascore unless the operator
 * says so.
 *
 * The four paths, each of which still writes the local identity:
 *   1. interactive terminal, no flag: show the exact request and endpoint,
 *      ask a yes/no question that defaults to No, publish only on yes;
 *   2. `--publish`: publish without a prompt (scripted use);
 *   3. `--no-publish`: never publish;
 *   4. no TTY and neither flag: do not publish, print how to with `--publish`.
 *
 * The non-interactive paths spawn the built binary with stdin ignored (no
 * TTY). The interactive path drives the exported `run` entry point with an
 * in-memory input stream and `interactive: true`, which is the same value
 * the binary computes from `process.stdin.isTTY && process.stdout.isTTY`.
 *
 * Run after `npm run build`.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import { readFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  DIST_DIR,
  makeTempHome,
  readIdentity,
  removeTempHome,
  runCli,
  startMockVerascore,
} from "./helpers.js";

const PROMPT_MARKER = "[y/N]";

/** Load the built CLI module; a missing module fails the test that needs it. */
async function loadCli() {
  return import(pathToFileURL(path.join(DIST_DIR, "cli.js")).href);
}

/**
 * Run the CLI in interactive mode. `answer` is typed once the publish
 * question appears; `null` means the question must never appear.
 */
async function runInteractive(args, { home, verascoreUrl, answer }) {
  const { run } = await loadCli();
  const input = new PassThrough();
  const output = new PassThrough();
  let text = "";
  let answered = false;
  output.on("data", (chunk) => {
    text += chunk.toString();
    if (answer !== null && !answered && text.includes(PROMPT_MARKER)) {
      answered = true;
      input.write(`${answer}\n`);
    }
  });
  const code = await run({
    argv: args,
    env: { VERASCORE_URL: verascoreUrl },
    input,
    output,
    interactive: true,
    homeDir: home,
  });
  input.end();
  return { code, stdout: text };
}

async function withFixture(fn) {
  const home = await makeTempHome();
  const mock = await startMockVerascore();
  try {
    await fn({ home, mock });
  } finally {
    await mock.close();
    await removeTempHome(home);
  }
}

async function assertIdentityWritten(home, stdout) {
  const identity = await readIdentity(home);
  assert.ok(identity.did?.startsWith("did:key:z"), "identity file missing or malformed");
  assert.ok(
    !stdout.includes(identity.privateKey),
    "the private key must never be printed",
  );
  return identity;
}

// ─── Path 1: interactive terminal ───────────────────────────────────────

test("interactive: shows the exact request and endpoint, publishes on yes", async () => {
  await withFixture(async ({ home, mock }) => {
    const { code, stdout } = await runInteractive(["--name=Consent Agent"], {
      home,
      verascoreUrl: mock.url,
      answer: "y",
    });
    assert.equal(code, 0, stdout);
    assert.ok(stdout.includes(PROMPT_MARKER), "publish question was not asked");
    assert.ok(
      stdout.includes(`${mock.url}/api/publish`),
      "the destination endpoint was not shown before asking",
    );
    assert.equal(mock.received.length, 1, "expected exactly one publish after yes");

    // What was shown is what was sent: every field of the received request
    // body appears in the disclosure printed before the question.
    const disclosure = stdout.slice(0, stdout.indexOf(PROMPT_MARKER));
    const sent = mock.received[0].body;
    assert.ok(disclosure.includes(JSON.stringify(sent, null, 2)), "shown body differs from sent body");
    const identity = await assertIdentityWritten(home, stdout);
    assert.equal(sent.data.did, identity.did);
  });
});

test("interactive: Enter takes the default, which is No", async () => {
  await withFixture(async ({ home, mock }) => {
    const { code, stdout } = await runInteractive(["--name=Consent Agent"], {
      home,
      verascoreUrl: mock.url,
      answer: "",
    });
    assert.equal(code, 0, stdout);
    assert.ok(stdout.includes(PROMPT_MARKER), "publish question was not asked");
    assert.equal(mock.received.length, 0, "Enter must not publish");
    assert.match(stdout, /--publish/, "should say how to publish later");
    await assertIdentityWritten(home, stdout);
  });
});

test("interactive: an explicit no does not publish", async () => {
  await withFixture(async ({ home, mock }) => {
    const { code, stdout } = await runInteractive(["--name=Consent Agent"], {
      home,
      verascoreUrl: mock.url,
      answer: "n",
    });
    assert.equal(code, 0, stdout);
    assert.equal(mock.received.length, 0, "no must not publish");
    await assertIdentityWritten(home, stdout);
  });
});

test("interactive: --no-publish and --publish skip the question", async () => {
  await withFixture(async ({ home, mock }) => {
    const skipped = await runInteractive(["--name=A", "--no-publish"], {
      home,
      verascoreUrl: mock.url,
      answer: null,
    });
    assert.equal(skipped.code, 0, skipped.stdout);
    assert.ok(!skipped.stdout.includes(PROMPT_MARKER), "--no-publish must not ask");
    assert.equal(mock.received.length, 0, "--no-publish must not publish");

    const published = await runInteractive(["--name=A", "--publish"], {
      home,
      verascoreUrl: mock.url,
      answer: null,
    });
    assert.equal(published.code, 0, published.stdout);
    assert.ok(!published.stdout.includes(PROMPT_MARKER), "--publish must not ask");
    assert.equal(mock.received.length, 1, "--publish must publish once");
  });
});

// ─── Path 2: --publish ───────────────────────────────────────────────────

test("--publish: publishes without a prompt", async () => {
  await withFixture(async ({ home, mock }) => {
    const { code, stdout, stderr } = await runCli(["--name=Scripted", "--publish"], {
      home,
      verascoreUrl: mock.url,
    });
    assert.equal(code, 0, stderr);
    assert.ok(!stdout.includes(PROMPT_MARKER), "--publish must not ask");
    assert.equal(mock.received.length, 1, "--publish must publish once");
    await assertIdentityWritten(home, stdout);
  });
});

// ─── Path 3: --no-publish ────────────────────────────────────────────────

test("--no-publish: never publishes, still writes the identity", async () => {
  await withFixture(async ({ home, mock }) => {
    const { code, stdout, stderr } = await runCli(["--name=Local", "--no-publish"], {
      home,
      verascoreUrl: mock.url,
    });
    assert.equal(code, 0, stderr);
    assert.equal(mock.received.length, 0, "--no-publish must not publish");
    await assertIdentityWritten(home, stdout);
  });
});

// ─── Path 4: no TTY, no flag ─────────────────────────────────────────────

test("no TTY and no flag: does not publish, prints how to with --publish", async () => {
  await withFixture(async ({ home, mock }) => {
    const { code, stdout, stderr } = await runCli(["--name=Piped"], {
      home,
      verascoreUrl: mock.url,
    });
    assert.equal(code, 0, stderr);
    assert.equal(mock.received.length, 0, "a non-interactive run must not publish by default");
    assert.match(stdout, /--publish/, "should print how to publish");
    await assertIdentityWritten(home, stdout);
  });
});

test("no TTY, --yes and no name: takes defaults, which never include publishing", async () => {
  await withFixture(async ({ home, mock }) => {
    const { code, stdout, stderr } = await runCli(["--yes"], {
      home,
      verascoreUrl: mock.url,
    });
    assert.equal(code, 0, stderr);
    assert.equal(mock.received.length, 0, "--yes alone must not publish");
    await assertIdentityWritten(home, stdout);
  });
});

test("--publish together with --no-publish is refused before anything runs", async () => {
  await withFixture(async ({ home, mock }) => {
    const { code } = await runCli(["--publish", "--no-publish"], {
      home,
      verascoreUrl: mock.url,
    });
    assert.equal(code, 2, "conflicting flags must exit with a usage error");
    assert.equal(mock.received.length, 0);
  });
});

test("payload version is derived from package.json, which is 0.2.0", async () => {
  const pkg = JSON.parse(
    readFileSync(path.join(DIST_DIR, "..", "package.json"), "utf8"),
  );
  assert.equal(pkg.version, "0.2.0");
  const { buildPayload } = await import(
    pathToFileURL(path.join(DIST_DIR, "publish.js")).href
  );
  const payload = buildPayload(
    { did: "did:key:zTest", publicKey: "", privateKey: "", createdAt: "" },
    "Version Check",
  );
  assert.equal(payload.sanctuary_version, `quickstart-${pkg.version}`);
});
