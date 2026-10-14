/**
 * Saved identity is never overwritten by an ordinary run.
 *
 * ~/.sanctuary/quickstart-identity.json may hold the only copy of the key
 * behind a profile that is already public. A run reuses it and never writes
 * it, so a declined, skipped or repeated run leaves the file byte-identical.
 * Only `--new-identity` mints a fresh identity, and it copies the old file to
 * a backup first. An unusable saved file is left alone and the run stops
 * before anything is sent.
 *
 * Every run uses a throwaway HOME. Run after `npm run build`.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import { promises as fs } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  DIST_DIR,
  identityPathIn,
  makeTempHome,
  removeTempHome,
  runCli,
  startMockVerascore,
} from "./helpers.js";

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

/** Create a saved identity with a first, non-publishing run; return its bytes. */
async function seedIdentity(home, verascoreUrl) {
  const first = await runCli(["--name=Seed", "--no-publish"], { home, verascoreUrl });
  assert.equal(first.code, 0, first.stderr);
  return fs.readFile(identityPathIn(home));
}

async function runInteractiveDecline(home, verascoreUrl) {
  const { run } = await import(pathToFileURL(path.join(DIST_DIR, "cli.js")).href);
  const input = new PassThrough();
  const output = new PassThrough();
  let text = "";
  let answered = false;
  output.on("data", (chunk) => {
    text += chunk.toString();
    if (!answered && text.includes("[y/N]")) {
      answered = true;
      input.write("n\n");
    }
  });
  const code = await run({
    argv: ["--name=Decliner"],
    env: { VERASCORE_URL: verascoreUrl },
    input,
    output,
    interactive: true,
    homeDir: home,
  });
  input.end();
  return { code, stdout: text };
}

test("a saved identity is reused, and declined or skipped runs leave it byte-identical", async () => {
  await withFixture(async ({ home, mock }) => {
    const before = await seedIdentity(home, mock.url);
    const savedDid = JSON.parse(before.toString("utf8")).did;

    const declined = await runInteractiveDecline(home, mock.url);
    assert.equal(declined.code, 0, declined.stdout);
    assert.ok(declined.stdout.includes(savedDid), "the prompt must show the saved DID");

    const skipped = await runCli(["--name=Again", "--no-publish"], { home, verascoreUrl: mock.url });
    assert.equal(skipped.code, 0, skipped.stderr);
    const piped = await runCli(["--name=Piped"], { home, verascoreUrl: mock.url });
    assert.equal(piped.code, 0, piped.stderr);

    const after = await fs.readFile(identityPathIn(home));
    assert.ok(after.equals(before), "the saved identity file must be byte-identical");
    assert.equal(mock.received.length, 0, "nothing was published");
  });
});

test("--publish publishes the saved identity, not a new one", async () => {
  await withFixture(async ({ home, mock }) => {
    const before = await seedIdentity(home, mock.url);
    const savedDid = JSON.parse(before.toString("utf8")).did;

    const published = await runCli(["--name=Later", "--publish"], { home, verascoreUrl: mock.url });
    assert.equal(published.code, 0, published.stderr);
    assert.equal(mock.received.length, 1);
    assert.equal(mock.received[0].body.data.did, savedDid);
    assert.ok((await fs.readFile(identityPathIn(home))).equals(before));
  });
});

test("--new-identity mints a fresh identity and keeps the previous one as a byte-identical backup", async () => {
  await withFixture(async ({ home, mock }) => {
    const before = await seedIdentity(home, mock.url);
    const oldDid = JSON.parse(before.toString("utf8")).did;

    const fresh = await runCli(["--name=Fresh", "--new-identity", "--no-publish"], {
      home,
      verascoreUrl: mock.url,
    });
    assert.equal(fresh.code, 0, fresh.stderr);

    const current = JSON.parse(await fs.readFile(identityPathIn(home), "utf8"));
    assert.notEqual(current.did, oldDid, "a new DID was minted");
    const dir = path.dirname(identityPathIn(home));
    const backups = (await fs.readdir(dir)).filter((f) => f.startsWith("quickstart-identity.backup-"));
    assert.equal(backups.length, 1, "exactly one backup");
    assert.ok((await fs.readFile(path.join(dir, backups[0]))).equals(before), "backup holds the old bytes");
    assert.match(fresh.stdout, /Previous identity kept at/);
    assert.equal(mock.received.length, 0);
  });
});

test("an unusable saved identity file is left unchanged and nothing is sent", async () => {
  await withFixture(async ({ home, mock }) => {
    await fs.mkdir(path.dirname(identityPathIn(home)), { recursive: true });
    const junk = Buffer.from('{"did":"did:key:zNotReal","publicKey":"x","privateKey":"y"}');
    await fs.writeFile(identityPathIn(home), junk, { mode: 0o600 });

    const result = await runCli(["--name=Junk", "--publish"], { home, verascoreUrl: mock.url });
    assert.equal(result.code, 1);
    assert.match(result.stdout, /left unchanged/);
    assert.ok((await fs.readFile(identityPathIn(home))).equals(junk));
    assert.equal(mock.received.length, 0);
  });
});
