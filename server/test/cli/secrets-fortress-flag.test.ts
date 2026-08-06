/**
 * `sanctuary secrets` refuses a post-subcommand `--fortress`.
 *
 * `secrets.ts` never parses `--fortress`; the fortress comes from
 * `SecretsArgs.storagePath` or from `SANCTUARY_STORAGE_PATH` via
 * `loadConfig()`. So `sanctuary secrets add NAME VALUE --fortress /other`
 * used to write the credential into the ambient fortress and print
 * "Stored secret", with `/other` left untouched. Reproduced against the built
 * CLI on 2026-08-05; see `assertNoFortressFlag` in `src/cli/secrets.ts`.
 *
 * These tests are NOT darwin-gated, unlike `secrets.test.ts`. That is the
 * point: the refusal returns before `openBroker` runs, so no keychain, no
 * passphrase and no master key are involved. Each write-verb case asserts the
 * storage path is still empty afterwards, which is the property that matters
 * (nothing was written anywhere) and is what a guard placed after the broker
 * opened would fail.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable, Readable } from "node:stream";
import { runSecretsCommand } from "../../src/cli/secrets.js";

class StringWritable extends Writable {
  chunks: string[] = [];
  _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void
  ) {
    this.chunks.push(
      typeof chunk === "string" ? chunk : chunk.toString("utf8")
    );
    cb();
  }
  get text(): string {
    return this.chunks.join("");
  }
}

function emptyStdin(): NodeJS.ReadableStream & { isTTY?: boolean } {
  const stream = Readable.from([]) as unknown as NodeJS.ReadableStream & {
    isTTY?: boolean;
  };
  stream.isTTY = false;
  return stream;
}

describe("sanctuary secrets: post-subcommand --fortress", () => {
  let ambient: string;
  let other: string;

  beforeEach(() => {
    ambient = mkdtempSync(join(tmpdir(), "sanctuary-secrets-ambient-"));
    other = mkdtempSync(join(tmpdir(), "sanctuary-secrets-other-"));
  });

  afterEach(() => {
    for (const dir of [ambient, other]) {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {}
    }
  });

  async function run(argv: string[]) {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runSecretsCommand({
      argv,
      out,
      err,
      stdin: emptyStdin(),
      // The ambient fortress the command would have run against. Supplied
      // explicitly so a refusal that leaked through would be visible as a
      // write here rather than in the operator's real ~/.sanctuary.
      storagePath: ambient,
      passphrase: "unused-because-the-refusal-returns-first",
    });
    return { code, out: out.text, err: err.text };
  }

  /** Nothing was opened, derived, or written in either fortress. */
  function expectBothFortressesUntouched(): void {
    expect(readdirSync(ambient)).toEqual([]);
    expect(readdirSync(other)).toEqual([]);
  }

  // The three verbs that WRITE. These are the reason this refusal exists: a
  // dropped flag here puts a credential in a fortress the operator did not
  // name and reports success.
  for (const verb of ["add", "rotate", "delete"]) {
    it(`refuses '${verb} ... --fortress <path>' and writes nothing`, async () => {
      const r = await run([verb, "demo_token", "secret-value", "--fortress", other]);
      expect(r.code).toBe(2);
      expect(r.err).toContain("--fortress is not read after the subcommand");
      expect(r.out).toBe("");
      expectBothFortressesUntouched();
    });
  }

  it("refuses 'list --fortress <path>' (the read side of the same slip)", async () => {
    const r = await run(["list", "--fortress", other]);
    expect(r.code).toBe(2);
    expect(r.err).toContain("--fortress is not read after the subcommand");
    expectBothFortressesUntouched();
  });

  it("refuses the --fortress=<path> spelling", async () => {
    const r = await run(["add", "demo_token", "v", `--fortress=${other}`]);
    expect(r.code).toBe(2);
    expect(r.err).toContain("--fortress is not read after the subcommand");
    expectBothFortressesUntouched();
  });

  it("refuses the missing-value form, where the flag is the last token", async () => {
    // `identity create --fortress --json` consumed `--json` as the path and
    // created a directory named `--json`. Matching on the flag token rather
    // than on a well-formed flag+value pair is what covers this shape.
    const r = await run(["add", "demo_token", "--fortress"]);
    expect(r.code).toBe(2);
    expect(r.err).toContain("--fortress is not read after the subcommand");
    expectBothFortressesUntouched();
  });

  it("names a form that works, so the refusal is one line to recover from", async () => {
    const r = await run(["list", "--fortress", other]);
    expect(r.err).toContain("sanctuary --fortress <path> secrets");
    expect(r.err).toContain("SANCTUARY_STORAGE_PATH");
  });

  // Negative direction: the refusal must not fire on anything else. Both cases
  // below stop at the dispatch switch before `openBroker`, so they assert the
  // guard's precision without needing a keychain.
  it("does not fire on a look-alike flag", async () => {
    const r = await run(["not-a-verb", "--fortress-url", "https://example.test"]);
    expect(r.err).toContain("Unknown subcommand");
    expect(r.err).not.toContain("not read after the subcommand");
  });

  it("leaves an unrelated invocation alone", async () => {
    const usage = await run([]);
    expect(usage.code).toBe(0);
    expect(usage.out).toContain("Usage:");
    expect(usage.err).toBe("");

    const unknown = await run(["not-a-verb"]);
    expect(unknown.code).toBe(2);
    expect(unknown.err).toContain("Unknown subcommand");
    expect(unknown.err).not.toContain("not read after the subcommand");
  });
});
