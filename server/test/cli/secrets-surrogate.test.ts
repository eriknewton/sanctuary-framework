/**
 * Capability: the operator CLI refuses to grant a surrogate-bound secret, and
 * the `secrets surrogate` verb family reads bindings without ever printing a
 * value or a placeholder.
 *
 * Host-free: every case here is reached BEFORE the keychain is opened, so no
 * `security` subprocess runs, no operator keychain is touched, and the suite is
 * not darwin-only. The paths that do open a keychain (`surrogate add`) are
 * covered separately.
 *
 * Defect id: SURROGATE-BROKER-REACHABLE.
 */

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { parseSurrogateAddFlags, runSecretsCommand } from "../../src/cli/secrets.js";
import { surrogatePolicyPath, brokerPolicyPath } from "../../src/disclosure/broker/open.js";
import { SURROGATE_POLICY_VERSION } from "../../src/disclosure/broker/policy.js";

class StringWritable extends Writable {
  chunks: string[] = [];
  _write(chunk: Buffer | string, _enc: BufferEncoding, cb: (err?: Error) => void) {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }
  get text(): string {
    return this.chunks.join("");
  }
}

const BINDING = {
  secret: "openai-api-key",
  agent: "hermes",
  env: "OPENAI_API_KEY",
  destinations: [{ host: "api.openai.com", port: 443 }],
  header: "Authorization",
};

let storagePath: string;

async function writeSurrogatePolicy(bindings: unknown[]): Promise<void> {
  await writeFile(
    surrogatePolicyPath(storagePath),
    JSON.stringify({ surrogate_policy_version: SURROGATE_POLICY_VERSION, bindings }),
    "utf8",
  );
}

async function run(argv: string[]) {
  const out = new StringWritable();
  const err = new StringWritable();
  const code = await runSecretsCommand({ argv, out, err, storagePath });
  return { code, out: out.text, err: err.text };
}

beforeEach(async () => {
  storagePath = await mkdtemp(join(tmpdir(), "sanctuary-cli-surrogate-"));
});

afterEach(async () => {
  await rm(storagePath, { recursive: true, force: true });
});

describe("secrets grant refuses a surrogate-bound secret", () => {
  it("refuses before the broker policy file is written", async () => {
    await writeSurrogatePolicy([BINDING]);
    const result = await run(["grant", "mailer", "openai-api-key", "--scope", "read"]);

    expect(result.code).toBe(1);
    expect(result.err).toContain("bound as a surrogate");
    expect(result.err).toContain("surrogate remove openai-api-key");
    // The refusal happens ahead of the write, so no broker policy exists at all.
    const { existsSync } = await import("node:fs");
    expect(existsSync(brokerPolicyPath(storagePath))).toBe(false);
  });

  it("refuses when the surrogate policy is present and unreadable", async () => {
    await writeFile(surrogatePolicyPath(storagePath), "{ not json", "utf8");
    const result = await run(["grant", "mailer", "anything", "--scope", "read"]);

    expect(result.code).toBe(1);
    // Refusing rather than guessing: a broken file must not read as "no bindings".
    expect(result.err).toContain("could not be");
    expect(result.err).toContain("json_error");
  });

  it("an unbound secret is not refused by the binding check", async () => {
    // No-regression, and the boundary of the refusal. It gets past the check and
    // then fails on the keychain, which is a different failure than a refusal.
    await writeSurrogatePolicy([BINDING]);
    const result = await run(["grant", "mailer", "sendgrid-key", "--scope", "read"]);
    expect(result.err).not.toContain("bound as a surrogate");
  });
});

describe("secrets surrogate list", () => {
  it("prints nothing but names, destinations and the bound header", async () => {
    await writeSurrogatePolicy([BINDING]);
    const result = await run(["surrogate", "list"]);

    expect(result.code).toBe(0);
    expect(result.out).toContain("openai-api-key");
    expect(result.out).toContain("agent=hermes");
    expect(result.out).toContain("hosts=api.openai.com:443");
    // A placeholder is a live bearer surrogate for its generation, so no line
    // this command prints may ever carry the grammar.
    expect(result.out).not.toContain("sanctuary_surrogate_");
  });

  it("says so plainly when there are no bindings", async () => {
    const result = await run(["surrogate", "list"]);
    expect(result.code).toBe(0);
    expect(result.out).toContain("No surrogate bindings");
  });

  it("reports a broken policy rather than an empty list", async () => {
    await writeFile(surrogatePolicyPath(storagePath), "{ not json", "utf8");
    const result = await run(["surrogate", "list"]);
    expect(result.code).toBe(1);
    expect(result.out).not.toContain("No surrogate bindings");
  });
});

describe("secrets surrogate dispatch", () => {
  it("prints its own command list with no subcommand", async () => {
    const result = await run(["surrogate"]);
    expect(result.code).toBe(0);
    expect(result.out).toContain("surrogate <command>");
    expect(result.out).toContain("--header");
  });

  it("refuses an unknown subcommand with the usage-error code", async () => {
    const result = await run(["surrogate", "unlokc"]);
    expect(result.code).toBe(2);
    expect(result.err).toContain("Unknown surrogate subcommand");
  });

  it("appears in the top-level secrets usage", async () => {
    const result = await run(["--help"]);
    expect(result.out).toContain("surrogate <command>");
  });
});

describe("surrogate add flag grammar", () => {
  it("names every missing required flag at once", () => {
    const flags = parseSurrogateAddFlags(["openai-api-key"]);
    expect(flags.error).toBeDefined();
    for (const flag of ["--agent", "--env", "--header", "--host"]) {
      expect(flags.error).toContain(flag);
    }
  });

  it("splits a comma list into hosts and trims them", () => {
    const flags = parseSurrogateAddFlags([
      "openai-api-key",
      "--agent",
      "hermes",
      "--env",
      "OPENAI_API_KEY",
      "--header",
      "Authorization",
      "--host",
      "api.openai.com, api.example.com",
    ]);
    expect(flags.error).toBeUndefined();
    expect(flags.hosts).toEqual(["api.openai.com", "api.example.com"]);
  });

  it("a trailing comma does not produce an empty host", () => {
    const flags = parseSurrogateAddFlags([
      "openai-api-key",
      "--agent",
      "hermes",
      "--env",
      "OPENAI_API_KEY",
      "--header",
      "Authorization",
      "--host",
      "api.openai.com,",
    ]);
    expect(flags.hosts).toEqual(["api.openai.com"]);
  });
});
