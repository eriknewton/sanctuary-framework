/**
 * Capability: the operator verbs that address a running helper decide "armed"
 * from the helper's own answer, refuse on every outcome that is not a clean
 * absent socket, and reach no keychain until after they have refused. Covers
 * `surrogate remove`, `secrets revoke` on a bound name, `unlock`'s no-core
 * rule and its helper-first step order, `lock`, `status` and the root-only
 * `events`.
 *
 * Host-free: the unlock socket and the core-limit check are injected seams, the
 * keychain is an in-memory backend through the store's chokepoint, and the gate
 * log is a fixture file in a temp directory. No `security` subprocess runs, no
 * socket is created under a root-owned path, and no helper is started.
 *
 * Defect id: SURROGATE-BROKER-REACHABLE.
 */

import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  runSecretsCommand,
  probeSurrogateHelperArmed,
  SURROGATE_NO_CORE_SHELL_SCRIPT,
  type SurrogateNoCoreOps,
  type SurrogateUnlockOutcome,
  type SurrogateUnlockTransport,
} from "../../src/cli/secrets.js";
import type { Backend } from "../../src/disclosure/broker/backend-interface.js";
import { SecretNotFoundError } from "../../src/disclosure/broker/backend-interface.js";
import { surrogatePolicyPath } from "../../src/disclosure/broker/open.js";
import { SURROGATE_POLICY_VERSION } from "../../src/disclosure/broker/policy.js";
import { SURROGATE_WIRE_VERSION } from "../../src/credential-surrogate/wire.js";
import { SURROGATE_PLACEHOLDER_REDACTION } from "../../src/credential-surrogate/redaction.js";
import { generateRandomKey } from "../../src/core/random.js";

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

const AGENT_UID = 502;
const SECRET = "openai-api-key";
const BINDING = {
  secret: SECRET,
  agent: "hermes",
  env: "OPENAI_API_KEY",
  destinations: [{ host: "api.openai.com", port: 443 }],
  header: "Authorization",
};
/** Generated per run. The surrogate test value is never a literal in the tree. */
const BOUND_VALUE = Buffer.from(generateRandomKey()).toString("base64url");
const PASSPHRASE = "test-passphrase-not-an-operator-credential";

let storagePath: string;
/** Set by any transport whose call must be proved never to have happened. */
let keychainReads: string[];

function memoryBackend(seed: Record<string, string> = {}): Backend {
  const items = new Map<string, string>(Object.entries(seed));
  return {
    async ensureInitialized() {},
    async unlock() {},
    async isUnlocked() {
      return true;
    },
    async addSecret(name, value) {
      items.set(name, value);
    },
    async readSecret(name) {
      keychainReads.push(name);
      const v = items.get(name);
      if (v === undefined) throw new SecretNotFoundError(name);
      return v;
    },
    async rotateSecret(name, value) {
      items.set(name, value);
    },
    async deleteSecret(name) {
      if (!items.delete(name)) throw new SecretNotFoundError(name);
    },
    async listSecretNames() {
      return Array.from(items.keys());
    },
  };
}

/** A transport that answers every request with one canned outcome. */
function fixedTransport(outcome: SurrogateUnlockOutcome): SurrogateUnlockTransport {
  return { async send() { return outcome; } };
}

function absentTransport(): SurrogateUnlockTransport {
  return fixedTransport({ outcome: "absent" });
}

function statusOutcome(bindings: { secret: string; unlocked: boolean; expires_at: number | null }[]) {
  return (id: string): SurrogateUnlockOutcome => ({
    outcome: "answered",
    response: {
      v: SURROGATE_WIRE_VERSION,
      id,
      kind: "status",
      generation_id: 7,
      bindings,
    },
  });
}

/** Armed helper: answers `status`, accepts every `unlock` and `lock`. */
function armedTransport(): SurrogateUnlockTransport & { unlocked: string[] } {
  const unlocked: string[] = [];
  return {
    unlocked,
    async send(_uid, request) {
      if (request.kind === "status") {
        return statusOutcome([{ secret: SECRET, unlocked: false, expires_at: null }])(request.id);
      }
      if (request.kind === "unlock") unlocked.push(request.value);
      return {
        outcome: "answered",
        response: { v: SURROGATE_WIRE_VERSION, id: request.id, kind: "ok" },
      };
    },
  };
}

async function writePolicy(bindings: unknown[]): Promise<void> {
  await writeFile(
    surrogatePolicyPath(storagePath),
    JSON.stringify({ surrogate_policy_version: SURROGATE_POLICY_VERSION, bindings }),
    "utf8",
  );
}

async function run(argv: string[], extra: Record<string, unknown> = {}) {
  const out = new StringWritable();
  const err = new StringWritable();
  const code = await runSecretsCommand({
    argv,
    out,
    err,
    storagePath,
    passphrase: PASSPHRASE,
    ...extra,
  } as Parameters<typeof runSecretsCommand>[0]);
  return { code, out: out.text, err: err.text };
}

beforeEach(async () => {
  storagePath = await mkdtemp(join(tmpdir(), "sanctuary-cli-surrogate-op-"));
  keychainReads = [];
});

afterEach(async () => {
  await rm(storagePath, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// The armed probe: one classification per outcome, and "indeterminate" is not
// "unarmed". This is the decision every destructive verb below rests on.
// ---------------------------------------------------------------------------

describe("probeSurrogateHelperArmed classifies every outcome", () => {
  it("an absent socket is unarmed, and only an absent socket is", async () => {
    expect((await probeSurrogateHelperArmed(absentTransport(), AGENT_UID)).state).toBe("unarmed");
  });

  it("a status answer is armed and carries the generation", async () => {
    const probe = await probeSurrogateHelperArmed(armedTransport(), AGENT_UID);
    expect(probe.state).toBe("armed");
    expect(probe.generationId).toBe(7);
  });

  it.each(["permission_denied", "timed_out", "malformed_reply", "connect_failed"] as const)(
    "%s is indeterminate, never unarmed",
    async (failureClass) => {
      const probe = await probeSurrogateHelperArmed(
        fixedTransport({ outcome: "unreachable", failureClass }),
        AGENT_UID,
      );
      expect(probe.state).toBe("indeterminate");
      expect(probe.failureClass).toBe(failureClass);
    },
  );

  it("an `ok` in answer to `status` is indeterminate: that is not this codec", async () => {
    const wrongKind = fixedTransport({
      outcome: "answered",
      // The id is checked by the transport, not the probe, so a hand-built
      // response here stands in for a helper that answered the wrong kind.
      response: { v: SURROGATE_WIRE_VERSION, id: "0".repeat(32), kind: "ok" },
    });
    expect((await probeSurrogateHelperArmed(wrongKind, AGENT_UID)).state).toBe("indeterminate");
  });
});

// ---------------------------------------------------------------------------
// surrogate remove and secrets revoke: refuse unless the agent is unarmed
// ---------------------------------------------------------------------------

describe("surrogate remove refuses unless the bound agent is unarmed", () => {
  it("refuses while the helper answers, and leaves the row in place", async () => {
    await writePolicy([BINDING]);
    const result = await run(
      ["surrogate", "remove", SECRET, "--agent-uid", String(AGENT_UID)],
      { surrogateUnlock: armedTransport() },
    );
    expect(result.code).toBe(1);
    expect(result.err).toContain("its agent is armed");
    expect(result.err).toContain("surrogate lock");
    const after = JSON.parse(await readFile(surrogatePolicyPath(storagePath), "utf8"));
    expect(after.bindings).toHaveLength(1);
  });

  it.each(["permission_denied", "timed_out", "malformed_reply", "connect_failed"] as const)(
    "refuses on %s, because a helper may still be serving the binding",
    async (failureClass) => {
      await writePolicy([BINDING]);
      const result = await run(
        ["surrogate", "remove", SECRET, "--agent-uid", String(AGENT_UID)],
        { surrogateUnlock: fixedTransport({ outcome: "unreachable", failureClass }) },
      );
      expect(result.code).toBe(1);
      expect(result.err).toContain("could not establish");
      expect(result.err).toContain(failureClass);
      const after = JSON.parse(await readFile(surrogatePolicyPath(storagePath), "utf8"));
      expect(after.bindings).toHaveLength(1);
    },
  );

  it("succeeds on a socket ENOENT, dropping the row and the stored value", async () => {
    await writePolicy([BINDING]);
    const result = await run(
      ["surrogate", "remove", SECRET, "--agent-uid", String(AGENT_UID)],
      {
        surrogateUnlock: absentTransport(),
        surrogateBackend: memoryBackend({ [SECRET]: BOUND_VALUE }),
      },
    );
    expect(result.code).toBe(0);
    expect(result.out).toContain("Removed binding and surrogate value");
    const after = JSON.parse(await readFile(surrogatePolicyPath(storagePath), "utf8"));
    expect(after.bindings).toHaveLength(0);
  });

  it("requires --agent-uid: there is no uid to probe without one", async () => {
    await writePolicy([BINDING]);
    const result = await run(["surrogate", "remove", SECRET], {
      surrogateUnlock: absentTransport(),
    });
    expect(result.code).toBe(2);
    expect(result.err).toContain("--agent-uid");
  });
});

describe("secrets revoke on a bound secret", () => {
  it("refuses while the helper answers", async () => {
    await writePolicy([BINDING]);
    const result = await run(
      ["revoke", "mailer", SECRET, "--agent-uid", String(AGENT_UID)],
      { surrogateUnlock: armedTransport() },
    );
    expect(result.code).toBe(1);
    expect(result.err).toContain("its agent is armed");
    const after = JSON.parse(await readFile(surrogatePolicyPath(storagePath), "utf8"));
    expect(after.bindings).toHaveLength(1);
  });

  it("removes the binding row on ENOENT and keeps the stored value", async () => {
    await writePolicy([BINDING]);
    const backend = memoryBackend({ [SECRET]: BOUND_VALUE });
    const result = await run(
      ["revoke", "mailer", SECRET, "--agent-uid", String(AGENT_UID)],
      { surrogateUnlock: absentTransport(), surrogateBackend: backend, brokerBackend: memoryBackend() },
    );
    expect(result.code).toBe(0);
    expect(result.out).toContain("Removed surrogate binding");
    expect(result.out).toContain("the stored value was kept");
    const after = JSON.parse(await readFile(surrogatePolicyPath(storagePath), "utf8"));
    expect(after.bindings).toHaveLength(0);
    // `revoke` is a policy verb: it has never deleted a secret, and does not
    // start now just because the name happens to be bound.
    expect(await backend.listSecretNames()).toContain(SECRET);
  });

  it("is untouched for a name that is not bound", async () => {
    await writePolicy([]);
    const result = await run(["revoke", "mailer", "some-other-secret"], {
      surrogateUnlock: fixedTransport({ outcome: "unreachable", failureClass: "timed_out" }),
      surrogateBackend: memoryBackend(),
      brokerBackend: memoryBackend(),
    });
    // The transport above would refuse if it were consulted. An unbound name
    // never reaches the probe, so the ordinary revoke path runs.
    expect(result.code).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// unlock: the no-core rule first, then the helper, then the keychain
// ---------------------------------------------------------------------------

function noCoreOps(hardLimit: string, opts: { reexeced?: boolean } = {}): SurrogateNoCoreOps & { reexecs: number } {
  const state = { reexecs: 0 };
  return {
    get reexecs() {
      return state.reexecs;
    },
    alreadyReexeced: () => opts.reexeced ?? true,
    readHardCoreLimit: async () => hardLimit,
    reexecWithoutCore: async () => {
      state.reexecs += 1;
      return 0;
    },
  };
}

describe("surrogate unlock establishes the no-core rule before anything else", () => {
  it("re-executes itself when it is not yet the core-limited child", async () => {
    await writePolicy([BINDING]);
    const noCore = noCoreOps("0", { reexeced: false });
    const transport = armedTransport();
    const result = await run(["surrogate", "unlock", "--agent-uid", String(AGENT_UID)], {
      surrogateNoCore: noCore,
      surrogateUnlock: transport,
      surrogateBackend: memoryBackend({ [SECRET]: BOUND_VALUE }),
    });
    expect(result.code).toBe(0);
    expect(noCore.reexecs).toBe(1);
    // The parent does no work of its own: it re-execs and returns the child's
    // code. Nothing was sent and nothing was read in this process.
    expect(transport.unlocked).toHaveLength(0);
    expect(keychainReads).toHaveLength(0);
  });

  it("refuses, reading nothing, when the verified hard core limit is not 0", async () => {
    await writePolicy([BINDING]);
    const transport = armedTransport();
    const result = await run(["surrogate", "unlock", "--agent-uid", String(AGENT_UID)], {
      surrogateNoCore: noCoreOps("unlimited"),
      surrogateUnlock: transport,
      surrogateBackend: memoryBackend({ [SECRET]: BOUND_VALUE }),
    });
    expect(result.code).toBe(1);
    expect(result.err).toContain("could still write a core file");
    expect(result.err).toContain("Nothing was sent and no secret was read");
    expect(transport.unlocked).toHaveLength(0);
    expect(keychainReads).toHaveLength(0);
  });

  it("refuses with helper-not-running BEFORE any keychain read when the socket is absent", async () => {
    await writePolicy([BINDING]);
    const result = await run(["surrogate", "unlock", "--agent-uid", String(AGENT_UID)], {
      surrogateNoCore: noCoreOps("0"),
      surrogateUnlock: absentTransport(),
      surrogateBackend: memoryBackend({ [SECRET]: BOUND_VALUE }),
    });
    expect(result.code).toBe(1);
    expect(result.err).toContain("helper-not-running");
    expect(result.err).toContain("Nothing was read");
    // The whole point of the step order: a down helper never causes the
    // operator's master key to unwrap a value.
    expect(keychainReads).toHaveLength(0);
  });

  it("refuses on an indeterminate answer, also before any keychain read", async () => {
    await writePolicy([BINDING]);
    const result = await run(["surrogate", "unlock", "--agent-uid", String(AGENT_UID)], {
      surrogateNoCore: noCoreOps("0"),
      surrogateUnlock: fixedTransport({ outcome: "unreachable", failureClass: "permission_denied" }),
      surrogateBackend: memoryBackend({ [SECRET]: BOUND_VALUE }),
    });
    expect(result.code).toBe(1);
    expect(result.err).toContain("permission_denied");
    expect(keychainReads).toHaveLength(0);
  });

  it("sends one value per connection for the secrets the helper reports", async () => {
    await writePolicy([BINDING]);
    const transport = armedTransport();
    const result = await run(
      ["surrogate", "unlock", "--agent-uid", String(AGENT_UID), "--ttl", "120"],
      {
        surrogateNoCore: noCoreOps("0"),
        surrogateUnlock: transport,
        surrogateBackend: memoryBackend({ [SECRET]: BOUND_VALUE }),
      },
    );
    expect(result.code).toBe(0);
    expect(transport.unlocked).toEqual([BOUND_VALUE]);
    expect(keychainReads).toEqual([SECRET]);
    // Counts and the generation only. The operator line never carries a value.
    expect(result.out).toContain("Unlocked 1 of 1");
    expect(result.out).not.toContain(BOUND_VALUE);
  });

  it("refuses a non-integer --ttl rather than sending an unbounded request", async () => {
    await writePolicy([BINDING]);
    const result = await run(
      ["surrogate", "unlock", "--agent-uid", String(AGENT_UID), "--ttl", "forever"],
      { surrogateNoCore: noCoreOps("0"), surrogateUnlock: armedTransport() },
    );
    expect(result.code).toBe(2);
    expect(result.err).toContain("--ttl must be a positive integer");
  });

  it("pins the no-core shell script both sides of the re-exec agree on", () => {
    // Must match the verification the child performs (`ulimit -H -c`) and the
    // string in `surrogate-helper-daemon.ts`'s plist reasoning: hard THEN soft,
    // then exec, so the limits are in force for the process that holds a value.
    expect(SURROGATE_NO_CORE_SHELL_SCRIPT).toBe('ulimit -H -c 0 && ulimit -S -c 0 && exec "$@"');
  });
});

// ---------------------------------------------------------------------------
// lock, status, events
// ---------------------------------------------------------------------------

describe("surrogate lock and status", () => {
  it("lock reports the drop when the helper acknowledges", async () => {
    const result = await run(["surrogate", "lock", "--agent-uid", String(AGENT_UID)], {
      surrogateUnlock: armedTransport(),
    });
    expect(result.code).toBe(0);
    expect(result.out).toContain("every value for agent uid 502 was dropped");
  });

  it("status prints lock state and never a value or a placeholder", async () => {
    const transport: SurrogateUnlockTransport = {
      async send(_uid, request) {
        return statusOutcome([
          { secret: SECRET, unlocked: true, expires_at: 1700000000 },
          { secret: "other-key", unlocked: false, expires_at: null },
        ])(request.id);
      },
    };
    const result = await run(["surrogate", "status", "--agent-uid", String(AGENT_UID)], {
      surrogateUnlock: transport,
    });
    expect(result.code).toBe(0);
    expect(result.out).toContain("generation 7");
    expect(result.out).toContain(`${SECRET}  unlocked  expires_at=1700000000`);
    expect(result.out).toContain("other-key  locked");
    expect(result.out).not.toContain("sanctuary_surrogate_");
    expect(result.out).not.toContain(BOUND_VALUE);
  });

  it("status reports an absent socket as unarmed rather than as a failure", async () => {
    const result = await run(["surrogate", "status", "--agent-uid", String(AGENT_UID)], {
      surrogateUnlock: absentTransport(),
    });
    expect(result.code).toBe(0);
    expect(result.out).toContain("unarmed");
  });
});

describe("surrogate events", () => {
  it("refuses when the effective uid is not root", async () => {
    const result = await run(
      ["surrogate", "events", "--agent-uid", String(AGENT_UID), "--agent", "hermes"],
      { effectiveUid: 501 },
    );
    expect(result.code).toBe(1);
    expect(result.err).toContain("must run as root");
  });

  it("prints only surrogate lines, with placeholders redacted", async () => {
    // The gate emits no surrogate events in slice 1a, so the fixture stands in
    // for the lines slice 1b will write. Redaction is the property under test.
    const logPath = join(storagePath, "egress-gate-502.err.log");
    const placeholder = `sanctuary_surrogate_${"a1b2c3d4".repeat(4)}`;
    await writeFile(
      logPath,
      [
        "gate_started uid=502",
        `surrogate_swap_applied host=api.openai.com placeholder=${placeholder}`,
        "gate_denied reason=plain-http",
        `surrogate_denied reason=surrogate-locked placeholder=${placeholder}`,
      ].join("\n"),
      "utf8",
    );
    const result = await run(
      ["surrogate", "events", "--agent-uid", String(AGENT_UID), "--agent", "hermes"],
      { effectiveUid: 0, gateLogPathOverride: logPath },
    );
    expect(result.code).toBe(0);
    expect(result.out).toContain("surrogate_swap_applied");
    expect(result.out).toContain("surrogate_denied");
    expect(result.out).not.toContain("gate_started");
    expect(result.out).not.toContain("gate_denied reason=plain-http");
    // A placeholder is a live bearer surrogate for its generation, so it never
    // reaches a terminal that is very often being recorded.
    expect(result.out).not.toContain(placeholder);
    expect(result.out).toContain(SURROGATE_PLACEHOLDER_REDACTION);
  });

  it("reports an absent gate log as no events rather than as an error", async () => {
    const result = await run(
      ["surrogate", "events", "--agent-uid", String(AGENT_UID), "--agent", "hermes"],
      { effectiveUid: 0, gateLogPathOverride: join(storagePath, "no-such.log") },
    );
    expect(result.code).toBe(0);
    expect(result.out).toContain("No gate log for this agent yet");
  });
});
