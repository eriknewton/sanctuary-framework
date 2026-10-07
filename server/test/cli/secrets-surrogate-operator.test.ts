/**
 * Capability: the operator verbs that address a running helper decide "armed"
 * from the helper's own answer, refuse on every outcome that is not a clean
 * absent socket with no installed helper artifact, and reach no keychain until
 * after they have refused. The verbs that remove a binding check the helper of
 * the binding's OWN agent (an operator-named uid can only confirm it) and record
 * a refusal on the chain. An unlock loads exactly one value per run, the chain
 * records a successful unlock only after the helper accepted it, and an outcome
 * the helper never answered is recorded as unknown with the commands that
 * settle it. The no-core re-exec passes argv only as positional parameters of a
 * fixed script and refuses an exec path or argv it cannot vouch for, and the
 * installed-helper scan matches its label prefix literally. Covers `surrogate remove`, `secrets revoke` on a bound name,
 * `unlock`'s no-core rule and its helper-first step order, `lock`, `status`
 * and the root-only `events`.
 *
 * Host-free: the unlock socket and the core-limit check are injected seams, the
 * keychain is an in-memory backend through the store's chokepoint, and the gate
 * log is a fixture file in a temp directory. No `security` subprocess runs, no
 * socket is created under a root-owned path, and no helper is started.
 *
 * Defect id: SURROGATE-BROKER-REACHABLE, SURROGATE-ARMED-UID,
 * SURROGATE-UNLOCK-PARTIAL, SURROGATE-UNLOCK-CHAIN-ORDER, SURROGATE-REEXEC-ARGV,
 * SURROGATE-PLIST-MATCH.
 */

import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventEmitter } from "node:events";
import { Writable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  runSecretsCommand,
  probeSurrogateBindingArmed,
  probeSurrogateHelperArmed,
  type SurrogateArmingView,
  SURROGATE_NO_CORE_SHELL_SCRIPT,
  createSurrogateNoCoreOps,
  parseSurrogateHelperPlistUid,
  surrogateReexecRefusal,
  type SurrogateNoCoreOps,
  type SurrogateUnlockOutcome,
  type SurrogateUnlockTransport,
} from "../../src/cli/secrets.js";
import type { Backend } from "../../src/disclosure/broker/backend-interface.js";
import { SecretNotFoundError } from "../../src/disclosure/broker/backend-interface.js";
import { openSurrogateStore, surrogatePolicyPath } from "../../src/disclosure/broker/open.js";
import { SURROGATE_POLICY_VERSION } from "../../src/disclosure/broker/policy.js";
import { SURROGATE_WIRE_VERSION } from "../../src/credential-surrogate/wire.js";
import { SURROGATE_HELPER_DAEMON_LABEL_PREFIX } from "../../src/egress-gate/surrogate-helper-daemon.js";
import { SURROGATE_PLACEHOLDER_REDACTION } from "../../src/credential-surrogate/redaction.js";
import { generateRandomKey } from "../../src/core/random.js";
import { BROKER_OPS } from "../../src/operational/audit-log.js";

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
/** A second uid with no helper socket: a mistyped or stale --agent-uid. */
const OTHER_UID = 777;
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

/**
 * The arming twin's installed state, injected. Defaults: the binding's agent
 * resolves to AGENT_UID, no helper plist is installed anywhere, and no
 * artifact exists for any uid.
 */
function armingView(opts: {
  agentUid?: number | undefined | "throws";
  installed?: number[];
  artifactsFor?: number[];
} = {}): SurrogateArmingView {
  return {
    async resolveAgentUid() {
      if (opts.agentUid === "throws") throw new Error("directory service unavailable");
      return "agentUid" in opts ? (opts.agentUid as number | undefined) : AGENT_UID;
    },
    async installedHelperUids() {
      return opts.installed ?? [];
    },
    async hasHelperArtifacts(uid) {
      return (opts.artifactsFor ?? []).includes(uid);
    },
  };
}

/** A transport that routes by uid; an unlisted uid has no socket (ENOENT). */
function perUidTransport(byUid: Record<number, SurrogateUnlockTransport>): SurrogateUnlockTransport {
  return {
    async send(uid, request) {
      const t = byUid[uid];
      return t === undefined ? { outcome: "absent" } : t.send(uid, request);
    },
  };
}

/** Every chain row for one broker operation, read back through the same store. */
async function chainRows(operation: string) {
  const { auditLog, close } = await openSurrogateStore({
    passphrase: PASSPHRASE,
    storagePath,
    backend: memoryBackend(),
  });
  try {
    return (await auditLog.query({ operation_type: operation, limit: 100 })).entries;
  } finally {
    await close();
  }
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
    // Defaults every verb can be refused or recorded under without touching a
    // real keychain or the real directory service; a test overrides either.
    surrogateArming: armingView(),
    surrogateBackend: memoryBackend(),
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
  it("an absent socket is unarmed at the transport only; with any artifact installed the binding is indeterminate", async () => {
    // The transport-level classification is unchanged: ENOENT means no socket.
    expect((await probeSurrogateHelperArmed(absentTransport(), AGENT_UID)).state).toBe("unarmed");
    // The BINDING-level decision is what the destructive verbs use, and there
    // an absent socket is unarmed only when no installed artifact remains.
    const withArtifacts = await probeSurrogateBindingArmed({
      transport: absentTransport(),
      arming: armingView({ artifactsFor: [AGENT_UID] }),
      secret: SECRET,
      agentId: "hermes",
    });
    expect(withArtifacts).toMatchObject({
      state: "indeterminate",
      refusal: "socket_absent_with_artifacts",
    });
    const clean = await probeSurrogateBindingArmed({
      transport: absentTransport(),
      arming: armingView(),
      secret: SECRET,
      agentId: "hermes",
    });
    expect(clean).toMatchObject({ state: "unarmed", agentUid: AGENT_UID });
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
    expect(result.err).toContain("is serving that binding now");
    expect(result.err).toContain(`surrogate lock --agent-uid ${AGENT_UID}`);
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

  it("succeeds on a socket ENOENT with no installed artifact, dropping the row and the stored value", async () => {
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

  it("derives the uid from the binding's own agent when --agent-uid is omitted", async () => {
    await writePolicy([BINDING]);
    const asked: number[] = [];
    const result = await run(["surrogate", "remove", SECRET], {
      surrogateUnlock: {
        async send(uid: number) {
          asked.push(uid);
          return { outcome: "absent" } as SurrogateUnlockOutcome;
        },
      },
      surrogateBackend: memoryBackend({ [SECRET]: BOUND_VALUE }),
    });
    expect(result.code).toBe(0);
    expect(asked).toEqual([AGENT_UID]);
  });

  it("refuses a malformed --agent-uid rather than ignoring it", async () => {
    await writePolicy([BINDING]);
    const result = await run(["surrogate", "remove", SECRET, "--agent-uid", "abc"], {
      surrogateUnlock: absentTransport(),
    });
    expect(result.code).toBe(2);
    expect(result.err).toContain("--agent-uid must be a positive integer");
  });
});

// ---------------------------------------------------------------------------
// The binding's own agent decides which helper is checked.
// ---------------------------------------------------------------------------

describe("remove and revoke probe the binding's own agent, never only the operator's uid", () => {
  /** uid A (AGENT_UID) is armed and serving SECRET; every other uid is absent. */
  function armedOnAgentUid(): SurrogateUnlockTransport {
    return perUidTransport({ [AGENT_UID]: armedTransport() });
  }

  it.each([
    ["surrogate remove", ["surrogate", "remove", SECRET, "--agent-uid", String(OTHER_UID)]],
    ["revoke", ["revoke", "mailer", SECRET, "--agent-uid", String(OTHER_UID)]],
  ] as const)(
    "%s refuses when --agent-uid names a uid with no socket while the real agent is armed",
    async (verb, argv) => {
      await writePolicy([BINDING]);
      const backend = memoryBackend({ [SECRET]: BOUND_VALUE });
      const result = await run([...argv], {
        surrogateUnlock: armedOnAgentUid(),
        surrogateBackend: backend,
        brokerBackend: memoryBackend(),
      });
      expect(result.code).toBe(1);
      expect(result.err).toContain("does not match");
      const after = JSON.parse(await readFile(surrogatePolicyPath(storagePath), "utf8"));
      expect(after.bindings).toHaveLength(1);
      expect(await backend.listSecretNames()).toContain(SECRET);
      const rows = await chainRows(BROKER_OPS.SURROGATE_REMOVED);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        result: "failure",
        details: { secret: SECRET, verb, outcome: "refused", reason: "agent_uid_mismatch" },
      });
    },
  );

  it.each([
    ["surrogate remove", ["surrogate", "remove", SECRET]],
    ["revoke", ["revoke", "mailer", SECRET]],
  ] as const)(
    "%s with no flag refuses when the real agent's helper is serving the secret",
    async (verb, argv) => {
      await writePolicy([BINDING]);
      const backend = memoryBackend({ [SECRET]: BOUND_VALUE });
      const result = await run([...argv], {
        surrogateUnlock: armedOnAgentUid(),
        surrogateBackend: backend,
        brokerBackend: memoryBackend(),
      });
      expect(result.code).toBe(1);
      expect(result.err).toContain("is serving that binding now");
      const after = JSON.parse(await readFile(surrogatePolicyPath(storagePath), "utf8"));
      expect(after.bindings).toHaveLength(1);
      expect(await backend.listSecretNames()).toContain(SECRET);
      const rows = await chainRows(BROKER_OPS.SURROGATE_REMOVED);
      expect(rows[0]).toMatchObject({
        result: "failure",
        details: { verb, outcome: "refused", reason: "armed", agent_uid: AGENT_UID },
      });
    },
  );

  it("refuses when the account no longer resolves but an installed helper serves the secret", async () => {
    // An account rename breaks the id-to-uid lookup without stopping the
    // helper armed under the old uid; its own status table still decides.
    await writePolicy([BINDING]);
    const result = await run(["surrogate", "remove", SECRET], {
      surrogateUnlock: armedOnAgentUid(),
      surrogateArming: armingView({ agentUid: undefined, installed: [AGENT_UID] }),
      surrogateBackend: memoryBackend({ [SECRET]: BOUND_VALUE }),
    });
    expect(result.code).toBe(1);
    expect(result.err).toContain("is serving that binding now");
  });

  it("refuses when the socket is absent but the helper's artifacts are installed", async () => {
    await writePolicy([BINDING]);
    const result = await run(["surrogate", "remove", SECRET], {
      surrogateUnlock: absentTransport(),
      surrogateArming: armingView({ artifactsFor: [AGENT_UID] }),
      surrogateBackend: memoryBackend({ [SECRET]: BOUND_VALUE }),
    });
    expect(result.code).toBe(1);
    expect(result.err).toContain("socket_absent_with_artifacts");
    const after = JSON.parse(await readFile(surrogatePolicyPath(storagePath), "utf8"));
    expect(after.bindings).toHaveLength(1);
  });

  it("refuses when the directory service cannot answer", async () => {
    await writePolicy([BINDING]);
    const result = await run(["surrogate", "remove", SECRET], {
      surrogateUnlock: absentTransport(),
      surrogateArming: armingView({ agentUid: "throws" }),
    });
    expect(result.code).toBe(1);
    expect(result.err).toContain("account_lookup_failed");
  });

  it("proceeds when the agent's helper answers but does not hold this secret", async () => {
    await writePolicy([BINDING]);
    const other: SurrogateUnlockTransport = {
      async send(_uid, request) {
        return statusOutcome([{ secret: "some-other-secret", unlocked: true, expires_at: 1 }])(
          request.id,
        );
      },
    };
    const result = await run(["surrogate", "remove", SECRET, "--agent-uid", String(AGENT_UID)], {
      surrogateUnlock: other,
      surrogateBackend: memoryBackend({ [SECRET]: BOUND_VALUE }),
    });
    expect(result.code).toBe(0);
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
    expect(result.err).toContain("is serving that binding now");
    const after = JSON.parse(await readFile(surrogatePolicyPath(storagePath), "utf8"));
    expect(after.bindings).toHaveLength(1);
  });

  it("removes the binding row on ENOENT with no installed artifact and keeps the stored value", async () => {
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
    const result = await run(["surrogate", "unlock", SECRET, "--agent-uid", String(AGENT_UID)], {
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
    const result = await run(["surrogate", "unlock", SECRET, "--agent-uid", String(AGENT_UID)], {
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
    const result = await run(["surrogate", "unlock", SECRET, "--agent-uid", String(AGENT_UID)], {
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
    const result = await run(["surrogate", "unlock", SECRET, "--agent-uid", String(AGENT_UID)], {
      surrogateNoCore: noCoreOps("0"),
      surrogateUnlock: fixedTransport({ outcome: "unreachable", failureClass: "permission_denied" }),
      surrogateBackend: memoryBackend({ [SECRET]: BOUND_VALUE }),
    });
    expect(result.code).toBe(1);
    expect(result.err).toContain("permission_denied");
    expect(keychainReads).toHaveLength(0);
  });

  it("sends the one named value when the helper serves it", async () => {
    await writePolicy([BINDING]);
    const transport = armedTransport();
    const result = await run(
      ["surrogate", "unlock", SECRET, "--agent-uid", String(AGENT_UID), "--ttl", "120"],
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
    expect(result.out).toContain(`Unlocked "${SECRET}"`);
    expect(result.out).not.toContain(BOUND_VALUE);
  });

  it("refuses a non-integer --ttl rather than sending an unbounded request", async () => {
    await writePolicy([BINDING]);
    const result = await run(
      ["surrogate", "unlock", SECRET, "--agent-uid", String(AGENT_UID), "--ttl", "forever"],
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
// The no-core re-exec: argv are positional parameters, and bad input refuses.
// ---------------------------------------------------------------------------

/** A spawn stand-in that records its call and exits 0 on the next tick. */
function recordingSpawn() {
  const calls: { file: string; args: string[] }[] = [];
  const spawn = ((file: string, args: string[]) => {
    calls.push({ file, args });
    const child = new EventEmitter();
    setImmediate(() => child.emit("exit", 0));
    return child;
  }) as unknown as typeof import("node:child_process").spawn;
  return { calls, spawn };
}

describe("the no-core re-exec validates what it hands the shell", () => {
  it("passes argv only as positional parameters after the fixed script", async () => {
    const rec = recordingSpawn();
    const ops = createSurrogateNoCoreOps({
      execPath: process.execPath,
      argv: [process.execPath, "cli.js", "secrets", "surrogate", "unlock", "k; echo x"],
      spawn: rec.spawn,
    });
    expect(await ops.reexecWithoutCore()).toBe(0);
    expect(rec.calls).toEqual([
      {
        file: "/bin/sh",
        args: [
          "-c",
          SURROGATE_NO_CORE_SHELL_SCRIPT,
          "sh",
          process.execPath,
          "cli.js",
          "secrets",
          "surrogate",
          "unlock",
          "k; echo x",
        ],
      },
    ]);
  });

  it("refuses, with exit 1 and no spawn, an argv element carrying a newline", async () => {
    const rec = recordingSpawn();
    const ops = createSurrogateNoCoreOps({
      execPath: process.execPath,
      argv: [process.execPath, "cli.js", "unlock\nk"],
      spawn: rec.spawn,
    });
    expect(await ops.reexecWithoutCore()).toBe(1);
    expect(rec.calls).toHaveLength(0);
  });

  it("refuses, with exit 1 and no spawn, a relative exec path", async () => {
    const rec = recordingSpawn();
    const ops = createSurrogateNoCoreOps({ execPath: "node", argv: ["node", "cli.js"], spawn: rec.spawn });
    expect(await ops.reexecWithoutCore()).toBe(1);
    expect(rec.calls).toHaveLength(0);
  });

  it("names each refusal class", () => {
    expect(surrogateReexecRefusal(process.execPath, ["a", "b"])).toBeNull();
    expect(surrogateReexecRefusal("node", [])).toBe("exec_path_not_absolute");
    expect(surrogateReexecRefusal(join(storagePath, "no-such-binary"), [])).toBe("exec_path_missing");
    expect(surrogateReexecRefusal(storagePath, [])).toBe("exec_path_not_a_file");
    expect(surrogateReexecRefusal(process.execPath, ["a\0b"])).toBe("argv_element_rejected");
    expect(surrogateReexecRefusal(process.execPath, ["a\nb"])).toBe("argv_element_rejected");
  });
});

describe("the installed-helper scan matches its label prefix literally", () => {
  it("reads the uid from a helper plist name and nothing else", () => {
    const prefix = SURROGATE_HELPER_DAEMON_LABEL_PREFIX;
    expect(parseSurrogateHelperPlistUid(`${prefix}.502.plist`)).toBe(502);
    expect(parseSurrogateHelperPlistUid(`${prefix}.502.plist.bak`)).toBeUndefined();
    expect(parseSurrogateHelperPlistUid(`${prefix}.5a2.plist`)).toBeUndefined();
    expect(parseSurrogateHelperPlistUid(`${prefix}..plist`)).toBeUndefined();
    expect(parseSurrogateHelperPlistUid(`x${prefix}.502.plist`)).toBeUndefined();
  });

  it("a prefix containing a regex metacharacter cannot match a different label", () => {
    // `+` and `.` would both widen a regex built from the prefix.
    expect(parseSurrogateHelperPlistUid("a+b.5.plist", "a+b")).toBe(5);
    expect(parseSurrogateHelperPlistUid("aab.5.plist", "a+b")).toBeUndefined();
    expect(parseSurrogateHelperPlistUid("a.b.5.plist", "a.b")).toBe(5);
    expect(parseSurrogateHelperPlistUid("aXb.5.plist", "a.b")).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// unlock: one value per run; the chain row follows the helper's answer.
// ---------------------------------------------------------------------------

/**
 * A helper that serves SECRET and answers the one unlock with `answer`.
 * Records every request kind in order, and how many success rows the chain
 * held at the moment the unlock frame was sent.
 */
function oneBindingTransport(
  answer: (id: string) => SurrogateUnlockOutcome,
): SurrogateUnlockTransport & { kinds: string[]; successRowsAtSend: number[] } {
  const kinds: string[] = [];
  const successRowsAtSend: number[] = [];
  return {
    kinds,
    successRowsAtSend,
    async send(_uid, request) {
      kinds.push(request.kind);
      if (request.kind === "status") {
        return statusOutcome([{ secret: SECRET, unlocked: false, expires_at: null }])(request.id);
      }
      if (request.kind === "unlock") {
        successRowsAtSend.push(
          (await chainRows(BROKER_OPS.SURROGATE_UNLOCKED)).filter((r) => r.result === "success")
            .length,
        );
        return answer(request.id);
      }
      return {
        outcome: "answered",
        response: { v: SURROGATE_WIRE_VERSION, id: request.id, kind: "ok" },
      };
    },
  };
}

function okOutcome(id: string): SurrogateUnlockOutcome {
  return { outcome: "answered", response: { v: SURROGATE_WIRE_VERSION, id, kind: "ok" } };
}

function denyOutcome(reason: "unknown_secret" | "malformed") {
  return (id: string): SurrogateUnlockOutcome => ({
    outcome: "answered",
    response: { v: SURROGATE_WIRE_VERSION, id, kind: "deny", reason },
  });
}

describe("surrogate unlock loads one value and records the helper's answer", () => {
  const unlockArgv = ["surrogate", "unlock", SECRET, "--agent-uid", String(AGENT_UID)];
  const seeded = () => memoryBackend({ [SECRET]: BOUND_VALUE });

  it("writes the success row only after the helper's ok", async () => {
    await writePolicy([BINDING]);
    const transport = oneBindingTransport(okOutcome);
    const result = await run(unlockArgv, {
      surrogateNoCore: noCoreOps("0"),
      surrogateUnlock: transport,
      surrogateBackend: seeded(),
    });
    expect(result.code).toBe(0);
    // At the moment the unlock frame left, the chain held NO success row.
    expect(transport.successRowsAtSend).toEqual([0]);
    expect(transport.kinds).toEqual(["status", "unlock"]);
    const rows = await chainRows(BROKER_OPS.SURROGATE_UNLOCKED);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      result: "success",
      details: { agent_uid: AGENT_UID, generation_id: 7, secret: SECRET },
    });
    expect(JSON.stringify(rows[0])).not.toContain(BOUND_VALUE);
  });

  it("records a refusal on deny and sends no lock, because the helper stored nothing", async () => {
    await writePolicy([BINDING]);
    const transport = oneBindingTransport(denyOutcome("unknown_secret"));
    const result = await run(unlockArgv, {
      surrogateNoCore: noCoreOps("0"),
      surrogateUnlock: transport,
      surrogateBackend: seeded(),
    });
    expect(result.code).toBe(1);
    expect(transport.kinds).not.toContain("lock");
    expect(result.err).toContain("Nothing was stored");
    const rows = await chainRows(BROKER_OPS.SURROGATE_UNLOCKED);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      result: "failure",
      details: { secret: SECRET, outcome: "refused", reason: "unknown_secret" },
    });
  });

  it("records an unknown outcome on a timeout and names the status and lock commands", async () => {
    await writePolicy([BINDING]);
    const transport = oneBindingTransport(() => ({
      outcome: "unreachable",
      failureClass: "timed_out",
    }));
    const result = await run(unlockArgv, {
      surrogateNoCore: noCoreOps("0"),
      surrogateUnlock: transport,
      surrogateBackend: seeded(),
    });
    expect(result.code).toBe(1);
    expect(transport.kinds).not.toContain("lock");
    expect(result.err).toContain(`sanctuary secrets surrogate status --agent-uid ${AGENT_UID}`);
    expect(result.err).toContain(`sanctuary secrets surrogate lock --agent-uid ${AGENT_UID}`);
    const rows = await chainRows(BROKER_OPS.SURROGATE_UNLOCKED);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      result: "failure",
      details: { secret: SECRET, outcome: "unknown", reason: "timed_out" },
    });
    expect(rows.filter((r) => r.result === "success")).toHaveLength(0);
  });

  it("refuses a name the helper does not serve before any keychain read", async () => {
    await writePolicy([BINDING]);
    const transport = oneBindingTransport(okOutcome);
    const result = await run(
      ["surrogate", "unlock", "not-a-served-secret", "--agent-uid", String(AGENT_UID)],
      { surrogateNoCore: noCoreOps("0"), surrogateUnlock: transport, surrogateBackend: seeded() },
    );
    expect(result.code).toBe(1);
    expect(result.err).toContain("does not serve");
    expect(transport.kinds).not.toContain("unlock");
    expect(keychainReads).toHaveLength(0);
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
    const logPath = join(storagePath, "egress-gate-502.err.log");
    const placeholder = `sanctuary_surrogate_${"a1b2c3d4".repeat(4)}`;
    await writeFile(
      logPath,
      [
        "gate_started uid=502",
        `[egress-gate] ${JSON.stringify({ kind: "surrogate_swap", authority: placeholder })}`,
        "gate_denied reason=plain-http",
        `[egress-gate] ${JSON.stringify({ kind: "surrogate_denied", authority: placeholder })}`,
        '[egress-gate] {"kind":"other","reason":"surrogate_in_unrelated_event"}',
        '[egress-gate] malformed surrogate_line',
        'untrusted {"kind":"surrogate_wrong_prefix"}',
        '[egress-gate] {"kind":4}',
        '[egress-gate] null',
        '[egress-gate] ["surrogate_array"]',
      ].join("\n"),
      "utf8",
    );
    const result = await run(
      ["surrogate", "events", "--agent-uid", String(AGENT_UID), "--agent", "hermes"],
      { effectiveUid: 0, gateLogPathOverride: logPath },
    );
    expect(result.code).toBe(0);
    expect(result.out).toContain("surrogate_swap");
    expect(result.out).not.toContain("surrogate_in_unrelated_event");
    expect(result.out).not.toContain("surrogate_line");
    expect(result.out).not.toContain("surrogate_wrong_prefix");
    expect(result.out).not.toContain("surrogate_array");
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
