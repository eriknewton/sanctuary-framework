import { describe, expect, it, vi } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable, Writable } from "node:stream";
import * as locks from "../../src/storage/cross-process-lock.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { establishMaster, CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME } from "../../src/core/master-custody.js";
import { createIdentity } from "../../src/core/identity.js";
import { deriveMasterKey, derivePurposeKey } from "../../src/core/key-derivation.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { hashToString } from "../../src/core/hashing.js";
import { unlockLocalFortress } from "../../src/cli/local-fortress-unlock.js";
import { persistStoredIdentity } from "../util/persist-stored-identity.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { runExitCommand } from "../../src/exit/cli.js";
import { runAuditCommand } from "../../src/cli/audit.js";
import { runIdentityCommand } from "../../src/cli/identity.js";
import { runCheckpointCommand } from "../../src/cli/checkpoint.js";
import { runFileGrantCommand } from "../../src/cli/file-grant.js";
import { runObserveCommand } from "../../src/cli/castle-wall-observe.js";
import { runDidWebCommand } from "../../src/cli/did-web.js";
import { runErc8004Command } from "../../src/cli/erc8004.js";
import { runConciergeCommand } from "../../src/cli/concierge.js";
import { runAutoTriggerCommand } from "../../src/cli/auto-trigger.js";
import { runAnomalyCommand } from "../../src/cli/anomaly.js";
import { runSentinelCommand } from "../../src/cli/sentinel.js";
import { runTemplateCommand } from "../../src/templates/cli.js";
import { runPolicyCommand } from "../../src/cli/policy.js";
import { openIssuer, openVerifier } from "../../src/cli/custody-unlock.js";
import { openOperatorSigner } from "../../src/cli/federation-operator-signing.js";
import { openBroker, openSurrogateStore } from "../../src/disclosure/broker/open.js";
import type { Backend } from "../../src/disclosure/broker/backend-interface.js";
import { SubstrateSelector } from "../../src/intelligence/selector.js";
import { ConciergeReadError, ConciergeService } from "../../src/concierge/index.js";

import * as custody from "../../src/core/master-custody.js";
import { runSecretsCommand } from "../../src/cli/secrets.js";
import { runLicenseCommand } from "../../src/cli/license.js";
import { runFleetCommand } from "../../src/cli/fleet.js";
import { runTransparencyCommand } from "../../src/cli/transparency.js";
import { runDistressCommand } from "../../src/cli/distress.js";
import { runCortexExportCommand } from "../../src/cli/cortex-export.js";
import { runSdwOwnerCommand } from "../../src/cli/sdw-owner.js";
import { runFederationEnableDisable, runFederationProvision } from "../../src/cli/federation.js";
import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "../../src/core/random.js";
import { encrypt } from "../../src/core/encryption.js";
import { SURROGATE_BOUND_PORT } from "../../src/credential-surrogate/binding.js";
import { SURROGATE_POLICY_VERSION } from "../../src/disclosure/broker/policy.js";
import { EXIT_IMPORT_JOURNAL_NAMESPACE } from "../../src/storage/exit-import-journal.js";

import { runDoctorChecks } from "../../src/cli/doctor.js";
import { runMemoryIngestCommand, runMemoryEmitCommand, runMemoryTranscodeCommand, runMemoryTranscodeRestoreCommand } from "../../src/cli/memory-file.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import * as isolation from "../../src/sdw/memory-isolation.js";
import * as brokerOpen from "../../src/disclosure/broker/open.js";
import { SURROGATE_WIRE_VERSION } from "../../src/credential-surrogate/wire.js";

const passphrase = "consumer-session-fixture-passphrase";
const supported = locks.kernelBackedCrossProcessLockPlatformSupported(process.platform);
class Capture extends Writable {
  text = "";
  override _write(chunk: unknown, _encoding: BufferEncoding, done: () => void) { this.text += String(chunk); done(); }
}
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}
type Fixture = {
  root: string; out: Capture; err: Capture; env: NodeJS.ProcessEnv;
  leases: locks.MasterWriteBarrierLease[];
  exclusive: () => Promise<string>;
  args: (argv: string[]) => { argv: string[]; env: NodeJS.ProcessEnv; out: Capture; err: Capture; storagePath: string; passphrase: string };
};
async function fixture(identity: boolean, test: (fixture: Fixture) => Promise<void>, releaseError?: Error, legacy = false) {
  const root = await mkdtemp(join(tmpdir(), "consumer-session-"));
  const leases: locks.MasterWriteBarrierLease[] = [];
  const out = new Capture();
  const err = new Capture();
  try {
    vi.stubEnv("HOME", root);
    vi.stubEnv("SANCTUARY_CUSTODY_LOCK_ROOT", join(root, "locks"));
    vi.stubEnv("SANCTUARY_STORAGE_PATH", root);
    vi.stubEnv("SANCTUARY_PASSPHRASE", passphrase);
    vi.stubEnv("SANCTUARY_DASHBOARD_URL", "");
    const storage = new FilesystemStorage(join(root, "state"));
    const seed = legacy ? await (async () => {
      const { key, params } = await deriveMasterKey(passphrase);
      try {
        await storage.write("_meta", "key-params", stringToBytes(JSON.stringify(params)));
        await storage.write("_meta", "recovery-key-hash", stringToBytes(hashToString(key)));
        return { masterKey: key, masterWriteBarrier: undefined };
      } catch (error) { key.fill(0); throw error; }
    })() : await establishMaster({ storage, passphrase, firstRun: { installMode: "headless", mintRecoveryKey: false } });
    try {
      const privateKey = randomBytes(32); // Ed25519 seeds contain 32 bytes.
      try {
        await writeFile(join(root, "castle-pinned-pubkey.bin"), ed25519.getPublicKey(privateKey));
        await writeFile(join(root, "castle-pinned-privkey.enc"), JSON.stringify(encrypt(privateKey, seed.masterKey)));
      } finally { privateKey.fill(0); }
      if (identity) {
        const key = derivePurposeKey(seed.masterKey, "identity-encryption");
        try {
          const { storedIdentity } = createIdentity("session-fixture", key, "passphrase");
          await persistStoredIdentity(storage, seed.masterKey, storedIdentity);
          await storage.write("_meta", "primary_identity_id", stringToBytes(JSON.stringify(storedIdentity.identity_id)));
        } finally { key.fill(0); }
      }
    } finally {
      await seed.masterWriteBarrier?.release();
      seed.masterKey.fill(0);
    }
    const acquire = locks.acquireMasterWriteBarrier;
    vi.spyOn(locks, "acquireMasterWriteBarrier").mockImplementation(async (...args) => {
      const lease = await acquire(...args);
      leases.push(lease);
      if (!releaseError) return lease;
      return { ...lease, release: async () => { await lease.release(); throw releaseError; } };
    });
    const env = { SANCTUARY_PASSPHRASE: passphrase, SANCTUARY_STORAGE_PATH: root };
    const exclusive = () => locks.withExclusiveMasterRotationBarrier(
      new FilesystemStorage(join(root, "state")), CUSTODY_WRITE_LOCK_NAMESPACE,
      MASTER_ROTATION_BARRIER_NAME, async () => "entered", { timeoutMs: 0 },
    );
    await test({ root, out, err, env, leases, exclusive, args: (argv) => ({ argv, env, out, err, storagePath: root, passphrase }) });
  } finally {
    vi.restoreAllMocks();
    try { for (const lease of leases) await lease.release(); }
    finally {
      vi.unstubAllEnvs();
      vi.unstubAllGlobals();
      out.destroy();
      err.destroy();
      await rm(root, { recursive: true, force: true });
    }
  }
}
async function released(f: Fixture) {
  expect(f.leases.length).toBeGreaterThan(0);
  for (const lease of f.leases) expect(lease.signal.aborted).toBe(true);
  await expect(f.exclusive()).resolves.toBe("entered");
}
const commands = [
  { name: "audit search", run: runAuditCommand, argv: ["search"], identity: true, code: 0 },
  { name: "identity show refusal", run: runIdentityCommand, argv: ["show"], identity: false, code: 1 },
  { name: "identity show", run: runIdentityCommand, argv: ["show"], identity: true, code: 0 },
  { name: "checkpoint refusal", run: runCheckpointCommand, argv: ["list"], identity: false, code: 1 },
  { name: "checkpoint list", run: runCheckpointCommand, argv: ["list"], identity: true, code: 0 },
  { name: "file grant refusal", run: runFileGrantCommand, argv: ["list"], identity: false, code: 1 },
  { name: "file grant list", run: runFileGrantCommand, argv: ["list"], identity: true, code: 0 },
  { name: "observe refusal", run: runObserveCommand, argv: ["status"], identity: false, code: 1 },
  { name: "observe status", run: runObserveCommand, argv: ["status"], identity: true, code: 0 },
  { name: "did web refusal", run: runDidWebCommand, argv: ["issue", "--authority-host", "fixture.example"], identity: false, code: 1 },
  { name: "erc8004 refusal", run: runErc8004Command, argv: ["register", "--registry", "0x0000000000000000000000000000000000000001", "--chain", "1", "--agent-id", "fixture", "--nonce", "0"], identity: false, code: 1 },
  { name: "concierge refusal", run: runConciergeCommand, argv: ["status"], identity: false, code: 1 },
  { name: "threshold store", run: runAutoTriggerCommand, argv: ["rules", "list"], identity: true, code: 0 },
  { name: "calibration context", run: runAutoTriggerCommand, argv: ["recommendations", "list"], identity: true, code: 0 },
  { name: "anomaly findings", run: runAnomalyCommand, argv: ["findings"], identity: true, code: 0 },
  { name: "sentinel findings", run: runSentinelCommand, argv: ["findings"], identity: true, code: 0 },
];

describe.skipIf(!supported)("CLI consuming finalization", () => {
  it.each(commands)("$name releases its session after final work", async ({ name, run, argv, identity, code }) => {
    await fixture(identity, async (f) => {
      expect(await run(f.args(argv)).catch((error: unknown) => {
        if (name === "concierge refusal" && error instanceof ConciergeReadError) return 1;
        throw error;
      })).toBe(code);
      await released(f);
    });
  });

  it.each([
    { name: "license issue", run: (f: Fixture) => runLicenseCommand(f.args(["issue", "--tier", "fleet", "--subject", "fixture", "--nodes", "1", "--expires", "2099-01-01T00:00:00Z"])) },
    { name: "fleet export", run: (f: Fixture) => runFleetCommand({ ...f.args(["attest", "export"]), fetchPosture: async () => null }) },
    { name: "transparency checkpoint", run: async (f: Fixture) => {
      const binary = join(f.root, "binary");
      await writeFile(binary, "fixture binary");
      const rules = join(f.root, "policy", "egress", "rules");
      await mkdir(rules, { recursive: true });
      await writeFile(join(rules, "fixture.json"), JSON.stringify({ rule_id: "fixture" }));
      return runTransparencyCommand(f.args(["checkpoint", "--local-sign", "--binary", binary]));
    } },
    { name: "policy compile", run: async (f: Fixture) => {
      await mkdir(join(f.root, "state", "_intelligence"), { recursive: true });
      return runPolicyCommand(f.args(["compile", "always require approval for state_export"]));
    } },
    { name: "distress", run: (f: Fixture) => runDistressCommand(f.args(["send", "--reason", "policy_constraint", "--severity", "urgent"])) },
    { name: "cortex export", run: (f: Fixture) => runCortexExportCommand(f.args(["run"])) },
    { name: "sdw owner", run: (f: Fixture) => runSdwOwnerCommand({ ...f.args(["claim", "--agent-id", "codex:fixture", "--fortress", f.root]), stdin: Readable.from("codex:fixture\nCLAIM\n") }) },
    { name: "exit recover only", run: async (f: Fixture) => {
      await mkdir(join(f.root, "state", EXIT_IMPORT_JOURNAL_NAMESPACE), { recursive: true });
      return runExitCommand(f.args(["recover", "--fortress", f.root]));
    } },
    { name: "federation admin signer", run: (f: Fixture) => runFederationEnableDisable({ ...f.args(["--fortress", f.root, "--fortress-url", "http://fixture.invalid", "--auth-token", "fixture-token"]), enable: true, request: async () => ({ enabled: true }) }) },
    { name: "federation operator signer", run: (f: Fixture) => runFederationProvision(f.args(["--fortress", f.root, "--node-id", "fixture-node", "--classical"])) },
  ])("$name success releases custody before returning", async ({ run }) => {
    await fixture(true, async (f) => {
      expect(await run(f), f.err.text).toBe(0);
      await released(f);
    });
  });

  it.each(["start", "status", "candidates", "promote", "discard"].flatMap((verb) =>
    ["flush", "release"].map((failure) => ({ verb, failure })),
  ))("observe $verb preserves best-effort flush semantics on $failure failure", async ({ verb, failure }) => {
    const releaseError = failure === "release" ? new Error("release rejected") : undefined;
    await fixture(true, async (f) => {
      const flush = AuditLog.prototype.flush;
      const outputAtFlush: string[] = [];
      const finalFlush = vi.spyOn(AuditLog.prototype, "flush").mockImplementation(async function (this: AuditLog) {
        outputAtFlush.push(f.out.text);
        if (failure === "flush") throw new Error("flush rejected");
        return flush.call(this);
      });
      const operation = runObserveCommand(f.args([verb, "--all"]));
      if (releaseError) await expect(operation).rejects.toBe(releaseError);
      else await expect(operation).resolves.toBe(0);
      expect(f.out.text).not.toBe("");
      expect(finalFlush).toHaveBeenCalled();
      expect(outputAtFlush).toContain(f.out.text);
      await released(f);
    }, releaseError);
  });

  it("exit export keeps success when the final best-effort flush rejects", async () => {
    await fixture(true, async (f) => {
      const flush = AuditLog.prototype.flush;
      const finalFlush = vi.spyOn(AuditLog.prototype, "flush").mockImplementation(async function (this: AuditLog) {
        if (f.out.text.includes("exported:")) throw new Error("final export flush rejected");
        return flush.call(this);
      });
      expect(await runExitCommand(f.args(["export", "--out", join(f.root, "bundle"), "--yes"])), f.err.text).toBe(0);
      expect(f.out.text).toContain("exported:");
      expect(finalFlush).toHaveBeenCalled();
      await released(f);
      const acquire = vi.mocked(locks.acquireMasterWriteBarrier).getMockImplementation()!;
      vi.spyOn(locks, "acquireMasterWriteBarrier").mockImplementation(async (...args) => {
        const lease = await acquire(...args);
        return { ...lease, release: async () => { await lease.release(); throw new Error("export release rejected"); } };
      });
      f.out.text = "";
      expect(await runExitCommand(f.args(["export", "--out", join(f.root, "second-bundle"), "--yes"]))).toBe(1);
      expect(f.out.text).toContain("exported:");
      expect(f.err.text).toContain("export release rejected");
      await released(f);
    });
  });

  const legacyFailures = [
    {
      failure: "other",
      env: { SANCTUARY_PASSPHRASE: "wrong-passphrase" },
      message: "legacy fortress custody could not be migrated; no credential or secret detail was emitted",
    },
    {
      failure: "mismatch",
      // A recovery key is 256 bits, encoded as base64url; the all-zero key is not the fixture master.
      env: { SANCTUARY_RECOVERY_KEY: toBase64url(new Uint8Array(32)) },
      message: "Sanctuary: recovery key does not match the stored key hash.\n"
        + "The recovery key provided via SANCTUARY_RECOVERY_KEY is incorrect.\n"
        + "Use the exact recovery key that was displayed at first run.",
    },
  ];

  it.each(legacyFailures)("legacy migration propagates establishment release failure after $failure refusal", async ({ env }) => {
    const releaseError = new Error("legacy establishment release rejected");
    await fixture(true, async (f) => {
      const storage = new FilesystemStorage(join(f.root, "state"));
      expect(await storage.read("_meta", "custody-envelope")).toBeNull();
      const operation = unlockLocalFortress({ storage, storagePath: f.root, env });
      await expect(operation).rejects.toBeInstanceOf(custody.MasterEstablishmentReleaseError);
      await expect(operation).rejects.toMatchObject({ errors: expect.arrayContaining([releaseError]), cause: releaseError });
      expect(await storage.read("_meta", "custody-envelope")).toBeNull();
      await released(f);
    }, releaseError, true);
  });

  it.each(legacyFailures)("legacy migration preserves plain $failure refusal and text when release succeeds", async ({ failure, env, message }) => {
    await fixture(true, async (f) => {
      const storage = new FilesystemStorage(join(f.root, "state"));
      expect(await storage.read("_meta", "custody-envelope")).toBeNull();
      expect(await unlockLocalFortress({ storage, storagePath: f.root, env })).toEqual({ ok: false, failure, message });
      expect(await storage.read("_meta", "custody-envelope")).toBeNull();
      await released(f);
    }, undefined, true);
  });

  it("doctor propagates establishment release failure instead of continuing without a key", async () => {
    const releaseError = new Error("establishment release rejected");
    await fixture(true, async (f) => {
      await expect(runDoctorChecks({ storagePath: f.root, platform: process.platform,
        env: { ...f.env, SANCTUARY_PASSPHRASE: "wrong-passphrase" },
      })).rejects.toMatchObject({ errors: expect.arrayContaining([releaseError]) });
      await released(f);
    }, releaseError);
  });

  it("transparency propagates establishment release failure instead of continuing without a key", async () => {
    await fixture(true, async (f) => {
      const binary = join(f.root, "binary");
      const bundle = join(f.root, "checkpoints.json");
      await writeFile(binary, "fixture binary");
      const rules = join(f.root, "policy", "egress", "rules");
      await mkdir(rules, { recursive: true });
      await writeFile(join(rules, "fixture.json"), JSON.stringify({ rule_id: "fixture" }));
      expect(await runTransparencyCommand(f.args(["checkpoint", "--local-sign", "--binary", binary]))).toBe(0);
      expect(await runTransparencyCommand(f.args(["export", "--output", bundle]))).toBe(0);
      const acquire = vi.mocked(locks.acquireMasterWriteBarrier).getMockImplementation()!;
      vi.spyOn(locks, "acquireMasterWriteBarrier").mockImplementation(async (...args) => {
        const lease = await acquire(...args);
        return { ...lease, release: async () => { await lease.release(); throw new Error("establishment release rejected"); } };
      });
      expect(await runTransparencyCommand({ ...f.args(["verify", "--input", bundle, "--against-log", "--public-key-file", join(f.root, "castle-pinned-pubkey.bin"), "--passphrase", "wrong-passphrase"]) })).toBe(1);
      expect(f.err.text).toContain("master establishment");
      await released(f);
    });
  });

  const memoryVerbs = [
    { name: "ingest", run: runMemoryIngestCommand, argv: ["--harness", "claude-code"] },
    { name: "emit", run: runMemoryEmitCommand, argv: ["--harness", "claude-code"] },
    { name: "transcode", run: runMemoryTranscodeCommand, argv: ["--from-harness", "claude-code", "--to-harness", "codex", "--mode", "reversible"] },
    { name: "restore", run: runMemoryTranscodeRestoreCommand, argv: ["--archive-id", "a".repeat(32)] }, // Archive identifiers encode 16 bytes as 32 hex characters.
  ];
  it.each(memoryVerbs.flatMap((verb) => ["refusal", "operation", "flush"].map((failure) => ({ ...verb, failure }))))(
    "memory $name retains $failure outcome when release fails", async ({ run, argv, failure }) => {
      const releaseError = new Error("memory release rejected");
      const operationError = new Error("memory operation rejected");
      await fixture(true, async (f) => {
        if (failure === "operation") vi.spyOn(isolation, "precheckSdwOwnerPin").mockRejectedValue(operationError);
        else vi.spyOn(isolation, "precheckSdwOwnerPin").mockResolvedValue({ status: "refuse", reason: "owner_scope_conflict" });
        const flushing = deferred();
        const finish = deferred();
        if (failure === "flush") vi.spyOn(AuditLog.prototype, "flush").mockImplementation(async () => {
          flushing.resolve();
          await finish.promise;
          throw operationError;
        });
        const operation = run({ ...f.args([...argv, "--dir", join(f.root, "memory"), "--fortress", f.root]),
          env: { ...f.env, SANCTUARY_AGENT_ID: "claude_code:fixture" },
          dialogRunner: () => ({ status: 0, signal: null, stdout: Buffer.from("approve\n") }),
        });
        const outcome = failure === "refusal"
          ? expect(operation).rejects.toBe(releaseError)
          : expect(operation).rejects.toMatchObject({ errors: [operationError, releaseError] });
        try {
          if (failure === "flush") {
            await Promise.race([flushing.promise, operation.then(() => { throw new Error("command skipped its final flush"); })]);
            expect(f.leases.at(-1)!.signal.aborted).toBe(false);
            await expect(f.exclusive()).rejects.toMatchObject({ kind: "contention" });
          }
        } finally { finish.resolve(); await outcome; }
        expect(f.err.text).not.toBe("");
        await released(f);
      }, releaseError);
    },
  );

  it.each(["identity refusal", "construction", "observer"])("memory bootstrap retains %s outcome when release fails", async (failure) => {
    const releaseError = new Error("bootstrap release rejected");
    const operationError = new Error("bootstrap operation rejected");
    await fixture(failure !== "identity refusal", async (f) => {
      if (failure === "construction") vi.spyOn(BaselineTracker.prototype, "load").mockRejectedValue(operationError);
      const operation = runMemoryIngestCommand({ ...f.args(["--harness", "claude-code", "--dir", join(f.root, "memory"), "--fortress", f.root]),
        env: { ...f.env, SANCTUARY_AGENT_ID: "claude_code:fixture" },
          dialogRunner: () => ({ status: 0, signal: null, stdout: Buffer.from("approve\n") }),
        observeMasterKey: failure === "observer" ? () => { throw operationError; } : undefined,
      });
      if (failure === "identity refusal") await expect(operation).rejects.toBe(releaseError);
      else await expect(operation).rejects.toMatchObject({ errors: [operationError, releaseError] });
      await released(f);
    }, releaseError);
  });

  it.each(["credential", "store", "aggregate store"])("secrets preserves the refusal-recording message on ordinary %s open failure", async (failure) => {
    await fixture(true, async (f) => {
      await seedSurrogateBinding(f);
      const store = backend();
      if (failure !== "credential") store.ensureInitialized = async () => {
        const error = new Error("store open rejected");
        throw failure === "aggregate store" ? new AggregateError([error], "ordinary store open failure") : error;
      };
      expect(await runSecretsCommand({ ...f.args(["surrogate", "remove", "fixture-secret"]),
        passphrase: failure === "credential" ? "wrong-passphrase" : passphrase,
        surrogateBackend: store,
        surrogateArming: { resolveAgentUid: async () => process.getuid!(), installedHelperUids: async () => [], hasHelperArtifacts: async () => true },
        surrogateUnlock: { send: async () => ({ outcome: "absent" }) },
      })).toBe(1);
      expect(f.err.text).toContain("The refusal itself could not be recorded on the audit chain");
      expect(f.err.text).not.toContain("sanctuary secrets:");
      await released(f);
      f.err.text = "";
      const acquire = vi.mocked(locks.acquireMasterWriteBarrier).getMockImplementation()!;
      vi.spyOn(locks, "acquireMasterWriteBarrier").mockImplementation(async (...args) => {
        const lease = await acquire(...args);
        return { ...lease, release: async () => { await lease.release(); throw new Error("open release rejected"); } };
      });
      expect(await runSecretsCommand({ ...f.args(["surrogate", "remove", "fixture-secret"]),
        passphrase: failure === "credential" ? "wrong-passphrase" : passphrase,
        surrogateBackend: store,
        surrogateArming: { resolveAgentUid: async () => process.getuid!(), installedHelperUids: async () => [], hasHelperArtifacts: async () => true },
        surrogateUnlock: { send: async () => ({ outcome: "absent" }) },
      })).toBe(1);
      expect(f.err.text).toContain("sanctuary secrets:");
      expect(f.err.text).not.toContain("The refusal itself could not be recorded");
      await released(f);
    });
  });

  it("secrets recognises the shared message of an aggregate created by withCliFinalization during open", async () => {
    const operationError = new Error("surrogate open rejected");
    const releaseError = new Error("surrogate open release rejected");
    await fixture(true, async (f) => {
      await seedSurrogateBinding(f);
      const store = backend();
      let aggregate: unknown;
      store.ensureInitialized = async () => {
        try {
          await custody.withCliFinalization(async () => { throw operationError; }, async () => { throw releaseError; });
        } catch (error) { aggregate = error; throw error; }
      };
      expect(await runSecretsCommand({ ...f.args(["surrogate", "remove", "fixture-secret"]),
        surrogateBackend: store,
        surrogateArming: { resolveAgentUid: async () => process.getuid!(), installedHelperUids: async () => [], hasHelperArtifacts: async () => true },
        surrogateUnlock: { send: async () => ({ outcome: "absent" }) },
      })).toBe(1); // Refusal and cleanup failure both require a nonzero command status.
      expect(aggregate).toBeInstanceOf(AggregateError);
      expect(aggregate).toMatchObject({ errors: [operationError, releaseError], cause: releaseError });
      expect((aggregate as AggregateError).message).toBe(custody.CLI_FINALIZATION_ERROR_MESSAGE);
      expect(f.err.text).toContain(`sanctuary secrets: ${custody.CLI_FINALIZATION_ERROR_MESSAGE}`);
      expect(f.err.text).not.toContain("The refusal itself could not be recorded");
      await released(f);
    });
  });

  it.each(["flush", "release"])("committed exit import preserves best-effort flush semantics on %s failure", async (failure) => {
    await fixture(true, async (f) => {
      const bundle = join(f.root, "bundle");
      expect(await runExitCommand(f.args(["export", "--out", bundle, "--yes"]))).toBe(0);
      for (const lease of f.leases.splice(0)) await lease.release();
      f.out.text = "";
      if (failure === "release") {
        const acquire = locks.acquireMasterWriteBarrier;
        vi.spyOn(locks, "acquireMasterWriteBarrier").mockImplementationOnce(async (...args) => {
          const lease = await acquire(...args);
          return { ...lease, release: async () => { await lease.release(); throw new Error("release rejected"); } };
        });
      }
      const flush = AuditLog.prototype.flush;
      vi.spyOn(AuditLog.prototype, "flush").mockImplementation(async function (this: AuditLog) {
        if (f.out.text.includes("activated: true")) throw new Error("post-commit flush rejected");
        return flush.call(this);
      });
      expect(await runExitCommand(f.args(["import", bundle, "--activate", "--yes"])), f.err.text).toBe(failure === "release" ? 1 : 0);
      expect(f.out.text).toContain("activated: true");
      await released(f);
    });
  });

  it.each([
    { name: "anomaly", run: runAnomalyCommand, argv: ["subscribe", "unknown", "--classifier", "unknown"] },
    { name: "sentinel", run: runSentinelCommand, argv: ["subscribe", "unknown"] },
    { name: "template", run: (args: ReturnType<Fixture["args"]>) => runTemplateCommand({ ...args, isAgentWrapped: async () => true }), argv: ["init", "research-assistant", "--agent-id", "fixture"] },
  ])("$name establishment release failure escapes its audit catch", async ({ name, run, argv }) => {
    const releaseError = new Error("establishment release rejected");
    await fixture(true, async (f) => {
      vi.stubEnv("SANCTUARY_PASSPHRASE", "wrong-passphrase");
      const operation = run({ ...f.args(argv), passphrase: "wrong-passphrase", env: { ...f.env, SANCTUARY_PASSPHRASE: "wrong-passphrase" } });
      if (name === "template") await expect(operation).rejects.toMatchObject({ errors: expect.arrayContaining([releaseError]) });
      else expect(await operation).toBe(1);
      expect(f.out.text).not.toContain("initialized successfully");
      await released(f);
    }, releaseError);
  });

  it("secrets reports refusal cleanup failure through the generic error path", async () => {
    const releaseError = new Error("release rejected");
    await fixture(true, async (f) => {
      await writeFile(join(f.root, "surrogate-policy.json"), JSON.stringify({
        surrogate_policy_version: SURROGATE_POLICY_VERSION,
        bindings: [{ secret: "fixture-secret", agent: "hermes", env: "FIXTURE", header: "Authorization", destinations: [{ host: "fixture.invalid", port: SURROGATE_BOUND_PORT }] }],
      }));
      expect(await runSecretsCommand({
        ...f.args(["surrogate", "remove", "fixture-secret"]), surrogateBackend: backend(),
        surrogateArming: { resolveAgentUid: async () => process.getuid!(), installedHelperUids: async () => [], hasHelperArtifacts: async () => true },
        surrogateUnlock: { send: async () => ({ outcome: "absent" }) },
      })).toBe(1);
      expect(f.err.text).toContain("sanctuary secrets: release rejected");
      expect(f.err.text).not.toContain("The refusal itself could not be recorded");
      await released(f);
    }, releaseError);
  });

  it.each([
    { name: "add", argv: ["add", "fixture-secret", "fixture-value"], target: "broker", method: "addSecret" },
    { name: "list", argv: ["list"], target: "broker", method: "listSecretNames" },
    { name: "rotate", argv: ["rotate", "fixture-secret", "fixture-value"], target: "broker", method: "rotateSecret" },
    { name: "delete", argv: ["delete", "fixture-secret"], target: "broker", method: "deleteSecret" },
    { name: "grant", argv: ["grant", "fixture-skill", "fixture-secret"], target: "broker", method: "grant" },
    { name: "revoke", argv: ["revoke", "fixture-skill", "fixture-secret"], target: "broker", method: "revoke" },
    { name: "revoke binding", argv: ["revoke", "fixture-skill", "fixture-secret"], target: "surrogate", method: "appendCritical", binding: true },
    { name: "surrogate add broker check", argv: surrogateAddArgs(), target: "broker", method: "listSecretNames" },
    { name: "surrogate add value", argv: surrogateAddArgs(), target: "surrogate", method: "bindValue" },
    { name: "surrogate refusal recorder", argv: ["surrogate", "remove", "fixture-secret"], target: "surrogate", method: "appendCritical", binding: true, armed: true },
    { name: "surrogate remove", argv: ["surrogate", "remove", "fixture-secret"], target: "surrogate", method: "removeValue", binding: true },
    { name: "surrogate unlock", argv: ["surrogate", "unlock", "fixture-secret", "--agent-uid", String(process.getuid!())], target: "surrogate", method: "transport" },
    { name: "audit", argv: ["audit"], target: "broker", method: "queryAuditOperator" },
  ])("secrets $name retains the operation error alongside a close failure", async ({ argv, target, method, binding, armed }) => {
    const releaseError = new Error("close rejected");
    const operationError = new Error("operation rejected");
    await fixture(true, async (f) => {
      if (binding) await seedSurrogateBinding(f);
      const finalize = custody.withCliFinalization;
      const errors: unknown[] = [];
      vi.spyOn(custody, "withCliFinalization").mockImplementation(async (operation, close) => {
        try { return await finalize(operation, close); }
        catch (error) { errors.push(error); throw error; }
      });
      const openBroker = brokerOpen.openBroker;
      vi.spyOn(brokerOpen, "openBroker").mockImplementation(async (opts) => {
        const context = await openBroker({ ...opts, backend: backend() });
        if (target !== "broker") return context;
        const member = method as "addSecret" | "listSecretNames" | "rotateSecret" | "deleteSecret" | "grant" | "revoke" | "queryAuditOperator";
        vi.spyOn(context.broker, member).mockImplementation(() => { throw operationError; });
        return { ...context, close: async () => { await context.close(); throw releaseError; } };
      });
      const openSurrogate = brokerOpen.openSurrogateStore;
      vi.spyOn(brokerOpen, "openSurrogateStore").mockImplementation(async (opts) => {
        const context = await openSurrogate({ ...opts, backend: { ...backend(), readSecret: async () => "fixture-value" } });
        if (target !== "surrogate") return context;
        if (method === "appendCritical") vi.spyOn(context.auditLog, "appendCritical").mockRejectedValue(operationError);
        else if (method !== "transport") vi.spyOn(context.store, method as "bindValue" | "removeValue").mockRejectedValue(operationError);
        return { ...context, close: async () => { await context.close(); throw releaseError; } };
      });
      expect(await runSecretsCommand({ ...f.args(argv),
        surrogateNoCore: { alreadyReexeced: () => true, readHardCoreLimit: async () => "0", reexecWithoutCore: async () => 0 },
        surrogateArming: { resolveAgentUid: async () => process.getuid!(), installedHelperUids: async () => [], hasHelperArtifacts: async () => armed ?? false },
        surrogateUnlock: { send: async (_uid, request) => {
          if (method !== "transport") return { outcome: "absent" };
          if (request.kind !== "status") throw operationError;
          return { outcome: "answered", response: { v: SURROGATE_WIRE_VERSION, id: request.id, kind: "status",
            generation_id: 1, // One fixture generation is armed.
            bindings: [{ secret: "fixture-secret", unlocked: false, expires_at: null }],
          } };
        } },
      })).toBe(1);
      expect(errors).toContainEqual(expect.objectContaining({ errors: [operationError, releaseError] }));
      await released(f);
    });
  });

  it("exit import releases its context before returning an invalid conflict refusal", async () => {
    await fixture(true, async (f) => {
      const bundle = join(f.root, "bundle");
      expect(await runExitCommand(f.args(["export", "--out", bundle, "--yes"]))).toBe(0);
      for (const seedLease of f.leases.splice(0)) await seedLease.release();
      expect(await runExitCommand(f.args(["import", bundle, "--conflict", "invalid"]))).toBe(2);
      await released(f);
    });
  });

  it("exit export releases its context before returning a malformed policy refusal", async () => {
    await fixture(true, async (f) => {
      await writeFile(join(f.root, "principal-policy.yaml"), "version: 1\n");
      expect(await runExitCommand(f.args(["export", "--out", join(f.root, "bundle"), "--yes"]))).toBe(1);
      await released(f);
    });
  });

  it("identity creation retains its session until primary metadata finishes", async () => {
    await fixture(false, async (f) => {
      const entered = deferred();
      const finish = deferred();
      const write = FilesystemStorage.prototype.write;
      vi.spyOn(FilesystemStorage.prototype, "write").mockImplementation(async function (this: FilesystemStorage, ...args) {
        if (args[0] === "_meta" && args[1] === "primary_identity_id") {
          entered.resolve();
          await finish.promise;
        }
        return write.apply(this, args);
      });
      const operation = runIdentityCommand(f.args(["create", "--label", "session-fixture"]));
      try {
        await Promise.race([entered.promise, operation.then(() => { throw new Error("creation completed before primary metadata"); })]);
        expect(f.leases.at(-1)!.signal.aborted).toBe(false);
        await expect(f.exclusive()).rejects.toMatchObject({ kind: "contention" });
      } finally {
        finish.resolve();
        expect(await operation).toBe(0);
      }
      await released(f);
    });
  });

  it("the audit command releases its session after output rejects", async () => {
    await fixture(true, async (f) => {
      vi.spyOn(f.out, "write").mockImplementation(() => { throw new Error("output rejected"); });
      expect(await runAuditCommand(f.args(["search"]))).toBe(1);
      await released(f);
    });
  });

  it.each([
    { name: "anomaly", run: runAnomalyCommand, argv: ["subscribe", "unknown", "--classifier", "unknown"] },
    { name: "sentinel", run: runSentinelCommand, argv: ["subscribe", "unknown"] },
  ])("$name reports release failure outside its best-effort audit catch", async ({ run, argv }) => {
    const sentinel = new Error("release rejected");
    await fixture(true, async (f) => {
      vi.spyOn(AuditLog.prototype, "append").mockRejectedValue(new Error("audit rejected"));
      expect(await run(f.args(argv))).toBe(1);
      expect(f.err.text).toContain(sentinel.message);
      await released(f);
    }, sentinel);
  });

  it("policy activation retains its session through the response and failure audit", async () => {
    await fixture(true, async (f) => {
      vi.stubEnv("SANCTUARY_POLICY_API_TOKEN", "fixture-token");
      const entered = deferred();
      const finish = deferred();
      vi.stubGlobal("fetch", vi.fn(async () => {
        entered.resolve();
        await finish.promise;
        return new Response(JSON.stringify({ ok: false, error: "refused" }), { status: 400 });
      }));
      const operation = runPolicyCommand(f.args(["drafts", "activate", "fixture", "--api-base", "http://127.0.0.1"]));
      try {
        await Promise.race([entered.promise, operation.then(() => { throw new Error("operation ended before the deferred boundary"); })]);
        expect(f.leases[0]!.signal.aborted).toBe(false);
        await expect(f.exclusive()).rejects.toMatchObject({ kind: "contention" });
      } finally { finish.resolve(); await operation; }
      expect(await operation).toBe(1);
      await released(f);
    });
  });

  it("local concierge retains its session through status completion", async () => {
    await fixture(true, async (f) => {
      const entered = deferred();
      const finish = deferred();
      vi.spyOn(ConciergeService.prototype, "status").mockImplementation(async () => {
        entered.resolve();
        await finish.promise;
        throw new Error("status rejected");
      });
      const operation = runConciergeCommand(f.args(["status"]));
      try {
        await Promise.race([entered.promise, operation.then(() => { throw new Error("operation ended before the deferred boundary"); })]);
        expect(f.leases[0]!.signal.aborted).toBe(false);
        await expect(f.exclusive()).rejects.toMatchObject({ kind: "contention" });
      } finally { finish.resolve(); await operation.catch(() => undefined); }
      await expect(operation).rejects.toThrow("status rejected");
      await released(f);
    });
  });

  it.each(commands.filter((command) => ["checkpoint list", "file grant list", "observe status", "identity show"].includes(command.name)))
    ("$name finalizes a later construction failure", async ({ run, argv }) => {
      await fixture(true, async (f) => {
        vi.spyOn(IdentityManager.prototype, "load").mockRejectedValue(new Error("identity load rejected"));
        await run(f.args(argv)).catch(() => undefined);
        await released(f);
      });
    });

  it.each([
    { name: "verifier", open: openVerifier },
    { name: "issuer", open: openIssuer },
    { name: "operator signer", open: openOperatorSigner },
  ])("$name transfers its session to the caller", async ({ open }) => {
    await fixture(true, async (f) => {
      const context = await open({ passphrase, fortressPath: f.root });
      try {
        expect(context.masterWriteBarrier?.signal.aborted).toBe(false);
        await expect(f.exclusive()).rejects.toMatchObject({ kind: "contention" });
      } finally {
        await context.masterWriteBarrier?.release();
        context.masterKey.fill(0);
      }
      await released(f);
    });
  });

  it.each([
    { name: "verifier", open: openVerifier },
    { name: "issuer", open: openIssuer },
    { name: "operator signer", open: openOperatorSigner },
  ])("$name releases when identity construction refuses", async ({ open }) => {
    await fixture(false, async (f) => {
      await expect(open({ passphrase, fortressPath: f.root })).rejects.toThrow();
      await released(f);
    });
  });

  it.each([
    { name: "broker", open: openBroker },
    { name: "surrogate store", open: openSurrogateStore },
  ])("$name closes once after a failed flush", async ({ open }) => {
    await fixture(true, async (f) => {
      const context = await open({ passphrase, storagePath: f.root, backend: backend() });
      const sentinel = new Error("flush rejected");
      try {
        expect(f.leases[0]!.signal.aborted).toBe(false);
        await expect(f.exclusive()).rejects.toMatchObject({ kind: "contention" });
        const flush = vi.spyOn(context.auditLog, "flush").mockRejectedValue(sentinel);
        const first = context.close();
        expect(context.close()).toBe(first);
        await expect(first).rejects.toBe(sentinel);
        await expect(context.close()).rejects.toBe(sentinel);
        expect(flush).toHaveBeenCalledTimes(1);
        await released(f);
      } finally { await context.close().catch(() => undefined); }
    });
  });

  it.each([
    { name: "broker", open: openBroker },
    { name: "surrogate store", open: openSurrogateStore },
  ])("$name releases after backend construction fails", async ({ open }) => {
    await fixture(true, async (f) => {
      const sentinel = new Error("backend rejected");
      const store = backend();
      store.ensureInitialized = async () => { throw sentinel; };
      await expect(open({ passphrase, storagePath: f.root, backend: store })).rejects.toBe(sentinel);
      await released(f);
    });
  });

  it.each(commands.filter((command) => ["checkpoint list", "file grant list", "observe status", "did web refusal", "erc8004 refusal", "concierge refusal"].includes(command.name)))
    ("$name releases when loaded identities have no default", async ({ run, argv }) => {
      await fixture(true, async (f) => {
        vi.spyOn(IdentityManager.prototype, "getDefault").mockReturnValue(undefined);
        expect(await run(f.args(argv)).catch((error: unknown) => {
          if (error instanceof ConciergeReadError) return 1;
          throw error;
        })).toBe(1);
        await released(f);
      });
    });

  it("template initialization reports release failure outside its best-effort audit", async () => {
    const sentinel = new Error("release rejected");
    await fixture(true, async (f) => {
      vi.spyOn(AuditLog.prototype, "append").mockRejectedValue(new Error("audit rejected"));
      await expect(runTemplateCommand({ ...f.args(["init", "research-assistant", "--agent-id", "fixture"]), isAgentWrapped: async () => true })).rejects.toBe(sentinel);
      await released(f);
      expect(f.out.text).toBe("");
    }, sentinel);
  });

  it("policy activation reports release failure outside its best-effort audit", async () => {
    const sentinel = new Error("release rejected");
    await fixture(true, async (f) => {
      vi.stubEnv("SANCTUARY_POLICY_API_TOKEN", "fixture-token");
      vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ ok: true }))));
      vi.spyOn(AuditLog.prototype, "append").mockRejectedValue(new Error("audit rejected"));
      expect(await runPolicyCommand(f.args(["drafts", "activate", "fixture", "--api-base", "http://127.0.0.1"]))).toBe(1);
      expect(f.err.text).toContain(sentinel.message);
      await released(f);
    }, sentinel);
  });

  it("broker close retains custody until pending audit persistence completes", async () => {
    await fixture(true, async (f) => {
      const context = await openBroker({ passphrase, storagePath: f.root, backend: backend() });
      const entered = deferred();
      const finish = deferred();
      vi.spyOn(context.auditLog, "flush").mockImplementation(async () => { entered.resolve(); await finish.promise; });
      const closing = context.close();
      try {
        await entered.promise;
        expect(f.leases[0]!.signal.aborted).toBe(false);
        await expect(f.exclusive()).rejects.toMatchObject({ kind: "contention" });
      } finally { finish.resolve(); await closing; }
      await released(f);
    });
  });

  it("broker construction keeps its operation and release failures", async () => {
    const releaseError = new Error("release rejected");
    const operationError = new Error("backend rejected");
    await fixture(true, async (f) => {
      const store = backend();
      store.ensureInitialized = async () => { throw operationError; };
      await expect(openBroker({ passphrase, storagePath: f.root, backend: store }))
        .rejects.toMatchObject({ errors: [operationError, releaseError] });
      await released(f);
    }, releaseError);
  });

  it("policy selector construction refusal releases before continuing without a selector", async () => {
    await fixture(true, async (f) => {
      await mkdir(join(f.root, "state", "_intelligence"), { recursive: true });
      vi.spyOn(SubstrateSelector.prototype, "load").mockRejectedValue(new Error("selector rejected"));
      await runPolicyCommand(f.args(["compile", "always require approval for state_export"]));
      await released(f);
    });
  });
});

function backend(): Backend {
  return {
    ensureInitialized: async () => {}, unlock: async () => {}, isUnlocked: async () => true,
    addSecret: async () => {}, readSecret: async () => "", rotateSecret: async () => {},
    deleteSecret: async () => {}, listSecretNames: async () => [],
  };
}

async function seedSurrogateBinding(f: Fixture) {
  await writeFile(join(f.root, "surrogate-policy.json"), JSON.stringify({
    surrogate_policy_version: SURROGATE_POLICY_VERSION,
    bindings: [{ secret: "fixture-secret", agent: "hermes", env: "FIXTURE", header: "Authorization", destinations: [{ host: "fixture.invalid", port: SURROGATE_BOUND_PORT }] }],
  }));
}

function surrogateAddArgs() {
  return ["surrogate", "add", "fixture-secret", "fixture-value", "--agent", "hermes", "--env", "FIXTURE", "--header", "Authorization", "--host", "fixture.invalid"];
}
