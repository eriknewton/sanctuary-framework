/**
 * PR-3 CLI surface + pre-declared drill fixtures for the anchor-verification
 * skeptic loop (synthetic-fixture rule: no network; Rekor is the
 * FakeRekorLog fixture).
 *
 * PRE-DECLARED DRILL CRITERIA (the coordinator-run drill repeats these
 * end-to-end scenarios; the fixtures here are their deterministic twins):
 *
 *   D1 CLEAN LOOP: operator exports bundle + anchors evidence; auditor
 *      verifies offline with the operator's pinned key AND the pinned
 *      Rekor log key. Expected: PASS, exit 0, all anchors verified.
 *   D2 STALE BUNDLE CAUGHT: the same evidence presented outside the
 *      --expect-fresh window. Expected: FAIL, exit 1, finding
 *      anchor_freshness_stale.
 *   D3 FORKED HISTORY CAUGHT: two bundles signed by the same key carrying
 *      the same counter with different contents, fed to --compare.
 *      Expected: FAIL, exit 1, finding fork_detected.
 *   D4 WITHHELD SUFFIX CAUGHT: a truncated bundle presented alongside the
 *      full anchors evidence. Expected: FAIL, exit 1, finding
 *      anchor_beyond_bundle.
 *
 * Plus CLI plumbing: anchor export verb, --fetch-anchors (incl. the
 * log-denies-entry case and the SSRF guard reuse), usage-error fail-closed
 * behavior, and the standalone artifact's offline-only refusal of
 * --fetch-anchors.
 */
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import { runTransparencyCommand } from "../../src/cli/transparency.js";
import { runStandaloneTransparencyVerifier } from "../../src/transparency/offline-cli.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { deriveMasterKey } from "../../src/core/key-derivation.js";
import { encrypt } from "../../src/core/encryption.js";
import { stringToBytes } from "../../src/core/encoding.js";
import { randomBytes } from "../../src/core/random.js";
import { fortressIdFromStoragePath } from "../../src/dashboard/v1_1/wiring.js";
import {
  emitEnforcementCheckpoint,
  readPersistedCheckpoints,
} from "../../src/transparency/emitter.js";
import { resolveTransparencySigner } from "../../src/transparency/signer.js";
import { TRANSPARENCY_BUNDLE_FORMAT } from "../../src/transparency/checkpoint.js";
import type { FetchLike } from "../../src/transparency/rekor-client.js";
import { FakeRekorLog } from "./fake-rekor-log.js";

class Capture extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: unknown,
    _enc: BufferEncoding,
    cb: (err?: Error | null) => void
  ): void {
    this.chunks.push(String(chunk));
    cb();
  }
  text(): string {
    return this.chunks.join("");
  }
}

const PASSPHRASE = "transparency-anchor-verify-cli-passphrase";
const REKOR_URL = "https://rekor.fixture.test";
const FIXTURE_TIME = 1_760_000_000;

describe("PR-3 anchor verification CLI + drill fixtures", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function makeFortress(): Promise<{
    fortress: string;
    binaryPath: string;
  }> {
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-anchor-vcli-"));
    tempDirs.push(fortress);
    const storage = new FilesystemStorage(join(fortress, "state"));
    const derived = await deriveMasterKey(PASSPHRASE);
    await storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(derived.params))
    );
    const privateKey = randomBytes(32);
    const publicKey = ed25519.getPublicKey(privateKey);
    await writeFile(join(fortress, "castle-pinned-pubkey.bin"), publicKey);
    await writeFile(
      join(fortress, "castle-pinned-privkey.enc"),
      JSON.stringify(encrypt(privateKey, derived.key))
    );
    const rulesDir = join(fortress, "policy", "egress", "rules");
    await mkdir(rulesDir, { recursive: true });
    await writeFile(
      join(rulesDir, "allow-github.json"),
      JSON.stringify({ rule_id: "allow-github" })
    );
    const binaryPath = join(fortress, "fake-binary.js");
    await writeFile(binaryPath, "exit(0)");
    const auditLog = new AuditLog(storage, derived.key, { checkpointInterval: 0 });
    await auditLog.appendCritical({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: "fortress-anchor-vcli",
      result: "success",
      details: { rule_id: "deny-default" },
    });
    await auditLog.flush();
    derived.key.fill(0);
    return { fortress, binaryPath };
  }

  function run(
    argv: string[],
    extras: { fetchFn?: FetchLike; now?: () => Date } = {}
  ): { code: Promise<number>; out: Capture; err: Capture } {
    const out = new Capture();
    const err = new Capture();
    const code = runTransparencyCommand({ argv, out, err, env: {}, ...extras });
    return { code, out, err };
  }

  async function appendAudit(
    fortress: string,
    operation: string,
    ruleId: string
  ): Promise<void> {
    const storage = new FilesystemStorage(join(fortress, "state"));
    const derived = await deriveMasterKey(
      PASSPHRASE,
      JSON.parse(
        Buffer.from(
          (await storage.read("_meta", "key-params"))!
        ).toString("utf8")
      )
    );
    const auditLog = new AuditLog(storage, derived.key, { checkpointInterval: 0 });
    await auditLog.appendCritical({
      layer: "l1",
      operation,
      identity_id: "fortress-anchor-vcli",
      result: "success",
      details: { rule_id: ruleId },
    });
    await auditLog.flush();
    derived.key.fill(0);
  }

  /**
   * Operator side of the drill: enable anchoring against the fixture log,
   * emit + anchor n checkpoints, export bundle and anchors evidence files,
   * and write the two pinned keys an auditor needs.
   */
  async function operatorScenario(n: number): Promise<{
    fortress: string;
    log: FakeRekorLog;
    bundlePath: string;
    anchorsPath: string;
    pinnedKeyPath: string;
    rekorKeyPath: string;
  }> {
    const { fortress, binaryPath } = await makeFortress();
    const log = new FakeRekorLog();
    log.appendNoise("pre-existing");
    const enable = run([
      "anchor",
      "enable",
      "--fortress",
      fortress,
      "--passphrase",
      PASSPHRASE,
      "--rekor-url",
      REKOR_URL,
      "--yes",
    ]);
    expect(await enable.code).toBe(0);
    for (let i = 0; i < n; i++) {
      if (i > 0) await appendAudit(fortress, "egress_allowed", `rule-${i}`);
      const emit = run(
        [
          "checkpoint",
          "--fortress",
          fortress,
          "--passphrase",
          PASSPHRASE,
          "--local-sign",
          "--binary",
          binaryPath,
        ],
        { fetchFn: log.fetchLike() }
      );
      expect(await emit.code).toBe(0);
      expect(emit.out.text()).toContain("anchored");
      log.appendNoise(`foreign-${i}`);
    }
    const bundlePath = join(fortress, "bundle.json");
    const bundleExport = run([
      "export",
      "--fortress",
      fortress,
      "--output",
      bundlePath,
    ]);
    expect(await bundleExport.code).toBe(0);
    const anchorsPath = join(fortress, "anchors.json");
    const anchorsExport = run([
      "anchor",
      "export",
      "--fortress",
      fortress,
      "--passphrase",
      PASSPHRASE,
      "--output",
      anchorsPath,
    ]);
    expect(await anchorsExport.code).toBe(0);
    expect(anchorsExport.err.text()).toContain("LOCAL commitment salt");
    const rekorKeyPath = join(fortress, "rekor-key.pem");
    await writeFile(rekorKeyPath, log.publicKeyPem());
    return {
      fortress,
      log,
      bundlePath,
      anchorsPath,
      pinnedKeyPath: join(fortress, "castle-pinned-pubkey.bin"),
      rekorKeyPath,
    };
  }

  it("D1 clean loop: bundle + anchors evidence verifies on the full CLI and the standalone artifact", async () => {
    const scenario = await operatorScenario(2);
    const verify = run([
      "verify",
      "--input",
      scenario.bundlePath,
      "--public-key-file",
      scenario.pinnedKeyPath,
      "--check-anchors",
      scenario.anchorsPath,
      "--rekor-public-key-file",
      scenario.rekorKeyPath,
    ]);
    expect(await verify.code).toBe(0);
    const text = verify.out.text();
    expect(text).toContain("Verdict: PASS");
    expect(text).toContain("Anchor coverage (log signatures: verified under pinned log key)");
    expect(text).toContain("2 verified, 0 consistent, 0 unverified, 0 invalid");
    expect(text).not.toContain("internal consistency only");

    // The standalone offline artifact reaches the same verdict with the
    // same files and no Sanctuary install semantics.
    const out = new Capture();
    const err = new Capture();
    const standaloneCode = await runStandaloneTransparencyVerifier({
      argv: [
        "--input",
        scenario.bundlePath,
        "--public-key-file",
        scenario.pinnedKeyPath,
        "--check-anchors",
        scenario.anchorsPath,
        "--rekor-public-key-file",
        scenario.rekorKeyPath,
        "--json",
      ],
      out,
      err,
    });
    expect(standaloneCode).toBe(0);
    const payload = JSON.parse(out.text()) as {
      verdict: string;
      anchors: { verified: number; log_signature_basis: string };
    };
    expect(payload.verdict).toBe("PASS");
    expect(payload.anchors.verified).toBe(2);
    expect(payload.anchors.log_signature_basis).toBe("pinned-rekor-key");
  });

  it("no pinned log key: anchors report consistent (never verified) and the trust level is stated", async () => {
    const scenario = await operatorScenario(2);
    const verify = run([
      "verify",
      "--input",
      scenario.bundlePath,
      "--public-key-file",
      scenario.pinnedKeyPath,
      "--check-anchors",
      scenario.anchorsPath,
    ]);
    // PASS is still possible: everything that CAN be verified at this
    // trust level passed. But nothing is counted "verified", and the
    // report says exactly what was and was not established.
    expect(await verify.code).toBe(0);
    const text = verify.out.text();
    expect(text).toContain("Verdict: PASS");
    expect(text).toContain(
      "Anchor coverage (log signatures: NOT verified, no pinned log key)"
    );
    expect(text).toContain("0 verified, 2 consistent, 0 unverified, 0 invalid");
    expect(text).toContain(
      "anchors checked for internal consistency only (operator-supplied evidence); supply --rekor-public-key-file for log-attested verification"
    );

    // Same pin on the standalone artifact's JSON report.
    const out = new Capture();
    const err = new Capture();
    const code = await runStandaloneTransparencyVerifier({
      argv: [
        "--input",
        scenario.bundlePath,
        "--public-key-file",
        scenario.pinnedKeyPath,
        "--check-anchors",
        scenario.anchorsPath,
        "--json",
      ],
      out,
      err,
    });
    expect(code).toBe(0);
    const payload = JSON.parse(out.text()) as {
      anchors: {
        verified: number;
        consistent: number;
        log_signature_basis: string;
        statuses: Array<{ status: string }>;
      };
    };
    expect(payload.anchors.verified).toBe(0);
    expect(payload.anchors.consistent).toBe(2);
    expect(payload.anchors.log_signature_basis).toBe("none");
    expect(
      payload.anchors.statuses.every((s) => s.status !== "verified")
    ).toBe(true);
  });

  it("D2 stale bundle caught by --expect-fresh against log-attested time", async () => {
    const scenario = await operatorScenario(2);
    const stale = run(
      [
        "verify",
        "--input",
        scenario.bundlePath,
        "--public-key-file",
        scenario.pinnedKeyPath,
        "--check-anchors",
        scenario.anchorsPath,
        "--rekor-public-key-file",
        scenario.rekorKeyPath,
        "--expect-fresh",
        "1h",
      ],
      { now: () => new Date((FIXTURE_TIME + 72 * 3600) * 1000) }
    );
    expect(await stale.code).toBe(1);
    expect(stale.out.text()).toContain("anchor_freshness_stale");

    const fresh = run(
      [
        "verify",
        "--input",
        scenario.bundlePath,
        "--public-key-file",
        scenario.pinnedKeyPath,
        "--check-anchors",
        scenario.anchorsPath,
        "--rekor-public-key-file",
        scenario.rekorKeyPath,
        "--expect-fresh",
        "1h",
      ],
      { now: () => new Date((FIXTURE_TIME + 600) * 1000) }
    );
    expect(await fresh.code).toBe(0);
  });

  it("D3 forked history caught by --compare (same key, same counter, divergent contents)", async () => {
    const { fortress, binaryPath } = await makeFortress();
    // Checkpoint 1: the shared history.
    const emit1 = run([
      "checkpoint",
      "--fortress",
      fortress,
      "--passphrase",
      PASSPHRASE,
      "--local-sign",
      "--binary",
      binaryPath,
    ]);
    expect(await emit1.code).toBe(0);
    // Fork the fortress state wholesale (same signing key, same chain so far).
    const forkPath = await mkdtemp(join(tmpdir(), "sanctuary-anchor-fork-"));
    tempDirs.push(forkPath);
    await cp(fortress, forkPath, { recursive: true, force: true });

    // History A: one more blocked event, checkpoint 2.
    await appendAudit(fortress, "egress_blocked", "rule-a");
    const emit2 = run([
      "checkpoint",
      "--fortress",
      fortress,
      "--passphrase",
      PASSPHRASE,
      "--local-sign",
      "--binary",
      binaryPath,
    ]);
    expect(await emit2.code).toBe(0);
    const bundleAPath = join(fortress, "bundle-a.json");
    expect(
      await run(["export", "--fortress", fortress, "--output", bundleAPath]).code
    ).toBe(0);

    // History B: DIFFERENT events, then checkpoint 2' signed by the SAME
    // key over the forked state. The fortress id is pinned to history A's
    // (ids derive from the storage path; the fork is the same fortress
    // presenting a second history, which is exactly the attack).
    await appendAudit(forkPath, "egress_allowed", "rule-b1");
    await appendAudit(forkPath, "egress_allowed", "rule-b2");
    const forkStorage = new FilesystemStorage(join(forkPath, "state"));
    const derived = await deriveMasterKey(
      PASSPHRASE,
      JSON.parse(
        Buffer.from((await forkStorage.read("_meta", "key-params"))!).toString("utf8")
      )
    );
    const forkAudit = new AuditLog(forkStorage, derived.key, { checkpointInterval: 0 });
    const signer = await resolveTransparencySigner({
      fortressPath: forkPath,
      masterKey: derived.key,
      env: {},
      mode: "local",
    });
    await emitEnforcementCheckpoint({
      storage: forkStorage,
      auditLog: forkAudit,
      fortressId: fortressIdFromStoragePath(fortress),
      fortressPath: forkPath,
      masterKey: derived.key,
      signer,
      binaryPath,
      version: "0.0.0-test",
    });
    const forkCheckpoints = await readPersistedCheckpoints(forkStorage);
    derived.key.fill(0);
    const bundleBPath = join(forkPath, "bundle-b.json");
    await writeFile(
      bundleBPath,
      JSON.stringify({
        format: TRANSPARENCY_BUNDLE_FORMAT,
        exported_at: new Date().toISOString(),
        public_key: forkCheckpoints[0]!.public_key,
        checkpoints: forkCheckpoints,
      })
    );

    const verify = run([
      "verify",
      "--input",
      bundleAPath,
      "--public-key-file",
      join(fortress, "castle-pinned-pubkey.bin"),
      "--compare",
      bundleBPath,
    ]);
    expect(await verify.code).toBe(1);
    const text = verify.out.text();
    expect(text).toContain("fork_detected");
    expect(text).toContain("FORK at counter 2");
  });

  it("D4 withheld suffix caught: truncated bundle vs full anchors evidence", async () => {
    const scenario = await operatorScenario(3);
    const bundle = JSON.parse(await readFile(scenario.bundlePath, "utf8")) as {
      checkpoints: unknown[];
    };
    bundle.checkpoints = bundle.checkpoints.slice(0, 2);
    const truncatedPath = join(scenario.fortress, "bundle-truncated.json");
    await writeFile(truncatedPath, JSON.stringify(bundle));
    const verify = run([
      "verify",
      "--input",
      truncatedPath,
      "--public-key-file",
      scenario.pinnedKeyPath,
      "--check-anchors",
      scenario.anchorsPath,
      "--rekor-public-key-file",
      scenario.rekorKeyPath,
    ]);
    expect(await verify.code).toBe(1);
    expect(verify.out.text()).toContain("anchor_beyond_bundle");
  });

  it("--fetch-anchors refreshes degraded receipts from the log (and stays SSRF-guarded)", async () => {
    const scenario = await operatorScenario(2);
    // Degrade the receipts: strip embedded body + proof as an older-build
    // receipt would look.
    const anchors = JSON.parse(await readFile(scenario.anchorsPath, "utf8")) as {
      rekor_url: string;
      receipts: Array<{ status: string; rekor?: Record<string, unknown> }>;
    };
    for (const receipt of anchors.receipts) {
      if (receipt.rekor) {
        delete receipt.rekor.body_b64;
        delete receipt.rekor.verification;
      }
    }
    const degradedPath = join(scenario.fortress, "anchors-degraded.json");
    await writeFile(degradedPath, JSON.stringify(anchors));

    // Offline, the degraded evidence is honestly unverified (still PASS,
    // coverage states it).
    const offline = run([
      "verify",
      "--input",
      scenario.bundlePath,
      "--public-key-file",
      scenario.pinnedKeyPath,
      "--check-anchors",
      degradedPath,
      "--rekor-public-key-file",
      scenario.rekorKeyPath,
    ]);
    expect(await offline.code).toBe(0);
    expect(offline.out.text()).toContain("0 verified, 0 consistent, 2 unverified");

    // With --fetch-anchors the entries come back from the log and verify.
    const fetched = run(
      [
        "verify",
        "--input",
        scenario.bundlePath,
        "--public-key-file",
        scenario.pinnedKeyPath,
        "--check-anchors",
        degradedPath,
        "--rekor-public-key-file",
        scenario.rekorKeyPath,
        "--fetch-anchors",
      ],
      { fetchFn: scenario.log.fetchLike() }
    );
    expect(await fetched.code).toBe(0);
    expect(fetched.out.text()).toContain("2 verified, 0 consistent, 0 unverified");

    // SSRF guard reuse: a loopback log URL in the anchors file is refused
    // fail-closed without the explicit unsafe override.
    anchors.rekor_url = "http://127.0.0.1:1";
    const loopbackPath = join(scenario.fortress, "anchors-loopback.json");
    await writeFile(loopbackPath, JSON.stringify(anchors));
    const refused = run(
      [
        "verify",
        "--input",
        scenario.bundlePath,
        "--public-key-file",
        scenario.pinnedKeyPath,
        "--check-anchors",
        loopbackPath,
        "--fetch-anchors",
      ],
      { fetchFn: scenario.log.fetchLike() }
    );
    expect(await refused.code).toBe(1);
    expect(refused.err.text()).toContain("https");
  });

  it("--fetch-anchors surfaces a log that DENIES the entry as a finding", async () => {
    const scenario = await operatorScenario(1);
    const emptyLog = new FakeRekorLog(); // knows nothing of our entries
    const verify = run(
      [
        "verify",
        "--input",
        scenario.bundlePath,
        "--public-key-file",
        scenario.pinnedKeyPath,
        "--check-anchors",
        scenario.anchorsPath,
        "--rekor-public-key-file",
        scenario.rekorKeyPath,
        "--fetch-anchors",
      ],
      { fetchFn: emptyLog.fetchLike() }
    );
    expect(await verify.code).toBe(1);
    expect(verify.out.text()).toContain("anchor_entry_not_found");
  });

  it("anchor-dependent flags fail closed at usage time", async () => {
    const scenario = await operatorScenario(1);
    const noAnchors = run([
      "verify",
      "--input",
      scenario.bundlePath,
      "--public-key-file",
      scenario.pinnedKeyPath,
      "--expect-fresh",
      "1h",
    ]);
    expect(await noAnchors.code).toBe(2);
    expect(noAnchors.err.text()).toContain("requires --check-anchors");

    const badWindow = run([
      "verify",
      "--input",
      scenario.bundlePath,
      "--public-key-file",
      scenario.pinnedKeyPath,
      "--check-anchors",
      scenario.anchorsPath,
      "--expect-fresh",
      "soon",
    ]);
    expect(await badWindow.code).toBe(2);

    // --expect-fresh without a pinned log key is a FINDING, not silence.
    const noLogKey = run(
      [
        "verify",
        "--input",
        scenario.bundlePath,
        "--public-key-file",
        scenario.pinnedKeyPath,
        "--check-anchors",
        scenario.anchorsPath,
        "--expect-fresh",
        "1h",
      ],
      { now: () => new Date(FIXTURE_TIME * 1000) }
    );
    expect(await noLogKey.code).toBe(1);
    expect(noLogKey.out.text()).toContain("anchor_freshness_unverifiable");
  });

  it("the standalone artifact refuses network flags (offline-only contract)", async () => {
    const out = new Capture();
    const err = new Capture();
    const code = await runStandaloneTransparencyVerifier({
      argv: ["--input", "whatever.json", "--fetch-anchors"],
      out,
      err,
    });
    expect(code).toBe(2);
    expect(err.text()).toContain("offline-only");
  });

  it("anchor export refuses when anchoring was never configured", async () => {
    const { fortress } = await makeFortress();
    const attempt = run([
      "anchor",
      "export",
      "--fortress",
      fortress,
      "--passphrase",
      PASSPHRASE,
    ]);
    expect(await attempt.code).toBe(1);
    expect(attempt.err.text()).toContain("never enabled");
  });
});
