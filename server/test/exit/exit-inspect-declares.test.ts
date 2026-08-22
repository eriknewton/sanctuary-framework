// fail-before-exempt: this PR's only edit here is a fixture consistency fix (total_keys=0 on the "genuinely empty bundle" case, F3/Exit V2 drill D1 2026-08-22) that holds under both pre-fix and post-fix source; the new F3/F4 behavior itself is covered fail-before by test/exit/exit-verifier-aggregator.test.ts and test/cli/import-state-warning.test.ts
/**
 * `sanctuary exit inspect` (exit-cluster item A5, 2026-08-05).
 *
 * Nothing answered "which credential does this bundle need?" without running an
 * import, and the import is the thing you cannot take back once the source
 * fortress is gone. `sanctuary exit inspect <dir>` answers it read-only.
 *
 * THREE FAILED ROUNDS ARE WHY THE CLAIM IS SHAPED THIS WAY. Round 1 classified
 * any object-shaped `source_custody` as a live re-key path while the import ran
 * a full shape-check and refused it, so inspect printed the re-key command and
 * exited 0 for a bundle no key could open. Round 2 descended into the wrap and
 * had the same bug one level down. Round 3 fixed the descent and broke the
 * import instead: a predicate demanding EVERY wrap be openable was shared with
 * the import gate, which turned a block carrying one intact wrap beside one
 * damaged wrap - a bundle that imports fine - into SOURCE_CUSTODY_MALFORMED.
 *
 * The pattern in all three is a tool without a credential trying to predict a
 * subsystem that has one. So the claim is now weaker and true by construction:
 * inspect reports what the artifact DECLARES (entry count, which re-key blocks
 * are present, whether they have a usable shape) and never asserts that an
 * import will succeed. The `credential check:` line states that bound in the
 * command's own output, on every path including the happy one.
 *
 * The differential below is what keeps declaration and import from drifting: it
 * drives the SAME crafted bundles through `exit inspect` and a real
 * `importExitBundle` and asserts they never CONTRADICT each other. Its table
 * carries three kinds of row on purpose:
 *
 *   `malformed`             the block has no usable shape; import refuses it
 *                           with SOURCE_CUSTODY_MALFORMED and inspect reports
 *                           `declares: damaged`.
 *   `opens`                 must survive; these are what stop the classifier
 *                           from degenerating to "everything is damaged", and
 *                           several mutate fields the unwrap path never reads
 *                           so an OVER-strict predicate fails too. The mixed
 *                           intact/damaged rows are the round-3 regression.
 *   `credential-dependent`  structurally perfect, opens only for the right
 *                           secret. Inspect names the declared material AND
 *                           must print the limit; this row is where the tool's
 *                           honesty about what it did not check is enforced.
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile, access } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Writable } from "node:stream";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { deriveMasterKey, derivePurposeKey } from "../../src/core/key-derivation.js";
import { hash } from "../../src/core/hashing.js";
import { sign as identitySign } from "../../src/core/identity.js";
import { canonicalize, canonicalizeToBytes } from "../../src/mesh/canonical-json.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createL4Tools } from "../../src/reputation/tools.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { defaultConfig } from "../../src/config.js";
import {
  exportExitBundle,
  importExitBundle,
  type ExportExitBundleResult,
} from "../../src/exit/index.js";
import { runExitCommand } from "../../src/exit/cli.js";

const SOURCE_PASSPHRASE = "correct horse battery fortress";

interface ToolDef {
  name: string;
  handler: (args: Record<string, unknown>) => Promise<{
    content: Array<{ type: string; text: string }>;
  }>;
}

async function callTool(
  tools: ToolDef[],
  name: string,
  args: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`Tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

async function buildHarness(storage: MemoryStorage, masterKey: Uint8Array) {
  const auditLog = new AuditLog(storage, masterKey);
  const stateStore = new StateStore(storage, masterKey);
  const { tools: l1Tools, identityManager } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "passphrase",
    auditLog
  );
  await identityManager.load();
  const { tools: l4Tools, reputationStore } = createL4Tools(
    storage,
    masterKey,
    identityManager,
    auditLog
  );
  return {
    storage,
    masterKey,
    auditLog,
    stateStore,
    identityManager,
    reputationStore,
    tools: [...l1Tools, ...l4Tools] as ToolDef[],
  };
}

type Harness = Awaited<ReturnType<typeof buildHarness>>;

/** A source fortress with one state entry and a bare random master. */
async function makeSource(label: string): Promise<Harness & { identityId: string }> {
  const harness = await buildHarness(new MemoryStorage(), generateRandomKey());
  const identity = await callTool(harness.tools, "identity_create", { label });
  const identityId = identity.identity_id as string;
  await callTool(harness.tools, "state_write", {
    namespace: "agent-memory",
    key: "handoff",
    value: "state that must survive the exit",
    identity_id: identityId,
  });
  return { ...harness, identityId };
}

async function makeDestination(): Promise<Harness & { identityId: string }> {
  const harness = await buildHarness(new MemoryStorage(), generateRandomKey());
  const identity = await callTool(harness.tools, "identity_create", {
    label: "destination-signer",
  });
  return { ...harness, identityId: identity.identity_id as string };
}

async function exportBundle(
  source: Harness,
  bundleDir: string,
  opts?: { mint?: boolean }
): Promise<ExportExitBundleResult> {
  return exportExitBundle({
    unpartitionedLegacyExport: true,
    bundleDir,
    storage: source.storage,
    masterKey: source.masterKey,
    identityManager: source.identityManager,
    auditLog: source.auditLog,
    reputationStore: source.reputationStore,
    policy: DEFAULT_POLICY,
    config: defaultConfig(),
    stateNamespaces: ["agent-memory"],
    keySource: "passphrase",
    mintStateRekeyKey: opts?.mint ?? false,
  });
}

function sha256Hex(bytes: Uint8Array): string {
  return Array.from(hash(bytes))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Rewrite `artifacts/encrypted_state.json` and RE-SIGN the manifest so the
 * bundle verifies again. This is how a pre-A3-fix damaged bundle (one already
 * in the wild, signed with garbage `source_key_derivation`) is reproduced
 * without needing an exporter that still emits garbage.
 *
 * FAILURE MODE if done wrong: forgetting the aggregate hash or the size field
 * leaves a bundle that fails verification, and the import then refuses for the
 * WRONG reason - the test would pass while proving nothing about A3.
 */
async function patchEncryptedStateAndResign(
  bundleDir: string,
  source: Harness,
  mutate: (artifact: Record<string, unknown>) => void
): Promise<void> {
  const artifactPath = join(bundleDir, "artifacts", "encrypted_state.json");
  const artifact = JSON.parse(await readFile(artifactPath, "utf8")) as Record<
    string,
    unknown
  >;
  mutate(artifact);
  await writeFile(artifactPath, JSON.stringify(artifact, null, 2) + "\n");

  const manifestPath = join(bundleDir, "manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
    body: {
      artifacts: Array<{ path: string; hash: string; size_bytes: number }>;
      artifacts_aggregate_hash: string;
    };
    signature: string;
  };
  for (const entry of manifest.body.artifacts) {
    const bytes = new Uint8Array(await readFile(join(bundleDir, entry.path)));
    entry.hash = sha256Hex(bytes);
    entry.size_bytes = bytes.length;
  }
  manifest.body.artifacts_aggregate_hash = sha256Hex(
    stringToBytes(canonicalize(manifest.body.artifacts))
  );
  const identity = source.identityManager.getDefault()!;
  manifest.signature = toBase64url(
    identitySign(
      canonicalizeToBytes(manifest.body),
      identity.encrypted_private_key,
      derivePurposeKey(source.masterKey, "identity-encryption")
    )
  );
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
}

function captureCli(): { chunks: string[]; out: Writable; err: Writable } {
  const chunks: string[] = [];
  const out = {
    write(s: string | Uint8Array): boolean {
      chunks.push(typeof s === "string" ? s : Buffer.from(s).toString());
      return true;
    },
  } as unknown as Writable;
  const err = {
    write(s: string | Uint8Array): boolean {
      chunks.push(typeof s === "string" ? s : Buffer.from(s).toString());
      return true;
    },
  } as unknown as Writable;
  return { chunks, out, err };
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}


describe("exit inspect: what the bundle declares, never what an import will do", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function newBundleDir(prefix = "sanctuary-exit-inspect-"): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), prefix));
    tempDirs.push(dir);
    return dir;
  }

  // ---- the report's shape and its stated bound ----------------------------

  it("names the declared bundle re-key key, and prints what it did NOT check", async () => {
    const source = await makeSource("inspect-source");
    const bundleDir = await newBundleDir("sanctuary-inspect-declares-");
    await exportBundle(source, bundleDir, { mint: true });

    const { chunks, out, err } = captureCli();
    const code = await runExitCommand({ argv: ["inspect", bundleDir], out, err });
    const printed = chunks.join("");
    expect(code).toBe(0);
    expect(printed).toContain("verdict: PASS");
    expect(printed).toContain("declares: bundle-rekey-key");
    expect(printed).toContain("state_entries: 1");
    expect(printed).toContain("namespaces: agent-memory");
    // The checkable runbook instruction, phrased as an attempt.
    expect(printed).toContain(
      "sanctuary exit import <dir> --activate --import-state " +
        "--source-recovery-key <bundle re-key key shown at export>"
    );
    // THE BOUND, asserted on the HAPPY path and by SUBSTANCE rather than by
    // prefix. A prefix assertion would let the sentence that names AES-GCM as
    // the real decider be deleted or softened without failing, which is exactly
    // how an overclaim gets back in.
    expect(printed).toContain("credential check: declaration and shape only");
    expect(printed).toContain("no credential was held and no import was attempted");
    expect(printed).toContain(
      "Whether the key you hold authenticates against that wrap is decided by " +
        "AES-GCM inside the import, and inspect does not and cannot answer it."
    );
    // The report must never promise an outcome it cannot know.
    expect(printed).not.toContain("will import");
    expect(printed).not.toContain("no key of any kind");
  });

  it("declares the legacy passphrase path when that is what the bundle carries", async () => {
    const source = await makeSource("inspect-legacy-source");
    const { params } = await deriveMasterKey(SOURCE_PASSPHRASE);
    await source.storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(params))
    );
    const bundleDir = await newBundleDir("sanctuary-inspect-legacy-");
    await exportBundle(source, bundleDir, { mint: false });

    const { chunks, out, err } = captureCli();
    const code = await runExitCommand({ argv: ["inspect", bundleDir], out, err });
    const printed = chunks.join("");
    expect(code).toBe(0);
    expect(printed).toContain("declares: legacy-passphrase");
    expect(printed).toContain("legacy_kdf_params: valid");
    expect(printed).toContain("--source-passphrase <source fortress passphrase>");
  });

  it("declares NOTHING for a bundle with neither block, and does not guess", async () => {
    // The pre-envelope shape. The recovery key IS the master for these, but the
    // artifact does not say so, so the report must not say so either - it names
    // the opt-in that makes the reading explicit and stops.
    const source = await makeSource("inspect-bare-source");
    const bundleDir = await newBundleDir("sanctuary-inspect-bare-");
    await exportBundle(source, bundleDir, { mint: false });

    const { chunks, out, err } = captureCli();
    const code = await runExitCommand({ argv: ["inspect", bundleDir], out, err });
    const printed = chunks.join("");
    expect(code).toBe(0);
    expect(printed).toContain("declares: none-declared");
    expect(printed).toContain("this bundle declares no re-key material");
    expect(printed).toContain("--legacy-source-master");
  });

  it("is READ-ONLY - it never touches fortress state or credentials", async () => {
    const source = await makeSource("inspect-readonly-source");
    const bundleDir = await newBundleDir("sanctuary-inspect-readonly-");
    await exportBundle(source, bundleDir, { mint: true });

    // No SANCTUARY_PASSPHRASE, no SANCTUARY_RECOVERY_KEY. `openExitContext`
    // would throw on that env; inspect must not call it at all.
    const { out, err } = captureCli();
    const code = await runExitCommand({
      argv: ["inspect", bundleDir],
      out,
      err,
      env: {},
    });
    expect(code).toBe(0);
  });

  it("requires a directory argument", async () => {
    const { chunks, out, err } = captureCli();
    const code = await runExitCommand({ argv: ["inspect"], out, err, env: {} });
    expect(code).toBe(2);
    expect(chunks.join("")).toContain("Usage: sanctuary exit inspect <dir>");
  });

  it("reports a non-bundle directory as an error, not a crash", async () => {
    const dir = await newBundleDir("sanctuary-inspect-notabundle-");
    const { chunks, out, err } = captureCli();
    const code = await runExitCommand({ argv: ["inspect", dir], out, err, env: {} });
    expect(code).toBe(1);
    expect(chunks.join("")).toContain("Not a valid SANCTUARY_EXIT_BUNDLE_V1 directory");
  });

  it("reports an UNREADABLE entries list as unreadable, never as an empty bundle", async () => {
    // The absent-as-benign conflation at the artifact level. The natural
    // narrowing (`Array.isArray(x) ? x : []`) reports zero entries and
    // `declares: no-state` - a confident, wrong "you need no credential" for an
    // artifact whose contents cannot be determined at all.
    const source = await makeSource("inspect-unreadable-source");
    const bundleDir = await newBundleDir("sanctuary-inspect-unreadable-");
    await exportBundle(source, bundleDir, { mint: true });
    await patchEncryptedStateAndResign(bundleDir, source, (artifact) => {
      delete artifact.entries;
    });

    const { chunks, out, err } = captureCli();
    const code = await runExitCommand({ argv: ["inspect", bundleDir], out, err });
    const printed = chunks.join("");
    expect(code).toBe(1);
    expect(printed).toContain("state_entries: unreadable");
    expect(printed).not.toContain("state_entries: 0");
    expect(printed).toContain("declares: damaged");
    expect(printed).toContain("no readable entries list");
    expect(printed).toContain("This is not an empty bundle.");
    expect(printed).not.toContain("declares: no-state");

    // And the import does not quietly agree that it is empty either. A bare
    // try/catch here (accepting ANY thrown value, including an unhandled
    // TypeError) previously masked LD2-01: `resolveSourceMasterKey` read
    // `entries.length` off the same unreadable field and crashed rather than
    // refusing cleanly. Asserting the NAMED, typed error code is what proves
    // import fails CLOSED here, not just that it fails somehow.
    const destination = await makeDestination();
    await expect(
      importExitBundle({
        bundleDir,
        storage: destination.storage,
        masterKey: destination.masterKey,
        identityManager: destination.identityManager,
        auditLog: destination.auditLog,
        reputationStore: destination.reputationStore,
        activate: true,
        forceRebind: true,
        sourceMasterKey: source.masterKey,
        destinationSignerIdentityId: destination.identityId,
      })
    ).rejects.toMatchObject({ code: "ENCRYPTED_STATE_ENTRIES_UNREADABLE" });
  });

  it("declares no-state for a genuinely empty bundle, and says the entry list was readable", async () => {
    // The control for the case above: `no-state` must stay reachable, or the
    // unreadable fix would have been a blanket downgrade rather than a
    // distinction.
    const source = await makeSource("inspect-empty-source");
    const bundleDir = await newBundleDir("sanctuary-inspect-empty-");
    await exportBundle(source, bundleDir, { mint: true });
    await patchEncryptedStateAndResign(bundleDir, source, (artifact) => {
      artifact.entries = [];
      // F3 (Exit V2 drill D1): total_keys must agree with the readable
      // entries count, or checkEncryptedStateStructure now reports
      // total_keys_mismatch instead of a genuinely empty, internally
      // consistent bundle - which is exactly this test's point. makeSource
      // seeds one state entry, so the pre-truncation export set
      // total_keys: 1; a genuinely empty bundle must also zero this out.
      artifact.total_keys = 0;
      artifact.empty_reason = "fortress_state_empty";
    });

    const { chunks, out, err } = captureCli();
    const code = await runExitCommand({ argv: ["inspect", bundleDir], out, err });
    const printed = chunks.join("");
    expect(code).toBe(0);
    expect(printed).toContain("state_entries: 0");
    expect(printed).toContain("declares: no-state");
    expect(printed).toContain("its entry list is readable and empty");
  });

  /**
   * What `exit inspect` is allowed to REPORT about a `source_custody` block,
   * holding NO credential, and what the import must do with the same block.
   *
   *  - `opens`: the block has a usable shape and the real re-key key imports
   *    it. Inspect must report `declares: bundle-rekey-key`.
   *  - `malformed`: the block has no usable shape, so the import gate refuses
   *    it (SOURCE_CUSTODY_MALFORMED) on the SAME predicate inspect classified
   *    with. Inspect reports `declares: damaged` and exits non-zero.
   *  - `credential-dependent`: the block is structurally everything that can be
   *    checked without a secret, and only the secret decides. Inspect names the
   *    declared material AND must state that bound; import with the
   *    right-shaped-but-non-authenticating wrap fails SOURCE_CREDENTIAL_INVALID.
   *    This row is the honest edge of the tool, not a hole in it.
   */
  type CustodyOutcome = "opens" | "malformed" | "credential-dependent";

  /** Replace the single minted wrap's payload, leaving the rest of the block. */
  function withPayload(
    real: Record<string, unknown>,
    patch: (payload: Record<string, unknown>) => unknown
  ): unknown {
    const wrap = { ...((real.wraps as Record<string, unknown>[])[0] ?? {}) };
    const payload = { ...(wrap.payload as Record<string, unknown>) };
    const replacement = patch(payload);
    if (replacement === undefined) delete wrap.payload;
    else wrap.payload = replacement;
    return { ...real, wraps: [wrap] };
  }

  /** A base64url string that decodes to exactly `n` bytes. */
  function b64OfLength(n: number): string {
    return toBase64url(new Uint8Array(n).fill(0x41));
  }

  /**
   * Every way a `source_custody` block can be damaged, plus the untouched
   * control. Each case is applied to a REAL minted bundle and re-signed, so the
   * only thing under test is the block itself.
   *
   * The table is the enumeration of the equivalence class, not a list of
   * reported bugs: block shape, wrap shape, and then EVERY field the unwrap
   * path (`core/master-custody.ts` unwrapMatchingWrap -> `core/encryption.ts`
   * decrypt) actually reads, in each way it can be wrong - absent, wrong type,
   * wrong constant, undecodable, wrong decoded length.
   *
   * Every payload row below mutates a SINGLE-wrap block, where "some wrap is
   * openable" and "every wrap is openable" coincide - which is exactly why the
   * round-3 regression survived a table of them. The multi-wrap rows are what
   * separate the two quantifiers, and they are marked as such.
   *
   * FAILURE MODE if a case is written wrong: a mutation that leaves the block
   * VALID makes the case assert the happy path twice and prove nothing. The
   * `opens` rows are what keep the whole table honest - if the classifier ever
   * degenerates to "everything is unusable", every one of them fails. Three of
   * them mutate fields the unwrap path never reads (`ts`, `verified`,
   * `created_at`) or duplicate a wrap id, precisely so an over-strict predicate
   * that validates the DECLARED type instead of the CONSUMED fields is caught.
   */
  const custodyCases: Array<{
    label: string;
    /** Returns the replacement block, given the real minted one. */
    mutate: (real: Record<string, unknown>) => unknown;
    outcome: CustodyOutcome;
  }> = [
    // ---- block shape ----
    {
      label: "valid custody (control)",
      mutate: (real) => real,
      outcome: "opens",
    },
    {
      label: "wrong format token",
      mutate: (real) => ({ ...real, format: "SANCTUARY_EXIT_SOURCE_CUSTODY_V2" }),
      outcome: "malformed",
    },
    {
      label: "format field missing entirely",
      mutate: (real) => ({ wraps: real.wraps }),
      outcome: "malformed",
    },
    {
      label: "wraps is not an array",
      mutate: (real) => ({ ...real, wraps: { id: "w1" } }),
      outcome: "malformed",
    },
    {
      label: "wraps is empty",
      mutate: (real) => ({ ...real, wraps: [] }),
      outcome: "malformed",
    },
    {
      label: "more wraps than the cap allows",
      // 5 > SOURCE_CUSTODY_MAX_WRAPS (4). The cap bounds unwrap work on a
      // crafted bundle; a classifier that ignores it advertises a re-key path
      // the import gate will refuse.
      mutate: (real) => ({
        ...real,
        wraps: Array.from({ length: 5 }, () => (real.wraps as unknown[])[0]),
      }),
      outcome: "malformed",
    },
    {
      label: "source_custody is null",
      mutate: () => null,
      outcome: "malformed",
    },
    // ---- wrap shape ----
    {
      label: "passphrase-type wrap smuggled in",
      // The security-relevant case: a passphrase wrap here would reintroduce
      // the offline guessing oracle and feed bundle-controlled Argon2id
      // parameters into the unwrap path. Import refuses it, so inspect must
      // never present it as an openable bundle.
      mutate: (real) => ({
        ...real,
        wraps: [
          {
            ...((real.wraps as Record<string, unknown>[])[0] ?? {}),
            type: "passphrase",
          },
        ],
      }),
      outcome: "malformed",
    },
    {
      label: "wrap missing its id",
      mutate: (real) => {
        const wrap = { ...((real.wraps as Record<string, unknown>[])[0] ?? {}) };
        delete wrap.id;
        return { ...real, wraps: [wrap] };
      },
      outcome: "malformed",
    },
    // ---- wrap payload container ----
    {
      label: "wrap payload is null",
      // `typeof null === "object"`, which is exactly how the round-2 predicate
      // let this through while import died on `payload.v`.
      mutate: (real) => withPayload(real, () => null),
      outcome: "malformed",
    },
    {
      label: "wrap payload is an array",
      mutate: (real) => withPayload(real, () => []),
      outcome: "malformed",
    },
    {
      label: "wrap payload is a string",
      mutate: (real) => withPayload(real, () => "not-a-payload"),
      outcome: "malformed",
    },
    {
      label: "wrap payload missing entirely",
      mutate: (real) => withPayload(real, () => undefined),
      outcome: "malformed",
    },
    // ---- payload version / algorithm ----
    {
      label: "payload version missing",
      mutate: (real) =>
        withPayload(real, (payload) => {
          delete payload.v;
          return payload;
        }),
      outcome: "malformed",
    },
    {
      label: "payload version is 2",
      mutate: (real) => withPayload(real, (payload) => ({ ...payload, v: 2 })),
      outcome: "malformed",
    },
    {
      label: "payload version is the string \"1\"",
      // decrypt compares with `!==`, so "1" is a different value, not a
      // coercible one. A predicate using `==` would wrongly pass this.
      mutate: (real) => withPayload(real, (payload) => ({ ...payload, v: "1" })),
      outcome: "malformed",
    },
    {
      label: "payload alg missing",
      mutate: (real) =>
        withPayload(real, (payload) => {
          delete payload.alg;
          return payload;
        }),
      outcome: "malformed",
    },
    {
      label: "payload alg is aes-128-gcm",
      mutate: (real) =>
        withPayload(real, (payload) => ({ ...payload, alg: "aes-128-gcm" })),
      outcome: "malformed",
    },
    // ---- payload iv ----
    {
      label: "payload iv missing",
      mutate: (real) =>
        withPayload(real, (payload) => {
          delete payload.iv;
          return payload;
        }),
      outcome: "malformed",
    },
    {
      label: "payload iv is a number",
      mutate: (real) => withPayload(real, (payload) => ({ ...payload, iv: 12 })),
      outcome: "malformed",
    },
    {
      label: "payload iv is empty",
      mutate: (real) => withPayload(real, (payload) => ({ ...payload, iv: "" })),
      outcome: "malformed",
    },
    {
      label: "payload iv decodes below the GCM nonce floor",
      // 6 < 8. `fromBase64url` is lenient, so the ONLY observable defect is the
      // decoded byte count; the AES-GCM construction refuses it outright.
      mutate: (real) =>
        withPayload(real, (payload) => ({ ...payload, iv: b64OfLength(6) })),
      outcome: "malformed",
    },
    {
      label: "payload iv is not base64url at all",
      // Lenient decoding drops every out-of-alphabet character, so this decodes
      // to zero bytes rather than throwing - a classifier that only checks
      // `typeof iv === "string"` sees nothing wrong.
      mutate: (real) =>
        withPayload(real, (payload) => ({ ...payload, iv: "!!!!" })),
      outcome: "malformed",
    },
    // ---- payload ciphertext ----
    {
      label: "payload ct missing",
      mutate: (real) =>
        withPayload(real, (payload) => {
          delete payload.ct;
          return payload;
        }),
      outcome: "malformed",
    },
    {
      label: "payload ct is a number",
      mutate: (real) => withPayload(real, (payload) => ({ ...payload, ct: 0 })),
      outcome: "malformed",
    },
    {
      label: "payload ct is empty",
      mutate: (real) => withPayload(real, (payload) => ({ ...payload, ct: "" })),
      outcome: "malformed",
    },
    {
      label: "payload ct is one byte short of master+tag",
      mutate: (real) =>
        withPayload(real, (payload) => ({ ...payload, ct: b64OfLength(47) })),
      outcome: "malformed",
    },
    {
      label: "payload ct is longer than master+tag",
      mutate: (real) =>
        withPayload(real, (payload) => ({ ...payload, ct: b64OfLength(64) })),
      outcome: "malformed",
    },
    // ---- structurally perfect, only the credential can tell ----
    {
      label: "payload ct is the right length but does not authenticate",
      // THE BOUND. Nothing readable without the re-key key distinguishes this
      // from the control; only GCM authentication does. Inspect must still name
      // the re-key path and must say, in its own output, that it checked shape
      // and not the key.
      mutate: (real) =>
        withPayload(real, (payload) => ({ ...payload, ct: b64OfLength(48) })),
      outcome: "credential-dependent",
    },
    // ---- fields the unwrap path never reads: must NOT be rejected ----
    {
      label: "payload ts removed (never read by decrypt)",
      mutate: (real) =>
        withPayload(real, (payload) => {
          delete payload.ts;
          return payload;
        }),
      outcome: "opens",
    },
    {
      label: "wrap verified/created_at removed (never read by unwrap)",
      mutate: (real) => {
        const wrap = { ...((real.wraps as Record<string, unknown>[])[0] ?? {}) };
        delete wrap.verified;
        delete wrap.created_at;
        return { ...real, wraps: [wrap] };
      },
      outcome: "opens",
    },
    {
      label: "one intact wrap and one damaged wrap",
      // THE ROUND-3 REGRESSION, now a permanent row. `unwrapMatchingWrap`
      // returns on the first wrap that authenticates and never reaches the
      // second, so this bundle imports. A predicate demanding EVERY wrap be
      // openable was shared with the import gate and turned this exact bundle
      // into SOURCE_CUSTODY_MALFORMED - a new, unrecoverable refusal on the
      // exit path. `payload: null` specifically, because that is the shape a
      // per-wrap payload check rejects.
      mutate: (real) => {
        const wrap = (real.wraps as Record<string, unknown>[])[0]!;
        return {
          ...real,
          wraps: [wrap, { ...wrap, id: "second-wrap", payload: null }],
        };
      },
      outcome: "opens",
    },
    {
      label: "one DAMAGED wrap listed before the intact one",
      // The same regression with the order reversed, so the tolerance cannot
      // be satisfied by an implementation that merely checks the FIRST wrap.
      mutate: (real) => {
        const wrap = (real.wraps as Record<string, unknown>[])[0]!;
        return {
          ...real,
          wraps: [{ ...wrap, id: "damaged-first", payload: null }, wrap],
        };
      },
      outcome: "opens",
    },
    {
      label: "a passphrase wrap smuggled in BESIDE an intact recovery-key wrap",
      // The counterweight to the two rows above, so the tolerance cannot be
      // read as "the gate stopped caring". The recovery-key-only rule is
      // genuinely per-wrap: one smuggled passphrase wrap reopens the offline
      // guessing oracle on its own, so "some wrap is safe" is not a safety
      // claim about the block.
      mutate: (real) => {
        const wrap = (real.wraps as Record<string, unknown>[])[0]!;
        return {
          ...real,
          wraps: [wrap, { ...wrap, id: "passphrase-wrap", type: "passphrase" }],
        };
      },
      outcome: "malformed",
    },
    {
      label: "ciphertext carries a newline the lenient decoder drops",
      // Adversarial, and the reason this file decodes with `fromBase64url` and
      // not `fromBase64urlStrict`: Node's base64 decoder silently drops
      // whitespace, so this still decodes to the same 48 real bytes and the
      // import opens it. A predicate that decoded STRICTLY would report
      // `unusable` for a bundle that works - the same disagreement, inverted.
      mutate: (real) => {
        const wrap = { ...((real.wraps as Record<string, unknown>[])[0] ?? {}) };
        const payload = { ...(wrap.payload as Record<string, unknown>) };
        const ct = payload.ct as string;
        payload.ct = ct.slice(0, 10) + "\n" + ct.slice(10);
        wrap.payload = payload;
        return { ...real, wraps: [wrap] };
      },
      outcome: "opens",
    },
    {
      label: "a non-authenticating wrap listed BEFORE the real one",
      // Adversarial: `unwrapMatchingWrap` walks wraps in order and returns on
      // the first that authenticates, so a decoy in front does not stop the
      // import. Inspect must not treat "some wrap is a decoy" as unusable.
      mutate: (real) => {
        const wrap = (real.wraps as Record<string, unknown>[])[0]!;
        const decoy = {
          ...wrap,
          id: "decoy-wrap",
          payload: {
            ...(wrap.payload as Record<string, unknown>),
            ct: b64OfLength(48),
          },
        };
        return { ...real, wraps: [decoy, wrap] };
      },
      outcome: "opens",
    },
    {
      label: "wrap id rewritten so no AAD can match",
      // Adversarial, and a SECOND member of the credential-dependent class with
      // a different mechanism than a corrupted ciphertext: the id is bound into
      // the AEAD's associated data, so rewriting it breaks authentication while
      // leaving every readable field perfect. Nothing without the key can tell
      // this from the control, and inspect must not pretend otherwise.
      mutate: (real) => ({
        ...real,
        wraps: [
          {
            ...((real.wraps as Record<string, unknown>[])[0] ?? {}),
            id: "rewritten-wrap-id",
          },
        ],
      }),
      outcome: "credential-dependent",
    },
    {
      label: "the same wrap listed twice (duplicate ids)",
      // Enumerated and DELIBERATELY not rejected: `unwrapMatchingWrap` tries
      // wraps in order and the first one authenticates, so a duplicate id does
      // not stop an import. Rejecting it would make inspect say "unusable"
      // about a bundle that opens - the same disagreement, mirrored.
      mutate: (real) => ({
        ...real,
        wraps: [(real.wraps as unknown[])[0], (real.wraps as unknown[])[0]],
      }),
      outcome: "opens",
    },
  ];


  for (const custodyCase of custodyCases) {
    it(`differential: inspect and import never contradict on "${custodyCase.label}"`, async () => {
      const source = await makeSource("differential-source");
      const bundleDir = await newBundleDir("sanctuary-inspect-diff-");
      const exported = await exportBundle(source, bundleDir, { mint: true });
      const rekeyKey = exported.state_rekey_key!;
      expect(rekeyKey).toBeDefined();

      const artifactPath = join(bundleDir, "artifacts", "encrypted_state.json");
      const realCustody = (
        JSON.parse(await readFile(artifactPath, "utf8")) as {
          source_custody: Record<string, unknown>;
        }
      ).source_custody;
      await patchEncryptedStateAndResign(bundleDir, source, (artifact) => {
        artifact.source_custody = custodyCase.mutate(realCustody);
      });

      // What the operator is told, read-only, with the source fortress gone.
      const { chunks, out, err } = captureCli();
      const inspectCode = await runExitCommand({
        argv: ["inspect", bundleDir],
        out,
        err,
      });
      const printed = chunks.join("");

      // What actually happens when they try it, with the real re-key key.
      const destination = await makeDestination();
      let importCode: string | undefined;
      let importSucceeded = false;
      try {
        const result = await importExitBundle({
          bundleDir,
          storage: destination.storage,
          masterKey: destination.masterKey,
          identityManager: destination.identityManager,
          auditLog: destination.auditLog,
          reputationStore: destination.reputationStore,
          activate: true,
          forceRebind: true,
          sourceRecoveryKey: rekeyKey,
          destinationSignerIdentityId: destination.identityId,
        });
        importSucceeded = result.state.status === "rekeyed";
      } catch (e) {
        importCode = (e as { code?: string }).code;
      }

      // THE ASSERTION: the report and the reality never contradict. Inspect is
      // not required to predict the import - it is required never to describe a
      // block as usable that the shared gate refuses, and never to call a block
      // damaged that the gate accepts.
      if (custodyCase.outcome === "opens") {
        expect(importSucceeded).toBe(true);
        expect(printed).toContain("declares: bundle-rekey-key");
        expect(printed).toContain("source_custody: valid");
        expect(printed).not.toContain("declares: damaged");
        expect(inspectCode).toBe(0);
        return;
      }

      if (custodyCase.outcome === "credential-dependent") {
        // Inspect still names the declared material (it cannot know better),
        // and the import fails on AUTHENTICATION, not on shape. The two are
        // only consistent because inspect states the limit in its own output;
        // an unqualified "bundle-rekey-key" here would be the original
        // overclaim, so the bound is asserted by substance.
        expect(importSucceeded).toBe(false);
        expect(importCode).toBe("SOURCE_CREDENTIAL_INVALID");
        expect(printed).toContain("declares: bundle-rekey-key");
        expect(printed).toContain("source_custody: valid");
        expect(printed).toContain(
          "credential check: declaration and shape only"
        );
        expect(printed).toContain(
          "Whether the key you hold authenticates against that wrap is decided " +
            "by AES-GCM inside the import, and inspect does not and cannot " +
            "answer it."
        );
        expect(inspectCode).toBe(0);
        return;
      }

      expect(importSucceeded).toBe(false);
      expect(importCode).toBe("SOURCE_CUSTODY_MALFORMED");
      // Not merely "not bundle-rekey-key": the report must name the damaged
      // block so the operator knows what to re-export, and must exit non-zero
      // so a script can branch on it.
      expect(printed).toContain("declares: damaged");
      expect(printed).toContain("source_custody: malformed");
      expect(printed).toContain(
        "re-key block (source_custody) does not have a usable shape"
      );
      expect(inspectCode).toBe(1);
    });
  }

  it("scope pin: a programmatic sourceMasterKey import is OUTSIDE what this report describes", async () => {
    // `resolveSourceMasterKey` returns `opts.sourceMasterKey` BEFORE
    // `validateSourceCustody`, so this import succeeds on a bundle whose custody
    // block inspect calls damaged. That is not a contradiction under the current
    // wording - inspect says the BLOCK has no usable shape, which is true, and
    // says nothing about whether some other credential path exists. It WOULD
    // have been a contradiction under the old `credential: unusable` /
    // "no key of any kind opens this bundle" wording, which is why that wording
    // is gone and why this test asserts its absence.
    const source = await makeSource("scope-pin-source");
    const bundleDir = await newBundleDir("sanctuary-inspect-scopepin-");
    await exportBundle(source, bundleDir, { mint: true });
    await patchEncryptedStateAndResign(bundleDir, source, (artifact) => {
      const custody = artifact.source_custody as Record<string, unknown>;
      const wrap = { ...((custody.wraps as Record<string, unknown>[])[0] ?? {}) };
      wrap.payload = null;
      artifact.source_custody = { ...custody, wraps: [wrap] };
    });

    const { chunks, out, err } = captureCli();
    const inspectCode = await runExitCommand({ argv: ["inspect", bundleDir], out, err });
    const printed = chunks.join("");
    expect(inspectCode).toBe(1);
    expect(printed).toContain("declares: damaged");
    expect(printed).not.toMatch(/no key of any kind/i);
    expect(printed).not.toMatch(/cannot be re-keyed/i);

    // No CLI flag reaches this option; only a programmatic caller can.
    const cliSource = await readFile(
      new URL("../../src/exit/cli.ts", import.meta.url),
      "utf8"
    );
    expect(cliSource).not.toContain("sourceMasterKey");

    const destination = await makeDestination();
    const result = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: true,
      forceRebind: true,
      sourceMasterKey: source.masterKey,
      destinationSignerIdentityId: destination.identityId,
    });
    expect(result.state.status).toBe("rekeyed");
    expect(result.state.imported_keys).toBeGreaterThan(0);
  });

  it("a damaged custody block is reported even when a usable legacy marker exists", async () => {
    // Import validates custody BEFORE it looks at anything else, so a damaged
    // block kills the legacy passphrase path with it. A classifier that read the
    // legacy marker first would print a passphrase command that cannot run.
    const source = await makeSource("outrank-source");
    const { params } = await deriveMasterKey(SOURCE_PASSPHRASE);
    await source.storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(params))
    );
    const bundleDir = await newBundleDir("sanctuary-inspect-outrank-");
    await exportBundle(source, bundleDir, { mint: true });
    await patchEncryptedStateAndResign(bundleDir, source, (artifact) => {
      artifact.source_custody = { format: "nope", wraps: [] };
    });

    const { chunks, out, err } = captureCli();
    const code = await runExitCommand({ argv: ["inspect", bundleDir], out, err });
    const printed = chunks.join("");
    expect(printed).toContain("legacy_kdf_params: valid");
    expect(printed).toContain("declares: damaged");
    expect(printed).toContain(
      "re-key block (source_custody) does not have a usable shape"
    );
    expect(code).toBe(1);

    const destination = await makeDestination();
    await expect(
      importExitBundle({
        bundleDir,
        storage: destination.storage,
        masterKey: destination.masterKey,
        identityManager: destination.identityManager,
        auditLog: destination.auditLog,
        reputationStore: destination.reputationStore,
        activate: true,
        forceRebind: true,
        sourcePassphrase: SOURCE_PASSPHRASE,
        destinationSignerIdentityId: destination.identityId,
      })
    ).rejects.toMatchObject({ code: "SOURCE_CUSTODY_MALFORMED" });
  });
});
