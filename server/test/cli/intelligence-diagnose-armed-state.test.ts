/**
 * `sanctuary intelligence diagnose` armed-state reporting (R2-F3).
 *
 * The verb used to print a directory listing, audit filenames, and env-var
 * presence, none of which can answer "is local intelligence armed, and to
 * which model". These tests drive the real ceremony against a real filesystem
 * fortress, then assert that diagnose reports the SAME classification the
 * runtime's load path produces, in both the human and `--json` renderings, for
 * an armed record, a record this build cannot verify, an absent record, and an
 * unreadable one.
 */

import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { describe, expect, it, vi } from "vitest";

import { stringToBytes } from "../../src/core/encoding.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { deriveMasterKey } from "../../src/core/key-derivation.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { runLocalIntelligenceSetup } from "../../src/wrap/local-intelligence.js";
import { runIntelligenceCommand, type DiagnoseDeps } from "../../src/cli/intelligence.js";
import {
  CATALOG_PUBLIC_KEY,
  FIXTURE_MANIFEST_DIGEST,
  FIXTURE_MANIFEST_VERSION,
  FIXTURE_RUNTIME_TAG,
  OTHER_CATALOG_PUBLIC_KEY,
  armedCeremonyDeps,
} from "../intelligence/__fixtures__/armed-local-intelligence.js";

/**
 * Test seam for the credential chokepoint. Hands back a COPY: diagnose zeroes
 * the master it is given, so a shared buffer would blank the fixture's key.
 */
function unlockWith(masterKey: Uint8Array): DiagnoseDeps["unlock"] {
  return (async () => ({
    ok: true as const,
    masterKey: new Uint8Array(masterKey),
    source: "env-passphrase" as const,
  })) as DiagnoseDeps["unlock"];
}

async function withFortress(
  run: (fortress: {
    storagePath: string;
    storage: FilesystemStorage;
    masterKey: Uint8Array;
  }) => Promise<void>,
): Promise<void> {
  const storagePath = await mkdtemp(join(tmpdir(), "sanctuary-diagnose-armed-"));
  try {
    await run({
      storagePath,
      storage: new FilesystemStorage(join(storagePath, "state")),
      masterKey: generateRandomKey(),
    });
  } finally {
    await rm(storagePath, { recursive: true, force: true }).catch(() => {});
  }
}

async function arm(fortress: {
  storagePath: string;
  storage: FilesystemStorage;
  masterKey: Uint8Array;
}): Promise<string[]> {
  const print = vi.fn();
  const outcome = await runLocalIntelligenceSetup({
    storage: fortress.storage,
    masterKey: fortress.masterKey,
    auditLog: new AuditLog(fortress.storage, fortress.masterKey),
    identityId: "diagnose-fixture",
    isTty: true,
    print,
  }, armedCeremonyDeps());
  expect(outcome.kind).toBe("already-provisioned");
  return print.mock.calls.map((call) => String(call[0]));
}

function captureStreams(): { err: () => string; out: () => string } {
  const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  const outSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  return {
    err: () => errSpy.mock.calls.map((call) => call.join(" ")).join("\n"),
    out: () => outSpy.mock.calls.map((call) => call.join(" ")).join("\n"),
  };
}

describe("sanctuary intelligence diagnose armed-state reporting (R2-F3)", () => {
  it("prints the verification and armed lines from the ceremony itself", async () => {
    await withFortress(async (fortress) => {
      const printed = await arm(fortress);
      expect(printed).toContain(
        `Verified signed model manifest v${FIXTURE_MANIFEST_VERSION} against the pinned catalog key.`,
      );
      expect(printed).toContain(
        `Local intelligence armed: ${FIXTURE_RUNTIME_TAG} (manifest sha256 ${FIXTURE_MANIFEST_DIGEST.slice(0, 12)})`,
      );
    });
  });

  it("reports an armed record with its manifest version, model tag, and digests", async () => {
    await withFortress(async (fortress) => {
      await arm(fortress);
      const streams = captureStreams();
      const code = await runIntelligenceCommand({
        argv: ["diagnose", "--fortress", fortress.storagePath],
        diagnoseDeps: {
          unlock: unlockWith(fortress.masterKey),
          modelManifestV2PublicKey: CATALOG_PUBLIC_KEY,
        },
      });
      expect(code).toBe(0);
      const human = streams.err();
      expect(human).toContain("Local intelligence: armed");
      expect(human).toContain(`model manifest version: ${FIXTURE_MANIFEST_VERSION}`);
      expect(human).toContain(`concierge: ${FIXTURE_RUNTIME_TAG}`);
      expect(human).toContain(`ollama manifest sha256 ${FIXTURE_MANIFEST_DIGEST}`);
      expect(human).toMatch(/manifest body sha256: [0-9a-f]{64}/);
      vi.restoreAllMocks();

      const jsonStreams = captureStreams();
      await runIntelligenceCommand({
        argv: ["diagnose", "--json", "--fortress", fortress.storagePath],
        diagnoseDeps: {
          unlock: unlockWith(fortress.masterKey),
          modelManifestV2PublicKey: CATALOG_PUBLIC_KEY,
        },
      });
      const parsed = JSON.parse(jsonStreams.out()) as {
        local_intelligence: {
          state: string;
          manifest_version: number;
          signed_body_sha256: string;
          bindings: Array<{ surface: string; runtime_tag: string; ollama_manifest_sha256: string }>;
        };
      };
      expect(parsed.local_intelligence.state).toBe("armed");
      expect(parsed.local_intelligence.manifest_version).toBe(FIXTURE_MANIFEST_VERSION);
      expect(parsed.local_intelligence.signed_body_sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(parsed.local_intelligence.bindings).toContainEqual(
        expect.objectContaining({
          surface: "concierge",
          runtime_tag: FIXTURE_RUNTIME_TAG,
          ollama_manifest_sha256: FIXTURE_MANIFEST_DIGEST,
        }),
      );
      vi.restoreAllMocks();
    });
  });

  it("reports a record this build cannot verify as integrity_state_invalid, never as armed", async () => {
    await withFortress(async (fortress) => {
      await arm(fortress);
      const streams = captureStreams();
      await runIntelligenceCommand({
        argv: ["diagnose", "--json", "--fortress", fortress.storagePath],
        diagnoseDeps: {
          unlock: unlockWith(fortress.masterKey),
          // A different catalog root: the same bytes no longer verify.
          modelManifestV2PublicKey: OTHER_CATALOG_PUBLIC_KEY,
        },
      });
      const parsed = JSON.parse(streams.out()) as {
        local_intelligence: { state: string; detail: string; bindings: unknown[] };
      };
      expect(parsed.local_intelligence.state).toBe("integrity_state_invalid");
      expect(parsed.local_intelligence.detail).toContain("Q5 integrity validation");
      expect(parsed.local_intelligence.bindings).toEqual([]);
      vi.restoreAllMocks();

      const humanStreams = captureStreams();
      await runIntelligenceCommand({
        argv: ["diagnose", "--fortress", fortress.storagePath],
        diagnoseDeps: {
          unlock: unlockWith(fortress.masterKey),
          modelManifestV2PublicKey: OTHER_CATALOG_PUBLIC_KEY,
        },
      });
      expect(humanStreams.err()).toContain("Local intelligence: integrity_state_invalid");
      vi.restoreAllMocks();
    });
  });

  it("reports an absent record as absent and names the opt-in flag", async () => {
    await withFortress(async (fortress) => {
      // Touch the fortress so the state directory exists without a record.
      await fortress.storage.write("_meta", "probe", stringToBytes("{}"));
      const streams = captureStreams();
      await runIntelligenceCommand({
        argv: ["diagnose", "--fortress", fortress.storagePath],
        diagnoseDeps: { unlock: unlockWith(fortress.masterKey) },
      });
      const human = streams.err();
      expect(human).toContain("Local intelligence: absent");
      expect(human).toContain("--provision-local-intelligence");
      vi.restoreAllMocks();
    });
  });

  it("reports an unreadable record as corrupt and names the config-reset verb", async () => {
    await withFortress(async (fortress) => {
      await fortress.storage.write(
        "_intelligence",
        "substrate-config",
        stringToBytes("not an encrypted record"),
      );
      const streams = captureStreams();
      await runIntelligenceCommand({
        argv: ["diagnose", "--json", "--fortress", fortress.storagePath],
        diagnoseDeps: { unlock: unlockWith(fortress.masterKey) },
      });
      const parsed = JSON.parse(streams.out()) as {
        local_intelligence: { state: string; remedy: string };
      };
      expect(parsed.local_intelligence.state).toBe("corrupt");
      expect(parsed.local_intelligence.remedy).toContain(
        "sanctuary intelligence config-reset",
      );
      vi.restoreAllMocks();
    });
  });

  it("says unavailable, not unarmed, when no fortress credential is reachable", async () => {
    await withFortress(async (fortress) => {
      await arm(fortress);
      const streams = captureStreams();
      await runIntelligenceCommand({
        argv: ["diagnose", "--json", "--fortress", fortress.storagePath],
        diagnoseDeps: {
          unlock: (async () => ({
            ok: false as const,
            failure: "locked" as const,
            message: "the OS keyring is locked in this session",
          })) as DiagnoseDeps["unlock"],
        },
      });
      const parsed = JSON.parse(streams.out()) as {
        local_intelligence: { state: string; credential_failure: string };
      };
      expect(parsed.local_intelligence.state).toBe("unavailable");
      expect(parsed.local_intelligence.credential_failure).toBe("locked");
      vi.restoreAllMocks();
    });
  });
});

/**
 * Properties the armed-state section must hold no matter what the record says:
 * it changes nothing, it forwards no underlying credential error text, its
 * machine-readable verdict follows the classification, and a record it could
 * not read is never reported as one that does not exist.
 */
const LEGACY_PASSPHRASE = "diagnose-legacy-fortress-passphrase-not-a-real-secret";

describe("sanctuary intelligence diagnose is read-only and closed-vocabulary (R2-F3)", () => {
  /** sha256 of every file under the fortress, keyed by relative path. */
  async function snapshot(root: string): Promise<Record<string, string>> {
    const out: Record<string, string> = {};
    const walk = async (dir: string): Promise<void> => {
      for (const entry of await readdir(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name);
        if (entry.isDirectory()) {
          await walk(full);
          continue;
        }
        out[relative(root, full)] = createHash("sha256")
          .update(await readFile(full))
          .digest("hex");
      }
    };
    await walk(root);
    return out;
  }

  it("leaves the fortress byte-for-byte unchanged", async () => {
    await withFortress(async (fortress) => {
      await arm(fortress);
      const before = await snapshot(fortress.storagePath);
      expect(Object.keys(before).length).toBeGreaterThan(0);
      const streams = captureStreams();
      for (const argv of [
        ["diagnose", "--fortress", fortress.storagePath],
        ["diagnose", "--json", "--fortress", fortress.storagePath],
      ]) {
        await runIntelligenceCommand({
          argv,
          diagnoseDeps: {
            unlock: unlockWith(fortress.masterKey),
            modelManifestV2PublicKey: CATALOG_PUBLIC_KEY,
          },
        });
      }
      vi.restoreAllMocks();
      // Reporting state must never change it: no quarantine, no custody
      // migration, no config rewrite, not even a touched timestamp file.
      expect(await snapshot(fortress.storagePath)).toEqual(before);
      expect(streams.err()).toContain("Local intelligence: armed");
    });
  });

  it("asks the unlock chokepoint for a read-only session", async () => {
    await withFortress(async (fortress) => {
      await arm(fortress);
      const unlock = vi.fn(async () => ({
        ok: true as const,
        masterKey: new Uint8Array(fortress.masterKey),
        source: "env-passphrase" as const,
      })) as unknown as DiagnoseDeps["unlock"];
      const streams = captureStreams();
      await runIntelligenceCommand({
        argv: ["diagnose", "--fortress", fortress.storagePath],
        diagnoseDeps: { unlock, modelManifestV2PublicKey: CATALOG_PUBLIC_KEY },
      });
      vi.restoreAllMocks();
      // The intent is declared at the chokepoint, not merely implied by which
      // functions this verb happens to call today.
      expect(vi.mocked(unlock!).mock.calls[0]![0]).toMatchObject({
        readOnly: true,
      });
      expect(vi.mocked(unlock!).mock.calls[0]![0]).not.toHaveProperty(
        "writeIntent",
        true,
      );
      expect(streams.err()).toContain("Local intelligence: armed");
    });
  });

  it("projects only the closed credential-failure code, never the underlying message", async () => {
    const sentinel = "SENTINEL-credential-detail-must-not-be-printed";
    await withFortress(async (fortress) => {
      await arm(fortress);
      const deps: DiagnoseDeps = {
        unlock: (async () => ({
          ok: false as const,
          failure: "mismatch" as const,
          // A remediation string written for a different audience: it can name
          // the fortress path, and it is where an underlying Error.message or
          // cause would travel.
          message: `custody unlock failed: ${sentinel}`,
        })) as DiagnoseDeps["unlock"],
      };
      const streams = captureStreams();
      await runIntelligenceCommand({
        argv: ["diagnose", "--json", "--fortress", fortress.storagePath],
        diagnoseDeps: deps,
      });
      const jsonOut = streams.out();
      const jsonErr = streams.err();
      vi.restoreAllMocks();

      const humanStreams = captureStreams();
      await runIntelligenceCommand({
        argv: ["diagnose", "--fortress", fortress.storagePath],
        diagnoseDeps: deps,
      });
      const humanErr = humanStreams.err();
      vi.restoreAllMocks();

      for (const text of [jsonOut, jsonErr, humanErr]) {
        expect(text).not.toContain(sentinel);
      }
      const parsed = JSON.parse(jsonOut) as {
        local_intelligence: { state: string; credential_failure: string; remedy: string };
      };
      expect(parsed.local_intelligence.state).toBe("unavailable");
      expect(parsed.local_intelligence.credential_failure).toBe("mismatch");
      expect(parsed.local_intelligence.remedy).toContain("SANCTUARY_PASSPHRASE");
      expect(humanErr).toContain("Local intelligence: unavailable (mismatch");
    });
  });

  /**
   * A pre-envelope fortress: key-params and no custody envelope. Failure mode
   * to expect if this fixture drifts: with no `key-params` marker the unlock
   * refuses with "absent" (a genuine credential answer) and the test would
   * assert the migration rendering against the wrong state.
   */
  async function seedLegacyFortress(): Promise<{
    storagePath: string;
    storage: FilesystemStorage;
    cleanup: () => Promise<void>;
  }> {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-diagnose-legacy-"));
    const storagePath = join(dir, ".sanctuary");
    const storage = new FilesystemStorage(join(storagePath, "state"));
    const derived = await deriveMasterKey(LEGACY_PASSPHRASE);
    await storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(derived.params)),
    );
    derived.key.fill(0);
    // A record must EXIST for the credential to matter at all: with no record
    // the verb settles absence from the bytes and never unlocks. The bytes
    // here are never decoded, because the unlock refuses first.
    await storage.write(
      "_intelligence",
      "substrate-config",
      stringToBytes("{}"),
    );
    return {
      storagePath,
      storage,
      cleanup: () => rm(dir, { recursive: true, force: true }),
    };
  }

  it("settles an absent record without touching the credential store at all", async () => {
    await withFortress(async (fortress) => {
      // A fortress that was never armed: an intelligence directory, no record.
      // Absence is provable from the bytes, so resolving a credential here
      // would make a read-only report reach the OS keyring on the commonest
      // shape there is, and would then report the missing credential instead
      // of the missing record. The directory is created directly, matching the
      // shape `vocab-drift-cleanup.test.ts` builds, so `ok` is not decided by
      // the unrelated config-directory check.
      await mkdir(join(fortress.storagePath, "state", "_intelligence"), {
        recursive: true,
      });
      const unlock = vi.fn(async () => {
        throw new Error("diagnose must not unlock a fortress with no record");
      }) as unknown as DiagnoseDeps["unlock"];
      const streams = captureStreams();
      const code = await runIntelligenceCommand({
        argv: ["diagnose", "--json", "--fortress", fortress.storagePath],
        diagnoseDeps: { unlock },
      });
      const parsed = JSON.parse(streams.out()) as {
        ok: boolean;
        local_intelligence: { state: string; credential_failure: string | null };
      };
      vi.restoreAllMocks();
      expect(vi.mocked(unlock!)).not.toHaveBeenCalled();
      expect(parsed.local_intelligence.state).toBe("absent");
      expect(parsed.local_intelligence.credential_failure).toBeNull();
      // Nothing is wrong with this fortress: nobody asked for local
      // intelligence on it.
      expect(parsed.ok).toBe(true);
      expect(code).toBe(0);
    });
  });

  it("says unavailable and not ok when a record EXISTS and no credential resolves", async () => {
    await withFortress(async (fortress) => {
      await arm(fortress);
      const streams = captureStreams();
      const code = await runIntelligenceCommand({
        argv: ["diagnose", "--json", "--fortress", fortress.storagePath],
        diagnoseDeps: {
          unlock: (async () => ({
            ok: false as const,
            failure: "absent" as const,
            message: "no fortress credential is available",
          })) as DiagnoseDeps["unlock"],
        },
      });
      const parsed = JSON.parse(streams.out()) as {
        ok: boolean;
        local_intelligence: { state: string; credential_failure: string | null };
      };
      vi.restoreAllMocks();
      // The mirror of the case above: here a record IS present, so "I could
      // not open it" is the honest answer and it is not a passing one.
      expect(parsed.local_intelligence.state).toBe("unavailable");
      expect(parsed.local_intelligence.credential_failure).toBe("absent");
      expect(parsed.ok).toBe(false);
      // The exit code still tracks only the config directory, unchanged.
      expect(code).toBe(0);
    });
  });

  it("tells a pre-envelope fortress it needs a migration, not that its credential is missing", async () => {
    const legacy = await seedLegacyFortress();
    try {
      // The REAL unlock chokepoint, with a valid credential in the env: the
      // only reason this fortress will not open is the migration this
      // read-only verb refuses to perform.
      const deps: DiagnoseDeps = { env: { SANCTUARY_PASSPHRASE: LEGACY_PASSPHRASE } };
      const jsonStreams = captureStreams();
      await runIntelligenceCommand({
        argv: ["diagnose", "--json", "--fortress", legacy.storagePath],
        diagnoseDeps: deps,
      });
      const jsonOut = jsonStreams.out();
      vi.restoreAllMocks();

      const humanStreams = captureStreams();
      await runIntelligenceCommand({
        argv: ["diagnose", "--fortress", legacy.storagePath],
        diagnoseDeps: deps,
      });
      const humanErr = humanStreams.err();
      vi.restoreAllMocks();

      const parsed = JSON.parse(jsonOut) as {
        ok: boolean;
        local_intelligence: {
          state: string;
          detail: string;
          remedy: string;
          credential_failure: string | null;
        };
      };
      expect(parsed.local_intelligence.state).toBe("custody_migration_required");
      expect(parsed.local_intelligence.detail).toContain("predates the custody envelope");
      expect(parsed.local_intelligence.remedy).toContain("sanctuary protect");
      // Not a credential problem: the credential resolved and is valid.
      expect(parsed.local_intelligence.credential_failure).toBeNull();
      expect(parsed.ok).toBe(false);
      expect(humanErr).toContain("Local intelligence: custody_migration_required");
      expect(humanErr).toContain("sanctuary protect");

      // The credential-unavailable rendering must appear in NEITHER form.
      for (const text of [jsonOut, humanErr]) {
        expect(text).not.toContain("the fortress credential is not available");
        expect(text).not.toContain("SANCTUARY_PASSPHRASE");
        expect(text).not.toContain("keyring");
        expect(text).not.toContain(LEGACY_PASSPHRASE);
      }
      // And the refusal held: reporting the state did not migrate the fortress.
      expect(await legacy.storage.read("_meta", "custody-envelope")).toBeNull();
    } finally {
      await legacy.cleanup();
    }
  });

  it("reports a record it could not read as indeterminate, not as absent", async () => {
    await withFortress(async (fortress) => {
      // The state directory exists, so absence cannot be established by its
      // absence; the record read is what fails.
      await fortress.storage.write("_meta", "probe", stringToBytes("{}"));
      const unreadable = new MemoryStorage();
      vi.spyOn(unreadable, "read").mockImplementation(async () => {
        const error = new Error("EACCES: permission denied") as NodeJS.ErrnoException;
        error.code = "EACCES";
        throw error;
      });
      const streams = captureStreams();
      await runIntelligenceCommand({
        argv: ["diagnose", "--json", "--fortress", fortress.storagePath],
        diagnoseDeps: {
          unlock: unlockWith(fortress.masterKey),
          storage: unreadable,
        },
      });
      const parsed = JSON.parse(streams.out()) as {
        ok: boolean;
        local_intelligence: { state: string; detail: string };
      };
      vi.restoreAllMocks();
      expect(parsed.local_intelligence.state).toBe("storage_unreadable");
      expect(parsed.local_intelligence.detail).toContain("indeterminate");
      expect(parsed.ok).toBe(false);
    });
  });

  it("folds the armed classification into the --json ok flag", async () => {
    await withFortress(async (fortress) => {
      await arm(fortress);
      const armedStreams = captureStreams();
      await runIntelligenceCommand({
        argv: ["diagnose", "--json", "--fortress", fortress.storagePath],
        diagnoseDeps: {
          unlock: unlockWith(fortress.masterKey),
          modelManifestV2PublicKey: CATALOG_PUBLIC_KEY,
        },
      });
      const armedJson = JSON.parse(armedStreams.out()) as { ok: boolean };
      vi.restoreAllMocks();
      expect(armedJson.ok).toBe(true);

      // Same fortress, same directories, a record this build cannot verify:
      // before the fold this read as ok because the directory existed.
      const invalidStreams = captureStreams();
      await runIntelligenceCommand({
        argv: ["diagnose", "--json", "--fortress", fortress.storagePath],
        diagnoseDeps: {
          unlock: unlockWith(fortress.masterKey),
          modelManifestV2PublicKey: OTHER_CATALOG_PUBLIC_KEY,
        },
      });
      const invalidJson = JSON.parse(invalidStreams.out()) as {
        ok: boolean;
        local_intelligence: { state: string };
      };
      vi.restoreAllMocks();
      expect(invalidJson.local_intelligence.state).toBe("integrity_state_invalid");
      expect(invalidJson.ok).toBe(false);

      // An unreadable credential is indeterminate, which is also not ok.
      const unavailableStreams = captureStreams();
      await runIntelligenceCommand({
        argv: ["diagnose", "--json", "--fortress", fortress.storagePath],
        diagnoseDeps: {
          unlock: (async () => ({
            ok: false as const,
            failure: "locked" as const,
            message: "the OS keyring is locked in this session",
          })) as DiagnoseDeps["unlock"],
        },
      });
      const unavailableJson = JSON.parse(unavailableStreams.out()) as { ok: boolean };
      vi.restoreAllMocks();
      expect(unavailableJson.ok).toBe(false);
    });
  });

  it("names no remedy for a record that failed Q5 integrity validation", async () => {
    await withFortress(async (fortress) => {
      await arm(fortress);
      const streams = captureStreams();
      await runIntelligenceCommand({
        argv: ["diagnose", "--json", "--fortress", fortress.storagePath],
        diagnoseDeps: {
          unlock: unlockWith(fortress.masterKey),
          modelManifestV2PublicKey: OTHER_CATALOG_PUBLIC_KEY,
        },
      });
      const parsed = JSON.parse(streams.out()) as {
        local_intelligence: { remedy: string | null; detail: string };
      };
      vi.restoreAllMocks();
      // config-reset refuses this state and re-provisioning cannot write over
      // it, so naming either verb would send the operator between two
      // refusals; the honest report offers none.
      expect(parsed.local_intelligence.remedy).toBeNull();
      expect(parsed.local_intelligence.detail).toContain("no in-product recovery");
    });
  });
});
