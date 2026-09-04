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

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

import { stringToBytes } from "../../src/core/encoding.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
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
