/**
 * Wrap fresh-fortress passphrase disclosure (Finding X / v1.1.3 hotfix).
 *
 * Pre-fix: `sanctuary wrap` against a fresh fortress with no env-supplied
 * passphrase generated one via getOrCreatePassphrase(), persisted it to
 * the keychain (or fallback file), and never showed the value. The
 * operator had no off-host backup; keychain compromise + host loss =
 * fortress loss. Same trust-failure shape as Finding U on init.
 *
 * Coordinator decision B-1 (Review/Sanctuary/V1.1.3_Phase_0_Coordinator_Decision_2026-04-26.md):
 * disclose only on case 3 (passphraseSource === "generated"). Cases 1
 * (`--passphrase` flag) and 2 (`SANCTUARY_PASSPHRASE` env) skip disclosure;
 * the operator already holds the secret.
 *
 * These tests pin all three cases against runWrap end-to-end. The
 * disclosure helper is NOT mocked: writePassphraseBackupFile lands a
 * real file at the real path; the banner is intercepted by spying on
 * process.stderr.write.
 */

import {
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
  vi,
  type MockInstance,
} from "vitest";
import {
  writeFile,
  mkdir,
  readFile,
  rm,
  stat,
  access,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runWrap } from "../../src/cocoon/cli.js";
import { PASSPHRASE_BACKUP_FILENAME } from "../../src/cocoon/recovery-key-disclosure.js";
import type { DashboardHandle } from "../../src/dashboard/index.js";

const FIXTURE_GENERATED_PASSPHRASE = "drill-canonical-passphrase-test-fixture-001";

describe("Wrap fresh-fortress passphrase disclosure (Finding X)", () => {
  let tmpHome: string;
  let tmpFortress: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;
  let originalEnvPassphrase: string | undefined;
  let stderrSpy: MockInstance;
  let stderrWrites: string[];

  beforeEach(async () => {
    tmpHome = join(
      tmpdir(),
      `sanctuary-wrap-X-${Date.now()}-${Math.random().toString(36).slice(2)}`
    );
    tmpFortress = join(tmpHome, ".sanctuary");
    await mkdir(tmpHome, { recursive: true, mode: 0o700 });
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    originalEnvPassphrase = process.env.SANCTUARY_PASSPHRASE;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = tmpFortress;
    delete process.env.SANCTUARY_PASSPHRASE;

    // Bootstrap the harness config so detection succeeds for --claude-code.
    await writeFile(join(tmpHome, ".claude.json"), JSON.stringify({ mcpServers: {} }));

    stderrWrites = [];
    stderrSpy = vi
      .spyOn(process.stderr, "write")
      .mockImplementation(((chunk: unknown) => {
        stderrWrites.push(typeof chunk === "string" ? chunk : String(chunk));
        return true;
      }) as typeof process.stderr.write);
  });

  afterEach(async () => {
    stderrSpy.mockRestore();
    if (originalHome !== undefined) process.env.HOME = originalHome;
    else delete process.env.HOME;
    if (originalStoragePath !== undefined)
      process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    else delete process.env.SANCTUARY_STORAGE_PATH;
    if (originalEnvPassphrase !== undefined)
      process.env.SANCTUARY_PASSPHRASE = originalEnvPassphrase;
    else delete process.env.SANCTUARY_PASSPHRASE;
    try {
      await rm(tmpHome, { recursive: true, force: true });
    } catch {}
  });

  function makeDeps(passphraseSource: string) {
    const fakeHandle = {
      url: "http://127.0.0.1:0",
      port: 0,
      host: "127.0.0.1",
      mode: "co-located",
      stop: async () => {},
      setV11Bindings: () => {},
      setV11LoopbackAutoAuth: () => {},
    } as unknown as DashboardHandle;
    return {
      startDashboard: async () => fakeHandle,
      openBrowser: async () => {},
      resolvePassphrase: async () => ({
        value: FIXTURE_GENERATED_PASSPHRASE,
        location: "test-keychain",
        source: passphraseSource,
      }),
      persistPassphrase: async (_value: string) => ({
        location: "test-keychain",
        source: "keychain" as const,
      }),
    };
  }

  describe("case 3 (Sanctuary-generated passphrase)", () => {
    it("prints the FULL passphrase in a banner with no truncation", async () => {
      await runWrap(
        { claudeCode: true, noOpen: true },
        makeDeps("generated")
      );
      const printed = stderrWrites.join("");
      expect(printed).toContain(FIXTURE_GENERATED_PASSPHRASE);
      expect(printed).not.toContain("...");
      expect(printed).toContain("SANCTUARY: First Run, Passphrase Generated");
      expect(printed).toContain("SAVE THIS PASSPHRASE");
    });

    it("writes passphrase-backup.txt at mode 0600 with the full passphrase", async () => {
      await runWrap(
        { claudeCode: true, noOpen: true },
        makeDeps("generated")
      );
      const filePath = join(tmpFortress, PASSPHRASE_BACKUP_FILENAME);
      const content = await readFile(filePath, "utf-8");
      expect(content).toContain(FIXTURE_GENERATED_PASSPHRASE);
      expect(content).toContain(
        "DO NOT COMMIT, DO NOT EMAIL, MOVE OFF-HOST IMMEDIATELY"
      );
      expect(content).toContain("Fortress:");
      expect(content).toContain(
        "Sanctuary will NOT regenerate this file"
      );
      const st = await stat(filePath);
      expect(st.mode & 0o777).toBe(0o600);
    });

    it("includes the passphrase-backup.txt path in the banner", async () => {
      await runWrap(
        { claudeCode: true, noOpen: true },
        makeDeps("generated")
      );
      const printed = stderrWrites.join("");
      expect(printed).toContain(PASSPHRASE_BACKUP_FILENAME);
      expect(printed).toContain("Move it off-host");
    });

    it("never overwrites an existing passphrase-backup.txt (single-issuance)", async () => {
      // First wrap creates the file.
      await runWrap(
        { claudeCode: true, noOpen: true },
        makeDeps("generated")
      );
      const filePath = join(tmpFortress, PASSPHRASE_BACKUP_FILENAME);
      const firstContent = await readFile(filePath, "utf-8");

      // Second wrap (simulating re-run) must NOT overwrite the file even if
      // the generated passphrase differs.
      stderrWrites.length = 0;
      const secondDeps = {
        ...makeDeps("generated"),
        resolvePassphrase: async () => ({
          value: "DIFFERENT-passphrase-must-not-clobber-the-first",
          location: "test-keychain",
          source: "generated",
        }),
      };
      await runWrap({ claudeCode: true, noOpen: true }, secondDeps);

      const secondContent = await readFile(filePath, "utf-8");
      expect(secondContent).toBe(firstContent);
      expect(secondContent).not.toContain(
        "DIFFERENT-passphrase-must-not-clobber-the-first"
      );
      expect(secondContent).toContain(FIXTURE_GENERATED_PASSPHRASE);
    });
  });

  describe("case 2 (SANCTUARY_PASSPHRASE env)", () => {
    it("does NOT write passphrase-backup.txt when env supplies the passphrase", async () => {
      process.env.SANCTUARY_PASSPHRASE = "operator-supplied-via-env";
      await runWrap(
        { claudeCode: true, noOpen: true },
        // resolvePassphrase is unused on the env path; pass a stub anyway.
        makeDeps("env")
      );
      const filePath = join(tmpFortress, PASSPHRASE_BACKUP_FILENAME);
      await expect(access(filePath)).rejects.toThrow();
    });

    it("does NOT print the passphrase banner when env supplies the passphrase", async () => {
      process.env.SANCTUARY_PASSPHRASE = "operator-supplied-via-env";
      await runWrap(
        { claudeCode: true, noOpen: true },
        makeDeps("env")
      );
      const printed = stderrWrites.join("");
      expect(printed).not.toContain("SANCTUARY: First Run, Passphrase Generated");
      expect(printed).not.toContain("SAVE THIS PASSPHRASE");
      expect(printed).not.toContain("operator-supplied-via-env");
    });
  });

  describe("case 1 (--passphrase flag)", () => {
    it("does NOT write passphrase-backup.txt when --passphrase is supplied", async () => {
      await runWrap(
        {
          claudeCode: true,
          noOpen: true,
          passphrase: "operator-typed-via-flag",
        },
        makeDeps("flag")
      );
      const filePath = join(tmpFortress, PASSPHRASE_BACKUP_FILENAME);
      await expect(access(filePath)).rejects.toThrow();
    });

    it("does NOT print the passphrase banner when --passphrase is supplied", async () => {
      await runWrap(
        {
          claudeCode: true,
          noOpen: true,
          passphrase: "operator-typed-via-flag",
        },
        makeDeps("flag")
      );
      const printed = stderrWrites.join("");
      expect(printed).not.toContain("SANCTUARY: First Run, Passphrase Generated");
      expect(printed).not.toContain("SAVE THIS PASSPHRASE");
      expect(printed).not.toContain("operator-typed-via-flag");
    });
  });
});
