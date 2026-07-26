/**
 * DOCUMENTED BEHAVIOUR CHANGE, made executable.
 *
 * `loadConfig().storage_path` and `paths.resolveStoragePath()` are two
 * different answers to "which fortress", and they disagree in exactly one
 * configuration: `SANCTUARY_STORAGE_PATH` unset AND the config file carrying a
 * `storage_path` key that points elsewhere.
 *
 * The CLI verbs that derive a fortress master key used to scope their
 * passphrase lookup ambiently (i.e. to `resolveStoragePath()`, inside
 * `getOrCreatePassphrase`). They now scope it to `loadConfig().storage_path`
 * -- the fortress they actually open. For an operator with a divergent config
 * that changes which keychain entry is consulted, from the HOME-default
 * `sanctuary-passphrase` to the fortress-named
 * `sanctuary-passphrase-<sha256(path)[0:16]>`.
 *
 * That is deliberate: the credential that unlocks a fortress should be named
 * after that fortress. The change is written up in full, with its fail-closed
 * bound, on `loadConfig` in `src/config.ts`. These tests exist so the change
 * is pinned rather than merely described -- a silent change to which keychain
 * entry holds an operator's master key is exactly the kind of thing that must
 * be observable from the test suite, not only from a comment.
 *
 * The second test is the one that fails against the pre-fix code: before the
 * threading, `runTemplateCommand` reached `getOrCreatePassphrase()` with no
 * argument and the callee re-resolved ambiently, so the observed path was the
 * HOME default rather than the configured fortress.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { resolveStoragePath, DEFAULT_STORAGE_DIR } from "../../src/paths.js";
import { keychainServiceFor } from "../../src/wrap/passphrase.js";

/**
 * The legacy, HOME-default keychain service name, spelled as a literal rather
 * than imported: this test pins the OBSERVABLE name an operator would see in
 * their login keychain, so renaming the constant cannot quietly rename the
 * thing the behaviour-change note describes.
 */
const KEYCHAIN_SERVICE_DEFAULT = "sanctuary-passphrase";

/**
 * Build a home directory whose `~/.sanctuary/sanctuary.json` redirects
 * `storage_path` somewhere else -- the one shape in which the two readers
 * disagree.
 */
async function makeDivergentHome(): Promise<{
  home: string;
  homeFortress: string;
  configuredFortress: string;
  cleanup: () => Promise<void>;
}> {
  // mkdtemp: atomic fresh 0o700 dir (CodeQL js/insecure-temporary-file).
  const root = await mkdtemp(join(tmpdir(), "sanctuary-divergence-"));
  const home = join(root, "home");
  const homeFortress = join(home, DEFAULT_STORAGE_DIR);
  const configuredFortress = join(root, "srv-agent-b");
  await mkdir(homeFortress, { recursive: true, mode: 0o700 });
  await mkdir(join(configuredFortress, "state"), { recursive: true, mode: 0o700 });
  await writeFile(
    join(homeFortress, "sanctuary.json"),
    JSON.stringify({ storage_path: configuredFortress }, null, 2),
    { mode: 0o600 },
  );
  return {
    home,
    homeFortress,
    configuredFortress,
    cleanup: () => rm(root, { recursive: true, force: true }),
  };
}

describe("config-file storage_path divergence (documented behaviour change)", () => {
  let fixture: Awaited<ReturnType<typeof makeDivergentHome>>;
  let savedHome: string | undefined;
  let savedStoragePath: string | undefined;
  let savedPassphrase: string | undefined;

  beforeEach(async () => {
    fixture = await makeDivergentHome();
    savedHome = process.env.HOME;
    savedStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    savedPassphrase = process.env.SANCTUARY_PASSPHRASE;
    process.env.HOME = fixture.home;
    // The divergence exists ONLY when the env var is absent; setting it makes
    // both readers agree, which is the recovery the doc-comment recommends.
    delete process.env.SANCTUARY_STORAGE_PATH;
    delete process.env.SANCTUARY_PASSPHRASE;
  });

  afterEach(async () => {
    if (savedHome === undefined) delete process.env.HOME;
    else process.env.HOME = savedHome;
    if (savedStoragePath === undefined) delete process.env.SANCTUARY_STORAGE_PATH;
    else process.env.SANCTUARY_STORAGE_PATH = savedStoragePath;
    if (savedPassphrase === undefined) delete process.env.SANCTUARY_PASSPHRASE;
    else process.env.SANCTUARY_PASSPHRASE = savedPassphrase;
    vi.restoreAllMocks();
    vi.resetModules();
    await fixture.cleanup();
  });

  it("the two fortress readers disagree, and name different keychain entries", async () => {
    const { loadConfig } = await import("../../src/config.js");
    const configured = (await loadConfig()).storage_path;
    const ambient = resolveStoragePath(process.env, fixture.home);

    expect(configured).toBe(fixture.configuredFortress);
    expect(ambient).toBe(fixture.homeFortress);
    expect(configured).not.toBe(ambient);

    // The consequence the change is documented for.
    expect(keychainServiceFor(ambient, fixture.home)).toBe(
      KEYCHAIN_SERVICE_DEFAULT,
    );
    expect(keychainServiceFor(configured, fixture.home)).not.toBe(
      KEYCHAIN_SERVICE_DEFAULT,
    );
    expect(keychainServiceFor(configured, fixture.home)).toMatch(
      new RegExp(`^${KEYCHAIN_SERVICE_DEFAULT}-[0-9a-f]{16}$`),
    );
  });

  it("a CLI verb scopes its passphrase lookup to the fortress it opens", async () => {
    // Pre-fix this observed the HOME default, because the verb called
    // `getOrCreatePassphrase()` with no argument and the callee re-resolved
    // from the environment. That is the divergence made visible.
    const seen: Array<string | undefined> = [];
    vi.doMock("../../src/wrap/passphrase.js", async () => {
      const actual = await vi.importActual<
        typeof import("../../src/wrap/passphrase.js")
      >("../../src/wrap/passphrase.js");
      return {
        ...actual,
        getOrCreatePassphrase: vi.fn(async (opts?: { storagePath?: string }) => {
          seen.push(opts?.storagePath);
          return {
            value: "divergence-test-passphrase",
            source: "keychain" as const,
            location: "test",
          };
        }),
      };
    });

    const { runTemplateCommand } = await import("../../src/templates/cli.js");
    const sink = { write: () => true } as unknown as NodeJS.WritableStream;
    const code = await runTemplateCommand({
      argv: ["init", "research-assistant", "--agent-id", "ag-divergence-test"],
      out: sink,
      err: sink,
      isAgentWrapped: async () => true,
    });
    expect(code).toBe(0);

    expect(seen).toHaveLength(1);
    expect(seen[0]).toBe(fixture.configuredFortress);
    expect(seen[0]).not.toBe(fixture.homeFortress);
  });
});
