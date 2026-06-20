/**
 * Sanctuary MCP Server — Configuration Tests
 *
 * Tests for config precedence (Bug 1: env vars must override file config)
 * and version stamping (Bug 2: version must come from package.json, not stored config).
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { loadConfig, saveConfig, defaultConfig, SANCTUARY_VERSION } from "../../../src/config.js";
import { writeFile, mkdtemp, rm, readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

describe("loadConfig", () => {
  let tempDir: string;

  beforeEach(async () => {
    // Create a unique temp directory for each test. mkdtemp creates the
    // directory atomically with a randomized suffix the caller cannot predict,
    // which avoids the insecure-temporary-file (TOCTOU) class that a manually
    // joined tmpdir() path plus mkdir would expose. Every config file written
    // by a test below lives INSIDE this per-test directory, never directly in
    // os.tmpdir() under a predictable name.
    tempDir = await mkdtemp(join(tmpdir(), "sanctuary-config-test-"));
  });

  afterEach(async () => {
    // Clean env vars
    delete process.env.SANCTUARY_DASHBOARD_ENABLED;
    delete process.env.SANCTUARY_DASHBOARD_PORT;
    delete process.env.SANCTUARY_DASHBOARD_HOST;
    delete process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
    delete process.env.SANCTUARY_WEBHOOK_ENABLED;
    delete process.env.SANCTUARY_STORAGE_PATH;
    delete process.env.SANCTUARY_TRANSPORT;
    delete process.env.SANCTUARY_HTTP_PORT;
    delete process.env.SANCTUARY_PRIVACY_FILTER;
    delete process.env.SANCTUARY_PRIVACY_FILTER_FAIL_MODE;
    delete process.env.SANCTUARY_PRIVACY_FILTER_COMMAND;
    delete process.env.SANCTUARY_PRIVACY_FILTER_TIMEOUT_MS;
    vi.restoreAllMocks();
    vi.doUnmock("node:fs/promises");

    // Clean up temp dir
    await rm(tempDir, { recursive: true, force: true }).catch(() => {});
  });

  describe("Bug 1: Config precedence — env vars override file config", () => {
    it("env var SANCTUARY_DASHBOARD_ENABLED=true overrides file dashboard.enabled=false", async () => {
      // Simulate the exact Mac Mini scenario: sanctuary.json has enabled:false,
      // env var sets true. Before the fix, file would win.
      const configFile = join(tempDir, "sanctuary.json");
      await writeFile(configFile, JSON.stringify({
        ...defaultConfig(),
        dashboard: { enabled: false, port: 3501, host: "127.0.0.1" },
      }));

      process.env.SANCTUARY_DASHBOARD_ENABLED = "true";
      const config = await loadConfig(configFile);

      expect(config.dashboard.enabled).toBe(true);
    });

    it("env var SANCTUARY_DASHBOARD_ENABLED=false overrides file dashboard.enabled=true", async () => {
      const configFile = join(tempDir, "sanctuary.json");
      await writeFile(configFile, JSON.stringify({
        ...defaultConfig(),
        dashboard: { enabled: true, port: 3501, host: "127.0.0.1" },
      }));

      process.env.SANCTUARY_DASHBOARD_ENABLED = "false";
      const config = await loadConfig(configFile);

      expect(config.dashboard.enabled).toBe(false);
    });

    it("env var SANCTUARY_DASHBOARD_PORT overrides file value", async () => {
      const configFile = join(tempDir, "sanctuary.json");
      await writeFile(configFile, JSON.stringify({
        ...defaultConfig(),
        dashboard: { enabled: false, port: 9999, host: "127.0.0.1" },
      }));

      process.env.SANCTUARY_DASHBOARD_PORT = "4000";
      const config = await loadConfig(configFile);

      expect(config.dashboard.port).toBe(4000);
    });

    it("env var SANCTUARY_WEBHOOK_ENABLED=true overrides file webhook.enabled=false", async () => {
      const configFile = join(tempDir, "sanctuary.json");
      await writeFile(configFile, JSON.stringify({
        ...defaultConfig(),
        webhook: { enabled: false, url: "", secret: "", callback_port: 3502, callback_host: "127.0.0.1" },
      }));

      process.env.SANCTUARY_WEBHOOK_ENABLED = "true";
      const config = await loadConfig(configFile);

      expect(config.webhook.enabled).toBe(true);
    });

    it("file config values apply when no env var overrides them", async () => {
      const configFile = join(tempDir, "sanctuary.json");
      await writeFile(configFile, JSON.stringify({
        ...defaultConfig(),
        dashboard: { enabled: true, port: 7777, host: "0.0.0.0" },
      }));

      // No env vars set — file values should apply
      const config = await loadConfig(configFile);

      expect(config.dashboard.enabled).toBe(true);
      expect(config.dashboard.port).toBe(7777);
      expect(config.dashboard.host).toBe("0.0.0.0");
    });
  });

  describe("Bug 2: Version string — always from package.json", () => {
    it("version comes from package.json even when sanctuary.json stores an old version", async () => {
      // Simulate the Mac Mini scenario: sanctuary.json stores version "0.3.0"
      // from first run, but package.json is 0.5.0
      const configFile = join(tempDir, "sanctuary.json");
      await writeFile(configFile, JSON.stringify({
        ...defaultConfig(),
        version: "0.3.0",
      }));

      const config = await loadConfig(configFile);

      expect(config.version).toBe(SANCTUARY_VERSION);
      expect(config.version).not.toBe("0.3.0");
    });

    it("version matches SANCTUARY_VERSION constant", async () => {
      // No config file — defaults only
      const config = await loadConfig(join(tempDir, "nonexistent.json"));
      expect(config.version).toBe(SANCTUARY_VERSION);
    });
  });

  describe("Config file missing — graceful fallback", () => {
    it("returns valid defaults when config file does not exist", async () => {
      const config = await loadConfig(join(tempDir, "nonexistent.json"));

      expect(config.dashboard.enabled).toBe(false);
      expect(config.dashboard.port).toBe(3501);
      expect(config.transport).toBe("stdio");
    });

    it("env vars still apply when config file is missing", async () => {
      process.env.SANCTUARY_DASHBOARD_ENABLED = "true";
      process.env.SANCTUARY_HTTP_PORT = "5000";

      const config = await loadConfig(join(tempDir, "nonexistent.json"));

      expect(config.dashboard.enabled).toBe(true);
      expect(config.http_port).toBe(5000);
    });
  });

  describe("Empty / partial config file — transient-write race", () => {
    // A concurrent writer (saveConfig in another process, or a parallel test
    // sharing a config path) truncates to zero bytes before rewriting. A
    // reader that hits that window sees "". This MUST fall back to defaults,
    // not be treated as corruption — quarantining a file that is about to be
    // valid again is destructive and itself racy. Regression for the
    // "SyntaxError: Unexpected end of JSON input" flake in
    // test/cli/singleton-audit-writes.test.ts.
    it("treats an empty config file as defaults without quarantining", async () => {
      const configFile = join(tempDir, "empty.json");
      await writeFile(configFile, "");

      const config = await loadConfig(configFile);

      // Falls back to defaults rather than throwing.
      expect(config.transport).toBe("stdio");
      expect(config.dashboard.enabled).toBe(false);
      expect(config.dashboard.port).toBe(3501);
      // The file is left untouched — NOT renamed to *.corrupted.*
      expect(await readFile(configFile, "utf-8")).toBe("");
      const files = await readdir(tempDir);
      expect(files.some((file) => file.includes(".corrupted."))).toBe(false);
    });

    it("treats a whitespace-only config file as defaults without quarantining", async () => {
      const configFile = join(tempDir, "whitespace.json");
      await writeFile(configFile, "  \n\t\r\n  ");

      const config = await loadConfig(configFile);

      expect(config.transport).toBe("stdio");
      const files = await readdir(tempDir);
      expect(files.some((file) => file.includes(".corrupted."))).toBe(false);
    });

    it("still quarantines a non-empty malformed config file", async () => {
      // The empty-file carve-out must not weaken genuine-corruption handling:
      // partial-but-non-empty JSON is still treated as corruption.
      const configFile = join(tempDir, "partial.json");
      await writeFile(configFile, '{ "transport": "std');

      await expect(loadConfig(configFile)).rejects.toMatchObject({
        name: "ConfigLoadError",
        classification: "corrupted",
      });
      const files = await readdir(tempDir);
      expect(files.some((file) => file.startsWith("partial.json.corrupted."))).toBe(true);
    });
  });

  describe("Atomic save — root cause of the truncate-before-write race", () => {
    // saveConfig writes to a temp file then renames into place, so a
    // concurrent loadConfig never observes an empty or partial file. This is
    // the source-side half of the race fix; the loadConfig empty-read
    // tolerance above is the reader-side defense-in-depth.
    it("round-trips config and leaves no temp file behind", async () => {
      const configFile = join(tempDir, "atomic.json");
      const cfg = defaultConfig();
      cfg.dashboard.port = 4321;

      await saveConfig(cfg, configFile);

      const loaded = await loadConfig(configFile);
      expect(loaded.dashboard.port).toBe(4321);

      const files = await readdir(tempDir);
      expect(files).toContain("atomic.json");
      // The temp file used during the atomic write must not be left behind.
      expect(files.some((file) => file.includes("atomic.json.tmp."))).toBe(false);
    });
  });

  describe("Fail-closed config loading", () => {
    it("throws with recovery guidance and quarantines malformed JSON", async () => {
      const configFile = join(tempDir, "malformed.json");
      await writeFile(configFile, "{ not json");

      await expect(loadConfig(configFile)).rejects.toMatchObject({
        name: "ConfigLoadError",
        classification: "corrupted",
        path: configFile,
        message: expect.stringContaining("Recovery:"),
      });

      await expect(readFile(configFile, "utf-8")).rejects.toMatchObject({ code: "ENOENT" });
      const files = await readdir(tempDir);
      const quarantine = files.find((file) => file.startsWith("malformed.json.corrupted."));
      expect(quarantine).toBeTruthy();
      expect(await readFile(join(tempDir, quarantine!), "utf-8")).toBe("{ not json");
    });

    it("throws on permission errors instead of continuing with defaults", async () => {
      const configFile = join(tempDir, "unreadable.json");
      await writeFile(configFile, JSON.stringify(defaultConfig()));

      vi.resetModules();
      vi.doMock("node:fs/promises", async (importOriginal) => {
        const actual = await importOriginal<typeof import("node:fs/promises")>();
        const permissionDenied = Object.assign(new Error("permission denied"), {
          code: "EACCES",
        });
        return {
          ...actual,
          readFile: vi.fn(async () => {
            throw permissionDenied;
          }),
        };
      });

      const { loadConfig: mockedLoadConfig } = await import("../../../src/config.js");
      await expect(mockedLoadConfig(configFile)).rejects.toMatchObject({
        name: "ConfigLoadError",
        classification: "unreadable",
        path: configFile,
      });
    });
  });

  describe("Privacy filter config", () => {
    it("defaults to local placeholder filtering with closed fail mode", async () => {
      // Default fail_mode is "closed" (Sanctuary Invariant #5: never silently
      // degrade on error). Operators opt in to legacy fallback explicitly.
      const config = await loadConfig(join(tempDir, "nonexistent.json"));
      expect(config.privacy_filter).toEqual({
        mode: "local",
        fail_mode: "closed",
        command: "opf",
        timeout_ms: 5000,
      });
    });

    it("env vars override privacy filter config", async () => {
      process.env.SANCTUARY_PRIVACY_FILTER = "opf";
      process.env.SANCTUARY_PRIVACY_FILTER_FAIL_MODE = "closed";
      process.env.SANCTUARY_PRIVACY_FILTER_COMMAND = "/tmp/mock-opf";
      process.env.SANCTUARY_PRIVACY_FILTER_TIMEOUT_MS = "750";

      const config = await loadConfig(join(tempDir, "nonexistent.json"));
      expect(config.privacy_filter).toEqual({
        mode: "opf",
        fail_mode: "closed",
        command: "/tmp/mock-opf",
        timeout_ms: 750,
      });
    });

    it("rejects invalid privacy filter mode", async () => {
      process.env.SANCTUARY_PRIVACY_FILTER = "remote";
      await expect(loadConfig(join(tempDir, "nonexistent.json"))).rejects.toThrow(
        /privacy_filter\.mode/
      );
    });
  });

  describe("Dashboard port validation - invalid-port fail-closed", () => {
    // The server-side override used a lenient parseInt, so without validation
    // "80abc" -> 80 and "70000" -> a truncated/out-of-spec port would bind the
    // server to a port the operator never typed. These cases pin that an invalid
    // port is now REFUSED rather than silently bound (fail-closed hardening).
    //
    // Forward note (not yet true in-tree): the deferred native macOS resolver is
    // intended to parse SANCTUARY_DASHBOARD_PORT strictly (Int + 1..65535,
    // fallback 3501) so server and native reads share one source. Today the
    // native bridge hardcodes 3501 and never reads the env var, so full
    // single-source port parity does NOT hold yet; this only closes the
    // invalid-port hole.
    it("rejects a non-numeric-suffixed env port the server would otherwise truncate", async () => {
      process.env.SANCTUARY_DASHBOARD_PORT = "80abc";
      await expect(loadConfig(join(tempDir, "nonexistent.json"))).rejects.toThrow(
        /dashboard\.port/
      );
    });

    it("rejects an out-of-range env port (> 65535)", async () => {
      process.env.SANCTUARY_DASHBOARD_PORT = "70000";
      await expect(loadConfig(join(tempDir, "nonexistent.json"))).rejects.toThrow(
        /dashboard\.port/
      );
    });

    it("rejects an env port of 0", async () => {
      process.env.SANCTUARY_DASHBOARD_PORT = "0";
      await expect(loadConfig(join(tempDir, "nonexistent.json"))).rejects.toThrow(
        /dashboard\.port/
      );
    });

    it("rejects a non-numeric env port", async () => {
      process.env.SANCTUARY_DASHBOARD_PORT = "not-a-port";
      await expect(loadConfig(join(tempDir, "nonexistent.json"))).rejects.toThrow(
        /dashboard\.port/
      );
    });

    it("rejects a signed env port (reader-parity with paths.ts resolveDashboardPort)", async () => {
      // A TCP port is unsigned, so a leading sign ("+8443") is never operator
      // intent. The boot reader (strictParseIntEnv) screens with the SAME
      // digit-only regex as the wrap reader (paths.ts parseStrictPortEnv), so an
      // in-range-but-signed value is refused on BOTH paths rather than binding
      // 8443 here while the wrap path falls back to 3501. Guards against the two
      // readers diverging on signed input.
      process.env.SANCTUARY_DASHBOARD_PORT = "+8443";
      await expect(loadConfig(join(tempDir, "nonexistent.json"))).rejects.toThrow(
        /dashboard\.port/
      );
    });

    it("rejects an out-of-range port in a config FILE", async () => {
      const path = join(tempDir, "bad-port.json");
      await writeFile(
        path,
        JSON.stringify({ dashboard: { enabled: true, port: 70000, host: "127.0.0.1" } })
      );
      await expect(loadConfig(path)).rejects.toThrow(/dashboard\.port/);
    });

    it("refuses an out-of-range FILE port WITHOUT quarantining (a port typo is not corruption)", async () => {
      // Regression guard: an out-of-range dashboard.port in a structurally-valid
      // config FILE must fail CLOSED (server refuses to start) but must NOT
      // destructively rename the operator's file to .corrupted.<ts>. A value
      // typo is recoverable in place; moving the file away from under the
      // operator is the defect this guards against.
      const path = join(tempDir, "typo-port.json");
      const original = JSON.stringify(
        { dashboard: { enabled: true, port: 70000, host: "127.0.0.1" } },
        null,
        2
      );
      await writeFile(path, original);

      await expect(loadConfig(path)).rejects.toMatchObject({
        name: "ConfigLoadError",
        classification: "invalid-value",
      });

      // The original file is still present and byte-identical.
      expect(await readFile(path, "utf-8")).toBe(original);
      // No quarantine copy was created.
      const files = await readdir(tempDir);
      expect(files.some((f) => f.includes(".corrupted."))).toBe(false);
    });

    it("STILL quarantines a genuine schema mismatch in a config FILE (unimplemented feature)", async () => {
      // The non-quarantine carve-out is scoped to scalar VALUE typos only. A
      // config that references an unimplemented feature is a genuine schema
      // mismatch and must still be quarantined (pre-existing behavior).
      const path = join(tempDir, "bad-feature.json");
      await writeFile(
        path,
        JSON.stringify({
          disclosure: { proof_system: "groth16", default_policy: "minimum-necessary" },
        })
      );

      await expect(loadConfig(path)).rejects.toMatchObject({
        name: "ConfigLoadError",
        classification: "schema-mismatch",
      });

      await expect(readFile(path, "utf-8")).rejects.toMatchObject({ code: "ENOENT" });
      const files = await readdir(tempDir);
      expect(files.some((f) => f.startsWith("bad-feature.json.corrupted."))).toBe(true);
    });

    it("quarantines when a value typo coexists with a feature mismatch (feature wins)", async () => {
      // If a file has BOTH a feature mismatch and a value typo, the file is
      // going to be quarantined regardless, and both problems are reported.
      const path = join(tempDir, "mixed-bad.json");
      await writeFile(
        path,
        JSON.stringify({
          disclosure: { proof_system: "groth16", default_policy: "minimum-necessary" },
          dashboard: { enabled: true, port: 70000, host: "127.0.0.1" },
        })
      );

      await expect(loadConfig(path)).rejects.toMatchObject({
        name: "ConfigLoadError",
        classification: "schema-mismatch",
      });
      const files = await readdir(tempDir);
      expect(files.some((f) => f.startsWith("mixed-bad.json.corrupted."))).toBe(true);
    });

    it("accepts a valid in-range env port (boundary 65535)", async () => {
      process.env.SANCTUARY_DASHBOARD_PORT = "65535";
      const config = await loadConfig(join(tempDir, "nonexistent.json"));
      expect(config.dashboard.port).toBe(65535);
    });
  });

  describe("Config structural shape validation (#4)", () => {
    it("rejects a config file that overrides an object-typed key with a string", async () => {
      const path = join(tempDir, "broken-shape.json");
      await writeFile(path, JSON.stringify({ dashboard: "totally-not-an-object" }));
      await expect(loadConfig(path)).rejects.toThrow(/dashboard.*must be an object/);
    });

    it("rejects a config file that overrides an object-typed key with an array", async () => {
      const path = join(tempDir, "broken-shape-array.json");
      await writeFile(path, JSON.stringify({ privacy_filter: ["not", "an", "object"] }));
      await expect(loadConfig(path)).rejects.toThrow(/privacy_filter.*must be an object/);
    });

    it("rejects a config file that overrides transport with an unknown literal", async () => {
      const path = join(tempDir, "broken-transport.json");
      await writeFile(path, JSON.stringify({ transport: "carrier-pigeon" }));
      await expect(loadConfig(path)).rejects.toThrow(/transport.*"stdio"/);
    });

    it("accepts a well-formed config file", async () => {
      const path = join(tempDir, "well-formed.json");
      await writeFile(
        path,
        JSON.stringify({ dashboard: { enabled: true, port: 9999, host: "0.0.0.0" } })
      );
      const config = await loadConfig(path);
      expect(config.dashboard.port).toBe(9999);
      expect(config.dashboard.enabled).toBe(true);
    });
  });
});
