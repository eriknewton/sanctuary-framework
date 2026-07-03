/**
 * Hermes config.yaml parse-parity guard
 * (Review/Sanctuary/PR849_Hermes_YAML_ParseParity_Decision_2026-07-03.md)
 *
 * The wrap-time Hermes injection edits config.yaml with a hand-rolled line
 * scanner (hermes-yaml.ts) that has repeatedly diverged from PyYAML, the
 * parser Hermes itself uses (a silent stale-config / secret-drop class).
 * The parse-parity guard validates the scanner's view against a REAL
 * PyYAML parse and refuses to edit on disagreement, and refuses (fail
 * closed) when that parser cannot run at all.
 *
 * Test strategy:
 *   - Deterministic UNIT tests inject a mock sidecar exec so CI never
 *     depends on a python3 interpreter: they pin agreement, every
 *     disagreement shape, and every sidecar-unavailable path.
 *   - REAL-sidecar tests run only when this host has python3 + PyYAML
 *     (skipped otherwise) and prove the guard against the actual parser:
 *     real agreement, the real duplicate-key P1 the decision doc flagged
 *     (scanner sees two `sanctuary` entries, PyYAML last-wins collapses to
 *     one), and a real fail-closed when pointed at a bogus interpreter.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtemp, writeFile, mkdir, rm, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  assertHermesYamlParseParity,
  HermesYamlParityRefusedError,
  type SidecarExec,
  type ParseParityOptions,
} from "../../src/wrap/hermes-yaml-parse-parity.js";
import { runWrap, type RunWrapDeps } from "../../src/wrap/cli.js";
import { yamlContainsSanctuaryEntry } from "../../src/wrap/hermes-yaml.js";
import type { DashboardHandle } from "../../src/dashboard/index.js";
import { agreeingHermesParity } from "../helpers/hermes-parity.js";

// -- Mock sidecar helpers -------------------------------------------------

/** A sidecar that returns a fixed {hasBlock, entryNames} parse (exit 0). */
function mockAgreeing(view: {
  hasBlock: boolean;
  entryNames: string[];
}): SidecarExec {
  return async () => ({
    stdout: JSON.stringify(view),
    stderr: "",
    code: 0,
  });
}

/** A sidecar that returns a fixed exit code and stdout. */
function mockExit(code: number | null, stdout = ""): SidecarExec {
  return async () => ({ stdout, stderr: "", code });
}

// -- Deterministic unit tests (mocked sidecar) ---------------------------

describe("assertHermesYamlParseParity - agreement (mocked)", () => {
  it("resolves when scanner and PyYAML agree on a normal block", async () => {
    const yaml = [
      "mcp_servers:",
      "  weather:",
      '    command: "uvx"',
      "  search:",
      '    command: "npx"',
      "",
    ].join("\n");
    // Scanner sees [weather, search]; the mock parser agrees.
    await expect(
      assertHermesYamlParseParity(yaml, {
        exec: mockAgreeing({ hasBlock: true, entryNames: ["weather", "search"] }),
      })
    ).resolves.toBeUndefined();
  });

  it("agrees regardless of key ordering (name-set, not order)", async () => {
    const yaml = "mcp_servers:\n  a:\n    command: \"x\"\n  b:\n    command: \"y\"\n";
    await expect(
      assertHermesYamlParseParity(yaml, {
        exec: mockAgreeing({ hasBlock: true, entryNames: ["b", "a"] }),
      })
    ).resolves.toBeUndefined();
  });

  it("short-circuits to agreement for an absent file WITHOUT calling the sidecar", async () => {
    let called = false;
    const exec: SidecarExec = async () => {
      called = true;
      return { stdout: "", stderr: "", code: 0 };
    };
    await expect(
      assertHermesYamlParseParity(null, { exec })
    ).resolves.toBeUndefined();
    expect(called).toBe(false);
  });

  it("does not spend a sidecar call when the scanner already flags an unsupported shape", async () => {
    // Duplicate top-level mcp_servers keys: scanMcpServersBlock throws
    // HermesYamlUnsupportedError, which the plan rejects loudly first.
    let called = false;
    const exec: SidecarExec = async () => {
      called = true;
      return { stdout: "", stderr: "", code: 0 };
    };
    const dupKeys =
      "mcp_servers:\n  a:\n    command: \"x\"\nmcp_servers:\n  b:\n    command: \"y\"\n";
    await expect(
      assertHermesYamlParseParity(dupKeys, { exec })
    ).resolves.toBeUndefined();
    expect(called).toBe(false);
  });
});

describe("assertHermesYamlParseParity - disagreement REFUSES (mocked)", () => {
  it("refuses when the scanner sees a block but PyYAML does not", async () => {
    const yaml = "mcp_servers:\n  weather:\n    command: \"uvx\"\n";
    // Fabricated parse: PyYAML reports no block. The scanner disagrees.
    const err = await assertHermesYamlParseParity(yaml, {
      exec: mockAgreeing({ hasBlock: false, entryNames: [] }),
    }).catch((e) => e);
    expect(err).toBeInstanceOf(HermesYamlParityRefusedError);
    expect((err as HermesYamlParityRefusedError).reason).toBe("disagreement");
  });

  it("refuses when the scanner and PyYAML see a different entry-name SET", async () => {
    const yaml = [
      "mcp_servers:",
      "  weather:",
      '    command: "uvx"',
      "",
    ].join("\n");
    // Scanner sees [weather]; fabricated parser sees [weather, hidden]: an
    // entry the line scanner missed. Refuse.
    const err = await assertHermesYamlParseParity(yaml, {
      exec: mockAgreeing({ hasBlock: true, entryNames: ["weather", "hidden"] }),
    }).catch((e) => e);
    expect(err).toBeInstanceOf(HermesYamlParityRefusedError);
    expect((err as HermesYamlParityRefusedError).reason).toBe("disagreement");
  });

  it("refuses a duplicate-entry mismatch: scanner counts 3, PyYAML last-wins collapses to 2 (the P1)", async () => {
    const yaml = [
      "mcp_servers:",
      "  sanctuary:",
      '    command: "old"',
      "  weather:",
      '    command: "uvx"',
      "  sanctuary:",
      '    command: "new"',
      "",
    ].join("\n");
    // The scanner records both `sanctuary` lines (3 names); PyYAML's dict
    // keeps one `sanctuary` key (2 names). Mismatched multiset -> refuse.
    const err = await assertHermesYamlParseParity(yaml, {
      exec: mockAgreeing({ hasBlock: true, entryNames: ["sanctuary", "weather"] }),
    }).catch((e) => e);
    expect(err).toBeInstanceOf(HermesYamlParityRefusedError);
    expect((err as HermesYamlParityRefusedError).reason).toBe("disagreement");
  });
});

describe("assertHermesYamlParseParity - sidecar unavailable REFUSES fail-closed (mocked)", () => {
  const yaml = "mcp_servers:\n  weather:\n    command: \"uvx\"\n";

  it("refuses when the interpreter never ran (exit code null)", async () => {
    const err = await assertHermesYamlParseParity(yaml, {
      exec: mockExit(null),
    }).catch((e) => e);
    expect(err).toBeInstanceOf(HermesYamlParityRefusedError);
    expect((err as HermesYamlParityRefusedError).reason).toBe(
      "sidecar-unavailable"
    );
  });

  it("refuses when PyYAML is not importable (exit 20)", async () => {
    const err = await assertHermesYamlParseParity(yaml, {
      exec: mockExit(20),
    }).catch((e) => e);
    expect(err).toBeInstanceOf(HermesYamlParityRefusedError);
    expect((err as HermesYamlParityRefusedError).reason).toBe(
      "sidecar-unavailable"
    );
    expect((err as HermesYamlParityRefusedError).message).toContain("PyYAML");
  });

  it("refuses when PyYAML cannot parse the file (exit 21)", async () => {
    const err = await assertHermesYamlParseParity(yaml, {
      exec: mockExit(21),
    }).catch((e) => e);
    expect(err).toBeInstanceOf(HermesYamlParityRefusedError);
    expect((err as HermesYamlParityRefusedError).reason).toBe(
      "sidecar-unavailable"
    );
  });

  it("refuses when PyYAML reads mcp_servers as a non-mapping (exit 22)", async () => {
    const err = await assertHermesYamlParseParity(yaml, {
      exec: mockExit(22),
    }).catch((e) => e);
    expect(err).toBeInstanceOf(HermesYamlParityRefusedError);
    expect((err as HermesYamlParityRefusedError).reason).toBe(
      "sidecar-unavailable"
    );
  });

  it("refuses on any other non-zero exit code", async () => {
    const err = await assertHermesYamlParseParity(yaml, {
      exec: mockExit(7),
    }).catch((e) => e);
    expect(err).toBeInstanceOf(HermesYamlParityRefusedError);
    expect((err as HermesYamlParityRefusedError).reason).toBe(
      "sidecar-unavailable"
    );
  });

  it("refuses when the parser output is not valid JSON", async () => {
    const err = await assertHermesYamlParseParity(yaml, {
      exec: mockExit(0, "not json at all"),
    }).catch((e) => e);
    expect(err).toBeInstanceOf(HermesYamlParityRefusedError);
    expect((err as HermesYamlParityRefusedError).reason).toBe(
      "sidecar-unavailable"
    );
  });

  it("refuses when the parser output is valid JSON but the wrong shape", async () => {
    const err = await assertHermesYamlParseParity(yaml, {
      exec: mockExit(0, JSON.stringify({ hasBlock: "yes", entryNames: 3 })),
    }).catch((e) => e);
    expect(err).toBeInstanceOf(HermesYamlParityRefusedError);
    expect((err as HermesYamlParityRefusedError).reason).toBe(
      "sidecar-unavailable"
    );
  });

  it("refuses when entryNames contains a non-string element", async () => {
    const err = await assertHermesYamlParseParity(yaml, {
      exec: mockExit(0, JSON.stringify({ hasBlock: true, entryNames: [1, 2] })),
    }).catch((e) => e);
    expect(err).toBeInstanceOf(HermesYamlParityRefusedError);
    expect((err as HermesYamlParityRefusedError).reason).toBe(
      "sidecar-unavailable"
    );
  });
});

// -- Real-sidecar tests (skipped when python3 + PyYAML absent) ------------

function hasRealPyYaml(): boolean {
  try {
    execFileSync("python3", ["-c", "import yaml"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const realPyYaml = hasRealPyYaml();
const describeReal = realPyYaml ? describe : describe.skip;

describeReal("assertHermesYamlParseParity - REAL python3 + PyYAML", () => {
  it("resolves on real agreement for a normal config (default exec)", async () => {
    const yaml = [
      "# operator notes",
      "mcp_servers:",
      "  weather:",
      '    command: "uvx"',
      "    args:",
      '      - "mcp-weather"',
      "  search:",
      '    command: "npx"',
      "",
    ].join("\n");
    // No exec injected: the real defaultSidecarExec runs python3 for real.
    await expect(
      assertHermesYamlParseParity(yaml)
    ).resolves.toBeUndefined();
  });

  it("REFUSES the real duplicate-`sanctuary` P1: scanner sees two, PyYAML last-wins keeps one", async () => {
    const yaml = [
      "mcp_servers:",
      "  sanctuary:",
      '    command: "old"',
      "  weather:",
      '    command: "uvx"',
      "  sanctuary:",
      '    command: "new"',
      "",
    ].join("\n");
    // Sanity-check the ground truth this test relies on: the real PyYAML
    // parse collapses the duplicate key, so its name count differs from the
    // scanner's. If PyYAML ever stopped last-wins-collapsing, this assert
    // would catch it rather than the test silently passing for a wrong
    // reason.
    const realNames = JSON.parse(
      execFileSync(
        "python3",
        [
          "-c",
          "import sys,json,yaml; d=yaml.safe_load(sys.stdin.read()); print(json.dumps(list(d['mcp_servers'].keys())))",
        ],
        { input: yaml }
      )
        .toString()
        .trim()
    ) as string[];
    expect(realNames.length).toBe(2); // sanctuary, weather (last-wins)

    const err = await assertHermesYamlParseParity(yaml).catch((e) => e);
    expect(err).toBeInstanceOf(HermesYamlParityRefusedError);
    expect((err as HermesYamlParityRefusedError).reason).toBe("disagreement");
  });

  it("REFUSES fail-closed when pointed at a non-existent interpreter (real spawn ENOENT)", async () => {
    const yaml = "mcp_servers:\n  weather:\n    command: \"uvx\"\n";
    const err = await assertHermesYamlParseParity(yaml, {
      pythonPath: "/nonexistent/definitely-not-a-python-interpreter-xyz",
    }).catch((e) => e);
    expect(err).toBeInstanceOf(HermesYamlParityRefusedError);
    expect((err as HermesYamlParityRefusedError).reason).toBe(
      "sidecar-unavailable"
    );
  });

  it("REFUSES fail-closed when the real parser rejects malformed YAML", async () => {
    // Unbalanced flow bracket: a real PyYAML parse throws (exit 21), so the
    // guard refuses rather than trusting the line scanner's read.
    const yaml = "mcp_servers:\n  weather: {command: \"uvx\"\n";
    const err = await assertHermesYamlParseParity(yaml).catch((e) => e);
    expect(err).toBeInstanceOf(HermesYamlParityRefusedError);
    expect((err as HermesYamlParityRefusedError).reason).toBe(
      "sidecar-unavailable"
    );
  });
});

// -- CLI end-to-end fail-before / pass-after ------------------------------
//
// The unit tests above pin assertHermesYamlParseParity in isolation. These
// prove the wired behaviour through `runWrap`, which is the acceptance
// contract: a refusal must leave config.yaml UNTOUCHED (no mutation), and a
// legitimate wrap (agreement) must still edit as before (no regression).
// The sidecar is injected via deps.hermesParity so these are deterministic
// on any host; one real-sidecar case is included where PyYAML is present.

describe("runWrap --hermes parse-parity guard (end-to-end)", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;
  let errSpy: ReturnType<typeof vi.spyOn>;
  let exitSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    tmpHome = await mkdtemp(join(tmpdir(), "sanctuary-hermes-parity-"));
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
    errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    exitSpy = vi
      .spyOn(process, "exit")
      .mockImplementation((code?: string | number | null) => {
        throw new Error(`process.exit:${code}`);
      });
  });

  afterEach(async () => {
    errSpy.mockRestore();
    exitSpy.mockRestore();
    vi.restoreAllMocks();
    if (originalHome !== undefined) process.env.HOME = originalHome;
    else delete process.env.HOME;
    if (originalStoragePath !== undefined)
      process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    else delete process.env.SANCTUARY_STORAGE_PATH;
    try {
      await rm(tmpHome, { recursive: true, force: true });
    } catch {
      // best effort
    }
  });

  function baseDeps(hermesParity: ParseParityOptions): RunWrapDeps {
    const fakeHandle: DashboardHandle = {
      url: "http://127.0.0.1:0",
      port: 0,
      host: "127.0.0.1",
      mode: "co-located",
      stop: async () => {},
    } as unknown as DashboardHandle;
    return {
      startDashboard: async () => fakeHandle,
      openBrowser: async () => {},
      resolvePassphrase: async () => ({
        value: "test-passphrase",
        location: "test-keychain",
        source: "generated",
      }),
      hermesParity,
    };
  }

  function stderrOutput(): string {
    return errSpy.mock.calls.map((c) => c.map(String).join(" ")).join("\n");
  }

  /** A refusing sidecar: any given fixed exit code / stdout. */
  function refusingParity(code: number | null, stdout = ""): ParseParityOptions {
    return { exec: async () => ({ stdout, stderr: "", code }) };
  }

  /** A disagreeing sidecar: reports a DIFFERENT view than the scanner. */
  function disagreeingParity(view: {
    hasBlock: boolean;
    entryNames: string[];
  }): ParseParityOptions {
    return {
      exec: async () => ({ stdout: JSON.stringify(view), stderr: "", code: 0 }),
    };
  }

  async function writeHermesConfig(yaml: string): Promise<string> {
    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    await writeFile(join(hermesDir, "cli-config.json"), "{}");
    const yamlPath = join(hermesDir, "config.yaml");
    await writeFile(yamlPath, yaml);
    return yamlPath;
  }

  it("(1) disagreement -> wrap REFUSES and leaves config.yaml byte-for-byte untouched", async () => {
    const original = [
      "mcp_servers:",
      "  weather:",
      '    command: "uvx"',
      "",
    ].join("\n");
    const yamlPath = await writeHermesConfig(original);

    // The scanner sees [weather]; the injected parser reports an extra entry
    // the scanner missed. Disagreement -> refuse.
    await expect(
      runWrap(
        { hermes: true, noOpen: true },
        baseDeps(
          disagreeingParity({ hasBlock: true, entryNames: ["weather", "hidden"] })
        )
      )
    ).rejects.toThrow("process.exit:1");

    // FAIL-BEFORE / PASS-AFTER core assertion: the file is unchanged. No
    // sanctuary entry was written; the operator's bytes are identical.
    expect(await readFile(yamlPath, "utf-8")).toBe(original);
    expect(stderrOutput()).toContain("Not Editable");
    expect(stderrOutput()).toContain("parse-parity");
  });

  it("(2) sidecar unavailable (PyYAML not importable) -> wrap REFUSES fail-closed, file untouched", async () => {
    const original = "mcp_servers:\n  weather:\n    command: \"uvx\"\n";
    const yamlPath = await writeHermesConfig(original);

    // exit 20 == PyYAML not importable. Fail-closed: refuse, do not fall
    // through to the un-validated scanner.
    await expect(
      runWrap(
        { hermes: true, noOpen: true },
        baseDeps(refusingParity(20))
      )
    ).rejects.toThrow("process.exit:1");

    expect(await readFile(yamlPath, "utf-8")).toBe(original);
    expect(stderrOutput()).toContain("fail-closed");
  });

  it("(2b) sidecar cannot run at all (exit code null) -> wrap REFUSES fail-closed, file untouched", async () => {
    const original = "mcp_servers:\n  weather:\n    command: \"uvx\"\n";
    const yamlPath = await writeHermesConfig(original);

    await expect(
      runWrap(
        { hermes: true, noOpen: true },
        baseDeps(refusingParity(null))
      )
    ).rejects.toThrow("process.exit:1");

    expect(await readFile(yamlPath, "utf-8")).toBe(original);
    expect(await readFile(yamlPath, "utf-8")).not.toContain("sanctuary");
  });

  it("(3) agreement -> wrap PROCEEDS and injects the sanctuary entry (no regression)", async () => {
    const original = [
      "mcp_servers:",
      "  weather:",
      '    command: "uvx"',
      "",
    ].join("\n");
    const yamlPath = await writeHermesConfig(original);

    // Agree with the scanner's view -> the guard passes and the edit lands.
    await runWrap(
      { hermes: true, noOpen: true },
      baseDeps(agreeingHermesParity)
    );

    const after = await readFile(yamlPath, "utf-8");
    expect(yamlContainsSanctuaryEntry(after)).toBe(true);
    expect(after).toContain("  weather:"); // user entry preserved
  });

  it("(real sidecar) duplicate-`sanctuary` config -> wrap REFUSES, no mutation (the P1, end-to-end)", async () => {
    if (!realPyYaml) return; // real python3 + PyYAML required
    const original = [
      "mcp_servers:",
      "  sanctuary:",
      '    command: "old"',
      "  weather:",
      '    command: "uvx"',
      "  sanctuary:",
      '    command: "new"',
      "",
    ].join("\n");
    const yamlPath = await writeHermesConfig(original);

    // No injected exec: the REAL python3 PyYAML sidecar runs. Its dict keeps
    // one `sanctuary` key (last-wins) while the scanner records two, so the
    // guard refuses and the duplicate the scanner would have mis-edited is
    // left exactly as the operator had it.
    await expect(
      runWrap({ hermes: true, noOpen: true }, baseDeps({}))
    ).rejects.toThrow("process.exit:1");

    expect(await readFile(yamlPath, "utf-8")).toBe(original);
  });
});
