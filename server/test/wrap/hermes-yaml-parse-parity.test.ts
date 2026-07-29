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
  describePyYamlCandidateFailure,
  hermesParityPythonCandidates,
  probePyYamlCandidates,
  PYYAML_PARSE_PROGRAM,
  HermesYamlParityRefusedError,
  type SidecarExec,
  type ParseParityOptions,
} from "../../src/wrap/hermes-yaml-parse-parity.js";
import { runWrap, type RunWrapDeps } from "../../src/wrap/cli.js";
import { yamlContainsSanctuaryEntry } from "../../src/wrap/hermes-yaml.js";
import type { DashboardHandle } from "../../src/dashboard/index.js";
import {
  agreeingHermesParity,
  installHermesParityHook,
  clearHermesParityHook,
} from "../helpers/hermes-parity.js";

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

describe("assertHermesYamlParseParity - case-insensitive sanctuary collision REFUSES (mocked)", () => {
  it("refuses when PyYAML resolves both `Sanctuary` and `sanctuary` (P1: replace-one silent no-wrap)", async () => {
    // The scanner records BOTH keys, and PyYAML keeps them as DISTINCT dict
    // keys (they differ as exact-case keys), so the case-insensitive multiset
    // check AGREES (both lowercase to two `sanctuary`). But the injection
    // planner replaces only the FIRST case-insensitive `sanctuary` match,
    // leaving the second stale + unwrapped while the post-write scanner
    // reports success. FAIL-BEFORE: without the collision count this passes
    // parity and wrap silently mis-edits. PASS-AFTER: refuse.
    const yaml = [
      "mcp_servers:",
      "  Sanctuary:",
      '    command: "old"',
      "  sanctuary:",
      '    command: "new"',
      "",
    ].join("\n");
    const err = await assertHermesYamlParseParity(yaml, {
      // Parser agrees with the scanner's two-name view (both distinct keys).
      exec: mockAgreeing({
        hasBlock: true,
        entryNames: ["Sanctuary", "sanctuary"],
      }),
    }).catch((e) => e);
    expect(err).toBeInstanceOf(HermesYamlParityRefusedError);
    expect((err as HermesYamlParityRefusedError).reason).toBe("disagreement");
    expect((err as HermesYamlParityRefusedError).detail).toContain(
      "case-insensitively"
    );
  });

  it("does NOT refuse a single canonical `sanctuary` entry (no false positive)", async () => {
    const yaml = [
      "mcp_servers:",
      "  sanctuary:",
      '    command: "x"',
      "  weather:",
      '    command: "y"',
      "",
    ].join("\n");
    await expect(
      assertHermesYamlParseParity(yaml, {
        exec: mockAgreeing({
          hasBlock: true,
          entryNames: ["sanctuary", "weather"],
        }),
      })
    ).resolves.toBeUndefined();
  });
});

describe("assertHermesYamlParseParity - top-level non-mapping REFUSES (mocked)", () => {
  it("refuses when PyYAML signals the whole document is not a mapping (exit 23)", async () => {
    // A top-level sequence: scanner sees no mcp_servers block (hasBlock=false)
    // and, before the fix, PyYAML collapsed to hasBlock=false too -> they
    // AGREE -> add-key appends a top-level `mcp_servers:` mapping onto a
    // sequence, producing mixed types PyYAML then rejects. The distinct exit
    // 23 makes the guard refuse fail-closed instead.
    const yaml = "- a\n- b\n";
    const err = await assertHermesYamlParseParity(yaml, {
      exec: mockExit(23),
    }).catch((e) => e);
    expect(err).toBeInstanceOf(HermesYamlParityRefusedError);
    expect((err as HermesYamlParityRefusedError).reason).toBe(
      "sidecar-unavailable"
    );
    expect((err as HermesYamlParityRefusedError).detail).toContain(
      "non-mapping"
    );
  });
});

// -- Interpreter resolution by PyYAML importability (mocked, deterministic) --
//
// These pin the resolver's precedence WITHOUT depending on which real python on
// the host actually carries PyYAML -- the exact hazard that sank the first fix
// (first-EXISTING != first-with-PyYAML, and a dev Mac is the INVERSE of the
// drill host). The injected exec decides per-candidate whether that interpreter
// "has PyYAML", so every case is deterministic and platform-agnostic.

/**
 * A sidecar that RECORDS the interpreters it was asked to run, and answers
 * per-interpreter: `withPyYaml` interpreters return a successful agreeing parse
 * (exit 0); interpreters in `absent` return exit code null (could not run at
 * all); everything else returns IMPORT_MISSING (exit 20: "ran but no PyYAML").
 * Lets a test assert BOTH the outcome and exactly which candidates were probed.
 */
function recordingResolverExec(opts: {
  withPyYaml: string[];
  absent?: string[];
  view?: { hasBlock: boolean; entryNames: string[] };
}): { exec: SidecarExec; calls: string[] } {
  const calls: string[] = [];
  // Default agreeing view: matches the scanner's read of the single-entry
  // `mcp_servers: { weather }` yaml these tests use, so a successful resolve
  // passes the parity check. (Resolution, not parity semantics, is under test
  // here.)
  const view = opts.view ?? { hasBlock: true, entryNames: ["weather"] };
  const absent = new Set(opts.absent ?? []);
  const withPyYaml = new Set(opts.withPyYaml);
  const exec: SidecarExec = async (command) => {
    calls.push(command);
    if (absent.has(command)) return { stdout: "", stderr: "", code: null };
    if (withPyYaml.has(command)) {
      return { stdout: JSON.stringify(view), stderr: "", code: 0 };
    }
    return { stdout: "", stderr: "", code: 20 }; // ran, no PyYAML
  };
  return { exec, calls };
}

describe("assertHermesYamlParseParity - interpreter resolution precedence (mocked)", () => {
  const yaml = "mcp_servers:\n  weather:\n    command: \"uvx\"\n";
  const HOMEBREW = "/opt/homebrew/bin/python3";
  const USRLOCAL = "/usr/local/bin/python3";
  const SYSTEM = "/usr/bin/python3";

  it("candidate list is the absolute SYSTEM_PYTHON3_CANDIDATES only (no bare python3 / PATH / env input)", () => {
    expect(hermesParityPythonCandidates()).toEqual([HOMEBREW, USRLOCAL, SYSTEM]);
  });

  it("runs the parse interpreter in a hardened import environment (`-E` ahead of `-c`)", async () => {
    // Defense-in-depth: the fail-closed validator must not import an
    // attacker-planted `yaml` via PYTHONPATH/cwd. Every parse invocation passes
    // `-E` (ignore PYTHONPATH/PYTHONHOME) before `-c`; the cwd vector is closed
    // by the sys.path absolute-only filter inside the parse program itself.
    let seenArgs: string[] | undefined;
    const exec: SidecarExec = async (_command, args) => {
      seenArgs = args;
      return {
        stdout: JSON.stringify({ hasBlock: true, entryNames: ["weather"] }),
        stderr: "",
        code: 0,
      };
    };
    await expect(
      assertHermesYamlParseParity(yaml, { exec })
    ).resolves.toBeUndefined();
    expect(seenArgs?.[0]).toBe("-E");
    expect(seenArgs?.[1]).toBe("-c");
  });

  it("parse program sanitizes sys.path BEFORE importing any non-builtin (no cwd import-hijack of json/yaml)", () => {
    // `import json`/`import yaml` do sys.path lookups; if either ran before the
    // sys.path filter, a cwd-planted ./json.py or ./yaml.py could forge the
    // parse output (this program emits its result via json.dumps). Only `sys`
    // (a builtin, never resolved via sys.path) may be imported before the
    // filter drops the `-c` '' cwd entry.
    const lines = PYYAML_PARSE_PROGRAM.split("\n");
    const filterIdx = lines.findIndex(
      (l) => l.includes("sys.path") && l.includes("startswith")
    );
    expect(filterIdx).toBeGreaterThan(0);
    const importsBeforeFilter = lines
      .slice(0, filterIdx)
      .filter((l) => /^\s*(import|from)\b/.test(l));
    expect(importsBeforeFilter).toEqual(["import sys"]);
  });

  it("THE REGRESSION HOST: homebrew python exists but lacks PyYAML while a later candidate has it -> selects the one WITH PyYAML", async () => {
    // The first fix picked homebrew-first BY EXISTENCE and shipped RED on
    // exactly this shape. The resolver must skip the PyYAML-less homebrew
    // python and resolve the system python that can actually import yaml.
    const { exec, calls } = recordingResolverExec({ withPyYaml: [SYSTEM] });
    await expect(
      assertHermesYamlParseParity(yaml, { exec })
    ).resolves.toBeUndefined();
    // Probed homebrew (no PyYAML) -> usr/local (no PyYAML) -> system (has it),
    // and stopped there (never fell through to bare python3).
    expect(calls).toEqual([HOMEBREW, USRLOCAL, SYSTEM]);
  });

  it("selects the homebrew python when IT is the one with PyYAML (drill-host shape)", async () => {
    const { exec, calls } = recordingResolverExec({ withPyYaml: [HOMEBREW] });
    await expect(
      assertHermesYamlParseParity(yaml, { exec })
    ).resolves.toBeUndefined();
    expect(calls).toEqual([HOMEBREW]); // stopped at the first, which had PyYAML
  });

  it("an explicit pythonPath is used as-is and NEVER falls back when it lacks PyYAML", async () => {
    // Precedence top: an explicit interpreter pin must fail closed rather than
    // silently resolving a different python behind the caller's back.
    const { exec, calls } = recordingResolverExec({ withPyYaml: [SYSTEM] });
    const err = await assertHermesYamlParseParity(yaml, {
      exec,
      pythonPath: "/pinned/python3",
    }).catch((e) => e);
    expect(err).toBeInstanceOf(HermesYamlParityRefusedError);
    expect((err as HermesYamlParityRefusedError).reason).toBe(
      "sidecar-unavailable"
    );
    expect(calls).toEqual(["/pinned/python3"]); // no fallback to SYSTEM
  });

  it("an explicit EMPTY-STRING pythonPath still pins and fails closed (no truthiness fallback)", async () => {
    // Regression guard for the `!== undefined` fix: an empty-string pin is an
    // explicit (if invalid) interpreter choice and must NOT fall through to the
    // candidate list. It pins [""], which cannot run, so the guard fails closed.
    const { exec, calls } = recordingResolverExec({
      withPyYaml: [SYSTEM],
      absent: [""],
    });
    const err = await assertHermesYamlParseParity(yaml, {
      exec,
      pythonPath: "",
    }).catch((e) => e);
    expect(err).toBeInstanceOf(HermesYamlParityRefusedError);
    expect((err as HermesYamlParityRefusedError).reason).toBe(
      "sidecar-unavailable"
    );
    expect(calls).toEqual([""]); // pinned to "", never fell back to SYSTEM
  });

  it("refuses fail-closed (never reaching for a PATH python3) with a PyYAML-mentioning message when NO absolute candidate has PyYAML", async () => {
    const { exec, calls } = recordingResolverExec({ withPyYaml: [] });
    const err = await assertHermesYamlParseParity(yaml, { exec }).catch(
      (e) => e
    );
    expect(err).toBeInstanceOf(HermesYamlParityRefusedError);
    expect((err as HermesYamlParityRefusedError).reason).toBe(
      "sidecar-unavailable"
    );
    expect((err as HermesYamlParityRefusedError).message).toContain("PyYAML");
    // Tried exactly the three absolute candidates and then failed closed --
    // never fell back to a PATH-resolved bare "python3".
    expect(calls).toEqual([HOMEBREW, USRLOCAL, SYSTEM]);
  });

  it("a candidate WITH PyYAML that rejects the file does NOT fall through to another python", async () => {
    // exit 21 (unparseable) means a real parser refused the FILE -- the file is
    // the problem, not the interpreter, so the resolver must stop, not keep
    // trying other pythons hoping for a different answer.
    const calls: string[] = [];
    const exec: SidecarExec = async (command) => {
      calls.push(command);
      // homebrew lacks PyYAML (skip); usr/local HAS PyYAML but the file is bad.
      if (command === HOMEBREW) return { stdout: "", stderr: "", code: 20 };
      return { stdout: "", stderr: "", code: 21 };
    };
    const err = await assertHermesYamlParseParity(yaml, { exec }).catch(
      (e) => e
    );
    expect(err).toBeInstanceOf(HermesYamlParityRefusedError);
    expect((err as HermesYamlParityRefusedError).reason).toBe(
      "sidecar-unavailable"
    );
    expect(calls).toEqual([HOMEBREW, USRLOCAL]); // stopped at the first with PyYAML
  });
});

// -- Real-sidecar tests (skipped when bare `python3` cannot import PyYAML) --
//
// The gate stays keyed to bare `python3` (the production resolver now uses
// ABSOLUTE candidates only). This keeps the real-tests run/skip decision -- and
// therefore the Linux-CI passing count -- independent of the resolver's
// candidate set: coupling the gate to the absolute candidates could flip these
// tests' run/skip status on some hosts and make the `.test-baseline` count
// platform-dependent. The resolver's precedence (including the exact
// regression-host case) is covered deterministically by the injected-exec unit
// tests above; the drill host validates the real fix via the actual
// `protect --hermes` CLI, not vitest.
//
// HONEST caveat (the resolver no longer has a bare-`python3` fallback): the gate
// and the resolver CAN diverge on a host where bare `python3` imports yaml but
// none of the three absolute candidates does (e.g. a pyenv/conda/asdf box whose
// only PyYAML sits on a shim `python3`). There the gate runs these real tests
// while the resolver fail-closes, so a case like "resolves on real agreement"
// would spuriously FAIL. That is fail-SAFE (a false RED, never a false GREEN),
// touches no production surface, and is accepted to keep the CI baseline
// deterministic.

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

  it("REFUSES the real case-insensitive `Sanctuary`/`sanctuary` collision (P1, real parser)", async () => {
    // PyYAML keeps `Sanctuary` and `sanctuary` as DISTINCT keys (verified
    // here as ground truth). The planner would replace only the first, so the
    // guard must refuse rather than let a stale unwrapped sibling survive.
    const yaml = [
      "mcp_servers:",
      "  Sanctuary:",
      '    command: "old"',
      "  sanctuary:",
      '    command: "new"',
      "",
    ].join("\n");
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
    expect(realNames).toEqual(["Sanctuary", "sanctuary"]); // two distinct keys

    const err = await assertHermesYamlParseParity(yaml).catch((e) => e);
    expect(err).toBeInstanceOf(HermesYamlParityRefusedError);
    expect((err as HermesYamlParityRefusedError).reason).toBe("disagreement");
    expect((err as HermesYamlParityRefusedError).detail).toContain(
      "case-insensitively"
    );
  });

  it("REFUSES fail-closed when the real document top-level is a sequence (exit 23)", async () => {
    // A top-level YAML sequence: the scanner sees no mcp_servers block, and a
    // naive block=false would AGREE and drive an add-key that appends a
    // mapping onto a sequence (mixed types Hermes then rejects). The real
    // parser's exit 23 makes the guard refuse.
    const yaml = "- one\n- two\n";
    const err = await assertHermesYamlParseParity(yaml).catch((e) => e);
    expect(err).toBeInstanceOf(HermesYamlParityRefusedError);
    expect((err as HermesYamlParityRefusedError).reason).toBe(
      "sidecar-unavailable"
    );
    expect((err as HermesYamlParityRefusedError).detail).toContain(
      "non-mapping"
    );
  });
});

// -- CLI end-to-end fail-before / pass-after ------------------------------
//
// The unit tests above pin assertHermesYamlParseParity in isolation. These
// prove the wired behaviour through `runWrap`, which is the acceptance
// contract: a refusal must leave config.yaml UNTOUCHED (no mutation), and a
// legitimate wrap (agreement) must still edit as before (no regression).
// The sidecar is injected via the test-only __hermesParityTestHook (NOT a
// public runWrap dep - DI-bypass closed 2026-07-03) so the deterministic
// cases run on any host; the real-sidecar cases run where PyYAML is present.

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
    // Clear the test-only parse-parity override so it never leaks into a
    // test whose expectation is the real sidecar.
    clearHermesParityHook();
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

  /**
   * Base runWrap deps WITHOUT a parse-parity override: the sidecar seam is a
   * test-only module hook, not a public dep (DI-bypass closed 2026-07-03).
   * Tests that want a specific parity install it via installHermesParityHook()
   * BEFORE calling runWrap; tests that omit that get the real python3 sidecar.
   */
  function baseDeps(hermesParity?: ParseParityOptions): RunWrapDeps {
    if (hermesParity) installHermesParityHook(hermesParity);
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
      runWrap({ hermes: true, noOpen: true }, baseDeps())
    ).rejects.toThrow("process.exit:1");

    expect(await readFile(yamlPath, "utf-8")).toBe(original);
  });

  it("(P1 end-to-end) case-insensitive `Sanctuary`/`sanctuary` collision -> wrap REFUSES, no mutation", async () => {
    if (!realPyYaml) return; // real python3 + PyYAML required
    // Sanctuary first, sanctuary later: parity passes the multiset check
    // (both lowercase to two `sanctuary`) but the planner would replace only
    // `Sanctuary` and leave the later `sanctuary` stale + unwrapped. The
    // collision count in the REAL parse makes the guard refuse. FAIL-BEFORE:
    // without the count, wrap silently mis-edits and Hermes routes to the
    // stale entry. PASS-AFTER: refuse, file byte-for-byte untouched.
    const original = [
      "mcp_servers:",
      "  Sanctuary:",
      '    command: "old"',
      "  sanctuary:",
      '    command: "new"',
      "",
    ].join("\n");
    const yamlPath = await writeHermesConfig(original);

    await expect(
      runWrap({ hermes: true, noOpen: true }, baseDeps())
    ).rejects.toThrow("process.exit:1");

    expect(await readFile(yamlPath, "utf-8")).toBe(original);
    expect(stderrOutput()).toContain("Not Editable");
  });

  it("(MED end-to-end) top-level-sequence config.yaml -> wrap REFUSES, no mutation", async () => {
    if (!realPyYaml) return; // real python3 + PyYAML required
    // The whole document is a sequence. The scanner sees no mcp_servers
    // block; before the exit-23 signal, PyYAML collapsed to hasBlock=false
    // too -> agreement -> add-key would append a top-level `mcp_servers:`
    // mapping onto the sequence (mixed types Hermes rejects) while the
    // post-write scanner falsely reported success. FAIL-BEFORE: silent
    // corruption. PASS-AFTER: refuse, file untouched.
    const original = "- one\n- two\n";
    const yamlPath = await writeHermesConfig(original);

    await expect(
      runWrap({ hermes: true, noOpen: true }, baseDeps())
    ).rejects.toThrow("process.exit:1");

    expect(await readFile(yamlPath, "utf-8")).toBe(original);
    expect(stderrOutput()).toContain("Not Editable");
  });

  it("(HIGH end-to-end) production runWrap CANNOT bypass the real sidecar via a deps property", async () => {
    if (!realPyYaml) return; // real python3 + PyYAML required
    // A top-level-SEQUENCE config the REAL sidecar refuses (exit 23). The
    // scanner sees no mcp_servers block, so an AGREEING no-op parity (which
    // echoes the scanner's hasBlock=false) would slip past the disagreement
    // check and let add-key append a top-level `mcp_servers:` mapping onto
    // the sequence - corrupting the file into mixed types. A programmatic
    // caller tries to inject exactly that agreeing parity through the deps
    // object under the OLD public property name.
    //
    // FAIL-BEFORE (old code, deps.hermesParity honored on the mutating
    // path): the injected agreeing parity bypasses the real sidecar, wrap
    // proceeds, and the file is rewritten to `- one\n- two\nmcp_servers:...`
    // (verified: MUTATED=true). PASS-AFTER: the mutating path always runs the
    // real python3 PyYAML validator, ignores the injected parity, refuses on
    // exit 23, and leaves the file byte-for-byte untouched.
    const original = "- one\n- two\n";
    const yamlPath = await writeHermesConfig(original);

    // The hook is deliberately NOT installed. The cast models a programmatic
    // caller passing an unexpected extra property; it must have no effect on
    // the production mutating path.
    const bypassDeps = {
      ...baseDeps(),
      hermesParity: agreeingHermesParity,
    } as unknown as RunWrapDeps;

    await expect(
      runWrap({ hermes: true, noOpen: true }, bypassDeps)
    ).rejects.toThrow("process.exit:1");

    // The real sidecar ran and refused despite the injected agreeing parity:
    // the file is unchanged, no mcp_servers mapping was appended onto the
    // sequence.
    expect(await readFile(yamlPath, "utf-8")).toBe(original);
    expect(await readFile(yamlPath, "utf-8")).not.toContain("mcp_servers");
  });
});

// -- The interpreter-resolution CHOKEPOINT (probePyYamlCandidates) ---------
//
// One resolver, exported, so every consumer (the wrap guard, `sanctuary
// doctor`, any future preflight) measures the SAME predicate. The first fix
// attempt at this shipped RED because a second, hand-rolled copy resolved the
// first EXISTING python3 instead of the first one that can import yaml -- and
// the dev Mac is the INVERSE of the drill host, so the wrong rule passed
// locally and failed on the machine that mattered. Every case below simulates
// the host layout through the injected exec; none of them reads this machine.

describe("probePyYamlCandidates - resolve by capability, not existence", () => {
  const HOMEBREW = "/opt/homebrew/bin/python3";
  const USRLOCAL = "/usr/local/bin/python3";
  const SYSTEM = "/usr/bin/python3";

  it("THE INVERSE-LAYOUT CASE: an interpreter that EXISTS and runs but cannot import yaml loses to a later one that can", async () => {
    // Drill-host shape inverted onto the dev Mac: homebrew python is present
    // and perfectly runnable, it simply has no PyYAML. An existence-based
    // resolver stops there and fails; a capability-based one walks on.
    const { exec } = recordingResolverExec({ withPyYaml: [SYSTEM] });
    const probe = await probePyYamlCandidates("", { exec });
    expect(probe.selected?.interpreter).toBe(SYSTEM);
    expect(probe.outcomes).toEqual([
      { interpreter: HOMEBREW, status: "no-pyyaml" },
      { interpreter: USRLOCAL, status: "no-pyyaml" },
      { interpreter: SYSTEM, status: "usable" },
    ]);
  });


  it("distinguishes 'ran but no PyYAML' from 'could not be run at all'", async () => {
    // These two need OPPOSITE remedies (pip install here vs install python3
    // there), so collapsing them into one "tried: a, b, c" line sends the
    // operator to install PyYAML into a path that does not exist.
    const { exec } = recordingResolverExec({
      withPyYaml: [SYSTEM],
      absent: [HOMEBREW],
    });
    const probe = await probePyYamlCandidates("", { exec });
    expect(probe.outcomes).toEqual([
      { interpreter: HOMEBREW, status: "unrunnable" },
      { interpreter: USRLOCAL, status: "no-pyyaml" },
      { interpreter: SYSTEM, status: "usable" },
    ]);
  });

  it("records NO outcome for a candidate it never probed (stops at the first usable one)", async () => {
    // An unprobed candidate must never be reported as if it had been measured.
    const { exec, calls } = recordingResolverExec({ withPyYaml: [HOMEBREW] });
    const probe = await probePyYamlCandidates("", { exec });
    expect(calls).toEqual([HOMEBREW]);
    expect(probe.outcomes).toEqual([
      { interpreter: HOMEBREW, status: "usable" },
    ]);
  });

  it("selects nothing (fails closed) when no candidate can import yaml, and reports all three", async () => {
    const { exec } = recordingResolverExec({ withPyYaml: [] });
    const probe = await probePyYamlCandidates("", { exec });
    expect(probe.selected).toBeUndefined();
    expect(probe.outcomes.map((o) => o.interpreter)).toEqual([
      HOMEBREW,
      USRLOCAL,
      SYSTEM,
    ]);
    expect(probe.outcomes.every((o) => o.status === "no-pyyaml")).toBe(true);
  });
});

describe("describePyYamlCandidateFailure - name what was probed and what is wanted", () => {
  const HOMEBREW = "/opt/homebrew/bin/python3";
  const USRLOCAL = "/usr/local/bin/python3";

  it("names every interpreter probed, what each one turned out to be, and the remedy", async () => {
    const { exec } = recordingResolverExec({
      withPyYaml: [],
      absent: [HOMEBREW],
    });
    const probe = await probePyYamlCandidates("", { exec });
    const message = describePyYamlCandidateFailure(probe.outcomes);
    // Every candidate named...
    for (const candidate of hermesParityPythonCandidates()) {
      expect(message).toContain(candidate);
    }
    // ...with its ACTUAL outcome, not a single undifferentiated list...
    expect(message).toContain("could not be run");
    expect(message).toContain("ran but cannot import yaml");
    // ...and a remedy pointed at an interpreter that actually RAN, never at
    // the absent one (installing PyYAML into a path that is not there is the
    // advice the old undifferentiated "tried: a, b, c" message produced).
    expect(message).toContain(`"${USRLOCAL} -m pip install`);
    expect(message).not.toContain(`"${HOMEBREW} -m pip install`);
  });

  it("asks for python3 itself (never a pip install) when nothing could be run at all", async () => {
    const { exec } = recordingResolverExec({
      withPyYaml: [],
      absent: hermesParityPythonCandidates(),
    });
    const probe = await probePyYamlCandidates("", { exec });
    const message = describePyYamlCandidateFailure(probe.outcomes);
    expect(message).toContain("install python3 with PyYAML");
    expect(message).not.toContain("pip install");
  });
});

describe("assertHermesYamlParseParity - the refusal names each candidate's outcome", () => {
  const yaml = "mcp_servers:\n  weather:\n    command: \"uvx\"\n";
  const HOMEBREW = "/opt/homebrew/bin/python3";

  it("wrap's fail-closed refusal carries the per-candidate diagnosis, not just the list", async () => {
    const { exec } = recordingResolverExec({
      withPyYaml: [],
      absent: [HOMEBREW],
    });
    const err = await assertHermesYamlParseParity(yaml, { exec }).catch(
      (e) => e
    );
    expect(err).toBeInstanceOf(HermesYamlParityRefusedError);
    expect((err as HermesYamlParityRefusedError).reason).toBe(
      "sidecar-unavailable"
    );
    const message = (err as HermesYamlParityRefusedError).message;
    expect(message).toContain("PyYAML");
    expect(message).toContain(`${HOMEBREW} (could not be run`);
    expect(message).toContain("-m pip install");
  });
});
