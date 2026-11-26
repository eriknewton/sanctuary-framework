/**
 * The `verify-release` command handler: flags, help, the human and JSON
 * output contract, escaping, and exit codes. Production wiring is replaced
 * only through the injected `deps` object.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Writable } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";
import {
  VERIFY_RELEASE_HELP, VERIFY_RELEASE_REFUSED_EXIT_CODE, VERIFY_RELEASE_USAGE_EXIT_CODE, parseVerifyReleaseArgs, runVerifyReleaseCommand,
} from "../../src/cli/verify-release.js";
import { REFUSAL_REASON_BASES, escapeDetail, escapePrintable } from "../../src/verify-release/reasons.js";
import { STEP_NAMES } from "../../src/verify-release/evidence.js";
import { MAX_ARCHIVE_ENTRIES, MAX_INSTALLED_ENTRIES } from "../../src/verify-release/constants.js";
import { PRODUCTION_PROVENANCE } from "../../src/verify-release/run.js";
import { denyAllNetwork, fixtureJson, modelledRequester } from "./helpers.js";
import { VERSION, cleanupTempRoots, deps, install, release, routesFor, stubProvenance } from "./synthetic.js";
import { readFileSync } from "node:fs";

denyAllNetwork();
afterEach(cleanupTempRoots);

function sink(): Writable & { text: () => string } {
  const chunks: string[] = [];
  const stream = new Writable({ write(chunk, _enc, done) { chunks.push(String(chunk)); done(); } });
  return Object.assign(stream, { text: () => chunks.join("") });
}

async function invoke(argv: string[], overrides: Parameters<typeof deps>[1] | undefined = undefined, r = release()) {
  const out = sink();
  const err = sink();
  const code = await runVerifyReleaseCommand({ argv, entryModuleUrl: "file:///nonexistent/dist/cli.js", out, err, deps: deps(r, overrides) });
  return { code, out: out.text(), err: err.text() };
}

describe("flags", () => {
  it.each([
    [["--target", "a", "--target", "b"], "--target may only be provided once"],
    [["--target=a", "--target", "b"], "--target may only be provided once"],
    [["--version", "1.0.0", "--version", "1.0.0"], "--version may only be provided once"],
    [["--json", "--json"], "--json may only be provided once"],
    [["--target"], "--target requires a value"],
    [["--version"], "--version requires a value"],
    [["--target", "--json"], "--target requires a value"],
    [["--bogus"], "unrecognized argument"],
    [["positional"], "unrecognized argument"],
    [["-x"], "unrecognized argument"],
  ])("%j is a usage error", (argv, message) => {
    const parsed = parseVerifyReleaseArgs(argv);
    expect(parsed.ok).toBe(false);
    expect((parsed as { message: string }).message).toContain(message);
  });

  it("parses each flag once, in either form", () => {
    expect(parseVerifyReleaseArgs(["--target=/t", "--version", "1.0.0", "--json"])).toEqual({ ok: true, json: true, target: "/t", version: "1.0.0" });
    expect(parseVerifyReleaseArgs([])).toEqual({ ok: true, json: false });
  });

  it("a usage error exits 2, prints one stderr line, and nothing on stdout, in both modes, without echoing the token", async () => {
    for (const argv of [["--bogus-secret-value"], ["--json", "--bogus-secret-value"], ["--json", "--json"]]) {
      const { code, out, err } = await invoke(argv);
      expect(code).toBe(VERIFY_RELEASE_USAGE_EXIT_CODE);
      expect(out).toBe("");
      expect(err.split("\n").filter(Boolean)).toHaveLength(1);
      expect(err).not.toContain("secret");
    }
  });

  it("--help prints the help on stdout, exits 0 and makes zero requests, even with --json or other flags", async () => {
    for (const argv of [["--help"], ["-h"], ["--json", "--help"], ["--target", "/x", "--help"]]) {
      const r = release();
      const requester = modelledRequester({});
      const out = sink();
      const err = sink();
      const code = await runVerifyReleaseCommand({ argv, entryModuleUrl: "file:///x/dist/cli.js", out, err, deps: deps(r, { requester }) });
      expect(code).toBe(0);
      expect(out.text()).toBe(VERIFY_RELEASE_HELP);
      expect(err.text()).toBe("");
      expect(requester.calls).toEqual([]);
    }
  });
});

describe("output contract", () => {
  it("human mode: the target path, the version, one line per step, then the verdict; exit 0 on verified", async () => {
    const r = release();
    const root = install(r.files);
    const { code, out } = await invoke(["--target", root], {}, r);
    expect(code).toBe(0);
    expect(out).toBe([`target path: ${root}`, `version: ${VERSION}`, ...STEP_NAMES.map(s => `${s}: passed`), "verdict: verified", ""].join("\n"));
  });

  it("human mode refusal: the refusing step names the reason, later steps not-run, exit 3", async () => {
    const r = release();
    const root = install({ ...r.files, "extra.js": "x" });
    const { code, out } = await invoke(["--target", root], {}, r);
    expect(code).toBe(VERIFY_RELEASE_REFUSED_EXIT_CODE);
    expect(out).toContain("installed: refused (installed-file-extra:extra.js)\n");
    expect(out.endsWith("verdict: refused (installed-file-extra:extra.js)\n")).toBe(true);
  });

  it("--json: stdout is exactly one JSON object with verdict, version, target, steps and reason", async () => {
    const r = release();
    const root = install(r.files);
    const verified = await invoke(["--target", root, "--json"], {}, r);
    expect(verified.out.endsWith("\n")).toBe(true);
    expect(verified.out.trim().split("\n")).toHaveLength(1);
    expect(JSON.parse(verified.out)).toEqual({ verdict: "verified", version: VERSION, target: root, steps: STEP_NAMES.map(step => ({ step, result: "passed" })) });
    const refused = await invoke(["--target", root, "--json", "--version", "9.9.9"], {}, r);
    expect(refused.code).toBe(3);
    expect(JSON.parse(refused.out)).toMatchObject({ verdict: "refused", version: null, target: null, reason: "version-mismatch" });
  });

  it("target and version are null when the run stops before they are known", async () => {
    const { out } = await invoke(["--json"], { nodeVersion: "20.0.0" });
    expect(JSON.parse(out)).toMatchObject({ verdict: "refused", version: null, target: null, reason: "runtime-unsupported" });
  });

  it("an internal error exits 1 with one fixed stderr line, nothing on stdout, and no message from the error", async () => {
    const r = release();
    const provenance = { ...stubProvenance(r), identity: () => { throw new Error("SECRET-STACK-DETAIL"); } };
    for (const argv of [["--target", install(r.files)], ["--target", install(r.files), "--json"]]) {
      const { code, out, err } = await invoke(argv, { provenance }, r);
      expect(code).toBe(1);
      expect(out).toBe("");
      expect(err).toBe("sanctuary verify-release: internal error; no verdict was produced\n");
    }
  });

  it("a provenance bundle whose leaf certificate DER is malformed refuses at state_SIGSTORE in JSON with exit 3, not the internal-error exit", async () => {
    const r = release("1.8.4");
    const attestations = fixtureJson<{ attestations: Array<{ predicateType: string; bundle: any }> }>("attestations-1.8.4.json");
    const slsa = attestations.attestations.find(a => a.predicateType === "https://slsa.dev/provenance/v1")!;
    slsa.bundle.verificationMaterial.certificate.rawBytes = "AQ==";
    const requester = modelledRequester(routesFor(r, { attestations }));
    const { code, out, err } = await invoke(["--target", install(r.files), "--json"], { provenance: PRODUCTION_PROVENANCE, requester }, r);
    expect(err).toBe("");
    expect(code).toBe(VERIFY_RELEASE_REFUSED_EXIT_CODE);
    const report = JSON.parse(out);
    expect(report).toMatchObject({ verdict: "refused", reason: "sigstore-invalid:BUNDLE_INVALID" });
    expect(report.steps.find((s: { result: string }) => s.result === "refused")).toEqual({ step: "sigstore", result: "refused" });
  });

  it("a target path with a newline is escaped in both modes, so it cannot forge a line", async () => {
    const r = release();
    const parent = install({});
    const root = join(parent, "evil\nverdict: verified");
    mkdirSync(root);
    for (const [path, body] of Object.entries(r.files)) {
      mkdirSync(join(root, path, ".."), { recursive: true });
      writeFileSync(join(root, path), body);
    }
    const human = await invoke(["--target", root], {}, r);
    expect(human.out.split("\n").filter(line => line === "verdict: verified")).toHaveLength(1);
    expect(human.out).toContain("evil\\x0averdict: verified");
    const json = await invoke(["--target", root, "--json"], {}, r);
    expect(JSON.parse(json.out).target).toBe(escapePrintable(root));
  });
});

describe("escaping", () => {
  it("keeps printable ASCII, doubles backslashes, and hex-escapes everything else", () => {
    expect(escapeDetail("dist/a b.js")).toBe("dist/a b.js");
    expect(escapeDetail("a\\b")).toBe("a\\\\b");
    expect(escapeDetail("a\nb\u001b[31m")).toBe("a\\x0ab\\x1b[31m");
    expect(escapeDetail("café")).toBe("caf\\xc3\\xa9");
  });
  it("caps a detail at 256 characters on an escape boundary", () => {
    const long = escapeDetail("é".repeat(200));
    expect(long.length).toBeLessThanOrEqual(256);
    expect(long.endsWith("...")).toBe(true);
    expect(long.slice(0, -3)).toMatch(/^(\\x[0-9a-f]{2})+$/);
    expect(escapeDetail("x".repeat(256))).toBe("x".repeat(256));
    expect(escapeDetail("x".repeat(257))).toBe(`${"x".repeat(253)}...`);
  });
});

describe("reason vocabulary", () => {
  it("the source table documents every reason base, and the base list matches the union type's entries", () => {
    const source = readFileSync(join(__dirname, "..", "..", "src", "verify-release", "reasons.ts"), "utf8");
    const tabled = [...source.matchAll(/^ \* \| `([a-z-]+)(?::<[a-z]+>)?` \|/gm)].map(m => m[1]);
    expect(tabled).toEqual(REFUSAL_REASON_BASES);
    const unionBases = [...source.slice(source.indexOf("export type RefusalReason"), source.indexOf("export type FetchResource")).matchAll(/\| [`"]([a-z-]+)/g)].map(m => m[1]);
    expect(unionBases).toEqual(REFUSAL_REASON_BASES);
    expect(REFUSAL_REASON_BASES).toHaveLength(38);
  });
  it("the operator doc and the help name each installed-tree reason added for the bounded walk, and the doc states the walk's cap", () => {
    const doc = readFileSync(join(__dirname, "..", "..", "docs", "cli-operator-verbs.md"), "utf8");
    for (const reason of ["installed-file-unreadable", "installed-name-invalid", "installed-tree-oversize"]) {
      expect(doc).toContain(`\`${reason}`);
      expect(VERIFY_RELEASE_HELP).toContain(reason);
    }
    expect(doc).toContain(`(${MAX_INSTALLED_ENTRIES.toLocaleString("en-US")}: twice the archive's ${MAX_ARCHIVE_ENTRIES.toLocaleString("en-US")}-entry cap, plus one)`);
  });
});
