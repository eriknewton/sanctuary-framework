/**
 * The ordered run. The success witness here is an ORCHESTRATION witness: a
 * synthetic tarball, a test-key manifest and a synthetic install go through
 * the real subject, manifest, archive and installed states, with provenance
 * evidence from an injected stub whose subject digest is the synthetic
 * tarball's sha512. The real 1.8.4 bundle with a synthetic tarball must refuse
 * at the subject state. Every continuing-path modifier combination is run.
 */
import { spawnSync } from "node:child_process";
import { mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { RUN_DEADLINE_MS, attestationsUrl, manifestUrl, tarballUrl, versionDocumentUrl } from "../../src/verify-release/constants.js";
import { Deadline } from "../../src/verify-release/deadline.js";
import { IncompleteEvidenceError, STEP_NAMES, constructVerifiedVerdict, mint, type VerdictEvidence } from "../../src/verify-release/evidence.js";
import { PRODUCTION_PROVENANCE, runVerifyRelease } from "../../src/verify-release/run.js";
import { state_BUNDLE_SELECT } from "../../src/verify-release/sigstore.js";
import { state_TARGET } from "../../src/verify-release/target.js";
import { ManualClock, attestations184, denyAllNetwork, fixtureJson, modelledRequester, response, sha512 } from "./helpers.js";
import { NAME, VERSION, cleanupTempRoots, deps, install, release, routesFor, stubProvenance, tempRoot } from "./synthetic.js";

denyAllNetwork();
afterEach(cleanupTempRoots);

const allPassed = STEP_NAMES.map(step => ({ step, result: "passed" }));

describe("orchestration witness", () => {
  it("ORCHESTRATION witness: synthetic tarball, test-key manifest and synthetic install reach verified through every state", async () => {
    const r = release();
    const root = install(r.files);
    const report = await runVerifyRelease({ target: root }, deps(r));
    expect(report).toEqual({ verdict: "verified", version: VERSION, target: root, steps: allPassed });
  });

  it("the real 1.8.4 bundle through the real provenance states with a synthetic 1.8.4 tarball refuses at state_SUBJECT", async () => {
    const r = release("1.8.4");
    const root = install(r.files);
    const routes = routesFor(r, { attestations: fixtureJson("attestations-1.8.4.json") });
    const report = await runVerifyRelease({ target: root }, deps(r, { provenance: PRODUCTION_PROVENANCE, requester: modelledRequester(routes) }));
    expect(report.verdict).toBe("refused");
    expect(report.reason).toBe("subject-digest-mismatch");
    expect(report.steps.map(s => s.result)).toEqual(["passed", "passed", "passed", "passed", "passed", "passed", "passed", "refused", "not-run", "not-run", "not-run"]);
  });

  it("a stub whose subject digest is not the tarball's refuses at state_SUBJECT", async () => {
    const r = release();
    const report = await runVerifyRelease({ target: install(r.files) }, deps(r, { provenance: stubProvenance(r, sha512(Buffer.from("x")).toString("hex")) }));
    expect(report).toMatchObject({ verdict: "refused", reason: "subject-digest-mismatch" });
  });

  it("a refusal stops the run: later steps are not-run and no request is made after it", async () => {
    const r = release();
    const requester = modelledRequester({ ...routesFor(r), [tarballUrl(r.version)]: () => response(503) });
    const report = await runVerifyRelease({ target: install(r.files) }, deps(r, { requester }));
    expect(report).toMatchObject({ verdict: "refused", reason: "fetch-failed:tarball" });
    expect(report.steps.map(s => s.result)).toEqual(["passed", "passed", "refused", ...Array(8).fill("not-run")]);
    expect(requester.calls).not.toContain(manifestUrl(r.version));
  });

  it.each([
    ["version-document", versionDocumentUrl(VERSION)],
    ["attestations", attestationsUrl(VERSION)],
    ["tarball", tarballUrl(VERSION)],
    ["manifest", manifestUrl(VERSION)],
  ])("a failure at %s refuses fetch-failed for that resource", async (resource, url) => {
    const r = release();
    const report = await runVerifyRelease({ target: install(r.files) }, deps(r, { requester: modelledRequester({ ...routesFor(r, { hops: 0 }), [url]: () => response(500) }) }));
    expect(report.reason).toBe(`fetch-failed:${resource}`);
  });

  it.each([
    ["version-document", versionDocumentUrl(VERSION), 128 * 1024],
    ["attestations", attestationsUrl(VERSION), 256 * 1024],
    ["manifest", manifestUrl(VERSION), 5 * 1024],
  ])("an oversize %s refuses fetch-oversize for that resource", async (resource, url, cap) => {
    const r = release();
    const report = await runVerifyRelease({ target: install(r.files) }, deps(r, { requester: modelledRequester({ ...routesFor(r, { hops: 0 }), [url]: () => response(200, Buffer.alloc(cap + 1, 0x20)) }) }));
    expect(report.reason).toBe(`fetch-oversize:${resource}`);
  });

  it("a document that is not JSON refuses fetch-failed for it", async () => {
    const r = release();
    const report = await runVerifyRelease({ target: install(r.files) }, deps(r, { requester: modelledRequester({ ...routesFor(r), [attestationsUrl(VERSION)]: () => response(200, "{") }) }));
    expect(report.reason).toBe("fetch-failed:attestations");
  });

  it("a version document naming another tarball URL refuses tarball-url-mismatch before the tarball is fetched", async () => {
    const r = release();
    (r.versionDocument as any).dist.tarball = "https://evil.example/mcp-server-3.1.0.tgz";
    const requester = modelledRequester(routesFor(r));
    const report = await runVerifyRelease({ target: install(r.files) }, deps(r, { requester }));
    expect(report.reason).toBe("tarball-url-mismatch");
    expect(requester.calls).toEqual([versionDocumentUrl(VERSION)]);
  });

  it("an attestations document with no SLSA bundle refuses provenance-absent", async () => {
    const r = release();
    const report = await runVerifyRelease({ target: install(r.files) }, deps(r, {}, { attestations: { attestations: [attestations184().attestations[0]] } }));
    expect(report.reason).toBe("provenance-absent");
  });

  it("repeated runs in one process carry no state", async () => {
    const r = release();
    const root = install(r.files);
    const failing = await runVerifyRelease({ target: root }, deps(r, { requester: modelledRequester({}) }));
    expect(failing.verdict).toBe("refused");
    const clock = new ManualClock();
    let t = 0;
    clock.now = () => (t += RUN_DEADLINE_MS);
    const expired = await runVerifyRelease({ target: root }, deps(r, { clock }));
    expect(expired.verdict).toBe("refused");
    expect((await runVerifyRelease({ target: root }, deps(r))).verdict).toBe("verified");
  });

  it("an unexpected throw from a step propagates (the CLI maps it to an internal error), never to verified", async () => {
    const r = release();
    const provenance = { ...stubProvenance(r), identity: () => { throw new Error("boom"); } };
    await expect(runVerifyRelease({ target: install(r.files) }, deps(r, { provenance }))).rejects.toThrow("boom");
  });
});

describe("continuing paths", () => {
  // Every combination of the orthogonal modifiers reaches verified only with the full evidence set.
  const combos: Array<[string, boolean, number, boolean, boolean, boolean]> = [];
  for (const mode of ["target", "self"]) for (const versionFlag of [false, true]) for (const hops of [0, 1, 2, 3])
    for (const withPublish of [false, true]) for (const nodeModules of [false, true]) for (const dsStore of [false, true])
      combos.push([mode, versionFlag, hops, withPublish, nodeModules, dsStore]);

  it(`all ${combos.length} combinations of target mode, --version, manifest hops, attestation set, node_modules and .DS_Store verify`, async () => {
    const r = release();
    const failures: string[] = [];
    for (const [mode, versionFlag, hops, withPublish, nodeModules, dsStore] of combos) {
      const root = install({
        ...r.files,
        ...(nodeModules ? { "node_modules/dep/index.js": "dep" } : {}),
        ...(dsStore ? { ".DS_Store": "x", "dist/.DS_Store": "x" } : {}),
      });
      if (nodeModules) symlinkSync("/etc", join(root, "node_modules", "dep", "link"));
      const request = { ...(mode === "target" ? { target: root } : {}), ...(versionFlag ? { version: VERSION } : {}) };
      const report = await runVerifyRelease(request, deps(r, mode === "self" ? { selfRoot: root } : {}, { hops, withPublish }));
      if (report.verdict !== "verified") failures.push(`${JSON.stringify({ mode, versionFlag, hops, withPublish, nodeModules, dsStore })}: ${report.reason}`);
    }
    expect(failures).toEqual([]);
  }, 120_000);
});

describe("deadline across the run", () => {
  it("expiry after the fetch, before the next step's evidence is accepted, refuses deadline-exceeded at that step", async () => {
    const r = release();
    const clock = new ManualClock();
    const provenance = { ...stubProvenance(r), bundleSelect: (doc: unknown) => { clock.advance(RUN_DEADLINE_MS); return state_BUNDLE_SELECT(doc); } };
    const report = await runVerifyRelease({ target: install(r.files) }, deps(r, { clock, provenance }));
    expect(report).toMatchObject({ verdict: "refused", reason: "deadline-exceeded" });
    expect(report.steps.find(s => s.step === "fetch")!.result).toBe("passed");
    expect(report.steps.find(s => s.step === "bundle-select")!.result).toBe("refused");
  });

  it("expiry immediately before the verdict, after every step passed, refuses deadline-exceeded", async () => {
    const r = release();
    const root = install(r.files);
    // Count the clock reads of a passing run; the last read is the verdict constructor's own check.
    let reads = 0;
    const counting = new ManualClock();
    counting.now = () => { reads += 1; return 0; };
    expect((await runVerifyRelease({ target: root }, deps(r, { clock: counting }))).verdict).toBe("verified");
    const total = reads;
    let second = 0;
    const late = new ManualClock();
    late.now = () => (++second >= total ? RUN_DEADLINE_MS : 0);
    const report = await runVerifyRelease({ target: root }, deps(r, { clock: late }));
    expect(report.steps).toEqual(allPassed);
    expect(report).toMatchObject({ verdict: "refused", reason: "deadline-exceeded" });
  });
});

describe("verdict constructor", () => {
  async function fullEvidence(): Promise<VerdictEvidence> {
    const r = release();
    const root = install(r.files);
    const target = await state_TARGET({ target: root }, "/x", VERSION);
    if (!target.ok) throw new Error("target");
    const evidence = {
      runtime: mint({ state: "state_RUNTIME", nodeVersion: "22.23.3" }),
      target: target.evidence,
      fetch: mint({ state: "state_FETCH", versionDocument: {}, attestations: {}, tarball: Buffer.alloc(0), manifest: {} }),
      bundle: mint({ state: "state_BUNDLE_SELECT", bundle: {} }),
      sigstore: mint({ state: "state_SIGSTORE", payload: Buffer.alloc(0), payloadType: "", certificate: { sanUri: undefined, extensions: [] }, integratedTime: 1 }),
      identity: mint({ state: "state_IDENTITY", repositoryUri: "", repositoryId: "", repositoryOwnerId: "", ref: "", trigger: "" }),
      statement: mint({ state: "state_STATEMENT", subjects: [] }),
      subject: mint({ state: "state_SUBJECT", sha512: Buffer.alloc(64) }),
      manifest: mint({ state: "state_MANIFEST", sha256: "" }),
      archive: mint({ state: "state_ARCHIVE", files: new Map(), directories: new Set() }),
      installed: mint({ state: "state_INSTALLED", fileCount: 0 }),
    } satisfies VerdictEvidence;
    return evidence;
  }

  it("builds verified from one minted evidence object per state", async () => {
    const deadline = new Deadline(new ManualClock(), RUN_DEADLINE_MS);
    expect(constructVerifiedVerdict(await fullEvidence(), deadline)).toMatchObject({ ok: true, verdict: { verdict: "verified", version: VERSION } });
  });

  it("refuses deadline-exceeded when the deadline has passed", async () => {
    const clock = new ManualClock();
    const deadline = new Deadline(clock, RUN_DEADLINE_MS);
    clock.advance(RUN_DEADLINE_MS);
    expect(constructVerifiedVerdict(await fullEvidence(), deadline)).toEqual({ ok: false, reason: "deadline-exceeded" });
  });

  it.each(["runtime", "target", "fetch", "bundle", "sigstore", "identity", "statement", "subject", "manifest", "archive", "installed"] as const)(
    "throws without %s evidence, or with an unminted or mislabelled object in its place",
    async field => {
      const deadline = new Deadline(new ManualClock(), RUN_DEADLINE_MS);
      const evidence = await fullEvidence();
      const { [field]: _removed, ...missing } = evidence;
      // @ts-expect-error: the constructor's type requires every evidence object.
      expect(() => constructVerifiedVerdict(missing, deadline)).toThrow(IncompleteEvidenceError);
      expect(() => constructVerifiedVerdict({ ...evidence, [field]: { ...evidence[field] } }, deadline)).toThrow(IncompleteEvidenceError);
      const other = field === "runtime" ? evidence.installed : evidence.runtime;
      expect(() => constructVerifiedVerdict({ ...evidence, [field]: other } as unknown as VerdictEvidence, deadline)).toThrow(IncompleteEvidenceError);
    },
  );
});

describe("state_TARGET", () => {
  const pkg = (body: unknown) => install({ "package.json": typeof body === "string" ? body : JSON.stringify(body) });

  it("resolves the realpath and the version from the target's package.json", async () => {
    const root = pkg({ name: NAME, version: VERSION });
    const link = join(tempRoot(), "link");
    symlinkSync(root, link);
    expect(await state_TARGET({ target: link }, "/x", "0.0.0")).toEqual({ ok: true, evidence: { state: "state_TARGET", root, version: VERSION, mode: "target" } });
  });
  it("another package refuses target-package-mismatch", async () => {
    expect(await state_TARGET({ target: pkg({ name: "@sigstore/verify", version: "4.1.4" }) }, "/x", "0")).toEqual({ ok: false, reason: "target-package-mismatch" });
  });
  it("--version differing from the target refuses version-mismatch; equal passes", async () => {
    const root = pkg({ name: NAME, version: VERSION });
    expect(await state_TARGET({ target: root, version: "3.1.1" }, "/x", "0")).toEqual({ ok: false, reason: "version-mismatch" });
    expect((await state_TARGET({ target: root, version: VERSION }, "/x", "0")).ok).toBe(true);
  });
  it.each(["3.1.0+build.1", "03.1.0", "3.1", "v3.1.0", "3.1.0-", "3.1.0-01"])("a malformed version (%s) refuses version-malformed", async version => {
    expect(await state_TARGET({ target: pkg({ name: NAME, version }) }, "/x", "0")).toEqual({ ok: false, reason: "version-malformed" });
  });
  it("accepts a prerelease version", async () => {
    expect((await state_TARGET({ target: pkg({ name: NAME, version: "1.9.0-rc.4" }) }, "/x", "0")).ok).toBe(true);
  });
  it.each([
    ["not JSON", "{"],
    ["not UTF-8", "�"],
    ["a JSON array", "[]"],
    ["a non-string name", JSON.stringify({ name: 1, version: VERSION })],
    ["a missing version", JSON.stringify({ name: NAME })],
  ])("a package.json that is %s refuses target-package-json-invalid", async (_label, text) => {
    const root = install({});
    writeFileSync(join(root, "package.json"), _label === "not UTF-8" ? Buffer.from([0xff, 0xfe]) : text);
    expect(await state_TARGET({ target: root }, "/x", "0")).toEqual({ ok: false, reason: "target-package-json-invalid" });
  });
  it("a missing target, a missing package.json, a package.json symlink or directory refuse target-unreadable", async () => {
    expect(await state_TARGET({ target: join(tempRoot(), "absent") }, "/x", "0")).toEqual({ ok: false, reason: "target-unreadable" });
    expect(await state_TARGET({ target: tempRoot() }, "/x", "0")).toEqual({ ok: false, reason: "target-unreadable" });
    const linked = tempRoot();
    const real = pkg({ name: NAME, version: VERSION });
    symlinkSync(join(real, "package.json"), join(linked, "package.json"));
    expect(await state_TARGET({ target: linked }, "/x", "0")).toEqual({ ok: false, reason: "target-unreadable" });
    const dir = tempRoot();
    mkdirSync(join(dir, "package.json"));
    expect(await state_TARGET({ target: dir }, "/x", "0")).toEqual({ ok: false, reason: "target-unreadable" });
  });
  it("a package.json that is a FIFO refuses target-unreadable without blocking", async () => {
    const root = tempRoot();
    expect(spawnSync("mkfifo", [join(root, "package.json")]).status).toBe(0);
    expect(await state_TARGET({ target: root }, "/x", "0")).toEqual({ ok: false, reason: "target-unreadable" });
  });
  it("a package.json over the read cap refuses target-unreadable", async () => {
    const root = install({ "package.json": JSON.stringify({ name: NAME, version: VERSION, pad: "x".repeat(128 * 1024) }) });
    expect(await state_TARGET({ target: root }, "/x", "0")).toEqual({ ok: false, reason: "target-unreadable" });
  });
  it("self mode uses the running root and requires the running version", async () => {
    const root = pkg({ name: NAME, version: VERSION });
    expect(await state_TARGET({}, root, VERSION)).toMatchObject({ ok: true, evidence: { mode: "self", root } });
    expect(await state_TARGET({}, root, "3.1.1")).toEqual({ ok: false, reason: "self-version-mismatch" });
  });
});
