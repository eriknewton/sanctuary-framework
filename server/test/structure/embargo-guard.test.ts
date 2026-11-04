/** Refuses ranges and PR text that cite listed ids, while retaining private input. */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const yaml = require("js-yaml") as { load(source: string): any };
const root = resolve(import.meta.dirname, "../../..");
const scripts = join(root, "scripts/disclosure");
const scanner = join(scripts, "check-embargo.sh");
const generator = join(scripts, "generate-embargo-digests.sh");
const lib = join(scripts, "embargo-digest-lib.sh");
const workflowPath = join(root, ".github/workflows/embargo-guard.yml");
const listPath = "scripts/disclosure/embargoed-id-digests.txt";
const saltPath = "scripts/disclosure/embargo-salt.txt";
const listed = "TESTEMB-ZULU-01";
const allowed = "TESTEMB-YANKEE-02";
// Thirty-two bytes, each represented by two hex characters.
const salt = "ab".repeat(32);
const zero = "0".repeat(40); // Git SHA-1 zero sentinel, not a commit.
// This must match embargo_digest in scripts/disclosure/embargo-digest-lib.sh.
const digest = (value: string, seed = salt) => createHash("sha256").update(`${seed}\n${value}`).digest("hex");

describe("embargo guard", () => {
  let temp: string;
  let repo: string;
  // The test-run signal keeps child credential access inside the test guard.
  const env: NodeJS.ProcessEnv = { VITEST: "true" };
  let base: string;
  let subjects: string[];

  const git = (...args: string[]) => execFileSync("git", args, { cwd: repo, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  const put = (path: string, body: string) => {
    mkdirSync(dirname(join(repo, path)), { recursive: true });
    writeFileSync(join(repo, path), body);
  };
  const commit = (subject: string) => {
    subjects.push(subject);
    git("add", ".");
    git("-c", "commit.gpgsign=false", "commit", "--no-verify", "--allow-empty", "-qm", subject);
    return git("rev-parse", "HEAD");
  };
  const generate = (ids: string) => {
    const input = join(temp, "extract.txt");
    writeFileSync(input, ids);
    return spawnSync("bash", [generator, input, "--salt", join(repo, saltPath)], { cwd: repo, env, encoding: "utf8" });
  };
  const seed = (ids = listed) => {
    put(saltPath, `${salt}\n`);
    const generated = generate(ids);
    expect(generated.status, generated.stderr).toBe(0);
    put(listPath, generated.stdout);
    base = commit("Initial fixture");
    git("switch", "-qc", "candidate");
  };
  const scan = (head = git("rev-parse", "HEAD"), args: string[] = [], from = base) => {
    const result = spawnSync("bash", [scanner, "--repo", repo, "--base", from, "--head", head, ...args], { cwd: repo, env, encoding: "utf8" });
    // W10: every scanner result is checked, so each continuing and refusing path stays private.
    const output = result.stdout + result.stderr;
    for (const value of [listed, listed.toLowerCase(), listed.replaceAll("-", "_"), ...subjects]) {
      expect(output).not.toContain(value);
    }
    expect(output).not.toContain("private-fixture-path");
    return result;
  };
  const refusal = (result: ReturnType<typeof scan>, surface: string) => {
    expect(result.status, result.stderr).toBe(1);
    expect(result.stdout).toMatch(new RegExp(`FAIL EMB-01 ${surface} line [0-9]+ digest [0-9a-f]{12}`));
  };
  const text = (value: string) => {
    const file = join(temp, "body.txt");
    writeFileSync(file, value);
    return file;
  };

  beforeEach(() => {
    temp = mkdtempSync(join(tmpdir(), "embargo-fixture-"));
    repo = join(temp, "repo");
    const home = join(temp, "home");
    mkdirSync(repo);
    mkdirSync(home);
    // Explicit environment prevents inherited git routing and operator credential access.
    Object.assign(env, { PATH: process.env.PATH, HOME: home, TMPDIR: temp, LC_ALL: "C", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null", GIT_TERMINAL_PROMPT: "0" });
    subjects = [];
    git("init", "-q");
    expect(realpathSync(git("rev-parse", "--show-toplevel"))).toBe(realpathSync(repo));
    git("config", "--local", "user.name", "Fixture");
    git("config", "--local", "user.email", "fixture@example.invalid");
    git("config", "--local", "core.hooksPath", "/dev/null");
  });
  afterEach(() => { rmSync(temp, { recursive: true, force: true }); });

  it("W1 refuses listed commit messages across the entire range", () => {
    seed();
    commit(`Fixture citation ${listed}`);
    refusal(scan(commit("Later clean fixture")), "commit-message");
  });
  it.each(["pr-body", "pr-title"])("W2 refuses listed %s text", (surface) => {
    seed();
    refusal(scan(commit("Clean fixture"), ["--text", `${surface}=${text(listed)}`]), surface);
  });
  it("W3 accepts unlisted ids on all three surfaces", () => {
    seed();
    put("content.txt", allowed);
    expect(scan(commit(`Allowed citation ${allowed}`), ["--text", `pr-body=${text(allowed)}`]).status).toBe(0);
  });
  it.each(["`testemb-zulu-01`.", "TESTEMB_ZULU_01"])("W4 normalizes %s", (value) => {
    seed();
    refusal(scan(commit(`Normalized citation ${value}`)), "commit-message");
  });
  it.each([listed, "defect.testemb-zulu-01"])("W5 recognizes node aliases %s", (value) => {
    seed("defect.testemb-zulu-01");
    refusal(scan(commit(`Alias citation ${value}`)), "commit-message");
  });
  it("W6 refuses added content including content beginning with plus signs", () => {
    seed();
    put("private-fixture-path.txt", `++ ${listed}\n`);
    refusal(scan(commit("Add fixture text")), "added-line");
  });
  it("W6 accepts removal of listed content", () => {
    seed();
    put("content.txt", listed);
    base = commit("Seed historical text");
    put("content.txt", "");
    expect(scan(commit("Remove fixture text")).status).toBe(0);
  });
  it("W7 retains base membership after head removes the list", () => {
    seed();
    rmSync(join(repo, listPath));
    refusal(scan(commit(`Remove fixture list ${listed}`)), "commit-message");
  });
  it("W8 permits a lift followed by a separate citation range", () => {
    seed();
    put(listPath, "# Lifted fixture list\n");
    const lift = commit("Lift fixture membership");
    expect(scan(lift).status).toBe(0);
    base = lift;
    expect(scan(commit(`Released fixture ${listed}`)).status).toBe(0);
  });
  it.each(["list", "salt"])("W9 refuses absent %s evidence", (missing) => {
    if (missing === "list") put(saltPath, `${salt}\n`);
    else put(listPath, `${digest(listed)}\n`);
    base = commit("Incomplete fixture evidence");
    expect(scan(commit("Clean fixture")).status).toBe(2);
  });
  it("W11 generates sorted padded aliases with the independently computed recipe", () => {
    put(saltPath, `${salt}\n`);
    const result = generate(`${listed}\n# Fixture comment\ndefect.testemb-yankee-02\nTESTEMB-ALPHA-THREE\n`);
    expect(result.status).toBe(0);
    const lines = result.stdout.trim().split("\n");
    const rows = lines.slice(2); // Exactly two public header lines.
    expect(lines[0]).toBe("# Salted digests for listed-id membership checks.");
    expect(lines[1]).toBe(`# Digest lines: ${rows.length}`);
    expect(rows.length % 16).toBe(0); // Padding bucket is sixteen rows.
    expect(rows).toEqual([...new Set(rows)].sort());
    expect(rows.every((row) => /^[0-9a-f]{64}$/.test(row))).toBe(true);
    for (const value of [listed, "TESTEMB-YANKEE-02", "TESTEMB-ALPHA-THREE"]) {
      expect(result.stdout.toLowerCase()).not.toContain(value.toLowerCase());
      expect(rows).toContain(digest(value));
      expect(rows).toContain(digest(`DEFECT.${value}`));
    }
  });
  it("W12 pins salt and newline hashing across implementations", () => {
    const result = spawnSync("bash", ["-c", 'source "$1"; embargo_digest fixture-salt X-1', "fixture", lib], { cwd: repo, env, encoding: "utf8" });
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe(digest("X-1", "fixture-salt"));
  });
  it("W13 wires the parsed workflow to every event and environment text binding", () => {
    // This must match the wiring in .github/workflows/embargo-guard.yml.
    const source = readFileSync(workflowPath, "utf8");
    const flow = yaml.load(source);
    expect(flow.name).toBe("embargo-guard");
    expect(flow.on.pull_request.types).toContain("edited");
    expect(flow.on.push.branches).toContain("main");
    expect(flow.on).toHaveProperty("workflow_dispatch");
    expect(flow.on).not.toHaveProperty("pull_request_target");
    expect(source).not.toMatch(/^\s*paths(?:-ignore)?:/m);
    expect(flow.permissions).toEqual({ contents: "read" });
    const steps = flow.jobs["embargo-guard"].steps;
    expect(steps.find((step: any) => step.uses === "actions/checkout@v7").with["fetch-depth"]).toBe(0);
    const run = steps.find((step: any) => step.run);
    expect(run.run).toMatch(/scripts\/disclosure\/check-embargo.sh --base "\$base" --head "\$head"/);
    for (const ref of ["github.event.pull_request.base.sha", "github.event.pull_request.head.sha", "github.event.before", "github.sha"]) expect(Object.values(run.env)).toContain(`\u0024{{ ${ref} }}`);
    for (const field of ["title", "body"]) {
      const refs = source.split("\n").filter((line) => line.includes(`github.event.pull_request.${field}`));
      expect(refs.length).toBe(1);
      expect(refs[0]).toMatch(new RegExp(`^\\s+PR_${field.toUpperCase()}:\\s*\\$\\{\\{\\s*github\\.event\\.pull_request\\.${field}\\s*\\}\\}\\s*$`));
    }
  });
  it.each(["pull_request", "push", "workflow_dispatch"])("W13 executes the workflow consumer for %s", (event) => {
    seed();
    const head = commit(event === "pull_request" ? "Clean fixture" : `Event fixture ${listed}`);
    for (const name of ["check-embargo.sh", "embargo-digest-lib.sh"]) copyFileSync(join(scripts, name), join(repo, "scripts/disclosure", name));
    const flow = yaml.load(readFileSync(workflowPath, "utf8"));
    const run = flow.jobs["embargo-guard"].steps.find((step: any) => step.run).run;
    const result = spawnSync("bash", ["-c", run], { cwd: repo, env: { ...env, VITEST: env.VITEST, EVENT_NAME: event, PR_BASE: base, PR_HEAD: head, PUSH_BASE: base, EVENT_HEAD: head, PR_TITLE: "Fixture title", PR_BODY: `${listed} $(touch should-not-exist)` }, encoding: "utf8" });
    expect(result.status, result.stderr).toBe(1);
    expect(result.stdout).toContain(event === "pull_request" ? "pr-body" : "commit-message");
    expect(result.stdout + result.stderr).not.toContain(listed);
    expect(existsSync(join(repo, "should-not-exist"))).toBe(false);
  });
  it("reads both parents from a merge checkout", () => {
    seed();
    const head = commit("Branch fixture");
    git("checkout", "-q", "--detach", base);
    put("base-only.txt", "base fixture");
    base = commit("Base advances");
    git("-c", "commit.gpgsign=false", "merge", "--no-ff", "-qm", "Merge fixture", head);
    expect(git("show", `${base}:${listPath}`)).toContain(digest(listed));
    expect(scan(head).status).toBe(0);
  });
  it("checks head additions to membership in the same range", () => {
    seed(allowed);
    put(listPath, generate(listed).stdout);
    refusal(scan(commit(`Added membership ${listed}`)), "commit-message");
  });
  it("uses head-only evidence for the zero base", () => {
    seed();
    refusal(scan(commit(`Head fixture ${listed}`), [], zero), "commit-message");
  });
  it("uses base salt when head omits it", () => {
    seed();
    rmSync(join(repo, saltPath));
    refusal(scan(commit(`Salt fixture ${listed}`)), "commit-message");
  });
  it.each(["salt", "list", "rotation"])("refuses inconsistent %s evidence", (kind) => {
    seed();
    put(kind === "list" ? listPath : saltPath, kind === "rotation" ? `${"cd".repeat(32)}\n` : "invalid\n");
    expect(scan(commit("Invalid fixture evidence")).status).toBe(2);
  });
  it("refuses an unreadable range and missing text", () => {
    seed();
    expect(scan("f".repeat(40)).status).toBe(2);
    expect(scan(base, ["--text", `pr-body=${join(temp, "absent")}`]).status).toBe(2);
  });
  it("preserves private labels in TSV reports", () => {
    seed();
    const result = scan(commit("Clean fixture"), ["--text", `${listed}=${text(listed)}`, "--format", "tsv"]);
    expect(result.status).toBe(1);
    expect(result.stdout).toMatch(/^FAIL\tEMB-01\ttext\tline\t1\tdigest\t[0-9a-f]{12}\n$/);
  });
  it.each(["TESTEMB-ALPHA-THREE", "defect.t7"])("accepts membership for the supported shape %s", (value) => {
    seed(value);
    refusal(scan(commit(`Shape fixture ${value}`)), "commit-message");
  });
  it("generates an empty bucket and refuses tracked extracts", () => {
    put(saltPath, `${salt}\n`);
    const empty = generate("");
    expect(empty.status).toBe(0);
    expect(empty.stdout.trim().split("\n")).toHaveLength(18); // Two header lines plus sixteen decoys.
    put("extract.txt", listed);
    git("add", "extract.txt");
    const result = spawnSync("bash", [generator, join(repo, "extract.txt"), "--salt", join(repo, saltPath)], { cwd: repo, env, encoding: "utf8" });
    expect(result.status).toBe(2);
    expect(result.stdout + result.stderr).not.toContain(listed);
  });
});
