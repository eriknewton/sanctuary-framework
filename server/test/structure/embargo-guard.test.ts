/** Refuses ranges and PR text that cite listed ids, while retaining private input.
 * W24 runs the step under Darwin /bin/bash 3.2; the scanner uses PATH bash.
 * Linux executes the host bash and witnesses workflow wiring only.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { platform, tmpdir } from "node:os";
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
    const result = spawnSync("bash", [generator, input, "--salt", join(repo, saltPath)], { cwd: repo, env, encoding: "utf8" });
    completed(result);
    return result;
  };
  const seed = (ids = listed) => {
    put(saltPath, `${salt}\n`);
    const generated = generate(ids);
    expect(generated.status, generated.stderr).toBe(0);
    put(listPath, generated.stdout);
    base = commit("Initial fixture");
    git("switch", "-qc", "candidate");
  };
  const completed = (result: ReturnType<typeof spawnSync>) => {
    expect(result.error).toBeUndefined();
    expect(result.signal).toBeNull();
  };
  const fakeTool = (name: string, body: string) => {
    const bin = join(temp, "bin");
    mkdirSync(bin, { recursive: true });
    const file = join(bin, name);
    writeFileSync(file, `#!/usr/bin/env bash\n${body}\n`);
    chmodSync(file, 0o755); // Executable fixture tool, writable only by its owner.
    return `${bin}:${env.PATH}`;
  };
  const realTool = (name: string) => execFileSync("bash", ["-c", 'command -v "$1"', "fixture", name], { cwd: repo, env, encoding: "utf8" }).trim();
  const copyScripts = () => {
    mkdirSync(join(repo, "scripts/disclosure"), { recursive: true });
    for (const name of ["check-embargo.sh", "embargo-digest-lib.sh", "generate-embargo-digests.sh"]) {
      copyFileSync(join(scripts, name), join(repo, "scripts/disclosure", name));
    }
  };
  const scan = (head = git("rev-parse", "HEAD"), args: string[] = [], from = base, childPath = env.PATH) => {
    const result = spawnSync("bash", [scanner, "--repo", repo, "--base", from, "--head", head, ...args], { cwd: repo, env: { ...env, VITEST: env.VITEST, PATH: childPath }, encoding: "utf8", timeout: 60_000 }); // One minute bounds each synchronous fixture child.
    completed(result);
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
    put("content.txt", `${allowed} v1.2.3-RC-1 SHA-256.md`);
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
  it("W7 retains base membership after head removes the listed rows", () => {
    seed();
    const rows = readFileSync(join(repo, listPath), "utf8").split("\n");
    put(listPath, rows.filter((row) => ![digest(listed), digest(`DEFECT.${listed}`)].includes(row)).join("\n"));
    refusal(scan(commit(`Update fixture list ${listed}`)), "commit-message");
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
    completed(result);
    expect(result.stdout.trim()).toBe(digest("X-1", "fixture-salt"));
  });
  it("W13 wires the parsed workflow to every event and environment text binding", () => {
    // This must match the wiring in .github/workflows/embargo-guard.yml.
    const source = readFileSync(workflowPath, "utf8");
    const flow = yaml.load(source);
    expect(flow.name).toBe("embargo-guard");
    expect(flow.on.pull_request.types).toContain("edited");
    expect(flow.on.push.branches).toContain("main");
    expect(Object.keys(flow.on).sort()).toEqual(["pull_request", "push"]);
    expect(flow.jobs["embargo-guard"]["timeout-minutes"]).toBe(30); // Minutes, matching the scanner work budget.
    expect(flow.on).not.toHaveProperty("pull_request_target");
    expect(source).not.toMatch(/^\s*paths(?:-ignore)?:/m);
    expect(flow.permissions).toEqual({ contents: "read" });
    const steps = flow.jobs["embargo-guard"].steps;
    expect(steps.find((step: any) => step.uses === "actions/checkout@v7").with["fetch-depth"]).toBe(0);
    const consumers = steps.filter((step: any) => step.name === "Scan range and PR text");
    expect(consumers).toHaveLength(1);
    const run = consumers[0];
    expect(typeof run.run).toBe("string");
    expect(run.run).toMatch(/scripts\/disclosure\/check-embargo.sh --base "\$base" --head "\$head"/);
    for (const ref of ["github.event.pull_request.base.sha", "github.event.pull_request.head.sha", "github.event.before", "github.sha"]) expect(Object.values(run.env)).toContain(`\u0024{{ ${ref} }}`);
    for (const field of ["title", "body"]) {
      const refs = source.split("\n").filter((line) => line.includes(`github.event.pull_request.${field}`));
      expect(refs.length).toBe(1);
      expect(refs[0]).toMatch(new RegExp(`^\\s+PR_${field.toUpperCase()}:\\s*\\$\\{\\{\\s*github\\.event\\.pull_request\\.${field}\\s*\\}\\}\\s*$`));
    }
  });
  const workflowConsumer = () => {
    const flow = yaml.load(readFileSync(workflowPath, "utf8"));
    const consumers = flow.jobs["embargo-guard"].steps.filter((step: any) => step.name === "Scan range and PR text");
    expect(consumers).toHaveLength(1);
    const run = consumers[0].run;
    expect(typeof run).toBe("string");
    const bash = platform() === "darwin" ? "/bin/bash" : "bash";
    if (platform() === "darwin") {
      const version = spawnSync(bash, ["-c", 'printf "%s" "$BASH_VERSION"'], { cwd: repo, env, encoding: "utf8" });
      completed(version);
      expect(version.status).toBe(0);
      expect(version.stdout).toMatch(/^3\.2/);
    }
    return (event: string, head: string, title = "Fixture title", body = "", pushBase = base) => {
      const result = spawnSync(bash, ["-c", run], { cwd: repo, env: { ...env, VITEST: env.VITEST, EVENT_NAME: event, PR_BASE: base, PR_HEAD: head, PUSH_BASE: pushBase, EVENT_HEAD: head, PR_TITLE: title, PR_BODY: body }, encoding: "utf8" });
      completed(result);
      expect(result.stdout + result.stderr).not.toContain(listed);
      return result;
    };
  };
  it("W24 executes push and PR consumers with literal text", () => {
    copyScripts();
    seed();
    const execute = workflowConsumer();
    const clean = commit("Clean fixture");
    expect(execute("push", clean).status).toBe(0);
    refusal(execute("push", commit(`Event fixture ${listed}`)), "commit-message");
    refusal(execute("pull_request", clean, listed), "pr-title");
    refusal(execute("pull_request", clean, "Fixture title", `${listed} $(touch should-not-exist)`), "pr-body");
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
  it.each(["salt", "list"])("refuses inconsistent %s evidence", (kind) => {
    seed();
    put(kind === "list" ? listPath : saltPath, "invalid\n");
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
    completed(result);
    expect(result.status).toBe(2);
    expect(result.stdout + result.stderr).not.toContain(listed);
  });
  it.each(["leading", "before", "after"])("W14 scans %s NUL token boundaries with original indices", (kind) => {
    seed();
    const content = kind === "leading" ? `\0\0${listed}` : kind === "before" ? `word\0${listed}` : `${listed}\0word`;
    put("content.bin", `Innocuous record\n${content}\n${listed}\n`);
    const result = scan(commit("Add binary fixture"));
    refusal(result, "added-line");
    // The NUL record is second; the unaffected following record remains third.
    const prefix = digest(listed).slice(0, 12); // Public report uses twelve hex digits.
    expect(result.stdout).toBe(`FAIL EMB-01 added-line line 2 digest ${prefix}\nFAIL EMB-01 added-line line 3 digest ${prefix}\n`);
  });
  it.each(["addition", "rename"])("W15 scans %s destination paths privately", (kind) => {
    seed();
    if (kind === "rename") {
      put("source.txt", "Innocuous fixture content\n");
      base = commit("Prepare path fixture");
    }
    const path = kind === "rename" ? `docs/${listed}.md` : `${listed}.txt`;
    if (kind === "rename") {
      mkdirSync(join(repo, "docs"));
      git("mv", "source.txt", path);
    } else put(path, "");
    const result = scan(commit("Update fixture path"));
    refusal(result, "added-path");
    expect(result.stdout + result.stderr).not.toContain(path);
  });
  it("W15 preserves record indices for newline paths", () => {
    seed();
    put(`docs/first\n${listed}.txt`, "");
    const result = scan(commit("Add multiline path"));
    refusal(result, "added-path");
    expect(result.stdout).toContain("added-path line 1 digest");
  });
  it.each(["tokenizer", "digest"])("W16 checks %s completion", (kind) => {
    seed();
    const head = commit("Clean fixture");
    const marker = join(temp, "called");
    const input = text(allowed);
    let childPath: string;
    if (kind === "tokenizer") {
      const tr = realTool("tr");
      childPath = fakeTool("tr", `if [[ "$1" == a-z_ && "$2" == A-Z- ]]; then touch '${marker}'; exit 3; fi\nexec '${tr}' "$@"`);
    } else {
      childPath = fakeTool("sha256sum", `touch '${marker}'; exit 3`);
      fakeTool("shasum", `touch '${marker}'; exit 3`);
    }
    expect(scan(head, ["--text", `pr-body=${input}`], base, childPath).status).toBe(2);
    expect(existsSync(marker)).toBe(true);
  });
  it("W17a requires the head list", () => {
    seed();
    rmSync(join(repo, listPath));
    expect(scan(commit("Update fixture evidence")).status).toBe(2);
  });
  it("W17b accepts checked pre-guard evidence", () => {
    base = commit("Initial fixture");
    put(saltPath, `${salt}\n`);
    put(listPath, generate(listed).stdout);
    const clean = scan(commit("Introduce fixture evidence"));
    expect(clean.status).toBe(0);
    expect(clean.stderr).toContain("INFO base tree carries no list; head list only.");
    refusal(scan(commit(`Fixture citation ${listed}`)), "commit-message");
  });
  it("W17c checks evidence inventory completion", () => {
    base = commit("Initial fixture");
    put(saltPath, `${salt}\n`);
    put(listPath, generate(listed).stdout);
    const head = commit("Introduce fixture evidence");
    const realGit = realTool("git");
    const marker = join(temp, "called");
    const childPath = fakeTool("git", `if [[ "$3" == ls-tree && "$6" == '${base}' ]]; then touch '${marker}'; exit 128; fi\nexec '${realGit}' "$@"`);
    expect(scan(head, [], base, childPath).status).toBe(2);
    expect(existsSync(marker)).toBe(true);
  });
  it("W18a uses both regenerated rotation pairs", () => {
    seed();
    put(saltPath, `${"cd".repeat(32)}\n`); // Second 32-byte salt.
    put(listPath, generate(`${listed}\n${allowed}`).stdout);
    const clean = commit("Rotate fixture evidence");
    expect(scan(clean).status).toBe(0);
    refusal(scan(commit(`Fixture citation ${listed}`)), "commit-message");
    git("reset", "--hard", clean);
    refusal(scan(commit(`Fixture citation ${allowed}`)), "commit-message");
  });
  it("W18b retains the base rotation pair", () => {
    seed();
    put(saltPath, `${"cd".repeat(32)}\n`); // Second 32-byte salt.
    put(listPath, generate(allowed).stdout);
    const result = scan(commit(`Rotate fixture evidence ${listed}`));
    refusal(result, "commit-message");
    expect(result.stdout).toContain(`digest ${digest(listed).slice(0, 12)}`); // Public report prefix length.
  });
  it("W19 checks the global token budget before hashing", () => {
    seed();
    // One more than the scanner's 50000-token budget, in a single added record.
    put("content.txt", Array.from({ length: 50_001 }, (_, i) => `TESTEMB-TOKEN-${i}`).join(" "));
    const head = commit("Add token fixture");
    const marker = join(temp, "hashed");
    const childPath = fakeTool("sha256sum", `touch '${marker}'; exit 3`);
    fakeTool("shasum", `touch '${marker}'; exit 3`);
    const result = scan(head, [], base, childPath);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("ERROR embargo scanner cannot run: token bound exceeded");
    expect(existsSync(marker)).toBe(false);
  }, 90_000); // Child has a one-minute budget plus test setup and cleanup margin.
  it("W20 recognizes dotted citation suffixes", () => {
    seed();
    refusal(scan(commit(`Add ${listed}.txt`)), "commit-message");
    base = git("rev-parse", "HEAD");
    put("docs/defect.testemb-zulu-01.md", "");
    refusal(scan(commit("Add prefixed path fixture")), "added-path");
  });
  it("W21 emits exactly the supported short-slug membership", () => {
    put(saltPath, `${salt}\n`);
    const input = join(temp, "short.txt");
    writeFileSync(input, "defect.t7\n");
    const counter = join(temp, "counter");
    const childPath = fakeTool("openssl", `n=0; [[ ! -f '${counter}' ]] || read -r n < '${counter}'\nn=$((n + 1)); printf '%s\n' "$n" > '${counter}'; printf '%064x\n' "$n"`);
    const result = spawnSync("bash", [generator, input, "--salt", join(repo, saltPath)], { cwd: repo, env: { ...env, VITEST: env.VITEST, PATH: childPath }, encoding: "utf8" });
    completed(result);
    expect(result.status).toBe(0);
    const decoys = new Set(Array.from({ length: Number(readFileSync(counter, "utf8")) }, (_, i) => digest((i + 1).toString(16).padStart(64, "0")))); // 32-byte decoy preimages.
    const rows = result.stdout.trim().split("\n").slice(2); // Two header lines.
    expect(rows.filter((row) => !decoys.has(row))).toEqual([digest("DEFECT.T7")]);
    expect(rows).not.toContain(digest("T7"));
    put(listPath, result.stdout);
    base = commit("Initial fixture");
    expect(scan(commit("fixes t7")).status).toBe(0);
    refusal(scan(commit("see defect.t7")), "commit-message");
  });
  it("W22 keeps extracts physically outside the checkout", () => {
    copyScripts();
    put(saltPath, `${salt}\n`);
    put("extract.txt", listed);
    const outside = join(temp, "extract.txt");
    writeFileSync(outside, listed);
    for (const [input, status] of [[join(repo, "extract.txt"), 2], [outside, 0]] as const) {
      const result = spawnSync("bash", [join(repo, "scripts/disclosure/generate-embargo-digests.sh"), input], { cwd: repo, env, encoding: "utf8" });
      completed(result);
      expect(result.status).toBe(status);
    }
  });
  it("W23 publishes output only after random generation completes", () => {
    seed();
    const out = join(temp, "fresh-output");
    const childPath = fakeTool("openssl", "exit 3");
    const result = spawnSync("bash", [generator, join(temp, "extract.txt"), "--salt", join(repo, saltPath), "--out", out], { cwd: repo, env: { ...env, VITEST: env.VITEST, PATH: childPath }, encoding: "utf8" });
    completed(result);
    expect(result.status).toBe(2);
    expect(existsSync(out)).toBe(false);
  });

  it.each(["text", "pr-title", "pr-body", "extract", "salt"])("W25 acquires complete %s input before parsing", (surface) => {
    seed();
    const head = commit("Clean fixture");
    const original = surface === "extract" ? join(temp, "extract.txt") : surface === "salt" ? join(repo, saltPath) : text("Innocuous text\n");
    const out = join(temp, "fresh-output");
    const marker = join(temp, "acquired");
    const cat = realTool("cat");
    const childPath = fakeTool("cat", `if [[ $# -eq 2 && "$1" == -- && "$2" == '${original}' ]]; then printf called > '${marker}'; printf 'clean\n'; exit 1; fi\nexec '${cat}' "$@"`);
    const result = surface === "extract" || surface === "salt"
      ? spawnSync("bash", [generator, join(temp, "extract.txt"), "--salt", join(repo, saltPath), "--out", out], { cwd: repo, env: { ...env, VITEST: env.VITEST, PATH: childPath }, encoding: "utf8" })
      : scan(head, ["--text", `${surface}=${original}`], base, childPath);
    completed(result);
    expect(result.status).toBe(2);
    expect(existsSync(marker)).toBe(true);
    expect(result.stdout + result.stderr).not.toContain(listed);
    expect(result.stdout + result.stderr).not.toContain(original);
    expect(result.stderr).toContain(`ERROR embargo ${surface === "extract" || surface === "salt" ? "generator" : "scanner"} cannot run`);
    expect(existsSync(out)).toBe(false);
  });
  // Salt is exactly 64 lowercase hex bytes followed by LF; all other framing is refused.
  const malformedSalts = [
    ["NUL", `${salt}\0`], ["missing LF", salt], ["CRLF", `${salt}\r\n`],
    ["BOM", `\ufeff${salt}\n`], ["extra LF", `${salt}\n\n`],
  ];
  it.each(malformedSalts)("W26 validates raw salt framing %s", (_kind, bytes) => {
    seed();
    put(saltPath, bytes);
    const result = scan(commit("Update salt fixture"));
    expect(result.status).toBe(2);
    expect(result.stderr).toBe("ERROR embargo scanner cannot run\n");
    const generated = generate(listed);
    expect(generated.status).toBe(2);
    expect(generated.stderr).toBe("ERROR embargo generator cannot run\n");
    expect(generated.stdout).toBe("");
  });
  it("W26 validates raw digest rows before string conversion", () => {
    seed();
    const row = digest(listed);
    put(listPath, `${row.slice(0, 32)}\0${row.slice(32)}\n`); // NUL inserted between the two 32-hex halves.
    const result = scan(commit("Update row fixture"));
    expect(result.status).toBe(2);
    expect(result.stderr).toBe("ERROR embargo scanner cannot run\n");
  });
  it("W26 accepts complete salt framing and requires newline extract entries", () => {
    seed();
    expect(scan(base).status).toBe(0);
    const generated = generate(`${listed}\0word\n`);
    expect(generated.status).toBe(2);
    expect(generated.stderr).toBe("ERROR embargo generator cannot run\n");
    expect(generated.stdout).toBe("");
  });
  it("W27 requires a scanned push range", () => {
    copyScripts();
    seed();
    const execute = workflowConsumer();
    const result = execute("push", base, "Fixture title", "", zero);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("ERROR embargo workflow cannot scan a branch-creation push");
  });
  it("W28 requires hash readiness even for empty ranges", () => {
    seed();
    const bin = join(temp, "ready-bin");
    mkdirSync(bin);
    // Resolve every real tool before limiting the child's PATH; no inherited suffix is added.
    const names = ["bash", "git", "awk", "sort", "tr", "dirname", "mktemp", "unlink", "rmdir", "cat", "cut", "wc", "grep", "sed", "cmp", "basename", "openssl", "cp", "mv"];
    const resolved = names.map((name) => [name, realTool(name)]);
    const hashName = platform() === "darwin" ? "shasum" : "sha256sum";
    const hash = realTool(hashName);
    for (const [name, path] of resolved) symlinkSync(path, join(bin, name));
    symlinkSync(hash, join(bin, hashName));
    expect(scan(base, [], base, bin).status).toBe(0);
    rmSync(join(bin, hashName));
    expect(scan(base, [], base, bin).status).toBe(2);
    const out = join(temp, "fresh-output");
    const generated = spawnSync(join(bin, "bash"), [generator, join(temp, "extract.txt"), "--salt", join(repo, saltPath), "--out", out], { cwd: repo, env: { ...env, VITEST: env.VITEST, PATH: bin }, encoding: "utf8" });
    completed(generated);
    expect(generated.status).toBe(2);
    expect(generated.stderr).toBe("ERROR embargo generator cannot run\n");
    expect(existsSync(out)).toBe(false);
  });
  it("W29 preserves added-record indices through bulk normalization", () => {
    seed();
    // Five thousand records exercise bulk processing; the sole listed id is penultimate.
    const records = Array<string>(5000).fill("Innocuous record");
    records[4998] = listed; // Zero-based index for added-record 4999.
    put("content.txt", `${records.join("\n")}\n`);
    const result = scan(commit("Add bulk fixture"));
    refusal(result, "added-line");
    expect(result.stdout).toBe(`FAIL EMB-01 added-line line 4999 digest ${digest(listed).slice(0, 12)}\n`); // Twelve-hex report prefix.
  });
  it("W30 requires complete membership lookup evidence", () => {
    seed();
    const head = commit(`Fixture citation ${listed}`);
    const grep = realTool("grep");
    const marker = join(temp, "looked-up");
    const childPath = fakeTool("grep", `if [[ "$1" == -Fqx ]]; then printf called > '${marker}'; exit 2; fi\nexec '${grep}' "$@"`);
    const result = scan(head, [], base, childPath);
    expect(result.status).toBe(2);
    expect(existsSync(marker)).toBe(true);
  });

  it.each(["unlink", "rmdir"])("reports %s cleanup completion for both tools", (tool) => {
    seed();
    const marker = join(temp, "cleaned");
    const real = realTool(tool);
    const childPath = fakeTool(tool, `printf called > '${marker}'\n'${real}' "$@" || exit 2\nexit 1`);
    expect(scan(base, [], base, childPath).status).toBe(2);
    expect(existsSync(marker)).toBe(true);
    rmSync(marker);
    const result = spawnSync("bash", [generator, join(temp, "extract.txt"), "--salt", join(repo, saltPath)], { cwd: repo, env: { ...env, VITEST: env.VITEST, PATH: childPath }, encoding: "utf8" });
    completed(result);
    expect(result.status).toBe(2);
    expect(existsSync(marker)).toBe(true);
    // The real removal completes, but the wrapper's failed status still prevents success.
    expect(readdirSync(temp).filter((name) => name.startsWith("embargo-"))).toEqual([]);
  });

});
