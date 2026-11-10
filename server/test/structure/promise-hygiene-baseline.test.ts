import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readlinkSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';

const SERVER = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const DRIVER = 'server/scripts/promise-hygiene/run.mjs';
const POLICY = 'server/scripts/promise-hygiene/policy.mjs';
const FINGERPRINT = 'server/scripts/promise-hygiene/fingerprint.mjs';
const BASELINE = 'server/scripts/promise-hygiene/baseline.json';
const CONFIG = 'server/tsconfig.promise-hygiene.json';
const COMPILER_CONFIG = 'server/tsconfig.json';
const SOURCE = 'server/src/sample-ts.ts';
const COMMAND_TIMEOUT = 60_000; // A tiny Program and subprocess startup get one minute.
const CASE_TIMEOUT = 180_000; // Multi-measure transition cases run sequentially within three minutes.
const BUFFER_BYTES = 8 * 1024 * 1024; // Refusals are bounded to eight MiB per child.
const JSON_INDENT = 2;
const EXIT_REFUSED = 1; // Must match the refusal exit code in scripts/promise-hygiene/run.mjs.
const EXTENSIONS = ['ts', 'tsx', 'mts', 'cts', 'js', 'jsx', 'mjs', 'cjs'];
const LABEL = 'promise-hygiene-reanchor';
type Entry = { path: string; rule: string; kind: string; preimage: string; fingerprint: string };
type Baseline = { sources?: string[]; entries: Entry[]; compilerDigest?: string; driftDigest?: string; policyDigest?: string };
let root: string;
let seedCommit: string;
let baseline: Baseline;
let environment: NodeJS.ProcessEnv;
const journal = new Map<string, { text?: Buffer; link?: string }>();
const hash = (text: string) => createHash('sha256').update(text).digest('hex');
const read = (name: string) => readFileSync(join(root, name), 'utf8');
const git = (...args: string[]) => execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
function remember(name: string) {
  if (journal.has(name)) return;
  const file = join(root, name);
  journal.set(name, existsSync(file) ? lstatSync(file).isSymbolicLink() ? { link: readlinkSync(file) } : { text: readFileSync(file) } : {});
}
function put(name: string, text: string) {
  remember(name);
  mkdirSync(dirname(join(root, name)), { recursive: true });
  writeFileSync(join(root, name), text);
}
function remove(name: string) { remember(name); unlinkSync(join(root, name)); }
function link(name: string, target: string) { remember(name); symlinkSync(target, join(root, name)); }
function restore() {
  // Restore every fixture write, including failure paths; retain empty temp directories, never recursive-delete.
  for (const [name, original] of [...journal].reverse()) {
    const file = join(root, name);
    try { if (lstatSync(file).isFile() || lstatSync(file).isSymbolicLink()) unlinkSync(file); } catch { /* absent already */ }
    if (original.link !== undefined) symlinkSync(original.link, file);
    else if (original.text !== undefined) writeFileSync(file, original.text);
  }
  journal.clear();
}
const saveBaseline = (value: Baseline) => put(BASELINE, JSON.stringify(value, null, JSON_INDENT));
function command(args = [DRIVER], cwd = root) {
  // Preserve the test-isolation signal explicitly while fixture GITHUB variables remain isolated.
  const result = spawnSync(process.execPath, args, { cwd, encoding: 'utf8', timeout: COMMAND_TIMEOUT,
    maxBuffer: BUFFER_BYTES, env: { ...environment, VITEST: process.env.VITEST } });
  expect(result.error).toBeUndefined();
  return { status: result.status, stdout: result.stdout, output: `${result.stdout}${result.stderr}` };
}
function evaluate(expression: string) {
  const result = command(['--input-type=module', '-e', expression]);
  expect(result.status, result.output).toBe(0);
  return JSON.parse(result.stdout);
}
function measure(): Baseline {
  // Namespace imports keep round-one runs loadable; new-mode witnesses may explicitly exempt fail-before.
  return evaluate(`import * as driver from './${DRIVER}'; import * as policy from './${POLICY}';
    const m=await driver.measure(process.cwd());
    console.log(JSON.stringify({sources:m.sources,entries:m.entries,compilerDigest:m.compilerDigest,driftDigest:m.driftDigest,policyDigest:policy.POLICY_DIGEST}));`);
}
function remeasure() { const next = measure(); saveBaseline(next); return next; }
function accept(state?: string) {
  const result = command();
  expect(result.status, result.output).toBe(0);
  if (state) expect(JSON.parse(result.stdout).state).toBe(state);
  return JSON.parse(result.stdout);
}
function refuse(reason: string) {
  const result = command();
  expect(result.output).toContain(reason);
  expect(result.status).toBe(1);
}
function commit(message = 'fixture edit') {
  git('add', '-A');
  git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--allow-empty', '-qm', message);
  return git('rev-parse', 'HEAD');
}
function anchor(message = 'fixture seed') {
  if (!read(POLICY).includes('SEED_DIGEST')) return commit(message);
  // Round one cannot reanchor history. Make this synthetic scenario its own reviewed root,
  // so fail-before assertions reach the behavior under test rather than a seed setup refusal.
  const source = evaluate(`import {sourceDigest,manifest} from './${DRIVER}'; console.log(JSON.stringify(sourceDigest(process.cwd(),manifest(process.cwd()))));`);
  put(POLICY, read(POLICY).replace(/SEED_DIGEST = '[a-f0-9]+'/u, `SEED_DIGEST = '${hash(JSON.stringify(JSON.parse(read(BASELINE))))}'`)
    .replace(/SEED_SOURCE_DIGEST = '[a-f0-9]+'/u, `SEED_SOURCE_DIGEST = '${source}'`));
  git('add', '-A');
  const initial = git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit-tree', git('write-tree'), '-m', message);
  git('update-ref', 'HEAD', initial); return initial;
}
function pr(labeled = false, base = seedCommit) {
  const candidate = commit();
  const tree = git('rev-parse', 'HEAD^{tree}');
  const merge = git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit-tree', tree, '-p', base, '-p', candidate, '-m', 'synthetic merge');
  git('update-ref', 'HEAD', merge);
  put('event.json', JSON.stringify({ pull_request: { base: { sha: base }, labels: labeled ? [{ name: LABEL }] : [] } }));
  environment.GITHUB_ACTIONS = 'true'; environment.GITHUB_EVENT_NAME = 'pull_request'; environment.GITHUB_EVENT_PATH = join(root, 'event.json');
}
function freshEnvironment() {
  // Every ambient GITHUB_* variable is removed; only these explicit fixture values select modes.
  environment = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('GITHUB_')));
  Object.assign(environment, { GITHUB_ACTIONS: 'false', GITHUB_EVENT_NAME: '', GITHUB_EVENT_PATH: '', SANCTUARY_NO_UPDATE_CHECK: '1', npm_config_update_notifier: 'false' });
}
function fixtureCase(name: string, body: () => void) {
  it(name, () => {
    freshEnvironment();
    try { body(); }
    finally {
      git('update-ref', 'HEAD', seedCommit);
      git('read-tree', seedCommit);
      restore();
      git('checkout', seedCommit, '--', '.');
    }
  }, CASE_TIMEOUT);
}

beforeAll(() => {
  expect(existsSync(join(SERVER, 'scripts/promise-hygiene/run.mjs'))).toBe(true);
  root = mkdtempSync(join(tmpdir(), 'promise-hygiene-'));
  freshEnvironment();
  try {
    mkdirSync(join(root, 'server'), { recursive: true });
    link('server/node_modules', join(SERVER, 'node_modules'));
    for (const name of ['run.mjs', 'policy.mjs', 'fingerprint.mjs']) put(`server/scripts/promise-hygiene/${name}`, readFileSync(join(SERVER, 'scripts/promise-hygiene', name), 'utf8'));
    for (const name of ['tsconfig.promise-hygiene.json', 'package.json', 'package-lock.json', 'eslint.config.js']) put(`server/${name}`, readFileSync(join(SERVER, name), 'utf8'));
    put('.gitignore', '**/node_modules\nevent.json\n');
    put('server/tsconfig.json', JSON.stringify({ compilerOptions: { target: 'ES2022', module: 'ESNext', moduleResolution: 'bundler', strict: true, skipLibCheck: true, types: [], jsx: 'preserve' }, include: ['src/**/*'] }));
    for (const extension of EXTENSIONS) put(`server/src/sample-${extension}.${extension}`, `void Promise.resolve('seed-${extension}');\nexport {};\n`);
    put('server/src/clean.ts', 'export {};\n');
    put('server/src/context.ts', String.raw`if (/a\/\//.test('left')) { void Promise.resolve('context'); }` + '\nexport {};\n');
    git('init', '-q'); git('add', '-A');
    baseline = measure(); saveBaseline(baseline);
    // Round-one compatibility only: fixture-owned seed pins permit assertions to reach the old driver.
    if (read(POLICY).includes('SEED_DIGEST')) {
      const source = evaluate(`import {sourceDigest,manifest} from './${DRIVER}'; console.log(JSON.stringify(sourceDigest(process.cwd(),manifest(process.cwd()))));`);
      put(POLICY, read(POLICY).replace(/SEED_DIGEST = '[a-f0-9]+'/u, `SEED_DIGEST = '${hash(JSON.stringify(baseline))}'`).replace(/SEED_SOURCE_DIGEST = '[a-f0-9]+'/u, `SEED_SOURCE_DIGEST = '${source}'`));
    }
    seedCommit = commit('fixture seed');
  } finally {
    // The committed template remains in the fixture object database; files are restored before tests.
    restore();
  }
  git('checkout', seedCommit, '--', '.');
  symlinkSync(join(SERVER, 'node_modules'), join(root, 'server/node_modules'), 'dir');
  return () => { unlinkSync(join(root, 'server/node_modules')); };
}, CASE_TIMEOUT);

describe('promise diagnostic identities', () => {
  fixtureCase('accepts unchanged coverage and reports local advice', () => {
    const result = accept('ADVISORY');
    expect(result.notice).toBe('advisory, CI is the gate');
    expect(result.files).toBe(EXTENSIONS.length + 2); // Clean and branch-context fixtures supplement the matrix.
    expect(result.diagnostics).toBe(EXTENSIONS.length + 1);
  });
  fixtureCase('preserves whitespace and comments', () => { put(SOURCE, "\n// trivia\nvoid  Promise . resolve ( 'seed-ts' ) ;\nexport {};\n"); accept(); });
  fixtureCase('preserves regular expression branch identity', () => { put('server/src/context.ts', read('server/src/context.ts').replace("'left'", "'right'")); refuse('new diagnostic'); });
  fixtureCase('rejects inline suppression of a planted diagnostic', () => { put(SOURCE, read(SOURCE) + '// eslint-disable-next-line @typescript-eslint/no-floating-promises\nvoid Promise.resolve("new");\n'); refuse('new diagnostic'); });
  fixtureCase('rejects stale entries', () => { put(SOURCE, 'export {};\n'); refuse('stale baseline'); });
  fixtureCase('accepts a source fix and baseline shrink', () => { put(SOURCE, 'export {};\n'); saveBaseline({ ...baseline, entries: baseline.entries.filter(entry => entry.path !== SOURCE) }); pr(); accept('RETAINED'); });
  fixtureCase('rejects constant count replacement', () => { put(SOURCE, 'void Promise.resolve("replacement");\nexport {};\n'); refuse('new diagnostic'); });
  fixtureCase('rejects twin copy multiplicity', () => { put(SOURCE, read(SOURCE) + "void Promise.resolve('seed-ts');\n"); refuse('fingerprint collision'); });
  fixtureCase('rejects a fabricated baseline entry', () => { const preimage = JSON.stringify({ context: [], statement: [], tokenPosition: 0 }); saveBaseline({ ...baseline, entries: [...baseline.entries, { ...baseline.entries[0]!, preimage, fingerprint: hash(preimage) }] }); refuse('stale baseline'); });
  fixtureCase('rejects colluding source and baseline growth', () => { put(SOURCE, read(SOURCE) + 'void Promise.resolve("added");\n'); remeasure(); pr(); refuse('new diagnostic'); });
  fixtureCase('refuses a weakened fixed rule even with a label', () => { put(POLICY, read(POLICY).replace('ignoreVoid: false', 'ignoreVoid: true')); pr(true); refuse('policy drift'); });
  fixtureCase('rejects coverage configuration changes', () => { const config = JSON.parse(read(CONFIG)); config.exclude.push('src'); put(CONFIG, JSON.stringify(config)); refuse('configuration drift'); });
  fixtureCase('rejects installed lock version mismatch', () => { const lock = JSON.parse(read('server/package-lock.json')); lock.packages['node_modules/typescript-eslint'].version = '0.0.0'; put('server/package-lock.json', JSON.stringify(lock)); refuse('lockfile version drift'); });
  fixtureCase('rejects unresolved imports and parser errors', () => { put(SOURCE, "import { missing } from './absent.js';\nvoid missing();\n"); refuse('type/parser failure'); put(SOURCE, 'export const broken = ;\n'); refuse('type/parser failure'); });
  fixtureCase('rejects untracked imported source', () => { put('server/src/untracked.ts', 'export const value = 1;\n'); put(SOURCE, read(SOURCE) + "import './untracked.js';\n"); refuse('Program/manifest mismatch'); });
  fixtureCase('rejects a Program file beyond the source prefix', () => { put('server/outside.ts', 'export const value = 1;\n'); put(SOURCE, read(SOURCE) + "import '../outside.js';\n"); refuse('Program/manifest mismatch'); });
  fixtureCase('rejects a tracked executable module outside the manifest', () => {
    put('server/outside.mts', 'export const value = 1;\n'); git('add', 'server/outside.mts');
    put(SOURCE, read(SOURCE) + "import '../outside.mjs';\n"); refuse('Program/manifest mismatch');
  });
  fixtureCase('rejects an untracked declaration outside the manifest', () => {
    put('server/outside.d.mts', 'export declare const value: number;\n');
    put(SOURCE, read(SOURCE) + "import '../outside.mjs';\n"); refuse('Program/manifest mismatch');
  });
  fixtureCase('rejects a linked declaration outside the manifest', () => {
    put('server/target.d.mts', 'export declare const value: number;\n');
    link('server/outside.d.mts', 'target.d.mts'); git('add', 'server/target.d.mts', 'server/outside.d.mts');
    put(SOURCE, read(SOURCE) + "import '../outside.mjs';\n"); refuse('Program/manifest mismatch');
  });
  fixtureCase('rejects declaration git link mode with regular worktree bytes', () => {
    put('server/outside.d.mts', 'export declare const value: number;\n'); git('add', 'server/outside.d.mts');
    git('update-index', '--cacheinfo', `120000,${git('hash-object', 'server/outside.d.mts')},server/outside.d.mts`);
    put(SOURCE, read(SOURCE) + "import '../outside.mjs';\n"); refuse('Program/manifest mismatch');
  });
  fixtureCase('rejects a declaration worktree link under a regular index mode', () => {
    put('server/outside.d.mts', 'export declare const value: number;\n'); git('add', 'server/outside.d.mts');
    put('server/target.d.mts', read('server/outside.d.mts')); git('add', 'server/target.d.mts');
    remove('server/outside.d.mts'); link('server/outside.d.mts', 'target.d.mts');
    put(SOURCE, read(SOURCE) + "import '../outside.mjs';\n"); refuse('Program/manifest mismatch');
  });
  fixtureCase('accepts tracked declarations without making them lint targets', () => {
    for (const extension of ['ts', 'mts', 'cts']) {
      const declaration = `server/outside.d.${extension}`;
      put(declaration, 'export declare const value: number;\n'); git('add', declaration);
      put(SOURCE, read(SOURCE) + `import '../outside.${extension === 'ts' ? 'js' : extension === 'mts' ? 'mjs' : 'cjs'}';\n`);
    }
    const measured = evaluate(`import * as d from './${DRIVER}'; const m=await d.measure(process.cwd()); console.log(JSON.stringify({accepted:m.acceptedDeclarations,sources:m.sources}));`);
    expect(measured.accepted).toEqual(['server/outside.d.cts', 'server/outside.d.mts', 'server/outside.d.ts']);
    expect(measured.sources.some((name: string) => name.startsWith('server/outside'))).toBe(false);
    accept();
  });
  fixtureCase('ignores unrelated untracked trees', () => { put('untracked-tree/example.ts', 'void Promise.resolve("untracked");\n'); accept(); });
  fixtureCase('visits tracked generated looking paths', () => { put('server/src/dist/nested.ts', 'void Promise.resolve("nested");\nexport {};\n'); git('add', 'server/src/dist/nested.ts'); refuse('new diagnostic'); });
  fixtureCase('rejects new misused callbacks', () => { put(SOURCE, read(SOURCE) + 'const consume = (_callback: () => void): void => {};\nconsume(async () => {});\n'); refuse('new diagnostic'); });
  fixtureCase('accounts for inert disables', () => { put(SOURCE, '// eslint-disable-next-line @typescript-eslint/no-floating-promises\n' + read(SOURCE)); expect(accept().inertDisableNotices).toBe(1); });
  fixtureCase('rejects unknown notices', () => { put(DRIVER, read(DRIVER).replace('const entries = [];', "results[0].messages.push({ruleId:null,severity:1,message:'unknown configuration notice'}); const entries = [];")); refuse('unknown lint message'); });
  fixtureCase('rejects unresolved JavaScript imports', () => { put('server/src/sample-js.js', "import { missing } from './absent.js';\nvoid missing();\n"); refuse('type/parser failure'); });
  fixtureCase('rejects absent worktree source', () => { remove(SOURCE); refuse('ENOENT'); });
  fixtureCase('rejects a source symlink', () => { remove(SOURCE); link(SOURCE, join(root, 'server/src/sample-js.js')); refuse('linked source'); });
  fixtureCase('rejects a symlinked source component', () => { link('server/src/linked', join(root, 'server/src')); git('update-index', '--add', '--cacheinfo', `100644,${git('rev-parse', `HEAD:${SOURCE}`)},server/src/linked/sample-ts.ts`); refuse('linked source'); });
  fixtureCase('rejects index symlink mode despite a regular worktree file', () => { git('update-index', '--cacheinfo', `120000,${git('rev-parse', `HEAD:${SOURCE}`)},${SOURCE}`); refuse('linked source'); });
  fixtureCase('runs the package command with forwarded eslint arguments', () => {
    put(SOURCE, read(SOURCE) + 'void Promise.resolve("package-plant");\n');
    const result = spawnSync('npm', ['run', 'lint', '--', '--fix'], { cwd: join(root, 'server'), encoding: 'utf8', timeout: COMMAND_TIMEOUT, maxBuffer: BUFFER_BYTES, env: { ...environment, VITEST: process.env.VITEST } });
    expect(result.error).toBeUndefined(); expect(`${result.stdout}${result.stderr}`).toContain('new diagnostic'); expect(result.status).toBe(1);
  });
});

describe('trusted transitions', () => {
  fixtureCase('accepts a clean file rename', () => { put('server/src/renamed.ts', read('server/src/clean.ts')); remove('server/src/clean.ts'); pr(); accept('RETAINED'); });
  fixtureCase('accepts a conserved diagnostic move without a sources floor', () => { put('server/src/renamed.ts', read(SOURCE)); remove(SOURCE); saveBaseline({ ...baseline, entries: baseline.entries.map(entry => entry.path === SOURCE ? { ...entry, path: 'server/src/renamed.ts' } : entry) }); pr(); accept('RETAINED'); });
  fixtureCase('accepts deletion of a source and its entries', () => { remove(SOURCE); saveBaseline({ ...baseline, entries: baseline.entries.filter(entry => entry.path !== SOURCE) }); pr(); accept('RETAINED'); });
  fixtureCase('rejects changed hash delete and add', () => { remove(SOURCE); put('server/src/renamed.ts', 'void Promise.resolve("different");\nexport {};\n'); git('add', '-A'); remeasure(); pr(); refuse('new diagnostic'); });
  fixtureCase('consumes a move donor only once', () => { for (const name of ['one', 'two']) put(`server/src/${name}.ts`, read(SOURCE)); remove(SOURCE); git('add', '-A'); remeasure(); pr(); refuse('new diagnostic'); });
  fixtureCase('rejects a donor that is still tracked', () => { put('server/src/renamed.ts', read(SOURCE)); put(SOURCE, 'export {};\n'); git('add', '-A'); remeasure(); pr(); refuse('new diagnostic'); });
  fixtureCase('rejects a destination that was a clean base file', () => { put('server/src/clean.ts', read(SOURCE)); remove(SOURCE); git('add', '-A'); remeasure(); pr(); refuse('new diagnostic'); });
  fixtureCase('rejects both tracked spellings in a case only move', () => {
    // Git tree names are case-sensitive on every host; no conflicting worktree files are needed.
    // Must match shrink() in run.mjs: a surviving donor path cannot fund a moved identity.
    const destination = 'server/src/Sample-ts.ts';
    const moved = { ...baseline, entries: baseline.entries.map(entry => entry.path === SOURCE ? { ...entry, path: destination } : entry) };
    const result = command(['--input-type=module', '-e', `import {shrink} from './${DRIVER}';
      shrink(${JSON.stringify(baseline)}, ${JSON.stringify(moved)}, new Set([${JSON.stringify(SOURCE)}]),
        new Set([${JSON.stringify(SOURCE)}, ${JSON.stringify(destination)}]));`]);
    expect(result.output).toContain('new diagnostic:');
    expect(result.output).not.toContain('type/parser failure');
    expect(result.status).toBe(EXIT_REFUSED);
  });
  fixtureCase('counts a rename out of the source prefix as a source change', () => {
    git('config', 'diff.renames', 'true');
    try {
      put('server/moved-clean.ts', read('server/src/clean.ts')); remove('server/src/clean.ts');
      put(DRIVER, read(DRIVER) + '\n// reviewed fixture comment\n');
      pr(); refuse('checker and source changes require reanchor label');
    } finally { git('config', '--unset', 'diff.renames'); }
  });
  fixtureCase('compares the final tree after an unrelated second commit', () => { put(SOURCE, read(SOURCE) + 'void Promise.resolve("surviving");\n'); remeasure(); commit('first addition'); put('unrelated.txt', 'unrelated\n'); commit('second unrelated'); pr(); refuse('new diagnostic'); });
  fixtureCase('accepts removal of an intermediate addition before the final tree', () => { put(SOURCE, read(SOURCE) + 'void Promise.resolve("temporary");\n'); remeasure(); commit(); git('checkout', seedCommit, '--', SOURCE, BASELINE); pr(); accept('RETAINED'); });
  fixtureCase('proves a shallow synthetic merge with both parents', () => { pr(); put('.git/shallow', git('rev-parse', 'HEAD^1') + '\n' + git('rev-parse', 'HEAD^2') + '\n'); accept('RETAINED'); });
  fixtureCase('refuses a missing base object', () => { pr(); put('event.json', JSON.stringify({ pull_request: { base: { sha: 'f'.repeat(40) }, labels: [{ name: LABEL }] } })); refuse('trusted parent baseline not available'); });
  fixtureCase('refuses a missing first parent despite a matching event', () => { pr(); put('.git/shallow', git('rev-parse', 'HEAD') + '\n'); refuse('trusted parent baseline not available'); });
  fixtureCase('refuses a non merge pull request head', () => { environment.GITHUB_ACTIONS = 'true'; environment.GITHUB_EVENT_NAME = 'pull_request'; put('event.json', JSON.stringify({ pull_request: { base: { sha: seedCommit }, labels: [] } })); environment.GITHUB_EVENT_PATH = join(root, 'event.json'); refuse('trusted parent baseline not available'); });
  fixtureCase('does not accept a ref override as base authority', () => { put(SOURCE, read(SOURCE) + 'void Promise.resolve("override");\n'); remeasure(); pr(); environment.PROMISE_HYGIENE_TRUSTED_REF = 'HEAD^2'; refuse('new diagnostic'); });
  for (const event of ['push', 'workflow_dispatch', 'other']) fixtureCase(`verifies exact sets for ${event}`, () => { environment.GITHUB_ACTIONS = 'true'; environment.GITHUB_EVENT_NAME = event; accept('VERIFIED'); put(SOURCE, read(SOURCE) + 'void Promise.resolve("new");\n'); refuse('new diagnostic'); remeasure(); accept('VERIFIED'); });
  for (const labeled of [false, true]) fixtureCase(`requires external authorization to initialize with label ${labeled}`, () => {
    git('update-index', '--force-remove', BASELINE);
    const tree = git('write-tree');
    const emptyBase = git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit-tree', tree, '-m', 'before checker');
    pr(labeled, emptyBase);
    if (labeled) accept('INITIAL_SEED'); else refuse('initialization requires reanchor label');
  });
  fixtureCase('does not reinitialize a base with a baseline', () => { put(SOURCE, read(SOURCE) + 'void Promise.resolve("growth");\n'); remeasure(); pr(true); refuse('new diagnostic'); });
  for (const labeled of [false, true]) fixtureCase(`checks simultaneous executable and source changes with label ${labeled}`, () => { put(DRIVER, read(DRIVER) + '\n// reviewed fixture comment\n'); put(SOURCE, read(SOURCE) + '\n// source comment\n'); pr(labeled); if (labeled) accept('RETAINED'); else refuse('checker and source changes'); });
  fixtureCase('refuses invalid trusted baseline structure', () => { saveBaseline({ entries: [] }); const invalid = commit(); saveBaseline(baseline); pr(true, invalid); refuse('trusted parent baseline not available'); });
  fixtureCase('refuses invalid trusted baseline bytes', () => { put(BASELINE, '{invalid json'); const invalid = commit(); saveBaseline(baseline); pr(true, invalid); refuse('trusted parent baseline not available'); });
});

describe('configuration and isolation', () => {
  fixtureCase('prints measured digest fields after a lockfile byte change', () => {
    put('server/package-lock.json', read('server/package-lock.json') + '\n');
    const measured = measure();
    const result = command();
    expect(result.status).toBe(EXIT_REFUSED);
    expect(result.output).toContain('stored configuration drift');
    expect(result.output).toContain(`${BASELINE}: compilerDigest=${measured.compilerDigest}, driftDigest=${measured.driftDigest}`);
  });
  for (const name of [BASELINE, CONFIG, 'server/package-lock.json']) fixtureCase(`refuses linked metadata ${name}`, () => {
    const target = `${name}.target`;
    put(target, read(name)); remove(name); link(name, join(root, target));
    refuse('linked metadata');
  });
  // Four drift/set combinations, each with and without the external label.
  for (const drift of [false, true]) for (const changed of [false, true]) for (const labeled of [false, true]) fixtureCase(`handles drift ${drift} identity change ${changed} label ${labeled}`, () => {
    // Nullable promise assignability changes with strictNullChecks, without a source edit.
    put('server/src/conditional.ts', 'export function check(value: Promise<void> | undefined): void { if (value) {} }\n');
    git('add', '-A'); remeasure(); const base = anchor('conditional seed');
    if (drift) put('server/package-lock.json', read('server/package-lock.json') + '\n');
    if (changed && drift) { const config = JSON.parse(read(COMPILER_CONFIG)); config.compilerOptions.strictNullChecks = false; put(COMPILER_CONFIG, JSON.stringify(config)); }
    if (changed && !drift) put(SOURCE, read(SOURCE) + 'void Promise.resolve("new");\n');
    const next = remeasure();
    const previous = JSON.parse(git('show', `${base}:${BASELINE}`)) as Baseline;
    expect(next.entries.length === previous.entries.length).toBe(!changed);
    pr(labeled, base);
    if (changed && !drift) refuse('new diagnostic');
    else if (changed && !labeled) refuse('configuration drift');
    else accept(changed ? 'REANCHORED' : 'RETAINED');
  });
  fixtureCase('refuses source changes during a labeled reanchor', () => { put('server/package-lock.json', read('server/package-lock.json') + '\n'); put(SOURCE, read(SOURCE) + 'void Promise.resolve("new");\n'); remeasure(); pr(true); refuse('configuration drift'); });
  fixtureCase('rejects copied digests after strict option override', () => { const config = JSON.parse(read(COMPILER_CONFIG)); config.compilerOptions.strictNullChecks = false; put(COMPILER_CONFIG, JSON.stringify(config)); pr(true); refuse('stored configuration drift'); });
  fixtureCase('hashes plugin options', () => { const before = measure(); const config = JSON.parse(read(COMPILER_CONFIG)); config.compilerOptions.plugins = [{ name: 'fixture-plugin' }]; put(COMPILER_CONFIG, JSON.stringify(config)); const after = measure(); expect(after.compilerDigest).not.toBe(before.compilerDigest); });
  fixtureCase('hashes conditional package resolution before accepting a shrink', () => {
    // A fixture package sits in its own node_modules, never the shared installed modules.
    put('server/src/node_modules/conditional-fixture/package.json', JSON.stringify({ name: 'conditional-fixture', type: 'module', exports: { '.': { promise: './promise.d.ts', default: './void.d.ts' } } }));
    put('server/src/node_modules/conditional-fixture/promise.d.ts', 'export declare function work(): Promise<void>;\n');
    put('server/src/node_modules/conditional-fixture/void.d.ts', 'export declare function work(): void;\n');
    put(SOURCE, 'import { work } from "conditional-fixture";\nwork();\n');
    const config = JSON.parse(read(COMPILER_CONFIG)); config.compilerOptions.customConditions = ['promise']; put(COMPILER_CONFIG, JSON.stringify(config));
    remeasure(); const base = anchor('conditional export seed');
    config.compilerOptions.customConditions = []; put(COMPILER_CONFIG, JSON.stringify(config));
    const next = remeasure(); expect(next.entries.length).toBe(baseline.entries.length - 1);
    pr(false, base); refuse('configuration drift');
  });
  fixtureCase('canonicalizes checkout paths and covers every emit exclusion', () => {
    const result = evaluate(`import * as d from './${DRIVER}'; import * as p from './${POLICY}';
      const names=['outDir','declaration','declarationMap','declarationDir','sourceMap','inlineSourceMap','inlineSources','removeComments','noEmit','emitDeclarationOnly','incremental','tsBuildInfoFile','composite','pretty','preserveWatchOutput','listFiles','listEmittedFiles','traceResolution','diagnostics','extendedDiagnostics'];
      const first={baseUrl:'/one/server',rootDir:'/one/server/src',rootDirs:['/one/server/src'],typeRoots:['/one/server/types'],paths:{'@/*':['src/*']},configFilePath:'/one/server/tsconfig.json',pathsBasePath:'/one/server'};
      const second=JSON.parse(JSON.stringify(first).replaceAll('/one','/two'));
      console.log(JSON.stringify({available:typeof d.compilerDigest==='function',names:p.EMIT_ONLY_OPTIONS,
      equal:typeof d.compilerDigest==='function' && d.compilerDigest('/one',first)===d.compilerDigest('/two',second),
      ignored:typeof d.compilerDigest==='function' && names.every(name=>d.compilerDigest('/one',{...first,[name]:true})===d.compilerDigest('/one',first))}));`);
    expect(result.available).toBe(true); expect(result.equal).toBe(true); expect(result.ignored).toBe(true);
    // Must match policy.mjs: denylist equality, not a permissive subset.
    expect(result.names).toEqual(['outDir', 'declaration', 'declarationMap', 'declarationDir', 'sourceMap', 'inlineSourceMap', 'inlineSources', 'removeComments', 'noEmit', 'emitDeclarationOnly', 'incremental', 'tsBuildInfoFile', 'composite', 'pretty', 'preserveWatchOutput', 'listFiles', 'listEmittedFiles', 'traceResolution', 'diagnostics', 'extendedDiagnostics']);
  });
  fixtureCase('refuses compiler paths outside the repository', () => {
    const config = JSON.parse(read(COMPILER_CONFIG)); config.compilerOptions.typeRoots = ['/outside/types']; put(COMPILER_CONFIG, JSON.stringify(config));
    refuse('compiler path outside repository');
  });
  fixtureCase('keeps compiler digests stable across actual checkouts', () => {
    const other = mkdtempSync(join(tmpdir(), 'promise-checkout-'));
    try {
      execFileSync('git', ['clone', '--quiet', '--shared', root, other], { stdio: 'pipe' });
      symlinkSync(join(SERVER, 'node_modules'), join(other, 'server/node_modules'), 'dir');
      const script = `import * as d from './${DRIVER}'; const m=await d.measure(process.cwd()); console.log(JSON.stringify({compiler:m.compilerDigest,drift:m.driftDigest}));`;
      const first = evaluate(script);
      expect(typeof first.compiler).toBe('string'); expect(typeof first.drift).toBe('string');
      const second = command(['--input-type=module', '-e', script], other);
      expect(second.status, second.output).toBe(0); expect(JSON.parse(second.stdout)).toEqual(first);
    } finally {
      // Only synthetic checkout files are unlinked; empty directories and object storage are retained.
      for (const name of git('ls-files', '-z').split('\0').filter(Boolean)) {
        const file = join(other, name); if (existsSync(file)) unlinkSync(file);
      }
      const modules = join(other, 'server/node_modules'); if (existsSync(modules)) unlinkSync(modules);
    }
  });
  fixtureCase('never evaluates project eslint configuration', () => {
    remember('sentinel');
    put('server/eslint.config.js', 'import fs from "node:fs"; fs.writeFileSync("../sentinel","ran"); throw new Error("hostile config ran");\n');
    put(SOURCE, read(SOURCE) + 'void Promise.resolve("isolation");\n'); refuse('new diagnostic'); expect(existsSync(join(root, 'sentinel'))).toBe(false);
  });
  fixtureCase('prevents project configuration from hiding a diagnostic', () => {
    put('server/eslint.config.js', 'export default [{ignores:["src/**"],linterOptions:{noInlineConfig:false},rules:{"@typescript-eslint/no-floating-promises":"off","@typescript-eslint/no-misused-promises":"off"}}];\n');
    put(SOURCE, read(SOURCE) + 'void Promise.resolve("isolation");\n'); refuse('new diagnostic');
  });
});

const callbackForms = {
  call: 'declare function use(callback: () => void): void;\nuse(async () => { BODY });',
  constructor: 'declare class Use { constructor(callback: () => void); }\nnew Use(async () => { BODY });',
  iife: '(function use(callback: () => void): void {})(async () => { BODY });',
  'iife body': 'await (async () => { BODY })();',
};
describe('callback and clause identities', () => {
  for (const [form, template] of Object.entries(callbackForms)) {
    for (const change of ['body edit', 'inner replacement', 'new callback']) fixtureCase(`${form} distinguishes ${change}`, () => {
      put(SOURCE, template.replace('BODY', 'void Promise.resolve("inner");') + '\nexport {};\n');
      remeasure(); const base = anchor('callback seed');
      if (change === 'body edit') put(SOURCE, read(SOURCE).replace('"inner");', '"inner"); const unrelated = 1;'));
      else if (change === 'inner replacement') put(SOURCE, read(SOURCE).replace('"inner"', '"replacement"'));
      else if (form === 'iife body') put(SOURCE, read(SOURCE) + '\ndeclare function another(callback: () => void): void; another(async () => {});\n');
      else put(SOURCE, read(SOURCE) + '\n' + template.replace('BODY', '').replaceAll('use', 'another').replaceAll('Use', 'Another').replace('async ()', 'async (different = 1)') + '\n');
      pr(false, base);
      if (change === 'body edit') accept('RETAINED'); else refuse('new diagnostic');
    });
    fixtureCase(`${form} preserves a conditional across then body edits`, () => {
      // checkJs=false retains typed linting while avoiding TypeScript's always-true condition error.
      const conditional = 'server/src/conditional.js';
      const forms: Record<string, string> = {
        call: '/** @param {() => void} callback */ function use(callback) {} use(async () => { BODY });',
        constructor: 'class Use { /** @param {() => void} callback */ constructor(callback) {} } new Use(async () => { BODY });',
        iife: '(/** @param {() => void} callback */ function use(callback) {})(async () => { BODY });',
        'iife body': 'await (async () => { BODY })();',
      };
      put(conditional, forms[form]!.replace('BODY', 'const promise = Promise.resolve(); if (promise) { const before = 1; }') + '\nexport {};\n');
      git('add', conditional);
      const measured = remeasure();
      expect(measured.entries.some(entry => entry.path === conditional && entry.kind === 'conditional')).toBe(true);
      const base = anchor();
      put(conditional, read(conditional).replace('const before = 1;', 'const after = 2;'));
      pr(false, base); accept('RETAINED');
    });
  }
  fixtureCase('names token kinds in reviewable preimages', () => { const entries = measure().entries; expect(entries.every(entry => !/\[\d+,"/u.test(entry.preimage))).toBe(true); });
  fixtureCase('enforces bounded source inventory', () => { put(POLICY, read(POLICY).replace('MAX_SOURCE_FILES = 4096', 'MAX_SOURCE_FILES = 1')); refuse('source manifest size refused'); });
  fixtureCase('enforces bounded baseline inventory', () => { put(POLICY, read(POLICY).replace('MAX_BASELINE_ENTRIES = 16384', 'MAX_BASELINE_ENTRIES = 1')); refuse('entry cap'); });
  fixtureCase('keeps callback index and invocation kind in the identity', () => { expect(read(FINGERPRINT)).toContain('callback.parent.arguments.indexOf(callback)'); expect(read(FINGERPRINT)).toContain("? 'new' : 'call'"); });
});
