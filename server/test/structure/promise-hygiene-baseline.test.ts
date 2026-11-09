import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';

const SERVER = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const DRIVER = 'server/scripts/promise-hygiene/run.mjs';
const POLICY = 'server/scripts/promise-hygiene/policy.mjs';
const BASELINE = 'server/scripts/promise-hygiene/baseline.json';
const CONFIG = 'server/tsconfig.promise-hygiene.json';
const COMMAND_TIMEOUT = 60_000; // Each tiny fixture gets one minute including compiler startup.
const BUFFER_BYTES = 8 * 1024 * 1024; // Eight MiB captures refusal diagnostics without unbounded output.
const JSON_INDENT = 2;
const EXTENSIONS = ['ts', 'tsx', 'mts', 'cts', 'js', 'jsx', 'mjs', 'cjs'];
const CONTEXT_FILES = 1; // One branch-context fixture in addition to the extension matrix.
let root: string;
let seedCommit: string;
let baseline: { sources: string[]; entries: Array<{ path: string; preimage: string; fingerprint: string }>; policyDigest: string };
const hash = (text: string) => createHash('sha256').update(text).digest('hex');
const put = (name: string, text: string) => {
  mkdirSync(dirname(join(root, name)), { recursive: true });
  writeFileSync(join(root, name), text);
};
const read = (name: string) => readFileSync(join(root, name), 'utf8');
const git = (...args: string[]) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
const saveBaseline = (value: typeof baseline) => put(BASELINE, JSON.stringify(value, null, JSON_INDENT));
function command(args = [DRIVER], cwd = root) {
  const result = spawnSync(process.execPath, args, {
    cwd, encoding: 'utf8', timeout: COMMAND_TIMEOUT, maxBuffer: BUFFER_BYTES,
    env: { ...process.env, SANCTUARY_NO_UPDATE_CHECK: '1' },
  });
  expect(result.error).toBeUndefined();
  return { status: result.status, output: `${result.stdout}${result.stderr}` };
}
function expectRefusal(reason: string) {
  const result = command();
  expect(result.output).toContain(reason);
  expect(result.status).toBe(1);
}

beforeAll(() => {
  // This assertion remains loadable on the base commit; no new module is statically imported.
  expect(existsSync(join(SERVER, 'scripts/promise-hygiene/run.mjs'))).toBe(true);
  root = mkdtempSync(join(tmpdir(), 'promise-hygiene-'));
  mkdirSync(join(root, 'server'), { recursive: true });
  symlinkSync(join(SERVER, 'node_modules'), join(root, 'server/node_modules'), 'dir');
  for (const name of ['run.mjs', 'policy.mjs', 'fingerprint.mjs']) {
    put(`server/scripts/promise-hygiene/${name}`, readFileSync(join(SERVER, 'scripts/promise-hygiene', name), 'utf8'));
  }
  put(CONFIG, readFileSync(join(SERVER, 'tsconfig.promise-hygiene.json'), 'utf8'));
  put('server/package.json', readFileSync(join(SERVER, 'package.json'), 'utf8'));
  put('server/package-lock.json', readFileSync(join(SERVER, 'package-lock.json'), 'utf8'));
  put('server/eslint.config.js', readFileSync(join(SERVER, 'eslint.config.js'), 'utf8'));
  put('.gitignore', 'server/node_modules\n');
  put('server/tsconfig.json', JSON.stringify({ compilerOptions: {
    target: 'ES2022', module: 'ESNext', moduleResolution: 'bundler', strict: true,
    skipLibCheck: true, types: [], jsx: 'preserve',
  }, include: ['src/**/*'] }));
  for (const extension of EXTENSIONS) put(`server/src/sample-${extension}.${extension}`, `void Promise.resolve('seed-${extension}');\nexport {};\n`);
  put('server/src/context.ts', String.raw`if (/a\/\//.test('left')) { void Promise.resolve('context'); }` + '\nexport {};\n');
  git('init', '-q');
  git('add', '-A');
  // Only synthetic fixtures are seeded here. There is no repository baseline update mode.
  const measured = command(['--input-type=module', '-e',
    `import {measure,sourceDigest} from './${DRIVER}';
     import {POLICY_DIGEST,digest} from './${POLICY}';
     const m=await measure(process.cwd());
     const b={policyDigest:POLICY_DIGEST,sources:m.sources,entries:m.entries};
     console.log(JSON.stringify({baseline:b,seed:digest(JSON.stringify(b)),source:sourceDigest(process.cwd(),m.sources)}));`]);
  expect(measured.status, measured.output).toBe(0);
  const fixture = JSON.parse(measured.output);
  baseline = fixture.baseline;
  saveBaseline(baseline);
  put(POLICY, read(POLICY).replace(/SEED_DIGEST = '[a-f0-9]+'/u, `SEED_DIGEST = '${fixture.seed}'`)
    .replace(/SEED_SOURCE_DIGEST = '[a-f0-9]+'/u, `SEED_SOURCE_DIGEST = '${fixture.source}'`));
  git('add', '-A');
  git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'reviewed fixture seed');
  seedCommit = git('rev-parse', 'HEAD');
}, COMMAND_TIMEOUT);

beforeEach(() => {
  if (root) git('checkout', seedCommit, '--', '.');
});

describe('promise diagnostic identities', () => {
  it('accepts the unchanged set with full source and Program parity', () => {
    const result = command();
    expect(result.status, result.output).toBe(0);
    expect(JSON.parse(result.output).files).toBe(EXTENSIONS.length + CONTEXT_FILES);
    expect(JSON.parse(result.output).diagnostics).toBe(EXTENSIONS.length + CONTEXT_FILES);
  });
  it('preserves identity across whitespace and comment movement', () => {
    put('server/src/sample-ts.ts', "\n// trivia\nvoid  Promise . resolve ( 'seed-ts' ) ;\nexport {};\n");
    expect(command().status).toBe(0);
  });
  it('preserves regular-expression branch context in diagnostic identity', () => {
    put('server/src/context.ts', read('server/src/context.ts').replace("'left'", "'right'"));
    expectRefusal('new diagnostic');
  });
  it('rejects a new floated promise despite an inline disable', () => {
    put('server/src/sample-ts.ts', read('server/src/sample-ts.ts') + '// eslint-disable-next-line @typescript-eslint/no-floating-promises\nvoid Promise.resolve("new");\n');
    expectRefusal('new diagnostic');
  });
  it('rejects stale entries when a diagnostic disappears', () => {
    put('server/src/sample-ts.ts', 'export {};\n');
    expectRefusal('stale baseline');
  });
  it('accepts removal of a diagnostic and its entry together', () => {
    put('server/src/sample-ts.ts', 'export {};\n');
    saveBaseline({ ...baseline, entries: baseline.entries.filter(entry => entry.path !== 'server/src/sample-ts.ts') });
    expect(command().status).toBe(0);
  });
  it('rejects replacement at constant diagnostic count', () => {
    put('server/src/sample-ts.ts', 'void Promise.resolve("replacement");\nexport {};\n');
    expectRefusal('new diagnostic');
  });
  it('rejects multiplicity growth of an indistinguishable occurrence', () => {
    put('server/src/sample-ts.ts', read('server/src/sample-ts.ts') + "void Promise.resolve('seed-ts');\n");
    expectRefusal('fingerprint collision');
  });
  it('rejects a fabricated but internally valid baseline key', () => {
    const original = baseline.entries[0]!;
    const preimage = JSON.stringify({ context: [], statement: [], tokenPosition: 0 });
    saveBaseline({ ...baseline, entries: [...baseline.entries, { ...original, preimage, fingerprint: hash(preimage) }] });
    expectRefusal('parent-baseline addition');
  });
  it('rejects adding matching source and baseline entries together', () => {
    put('server/src/sample-ts.ts', read('server/src/sample-ts.ts') + 'void Promise.resolve("colluding-addition");\n');
    // Seed only the synthetic fixture's proposed edit to exercise the trusted-parent boundary.
    const measured = command(['--input-type=module', '-e',
      `import {measure} from './${DRIVER}'; console.log(JSON.stringify((await measure(process.cwd())).entries));`]);
    expect(measured.status, measured.output).toBe(0);
    saveBaseline({ ...baseline, entries: JSON.parse(measured.output) });
    expectRefusal('parent-baseline addition');
  });
  it('rejects rule option drift', () => {
    put(POLICY, read(POLICY).replace('ignoreVoid: false', 'ignoreVoid: true'));
    expectRefusal('policy drift');
  });
  it('rejects compiler configuration drift', () => {
    const config = JSON.parse(read(CONFIG));
    config.exclude.push('src');
    put(CONFIG, JSON.stringify(config));
    expectRefusal('configuration drift');
  });
  it('rejects lockfile version drift', () => {
    const lock = JSON.parse(read('server/package-lock.json'));
    lock.packages['node_modules/typescript-eslint'].version = '0.0.0';
    put('server/package-lock.json', JSON.stringify(lock));
    expectRefusal('lockfile version drift');
  });
  it('rejects a hidden tracked source', () => {
    git('update-index', '--force-remove', 'server/src/sample-ts.ts');
    expectRefusal('missing source file');
  });
  it('rejects type resolution and parser failures separately', () => {
    put('server/src/sample-ts.ts', "import { missing } from './absent.js';\nvoid missing();\n");
    expectRefusal('type/parser failure');
    put('server/src/sample-ts.ts', 'export const broken = ;\n');
    expectRefusal('type/parser failure');
  });
  it('rejects an imported source outside the tracked Program manifest', () => {
    put('server/src/untracked.ts', 'export const value = 1;\n');
    put('server/src/sample-ts.ts', read('server/src/sample-ts.ts') + "import './untracked.js';\n");
    expectRefusal('Program/manifest mismatch');
  });
  it('ignores unrelated untracked trees', () => {
    put('untracked-tree/example.ts', 'void Promise.resolve("untracked");\n');
    expect(command().status).toBe(0);
  });
  it('visits tracked source under a generated-looking nested name', () => {
    put('server/src/dist/nested.ts', 'void Promise.resolve("nested");\nexport {};\n');
    git('add', 'server/src/dist/nested.ts');
    expectRefusal('new diagnostic');
    git('update-index', '--force-remove', 'server/src/dist/nested.ts');
  });
  it('rejects promise callbacks in void-return slots', () => {
    put('server/src/sample-ts.ts', read('server/src/sample-ts.ts') +
      'const consume = (_callback: () => void): void => {};\nconsume(async () => {});\n');
    expectRefusal('new diagnostic');
  });
  it('accounts for inert disable notices without suppressing diagnostics', () => {
    put('server/src/sample-ts.ts', '// eslint-disable-next-line @typescript-eslint/no-floating-promises\n' + read('server/src/sample-ts.ts'));
    const result = command();
    expect(result.status, result.output).toBe(0);
    expect(JSON.parse(result.output).inertDisableNotices).toBe(1);
  });
  it('rejects unknown configuration notices', () => {
    put(DRIVER, read(DRIVER).replace('const entries = [];',
      "results[0].messages.push({ruleId:null,severity:1,message:'unknown configuration notice'}); const entries = [];"));
    expectRefusal('unknown lint message');
  });
  it('rejects unresolved JavaScript imports', () => {
    put('server/src/sample-js.js', "import { missing } from './absent.js';\nvoid missing();\n");
    expectRefusal('type/parser failure');
  });
  it('rejects missing and linked source files', () => {
    const source = 'server/src/sample-ts.ts';
    unlinkSync(join(root, source));
    expectRefusal('ENOENT');
    symlinkSync(join(root, 'server/src/sample-js.js'), join(root, source));
    expectRefusal('linked source');
    unlinkSync(join(root, source));
  });
  it('rejects truncated trusted baseline history', () => {
    put('.git/shallow', seedCommit + '\n');
    try {
      expectRefusal('trusted baseline history unavailable');
    } finally {
      unlinkSync(join(root, '.git/shallow'));
    }
  });
  it('rejects an intermediate commit that adds a baseline key', () => {
    const original = baseline.entries[0]!;
    const preimage = JSON.stringify({ context: [], statement: [], tokenPosition: 0 });
    saveBaseline({ ...baseline, entries: [...baseline.entries, { ...original, preimage, fingerprint: hash(preimage) }] });
    git('add', BASELINE);
    git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'untrusted fixture addition');
    try {
      saveBaseline(baseline);
      expectRefusal('parent-baseline addition');
    } finally {
      // This ref belongs only to this test's synthetic repository.
      git('update-ref', 'HEAD', seedCommit);
    }
  });
  it('runs the actual package lint command against a planted finding', () => {
    put('server/src/sample-ts.ts', read('server/src/sample-ts.ts') + 'void Promise.resolve("package-plant");\n');
    const result = spawnSync('npm', ['run', 'lint'], {
      cwd: join(root, 'server'), encoding: 'utf8', timeout: COMMAND_TIMEOUT, maxBuffer: BUFFER_BYTES,
      env: { ...process.env, npm_config_update_notifier: 'false' },
    });
    expect(result.error).toBeUndefined();
    expect(`${result.stdout}${result.stderr}`).toContain('new diagnostic');
    expect(result.status).toBe(1);
  });
});
