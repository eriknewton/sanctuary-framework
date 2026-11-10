import { readFileSync, readdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve, posix } from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, it } from 'vitest';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const yaml = createRequire(import.meta.url)('js-yaml') as { load: (source: string) => Workflow };
type Step = { name?: string; run?: string; uses?: string; 'working-directory'?: string; with?: Record<string, unknown> };
type Defaults = { run?: { 'working-directory'?: string } };
type Workflow = { defaults?: Defaults; jobs?: Record<string, { defaults?: Defaults; steps?: Step[] }> };
// Must match both lint workflow checkouts and run.mjs's two-parent TRANSITION proof.
const CHECKOUT_DEPTH = 2;
const ROOT_DELEGATES_LINT = JSON.parse(readFileSync(resolve(ROOT, 'package.json'), 'utf8')).scripts?.lint === 'npm --prefix server run lint --';
const EXPECTED_CALLERS = ['ci.yml#lint#ESLint (src/)', 'evidence-pack-candidate.yml#candidate#Build candidate'];
function commands(script: string): string[][] {
  // Tokenize shell quoting and comments before identifying commands; comments never count as callers.
  const result: string[][] = [];
  let words: string[] = [], word = '', quote = '', comment = false;
  const flushWord = () => { if (word) { words.push(word); word = ''; } };
  const flushCommand = () => { flushWord(); if (words.length) result.push(words); words = []; };
  for (let index = 0; index < script.length; index++) {
    const char = script[index]!;
    if (comment) { if (char === '\n') { comment = false; flushCommand(); } continue; }
    if (char === '\\' && quote !== "'") { const next = script[++index]; if (next && next !== '\n') word += next; continue; }
    if (quote) { if (char === quote) quote = ''; else word += char; continue; }
    if (char === '"' || char === "'") { quote = char; continue; }
    if (char === '#' && !word) { comment = true; continue; }
    if ('\n;&|'.includes(char)) { flushCommand(); continue; }
    if (/\s/u.test(char)) flushWord(); else word += char;
  }
  flushCommand(); return result;
}
function callers(files: Map<string, string>) {
  const found: Array<{ id: string; checkout?: Step }> = [];
  for (const [file, source] of files) {
    const workflow = yaml.load(source);
    for (const [jobName, job] of Object.entries(workflow.jobs ?? {})) {
      let checkout: Step | undefined;
      for (const step of job.steps ?? []) {
        if (step.uses?.startsWith('actions/checkout@')) checkout = step;
        let cwd = step['working-directory'] ?? job.defaults?.run?.['working-directory'] ?? workflow.defaults?.run?.['working-directory'] ?? '.';
        for (const args of commands(step.run ?? '')) {
          if (args[0] === 'cd' && args[1]) { cwd = posix.normalize(posix.join(cwd, args[1])); continue; }
          if (args[0] !== 'npm') continue;
          const prefix = args.indexOf('--prefix');
          const effective = prefix >= 0 ? posix.normalize(posix.join(cwd, args[prefix + 1]!)) : posix.normalize(cwd);
          const run = args.indexOf('run');
          if ((effective === 'server' || (effective === '.' && ROOT_DELEGATES_LINT)) && run >= 0 && args[run + 1] === 'lint') found.push({ id: `${file}#${jobName}#${step.name}`, checkout });
        }
      }
    }
  }
  return found;
}
function assertContract(files: Map<string, string>) {
  const found = callers(files);
  expect(found.map(item => item.id).sort()).toEqual(EXPECTED_CALLERS);
  expect(found.length).toBeGreaterThan(0);
  for (const { checkout } of found) { expect(checkout?.with?.['fetch-depth']).toBe(CHECKOUT_DEPTH); expect(checkout?.with).not.toHaveProperty('ref'); }
}
function workflows() {
  return new Map(readdirSync(resolve(ROOT, '.github/workflows')).filter(name => /\.ya?ml$/u.test(name)).map(name => [name, readFileSync(resolve(ROOT, '.github/workflows', name), 'utf8')]));
}
it('pins every effective server lint caller to a merge checkout', () => { assertContract(workflows()); });
it('discovers prefixes defaults directory changes and ignores comments', () => {
  const found = callers(new Map([['fixture.yml', `defaults: {run: {working-directory: server}}
jobs:
  one:
    steps:
      - {name: default, run: 'npm run lint'}
      - {name: prefix, working-directory: '.', run: 'npm --prefix server run lint'}
      - name: change
        working-directory: '.'
        run: |
          # npm run lint
          cd server && npm run lint # ignored
      - {name: comment, run: '# npm run lint'}
  two:
    defaults: {run: {working-directory: '.'}}
    steps:
      - {name: root, run: 'npm run lint'}
`]]));
  expect(found.map(item => item.id)).toEqual(['fixture.yml#one#default', 'fixture.yml#one#prefix', 'fixture.yml#one#change', 'fixture.yml#two#root']);
});
for (const mutation of ['depth', 'ref', 'additional caller', 'removed caller']) it(`refuses workflow contract mutation ${mutation}`, () => {
  const files = workflows();
  const source = files.get('ci.yml')!;
  if (mutation === 'depth') files.set('ci.yml', source.replace('fetch-depth: 2', 'fetch-depth: 1'));
  else if (mutation === 'ref') files.set('ci.yml', source.replace('fetch-depth: 2', 'fetch-depth: 2\n          ref: candidate'));
  else if (mutation === 'removed caller') files.set('ci.yml', source.replace('run: npm run lint', 'run: npm run typecheck'));
  else files.set('extra.yml', 'jobs: {extra: {steps: [{name: extra, working-directory: server, run: npm run lint}]}}');
  expect(() => assertContract(files)).toThrow();
});
it('keeps tool updates outside the grouped dependency lane', () => {
  const config = yaml.load(readFileSync(resolve(ROOT, '.github/dependabot.yml'), 'utf8')) as unknown as { updates: Array<{ directory: string; groups: Record<string, { 'exclude-patterns'?: string[] }>; ignore?: unknown }> };
  const server = config.updates.find(update => update.directory === '/server')!;
  expect(server.groups['server-minor-patch']?.['exclude-patterns']).toEqual(['eslint', 'typescript', 'typescript-eslint', '@typescript-eslint/*', '@eslint/js']);
});
