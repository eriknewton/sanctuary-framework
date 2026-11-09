import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const SERVER = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const ROOT = resolve(SERVER, '..');
const BASELINE = 'scripts/promise-hygiene/baseline.json';
const read = (name: string) => readFileSync(resolve(SERVER, name), 'utf8');
const digest = (text: string) => createHash('sha256').update(text).digest('hex');

describe('promise hygiene command contract', () => {
  it('preserves original lint and reaches the separate driver', () => {
    // Must match the lint entry in ../../package.json; the fixture suite executes this exact command.
    expect(JSON.parse(read('package.json')).scripts.lint)
      .toBe('eslint src/ --max-warnings 0 && node scripts/promise-hygiene/run.mjs');
  });
  it('ships a reviewed seed with unique full identities and reviewable preimages', () => {
    expect(existsSync(resolve(SERVER, BASELINE))).toBe(true);
    const baseline = JSON.parse(read(BASELINE));
    const entries = baseline.entries as Array<{ path: string; rule: string; kind: string; fingerprint: string; preimage: string }>;
    const keys = entries.map(entry => JSON.stringify([entry.rule, entry.path, entry.kind, entry.fingerprint]));
    expect(new Set(keys).size).toBe(keys.length);
    for (const entry of entries) expect(digest(entry.preimage)).toBe(entry.fingerprint);
    // Must match SEED_DIGEST in policy.mjs at the sole initialization event.
    const history = execFileSync('git', ['log', '--first-parent', '--format=%H', '--', `server/${BASELINE}`], { cwd: ROOT, encoding: 'utf8' }).trim();
    if (!history) expect(read('scripts/promise-hygiene/policy.mjs')).toContain(`SEED_DIGEST = '${digest(JSON.stringify(baseline))}'`);
  });
  it('includes every tracked source extension in the baseline coverage floor', () => {
    expect(existsSync(resolve(SERVER, BASELINE))).toBe(true);
    const baseline = JSON.parse(read(BASELINE));
    const sources = execFileSync('git', ['ls-files', '-z'], { cwd: ROOT, encoding: 'utf8' }).split('\0')
      .filter(name => /^server\/src\/.*\.(?:ts|tsx|mts|cts|js|jsx|mjs|cjs)$/u.test(name)).sort();
    expect(baseline.sources).toEqual(sources);
  });
});
