import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const SERVER = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const BASELINE = 'scripts/promise-hygiene/baseline.json';
const read = (name: string) => readFileSync(resolve(SERVER, name), 'utf8');
const digest = (text: string) => createHash('sha256').update(text).digest('hex');

describe('promise hygiene command contract', () => {
  it('preserves original lint and forwards its arguments before the driver', () => {
    // Must match package.json; the fixture suite executes this command with --fix.
    expect(JSON.parse(read('package.json')).scripts.lint)
      .toBe('sh -c \'eslint src/ --max-warnings 0 "$@" && node scripts/promise-hygiene/run.mjs\' --');
  });
  it('ships unique full identities and reviewable preimages', () => {
    expect(existsSync(resolve(SERVER, BASELINE))).toBe(true);
    const baseline = JSON.parse(read(BASELINE));
    const entries = baseline.entries as Array<{ path: string; rule: string; kind: string; fingerprint: string; preimage: string }>;
    const keys = entries.map(entry => JSON.stringify([entry.rule, entry.path, entry.kind, entry.fingerprint]));
    expect(new Set(keys).size).toBe(keys.length);
    for (const entry of entries) expect(digest(entry.preimage)).toBe(entry.fingerprint);
    expect(typeof baseline.compilerDigest).toBe('string');
    expect(baseline.compilerDigest).toMatch(/^[a-f0-9]{64}$/u);
    expect(baseline.driftDigest).toMatch(/^[a-f0-9]{64}$/u);
  });
  it('measures the real tree with tracked declaration dependencies', () => {
    const timeout = 120_000; // The complete typed source pass gets two minutes on a loaded host.
    const result = spawnSync(process.execPath, ['--input-type=module', '-e',
      'import {measure} from "./server/scripts/promise-hygiene/run.mjs"; console.log(JSON.stringify(await measure(process.cwd())));'],
    { cwd: resolve(SERVER, '..'), encoding: 'utf8', timeout, maxBuffer: 8 * 1024 * 1024 }); // Eight MiB bounds measurement output.
    expect(result.error).toBeUndefined(); expect(result.status, result.stderr).toBe(0);
    const measured = JSON.parse(result.stdout);
    const baseline = JSON.parse(read(BASELINE));
    expect(measured.entries).toEqual(baseline.entries);
    expect(measured.compilerDigest).toBe(baseline.compilerDigest);
    expect(measured.driftDigest).toBe(baseline.driftDigest);
    expect(measured.acceptedDeclarations).toContain('server/scripts/sealed-cli-runtime-entries.d.mts');
    expect(measured.acceptedDeclarations.every((name: string) => /\.d\.(?:ts|mts|cts)$/u.test(name))).toBe(true);
    expect(measured.acceptedDeclarations.every((name: string) => !measured.sources.includes(name))).toBe(true);
  }, 150_000); // The subprocess timeout plus assertion and teardown headroom.
  it('keeps coverage in the tracked manifest rather than a baseline floor', () => {
    const driver = read('scripts/promise-hygiene/run.mjs');
    expect(driver).toContain("['ls-files', '-z']");
    expect(driver).not.toContain('baseline.sources');
    expect(read('scripts/promise-hygiene/policy.mjs')).toContain("['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs']");
  });
});
