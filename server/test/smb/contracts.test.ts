/** Shared SMB contracts and isolated peer admission. R2-B2, R2-B3, R2-F6, R2-F7. */
import { beforeAll, expect, it } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync, readdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { Duplex } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { allConstants, bound, constant } from '../../src/smb/constants.js';
import { jcs } from '../../src/smb/jcs.js';
import { parseStrict } from '../../src/smb/parse-strict.js';
import { edges, validate, validateBytes, ReplyMatcher, normalizeBootId } from '../../src/smb/wire.js';
import { encodeFrame, decodeFrame, readFrame } from '../../src/smb/frame.js';
import { MAX_SURROGATE_VALUE_BYTES, SURROGATE_QUERY_TIMEOUT_MS } from '../../src/credential-surrogate/constants.js';
import { SURROGATE_PLACEHOLDER_PREFIX } from '../../src/credential-surrogate/placeholder.js';

const root = resolve(fileURLToPath(new URL('../../../', import.meta.url)));
const crate = join(root, 'castle-wall-daemon');
const fixtures = join(root, 'server/test/smb/vectors');
const env = { ...process.env, CARGO_BUILD_JOBS: '2', CARGO_TERM_COLOR: 'never' };
let binary: string;
// Fixture data is intentionally independent of the schema interpreter's static types.
type Vector = Record<string, any>;
function fixture(name: string): any { return JSON.parse(readFileSync(join(fixtures, name + '.json'), 'utf8')); }
function maximum(v: Vector): number { return typeof v.maximum === 'number' ? v.maximum : bound(v.maximum ?? 'REQ_MAX'); }
beforeAll(() => {
  const features = process.env.SMB_WITNESS_FEATURES === 'smb-test-hooks' ? ['--features', 'smb-test-hooks'] : [];
  const build = spawnSync('cargo', ['test', '--locked', '--lib', 'smb', '--no-run', '--message-format=json', ...features], { cwd: crate, env, encoding: 'utf8', timeout: 300_000, maxBuffer: 16 * 1024 * 1024 });
  if (build.error || build.status !== 0) throw new Error('SMB_BUILD_FAILURE: ' + (build.error?.message ?? build.stderr + build.stdout));
  const artifacts = build.stdout.split('\n').filter(Boolean).map(line => JSON.parse(line)).filter(item => item.reason === 'compiler-artifact' && item.target.kind.includes('lib') && item.executable);
  if (artifacts.length !== 1) throw new Error('SMB_BUILD_FAILURE: missing real Rust test binary');
  binary = artifacts[0].executable;
}, 300_000);
function rust(name: string, extraEnv: Record<string, string> = {}): any {
  const result = spawnSync(binary, ['smb::tests::' + name, '--exact', '--nocapture'], { cwd: crate, env: { ...env, ...extraEnv }, encoding: 'utf8', timeout: 60_000, maxBuffer: 32 * 1024 * 1024 });
  if (result.error || result.status !== 0) throw new Error(`Rust witness ${name}: ${result.error?.message ?? ''}\n${result.stdout}\n${result.stderr}`);
  const lines = result.stdout.split('\n').filter(line => line.startsWith('SMB_RESULT '));
  expect(lines.length, 'real Rust witness must emit exactly one result set').toBe(1);
  return JSON.parse(lines[0].slice('SMB_RESULT '.length));
}
function wireGroup(group: string): unknown[] {
  return fixture('wire').vectors.filter((v: Vector) => v.group === group).map((v: Vector) => {
    let raw = v.raw ?? jcs(v.value);
    if (v.inflate) raw = ' '.repeat(maximum(v)) + raw;
    let accepted = false;
    try { validateBytes(v.schema, Buffer.from(raw), maximum(v)); accepted = true; } catch { /* expected refusal */ }
    expect(accepted, v.name).toBe(v.valid);
    return { name: v.name, accepted };
  });
}
function strictGroup(group: string): unknown[] {
  return fixture('strict-json').vectors.filter((v: Vector) => v.group === group).map((v: Vector) => {
    let accepted = false; let canonical: string | null = null;
    try {
      const value = parseStrict(v.hex ? Buffer.from(v.hex, 'hex') : Buffer.from(v.raw), maximum(v));
      accepted = !v.schema || validate(v.schema, value);
      if (accepted) canonical = jcs(value);
    } catch { /* expected refusal */ }
    expect(accepted, v.name).toBe(v.valid);
    if (accepted && v.expected !== undefined) expect(canonical, v.name).toBe(v.expected);
    return { name: v.name, accepted, canonical };
  });
}
it('constants_parity', () => {
  expect(rust('constants_parity')).toEqual({ constants: allConstants(), wire: JSON.parse(readFileSync(join(root, 'server/src/smb/wire.json'), 'utf8')) });
  // Must match the A4 producers; both readers' pin comments point to these equalities.
  expect(constant('MAX_VAULT_VALUE_BYTES')).toBe(MAX_SURROGATE_VALUE_BYTES);
  expect(constant('PLACEHOLDER_PREFIX')).toBe(SURROGATE_PLACEHOLDER_PREFIX);
  expect(constant('QUERY_REPLY_MAX')).toBe(SURROGATE_QUERY_TIMEOUT_MS);
});
it('wire_vectors_agree', () => {
  expect(rust('wire_vectors_agree')).toEqual(wireGroup('wire'));
  const vectors = fixture('wire').vectors as Vector[];
  // Whole-set coverage prevents a new edge from silently missing its seam witnesses.
  const expected = Object.values(edges).flatMap(edge => Object.values(edge.requests).flatMap(pair => Object.values(pair))).sort();
  expect(vectors.filter(v => /\.(request|reply)\.valid$/.test(v.name)).map(v => v.schema).sort()).toEqual(expected);
  for (const schema of expected) {
    expect(vectors.filter(v => v.schema === schema && v.group === 'wire').map(v => v.name.split('.').at(-1))).toEqual(expect.arrayContaining(['valid', 'unknown', 'missing', 'number', 'oversize', 'kind', 'id']));
  }
});
it('wire_event_has_one_discriminator', () => { expect(rust('wire_event_has_one_discriminator')).toEqual(wireGroup('event')); });
it('wire_pins_128_bit_ids_hex_and_class_string', () => {
  expect(rust('wire_pins_128_bit_ids_hex_and_class_string')).toEqual(wireGroup('ids'));
  expect(normalizeBootId('ABCDEF01-2345-6789-ABCD-EF0123456789')).toBe('abcdef0123456789abcdef0123456789');
});
it('strict_json_numeric_domain_agrees', () => { expect(rust('strict_json_numeric_domain_agrees')).toEqual(strictGroup('numeric_domain')); });
it('strict_json_vectors_agree', () => { expect(rust('strict_json_vectors_agree')).toEqual(strictGroup('syntax')); });
it('jcs_rfc8785_appendix_b', () => {
  const expected = fixture('jcs').numbers.map((v: Vector) => {
    const value = Buffer.from(v.bits, 'hex').readDoubleBE();
    let canonical: string | null = null;
    try { canonical = jcs(value); } catch { /* non-finite values refuse */ }
    expect(canonical, v.bits).toBe(v.expected);
    return { bits: v.bits, canonical };
  });
  expect(rust('jcs_rfc8785_appendix_b')).toEqual(expected);
});
it('jcs_documents_agree', () => {
  expect(rust('jcs_documents_agree')).toEqual(fixture('jcs').documents.map((v: Vector) => {
    const canonical = jcs(v.value); expect(canonical).toBe(v.expected); return canonical;
  }));
});
it('jcs_binary64_differential', () => {
  const scratch = mkdtempSync(join(tmpdir(), 'smb-numbers-'));
  try {
    // Fixed xorshift64 corpus plus every power-of-two neighborhood: repeatable, broad exponent coverage.
    const bits: string[] = []; let state = 0x123456789abcdef0n;
    for (let i = 0; i < 10_000; i++) {
      state ^= state << 13n; state ^= state >> 7n; state ^= state << 17n; state = BigInt.asUintN(64, state);
      bits.push(state.toString(16).padStart(16, '0'));
    }
    for (let exponent = 1n; exponent < 2047n; exponent++) {
      for (const offset of [-1n, 0n, 1n]) bits.push(((exponent << 52n) + offset).toString(16).padStart(16, '0'));
    }
    const input = join(scratch, 'bits.json'); writeFileSync(input, JSON.stringify(bits));
    const expected = bits.map(bits => { const n = Buffer.from(bits, 'hex').readDoubleBE(); return Number.isFinite(n) ? jcs(n) : null; });
    expect(rust('number_differential_runner', { SMB_NUMBER_INPUT: input })).toEqual(expected);
  } finally { execFileSync('find', [scratch, '-delete']); }
});
it('frame_vectors_agree', () => {
  const expected = fixture('frame').vectors.map((v: Vector) => {
    const bytes = Buffer.from(v.hex, 'hex'); let accepted = false;
    try { decodeFrame(bytes, v.schema, maximum(v)); accepted = true; } catch { /* expected refusal */ }
    expect(accepted, v.name).toBe(v.valid);
    if (accepted) expect(encodeFrame(v.value, v.schema, maximum(v))).toEqual(bytes);
    return { name: v.name, accepted };
  });
  expect(rust('frame_vectors_agree')).toEqual(expected);
});
it('frame_refusal_closes_without_reply', async () => {
  for (const v of fixture('frame').vectors as Vector[]) {
    const writes: Buffer[] = [];
    const stream = new Duplex({ read() {}, write(chunk, _encoding, done) { writes.push(Buffer.from(chunk)); done(); } });
    const result = readFrame(stream, v.schema, maximum(v));
    stream.push(Buffer.from(v.hex, 'hex')); stream.push(null);
    if (v.valid) expect(await result).toEqual(v.value);
    else { await expect(result).rejects.toThrow(); expect(stream.destroyed).toBe(true); }
    expect(writes).toEqual([]); stream.destroy();
  }
  const result = spawnSync(binary, ['smb::frame::tests::frame_refusal_closes_without_reply', '--exact'], { cwd: crate, env, encoding: 'utf8', timeout: 30_000 });
  expect(result.status, result.stdout + result.stderr).toBe(0);
});
it('reply_matcher_fails_closed', () => {
  expect(() => new ReplyMatcher('toString')).toThrow();
  const request = { kind: 'scope', id: '1', I: 'ab'.repeat(16), C: '1' };
  const good = { id: '1', ok: false, error: 'refused' };
  for (const reply of [{ ...good, id: '2' }, { id: '1', ok: true }]) {
    const matcher = new ReplyMatcher('gate-b'); matcher.register(request);
    expect(() => matcher.receive(reply)).toThrow(); expect(matcher.state).toBe('CLOSED'); expect(matcher.outstanding).toBe(0);
  }
  const matcher = new ReplyMatcher('gate-b'); matcher.register(request); matcher.receive(good);
  expect(() => matcher.receive(good)).toThrow(); expect(matcher.state).toBe('CLOSED');
  expect(rust('reply_matcher_fails_closed')).toEqual([true, true, true]);
});
it('reply_matcher_bounded_waves', () => {
  expect(rust('reply_matcher_bounded_waves')).toBe(true);
  for (let wave = 0; wave < 3; wave++) {
    const matcher = new ReplyMatcher('gate-b');
    for (let i = 1; i <= bound('GATE_B_PENDING_MAX'); i++) matcher.register({ kind: 'await', id: String(i), Q: 'ab'.repeat(16) });
    expect(() => matcher.register({ kind: 'await', id: String(bound('GATE_B_PENDING_MAX') + 1), Q: 'ab'.repeat(16) })).toThrow();
    expect(matcher.outstanding).toBe(0);
    expect(() => matcher.receive({ id: '1', ok: false, error: 'refused' })).toThrow();
  }
});
it('container_peer', () => {
  const result = spawnSync(binary, ['smb::peer::tests::container_peer', '--exact', '--nocapture'], { cwd: crate, env, encoding: 'utf8', timeout: 45_000 });
  process.stdout.write(result.stdout ?? '');
  expect(result.error).toBeUndefined(); expect(result.status, result.stderr).toBe(0);
}, 60_000);
it('enc_vectors_carry_class_after_a', () => {
  const vectors = fixture('enc').vectors as Vector[];
  expect(vectors.filter(v => v.domain === 'ENC_DECIDE').length).toBeGreaterThan(0);
  for (const v of vectors) {
    if (v.domain === 'ENC_DECIDE') {
      const a = v.fields.findIndex((f: Vector) => f.name === 'A');
      expect(a).toBeGreaterThanOrEqual(0);
      expect(v.fields.filter((f: Vector) => f.name === 'class')).toHaveLength(1);
      expect(v.fields[a + 1].name).toBe('class'); expect(v.fields[a + 1].type).toBe('0x03');
    }
    expect(Buffer.from(v.tag).toString('hex')).toBe(v.tag_hex);
    for (const f of v.fields) {
      const bytes = Buffer.from(f.bytes, 'hex');
      expect(Buffer.from(f.length_be, 'hex').readUInt32BE()).toBe(bytes.length);
      expect(bytes.toString(f.type === '0x03' ? 'utf8' : 'hex')).toBe(f.value);
    }
    expect(v.tag_hex + v.fields.map((f: Vector) => f.type.slice(2) + f.length_be + f.bytes).join('')).toBe(v.encoded_hex);
  }
});
it('default_features_exclude_hooks', () => {
  const result = execFileSync('cargo', ['metadata', '--locked', '--no-deps', '--format-version=1'], { cwd: crate, env, encoding: 'utf8' });
  const features = JSON.parse(result).packages.find((p: Vector) => p.name === 'castle-wall-daemon').features;
  expect(features['smb-test-hooks']).toEqual([]);
  const walk = (name: string): string[] => [name, ...(features[name] ?? []).flatMap(walk)];
  expect(walk('default')).not.toContain('smb-test-hooks');
});
function walk(path: string): string[] {
  return readdirSync(path, { withFileTypes: true }).flatMap(e => e.isDirectory() ? walk(join(path, e.name)) : [join(path, e.name)]);
}
function violations(path: string, text: string): string[] {
  const found: string[] = [];
  if (path.endsWith('.rs') && !path.endsWith('/peer.rs') && /\baccept\s*\(|\.incoming\s*\(/.test(text)) found.push('peer');
  if (path.endsWith('.socket') && /^\s*Accept\s*=\s*yes\s*$/mi.test(text)) found.push('socket');
  if (!/\/(jcs|strict_json|parse-strict)\.(rs|ts)$/.test(path) && /(?:fn|function)\s+(?:jcs|canonicalize|parseStrict|parse_strict|parse_json)\b|JSON\.(?:parse|stringify)\s*\(/.test(text)) found.push('codec');
  return found;
}
it('structural_seams', () => {
  // Red controls exercise each guard before the complete real-source scan goes green.
  expect(violations('/smb/new.rs', 'listener.accept();')).toEqual(['peer']);
  expect(violations('/smb/new.socket', 'Accept=yes')).toEqual(['socket']);
  expect(violations('/smb/new.ts', 'function canonicalize() {}')).toEqual(['codec']);
  const files = [...walk(join(crate, 'src/smb')), ...walk(join(root, 'server/src/smb')), ...walk(join(crate, 'systemd')).filter(p => p.endsWith('.socket') && /sanctuary-(wall|gate|custody|peerd|linux-activate)/.test(p))];
  for (const file of files.filter(p => /\.(rs|ts|socket)$/.test(p))) expect(violations(file, readFileSync(file, 'utf8')), file).toEqual([]);
});
