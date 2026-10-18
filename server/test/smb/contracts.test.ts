/** Shared SMB contracts and isolated peer admission. */
import { beforeAll, expect, it } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync, readdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { Duplex } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { allConstants, bound, constant } from '../../src/smb/constants.js';
import { jcs, number } from '../../src/smb/jcs.js';
import { parseStrict } from '../../src/smb/parse-strict.js';
import { edges, validate, validateBytes, ReplyMatcher, normalizeBootId } from '../../src/smb/wire.js';
import { encodeFrame, decodeFrame, readFrame } from '../../src/smb/frame.js';
import { MAX_SURROGATE_VALUE_BYTES, SURROGATE_QUERY_TIMEOUT_MS } from '../../src/credential-surrogate/constants.js';
import { SURROGATE_PLACEHOLDER_PREFIX } from '../../src/credential-surrogate/placeholder.js';

const root = resolve(fileURLToPath(new URL('../../../', import.meta.url)));
const crate = join(root, 'castle-wall-daemon');
const fixtures = join(root, 'server/test/smb/vectors');
const env = { ...process.env, CARGO_BUILD_JOBS: '2', CARGO_TERM_COLOR: 'never' };
// Fixture budgets: five minutes to build, one minute for Rust, and half a minute for small probes.
const MINUTE_MS = 60 * 1000;
const BUILD_TIMEOUT_MS = 5 * MINUTE_MS;
const PROBE_TIMEOUT_MS = MINUTE_MS / 2;
const RELEASE_TIMEOUT_MS = 15 * MINUTE_MS;
const RELEASE_CLEANUP_MARGIN_MS = 50 * 1000; // Allow 50 seconds to reap the build process group.
const RELEASE_CHILD_TIMEOUT_SECONDS = (RELEASE_TIMEOUT_MS - RELEASE_CLEANUP_MARGIN_MS) / 1000;
let binary: string;
// Fixture data is intentionally independent of the schema interpreter's static types.
type Vector = Record<string, any>;
function fixture(name: string): any { return JSON.parse(readFileSync(join(fixtures, name + '.json'), 'utf8')); }
function maximum(v: Vector): number { return typeof v.maximum === 'number' ? v.maximum : bound(v.maximum ?? 'REQ_MAX'); }
beforeAll(() => {
  const features = process.env.SMB_WITNESS_FEATURES === 'smb-test-hooks' ? ['--features', 'smb-test-hooks'] : [];
  const build = spawnSync('cargo', ['test', '--locked', '--lib', 'smb', '--no-run', '--message-format=json', ...features], { cwd: crate, env, encoding: 'utf8', timeout: BUILD_TIMEOUT_MS, maxBuffer: 16 * 1024 * 1024 });
  if (build.error || build.status !== 0) throw new Error('SMB_BUILD_FAILURE: ' + (build.error?.message ?? build.stderr + build.stdout));
  const artifacts = build.stdout.split('\n').filter(Boolean).map(line => JSON.parse(line)).filter(item => item.reason === 'compiler-artifact' && item.target.kind.includes('lib') && item.executable);
  if (artifacts.length !== 1) throw new Error('SMB_BUILD_FAILURE: missing real Rust test binary');
  binary = artifacts[0].executable;
}, BUILD_TIMEOUT_MS);
function rust(name: string, extraEnv: Record<string, string> = {}): any {
  const result = spawnSync(binary, ['smb::tests::' + name, '--exact', '--nocapture'], { cwd: crate, env: { ...env, ...extraEnv }, encoding: 'utf8', timeout: MINUTE_MS, maxBuffer: 32 * 1024 * 1024 });
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
    try { canonical = number(value); } catch { /* non-finite values refuse */ }
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
    const CORPUS_SIZE = 10_000; // Chosen deterministic sample budget, plus every exponent boundary.
    for (let i = 0; i < CORPUS_SIZE; i++) {
      state ^= state << 13n; state ^= state >> 7n; state ^= state << 17n; state = BigInt.asUintN(64, state);
      bits.push(state.toString(16).padStart(16, '0'));
    }
    const BINARY64_EXPONENT_RESERVED = (1n << 11n) - 1n; // IEEE-754 has an 11-bit exponent.
    const BINARY64_FRACTION_BITS = 52n; // 53-bit precision less the implicit leading bit.
    for (let exponent = 1n; exponent < BINARY64_EXPONENT_RESERVED; exponent++) {
      for (const offset of [-1n, 0n, 1n]) bits.push(((exponent << BINARY64_FRACTION_BITS) + offset).toString(16).padStart(16, '0'));
    }
    const input = join(scratch, 'bits.json'); writeFileSync(input, JSON.stringify(bits));
    const expected = bits.map(bits => { const n = Buffer.from(bits, 'hex').readDoubleBE(); return Number.isFinite(n) ? number(n) : null; });
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
  for (const v of (fixture('frame').vectors as Vector[]).filter(v => v.stream !== false)) {
    const writes: Buffer[] = [];
    const stream = new Duplex({ read() {}, write(chunk, _encoding, done) { writes.push(Buffer.from(chunk)); done(); } });
    const result = readFrame(stream, v.schema, maximum(v));
    stream.push(Buffer.from(v.hex, 'hex')); stream.push(null);
    if (v.valid) expect(await result).toEqual(v.value);
    else { await expect(result).rejects.toThrow(); expect(stream.destroyed).toBe(true); }
    expect(writes).toEqual([]); stream.destroy();
  }
  const result = spawnSync(binary, ['smb::frame::tests::frame_refusal_closes_without_reply', '--exact'], { cwd: crate, env, encoding: 'utf8', timeout: PROBE_TIMEOUT_MS });
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
it.skipIf(!process.env.SMB_CONTAINER_PEER_IMAGE)('container_peer', () => {
  const result = spawnSync(binary, ['smb::peer::tests::container_peer', '--exact', '--nocapture', '--ignored'], { cwd: crate, env, encoding: 'utf8', timeout: MINUTE_MS * 3 / 4 });
  process.stdout.write(result.stdout ?? '');
  expect(result.error).toBeUndefined(); expect(result.status, result.stderr).toBe(0);
}, MINUTE_MS);
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
// Only these canonical modules own codecs; a matching filename grants no exception.
const codecOwners = new Set([
  join(crate, 'src/smb/jcs.rs'), join(crate, 'src/smb/strict_json.rs'),
  join(root, 'server/src/smb/jcs.ts'), join(root, 'server/src/smb/parse-strict.ts'),
]);
function smbSource(path: string, text: string): boolean {
  return path.startsWith(join(crate, 'src/smb/')) || path.startsWith(join(root, 'server/src/smb/'))
    || (path.startsWith(join(crate, 'src/bin/')) && /smb/i.test(path.slice(path.lastIndexOf('/') + 1) + text));
}
function violations(path: string, text: string): string[] {
  const found: string[] = [];
  // Peer and socket ownership applies even when a source is outside the codec scope.
  if ((path.includes('/smb/') || /\bsmb\b/.test(text)) && path.endsWith('.rs') && path !== join(crate, 'src/smb/peer.rs') && /\baccept\s*\(|\.incoming\s*\(/.test(text)) found.push('peer');
  if (path.endsWith('.socket') && /^\s*Accept\s*=\s*yes\s*$/mi.test(text)) found.push('socket');
  if (!smbSource(path, text)) return found;
  // Permit data types and value construction only; every other serde spelling needs its owner.
  let codecs = text.replace(/use\s+serde_json\s*::\s*\{\s*(?:(?:Map|Number|Value|json)\s*,?\s*)+\}\s*;/g, '')
    .replace(/\bserde_json\s*::\s*(?:Map|Number|Value|json)\b/g, '');
  // Formatting can serialize a Value through Display. Only these scalar fixture expressions
  // have reviewed types; an unknown formatting call must move through the owning JCS module.
  const scalarCalls: Record<string, string[]> = {
    'mod.rs': ['println!("SMB_RESULT {}", jcs::encode(&value).unwrap())', 'format!("{name}.json")', 'format!("[{raw}]")', 'format!("{{\\"a\\":{raw}}}")', 'id.to_string()', '(maximum+1).to_string()'],
    'constants.rs': ['panic!("unknown SMB constant expression")'],
    'wire.rs': ['id.to_string()'],
    'peer.rs': ['panic!("permitted peer refused")', 'println!("permitted uid admitted; other uid closed without payload read")', 'println!("{}", String::from_utf8_lossy(&output.stdout))', 'format!("--reuid={uid}")', 'format!("--regid={uid}")', 'format!("smb-peer-{}", std::process::id())', 'format!("{}:/peer-test:ro", exe.display())'],
  };
  for (const [file, calls] of Object.entries(scalarCalls)) {
    if (path === join(crate, 'src/smb', file)) for (const call of calls) codecs = codecs.replace(call, 'SCALAR_FORMAT');
  }
  // FromStr can decode a Value without naming serde; only explicit numeric primitives bypass ownership.
  const valueDecode = path.endsWith('.rs') && /\bfrom_str\b|\.\s*parse\b(?!\s*::\s*<\s*(?:[ui](?:8|16|32|64|128|size)|f(?:32|64))\s*>)/.test(codecs);
  if (!codecOwners.has(path) && (valueDecode || /(?:fn|function)\s+(?:jcs|canonicalize|parseStrict|parse_strict|parse_json)\b|JSON\s*\.\s*(?:parse|stringify)\s*\(|\bserde_json\b|\bto_string\b|\b(?:format|write|writeln|print|println|eprint|eprintln|format_args|panic)\s*!/.test(codecs))) found.push('codec');
  // SMB may reuse the peer credential primitive, but not a non-SMB codec or its reexports.
  let references = text.replace('use crate::ipc::auth::peer_uid_for_stream;', 'PEER_CREDENTIAL_PRIMITIVE');
  // In the SMB root, super names the crate root; only the exact test-module import stays local.
  if (path === join(crate, 'src/smb/mod.rs')) references = references.replace('use super::*;', 'SMB_TEST_PARENT');
  const parentEscape = path === join(crate, 'src/smb/mod.rs') && /\bsuper\s*::/.test(references);
  if (parentEscape || /\b(?:manifest|ipc)\s*(?:::|[,};]|\s+as\b)|\b(?:crate|castle_wall_daemon)\s*::\s*(?!smb\b)|\bsuper\s*::\s*super\b/.test(references)) found.push('legacy-codec');
  return found;
}
it('structural_seams', () => {
  const rustSource = join(crate, 'src/smb/new.rs');
  const tsSource = join(root, 'server/src/smb/new.ts');
  // Red controls exercise every spelling before the scoped real-source scan goes green.
  expect(violations(rustSource, 'listener.accept();')).toEqual(['peer']);
  expect(violations('/smb/new.socket', 'Accept=yes')).toEqual(['socket']);
  expect(violations(tsSource, 'function canonicalize() {}')).toEqual(['codec']);
  expect(violations(join(crate, 'src/smb/other/jcs.rs'), 'serde_json::to_vec(value)')).toEqual(['codec']);
  expect(violations(join(crate, 'src/other/jcs.rs'), 'serde_json::to_vec(value)')).toEqual([]);
  expect(violations(join(crate, 'src/other.rs'), '/* smb */ listener.accept(); serde_json::to_vec(value)')).toEqual(['peer']);
  for (const operation of ['from_slice', 'from_str', 'from_reader', 'from_value', 'to_string', 'to_string_pretty', 'to_vec', 'to_vec_pretty', 'to_writer', 'to_writer_pretty']) {
    for (const source of [`serde_json::${operation}(input)`, `use serde_json::{${operation}};`, `use serde_json::{Value, ${operation} as codec};`, `use serde_json as x; x::${operation}(input)`]) {
      expect(violations(rustSource, source), source).toEqual(['codec']);
      expect(violations(join(crate, 'src/bin/smb-service.rs'), source), source).toEqual(['codec']);
    }
  }
  for (const source of ['serde_json::Deserializer::from_slice(bytes)', 'serde_json::Deserializer::from_str(text)', 'serde_json::Deserializer::from_reader(reader)', 'use serde_json::Value; value.to_string()', 'use serde_json::{Value}; format!("{value}")', 'serde_json::Value::Null.to_string()', 'use serde_json::*;', 'use serde_json::Value; values.iter().map(Value::to_string)']) {
    expect(violations(rustSource, source), source).toEqual(['codec']);
  }
  for (const source of [
    'use serde_json::Value; fn f(s: &str) -> Value { s.parse().unwrap() }',
    's.parse()', 's.parse::<Value>()', 's.parse::<serde_json::Value>()',
    'use std::str::FromStr; Value::from_str(s)', 's.parse::<String>()',
    's.parse::<u64Alias>()', 's . parse :: < Value > ()',
  ]) {
    expect(violations(rustSource, source), source).toEqual(['codec']);
    expect(violations(join(crate, 'src/bin/smb-service.rs'), source), source).toEqual(['codec']);
    expect(violations(join(crate, 'src/other.rs'), source), source).toEqual([]);
  }
  for (const primitive of ['u8', 'u16', 'u32', 'u64', 'u128', 'usize', 'i8', 'i16', 'i32', 'i64', 'i128', 'isize', 'f32', 'f64']) {
    for (const source of [`s.parse::<${primitive}>()`, `s . parse :: < ${primitive} > ()`]) {
      expect(violations(rustSource, source), source).toEqual([]);
    }
  }
  expect(violations(rustSource, 'u64::from_str_radix(s, 16)')).toEqual([]);
  for (const source of ['crate::manifest::canonical_json::canonicalize(value)', 'use crate::ipc::messages;', 'use crate::{manifest as legacy};', 'use super::super::ipc as legacy;', 'manifest::canonical_json::canonicalize(value)', 'use ipc::{messages};']) {
    expect(violations(rustSource, source), source).toEqual(['legacy-codec']);
  }
  for (const macro of ['format', 'write', 'writeln', 'print', 'println', 'eprint', 'eprintln', 'format_args', 'panic']) {
    expect(violations(rustSource, `use serde_json::Value; ${macro}!("{value}")`)).toEqual(['codec']);
  }
  for (const source of ['use super::manifest as legacy;', 'use super::ipc as legacy;', 'use super::manifest;', 'use super::ipc;', 'use super::launcher as legacy;', 'use super::{ownership_journal as legacy};']) {
    expect(violations(join(crate, 'src/smb/mod.rs'), source), source).toEqual(['legacy-codec']);
  }
  // Owning a codec never exempts peer admission or socket activation checks.
  expect(violations(join(crate, 'src/smb/jcs.rs'), 'listener.accept();')).toEqual(['peer']);
  const files = [...walk(join(crate, 'src')), ...walk(join(root, 'server/src/smb')), ...walk(join(crate, 'systemd')), ...walk(join(crate, 'packaging/ubuntu'))];
  for (const file of files.filter(p => /\.(rs|ts|socket)$/.test(p))) {
    expect(violations(file, readFileSync(file, 'utf8')), file).toEqual([]);
  }
});

it('codec_bounds_agree', () => {
  const vectors = fixture('bounds');
  const expected: unknown[] = vectors.depth.map((v: Vector) => {
    const depth = bound('JSON_MAX_DEPTH') + v.offset;
    let value: unknown = v.shape === 'array' ? [] : {};
    for (let i = 0; i < depth; i++) value = v.shape === 'array' ? [value] : { a: value };
    let encoded = false; let parsed = false;
    try { jcs(value); encoded = true; } catch { /* refusal */ }
    try { parseStrict(Buffer.from(JSON.stringify(value))); parsed = true; } catch { /* refusal */ }
    expect(encoded, v.name).toBe(v.valid); expect(parsed, v.name).toBe(v.valid);
    return { encoded, parsed };
  });
  for (const v of vectors.numbers) {
    let accepted = false;
    try { jcs(Number(v.literal)); accepted = true; } catch { /* refusal */ }
    expect(accepted).toBe(v.valid); expected.push(accepted);
  }
  expect(rust('codec_bounds_agree')).toEqual(expected);
});
it('wire_unknown_schema_refuses', () => { expect(rust('wire_unknown_schema_refuses')).toEqual(wireGroup('unknown')); });
it('normalize_boot_id_agrees', () => {
  expect(normalizeBootId('ABCDEF01-2345-6789-ABCD-EF0123456789')).toBe('abcdef0123456789abcdef0123456789');
  expect(() => normalizeBootId('not-a-uuid')).toThrow();
  expect(rust('normalize_boot_id_agrees')).toBe(true);
});
it('fifo_result_encoded_bound', () => {
  const encodedMax = bound('FIFO_RESULT_ENCODED_MAX');
  const decodedMax = encodedMax / bound('BASE64_OUTPUT') * bound('BASE64_INPUT');
  for (const v of fixture('bounds').fifo) {
    const extra = v.extra_decoded_bytes;
    const value = { type: 'result', data_b64: Buffer.alloc(decodedMax + extra).toString('base64') };
    expect(validate('fifo_result', value), v.name).toBe(v.valid);
    if (extra === 0) expect(encodeFrame(value, 'fifo_result', bound('TASK_OUT_FRAME_MAX')).length).toBeLessThanOrEqual(bound('TASK_OUT_FRAME_MAX') + bound('FRAME_HEADER'));
  }
  expect(rust('fifo_result_encoded_bound')).toBe(true);
});
it('peer_refusal_keeps_listener_serving', () => {
  const result = spawnSync(binary, ['smb::peer::tests::peer_refusal_keeps_listener_serving', '--exact'], { cwd: crate, env, encoding: 'utf8', timeout: PROBE_TIMEOUT_MS });
  expect(result.status, result.stdout + result.stderr).toBe(0);
});
it('constants_composites_derive_from_names', () => {
  const entries = fixtureSource('constants').constants;
  for (const name of ['ORIGIN', 'WALL_TABLE', 'AGENT_WRITE_SET', 'AGENT_UNIT_PROPERTIES', 'AGENT_LEAF', 'K', 'MACHINE_ID']) expect(entries[name]).toHaveProperty('template');
  for (const name of ['P_GATE', 'AGENT_STOP', 'UNLOCK_HOURS', 'ENROLLMENT_TTL', 'ARGON2_M_KIB']) expect(entries[name].source).toContain('brief section 5');
  for (const name of ['BASE64_INPUT', 'BASE64_OUTPUT']) expect(entries[name].source).toContain('RFC 4648');
  const properties = constant('AGENT_UNIT_PROPERTIES') as Record<string, unknown>;
  expect(properties.TimeoutStopSec).toBe(String(bound('AGENT_STOP')));
  expect(properties.TemporaryFileSystem).toContain(`${constant('WORKSPACE')}:size=${bound('WORKSPACE_MIB')}M,nr_inodes=${bound('WORKSPACE_INODES')}`);
  expect(properties.OpenFile).toEqual(['in', 'out', 'err'].map(name => `${constant('FIFO_DIR')}/${name}:task-${name}`));
  expect(constant('AGENT_WRITE_SET')).toEqual([constant('WORKSPACE')]);
  expect(constant('ORIGIN')).toBe(`https://<private-name>:${bound('P_WEB')}`);
  expect(constant('WALL_TABLE')).toContain(`ip daddr ${constant('GATE_ADDR')} tcp dport ${bound('P_GATE')} accept`);
  expect(JSON.stringify(fixtureSource('wire'))).not.toContain('"pattern":');
  // Named fixture deadlines keep the isolation policy visible at every blocking read.
  for (const file of ['peer.rs', 'frame.rs']) expect(readFileSync(join(crate, 'src/smb', file), 'utf8')).not.toMatch(/Duration::from_secs\(\d+\)/);

});
function fixtureSource(name: string): any { return JSON.parse(readFileSync(join(root, 'server/src/smb', name + '.json'), 'utf8')); }

it.skipIf(process.env.SMB_RELEASE_HOOK_SCAN !== '1')('release_hook_scan', () => {
  // Run the scanner's packaging invocation; compile errors must remain BROKEN in mutate.sh.
  const result = spawnSync('python3', ['-c', `import os, signal, subprocess, sys
# The child deadline leaves the named cleanup margin inside the Vitest deadline.
p = subprocess.Popen(sys.argv[1:], start_new_session=True)
try:
    sys.exit(p.wait(timeout=${RELEASE_CHILD_TIMEOUT_SECONDS}))
except subprocess.TimeoutExpired:
    os.killpg(p.pid, signal.SIGKILL)
    p.wait()
    sys.exit(124)`, 'bash', join(root, 'scripts/smb/release-hook-scan.sh')], { cwd: root, env, encoding: 'utf8', timeout: RELEASE_TIMEOUT_MS, maxBuffer: 16 * 1024 * 1024 });
  const output = (result.stdout ?? '') + (result.stderr ?? '');
  if (result.error || result.status === 124 || output.includes('SMB_BUILD_FAILURE')) throw new Error('SMB_BUILD_FAILURE: ' + output + result.error);
  expect(result.status, output).toBe(0);
  expect(output).toContain('RELEASE_HOOK_SCAN: PASS');
}, RELEASE_TIMEOUT_MS);
it('mutation_runner_controls', () => {
  const result = spawnSync('python3', [join(root, 'scripts/smb/test_mutation_runner.py')], { cwd: root, env, encoding: 'utf8', timeout: PROBE_TIMEOUT_MS });
  expect(result.status, result.stdout + result.stderr).toBe(0);
});

it('container_peer_is_opt_in', () => {
  const result = spawnSync(binary, ['--list', '--ignored'], { cwd: crate, env, encoding: 'utf8', timeout: PROBE_TIMEOUT_MS });
  expect(result.status).toBe(0);
  expect(result.stdout).toContain('smb::peer::tests::container_peer: test');
  expect(result.stdout).toContain('smb::peer::tests::peer_client: test');
  expect(result.stdout).toContain('smb::tests::release_hook_scan: test');
});
