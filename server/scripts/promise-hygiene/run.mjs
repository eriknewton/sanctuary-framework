import { execFileSync } from 'node:child_process';
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ESLint } from 'eslint';
import tseslint from 'typescript-eslint';
import ts from 'typescript';
import {
  BASELINE_PATH, CONFIG_PATH, CONFIG, EXTENSIONS, POLICY, SOURCE_PREFIX,
  MAX_GIT_BYTES, MAX_SOURCE_BYTES, MAX_SOURCE_FILES, MAX_BASELINE_ENTRIES,
  MAX_METADATA_BYTES, MODES, STATES, REANCHOR_LABEL, EMIT_ONLY_OPTIONS, digest,
} from './policy.mjs';
import { fingerprint, key } from './fingerprint.mjs';

const EXIT_REFUSED = 1; // Must match EXIT_REFUSED in promise-hygiene-baseline.test.ts.
const JSON_INDENT = 2;
export function git(root, args) {
  return execFileSync('git', args, { cwd: root, encoding: 'utf8', maxBuffer: MAX_GIT_BYTES, stdio: ['ignore', 'pipe', 'pipe'] });
}
function insist(condition, reason) {
  if (!condition) throw new Error(reason);
}
function readMetadata(root, name) {
  const filename = path.resolve(root, name);
  let descriptor;
  try {
    // O_NOFOLLOW refuses a link at open, so the checks below and the read share one descriptor
    // and a file swapped in after the check cannot be the one that is read.
    descriptor = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    // ELOOP is what open reports for a final-component link under O_NOFOLLOW (Linux and macOS).
    insist(error?.code !== 'ELOOP', `linked metadata: ${name}`);
    throw error;
  }
  try {
    const stat = fstatSync(descriptor);
    // Metadata must not follow a link around the shared size cap, including lockfile digest reads.
    insist(stat.isFile(), `metadata type refused: ${name}`);
    insist(stat.size <= MAX_METADATA_BYTES, 'metadata size refused');
    const bytes = readFileSync(descriptor);
    // The read runs to end of file, so a file that grew after fstat is capped on what was read.
    insist(bytes.length <= MAX_METADATA_BYTES, 'metadata size refused');
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}
function readJson(root, name) {
  return JSON.parse(readMetadata(root, name).toString('utf8'));
}

export function manifest(root) {
  const paths = git(root, ['ls-files', '-z']).split('\0').filter(Boolean);
  const modes = new Map(git(root, ['ls-files', '--stage', '-z']).split('\0').filter(Boolean)
    .map(row => [row.slice(row.indexOf('\t') + 1), row.split(' ')[0]]));
  const seen = new Set();
  const sources = [];
  for (const name of paths) {
    insist(!path.isAbsolute(name) && !name.includes('\\') && name === path.posix.normalize(name)
      && !name.split('/').includes('..') && !seen.has(name), 'invalid or duplicate manifest path');
    seen.add(name);
    if (!name.startsWith(SOURCE_PREFIX) || !EXTENSIONS.includes(path.extname(name))) continue;
    insist(modes.get(name) !== '120000', `linked source git mode: ${name}`);
    let component = root;
    // Missing files and links fail closed; a disappearing source cannot reduce lint coverage.
    for (const part of name.split('/')) {
      component = path.join(component, part);
      insist(!lstatSync(component).isSymbolicLink(), `linked source: ${name}`);
    }
    const stat = lstatSync(component);
    insist(stat.isFile() && stat.size <= MAX_SOURCE_BYTES, `invalid source size/type: ${name}`);
    sources.push(name);
  }
  // The manifest is finite and work is linear in its bounded source list; no recursive root walk.
  insist(sources.length > 0 && sources.length <= MAX_SOURCE_FILES, 'source manifest size refused');
  return sources.sort();
}
export function sourceDigest(root, sources) {
  return digest(JSON.stringify(sources.map(name => [name, digest(readFileSync(path.join(root, name)))])));
}

// Stable object ordering is shared by compiler and fixed-policy verification.
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(name => [name, canonical(value[name])]));
  return value;
}
const serialize = value => JSON.stringify(canonical(value));
function assertPolicy() {
  // Fixed design policy, must match policy.mjs and the policy mutation witnesses.
  const expected = {
    '@typescript-eslint/no-floating-promises': ['error', { ignoreVoid: false, ignoreIIFE: false, checkThenables: true }],
    '@typescript-eslint/no-misused-promises': ['error', {
      checksConditionals: true, checksSpreads: true,
      checksVoidReturn: { arguments: true, attributes: true, inheritedMethods: true, properties: true, returns: true, variables: true },
    }],
  };
  insist(serialize(POLICY.rules) === serialize(expected) && POLICY.noInlineConfig === true
    && serialize(EXTENSIONS) === serialize(['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs'])
    && serialize(POLICY.extensions) === serialize(EXTENSIONS), 'fixed rule policy drift');
}
export function compilerDigest(root, options) {
  const relative = (value, base = root) => {
    const name = path.relative(root, path.resolve(base, value));
    insist(name !== '..' && !name.startsWith(`..${path.sep}`) && !path.isAbsolute(name), 'compiler path outside repository');
    return name.split(path.sep).join('/') || '.';
  };
  const normalized = {};
  for (const [name, value] of Object.entries(options)) {
    if (['configFilePath', 'pathsBasePath'].includes(name) || EMIT_ONLY_OPTIONS.includes(name)) continue;
    const declaration = ts.optionDeclarations.find(option => option.name === name);
    if (name === 'paths') {
      normalized[name] = Object.fromEntries(Object.entries(value).map(([alias, targets]) =>
        [alias, targets.map(target => relative(target, options.baseUrl ?? options.pathsBasePath ?? path.join(root, 'server')))]));
    } else if (declaration?.isFilePath) normalized[name] = relative(value);
    else if (declaration?.element?.isFilePath) normalized[name] = value.map(item => relative(item));
    else if (declaration?.type instanceof Map) {
      const enumName = [...declaration.type].find(([, number]) => number === value)?.[0];
      insist(enumName !== undefined, `unknown compiler enum: ${name}`);
      normalized[name] = enumName;
    } else normalized[name] = value;
  }
  return digest(serialize(normalized));
}
export function validateBaseline(baseline) {
  // Parent blobs validate structure only. Their digests deliberately belong to the previous tools.
  insist(Array.isArray(baseline.entries) && baseline.entries.length <= MAX_BASELINE_ENTRIES, 'invalid baseline or entry cap');
  const isDigest = value => typeof value === 'string' && /^[a-f0-9]{64}$/u.test(value);
  // A trusted legacy seed has a policy digest; an unversioned blob is never an anchor.
  insist((isDigest(baseline.compilerDigest) && isDigest(baseline.driftDigest))
    || isDigest(baseline.policyDigest), 'invalid baseline digests');
  const identities = new Set();
  for (const entry of baseline.entries) {
    insist(POLICY.rules[entry.rule] && typeof entry.kind === 'string'
      && typeof entry.path === 'string' && entry.path.startsWith(SOURCE_PREFIX)
      && entry.path === path.posix.normalize(entry.path) && !entry.path.includes('\\')
      && EXTENSIONS.includes(path.extname(entry.path)), 'invalid baseline entry');
    // Must match fingerprint.mjs: preimages retain context, statement and relative token position.
    const preimage = JSON.parse(entry.preimage);
    insist(Array.isArray(preimage.context) && Array.isArray(preimage.statement)
      && Number.isInteger(preimage.tokenPosition) && preimage.tokenPosition >= 0
      && digest(entry.preimage) === entry.fingerprint, 'invalid fingerprint preimage');
    insist(!identities.has(key(entry)), 'fingerprint collision');
    identities.add(key(entry));
  }
  return identities;
}
export function compare(current, baseline) {
  const retained = validateBaseline(baseline);
  const actual = new Set();
  for (const entry of current) {
    const identity = key(entry);
    insist(!actual.has(identity), 'fingerprint collision');
    actual.add(identity);
    insist(retained.has(identity), `new diagnostic: ${identity}`);
  }
  for (const identity of retained) insist(actual.has(identity), `stale baseline: ${identity}`);
}
const sameSet = (left, right) => left.size === right.size && [...left].every(identity => right.has(identity));
function tree(root, ref) {
  return new Set(git(root, ['ls-tree', '-r', '--name-only', '-z', ref]).split('\0').filter(Boolean));
}
export function shrink(parent, current, baseTree, tipTree) {
  const trusted = validateBaseline(parent);
  const retained = validateBaseline(current);
  const movable = new Map();
  const signature = entry => JSON.stringify([entry.rule, entry.kind, entry.fingerprint]);
  // Each removed identity donates once, and only if its entire source path disappeared.
  // Must match the case-only conservation witness in promise-hygiene-baseline.test.ts.
  for (const entry of parent.entries) {
    if (retained.has(key(entry)) || tipTree.has(entry.path)) continue;
    const id = signature(entry);
    movable.set(id, (movable.get(id) ?? 0) + 1);
  }
  for (const entry of current.entries) {
    if (trusted.has(key(entry))) continue;
    const id = signature(entry);
    insist(!baseTree.has(entry.path) && (movable.get(id) ?? 0) > 0, `new diagnostic: ${key(entry)}`);
    movable.set(id, movable.get(id) - 1);
  }
}
function context(root) {
  // These mode-selection inputs must match MODE_INPUTS in promise-hygiene-workflows.test.ts.
  if (process.env.GITHUB_ACTIONS !== 'true') return { mode: MODES.LOCAL, trusted: 'HEAD', labeled: false };
  if (process.env.GITHUB_EVENT_NAME !== 'pull_request') return { mode: MODES.VERIFY, labeled: false };
  try {
    const event = readJson(root, process.env.GITHUB_EVENT_PATH);
    const trusted = event.pull_request.base.sha;
    insist(/^[a-f0-9]{40,64}$/u.test(trusted), 'invalid base sha');
    // Must match fetch-depth: 2 and no ref in both lint workflows, and promise-hygiene-workflows.test.ts.
    const MERGE_PARENT_COUNT = 2;
    const parents = git(root, ['rev-list', '--parents', '-n', '1', 'HEAD']).trim().split(' ').slice(1);
    insist(parents.length === MERGE_PARENT_COUNT && parents[0] === trusted, 'unproven merge base');
    git(root, ['rev-parse', '--verify', `${trusted}^{commit}`]);
    return { mode: MODES.TRANSITION, trusted,
      labeled: event.pull_request.labels?.some(label => label.name === REANCHOR_LABEL) === true };
  } catch {
    throw new Error('trusted parent baseline not available');
  }
}
function trustedBaseline(root, trusted) {
  try { git(root, ['rev-parse', '--verify', `${trusted}^{commit}`]); }
  catch { throw new Error('trusted parent baseline not available'); }
  try { git(root, ['cat-file', '-e', `${trusted}:${BASELINE_PATH}`]); }
  catch {
    // Only proven tree-path absence initializes; missing/corrupt objects never do.
    insist(!tree(root, trusted).has(BASELINE_PATH), 'trusted parent baseline not available');
    return undefined;
  }
  try {
    const baseline = JSON.parse(git(root, ['show', `${trusted}:${BASELINE_PATH}`]));
    validateBaseline(baseline);
    return baseline;
  } catch { throw new Error('trusted parent baseline not available'); }
}
function checkTransition(root, baseline, measured, ctx) {
  const parent = trustedBaseline(root, ctx.trusted);
  if (!parent) {
    insist(ctx.mode === MODES.TRANSITION && ctx.labeled, 'initialization requires reanchor label');
    return STATES.INITIAL_SEED;
  }
  const tip = ctx.mode === MODES.LOCAL ? [] : ['HEAD'];
  // Source deletions remain changes even when Git could pair them with destinations outside coverage.
  const changed = git(root, ['diff', '--no-renames', '--name-only', '-z', ctx.trusted, ...tip, '--']).split('\0').filter(Boolean);
  const sourceChanged = changed.some(name => name.startsWith(SOURCE_PREFIX));
  const checkerFiles = ['run.mjs', 'fingerprint.mjs', 'policy.mjs'].map(name => `server/scripts/promise-hygiene/${name}`);
  checkerFiles.push(CONFIG_PATH);
  let checkerChanged = changed.some(name => checkerFiles.includes(name));
  if (changed.includes('server/package.json')) {
    const before = JSON.parse(git(root, ['show', `${ctx.trusted}:server/package.json`]));
    const after = ctx.mode === MODES.LOCAL ? readJson(root, 'server/package.json')
      : JSON.parse(git(root, ['show', 'HEAD:server/package.json']));
    checkerChanged ||= before.scripts?.lint !== after.scripts?.lint;
  }
  insist(ctx.labeled || !checkerChanged || !sourceChanged, 'checker and source changes require reanchor label');
  const unchanged = sameSet(validateBaseline(parent), validateBaseline(baseline));
  const drift = parent.driftDigest !== measured.driftDigest || parent.compilerDigest !== measured.compilerDigest;
  // Continuing paths: no drift -> conserved transition; drift/same set -> retained;
  // drift/changed set -> labeled, source-unchanged reanchor. Exact measurement precedes all arms.
  if (drift && !unchanged) {
    insist(ctx.labeled && !sourceChanged, 'configuration drift');
    return STATES.REANCHORED;
  }
  if (!drift) shrink(parent, baseline, tree(root, ctx.trusted), ctx.mode === MODES.LOCAL
    ? new Set(git(root, ['ls-files', '-z']).split('\0').filter(Boolean)) : tree(root, 'HEAD'));
  return STATES.RETAINED;
}

export async function measure(root) {
  const sources = manifest(root);
  assertPolicy();
  // Installed version metadata is data, never an executable or computed module import.
  const versions = Object.fromEntries(Object.keys(POLICY.versions).map(name => [name, readJson(root, `server/node_modules/${name}/package.json`).version]));
  insist(serialize(versions) === serialize(POLICY.versions), 'installed version drift');
  const lockBytes = readMetadata(root, 'server/package-lock.json');
  const lock = JSON.parse(lockBytes.toString('utf8'));
  for (const [name, version] of Object.entries(versions)) {
    insist(lock.packages[`node_modules/${name}`]?.version === version, 'lockfile version drift');
  }
  const config = readJson(root, CONFIG_PATH);
  delete config['//'];
  // Hygiene coverage is fixed; effective semantic options inherited or overridden are drift-tracked.
  insist(serialize(config.include) === serialize(CONFIG.include) && serialize(config.exclude) === serialize(CONFIG.exclude)
    && Object.entries(CONFIG.compilerOptions).every(([name, value]) => config.compilerOptions?.[name] === value), 'configuration drift');
  const configFile = ts.readConfigFile(path.join(root, CONFIG_PATH), ts.sys.readFile);
  const parsed = ts.parseJsonConfigFileContent(configFile.config, ts.sys, path.join(root, 'server'));
  insist(!configFile.error && parsed.errors.length === 0, 'configuration parse failure');
  const compiler = compilerDigest(root, parsed.options);
  const driftDigest = digest(serialize({ versions, lock: digest(lockBytes), compilerDigest: compiler }));
  const program = ts.createProgram(sources.map(name => path.join(root, name)), parsed.options);
  const programSources = program.getSourceFiles().map(file => path.relative(root, file.fileName).split(path.sep).join('/'))
    .filter(name => !name.split('/').includes('node_modules') && EXTENSIONS.includes(path.extname(name))).sort();
  const targets = new Set(sources);
  const tracked = new Map(git(root, ['ls-files', '--stage', '-z']).split('\0').filter(Boolean)
    .map(row => [row.slice(row.indexOf('\t') + 1), row.split(' ')[0]]));
  const acceptedDeclarations = [];
  for (const name of programSources) {
    if (targets.has(name)) continue;
    // Declarations contain no executable statements and are never lint targets here.
    // Only tracked regular declarations with no linked component may extend the Program.
    insist(/\.d\.(?:ts|mts|cts)$/u.test(name) && tracked.has(name)
      && tracked.get(name) === '100644', `Program/manifest mismatch: ${name}`);
    let component = root;
    for (const part of name.split('/')) {
      component = path.join(component, part);
      insist(!lstatSync(component).isSymbolicLink(), `Program/manifest mismatch: ${name}`);
    }
    insist(lstatSync(component).isFile(), `Program/manifest mismatch: ${name}`);
    acceptedDeclarations.push(name);
  }
  insist(sources.every(name => programSources.includes(name)), 'Program/manifest mismatch');
  const checker = program.getTypeChecker();
  // JavaScript is type-aware without checkJs; unresolved module edges must still refuse coverage.
  for (const name of sources) {
    const source = program.getSourceFile(path.join(root, name));
    const visit = node => {
      let specifier;
      if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) specifier = node.moduleSpecifier;
      if (ts.isCallExpression(node) && (node.expression.kind === ts.SyntaxKind.ImportKeyword
        || (ts.isIdentifier(node.expression) && node.expression.text === 'require'))) {
        [specifier] = node.arguments;
      }
      if (specifier && ts.isStringLiteralLike(specifier)) {
        const symbol = checker.getSymbolAtLocation(specifier);
        const resolved = ts.resolveModuleName(specifier.text, source.fileName, parsed.options, ts.sys).resolvedModule;
        insist(symbol || resolved, `type/parser failure: unresolved module in ${name}`);
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  const typeErrors = ts.getPreEmitDiagnostics(program);
  insist(typeErrors.length === 0, `type/parser failure: ${ts.formatDiagnosticsWithColorAndContext(typeErrors, {
    getCurrentDirectory: () => root, getCanonicalFileName: name => name, getNewLine: () => '\n',
  })}`);
  const lint = new ESLint({
    // ESLint 10: true disables lookup. Project config must never execute or weaken these rules.
    cwd: path.join(root, 'server'), overrideConfigFile: true, ignore: false,
    overrideConfig: [{
      files: ['**/*.{ts,tsx,mts,cts,js,jsx,mjs,cjs}'],
      languageOptions: { parser: tseslint.parser, parserOptions: { programs: [program] } },
      linterOptions: { noInlineConfig: POLICY.noInlineConfig },
      plugins: { '@typescript-eslint': tseslint.plugin }, rules: POLICY.rules,
    }],
  });
  const results = await lint.lintFiles(sources.map(name => path.join(root, name)));
  insist(results.length === sources.length, 'lint manifest mismatch');
  const entries = [];
  const notices = [];
  for (const result of results) {
    const name = path.relative(root, result.filePath).split(path.sep).join('/');
    const source = program.getSourceFile(result.filePath);
    insist(source && sources.includes(name), 'lint file outside Program');
    for (const message of result.messages) {
      if (message.ruleId === null && message.severity === 1 && !message.fatal
        && /^'.+' has no effect because you have 'noInlineConfig' setting in your config\.$/u.test(message.message)) {
        notices.push({ path: name, message: message.message });
        continue;
      }
      insist(!message.fatal && POLICY.rules[message.ruleId] && message.messageId, `unknown lint message: ${JSON.stringify(message)}`);
      entries.push(fingerprint(source, message, name));
    }
  }
  entries.sort((left, right) => key(left).localeCompare(key(right)));
  const collisions = entries.length - new Set(entries.map(key)).size;
  insist(collisions === 0, `fingerprint collision: ${collisions}`);
  insist(entries.length <= MAX_BASELINE_ENTRIES, 'baseline entry cap');
  return { sources, entries, notices, acceptedDeclarations, compilerDigest: compiler, driftDigest };
}

export async function run(root) {
  const ctx = context(root);
  const baseline = readJson(root, BASELINE_PATH);
  validateBaseline(baseline);
  const measured = await measure(root);
  // A candidate cannot copy an old digest while using different effective options.
  // Print computed values for review; a refusal never rewrites the stored anchor.
  insist(baseline.compilerDigest === measured.compilerDigest && baseline.driftDigest === measured.driftDigest,
    `stored configuration drift; review and update ${BASELINE_PATH}: compilerDigest=${measured.compilerDigest}, driftDigest=${measured.driftDigest}`);
  compare(measured.entries, baseline);
  // State | Continuing evidence | Refusal
  // INITIAL_SEED | proven base path absence, label, exact set | unproven base or missing label
  // RETAINED | exact set, valid conservation or drift with unchanged identities | new/stale key
  // REANCHORED | label, no source change, exact set and computed digests | configuration drift
  // VERIFIED | exact set and computed digests, no transition | new/stale key or digest lie
  // ADVISORY | LOCAL transition against committed HEAD | same transition refusals, advisory only
  const transition = ctx.mode === MODES.VERIFY ? STATES.VERIFIED : checkTransition(root, baseline, measured, ctx);
  return { mode: ctx.mode, state: ctx.mode === MODES.LOCAL ? STATES.ADVISORY : transition,
    ...(ctx.mode === MODES.LOCAL ? { transition, notice: 'advisory, CI is the gate' } : {}),
    files: measured.sources.length, diagnostics: measured.entries.length, inertDisableNotices: measured.notices.length };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = path.resolve(import.meta.dirname, '../../..');
  try {
    insist(process.argv.length === 2, 'unexpected arguments; no regeneration mode exists');
    console.log(JSON.stringify(await run(root), null, JSON_INDENT));
  } catch (error) {
    console.error(`Promise hygiene refused: ${error.message}${process.env.GITHUB_ACTIONS !== 'true' ? '; advisory, CI is the gate' : ''}`);
    process.exitCode = EXIT_REFUSED;
  }
}
