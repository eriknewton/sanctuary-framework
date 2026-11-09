import { execFileSync } from 'node:child_process';
import { lstatSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ESLint } from 'eslint';
import tseslint from 'typescript-eslint';
import ts from 'typescript';
import {
  BASELINE_PATH, CONFIG_PATH, CONFIG, EXTENSIONS, POLICY, POLICY_DIGEST,
  SEED_DIGEST, SEED_SOURCE_DIGEST, SOURCE_PREFIX, MAX_GIT_BYTES, MAX_SOURCE_BYTES,
  MAX_SOURCE_FILES, MAX_HISTORY_COMMITS, digest,
} from './policy.mjs';
import { fingerprint, key } from './fingerprint.mjs';

const EXIT_REFUSED = 1;
const JSON_INDENT = 2;
export function git(root, args) {
  return execFileSync('git', args, { cwd: root, encoding: 'utf8', maxBuffer: MAX_GIT_BYTES });
}
function insist(condition, reason) {
  if (!condition) throw new Error(reason);
}
function readJson(root, name) {
  return JSON.parse(readFileSync(path.join(root, name), 'utf8'));
}

export function manifest(root) {
  const paths = git(root, ['ls-files', '-z']).split('\0').filter(Boolean);
  const seen = new Set();
  const sources = [];
  for (const name of paths) {
    insist(!path.isAbsolute(name) && !name.includes('\\') && name === path.posix.normalize(name)
      && !name.split('/').includes('..') && !seen.has(name), 'invalid or duplicate manifest path');
    seen.add(name);
    if (!name.startsWith(SOURCE_PREFIX) || !EXTENSIONS.includes(path.extname(name))) continue;
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

export function validateBaseline(baseline) {
  insist(baseline.policyDigest === POLICY_DIGEST, 'policy drift');
  insist(Array.isArray(baseline.sources) && Array.isArray(baseline.entries), 'invalid baseline');
  insist(baseline.sources.length <= MAX_SOURCE_FILES, 'baseline source cap');
  insist(new Set(baseline.sources).size === baseline.sources.length, 'duplicate baseline source');
  const identities = new Set();
  for (const entry of baseline.entries) {
    insist(POLICY.rules[entry.rule] && typeof entry.kind === 'string'
      && baseline.sources.includes(entry.path), 'invalid baseline entry');
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
export function shrink(parent, current) {
  const trusted = validateBaseline(parent);
  const retained = validateBaseline(current);
  for (const identity of retained) insist(trusted.has(identity), `parent-baseline addition: ${identity}`);
  for (const source of parent.sources) insist(current.sources.includes(source), `hidden source: ${source}`);
}

export function checkHistory(root, baseline, sources) {
  // A shallow tip can conceal a removed key and launder its resurrection as the reviewed seed.
  insist(git(root, ['rev-parse', '--is-shallow-repository']).trim() === 'false',
    'trusted baseline history unavailable: shallow repository');
  // State | Continuing evidence | Refusal
  // INITIAL_SEED | Exact reviewed baseline and source digest | Missing or changed seed
  // RETAINED | Every historical transition and current edit shrink | Added key or hidden source
  // MEASURED | Full manifest/Program parity and known typed diagnostics | Coverage/type/config error
  // ACCEPTED | Current identities equal retained identities | New, duplicate or stale identity
  // The later measure/compare stages apply to both continuing history arms.
  // Every first-parent baseline transition is checked, so an intermediate commit cannot launder additions.
  const commits = git(root, ['log', '--first-parent', '--format=%H', '--', BASELINE_PATH])
    .trim().split('\n').filter(Boolean).reverse();
  insist(commits.length <= MAX_HISTORY_COMMITS, 'history cap exceeded');
  let trusted;
  for (const commit of commits) {
    const previous = JSON.parse(git(root, ['show', `${commit}:${BASELINE_PATH}`]));
    validateBaseline(previous);
    if (!trusted) insist(digest(JSON.stringify(previous)) === SEED_DIGEST, 'unreviewed initial seed');
    else shrink(trusted, previous);
    trusted = previous;
  }
  if (trusted) shrink(trusted, baseline);
  else {
    insist(digest(JSON.stringify(baseline)) === SEED_DIGEST, 'unreviewed initial seed');
    insist(sourceDigest(root, sources) === SEED_SOURCE_DIGEST, 'initial source snapshot changed');
  }
}

export async function measure(root) {
  const sources = manifest(root);
  const versions = { eslint: ESLint.version, typescript: ts.version, typescriptEslint: tseslint.plugin.meta.version };
  insist(JSON.stringify(versions) === JSON.stringify(POLICY.versions), 'installed version drift');
  const lock = readJson(root, 'server/package-lock.json');
  for (const [name, version] of Object.entries({ eslint: versions.eslint, typescript: versions.typescript, 'typescript-eslint': versions.typescriptEslint })) {
    insist(lock.packages[`node_modules/${name}`]?.version === version, 'lockfile version drift');
  }
  const config = readJson(root, CONFIG_PATH);
  delete config['//'];
  insist(JSON.stringify(config) === JSON.stringify(CONFIG), 'configuration drift');
  const configFile = ts.readConfigFile(path.join(root, CONFIG_PATH), ts.sys.readFile);
  const parsed = ts.parseJsonConfigFileContent(configFile.config, ts.sys, path.join(root, 'server'));
  insist(!configFile.error && parsed.errors.length === 0, 'configuration parse failure');
  const program = ts.createProgram(sources.map(name => path.join(root, name)), parsed.options);
  const programSources = program.getSourceFiles().map(file => path.relative(root, file.fileName).split(path.sep).join('/'))
    .filter(name => name.startsWith(SOURCE_PREFIX) && EXTENSIONS.includes(path.extname(name))).sort();
  insist(JSON.stringify(programSources) === JSON.stringify(sources), 'Program/manifest mismatch');
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
  insist(new Set(entries.map(key)).size === entries.length, 'fingerprint collision');
  return { sources, entries, notices };
}

export async function run(root) {
  const baseline = readJson(root, BASELINE_PATH);
  validateBaseline(baseline);
  const sources = manifest(root);
  for (const name of baseline.sources) insist(sources.includes(name), `missing source file: ${name}`);
  checkHistory(root, baseline, sources);
  const measured = await measure(root);
  compare(measured.entries, baseline);
  return { state: 'RETAINED', files: measured.sources.length, diagnostics: measured.entries.length, inertDisableNotices: measured.notices.length };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = path.resolve(import.meta.dirname, '../../..');
  try {
    insist(process.argv.length === 2, 'unexpected arguments; no regeneration mode exists');
    console.log(JSON.stringify(await run(root), null, JSON_INDENT));
  } catch (error) {
    console.error(`Promise hygiene refused: ${error.message}`);
    process.exitCode = EXIT_REFUSED;
  }
}
