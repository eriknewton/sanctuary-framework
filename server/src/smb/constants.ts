import source from './constants.json';

// Must match the include_str! loader in castle-wall-daemon/src/smb/constants.rs.
// A4 equalities must match MAX_SURROGATE_VALUE_BYTES and SURROGATE_QUERY_TIMEOUT_MS
// in credential-surrogate/constants.ts and SURROGATE_PLACEHOLDER_PREFIX in
// credential-surrogate/placeholder.ts; contracts.test.ts binds the unchanged producers.
type Entry = { value?: unknown; template?: unknown; expression?: { op: string; args: string[] }; source: string };
const entries: Record<string, Entry> = source.constants;

/** Resolve the shared constant expression tree; unknown names or cycles refuse startup. */
export function constant(name: string, visiting = new Set<string>()): unknown {
  const entry = entries[name];
  if (!entry || visiting.has(name)) throw new Error('invalid SMB constant');
  if ('value' in entry) return entry.value;
  visiting.add(name);
  if ('template' in entry) {
    const expand = (value: unknown): unknown => {
      if (typeof value === 'string') return value.replace(/\$\{([A-Z0-9_]+)\}/g, (_match, key: string) => String(constant(key, visiting)));
      if (Array.isArray(value)) return value.map(expand);
      if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, expand(item)]));
      return value;
    };
    const result = expand(entry.template); visiting.delete(name); return result;
  }
  const expression = entry.expression!;
  const args = expression.args.map(key => {
    const value = constant(key, visiting);
    if (typeof value !== 'number') throw new Error('non-numeric SMB expression');
    return value;
  });
  visiting.delete(name);
  switch (expression.op) {
    case 'ref': return args[0];
    case 'add': return args.reduce((a, b) => a + b, 0);
    case 'sub': return args[0] - args[1];
    case 'div': return args[0] / args[1];
    case 'floor_multiple': return Math.floor(args[0] / args[1]) * args[1];
    case 'mul': return args.reduce((a, b) => a * b, 1);
    case 'base64': return Math.ceil(args[0] / args[1]) * args[2];
    default: throw new Error('unknown SMB expression');
  }
}

/** Read a nonnegative integral bound from the shared constants. */
export function bound(name: string | number): number {
  const value = typeof name === 'number' ? name : constant(name);
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw new Error('invalid SMB bound');
  return value;
}

/** Full resolved inventory for consumers and cross-language parity checks. */
export function allConstants(): Record<string, unknown> {
  return Object.fromEntries(Object.keys(entries).map(name => [name, constant(name)]));
}
