import source from './wire.json';
import { bound, constant } from './constants.js';
import { jcs } from './jcs.js';
import { parseStrict } from './parse-strict.js';

// Must match the data-language interpreter in castle-wall-daemon/src/smb/wire.rs.
// All message fields and edge registries come from wire.json, never from a second table.
type Schema = string | { ref?: string; const?: unknown; enum?: unknown[]; oneOf?: Schema[]; type?: string; extends?: string; fields?: Record<string, Schema>; items?: Schema; min?: string | number; max?: string | number; chars?: string; prefix?: string; suffix?: string };
const schemas = source.schemas as Record<string, Schema>;
/** Shared edge inventory, including frame bounds, capacity and per-kind schemas. */
export const edges = source.edges as Record<string, { path: string; frame_max: string; pending_max: string | number; requests: Record<string, { request: string; reply: string }> }>;
function object(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value); }
function resolve(schema: Schema): Exclude<Schema, string> {
  if (typeof schema === 'string') return resolve(schemas[schema]);
  if (!schema) throw new Error('unknown SMB schema');
  return schema.ref ? resolve(schema.ref) : schema;
}
function fields(schema: Exclude<Schema, string>): Record<string, Schema> {
  return { ...(schema.extends ? fields(resolve(schema.extends)) : {}), ...schema.fields };
}
function matches(spec: Schema, value: unknown, depth: number): boolean {
  if (depth > bound('JSON_MAX_DEPTH') + 1) return false;
  const schema = resolve(spec);
  if ('const' in schema) return value === schema.const;
  if (schema.enum) return schema.enum.includes(value);
  if (schema.oneOf) return schema.oneOf.filter(s => matches(s, value, depth)).length === 1;
  switch (schema.type) {
    case 'object': {
      if (!object(value)) return false;
      const expected = fields(schema);
      // Exact field-set equality prevents a second interpretation at a later consumer.
      return Object.keys(value).length === Object.keys(expected).length && Object.entries(expected).every(([key, s]) => Object.hasOwn(value, key) && matches(s, value[key], depth + 1));
    }
    case 'array': return Array.isArray(value) && value.length <= bound(schema.max!) && value.every(v => matches(schema.items!, v, depth + 1));
    case 'decimal':
      // Decimal strings preserve all u64 bits across the JavaScript boundary; numbers never substitute.
      return typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) <= BigInt(schema.max!) && BigInt(value) >= BigInt(schema.min ?? 0);
    case 'integer': return typeof value === 'number' && Number.isSafeInteger(value);
    case 'string': {
      if (typeof value !== 'string') return false;
      if (schema.prefix) {
        const prefix = constant(schema.prefix) as string;
        return value.startsWith(prefix) && matches(schema.suffix!, value.slice(prefix.length), depth + 1);
      }
      const size = Buffer.byteLength(value);
      return size >= bound(schema.min!) && size <= bound(schema.max!) && (!schema.chars || [...value].every(c => schema.chars!.includes(c)));
    }
    case 'base64': case 'base64url': {
      if (typeof value !== 'string') return false;
      const encoding = schema.type === 'base64' ? 'base64' : 'base64url';
      const decoded = Buffer.from(value, encoding);
      // Canonical re-encoding refuses ignored characters and ambiguous base64 padding.
      return decoded.length <= bound(schema.max!) && decoded.toString(encoding) === value;
    }
    case 'json': return true; // validate() has already applied the shared JSON-domain check.
    default: throw new Error('unknown SMB schema operation');
  }
}

/** Validate a value against the shared schema and the strict JSON domain. */
export function validate(schema: string, value: unknown): boolean {
  try {
    parseStrict(Buffer.from(jcs(value)), bound('TASK_STORE_BYTES'));
    return matches(schema, value, 0);
  } catch { return false; }
}

/** Validate one raw message without erasing duplicate names before the strict parser sees them. */
export function validateBytes(schema: string, bytes: Uint8Array, maximum: number): unknown {
  const value = parseStrict(bytes, maximum);
  if (!validate(schema, value)) throw new Error('SMB schema');
  return value;
}

/** Normalize a kernel boot UUID before passing it to the hex128 wire schema. */
export function normalizeBootId(uuid: string): string {
  const normalized = uuid.replaceAll('-', '').toLowerCase();
  if (!validate('boot_id', normalized)) throw new Error('SMB boot id');
  return normalized;
}

/** Match bounded pending requests; any malformed, duplicate, or unknown reply closes all pending work. */
export class ReplyMatcher {
  state: 'OPEN' | 'CLOSED' = 'OPEN';
  private nextId = 1n;
  private readonly pending = new Map<string, string>();
  constructor(readonly edge: string) {
    // Only a declared edge can supply the mandatory schemas and capacity; prototype properties are not edges.
    if (!Object.hasOwn(edges, edge)) throw new Error('unknown SMB edge');
  }
  get outstanding(): number { return this.pending.size; }
  close(): void { this.state = 'CLOSED'; this.pending.clear(); }
  register(request: unknown): void {
    const connection = edges[this.edge];
    const route = object(request) && typeof request.kind === 'string' ? connection.requests[request.kind] : undefined;
    // OPEN continues only with a fresh monotonic id, an exact schema, and reserved capacity.
    if (this.state !== 'OPEN' || !route || !validate(route.request, request) || (request as Record<string, unknown>).id !== this.nextId.toString() || this.pending.size >= bound(connection.pending_max)) {
      this.close(); throw new Error('SMB request refused');
    }
    this.pending.set(this.nextId.toString(), route.reply); this.nextId++;
  }
  receive(reply: unknown): unknown {
    const id = object(reply) && typeof reply.id === 'string' ? reply.id : '';
    const schema = this.pending.get(id);
    // OPEN continues only for exactly one outstanding id and that request's reply schema.
    if (this.state !== 'OPEN' || !schema || !(validate(schema, reply) || validate('error_envelope', reply))) {
      this.close(); throw new Error('SMB reply refused');
    }
    this.pending.delete(id);
    return reply;
  }
}
