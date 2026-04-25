/**
 * Lightweight local privacy filter for outbound context.
 *
 * This is not a replacement for a full detector such as OpenAI privacy-filter.
 * It gives Sanctuary a deterministic baseline that catches common high-risk
 * spans inside otherwise-allowed fields, so policy gates are not limited to
 * top-level field names.
 */

import type { StorageBackend } from "../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";
import { hmacSha256 } from "../core/hashing.js";
import type { PrivacyDetectorClass } from "../contracts/v1.1/constants.js";

export type PrivacySpanClass =
  | "email"
  | "phone"
  | "ssn"
  | "credit_card"
  | "secret_assignment"
  | "secret"
  | "credential"
  | "account_number"
  | "address"
  | "person"
  | "client"
  | "project"
  | "file_path"
  | "domain_term"
  | "url"
  | "date"
  | "custom";

export interface PrivacyFinding {
  path: string;
  class: PrivacySpanClass;
  action: "redact" | "placeholder";
  placeholder?: string;
}

export interface PrivacyFilterResult<T = unknown> {
  value: T;
  findings: PrivacyFinding[];
}

interface SpanPattern {
  class: PrivacySpanClass;
  pattern: RegExp;
  replacement: string;
  placeholderPrefix: string;
  detectorClass?: PrivacyDetectorClass;
}

const SPAN_PATTERNS: SpanPattern[] = [
  {
    class: "email",
    pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    replacement: "[EMAIL_REDACTED]",
    placeholderPrefix: "EMAIL",
    detectorClass: "person",
  },
  {
    class: "ssn",
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
    replacement: "[SSN_REDACTED]",
    placeholderPrefix: "SSN",
    detectorClass: "person",
  },
  {
    class: "credit_card",
    pattern: /\b(?:\d[ -]*?){13,19}\b/g,
    replacement: "[CARD_REDACTED]",
    placeholderPrefix: "CARD",
    detectorClass: "account",
  },
  {
    class: "phone",
    pattern: /\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b/g,
    replacement: "[PHONE_REDACTED]",
    placeholderPrefix: "PHONE",
    detectorClass: "person",
  },
  {
    class: "secret_assignment",
    pattern: /\b(api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret)\s*[:=]\s*["']?[^"',\s}]+/gi,
    replacement: "$1=[SECRET_REDACTED]",
    placeholderPrefix: "SECRET",
    detectorClass: "secret",
  },
  {
    class: "secret",
    pattern: /\b(?:Bearer\s+[A-Za-z0-9._~+/-]{16,}|sk-[A-Za-z0-9_-]{12,}|sk_(?:live|test)_[A-Za-z0-9]{12,}|ghp_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
    replacement: "[SECRET_REDACTED]",
    placeholderPrefix: "SECRET",
    detectorClass: "secret",
  },
  {
    class: "credential",
    pattern: /\b(?:credential|credentials|client[_-]?secret|private[_-]?key)\s*[:=]\s*["']?[^"',\s}]+/gi,
    replacement: "[CREDENTIAL_REDACTED]",
    placeholderPrefix: "CREDENTIAL",
    detectorClass: "credential",
  },
  {
    class: "account_number",
    pattern: /\b(?:(?:acct|account|customer|tenant|org)[_-][A-Za-z0-9]{4,}|(?:acct|account)[0-9]{4,})\b/gi,
    replacement: "[ACCOUNT_REDACTED]",
    placeholderPrefix: "ACCOUNT",
    detectorClass: "account",
  },
  {
    class: "file_path",
    pattern: /(?:~\/|\/(?:Users|home|var|tmp|etc|opt)\/|[A-Za-z]:\\|\.{1,2}\/)(?:[A-Za-z0-9._-]+[\\/])+[A-Za-z0-9._-]+/g,
    replacement: "[FILE_PATH_REDACTED]",
    placeholderPrefix: "FILE_PATH",
    detectorClass: "file_path",
  },
];

const MAX_DEPTH = 20;
const VAULT_NAMESPACE = "_privacy_placeholder_vault";

interface PlaceholderRecord {
  version: 1;
  kind: "placeholder";
  scope: string;
  class: PrivacySpanClass;
  placeholder: string;
  raw_value: string;
  raw_hash: string;
  created_at: string;
}

interface PlaceholderIndex {
  version: 1;
  counters: Partial<Record<PrivacySpanClass, number>>;
}

interface FieldPathRecord {
  version: 1;
  kind: "field_path";
  scope: string;
  alias: string;
  raw_path: string;
  raw_hash: string;
  created_at: string;
}

interface FieldPathIndex {
  version: 1;
  next: number;
}

export interface SensitiveSpan {
  class: PrivacySpanClass;
  detectorClass: PrivacyDetectorClass;
  start: number;
  end: number;
  text: string;
  placeholderPrefix: string;
}

export interface SensitiveSpanDetectionOptions {
  clientNames?: string[];
  projectNames?: string[];
  domainTerms?: string[];
  personNames?: string[];
  pathHint?: string;
}

export class PrivacyPlaceholderVault {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;
  private lookupKey: Uint8Array;
  private cache = new Map<string, PlaceholderRecord>();
  private pathCache = new Map<string, FieldPathRecord>();

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "l2-privacy-placeholders");
    this.lookupKey = derivePurposeKey(masterKey, "l2-privacy-placeholder-lookup");
  }

  async placeholderFor(
    spanClass: PrivacySpanClass,
    rawValue: string,
    scope = "default"
  ): Promise<string> {
    const key = this.recordKey(spanClass, rawValue, scope);
    const cached = this.cache.get(key);
    if (cached) return cached.placeholder;

    const existing = await this.readRecord(key);
    if (existing) {
      this.cache.set(key, existing);
      return existing.placeholder;
    }

    const index = await this.readIndex(scope);
    const next = (index.counters[spanClass] ?? 0) + 1;
    index.counters[spanClass] = next;

    const placeholder = `${placeholderPrefixFor(spanClass)}_${next}`;
    const record: PlaceholderRecord = {
      version: 1,
      kind: "placeholder",
      scope,
      class: spanClass,
      placeholder,
      raw_value: rawValue,
      raw_hash: this.hmacString(`raw:${rawValue}`),
      created_at: new Date().toISOString(),
    };
    await this.writeRecord(key, record);
    await this.writeIndex(scope, index);
    this.cache.set(key, record);
    return placeholder;
  }

  async resolvePlaceholder(
    placeholder: string,
    scope = "default"
  ): Promise<string | null> {
    const entries = await this.storage.list(VAULT_NAMESPACE, `${scope}__record__`);
    for (const meta of entries) {
      const record = await this.readRecord(meta.key);
      if (record?.placeholder === placeholder) {
        return record.raw_value;
      }
    }
    return null;
  }

  async aliasForFieldPath(path: string, scope = "default"): Promise<string> {
    const key = this.pathRecordKey(path, scope);
    const cached = this.pathCache.get(key);
    if (cached) return cached.alias;

    const existing = await this.readPathRecord(key);
    if (existing) {
      this.pathCache.set(key, existing);
      return existing.alias;
    }

    const index = await this.readPathIndex(scope);
    const alias = `$${index.next}`;
    const nextIndex = { version: 1 as const, next: index.next + 1 };
    const record: FieldPathRecord = {
      version: 1,
      kind: "field_path",
      scope,
      alias,
      raw_path: path,
      raw_hash: this.hmacString(`path:${path}`),
      created_at: new Date().toISOString(),
    };

    await this.writePathRecord(key, record);
    await this.writePathIndex(scope, nextIndex);
    this.pathCache.set(key, record);
    return alias;
  }

  async resolveFieldPathAlias(
    alias: string,
    scope = "default"
  ): Promise<string | null> {
    const entries = await this.storage.list(VAULT_NAMESPACE, `${scope}__path__`);
    for (const meta of entries) {
      const record = await this.readPathRecord(meta.key);
      if (record?.alias === alias) {
        return record.raw_path;
      }
    }
    return null;
  }

  private recordKey(
    spanClass: PrivacySpanClass,
    rawValue: string,
    scope: string
  ): string {
    const rawHash = this.hmacString(`${scope}:${spanClass}:${rawValue}`);
    return `${scope}__record__${spanClass}__${rawHash}`;
  }

  private indexKey(scope: string): string {
    return `${scope}__index`;
  }

  private pathRecordKey(path: string, scope: string): string {
    return `${scope}__path__${this.hmacString(`${scope}:field_path:${path}`)}`;
  }

  private pathIndexKey(scope: string): string {
    return `${scope}__path_index`;
  }

  private async readIndex(scope: string): Promise<PlaceholderIndex> {
    const raw = await this.storage.read(VAULT_NAMESPACE, this.indexKey(scope));
    if (!raw) return { version: 1, counters: {} };
    try {
      const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.encryptionKey);
      return JSON.parse(bytesToString(decrypted)) as PlaceholderIndex;
    } catch (err) {
      throw new PrivacyVaultError("privacy_vault_index_unreadable", err);
    }
  }

  private async writeIndex(scope: string, index: PlaceholderIndex): Promise<void> {
    const encrypted = encrypt(stringToBytes(JSON.stringify(index)), this.encryptionKey);
    await this.storage.write(
      VAULT_NAMESPACE,
      this.indexKey(scope),
      stringToBytes(JSON.stringify(encrypted))
    );
  }

  private async readRecord(key: string): Promise<PlaceholderRecord | null> {
    const raw = await this.storage.read(VAULT_NAMESPACE, key);
    if (!raw) return null;
    try {
      const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.encryptionKey);
      const parsed = JSON.parse(bytesToString(decrypted)) as PlaceholderRecord;
      return parsed.kind === "placeholder" || parsed.kind === undefined
        ? parsed
        : null;
    } catch (err) {
      throw new PrivacyVaultError("privacy_vault_record_unreadable", err);
    }
  }

  private async writeRecord(key: string, record: PlaceholderRecord): Promise<void> {
    const encrypted = encrypt(stringToBytes(JSON.stringify(record)), this.encryptionKey);
    await this.storage.write(
      VAULT_NAMESPACE,
      key,
      stringToBytes(JSON.stringify(encrypted))
    );
  }

  private async readPathIndex(scope: string): Promise<FieldPathIndex> {
    const raw = await this.storage.read(VAULT_NAMESPACE, this.pathIndexKey(scope));
    if (!raw) return { version: 1, next: 0 };
    try {
      const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.encryptionKey);
      return JSON.parse(bytesToString(decrypted)) as FieldPathIndex;
    } catch (err) {
      throw new PrivacyVaultError("privacy_vault_path_index_unreadable", err);
    }
  }

  private async writePathIndex(
    scope: string,
    index: FieldPathIndex
  ): Promise<void> {
    const encrypted = encrypt(stringToBytes(JSON.stringify(index)), this.encryptionKey);
    await this.storage.write(
      VAULT_NAMESPACE,
      this.pathIndexKey(scope),
      stringToBytes(JSON.stringify(encrypted))
    );
  }

  private async readPathRecord(key: string): Promise<FieldPathRecord | null> {
    const raw = await this.storage.read(VAULT_NAMESPACE, key);
    if (!raw) return null;
    try {
      const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.encryptionKey);
      const parsed = JSON.parse(bytesToString(decrypted)) as FieldPathRecord;
      return parsed.kind === "field_path" ? parsed : null;
    } catch (err) {
      throw new PrivacyVaultError("privacy_vault_path_record_unreadable", err);
    }
  }

  private async writePathRecord(
    key: string,
    record: FieldPathRecord
  ): Promise<void> {
    const encrypted = encrypt(stringToBytes(JSON.stringify(record)), this.encryptionKey);
    await this.storage.write(
      VAULT_NAMESPACE,
      key,
      stringToBytes(JSON.stringify(encrypted))
    );
  }

  private hmacString(value: string): string {
    return bytesToHex(hmacSha256(this.lookupKey, stringToBytes(value)));
  }
}

export class PrivacyVaultError extends Error {
  readonly code: string;
  readonly cause?: unknown;

  constructor(code: string, cause?: unknown) {
    super(code);
    this.name = "PrivacyVaultError";
    this.code = code;
    this.cause = cause;
  }
}

export function applyLocalPrivacyFilter<T = unknown>(
  value: T,
  path = "$"
): PrivacyFilterResult<T> {
  const findings: PrivacyFinding[] = [];
  const filtered = filterValue(value, path, findings, 0) as T;
  return { value: filtered, findings };
}

export async function applyPrivacyPlaceholders<T = unknown>(
  value: T,
  vault: PrivacyPlaceholderVault,
  scope = "default",
  path = "$"
): Promise<PrivacyFilterResult<T>> {
  const findings: PrivacyFinding[] = [];
  const filtered = await placeholderValue(value, path, findings, vault, scope, 0) as T;
  return { value: filtered, findings };
}

export interface OpenAIPrivacyFilterSpan {
  label: string;
  start: number;
  end: number;
  text: string;
  placeholder?: string;
}

export interface OpenAIPrivacyFilterResult {
  schema_version: number;
  detected_spans: OpenAIPrivacyFilterSpan[];
  text: string;
  redacted_text?: string;
}

export async function applyOpenAIPrivacyFilterResult(
  result: OpenAIPrivacyFilterResult,
  vault: PrivacyPlaceholderVault,
  scope = "default",
  path = "$"
): Promise<PrivacyFilterResult<string>> {
  const text = result.text;
  const findings: PrivacyFinding[] = [];
  const spans = result.detected_spans
    .map((span) => ({
      ...span,
      class: mapOpenAIPrivacyLabel(span.label),
    }))
    .filter((span): span is OpenAIPrivacyFilterSpan & { class: PrivacySpanClass } =>
      span.class !== null &&
      Number.isInteger(span.start) &&
      Number.isInteger(span.end) &&
      span.start >= 0 &&
      span.end > span.start &&
      span.end <= text.length
    )
    .sort((a, b) => a.start - b.start);

  let cursor = 0;
  const pieces: string[] = [];
  for (const span of spans) {
    if (span.start < cursor) continue;
    const raw = text.slice(span.start, span.end);
    const placeholder = await vault.placeholderFor(span.class, raw, scope);
    pieces.push(text.slice(cursor, span.start));
    pieces.push(placeholder);
    cursor = span.end;
    findings.push({
      path,
      class: span.class,
      action: "placeholder",
      placeholder,
    });
  }
  pieces.push(text.slice(cursor));

  return {
    value: pieces.join(""),
    findings,
  };
}

export function detectSensitiveSpans(
  input: string,
  options: SensitiveSpanDetectionOptions = {}
): SensitiveSpan[] {
  const spans: SensitiveSpan[] = [];

  addConfiguredTermSpans(
    spans,
    input,
    options.clientNames ?? [],
    "client",
    "client",
    "CLIENT"
  );
  addConfiguredTermSpans(
    spans,
    input,
    options.projectNames ?? [],
    "project",
    "project",
    "PROJECT"
  );
  addConfiguredTermSpans(
    spans,
    input,
    options.domainTerms ?? [],
    "domain_term",
    "domain_term",
    "TERM"
  );
  addConfiguredTermSpans(
    spans,
    input,
    options.personNames ?? [],
    "person",
    "person",
    "PERSON"
  );

  const pathHint = options.pathHint?.toLowerCase() ?? "";
  if (
    input.length <= 120 &&
    /(?:^|[^a-z0-9])(?:name|owner|recipient|contact|person)(?:$|[^a-z0-9])/.test(pathHint) &&
    /^[A-Z][A-Za-z'-]+(?:\s+[A-Z][A-Za-z'-]+){1,3}$/.test(input.trim())
  ) {
    const start = input.indexOf(input.trim());
    spans.push({
      class: "person",
      detectorClass: "person",
      start,
      end: start + input.trim().length,
      text: input.trim(),
      placeholderPrefix: "PERSON",
    });
  }

  for (const pattern of SPAN_PATTERNS) {
    pattern.pattern.lastIndex = 0;
    for (const match of input.matchAll(pattern.pattern)) {
      if (match.index === undefined || match[0].length === 0) continue;
      spans.push({
        class: pattern.class,
        detectorClass: pattern.detectorClass ?? detectorClassForSpan(pattern.class),
        start: match.index,
        end: match.index + match[0].length,
        text: match[0],
        placeholderPrefix: pattern.placeholderPrefix,
      });
    }
  }

  return removeOverlappingSpans(spans);
}

export function detectorClassForSpan(
  spanClass: PrivacySpanClass
): PrivacyDetectorClass {
  switch (spanClass) {
    case "client":
      return "client";
    case "project":
      return "project";
    case "secret":
    case "secret_assignment":
      return "secret";
    case "credential":
      return "credential";
    case "account_number":
    case "credit_card":
      return "account";
    case "file_path":
      return "file_path";
    case "domain_term":
      return "domain_term";
    case "custom":
      return "custom";
    case "email":
    case "phone":
    case "ssn":
    case "address":
    case "person":
    case "url":
    case "date":
    default:
      return "person";
  }
}

export function placeholderPrefixFor(spanClass: PrivacySpanClass): string {
  return SPAN_PATTERNS.find((p) => p.class === spanClass)?.placeholderPrefix
    ?? OPENAI_LABEL_PREFIXES[spanClass]
    ?? CONTRACT_CLASS_PREFIXES[spanClass]
    ?? "PRIVATE";
}

function filterValue(
  value: unknown,
  path: string,
  findings: PrivacyFinding[],
  depth: number
): unknown {
  if (depth > MAX_DEPTH) return value;

  if (typeof value === "string") {
    return filterString(value, path, findings);
  }

  if (Array.isArray(value)) {
    return value.map((item, index) =>
      filterValue(item, `${path}[${index}]`, findings, depth + 1)
    );
  }

  if (value && typeof value === "object") {
    const filtered: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      filtered[key] = filterValue(child, `${path}.${key}`, findings, depth + 1);
    }
    return filtered;
  }

  return value;
}

function filterString(
  input: string,
  path: string,
  findings: PrivacyFinding[]
): string {
  let output = input;

  for (const span of SPAN_PATTERNS) {
    const before = output;
    output = output.replace(span.pattern, span.replacement);
    if (output !== before) {
      findings.push({ path, class: span.class, action: "redact" });
    }
  }

  return output;
}

async function placeholderValue(
  value: unknown,
  path: string,
  findings: PrivacyFinding[],
  vault: PrivacyPlaceholderVault,
  scope: string,
  depth: number
): Promise<unknown> {
  if (depth > MAX_DEPTH) return value;

  if (typeof value === "string") {
    return placeholderString(value, path, findings, vault, scope);
  }

  if (Array.isArray(value)) {
    const out: unknown[] = [];
    for (let index = 0; index < value.length; index++) {
      out.push(await placeholderValue(
        value[index],
        `${path}[${index}]`,
        findings,
        vault,
        scope,
        depth + 1
      ));
    }
    return out;
  }

  if (value && typeof value === "object") {
    const filtered: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      filtered[key] = await placeholderValue(
        child,
        `${path}.${key}`,
        findings,
        vault,
        scope,
        depth + 1
      );
    }
    return filtered;
  }

  return value;
}

async function placeholderString(
  input: string,
  path: string,
  findings: PrivacyFinding[],
  vault: PrivacyPlaceholderVault,
  scope: string
): Promise<string> {
  const spans = detectSensitiveSpans(input, { pathHint: path });
  if (spans.length === 0) return input;

  let cursor = 0;
  const pieces: string[] = [];
  for (const span of spans) {
    const placeholder = await vault.placeholderFor(span.class, span.text, scope);
    pieces.push(input.slice(cursor, span.start));
    pieces.push(placeholder);
    cursor = span.end;
    findings.push({
      path,
      class: span.class,
      action: "placeholder",
      placeholder,
    });
  }
  pieces.push(input.slice(cursor));
  return pieces.join("");
}

const OPENAI_LABEL_PREFIXES: Partial<Record<PrivacySpanClass, string>> = {
  account_number: "ACCOUNT",
  address: "ADDRESS",
  client: "CLIENT",
  credential: "CREDENTIAL",
  domain_term: "TERM",
  person: "PERSON",
  project: "PROJECT",
  file_path: "FILE_PATH",
  secret: "SECRET",
  url: "URL",
  date: "DATE",
};

const CONTRACT_CLASS_PREFIXES: Partial<Record<PrivacySpanClass, string>> = {
  account_number: "ACCOUNT",
  client: "CLIENT",
  credential: "CREDENTIAL",
  domain_term: "TERM",
  file_path: "FILE_PATH",
  project: "PROJECT",
  secret: "SECRET",
};

function addConfiguredTermSpans(
  spans: SensitiveSpan[],
  input: string,
  terms: string[],
  spanClass: PrivacySpanClass,
  detectorClass: PrivacyDetectorClass,
  placeholderPrefix: string
): void {
  const sortedTerms = [...new Set(terms.map((term) => term.trim()).filter(Boolean))]
    .sort((a, b) => b.length - a.length);

  for (const term of sortedTerms) {
    const pattern = new RegExp(escapeRegExp(term), "gi");
    for (const match of input.matchAll(pattern)) {
      if (match.index === undefined || match[0].length === 0) continue;
      spans.push({
        class: spanClass,
        detectorClass,
        start: match.index,
        end: match.index + match[0].length,
        text: match[0],
        placeholderPrefix,
      });
    }
  }
}

function removeOverlappingSpans(spans: SensitiveSpan[]): SensitiveSpan[] {
  const sorted = spans.sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    return (b.end - b.start) - (a.end - a.start);
  });

  const accepted: SensitiveSpan[] = [];
  let cursor = -1;
  for (const span of sorted) {
    if (span.start < cursor) continue;
    accepted.push(span);
    cursor = span.end;
  }
  return accepted;
}

function escapeRegExp(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function mapOpenAIPrivacyLabel(label: string): PrivacySpanClass | null {
  switch (label) {
    case "account_number":
      return "account_number";
    case "private_address":
      return "address";
    case "private_email":
      return "email";
    case "private_person":
      return "person";
    case "private_phone":
      return "phone";
    case "private_url":
      return "url";
    case "private_date":
      return "date";
    case "secret":
      return "secret_assignment";
    case "redacted":
      return "secret_assignment";
    default:
      return null;
  }
}
