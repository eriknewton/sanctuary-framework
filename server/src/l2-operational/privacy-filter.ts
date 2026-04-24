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
import { hashToString } from "../core/hashing.js";

export type PrivacySpanClass =
  | "email"
  | "phone"
  | "ssn"
  | "credit_card"
  | "secret_assignment";

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
}

const SPAN_PATTERNS: SpanPattern[] = [
  {
    class: "email",
    pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    replacement: "[EMAIL_REDACTED]",
    placeholderPrefix: "EMAIL",
  },
  {
    class: "ssn",
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
    replacement: "[SSN_REDACTED]",
    placeholderPrefix: "SSN",
  },
  {
    class: "credit_card",
    pattern: /\b(?:\d[ -]*?){13,19}\b/g,
    replacement: "[CARD_REDACTED]",
    placeholderPrefix: "CARD",
  },
  {
    class: "phone",
    pattern: /\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b/g,
    replacement: "[PHONE_REDACTED]",
    placeholderPrefix: "PHONE",
  },
  {
    class: "secret_assignment",
    pattern: /\b(api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret)\s*[:=]\s*["']?[^"',\s}]+/gi,
    replacement: "$1=[SECRET_REDACTED]",
    placeholderPrefix: "SECRET",
  },
];

const MAX_DEPTH = 20;
const VAULT_NAMESPACE = "_privacy_placeholder_vault";

interface PlaceholderRecord {
  version: 1;
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

export class PrivacyPlaceholderVault {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;
  private cache = new Map<string, PlaceholderRecord>();

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "l2-privacy-placeholders");
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
    await this.writeIndex(scope, index);

    const placeholder = `${placeholderPrefixFor(spanClass)}_${next}`;
    const record: PlaceholderRecord = {
      version: 1,
      scope,
      class: spanClass,
      placeholder,
      raw_value: rawValue,
      raw_hash: hashToString(stringToBytes(rawValue)),
      created_at: new Date().toISOString(),
    };
    await this.writeRecord(key, record);
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

  private recordKey(
    spanClass: PrivacySpanClass,
    rawValue: string,
    scope: string
  ): string {
    const rawHash = hashToString(stringToBytes(`${scope}:${spanClass}:${rawValue}`));
    return `${scope}__record__${spanClass}__${rawHash}`;
  }

  private indexKey(scope: string): string {
    return `${scope}__index`;
  }

  private async readIndex(scope: string): Promise<PlaceholderIndex> {
    const raw = await this.storage.read(VAULT_NAMESPACE, this.indexKey(scope));
    if (!raw) return { version: 1, counters: {} };
    try {
      const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.encryptionKey);
      return JSON.parse(bytesToString(decrypted)) as PlaceholderIndex;
    } catch {
      return { version: 1, counters: {} };
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
      return JSON.parse(bytesToString(decrypted)) as PlaceholderRecord;
    } catch {
      return null;
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
  let output = input;

  for (const span of SPAN_PATTERNS) {
    const matches = Array.from(output.matchAll(span.pattern));
    for (const match of matches) {
      const raw = match[0];
      const placeholder = await vault.placeholderFor(span.class, raw, scope);
      output = output.replace(raw, placeholder);
      findings.push({
        path,
        class: span.class,
        action: "placeholder",
        placeholder,
      });
    }
  }

  return output;
}

function placeholderPrefixFor(spanClass: PrivacySpanClass): string {
  return SPAN_PATTERNS.find((p) => p.class === spanClass)?.placeholderPrefix ?? "PRIVATE";
}
