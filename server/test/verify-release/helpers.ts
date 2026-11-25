/**
 * Shared fixtures and isolation for the verify-release tests.
 *
 * `denyAllNetwork()` replaces every outbound socket entry point with one that
 * records the attempt and throws, and asserts after the file that nothing tried.
 * The verifier's own transport is always an injected requester in these tests,
 * so a recorded attempt means some path reached the real network.
 */

// Default imports are the CommonJS module objects, which are writable; the namespace objects are not.
import dgram from "node:dgram";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { readFileSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { join } from "node:path";
import { afterAll, beforeAll, expect } from "vitest";
import type { Clock } from "../../src/verify-release/deadline.js";
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { Readable } from "node:stream";
import { ed25519 } from "@noble/curves/ed25519";
import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url } from "../../src/core/encoding.js";
import { buildReleaseManifestMessage, verifyReleaseManifestWithKey, type ReleaseManifestBody } from "../../src/release-manifest.js";
import type { HttpRequester, RawResponse } from "../../src/verify-release/transport.js";

export const FIXTURES = join(__dirname, "..", "fixtures", "verify-release");
export const TRUSTED_ROOT_PATH = join(__dirname, "..", "..", "src", "verify-release", "trusted_root.json");

export function fixtureBytes(name: string): Buffer {
  return readFileSync(join(FIXTURES, name));
}
export function fixtureJson<T = unknown>(name: string): T {
  return JSON.parse(fixtureBytes(name).toString("utf8")) as T;
}

/** The 1.8.4 attestations document, freshly parsed (tests mutate their own copy). */
export function attestations184(): { attestations: Array<{ predicateType: string; bundle: Record<string, any> }> } {
  return fixtureJson("attestations-1.8.4.json");
}
export function slsaBundle184(): Record<string, any> {
  return attestations184().attestations.find(item => item.predicateType === "https://slsa.dev/provenance/v1")!.bundle;
}
export function foreignSlsaBundle(): Record<string, any> {
  return fixtureJson<{ attestations: Array<{ predicateType: string; bundle: Record<string, any> }> }>("attestations-sigstore-verify-4.1.4.json")
    .attestations.find(item => item.predicateType === "https://slsa.dev/provenance/v1")!.bundle;
}
export function trustedRootBytes(): Buffer {
  return readFileSync(TRUSTED_ROOT_PATH);
}

type Patched = { target: Record<string, unknown>; key: string; original: unknown };

export function denyAllNetwork(): { attempts: string[] } {
  const record = { attempts: [] as string[] };
  const patched: Patched[] = [];
  const deny = (target: Record<string, unknown>, key: string, label: string): void => {
    patched.push({ target, key, original: target[key] });
    target[key] = (...args: unknown[]) => {
      record.attempts.push(`${label}:${String(args[0] && typeof args[0] === "object" ? (args[0] as { href?: string; host?: string }).href ?? (args[0] as { host?: string }).host : args[0])}`);
      throw new Error(`network denied in verify-release tests: ${label}`);
    };
  };
  beforeAll(() => {
    deny(http as unknown as Record<string, unknown>, "request", "http.request");
    deny(http as unknown as Record<string, unknown>, "get", "http.get");
    deny(https as unknown as Record<string, unknown>, "request", "https.request");
    deny(https as unknown as Record<string, unknown>, "get", "https.get");
    deny(net as unknown as Record<string, unknown>, "connect", "net.connect");
    deny(net as unknown as Record<string, unknown>, "createConnection", "net.createConnection");
    deny(tls as unknown as Record<string, unknown>, "connect", "tls.connect");
    deny(dgram as unknown as Record<string, unknown>, "createSocket", "dgram.createSocket");
    deny(globalThis as unknown as Record<string, unknown>, "fetch", "fetch");
    syncBuiltinESMExports();
  });
  afterAll(() => {
    for (const { target, key, original } of patched.reverse()) target[key] = original;
    syncBuiltinESMExports();
    expect(record.attempts).toEqual([]);
  });
  return record;
}

/** A manual monotonic clock: time moves only when a test moves it; timers fire when it passes them. */
export class ManualClock implements Clock {
  #now = 0;
  #timers = new Map<number, { at: number; fire: () => void }>();
  #next = 1;
  now(): number {
    return this.#now;
  }
  setTimeout(fire: () => void, ms: number): unknown {
    const id = this.#next++;
    this.#timers.set(id, { at: this.#now + ms, fire });
    return id;
  }
  clearTimeout(handle: unknown): void {
    this.#timers.delete(handle as number);
  }
  advance(ms: number): void {
    this.#now += ms;
    for (const [id, timer] of [...this.#timers].sort((a, b) => a[1].at - b[1].at)) {
      if (timer.at <= this.#now) {
        this.#timers.delete(id);
        timer.fire();
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Minimal DER encoding, for generated test certificates.
// ---------------------------------------------------------------------------

export function derLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  for (let rest = length; rest > 0; rest >>= 8) bytes.unshift(rest & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
export function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}
export function derOid(oid: string): Buffer {
  const parts = oid.split(".").map(Number);
  const bytes: number[] = [parts[0]! * 40 + parts[1]!];
  for (const part of parts.slice(2)) {
    const chunk: number[] = [part & 0x7f];
    for (let rest = part >> 7; rest > 0; rest >>= 7) chunk.unshift(0x80 | (rest & 0x7f));
    bytes.push(...chunk);
  }
  return tlv(0x06, Buffer.from(bytes));
}
export const derUtf8 = (value: string): Buffer => tlv(0x0c, Buffer.from(value, "utf8"));
export const derSequence = (...items: Buffer[]): Buffer => tlv(0x30, Buffer.concat(items));
export const derOctets = (content: Buffer): Buffer => tlv(0x04, content);
/** One X.509 extension: OID, optional critical flag, extnValue contents. */
export function derExtension(oid: string, value: Buffer, critical = false): Buffer {
  return derSequence(derOid(oid), ...(critical ? [tlv(0x01, Buffer.from([0xff]))] : []), derOctets(value));
}
/** SubjectAltName with one URI GeneralName ([6] IA5String). */
export function derSanUri(uri: string): Buffer {
  return derSequence(tlv(0x86, Buffer.from(uri, "ascii")));
}

/**
 * A certificate DER whose fields are taken from a real certificate's TBS but
 * whose extension list is replaced. The signature is not valid; these
 * certificates go to the identity adapter directly, never through the verifier.
 */
export function certificateWithExtensions(realDer: Buffer, extensions: Buffer[]): Buffer {
  const items = topLevelItems(realDer);
  const tbsItems = topLevelItems(items[0]!);
  // TBS: [0] version, serial, sigAlg, issuer, validity, subject, spki, [3] extensions.
  const kept = tbsItems.filter(item => item[0] !== 0xa3);
  const extensionsField = tlv(0xa3, derSequence(...extensions));
  const tbs = derSequence(...kept, extensionsField);
  return derSequence(tbs, items[1]!, items[2]!);
}

/** The TLV items inside one constructed TLV. */
export function topLevelItems(der: Buffer): Buffer[] {
  const { headerLength, length } = readHeader(der, 0);
  const content = der.subarray(headerLength, headerLength + length);
  const items: Buffer[] = [];
  for (let offset = 0; offset < content.length;) {
    const header = readHeader(content, offset);
    items.push(content.subarray(offset, offset + header.headerLength + header.length));
    offset += header.headerLength + header.length;
  }
  return items;
}
function readHeader(der: Buffer, offset: number): { headerLength: number; length: number } {
  const first = der[offset + 1]!;
  if ((first & 0x80) === 0) return { headerLength: 2, length: first };
  const octets = first & 0x7f;
  let length = 0;
  for (let i = 0; i < octets; i++) length = length * 256 + der[offset + 2 + i]!;
  return { headerLength: 2 + octets, length };
}

// ---------------------------------------------------------------------------
// Synthetic tarballs, release manifests and a modelled requester.
// ---------------------------------------------------------------------------


export interface TarEntrySpec {
  path: string;
  /** Default "0" (regular file). "5" directory, "2" symlink, "1" hardlink, "3" char device, "6" FIFO. */
  type?: string;
  body?: Buffer | string;
  /** Declared size, when it must differ from the body (truncation tests). */
  size?: number;
  linkpath?: string;
}

const BLOCK = 512;
function octal(value: number, width: number): string {
  return `${value.toString(8).padStart(width - 1, "0")}\0`;
}
function header(name: string, type: string, size: number, linkpath = ""): Buffer {
  const block = Buffer.alloc(BLOCK, 0);
  block.write(name, 0, 100, "utf8");
  block.write(octal(type === "5" ? 0o755 : 0o644, 8), 100, "ascii");
  block.write(octal(0, 8), 108, "ascii");
  block.write(octal(0, 8), 116, "ascii");
  block.write(octal(size, 12), 124, "ascii");
  block.write(octal(0, 12), 136, "ascii");
  block.write("        ", 148, "ascii");
  block.write(type, 156, "ascii");
  block.write(linkpath, 157, 100, "utf8");
  block.write("ustar\u000000", 257, "binary");
  let sum = 0;
  for (const byte of block) sum += byte;
  block.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "ascii");
  return block;
}
function padded(body: Buffer): Buffer {
  const rest = body.length % BLOCK;
  return rest === 0 ? body : Buffer.concat([body, Buffer.alloc(BLOCK - rest, 0)]);
}
function paxRecord(key: string, value: string): string {
  const content = ` ${key}=${value}\n`;
  let length = content.length;
  while (`${length}${content}`.length !== length) length = `${length}${content}`.length;
  return `${length}${content}`;
}

/** An uncompressed tar stream; names over 100 bytes get a pax `path` record. */
export function tarBytes(entries: TarEntrySpec[], { endBlocks = true } = {}): Buffer {
  const parts: Buffer[] = [];
  for (const entry of entries) {
    const type = entry.type ?? "0";
    const body = Buffer.from(entry.body ?? "");
    let name = entry.path;
    if (Buffer.byteLength(name) > 100) {
      const pax = Buffer.from(paxRecord("path", name), "utf8");
      parts.push(header("PaxHeader", "x", pax.length), padded(pax));
      name = name.slice(0, 99);
    }
    parts.push(header(name, type, entry.size ?? (type === "0" ? body.length : 0), entry.linkpath ?? ""));
    if (type === "0") parts.push(padded(body));
  }
  if (endBlocks) parts.push(Buffer.alloc(BLOCK * 2, 0));
  return Buffer.concat(parts);
}
export function tgz(entries: TarEntrySpec[]): Buffer {
  return gzipSync(tarBytes(entries));
}

export const sha256Hex = (bytes: Buffer): string => createHash("sha256").update(bytes).digest("hex");
export const sha512 = (bytes: Buffer): Buffer => createHash("sha512").update(bytes).digest();

export const TEST_MANIFEST_KEY = generateKeypair();
export function signManifest(body: ReleaseManifestBody, privateKey: Uint8Array = TEST_MANIFEST_KEY.privateKey): { body: ReleaseManifestBody; signature: string } {
  return { body, signature: toBase64url(ed25519.sign(buildReleaseManifestMessage(body), privateKey)) };
}
/** `verifyReleaseManifestWithKey` bound to the test key: the manifest seam. */
export const verifyWithTestKey = (value: unknown) => verifyReleaseManifestWithKey(value, TEST_MANIFEST_KEY.publicKey);

export function body(bytes: Buffer | string): RawResponse["body"] {
  return Readable.from([Buffer.from(bytes)]);
}
export function response(status: number, payload: Buffer | string = "", headers: Record<string, string> = {}): RawResponse {
  return { status, headers, body: body(payload) };
}

/** A requester serving fixed responses by URL; every call is recorded. */
export function modelledRequester(routes: Record<string, () => RawResponse | Promise<RawResponse>>): HttpRequester & { calls: string[] } {
  const calls: string[] = [];
  const requester: HttpRequester = async url => {
    calls.push(url.href);
    const route = routes[url.href];
    if (route === undefined) return response(404);
    return route();
  };
  return Object.assign(requester, { calls });
}
