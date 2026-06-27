#!/usr/bin/env node
/*
 * Sanctuary reference plugin — domain blocklist egress vetoer.
 *
 * This is a FIRST-PARTY REFERENCE implementation of the Sanctuary plugin vendor
 * contract (Plugin_Host_Architecture_Design_2026-06-12.md §3). It is deliberately
 * written against the PUBLIC contract ONLY:
 *
 *   - It imports NOTHING from Sanctuary. The only modules it uses are the Node
 *     standard library (`fs`, `path`). An outside vendor (Pi-hole, NextDNS,
 *     Crowdstrike) could write a byte-identical plugin without ever seeing
 *     server/src. This is the dogfood proof: the contract is implementable from
 *     the outside, with no SDK and no API key.
 *   - It performs domain-name parsing + local rule evaluation only. It opens no
 *     socket, reads no host file outside its own bundle, makes no network call.
 *     Its entire job is: given (host, port), decide deny | no_objection.
 *
 * Wire protocol (host-enforced; this side simply honors it):
 *   stdin : u32 big-endian length prefix, then exactly that many UTF-8 JSON bytes —
 *           one EgressDecisionRequest. Lockstep: one request, one verdict, repeat.
 *   stdout: u32 big-endian length prefix, then the verdict JSON. The verdict echoes
 *           BOTH request_id and nonce of the request it answers (the host rejects a
 *           mismatch). A plugin may emit only deny | escalate | observe |
 *           no_objection — never "allow" (no such verdict exists) and never
 *           "plugin_error" (that is host-minted on crash/timeout/malformed).
 *
 * Blocklist source: rules/blocklist.txt in the bundle, one domain per line, '#'
 * comments and blank lines ignored. A request host is DENIED if it equals a listed
 * domain or is a subdomain of one (suffix match on a label boundary). Everything
 * else is no_objection — the plugin never authorizes, it only objects, exactly as
 * the contract requires.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const MAX_REQUEST_FRAME_BYTES = 64 * 1024;
const MAX_VERDICT_FRAME_BYTES = 16 * 1024;

/* ---- blocklist loading + domain matching (the entire detection logic) ---- */

/**
 * Load the blocklist from the bundle. The bundle dir is the plugin's own directory
 * tree; the rules file ships alongside the binary and is covered by the signed
 * BundleDescriptor, so the host has already integrity-checked it before exec.
 */
function loadBlocklist() {
  // The entry binary lives at <bundle>/bin/blocklist.mjs; rules at
  // <bundle>/rules/blocklist.txt.
  const rulesPath = path.join(__dirname, "..", "rules", "blocklist.txt");
  let text;
  try {
    text = fs.readFileSync(rulesPath, "utf8");
  } catch {
    // No readable rules file ⇒ an empty blocklist. The plugin then objects to
    // nothing; the host's own default-deny still governs egress, so a missing
    // ruleset can only make this plugin object LESS, never loosen the wall.
    // Fail-closed lives in the host, not here.
    return new Set();
  }
  const set = new Set();
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith("#")) continue;
    const normalized = normalizeDomain(line);
    if (normalized) set.add(normalized);
  }
  return set;
}

/**
 * Normalize a domain for comparison: lowercase, strip a single trailing dot, reject
 * anything that is not a plausible bare hostname (no scheme, no path, no port, no
 * userinfo, no whitespace). Returns the normalized domain, or null.
 */
function normalizeDomain(input) {
  if (typeof input !== "string") return null;
  let host = input.trim().toLowerCase();
  if (host.length === 0 || host.length > 253) return null;
  // strip a single trailing dot (FQDN form)
  if (host.endsWith(".")) host = host.slice(0, -1);
  // reject embedded scheme/path/port/userinfo/whitespace — bare hostnames only
  if (/[/\\:@\s]/.test(host)) return null;
  // each label: 1..63 chars, alnum or hyphen, not starting/ending with a hyphen
  const labels = host.split(".");
  for (const label of labels) {
    if (label.length === 0 || label.length > 63) return null;
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(label)) return null;
  }
  return host;
}

/**
 * Decide whether `host` is blocked by `blocklist`. A host is blocked if it equals a
 * listed domain, or is a subdomain of one (label-boundary suffix). Returns the
 * matched rule on a hit, or null.
 */
function matchBlocked(host, blocklist) {
  const normalized = normalizeDomain(host);
  if (!normalized) return null;
  if (blocklist.has(normalized)) return normalized;
  // walk parent domains: a.b.evil.com → b.evil.com → evil.com
  const labels = normalized.split(".");
  for (let i = 1; i < labels.length; i++) {
    const parent = labels.slice(i).join(".");
    if (blocklist.has(parent)) return parent;
  }
  return null;
}

/* ---- verdict construction (contract-shaped; extras are attribution-only) ---- */

function buildVerdict(request, blocklist) {
  const requestId = typeof request.request_id === "string" ? request.request_id : "";
  const nonce = typeof request.nonce === "string" ? request.nonce : "";
  const host = typeof request.host === "string" ? request.host : "";

  const matched = matchBlocked(host, blocklist);
  if (matched) {
    return {
      decision: "deny",
      request_id: requestId,
      nonce,
      rationale: `host "${host}" matches blocklist entry "${matched}"`,
      confidence: 1,
      signals: { blocked_rule: matched },
    };
  }
  return {
    decision: "no_objection",
    request_id: requestId,
    nonce,
    rationale: `host "${host}" is not on the blocklist`,
    confidence: 1,
  };
}

/* ---- framed stdin/stdout loop ---- */

function writeFrame(stream, obj) {
  const json = Buffer.from(JSON.stringify(obj), "utf8");
  if (json.length > MAX_VERDICT_FRAME_BYTES) {
    // A verdict that would exceed the host cap is a bug in this plugin; emit a
    // minimal verdict (decision + correlation only) rather than a frame the host
    // will reject. The decision is preserved; the over-long rationale/signals are
    // dropped.
    const minimal = {
      decision: obj.decision,
      request_id: obj.request_id,
      nonce: obj.nonce,
      rationale: "rationale omitted (oversized)",
    };
    const minimalJson = Buffer.from(JSON.stringify(minimal), "utf8");
    const prefix = Buffer.alloc(4);
    prefix.writeUInt32BE(minimalJson.length, 0);
    stream.write(Buffer.concat([prefix, minimalJson]));
    return;
  }
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(json.length, 0);
  stream.write(Buffer.concat([prefix, json]));
}

function main() {
  const blocklist = loadBlocklist();
  let buffer = Buffer.alloc(0);

  const drain = () => {
    // Process as many complete frames as the buffer holds (the host is lockstep,
    // but we tolerate buffered bytes arriving in one chunk).
    for (;;) {
      if (buffer.length < 4) return;
      const length = buffer.readUInt32BE(0);
      if (length > MAX_REQUEST_FRAME_BYTES) {
        // Oversized request frame: the stream framing can no longer be trusted.
        // Exit non-zero; the host mints plugin_error and applies the egress
        // fail-mode (deny). We never guess past a corrupt length prefix.
        process.exit(2);
      }
      if (buffer.length < 4 + length) return;
      const frame = buffer.subarray(4, 4 + length);
      buffer = buffer.subarray(4 + length);
      let request;
      try {
        request = JSON.parse(frame.toString("utf8"));
      } catch {
        process.exit(2);
      }
      if (request === null || typeof request !== "object" || Array.isArray(request)) {
        process.exit(2);
      }
      writeFrame(process.stdout, buildVerdict(request, blocklist));
    }
  };

  process.stdin.on("data", (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    drain();
  });
  process.stdin.on("end", () => process.exit(0));
  process.stdin.on("error", () => process.exit(2));
}

main();
