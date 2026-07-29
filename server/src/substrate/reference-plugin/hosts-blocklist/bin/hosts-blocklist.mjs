#!/usr/bin/env node
/*
 * Sanctuary reference plugin (second bundled, first-party) - Pi-hole / hosts-format
 * egress vetoer.
 *
 * This is the SECOND first-party REFERENCE implementation of the Sanctuary plugin
 * vendor contract (Plugin_Host_Architecture_Design_2026-06-12.md §3). It exists to
 * prove the plugin host handles n>1 bundled plugins under supervisor isolation: two
 * independently signed first-party bundles enumerate, integrity-verify, and run side
 * by side, and one plugin's fault cannot corrupt or take down the other.
 *
 * It is a BUNDLED FIRST-PARTY plugin (a second reference plugin), NOT a third-party
 * plugin from a marketplace. Third-party install stays F1-gated; nothing here implies
 * marketplace or third-party support.
 *
 * Like the first reference plugin it is written against the PUBLIC contract ONLY:
 *   - It imports NOTHING from Sanctuary. Only the Node standard library (`fs`,
 *     `path`). An outside vendor shipping a Pi-hole export could write a
 *     byte-identical plugin without ever seeing server/src.
 *   - It performs domain-name parsing + local rule evaluation only. It opens no
 *     socket, reads no host file outside its own bundle, makes no network call. Its
 *     entire job is: given (host, port), decide deny | no_objection.
 *
 * The one deliberate DIFFERENCE from the first reference plugin is the on-disk rule
 * FORMAT. The first plugin ships a bare-domain-per-line list; this plugin ships a
 * Pi-hole / hosts-file list - the exact `0.0.0.0 domain.example` shape a Pi-hole
 * gravity export or a `/etc/hosts`-style adblock list emits. Proving the host runs
 * BOTH proves the contract is format-agnostic: a vendor brings whatever list format
 * they already maintain, so long as their plugin binary honors the wire contract.
 *
 * hosts / Pi-hole line grammar (this plugin's parser, see parseHostsBlocklist):
 *   - '#' starts a comment (whole-line or trailing); blank lines ignored.
 *   - A rule line is "<ip> <domain>" where <ip> is a sink address
 *     (0.0.0.0, 127.0.0.1, ::, ::1). Extra whitespace and a trailing comment are
 *     tolerated. Lines whose IP is NOT a recognized sink are IGNORED (a real hosts
 *     file can carry non-block entries; a blocklist only ever ADDS objections, so an
 *     unrecognized line can only make this plugin object LESS, never loosen the wall).
 *   - A bare-domain line (no IP) is ALSO accepted, so a plain domain list still works.
 *
 * Wire protocol (host-enforced; this side simply honors it) is identical to the first
 * reference plugin: u32 big-endian length prefix + UTF-8 JSON, lockstep one-in
 * one-out, echoing request_id + nonce, emitting only deny | no_objection here.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const MAX_REQUEST_FRAME_BYTES = 64 * 1024;
const MAX_VERDICT_FRAME_BYTES = 16 * 1024;

/** Sink IPs a Pi-hole / hosts-format blocklist uses to null-route a blocked domain. */
const SINK_IPS = new Set(["0.0.0.0", "127.0.0.1", "::", "::1"]);

/* ---- blocklist loading + domain matching (the entire detection logic) ---- */

/**
 * Load the hosts-format blocklist from the bundle. The rules file ships alongside the
 * binary and is covered by the signed BundleDescriptor, so the host has already
 * integrity-checked it before exec.
 */
function loadBlocklist() {
  const rulesPath = path.join(__dirname, "..", "rules", "hosts-blocklist.hosts");
  let text;
  try {
    text = fs.readFileSync(rulesPath, "utf8");
  } catch {
    // No readable rules file => an empty blocklist. The plugin then objects to
    // nothing; the host's own default-deny still governs egress, so a missing
    // ruleset can only make this plugin object LESS, never loosen the wall.
    return new Set();
  }
  return parseHostsBlocklist(text);
}

/**
 * Parse Pi-hole / hosts-file text into a Set of normalized blocked domains. Exported
 * for the fixture parse test. Pure: no I/O, no host state.
 */
export function parseHostsBlocklist(text) {
  const set = new Set();
  if (typeof text !== "string") return set;
  for (const rawLine of text.split("\n")) {
    // strip a trailing comment, then trim
    const hashIdx = rawLine.indexOf("#");
    const line = (hashIdx >= 0 ? rawLine.slice(0, hashIdx) : rawLine).trim();
    if (line.length === 0) continue;
    // split on any run of whitespace
    const fields = line.split(/\s+/);
    let domainField;
    if (fields.length === 1) {
      // bare-domain line (no IP): accept the domain directly
      domainField = fields[0];
    } else {
      // "<ip> <domain> [more]" - only a recognized sink IP counts as a block rule
      if (!SINK_IPS.has(fields[0])) continue;
      domainField = fields[1];
    }
    const normalized = normalizeDomain(domainField);
    if (normalized) set.add(normalized);
  }
  return set;
}

/**
 * Normalize a domain for comparison: lowercase, strip a single trailing dot, reject
 * anything that is not a plausible bare hostname. Returns the normalized domain, or
 * null. Identical rules to the first reference plugin so the two agree on what a
 * hostname is.
 */
function normalizeDomain(input) {
  if (typeof input !== "string") return null;
  let host = input.trim().toLowerCase();
  if (host.length === 0 || host.length > 253) return null;
  if (host.endsWith(".")) host = host.slice(0, -1);
  // reject embedded scheme/path/port/userinfo/whitespace - bare hostnames only
  if (/[/\\:@\s]/.test(host)) return null;
  const labels = host.split(".");
  // a single-label token like "localhost" is a valid hostname but never a useful
  // blocklist entry; require at least two labels so "0.0.0.0 localhost" self-routes
  // don't turn into a wildcard.
  if (labels.length < 2) return null;
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
      rationale: `host "${host}" matches hosts-blocklist entry "${matched}"`,
      confidence: 1,
      signals: { blocked_rule: matched },
    };
  }
  return {
    decision: "no_objection",
    request_id: requestId,
    nonce,
    rationale: `host "${host}" is not on the hosts-blocklist`,
    confidence: 1,
  };
}

/* ---- framed stdin/stdout loop ---- */

function writeFrame(stream, obj) {
  const json = Buffer.from(JSON.stringify(obj), "utf8");
  if (json.length > MAX_VERDICT_FRAME_BYTES) {
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
    for (;;) {
      if (buffer.length < 4) return;
      const length = buffer.readUInt32BE(0);
      if (length > MAX_REQUEST_FRAME_BYTES) {
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

// Only run the wire loop when executed as the entry binary; importing the module
// (parse test) must NOT start reading stdin.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
