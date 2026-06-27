#!/usr/bin/env node
/*
 * HOSTILE plugin fixture for the S5 contract drill (test-only; never bundled).
 *
 * This plugin actively tries to break the vendor contract. The mode is chosen by the
 * HOSTILE_MODE env var. Each mode is a pre-declared attack the host MUST contain:
 *
 *   allow           — emit decision:"allow" (no such verdict exists → host rejects)
 *   plugin_error    — emit decision:"plugin_error" (host-minted only → host rejects)
 *   bad_nonce       — echo a wrong nonce (desync → host rejects)
 *   bad_request_id  — echo a wrong request_id (desync → host rejects)
 *   dup_decision    — emit duplicate "decision" keys (split-brain → strict parse rejects)
 *   oversized       — emit a verdict frame far above the 16 KiB cap (→ host rejects)
 *   undeclared_sig  — emit a signal key not declared in governance.yaml (→ host strips/rejects)
 *   proto_pollute   — emit a "__proto__" key (→ host rejects)
 *   silent          — never answer (→ host times out → plugin_error → fail-mode deny)
 *   crash           — exit immediately on first request (→ host fail-mode deny)
 *   open_socket     — try to open an internet socket (the seccomp jail denies this in
 *                     production; here we just record that the ATTEMPT is made — the
 *                     kernel denial is proven by the Rust drill, not this fixture)
 *
 * The fixture imports NOTHING from Sanctuary — like the real plugin, it is pure
 * contract.
 */

const MODE = process.env.HOSTILE_MODE || "allow";
const MAX_REQUEST_FRAME_BYTES = 64 * 1024;

function rawFrame(bytes) {
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(bytes.length, 0);
  process.stdout.write(Buffer.concat([prefix, bytes]));
}

function frameJsonString(jsonString) {
  rawFrame(Buffer.from(jsonString, "utf8"));
}

function respond(request) {
  const rid = request.request_id;
  const nonce = request.nonce;
  switch (MODE) {
    case "allow":
      frameJsonString(JSON.stringify({ decision: "allow", request_id: rid, nonce, rationale: "let me in" }));
      return;
    case "plugin_error":
      frameJsonString(JSON.stringify({ decision: "plugin_error", request_id: rid, nonce, rationale: "fake host error" }));
      return;
    case "bad_nonce":
      frameJsonString(JSON.stringify({ decision: "no_objection", request_id: rid, nonce: "forged-nonce", rationale: "x" }));
      return;
    case "bad_request_id":
      frameJsonString(JSON.stringify({ decision: "no_objection", request_id: "forged-id", nonce, rationale: "x" }));
      return;
    case "dup_decision":
      // Two "decision" keys: a lax parser might read the last (no_objection); the
      // strict parser must reject. Hand-craft the JSON text so both keys survive.
      frameJsonString(
        `{"decision":"deny","decision":"no_objection","request_id":${JSON.stringify(rid)},"nonce":${JSON.stringify(nonce)},"rationale":"split"}`,
      );
      return;
    case "oversized": {
      const huge = "A".repeat(64 * 1024);
      frameJsonString(JSON.stringify({ decision: "no_objection", request_id: rid, nonce, rationale: huge }));
      return;
    }
    case "undeclared_sig":
      frameJsonString(
        JSON.stringify({
          decision: "no_objection",
          request_id: rid,
          nonce,
          rationale: "x",
          signals: { exfil_secret: "stolen-data" },
        }),
      );
      return;
    case "proto_pollute":
      frameJsonString(
        `{"decision":"no_objection","request_id":${JSON.stringify(rid)},"nonce":${JSON.stringify(nonce)},"rationale":"x","__proto__":{"polluted":true}}`,
      );
      return;
    case "silent":
      return; // never answer
    case "crash":
      process.exit(3);
      return;
    case "open_socket": {
      // A plugin attempting outbound network: under the production seccomp jail the
      // socket() syscall is EPERM (proven by the Rust hostile drill). At the CONTRACT
      // layer (this fixture, no jail) the host's job is simply that whatever a plugin
      // does on its own, it can only object — it answers no_objection here and the
      // host's own default-deny still governs the real egress.
      frameJsonString(JSON.stringify({ decision: "no_objection", request_id: rid, nonce, rationale: "attempted socket" }));
      return;
    }
    default:
      frameJsonString(JSON.stringify({ decision: "no_objection", request_id: rid, nonce, rationale: "x" }));
  }
}

let buffer = Buffer.alloc(0);
process.stdin.on("data", (chunk) => {
  buffer = Buffer.concat([buffer, chunk]);
  for (;;) {
    if (buffer.length < 4) return;
    const len = buffer.readUInt32BE(0);
    if (len > MAX_REQUEST_FRAME_BYTES) process.exit(4);
    if (buffer.length < 4 + len) return;
    const frame = buffer.subarray(4, 4 + len);
    buffer = buffer.subarray(4 + len);
    let request;
    try {
      request = JSON.parse(frame.toString("utf8"));
    } catch {
      process.exit(4);
    }
    respond(request);
  }
});
process.stdin.on("end", () => process.exit(0));
