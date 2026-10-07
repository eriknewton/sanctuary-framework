/**
 * Tests for the two one-shot surrogate codecs.
 *
 * WHAT THESE PIN. The query socket (gate to helper) and the unlock socket
 * (operator to helper) are different principals, and each socket is bound to
 * exactly one codec. A query frame arriving on the unlock socket, and an unlock
 * frame arriving on the query socket, must both be malformed: that separation is
 * what stops the gate uid from loading a value and stops the operator uid from
 * asking for one back. Both codecs also check the frame cap BEFORE parsing, so an
 * oversized stream never reaches `JSON.parse` in a root process.
 *
 * Element-level parity (AGENTS.md rule 11): both codecs validate hosts, ports,
 * secret names and value bytes through the shared validators in `binding.ts`, the
 * same functions the policy parser and the helper's table loader call, so a value
 * one stage accepts is not one another stage would have refused.
 */

import { describe, expect, it } from "vitest";

import {
  MAX_SURROGATE_UNLOCK_SECONDS,
  MAX_SURROGATE_VALUE_BYTES,
  SURROGATE_WIRE_MAX_FRAME_BYTES,
} from "../../src/credential-surrogate/constants.js";
import { mintSurrogatePlaceholder } from "../../src/credential-surrogate/placeholder.js";
import {
  SURROGATE_TARGET_LOCATION,
  encodeSurrogateQueryRequest,
  encodeSurrogateQueryResponse,
  isSurrogateQueryLocation,
  parseSurrogateQueryRequest,
  parseSurrogateQueryResponse,
  surrogateHeaderLocation,
  type SurrogateQueryRequest,
} from "../../src/credential-surrogate/query-codec.js";
import {
  encodeSurrogateUnlockSocketRequest,
  parseSurrogateUnlockSocketRequest,
  parseSurrogateUnlockSocketResponse,
  type SurrogateUnlockRequest,
} from "../../src/credential-surrogate/unlock-codec.js";
import {
  SURROGATE_WIRE_VERSION,
  newSurrogateCorrelationId,
} from "../../src/credential-surrogate/wire.js";

function byte(code: number): string {
  return String.fromCharCode(code);
}

const ID = "0123456789abcdef0123456789abcdef";

function queryRequest(over: Partial<SurrogateQueryRequest> = {}): SurrogateQueryRequest {
  return {
    v: SURROGATE_WIRE_VERSION,
    id: ID,
    kind: "resolve",
    placeholder: mintSurrogatePlaceholder(),
    host: "api.openai.com",
    port: 443,
    location: surrogateHeaderLocation("Authorization"),
    ...over,
  };
}

function unlockRequest(over: Partial<SurrogateUnlockRequest> = {}): SurrogateUnlockRequest {
  return {
    v: SURROGATE_WIRE_VERSION,
    id: ID,
    kind: "unlock",
    generation_id: 7,
    ttl_seconds: 3600,
    secret: "openai-api-key",
    value: "Bearer test-value-generated-in-this-test",
    ...over,
  };
}

/** One frame as the socket layer hands it to the parser: the JSON line without its newline. */
function line(buf: Buffer): string {
  return buf.toString("utf8").replace(/\n$/, "");
}

describe("correlation ids", () => {
  it("are 32 lowercase hex characters and fresh per call", () => {
    const a = newSurrogateCorrelationId();
    const b = newSurrogateCorrelationId();
    expect(a).toMatch(/^[0-9a-f]{32}$/);
    expect(b).not.toBe(a);
  });

  it("are required on every frame, both directions, both codecs", () => {
    expect(parseSurrogateQueryRequest(line(encodeSurrogateQueryRequest(queryRequest({ id: "nope" }))))).toBeNull();
    expect(parseSurrogateQueryResponse(JSON.stringify({ v: 1, id: "nope", kind: "deny", reason: "locked" }))).toBeNull();
    expect(parseSurrogateUnlockSocketRequest(JSON.stringify({ v: 1, id: "nope", kind: "lock" }))).toBeNull();
    expect(parseSurrogateUnlockSocketResponse(JSON.stringify({ v: 1, id: "nope", kind: "ok" }))).toBeNull();
  });
});

describe("query codec: request", () => {
  it("round-trips a well-formed resolve", () => {
    const req = queryRequest();
    expect(parseSurrogateQueryRequest(line(encodeSurrogateQueryRequest(req)))).toEqual(req);
  });

  it("accepts a target location as well as a header location", () => {
    const req = queryRequest({ location: SURROGATE_TARGET_LOCATION });
    expect(parseSurrogateQueryRequest(line(encodeSurrogateQueryRequest(req)))).toEqual(req);
  });

  it("refuses an unknown key, so a future field cannot be smuggled past this parser", () => {
    const raw = JSON.stringify({ ...queryRequest(), extra: 1 });
    expect(parseSurrogateQueryRequest(raw)).toBeNull();
  });

  it("refuses a missing key", () => {
    const { host: _host, ...withoutHost } = queryRequest();
    expect(parseSurrogateQueryRequest(JSON.stringify(withoutHost))).toBeNull();
  });

  it("refuses a wrong version and a wrong kind", () => {
    expect(parseSurrogateQueryRequest(JSON.stringify({ ...queryRequest(), v: 2 }))).toBeNull();
    expect(parseSurrogateQueryRequest(JSON.stringify({ ...queryRequest(), kind: "unlock" }))).toBeNull();
  });

  it("refuses a placeholder that is not one, element by element", () => {
    expect(parseSurrogateQueryRequest(JSON.stringify(queryRequest({ placeholder: "sk-real-looking" })))).toBeNull();
    expect(
      parseSurrogateQueryRequest(JSON.stringify(queryRequest({ placeholder: `sanctuary_surrogate_${"A".repeat(32)}` }))),
    ).toBeNull();
  });

  it("refuses a host or port the shared validators refuse", () => {
    expect(parseSurrogateQueryRequest(JSON.stringify(queryRequest({ host: "*.openai.com" })))).toBeNull();
    expect(parseSurrogateQueryRequest(JSON.stringify(queryRequest({ host: "192.0.2.1" })))).toBeNull();
    expect(parseSurrogateQueryRequest(JSON.stringify(queryRequest({ host: "API.openai.com" })))).toBeNull();
    expect(parseSurrogateQueryRequest(JSON.stringify(queryRequest({ port: 80 })))).toBeNull();
    expect(parseSurrogateQueryRequest(JSON.stringify(queryRequest({ port: 8443 })))).toBeNull();
  });

  it("refuses an ill-formed location", () => {
    expect(isSurrogateQueryLocation("header:authorization")).toBe(true);
    expect(isSurrogateQueryLocation("target")).toBe(true);
    expect(isSurrogateQueryLocation("header:")).toBe(false);
    expect(isSurrogateQueryLocation("header:Authorization")).toBe(false);
    expect(isSurrogateQueryLocation("body")).toBe(false);
    expect(isSurrogateQueryLocation(`header:${"a".repeat(65)}`)).toBe(false);
    expect(parseSurrogateQueryRequest(JSON.stringify(queryRequest({ location: "body" })))).toBeNull();
  });

  it("lowercases a header name when building a location, so the helper compares one spelling", () => {
    expect(surrogateHeaderLocation("Authorization")).toBe("header:authorization");
    expect(surrogateHeaderLocation("X-Api-Key")).toBe("header:x-api-key");
  });
});

describe("query codec: response", () => {
  it("round-trips a swap and a deny, echoing the request id", () => {
    const swap = { v: SURROGATE_WIRE_VERSION, id: ID, kind: "swap" as const, value: "Bearer v" };
    const deny = { v: SURROGATE_WIRE_VERSION, id: ID, kind: "deny" as const, reason: "misroute" as const };
    expect(parseSurrogateQueryResponse(line(encodeSurrogateQueryResponse(swap)))).toEqual(swap);
    expect(parseSurrogateQueryResponse(line(encodeSurrogateQueryResponse(deny)))).toEqual(deny);
  });

  it("refuses a deny reason outside the closed enum", () => {
    expect(
      parseSurrogateQueryResponse(JSON.stringify({ v: 1, id: ID, kind: "deny", reason: "because" })),
    ).toBeNull();
  });

  it("refuses an extra field on a swap, so no free-form text can ride back with a value", () => {
    expect(
      parseSurrogateQueryResponse(JSON.stringify({ v: 1, id: ID, kind: "swap", value: "v", message: "oops" })),
    ).toBeNull();
  });

  it("refuses an empty swap value", () => {
    expect(parseSurrogateQueryResponse(JSON.stringify({ v: 1, id: ID, kind: "swap", value: "" }))).toBeNull();
  });
});

describe("unlock codec", () => {
  it("round-trips unlock, lock and status requests", () => {
    const unlock = unlockRequest();
    expect(parseSurrogateUnlockSocketRequest(line(encodeSurrogateUnlockSocketRequest(unlock)))).toEqual(unlock);
    const lock = { v: SURROGATE_WIRE_VERSION, id: ID, kind: "lock" as const };
    expect(parseSurrogateUnlockSocketRequest(line(encodeSurrogateUnlockSocketRequest(lock)))).toEqual(lock);
    const status = { v: SURROGATE_WIRE_VERSION, id: ID, kind: "status" as const };
    expect(parseSurrogateUnlockSocketRequest(line(encodeSurrogateUnlockSocketRequest(status)))).toEqual(status);
  });

  it("refuses a value carrying CR, LF or NUL, so a value can never split a header", () => {
    for (const code of [13, 10, 0]) {
      expect(
        parseSurrogateUnlockSocketRequest(JSON.stringify(unlockRequest({ value: `Bearer a${byte(code)}b` }))),
      ).toBeNull();
    }
  });

  it("refuses a value over the byte cap and accepts one exactly at it", () => {
    const atCap = "a".repeat(MAX_SURROGATE_VALUE_BYTES);
    expect(parseSurrogateUnlockSocketRequest(JSON.stringify(unlockRequest({ value: atCap })))).not.toBeNull();
    expect(
      parseSurrogateUnlockSocketRequest(JSON.stringify(unlockRequest({ value: `${atCap}a` }))),
    ).toBeNull();
  });

  it("measures the value in bytes, not characters, so a multi-byte value cannot exceed the header budget", () => {
    // Two-byte characters: half the cap in characters is exactly the cap in bytes.
    const twoByte = "é".repeat(MAX_SURROGATE_VALUE_BYTES / 2);
    expect(twoByte.length).toBe(MAX_SURROGATE_VALUE_BYTES / 2);
    expect(Buffer.byteLength(twoByte, "utf8")).toBe(MAX_SURROGATE_VALUE_BYTES);
    // It is refused anyway, because a non-ASCII byte is not a legal field value;
    // the point of this case is that the length check does not pass it on size.
    expect(parseSurrogateUnlockSocketRequest(JSON.stringify(unlockRequest({ value: twoByte })))).toBeNull();
  });

  it("refuses an empty value and a non-positive TTL, and PASSES an over-clamp TTL to the helper", () => {
    expect(parseSurrogateUnlockSocketRequest(JSON.stringify(unlockRequest({ value: "" })))).toBeNull();
    expect(parseSurrogateUnlockSocketRequest(JSON.stringify(unlockRequest({ ttl_seconds: 0 })))).toBeNull();
    expect(parseSurrogateUnlockSocketRequest(JSON.stringify(unlockRequest({ ttl_seconds: -1 })))).toBeNull();
    expect(parseSurrogateUnlockSocketRequest(JSON.stringify(unlockRequest({ ttl_seconds: 1.5 })))).toBeNull();
    // An over-clamp TTL PARSES on purpose: the relying side clamps (design 3.4.3,
    // AGENTS.md rule 10), so the helper turns a generous request into a bounded
    // unlock rather than no unlock at all. A refusal here would move the bound
    // into the wire grammar, where a second copy of it would have to be kept in
    // step with `clampSurrogateUnlockSeconds`.
    const generous = parseSurrogateUnlockSocketRequest(
      JSON.stringify(unlockRequest({ ttl_seconds: MAX_SURROGATE_UNLOCK_SECONDS + 1 })),
    );
    expect(generous).toMatchObject({ ttl_seconds: MAX_SURROGATE_UNLOCK_SECONDS + 1 });
    expect(
      parseSurrogateUnlockSocketRequest(
        JSON.stringify(unlockRequest({ ttl_seconds: MAX_SURROGATE_UNLOCK_SECONDS })),
      ),
    ).not.toBeNull();
  });

  it("refuses generation zero, the wrapper's parked sentinel", () => {
    expect(parseSurrogateUnlockSocketRequest(JSON.stringify(unlockRequest({ generation_id: 0 })))).toBeNull();
    expect(parseSurrogateUnlockSocketRequest(JSON.stringify(unlockRequest({ generation_id: -1 })))).toBeNull();
  });

  it("refuses an unknown key on any request kind", () => {
    expect(
      parseSurrogateUnlockSocketRequest(JSON.stringify({ v: 1, id: ID, kind: "lock", force: true })),
    ).toBeNull();
    expect(parseSurrogateUnlockSocketRequest(JSON.stringify({ ...unlockRequest(), extra: 1 }))).toBeNull();
  });

  it("parses a status answer that carries no value and no placeholder", () => {
    const raw = JSON.stringify({
      v: 1,
      id: ID,
      kind: "status",
      generation_id: 7,
      bindings: [
        { secret: "openai-api-key", unlocked: true, expires_at: 1_700_000_000_000 },
        { secret: "other-key", unlocked: false, expires_at: null },
      ],
    });
    const parsed = parseSurrogateUnlockSocketResponse(raw);
    expect(parsed?.kind).toBe("status");
    expect(raw).not.toContain("sanctuary_surrogate_");
    expect(raw).not.toContain("value");
  });

  it("refuses a status row carrying any extra field, which is how a value would sneak in", () => {
    expect(
      parseSurrogateUnlockSocketResponse(
        JSON.stringify({
          v: 1,
          id: ID,
          kind: "status",
          generation_id: 7,
          bindings: [{ secret: "s", unlocked: true, expires_at: null, value: "leak" }],
        }),
      ),
    ).toBeNull();
  });
});

describe("each socket is bound to exactly one codec", () => {
  it("a query frame on the unlock socket is malformed", () => {
    expect(parseSurrogateUnlockSocketRequest(line(encodeSurrogateQueryRequest(queryRequest())))).toBeNull();
  });

  it("an unlock frame on the query socket is malformed", () => {
    expect(parseSurrogateQueryRequest(line(encodeSurrogateUnlockSocketRequest(unlockRequest())))).toBeNull();
  });

  it("a query response is not a legal unlock-socket response, and the reverse", () => {
    const swap = JSON.stringify({ v: 1, id: ID, kind: "swap", value: "v" });
    expect(parseSurrogateUnlockSocketResponse(swap)).toBeNull();
    const ok = JSON.stringify({ v: 1, id: ID, kind: "ok" });
    expect(parseSurrogateQueryResponse(ok)).toBeNull();
  });
});

describe("the frame cap is checked before JSON.parse", () => {
  it("refuses an over-cap frame on both codecs, both directions", () => {
    const oversized = `{"v":1,"id":"${ID}","kind":"lock","pad":"${"a".repeat(SURROGATE_WIRE_MAX_FRAME_BYTES)}"}`;
    expect(Buffer.byteLength(oversized, "utf8")).toBeGreaterThan(SURROGATE_WIRE_MAX_FRAME_BYTES);
    expect(parseSurrogateUnlockSocketRequest(oversized)).toBeNull();
    expect(parseSurrogateQueryRequest(oversized)).toBeNull();
    expect(parseSurrogateUnlockSocketResponse(oversized)).toBeNull();
    expect(parseSurrogateQueryResponse(oversized)).toBeNull();
  });

  it("refuses an over-cap frame that is not even valid JSON, so the size check runs first", () => {
    // Unterminated: `JSON.parse` would throw. The size check returns null before
    // it runs, which is what keeps an endless stream off a root event loop.
    const oversizedBadJson = `{"v":1,"pad":"${"a".repeat(SURROGATE_WIRE_MAX_FRAME_BYTES)}`;
    expect(parseSurrogateQueryRequest(oversizedBadJson)).toBeNull();
    expect(parseSurrogateUnlockSocketRequest(oversizedBadJson)).toBeNull();
  });

  it("refuses arrays, null and scalars rather than treating them as records", () => {
    for (const raw of ["[]", "null", "42", '"a"', "true"]) {
      expect(parseSurrogateQueryRequest(raw)).toBeNull();
      expect(parseSurrogateUnlockSocketRequest(raw)).toBeNull();
      expect(parseSurrogateQueryResponse(raw)).toBeNull();
      expect(parseSurrogateUnlockSocketResponse(raw)).toBeNull();
    }
  });

  it("encoding refuses to emit a frame over the bound rather than truncating it", () => {
    expect(() =>
      encodeSurrogateUnlockSocketRequest(unlockRequest({ value: "a".repeat(SURROGATE_WIRE_MAX_FRAME_BYTES) })),
    ).toThrow(/exceeds/);
  });
});
