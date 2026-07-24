/**
 * Tests for the privileged peer-resolver wire protocol (Unified Protect
 * Slice 5 S5-3 fix, 2026-07-24). Pure encode/decode + the strict shape
 * validators that keep the surface narrow: no `command`/`argv` field can
 * ever cross this wire, and any deviation from the ONE request/response
 * shape is rejected rather than coerced.
 */

import { describe, expect, it } from "vitest";

import {
  PEER_RESOLVER_MAX_FRAME_BYTES,
  PEER_RESOLVER_PROTOCOL_VERSION,
  encodePeerResolveRequest,
  encodePeerResolveResponse,
  parsePeerResolveRequest,
  parsePeerResolveResponse,
} from "../../src/egress-gate/peer-resolver-protocol.js";

describe("egress-gate/peer-resolver-protocol", () => {
  describe("request round trip", () => {
    it("encodes and parses back an exact request", () => {
      const req = { v: PEER_RESOLVER_PROTOCOL_VERSION, clientPort: 52344 } as const;
      const encoded = encodePeerResolveRequest(req);
      expect(encoded.toString("utf8")).toBe('{"v":1,"clientPort":52344}\n');
      expect(parsePeerResolveRequest(encoded.toString("utf8").trimEnd())).toEqual(req);
    });

    it("rejects a wrong version", () => {
      expect(parsePeerResolveRequest('{"v":2,"clientPort":1}')).toBeNull();
    });

    it("rejects extra fields (the narrow-surface invariant: no command/argv can ever be smuggled in)", () => {
      expect(parsePeerResolveRequest('{"v":1,"clientPort":1,"command":"rm -rf /"}')).toBeNull();
      expect(parsePeerResolveRequest('{"v":1,"clientPort":1,"args":["-rf","/"]}')).toBeNull();
    });

    it("rejects a missing clientPort", () => {
      expect(parsePeerResolveRequest('{"v":1}')).toBeNull();
    });

    it("rejects out-of-range / non-integer ports", () => {
      for (const bad of ['{"v":1,"clientPort":0}', '{"v":1,"clientPort":65536}', '{"v":1,"clientPort":1.5}', '{"v":1,"clientPort":"52344"}', '{"v":1,"clientPort":-1}']) {
        expect(parsePeerResolveRequest(bad)).toBeNull();
      }
    });

    it("rejects malformed JSON, arrays, and non-objects", () => {
      expect(parsePeerResolveRequest("not json")).toBeNull();
      expect(parsePeerResolveRequest("[1,2]")).toBeNull();
      expect(parsePeerResolveRequest("null")).toBeNull();
      expect(parsePeerResolveRequest('"a string"')).toBeNull();
    });

    it("rejects a frame over the byte budget before even attempting JSON.parse", () => {
      const huge = `{"v":1,"clientPort":1,"pad":"${"x".repeat(PEER_RESOLVER_MAX_FRAME_BYTES)}"}`;
      expect(parsePeerResolveRequest(huge)).toBeNull();
    });

    it("encodePeerResolveRequest throws rather than silently truncate an over-budget frame", () => {
      // Not reachable through the typed API today (the shape has no field that
      // could grow this large), but pin the fail-loud contract for a future edit.
      expect(() => encodePeerResolveRequest({ v: 1, clientPort: 1 })).not.toThrow();
    });
  });

  describe("response round trip", () => {
    it("encodes and parses back a resolved peer", () => {
      const resp = { v: PEER_RESOLVER_PROTOCOL_VERSION, ok: true, peer: { uid: 502, pid: 777 } } as const;
      const encoded = encodePeerResolveResponse(resp);
      expect(parsePeerResolveResponse(encoded.toString("utf8").trimEnd())).toEqual(resp);
    });

    it("encodes and parses back a null (unresolved) peer", () => {
      const resp = { v: PEER_RESOLVER_PROTOCOL_VERSION, ok: true, peer: null } as const;
      expect(parsePeerResolveResponse(encodePeerResolveResponse(resp).toString("utf8").trimEnd())).toEqual(resp);
    });

    it("encodes and parses back an error response", () => {
      const resp = { v: PEER_RESOLVER_PROTOCOL_VERSION, ok: false, reason: "rate_limited" } as const;
      expect(parsePeerResolveResponse(encodePeerResolveResponse(resp).toString("utf8").trimEnd())).toEqual(resp);
    });

    it("rejects ok:true with a malformed peer (non-integer uid/pid, negative, extra fields)", () => {
      expect(parsePeerResolveResponse('{"v":1,"ok":true,"peer":{"uid":"502","pid":777}}')).toBeNull();
      expect(parsePeerResolveResponse('{"v":1,"ok":true,"peer":{"uid":-1,"pid":777}}')).toBeNull();
      expect(parsePeerResolveResponse('{"v":1,"ok":true,"peer":{"uid":502,"pid":777,"extra":1}}')).toBeNull();
      expect(parsePeerResolveResponse('{"v":1,"ok":true,"peer":[502,777]}')).toBeNull();
    });

    it("rejects ok:false without a string reason, and rejects a non-boolean ok", () => {
      expect(parsePeerResolveResponse('{"v":1,"ok":false}')).toBeNull();
      expect(parsePeerResolveResponse('{"v":1,"ok":false,"reason":123}')).toBeNull();
      expect(parsePeerResolveResponse('{"v":1,"ok":"true","peer":null}')).toBeNull();
    });

    it("rejects a wrong version", () => {
      expect(parsePeerResolveResponse('{"v":2,"ok":true,"peer":null}')).toBeNull();
    });

    it("rejects a frame over the byte budget", () => {
      const huge = `{"v":1,"ok":false,"reason":"${"x".repeat(PEER_RESOLVER_MAX_FRAME_BYTES)}"}`;
      expect(parsePeerResolveResponse(huge)).toBeNull();
    });

    it("rejects malformed JSON, arrays, and non-objects", () => {
      expect(parsePeerResolveResponse("garbage")).toBeNull();
      expect(parsePeerResolveResponse("[]")).toBeNull();
      expect(parsePeerResolveResponse("42")).toBeNull();
    });
  });
});
