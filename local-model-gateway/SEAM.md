# Local model gateway G1 seam

This package contains pure parsers and framing fixtures. It has no listener, runtime, upstream client, journal or installation behavior and is not a qualified gateway. G2 through G4 must supply those consumers and their independent witnesses.

## Request contract

`RequestFramer.receive` consumes incremental HTTP bytes and returns at most one `ValidatedRequest`. A thrown refusal is terminal. `refusedTarget` exposes the closed probe classification after valid framing; it never retains an arbitrary target for logging. A second request or any buffered extra byte refuses before a typed value escapes. Later bytes require G2 cancellation of any already dispatched request. EOF before completion refuses. G2 checks cancellation and deadlines before calling the parser, owns bounded refusal draining and never dispatches after a refusal.

`ValidatedRequest.parse` is the only constructor. `RequestSerializer.body` and `RequestSerializer.http` accept only that type. The parser applies one shared JSON grammar, recursive decoded-byte duplicate checks, protocol member validation, model pinning, schema validation and canonical output budgeting. Protocol key identity uses decoded UTF-8 bytes without normalization; opaque tool parameter keys remain data. Go-fold equivalents reaching ASCII are A-Z, U+017F and U+212A. This list must match `goFold` in `Protocol.swift` and `RequestTests.testCaseLayers`.

The request route registry in `Protocol.swift` is the sole method/target authority. Consumers use its values for classifications and serialization; they must not add a URL-normalizing adapter. `unknownMember` on CHAT is a readiness stop, not permission to discard an emitted field.

## Response contract

`ResponseFramer.receive` consumes one upstream byte and returns zero or one bounded output segment. The caller must finish writing the returned segment before feeding more bytes; the parser queues no second event. G2 must preserve event boundaries across partial writes. If it cannot finish an event within terminal reserve, it aborts the downstream connection rather than inserting another event into partial bytes.

`endOfInput` means a genuine upstream transport EOF. For length and chunk framing it additionally requires completed framing; close-delimited responses end at EOF. Exact DONE remains held until this call. Extra HTTP bytes or payload after DONE refuse. Reset and deadline use `fail`, never `endOfInput`; calling EOF on a reset can wrongly authorize a close-delimited body. Before stream commitment a protocol failure emits fixed 502; G2 uses fixed 504 for a deadline before commitment. After commitment `fail` returns exactly one B27 error chunk and no terminal zero chunk. Closed states absorb late input and repeated terminal calls. G2 must close after the terminal segment and must not append its own zero chunk.

| Continuing path | Required evidence | Output |
| --- | --- | --- |
| Partial request | Within H/B and declared framing | No typed request |
| Complete request | Exact route, no extra bytes, shared schema, rebuilt cap | One typed request |
| Partial response | Within H/R/event budgets and framing | No nonstream bytes |
| SSE event | Exact grammar, object JSON, no duplicate keys | One chunk |
| Exact DONE | No later payload, complete HTTP framing and EOF | Original DONE chunk then zero chunk |
| Nonstream/error JSON | Allowed status/type, full framing and EOF, one valid JSON value | Regenerated Content-Length response |

| Refusal path | Output and continuing restriction |
| --- | --- |
| Request framing, route, size, schema | Closed refusal reason; no serializer input |
| Upstream headers/type/status/framing before commitment | Fixed 502; closed |
| Bad SSE, cap, EOF without DONE, reset/deadline after commitment | Fixed B27 chunk; no zero chunk; closed |
| Late input after closed | No output |

## Pins

The following values must match `GatewayProtocol` in `Protocol.swift`, `FixedResponse` in `HTTP.swift`, `WireTests.testFixedWireBytes` and the fixed `.http` fixtures. These implement accepted G-r2 sections 2 through 5 and bindings B18/B19/B24/B27; later slices import them directly.

| Pin | Value |
| --- | --- |
| Model | `qwen3.5:9b` |
| Listener / sole upstream Host | `127.0.0.1:11436` / `127.0.0.1:11434` |
| SHOW | `{"name":"qwen3.5:9b"}`, 21 bytes, no LF |
| DONE | `data: [DONE]` then two LF bytes, 14 bytes |
| B27 payload | `data: {"error":{"message":"Gateway stream truncated","type":"gateway_error","code":"stream_truncated"}}` then two LF bytes, 105 bytes |
| Fixed response status/body lengths | 404/76, 413/84, 400/88, 503/74, 504/82, 502/82 |
| Output/context token inputs | 65536 / 131072 |
| JSON container depth / identifier bytes | 64 / 128 |
| JSON nodes | floor(payload budget / 2), counting keys and values |
| Fixture B/H/R | 1 MiB / 64 * 256 bytes / 32 MiB, explicit fixture allowances only |

Production B, H and R require capture-derived values, not the fixture profile. Event cap equals B. Authorization stripping is an explicit caller decision requiring the B18 comparison; otherwise use `.placeholder`. No arbitrary credentials can enter serialization. B29 launchd activation, B30 durable recovery and B31 runtime/capture requirements are later-slice obligations.

`Fixtures/allowed-chat.json` covers text, reasoning, tool continuation, opaque byte-distinct schema names and compatibility fields. `Fixtures/media-data.txt` contains one complete 1x1 RGBA PNG and one PNG with a CRC-valid header claiming 2147483647 by 2147483647 dimensions; both are refused before image decoding.
