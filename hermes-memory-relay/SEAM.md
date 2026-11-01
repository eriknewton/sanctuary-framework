# Hermes Memory Relay Seam

This file is the relay-to-Node contract for the Hermes memory bridge. The Node bridge must consume `Tests/HermesMemoryRelayCoreTests/Fixtures/relay-frames.json`; the Swift tests consume that same file now. Any change to this contract updates both this document and the fixture in the same change. Stream vectors carry literal `bytes_hex`; recipe names are not part of the slice-2 contract.

Slice status: this package implements the relay runtime. Installed-platform acceptance is not established. The Node capability is catalog v2: scoped memory save, get, search and bounded recall. Each write is an own-scope save audited with the agent named. `ready` does not establish policy pinning; `state_POLICY_PINNED` is `not_provided`.

## Transport

The relay creates a Unix `socketpair(AF_UNIX, SOCK_STREAM)` and starts the Node bridge as its direct child. Node receives exactly one inherited stream fd, fixed at fd 3. There is no private relay socket path.

The child argv is:

```text
[absolute node path]
[absolute bridge entry path]
hermes-memory-bridge
run
--relay-fd
3
```

Child stdin is `/dev/null`. Child stdout and stderr go to the bridge log opened by the relay with append, no-follow, and close-on-exec flags. The child environment is an allowlist: `HOME`, `LANG`, `TMPDIR`, plus `HERMES_MEMORY_BRIDGE_IDENTITY`, `HERMES_MEMORY_AGENT_ID`, and `HERMES_MEMORY_FORTRESS_ID`. The relay sets those identity variables from install configuration, never from its own inherited environment. The native spawn array contains exactly these six keys. On macOS, Node may additionally observe the CoreFoundation encoding hint initialized by the OS; the child validates its format and own uid. No other extra environment key is accepted. The configured `TMPDIR` is `/tmp`, so custody uses the platform rendezvous rather than an instance-specific path.

Every frame on the inherited fd is:

```text
u32 big-endian payload length
JSON object payload
```

The length prefix counts only the JSON payload bytes. JSON is UTF-8 with slash characters unescaped; Swift uses `JSONEncoder.OutputFormatting.withoutEscapingSlashes` only for relay-built frames, and Node uses `JSON.stringify`. The relay never fully parses or re-encodes public JSON. It scans the top-level object with a bounded iterative scanner, reads only the string fields it routes on (`type`, `request_id`, `mcp_request_id`, `connection_id`, `nonce`, `result_b64`), and skips nested values by counting brackets. A non-object top level, malformed top-level token, lone surrogate in any string, or nesting deeper than `MAX_JSON_NESTING_DEPTH = 64` rejects that frame. Duplicate top-level keys read by the relay are malformed by decoded UTF-8 key bytes, with no Unicode normalization. Nested duplicate keys are Node's parser responsibility. The relay rejects an over-cap length before allocating or slicing a payload; when that length follows valid complete frames in the same read, the valid prefix is still delivered before the connection closes. The incomplete-tail retention cap applies after every complete frame in the read chunk is decoded.

The top-level object is depth 1. Nested composites up to `MAX_JSON_NESTING_DEPTH = 64` levels below that object are accepted by the scanner. At the public frame boundary, use a field whose frame type permits nested content: a `tools_call.arguments` object plus 63 nested arrays is accepted, and the same object plus 64 nested arrays is refused. Node should emit well-formed strings before base64 encoding response payloads. The 3b socket reader reads at most `MAX_PUBLIC_READ_CHUNK_BYTES = 65536` bytes from one public fd at a time, so scanner work is bounded per read.

Values, which must match `RelayProtocolConstants` in `Sources/HermesMemoryRelayCore/Core.swift`:

```text
MAX_PUBLIC_FRAME_BYTES = 65536
MAX_RESULT_FRAME_BYTES = 65536
MAX_REQUEST_ID_BYTES = 128
PROBE_NONCE_BYTES = 32
MAX_CONNECTION_ID_BYTES = 21
PRIVATE_RESPONSE_ENVELOPE_SYNTAX_BYTES = measured by the relay encoder for empty response = 70
PRIVATE_RESPONSE_FRAME_HEADROOM_BYTES = 256
MAX_FRAME_OVERHEAD_BYTES = 70 private response syntax + 21 connection_id + 128 request_id bytes + 256 headroom = 475
MAX_PRIVATE_FRAME_BYTES = 4 * ceil(65536 / 3) + 475 = 87859
MAX_PARTIAL_FRAME_BYTES = 65536 + 4 = 65540
CONTROL_QUEUE_DEPTH_PER_CONNECTION = 8
CONTROL_RESPONSE_ALLOWANCE_PER_CONNECTION = 2
MAX_CLIENT_OUTBOUND_FRAMES_PER_CONNECTION = 1 result/error + 1 busy denial + 2 control responses = 4
MAX_JSON_NESTING_DEPTH = 64
MAX_PUBLIC_READ_CHUNK_BYTES = 65536
PROBE_REPLY_BOUND_MS = 2000
CHILD_READY_TIMEOUT_MS = 5000
RELAY_CHILD_EXIT_BOUND_MS = 2000 probe bound + 3000 SIGTERM grace = 5000
MAX_PUBLIC_CONNECTIONS = 4
PROBE_DRAIN_MAX_BYTES = 65540 retained partial + 65536 read chunk = 131076
PROBE_DRAIN_MAX_FRAMES = 8 controls + 1 primary call + 1 busy-denied call + 2 pings = 12
RELAY_CHILD_REAP_BOUND_MS = 1000
```

`relay-frames.json` uses this `expected_action` vocabulary:

```text
accept: the frame is valid for its channel and does not close the connection or relay.
poison_connection: only the named public connection closes and emits closed.
fatal_relay_error: the inherited-fd protocol is invalid and the relay exits.
reject_before_payload_allocation: the length prefix exceeds the channel cap before payload allocation.
retain_until_probe_then_closed: an incomplete tail is retained, and a later probe closes that connection.
decode_all_complete_frames: every complete public frame in the byte stream is processed.
decode_prefix_keep_partial_tail: the complete public prefix is processed and the incomplete tail is retained.
decode_one_frame: exactly one public frame reaches the next relay stage with no client response.
decode_response_and_forward: a Node response is decoded and forwarded as exact public bytes.
decode_response_and_deny: a Node response is decoded but converted to the fixed public denial.
close_then_late_response_discarded: Node close closes the named public connection, and a later response for that closed id is discarded.
discard_late_probe_reply: Node consumes and discards a relay `probe_reply` for an accepted connection when the echoed nonce was issued by Node but the probe waiter was already resolved.
fatal_bridge: Node treats the relay-to-Node private channel as broken, refuses every waiting entry, and exits nonzero within RELAY_CHILD_EXIT_BOUND_MS.
```

`node_to_relay` and `relay_to_node` fixture envelopes are compared by parse equality, not encoder byte order. State-dependent vectors require the matching accepted connection, in-flight request, or issued probe pair. Forwarded public payload bytes remain exact. Both sides enforce `MAX_PRIVATE_FRAME_BYTES`. Node emits padded standard base64 and matching inner and outer request IDs. An oversized public result becomes a fixed denial response and leaves the connection usable; an unparseable request or oversized private frame follows its channel's close or fatal path.

The relay sends `relay_shutdown {}` after closing admission, allows `PROBE_REPLY_BOUND_MS = 2000` for child exit, then sends SIGTERM to the exact spawned child and allows 3000 ms of grace. `RELAY_CHILD_EXIT_BOUND_MS = 5000` is this outer stop window, not a durable-write guarantee. After SIGKILL, `RELAY_CHILD_REAP_BOUND_MS = 1000` covers scheduler latency while the child leaves the kernel. The total outer bound is 6000 ms. A reap timeout reports `reap_timeout` and exits `EX_SOFTWARE`; cleanup never unlinks an object whose ownership is unproven. The public socket is removed only after reaping, and the instance flock is released last without unlinking its file. Forced death may leave a corpus lock; the next startup refuses pending exact operator recovery.

## Public Frames

Public frames are accepted only after the kernel peer uid check succeeds. Public frame types are:

```text
hello { request_id: string, protocol_version: string, client_name: string }
tools_list { request_id: string }
tools_call { request_id: string, name: string, arguments: object }
cancel { mcp_request_id: string }
ping {}
shutdown {}
```

`probe`, `probe_reply`, `ready`, `accepted`, `frame`, `closed`, `response`, `close`, and `relay_shutdown` are never accepted from the public socket.

`request_id` and `cancel.mcp_request_id` match `^[A-Za-z0-9._:-]{1,128}$` exactly on the decoded string. Empty ids, ids longer than `MAX_REQUEST_ID_BYTES = 128`, non-ASCII ids, controls, NUL, `"`, `\`, and every other character outside that set poison only that public connection. These characters are never escaped by JSON, so encoded and decoded request-id lengths are equal and the frame budget is exact. The stdio shim mints MCP ids and stringifies numeric ids, including `cancel.mcp_request_id`, before the relay sees them, so this restriction costs Hermes no compatibility.

## Node To Relay

Node-to-relay frame types are:

```text
ready {}
probe { connection_id: string, nonce: string }
response { connection_id: string, request_id: string, result_b64: string }
close { connection_id: string }
```

`ready` is the first frame and is sent exactly once after Node composition succeeds. Any other first frame, or any second `ready`, is refused. The relay takes the private flock, validates the socket ancestors under that lock, spawns Node, waits up to `CHILD_READY_TIMEOUT_MS = 5000` for `ready`, unlinks a leftover public socket only if it is a socket owned by the relay uid, binds `memory.sock`, applies mode `0660`, and verifies owner and mode. Timeout or child exit before `ready` exits without binding the public socket and writes an operator message naming the bridge log.

`probe.nonce` is exactly `PROBE_NONCE_BYTES = 32` lowercase hex characters. A Node `probe` with any other nonce format is a Node protocol violation and a fatal relay error; the relay never echoes an unbounded nonce value.

`response.result_b64` is standard base64 with required padding of the exact public `result` or `error` JSON payload bytes Node built. The relay decodes those bytes, checks their decoded length against `MAX_RESULT_FRAME_BYTES`, scans only their top-level `type` and `request_id`, requires `type` to be `result` or `error`, and requires the payload `request_id` and outer `request_id` to match the connection's current in-flight id. A matching response alone ends in-flight, and the relay writes the decoded public payload bytes verbatim with a length prefix. If the decoded payload has missing padding, a lone surrogate, is over cap, exceeds the depth bound, or does not match the in-flight request, the relay sends its own fixed `error { request_id, message: "Memory request denied." }` for the in-flight id and the connection continues. Node owns the complete client frame shape: the relay does not enforce the client allowlist on Node's result bytes beyond the top-level `type` and `request_id` checks above. A response for an unknown connection id or a never-minted id is a fatal relay error; a response for an already closed id is discarded. `close` asks the relay to drop that public connection; the relay closes the public fd and emits `closed` once. `close` for an already closed or never-admitted-but-minted id is a no-op; `close` for a never-minted id is fatal.

## Relay To Node

Relay-to-Node frame types are:

```text
accepted { connection_id: string }
frame { connection_id: string, frame_b64: string }
closed { connection_id: string }
probe_reply { connection_id: string, nonce: string }
relay_shutdown {}
```

The relay mints `connection_id` values. The format is the string `c` followed by a decimal u64 counter starting at 1, so the maximum length is `MAX_CONNECTION_ID_BYTES = 21`. Values are never reused for the relay lifetime. After the peer check passes, the relay sends `accepted { connection_id }` before any `frame` for that id. Node treats ids as opaque.

`frame_b64` is standard base64 with padding of the exact public frame JSON payload bytes, meaning the JSON after the public length prefix. There is no `request_id`, `type`, or sentinel string on the envelope. Node parses and validates the public JSON itself, including duplicate keys at every depth. Public control frames use the same `frame` envelope unless this seam names a relay-local response. Node never sends a private `error` frame.

Any malformed relay-to-Node private frame is `fatal_bridge`: malformed JSON, an unknown `type`, missing or wrongly typed required fields, duplicate top-level keys, over-cap length, duplicate lifecycle frames, `probe_reply` for a connection id Node never saw in `accepted`, `probe_reply` with a nonce Node never issued, and frames for unknown or impossible connection ids all make Node refuse every waiting entry and exit nonzero within `RELAY_CHILD_EXIT_BOUND_MS`. What Node would do with a disallowed public id is irrelevant to this relay seam because the relay never forwards one; Node's own private encoder only emits ids it received from the relay.

If Node's parser or validator rejects a forwarded catalogued `tools_call` with a recoverable request id, Node sends a private `response` carrying an ordinary public `result`. Catalogued-tool refusals use the fixed outcomes below. A non-catalogued name, invalid `hello` or `tools_list`, or an unrecoverable frame remains a protocol fault and keeps the fixed public `error { request_id, message: "Memory request denied." }` contract where an id can be recovered. If Node rejects a forwarded `cancel` or `shutdown`, Node sends nothing. If Node cannot parse the bytes well enough to recover a request id, or if its response would exceed `MAX_PRIVATE_FRAME_BYTES`, Node sends `close { connection_id }`; the relay closes only that public connection. The relay derives the private response budget as the measured 70-byte empty response envelope, plus the 21-byte longest relay-minted `connection_id`, plus the 128-byte longest allowed `request_id`, plus 256 bytes of named headroom; the product assertion and fixture test build that longest-id, longest-connection, full-65536-byte-result response through the real encoder.

Public `cancel` does not remove the relay's in-flight state: every forwarded `hello`, `tools_list`, or `tools_call` has exactly one `response` or one `close` for that connection, including after any later `cancel`. A `response` for a connection with nothing in flight, or a second `response` after the relay already accepted or denied the call, is a fatal relay error.

Forwarded controls reserve a slot that becomes queued only after transport acceptance (`markNodeFrameQueued`); refusal cancels that reservation. Every relay-to-Node output carries the completion kind shown below, which the writer passes back after that exact frame is written:

```text
forwarded public cancel -> markNodeFrameWritten(.forwardedControlFrame)
forwarded public shutdown -> markNodeFrameWritten(.forwardedControlFrame)
forwarded public hello, tools_list, tools_call -> markNodeFrameWritten(nil)
accepted, closed, probe_reply, relay_shutdown -> markNodeFrameWritten(nil)
```

The relay enforces `MAX_PUBLIC_CONNECTIONS = 4`; the fifth public connection is closed before `accepted` and never reaches Node. A terminal connection closes its public fd immediately; its admission slot remains charged until its private output drains. The runtime retains at most four live or draining records and a monotonic UInt64 issued counter. An ID at or below that counter and absent from the live map is closed; a larger ID is never-issued. No historical connection objects or finished approval entries are retained.

## Relay To Client

Relay-to-client public frames are:

```text
result { request_id: string, payload: object }
error { request_id: string, message: string }
pong {}
```

A Node `response.result_b64` becomes the exact public `result` or `error` payload bytes Node supplied after the relay's top-level checks pass. The relay never re-encodes Node content. The busy denial is `error { request_id: <the caller's own request_id>, message: "Memory request denied." }`, and it is delivered even during a probe drain. Ping is answered by the relay with `pong` and is never forwarded; it counts against the per-connection control-response allowance until the pong write-completion hook fires.

Every relay-to-client output carries the completion kind the writer must pass back after that exact frame is written:

```text
pong -> markClientFrameWritten(.pong)
busy denial -> markClientFrameWritten(.busyDenial)
Node result payload -> markClientFrameWritten(.result)
relay-generated denial from a Node response -> markClientFrameWritten(.result)
```

A busy denial is retired only by the write-completion hook for that busy-denial frame. A result or relay-generated denial from a Node response is retired only by the write-completion hook for that client frame.

## Probe Barrier

When the relay receives `probe { connection_id, nonce }`, it routes to and drains the target public connection:

1. Parse any complete frames already retained by the `BoundedFrameStream`.
2. Poll the public fd with zero timeout.
3. If readable, read incrementally toward `EAGAIN`, bounded by `PROBE_DRAIN_MAX_BYTES = 131076` and `PROBE_DRAIN_MAX_FRAMES = 12`. Readable data left at either bound closes the connection before reply.
4. Forward every resulting `cancel`, `shutdown`, and synthesized `closed` to Node.
5. Convert `POLLHUP`, EOF, partial frame, over-cap length, malformed frame, or poison to terminal `closed { connection_id }`.
6. Deliver any client-bound output produced by the drain.
7. Write `probe_reply { connection_id, nonce }` only after those outputs.

Socketpair FIFO ordering is the barrier: Node observes forwarded control events before the matching `probe_reply`. Node, not the relay, compares the echoed probe nonce and refuses the waiting check on mismatch or on `PROBE_REPLY_BOUND_MS = 2000` timeout. A probe for a connection already in `state_CLOSED` gets `probe_reply` immediately. A probe naming an unknown or mismatched live connection id is a fatal relay error.

Late `probe_reply` is normal on the Node side only for an issued `(connection_id, nonce)` pair. Must match `ABANDONED_PROBE_NONCE_CAP` in `server/src/hermes-memory-bridge/constants.ts`: the cap is 16, with no eviction. Live and abandoned pairs consume capacity; new probes refuse when capacity is exhausted. A matching live pair resolves its waiter; a matching abandoned pair is consumed silently. Unmatched and already-consumed replies are immediately fatal. Closed connection objects and separate tombstone sets are not retained for this check.

## Connection State

`state_CLOSED` is absorbing. `closed` is terminal and sent exactly once per connection. After `closed`, the relay drops every later public byte for that id and ignores any Node frame naming it. A `probe` for a closed id gets `probe_reply` immediately. `finishInFlight` from a poisoned or closed state does nothing.

While one call is in flight for a connection, the relay forwards only `cancel`, `shutdown`, and peer close. A second `tools_call`, `hello`, or `tools_list` receives the fixed busy denial with at most one busy denial outstanding. Any further non-control frame poisons the connection and emits `closed`.

In flight means any forwarded request awaiting its `response`: `tools_call`, `tools_list`, and `hello` all count. Public `shutdown` is forwarded to Node, then the relay closes the caller's public fd and emits `closed` once. The control queue counts events queued and not yet written to the socketpair and drains only on the write-completion hook for that control frame; idle `cancel` frames count against the same queue. Pongs count until their own client write-completion hook fires. The queue is capped at `CONTROL_QUEUE_DEPTH_PER_CONNECTION = 8`. Overflow poisons that connection only. The outbound bound per connection is one result frame, one busy denial, and `CONTROL_RESPONSE_ALLOWANCE_PER_CONNECTION = 2` pong responses.

## Stdio client contract

`sanctuary hermes-memory-client` adapts the public socket to MCP stdio. Scoped memory save, get, search and bounded recall are available through the bridge. A save into the agent's own memory runs without a human prompt and is audited with the agent named. Silent saves are limited to 120 admissions and 1 MiB of UTF-8 text in a rolling ten-minute window per bridge process. The allowance starts fresh at each start; excess saves return `unavailable`. Admission also refuses at 2000 owner documents, the `MEMORY_CORPUS_SCAN_CAP` search and recall ceiling that bounds total growth across restarts. It connects once and never launches the bridge or ordinary Sanctuary. The socket location is fixed by the installation contract; the shim code reads no environment selector for socket, identity, write flag, or boot mode. The agent account can reach the socket directly, so inherited environment is not a security boundary here.

The client constants in `server/src/hermes-memory-client/protocol.ts` must match `RelayProtocolConstants` in `Sources/HermesMemoryRelayCore/Core.swift`: public payload 65536 bytes excluding the 4-byte prefix, retained socket frame 65540 bytes, 64 composite levels below the public root, two outstanding pongs, and eight queued/reserved forwarded controls. The client cannot observe `markNodeFrameWritten`, so its `CONTROL_CAP` conservatively limits controls over the connection lifetime, reserving the eighth credit for shutdown. A socket write never refunds credit.

`MAX_STDIO_LINE_BYTES` must match `server/src/hermes-memory-client/protocol.ts`: 65536 payload + 35 fixed MCP envelope bytes + 128 ID bytes + 2 CRLF bytes = 65701. The maximum compact call overhead is 222 MCP bytes versus 127 relay bytes: 65536 - 127 + 222 = 65631, within the 65699 JSON ceiling. The 128-character ASCII ID rule is client-local; integer IDs remain typed. The client mints unrelated wire IDs using 128 random bits and a non-wrapping UInt64 counter.

`SHIM_CALL_DEADLINE_MS` is 120000 minus the 2000 response delivery reserve = 118000, measured from shim admission. The Hermes clock starts earlier; this is not a guarantee of delivery before its deadline. Call reply stalls use the remainder of that 120000 window. Other replies use the 2000 delivery reserve. CD1a allows 5000 for connect/hello; CD1b allows 5000 in each initialization waiting/output state. Ping waits are 30000 minus 2000 = 28000 through parsing pong. Cancel settlement allows 30000 lock wait + 2000 probe = 32000 without a durable-completion guarantee. EOF and non-EOF drains allow 2000 Python process grace minus 500 scheduler/exit margin = 1500. HERMES_INSERT_DEADLINE_MS is 83000, the deadline for an admitted insert to pass its commit check before any effect.

MCP call results must match `CallToolResultSchema` with an actual content array; list results must match `ListToolsResultSchema` after tool-level `input_schema` becomes `inputSchema`. The exact seven names are memory_insert, memory_get, memory_search, memory_recall, sign_statement, export_memory, protection_rules, with no cursor. Payload bytes are spliced without re-encoding. Unknown call param fields are ignored; only the tool name and object arguments cross the seam. The bridge remains the argument-allowlist and effective-taint authority.

| Refusing event | Client disposition |
|---|---|
| Catalogued-tool denial or malformed tool arguments | Ordinary `result`, outcome `denied`, continue |
| Sign or export | Ordinary `result`, outcome `unavailable`; not available yet |
| Capacity, admission or audit unavailable | Ordinary `result`, outcome `unavailable` |
| Insert completion unconfirmed | Ordinary `result`, outcome `unconfirmed` |
| Unknown tool or relay-generated denial | Fixed -32002, continue |
| Occupied primary or third ping | Fixed -32003, no call queue |
| Relay unavailable | Fixed -32004, insert outcome unknown, continue |
| Admission deadline | Fixed -32005, outcome unknown, at most one eligible cancel |
| Size or depth with recovered ID | -32602, continue; rejected tails retain only a bounded ID scanner |
| Invalid framing or lifecycle | Correlate outstanding IDs and drain while stdout remains usable |
| Malformed relay result or unsolicited pong | Fixed -32603 for the protocol fault; other admitted IDs receive unavailable, insert outcome unknown |
| EOF or signal | No new stdout writes; eligible cancel, shutdown, bounded exit |
| Dead stdout | Cancel where eligible, bounded exit; delivery cannot be guaranteed |
| Native call write error | Correlated outcome unknown, no cancel and no replay; partial progress resumes at its offset and EAGAIN waits for writability |

| Continuing effect | Required evidence |
|---|---|
| Hello | One connection, primary reserved, fixed facade identity |
| Initialize success | Validated hello releases primary; named initialize output slot |
| Initialized readiness | Initialize output completed; initialized notification validated |
| List or call forwarding | READY, free primary, validated encoded size/depth and allowed method |
| Result delivery | First settlement winner, wanted ID, validated schema and bounded immutable bytes |
| Ping | Reserved typed FIFO entry; before hello it remains held |
| Pong delivery | Oldest unexpired FIFO record; expired positions consume late pongs silently |
| Cancel | Intent selected before settlement; complete wire frame before sending, once, with control credit |
| Shutdown | Only this public connection, after eligible cancel, once |
| Output resume | Finish the existing line before any other line; timers and relay reads continue |
| Non-EOF drain | Settle outstanding IDs and complete buffered request lines within the total bound |
| Wire retirement | Disarm settlement expiry; retire MCP ID independently after delivery/suppression |

Retained state is one primary, one local refusal, two ping records, a dedicated initialize output slot during startup, and one terminal-only refusal slot. Each slot is retired on delivery/suppression and, where applicable, wire settlement. Input processing yields between lines. Output never queues without its record reservation. The primary may retain one encoded frame, at most 65540 bytes including its prefix, behind a completing control write; cancellation or drain discards an unwritten frame locally. Oversized input scanning retains only bounded key/ID tokens and nesting counters. Wire and stdout buffers are disposed on close.

The client emits no -32000 or -32001 and only fixed errors. A process crash, SIGKILL, dead stdout, or keepalive-triggered teardown during an admitted call can still leave the SDK to synthesize a transport error. Hermes must be configured with timeout 120 and must not mark this server parallel-safe. A dead client is noticed on the next call or keepalive. Installed uid and SDK parity evidence remains separate from fixture acceptance.

### Catalog v2 ordinary outcomes

Must match `HERMES_TOOL_OUTCOMES` in `server/src/hermes-memory-bridge/public-results.ts`. These tool results carry content without `isError`; the fixed wording is part of the client contract.

| Outcome | Message |
|---|---|
| denied | Request denied. |
| unavailable, signing or export not built | This is not available yet; nothing was done. |
| unavailable | Sanctuary could not take this request right now; nothing was done. |
| unconfirmed | I could not confirm whether this completed. |

`memory_get` returns `denied` when the passage is not found, including an id outside the owner scope.

Recall bounds per-call work after the key listing: candidate and text-unit ceilings, three retained passages and a four-second wall budget. Abort and wall budget are checked before listing, but the key enumeration itself is not bounded by those ceilings. A stalled storage read can outlast the wall budget. Per-call cancellation does not abort the scan; the wall budget still applies.

`sign_statement` and `export_memory` validate arguments but perform no operation. `protection_rules` is refused. No owner channel, socket, frame, hold protocol or evidence frame is provided by this slice.

The shim passes validated bridge results through unchanged. Its own transport and protocol faults remain JSON-RPC errors: busy (-32003), unavailable (-32004), deadline (-32005), parse and params faults, and the relay's own busy or invalid-response error frames. A later plugin slice owns their mapping. Bridge refusals do not produce those transport faults.
