"""Bounded, process-shared transport for Hermes memory and tool results."""
from __future__ import annotations

import atexit
from collections import deque
import json
import os
from pathlib import Path
import re
import selectors
import posixpath
import shutil
import signal
import subprocess
import threading
import time

# Must match HERMES_MEMORY_TOOL_NAMES in server/src/hermes-memory-bridge/envelopes.ts; the complete catalog.
TOOL_NAMES = ("memory_insert", "memory_get", "memory_search", "memory_recall", "sign_statement", "export_memory", "protection_rules")
# Must match MAX_STDIO_LINE_BYTES in server/src/hermes-memory-client/protocol.ts: payload, envelope, id, CRLF.
MAX_STDIO_LINE_BYTES = 65536 + 35 + 128 + 2
# Must match HERMES_TOOL_TIMEOUT_MS in server/src/hermes-memory-bridge/constants.ts; two minutes.
HERMES_TOOL_TIMEOUT_MS = 120000
# Must match SHIM_CALL_DEADLINE_MS in server/src/hermes-memory-client/protocol.ts; reserve two seconds for delivery.
SHIM_CALL_DEADLINE_MS = HERMES_TOOL_TIMEOUT_MS - 2000
# Must match SHIM_CONNECT_HELLO_TIMEOUT_MS in server/src/hermes-memory-client/protocol.ts; five seconds for connection.
SHIM_CONNECT_HELLO_TIMEOUT_MS = 5000
# Must match SHIM_INITIALIZATION_TIMEOUT_MS in server/src/hermes-memory-client/protocol.ts; five seconds for initialization.
SHIM_INITIALIZATION_TIMEOUT_MS = 5000
# Must match SHIM_STDIN_EOF_EXIT_MS in server/src/hermes-memory-client/protocol.ts; two-second grace less scheduler reserve.
SHIM_STDIN_EOF_EXIT_MS = 2000 - 500
# Must match RECALL_PREFETCH_BUDGET_MS in server/src/hermes-memory-bridge/recall.ts; five seconds including admission.
RECALL_PREFETCH_BUDGET_MS = 5000
# Must match HERMES_MAX_PUBLIC_CONNECTIONS in server/src/hermes-memory-bridge/constants.ts; four public connections.
HERMES_MAX_PUBLIC_CONNECTIONS = 4
# The waiting queue uses the public connection count as its fixed capacity.
MAX_QUEUED_CALLS = HERMES_MAX_PUBLIC_CONNECTIONS
# Must match VERSIONS[0] in server/src/hermes-memory-client/protocol.ts; the preferred MCP revision.
MCP_PROTOCOL_VERSION = "2025-11-25"
# Must match CLIENT_NAME in server/src/hermes-memory-client/protocol.ts; the fixed facade name.
CLIENT_NAME = "sanctuary-hermes-memory-client"
# Must match the Sanctuary/ prefix of FIXED_SOCKET_PATH in server/src/hermes-memory-client/protocol.ts.
SANCTUARY_INSTALL_ROOT = "/Library/Application Support/Sanctuary/"
# Only insertion has an effect; a later implementation giving signing or export an effect must add them here.
EFFECT_TOOLS = ("memory_insert",)
# Must match HERMES_TOOL_OUTCOMES in server/src/hermes-memory-bridge/public-results.ts; saved is the local projection.
OUTCOMES = {
    "saved": {"outcome": "saved", "message": "Saved."},
    "denied": {"outcome": "denied", "message": "Request denied."},
    "unavailable_not_built": {"outcome": "unavailable", "message": "This is not available yet; nothing was done."},
    "unavailable": {"outcome": "unavailable", "message": "Sanctuary could not take this request right now; nothing was done."},
    "unconfirmed": {"outcome": "unconfirmed", "message": "I could not confirm whether this completed."},
}
if any(re.search(r"error|failed", value["message"] + json.dumps(value), re.I) for value in OUTCOMES.values()):
    raise ValueError("tool result messages must remain ordinary results")
# Must match HERMES_TOOLS_LIST_PAYLOAD in server/src/hermes-memory-bridge/public-results.ts.
TOOL_SCHEMAS = [
    {"name": "sign_statement", "description": "Not available yet; nothing is signed.", "parameters": {
        "type": "object", "required": ["statement"], "properties": {"statement": {"type": "string"}}, "additionalProperties": False}},
    {"name": "export_memory", "description": "Not available yet; nothing is exported.", "parameters": {
        "type": "object", "required": ["scope"], "properties": {"scope": {"type": "string", "enum": ["all"]}}, "additionalProperties": False}},
    {"name": "protection_rules", "description": "Requests are refused.", "parameters": {
        "type": "object", "properties": {}, "additionalProperties": False}},
]
REMEMBER_SCHEMA = {"name": "remember", "description": "Save a memory persistently in Sanctuary.",
                   "parameters": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}}
SECONDS_PER_MS = 1 / 1000  # Monotonic clocks use seconds; contracts use milliseconds.


def pair(name):
    return json.dumps(OUTCOMES[name])


def resolve_command():
    """Read the command written by the installer, without starting a process."""
    try:
        path = Path(__file__).resolve().parent / "shim-command.json"
        try:
            with path.open(encoding="utf-8") as stream:
                command = json.load(stream)
        except FileNotFoundError:
            executable = shutil.which("sanctuary")
            return [executable, "hermes-memory-client"] if executable else None
        # Eight argv entries cover executable, loader, entry, and fixed arguments.
        if not isinstance(command, list) or not 1 <= len(command) <= 8:
            return None
        if not all(isinstance(arg, str) and arg and "\0" not in arg for arg in command):
            return None
        if not os.path.isabs(command[0]):
            return None
        return command
    except Exception:
        return None


def normalize(text):
    text = re.sub(r"/+", "/", text.casefold().replace("\\", "/"))
    # A run of dot components is removed in one pass, preserving linear work.
    return posixpath.normpath(re.sub(r"/(?:\./)+", "/", text))


def guard(tool_name=None, args=None, **kwargs):
    try:
        # The guard is not the lock; relative paths, symlinks, paths built at run time and encoded strings are not resolved.
        if tool_name in ("remember", "sign_statement", "export_memory", "protection_rules"):
            return None
        root = normalize(SANCTUARY_INSTALL_ROOT)
        pending, seen = [args], set()
        while pending:
            value = pending.pop()
            if isinstance(value, str):
                normalized = normalize(value)
                if root + "/" in normalized or normalized.endswith(root):
                    return {"action": "block", "message": OUTCOMES["denied"]["message"]}
            elif isinstance(value, (dict, list, tuple)) and id(value) not in seen:
                seen.add(id(value))
                if isinstance(value, dict):
                    pending.extend(value.keys())
                    pending.extend(value.values())
                else:
                    pending.extend(value)
        return None
    except Exception:
        return {"action": "block", "message": OUTCOMES["denied"]["message"]}


def uncertain(name, sent):
    return OUTCOMES["unconfirmed" if sent and name in EFFECT_TOOLS else "unavailable"]


def map_reply(name, reply):
    """Accept only the bridge's complete result shapes and fixed refusal pairs."""
    try:
        if not isinstance(reply, dict):
            return uncertain(name, True)
        if "error" in reply:
            fault = reply["error"]
            if not isinstance(fault, dict) or type(fault.get("code")) is not int or not isinstance(fault.get("message"), str):
                return uncertain(name, True)
            if fault["code"] in (-32002, -32602):
                return OUTCOMES["denied"]
            if "Outcome unknown" in fault.get("message", ""):
                return uncertain(name, True)
            return OUTCOMES["unavailable"]
        result = reply["result"]
        if set(result) != {"content"} or len(result["content"]) != 1:
            return uncertain(name, True)
        content = result["content"][0]
        if set(content) != {"type", "text"} or content["type"] != "text":
            return uncertain(name, True)
        value = json.loads(content["text"])
        if value in [OUTCOMES[key] for key in ("denied", "unavailable", "unavailable_not_built", "unconfirmed")]:
            return value
        if name == "memory_insert" and set(value) == {"outcome", "inserted", "passage"}:
            passage = value["passage"]
            if value["outcome"] == "saved" and value["inserted"] is True and set(passage) == {"passage_id", "document_id"} and all(isinstance(v, str) and v for v in passage.values()):
                return OUTCOMES["saved"]
        if name == "memory_recall" and set(value) == {"outcome", "context", "passages", "truncated"}:
            if value["outcome"] == "recalled" and isinstance(value["context"], str) and type(value["truncated"]) is bool and isinstance(value["passages"], list):
                if all(isinstance(p, dict) and set(p) == {"passage_id", "created_at"} and all(isinstance(v, str) for v in p.values()) for p in value["passages"]):
                    return value
    except Exception:
        pass
    return uncertain(name, True)


class _Call:
    def __init__(self, name, args, deadline):
        self.name, self.args, self.deadline = name, args, deadline
        self.done = threading.Event()
        self.state = "waiting"
        self.accepted_bytes = 0
        self.sent = False
        self.sent_at = None
        self.abandoned = False
        self.result = OUTCOMES["unavailable"]


class Client:
    """One worker owns all sends and one bounded reader owns each shim's output."""
    def __init__(self, *, tool_timeout_ms=HERMES_TOOL_TIMEOUT_MS,
                 prefetch_budget_ms=RECALL_PREFETCH_BUDGET_MS,
                 initialization_ms=SHIM_CONNECT_HELLO_TIMEOUT_MS + SHIM_INITIALIZATION_TIMEOUT_MS,
                 exit_ms=SHIM_STDIN_EOF_EXIT_MS):
        for value, maximum in ((tool_timeout_ms, HERMES_TOOL_TIMEOUT_MS), (prefetch_budget_ms, RECALL_PREFETCH_BUDGET_MS),
                               (initialization_ms, SHIM_CONNECT_HELLO_TIMEOUT_MS + SHIM_INITIALIZATION_TIMEOUT_MS), (exit_ms, SHIM_STDIN_EOF_EXIT_MS)):
            if not isinstance(value, (int, float)) or not 0 < value <= maximum:
                raise ValueError("deadline must tighten the contract")
        self.tool_seconds = tool_timeout_ms * SECONDS_PER_MS
        self.prefetch_seconds = prefetch_budget_ms * SECONDS_PER_MS
        self.init_seconds = initialization_ms * SECONDS_PER_MS
        self.exit_seconds = exit_ms * SECONDS_PER_MS
        self.condition = threading.Condition()
        self.queue = deque()
        self.active = None
        self.worker = None
        self.reader = None
        self.process = None
        self.pending = None
        self.serial = 0
        self.stopped = False
        self.ready = threading.Event()
        self.connecting = False
        self.transport_fault = False
        self.reap_lock = threading.RLock()

    def _start_worker(self):
        if self.worker is None:
            self.worker = threading.Thread(target=self._work, name="sanctuary-client", daemon=True)
            self.worker.start()

    def connect_background(self):
        with self.condition:
            if self.stopped or self.connecting or self.ready.is_set():
                return
            self.connecting = True
            self._start_worker()
            self.condition.notify_all()

    def call(self, name, args, *, deadline=None):
        call = None
        try:
            deadline = deadline if deadline is not None else time.monotonic() + self.tool_seconds
            if not isinstance(args, dict) or name not in TOOL_NAMES:
                return OUTCOMES["denied"]
            if name == "memory_insert" and not isinstance(args.get("text"), str):
                return OUTCOMES["denied"]
            # Reserve the shim's 128-character id allowance before admission so oversized calls never spawn.
            probe = {"jsonrpc": "2.0", "id": "0" * 128, "method": "tools/call", "params": {"name": name, "arguments": args}}
            encoded = self._encode(probe)
            if len(encoded) > MAX_STDIO_LINE_BYTES:
                return OUTCOMES["denied"]
            call = _Call(name, json.loads(encoded)["params"]["arguments"], deadline)
            with self.condition:
                # A fixed FIFO waiting cap keeps repeated timed-out admission waves bounded.
                if self.stopped or len(self.queue) >= MAX_QUEUED_CALLS or time.monotonic() >= call.deadline:
                    return OUTCOMES["unavailable"]
                self.queue.append(call)
                self._start_worker()
                self.condition.notify_all()
            call.done.wait(max(0, call.deadline - time.monotonic()))
            with self.condition:
                if call.done.is_set():
                    return call.result
                # A claimed send settles its byte accounting before the caller can classify it.
                self.condition.wait_for(lambda: call.state != "sending")
                if call.done.is_set():
                    return call.result
                call.abandoned = True
                if call in self.queue:
                    self.queue.remove(call)
                return uncertain(name, call.sent)
        except (TypeError, ValueError, OverflowError, RecursionError):
            return OUTCOMES["denied"] if call is None else uncertain(name, call.sent)
        except Exception:
            return uncertain(name, call.sent if call else False)

    def prefetch(self, query, *, deadline=None):
        started = time.monotonic()
        try:
            deadline = min(deadline, started + self.prefetch_seconds) if deadline is not None else started + self.prefetch_seconds
            result = self.call("memory_recall", {"query": query}, deadline=deadline)
            if time.monotonic() > deadline:
                return ""
            return result["context"] if result.get("outcome") == "recalled" else ""
        except Exception:
            return ""

    @staticmethod
    def _encode(value):
        return (json.dumps(value, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")

    def _write(self, data, deadline, call=None):
        fd = self.process.stdin.fileno()
        offset = 0
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(fd, selectors.EVENT_WRITE)
                while offset < len(data):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise OSError("unavailable")
                    with self.condition:
                        if self.stopped:
                            raise OSError("unavailable")
                        if call is not None and call.state == "waiting":
                            # A call is written only after it is claimed under the lock; an abandoned call is never written, and an insert with any accepted byte is never reported as not done.
                            if call.abandoned or time.monotonic() >= call.deadline:
                                raise OSError("unavailable")
                            call.state = "sending"
                        elif time.monotonic() >= deadline:
                            raise OSError("unavailable")
                        try:
                            # Nonblocking write and accepted-byte accounting share the caller's classification lock.
                            written = os.write(fd, data[offset:])
                        except BlockingIOError:
                            continue
                        if written <= 0:
                            raise OSError("unavailable")
                        offset += written
                        if call is not None:
                            call.accepted_bytes += written
                            if not call.sent:
                                call.sent_at = time.monotonic()
                            call.sent = True
                            self.condition.notify_all()
        finally:
            if call is not None:
                with self.condition:
                    if call.state == "sending":
                        call.state = "sent" if call.sent else "unsent"
                    self.condition.notify_all()

    def _exchange(self, method, params, deadline, call=None):
        self.serial += 1
        request_id = self.serial
        event = threading.Event()
        pending = {"id": request_id, "event": event, "reply": None}
        with self.condition:
            self.pending = pending
        self._write(self._encode({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}), deadline, call)
        if call is not None and call.sent_at is not None:
            deadline = call.sent_at + self.tool_seconds
        if not event.wait(max(0, deadline - time.monotonic())) or pending["reply"] is None:
            raise OSError("unavailable")
        return pending["reply"]

    def _read(self, process):
        try:
            with selectors.DefaultSelector() as selector:
                fd = process.stdout.fileno()
                selector.register(fd, selectors.EVENT_READ)
                line = bytearray()
                while True:
                    with self.condition:
                        if self.process is not process:
                            return
                    if not selector.select(self.exit_seconds):
                        continue
                    with self.condition:
                        if self.process is not process:
                            return
                        try:
                            data = os.read(fd, 1)
                        except BlockingIOError:
                            continue
                    if not data or len(line) >= MAX_STDIO_LINE_BYTES:
                        raise OSError("unavailable")
                    line.extend(data)
                    if data != b"\n":
                        continue
                    reply = json.loads(line)
                    with self.condition:
                        # A reader belongs to one process generation and cannot deliver into its replacement.
                        if self.process is not process:
                            return
                        pending = self.pending
                        if not isinstance(reply, dict) or reply.get("jsonrpc") != "2.0" or type(reply.get("id")) is not int or pending is None or reply["id"] != pending["id"]:
                            raise OSError("unavailable")
                        self.pending = None
                        pending["reply"] = reply
                        pending["event"].set()
                        reply, pending = None, None
                        line.clear()
        except Exception:
            with self.condition:
                if self.process is not process:
                    return
                self.ready.clear()
                self.transport_fault = True
                self.condition.notify_all()
                if self.pending is not None:
                    self.pending["event"].set()
                    self.pending = None

    def _connect(self):
        with self.reap_lock:
            if self.stopped:
                return False
            return self._connect_locked()

    def _connect_locked(self):
        if self.ready.is_set() and self.process is not None and self.process.poll() is None:
            return True
        self._end_process()
        if self.stopped:
            return False
        command = resolve_command()
        if command is None:
            return False
        deadline = time.monotonic() + self.init_seconds
        try:
            self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=subprocess.DEVNULL, start_new_session=True, bufsize=0)
            os.set_blocking(self.process.stdin.fileno(), False)
            os.set_blocking(self.process.stdout.fileno(), False)
            self.reader = threading.Thread(target=self._read, args=(self.process,), name="sanctuary-reader", daemon=True)
            self.reader.start()
            reply = self._exchange("initialize", {"protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {},
                                   "clientInfo": {"name": CLIENT_NAME, "version": "1"}}, deadline)
            if reply.get("result", {}).get("protocolVersion") != MCP_PROTOCOL_VERSION:
                raise ValueError("unavailable")
            self._write(self._encode({"jsonrpc": "2.0", "method": "notifications/initialized"}), deadline)
            catalog = self._exchange("tools/list", {}, deadline)["result"]["tools"]
            names = [entry["name"] for entry in catalog]
            if len(names) != len(TOOL_NAMES) or set(names) != set(TOOL_NAMES):
                raise ValueError("unavailable")
            self.ready.set()
            return True
        except Exception:
            self._end_process()
            return False

    def _work(self):
        while True:
            with self.condition:
                self.condition.wait_for(lambda: self.stopped or self.transport_fault or self.connecting or self.queue)
                if self.stopped:
                    return
                fault = self.transport_fault
                self.transport_fault = False
                if fault:
                    call = None
                elif self.connecting:
                    self.connecting = False
                    call = None
                else:
                    call = self.queue.popleft()
                    self.active = call
            try:
                if fault:
                    self._end_process()
                    continue
                if call is None:
                    self._connect()
                    continue
                if time.monotonic() >= call.deadline:
                    continue
                if not self._connect():
                    continue
                if time.monotonic() >= call.deadline or call.abandoned:
                    continue
                # No request is retried or resent, including an insert with a lost reply.
                reply = self._exchange("tools/call", {"name": call.name, "arguments": call.args}, call.deadline, call)
                call.result = map_reply(call.name, reply)
            except Exception:
                if call is not None:
                    call.result = uncertain(call.name, call.sent)
                self._end_process()
            finally:
                reply = None
                if call is not None:
                    with self.condition:
                        if call.abandoned:
                            call.result = uncertain(call.name, call.sent)
                        call.state = "done"
                        call.args = None
                        self.active = None
                        call.done.set()
                        self.condition.notify_all()
                call = None

    def _group_gone(self, process):
        deadline = time.monotonic() + self.exit_seconds
        pause = threading.Event()
        while True:
            process.poll()
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            pause.wait(min(remaining, self.exit_seconds / 10))  # Ten bounded group-exit checks per grace period.

    def _end_process(self):
        with self.reap_lock:
            with self.condition:
                self.ready.clear()
                process, reader = self.process, self.reader
                if process is None:
                    return
                # End the reader generation before closing descriptors or allowing another process.
                self.process, self.reader = None, None
                self.transport_fault = False
                if self.pending is not None:
                    self.pending["event"].set()
                    self.pending = None
            try:
                try:
                    process.stdin.close()
                except OSError:
                    pass
                try:
                    process.wait(timeout=self.exit_seconds)
                except subprocess.TimeoutExpired:
                    pass
                # The group owns the lifetime even when its leader has already exited.
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                if not self._group_gone(process):
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    self._group_gone(process)
                try:
                    process.wait(timeout=self.exit_seconds)
                except subprocess.TimeoutExpired:
                    # A replacement needs a reaped leader; an unsettled generation stops admission.
                    with self.condition:
                        self.stopped = True
            finally:
                if reader is not None and reader is not threading.current_thread():
                    reader.join(self.exit_seconds)
                process.stdout.close()

    def close(self):
        with self.condition:
            self.stopped = True
            for call in self.queue:
                call.done.set()
            self.queue.clear()
            self.condition.notify_all()
        self._end_process()
        if self.worker is not None and self.worker is not threading.current_thread():
            self.worker.join(self.exit_seconds)


_client = None
_client_lock = threading.Lock()


def get_client():
    global _client
    with _client_lock:
        if _client is None:
            _client = Client()
            atexit.register(_client.close)
        return _client


def tool_handler(name):
    def handle(args, **kwargs):
        try:
            return json.dumps(get_client().call(name, args))
        except Exception:
            return pair("unavailable")
    return handle
