"""Persistent memory through the Sanctuary bridge."""
from __future__ import annotations

import _imp
import atexit
import importlib.util
import json
import logging
from pathlib import Path
import re
import sys
import threading
from agent.memory_provider import MemoryProvider

logger = logging.getLogger(__name__)


def _client_module():
    # Both plugin loaders use one module identity so all calls share one shim.
    _imp.acquire_lock()
    try:
        if "sanctuary_hermes_client" in sys.modules:
            return sys.modules["sanctuary_hermes_client"]
        path = Path(__file__).resolve().parent.parent / "sanctuary" / "sanctuary_client.py"
        spec = importlib.util.spec_from_file_location("sanctuary_hermes_client", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules["sanctuary_hermes_client"] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            sys.modules.pop("sanctuary_hermes_client", None)
            raise
        return module
    finally:
        _imp.release_lock()


_shared = _client_module()

# Must match CAPTURE_TAG in hermes-plugin/tests/unit/test_capture.py and server/test/hermes-plugin/hermes-default-acceptance.test.ts.
# The tag also satisfies SDW_IDENTIFIER_PATTERN in server/src/sdw/grammar.ts, which the bridge applies to every insert tag.
CAPTURE_TAG = "turn-capture"
# Capture runs only on the platform the install was reviewed for, a Telegram chat with one sender; any other value
# captures nothing, and enabling another platform or a second sender needs a fresh review first.
CAPTURE_PLATFORM = "telegram"
# Defense in depth: hermes-agent 0.17.0 always passes "primary" (derived agent/agent_init.py:1171). Subagents, cron,
# background review and the other helper agents are excluded because Hermes builds them without memory, so they never
# reach this provider; the check keeps a future Hermes that passes another context from capturing its text.
CAPTURE_AGENT_CONTEXT = "primary"
# Gateway enrichment markers. A turn carrying one is skipped whole, never stripped, because the enrichment
# (quoted replies, vision and voice notes, other senders, backfill, attached files) is text the user did not write.
# Rows are (kind, marker, source): "leading" matches the first non-space characters, "line" matches at the start
# of the text or of any line, and "pattern" is a regular expression matched at the start of the stripped text, where
# its producer always puts it; searched anywhere it would skip a plain sentence that mentions "[1 image]".
# These anchors are valid only for the reviewed Hermes column; the install refuses any other Hermes version,
# and a new Hermes version must re-derive this table before capture runs on it.
ENRICHMENT_MARKERS = (
    # The leading row also keeps out the turns that carry tool output or text Hermes wrote, only because Hermes 0.17.0
    # opens each with "["; a re-derivation must check every source below, not only the enrichment ones.
    ("leading", "[", "derived hermes-agent 0.17.0 gateway/run.py:8610 (reply quote), :8423 (sender prefix), "
                     ":1771, :8542, :8561 (document, audio and video notes), :12625 (vision text), :12680, :12716 "
                     "(voice notes); tool output: gateway/run.py:2146, :2153 and tools/process_registry.py:1630, :1637, "
                     ":1668 (process watch and completion notices with command output), :1580 (async delegation result); "
                     "synthetic turns: gateway/run.py:5886 (CLI handoff), :15705, :15716 (interruption notes), "
                     "gateway/slash_commands.py:1356 (model switch), :3500 (skills reload), hermes_cli/goals.py:72, :83, "
                     ":759, :771 (goal and kanban continuations), gateway/sticker_cache.py:112, :121, :124 (stickers), "
                     "gateway/platforms/telegram.py:6022 (location pin)"),
    ("line", "[New message]\n", "derived hermes-agent 0.17.0 gateway/run.py:8429"),
    ("line", "--- Attached Context ---\n", "derived hermes-agent 0.17.0 agent/context_references.py:193"),
    ("line", "--- Context Warnings ---\n", "derived hermes-agent 0.17.0 agent/context_references.py:191"),
    # Defense only: the combined caption-and-hint text lives in the API parts. With a caption Hermes passes the bare
    # caption (gateway/run.py:9365, :15777), which is captured; with none it passes a summary led by "[".
    ("line", "[Image attached", "derived hermes-agent 0.17.0 agent/image_routing.py:522-523"),
    ("pattern", r"\[[1-9][0-9]* images?\]", "derived hermes-agent 0.17.0 agent/codex_responses_adapter.py:169"),
)


def enriched(text):
    stripped = text.lstrip()
    for kind, marker, _source in ENRICHMENT_MARKERS:
        if kind == "leading" and stripped.startswith(marker):
            return True
        if kind == "line" and (stripped.startswith(marker) or "\n" + marker in text):
            return True
        if kind == "pattern" and re.match(marker, stripped):
            return True
    return False


# Stated bounds on what the text alone can show, for hermes-agent 0.17.0 on Telegram:
# - Hermes merges messages sent in one quick burst (derived gateway/platforms/telegram.py:6076), so a fact followed
#   at once by a question arrives as one turn ending in "?" and is skipped as a question.
# - Hermes drops a forwarded message's origin, so a forward arrives as plain text and is saved as a user turn.
# - A /background prompt runs a memory-bearing Telegram agent (derived gateway/run.py:11041-11070) and is captured;
#   it is the owner's own text.
def capturable(text):
    """Return whether a completed user turn's text is captured; every refusal here is a skip, never an edit."""
    if not isinstance(text, str) or not text.strip():
        return False
    # A question is not a fact to keep, and capturing questions would crowd recall.
    if text.rstrip().endswith("?"):
        return False
    return not enriched(text)


# Prompt text is guidance, not enforcement: capture is what makes saving true, and the model is told only what holds.
# Must match the skips in capturable(): plain text, not a question, no enrichment marker. The automatic-save wording and
# the honesty clause must match INSTRUCTIONS in server/src/wrap/hermes-posture.ts.
# A caption sent with a natively attached image reaches capture as plain text (Hermes passes the bare caption),
# so it may be saved; the image itself never is.
CAPTURE_PROMPT = ("Plain messages from the user may be saved to memory automatically after the turn ends; questions "
                  "and quoted replies are not, attachments themselves are never saved though a caption the user typed "
                  "with one may be. You are told when automatic saving may have failed; otherwise you cannot tell "
                  "whether a given message was saved. "
                  "Call remember only for a note the user asks you to keep in words other than theirs, or from a message "
                  "that is never saved automatically. Never say something was saved unless remember returned saved in "
                  "this turn. Matching saved memories appear in the memory context.")
REMEMBER_PROMPT = ("Memory is persistent. Save memories with remember. Never say something was saved unless remember "
                   "returned saved in this turn. Matching saved memories appear in the memory context.")
# A fixed, content-free line: the log never names the turn, the outcome detail or the skip that applied.
CAPTURE_INCOMPLETE_LOG = "Sanctuary automatic save did not complete; it was not retried."
# Must match STATUS_LINE in hermes-plugin/tests/unit/test_capture.py. Worded to stay true for every cause (a refusal,
# an unavailable bridge, an expired wait, an exception, or an unconfirmed send the bridge may still have committed)
# and every timing: the next turn's prefetch can run while that turn's own capture has not happened yet.
CAPTURE_STATUS_LINE = "An earlier message may not have been saved to memory automatically."
# Hermes runs every provider's sync_turn on one memory worker, one turn after another. Capture's whole wait
# (admission, connection, a send still in progress, and the reply) ends CAPTURE_DEADLINE_MS after it starts,
# and the capture client's own tool timeout is the same value, so its worker also stops waiting for a sent
# insert's reply at send time plus CAPTURE_DEADLINE_MS and ends that shim. 5000 ms = RECALL_PREFETCH_BUDGET_MS:
# a stalled capture holds the memory worker no longer than one recall window, so the next turn's capture is
# admitted at most 5 s after this one started. Its send can still wait behind the bounded shim teardown; if that
# outlasts its own deadline it answers unavailable, unsent, and the status line reports it.
# Must match captureDeadlineMs in server/test/hermes-plugin/capture-remember-contention.test.ts.
CAPTURE_DEADLINE_MS = _shared.RECALL_PREFETCH_BUDGET_MS
_capture_client = None
_capture_lock = threading.Lock()


def capture_client():
    global _capture_client
    with _capture_lock:
        if _capture_client is None:
            # Capture owns a second Client and shim connection, so a slow capture never queues a prefetch or remember
            # behind it in this process. The bridge still admits one insert at a time per bridge process: while a
            # capture insert is in flight there, including after its caller gave up and until the bridge finishes it,
            # a remember or the next capture is answered unavailable at once. Nothing is lost silently or committed
            # twice, recall is unaffected, and the model is told. Must stay within HERMES_MAX_PUBLIC_CONNECTIONS in
            # server/src/hermes-memory-bridge/constants.ts: one foreground and one capture connection per Hermes process.
            _capture_client = _shared.Client(tool_timeout_ms=CAPTURE_DEADLINE_MS)
            atexit.register(_capture_client.close)
        return _capture_client


class SanctuaryMemory(MemoryProvider):
    name = "sanctuary_memory"
    _platform = None
    _agent_context = None
    # Set while this provider's last attempted capture did not return saved. It lives on the provider, one per Hermes
    # agent session, so one chat's failed capture never speaks for another chat; a bool store is atomic in CPython.
    _capture_unsaved = False

    def is_available(self):
        try:
            return _shared.resolve_command() is not None
        except Exception:
            return False

    def initialize(self, session_id="", **kwargs):
        self._platform = kwargs.get("platform")
        self._agent_context = kwargs.get("agent_context")
        try:
            _shared.get_client().connect_background()
            if self._captures():
                capture_client().connect_background()
        except Exception:
            return None

    def system_prompt_block(self):
        # Sessions that never capture keep remember as their only save path and are not told otherwise.
        return CAPTURE_PROMPT if self._captures() else REMEMBER_PROMPT

    def get_tool_schemas(self):
        return [_shared.REMEMBER_SCHEMA]

    def handle_tool_call(self, tool_name, args, **kwargs):
        try:
            if tool_name != "remember" or not isinstance(args, dict) or not isinstance(args.get("text"), str):
                return _shared.pair("denied")
            return json.dumps(_shared.get_client().call("memory_insert", {"text": args["text"], "taint": "user_content"}))
        except Exception:
            return _shared.pair("unavailable")

    def prefetch(self, query, **kwargs):
        try:
            deadline = _shared.time.monotonic() + _shared.RECALL_PREFETCH_BUDGET_MS * _shared.SECONDS_PER_MS
            context = _shared.get_client().prefetch(query, deadline=deadline)
        except Exception:
            context = ""
        # Automatic saving never pauses, so the model is told when a capture may not have saved rather than
        # left to infer a save from silence; the line clears on this session's next saved capture.
        if self._captures() and self._capture_unsaved:
            return CAPTURE_STATUS_LINE + "\n" + context if context else CAPTURE_STATUS_LINE
        return context

    def _captures(self):
        return self._platform == CAPTURE_PLATFORM and self._agent_context == CAPTURE_AGENT_CONTEXT

    def sync_turn(self, user_content, assistant_content="", *, session_id="", messages=None):
        """Save the completed turn's user text once; never raises into Hermes and never retries."""
        try:
            if not self._captures() or not capturable(user_content):
                return None
            # Only the user turn text Hermes passes in is persisted: assistant_content and messages (tool calls,
            # tool results, fetched pages) can carry text the user never wrote, so capture never reads them.
            # The taint is pinned by the bridge and says nothing about authorship; the tag is an agent-asserted
            # label that may drive retention only, never a "you said this" display or a trust decision.
            args = {"text": user_content, "taint": "user_content", "tags": [CAPTURE_TAG]}
            # An oversized turn is skipped whole, never truncated, because a cut passage is a different statement.
            if not _shared.fits_line("memory_insert", args):
                return None
            deadline = _shared.time.monotonic() + CAPTURE_DEADLINE_MS * _shared.SECONDS_PER_MS
            # One call and no retry: after an unconfirmed outcome a second send could save the turn twice.
            result = capture_client().call("memory_insert", args, deadline=deadline, bound_send=True)
            if result.get("outcome") == "saved":
                self._capture_unsaved = False
                return None
        except Exception:
            pass
        # Any attempted capture that did not return saved, including denied and unconfirmed, sets the status line.
        self._capture_unsaved = True
        logger.warning(CAPTURE_INCOMPLETE_LOG)
        return None

    def queue_prefetch(self, *args, **kwargs):
        return None

    # Built-in memory writes and lifecycle hooks never save; only remember and completed-turn capture do.
    def on_memory_write(self, *args, **kwargs):
        return None

    def on_pre_compress(self, *args, **kwargs):
        return ""

    def shutdown(self):
        # Gateway sessions share the client; ending one provider must not close another session's transport.
        return None
