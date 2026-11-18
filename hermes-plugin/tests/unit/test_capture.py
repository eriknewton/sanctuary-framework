"""Completed-turn capture through the provider, against the real client and a scripted shim."""
from __future__ import annotations
import json
import logging
import selectors
import sys
import threading
import time
import types
import unittest
from unittest.mock import Mock, patch
from . import test_client as fixture

c = fixture.c
ROOT = fixture.ROOT
TOOL_MS = fixture.TOOL_MS
PREFETCH_MS = fixture.PREFETCH_MS
WAIT_SECONDS = fixture.WAIT_SECONDS
# Must match CAPTURE_TAG in hermes-plugin/sanctuary_memory/__init__.py.
CAPTURE_TAG = "turn-capture"
# Must match CAPTURE_STATUS_LINE in hermes-plugin/sanctuary_memory/__init__.py; worded to stay true for every cause.
STATUS_LINE = "An earlier message may not have been saved to memory automatically."
# Must match CAPTURE_INCOMPLETE_LOG in hermes-plugin/sanctuary_memory/__init__.py; fixed and content-free.
INCOMPLETE_LOG = "Sanctuary automatic save did not complete; it was not retried."
FACT = "FYI, the Lisbon demo for Jamie is set for Thursday at 3pm."
SECOND_FACT = "The Porto review moved to Monday at 9am."
TOKEN = "never-sent-token-7d41"
SAVED = c.OUTCOMES["saved"]
# Half a capture deadline (300 ms) absorbs thread scheduling on a loaded runner. A bounded wait ends at its deadline, so
# only the waiter's wake-up and its classification under the client lock fall inside the slack; an unbounded wait ends
# no sooner than the three-deadline stall (1800 ms), twice the 900 ms bound, so the slack cannot hide one.
SCHEDULING_SLACK_SECONDS = TOOL_MS / 2000
# Gateway-built turns, each exactly as hermes-agent 0.17.0 writes it; every one is skipped whole. Their sources are the
# rows of ENRICHMENT_MARKERS in hermes-plugin/sanctuary_memory/__init__.py.
ENRICHED_TURNS = (
    '[Replying to: "Lunch on Friday?"]\n\nThat works for me.',  # reply quote
    "[Jamie] The demo moved to Friday.",  # another sender in a shared session
    "Earlier channel text\n\n[New message]\nThe demo moved to Friday.",  # channel backfill
    "[The user sent an image~ Here's what I can see:\na whiteboard]\n[If you need a closer look, use vision_analyze ~]\n\nNotes.",  # vision text
    "[The user sent a voice message: /tmp/voice.ogg (duration: 0:04)]\n\nPlease file this.",  # voice note
    "[The user sent a text document: 'plan.txt'. Its content has been included below.]\n\nplan body",  # document note
    "Keep this with the plan\n\n--- Attached Context ---\n\nplan body",  # an @ reference expanded
    "--- Attached Context ---\n\nplan body",  # a message that was only a reference, after Hermes strips it
    "Keep this\n\n--- Context Warnings ---\n- @ context injection warning",  # an @ reference warning
    # A native image with no caption: Hermes passes the summary of its API parts, led by the image count.
    "[1 image] What do you see in this image?\n\n[Image attached at: /tmp/photo.png]",
    "[2 images]",
)
# A native image with a caption: Hermes passes the bare caption, so the caption is captured and the image is not.
IMAGE_CAPTION = "Our new office"


class Untouchable:
    """Any read of this value raises, so a provider that inspected it could not capture."""
    def __getattribute__(self, name):
        raise AssertionError("capture read assistant or tool content")


def load_provider(test):
    memory = types.ModuleType("agent.memory_provider")
    memory.MemoryProvider = type("MemoryProvider", (), {})
    patches = patch.dict(sys.modules, {"agent.memory_provider": memory, "sanctuary_hermes_client": c})
    patches.start()
    test.addCleanup(patches.stop)
    module = fixture.load_entry(ROOT / "sanctuary_memory/__init__.py", "capture_fixture")
    # Expected capture warnings stay out of the suite output; assertLogs still observes them.
    quiet, logger = logging.NullHandler(), logging.getLogger(module.__name__)
    logger.addHandler(quiet)
    test.addCleanup(logger.removeHandler, quiet)
    return module


class CaptureRuleTests(unittest.TestCase):
    """Which turns are captured, with mock clients; no process is spawned."""

    def setUp(self):
        self.module = load_provider(self)
        self.capture = Mock()
        self.capture.call.return_value = SAVED
        self.module._capture_client = self.capture
        self.foreground = Mock()
        self.foreground.prefetch.return_value = fixture.RECALLED["context"]
        shared = patch.object(c, "get_client", return_value=self.foreground)
        shared.start()
        self.addCleanup(shared.stop)

    def provider(self, **kwargs):
        provider = self.module.SanctuaryMemory()
        provider.initialize("session", hermes_home="/nonexistent", **({"platform": "telegram", "agent_context": "primary"} | kwargs))
        return provider

    def captured(self, text, **kwargs):
        self.capture.call.reset_mock()
        self.assertIsNone(self.provider(**kwargs).sync_turn(text, "assistant reply", session_id="session", messages=[]))
        return [call.args for call in self.capture.call.call_args_list]

    def test_plain_turn_is_captured_once_with_tag_and_taint(self):
        self.assertEqual(self.captured(FACT), [("memory_insert", {"text": FACT, "taint": "user_content", "tags": [CAPTURE_TAG]})])
        self.capture.connect_background.assert_called_once_with()
        kwargs = self.capture.call.call_args.kwargs
        self.assertIs(kwargs["bound_send"], True)
        self.assertLessEqual(kwargs["deadline"] - time.monotonic(), self.module.CAPTURE_DEADLINE_MS / 1000)

    def test_non_text_and_whitespace_turns_are_skipped(self):
        for value in (None, 7, b"bytes", ["list"], {"text": FACT}, "", " ", "\n\t \r\n"):
            with self.subTest(value=value):
                self.assertEqual(self.captured(value), [])
        self.assertEqual(len(self.captured(" " + FACT + "\n")), 1, "the same setup captures plain text")

    def test_questions_are_skipped(self):
        for text in ("When is the Lisbon demo?", "Is it Thursday?  \n", "?"):
            with self.subTest(text=text):
                self.assertEqual(self.captured(text), [])
        self.assertEqual(len(self.captured("Why? Because the venue moved.")), 1)

    def test_every_enrichment_marker_row_skips(self):
        for kind, marker, source in getattr(self.module, "ENRICHMENT_MARKERS", ()):
            self.assertTrue(source.startswith("derived hermes-agent 0.17.0 "), source)
            if kind == "leading":
                samples = ["  " + marker + "x] note"]
            elif kind == "line":
                samples = [marker + "note", "Plain text\n" + marker + "note"]
            else:
                samples = ["[3 images] note", "  [1 image]"]
            for sample in samples:
                with self.subTest(kind=kind, sample=sample):
                    self.assertEqual(self.captured(sample), [])
        self.assertEqual(len(self.captured("A note about images and context")), 1, "the same setup captures plain text")
        # The image count is a marker only where Hermes writes it, first; a sentence that mentions one is plain text.
        for text in ("See the diagram in [1 image] from the notes.", "Notes\n[2 images] are in the shared folder."):
            with self.subTest(text=text):
                self.assertEqual(len(self.captured(text)), 1)

    def test_gateway_enrichment_turns_are_skipped(self):
        for text in ENRICHED_TURNS:
            with self.subTest(text=text):
                self.assertEqual(self.captured(text), [])
        self.assertEqual(len(self.captured("That works for me.")), 1, "the same setup captures plain text")

    def test_image_caption_is_captured_and_the_default_image_question_is_not(self):
        self.assertEqual(self.captured(IMAGE_CAPTION), [("memory_insert", {"text": IMAGE_CAPTION, "taint": "user_content", "tags": [CAPTURE_TAG]})])
        self.assertEqual(self.captured("[1 image] What do you see in this image?\n\n[Image attached at: /tmp/photo.png]"), [])

    def test_stated_bounds_on_forwards_and_merged_bursts(self):
        # A forward reaches capture as plain text with no origin, so it is saved as a user turn.
        forward = "Your parcel is held at the depot; confirm your address at the link."
        self.assertEqual([call[1]["text"] for call in self.captured(forward)], [forward])
        # A fact and a question Hermes merged from one burst end in "?" and are skipped together as a question.
        self.assertEqual(self.captured(SECOND_FACT + "\nCan you note that?"), [])

    def test_path_first_turn_is_captured(self):
        text = "/home/user/notes/plan.md has the final agenda."
        self.assertEqual(self.captured(text), [("memory_insert", {"text": text, "taint": "user_content", "tags": [CAPTURE_TAG]})])

    def test_only_telegram_platform_captures(self):
        for platform in (None, "", "cli", "cron", "discord", "slack", "whatsapp", "Telegram", "telegram ", " telegram"):
            with self.subTest(platform=platform):
                self.assertEqual(self.captured(FACT, platform=platform), [])
        self.assertEqual(len(self.captured(FACT, platform="telegram")), 1)
        self.module._capture_client = None
        constructed = []
        with patch.object(c, "Client", side_effect=lambda *a, **k: constructed.append(k) or Mock()):
            provider = self.module.SanctuaryMemory()
            provider.initialize("session", hermes_home="/nonexistent", platform="cli", agent_context="primary")
            provider.sync_turn(FACT, "assistant reply", session_id="session", messages=[])
        self.assertEqual(constructed, [], "a session that never captures opened a capture connection")

    def test_absent_platform_captures_nothing(self):
        provider = self.module.SanctuaryMemory()
        provider.initialize("session", hermes_home="/nonexistent", agent_context="primary")
        provider.sync_turn(FACT, "assistant reply", session_id="session", messages=[])
        self.capture.call.assert_not_called()
        provider.initialize("session", hermes_home="/nonexistent", agent_context="primary", platform="telegram")
        provider.sync_turn(FACT, "assistant reply", session_id="session", messages=[])
        self.assertEqual(self.capture.call.call_count, 1, "the same provider captures once the platform is telegram")

    def test_only_primary_agent_context_captures(self):
        for context in (None, "", "subagent", "cron", "flush", "Primary"):
            with self.subTest(context=context):
                self.assertEqual(self.captured(FACT, agent_context=context), [])
        self.assertEqual(len(self.captured(FACT, agent_context="primary")), 1)
        self.capture.call.reset_mock()
        provider = self.module.SanctuaryMemory()
        provider.initialize("session", hermes_home="/nonexistent", platform="telegram")
        provider.sync_turn(FACT, "assistant reply", session_id="session", messages=[])
        self.capture.call.assert_not_called()

    def test_assistant_and_tool_content_are_never_read(self):
        provider = self.provider()
        provider.sync_turn(FACT, Untouchable(), session_id="session", messages=Untouchable())
        self.assertEqual([call.args[1]["text"] for call in self.capture.call.call_args_list], [FACT])

    def test_oversize_turn_is_skipped_whole_and_matches_the_client_check(self):
        args = {"text": "", "taint": "user_content", "tags": [CAPTURE_TAG]}
        # Computed independently of the client: the request line a call would send, with the shim's 128-character id.
        envelope = json.dumps({"jsonrpc": "2.0", "id": "0" * 128, "method": "tools/call",
                               "params": {"name": "memory_insert", "arguments": args}}, separators=(",", ":"))
        fitting = "a" * (c.MAX_STDIO_LINE_BYTES - len(envelope) - len("\n"))
        self.assertEqual(self.captured(fitting + "a"), [])
        self.assertEqual([call[1]["text"] for call in self.captured(fitting)], [fitting], "a fitting turn is sent whole")
        # The client's own admission applies the same check: the oversize turn would be refused unsent.
        with patch.object(c.subprocess, "Popen", side_effect=AssertionError("spawn")):
            self.assertEqual(c.Client().call("memory_insert", {**args, "text": fitting + "a"}), c.OUTCOMES["denied"])

    def test_failed_capture_never_raises_or_retries(self):
        for outcome in ("denied", "unavailable", "unconfirmed"):
            with self.subTest(outcome=outcome):
                self.capture.call.return_value = c.OUTCOMES[outcome]
                with self.assertLogs(self.module.__name__, "WARNING") as logs:
                    self.assertEqual(len(self.captured(FACT)), 1)
                self.assertEqual(logs.output, ["WARNING:" + self.module.__name__ + ":" + INCOMPLETE_LOG])
        self.capture.call.side_effect = RuntimeError(FACT)
        with self.assertLogs(self.module.__name__, "WARNING") as logs:
            self.assertEqual(len(self.captured(FACT)), 1)
        self.assertNotIn(FACT, "".join(logs.output))

    def test_status_line_set_when_unsaved_and_cleared_on_next_saved(self):
        provider = self.provider()
        context = fixture.RECALLED["context"]
        self.assertEqual(provider.prefetch("query"), context)
        for failure in (c.OUTCOMES["unavailable"], c.OUTCOMES["unconfirmed"], c.OUTCOMES["denied"], RuntimeError("fixture")):
            with self.subTest(failure=failure):
                self.capture.call.side_effect = failure if isinstance(failure, Exception) else None
                self.capture.call.return_value = None if isinstance(failure, Exception) else failure
                provider.sync_turn(FACT, "assistant reply", session_id="session", messages=[])
                self.assertEqual(provider.prefetch("query"), STATUS_LINE + "\n" + context)
                self.foreground.prefetch.return_value = ""
                self.assertEqual(provider.prefetch("query"), STATUS_LINE)
                self.foreground.prefetch.return_value = context
                # A skipped turn is not a capture attempt and leaves the line as it was.
                provider.sync_turn("Is it Thursday?", "assistant reply", session_id="session", messages=[])
                self.assertEqual(provider.prefetch("query"), STATUS_LINE + "\n" + context)
                # A session that never captures is never told about automatic saving.
                self.assertEqual(self.provider(platform="cli").prefetch("query"), context)
                self.capture.call.side_effect = None
                self.capture.call.return_value = SAVED
                provider.sync_turn(SECOND_FACT, "assistant reply", session_id="session", messages=[])
                self.assertEqual(provider.prefetch("query"), context)

    def test_status_line_belongs_to_the_session_whose_capture_failed(self):
        failed, other = self.provider(), self.provider()
        context = fixture.RECALLED["context"]
        self.capture.call.return_value = c.OUTCOMES["unconfirmed"]
        failed.sync_turn(FACT, "assistant reply", session_id="one", messages=[])
        self.assertEqual(failed.prefetch("query"), STATUS_LINE + "\n" + context)
        self.assertEqual(other.prefetch("query"), context, "another chat was told about this chat's capture")
        # A saved capture in another chat leaves this chat's line in place.
        self.capture.call.return_value = SAVED
        other.sync_turn(SECOND_FACT, "assistant reply", session_id="two", messages=[])
        self.assertEqual(failed.prefetch("query"), STATUS_LINE + "\n" + context)
        failed.sync_turn(SECOND_FACT, "assistant reply", session_id="one", messages=[])
        self.assertEqual(failed.prefetch("query"), context)

    def test_prompt_is_honest_for_capturing_and_other_sessions(self):
        capturing, other = self.provider().system_prompt_block(), self.provider(platform="cli").system_prompt_block()
        honesty = "Never say something was saved unless remember returned saved in this turn."
        for clause in ("may be saved to memory automatically after the turn ends",
                       "You are told when automatic saving may have failed; otherwise you cannot tell whether a given message was saved.",
                       "attachments themselves are never saved though a caption the user typed with one may be", honesty):
            self.assertIn(clause, capturing)
        self.assertIn(honesty, other)
        self.assertIn("Save memories with remember.", other)
        self.assertNotIn("automatically", other)
        self.assertTrue(c.REMEMBER_SCHEMA["description"].endswith("Never say something was saved unless this returned saved."))

    def test_capture_uses_its_own_client_and_a_prefetch_length_deadline(self):
        self.module._capture_client = None
        self.assertEqual(getattr(self.module, "CAPTURE_DEADLINE_MS", None), c.RECALL_PREFETCH_BUDGET_MS)
        capture = self.module.capture_client()
        try:
            self.assertIsInstance(capture, c.Client)
            self.assertIsNot(capture, c.get_client())
            self.assertIs(self.module.capture_client(), capture)
            self.assertEqual(capture.tool_seconds, self.module.CAPTURE_DEADLINE_MS / 1000)
        finally:
            capture.close()


class CaptureTransportTests(unittest.TestCase):
    """Capture over the real client and scripted shims: frames, faults and a stalled insert."""
    setUp_client = fixture.ClientTests.setUp
    client = fixture.ClientTests.client
    records = fixture.ClientTests.records

    def setUp(self):
        self.setUp_client()
        self.module = load_provider(self)
        deadline = patch.object(self.module, "CAPTURE_DEADLINE_MS", TOOL_MS, create=True)
        deadline.start()
        self.addCleanup(deadline.stop)

    def provider(self, foreground, capture):
        self.module._capture_client = capture
        shared = patch.object(c, "get_client", return_value=foreground)
        shared.start()
        self.addCleanup(shared.stop)
        provider = self.module.SanctuaryMemory()
        provider.initialize("session", hermes_home="/nonexistent", platform="telegram", agent_context="primary")
        # Initialization connects both; connecting again here is a no-op that keeps each test's own assertions reachable.
        foreground.connect_background()
        capture.connect_background()
        self.assertTrue(foreground.ready.wait(WAIT_SECONDS))
        self.assertTrue(capture.ready.wait(WAIT_SECONDS))
        return provider

    def inserts(self):
        return [row for row in self.records() if row.get("name") == "memory_insert"]

    def test_exactly_one_tagged_frame_per_accepted_turn(self):
        self.data["record_lines"] = True
        provider = self.provider(self.client(), self.client())
        third = "The Faro trip is booked for May."
        turns = [FACT, "Is it Thursday?", SECOND_FACT, '[Replying to: "x"]\n\ny', third, "   "]
        for text in turns:
            provider.sync_turn(text, "reply " + TOKEN, session_id="session", messages=[{"role": "tool", "content": TOKEN}])
        self.assertEqual([(row["taint"], row["tags"]) for row in self.inserts()], [("user_content", [CAPTURE_TAG])] * 3)
        # Which turns produced a frame, by their text and in order, not only how many.
        frames = [json.loads(row["line"])["params"]["arguments"] for row in self.records()
                  if "line" in row and json.loads(row["line"]).get("params", {}).get("name") == "memory_insert"]
        self.assertEqual([frame["text"] for frame in frames], [FACT, SECOND_FACT, third])

    def test_turn_tokens_never_reach_a_frame(self):
        self.data["record_lines"] = True
        provider = self.provider(self.client(), self.client())
        messages = [{"role": "assistant", "content": TOKEN, "tool_calls": [{"function": {"name": "read_file", "arguments": TOKEN}}]},
                    {"role": "tool", "content": "fetched page " + TOKEN}]
        provider.sync_turn(FACT, "Noted. " + TOKEN, session_id="session", messages=messages)
        lines = [row["line"] for row in self.records() if "line" in row]
        self.assertEqual(sum("memory_insert" in line and FACT in line for line in lines), 1)
        self.assertFalse(any(TOKEN in line for line in lines))

    def test_unsaved_outcomes_send_once_and_never_retry(self):
        for step in ({"value": c.OUTCOMES["unavailable"]}, {"value": c.OUTCOMES["denied"]}, {"value": c.OUTCOMES["unconfirmed"]},
                     {"rpc_error": {"code": -32004, "message": "Memory service unavailable. Outcome unknown."}}, {"action": "eof"}, {"action": "invalid"}):
            with self.subTest(step=step):
                self.log.unlink(missing_ok=True)
                foreground, capture = self.client([step]), self.client([step])
                provider = self.provider(foreground, capture)
                self.assertIsNone(provider.sync_turn(FACT, "reply", session_id="session", messages=[]))
                with capture.condition:
                    self.assertTrue(capture.condition.wait_for(lambda: capture.active is None, WAIT_SECONDS))
                self.assertEqual(len(self.inserts()), 1)
                self.assertTrue(provider.prefetch("query").startswith(STATUS_LINE))
                capture.close()
                foreground.close()

    def test_stalled_capture_is_bounded_and_never_queues_recall_or_remember_behind_it(self):
        marker = self.root / "stalled"
        # Three capture deadlines: the stall outlasts both the capture deadline and the prefetch budget.
        stall_seconds = 3 * TOOL_MS / 1000
        self.data.update(replies={"memory_recall": fixture.RECALLED, "memory_insert": fixture.SAVED},
                         tagged_stall={"marker": str(marker), "seconds": stall_seconds})
        provider = self.provider(self.client(), self.client())
        results, finished = [], []
        started = time.monotonic()
        worker = threading.Thread(target=lambda: (results.append(provider.sync_turn(FACT, "reply", session_id="session", messages=[])),
                                                  finished.append(time.monotonic())))
        worker.start()
        self.addCleanup(worker.join, WAIT_SECONDS)
        deadline = time.monotonic() + WAIT_SECONDS
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(PREFETCH_MS / 1000)
        self.assertTrue(marker.exists(), "the capture frame never reached the shim")
        # While capture stalls, recall and remember on the shared client finish inside their own budgets. Each fake shim
        # answers alone, so this shows only that nothing queues behind capture in this process; the bridge's single
        # insert slot is witnessed against the real bridge in server/test/hermes-plugin/capture-remember-contention.test.ts.
        begun = time.monotonic()
        self.assertEqual(provider.prefetch("query"), fixture.RECALLED["context"])
        self.assertLess(time.monotonic() - begun, 2 * PREFETCH_MS / 1000)  # The same bound the client tier uses for a prefetch.
        begun = time.monotonic()
        self.assertEqual(json.loads(provider.handle_tool_call("remember", {"text": "A deliberate note."})), SAVED)
        self.assertLess(time.monotonic() - begun, TOOL_MS / 1000)
        worker.join(WAIT_SECONDS)
        self.assertEqual(results, [None])
        # The capture thread's own wait, measured where it ends: the capture deadline plus scheduling only.
        self.assertLess(finished[0] - started, TOOL_MS / 1000 + SCHEDULING_SLACK_SECONDS)
        # The whole exchange under the same bound: the prefetch and remember above ran during the capture's wait, so they
        # extend it only if, with the marker wait, they outlast the deadline; against a fake shim they take milliseconds.
        self.assertLess(time.monotonic() - started, TOOL_MS / 1000 + SCHEDULING_SLACK_SECONDS)
        self.assertTrue(provider.prefetch("query").startswith(STATUS_LINE))
        # The next turn's capture is admitted at once and saves inside its own deadline.
        begun = time.monotonic()
        provider.sync_turn(SECOND_FACT, "reply", session_id="session", messages=[])
        self.assertLess(time.monotonic() - begun, TOOL_MS / 1000 + SCHEDULING_SLACK_SECONDS)
        self.assertEqual(provider.prefetch("query"), fixture.RECALLED["context"])
        tagged = [row for row in self.inserts() if row["tags"] == [CAPTURE_TAG]]
        self.assertEqual(len(tagged), 2, "the stalled frame was sent once and never resent")
        self.assertLessEqual(sum(row.get("after_stall", False) for row in self.records()), 1)
        self.assertEqual([row["tags"] for row in self.inserts() if row["tags"] != [CAPTURE_TAG]], [None])

    def test_bounded_reply_wait_ends_at_the_call_deadline(self):
        marker = self.root / "stalled"
        # The reply allowance is four call windows, as for a send made with a quarter of its window left; the stall
        # outlasts that allowance, so only the call's own deadline can end the worker's wait.
        allowance_ms = 4 * TOOL_MS
        self.data.update(tagged_stall={"marker": str(marker), "seconds": (allowance_ms + TOOL_MS) / 1000})
        capture = self.client(tool_timeout_ms=allowance_ms)
        capture.connect_background()
        self.assertTrue(capture.ready.wait(WAIT_SECONDS))
        started = time.monotonic()
        args = {"text": FACT, "taint": "user_content", "tags": [CAPTURE_TAG]}
        self.assertEqual(capture.call("memory_insert", args, deadline=started + TOOL_MS / 1000, bound_send=True), c.OUTCOMES["unconfirmed"])
        self.assertTrue(marker.exists(), "the capture frame never reached the shim")
        # Teardown after the deadline is at most five exit graces: leader wait, group check, SIGKILL group check,
        # leader reap and reader join, each capped at the fixture's exit_ms = PREFETCH_MS.
        teardown_seconds = 5 * PREFETCH_MS / 1000
        with capture.condition:
            released = capture.condition.wait_for(lambda: capture.active is None,
                                                  started + TOOL_MS / 1000 + teardown_seconds + SCHEDULING_SLACK_SECONDS - time.monotonic())
        self.assertTrue(released, "the worker held the connection past the call's deadline")
        self.assertLess(time.monotonic() - started, allowance_ms / 1000)
        # Nothing was resent, and the next call is served on a fresh shim.
        self.assertEqual(capture.call("memory_insert", fixture.INSERT), SAVED)
        self.assertEqual(len(self.inserts()), 2)
        self.assertEqual(sum(row.get("after_stall", False) for row in self.records()), 0)
        capture.close()


class BoundedSendTests(unittest.TestCase):
    """A bounded call's whole wait, including a send still in progress, ends at its deadline."""
    setUp = fixture.ClientTests.setUp
    client = fixture.ClientTests.client
    records = fixture.ClientTests.records
    insert_count = fixture.ClientTests.insert_count

    def test_bounded_call_returns_at_deadline_while_its_send_is_held(self):
        client = self.client()
        client.connect_background()
        self.assertTrue(client.ready.wait(WAIT_SECONDS))
        fd = client.process.stdin.fileno()
        original_write, original_select = c.os.write, selectors.DefaultSelector.select
        first_byte, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)

        def partial_write(target, data):
            # Accept one byte of the frame first, so the call is in its sending state with bytes delivered.
            if target == fd and not first_byte.is_set():
                first_byte.set()
                return original_write(target, data[:1])
            return original_write(target, data)

        def held_select(selector, timeout=None):
            # After the first byte the writer waits for the pipe outside the lock, as a stalled reader makes it.
            if first_byte.is_set() and not release.is_set() and any(key.fd == fd for key in selector.get_map().values()):
                if not release.wait(WAIT_SECONDS):
                    raise OSError("coordination expired")
            return original_select(selector, timeout)

        values = []
        with patch.object(c.os, "write", partial_write), patch.object(selectors.DefaultSelector, "select", held_select):
            started = time.monotonic()
            thread = threading.Thread(target=lambda: values.append(client.call(
                "memory_insert", fixture.INSERT, deadline=started + TOOL_MS / 1000, bound_send=True)))
            thread.start()
            try:
                thread.join(TOOL_MS / 1000 + SCHEDULING_SLACK_SECONDS)
                self.assertFalse(thread.is_alive(), "a bounded caller waited past its deadline for a held send")
                self.assertEqual(values, [c.OUTCOMES["unconfirmed"]])
                with client.condition:
                    self.assertEqual(client.active.state, "sending")
            finally:
                release.set()
                thread.join(WAIT_SECONDS)
            with client.condition:
                self.assertTrue(client.condition.wait_for(lambda: client.active is None, WAIT_SECONDS))
        # Past its deadline the writer ends the shim holding the partial frame; nothing is resent, and the next call is served.
        self.assertEqual(client.call("memory_insert", fixture.INSERT), SAVED)
        self.assertEqual(self.insert_count(), 1)
        self.assertEqual(sum(row.get("event") == "spawn" for row in self.records()), 2)


if __name__ == "__main__":
    unittest.main()
