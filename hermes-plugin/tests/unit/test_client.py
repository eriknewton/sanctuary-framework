from __future__ import annotations
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import random
import shutil
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("client_under_test", ROOT / "sanctuary" / "sanctuary_client.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)
RECALLED = {"outcome": "recalled", "context": "  Thursday 3pm.\n", "passages": [{"passage_id": "p", "created_at": "now"}], "truncated": False}
SAVED = {"outcome": "saved", "inserted": True, "passage": {"passage_id": "p", "document_id": "d"}}
INSERT = {"text": "private saved sentence", "taint": "user_content"}
# Short fixture deadlines exercise the same production machinery without long stalls.
TOOL_MS = 600
PREFETCH_MS = 60
WAIT_SECONDS = 3  # Outer coordination bound exceeds every tightened fixture deadline.


def load_entry(path, name):
    spec = importlib.util.spec_from_file_location(name, path, submodule_search_locations=[str(path.parent)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log = self.root / "requests"
        self.scenario = self.root / "scenario"
        self.data = {"catalog": list(c.TOOL_NAMES), "log": str(self.log), "line_cap": c.MAX_STDIO_LINE_BYTES}
        self.command = [sys.executable, "-I", "-B", str(ROOT / "tests/unit/fake_shim.py"), str(self.scenario)]
        self.resolver = patch.object(c, "resolve_command", return_value=self.command)
        self.resolver.start()
        self.addCleanup(self.resolver.stop)
        self.clients = []
        self.addCleanup(lambda: [client.close() for client in self.clients])

    def client(self, steps=None, **kwargs):
        if steps is not None:
            self.data["steps"] = steps
        self.scenario.write_text(json.dumps(self.data))
        client = c.Client(tool_timeout_ms=kwargs.pop("tool_timeout_ms", TOOL_MS), prefetch_budget_ms=PREFETCH_MS,
                          initialization_ms=TOOL_MS, exit_ms=PREFETCH_MS, **kwargs)
        self.clients.append(client)
        return client

    def records(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def insert_count(self):
        return sum(row.get("name") == "memory_insert" for row in self.records())

    def wait_sent(self, client):
        with client.condition:
            self.assertTrue(client.condition.wait_for(lambda: client.active is not None and client.active.sent, WAIT_SECONDS))

    def thread_call(self, client, name="memory_insert", args=None, **kwargs):
        values = []
        thread = threading.Thread(target=lambda: values.append(client.call(name, INSERT if args is None else args, **kwargs)))
        thread.start()
        self.addCleanup(lambda: thread.join(WAIT_SECONDS))
        return thread, values

    def test_saved_projection(self):
        self.assertEqual(self.client().call("memory_insert", INSERT), c.OUTCOMES["saved"])

    def test_recalled_context_exact(self):
        client = self.client([{"value": RECALLED}])
        self.assertEqual(client.prefetch("private query"), RECALLED["context"])

    def test_fixed_pairs_verbatim(self):
        for key in ("denied", "unavailable", "unavailable_not_built", "unconfirmed"):
            with self.subTest(key=key):
                client = self.client([{"value": c.OUTCOMES[key]}])
                self.assertEqual(client.call("sign_statement", {}), c.OUTCOMES[key])
                client.close()

    def test_rpc_mapping_every_code(self):
        for name in ("memory_insert", "sign_statement"):
            for code, message in ((-32002, "denied"), (-32602, "params"), (-32004, "Memory service unavailable."),
                                  (-32004, "Memory service unavailable. Outcome unknown."), (-32005, "Outcome unknown"),
                                  (-32003, "busy"), (-32700, "parse"), (-32600, "invalid"), (-32601, "method"), (-32603, "internal")):
                with self.subTest(name=name, code=code, message=message):
                    client = self.client([{"rpc_error": {"code": code, "message": message}}])
                    expected = "denied" if code in (-32002, -32602) else "unconfirmed" if "Outcome unknown" in message and name in c.EFFECT_TOOLS else "unavailable"
                    self.assertEqual(client.call(name, INSERT), c.OUTCOMES[expected])
                    client.close()

    def test_invalid_shapes(self):
        for value in (None, [], {}, {"outcome": "saved"}, {**SAVED, "extra": True}, {**RECALLED, "passages": [None]}):
            for name in ("memory_insert", "memory_recall"):
                with self.subTest(value=value, name=name):
                    client = self.client([{"value": value}])
                    self.assertEqual(client.call(name, INSERT), c.uncertain(name, True))
                    client.close()

    def test_post_send_loss_never_reinserts(self):
        client = self.client([{"action": "eof"}])
        self.assertEqual(client.call("memory_insert", INSERT), c.OUTCOMES["unconfirmed"])
        self.assertEqual(self.insert_count(), 1)
        self.assertEqual(sum(row.get("event") == "spawn" for row in self.records()), 1)

    def test_transport_faults(self):
        for action in ("eof", "invalid", "oversize", "wrong_id"):
            for name in ("memory_insert", "sign_statement"):
                with self.subTest(action=action, name=name):
                    client = self.client([{"action": action}])
                    self.assertEqual(client.call(name, INSERT), c.uncertain(name, True))
                    client.close()

    def test_before_send_fault(self):
        client = self.client()
        client.connect_background()
        self.assertTrue(client.ready.wait(WAIT_SECONDS))
        with patch.object(client, "_write", side_effect=OSError()):
            self.assertEqual(client.call("memory_insert", INSERT), c.OUTCOMES["unavailable"])
        self.assertEqual(self.insert_count(), 0)

    def test_after_send_handler_exception(self):
        client = self.client()
        with patch.object(c, "map_reply", side_effect=RuntimeError()):
            self.assertEqual(client.call("memory_insert", INSERT), c.OUTCOMES["unconfirmed"])

    def test_invalid_arguments_never_spawn(self):
        client = self.client()
        for args in (None, [], "text", {"text": None}, {"text": c.MAX_STDIO_LINE_BYTES * "a"}):
            self.assertEqual(client.call("memory_insert", args), c.OUTCOMES["denied"])
        self.assertEqual(self.records(), [])

    def test_spawn_initialize_and_catalog_failure(self):
        for change in ({"early_eof": True}, {"initialize_fault": True}, {"catalog": list(c.TOOL_NAMES[:-1])}, {"catalog": list(c.TOOL_NAMES) + [c.TOOL_NAMES[0]]}):
            with self.subTest(change=change):
                original = dict(self.data)
                self.data.update(change)
                client = self.client()
                self.assertEqual(client.call("memory_insert", INSERT), c.OUTCOMES["unavailable"])
                client.close()
                self.data = original
        with patch.object(c, "resolve_command", return_value=[str(self.root / "missing")]):
            client = self.client()
            self.assertEqual(client.call("memory_insert", INSERT), c.OUTCOMES["unavailable"])
            self.assertEqual(client.prefetch("query"), "")

    def test_prefetch_other_results_empty(self):
        for value in (SAVED, *c.OUTCOMES.values()):
            client = self.client([{"value": value}])
            self.assertEqual(client.prefetch("query"), "")
            client.close()

    def test_queue_bound_and_fifo(self):
        client = self.client([{"delay": PREFETCH_MS / 1000, "value": SAVED}])
        entered, release = threading.Event(), threading.Event()
        original = client._exchange
        sent_order = []
        def hold(method, *args, **kwargs):
            if method == "tools/call":
                entered.set()
                self.assertTrue(release.wait(WAIT_SECONDS))
                sent_order.append(args[0]["arguments"]["text"])
            return original(method, *args, **kwargs)
        with patch.object(client, "_exchange", side_effect=hold):
            first, _ = self.thread_call(client)
            self.assertTrue(entered.wait(WAIT_SECONDS))
            waiting = []
            for index in range(c.HERMES_MAX_PUBLIC_CONNECTIONS):
                waiting.append(self.thread_call(client, args={"text": str(index), "taint": "user_content"}))
                with client.condition:
                    self.assertTrue(client.condition.wait_for(lambda: len(client.queue) == index + 1, WAIT_SECONDS))
            try:
                started = time.monotonic()
                self.assertEqual(client.call("memory_insert", INSERT, deadline=started + PREFETCH_MS / 1000), c.OUTCOMES["unavailable"])
                self.assertLess(time.monotonic() - started, PREFETCH_MS / 2000)  # Refusal must precede half the admission window.
                with client.condition:
                    self.assertEqual(len(client.queue), c.HERMES_MAX_PUBLIC_CONNECTIONS)
            finally:
                release.set()
            first.join(WAIT_SECONDS)
            for thread, values in waiting:
                thread.join(WAIT_SECONDS)
                self.assertEqual(values, [c.OUTCOMES["saved"]])
        self.assertEqual(self.insert_count(), 1 + c.HERMES_MAX_PUBLIC_CONNECTIONS)
        self.assertEqual(sent_order, [INSERT["text"]] + [str(index) for index in range(c.HERMES_MAX_PUBLIC_CONNECTIONS)])

    def test_expired_admission_unsent(self):
        client = self.client()
        self.assertEqual(client.call("memory_insert", INSERT, deadline=time.monotonic()), c.OUTCOMES["unavailable"])
        self.assertEqual(self.records(), [])

    def test_prefetch_budget_late_reply_and_next_call(self):
        client = self.client([{"delay": PREFETCH_MS * 3 / 1000, "value": RECALLED}, {"value": SAVED}])
        client.connect_background()
        self.assertTrue(client.ready.wait(WAIT_SECONDS))
        started = time.monotonic()
        self.assertEqual(client.prefetch("private query"), "")
        self.assertLess(time.monotonic() - started, PREFETCH_MS * 2 / 1000)
        self.assertIsNotNone(client.active)
        self.assertEqual(client.call("memory_insert", INSERT), c.OUTCOMES["saved"])
        self.assertEqual(self.insert_count(), 1)

    def test_complexity_repeated_timeout_waves(self):
        client = self.client([{"delay": TOOL_MS / 1000, "value": RECALLED}])
        client.connect_background()
        self.assertTrue(client.ready.wait(WAIT_SECONDS))
        baseline = threading.active_count()
        for _ in range(3):  # Three waves expose retention across repeated expiration.
            threads = [threading.Thread(target=client.prefetch, args=("query",)) for _ in range(c.MAX_QUEUED_CALLS + 1)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(WAIT_SECONDS)
                self.assertFalse(thread.is_alive())
            with client.condition:
                self.assertLessEqual(len(client.queue), c.HERMES_MAX_PUBLIC_CONNECTIONS)
                self.assertEqual(len(client.queue), 0)
                self.assertIsNotNone(client.active)
            self.assertLessEqual(threading.active_count(), baseline)
        self.assertEqual(sum(row.get("method") == "tools/call" for row in self.records()), 1)

    def test_hard_deadline_reaps_and_respawns(self):
        client = self.client([{"delay": TOOL_MS * 2 / 1000}])
        self.assertEqual(client.call("memory_insert", INSERT), c.OUTCOMES["unconfirmed"])
        with client.condition:
            self.assertTrue(client.condition.wait_for(lambda: client.active is None, WAIT_SECONDS))
        self.data["steps"] = [{"value": SAVED}]
        self.scenario.write_text(json.dumps(self.data))
        self.assertEqual(client.call("memory_insert", INSERT), c.OUTCOMES["saved"])
        self.assertEqual(sum(row.get("event") == "spawn" for row in self.records()), 2)
        self.assertEqual(self.insert_count(), 2)

    def test_both_loaders_share_one_spawn(self):
        memory = types.ModuleType("agent.memory_provider")
        memory.MemoryProvider = type("MemoryProvider", (), {})
        client = self.client()
        with patch.dict(sys.modules, {"agent.memory_provider": memory, "sanctuary_hermes_client": c}), patch.object(c, "get_client", return_value=client):
            provider = load_entry(ROOT / "sanctuary_memory/__init__.py", "shared_provider").SanctuaryMemory()
            plugin = load_entry(ROOT / "sanctuary/__init__.py", "shared_tools")
            handlers = {}
            ctx = types.SimpleNamespace(register_tool=lambda **kw: handlers.update({kw["name"]: kw["handler"]}), register_hook=lambda *args: None)
            plugin.register(ctx)
            provider.handle_tool_call("remember", {"text": "text"})
            handlers["sign_statement"]({"statement": "hello"})
        self.assertEqual(sum(row.get("event") == "spawn" for row in self.records()), 1)

    def test_partial_writes_resume_only_the_suffix(self):
        client = c.Client(tool_timeout_ms=TOOL_MS)
        # The mocked descriptor is stdin's conventional number; no real descriptor is written.
        client.process = types.SimpleNamespace(stdin=types.SimpleNamespace(fileno=lambda: 0))
        call = c._Call("memory_insert", INSERT, time.monotonic() + TOOL_MS / 1000)
        try:
            with patch.object(c.select, "select", return_value=([], [0], [])), patch.object(c.os, "write", side_effect=[2, BlockingIOError(), 2]) as write:
                client._write(b"abcd", call.deadline, call)
                self.assertEqual([args.args[1] for args in write.call_args_list], [b"abcd", b"cd", b"cd"])
                self.assertTrue(call.sent)
                self.assertIsNotNone(call.sent_at)
        finally:
            client.process = None
            client.close()

    def test_write_deadline_before_and_after_first_byte(self):
        for first_write in (False, True):
            client = c.Client(tool_timeout_ms=TOOL_MS)
            client.process = types.SimpleNamespace(stdin=types.SimpleNamespace(fileno=lambda: 0))
            call = c._Call("memory_insert", INSERT, time.monotonic() + TOOL_MS / 1000)
            readiness = [([], [0], []), ([], [], [])] if first_write else [([], [], [])]
            try:
                with patch.object(c.select, "select", side_effect=readiness), patch.object(c.os, "write", return_value=1) as write:
                    with self.assertRaises(OSError):
                        client._write(b"ab", call.deadline, call)
                    self.assertEqual(write.call_count, int(first_write))
                    self.assertEqual(c.uncertain(call.name, call.sent), c.OUTCOMES["unconfirmed" if first_write else "unavailable"])
            finally:
                client.process = None
                client.close()

    def test_deadlines_only_tighten(self):
        for key, value in (("tool_timeout_ms", c.HERMES_TOOL_TIMEOUT_MS), ("prefetch_budget_ms", c.RECALL_PREFETCH_BUDGET_MS),
                           ("initialization_ms", c.SHIM_CONNECT_HELLO_TIMEOUT_MS + c.SHIM_INITIALIZATION_TIMEOUT_MS), ("exit_ms", c.SHIM_STDIN_EOF_EXIT_MS)):
            with self.assertRaises(ValueError):
                c.Client(**{key: value + 1})

    def test_content_never_logged(self):
        client = self.client([{"value": RECALLED}])
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            client.prefetch("private query")
            client.call("memory_insert", INSERT)
        logs = stdout.getvalue() + stderr.getvalue() + self.log.read_text()
        for private in ("private query", INSERT["text"], RECALLED["context"]):
            self.assertNotIn(private, logs)


class EntryTests(unittest.TestCase):
    def setUp(self):
        # A stdlib stand-in supplies only the abstract type; installed acceptance uses the actual Hermes class.
        memory = types.ModuleType("agent.memory_provider")
        memory.MemoryProvider = type("MemoryProvider", (), {})
        self.patches = patch.dict(sys.modules, {"agent.memory_provider": memory, "sanctuary_hermes_client": c})
        self.patches.start()
        self.addCleanup(self.patches.stop)
        self.provider_module = load_entry(ROOT / "sanctuary_memory/__init__.py", "provider_fixture")
        self.tools_module = load_entry(ROOT / "sanctuary/__init__.py", "tools_fixture")
        self.provider = self.provider_module.SanctuaryMemory()

    def test_loader_identity(self):
        self.assertIs(self.provider_module._shared, self.tools_module._shared)
        self.assertIs(self.provider_module._client_module(), self.tools_module._client_module())

    def test_import_has_no_process_or_thread(self):
        with patch.object(c.subprocess, "Popen", side_effect=AssertionError("spawn")), patch.object(c.threading.Thread, "start", side_effect=AssertionError("thread")):
            module = importlib.util.module_from_spec(SPEC)
            SPEC.loader.exec_module(module)

    def test_tools_directory_not_a_provider(self):
        source = (ROOT / "sanctuary/__init__.py").read_text()
        for token in ("MemoryProvider", "register_memory_provider"):
            self.assertNotIn(token, source)
        self.assertEqual([p.name for p in (ROOT / "sanctuary_memory").glob("*.py")], ["__init__.py"])

    def test_provider_is_available_never_spawns(self):
        with patch.object(c, "resolve_command", return_value=[sys.executable]), patch.object(c, "get_client", side_effect=AssertionError("spawn")):
            self.assertTrue(self.provider.is_available())

    def test_save_hooks_are_noops_and_shutdown_shared(self):
        with patch.object(c, "get_client", side_effect=AssertionError("implicit save")) as shared:
            self.provider.sync_turn("user", "assistant")
            self.provider.queue_prefetch("query")
            self.provider.on_memory_write("add", "memory", "text")
            self.assertEqual(self.provider.on_pre_compress([]), "")
            self.provider.shutdown()
            shared.assert_not_called()

    def test_handler_outer_wrappers(self):
        with patch.object(c, "get_client", side_effect=RuntimeError("fixture")):
            self.assertEqual(json.loads(self.provider.handle_tool_call("remember", {"text": "text"})), c.OUTCOMES["unavailable"])
            for schema in c.TOOL_SCHEMAS:
                self.assertEqual(json.loads(c.tool_handler(schema["name"])({})), c.OUTCOMES["unavailable"])
            self.assertEqual(self.provider.prefetch("query"), "")

    def test_provider_exact_context(self):
        with patch.object(c, "get_client") as client:
            client.return_value.prefetch.return_value = RECALLED["context"]
            self.assertEqual(self.provider.prefetch("query"), RECALLED["context"])

    def test_remember_arguments_and_forwarding(self):
        with patch.object(c, "get_client") as client:
            client.return_value.call.return_value = c.OUTCOMES["saved"]
            self.provider.handle_tool_call("remember", {"text": "text", "other": "ignored"})
            client.return_value.call.assert_called_once_with("memory_insert", {"text": "text", "taint": "user_content"})
            for schema in c.TOOL_SCHEMAS:
                args = {"extra": ["unchanged"]}
                c.tool_handler(schema["name"])(args)
                self.assertIs(client.return_value.call.call_args[0][1], args)

    def test_guard_normalized_nested_cycles_and_keys(self):
        block = {"action": "block", "message": c.OUTCOMES["denied"]["message"]}
        for value in (c.SANCTUARY_INSTALL_ROOT + "x", "\\LIBRARY\\Application Support\\SANCTUARY\\x", "/Library///././Application Support/./Sanctuary/x"):
            self.assertEqual(c.guard("read_file", {"nested": [({}, {value: "x"})]}), block)
        cycle = []
        cycle.append(cycle)
        self.assertIsNone(c.guard("read_file", {"path": "/tmp/ordinary", "cycle": cycle}))
        for name in ("remember", "sign_statement", "export_memory", "protection_rules"):
            self.assertIsNone(c.guard(name, {"path": c.SANCTUARY_INSTALL_ROOT}))
        self.assertIsNone(c.guard("read_file", {}))

    def test_guard_exception_blocks_and_never_approves(self):
        with patch.object(c, "normalize", side_effect=RuntimeError()):
            self.assertEqual(c.guard("read_file", {}), {"action": "block", "message": c.OUTCOMES["denied"]["message"]})

    def test_fuzz_arguments_and_results_total(self):
        rng = random.Random(0)
        values = [None, True, 0, "text", [], {}, {"text": []}, {"text": "ok"}, {"value": object()}]
        cycle = {}
        cycle["self"] = cycle
        values.append(cycle)
        with patch.object(c, "get_client") as client:
            client.return_value.call.return_value = c.OUTCOMES["unavailable"]
            for _ in range(100):  # A fixed seed and hundred draws cover malformed scalars and composites.
                value = rng.choice(values)
                json.loads(self.provider.handle_tool_call("remember", value))
                for schema in c.TOOL_SCHEMAS:
                    json.loads(c.tool_handler(schema["name"])(value))
                self.assertIn(c.guard("read_file", value), (None, {"action": "block", "message": c.OUTCOMES["denied"]["message"]}))
                self.assertIsInstance(c.map_reply("memory_insert", value), dict)

    def test_command_file_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command_file = root / "shim-command.json"
            with patch.object(c, "__file__", str(root / "sanctuary_client.py")), patch.object(c.shutil, "which", return_value=sys.executable) as which:
                self.assertEqual(c.resolve_command(), [sys.executable, "hermes-memory-client"])
                which.reset_mock()
                for value in (None, {}, [], ["relative"], [sys.executable, ""], [sys.executable] * 9):
                    command_file.write_text(json.dumps(value))
                    self.assertIsNone(c.resolve_command())
                command_file.write_text("{")
                self.assertIsNone(c.resolve_command())
                command_file.write_text(json.dumps([sys.executable, "-B"]))
                self.assertEqual(c.resolve_command(), [sys.executable, "-B"])
                which.assert_not_called()


if __name__ == "__main__":
    unittest.main()
