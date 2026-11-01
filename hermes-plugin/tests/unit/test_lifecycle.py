"""Controlled pipe and process-group schedules exercise the real client."""
from __future__ import annotations
import ctypes
import os
import resource
import selectors
import signal
import socket
import sys
import threading
import time
import unittest
from unittest.mock import patch
from . import test_client as fixture

c = fixture.c
WAIT_SECONDS = fixture.WAIT_SECONDS


class LifecycleTests(unittest.TestCase):
    setUp = fixture.ClientTests.setUp
    client = fixture.ClientTests.client
    records = fixture.ClientTests.records
    thread_call = fixture.ClientTests.thread_call
    insert_count = fixture.ClientTests.insert_count

    def controlled(self, **options):
        listener = socket.socket(socket.AF_UNIX)
        self.addCleanup(listener.close)
        listener.bind(str(self.root / "control"))
        listener.listen(1)
        listener.settimeout(WAIT_SECONDS)
        self.data.update(control=str(self.root / "control"), **options)
        client = self.client()
        client.connect_background()
        control, _ = listener.accept()
        control.settimeout(WAIT_SECONDS)
        self.addCleanup(control.close)
        stream = control.makefile("rwb", buffering=0)
        self.addCleanup(stream.close)
        self.assertEqual(stream.readline(), b"paused\n")
        self.assertTrue(client.ready.wait(WAIT_SECONDS))
        return client, stream

    def test_abandoned_insert_never_written_after_pipe_drains(self):
        client, control = self.controlled()
        fd = client.process.stdin.fileno()
        while True:
            try:
                os.write(fd, b" " * 4096)  # One conventional pipe page of inert padding.
            except BlockingIOError:
                break
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        original_select = selectors.DefaultSelector.select
        original_write = os.write
        writes = []

        def held_select(selector, timeout=None):
            if any(key.fd == fd for key in selector.get_map().values()):
                entered.set()
                if not release.wait(WAIT_SECONDS):
                    raise OSError("coordination expired")
                return original_select(selector, WAIT_SECONDS)
            return original_select(selector, timeout)

        def observed_write(target, data):
            count = original_write(target, data)
            if target == fd:
                writes.append(data[:count])
            return count

        with patch.object(selectors.DefaultSelector, "select", held_select), patch.object(c.os, "write", observed_write):
            thread, values = self.thread_call(client)
            self.assertTrue(entered.wait(WAIT_SECONDS))
            thread.join(WAIT_SECONDS)
            self.assertFalse(thread.is_alive())
            self.assertEqual(values, [c.OUTCOMES["unavailable"]])
            control.write(b"drain\n")
            self.assertEqual(control.readline(), b"drained\n")
            release.set()
            with client.condition:
                self.assertTrue(client.condition.wait_for(lambda: client.active is None, WAIT_SECONDS))
            client.close()
        self.assertEqual(writes, [], "abandoned insert wrote bytes after the caller was answered")
        self.assertEqual(self.insert_count(), 0)
        self.assertFalse(any(row.get("insert_bytes") for row in self.records()))

    def test_first_byte_deadline_is_unconfirmed(self):
        client = self.client()
        client.connect_background()
        self.assertTrue(client.ready.wait(WAIT_SECONDS))
        fd = client.process.stdin.fileno()
        accepted, release = threading.Event(), threading.Event()
        original = os.write
        observed = []

        def first_byte(target, data):
            if target != fd:
                return original(target, data)
            count = original(target, data[:1])
            observed.append(count)
            accepted.set()
            if not release.wait(WAIT_SECONDS):
                raise OSError("coordination expired")
            return count

        with patch.object(c.os, "write", first_byte):
            thread, values = self.thread_call(client)
            try:
                self.assertTrue(accepted.wait(WAIT_SECONDS))
                thread.join(client.tool_seconds * 2)  # Observe the caller after its deadline, while the write owns classification.
                self.assertTrue(thread.is_alive(), "caller answered before accepted bytes were classified")
            finally:
                release.set()
                thread.join(WAIT_SECONDS)
            self.assertEqual(values, [c.OUTCOMES["unconfirmed"]])
            self.assertEqual(observed, [1])

    def test_first_write_raises_without_accepted_bytes(self):
        client = self.client()
        client.connect_background()
        self.assertTrue(client.ready.wait(WAIT_SECONDS))
        with patch.object(c.os, "write", side_effect=OSError("closed pipe")) as write:
            self.assertEqual(client.call("memory_insert", fixture.INSERT), c.OUTCOMES["unavailable"])
            self.assertEqual(write.call_count, 1)
        self.assertEqual(self.insert_count(), 0)

    def test_old_reader_cannot_change_replacement_state(self):
        client = self.client()
        client.connect_background()
        self.assertTrue(client.ready.wait(WAIT_SECONDS))
        old_process = client.process
        client._end_process()
        self.assertTrue(client._connect())
        pending = {"id": client.serial + 1, "event": threading.Event(), "reply": None}
        with client.condition:
            client.pending = pending
        client._read(old_process)
        self.assertTrue(client.ready.is_set())
        self.assertFalse(client.transport_fault)
        self.assertIs(client.pending, pending)
        self.assertFalse(pending["event"].is_set())
        with client.condition:
            client.pending = None
        self.assertEqual(client.call("memory_insert", fixture.INSERT), c.OUTCOMES["saved"])

    def test_malformed_error_envelopes(self):
        for error in ({}, {"code": -32603}, {"code": "x", "message": 1}, None, "text", {"code": True, "message": "text"}):
            for name, outcome in (("memory_insert", "unconfirmed"), ("memory_get", "unavailable")):
                with self.subTest(error=error, name=name):
                    client = self.client([{"rpc_error": error}])
                    self.assertEqual(client.call(name, fixture.INSERT), c.OUTCOMES[outcome])
                    client.close()

    def group_case(self, hard_deadline, ignore_term=False):
        # Linux adopts fixture descendants here so their exit can be reaped even without a system init.
        libc = ctypes.CDLL(None, use_errno=True) if sys.platform == "linux" else None
        previous = ctypes.c_int()
        if libc is not None:
            self.assertEqual(libc.prctl(37, ctypes.byref(previous), 0, 0, 0), 0)  # PR_GET_CHILD_SUBREAPER.
            self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)  # PR_SET_CHILD_SUBREAPER.
            self.addCleanup(lambda: libc.prctl(36, previous.value, 0, 0, 0))
        child = []
        def reap(signum, frame):
            if child:
                try:
                    os.waitpid(child[0], os.WNOHANG)
                except ChildProcessError:
                    pass
        old_handler = signal.signal(signal.SIGCHLD, reap)
        self.addCleanup(signal.signal, signal.SIGCHLD, old_handler)
        client, control = self.controlled(group_child=True, hold_reply=hard_deadline, ignore_term=ignore_term)
        control.write(b"child\n")
        child.append(int(control.readline()))
        pgid = client.process.pid
        def cleanup_group():
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            client.close()
            reap(None, None)
        self.addCleanup(cleanup_group)
        control.write(b"resume\n")
        self.assertEqual(control.readline(), b"resumed\n")
        if hard_deadline:
            self.assertEqual(client.call("memory_insert", fixture.INSERT), c.OUTCOMES["unconfirmed"])
            with client.condition:
                self.assertTrue(client.condition.wait_for(lambda: client.active is None, WAIT_SECONDS))
        else:
            client.close()
        reap(None, None)
        with self.assertRaises(ProcessLookupError):
            os.killpg(pgid, 0)
        if hard_deadline:
            self.data.pop("control")
            self.data.pop("group_child")
            self.data.pop("hold_reply")
            self.scenario.write_text(fixture.json.dumps(self.data))
            spawn = c.subprocess.Popen
            def checked_spawn(*args, **kwargs):
                with self.assertRaises(ProcessLookupError):
                    os.killpg(pgid, 0)
                return spawn(*args, **kwargs)
            with patch.object(c.subprocess, "Popen", side_effect=checked_spawn):
                self.assertEqual(client.call("memory_insert", fixture.INSERT), c.OUTCOMES["saved"])

    def test_close_ends_group_after_leader_eof(self):
        self.group_case(False)

    def test_hard_deadline_ends_group_before_replacement(self):
        self.group_case(True)

    def test_close_kills_group_that_ignores_term(self):
        self.group_case(False, ignore_term=True)

    def test_descriptors_above_select_limit(self):
        required = 1100  # Exceeds select's 1024 descriptor ceiling with room for shim pipes.
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if hard != resource.RLIM_INFINITY and hard < required:
            self.skipTest("hard descriptor limit forbids opening descriptors above 1024")
        resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, required), hard))
        descriptors = []
        try:
            while not descriptors or descriptors[-1] <= 1024:
                descriptors.append(os.open(os.devnull, os.O_RDONLY))
            client = self.client()
            self.assertEqual(client.call("memory_insert", fixture.INSERT), c.OUTCOMES["saved"])
            self.assertGreater(client.process.stdout.fileno(), 1024)
            client.close()
        finally:
            for fd in descriptors:
                os.close(fd)
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
