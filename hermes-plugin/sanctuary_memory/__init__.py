"""Persistent memory through the Sanctuary bridge."""
from __future__ import annotations

import _imp
import importlib.util
import json
from pathlib import Path
import sys
from agent.memory_provider import MemoryProvider


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


class SanctuaryMemory(MemoryProvider):
    name = "sanctuary_memory"

    def is_available(self):
        try:
            return _shared.resolve_command() is not None
        except Exception:
            return False

    def initialize(self, session_id="", **kwargs):
        try:
            _shared.get_client().connect_background()
        except Exception:
            return None

    def system_prompt_block(self):
        return "Memory is persistent. Save memories with remember. Matching saved memories appear in the memory context."

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
            return _shared.get_client().prefetch(query, deadline=deadline)
        except Exception:
            return ""

    # Memory is saved only by remember; completed turns and lifecycle hooks never save implicitly.
    def sync_turn(self, *args, **kwargs):
        return None

    def queue_prefetch(self, *args, **kwargs):
        return None

    def on_memory_write(self, *args, **kwargs):
        return None

    def on_pre_compress(self, *args, **kwargs):
        return ""

    def shutdown(self):
        # Gateway sessions share the client; ending one provider must not close another session's transport.
        return None
