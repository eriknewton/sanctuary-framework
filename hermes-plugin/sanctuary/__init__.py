"""Hermes tools and native-call guard."""
from __future__ import annotations

import _imp
import importlib.util
from pathlib import Path
import sys


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


def register(ctx):
    for schema in _shared.TOOL_SCHEMAS:
        ctx.register_tool(name=schema["name"], toolset="sanctuary", schema=schema,
                          handler=_shared.tool_handler(schema["name"]), description=schema["description"])
    ctx.register_hook("pre_tool_call", _shared.guard)
