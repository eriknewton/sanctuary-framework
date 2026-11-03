"""Run one offline Hermes session with temporary plugin installation and a real executor."""
from __future__ import annotations
import time
STARTED = time.monotonic()

import argparse
import contextlib
import hashlib
import io
import json
import logging
import os
from pathlib import Path
import shutil
import signal
import sys
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
QUERY = "When is the board meeting?"
TEXT = "The board meeting moved to Thursday 3pm."
MS_PER_SECOND = 1000


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--preinstalled", action="store_true")
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--home", required=True)
    parser.add_argument("--socket", required=True)
    args = parser.parse_args()
    home = Path(args.home)
    hermes_home = home / "hermes"
    os.environ.update(HOME=str(home), HERMES_HOME=str(hermes_home),
                      HTTP_PROXY="http://127.0.0.1:9", HTTPS_PROXY="http://127.0.0.1:9", ALL_PROXY="http://127.0.0.1:9",
                      NO_PROXY="", no_proxy="")
    os.chdir(ROOT / "server")
    plugin_root = hermes_home / "plugins"
    log = home / "shim.log"
    if not args.preinstalled:
        plugin_root.mkdir(parents=True)
        for name in ("sanctuary", "sanctuary_memory"):
            shutil.copytree(ROOT / "hermes-plugin" / name, plugin_root / name)
        command = [shutil.which("node"), "--import", "tsx", str(ROOT / "server/test/hermes-plugin/harness/shim.ts"), args.socket, str(log)]
        if args.scenario == "fault-insert":
            command.append("--die-after-request")
        if args.scenario == "no-shim":
            command = [str(home / "missing-executable")]
        (plugin_root / "sanctuary/shim-command.json").write_text(json.dumps(command))
        enabled = ["sanctuary"]
        if args.scenario in ("block-first", "approve-first"):
            # Sorted directory discovery supplies both load orders without changing production callbacks.
            other = "aaa_directive" if args.scenario == "approve-first" else "zzz_directive"
            target = plugin_root / other
            target.mkdir()
            (target / "plugin.yaml").write_text("name: " + other + "\nkind: standalone\n")
            (target / "__init__.py").write_text('def register(ctx):\n    ctx.register_hook("pre_tool_call", lambda **kwargs: {"action": "approve", "message": "Fixture confirmation."})\n')
            enabled.append(other)
        (hermes_home / "config.yaml").write_text(
            "memory:\n  provider: sanctuary_memory\n  memory_enabled: false\n  user_profile_enabled: false\nplugins:\n  enabled: " + json.dumps(enabled) + "\n")
    captured = io.StringIO()
    report = {"executed_tools": [], "fallback": False}
    with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
        logging.basicConfig(stream=captured, level=logging.INFO, force=True)
        from hermes_cli.plugins import get_plugin_manager
        manager = get_plugin_manager()
        manager.discover_and_load()
        if args.scenario in ("block-first", "approve-first"):
            from hermes_cli.plugins import get_pre_tool_call_directive
            shared = sys.modules["sanctuary_hermes_client"]
            action, message = get_pre_tool_call_directive("read_file", {"path": shared.SANCTUARY_INSTALL_ROOT})
            return {"order": args.scenario, "selected": {"action": action, "message": message}}
        from run_agent import AIAgent
        from agent.tool_executor import execute_tool_calls_sequential, execute_tool_calls_concurrent
        from agent.tool_guardrails import classify_tool_failure
        from agent.memory_manager import build_memory_context_block
        from tools.registry import registry
        from tools import session_search_tool
        agent = AIAgent(base_url="http://127.0.0.1:9/v1", api_key="offline-fixture", model="offline-fixture",
                        provider="custom", enabled_toolsets=["sanctuary", "file"], quiet_mode=True,
                        tool_progress_mode="off", skip_context_files=True, tool_delay=0)
        if args.preinstalled:
            from agent.prompt_builder import load_soul_md, build_skills_system_prompt
            from tools.mcp_tool import _load_mcp_config
            report["mcp_names"] = list(_load_mcp_config())
            report["soul"] = load_soul_md()
            report["skills"] = build_skills_system_prompt()
            if args.scenario == "uninstalled":
                report["memory_store_none"] = agent._memory_store is None
                providers = agent._memory_manager.providers if agent._memory_manager else []
                report["provider"] = providers[0].name if providers else None
                report["plugin_loaded"] = "sign_statement" in manager._plugin_tool_names
                agent.close()
                return report
        shared = sys.modules["sanctuary_hermes_client"]
        client = shared.get_client()
        observers = contextlib.ExitStack()
        # Observe registry and provider dispatch plus the executor's inline session search throughout the session.
        def observe(original):
            def dispatched(name, *values, **kwargs):
                report["executed_tools"].append(name)
                return original(name, *values, **kwargs)
            return dispatched
        observers.enter_context(patch.object(registry, "dispatch", side_effect=observe(registry.dispatch)))
        if agent._memory_manager is not None:
            observers.enter_context(patch.object(agent._memory_manager, "handle_tool_call",
                                                 side_effect=observe(agent._memory_manager.handle_tool_call)))
        original_session_search = session_search_tool.session_search
        def observed_session_search(*values, **kwargs):
            report["executed_tools"].append("session_search")
            return original_session_search(*values, **kwargs)
        observers.enter_context(patch.object(session_search_tool, "session_search", side_effect=observed_session_search))
        try:
            report["memory_store_none"] = agent._memory_store is None
            report["plugin_loaded"] = "sign_statement" in manager._plugin_tool_names
            providers = agent._memory_manager.providers if agent._memory_manager else []
            report["provider"] = providers[0].name if providers else None
            if not providers:
                raise AssertionError("configured provider did not activate")
            provider = providers[0]
            if args.scenario != "no-shim":
                if not client.ready.wait((shared.SHIM_CONNECT_HELLO_TIMEOUT_MS + shared.SHIM_INITIALIZATION_TIMEOUT_MS) / MS_PER_SECOND):
                    raise AssertionError("shared client did not become ready")
            report["ready_ms"] = (time.monotonic() - STARTED) * MS_PER_SECOND

            def execute(calls, concurrent=False):
                messages = []
                tool_calls = []
                for index, (name, arguments) in enumerate(calls):
                    tool_calls.append(SimpleNamespace(id="call-" + str(index), type="function",
                                      function=SimpleNamespace(name=name, arguments=json.dumps(arguments))))
                assistant = SimpleNamespace(tool_calls=tool_calls, content=None)
                executor = execute_tool_calls_concurrent if concurrent else execute_tool_calls_sequential
                executor(agent, assistant, messages, "fixture")
                tool_messages = [message for message in messages if message["role"] == "tool"]
                report["raw_results"] = [message["content"] for message in tool_messages]
                return [json.loads(message["content"]) for message in tool_messages]

            def recall():
                returned = []
                original = provider.prefetch
                def observed(query, **kwargs):
                    value = original(query, **kwargs)
                    returned.append(value)
                    return value
                with patch.object(provider, "prefetch", side_effect=observed):
                    start = time.monotonic()
                    context = agent._memory_manager.prefetch_all(QUERY)
                    report["prefetch_ms"] = (time.monotonic() - start) * MS_PER_SECOND
                report["context"] = build_memory_context_block(context)
                report["provider_sha256"] = hashlib.sha256(returned[0].encode()).hexdigest()
                if args.scenario == "recall-session-search":
                    execute([("session_search", {"query": "observer fixture"})])

            if args.scenario in ("loading", "recall-session-search"):
                report["results"] = execute([("sign_statement", {"statement": "hello"})])
                if args.scenario == "loading":
                    provider.prefetch("empty")
                else:
                    # Reuse the loading prefetch so the observer check adds no bridge requests.
                    recall()
            elif args.scenario in ("save", "fault-insert", "no-shim"):
                start = time.monotonic()
                report["results"] = execute([("remember", {"text": TEXT})])
                tool_ms = (time.monotonic() - start) * MS_PER_SECOND
                if args.scenario == "no-shim":
                    start = time.monotonic()
                    report["context"] = agent._memory_manager.prefetch_all(QUERY)
                    report["within_budgets"] = tool_ms < shared.HERMES_TOOL_TIMEOUT_MS and (time.monotonic() - start) * MS_PER_SECOND < shared.RECALL_PREFETCH_BUDGET_MS
            elif args.scenario == "recall":
                recall()
            elif args.scenario.startswith("refusals"):
                report["results"] = execute([("sign_statement", {"statement": "I approve the Q3 plan."}),
                                             ("protection_rules", {}), ("export_memory", {"scope": "all"})], args.scenario.endswith("concurrent"))
                report["classified_failures"] = [classify_tool_failure(name, result)[0] for name, result in zip(report["executed_tools"], report["raw_results"])]
                report["failure_count"] = sum(agent._tool_guardrails._same_tool_failure_counts.values())
            elif args.scenario == "guard":
                ordinary = home / "ordinary.txt"
                ordinary.write_text("ordinary fixture")
                entry = registry.get_entry("read_file")
                original = entry.handler
                native_calls = []
                def spy(arguments, **kwargs):
                    native_calls.append(arguments)
                    return original(arguments, **kwargs)
                with patch.object(entry, "handler", side_effect=spy):
                    results = execute([("read_file", {"path": shared.SANCTUARY_INSTALL_ROOT + "fixture"}),
                                       ("read_file", {"path": str(ordinary)})])
                report["blocked_message"] = results[0].get("error")
                report["native_calls"] = len(native_calls)
                report["ordinary_ran"] = "ordinary fixture" in json.dumps(results[1])
                own_calls = [("remember", {"text": shared.SANCTUARY_INSTALL_ROOT}),
                             ("sign_statement", {"statement": shared.SANCTUARY_INSTALL_ROOT}),
                             ("export_memory", {"scope": shared.SANCTUARY_INSTALL_ROOT}),
                             ("protection_rules", {"path": shared.SANCTUARY_INSTALL_ROOT})]
                own_results = execute(own_calls)
                report["own_results"] = own_results
                report["own_directives"] = [shared.guard(name, values) for name, values in own_calls]
                import hermes_cli.plugins as hooks
                if hasattr(hooks, "get_pre_tool_call_directive"):
                    action, message = hooks.get_pre_tool_call_directive("read_file", {"path": shared.SANCTUARY_INSTALL_ROOT})
                    report["directive"] = {"action": action, "message": message}
                else:
                    report["directive"] = {"action": "block", "message": hooks.get_pre_tool_call_block_message("read_file", {"path": shared.SANCTUARY_INSTALL_ROOT})}
        finally:
            observers.close()
            agent.close()
            client.close()
    report["hermes_log"] = captured.getvalue()
    report["shim_log"] = log.read_text() if log.exists() else ""
    lines = [json.loads(line) for line in report["shim_log"].splitlines()]
    report["shim_lines"] = lines
    report["spawns"] = sum(line.get("event") == "spawn" for line in lines)
    report["insert_requests"] = sum(line.get("event") == "request" and line.get("name") == "memory_insert" for line in lines)
    return report


if __name__ == "__main__":
    def stop(signum, frame):
        raise SystemExit(128 + signum)  # Conventional signal exit status.
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        print(json.dumps(main()))
    finally:
        shared = sys.modules.get("sanctuary_hermes_client")
        client = getattr(shared, "_client", None)
        if client is not None:
            client.close()
