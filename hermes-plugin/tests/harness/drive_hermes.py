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
# Must match captureFact, captureQuery and the tokens in server/test/hermes-plugin/hermes-default-acceptance.test.ts.
FACT = "FYI, the Lisbon demo for Jamie is set for Thursday at 3pm."
FACT_QUERY = "When is the Lisbon demo for Jamie?"
CRON_FACT = "The Porto review moved to Monday at 9am."
ASSISTANT_TOKEN = "assistant-token-5f1c"
TOOL_TOKEN = "tool-token-9b3e"
CAPTURE_SCENARIOS = ("capture", "capture-recall", "capture-cron")


def scripted_model(agent, replies, seen):
    """Answer each model request from a script, offline; a reply is text or one tool call, optionally interrupting."""
    def answer(api_kwargs, **kwargs):
        seen.append(json.dumps(api_kwargs.get("messages", []), default=str))
        step = replies.pop(0)
        if step.get("interrupt"):
            agent.interrupt("fixture")
        calls = None
        if "tool" in step:
            calls = [SimpleNamespace(id="call-" + str(len(seen)), type="function",
                                     function=SimpleNamespace(name=step["tool"], arguments=json.dumps(step["arguments"])))]
        message = SimpleNamespace(role="assistant", content=step.get("text"), tool_calls=calls,
                                  reasoning=None, reasoning_content=None, refusal=None)
        usage = SimpleNamespace(prompt_tokens=1, completion_tokens=1, total_tokens=2,
                                prompt_tokens_details=None, completion_tokens_details=None)
        return SimpleNamespace(id="fixture", model="offline-fixture", object="chat.completion", created=0, usage=usage,
                               choices=[SimpleNamespace(index=0, message=message, finish_reason="tool_calls" if calls else "stop")])
    return answer


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
        # Capture scenarios run as the gateway's Telegram agent, or as a cron-platform agent with memory left on.
        platform = {"capture": "telegram", "capture-recall": "telegram", "capture-cron": "cron"}.get(args.scenario)
        agent = AIAgent(base_url="http://127.0.0.1:9/v1", api_key="offline-fixture", model="offline-fixture",
                        provider="custom", enabled_toolsets=["sanctuary", "file"], quiet_mode=True,
                        tool_progress_mode="off", skip_context_files=True, tool_delay=0,
                        **({"platform": platform} if platform else {}))
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
        # Every line either client sends is recorded, so a frame's exact content can be checked. Size checks encode
        # with the placeholder id call_line reserves; only lines without it are sent.
        encoded_lines = []
        original_encode = shared.Client._encode
        def observed_encode(value):
            line = original_encode(value)
            if not isinstance(value.get("id"), str):
                encoded_lines.append(line.decode("utf-8"))
            return line
        observers.enter_context(patch.object(shared.Client, "_encode", staticmethod(observed_encode)))
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
            elif args.scenario in CAPTURE_SCENARIOS:
                capture(args.scenario, agent, provider, home, report, encoded_lines)
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
            capture_client = getattr(sys.modules.get(type(provider).__module__) if providers else None, "_capture_client", None)
            if capture_client is not None:
                capture_client.close()
    report["hermes_log"] = captured.getvalue()
    report["shim_log"] = log.read_text() if log.exists() else ""
    lines = [json.loads(line) for line in report["shim_log"].splitlines()]
    report["shim_lines"] = lines
    report["spawns"] = sum(line.get("event") == "spawn" for line in lines)
    report["insert_requests"] = sum(line.get("event") == "request" and line.get("name") == "memory_insert" for line in lines)
    return report


def shared_budget():
    # A provider without its own capture deadline still gets a bounded barrier.
    return sys.modules["sanctuary_hermes_client"].RECALL_PREFETCH_BUDGET_MS


def insert_lines(lines):
    return [json.loads(line)["params"]["arguments"] for line in lines
            if json.loads(line).get("params", {}).get("name") == "memory_insert"]


def capture(scenario, agent, provider, home, report, encoded_lines):
    """Drive whole turns through run_conversation and record which turns sent a capture frame."""
    module = sys.modules[type(provider).__module__]
    # The background capture finishes inside its own deadline; one more deadline bounds Hermes's worker barrier.
    flush_seconds = 2 * getattr(module, "CAPTURE_DEADLINE_MS", shared_budget()) / MS_PER_SECOND
    notes = home / "notes.txt"
    notes.write_text("Tool output " + TOOL_TOKEN + ".")
    seen = []
    replies = []
    answer = scripted_model(agent, replies, seen)
    report["turns"] = {}

    def turn(label, text, script):
        replies[:] = script
        before = len(encoded_lines)
        with patch.object(agent, "_interruptible_api_call", side_effect=answer), \
             patch.object(agent, "_interruptible_streaming_api_call", side_effect=lambda kw, **rest: answer(kw)):
            result = agent.run_conversation(text)
        report["turns"][label] = {"flushed": agent._memory_manager.flush_pending(timeout=flush_seconds),
                                  "interrupted": bool(result.get("interrupted")),
                                  "inserts": insert_lines(encoded_lines[before:])}
        return result

    if scenario == "capture":
        # The model reads a file and replies; the tool result and the reply each carry a token capture must never send.
        turn("fact", FACT, [{"tool": "read_file", "arguments": {"path": str(notes)}},
                            {"text": "Noted. " + ASSISTANT_TOKEN}])
        report["tool_token_reached_model"] = any(TOOL_TOKEN in value for value in seen)
        # Gateway enrichment, built exactly as hermes-agent 0.17.0 gateway/run.py:8610 builds a reply quote.
        turn("reply_quote", '[Replying to: "Lunch on Friday?"]\n\nThat works for me.', [{"text": "Great."}])
        from agent.context_references import preprocess_context_references
        from agent.model_metadata import CONTEXT_PROBE_TIERS
        # Hermes's own @ expansion; its first probe step is the window it assumes for an undetectable model.
        plan = home / "plan.txt"
        plan.write_text("Plan outline.")
        expanded = preprocess_context_references("Keep this with the plan @file:" + plan.name, cwd=home,
                                                 context_length=CONTEXT_PROBE_TIERS[0], allowed_root=home).message
        report["expanded_has_marker"] = "--- Attached Context ---" in expanded
        turn("at_reference", expanded, [{"text": "Done."}])
        turn("interrupted", "The Faro trip is booked for May.", [{"tool": "read_file", "arguments": {"path": str(notes)}, "interrupt": True}])
    elif scenario == "capture-recall":
        turn("question", FACT_QUERY, [{"text": "Thursday at 3pm."}])
        # The fresh process's recall reached the model inside Hermes's memory-context block.
        report["fact_reached_model"] = any("Thursday at 3pm" in value and "memory-context" in value for value in seen)
    else:
        turn("cron", CRON_FACT, [{"text": "Noted."}])
    # The first model request carries the system prompt the provider contributed for this platform.
    prompt = getattr(module, "CAPTURE_PROMPT", None)
    report["capture_prompt"] = prompt is not None and prompt in seen[0]
    # Recall queries carry the user message by Hermes's design; capture frames are the memory_insert lines.
    report["insert_lines_text"] = json.dumps(insert_lines(encoded_lines))


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
