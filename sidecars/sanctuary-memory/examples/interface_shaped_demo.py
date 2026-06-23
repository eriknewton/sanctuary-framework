"""Interface-shaped demo for the SDW-backed ContextProvider.

The Microsoft `agent_framework` package is not importable in the offline build
venv used for this change, so this demo does not claim live Microsoft runtime
execution. It shows the intended configuration shape:

    agent = Agent(context_providers=[SanctuaryContextProvider(...)])

The injected fake below uses the same six-tool JSON shapes as the shipped SDW
MCP memory tools and does not spawn a Sanctuary server.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sanctuary_memory import SanctuaryContextProvider, content_hash_for_text


class DemoMemoryTools:
    def __init__(self) -> None:
        self.passages: dict[str, dict[str, Any]] = {}
        self.next_id = 1

    def call_tool(self, name: str, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        args = dict(arguments)
        if name == "memory_insert":
            passage_id = f"demo{self.next_id}"
            self.next_id += 1
            text = args["text"]
            self.passages[passage_id] = {
                "passage_id": passage_id,
                "owner_ref": "fleet-self",
                "text": text,
                "tags": list(args.get("tags", [])),
                "metadata": [],
                "created_at": "2026-06-23T00:00:00Z",
                "chunk_count": 1,
                "content_hash": content_hash_for_text(text),
            }
            return {
                "inserted": True,
                "passage": {
                    "passage_id": passage_id,
                    "owner_ref": "fleet-self",
                    "content_hash": self.passages[passage_id]["content_hash"],
                    "created_at": "2026-06-23T00:00:00Z",
                    "chunk_count": 1,
                    "tag_count": len(self.passages[passage_id]["tags"]),
                },
            }
        if name == "memory_search":
            tag = args.get("tag")
            needle = args.get("text", "").lower()
            results = []
            for passage in self.passages.values():
                if isinstance(tag, str) and tag not in passage["tags"]:
                    continue
                matches = passage["text"].lower().count(needle) if needle else 0
                if matches:
                    results.append(
                        {
                            "passage": {
                                "passage_id": passage["passage_id"],
                                "owner_ref": passage["owner_ref"],
                                "content_hash": passage["content_hash"],
                                "created_at": passage["created_at"],
                                "chunk_count": passage["chunk_count"],
                                "tag_count": len(passage["tags"]),
                            },
                            "match_count": matches,
                        }
                    )
            return {"results": results}
        if name == "memory_get":
            passage = self.passages.get(args["passage_id"])
            return {"found": passage is not None, "passage": passage}
        if name == "memory_count":
            return {"count": len(self.passages)}
        if name == "memory_delete":
            return {
                "denied": True,
                "message": "This action is not available in the current context.",
                "remediation_class": "request_review",
                "retry_after": None,
                "audit_ref": "audit:gate:memory_delete",
            }
        raise ValueError(name)


class InterfaceShapedAgent:
    def __init__(self, *, context_providers: list[SanctuaryContextProvider]) -> None:
        self.context_providers = context_providers

    def run(self, prompt: str, *, session_id: str) -> dict[str, Any]:
        state: dict[str, Any] = {
            "session_id": session_id,
            "sanctuary_memory_query": prompt,
        }
        context: dict[str, Any] = {"prompt": prompt}
        for provider in self.context_providers:
            provider.before_run(agent=self, session=session_id, context=context, state=state)
        response = f"Answering with memory context: {state['sanctuary_memory_context']}"
        state["sanctuary_memory_text"] = f"User asked about: {prompt}"
        for provider in self.context_providers:
            provider.after_run(agent=self, session=session_id, context=context, state=state)
        return {"response": response, "state": state}


def main() -> None:
    provider = SanctuaryContextProvider(
        client=DemoMemoryTools(),
        operator_id="operator-demo",
        agent_id="agent-demo",
    )
    agent = InterfaceShapedAgent(context_providers=[provider])
    first = agent.run("release notes", session_id="demo-session")
    second = agent.run("release notes", session_id="demo-session")
    print(first["response"])
    print(second["response"])


if __name__ == "__main__":
    main()
