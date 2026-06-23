from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from sanctuary_memory import (
    ContentHashMismatch,
    DeleteRequestResult,
    MemoryWriteRejected,
    SanctuaryContextProvider,
    content_hash_for_text,
    owner_ref_for,
    session_tag_for,
)


class FakeSession:
    def __init__(self, session_id: str) -> None:
        self.session_id = session_id


class FakeMemoryTools:
    def __init__(self, *, tamper_get_hash: bool = False) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.passages: dict[str, dict[str, Any]] = {}
        self.tamper_get_hash = tamper_get_hash
        self.next_id = 1

    def call_tool(self, name: str, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        args = dict(arguments)
        self.calls.append((name, args))
        if name == "memory_insert":
            return self._insert(args)
        if name == "memory_search":
            return self._search(args)
        if name == "memory_get":
            return self._get(args)
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
        raise AssertionError(f"unexpected tool call: {name}")

    def _insert(self, args: dict[str, Any]) -> Mapping[str, Any]:
        text = args["text"]
        if "ghp_" in text or "BEGIN PRIVATE KEY" in text:
            return {
                "denied": True,
                "message": "This action is not available in the current context.",
                "remediation_class": "request_review",
                "retry_after": None,
                "audit_ref": "audit:memory_insert",
            }
        passage_id = args.get("passage_id") or f"p{self.next_id}"
        self.next_id += 1
        passage = {
            "passage_id": passage_id,
            "owner_ref": "fleet-self",
            "text": text,
            "tags": list(args.get("tags", [])),
            "metadata": [],
            "created_at": "2026-06-23T00:00:00Z",
            "chunk_count": 1,
            "content_hash": content_hash_for_text(text),
        }
        self.passages[passage_id] = passage
        return {
            "inserted": True,
            "passage": {
                "passage_id": passage_id,
                "owner_ref": "fleet-self",
                "content_hash": passage["content_hash"],
                "created_at": passage["created_at"],
                "chunk_count": 1,
                "tag_count": len(passage["tags"]),
            },
        }

    def _search(self, args: dict[str, Any]) -> Mapping[str, Any]:
        needle = args.get("text", "").lower()
        tag = args.get("tag")
        limit = args.get("limit", 10)
        results = []
        for passage in self.passages.values():
            if isinstance(tag, str) and tag not in passage["tags"]:
                continue
            match_count = passage["text"].lower().count(needle) if needle else 0
            if match_count == 0:
                continue
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
                    "match_count": match_count,
                }
            )
        return {"results": results[:limit]}

    def _get(self, args: dict[str, Any]) -> Mapping[str, Any]:
        passage = self.passages.get(args["passage_id"])
        if passage is None:
            return {"found": False}
        out = dict(passage)
        if self.tamper_get_hash:
            out["content_hash"] = "tampered"
        return {"found": True, "passage": out}


def test_round_trip_store_and_retrieve_with_content_hash() -> None:
    fake = FakeMemoryTools()
    provider = SanctuaryContextProvider(
        client=fake,
        operator_id="operator-a",
        agent_id="agent-a",
    )
    state: dict[str, Any] = {
        "sanctuary_memory_text": "The user prefers concise release notes.",
        "sanctuary_memory_query": "release notes",
    }

    provider.after_run(session=FakeSession("session-1"), context={}, state=state)

    writes = state["sanctuary_memory_writes"]
    assert len(writes) == 1
    assert writes[0]["content_hash"] == content_hash_for_text(
        "The user prefers concise release notes."
    )
    assert "mem_type:chat-summary" in writes[0]["tags"]
    assert session_tag_for("session-1") in writes[0]["tags"]

    read_state: dict[str, Any] = {"sanctuary_memory_query": "release notes"}
    context: dict[str, Any] = {}
    provider.before_run(session=FakeSession("session-1"), context=context, state=read_state)

    assert read_state["sanctuary_memories"][0]["text"] == (
        "The user prefers concise release notes."
    )
    assert read_state["sanctuary_memory_context"] == (
        "The user prefers concise release notes."
    )
    assert context["sanctuary_memory_context"] == read_state["sanctuary_memory_context"]
    assert [name for name, _args in fake.calls] == [
        "memory_insert",
        "memory_search",
        "memory_get",
    ]


def test_session_mapping_adds_scope_and_tags() -> None:
    fake = FakeMemoryTools()
    provider = SanctuaryContextProvider(
        client=fake,
        operator_id="operator-a",
        agent_id="agent-a",
    )
    state: dict[str, Any] = {
        "sanctuary_memory_items": [
            {
                "text": "Use the weekly finance checklist.",
                "memory_type": "procedural",
                "tags": ["workflow:finance"],
            }
        ]
    }

    provider.after_run(session=FakeSession("session-42"), context={}, state=state)

    insert_args = fake.calls[0][1]
    assert provider.owner_ref == owner_ref_for("operator-a", "agent-a")
    assert "mem_type:procedural" in insert_args["tags"]
    assert "workflow:finance" in insert_args["tags"]
    assert session_tag_for("session-42") in insert_args["tags"]
    metadata = state["sanctuary_memory_writes"][0]["profile_metadata"]
    assert {"key": "ttl_policy", "value": "operator_controlled_no_silent_expiry"} in metadata


def test_content_hash_mismatch_fails_closed() -> None:
    fake = FakeMemoryTools(tamper_get_hash=True)
    provider = SanctuaryContextProvider(client=fake)
    state: dict[str, Any] = {
        "sanctuary_memory_text": "Quarterly planning memory.",
        "sanctuary_memory_query": "planning",
    }
    provider.after_run(session=FakeSession("session-1"), context={}, state=state)

    with pytest.raises(ContentHashMismatch):
        provider.before_run(
            session=FakeSession("session-1"),
            context={},
            state={"sanctuary_memory_query": "planning"},
        )


def test_secret_bearing_memory_is_rejected_by_write_gate_stub() -> None:
    fake = FakeMemoryTools()
    provider = SanctuaryContextProvider(client=fake)

    with pytest.raises(MemoryWriteRejected) as exc_info:
        provider.after_run(
            session=FakeSession("session-1"),
            context={},
            state={"sanctuary_memory_text": "token ghp_example_secret must not persist"},
        )

    assert exc_info.value.payload["denied"] is True
    assert fake.passages == {}


def test_delete_request_surfaces_pending_operator_approval() -> None:
    fake = FakeMemoryTools()
    provider = SanctuaryContextProvider(client=fake)

    result = provider.request_delete("p1")

    assert isinstance(result, DeleteRequestResult)
    assert result.status == "pending_operator_approval"
    assert result.deleted is False
    assert result.audit_ref == "audit:gate:memory_delete"


def test_after_run_without_memory_still_calls_audited_read_tool() -> None:
    fake = FakeMemoryTools()
    provider = SanctuaryContextProvider(client=fake)
    state: dict[str, Any] = {}

    provider.after_run(session=FakeSession("session-1"), context={}, state=state)

    assert fake.calls == [("memory_count", {})]
    assert state["sanctuary_memory_writes"] == []


# TODO(coordinator): add the live MCP-stdio round-trip against a real Sanctuary
# server only after provisioning a keychain-free test fortress with a durable
# escrow target. This test file intentionally stays on the stubbed in-process
# six-tool layer for this build and never spawns the server locally.
