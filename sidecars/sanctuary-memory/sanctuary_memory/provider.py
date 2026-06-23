"""SDW-backed ContextProvider for Microsoft Agent Framework memory."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

try:  # pragma: no cover - unavailable in the offline build venv.
    from agent_framework import ContextProvider as _MicrosoftContextProvider

    MICROSOFT_CONTEXT_PROVIDER_IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover - exercised by import-time constant.
    _MicrosoftContextProvider = object
    MICROSOFT_CONTEXT_PROVIDER_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"


MICROSOFT_CONTEXT_PROVIDER_AVAILABLE = (
    MICROSOFT_CONTEXT_PROVIDER_IMPORT_ERROR is None
)

VALID_MEMORY_TYPES = {"procedural", "user-profile", "chat-summary"}
VALID_TAINTS = {"user_content", "agent_derived_clean", "system_generated"}
DEFAULT_STATE_CONTEXT_KEY = "sanctuary_memory_context"
DEFAULT_STATE_MEMORIES_KEY = "sanctuary_memories"
DEFAULT_STATE_WRITES_KEY = "sanctuary_memory_writes"


class SanctuaryMemoryError(RuntimeError):
    """Base class for provider failures."""


class ContentHashMismatch(SanctuaryMemoryError):
    """Raised when a returned passage does not match its SDW content hash."""


class MemoryWriteRejected(SanctuaryMemoryError):
    """Raised when SDW rejects a memory write."""

    def __init__(self, payload: Mapping[str, Any]) -> None:
        super().__init__("SDW rejected the memory write")
        self.payload = dict(payload)


class MemoryToolClient(Protocol):
    """Minimal client protocol for the six shipped SDW memory tools."""

    def call_tool(self, name: str, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        """Call one SDW memory tool and return its parsed JSON payload."""


@dataclass(frozen=True)
class RetrievedMemory:
    passage_id: str
    text: str
    content_hash: str
    tags: tuple[str, ...]
    owner_ref: str | None = None
    created_at: str | None = None
    match_count: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "passage_id": self.passage_id,
            "text": self.text,
            "content_hash": self.content_hash,
            "tags": list(self.tags),
            "owner_ref": self.owner_ref,
            "created_at": self.created_at,
            "match_count": self.match_count,
        }


@dataclass(frozen=True)
class WriteResult:
    passage_id: str
    content_hash: str
    tags: tuple[str, ...]
    profile_metadata: tuple[dict[str, str], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "passage_id": self.passage_id,
            "content_hash": self.content_hash,
            "tags": list(self.tags),
            "profile_metadata": [dict(item) for item in self.profile_metadata],
        }


@dataclass(frozen=True)
class DeleteRequestResult:
    status: str
    passage_id: str
    audit_ref: str | None = None
    deleted: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "passage_id": self.passage_id,
            "audit_ref": self.audit_ref,
            "deleted": self.deleted,
        }


def content_hash_for_text(text: str) -> str:
    """Return the SDW memory-passage content hash for `text`."""

    digest = hashlib.sha256(
        b"sdw-memory-passage-content-v1\n" + text.encode("utf-8")
    ).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _hash_component(domain: str, value: str) -> str:
    digest = hashlib.sha256(f"{domain}\0{value}".encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def owner_ref_for(operator_id: str, agent_id: str) -> str:
    body = f"{operator_id}\0{agent_id}"
    return _hash_component("sdw-ms-owner-v1", body)


def session_tag_for(session_id: str) -> str:
    return f"session_id:{_hash_component('sdw-ms-session-v1', session_id)}"


def agent_tag_for(agent_id: str) -> str:
    return f"agent_id:{_hash_component('sdw-ms-agent-v1', agent_id)}"


def ms_scope_tag_for(operator_id: str, agent_id: str, session_id: str) -> str:
    body = f"{operator_id}\0{agent_id}\0{session_id}"
    return f"ms_scope:{_hash_component('sanctuary-ms-scope-v1', body)}"


def foundry_memory_type_tag(memory_type: str) -> str:
    if memory_type not in VALID_MEMORY_TYPES:
        raise ValueError(f"unsupported memory_type: {memory_type}")
    return f"mem_type:{memory_type}"


class SanctuaryContextProvider(_MicrosoftContextProvider):  # type: ignore[misc]
    """Microsoft Agent Framework ContextProvider backed by SDW memory tools.

    Live subclassing against Microsoft `agent_framework.ContextProvider` is
    unverified in this offline environment. When the package is importable, this
    class subclasses it. Otherwise it subclasses `object` and follows the
    documented `before_run` / `after_run` lifecycle contract.
    """

    live_ms_subclassing_verified = False
    microsoft_context_provider_available = MICROSOFT_CONTEXT_PROVIDER_AVAILABLE
    microsoft_context_provider_import_error = MICROSOFT_CONTEXT_PROVIDER_IMPORT_ERROR

    def __init__(
        self,
        *,
        client: MemoryToolClient | None = None,
        server_command: Sequence[str] | None = None,
        server_cwd: str | None = None,
        server_env: Mapping[str, str] | None = None,
        operator_id: str | None = None,
        agent_id: str | None = None,
        search_limit: int = 5,
        default_memory_type: str = "chat-summary",
        default_taint: str = "agent_derived_clean",
    ) -> None:
        try:
            super().__init__()  # type: ignore[misc]
        except TypeError:
            # The real package may grow required base init args. The provider
            # has no state to give it in this documented-contract build.
            pass
        if client is not None and server_command is not None:
            raise ValueError("pass either client or server_command, not both")
        if search_limit < 1:
            raise ValueError("search_limit must be positive")
        if default_memory_type not in VALID_MEMORY_TYPES:
            raise ValueError(f"unsupported default_memory_type: {default_memory_type}")
        if default_taint not in VALID_TAINTS:
            raise ValueError(f"unsupported default_taint: {default_taint}")
        if not operator_id or not agent_id:
            raise ValueError(
                "operator_id and agent_id are required for memory scope isolation"
            )
        self.operator_id = operator_id
        self.agent_id = agent_id
        self.owner_ref = owner_ref_for(operator_id, agent_id)
        self.search_limit = search_limit
        self.default_memory_type = default_memory_type
        self.default_taint = default_taint
        if client is not None:
            self._client = client
            self._owns_client = False
        else:
            if server_command is None:
                raise ValueError("client or server_command is required")
            from .mcp_stdio import McpStdioClient

            self._client = McpStdioClient(
                list(server_command),
                cwd=server_cwd,
                env=server_env,
            )
            self._owns_client = True

    def close(self) -> None:
        close = getattr(self._client, "close", None)
        if self._owns_client and callable(close):
            close()

    def before_run(
        self,
        *,
        agent: Any = None,
        session: Any = None,
        context: Any = None,
        state: Any = None,
    ) -> None:
        session_id = self._session_id(session, state)
        query = self._query_text(context, state)
        session_tag = session_tag_for(session_id)
        scope_tag = ms_scope_tag_for(self.operator_id, self.agent_id, session_id)
        payload = self._call_tool(
            "memory_search",
            {
                "text": query,
                "tag": scope_tag,
                "limit": self.search_limit,
            },
        )
        memories = self._hydrate_search_results(payload)
        context_text = self._format_context(memories)
        bundle = {
            "owner_ref": self.owner_ref,
            "session_id": session_id,
            "session_tag": session_tag,
            "ms_scope_tag": scope_tag,
            "query": query,
            "memories": [memory.as_dict() for memory in memories],
            "context_text": context_text,
        }
        self._inject(context, state, bundle)

    def after_run(
        self,
        *,
        agent: Any = None,
        session: Any = None,
        context: Any = None,
        state: Any = None,
    ) -> None:
        session_id = self._session_id(session, state)
        writes: list[WriteResult] = []
        items = self._memory_items(context, state)
        if not items:
            # Read-only no-op call so a provider hook invocation still reaches
            # the audited MCP layer without inventing a new audit path.
            self._call_tool("memory_count", {})
            self._store_state_value(state, DEFAULT_STATE_WRITES_KEY, [])
            return
        for item in items:
            writes.append(self._insert_item(item, session_id))
        self._store_state_value(
            state,
            DEFAULT_STATE_WRITES_KEY,
            [write.as_dict() for write in writes],
        )

    def request_delete(self, passage_id: str) -> DeleteRequestResult:
        payload = self._call_tool("memory_delete", {"passage_id": passage_id})
        if payload.get("denied") is True:
            return DeleteRequestResult(
                status="pending_operator_approval",
                passage_id=passage_id,
                audit_ref=_string_or_none(payload.get("audit_ref")),
                deleted=False,
            )
        if payload.get("deleted") is True:
            return DeleteRequestResult(
                status="deleted_after_operator_approval",
                passage_id=passage_id,
                deleted=True,
            )
        return DeleteRequestResult(
            status="not_found",
            passage_id=passage_id,
            deleted=False,
        )

    def _insert_item(self, item: Mapping[str, Any], session_id: str) -> WriteResult:
        text = _required_string(item, "text")
        memory_type = _string_value(item.get("memory_type"), self.default_memory_type)
        if memory_type not in VALID_MEMORY_TYPES:
            raise ValueError(f"unsupported memory_type: {memory_type}")
        taint = _string_value(item.get("taint"), self.default_taint)
        if taint not in VALID_TAINTS:
            raise ValueError(f"unsupported taint: {taint}")
        tags = self._tags_for(session_id, memory_type, item.get("tags"))
        args: dict[str, Any] = {
            "text": text,
            "taint": taint,
            "tags": tags,
        }
        passage_id = item.get("passage_id")
        if isinstance(passage_id, str) and passage_id:
            args["passage_id"] = passage_id
        payload = self._call_tool("memory_insert", args)
        if payload.get("denied") is True or payload.get("inserted") is not True:
            raise MemoryWriteRejected(payload)
        passage = payload.get("passage")
        if not isinstance(passage, Mapping):
            raise SanctuaryMemoryError("memory_insert returned no passage metadata")
        returned_hash = _required_string(passage, "content_hash")
        expected_hash = content_hash_for_text(text)
        if returned_hash != expected_hash:
            raise ContentHashMismatch("memory_insert returned a mismatched content_hash")
        returned_id = _required_string(passage, "passage_id")
        return WriteResult(
            passage_id=returned_id,
            content_hash=returned_hash,
            tags=tuple(tags),
            profile_metadata=tuple(self._profile_metadata(session_id, memory_type)),
        )

    def _hydrate_search_results(self, payload: Mapping[str, Any]) -> list[RetrievedMemory]:
        results = payload.get("results")
        if not isinstance(results, list):
            raise SanctuaryMemoryError("memory_search returned malformed results")
        hydrated: list[RetrievedMemory] = []
        for result in results:
            if not isinstance(result, Mapping):
                continue
            passage_meta = result.get("passage")
            if not isinstance(passage_meta, Mapping):
                continue
            passage_id = _required_string(passage_meta, "passage_id")
            get_payload = self._call_tool("memory_get", {"passage_id": passage_id})
            if get_payload.get("found") is not True:
                continue
            passage = get_payload.get("passage")
            if not isinstance(passage, Mapping):
                raise SanctuaryMemoryError("memory_get returned malformed passage")
            text = _required_string(passage, "text")
            content_hash = _required_string(passage, "content_hash")
            expected_hash = content_hash_for_text(text)
            if content_hash != expected_hash:
                raise ContentHashMismatch(
                    f"memory_get content_hash mismatch for passage {passage_id}"
                )
            tags_value = passage.get("tags")
            tags = tuple(item for item in tags_value if isinstance(item, str)) if isinstance(tags_value, list) else ()
            match_count = result.get("match_count")
            hydrated.append(
                RetrievedMemory(
                    passage_id=passage_id,
                    text=text,
                    content_hash=content_hash,
                    tags=tags,
                    owner_ref=_string_or_none(passage.get("owner_ref")),
                    created_at=_string_or_none(passage.get("created_at")),
                    match_count=match_count if isinstance(match_count, int) else None,
                )
            )
        return hydrated

    def _call_tool(self, name: str, args: Mapping[str, Any]) -> Mapping[str, Any]:
        payload = self._client.call_tool(name, args)
        parsed = _parse_tool_payload(payload)
        if not isinstance(parsed, Mapping):
            raise SanctuaryMemoryError(f"{name} returned a non-object payload")
        return parsed

    def _session_id(self, session: Any, state: Any) -> str:
        from_state = _mapping_get_string(state, "session_id")
        if from_state:
            return from_state
        for attr in ("session_id", "id", "thread_id"):
            value = getattr(session, attr, None)
            if isinstance(value, str) and value:
                return value
        if isinstance(session, str) and session:
            return session
        return "default"

    def _query_text(self, context: Any, state: Any) -> str:
        explicit = _mapping_get_string(state, "sanctuary_memory_query")
        if explicit is not None:
            return explicit
        explicit = _mapping_get_string(context, "sanctuary_memory_query")
        if explicit is not None:
            return explicit
        for key in ("input", "prompt", "query"):
            value = _mapping_get_string(context, key)
            if value:
                return value
        message_text = _latest_message_text(_mapping_get(context, "messages"))
        if message_text:
            return message_text
        return ""

    def _memory_items(self, context: Any, state: Any) -> list[Mapping[str, Any]]:
        raw_items = _mapping_get(state, "sanctuary_memory_items")
        if raw_items is None:
            raw_items = _mapping_get(context, "sanctuary_memory_items")
        if isinstance(raw_items, list):
            items: list[Mapping[str, Any]] = []
            for item in raw_items:
                if isinstance(item, str):
                    items.append({"text": item})
                elif isinstance(item, Mapping):
                    items.append(item)
            return items
        text = _mapping_get_string(state, "sanctuary_memory_text")
        if text is None:
            text = _mapping_get_string(context, "sanctuary_memory_text")
        if text:
            return [{"text": text}]
        return []

    def _tags_for(
        self,
        session_id: str,
        memory_type: str,
        extra_tags: Any,
    ) -> list[str]:
        tags = [
            "ms_agent_framework",
            "sdw_context_provider",
            foundry_memory_type_tag(memory_type),
            ms_scope_tag_for(self.operator_id, self.agent_id, session_id),
            session_tag_for(session_id),
            agent_tag_for(self.agent_id),
        ]
        if isinstance(extra_tags, Sequence) and not isinstance(extra_tags, (str, bytes)):
            for item in extra_tags:
                if isinstance(item, str) and item not in tags:
                    tags.append(item)
        return tags

    def _profile_metadata(
        self,
        session_id: str,
        memory_type: str,
    ) -> list[dict[str, str]]:
        return [
            {"key": "ms_agent_framework_provider", "value": "SanctuaryContextProvider"},
            {"key": "ms_memory_type", "value": memory_type},
            {"key": "session_id_hash", "value": _hash_component("sdw-ms-session-v1", session_id)},
            {"key": "agent_id_hash", "value": _hash_component("sdw-ms-agent-v1", self.agent_id)},
            {"key": "sdw_owner_ref", "value": self.owner_ref},
            {"key": "ttl_policy", "value": "operator_controlled_no_silent_expiry"},
        ]

    def _format_context(self, memories: Sequence[RetrievedMemory]) -> str:
        if not memories:
            return ""
        return "\n\n".join(memory.text for memory in memories)

    def _inject(self, context: Any, state: Any, bundle: Mapping[str, Any]) -> None:
        self._store_state_value(state, DEFAULT_STATE_CONTEXT_KEY, bundle["context_text"])
        self._store_state_value(state, DEFAULT_STATE_MEMORIES_KEY, bundle["memories"])
        if isinstance(context, MutableMapping):
            context[DEFAULT_STATE_CONTEXT_KEY] = bundle["context_text"]
            context[DEFAULT_STATE_MEMORIES_KEY] = bundle["memories"]
        else:
            try:
                setattr(context, DEFAULT_STATE_CONTEXT_KEY, bundle["context_text"])
                setattr(context, DEFAULT_STATE_MEMORIES_KEY, bundle["memories"])
            except Exception:
                pass

    def _store_state_value(self, state: Any, key: str, value: Any) -> None:
        if isinstance(state, MutableMapping):
            state[key] = value
        else:
            try:
                setattr(state, key, value)
            except Exception:
                pass

    def __enter__(self) -> "SanctuaryContextProvider":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _parse_tool_payload(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    if "content" not in payload:
        return payload
    content = payload.get("content")
    if not isinstance(content, list) or not content:
        raise SanctuaryMemoryError("tool payload has no content")
    first = content[0]
    if not isinstance(first, Mapping):
        raise SanctuaryMemoryError("tool payload content is malformed")
    text = first.get("text")
    if not isinstance(text, str):
        raise SanctuaryMemoryError("tool payload text is malformed")
    parsed = json.loads(text)
    if not isinstance(parsed, Mapping):
        raise SanctuaryMemoryError("tool payload text is not a JSON object")
    return parsed


def _mapping_get(obj: Any, key: str) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(key)
    return getattr(obj, key, None)


def _mapping_get_string(obj: Any, key: str) -> str | None:
    value = _mapping_get(obj, key)
    return value if isinstance(value, str) else None


def _latest_message_text(messages: Any) -> str | None:
    if not isinstance(messages, Sequence) or isinstance(messages, (str, bytes)):
        return None
    for message in reversed(messages):
        if isinstance(message, Mapping):
            content = message.get("content")
            if isinstance(content, str) and content:
                return content
            parts = message.get("parts")
            if isinstance(parts, Sequence) and not isinstance(parts, (str, bytes)):
                texts = [
                    part.get("text")
                    for part in parts
                    if isinstance(part, Mapping) and isinstance(part.get("text"), str)
                ]
                if texts:
                    return "\n".join(texts)
        content = getattr(message, "content", None)
        if isinstance(content, str) and content:
            return content
    return None


def _required_string(mapping: Mapping[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise SanctuaryMemoryError(f"expected non-empty string at {key}")
    return value


def _string_value(value: Any, default: str) -> str:
    return value if isinstance(value, str) and value else default


def _string_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None
