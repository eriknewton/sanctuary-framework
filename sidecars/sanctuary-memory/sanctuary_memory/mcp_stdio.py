"""Minimal MCP stdio client for Sanctuary memory tools.

The unit tests for this sidecar use an in-process fake and never spawn a real
Sanctuary server. This client is the production transport seam for a
coordinator-run live round-trip against a pre-seeded, keychain-free fortress.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
from collections.abc import Mapping
from typing import Any


class McpStdioError(RuntimeError):
    """Raised when the MCP stdio transport fails."""


class McpStdioClient:
    """JSON-RPC client for MCP over stdio using Content-Length framing."""

    def __init__(
        self,
        command: list[str],
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        initialize: bool = True,
    ) -> None:
        if not command:
            raise ValueError("command must not be empty")
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        self._process = subprocess.Popen(
            command,
            cwd=cwd,
            env=merged_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._next_id = 1
        self._lock = threading.Lock()
        if initialize:
            self.initialize()

    def close(self) -> None:
        if self._process.poll() is not None:
            return
        self._process.terminate()
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=5)

    def initialize(self) -> None:
        self._request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "sanctuary-memory-provider",
                    "version": "0.1.0",
                },
            },
        )
        self._notify("notifications/initialized", {})

    def call_tool(self, name: str, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        response = self._request(
            "tools/call",
            {
                "name": name,
                "arguments": dict(arguments),
            },
        )
        content = response.get("content")
        if not isinstance(content, list) or not content:
            raise McpStdioError(f"MCP tool {name} returned no content")
        first = content[0]
        if not isinstance(first, Mapping) or first.get("type") != "text":
            raise McpStdioError(f"MCP tool {name} returned non-text content")
        text = first.get("text")
        if not isinstance(text, str):
            raise McpStdioError(f"MCP tool {name} returned malformed text content")
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise McpStdioError(f"MCP tool {name} returned invalid JSON text") from exc
        if not isinstance(parsed, Mapping):
            raise McpStdioError(f"MCP tool {name} returned non-object JSON")
        return parsed

    def _request(self, method: str, params: Mapping[str, Any]) -> Mapping[str, Any]:
        with self._lock:
            request_id = self._next_id
            self._next_id += 1
            self._write_message(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": method,
                    "params": dict(params),
                }
            )
            while True:
                message = self._read_message()
                if message.get("id") != request_id:
                    continue
                if "error" in message:
                    raise McpStdioError(f"MCP request {method} failed: {message['error']}")
                result = message.get("result")
                if not isinstance(result, Mapping):
                    raise McpStdioError(f"MCP request {method} returned malformed result")
                return result

    def _notify(self, method: str, params: Mapping[str, Any]) -> None:
        with self._lock:
            self._write_message(
                {
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": dict(params),
                }
            )

    def _write_message(self, message: Mapping[str, Any]) -> None:
        if self._process.stdin is None:
            raise McpStdioError("MCP process stdin is closed")
        body = json.dumps(message, separators=(",", ":")).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        self._process.stdin.write(header + body)
        self._process.stdin.flush()

    def _read_message(self) -> Mapping[str, Any]:
        if self._process.stdout is None:
            raise McpStdioError("MCP process stdout is closed")
        headers: dict[str, str] = {}
        while True:
            line = self._process.stdout.readline()
            if line == b"":
                raise McpStdioError("MCP process closed stdout")
            if line in (b"\r\n", b"\n"):
                break
            key, sep, value = line.decode("ascii").partition(":")
            if not sep:
                raise McpStdioError("Malformed MCP frame header")
            headers[key.lower()] = value.strip()
        try:
            length = int(headers["content-length"])
        except (KeyError, ValueError) as exc:
            raise McpStdioError("MCP frame missing valid Content-Length") from exc
        body = self._process.stdout.read(length)
        if len(body) != length:
            raise McpStdioError("MCP frame ended early")
        try:
            parsed = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise McpStdioError("MCP frame body is not JSON") from exc
        if not isinstance(parsed, Mapping):
            raise McpStdioError("MCP frame body is not a JSON object")
        return parsed

    def __enter__(self) -> "McpStdioClient":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
