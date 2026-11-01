"""Scripted MCP peer; all state lives in the caller's temporary directory."""
from __future__ import annotations
import json
import os
import signal
import socket
from pathlib import Path
import sys
import time


def main():
    scenario = json.loads(Path(sys.argv[1]).read_text())
    def record(value):
        with Path(scenario["log"]).open("a") as stream:
            stream.write(json.dumps(value) + "\n")
    record({"event": "spawn"})
    control = None
    if scenario.get("control"):
        control = socket.socket(socket.AF_UNIX)
        control.settimeout(3)  # Matches the outer fixture coordination bound.
        control.connect(scenario["control"])
        control = control.makefile("rwb", buffering=0)
    child = None
    if scenario.get("group_child"):
        parent_ready, child_ready = socket.socketpair()
        parent_ready.settimeout(3)  # Child setup uses the same bounded control window.
        child = os.fork()
        if child == 0:
            if scenario.get("ignore_term"):
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
            os.close(0)
            os.close(1)
            parent_ready.close()
            child_ready.sendall(b"ready")
            child_ready.close()
            while True:
                signal.pause()
        child_ready.close()
        if parent_ready.recv(len(b"ready")) != b"ready":
            raise RuntimeError("child did not become ready")
        parent_ready.close()
    index = 0
    if scenario.get("early_eof"):
        return
    for line in sys.stdin:
        if not line.strip():
            continue
        record({"insert_bytes": "memory_insert" in line})
        request = json.loads(line)
        method = request["method"]
        record({"method": method, "name": request.get("params", {}).get("name"), "id": request.get("id")})
        if method == "notifications/initialized":
            continue
        if method == "initialize":
            result = {"protocolVersion": "2025-11-25"}
            if scenario.get("initialize_fault"):
                result = {}
        elif method == "tools/list":
            result = {"tools": [{"name": name} for name in scenario["catalog"]]}
        else:
            if scenario.get("hold_reply"):
                continue
            steps = scenario.get("steps", [])
            step = steps[min(index, len(steps) - 1)] if steps else {}
            index += 1
            if step.get("delay"):
                time.sleep(step["delay"])
            action = step.get("action")
            if action == "eof":
                return
            if action == "oversize":
                print("x" * scenario["line_cap"], flush=True)
                continue
            if action == "invalid":
                print("{", flush=True)
                continue
            if action == "wrong_id":
                print(json.dumps({"jsonrpc": "2.0", "id": -1, "result": {}}), flush=True)
                continue
            if "rpc_error" in step:
                print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "error": step["rpc_error"]}), flush=True)
                continue
            value = step.get("value", {"outcome": "saved", "inserted": True,
                                        "passage": {"passage_id": "p", "document_id": "d"}})
            result = step.get("raw_result", {"content": [{"type": "text", "text": json.dumps(value)}]})
        print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)
        if method == "tools/list" and control is not None:
            control.write(b"paused\n")
            while True:
                command = control.readline()
                if command == b"child\n":
                    control.write((str(child) + "\n").encode())
                elif command == b"drain\n":
                    os.set_blocking(0, False)
                    while True:
                        try:
                            data = os.read(0, scenario["line_cap"])
                        except BlockingIOError:
                            break
                        if not data:
                            break
                        record({"insert_bytes": b"memory_insert" in data})
                    os.set_blocking(0, True)
                    control.write(b"drained\n")
                    break
                elif command == b"resume\n":
                    control.write(b"resumed\n")
                    break
                else:
                    return


if __name__ == "__main__":
    main()
