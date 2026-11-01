"""Scripted MCP peer; all state lives in the caller's temporary directory."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import time


def main():
    scenario = json.loads(Path(sys.argv[1]).read_text())
    def record(value):
        with Path(scenario["log"]).open("a") as stream:
            stream.write(json.dumps(value) + "\n")
    record({"event": "spawn"})
    index = 0
    if scenario.get("early_eof"):
        return
    for line in sys.stdin:
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


if __name__ == "__main__":
    main()
