"""Minimal MCP stdio adapter for the shared core tool registry.

MCP stdio transports one JSON-RPC message per line. Protocol output goes
only to stdout; a client may send notifications that require no reply.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from .core import TOOLS, call_tool


def response(message: dict[str, Any]) -> dict[str, Any] | None:
    if "id" not in message:
        return None
    request_id = message["id"]
    method = message.get("method")
    try:
        if method == "initialize":
            result = {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "CapPass", "version": "0.1.0"},
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {
                "tools": [
                    {"name": name, "description": tool["description"], "inputSchema": tool["inputSchema"]}
                    for name, tool in TOOLS.items()
                ]
            }
        elif method == "tools/call":
            params = message.get("params", {})
            try:
                data = call_tool(params["name"], params.get("arguments", {}))
                result = {
                    "content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False)}],
                    "structuredContent": data if isinstance(data, dict) else {"result": data},
                    "isError": False,
                }
            except Exception as exc:
                code = getattr(exc, "code", "E_INTERNAL")
                if not isinstance(code, str) or not code.startswith("E_"):
                    code = "E_SCHEMA" if isinstance(exc, (ValueError, KeyError)) else "E_INTERNAL"
                message = str(exc) if code != "E_INTERNAL" else "Internal tool error"
                result = {"content": [{"type": "text", "text": json.dumps({"error_code": code, "message": message})}], "isError": True}
        else:
            return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "Method not found"}}
        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    except Exception as exc:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32603, "message": str(exc)}}


def main() -> int:
    for line in sys.stdin:
        try:
            incoming = json.loads(line)
            if not isinstance(incoming, dict):
                continue
            outgoing = response(incoming)
            if outgoing is not None:
                print(json.dumps(outgoing, ensure_ascii=False, separators=(",", ":")), flush=True)
        except (ValueError, json.JSONDecodeError) as exc:
            print(f"MCP input error: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
