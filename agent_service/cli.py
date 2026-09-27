"""CLI entrypoint: one JSON input and one JSON output for other agents.

Error contract (SharedNet room #9/#11): every failure is reported as a single
JSON object on stderr of the form {"error_code": ..., "message": ...} and the
process exits with status 2. stdout is reserved for successful tool output so
calling agents can parse one stream per outcome.
"""

from __future__ import annotations

import argparse
import json
import sys

from .core import TOOLS, call_tool

EXIT_ERROR = 2

# Room #9 contract v1 error codes. The CLI maps local failures onto this set;
# core tool errors may carry their own code via ToolError.code if provided.
E_SCHEMA = "E_SCHEMA"
E_INTERNAL = "E_INTERNAL"


def emit_error(error_code: str, message: str) -> int:
    payload = {"error_code": error_code, "message": message}
    print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), file=sys.stderr)
    return EXIT_ERROR


def main() -> int:
    parser = argparse.ArgumentParser(prog="agent-room")
    parser.add_argument("tool", nargs="?", help="Tool name")
    parser.add_argument(
        "--json", default="{}", help="JSON object of tool arguments; use '-' for stdin"
    )
    parser.add_argument("--list", action="store_true", help="List tool schemas as JSON")
    args = parser.parse_args()

    try:
        if args.list:
            output = {
                name: {key: value for key, value in tool.items() if key != "handler"}
                for name, tool in TOOLS.items()
            }
        else:
            if not args.tool:
                return emit_error(E_SCHEMA, "Tool name required; use --list to inspect tools")
            raw = sys.stdin.read() if args.json == "-" else args.json
            try:
                arguments = json.loads(raw)
            except json.JSONDecodeError as exc:
                return emit_error(E_SCHEMA, f"Invalid --json input: {exc}")
            if not isinstance(arguments, dict):
                return emit_error(E_SCHEMA, "Tool arguments must be a JSON object")
            output = call_tool(args.tool, arguments)
        print(json.dumps(output, ensure_ascii=False, separators=(",", ":")))
        return 0
    except Exception as exc:  # noqa: BLE001 - every failure must stay JSON-shaped
        error_code = getattr(exc, "error_code", None) or getattr(exc, "code", None)
        if isinstance(error_code, str) and error_code.startswith("E_"):
            return emit_error(error_code, str(exc))
        if isinstance(exc, (ValueError, TypeError, KeyError)):
            return emit_error(E_SCHEMA, str(exc))
        return emit_error(E_INTERNAL, str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
