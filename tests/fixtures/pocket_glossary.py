"""Deterministic local sample CLI for an explicitly authorized runner test."""

import argparse
import json
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", required=True)
    args = parser.parse_args()
    try:
        payload = json.loads(args.json)
        term = payload["term"]
        if not isinstance(term, str) or not term:
            raise ValueError("term must be a non-empty string")
        definition = {
            "MCP": "A protocol for connecting an AI client to tools and context."
        }.get(term, "No definition is available for this term.")
        print(json.dumps({"term": term, "definition": definition}, ensure_ascii=False))
        return 0
    except (ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
