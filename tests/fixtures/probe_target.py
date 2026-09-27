"""Harmless test target for allowlisted local probes."""

import argparse
import json


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe target fixture")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--version", action="store_true")
    group.add_argument("--list", action="store_true")
    group.add_argument("--delete", action="store_true")
    args = parser.parse_args()
    if args.version:
        print("probe-target 1.2.3")
    elif args.list:
        print(json.dumps({"tools": ["status"]}))
    elif args.delete:
        # Sentinel only: if the runner ever invokes this flag, the test can
        # observe policy failure without changing files.
        print("FORBIDDEN_ACTION_INVOKED")
        return 99
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
