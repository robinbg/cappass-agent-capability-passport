"""Timeout fixture. `--help` intentionally waits instead of exiting."""

import sys
import time


if sys.argv[1:] == ["--help"]:
    time.sleep(2)
    print("slow help")
else:
    raise SystemExit(2)
