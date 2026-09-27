"""Emits an inert synthetic token marker for redaction integration tests."""

import sys


if sys.argv[1:] == ["--help"]:
    print("TOKEN=" + "sk" + "-" + "FAKEEXAMPLE" + "1234567890")
else:
    raise SystemExit(2)
