"""Output limit fixture. `--help` emits more than typical safe limits."""

import sys


if sys.argv[1:] == ["--help"]:
    sys.stdout.write("H" * 131072)
else:
    raise SystemExit(2)
