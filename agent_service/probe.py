"""Opt-in, bounded command observations for the Capability Passport service.

This is a command policy and resource limit, not a security sandbox. In
particular, importing a Python module can have side effects, and network
isolation is not enforced. Never derive ``commands`` from a README here:
the caller must supply each command explicitly.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shlex
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


_OUTPUT_LIMIT = 32 * 1024
_MAX_COMMAND_LENGTH = 4096
_MODULE = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\Z", re.ASCII)
_FORBIDDEN = re.compile(r"[;&|<>`$(){}~*!?\x00-\x1f\\]")
_SECRETS = (
    re.compile(r"(?i)\b(?:sk|ark)-[A-Za-z0-9._-]*"),
    re.compile(r"(?i)\bBearer\s+\S+"),
    re.compile(r"(?i)\b((?:api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*)[\"']?[^\s,\"']+"),
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _redact(value: str) -> str:
    value = _SECRETS[0].sub("[REDACTED]", value)
    value = _SECRETS[1].sub("Bearer [REDACTED]", value)
    return _SECRETS[2].sub(lambda match: match.group(1) + "[REDACTED]", value)


def _validate(command: str, cwd: Path, allow_side_effects: bool) -> tuple[list[str], str]:
    if not isinstance(command, str) or not command or len(command) > _MAX_COMMAND_LENGTH:
        raise ValueError("command must be a nonempty string of at most 4096 characters")
    if _FORBIDDEN.search(command):
        raise ValueError("shell metacharacters, backslashes and control characters are prohibited")
    try:
        parts = shlex.split(command, posix=True)
    except ValueError as exc:
        raise ValueError("invalid command quoting") from exc
    if not parts or parts[0] not in {"python", "python3"}:
        raise ValueError("executable_not_allowed: only python or python3")

    args = parts[1:]
    if not args:
        raise ValueError("a documented --help, --version or --list action is required")
    if args[0] == "-m":
        if len(args) < 3 or not _MODULE.fullmatch(args[1]):
            raise ValueError("-m requires a dotted Python module name and an action")
        action = args[2:]
    elif args[0].endswith(".py"):
        script = (cwd / args[0]).resolve()
        if not script.is_relative_to(cwd) or not script.is_file():
            raise ValueError("Python script must be an existing file inside cwd")
        args[0] = str(script)
        action = args[1:]
    else:
        action = args

    if action in (["--help"], ["--version"], ["--list"]):
        risk_tier = "low"
    elif action and action[0] == "status":
        if not allow_side_effects:
            raise ValueError("status requires allow_side_effects=true")
        if args[:2] != ["-m", "agent_service"]:
            raise ValueError("status is allowed only for python -m agent_service")
        if len(action) == 1:
            pass
        elif len(action) == 3 and action[1] == "--json":
            try:
                if not isinstance(json.loads(action[2]), dict):
                    raise ValueError("status --json must contain a JSON object")
            except json.JSONDecodeError as exc:
                raise ValueError("status --json must contain valid JSON") from exc
        else:
            raise ValueError("only status and status --json OBJECT are allowed")
        risk_tier = "elevated"
    else:
        raise ValueError("action must be exactly --help, --version or --list")
    return [sys.executable, *args], risk_tier


def _execute(argv: list[str], cwd: Path, timeout: int, env: dict[str, str]) -> tuple[int, str, str, bool, bool]:
    """Capture at most 32 KiB across stdout/stderr and kill process groups."""
    stdout = bytearray()
    stderr = bytearray()
    truncated = False
    timed_out = False
    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            assert proc.stdout is not None and proc.stderr is not None
            for pipe, target in ((proc.stdout, stdout), (proc.stderr, stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, target)
            while selector.get_map() or proc.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                if not selector.get_map():
                    time.sleep(min(remaining, 0.05))
                    continue
                for key, _ in selector.select(timeout=min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    room = _OUTPUT_LIMIT - len(stdout) - len(stderr)
                    key.data.extend(chunk)
                    if len(chunk) > room:
                        # Retain a tail, not a prefix, while keeping combined
                        # captured output within the global byte limit.
                        overflow = len(stdout) + len(stderr) - _OUTPUT_LIMIT
                        if overflow:
                            del key.data[: min(len(key.data), overflow)]
                            overflow = len(stdout) + len(stderr) - _OUTPUT_LIMIT
                            if overflow:
                                other = stderr if key.data is stdout else stdout
                                del other[:overflow]
                        truncated = True
                        break
                if truncated:
                    break
    finally:
        if proc.poll() is None or truncated or timed_out:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        proc.wait()
        if proc.stdout is not None:
            proc.stdout.close()
        if proc.stderr is not None:
            proc.stderr.close()
    return (
        proc.returncode,
        stdout.decode("utf-8", errors="ignore"),
        stderr.decode("utf-8", errors="ignore"),
        truncated,
        timed_out,
    )


def safe_probe(arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute only caller supplied, allowlisted commands and return evidence.

    ``budget`` limits command count to eight. ``timeout`` is a per-command
    limit of at most ten seconds. Rejected commands are never executed.
    """
    if not isinstance(arguments, dict):
        raise ValueError("probe input must be an object")
    commands = arguments.get("commands")
    if not isinstance(commands, list) or not all(isinstance(cmd, str) for cmd in commands):
        raise ValueError("commands must be an array of strings")
    path = arguments.get("cwd")
    if not isinstance(path, str) or not path:
        raise ValueError("cwd must name an existing directory")
    cwd = Path(path).resolve()
    if not cwd.is_dir():
        raise ValueError("cwd must name an existing directory")
    allow_side_effects = arguments.get("allow_side_effects", False)
    timeout = arguments.get("timeout", 5)
    budget = arguments.get("budget", 8)
    if type(allow_side_effects) is not bool:
        raise ValueError("allow_side_effects must be a boolean")
    if type(timeout) is not int or not 1 <= timeout <= 10:
        raise ValueError("timeout must be an integer from 1 to 10")
    if type(budget) is not int or not 1 <= budget <= 8:
        raise ValueError("budget must be an integer from 1 to 8")

    # Do not inherit tokens, proxies, home configuration or Python startup hooks.
    env = {
        "PATH": os.defpath,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    environment_identity = {
        "env": env,
        "os": platform.system(),
        "os_release": platform.release(),
        "machine": platform.machine(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
    }
    fingerprint = hashlib.sha256(
        json.dumps(environment_identity, sort_keys=True).encode("utf-8")
    ).hexdigest()
    evidence: list[dict[str, Any]] = []
    rejected: list[dict[str, str]] = []
    probe_id, timestamp = uuid4().hex, _now()
    result = {
        "probe_id": probe_id,
        "ts": timestamp,
        "envelope": {"probe_id": probe_id, "ts": timestamp, "env_fingerprint": fingerprint},
        "evidence": evidence,
        "rejected": rejected,
    }
    for index, command in enumerate(commands):
        safe_command = _redact(command)
        if index >= budget:
            rejected.append({"cmd": safe_command, "reason": "budget_exceeded"})
            continue
        try:
            argv, tier = _validate(command, cwd, allow_side_effects)
        except ValueError as exc:
            detail = str(exc)
            if "shell metacharacters" in detail:
                reason = "metachar"
            elif "executable_not_allowed" in detail:
                reason = "executable_not_allowed"
            elif "action must be" in detail:
                reason = "allowlist"
            elif "inside cwd" in detail:
                reason = "path_escape"
            elif "allow_side_effects" in detail:
                reason = "need_allow_side_effects"
            else:
                reason = "invalid_command"
            rejected.append({"cmd": safe_command, "reason": reason})
            continue
        started = time.monotonic()
        try:
            exit_code, out, err, truncated, timed_out = _execute(argv, cwd, timeout, env)
        except OSError as exc:
            rejected.append({"cmd": safe_command, "reason": f"execution failed: {type(exc).__name__}"})
            continue
        # Both the human-visible evidence and its digest use redacted text.
        out, err = _redact(out), _redact(err)
        digest = hashlib.sha256((out + "\n" + err).encode("utf-8")).hexdigest()
        evidence.append({
            "cmd": safe_command,
            "exit_code": None if timed_out else exit_code,
            "stdout_tail": out,
            "stderr_tail": err,
            "sha256": digest,
            "duration_ms": round((time.monotonic() - started) * 1000),
            "env_fingerprint": fingerprint,
            "redacted": True,
            "network_isolation": "not-enforced",
            "timestamp": _now(),
            "risk_tier": tier,
            "truncated": truncated,
            "timed_out": timed_out,
        })
        if timed_out:
            rejected.append({"cmd": safe_command, "reason": "timeout"})
    return result
