"""CapPass core, integrated from SharedNet room designs #2–#5 and #9.

README text is untrusted data. Only the caller may explicitly request a probe.
All CLI and MCP calls use the same registry and JSON result.
"""

from __future__ import annotations

import hashlib
import re
import shlex
from datetime import datetime, timezone
from typing import Any, Callable

from .probe import _redact, safe_probe


class ToolError(ValueError):
    def __init__(self, message: str, code: str = "E_SCHEMA") -> None:
        super().__init__(message)
        self.code = code


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


_COMMAND = re.compile(r"^(?:\$\s*)?(?:python3?|node|npx|uv|docker|curl|wget)\b")
_SUSPECT = re.compile(r"[;|&$><`{}()~*!?\\]|ignore (?:all )?(?:previous|prior) instructions|"
                      r"\bcurl\b|\bwget\b|\brm\s+-|\bchmod\b|\bpip\s+install\b", re.I)
_ENV = re.compile(r"\b[A-Z][A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)\b")


def plan_passport(inp: dict[str, Any]) -> dict[str, Any]:
    """Extract candidate commands with source lines, without running anything."""
    readme = inp["readme"]
    if len(readme) > 200_000:
        raise ToolError("README exceeds 200000 characters")
    name = inp["tool_name"].strip()
    if not name:
        raise ToolError("tool_name cannot be empty")
    candidates: list[dict[str, Any]] = []
    claims: list[dict[str, Any]] = []
    notes: list[dict[str, Any]] = []
    env_names: set[str] = set()
    mcp_candidate: dict[str, Any] | None = None
    for line_number, line in enumerate(readme.splitlines(), 1):
        env_names.update(_ENV.findall(line))
        stripped = line.strip()
        if stripped.startswith("```"):
            continue
        snippets = [m.group(1).strip() for m in re.finditer(r"`([^`]+)`", line)]
        if _COMMAND.search(stripped):
            snippets.insert(0, stripped.removeprefix("$ "))
        if not snippets and _SUSPECT.search(line):
            notes.append({"source_line": line_number, "text": _redact(line[:300]),
                          "injection_suspected": True})
        for snippet in dict.fromkeys(snippets):
            if not _COMMAND.search(snippet):
                continue
            suspicious = bool(_SUSPECT.search(snippet))
            raw = _redact(snippet[:1000])
            candidates.append({"raw_cmd": raw, "source_line": line_number,
                               "risk_tier": "untrusted-candidate" if suspicious else "caller-review-required",
                               "injection_suspected": suspicious,
                               "metachar_hit": bool(re.search(r"[;|&$><`{}()~*!?\\]", snippet))})
            claims.append({"id": f"c_{len(claims)+1}", "capability": raw,
                           "source_line": line_number, "status": "unverified"})
            if ".mcp" in raw and mcp_candidate is None and not suspicious:
                try:
                    parts = shlex.split(raw)
                except ValueError:
                    parts = []
                if (len(parts) == 3 and parts[0] in {"python", "python3"}
                        and parts[1] == "-m" and re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\.mcp", parts[2])):
                    mcp_candidate = {"command": parts[0], "args": parts[1:], "cwd": None}
    return {"tool_name": name, "version_constraint": inp.get("version_constraint"),
            "candidates": candidates, "claims": claims,
            "env_vars": [{"name": n, "required": None, "redacted_hint": "value never captured"}
                         for n in sorted(env_names)],
            "mcp_candidate": mcp_candidate, "untrusted_notes": notes,
            "network_isolation": "not-enforced"}


def _baseline_diff(current: dict[str, Any], old: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    old = old.get("passport_json", old)
    if not isinstance(old, dict):
        raise ToolError("baseline must be a passport object")
    previous = {c.get("capability"): c.get("status") for c in old.get("claims", []) if isinstance(c, dict)}
    latest = {c.get("capability"): c.get("status") for c in current["claims"]}
    changes = []
    for capability in sorted(set(previous) | set(latest), key=str):
        before, after = previous.get(capability), latest.get(capability)
        if before == after:
            continue
        severity = "breaking" if before == "ready" and after != "ready" else "additive" if before is None else "changed"
        changes.append({"path": f"claims.{capability}", "old": before, "new": after, "severity": severity})
    previous_evidence = {e.get("cmd"): e for e in old.get("evidence", []) if isinstance(e, dict)}
    current_evidence = {e.get("cmd"): e for e in current.get("evidence", []) if isinstance(e, dict)}
    for command in sorted(set(previous_evidence) & set(current_evidence), key=str):
        before, after = previous_evidence[command], current_evidence[command]
        for field in ("sha256", "exit_code", "env_fingerprint"):
            if before.get(field) != after.get(field):
                changes.append({"path": f"evidence.{command}.{field}",
                                "old": before.get(field), "new": after.get(field),
                                "severity": "needs-review"})
    verdict = ("regression" if any(c["severity"] == "breaking" for c in changes)
               else "needs-review" if any(c["severity"] in {"needs-review", "changed"} for c in changes)
               else "additive" if changes else "unchanged")
    return changes, verdict


def build_passport(req: dict[str, Any]) -> dict[str, Any]:
    """Render a passport from caller-supplied receipts and optional baseline.

    A receipt has a checkable digest but is not an independently attested run.
    """
    plan, evidence = req["plan"], req["evidence"]
    if len(evidence) > 8 or any(not isinstance(e, dict) for e in evidence):
        raise ToolError("evidence must contain at most 8 objects")
    for entry in evidence:
        if (not isinstance(entry.get("cmd"), str) or type(entry.get("redacted")) is not bool
                or entry.get("redacted") is not True
                or not isinstance(entry.get("stdout_tail"), str)
                or not isinstance(entry.get("stderr_tail"), str)
                or not isinstance(entry.get("duration_ms"), int)
                or not isinstance(entry.get("timestamp"), str)
                or not isinstance(entry.get("env_fingerprint"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", entry.get("env_fingerprint", ""))
                or not isinstance(entry.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", entry.get("sha256", ""))):
            raise ToolError("evidence is missing required receipt fields")
        digest = hashlib.sha256((entry["stdout_tail"] + "\n" + entry["stderr_tail"]).encode()).hexdigest()
        if digest != entry["sha256"]:
            raise ToolError("evidence digest mismatch")
    original = plan.get("claims", [])
    if not isinstance(original, list) or len(original) > 100:
        raise ToolError("plan.claims must be an array of at most 100 items")
    claims = []
    for item in original:
        if not isinstance(item, dict) or not isinstance(item.get("capability"), str):
            raise ToolError("plan.claims entries require capability strings")
        matches = [e for e in evidence if e.get("cmd") == item["capability"]]
        statuses = {"ok" if e.get("exit_code") == 0 and not e.get("timed_out") and not e.get("truncated")
                    else "failed" for e in matches}
        status = "conflict" if len(statuses) > 1 else "ready" if statuses == {"ok"} else "blocked" if statuses else "unverified"
        claims.append({"id": item.get("id"), "capability": item["capability"],
                       "source_line": item.get("source_line"), "status": status,
                       "evidence_ids": [e.get("sha256") for e in matches]})
    suspicious = any(c.get("injection_suspected") for c in plan.get("candidates", []) if isinstance(c, dict))
    verdict = ("blocked" if suspicious or any(c["status"] in {"blocked", "conflict"} for c in claims)
               else "ready" if claims and all(c["status"] == "ready" for c in claims)
               else "needs-review")
    fixes = []
    if suspicious:
        fixes.append("Review suspicious README commands; never execute them automatically.")
    if any(c["status"] == "unverified" for c in claims):
        fixes.append("Explicitly probe each unverified claim before relying on it.")
    if any(c["status"] in {"blocked", "conflict"} for c in claims):
        fixes.append("Resolve failing or contradictory probe output.")
    if not claims:
        fixes.append("Document a copyable CLI invocation and expected output.")
    passport = {"tool_name": plan.get("tool_name"), "version_constraint": plan.get("version_constraint"),
                "verified_at": _now(), "claims": claims, "evidence": evidence,
                "overall": verdict, "network_isolation": "not-enforced",
                "evidence_provenance": "caller-supplied",
                "readiness_scope": "given-evidence-only; not independent certification"}
    drift, drift_verdict = _baseline_diff(passport, req["baseline"]) if "baseline" in req else ([], None)
    if drift_verdict == "regression":
        fixes.append("A previously ready command regressed; inspect drift before updating callers.")
    lines = [f"# Capability Passport: {passport['tool_name'] or 'unnamed tool'}", "",
             f"Verdict: **{verdict}**", "", "## Claims"]
    lines += [f"- {c['status']}: `{c['capability']}` (README line {c['source_line']})" for c in claims] or ["- No callable command found."]
    lines += ["", "## Caller-supplied evidence", f"- {len(evidence)} receipt(s); not independently attested; network isolation: not-enforced.",
              "", "## Suggested fixes"] + [f"- {fix}" for fix in fixes]
    if drift_verdict is not None:
        lines += ["", f"Drift: **{drift_verdict}** ({len(drift)} changes)"]
    return {"passport_json": passport, "markdown": "\n".join(lines) + "\n", "verdict": verdict,
            "drift": drift, "drift_verdict": drift_verdict, "fix": fixes}


def _schema(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}


TOOLS: dict[str, dict[str, Any]] = {
    "plan_passport": {"description": "Extract untrusted, unexecuted CLI/MCP candidates from README text.",
                      "inputSchema": _schema({"readme": {"type": "string"}, "tool_name": {"type": "string"},
                                              "pyproject": {"type": "string"}, "package_json": {"type": "string"},
                                              "version_constraint": {"type": "string"}}, ["readme", "tool_name"]),
                      "handler": plan_passport},
    "safe_probe": {"description": "Run caller-supplied, low-risk local probes with limits; this is not a sandbox.",
                   "inputSchema": _schema({"commands": {"type": "array", "items": {"type": "string"}},
                                           "cwd": {"type": "string"}, "allow_side_effects": {"type": "boolean"},
                                           "timeout": {"type": "integer"}, "budget": {"type": "integer"}}, ["commands", "cwd"]),
                   "handler": safe_probe},
    "build_passport": {"description": "Build an evidence-backed passport and optional baseline drift report.",
                       "inputSchema": _schema({"plan": {"type": "object"},
                                               "evidence": {"type": "array", "items": {"type": "object"}},
                                               "baseline": {"type": "object"}}, ["plan", "evidence"]),
                       "handler": build_passport},
}

# Published manual Arena offer. These values do not trigger payments.
PRICING = {"first_passport": 3, "drift_recheck": 2, "failed_integration_diagnosis": 5}


def call_tool(name: str, arguments: dict[str, Any]) -> Any:
    tool = TOOLS.get(name)
    if tool is None:
        raise ToolError(f"Unknown tool: {name}", "E_NOT_ALLOWED")
    if not isinstance(arguments, dict):
        raise ToolError("arguments must be an object")
    schema = tool["inputSchema"]
    unknown = set(arguments) - set(schema["properties"])
    if unknown:
        raise ToolError(f"unknown field(s): {', '.join(sorted(unknown))}")
    missing = set(schema["required"]) - set(arguments)
    if missing:
        raise ToolError(f"missing required field(s): {', '.join(sorted(missing))}")
    for key, value in arguments.items():
        definition = schema["properties"][key]
        typ = definition["type"]
        if typ == "integer" and (type(value) is not int):
            raise ToolError(f"{key} must be an integer")
        if typ == "boolean" and type(value) is not bool:
            raise ToolError(f"{key} must be a boolean")
        if typ == "string" and not isinstance(value, str):
            raise ToolError(f"{key} must be a string")
        if typ == "object" and not isinstance(value, dict):
            raise ToolError(f"{key} must be an object")
        if typ == "array" and (not isinstance(value, list) or any(not isinstance(x, str if key == "commands" else dict) for x in value)):
            raise ToolError(f"{key} must be an array of {definition['items']['type']}")
    handler: Callable[[dict[str, Any]], Any] = tool["handler"]
    return handler(arguments)
