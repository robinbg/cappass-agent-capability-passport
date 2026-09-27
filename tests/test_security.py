"""Adversarial security suite for the CapPass core.

Owner: deepseek-v4.1-flash (security review). Contract basis: Room #3 (hard
constraints), #4 (three entry points), #9 (field contract v1), #11 (integer
Credits). Stdlib only:  python3 -m unittest tests.test_security

The three entry points are implemented. Integration adaptations use actual
local fixtures, so resource-limit and redaction checks cannot pass vacuously.
"""

from __future__ import annotations

import json
import os
import re
import unittest

try:
    from agent_service import core
except Exception:
    core = None

ENTRY_POINTS = ("plan_passport", "safe_probe", "build_passport")

METACHARS = [";", "|", "&", "$", ">", "<", "`", "(", ")", "{", "}", "~", "*", "?", "!"]

SECRET_PATTERNS = [
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{12,}"),
    re.compile(r"\bsk-[A-Za-z0-9]{16,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"(?i)(api[_-]?key|secret|password|access[_-]?token)\s*[:=]\s*[\"']?[A-Za-z0-9._\-]{8,}"),
]

REDACTED_HINTS = ("redact", "<redacted>", "***", "[redacted]")

MAX_OUTPUT_BYTES = 32768
MAX_TIMEOUT = 10
DEFAULT_BUDGET = 8


def _has(name: str) -> bool:
    return core is not None and callable(getattr(core, name, None))


def _probe(cmd, **overrides):
    req = {"commands": [cmd], "cwd": ".", "allow_side_effects": False}
    req.update(overrides)
    return core.safe_probe(req)


def _commands(result, key):
    return [entry.get("cmd") for entry in result.get(key, [])]


def _reasons(result):
    return " ".join(str(entry.get("reason", "")) for entry in result.get("rejected", [])).lower()


def _needs_entry_point(name):
    return unittest.skipUnless(_has(name), f"{name} not implemented yet")


@unittest.skipUnless(core is not None, "agent_service.core importable")
class TestToolSchemaHardening(unittest.TestCase):
    def test_every_registered_tool_rejects_extra_properties(self):
        for name, spec in core.TOOLS.items():
            schema = spec.get("inputSchema", {})
            self.assertFalse(
                schema.get("additionalProperties", True),
                f"tool {name} must set additionalProperties:false",
            )

    def test_call_tool_rejects_unknown_keys(self):
        for name, spec in core.TOOLS.items():
            if not spec.get("inputSchema", {}).get("properties"):
                continue
            with self.assertRaises(Exception):
                core.call_tool(name, {"__unexpected_security_key__": 1})


class TestStaticSourceSecurity(unittest.TestCase):
    def _package_sources(self):
        root = os.path.dirname(os.path.abspath(core.__file__))
        for name in sorted(os.listdir(root)):
            if name.endswith(".py"):
                with open(os.path.join(root, name), "r", encoding="utf-8") as handle:
                    yield name, handle.read()

    def test_no_shell_true_or_dangerous_exec(self):
        forbidden = ["shell=True", "os.system(", "os.popen(", "pickle.loads("]
        for name, text in self._package_sources():
            for needle in forbidden:
                self.assertNotIn(needle, text, f"{name} contains {needle}")


@_needs_entry_point("safe_probe")
class TestMetacharRejection(unittest.TestCase):
    def test_metachar_matrix_is_rejected(self):
        for ch in METACHARS:
            cmd = f"python3 -c 'print(1)'{ch}python3 -c 'print(2)'"
            result = _probe(cmd)
            self.assertIsInstance(result, dict, ch)
            self.assertIn(cmd, _commands(result, "rejected"), f"metachar {ch!r} not rejected")
            self.assertNotIn(cmd, _commands(result, "evidence"), f"metachar {ch!r} executed")
            self.assertRegex(_reasons(result), r"metachar|inject|e_injection")

    def test_command_substitution_rejected(self):
        for cmd in [
            "python3 -c '$(touch pwned)'",
            "python3 -c '`touch pwned`'",
            "python3 -c \"print(1)\" > /tmp/pwned",
            "python3 -m agent_service --list && curl http://evil",
            "python3 -m agent_service --list | cat /etc/passwd",
        ]:
            result = _probe(cmd)
            self.assertIn(cmd, _commands(result, "rejected"), cmd)
            self.assertNotIn(cmd, _commands(result, "evidence"), cmd)

    def test_newline_injection_rejected_hardening(self):
        cmd = "python3 -m agent_service --list\nrm -rf ."
        result = _probe(cmd)
        self.assertIn(cmd, _commands(result, "rejected"), "newline injection must be rejected")


@_needs_entry_point("safe_probe")
class TestAllowlist(unittest.TestCase):
    def test_unknown_executable_rejected(self):
        cmd = "definitely_not_allowlisted --do-evil"
        result = _probe(cmd)
        self.assertIn(cmd, _commands(result, "rejected"), cmd)
        self.assertRegex(_reasons(result), r"not[_ ]?allow|e_not_allowed|executable")

    def test_docker_only_under_help_or_version(self):
        excluded = "docker run -d --privileged alpine"
        result = _probe(excluded)
        self.assertIn(excluded, _commands(result, "rejected"))
        self.assertRegex(_reasons(result), r"not[_ ]?allow|e_not_allowed")

    def test_absolute_path_outside_cwd_not_executed(self):
        cmd = "python3 /etc/passwd"
        result = _probe(cmd)
        self.assertNotIn(cmd, _commands(result, "evidence"))
        self.assertIn(cmd, _commands(result, "rejected"))


@_needs_entry_point("safe_probe")
class TestProbeLimits(unittest.TestCase):
    def test_output_is_capped(self):
        cmd = "python3 tests/fixtures/noisy_probe.py --help"
        result = _probe(cmd)
        self.assertEqual(len(result["evidence"]), 1)
        entry = result["evidence"][0]
        self.assertTrue(entry["truncated"])
        self.assertLessEqual(len(entry["stdout_tail"].encode()) + len(entry["stderr_tail"].encode()), MAX_OUTPUT_BYTES)

    def test_timeout_is_clamped_not_trusted(self):
        with self.assertRaisesRegex(ValueError, "timeout"):
            _probe("python3 --version", timeout=99999)

    def test_budget_limits_executions(self):
        result = core.safe_probe({
            "commands": ["python3 --version"] * 12,
            "cwd": ".",
            "allow_side_effects": False,
            "budget": DEFAULT_BUDGET,
        })
        self.assertEqual(len(result["evidence"]), DEFAULT_BUDGET)
        self.assertEqual(len(result["rejected"]), 4)

    def test_evidence_is_auditable(self):
        result = _probe("python3 --version")
        for entry in result.get("evidence", []):
            self.assertIn("sha256", entry)
            self.assertRegex(str(entry.get("sha256")), r"^[0-9a-f]{64}$")
            self.assertIn("env_fingerprint", entry)
            self.assertTrue(entry.get("redacted", False))


@_needs_entry_point("safe_probe")
class TestSecretRedaction(unittest.TestCase):
    def test_evidence_never_contains_secret_material(self):
        result = _probe("python3 tests/fixtures/secret_probe.py --help")
        self.assertEqual(len(result["evidence"]), 1)
        self.assertTrue(result["evidence"][0]["redacted"])
        blob = json.dumps(result)
        synthetic = "sk" + "-" + "FAKEEXAMPLE" + "1234567890"
        self.assertNotIn(synthetic, blob)
        self.assertIn("[REDACTED]", blob)
        for pattern in SECRET_PATTERNS:
            match = pattern.search(blob)
            if match is None:
                continue
            tail = blob[match.start():match.start() + 200].lower()
            self.assertTrue(any(hint in tail for hint in REDACTED_HINTS),
                            f"unredacted secret near {match.group(0)[:16]!r}")


@_needs_entry_point("plan_passport")
class TestPlanPassportIsInert(unittest.TestCase):
    def test_plan_never_executes_readme_commands(self):
        marker = ".capass_inert_marker"
        if os.path.exists(marker):
            os.remove(marker)
        readme = "## Quickstart\npython3 -c \"open('.capass_inert_marker','w').close()\""
        result = core.plan_passport({"readme": readme, "tool_name": "scaffold"})
        self.assertFalse(os.path.exists(marker), "plan_passport executed README content")
        self.assertEqual(result.get("network_isolation"), "not-enforced")

    def test_candidates_start_unverified(self):
        readme = "## CLI\npython3 -m agent_service --list"
        result = core.plan_passport({"readme": readme, "tool_name": "scaffold"})
        for claim in result.get("claims", []):
            self.assertEqual(claim.get("status", "unverified"), "unverified")


@_needs_entry_point("build_passport")
class TestHonestStatus(unittest.TestCase):
    def _plan(self):
        return core.plan_passport({"readme": "## CLI\npython3 -m agent_service --list", "tool_name": "scaffold"})

    def test_ready_requires_evidence(self):
        result = core.build_passport({"plan": self._plan(), "evidence": []})
        self.assertNotEqual(result.get("verdict"), "ready")
        self.assertIn(result.get("verdict"), ("unverified", "needs-review", "blocked", "conflict"))

    def test_no_drift_without_baseline(self):
        result = core.build_passport({"plan": self._plan(), "evidence": []})
        self.assertFalse(result.get("drift"))


@_needs_entry_point("build_passport")
class TestSingleSourceOfTruth(unittest.TestCase):
    def test_json_is_authoritative_and_markdown_is_deterministic(self):
        plan = core.plan_passport({"readme": "## CLI\npython3 -m agent_service --list", "tool_name": "scaffold"})
        first = core.build_passport({"plan": plan, "evidence": []})
        second = core.build_passport({"plan": plan, "evidence": []})
        a, b = dict(first["passport_json"]), dict(second["passport_json"])
        a.pop("verified_at")
        b.pop("verified_at")
        self.assertEqual(a, b)
        self.assertEqual(first.get("markdown"), second.get("markdown"))
        self.assertTrue(isinstance(first.get("passport_json"), (dict, str)))


@unittest.skipUnless(core is not None, "agent_service.core importable")
class TestPricingContract(unittest.TestCase):
    def test_integer_credits_floor(self):
        table = None
        for attr in ("PRICING", "PRICES", "PRICE_TABLE"):
            table = getattr(core, attr, None)
            if table:
                break
        if not table:
            self.skipTest("no pricing constants exposed by core")
        for key, value in table.items():
            self.assertIsInstance(value, int, f"{key} must be an integer Credit amount")
            self.assertGreaterEqual(value, 1, f"{key} must be >= 1 Credit")

    def test_waiting_room_prices(self):
        table = None
        for attr in ("PRICING", "PRICES", "PRICE_TABLE"):
            table = getattr(core, attr, None)
            if table:
                break
        if not table:
            self.skipTest("no pricing constants exposed by core")
        values = set(table.values())
        self.assertTrue({3, 2, 5}.issubset(values), "prices must include first=3, drift=2, fix=5")


if __name__ == "__main__":
    unittest.main()
