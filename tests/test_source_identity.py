"""Local revision/lock binding and its explicitly untrusted drift semantics."""

from __future__ import annotations

import hashlib
import copy
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from agent_service.core import build_passport, plan_passport
from agent_service.probe import safe_probe


class TestSourceIdentity(unittest.TestCase):
    def test_git_head_and_lock_change_are_reported_as_review_not_regression(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("git unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args: str) -> str:
                return subprocess.run(["git", "-C", directory, *args], check=True,
                                      capture_output=True, text=True, timeout=5).stdout.strip()

            git("init", "-q")
            (root / "README.md").write_text("fixture\n")
            (root / "uv.lock").write_text("version = 1\n")
            git("add", "README.md", "uv.lock")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "fixture")
            head = git("rev-parse", "HEAD")
            plan = plan_passport({"readme": "python3 --version", "tool_name": "fixture"})

            def passport():
                probe = safe_probe({"commands": ["python3 --version"], "cwd": directory})
                self.assertEqual(len(probe["evidence"]), 1)
                self.assertEqual(probe["envelope"]["source_identity"], probe["evidence"][0]["source_identity"])
                return build_passport({"plan": plan, "evidence": probe["evidence"]})

            first = passport()
            first_identity = first["passport_json"]["source_identity"]
            self.assertEqual(first["verdict"], "ready")
            self.assertEqual(first_identity["git_head"], head)
            self.assertEqual(first_identity["dependency_lock"], {
                "path": "uv.lock", "sha256": hashlib.sha256(b"version = 1\n").hexdigest()})
            self.assertEqual(first_identity["coverage"], "git-head-and-lock")
            self.assertEqual(first_identity["provenance"], "caller-supplied; not independently attested")
            self.assertEqual(first_identity["working_tree"], "not-checked")

            (root / "uv.lock").write_text("version = 2\n")
            second_probe = safe_probe({"commands": ["python3 --version"], "cwd": directory})
            second = build_passport({"plan": plan, "evidence": second_probe["evidence"], "baseline": first})
            self.assertEqual(second["passport_json"]["source_identity"]["git_head"], head)
            self.assertEqual(second["drift_verdict"], "needs-review")
            self.assertIn("source_identity.dependency_lock", [change["path"] for change in second["drift"]])
            self.assertNotEqual(first_identity["dependency_lock"], second["passport_json"]["source_identity"]["dependency_lock"])

    def test_legacy_receipt_has_explicit_missing_identity(self) -> None:
        plan = plan_passport({"readme": "python3 --version", "tool_name": "legacy"})
        probe = safe_probe({"commands": ["python3 --version"], "cwd": "."})
        entry = dict(probe["evidence"][0])
        entry.pop("source_identity")
        passport = build_passport({"plan": plan, "evidence": [entry]})
        self.assertEqual(passport["verdict"], "ready")
        self.assertEqual(passport["passport_json"]["source_identity"]["status"], "missing")
        self.assertIsNone(passport["passport_json"]["source_identity"]["git_head"])
        self.assertIn("not independently attested", passport["markdown"])

    def test_conflicting_receipt_identity_cannot_yield_ready(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan = plan_passport({"readme": "python3 --version", "tool_name": "conflict"})
            first = safe_probe({"commands": ["python3 --version"], "cwd": directory})["evidence"][0]
            second = copy.deepcopy(first)
            second["source_identity"]["git_head"] = "0" * 40
            second["source_identity"]["coverage"] = "git-head-only"
            result = build_passport({"plan": plan, "evidence": [first, second]})
            self.assertEqual(result["verdict"], "needs-review")
            self.assertEqual(result["passport_json"]["source_identity"]["status"], "conflicting")
            self.assertIsNone(result["passport_json"]["source_identity"]["git_head"])


if __name__ == "__main__":
    unittest.main()
