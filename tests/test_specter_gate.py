#!/usr/bin/env python3
"""Contract tests for the Specter PostToolUse hook."""

import importlib.util
import json
import subprocess
import unittest
from pathlib import Path


HOOK_PATH = Path(__file__).parents[1] / "hooks" / "specter-gate.py"
SPEC = importlib.util.spec_from_file_location("specter_gate", HOOK_PATH)
specter_gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(specter_gate)


class SpecterHookContractTest(unittest.TestCase):
    def test_extracts_current_tool_response_field(self):
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "npm test"},
            "tool_response": "command output",
        }
        content = specter_gate.extract_content(payload)
        self.assertIn("command output", content)
        self.assertIn("npm test", content)

    def test_extracts_notebook_source(self):
        payload = {
            "tool_name": "NotebookEdit",
            "tool_input": {"new_source": "print('safe')"},
            "tool_response": {"status": "ok"},
        }
        content = specter_gate.extract_content(payload)
        self.assertIn("print('safe')", content)
        self.assertIn('"status": "ok"', content)

    def test_blocks_injection_in_bash_response(self):
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "generate query"},
            "tool_response": """SELECT * FROM users WHERE id='" + request.query.id + "'""",
        }
        result = subprocess.run(
            ["python3", str(HOOK_PATH)],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("BLOCKED", result.stderr)


if __name__ == "__main__":
    unittest.main()
