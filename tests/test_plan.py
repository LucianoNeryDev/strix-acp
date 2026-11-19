"""Prompt planning: fresh run, resume, or a clear error."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from strix_acp.server import StrixAcpServer  # noqa: E402


class PlanTest(unittest.TestCase):
    def setUp(self):
        self.srv = StrixAcpServer()
        self._tmp = tempfile.TemporaryDirectory()
        self.work = Path(self._tmp.name) / "work"
        run = self.work / "strix_runs" / "demo_ab12"
        run.mkdir(parents=True)
        (run / "run.json").write_text(json.dumps({"targets_info": [{"original": "demo.example"}]}))

    def tearDown(self):
        self._tmp.cleanup()

    def plan(self, prompt, last=None, targets=None):
        return self.srv._plan_prompt(prompt, str(self.work), [], "deep", last, targets or [])

    def test_follow_up_continues_the_session_run(self):
        plan = self.plan("where is the database?", last=("demo_ab12", str(self.work)))
        self.assertEqual(plan.kind, "resume")
        self.assertEqual(plan.resume_run, "demo_ab12")
        self.assertEqual(plan.resume_workspace, str(self.work))
        self.assertEqual(plan.instruction, "where is the database?")

    def test_same_target_keeps_continuity_and_wording(self):
        plan = self.plan(
            "explain the demo.example findings",
            last=("demo_ab12", str(self.work)),
            targets=["demo.example"],
        )
        self.assertEqual(plan.kind, "resume")
        self.assertEqual(plan.instruction, "explain the demo.example findings")

    def test_different_target_starts_fresh(self):
        plan = self.plan(
            "scan https://other.example.com now",
            last=("demo_ab12", str(self.work)),
            targets=["demo.example"],
        )
        self.assertEqual(plan.kind, "fresh")
        self.assertEqual(plan.targets, ["https://other.example.com"])

    def test_new_forces_a_fresh_run(self):
        plan = self.plan(
            "/new demo.example redo it", last=("demo_ab12", str(self.work)), targets=["demo.example"]
        )
        self.assertEqual(plan.kind, "fresh")
        plan = self.plan("/new", last=("demo_ab12", str(self.work)))
        self.assertEqual(plan.kind, "error")

    def test_resume_by_name_path_and_latest(self):
        plan = self.plan("/resume demo_ab12 check the login flow")
        self.assertEqual((plan.kind, plan.resume_run, plan.instruction),
                         ("resume", "demo_ab12", "check the login flow"))

        other = Path(self._tmp.name) / "other" / "strix_runs" / "other_cd34"
        other.mkdir(parents=True)
        (other / "run.json").write_text("{}")
        plan = self.plan(f"/resume {other} keep going")
        self.assertEqual((plan.kind, plan.resume_run), ("resume", "other_cd34"))
        self.assertEqual(plan.resume_workspace, str(other.parent.parent))

        plan = self.plan("/resume summarise what you found", last=("demo_ab12", str(self.work)))
        self.assertEqual((plan.kind, plan.resume_run), ("resume", "demo_ab12"))
        plan = self.plan("/resume summarise what you found")
        self.assertEqual((plan.kind, plan.resume_run), ("resume", "demo_ab12"))

    def test_resume_errors_are_explicit(self):
        plan = self.plan("/resume demo_ffff keep going", last=("demo_ab12", str(self.work)))
        self.assertEqual(plan.kind, "error")
        with tempfile.TemporaryDirectory() as empty:
            plan = self.srv._plan_prompt("/resume keep going", empty, [], "deep", None, [])
            self.assertEqual(plan.kind, "error")

    def test_target_parsing(self):
        mode, targets, instr = self.srv._parse_scan_prompt(
            "/quick check 192.168.1.10 and api.example.org/v1 using glm 5.3",
            str(self.work), [], "deep",
        )
        self.assertEqual(mode, "quick")
        self.assertEqual(targets, ["192.168.1.10", "api.example.org/v1"])
        self.assertEqual(instr, "check and using glm 5.3")

    def test_local_files_as_targets(self):
        (self.work / "main.py").write_text("print('hi')\n")
        (self.work / "api.yaml").write_text("openapi: 3.0.0\n")

        # A source filename is not a domain: the scan falls back to the cwd.
        _, targets, instr = self.srv._parse_scan_prompt("audit main.py", str(self.work), [], "deep")
        self.assertEqual(targets, [str(self.work.resolve())])
        self.assertEqual(instr, "audit main.py")

        # A local OpenAPI spec is a target of its own.
        _, targets, _ = self.srv._parse_scan_prompt("test api.yaml", str(self.work), [], "deep")
        self.assertEqual(targets, [str((self.work / "api.yaml").resolve())])

    def test_bare_domain_in_wrapper_is_the_target(self):
        wrapped = (
            "<t3_code_instructions>\nUse --watch and https://example.invalid/ignore\n</t3_code_instructions>\n\n"
            "<user_request>\nexample.org\n</user_request>\n\n"
            "<runtime_info>model=opencode_go/glm-5.3</runtime_info>\n"
        )
        prompt, extras = self.srv._extract_prompt([{"type": "text", "text": wrapped}], str(self.work))
        self.assertEqual((prompt, extras), ("example.org", []))
        mode, targets, instr = self.srv._parse_scan_prompt(prompt, str(self.work), extras, "deep")
        self.assertEqual((mode, targets, instr), ("deep", ["example.org"], ""))

    def test_clients_wrapper_is_unwrapped(self):
        wrapped = (
            "<client_instructions>ignore https://example.invalid/x</client_instructions>\n\n"
            "<user_request>\n/preflight opencode_go/glm-5.3\n</user_request>\n"
        )
        prompt, extras = self.srv._extract_prompt([{"type": "text", "text": wrapped}], str(self.work))
        self.assertEqual(prompt, "/preflight opencode_go/glm-5.3")
        self.assertEqual(extras, [])


if __name__ == "__main__":
    unittest.main()
