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

    def test_same_site_variants_continue_the_run(self):
        for prompt in (
            "check https://demo.example/login",
            "what does api.demo.example expose?",
            "DEMO.EXAMPLE:8443 runs the admin panel",
            "is www.demo.example the same app?",
        ):
            with self.subTest(prompt=prompt):
                plan = self.plan(prompt, last=("demo_ab12", str(self.work)), targets=["demo.example"])
                self.assertEqual(plan.kind, "resume")
                self.assertEqual(plan.extra_targets, [])
                self.assertEqual(plan.instruction, prompt)

    def test_related_target_with_a_new_site_resumes_with_added_scope(self):
        prompt = "continue on other.example.com, it shares the database with demo.example"
        plan = self.plan(prompt, last=("demo_ab12", str(self.work)), targets=["demo.example"])
        self.assertEqual(plan.kind, "resume")
        self.assertEqual(plan.resume_run, "demo_ab12")
        self.assertEqual(plan.extra_targets, ["other.example.com"])
        self.assertEqual(plan.instruction, prompt)

    def test_scan_command_forces_a_fresh_run_on_the_same_target(self):
        plan = self.plan("/scan demo.example", last=("demo_ab12", str(self.work)), targets=["demo.example"])
        self.assertEqual(plan.kind, "fresh")

    def test_targets_are_read_back_when_state_has_none(self):
        plan = self.srv._plan_prompt(
            "explain demo.example", str(self.work), [], "deep",
            ("demo_ab12", str(self.work)), [],
        )
        self.assertEqual(plan.kind, "resume")

    def test_attached_source_file_is_not_a_target(self):
        script = self.work / "strix_runs" / "demo_ab12" / "evidence" / "extractor.py"
        script.parent.mkdir(parents=True)
        script.write_text("print('hi')\n")

        plan = self.srv._plan_prompt(
            "what did we extract from the database?", str(self.work), [str(script)], "deep",
            ("demo_ab12", str(self.work)), ["demo.example"],
        )
        self.assertEqual(plan.kind, "resume")
        self.assertNotIn(str(script), plan.extra_targets)

        plan = self.srv._plan_prompt(
            "what did we extract from the database?", str(self.work), [str(script)], "deep", None, [],
        )
        self.assertEqual(plan.kind, "fresh")
        self.assertEqual(plan.targets, [str(self.work.resolve())])

        spec = self.work / "api.yaml"
        spec.write_text("openapi: 3.0.0\n")
        plan = self.srv._plan_prompt("review the API", str(self.work), [str(spec)], "deep", None, [])
        self.assertEqual(plan.targets, [str(spec)])

    def test_same_site_matching(self):
        from strix_acp.server import same_site, target_host

        self.assertEqual(target_host("https://Demo.Example/login?x=1"), "demo.example")
        self.assertEqual(target_host("user@demo.example:8443/x"), "demo.example")
        self.assertEqual(target_host("[2001:db8::1]:443"), "2001:db8::1")
        self.assertTrue(same_site("api.demo.example", "demo.example"))
        self.assertTrue(same_site("demo.example/login", "https://demo.example"))
        self.assertFalse(same_site("demo.example", "other.example.com"))
        self.assertTrue(same_site("/tmp/work/api", "/tmp/work"))
        self.assertFalse(same_site("/tmp/work", "/tmp/other"))

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
    def test_local_source_file_is_context_not_a_target(self):
        evidence = self.work / "strix_runs" / "demo_ab12" / "evidence"
        evidence.mkdir(parents=True)
        script = evidence / "extractor.py"
        script.write_text("print('x')\n")

        plan = self.plan(f"/scan {script} explain the extractor")
        self.assertEqual(plan.kind, "fresh")
        self.assertEqual(plan.targets, [str(self.work.resolve())])
        self.assertEqual(plan.workspace_files, [])
        self.assertIn(str(script), plan.instruction)

        relative = self.plan("/scan ./strix_runs/demo_ab12/evidence/extractor.py explain")
        self.assertEqual(relative.targets, [str(self.work.resolve())])
        self.assertIn("./strix_runs/demo_ab12/evidence/extractor.py", relative.instruction)

    def test_explicit_file_target_explains_the_rule(self):
        script = self.work / "extractor.py"
        script.write_text("print('x')\n")

        for prompt in (f"/scan -t {script} go", f"/scan --target={script} go"):
            plan = self.plan(prompt)
            self.assertEqual(plan.kind, "error")
            self.assertIn("only accepts a local directory", plan.error)
            self.assertIn(str(self.work.resolve()), plan.error)

        plan = self.plan("/scan -t extractor.py go")
        self.assertEqual(plan.kind, "error")

        # A directory or an API spec stays an accepted explicit target.
        spec = self.work / "api.yaml"
        spec.write_text("openapi: 3.0.0\n")
        self.assertEqual(self.plan(f"/scan -t {self.work} go").targets, [str(self.work.resolve())])
        self.assertEqual(self.plan(f"/scan -t {spec} go").targets, [str(spec.resolve())])

    def test_attached_file_is_staged_not_a_target(self):
        notes = self.work / "extractor.py"
        notes.write_text("print('x')\n")

        plan = self.srv._plan_prompt("explain what this does", str(self.work), [str(notes)], "deep", None)
        self.assertEqual(plan.kind, "fresh")
        self.assertEqual(plan.targets, [str(self.work.resolve())])
        self.assertEqual(plan.workspace_files, [str(notes.resolve())])

        # A spec attached as a resource can still be the target.
        spec = self.work / "api.yaml"
        spec.write_text("openapi: 3.0.0\n")
        plan = self.srv._plan_prompt("scan this", str(self.work), [str(spec)], "deep", None)
        self.assertEqual(plan.targets, [str(spec.resolve())])
        self.assertEqual(plan.workspace_files, [])

        # An attachment on a continuation is staged for the resumed run too.
        plan = self.srv._plan_prompt(
            "look at it", str(self.work), [str(notes)], "deep", ("demo_ab12", str(self.work))
        )
        self.assertEqual(plan.kind, "resume")
        self.assertEqual(plan.workspace_files, [str(notes.resolve())])

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
