"""ACP protocol behaviour, with a fake Strix interpreter.

No Docker, no model, no network: ``STRIX_PYTHON`` points at a short script that
prints the same JSON events the real worker does.
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from strix_acp.server import STANDING_INSTRUCTION, SessionState, StrixAcpServer  # noqa: E402

REAL_STRIX_PYTHON = Path(
    os.environ.get("STRIX_PYTHON_REAL", str(Path.home() / ".local/share/uv/tools/strix-agent/bin/python"))
)

def _write_mock_strix(home: Path, argv_log: Path | None = None) -> Path:
    mock = home / "mock-strix-python"
    log_line = (
        f"with open({str(argv_log)!r}, 'a') as fh:\n"
        f"    fh.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        if argv_log
        else ""
    )
    mock.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys, time\n"
        + log_line +
        "if 'scan' in sys.argv:\n"
        "    args = sys.argv\n"
        "    instr = args[args.index('--instruction') + 1] if '--instruction' in args else ''\n"
        "    if 'SLOW' in instr:\n"
        "        time.sleep(30)\n"
        "    print(json.dumps({'kind': 'started', 'run_name': 'mock-run',\n"
        "        'run_dir': os.environ['RUN_DIR'], 'targets': ['demo.example'],\n"
        "        'model': 'opencode_go/glm-5.3', 'scan_mode': 'deep',\n"
        "        'resume': '--resume' in args}), flush=True)\n"
        "    print(json.dumps({'kind': 'finished', 'run_name': 'mock-run',\n"
        "        'run_dir': os.environ['RUN_DIR'], 'findings': 1, 'final_result': 'done'}), flush=True)\n"
        "    raise SystemExit(0)\n"
        "print(json.dumps({'kind': 'preflight_result', 'ok': True,\n"
        "    'model': 'opencode_go/glm-5.3'}), flush=True)\n"
    )
    mock.chmod(0o755)
    return mock


class AcpServerTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        self.work = self.home / "work"
        self.run_dir = self.work / "strix_runs" / "mock-run"
        self.run_dir.mkdir(parents=True)
        (self.run_dir / "run.json").write_text(json.dumps({"targets_info": [{"original": "demo.example"}]}))

        docker = self.home / "docker"
        docker.write_text("#!/bin/sh\nexit 0\n")
        docker.chmod(0o755)

        self.argv_log = self.home / "argv.jsonl"
        mock = _write_mock_strix(self.home, self.argv_log)
        (self.home / "secret.env").write_text('OPENCODE_GO_API_KEY="test-key"\n')
        self.env = {
            **os.environ,
            "HOME": str(self.home),
            "PATH": str(self.home) + os.pathsep + os.environ["PATH"],
            "STRIX_PYTHON": str(mock),
            "STRIX_ACP_STATE": str(self.home / "state"),
            "STRIX_OPENCODE_GO_ENV": str(self.home / "secret.env"),
            "RUN_DIR": str(self.run_dir),
        }

    def tearDown(self):
        self._tmp.cleanup()

    def script(self, name, body):
        path = self.home / name
        path.write_text("#!/usr/bin/env python3\n" + body)
        path.chmod(0o755)
        return path

    def open_session(self, proc, mcp_servers=()):
        self.rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
        init = self.read_until(proc, 1)[-1]["result"]
        self.rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "session/new",
                        "params": {"cwd": str(self.work), "mcpServers": list(mcp_servers)}})
        session = self.read_until(proc, 2)[-1]["result"]
        update = json.loads(proc.stdout.readline())
        self.assertEqual(update["params"]["update"]["sessionUpdate"], "available_commands_update")
        return init, session

    def start(self, extra_env=None):
        env = {**self.env, "PYTHONPATH": str(ROOT / "src"), **(extra_env or {})}
        return subprocess.Popen(
            [sys.executable, "-m", "strix_acp.server"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, text=True, bufsize=1,
        )

    def rpc(self, proc, payload):
        proc.stdin.write(json.dumps(payload) + "\n")
        proc.stdin.flush()

    def read_until(self, proc, req_id):
        msgs = []
        while True:
            line = proc.stdout.readline()
            self.assertTrue(line, "unexpected EOF")
            msg = json.loads(line)
            msgs.append(msg)
            if msg.get("id") == req_id:
                return msgs

    @staticmethod
    def texts(msgs):
        return [
            m["params"]["update"]["content"]["text"]
            for m in msgs
            if m.get("method") == "session/update"
            and m["params"]["update"].get("sessionUpdate") == "agent_message_chunk"
        ]

    def close(self, proc):
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()
        proc.wait(timeout=5)

    def test_capabilities_and_runs(self):
        proc = self.start()
        try:
            self.rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
            caps = self.read_until(proc, 1)[-1]["result"]["agentCapabilities"]
            self.assertEqual(caps["sessionCapabilities"].get("resume"), {})
            self.assertEqual(caps["sessionCapabilities"].get("delete"), {})

            self.rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "session/new",
                            "params": {"cwd": str(self.work), "mcpServers": []}})
            sid = self.read_until(proc, 2)[-1]["result"]["sessionId"]
            proc.stdout.readline()  # available_commands_update

            self.rpc(proc, {"jsonrpc": "2.0", "id": 3, "method": "session/prompt",
                            "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "/runs"}]}})
            texts = self.texts(self.read_until(proc, 3))
            self.assertTrue(any("mock-run" in t for t in texts), texts)
        finally:
            self.close(proc)

    def test_docker_probe_timeout_is_reported_not_raised(self):
        docker = self.home / "docker"
        docker.write_text("#!/bin/sh\nsleep 5\n")
        docker.chmod(0o755)

        proc = self.start({"STRIX_DOCKER_PROBE_TIMEOUT": "1"})
        try:
            self.rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
            self.read_until(proc, 1)
            self.rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "session/new",
                            "params": {"cwd": str(self.work), "mcpServers": []}})
            sid = self.read_until(proc, 2)[-1]["result"]["sessionId"]
            proc.stdout.readline()

            self.rpc(proc, {"jsonrpc": "2.0", "id": 3, "method": "session/prompt",
                            "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "/scan demo.example"}]}})
            msgs = self.read_until(proc, 3)
            self.assertNotIn("error", msgs[-1])
            self.assertEqual(msgs[-1]["result"]["stopReason"], "end_turn")
            self.assertTrue(
                any("did not answer within 1s" in t for t in self.texts(msgs)),
                self.texts(msgs),
            )
            self.assertFalse(self.argv_log.exists() and self.argv_log.read_text().strip())
        finally:
            self.close(proc)

    def test_attached_file_is_staged_as_a_workspace_file(self):
        evidence = self.work / "strix_runs" / "mock-run" / "evidence"
        evidence.mkdir(parents=True)
        script = evidence / "extractor.py"
        script.write_text("print('x')\n")

        proc = self.start()
        try:
            self.rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
            self.read_until(proc, 1)
            self.rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "session/new",
                            "params": {"cwd": str(self.work), "mcpServers": []}})
            sid = self.read_until(proc, 2)[-1]["result"]["sessionId"]
            proc.stdout.readline()

            self.rpc(proc, {"jsonrpc": "2.0", "id": 3, "method": "session/prompt",
                            "params": {"sessionId": sid, "prompt": [
                                {"type": "text", "text": "explain what this extractor does"},
                                {"type": "resource_link", "uri": f"file://{script}", "name": "extractor.py"},
                            ]}})
            self.read_until(proc, 3)

            calls = [json.loads(line) for line in self.argv_log.read_text().splitlines()]
            scan = next(c for c in calls if "scan" in c)
            self.assertEqual(scan[scan.index("--workspace-file") + 1], str(script))
            targets = [scan[i + 1] for i, arg in enumerate(scan) if arg == "--target"]
            self.assertEqual(targets, [str(self.work.resolve())])
            self.assertIn(f"/workspace/{script.name}", scan[scan.index("--instruction") + 1])
        finally:
            self.close(proc)

    def test_follow_up_resumes_and_busy_prompt_is_answered(self):
        proc = self.start()
        try:
            self.rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
            self.read_until(proc, 1)
            self.rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "session/new",
                            "params": {"cwd": str(self.work), "mcpServers": []}})
            sid = self.read_until(proc, 2)[-1]["result"]["sessionId"]
            proc.stdout.readline()

            self.rpc(proc, {"jsonrpc": "2.0", "id": 3, "method": "session/prompt",
                            "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "/scan demo.example"}]}})
            self.assertTrue(any(t.startswith("Started Strix") for t in self.texts(self.read_until(proc, 3))))

            self.rpc(proc, {"jsonrpc": "2.0", "id": 4, "method": "session/prompt",
                            "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "where is the database?"}]}})
            follow = self.texts(self.read_until(proc, 4))
            self.assertTrue(any("Resuming Strix run `mock-run`" in t for t in follow), follow)
            self.assertTrue(any(t.startswith("Resumed Strix") for t in follow), follow)

            calls = [json.loads(line) for line in self.argv_log.read_text().splitlines()]
            scans = [c for c in calls if "scan" in c]
            self.assertEqual(len(scans), 2)
            self.assertNotIn("--resume", scans[0])
            self.assertIn("--resume", scans[1])
            self.assertEqual(scans[1][scans[1].index("--resume") + 1], "mock-run")
            self.assertEqual(scans[1][scans[1].index("--workspace") + 1], str(self.work))
            self.assertEqual(
                scans[1][scans[1].index("--instruction") + 1].split("\n")[0], "where is the database?"
            )
            self.assertEqual(scans[0][scans[0].index("--instruction") + 1], STANDING_INSTRUCTION)
            self.assertTrue(scans[1][scans[1].index("--instruction") + 1].endswith("\n\n" + STANDING_INSTRUCTION))

            # A prompt sent while a run is active is answered, not blocked.
            self.rpc(proc, {"jsonrpc": "2.0", "id": 5, "method": "session/prompt",
                            "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "/scan demo.example SLOW"}]}})
            time.sleep(0.4)
            self.rpc(proc, {"jsonrpc": "2.0", "id": 6, "method": "session/prompt",
                            "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "and another thing"}]}})
            busy = self.texts(self.read_until(proc, 6))
            self.assertTrue(any("already active" in t for t in busy), busy)

            self.rpc(proc, {"jsonrpc": "2.0", "id": 7, "method": "session/cancel", "params": {"sessionId": sid}})
            seen = {}
            while 5 not in seen or 7 not in seen:
                line = proc.stdout.readline()
                self.assertTrue(line, "unexpected EOF")
                msg = json.loads(line)
                if "id" in msg:
                    seen[msg["id"]] = msg
            self.assertEqual(seen[5]["result"]["stopReason"], "cancelled")
        finally:
            self.close(proc)

    def test_session_resume_restores_thread_state(self):
        first = self.start()
        try:
            self.rpc(first, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
            self.read_until(first, 1)
            self.rpc(first, {"jsonrpc": "2.0", "id": 2, "method": "session/new",
                             "params": {"cwd": str(self.work), "mcpServers": []}})
            sid = self.read_until(first, 2)[-1]["result"]["sessionId"]
            first.stdout.readline()
            self.rpc(first, {"jsonrpc": "2.0", "id": 3, "method": "session/prompt",
                             "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "/scan demo.example"}]}})
            self.read_until(first, 3)
        finally:
            self.close(first)

        def reopen(expect_run: str) -> None:
            proc = self.start()
            try:
                self.rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
                self.read_until(proc, 1)
                self.rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "session/resume",
                                "params": {"sessionId": sid, "cwd": str(self.work), "mcpServers": []}})
                resumed = self.read_until(proc, 2)[-1]
                self.assertNotIn("error", resumed, resumed)
                self.assertIn("configOptions", resumed.get("result", {}))
                proc.stdout.readline()

                self.rpc(proc, {"jsonrpc": "2.0", "id": 3, "method": "session/prompt",
                                "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "where is the database?"}]}})
                texts = self.texts(self.read_until(proc, 3))
                self.assertTrue(any(f"Resuming Strix run `{expect_run}`" in t for t in texts), texts)
            finally:
                self.close(proc)

        reopen("mock-run")

        # A thread older than the state file: adopt the workspace's newest run.
        for state_file in (self.home / "state").glob("*.json"):
            state_file.unlink()
        reopen("mock-run")

    def test_config_preflight_cancel_and_delete(self):
        self.env["STRIX_PYTHON"] = str(self.script("mock-strix-python", (
            "import json, os, sys, time\n"
            "assert '--mcp-json' not in sys.argv  # client MCP servers are not forwarded\n"
            "if 'scan' in sys.argv:\n"
            "    print(json.dumps({'kind': 'finished', 'run_name': 'mock-run',\n"
            "        'run_dir': os.environ['RUN_DIR'], 'findings': 0}), flush=True)\n"
            "    raise SystemExit(0)\n"
            "if '--model' in sys.argv and 'slow-cancel' in sys.argv:\n"
            "    time.sleep(30)\n"
            "    raise SystemExit(0)\n"
            "print(json.dumps({'kind': 'thought', 'text': 'mock check\\n'}), flush=True)\n"
            "print(json.dumps({'kind': 'preflight_result', 'ok': True, 'model': 'opencode_go/glm-5.3'}), flush=True)\n"
        )))
        proc = self.start()
        try:
            init, session = self.open_session(
                proc, [{"name": "coding", "type": "stdio", "command": "unused"}]
            )
            self.assertEqual(init["agentInfo"]["name"], "strix-acp")
            self.assertFalse(init["agentCapabilities"]["mcpCapabilities"]["http"])
            self.assertGreater(len(session["models"]["availableModels"]), 10)
            sid = session["sessionId"]

            self.rpc(proc, {"jsonrpc": "2.0", "id": 3, "method": "session/set_config_option",
                            "params": {"sessionId": sid, "configId": "scan_mode", "value": "quick"}})
            opts = self.read_until(proc, 3)[-1]["result"]["configOptions"]
            self.assertEqual({o["id"]: o["currentValue"] for o in opts}["scan_mode"], "quick")

            self.rpc(proc, {"jsonrpc": "2.0", "id": 4, "method": "session/prompt",
                            "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "/preflight opencode_go/glm-5.3"}]}})
            msgs = self.read_until(proc, 4)
            self.assertEqual(msgs[-1]["result"]["stopReason"], "end_turn")
            self.assertTrue(any("succeeded" in t for t in self.texts(msgs)), msgs)

            self.rpc(proc, {"jsonrpc": "2.0", "id": 5, "method": "session/prompt",
                            "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "/scan ."}]}})
            self.assertTrue(any("mock-run" in t for t in self.texts(self.read_until(proc, 5))))

            self.rpc(proc, {"jsonrpc": "2.0", "id": 6, "method": "session/prompt",
                            "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "/preflight slow-cancel"}]}})
            time.sleep(0.2)
            self.rpc(proc, {"jsonrpc": "2.0", "id": 7, "method": "session/cancel", "params": {"sessionId": sid}})
            seen = {}
            while 6 not in seen or 7 not in seen:
                line = proc.stdout.readline()
                self.assertTrue(line, "unexpected EOF")
                msg = json.loads(line)
                if "id" in msg:
                    seen[msg["id"]] = msg
            self.assertEqual(seen[6]["result"]["stopReason"], "cancelled")

            self.rpc(proc, {"jsonrpc": "2.0", "id": 8, "method": "session/delete", "params": {"sessionId": sid}})
            self.assertNotIn("error", self.read_until(proc, 8)[-1])
        finally:
            self.close(proc)

    def test_worker_crash_after_thought_is_reported(self):
        self.env["STRIX_PYTHON"] = str(self.script("mock-crash-python", (
            "import json, sys\n"
            "print(json.dumps({'kind': 'thought', 'text': 'Running preflight...\\n'}), flush=True)\n"
            "print('Traceback (most recent call last):\\n  File x.py, line 1\\nBoomError: bad mcp',\n"
            "      file=sys.stderr, flush=True)\n"
            "raise SystemExit(1)\n"
        )))
        proc = self.start()
        try:
            _, session = self.open_session(proc)
            self.rpc(proc, {"jsonrpc": "2.0", "id": 3, "method": "session/prompt",
                            "params": {"sessionId": session["sessionId"], "prompt": [{"type": "text", "text": "/preflight"}]}})
            out = "".join(self.texts(self.read_until(proc, 3)))
            self.assertIn("Strix worker exited with status 1", out)
            self.assertIn("BoomError: bad mcp", out)
        finally:
            self.close(proc)

    def test_worker_env_isolates_provider_keys(self):
        auth = self.home / "auth.json"
        auth.write_text(json.dumps({"openrouter": {"type": "api", "key": "sk-or-v1-mock"}}))
        go_env = self.home / "go.env"
        go_env.write_text('OPENCODE_GO_API_KEY="oc_sk_mock_glm53"\n')
        environ = {"HOME": str(self.home), "OPENCODE_AUTH_FILE": str(auth), "STRIX_OPENCODE_GO_ENV": str(go_env)}
        with mock.patch.dict(os.environ, environ):
            for name in ("OPENCODE_GO_API_KEY", "OPENROUTER_API_KEY", "LLM_EXTRA_HEADERS", "STRIX_REASONING_EFFORT"):
                os.environ.pop(name, None)
            srv = StrixAcpServer()

            openrouter = SessionState(session_id="s1", cwd=str(self.work),
                                      model_id="openrouter/z-ai/glm-5.3", reasoning_effort="medium")
            env, key = srv._worker_env(openrouter)
            self.assertEqual(key, "sk-or-v1-mock")
            self.assertEqual(env.get("OPENROUTER_API_KEY"), "sk-or-v1-mock")
            self.assertNotIn("OPENCODE_GO_API_KEY", env)
            self.assertNotIn("LLM_EXTRA_HEADERS", env)

            go = SessionState(session_id="s2", cwd=str(self.work),
                              model_id="opencode_go/glm-5.3", reasoning_effort="medium")
            env, key = srv._worker_env(go)
            self.assertEqual(key, "oc_sk_mock_glm53")
            self.assertEqual(env.get("STRIX_REASONING_EFFORT"), "high")
            self.assertEqual(json.loads(env["LLM_EXTRA_HEADERS"]), {"x-opencode-session": "s2"})

    def test_standing_instruction_mandates_extraction_and_escalation(self):
        text = STANDING_INSTRUCTION.lower()
        for needle in ("extract real rows", "credentials", "session tokens", "open proof gap",
                       "no destructive statements"):
            self.assertIn(needle, text)

    def test_glm53_wire_request_and_failed_preflight_leaves_no_run(self):
        """The real worker's preflight against a mock OpenCode Go endpoint."""
        if not REAL_STRIX_PYTHON.is_file():
            self.skipTest("Strix's interpreter is not installed")
        captured = []

        class MockGo(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                captured.append({"headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
                if body.get("model") == "fail-403":
                    status, payload = 403, {"error": {"type": "permission_error", "message":
                        "An active OpenCode Go subscription is required to use OpenCode Go models."}}
                else:
                    status, payload = 200, {
                        "id": "chatcmpl-glm53", "object": "chat.completion", "created": 1795000000,
                        "model": "glm-5.3",
                        "choices": [{"index": 0, "message": {"role": "assistant", "content": "OK"},
                                     "finish_reason": "stop"}],
                        "usage": {"prompt_tokens": 8, "completion_tokens": 2, "total_tokens": 10},
                    }
                raw = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), MockGo)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        work = self.home / "fresh-work"
        work.mkdir()
        strix_home = self.home / ".strix"
        strix_home.mkdir()
        # A hostile CLI config pointing elsewhere: the worker must ignore it.
        (strix_home / "cli-config.json").write_text(json.dumps({"env": {
            "STRIX_LLM": "openai/glm-5.3",
            "LLM_API_BASE": "http://127.0.0.1:9/invalid",
            "STRIX_API_TYPE": "responses",
        }}))
        (self.home / "secret.env").write_text('OPENCODE_GO_API_KEY="oc_sk_mock_glm53"\n')
        self.env.update({
            "STRIX_HOME": str(strix_home),
            "STRIX_IMAGE": "fixture-only",
            "STRIX_PYTHON": str(REAL_STRIX_PYTHON),
            "OPENCODE_AUTH_FILE": str(self.home / "auth.json"),
            "OPENCODE_GO_API_BASE": f"http://127.0.0.1:{server.server_address[1]}/inference/go/openai/v1",
        })
        self.work = work
        proc = self.start()
        try:
            _, session = self.open_session(proc)
            sid = session["sessionId"]
            model_ids = [m["modelId"] for m in session["models"]["availableModels"]]
            for model in ("opencode_go/glm-5.3", "opencode_go/glm-5.3-flash", "openrouter/z-ai/glm-5.3"):
                self.assertIn(model, model_ids)

            self.rpc(proc, {"jsonrpc": "2.0", "id": 3, "method": "session/prompt", "params": {
                "sessionId": sid,
                "prompt": [{"type": "text", "text": "<user_request>\n/preflight opencode_go/glm-5.3\n</user_request>"}],
            }})
            msgs = self.read_until(proc, 3)
            self.assertEqual(msgs[-1]["result"]["stopReason"], "end_turn")
            self.assertTrue(any("succeeded" in t for t in self.texts(msgs)), msgs)
            self.assertEqual(len(captured), 1)
            self.assertEqual(captured[0]["headers"].get("x-opencode-session"), sid)
            self.assertEqual(captured[0]["headers"].get("authorization"), "Bearer oc_sk_mock_glm53")
            self.assertEqual(captured[0]["body"].get("model"), "glm-5.3")

            # A scan whose preflight fails must not leave an orphan strix_runs/.
            self.rpc(proc, {"jsonrpc": "2.0", "id": 4, "method": "session/set_model",
                            "params": {"sessionId": sid, "modelId": "opencode_go/fail-403"}})
            self.read_until(proc, 4)
            self.rpc(proc, {"jsonrpc": "2.0", "id": 5, "method": "session/prompt", "params": {
                "sessionId": sid, "prompt": [{"type": "text", "text": "<user_request>\n/scan .\n</user_request>"}],
            }})
            out = "".join(self.texts(self.read_until(proc, 5)))
            self.assertIn("active OpenCode Go subscription", out)
            self.assertIn("openrouter/z-ai/glm-5.3", out)
            self.assertFalse((work / "strix_runs").exists())
        finally:
            self.close(proc)

    def test_resume_instruction_lands_in_root_session(self):
        """The headless worker writes the prompt into the root agent's session."""
        strix_py = REAL_STRIX_PYTHON
        if not strix_py.is_file():
            self.skipTest("Strix's interpreter is not installed")

        state = self.work / "strix_runs" / "demo_ab12" / ".state"
        state.mkdir(parents=True)
        (state / "agents.json").write_text(json.dumps({
            "parent_of": {"root01": None, "child01": "root01"},
            "statuses": {"root01": "completed", "child01": "completed"},
        }))
        probe = self.home / "probe.py"
        probe.write_text(
            "import asyncio, json, sys\n"
            "from strix_acp.worker import deliver_resume_instruction\n"
            "asyncio.run(deliver_resume_instruction('demo_ab12', 'what did you find so far?'))\n"
            "from pathlib import Path\n"
            "from strix.core.sessions import open_agent_session\n"
            "s = open_agent_session('root01', Path(sys.argv[1]))\n"
            "print(json.dumps(asyncio.run(s.get_items())[-1]))\n"
        )
        result = subprocess.run(
            [str(strix_py), str(probe), str(state / "agents.db")],
            cwd=str(self.work),
            env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            json.loads(result.stdout.strip().splitlines()[-1]),
            {"role": "user", "content": "what did you find so far?"},
        )

    def test_worker_compiles(self):
        import py_compile
        worker = ROOT / "src/strix_acp/worker.py"
        py_compile.compile(str(worker), doraise=True)


if __name__ == "__main__":
    unittest.main()
