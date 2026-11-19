"""ACP protocol behaviour, with a fake Strix interpreter.

No Docker, no model, no network: ``STRIX_PYTHON`` points at a short script that
prints the same JSON events the real worker does.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from strix_acp.server import StrixAcpServer  # noqa: E402

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

    def start(self):
        env = {**self.env, "PYTHONPATH": str(ROOT / "src")}
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

    def test_resume_instruction_lands_in_root_session(self):
        """The headless worker writes the prompt into the root agent's session."""
        strix_py = Path(
            os.environ.get("STRIX_PYTHON_REAL", str(Path.home() / ".local/share/uv/tools/strix-agent/bin/python"))
        )
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
