"""ACP v1 stdio server bridging ACP clients to Strix.

Strix (https://github.com/usestrix/strix) is an autonomous penetration-testing
agent with its own TUI. This adapter exposes it over the Agent Client Protocol
so any ACP editor -- T3 Code, Zed, JetBrains, or a custom client -- can launch
and drive scans, continue a run, and read findings as they land.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import traceback
from typing import Any
import uuid


from . import __version__

SERVER_NAME = "strix-acp"
SERVER_VERSION = __version__

WORKER_PATH = Path(__file__).with_name("worker.py")

REASONING_EFFORTS: tuple[tuple[str, str], ...] = (
    ("none", "None"),
    ("minimal", "Minimal"),
    ("low", "Low"),
    ("medium", "Medium"),
    ("high", "High"),
    ("xhigh", "Extra High"),
    ("max", "Max"),
)

SCAN_MODES: tuple[tuple[str, str, str], ...] = (
    ("deep", "Deep Scan", "Thorough multi-agent penetration test (default)"),
    ("standard", "Standard Scan", "Balanced speed and vulnerability coverage"),
    ("quick", "Quick Scan", "Fast surface triage scan"),
)

SCOPE_MODES: tuple[tuple[str, str, str], ...] = (
    ("auto", "Auto", "Use diff-scope on git repos with a base branch, else full scan"),
    ("diff", "Diff", "Require git diff-scope for repository targets"),
    ("full", "Full", "Scan entire target regardless of git diff"),
)

# Strix run names look like ``demonicscans-org_b733``: slug plus a short hash.
# A head token matching this shape is a run selector even when it does not
# resolve, so a typo fails loudly instead of becoming an instruction.
RUN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*_[0-9a-f]{4}$")

# Appended to every T3-driven scan. Kept short because the detailed procedure
# is the data_access_escalation skill inside Strix.
STANDING_INSTRUCTION = (
    "Data-store compromise means extract and escalate, never stop at 'possible'. "
    "When SQL/NoSQL/ORM injection, an exposed database or cache port, a leaked dump, "
    "an export/IDOR path, or SSRF into a data service confirms: enumerate engine "
    "version, current user, privileges, schemas, tables, columns and row counts; "
    "extract real rows through the primitive (all columns for credential, session "
    "and token tables, with real values so plaintext vs hashed is proven); quantify "
    "blast radius (accounts, tenants, payment/PII classes, other schemas and linked "
    "servers); then reuse recovered credentials and session tokens against login and "
    "admin surfaces, continue the assessment authenticated, and test file read/write, "
    "OS execution and cross-tenant reach from the database user. Follow the "
    "data_access_escalation skill. A table list, a COUNT(*), or one boolean "
    "differential is not a finding: if extraction is blocked, name the control and "
    "layer that blocked it and record an open proof gap. No destructive statements "
    "(DROP/TRUNCATE/DELETE/UPDATE) without explicit operator approval."
)

OPENCODE_GO_MODELS: tuple[tuple[str, str, str], ...] = (
    ("opencode_go/glm-5.3", "GLM-5.3 (OpenCode Go)", "Default OpenCode Go model for Strix"),
    ("opencode_go/glm-5.3-flash", "GLM-5.3 Flash (OpenCode Go)", "Fast OpenCode Go GLM model"),
    ("opencode_go/glm-5.2", "GLM-5.2 (OpenCode Go)", "OpenCode Go GLM-5.2"),
    ("opencode_go/kimi-k3.1-pro", "Kimi K3.1 Pro (OpenCode Go)", "High-reasoning Kimi Pro model"),
    ("opencode_go/kimi-k3", "Kimi K3 (OpenCode Go)", "OpenCode Go Kimi K3"),
    ("opencode_go/kimi-k2.7-code", "Kimi K2.7 Code (OpenCode Go)", "Code-focused Kimi K2.7"),
    ("opencode_go/deepseek-v4-pro", "DeepSeek V4 Pro (OpenCode Go)", "DeepSeek V4 Pro reasoning model"),
    ("opencode_go/deepseek-v4.1-flash", "DeepSeek V4.1 Flash (OpenCode Go)", "Fast DeepSeek V4.1 Flash"),
    ("opencode_go/gpt-6-luna", "GPT-6 Luna (OpenCode Go)", "OpenCode Go GPT-6 Luna"),
    ("opencode_go/gpt-5.6-luna", "GPT-5.6 Luna (OpenCode Go)", "OpenCode Go GPT-5.6 Luna"),
    ("opencode_go/grok-4.7", "Grok 4.7 (OpenCode Go)", "OpenCode Go Grok 4.7"),
    ("opencode_go/gemini-4-argon", "Gemini 4 Argon (OpenCode Go)", "OpenCode Go Gemini 4 Argon"),
    ("opencode_go/claude-haiku-5-5", "Claude Haiku 5.5 (OpenCode Go)", "OpenCode Go Claude Haiku 5.5"),
    ("opencode_go/qwen3.8-max", "Qwen 3.8 Max (OpenCode Go)", "OpenCode Go Qwen 3.8 Max"),
    ("opencode_go/qwen3.8-flash", "Qwen 3.8 Flash (OpenCode Go)", "OpenCode Go Qwen 3.8 Flash"),
    ("opencode_go/qwen3.7-plus", "Qwen 3.7 Plus (OpenCode Go)", "OpenCode Go Qwen 3.7 Plus"),
    ("opencode_go/minimax-m3", "MiniMax M3 (OpenCode Go)", "OpenCode Go MiniMax M3"),
    ("opencode_go/minimax-m3.1-flash", "MiniMax M3.1 Flash (OpenCode Go)", "OpenCode Go MiniMax M3.1 Flash"),
    ("opencode_go/mimo-v2.6-pro", "MiMo V2.6 Pro (OpenCode Go)", "OpenCode Go MiMo V2.6 Pro"),
    ("opencode_go/mimo-v2.6-flash", "MiMo V2.6 Flash (OpenCode Go)", "OpenCode Go MiMo V2.6 Flash"),
    ("opencode_go/mimo-v2.5-pro", "MiMo V2.5 Pro (OpenCode Go)", "OpenCode Go MiMo V2.5 Pro"),
    ("opencode_go/mimo-v2.5", "MiMo V2.5 (OpenCode Go)", "OpenCode Go MiMo V2.5"),
    ("opencode_go/hy4-preview", "HY4 Preview (OpenCode Go)", "OpenCode Go HY4 Preview"),
    ("opencode_go/hy3", "HY3 (OpenCode Go)", "OpenCode Go HY3"),
    ("opencode_go/longcat-2.0", "LongCat 2.0 (OpenCode Go)", "OpenCode Go LongCat 2.0"),
    ("opencode_go/longcat-2.5-preview-free", "LongCat 2.5 Preview Free (OpenCode Go)", "OpenCode Go LongCat 2.5 Free"),
    ("opencode_go/muse-spark-1.3-contributor", "Muse Spark 1.3 (OpenCode Go)", "OpenCode Go Muse Spark 1.3"),
    ("opencode_go/muse-spark-1.2-contributor", "Muse Spark 1.2 (OpenCode Go)", "OpenCode Go Muse Spark 1.2"),
    ("opencode_go/step-5-preview", "Step 5 Preview (OpenCode Go)", "OpenCode Go Step 5 Preview"),
    ("opencode_go/beam-free", "Beam Free (OpenCode Go)", "OpenCode Go Beam Free"),
)

OPENROUTER_MODELS: tuple[tuple[str, str, str], ...] = (
    ("openrouter/z-ai/glm-5.3", "GLM-5.3 (OpenRouter)", "GLM-5.3 via OpenRouter"),
    ("openrouter/z-ai/glm-5.3-flash", "GLM-5.3 Flash (OpenRouter)", "GLM-5.3 Flash via OpenRouter"),
)

DEFAULT_MODEL_ID = "opencode_go/glm-5.3"
CLI_OPENAI_ALIAS_MODEL = "openai/glm-5.3"

AVAILABLE_COMMANDS: list[dict[str, Any]] = [
    {
        "name": "preflight",
        "description": "Test OpenCode Go / configured LLM model connectivity",
        "input": {"hint": "[model-id]"},
    },
    {
        "name": "runs",
        "description": "List Strix scan runs under the current workspace",
    },
    {
        "name": "scan",
        "description": "Run a Strix security scan on target URL, repo, or path",
        "input": {"hint": "<target> [instructions]"},
    },
    {
        "name": "resume",
        "description": "Continue a prior run with its history (defaults to this session's last run)",
        "input": {"hint": "[run|path] [instructions]"},
    },
    {
        "name": "new",
        "description": "Force a fresh run instead of continuing the last one",
        "input": {"hint": "<target> [instructions]"},
    },
    {
        "name": "quick",
        "description": "Run a quick-mode Strix security scan",
        "input": {"hint": "[target] [instructions]"},
    },
    {
        "name": "standard",
        "description": "Run a standard-mode Strix security scan",
        "input": {"hint": "[target] [instructions]"},
    },
    {
        "name": "deep",
        "description": "Run a deep-mode Strix security scan",
        "input": {"hint": "[target] [instructions]"},
    },
]



def _read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if len(val) >= 2 and ((val[0] == val[-1] == '"') or (val[0] == val[-1] == "'")):
            val = val[1:-1]
        if key:
            values[key] = val
    return values


def _read_cli_config_env(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    env_block = data.get("env") if isinstance(data, dict) else None
    return env_block if isinstance(env_block, dict) else {}


def find_strix_python() -> str:
    override = os.environ.get("STRIX_PYTHON", "").strip()
    if override and os.access(override, os.X_OK):
        return override
    uv_python = Path.home() / ".local/share/uv/tools/strix-agent/bin/python"
    if uv_python.is_file() and os.access(uv_python, os.X_OK):
        return str(uv_python)
    strix_bin = os.environ.get("STRIX_BIN", "").strip() or shutil.which("strix") or ""
    if strix_bin:
        try:
            first_line = Path(strix_bin).read_text(encoding="utf-8", errors="ignore").splitlines()[0]
            if first_line.startswith("#!"):
                candidate = first_line[2:].strip().split()[0]
                if Path(candidate).exists():
                    return candidate
        except OSError:
            pass
    return sys.executable


def build_model_catalog() -> tuple[str, list[dict[str, Any]]]:
    cli_cfg = _read_cli_config_env(
        Path(os.environ.get("STRIX_HOME", Path.home() / ".strix")) / "cli-config.json"
    )
    efforts = [{"value": val, "label": label} for val, label in REASONING_EFFORTS]
    default_effort = str(
        os.environ.get("STRIX_REASONING_EFFORT")
        or cli_cfg.get("STRIX_REASONING_EFFORT")
        or "high"
    ).strip().lower()
    if default_effort not in {v for v, _ in REASONING_EFFORTS}:
        default_effort = "high"

    models: list[dict[str, Any]] = []
    seen: set[str] = set()
    for model_id, name, desc in (*OPENCODE_GO_MODELS, *OPENROUTER_MODELS):
        seen.add(model_id)
        models.append(
            {
                "modelId": model_id,
                "name": name,
                "description": desc,
                "_meta": {
                    "supportsReasoningEffort": True,
                    "reasoningEffort": default_effort,
                    "reasoningEfforts": efforts,
                },
            }
        )

    configured_model = str(
        os.environ.get("STRIX_LLM") or cli_cfg.get("STRIX_LLM") or ""
    ).strip()
    if configured_model and configured_model not in seen and configured_model != CLI_OPENAI_ALIAS_MODEL:
        models.insert(
            0,
            {
                "modelId": configured_model,
                "name": configured_model,
                "description": "Configured Strix model",
                "_meta": {
                    "supportsReasoningEffort": True,
                    "reasoningEffort": default_effort,
                    "reasoningEfforts": efforts,
                },
            },
        )
        default_model = configured_model
    elif configured_model in seen:
        default_model = configured_model
    else:
        default_model = DEFAULT_MODEL_ID

    return default_model, models


@dataclass
class SessionState:
    session_id: str
    cwd: str
    model_id: str
    reasoning_effort: str = "high"
    scan_mode: str = "deep"
    scope_mode: str = "auto"
    active_proc: subprocess.Popen[str] | None = None
    cancelled: bool = False
    # Last run touched by this session: what a follow-up prompt resumes by default.
    last_run: str | None = None
    last_run_dir: str | None = None
    last_targets: list[str] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)


@dataclass
class ScanPlan:
    """What one prompt should do: start a fresh run, resume an existing one, or stop."""

    kind: str  # "fresh" | "resume" | "error"
    scan_mode: str
    targets: list[str] = field(default_factory=list)
    instruction: str = ""
    resume_run: str | None = None
    resume_workspace: str | None = None
    error: str = ""


class StrixAcpServer:
    def __init__(self) -> None:
        self._write_lock = threading.Lock()
        self._sessions: dict[str, SessionState] = {}
        self._sessions_lock = threading.Lock()
        self._default_model, self._models = build_model_catalog()
        self._model_ids = {m["modelId"] for m in self._models}
        self._strix_python = find_strix_python()

    def send(self, payload: dict[str, Any]) -> None:
        line = json.dumps(payload, ensure_ascii=False)
        with self._write_lock:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()

    def send_result(self, req_id: Any, result: Any) -> None:
        self.send({"jsonrpc": "2.0", "id": req_id, "result": result})

    def send_error(self, req_id: Any, code: int, message: str, data: Any = None) -> None:
        err: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        self.send({"jsonrpc": "2.0", "id": req_id, "error": err})

    def send_update(self, session_id: str, update: dict[str, Any]) -> None:
        self.send(
            {
                "jsonrpc": "2.0",
                "method": "session/update",
                "params": {"sessionId": session_id, "update": update},
            }
        )

    def emit_text(self, session_id: str, text: str) -> None:
        if text:
            self.send_update(
                session_id,
                {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": text}},
            )

    def emit_thought(self, session_id: str, text: str) -> None:
        if text:
            self.send_update(
                session_id,
                {"sessionUpdate": "agent_thought_chunk", "content": {"type": "text", "text": text}},
            )

    def _config_options(self, s: SessionState) -> list[dict[str, Any]]:
        return [
            {
                "id": "model",
                "name": "Model",
                "description": "LLM used by Strix agents",
                "category": "model",
                "type": "select",
                "currentValue": s.model_id,
                "options": [
                    {
                        "value": m["modelId"],
                        "name": m["name"],
                        "description": m["description"],
                    }
                    for m in self._models
                ],
            },
            {
                "id": "reasoning_effort",
                "name": "Reasoning effort",
                "description": "Reasoning depth for Strix LLM calls",
                "category": "thought_level",
                "type": "select",
                "currentValue": s.reasoning_effort,
                "options": [
                    {"value": val, "name": label} for val, label in REASONING_EFFORTS
                ],
            },
            {
                "id": "scan_mode",
                "name": "Scan mode",
                "description": "Strix scan depth mode",
                "category": "mode",
                "type": "select",
                "currentValue": s.scan_mode,
                "options": [
                    {"value": val, "name": name, "description": desc}
                    for val, name, desc in SCAN_MODES
                ],
            },
            {
                "id": "scope_mode",
                "name": "Scope mode",
                "description": "Diff vs full scan scope for git repositories",
                "category": "other",
                "type": "select",
                "currentValue": s.scope_mode,
                "options": [
                    {"value": val, "name": name, "description": desc}
                    for val, name, desc in SCOPE_MODES
                ],
            },
        ]

    def _modes_state(self, s: SessionState) -> dict[str, Any]:
        return {
            "currentModeId": s.scan_mode,
            "availableModes": [
                {"id": val, "name": name, "description": desc}
                for val, name, desc in SCAN_MODES
            ],
        }

    def _models_state(self, s: SessionState) -> dict[str, Any]:
        return {
            "currentModelId": s.model_id,
            "availableModels": self._models,
        }

    @staticmethod
    def _read_opencode_auth_key(provider_id: str) -> str:
        auth_path = Path(
            os.environ.get("OPENCODE_AUTH_FILE", Path.home() / ".local/share/opencode/auth.json")
        )
        if not auth_path.is_file():
            return ""
        try:
            data = json.loads(auth_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return ""
        entry = data.get(provider_id) if isinstance(data, dict) else None
        if isinstance(entry, dict):
            key = entry.get("key")
            if isinstance(key, str) and key.strip():
                return key.strip()
        return ""

    def _worker_env(self, s: SessionState, model_override: str | None = None) -> tuple[dict[str, str], str]:
        config_home = Path(
            os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
        ) / "strix-acp"
        env = dict(os.environ)
        model = (model_override or s.model_id).strip() or DEFAULT_MODEL_ID
        env["STRIX_LLM"] = model
        effort = s.reasoning_effort
        if model in ("opencode_go/glm-5.3", "opencode_go/glm-5.3-flash") and effort == "medium":
            effort = "high"
        env["STRIX_REASONING_EFFORT"] = effort

        if model.startswith("openrouter/"):
            or_env_file = Path(
                os.environ.get("STRIX_OPENROUTER_ENV", config_home / "openrouter.env")
            )
            for k, v in _read_env_file(or_env_file).items():
                env.setdefault(k, v)
            api_key = (
                env.get("OPENROUTER_API_KEY")
                or self._read_opencode_auth_key("openrouter")
                or ""
            )
            if api_key:
                env["OPENROUTER_API_KEY"] = api_key
                env["LLM_API_KEY"] = api_key
            for key in (
                "OPENCODE_GO_API_KEY",
                "OPENCODE_API_KEY",
                "OPENCODE_GO_API_BASE",
                "LLM_API_BASE",
                "OPENAI_API_BASE",
                "OPENAI_BASE_URL",
                "LITELLM_BASE_URL",
                "STRIX_API_TYPE",
                "STRIX_FORCE_API",
                "LLM_EXTRA_HEADERS",
            ):
                env.pop(key, None)
            return env, api_key

        secret_file = Path(
            os.environ.get("STRIX_OPENCODE_GO_ENV", config_home / "opencode-go.env")
        )
        secret_env = _read_env_file(secret_file)
        for k, v in secret_env.items():
            env.setdefault(k, v)

        api_key = (
            env.get("OPENCODE_GO_API_KEY")
            or env.get("OPENCODE_API_KEY")
            or env.get("LLM_API_KEY")
            or ""
        )
        if api_key:
            env.setdefault("OPENCODE_GO_API_KEY", api_key)
            env.setdefault("OPENCODE_API_KEY", api_key)
            env.setdefault("LLM_API_KEY", api_key)
        if model.startswith("opencode_go/"):
            for key in (
                "LLM_API_BASE",
                "OPENAI_API_BASE",
                "OPENAI_BASE_URL",
                "LITELLM_BASE_URL",
                "STRIX_API_TYPE",
                "STRIX_FORCE_API",
            ):
                env.pop(key, None)
            env["LLM_EXTRA_HEADERS"] = json.dumps({"x-opencode-session": s.session_id})
        return env, api_key

    def handle_initialize(self, req_id: Any, _params: dict[str, Any]) -> None:
        self.send_result(
            req_id,
            {
                "protocolVersion": 1,
                "agentInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "agentCapabilities": {
                    "loadSession": False,
                    "promptCapabilities": {"image": False, "audio": False, "embeddedContext": True},
                    "mcpCapabilities": {"http": False, "sse": False, "acp": False},
                    "sessionCapabilities": {"delete": {}, "resume": {}},
                },
                "authMethods": [],
            },
        )

    def _state_dir(self) -> Path:
        return Path(
            os.environ.get(
                "STRIX_ACP_STATE",
                str(Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state")))
                    / "strix-acp" / "sessions"),
            )
        )

    def _state_path(self, session_id: str) -> Path | None:
        if not re.fullmatch(r"[A-Za-z0-9._-]{8,128}", session_id or ""):
            return None
        return self._state_dir() / f"{session_id}.json"

    def _save_session(self, s: SessionState) -> None:
        """Persist the session so a restarted client can resume it.

        ACP clients reopen a thread's provider session after their own restart,
        and an agent that advertises no session/load or session/resume makes that
        thread unusable. The scan state (workspace, modes, last run) lives here so
        session/resume can rebuild it in a fresh process.
        """
        path = self._state_path(s.session_id)
        if path is None:
            return
        payload = {
            "session_id": s.session_id,
            "cwd": s.cwd,
            "model_id": s.model_id,
            "reasoning_effort": s.reasoning_effort,
            "scan_mode": s.scan_mode,
            "scope_mode": s.scope_mode,
            "last_run": s.last_run,
            "last_run_dir": s.last_run_dir,
            "last_targets": s.last_targets,
        }
        try:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            os.chmod(tmp, 0o600)
            tmp.replace(path)
        except OSError:
            pass

    def _restore_session(self, session_id: str, cwd: str) -> SessionState:
        payload: dict[str, Any] = {}
        path = self._state_path(session_id)
        if path is not None and path.is_file():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    payload = loaded
            except (OSError, json.JSONDecodeError):
                payload = {}
        session = SessionState(
            session_id=session_id,
            cwd=str(payload.get("cwd") or cwd or os.getcwd()),
            model_id=str(payload.get("model_id") or self._default_model),
            reasoning_effort=str(payload.get("reasoning_effort") or "high"),
            scan_mode=str(payload.get("scan_mode") or "deep"),
            scope_mode=str(payload.get("scope_mode") or "auto"),
            last_run=payload.get("last_run") or None,
            last_run_dir=payload.get("last_run_dir") or None,
            last_targets=[str(t) for t in (payload.get("last_targets") or []) if isinstance(t, str)],
        )
        if not session.last_run:
            # A reopened thread that predates this state file: adopt the most recent
            # run in its workspace so a follow-up continues instead of rescanning.
            latest = self._latest_run_name(session.cwd)
            if latest:
                session.last_run = latest
                session.last_run_dir = str(Path(session.cwd) / "strix_runs" / latest)
        with self._sessions_lock:
            self._sessions[session_id] = session
        self._save_session(session)
        return session

    def handle_session_resume(self, req_id: Any, params: dict[str, Any]) -> None:
        session_id = params.get("sessionId")
        if not isinstance(session_id, str) or not session_id:
            self.send_error(req_id, -32602, "Missing sessionId")
            return
        cwd = str(params.get("cwd") or os.getcwd())
        s = self._get_session(session_id) or self._restore_session(session_id, cwd)
        self.send_result(
            req_id,
            {"modes": self._modes_state(s), "configOptions": self._config_options(s)},
        )
        self.send_update(
            session_id,
            {
                "sessionUpdate": "available_commands_update",
                "availableCommands": AVAILABLE_COMMANDS,
            },
        )

    def handle_session_new(self, req_id: Any, params: dict[str, Any]) -> None:
        session_id = str(uuid.uuid4())
        cwd_raw = params.get("cwd") or os.getcwd()
        cwd = str(Path(str(cwd_raw)).expanduser())
        # Strix loads its own MCP config in the worker.
        session = SessionState(
            session_id=session_id,
            cwd=cwd,
            model_id=self._default_model,
        )
        with self._sessions_lock:
            self._sessions[session_id] = session
        self._save_session(session)

        self.send_result(
            req_id,
            {
                "sessionId": session_id,
                "models": self._models_state(session),
                "modes": self._modes_state(session),
                "configOptions": self._config_options(session),
            },
        )
        self.send_update(
            session_id,
            {
                "sessionUpdate": "available_commands_update",
                "availableCommands": AVAILABLE_COMMANDS,
            },
        )

    def _get_session(self, session_id: Any) -> SessionState | None:
        if not isinstance(session_id, str):
            return None
        with self._sessions_lock:
            return self._sessions.get(session_id)

    def handle_set_model(self, req_id: Any, params: dict[str, Any]) -> None:
        s = self._get_session(params.get("sessionId"))
        if s is None:
            self.send_error(req_id, -32002, "Unknown sessionId")
            return
        model_id = str(params.get("modelId") or "").strip()
        if not model_id:
            self.send_error(req_id, -32602, "Missing modelId")
            return
        s.model_id = model_id
        self._save_session(s)
        self.send_result(req_id, {})
        self.send_update(
            s.session_id,
            {"sessionUpdate": "config_option_update", "configOptions": self._config_options(s)},
        )

    def handle_set_mode(self, req_id: Any, params: dict[str, Any]) -> None:
        s = self._get_session(params.get("sessionId"))
        if s is None:
            self.send_error(req_id, -32002, "Unknown sessionId")
            return
        mode_id = str(params.get("modeId") or "").strip().lower()
        if mode_id not in {v for v, _, _ in SCAN_MODES}:
            self.send_error(req_id, -32602, f"Unsupported modeId: {mode_id}")
            return
        s.scan_mode = mode_id
        self._save_session(s)
        self.send_result(req_id, {})
        self.send_update(
            s.session_id,
            {"sessionUpdate": "current_mode_update", "currentModeId": mode_id},
        )
        self.send_update(
            s.session_id,
            {"sessionUpdate": "config_option_update", "configOptions": self._config_options(s)},
        )

    def handle_set_config_option(self, req_id: Any, params: dict[str, Any]) -> None:
        s = self._get_session(params.get("sessionId"))
        if s is None:
            self.send_error(req_id, -32002, "Unknown sessionId")
            return
        config_id = str(params.get("configId") or "").strip()
        value = params.get("value")
        val_str = str(value).strip() if value is not None else ""
        if config_id == "model" and val_str:
            s.model_id = val_str
        elif config_id == "reasoning_effort" and val_str.lower() in {v for v, _ in REASONING_EFFORTS}:
            s.reasoning_effort = val_str.lower()
        elif config_id == "scan_mode" and val_str.lower() in {v for v, _, _ in SCAN_MODES}:
            s.scan_mode = val_str.lower()
        elif config_id == "scope_mode" and val_str.lower() in {v for v, _, _ in SCOPE_MODES}:
            s.scope_mode = val_str.lower()
        else:
            self.send_error(req_id, -32602, f"Unsupported config option {config_id}={val_str!r}")
            return
        self._save_session(s)
        opts = self._config_options(s)
        self.send_result(req_id, {"configOptions": opts})

    def handle_delete_or_close(self, req_id: Any, params: dict[str, Any]) -> None:
        session_id = params.get("sessionId")
        s = None
        if isinstance(session_id, str):
            with self._sessions_lock:
                s = self._sessions.pop(session_id, None)
        if s is not None:
            self._terminate_worker(s)
            path = self._state_path(s.session_id)
            if path is not None:
                try:
                    path.unlink()
                except OSError:
                    pass
        self.send_result(req_id, {})

    def handle_cancel(self, _req_id: Any, params: dict[str, Any]) -> None:
        s = self._get_session(params.get("sessionId"))
        if s is not None:
            s.cancelled = True
            self._terminate_worker(s)

    def _terminate_worker(self, s: SessionState) -> None:
        proc = s.active_proc
        if proc is None or proc.poll() is not None:
            return
        try:
            proc.terminate()
        except OSError:
            pass

    @staticmethod
    def _unwrap_user_request(text: str) -> str:
        # Clients wrap the prompt in their own scaffolding. Take the user request
        # when it is tagged, otherwise strip the known context blocks, so slash
        # commands and target parsing only see what the user actually wrote.
        matches = re.findall(r"<user_request>\s*(.*?)\s*</user_request>", text, flags=re.DOTALL)
        if matches:
            return "\n\n".join(m.strip() for m in matches if m.strip()).strip()
        cleaned = text
        for tag in (
            "t3_code_instructions",
            "client_instructions",
            "client_context",
            "runtime_info",
            "pull_request_linking",
        ):
            cleaned = re.sub(rf"<{tag}>.*?</{tag}>", "", cleaned, flags=re.DOTALL)
        return cleaned.strip()

    @staticmethod
    def _looks_like_domain_or_host_target(tok: str, cwd: str) -> str | None:
        cand = tok.strip().strip("\"'<>()[]{}").rstrip(",;.")
        if not cand or cand.startswith("-"):
            return None
        if re.match(r"^(https?://|git://|git@|postman://)\S+$", cand):
            return cand

        # Bare IPv4 / IPv6 / IPv4:port / [IPv6]:port
        ip_host = cand.split("/", 1)[0]
        if ip_host.startswith("[") and "]" in ip_host:
            ip_only = ip_host[1:ip_host.index("]")]
        elif ":" in ip_host and ip_host.count(":") == 1:
            ip_only, port_str = ip_host.rsplit(":", 1)
            if not port_str.isdigit():
                ip_only = ""
        else:
            ip_only = ip_host
        if ip_only:
            try:
                ipaddress.ip_address(ip_only)
                return cand
            except ValueError:
                pass

        # Avoid treating existing non-spec local files (e.g. README.md, app.py) as domains
        local_cand = (Path(cwd) / cand) if not Path(cand).is_absolute() else Path(cand)
        if local_cand.exists():
            if local_cand.is_dir() or local_cand.suffix.lower() in (".json", ".yaml", ".yml"):
                return str(local_cand.resolve())
            return None

        # Hostname or host:port or host/path matching Strix infer_target_type
        host_port = cand.split("/", 1)[0]
        if ":" in host_port:
            host_only, port_str = host_port.rsplit(":", 1)
            if not port_str.isdigit() or not (1 <= int(port_str) <= 65535):
                return None
        else:
            host_only = host_port
        if "." not in host_only or host_only.startswith(".") or host_only.endswith("."):
            return None
        labels = host_only.split(".")
        if len(labels) < 2:
            return None
        label_re = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
        if not all(label_re.match(lbl) for lbl in labels):
            return None
        tld = labels[-1].lower()
        if not re.match(r"^[a-z]{2,63}$", tld):
            return None
        common_file_exts = {
            "py", "js", "ts", "tsx", "jsx", "mjs", "cjs", "json", "yaml", "yml",
            "toml", "md", "txt", "env", "lock", "log", "csv", "xml", "html",
            "css", "scss", "sql", "java", "rb", "php", "c", "cpp", "h", "hpp",
            "pdf", "png", "jpg", "jpeg", "svg", "zip", "tar", "gz",
        }
        if "/" not in cand and ":" not in host_port and len(labels) == 2 and tld in common_file_exts:
            return None
        return cand

    def _extract_prompt(self, blocks: Any, cwd: str) -> tuple[str, list[str]]:
        if not isinstance(blocks, list):
            return "", []
        text_parts: list[str] = []
        extra_paths: list[str] = []
        for blk in blocks:
            if not isinstance(blk, dict):
                continue
            btype = blk.get("type")
            if btype == "text":
                t = blk.get("text")
                if isinstance(t, str) and t.strip():
                    unwrapped = self._unwrap_user_request(t)
                    if unwrapped:
                        text_parts.append(unwrapped)
            elif btype == "resource_link":
                uri = str(blk.get("uri") or "")
                if uri.startswith("file://"):
                    p = uri[len("file://"):]
                    if p not in extra_paths:
                        extra_paths.append(p)
            elif btype == "resource":
                res = blk.get("resource")
                if isinstance(res, dict):
                    uri = str(res.get("uri") or "")
                    txt = res.get("text")
                    if uri.startswith("file://"):
                        p = uri[len("file://"):]
                        if p not in extra_paths:
                            extra_paths.append(p)
                    if isinstance(txt, str) and txt.strip():
                        text_parts.append(f"[Context from {uri or 'resource'}]\n{txt.strip()}")
        return "\n\n".join(text_parts).strip(), extra_paths

    def _list_runs_markdown(self, cwd: str) -> str:
        runs_dir = Path(cwd) / "strix_runs"
        if not runs_dir.is_dir():
            return f"No `strix_runs` directory found under `{cwd}`."
        rows: list[tuple[float, str, str, str, int]] = []
        for child in runs_dir.iterdir():
            run_json = child / "run.json"
            if not run_json.is_file():
                continue
            try:
                mtime = run_json.stat().st_mtime
                rec = json.loads(run_json.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            targets = [
                str(t.get("original") or "")
                for t in (rec.get("targets_info") or [])
                if isinstance(t, dict) and t.get("original")
            ]
            target_str = targets[0] if len(targets) == 1 else (f"{targets[0]} (+{len(targets)-1})" if targets else "-")
            vulns_file = child / "vulnerabilities.json"
            vcount = 0
            if vulns_file.is_file():
                try:
                    vdata = json.loads(vulns_file.read_text(encoding="utf-8"))
                    if isinstance(vdata, list):
                        vcount = len(vdata)
                except (OSError, json.JSONDecodeError):
                    pass
            rows.append((mtime, child.name, str(rec.get("status") or "unknown"), target_str, vcount))
        if not rows:
            return f"No Strix scan runs found in `{runs_dir}`."
        rows.sort(reverse=True)
        lines = [
            f"Strix runs under `{runs_dir}`:",
            "",
            "| Run | Status | Findings | Target |",
            "| --- | --- | ---: | --- |",
        ]
        for _, name, status, target, vcount in rows[:20]:
            lines.append(f"| `{name}` | {status} | {vcount} | `{target}` |")
        lines.extend([
            "",
            "Continue one with `/resume <run> <instruction>` (or just send a follow-up "
            "to keep this session's run going). `/new <target>` starts a fresh run.",
        ])
        return "\n".join(lines)

    @staticmethod
    def _latest_run_name(workspace: str) -> str | None:
        base = Path(workspace) / "strix_runs"
        if not base.is_dir():
            return None
        candidates = [c for c in base.iterdir() if (c / "run.json").is_file()]
        if not candidates:
            return None
        return max(candidates, key=lambda c: (c / "run.json").stat().st_mtime).name

    @staticmethod
    def _locate_run(raw: str, cwd: str) -> tuple[str, str] | None:
        """Resolve a run name or a path to (run_name, workspace)."""
        cand = Path(raw).expanduser()
        if not cand.is_absolute():
            cand = Path(cwd) / cand
        if (cand / "run.json").is_file() and cand.parent.name == "strix_runs":
            return cand.name, str(cand.parent.parent)
        named = Path(cwd) / "strix_runs" / raw
        if (named / "run.json").is_file():
            return named.name, str(named.parent.parent)
        return None

    @staticmethod
    def _session_last_run(s: SessionState) -> tuple[str, str] | None:
        if not s.last_run:
            return None
        if s.last_run_dir:
            run_dir = Path(s.last_run_dir)
            if run_dir.parent.name == "strix_runs":
                return run_dir.name, str(run_dir.parent.parent)
        return s.last_run, s.cwd

    def _plan_prompt(
        self,
        prompt_text: str,
        cwd: str,
        extra_paths: list[str],
        default_scan_mode: str,
        last_run: tuple[str, str] | None,
        last_targets: list[str] | None = None,
    ) -> ScanPlan:
        """Decide whether a prompt starts a run or continues the session's last one.

        Continuation rules, in order:

        - ``/resume [run|path] [instruction]`` resumes the last run, or the named
          one, with the instruction as a new user message.
        - A prompt with no target continues the session's last run.
        - A prompt that names the same target as the last run continues it too.
        - ``/new`` (or ``/scan``, ``/quick``, ``/standard``, ``/deep``) and a
          different target always start a fresh run.
        """
        text = prompt_text.strip()
        scan_mode = default_scan_mode
        force_new = False
        resume_selector: str | None = None
        resume_requested = False
        resume_instruction = ""

        if text.startswith("/resume"):
            resume_requested = True
            rest = text[len("/resume"):].strip()
            head, _, tail = rest.partition(" ")
            head = head.strip()
            if head in ("", "last", "latest", "-"):
                resume_instruction = (rest[len(head):] if head else rest).strip()
            elif "/" in head or (Path(cwd) / "strix_runs" / head).exists() or RUN_NAME_RE.match(head):
                resume_selector = head
                resume_instruction = tail.strip()
            else:
                resume_instruction = rest
            text = ""
        elif text.startswith("/new"):
            force_new = True
            text = text[len("/new"):].strip()
        elif text.startswith("/quick"):
            scan_mode = "quick"
            text = text[len("/quick"):].strip()
        elif text.startswith("/standard"):
            scan_mode = "standard"
            text = text[len("/standard"):].strip()
        elif text.startswith("/deep"):
            scan_mode = "deep"
            text = text[len("/deep"):].strip()
        elif text.startswith("/scan"):
            text = text[len("/scan"):].strip()

        targets: list[str] = []
        instr_tokens: list[str] = []
        try:
            tokens = shlex.split(text)
        except ValueError:
            tokens = text.split()

        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok in ("-t", "--target") and i + 1 < len(tokens):
                targets.append(tokens[i + 1])
                i += 2
                continue
            if tok.startswith("--target="):
                targets.append(tok.split("=", 1)[1])
                i += 1
                continue
            if tok in ("--quick", "--standard", "--deep"):
                scan_mode = tok.lstrip("-")
                i += 1
                continue
            if tok in ("--scan-mode", "-m") and i + 1 < len(tokens):
                cand = tokens[i + 1].lower()
                if cand in {v for v, _, _ in SCAN_MODES}:
                    scan_mode = cand
                i += 2
                continue
            if tok.startswith(("/", "./", "../", "~/")) or tok == ".":
                cand_path = Path(tok).expanduser()
                if not cand_path.is_absolute():
                    cand_path = Path(cwd) / cand_path
                if cand_path.exists():
                    targets.append(str(cand_path.resolve()))
                    i += 1
                    continue
            matched_target = self._looks_like_domain_or_host_target(tok, cwd)
            if matched_target is not None:
                targets.append(matched_target)
                i += 1
                continue
            instr_tokens.append(tok)
            i += 1

        had_explicit_targets = bool(targets)
        if resume_requested:
            instruction = resume_instruction
            if resume_selector:
                located = self._locate_run(resume_selector, cwd) or (
                    self._locate_run(resume_selector, last_run[1]) if last_run else None
                )
                if located is None:
                    return ScanPlan(
                        kind="error",
                        scan_mode=scan_mode,
                        error=(
                            f"`{resume_selector}` is not a Strix run in this workspace. "
                            "Run `/runs` to list the runs, or pass the run directory path."
                        ),
                    )
            else:
                located = last_run or self._latest_run_tuple(cwd)
                if located is None:
                    return ScanPlan(
                        kind="error",
                        scan_mode=scan_mode,
                        error=(
                            "No Strix run to resume in this workspace. Start one with a target, "
                            "or pass a run name or path: `/resume <run> <instruction>`."
                        ),
                    )
            run_name, workspace = located
            return ScanPlan(
                kind="resume",
                scan_mode=scan_mode,
                instruction=instruction,
                resume_run=run_name,
                resume_workspace=workspace,
            )

        if not targets:
            for p in extra_paths:
                if Path(p).exists():
                    targets.append(p)
        if not targets and Path(cwd).is_dir():
            targets.append(str(Path(cwd).resolve()))

        if had_explicit_targets:
            instruction = " ".join(instr_tokens).strip()
        else:
            instruction = " ".join(instr_tokens).strip() or text
            # Preserve original multi-line wording if no flag stripping occurred
            if not tokens or (instruction == " ".join(tokens).strip() and "\n" in text):
                instruction = text

        if force_new and not had_explicit_targets:
            return ScanPlan(
                kind="error",
                scan_mode=scan_mode,
                error="`/new` needs a target: `/new <url|repo|path> [instructions]`.",
            )

        same_target = bool(
            had_explicit_targets
            and last_targets
            and {t.lower() for t in targets} <= {t.lower() for t in last_targets}
        )
        if (not had_explicit_targets or same_target) and last_run and not force_new:
            run_name, workspace = last_run
            return ScanPlan(
                kind="resume",
                scan_mode=scan_mode,
                # Keep the whole prompt: the target is already part of the run, so
                # dropping it from the instruction would lose the user's wording.
                instruction=text.strip() or instruction,
                resume_run=run_name,
                resume_workspace=workspace,
            )

        return ScanPlan(kind="fresh", scan_mode=scan_mode, targets=targets, instruction=instruction)

    def _latest_run_tuple(self, cwd: str) -> tuple[str, str] | None:
        name = self._latest_run_name(cwd)
        return (name, cwd) if name else None

    def _parse_scan_prompt(
        self,
        prompt_text: str,
        cwd: str,
        extra_paths: list[str],
        default_scan_mode: str,
    ) -> tuple[str, list[str], str]:
        """Fresh-run target parsing only (kept for callers that probe parsing)."""
        plan = self._plan_prompt(prompt_text, cwd, extra_paths, default_scan_mode, None)
        return plan.scan_mode, plan.targets, plan.instruction

    def _run_worker(self, s: SessionState, worker_args: list[str], model_override: str | None = None) -> tuple[int, list[dict[str, Any]], bool]:
        env, api_key = self._worker_env(s, model_override=model_override)
        cmd = [self._strix_python, "-u", str(WORKER_PATH), *worker_args]
        if "--api-key" not in worker_args:
            cmd.extend(["--api-key", api_key])
        if "--session-id" not in worker_args:
            cmd.extend(["--session-id", s.session_id])
        proc = subprocess.Popen(
            cmd,
            cwd=s.cwd if Path(s.cwd).is_dir() else None,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        s.active_proc = proc
        stderr_lines: list[str] = []

        def drain_stderr() -> None:
            assert proc.stderr is not None
            for line in proc.stderr:
                stderr_lines.append(line)

        err_thread = threading.Thread(target=drain_stderr, daemon=True)
        err_thread.start()

        events: list[dict[str, Any]] = []
        assert proc.stdout is not None
        for raw_line in proc.stdout:
            line = raw_line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                self.emit_thought(s.session_id, line + "\n")
                continue
            events.append(ev)
            kind = ev.get("kind")
            if kind == "thought":
                self.emit_thought(s.session_id, str(ev.get("text") or ""))
            elif kind == "tool_start":
                name = str(ev.get("name") or "tool")
                self.send_update(
                    s.session_id,
                    {
                        "sessionUpdate": "tool_call",
                        "toolCallId": str(ev.get("call_id") or uuid.uuid4()),
                        "title": f"Strix: {name}",
                        "kind": "execute",
                        "status": "in_progress",
                        "rawInput": ev.get("args") or {},
                    },
                )
            elif kind == "tool_end":
                self.send_update(
                    s.session_id,
                    {
                        "sessionUpdate": "tool_call_update",
                        "toolCallId": str(ev.get("call_id") or ""),
                        "status": "completed",
                        "rawOutput": str(ev.get("output") or ""),
                    },
                )
            elif kind == "started":
                targets_str = ", ".join(f"`{t}`" for t in (ev.get("targets") or []))
                s.last_run = str(ev.get("run_name") or s.last_run or "")
                s.last_run_dir = str(ev.get("run_dir") or s.last_run_dir or "")
                if ev.get("targets"):
                    s.last_targets = [str(t) for t in ev.get("targets") or []]
                self._save_session(s)
                verb = "Resumed" if ev.get("resume") else "Started"
                self.emit_text(
                    s.session_id,
                    f"{verb} Strix `{ev.get('scan_mode')}` scan `{ev.get('run_name')}` with `{ev.get('model')}` on {targets_str}.\n\n",
                )
            elif kind == "vuln":
                sev = str(ev.get("severity") or "info").upper()
                tag = "Updated" if ev.get("updated") else "Finding"
                title = str(ev.get("title") or "")
                target = str(ev.get("target") or "")
                endpoint = str(ev.get("endpoint") or "")
                loc = f" (`{endpoint}`)" if endpoint else (f" (`{target}`)" if target else "")
                self.emit_text(s.session_id, f"- **[{sev}] {tag} `{ev.get('id')}`**: {title}{loc}\n")
            elif kind == "vuln_deleted":
                self.emit_text(s.session_id, f"- **Withdrawn `{ev.get('id')}`**: {ev.get('title')}\n")
            elif kind == "error":
                self.emit_text(s.session_id, f"\n**Strix error:** {ev.get('message')}\n")

        rc = proc.wait()
        err_thread.join(timeout=2)
        s.active_proc = None
        has_error = any(e.get("kind") == "error" for e in events)
        if rc != 0 and not s.cancelled and not has_error:
            tail = "".join(stderr_lines[-40:]).strip()
            if tail:
                self.emit_text(s.session_id, f"\n**Strix worker exited with status {rc}:**\n```\n{tail}\n```\n")
            else:
                self.emit_text(s.session_id, f"\n**Strix worker exited with status {rc}.**\n")
        return rc, events, s.cancelled

    def handle_prompt(self, req_id: Any, params: dict[str, Any]) -> None:
        s = self._get_session(params.get("sessionId"))
        if s is None:
            self.send_error(req_id, -32002, "Unknown sessionId")
            return

        # Answer a second prompt immediately instead of blocking on the session
        # lock for the whole length of a scan: ACP clients time out a prompt that
        # never answers, which surfaces as an opaque failed run.
        active = s.active_proc
        if active is not None and active.poll() is None:
            self.emit_text(
                s.session_id,
                f"A Strix run is already active in this session (`{s.last_run or 'running'}`). "
                "Wait for it to finish, or cancel it, before sending another prompt.",
            )
            self.send_result(req_id, {"stopReason": "end_turn"})
            return

        with s.lock:
            s.cancelled = False
            prompt_text, extra_paths = self._extract_prompt(params.get("prompt"), s.cwd)
            if not prompt_text:
                self.emit_text(s.session_id, "Provide a target URL/path/repo or a command like `/preflight`, `/runs`, `/resume`, or `/scan <target> [instructions]`.")
                self.send_result(req_id, {"stopReason": "end_turn"})
                return

            if prompt_text.startswith("/runs"):
                self.emit_text(s.session_id, self._list_runs_markdown(s.cwd))
                self.send_result(req_id, {"stopReason": "end_turn"})
                return

            if prompt_text.startswith("/preflight"):
                rest = prompt_text[len("/preflight"):].strip().split()
                model = rest[0] if rest else s.model_id
                rc, events, cancelled = self._run_worker(s, ["preflight", "--model", model], model_override=model)
                if cancelled:
                    self.emit_text(s.session_id, "\nPreflight cancelled.\n")
                    self.send_result(req_id, {"stopReason": "cancelled"})
                    return
                res = next((e for e in reversed(events) if e.get("kind") == "preflight_result"), None)
                if res and res.get("ok"):
                    self.emit_text(s.session_id, f"Strix preflight succeeded for `{res.get('model')}`.")
                elif res:
                    self.emit_text(s.session_id, f"Strix preflight failed for `{res.get('model')}`:\n\n`{res.get('error')}`")
                elif rc != 0:
                    self.emit_text(s.session_id, f"Strix preflight failed (exit code {rc}).")
                self.send_result(req_id, {"stopReason": "end_turn"})
                return

            plan = self._plan_prompt(
                prompt_text, s.cwd, extra_paths, s.scan_mode, self._session_last_run(s), s.last_targets
            )
            if plan.kind == "error":
                self.emit_text(s.session_id, plan.error)
                self.send_result(req_id, {"stopReason": "end_turn"})
                return

            user_text = plan.instruction.strip()
            if user_text:
                instruction = f"{user_text}\n\n{STANDING_INSTRUCTION}"
            elif plan.kind == "fresh":
                instruction = STANDING_INSTRUCTION
            else:
                # Bare /resume: the worker seeds its own continue message.
                instruction = ""

            # Quick Docker daemon pre-check before importing Strix + LiteLLM
            docker_bin = shutil.which("docker")
            if not docker_bin:
                self.emit_text(s.session_id, "Docker binary not found in `PATH`. Strix requires Docker for its sandbox.")
                self.send_result(req_id, {"stopReason": "end_turn"})
                return
            probe = subprocess.run([docker_bin, "info"], capture_output=True, text=True, timeout=10)
            if probe.returncode != 0:
                detail = (probe.stderr or probe.stdout or "").strip()
                self.emit_text(s.session_id, f"Docker daemon is not reachable for Strix sandbox:\n```\n{detail}\n```")
                self.send_result(req_id, {"stopReason": "end_turn"})
                return

            worker_args = [
                "scan",
                "--model",
                s.model_id,
                "--scan-mode",
                plan.scan_mode,
                "--scope-mode",
                s.scope_mode,
                "--instruction",
                instruction,
            ]
            if plan.kind == "resume":
                assert plan.resume_run and plan.resume_workspace
                run_dir = Path(plan.resume_workspace) / "strix_runs" / plan.resume_run
                if not (run_dir / "run.json").is_file():
                    self.emit_text(
                        s.session_id,
                        f"Run `{plan.resume_run}` is gone (no `{run_dir}/run.json`). Start a fresh run with a target.",
                    )
                    self.send_result(req_id, {"stopReason": "end_turn"})
                    return
                self.emit_text(
                    s.session_id,
                    f"Resuming Strix run `{plan.resume_run}` — `{run_dir}`.\n\n"
                    f"Instruction: {user_text.splitlines()[0][:200] if user_text else '(continue from where it left off)'}\n\n",
                )
                worker_args.extend(["--resume", plan.resume_run, "--workspace", plan.resume_workspace])
            else:
                for t in plan.targets:
                    worker_args.extend(["--target", t])

            _rc, events, cancelled = self._run_worker(s, worker_args, model_override=s.model_id)
            if cancelled:
                self.emit_text(s.session_id, "\nStrix scan cancelled.\n")
                self.send_result(req_id, {"stopReason": "cancelled"})
                return

            fin = next((e for e in reversed(events) if e.get("kind") == "finished"), None)
            if fin:
                lines = [
                    "",
                    f"Completed Strix run `{fin.get('run_name')}` — **{fin.get('findings', 0)} finding(s)**.",
                    f"Artifacts: `{fin.get('run_dir')}`",
                ]
                final_result = str(fin.get("final_result") or "").strip()
                if final_result:
                    lines.extend(["", final_result])
                self.emit_text(s.session_id, "\n".join(lines))
            elif _rc == 0 and not any(e.get("kind") == "error" for e in events):
                self.emit_text(s.session_id, "\nStrix scan exited without producing a completion summary.")
            self.send_result(req_id, {"stopReason": "end_turn"})

    def dispatch(self, req: dict[str, Any]) -> None:
        method = req.get("method")
        req_id = req.get("id")
        params = req.get("params")
        if not isinstance(params, dict):
            params = {}

        try:
            if method == "initialize":
                self.handle_initialize(req_id, params)
            elif method == "session/new":
                self.handle_session_new(req_id, params)
            elif method == "session/set_model":
                self.handle_set_model(req_id, params)
            elif method == "session/resume":
                self.handle_session_resume(req_id, params)
            elif method == "session/set_mode":
                self.handle_set_mode(req_id, params)
            elif method == "session/set_config_option":
                self.handle_set_config_option(req_id, params)
            elif method in ("session/delete", "session/close"):
                self.handle_delete_or_close(req_id, params)
            elif method == "session/cancel":
                self.handle_cancel(req_id, params)
                if req_id is not None:
                    self.send_result(req_id, {})
            elif method == "session/prompt":
                # Run prompt in a thread so session/cancel can still be read immediately.
                threading.Thread(
                    target=self._run_prompt_safe,
                    args=(req_id, params),
                    daemon=True,
                ).start()
            elif req_id is not None:
                self.send_error(req_id, -32601, f"Method not found: {method}")
        except Exception as exc:
            if req_id is not None:
                self.send_error(req_id, -32603, f"Internal error: {exc}", traceback.format_exc())

    def _run_prompt_safe(self, req_id: Any, params: dict[str, Any]) -> None:
        try:
            self.handle_prompt(req_id, params)
        except Exception as exc:
            if req_id is not None:
                self.send_error(req_id, -32603, f"Prompt failed: {exc}", traceback.format_exc())

    def shutdown(self) -> None:
        with self._sessions_lock:
            sessions = list(self._sessions.values())
        for s in sessions:
            s.cancelled = True
            self._terminate_worker(s)

    def run(self) -> int:
        try:
            for raw_line in sys.stdin:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    req = json.loads(line)
                except json.JSONDecodeError as exc:
                    self.send_error(None, -32700, f"Parse error: {exc}")
                    continue
                if isinstance(req, dict):
                    self.dispatch(req)
        finally:
            self.shutdown()
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Strix ACP v1 stdio server")
    parser.add_argument("--version", action="version", version=f"{SERVER_NAME} {SERVER_VERSION}")
    parser.parse_args()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    return StrixAcpServer().run()


if __name__ == "__main__":
    raise SystemExit(main())
