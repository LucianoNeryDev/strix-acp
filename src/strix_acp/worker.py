"""Strix scan worker.

Runs under Strix's own interpreter (`STRIX_PYTHON` / the uv tool venv) and
speaks newline-delimited JSON events on stdout. Kept as a separate file, not a
string, so a syntax error is caught by the compiler instead of at runtime.
"""

import argparse
import asyncio
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import sys
import traceback

def emit(kind: str, **payload):
    msg = {"kind": kind, **payload}
    sys.stdout.write(json.dumps(msg, ensure_ascii=False) + "\n")
    sys.stdout.flush()


DEFAULT_RESUME_INSTRUCTION = (
    "Continue the assessment from where you left off. If you had a plan, carry on "
    "with the next step; otherwise re-check the open findings and finish the scan."
)


async def deliver_resume_instruction(run_name: str, instruction: str) -> None:
    # Append a resume prompt to the root agent's SDK session.
    #
    # Headless resume never drains the coordinator mailbox -- only the
    # interactive loop calls consume_pending -- so resume_instruction in
    # scan_config is dropped and the agent replays its history with no new
    # input. Writing the item into the session is what actually hands the new
    # instruction to the agent.
    from strix.core.paths import run_dir_for, runtime_state_dir
    from strix.core.sessions import open_agent_session, session_write_lock

    state_dir = runtime_state_dir(run_dir_for(run_name))
    snapshot = json.loads((state_dir / "agents.json").read_text(encoding="utf-8"))
    parents = snapshot.get("parent_of") or {}
    root_id = next((aid for aid, parent in parents.items() if parent is None), None)
    if not root_id:
        raise RuntimeError("agents.json has no root agent")
    session = open_agent_session(root_id, state_dir / "agents.db")
    try:
        async with session_write_lock(session):
            await session.add_items([{"role": "user", "content": instruction}])
    finally:
        close = getattr(session, "close", None)
        if close is not None:
            close()

def _patch_litellm_glm53():
    try:
        import litellm
    except Exception:
        return

    # Register OpenRouter GLM-5.3 entries if missing from LiteLLM's static map so Strix
    # enables reasoning + full 1M context window + tool calling without 200k fallback.
    base_meta = (
        litellm.model_cost.get("zai/glm-5.3")
        or litellm.model_cost.get("opencode_go/glm-5.3")
        or {}
    )
    for or_name, src_name in (
        ("openrouter/z-ai/glm-5.3", "zai/glm-5.3"),
        ("openrouter/z-ai/glm-5.3-flash", "zai/glm-5.3-flash"),
    ):
        if or_name not in litellm.model_cost:
            template = dict(litellm.model_cost.get(src_name) or base_meta)
            template.update(
                {
                    "litellm_provider": "openrouter",
                    "mode": "chat",
                    "max_input_tokens": template.get("max_input_tokens") or 1000000,
                    "max_output_tokens": template.get("max_output_tokens") or 131072,
                    "supports_function_calling": True,
                    "supports_reasoning": True,
                }
            )
            litellm.model_cost[or_name] = template

    # OpenCode Go OpenAILikeChatConfig omits reasoning_effort from get_supported_openai_params
    # even for models (like glm-5.3) whose catalog entry explicitly sets supports_reasoning=True.
    try:
        from litellm.llms.opencode.chat.transformation import OpenCodeGoChatConfig
        if not getattr(OpenCodeGoChatConfig, "_strix_acp_reasoning_patched", False):
            orig_supported = OpenCodeGoChatConfig.get_supported_openai_params
            def _patched_supported(self, model: str):
                params = list(orig_supported(self, model))
                info = litellm.model_cost.get(f"opencode_go/{model.removeprefix('opencode_go/')}", {})
                if info.get("supports_reasoning") and "reasoning_effort" not in params:
                    params.append("reasoning_effort")
                return params
            OpenCodeGoChatConfig.get_supported_openai_params = _patched_supported
            OpenCodeGoChatConfig._strix_acp_reasoning_patched = True
    except Exception:
        pass

def _format_preflight_error(model: str, exc: Exception) -> str:
    msg = str(exc)
    if model.startswith("opencode_go/") and (
        "active OpenCode Go subscription is required" in msg or "permission_error" in msg
    ):
        return (
            f"{msg} "
            "(OpenCode Go subscription is inactive on this org/key — activate Go at "
            "https://opencode.ai/console or switch the model to openrouter/z-ai/glm-5.3.)"
        )
    return msg

def configure_model_settings(model_name: str, api_key: str | None, session_id: str | None = None):
    from strix.config import apply_config_override, load_settings
    _patch_litellm_glm53()
    is_opencode_go = model_name.startswith("opencode_go/")
    is_openrouter = model_name.startswith("openrouter/")
    if is_opencode_go or is_openrouter:
        cli_cfg_path = Path(os.environ.get("STRIX_HOME", Path.home() / ".strix")) / "cli-config.json"
        if cli_cfg_path.is_file():
            try:
                env_block = json.loads(cli_cfg_path.read_text(encoding="utf-8")).get("env", {})
                if isinstance(env_block, dict):
                    skip = {
                        "STRIX_LLM",
                        "LLM_API_KEY",
                        "OPENAI_API_KEY",
                        "OPENROUTER_API_KEY",
                        "OPENCODE_GO_API_KEY",
                        "OPENCODE_API_KEY",
                        "LLM_API_BASE",
                        "OPENAI_API_BASE",
                        "OPENAI_BASE_URL",
                        "LITELLM_BASE_URL",
                        "STRIX_API_TYPE",
                        "STRIX_FORCE_API",
                        "LLM_EXTRA_HEADERS",
                    }
                    for k, v in env_block.items():
                        ku = str(k).upper()
                        if ku not in skip and isinstance(v, (str, int, float, bool)):
                            os.environ.setdefault(ku, str(v).lower() if isinstance(v, bool) else str(v))
            except Exception:
                pass
        # Prevent cli-config.json connection settings from leaking across providers.
        apply_config_override(Path("/nonexistent/strix-acp-isolated.json"))

    if is_opencode_go:
        key = (
            api_key
            or os.environ.get("OPENCODE_GO_API_KEY")
            or os.environ.get("OPENCODE_API_KEY")
            or os.environ.get("LLM_API_KEY")
            or ""
        )
        if key:
            os.environ["OPENCODE_GO_API_KEY"] = key
            os.environ["OPENCODE_API_KEY"] = key
            os.environ["LLM_API_KEY"] = key
        # Set LLM_EXTRA_HEADERS in os.environ BEFORE load_settings() so run_strix_scan()
        # also receives x-opencode-session (OpenCode Go requires stable session routing).
        os.environ["LLM_EXTRA_HEADERS"] = json.dumps({"x-opencode-session": session_id or "strix-acp-session"})
    elif is_openrouter:
        key = api_key or os.environ.get("OPENROUTER_API_KEY") or os.environ.get("LLM_API_KEY") or ""
        if key:
            os.environ["OPENROUTER_API_KEY"] = key
            os.environ["LLM_API_KEY"] = key
        os.environ.pop("LLM_EXTRA_HEADERS", None)
    elif api_key:
        os.environ.setdefault("LLM_API_KEY", api_key)

    effort = os.environ.get("STRIX_REASONING_EFFORT", "").strip().lower()
    if is_opencode_go and model_name in ("opencode_go/glm-5.3", "opencode_go/glm-5.3-flash") and effort == "medium":
        # OpenCode Go glm-5.3 supports effort=["low", "high", "max"]
        effort = "high"
        os.environ["STRIX_REASONING_EFFORT"] = effort

    settings = load_settings()
    if model_name:
        settings.llm.model = model_name
    if is_opencode_go:
        settings.llm.api_base = None
        settings.llm.api_type = None
        settings.llm.extra_headers = {"x-opencode-session": session_id or "strix-acp-session"}
    elif is_openrouter:
        settings.llm.api_base = None
        settings.llm.api_type = None
        settings.llm.extra_headers = None
    elif api_key and not settings.llm.api_key:
        settings.llm.api_key = api_key
    if effort:
        settings.llm.reasoning_effort = effort
    return settings

async def do_preflight(args):
    from strix.interface.scan_setup import preflight_model_connection
    settings = configure_model_settings(args.model, args.api_key, args.session_id)
    model = args.model or settings.llm.model or "opencode_go/glm-5.3"
    emit("thought", text=f"Testing Strix LLM preflight for {model}...\n")
    try:
        await preflight_model_connection(model, settings=settings)
    except Exception as exc:
        emit("preflight_result", ok=False, model=model, error=_format_preflight_error(model, exc))
        return 1
    emit("preflight_result", ok=True, model=model)
    return 0

async def do_scan(args):
    from strix.config import load_settings
    from strix.core.runner import run_strix_scan
    from strix.interface.scan_setup import build_targets_info, preflight_model_connection, prepare_run
    from strix.interface.utils import read_workspace_files, resolve_workspace_files
    from strix.report.state import ReportState, set_global_report_state
    from strix.runtime import session_manager

    settings = configure_model_settings(args.model, args.api_key, args.session_id)
    model = args.model or settings.llm.model or "opencode_go/glm-5.3"
    image = (settings.runtime.image or "").strip()
    if not image:
        emit("error", message="strix_image is not configured in ~/.strix/cli-config.json or STRIX_IMAGE.")
        return 1

    if args.resume:
        from strix.interface.cli_args import load_resume_state

        workspace = args.workspace or os.getcwd()
        try:
            os.chdir(os.path.expanduser(workspace))
        except OSError as exc:
            emit("error", message=f"Cannot enter run workspace {workspace}: {exc}")
            return 1
        scan_ns = argparse.Namespace(
            target=[],
            target_list=[],
            instruction=args.instruction or "",
            user_instruction=None,
            user_explicit_instruction=args.instruction or None,
            scan_mode=args.scan_mode,
            scope_mode=args.scope_mode,
            diff_base=None,
            non_interactive=True,
            workspace_files=None,
            workspace_mount=None,
            local_sources=None,
            resume=args.resume,
        )
        try:
            load_resume_state(scan_ns)
        except Exception as exc:
            emit("error", message=f"Cannot resume `{args.resume}`: {exc}")
            return 1
        if args.workspace_file:
            try:
                additions = resolve_workspace_files(args.workspace_file)
            except Exception as exc:
                emit("error", message=f"Cannot stage attached files: {exc}")
                return 1
            merged = list(scan_ns.workspace_files or [])
            taken = {entry.get("workspace_path") for entry in merged}
            for addition in additions:
                if addition["workspace_path"] in taken:
                    emit(
                        "error",
                        message=(
                            "Cannot stage attached files: the run already places a file at "
                            f"`{addition['workspace_path']}`."
                        ),
                    )
                    return 1
                merged.append(addition)
            scan_ns.workspace_files = merged

        resume_text = (args.instruction or "").strip() or DEFAULT_RESUME_INSTRUCTION
        try:
            await deliver_resume_instruction(args.resume, resume_text)
        except Exception as exc:
            emit("error", message=f"Cannot deliver the resume instruction: {exc}")
            return 1
        emit("thought", text="Resume instruction delivered to the root agent.\n")
    else:
        scan_ns = argparse.Namespace(
            target=args.target or [],
            target_list=[],
            instruction=args.instruction or "",
            user_instruction=args.instruction or "",
            scan_mode=args.scan_mode,
            scope_mode=args.scope_mode,
            diff_base=None,
            non_interactive=True,
            workspace_files=None,
            workspace_mount=None,
            resume=None,
        )

        try:
            scan_ns.workspace_files = resolve_workspace_files(args.workspace_file)
        except Exception as exc:
            emit("error", message=f"Cannot stage attached files: {exc}")
            return 1

        try:
            build_targets_info(scan_ns)
        except Exception as exc:
            emit("error", message=f"Failed to prepare Strix targets: {exc}")
            return 1

    emit("thought", text=f"Running preflight check for {model}...\n")
    try:
        await preflight_model_connection(model, settings=settings)
    except Exception as exc:
        emit("error", message=f"Model preflight failed for `{model}`: {_format_preflight_error(model, exc)}")
        return 1

    try:
        prepare_run(scan_ns)
    except Exception as exc:
        verb = "resume" if args.resume else "run"
        emit("error", message=f"Failed to prepare Strix {verb}: {exc}")
        return 1

    scan_config = {
        "scan_id": scan_ns.run_name,
        "targets": scan_ns.targets_info,
        "user_instructions": scan_ns.instruction or "",
        "run_name": scan_ns.run_name,
        "diff_scope": getattr(scan_ns, "diff_scope", {"active": False}),
        "scan_mode": scan_ns.scan_mode,
        "non_interactive": True,
        "local_sources": getattr(scan_ns, "local_sources", None) or [],
        "workspace_files": getattr(scan_ns, "workspace_files", None) or [],
        "workspace_mount": getattr(scan_ns, "workspace_mount", None),
        "scope_mode": scan_ns.scope_mode,
        "diff_base": None,
        # Delivered straight into the root agent's SDK session above; the mailbox
        # copy would never be drained by a headless run.
        "resume_instruction": "",
    }

    report_state = ReportState(scan_ns.run_name)
    report_state.hydrate_from_run_dir()
    report_state.set_scan_config(scan_config)
    report_state.save_run_data()
    set_global_report_state(report_state)

    def on_vuln(report, updated=False):
        emit(
            "vuln",
            updated=updated,
            id=str(report.get("id") or "unknown"),
            title=str(report.get("title") or ""),
            severity=str(report.get("severity") or "info"),
            target=str(report.get("target") or ""),
            endpoint=str(report.get("endpoint") or ""),
            description=str(report.get("description") or ""),
        )

    def on_vuln_deleted(report):
        emit(
            "vuln_deleted",
            id=str(report.get("id") or "unknown"),
            title=str(report.get("title") or ""),
        )

    report_state.vulnerability_found_callback = lambda r: on_vuln(r, updated=False)
    report_state.vulnerability_updated_callback = lambda r: on_vuln(r, updated=True)
    report_state.vulnerability_deleted_callback = on_vuln_deleted

    active_calls = {}

    def event_sink(agent_id: str, event):
        etype = getattr(event, "type", "")
        if etype == "raw_response_event":
            data = getattr(event, "data", None)
            if getattr(data, "type", "") == "response.output_text.delta":
                delta = getattr(data, "delta", "")
                if delta:
                    emit("thought", text=str(delta))
            return
        if etype != "run_item_stream_event":
            return
        item = getattr(event, "item", None)
        itype = getattr(item, "type", "")
        if itype == "tool_call_item":
            raw = getattr(item, "raw_item", None)
            call_id = str((raw.get("call_id") if isinstance(raw, dict) else getattr(raw, "call_id", None)) or (raw.get("id") if isinstance(raw, dict) else getattr(raw, "id", None)) or id(item))
            name = str((raw.get("name") if isinstance(raw, dict) else getattr(raw, "name", None)) or "tool")
            raw_args = raw.get("arguments") if isinstance(raw, dict) else getattr(raw, "arguments", None)
            try:
                parsed_args = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args if isinstance(raw_args, dict) else {})
            except Exception:
                parsed_args = {"raw": str(raw_args)[:500]}
            active_calls[call_id] = name
            emit("tool_start", call_id=f"{agent_id}:{call_id}", name=name, args=parsed_args)
        elif itype == "tool_call_output_item":
            raw = getattr(item, "raw_item", None)
            call_id = str((raw.get("call_id") if isinstance(raw, dict) else getattr(raw, "call_id", None)) or (raw.get("id") if isinstance(raw, dict) else getattr(raw, "id", None)) or id(item))
            output = getattr(item, "output", raw.get("output") if isinstance(raw, dict) else getattr(raw, "output", None))
            emit("tool_end", call_id=f"{agent_id}:{call_id}", output=str(output)[:4000])

    def status_sink(phase: str):
        emit("thought", text=f"[{phase}]\n")

    emit(
        "started",
        run_name=scan_ns.run_name,
        run_dir=str(report_state.get_run_dir()),
        targets=[t["original"] for t in scan_ns.targets_info],
        model=model,
        scan_mode=scan_ns.scan_mode,
        resume=bool(args.resume),
    )

    try:
        await run_strix_scan(
            scan_config=scan_config,
            scan_id=scan_ns.run_name,
            image=image,
            local_sources=getattr(scan_ns, "local_sources", None) or [],
            extra_files=read_workspace_files(getattr(scan_ns, "workspace_files", None)),
            interactive=False,
            model=model,
            event_sink=event_sink,
            status_sink=status_sink,
        )
    except Exception as exc:
        try:
            report_state.cleanup(status="failed")
        except Exception:
            pass
        emit("error", message=f"Strix scan error: {exc}\n{traceback.format_exc()}")
        return 1
    finally:
        with open(os.devnull, "w"):
            pass
        try:
            await session_manager.cleanup(scan_ns.run_name)
        except Exception:
            pass

    usage = report_state.get_total_llm_usage() or {}
    emit(
        "finished",
        run_name=scan_ns.run_name,
        run_dir=str(report_state.get_run_dir()),
        findings=len(report_state.vulnerability_reports),
        final_result=report_state.final_scan_result or "",
        usage=usage,
    )
    return 0

def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    pf = sub.add_parser("preflight")
    pf.add_argument("--model", required=True)
    pf.add_argument("--api-key", default="")
    pf.add_argument("--session-id", default="strix-acp-session")
    sc = sub.add_parser("scan")
    sc.add_argument("--model", required=True)
    sc.add_argument("--api-key", default="")
    sc.add_argument("--session-id", default="strix-acp-session")
    sc.add_argument("--scan-mode", default="deep")
    sc.add_argument("--scope-mode", default="auto")
    sc.add_argument("--target", action="append", default=[])
    sc.add_argument("--workspace-file", action="append", default=[])
    sc.add_argument("--instruction", default="")
    sc.add_argument("--resume", default="")
    sc.add_argument("--workspace", default="")
    args = parser.parse_args()
    if args.cmd == "preflight":
        raise SystemExit(asyncio.run(do_preflight(args)))
    raise SystemExit(asyncio.run(do_scan(args)))

if __name__ == "__main__":
    main()
