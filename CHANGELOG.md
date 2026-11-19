# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Forgejo Actions workflow that runs the test suite on Python 3.11 and 3.13 and
  builds the wheel.
- Tests for adapter behaviours that were only covered in the original harness.
- Files attached to a prompt are staged in the sandbox workspace with
  `--workspace-file` and named in the instruction, on a fresh run and on a
  resume.

### Fixed

- A local file was turned into a scan target, which Strix rejects with `Path
  exists but is not a directory` before the scan starts. Existing non-spec files
  are now context, and an explicit `-t` on one returns an actionable error.
- A `docker info` probe that times out or cannot be executed is reported as a
  message instead of failing the prompt with an internal error. The probe now
  allows 30 seconds, and `STRIX_DOCKER_PROBE_TIMEOUT` overrides it.

## [1.9.0] - 2026-11-19

First release: an [Agent Client Protocol](https://agentclientprotocol.com) server
for [Strix](https://github.com/usestrix/strix), so ACP editors can run a scan,
continue it and read findings as they land.

### Added

- Single JSON-RPC process over stdio with no dependencies of its own; everything
  that touches a target runs inside Strix's Docker sandbox.
- Prompt handling: a bare target URL starts a fresh scan, `/scan`, `/quick`,
  `/standard` and `/deep` start a scan in that mode, `/new` forces a fresh run,
  and a prompt with no target continues the session's current run.
- `/resume` continues a named run, a run directory or the workspace's newest run,
  keeping its name, authorized targets and findings; new findings are added to
  the same report.
- Continuation delivered into the root agent's SDK session before the scan
  starts, so a headless resume sees the new prompt.
- `/runs` to list the runs under the workspace with finding counts, and
  `/preflight [model]` to check model connectivity before a long scan.
- Per-session state files (mode 0600) so a client that restarts can reopen a
  thread with `session/resume` and keep working on the same run.
- Model picker, reasoning effort, scan mode and scope mode exposed as ACP config
  options, with an OpenCode Go and OpenRouter model catalog.
- Configuration through `STRIX_PYTHON`, `STRIX_BIN`, `STRIX_ACP_STATE`,
  `STRIX_OPENCODE_GO_ENV` and `STRIX_OPENROUTER_ENV`; API keys are passed to the
  worker through its environment, never through argv.
- `strix-acp --version`, and a test suite built on a fake Strix interpreter that
  needs no Docker, model or network.
