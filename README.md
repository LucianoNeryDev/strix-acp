# strix-acp

An [Agent Client Protocol](https://agentclientprotocol.com) server for
[Strix](https://github.com/usestrix/strix), the autonomous penetration-testing
agent. It lets any ACP editor — T3 Code, Zed, JetBrains, or your own client —
run a scan, continue it, and read findings as they land, instead of dropping to
a terminal.

Strix ships a TUI and a headless CLI, but no ACP entry point, so this project is
the bridge. It is a single JSON-RPC process over stdio, with no dependencies of
its own: everything that touches a target runs inside Strix's own Docker
sandbox.

## What it exposes

| Prompt | What happens |
| --- | --- |
| `https://example.com` | Fresh scan of that target |
| `/scan <target> [instructions]`, `/quick`, `/standard`, `/deep` | Fresh scan with that mode |
| any prompt with no target | Continues the session's current run |
| a prompt naming the run's own target or another host on that site | Continues that run, prompt kept as written |
| a prompt naming the run's target and another site | Continues the run and hands the other site to the agent as added scope |
| a new thread or fork in a workspace that has runs | Inherits the newest run, so follow-up prompts continue it |
| `/resume [run\|path] [instruction]` | Continues a named run, a run directory, or the workspace's newest |
| `/new <target> [instructions]` | Forces a fresh run |
| `/runs` | Lists runs under the workspace, with finding counts |
| `/preflight [model]` | Checks model connectivity before a long scan |

Continuation uses Strix's own run state (`strix_runs/<run>/.state/`: `agents.json`,
`agents.db`, notes, todos, coverage). A resumed run keeps its name, its authorized
targets and its findings; new findings are added to the same report rather than
forking a new directory.

Model picker, reasoning effort, scan mode and scope mode are exposed as ACP config
options, so the client's model/options UI drives them.

## Requirements

- Strix installed (`uv tool install strix-agent`, or the release binary) and its
  Docker sandbox working: `strix --target ...` must run on its own first.
- A model and API key configured for Strix (`~/.strix/cli-config.json`, or the
  env file below).
- Python 3.11+ for the adapter itself.

## Install

```bash
uv tool install git+https://git.lucianonery.dev/LucianoNeryDev/strix-acp
# or from a checkout
uv tool install --editable .
```

Then point your ACP client at `strix-acp`. For T3 Code, add a provider instance
in `~/.t3/userdata/settings.json`:

```json
{
  "providerInstances": {
    "strix": {
      "driver": "acpRegistry",
      "displayName": "Strix",
      "enabled": true,
      "config": { "source": "local", "commandPath": "/home/you/.local/bin/strix-acp" }
    }
  }
}
```

Any ACP client that launches a command and speaks v1 works the same way.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `STRIX_PYTHON` | uv tool venv, else the `strix` shebang | Interpreter that has `strix` importable; the worker runs under it |
| `STRIX_BIN` | `strix` on `PATH` | Used to discover that interpreter |
| `STRIX_ACP_STATE` | `$XDG_STATE_HOME/strix-acp/sessions` | Where per-session state is kept (mode 0600) |
| `STRIX_OPENCODE_GO_ENV` | `$XDG_CONFIG_HOME/strix-acp/opencode-go.env` | Env file holding `OPENCODE_GO_API_KEY` |
| `STRIX_OPENROUTER_ENV` | `$XDG_CONFIG_HOME/strix-acp/openrouter.env` | Env file holding `OPENROUTER_API_KEY` |

The model catalog (OpenCode Go and OpenRouter entries) lives in
`src/strix_acp/server.py`; add your own IDs there or select a model from the
client's list.

## How continuation works

Strix's own `--resume` restores a run from `strix_runs/<run>/.state/`, but its
`resume_instruction` travels through the coordinator mailbox and only the
*interactive* loop drains a mailbox — a headless resume replays the history and
never sees the new prompt. This adapter therefore appends the prompt to the root
agent's SDK session (`agents.db`) before the scan starts, which is the same write
the interactive path performs.

For the same reason the adapter persists a small per-session state file, so a
client that restarts and reopens a thread (`session/resume`) can rebuild the
session and keep working on the same run. A session with no state file adopts the
newest run in its workspace, targets included; so does a brand-new session, which
is what makes a forked thread continue its parent's run instead of rescanning
from zero.

Continuity is decided by site, not by string equality: `api.example.com`,
`https://example.com/login` and `example.com:8443` all belong to a run on
`example.com`. When a prompt names both that site and an unrelated host, the run
continues and the unrelated host is delivered to the agent as additional
authorized scope. Only a prompt whose targets share no site with the run — or an
explicit `/scan`, `/quick`, `/standard`, `/deep`, `/new` — starts a fresh run.

## Security notes

- This is a tool for authorized testing. Strix only scans targets you own or are
  permitted to test; the adapter adds no scope of its own.
- Credentials never pass through this process: the key file is read by the
  worker, and the adapter passes the key to the worker through its environment,
  not through argv.
- Per-session state contains working directories, run names and targets — no
  tokens. It is written mode 0600.
- A resumed run's prompt is written into that run's agent session, which is
  durable: the prompt becomes part of the run's history.

## Development

```bash
python -m unittest discover -s tests -v
```

The tests use a fake Strix interpreter (`STRIX_PYTHON`), so they need no Docker,
no model and no network beyond localhost. The two tests that run Strix's own
code (a preflight against a mock OpenCode Go endpoint, and resume delivery into
a real SDK session) are skipped unless Strix's Python is installed; point
`STRIX_PYTHON_REAL` at it if it is not under `~/.local/share/uv/tools/strix-agent`.

## License

MIT. If you use it, a credit to [Luciano Nery](https://lucianonery.dev) is
appreciated.
