---
name: manage-server
description: Control the MSN server process lifecycle — start, stop, restart, check status, tail logs, or arm a Monitor for protocol events. Use when the user asks to start/stop/restart the server, says the server is down or broken, wants to see server logs, or after edits under src/server/** that need a restart to take effect.
version: 1.0.0
---

# manage-server

Wraps the MSN server (`src/server/`) lifecycle. The script is the source of truth; this file exists to tell you when to call it.

## When to use

- User asks to start, stop, or restart the server.
- User asks "is the server running?", "check the server", "server is down", "why isn't the server responding?".
- User wants to see server logs or tail them.
- You just finished editing something under `src/server/` that affects runtime — restart without asking and report the new PID.
- `[Errno 98] Address already in use` on port 2323 — `stop` already runs `fuser -k 2323/tcp`, so just `stop` then `start` (or `restart`).

## Commands

Run from anywhere — the script resolves the repo root from its own location.

```
.claude/skills/manage-server/scripts/msn-server.sh {start|stop|restart|status|logs [N]|monitor-cmd}
```

- `start` — idempotent. If already running, prints the existing PID and exits 0. Launches `MSN_LOG_LEVEL=INFO uv run python -u -m server`, redirects stdout+stderr to `/tmp/msn_server.log`, stashes PID in `/tmp/msn_server.pid`. Verifies the process is alive before returning.
- `stop` — SIGTERM with 1s graceful window → SIGKILL → `fuser -k 2323/tcp` as safety net → clear pidfile. Safe to call when nothing is running.
- `restart` — `stop` then `start`. Use this after edits to `src/server/`.
- `status` — prints PID (or "not running"), the `ss` line for port 2323, and the last 5 log lines.
- `logs [N]` — `tail -n N /tmp/msn_server.log` (default 50).
- `monitor-cmd` — prints the canonical `tail | grep` recipe for the `Monitor` tool. Don't run it directly; feed it into a `Monitor` call.

Env overrides (rarely needed): `MSN_LOG_LEVEL` (e.g. `TRACE`, `DEBUG`), `MSN_SERVER_LOG`, `MSN_SERVER_PID`, `MSN_SERVER_PORT`.

## After editing src/server/

Restart without asking. Report the new PID from `start`'s output so the user can confirm the change landed:

```
.claude/skills/manage-server/scripts/msn-server.sh restart
```

## Waiting on protocol events

Don't tail-and-poll. Arm a persistent Monitor:

1. `.claude/skills/manage-server/scripts/msn-server.sh monitor-cmd` → prints the command string.
2. Pass it to the `Monitor` tool with `persistent: true`. The grep already includes `Traceback|Error` so a crash surfaces instead of looking like idle silence.

## Troubleshooting

- **Log shows only the `listen` line but `ss` shows real connections** → wrong launch path. The script always uses `uv run python -u -m server` (module `server`, not `src.server`); if you bypassed the script and launched some other way, that's the cause. Stop whatever you started and use `restart`.
- **`start` returns FAILED with a traceback** → it already tailed the last 20 log lines. Read those, fix the cause, re-run `start`. Don't loop.
- **Server restart ≠ VM/SoftICE restart** — the server is a Linux process; VM state (BPs, context) is untouched. Never re-ADDR or re-arm BPs just because you restarted the server.

## Don't

- Don't launch the server with `python -m src.server`, or without `-u`, or without the `/tmp/msn_server.log` redirect. The grep recipes and monitor command assume that exact path.
- Don't ask the user to start/stop/restart — do it yourself with the script.
