#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"

LOG="${MSN_SERVER_LOG:-/tmp/msn_server.log}"
PID_FILE="${MSN_SERVER_PID:-/tmp/msn_server.pid}"
PORT="${MSN_SERVER_PORT:-2323}"

is_alive() {
    [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

cmd_start() {
    if is_alive; then
        echo "already running pid=$(cat "$PID_FILE") log=$LOG"
        return 0
    fi
    rm -f "$PID_FILE"
    cd "$REPO_DIR"
    MSN_LOG_LEVEL="${MSN_LOG_LEVEL:-INFO}" nohup uv run python -u -m server \
        > "$LOG" 2>&1 &
    local pid=$!
    echo "$pid" > "$PID_FILE"
    sleep 1
    if kill -0 "$pid" 2>/dev/null; then
        echo "started pid=$pid log=$LOG level=${MSN_LOG_LEVEL:-INFO}"
    else
        rm -f "$PID_FILE"
        echo "FAILED to start — last 20 log lines:"
        tail -n 20 "$LOG" 2>/dev/null || true
        return 1
    fi
}

cmd_stop() {
    if [[ -f "$PID_FILE" ]]; then
        local pid
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            for _ in 1 2 3 4 5; do
                kill -0 "$pid" 2>/dev/null || break
                sleep 0.2
            done
            kill -9 "$pid" 2>/dev/null || true
        fi
        rm -f "$PID_FILE"
    fi
    fuser -k "${PORT}/tcp" 2>/dev/null || true
    echo "stopped"
}

cmd_restart() {
    cmd_stop
    cmd_start
}

cmd_status() {
    if is_alive; then
        echo "running pid=$(cat "$PID_FILE")"
    else
        echo "not running"
    fi
    echo "--- port ${PORT} ---"
    ss -ltnp 2>/dev/null | grep ":${PORT} " || echo "(port ${PORT} not bound)"
    echo "--- last 5 log lines ($LOG) ---"
    tail -n 5 "$LOG" 2>/dev/null || echo "(no log yet)"
}

cmd_logs() {
    local n="${1:-50}"
    tail -n "$n" "$LOG"
}

cmd_monitor_cmd() {
    echo "tail -n 0 -F $LOG | grep -E --line-buffered 'get_shabby|get_properties|svc_request|Traceback|Error'"
}

usage() {
    cat <<EOF
usage: msn-server.sh {start|stop|restart|status|logs [N]|monitor-cmd}

  start        launch 'uv run python -u -m server', log -> $LOG, pid -> $PID_FILE
  stop         SIGTERM (graceful) then SIGKILL; also fuser -k ${PORT}/tcp
  restart      stop + start
  status       pid, port ${PORT} listener, last 5 log lines
  logs [N]     tail last N lines (default 50)
  monitor-cmd  print the canonical tail|grep string for the Monitor tool

env overrides: MSN_LOG_LEVEL, MSN_SERVER_LOG, MSN_SERVER_PID, MSN_SERVER_PORT
EOF
}

case "${1:-}" in
    start)        cmd_start ;;
    stop)         cmd_stop ;;
    restart)      cmd_restart ;;
    status)       cmd_status ;;
    logs)         shift; cmd_logs "$@" ;;
    monitor-cmd)  cmd_monitor_cmd ;;
    ""|-h|--help|help) usage ;;
    *)            usage; exit 2 ;;
esac
