#!/bin/sh
# toolkit 入口：同时启动「执行 API」（给 FusionWeb worker）与「MCP server」（给 DSH）。
set -eu

workspace="${TOOLKIT_WORKSPACE:-/workspace}"
mkdir -p "$workspace" "$(dirname "${TOOLKIT_AUDIT_LOG:-/var/log/toolkit/audit.jsonl}")"

echo "toolkit 启动：workspace=$workspace exec=:${TOOLKIT_EXEC_PORT:-7001} mcp=:${TOOLKIT_MCP_PORT:-7000}"

python3 /opt/toolkit/exec_server.py &
exec_pid=$!

python3 /opt/toolkit/mcp_server.py &
mcp_pid=$!

# 任一进程退出即结束容器
while kill -0 "$exec_pid" 2>/dev/null && kill -0 "$mcp_pid" 2>/dev/null; do
  sleep 2
done

echo "toolkit 进程退出，关闭容器" >&2
kill "$exec_pid" "$mcp_pid" 2>/dev/null || true
wait "$exec_pid" 2>/dev/null || true
exit 1
