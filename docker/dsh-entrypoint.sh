#!/bin/sh
# DSH 启动入口。
#
# 约束（实测）：
#   - dsh web 的 --host 只接受 127.0.0.1（CLI 又拒绝 0.0.0.0）；
#   - Web 访问需要一次性 boot token（带 token 才会种下 dsh-auth-* cookie）。
# 因此：DSH 绑回环端口 → 容器内 TCP 转发对外暴露 → 转发器用 boot token 做首次访问引导。
set -eu

public_port="${DSH_PORT:-8990}"
inner_port="${DSH_INNER_PORT:-8991}"
log_file="/tmp/dsh-web.log"

set -- web --host 127.0.0.1 --port "$inner_port" --no-open

# 允许外部浏览器地址访问 DSH 的 /api（host 或 host:port，空格分隔）
for host in ${DSH_TRUSTED_HOSTS:-}; do
  set -- "$@" --trusted-host "$host"
done

echo "DSH starting: dsh $*"
: >"$log_file"
dsh "$@" >"$log_file" 2>&1 &
dsh_pid=$!

# 把 DSH 日志转发到容器 stdout
tail -n +1 -f "$log_file" &
tail_pid=$!

# 等待并提取 boot token（最多 60 秒）
boot_token=""
i=0
while [ "$i" -lt 60 ]; do
  boot_token="$(grep -o 'token=[A-Za-z0-9_-]*' "$log_file" 2>/dev/null | head -n1 | cut -d= -f2 || true)"
  [ -n "$boot_token" ] && break
  kill -0 "$dsh_pid" 2>/dev/null || break
  i=$((i + 1))
  sleep 1
done
if [ -n "$boot_token" ]; then
  echo "DSH boot token captured (len=${#boot_token})"
else
  echo "WARN: 未捕获到 DSH boot token，首次访问引导将被跳过" >&2
fi

export DSH_PORT="$public_port"
export DSH_INNER_PORT="$inner_port"
export DSH_BOOT_TOKEN="$boot_token"
node /usr/local/bin/dsh-proxy.mjs &
proxy_pid=$!

# 任一进程退出即结束容器
while kill -0 "$dsh_pid" 2>/dev/null && kill -0 "$proxy_pid" 2>/dev/null; do
  sleep 2
done

echo "DSH process exited; shutting down container"
kill "$dsh_pid" "$proxy_pid" "$tail_pid" 2>/dev/null || true
wait "$dsh_pid" 2>/dev/null || true
exit 1
