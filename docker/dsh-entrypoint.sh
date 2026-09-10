#!/bin/sh
# DSH 启动入口：把 Web UI 绑到本容器 IP（dsh 拒绝 --host 0.0.0.0），
# 并通过 --trusted-host 允许浏览器用容器外的地址访问其 /api。
set -eu

port="${DSH_PORT:-8990}"

# 容器自身 IP（dsh web 不支持 0.0.0.0，必须绑具体地址）
bind_host="${DSH_BIND_HOST:-}"
if [ -z "$bind_host" ]; then
  bind_host="$(hostname -i 2>/dev/null | awk '{print $1}')"
fi
if [ -z "$bind_host" ]; then
  bind_host="$(getent hosts "$(hostname)" 2>/dev/null | awk '{print $1}' | head -n1)"
fi
if [ -z "$bind_host" ]; then
  bind_host="127.0.0.1"
fi

set -- web --host "$bind_host" --port "$port" --no-open

# 允许外部浏览器地址访问 DSH 的 /api（host 或 host:port，空格分隔）
for host in ${DSH_TRUSTED_HOSTS:-}; do
  set -- "$@" --trusted-host "$host"
done

echo "DSH starting: dsh $*"
exec dsh "$@"
