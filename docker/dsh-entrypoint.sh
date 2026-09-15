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

# 叠加层：接入统一工具镜像的 MCP server（覆盖 dsh-mcp-studio 配置）
if [ -f /opt/dsh-redteam/fusionweb-mcp.patch.yml ]; then
  set -- --patch /opt/dsh-redteam/fusionweb-mcp.patch.yml web --host 127.0.0.1 --port "$inner_port" --no-open
else
  set -- web --host 127.0.0.1 --port "$inner_port" --no-open
fi

# 允许外部浏览器地址访问 DSH 的 /api（host 或 host:port，空格分隔）
for host in ${DSH_TRUSTED_HOSTS:-}; do
  set -- "$@" --trusted-host "$host"
done

echo "DSH starting: dsh $*"

# ── 安装 FusionWeb 内置插件（fusionweb-tools / fusionweb-approval） ────
# 直接放入 profile 的 node_modules 并登记到 bundle 列表，无需 pnpm、无需联网。
# web profile 供界面使用；headless profile 供桥（钉钉消息转 DSH 任务）使用。
FUSIONWEB_PLUGINS="${FUSIONWEB_PLUGINS:-fusionweb-tools fusionweb-approval}"

install_fusionweb_plugins() {
  for plugin in $FUSIONWEB_PLUGINS; do
    [ -d "/opt/$plugin" ] || continue
    for profile_name in web headless; do
      profile_dir="${DSH_HOME:-/root/.dsh}/profiles/${profile_name}"
      if [ ! -d "$profile_dir" ]; then
        dsh --profile "$profile_name" --dump-config >/dev/null 2>&1 || true
      fi
      if [ ! -d "$profile_dir" ]; then
        echo "WARN: 未找到 DSH profile（$profile_dir），跳过 $plugin 安装" >&2
        continue
      fi
      mkdir -p "$profile_dir/node_modules/$plugin"
      cp -r "/opt/$plugin/." "$profile_dir/node_modules/$plugin/" 2>/dev/null || true
      node /usr/local/bin/dsh-ensure-bundle.mjs "$profile_dir/package.json" "$plugin" "/opt/$plugin" || true
    done
  done
}
install_fusionweb_plugins

# ── 注册 dsh-redteam-model（红队十模式 + 插件，已 vendor 进镜像） ────────
# 幂等：模式目录用符号链接接入发现路径；插件以符号链接挂进各 profile 的 node_modules
# 并登记到 bundle 列表（等价于 dsh plugin add，但离线、无需 pnpm）。
install_redteam() {
  [ -d /opt/dsh-redteam ] || return 0
  dsh_home="${DSH_HOME:-/root/.dsh}"

  # ① 模式发现：$DSH_HOME/.agent-presets 指向 modes/（DSH 只扫其直接子目录）
  presets="$dsh_home/.agent-presets"
  if [ ! -e "$presets" ]; then
    ln -sfn /opt/dsh-redteam/modes "$presets" 2>/dev/null || cp -r /opt/dsh-redteam/modes "$presets"
    echo "已接入红队模式目录：$presets -> /opt/dsh-redteam/modes"
  fi

  # ② 全局指令文件（DSH 原生机制，对所有会话生效；已存在则不覆盖）
  if [ ! -f "$dsh_home/AGENTS.md" ] && [ -f /opt/dsh-redteam/AGENTS.md ]; then
    cp /opt/dsh-redteam/AGENTS.md "$dsh_home/AGENTS.md"
    echo "已写入 DSH 全局指令：$dsh_home/AGENTS.md"
  fi

  # ③ 各 profile 挂载管理器包与选定的运行时插件
  for profile_name in web headless; do
    profile_dir="$dsh_home/profiles/$profile_name"
    if [ ! -d "$profile_dir" ]; then
      dsh --profile "$profile_name" --dump-config >/dev/null 2>&1 || true
    fi
    [ -d "$profile_dir" ] || continue

    mkdir -p "$profile_dir/node_modules/@dsh-external"
    ln -sfn /opt/dsh-redteam "$profile_dir/node_modules/@dsh-external/dsh-redteam-model"
    node /usr/local/bin/dsh-ensure-bundle.mjs "$profile_dir/package.json" "@dsh-external/dsh-redteam-model" || true

    for plugin in ${DSH_REDTEAM_PLUGINS:-}; do
      [ -d "/opt/dsh-redteam/plugins/$plugin" ] || continue
      ln -sfn "/opt/dsh-redteam/plugins/$plugin" "$profile_dir/node_modules/@dsh-external/$plugin"
      node /usr/local/bin/dsh-ensure-bundle.mjs "$profile_dir/package.json" "@dsh-external/$plugin" || true
    done
    echo "红队插件已登记到 profile: $profile_name"
  done
}
install_redteam

# ── 启动 DSH 桥（把钉钉消息转成 DSH 任务，并把结果推回钉钉） ───────────
node /usr/local/bin/dsh-bridge.mjs &
bridge_pid=$!

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
while kill -0 "$dsh_pid" 2>/dev/null && kill -0 "$proxy_pid" 2>/dev/null && kill -0 "$bridge_pid" 2>/dev/null; do
  sleep 2
done

echo "DSH process exited; shutting down container"
kill "$dsh_pid" "$proxy_pid" "$bridge_pid" "$tail_pid" 2>/dev/null || true
wait "$dsh_pid" 2>/dev/null || true
exit 1
