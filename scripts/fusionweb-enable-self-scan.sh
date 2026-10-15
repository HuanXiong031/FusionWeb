#!/usr/bin/env bash
#
# 让 FusionWeb 的扫描容器能够扫到「宿主上由 Docker 映射出去的端口」（如 8988 / 8990）。
#
# 问题背景
#   Docker 为端口映射生成的 DNAT 规则带 `! -i <网桥>` 条件，明确排除来自同一网桥的流量：
#       -A DOCKER ! -i br-xxxxxxxx -p tcp --dport 8988 -j DNAT --to-destination 172.20.0.8:80
#   而扫描容器（worker）就在这条网桥上，于是它访问「宿主IP:映射端口」时不会命中 DNAT，
#   数据包被投递到宿主本机（那里并没有监听）→ 端口扫描结果永远是 0。
#
# 解决方式
#   在同一网桥上补两条规则，模拟标准 hairpin NAT：
#     1) DNAT：宿主IP:宿主端口 → 目标容器IP:容器端口
#     2) SNAT：把该流量的源伪装成网桥网关 IP，使目标容器的回包经宿主 conntrack 正确回转
#   （只加 DNAT 不够：回包源 IP 与客户端期望的对端不匹配，会被内核 RST 掉。）
#
# 用法
#   sudo ./scripts/fusionweb-enable-self-scan.sh              # 应用（幂等，可重复执行）
#   sudo ./scripts/fusionweb-enable-self-scan.sh --remove     # 移除本脚本添加的规则
#   sudo ./scripts/fusionweb-enable-self-scan.sh --dry-run    # 只打印将要执行的命令
#
# 可选环境变量
#   FUSIONWEB_NETWORK   指定 Docker 网络名（默认自动选取名字含 fusionweb 的网络）
#   IPTABLES            指定 iptables 命令（默认 iptables）
#
# 注意：Docker 重启/宿主重启后规则会丢失，需重新执行；仓库内提供了 systemd 单元模板
#      （scripts/fusionweb-self-scan.service）用于开机自动应用。
set -euo pipefail

MODE="apply"
case "${1:-}" in
  --remove) MODE="remove" ;;
  --dry-run) MODE="dry-run" ;;
  "" ) ;;
  *) echo "未知参数：$1（可用：--remove / --dry-run）" >&2; exit 2 ;;
esac

IPT="${IPTABLES:-iptables}"
DRY=""
[ "$MODE" = "dry-run" ] && DRY="echo [dry-run]"

log() { printf '%s\n' "$*"; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "缺少命令：$1" >&2; exit 1; }
}
need_cmd docker

if [ "$MODE" != "dry-run" ] && [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 执行（需要修改 iptables）：sudo $0 ${1:-}" >&2
  exit 1
fi

# ── 选定 Docker 网络 ───────────────────────────────────────────────────
find_network() {
  if [ -n "${FUSIONWEB_NETWORK:-}" ]; then
    echo "$FUSIONWEB_NETWORK"
    return
  fi
  local name
  name="$(docker network ls --format '{{.Name}}' | grep -i 'fusionweb' | head -n1 || true)"
  if [ -z "$name" ]; then
    echo "未找到名字含 fusionweb 的 Docker 网络，请用 FUSIONWEB_NETWORK 指定" >&2
    exit 1
  fi
  echo "$name"
}

NET="$(find_network)"
NET_ID="$(docker network inspect "$NET" --format '{{.Id}}')"
BRIDGE="br-$(printf '%s' "$NET_ID" | cut -c1-12)"

read -r SUBNET GATEWAY <<<"$(docker network inspect "$NET" --format '{{range .IPAM.Config}}{{.Subnet}} {{.Gateway}}{{end}}')"
if [ -z "$SUBNET" ] || [ -z "$GATEWAY" ]; then
  echo "无法从网络 $NET 解析子网/网关，跳过" >&2
  exit 1
fi

log "网络: $NET（网桥 $BRIDGE，子网 $SUBNET，网关 $GATEWAY）"

# ── 逐个容器处理已映射端口 ─────────────────────────────────────────────
# 输出格式：<容器名>\t<宿主机端口>\t<容器IP>\t<容器端口>
collect_mappings() {
  # 注意：同一映射会有 IPv4(0.0.0.0) 与 IPv6([::]) 两条绑定，这里统一去重
  local cid name ip
  {
  for cid in $(docker network inspect "$NET" --format '{{range $id, $c := .Containers}}{{$id}} {{end}}'); do
    name="$(docker inspect "$cid" --format '{{.Name}}' | sed 's#^/##')"
    ip="$(docker inspect "$cid" --format "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}")"
    [ -z "$ip" ] && continue
    # 每个「容器端口 ↔ 宿主端口」组合输出一行（同一容器端口可能映射到多个宿主端口）
    docker inspect "$cid" --format '{{range $p, $b := .NetworkSettings.Ports}}{{if $b}}{{range $b}}{{$p}} {{.HostPort}}{{"\n"}}{{end}}{{end}}{{end}}' |
      while read -r cport hostport; do
        [ -z "$cport" ] && continue
        [ -z "${hostport:-}" ] && continue
        printf '%s\t%s\t%s\t%s\n' "$name" "$hostport" "${cport%%/*}" "$ip"
      done
  done
  } | sort -u
}

rule_exists() { $IPT -t nat -C "$@" 2>/dev/null; }

apply_one() {
  local name="$1" hostport="$2" cport="$3" ip="$4"
  local dnat=(DOCKER -i "$BRIDGE" -p tcp -m tcp --dport "$hostport" -j DNAT --to-destination "${ip}:${cport}")
  local snat=(POSTROUTING -s "$SUBNET" -d "$ip" -p tcp -m tcp --dport "$cport" -j SNAT --to-source "$GATEWAY")

  if rule_exists "${dnat[@]}"; then
    log "  [已存在] DNAT $hostport -> $ip:$cport（$name）"
  else
    $DRY $IPT -t nat -I DOCKER 1 -i "$BRIDGE" -p tcp -m tcp --dport "$hostport" -j DNAT --to-destination "${ip}:${cport}"
    log "  [新增]   DNAT $hostport -> $ip:$cport（$name）"
  fi

  if rule_exists "${snat[@]}"; then
    log "  [已存在] SNAT 源伪装 $SUBNET -> $ip:$cport"
  else
    $DRY $IPT -t nat -I POSTROUTING 1 -s "$SUBNET" -d "$ip" -p tcp -m tcp --dport "$cport" -j SNAT --to-source "$GATEWAY"
    log "  [新增]   SNAT 源伪装 $SUBNET -> $ip:$cport"
  fi
}

remove_one() {
  local name="$1" hostport="$2" cport="$3" ip="$4"
  while $IPT -t nat -C DOCKER -i "$BRIDGE" -p tcp -m tcp --dport "$hostport" -j DNAT --to-destination "${ip}:${cport}" 2>/dev/null; do
    $DRY $IPT -t nat -D DOCKER -i "$BRIDGE" -p tcp -m tcp --dport "$hostport" -j DNAT --to-destination "${ip}:${cport}"
    log "  [移除] DNAT $hostport -> $ip:$cport（$name）"
  done
  while $IPT -t nat -C POSTROUTING -s "$SUBNET" -d "$ip" -p tcp -m tcp --dport "$cport" -j SNAT --to-source "$GATEWAY" 2>/dev/null; do
    $DRY $IPT -t nat -D POSTROUTING -s "$SUBNET" -d "$ip" -p tcp -m tcp --dport "$cport" -j SNAT --to-source "$GATEWAY"
    log "  [移除] SNAT 源伪装 $SUBNET -> $ip:$cport"
  done
}

# 应用前先清掉本网桥上的旧 self-scan 规则（容器重建后 IP 可能变化、Docker 也可能重建链），
# 避免残留指向已失效 IP 的规则。
purge_stale() {
  local spec removed=0
  while spec=$($IPT -t nat -S DOCKER 2>/dev/null | grep -m1 -- "-A DOCKER -i $BRIDGE "); do
    $DRY $IPT -t nat -D DOCKER ${spec#-A DOCKER }
    removed=$((removed + 1))
  done
  while spec=$($IPT -t nat -S POSTROUTING 2>/dev/null | grep -m1 -- "-A POSTROUTING .*-j SNAT --to-source $GATEWAY"); do
    $DRY $IPT -t nat -D POSTROUTING ${spec#-A POSTROUTING }
    removed=$((removed + 1))
  done
  [ "$removed" -gt 0 ] && log "  [清理] 移除 $removed 条旧的 self-scan 规则"
}

if [ "$MODE" = "apply" ]; then
  purge_stale
fi

count=0
while IFS=$'\t' read -r name hostport cport ip; do
  [ -z "${name:-}" ] && continue
  count=$((count + 1))
  if [ "$MODE" = "remove" ]; then
    remove_one "$name" "$hostport" "$cport" "$ip"
  else
    apply_one "$name" "$hostport" "$cport" "$ip"
  fi
done < <(collect_mappings)

if [ "$count" -eq 0 ]; then
  log "没有发现任何端口映射（容器未在 $NET 上发布端口？）"
elif [ "$MODE" = "remove" ]; then
  log "完成：已移除 self-scan 规则（共处理 $count 个映射）"
else
  log "完成：已为 $count 个端口映射启用 self-scan（扫描容器现在可以扫到宿主映射端口）"
  log "提示：Docker/宿主重启后需重新执行本脚本；可安装 scripts/fusionweb-self-scan.service 开机自动应用。"
fi
