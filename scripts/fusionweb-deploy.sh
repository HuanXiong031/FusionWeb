#!/usr/bin/env bash
#
# FusionWeb 一条命令部署：拉镜像 → 重启服务 → 修好 self-scan 规则。
#
# 为什么需要它：容器重建后 web 容器 IP 会变化，宿主的 hairpin DNAT 规则会失效，
# 导致「扫描容器扫不到宿主映射端口（8988/8756/8990）」。把这一步固化进部署流程，
# 避免每次手工补跑。
#
# 用法：
#   ./scripts/fusionweb-deploy.sh                 # 默认部署目录 /root/FusionWeb-test-20260828
#   DEPLOY_DIR=/path/to/stack ./scripts/fusionweb-deploy.sh
#   SKIP_PULL=1 ./scripts/fusionweb-deploy.sh     # 只重启与修规则
set -euo pipefail

DEPLOY_DIR="${DEPLOY_DIR:-/root/FusionWeb-test-20260828}"
SKIP_PULL="${SKIP_PULL:-0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f "$DEPLOY_DIR/docker-compose.yaml" ]; then
  echo "未找到部署目录（$DEPLOY_DIR/docker-compose.yaml）" >&2
  exit 1
fi

cd "$DEPLOY_DIR"

VERSION="$(grep -E '^FUSIONWEB_VERSION=' .env 2>/dev/null | cut -d= -f2- | tr -d "\"'" || true)"
echo "部署目录：$DEPLOY_DIR${VERSION:+（版本 $VERSION）}"

if [ "$SKIP_PULL" != "1" ]; then
  echo "── 拉取镜像 ──"
  docker compose pull
fi

echo "── 启动/更新服务 ──"
docker compose up -d --remove-orphans

echo "── 修复 self-scan 规则（容器重建后宿主映射端口规则会失效）──"
if [ -x "$SCRIPT_DIR/fusionweb-enable-self-scan.sh" ]; then
  "$SCRIPT_DIR/fusionweb-enable-self-scan.sh" || echo "WARN: self-scan 规则应用失败（如需扫描宿主映射端口请手工检查）" >&2
else
  echo "WARN: 未找到 fusionweb-enable-self-scan.sh，跳过" >&2
fi

echo "── 容器状态 ──"
docker compose ps --format 'table {{.Name}}\t{{.Status}}' 2>/dev/null || docker ps --format 'table {{.Names}}\t{{.Status}}'

echo "完成。"
