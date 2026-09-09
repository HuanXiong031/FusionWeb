#!/usr/bin/env bash
set -u

SCRIPT_VERSION="2.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yaml"
REMOTE_ACCESS_FILE="${SCRIPT_DIR}/docker-compose.remote-access.yaml"
ENV_FILE="${SCRIPT_DIR}/.env"
ENV_EXAMPLE="${SCRIPT_DIR}/.env.example"
VERSION_FILE="${SCRIPT_DIR}/VERSION"
CONTAINERS=(fusionweb_postgres fusionweb_redis fusionweb_minio fusionweb_api fusionweb_web fusionweb_worker)

cd "${SCRIPT_DIR}" || exit 1

if [[ -t 1 ]]; then
  GREEN='\033[32m'; YELLOW='\033[33m'; RED='\033[31m'; CYAN='\033[36m'; RESET='\033[0m'
  BWHITE='\033[1;37m'; ORANGE='\033[38;5;214m'; BCYAN='\033[1;36m'
else
  GREEN=''; YELLOW=''; RED=''; CYAN=''; RESET=''
  BWHITE=''; ORANGE=''; BCYAN=''
fi

info() { printf '%b[FusionWeb]%b %s\n' "${GREEN}" "${RESET}" "$*"; }
warn() { printf '%b[FusionWeb]%b %s\n' "${YELLOW}" "${RESET}" "$*"; }
fail() { printf '%b[FusionWeb]%b %s\n' "${RED}" "${RESET}" "$*" >&2; exit 1; }
command_exists() { command -v "$1" >/dev/null 2>&1; }

confirm() {
  local answer
  printf '%b[FusionWeb]%b %s [y/N]: ' "${CYAN}" "${RESET}" "$*"
  read -r answer
  [[ "${answer}" =~ ^[Yy]$ ]]
}

is_loopback_host() {
  local host="${1:-}"
  case "${host}" in
    ""|127.0.0.1|localhost|::1) return 0 ;;
    *) return 1 ;;
  esac
}

compose() {
  local files=(--env-file "${ENV_FILE}" -f "${COMPOSE_FILE}")
  local bind
  bind="$(get_env FUSIONWEB_INFRA_BIND)"
  if ! is_loopback_host "${bind}" && [[ -f "${REMOTE_ACCESS_FILE}" ]]; then
    files+=(-f "${REMOTE_ACCESS_FILE}")
  fi
  docker compose "${files[@]}" "$@"
}

read_version_file() {
  [[ -f "${VERSION_FILE}" ]] || fail "缺少 VERSION 文件。"
  tr -d '\r\n[:space:]' < "${VERSION_FILE}"
}

get_env() {
  local key="$1"
  [[ -f "${ENV_FILE}" ]] || return 0
  awk -v key="${key}" 'index($0, key "=") == 1 { print substr($0, length(key) + 2); exit }' "${ENV_FILE}" | tr -d '\r'
}

set_env() {
  local key="$1" value="$2" tmp
  tmp="$(mktemp)" || fail "无法创建临时文件。"
  awk -v key="${key}" -v value="${value}" '
    BEGIN { found=0 }
    index($0, key "=") == 1 {
      if (!found) print key "=" value
      found=1
      next
    }
    { print }
    END { if (!found) print key "=" value }
  ' "${ENV_FILE}" > "${tmp}" || { rm -f "${tmp}"; fail "更新 .env 失败。"; }
  cat "${tmp}" > "${ENV_FILE}"
  rm -f "${tmp}"
}

random_hex() {
  local bytes="${1:-32}"
  if command_exists openssl; then
    openssl rand -hex "${bytes}"
  elif [[ -r /dev/urandom ]] && command_exists od; then
    od -An -N "${bytes}" -tx1 /dev/urandom | tr -d '\r\n'
  else
    fail "无法生成安全随机密钥：需要 openssl 或 /dev/urandom + od。"
  fi
}

password_meets_policy() {
  local password="${1:-}"
  [[ ${#password} -ge 20 ]] || return 1
  [[ "${password}" =~ [[:upper:]] ]] || return 1
  [[ "${password}" =~ [[:lower:]] ]] || return 1
  [[ "${password}" =~ [[:digit:]] ]] || return 1
  [[ "${password}" =~ [^[:alnum:]] ]] || return 1
}

random_password() {
  local bytes="${1:-24}" candidate
  while :; do
    if command_exists openssl; then
      candidate="$(openssl rand -base64 "${bytes}" | tr -d '\r\n')"
    elif [[ -r /dev/urandom ]] && command_exists base64; then
      candidate="$(head -c "${bytes}" /dev/urandom | base64 | tr -d '\r\n')"
    else
      fail "无法生成安全随机密码：需要 openssl 或 base64。"
    fi
    if password_meets_policy "${candidate}"; then
      printf '%s' "${candidate}"
      return 0
    fi
  done
}

ensure_secret() {
  local key="$1" weak="${2:-}" bytes="${3:-32}" current generated
  current="$(get_env "${key}")"
  if [[ "${key}" == "FUSIONWEB_BASIC_PASS" ]]; then
    if [[ -z "${current}" ]]; then
      generated="$(random_password 24)"
      set_env "${key}" "${generated}"
      info "已生成 ${key}。"
    fi
    return 0
  fi

  if [[ -z "${current}" || ( -n "${weak}" && "${current}" == "${weak}" ) ]]; then
    if [[ "${key}" == "FUSIONWEB_BASIC_PASS" ]]; then
      generated='$$X5_fK8T+&%=U@X*5j|f'
    else
      generated="$(random_hex "${bytes}")"
    fi
    set_env "${key}" "${generated}"
    info "已生成 ${key}。"
  fi
}

detect_primary_ip() {
  local detected=""
  if command_exists ip; then
    detected="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i == "src") { print $(i+1); exit }}')"
    if [[ -z "${detected}" ]]; then
      detected="$(ip -o -4 addr show scope global up 2>/dev/null | awk '{split($4, a, "/"); print a[1]; exit}')"
    fi
  fi
  if [[ -z "${detected}" ]] && command_exists hostname; then
    detected="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi
  printf '%s' "${detected}"
}

sync_remote_connection_env() {
  local current_bind bind_host external_host postgres_user postgres_password postgres_db
  local pg_port redis_port minio_port pg_dsn redis_addr minio_endpoint

  current_bind="$(get_env FUSIONWEB_INFRA_BIND)"
  bind_host="${current_bind}"
  if is_loopback_host "${bind_host}" || [[ -z "${bind_host}" || "${bind_host}" == "0.0.0.0" ]]; then
    bind_host="$(detect_primary_ip)"
  fi
  if [[ -z "${bind_host}" ]]; then
    warn "未能自动探测主机 IPv4，已跳过远程 Worker 连接参数回填。"
    return 0
  fi

  external_host="$(get_env FUSIONWEB_REMOTE_HOST)"
  if [[ -z "${external_host}" ]]; then
    external_host="${bind_host}"
  fi

  postgres_user="$(get_env POSTGRES_USER)"; postgres_user="${postgres_user:-fusionweb}"
  postgres_password="$(get_env POSTGRES_PASSWORD)"
  postgres_db="$(get_env POSTGRES_DB)"; postgres_db="${postgres_db:-fusionweb}"
  pg_port="$(get_env FUSIONWEB_PG_PORT)"; pg_port="${pg_port:-5432}"
  redis_port="$(get_env FUSIONWEB_REDIS_PORT)"; redis_port="${redis_port:-6379}"
  minio_port="$(get_env FUSIONWEB_MINIO_PORT)"; minio_port="${minio_port:-9000}"

  if [[ -z "${postgres_password}" ]]; then
    warn "POSTGRES_PASSWORD 为空，暂时无法回填 FUSIONWEB_WORKER_EXTERNAL_PG_DSN。"
    return 0
  fi

  pg_dsn="postgres://${postgres_user}:${postgres_password}@${external_host}:${pg_port}/${postgres_db}?sslmode=disable"
  redis_addr="${external_host}:${redis_port}"
  minio_endpoint="http://${external_host}:${minio_port}"

  set_env FUSIONWEB_INFRA_BIND "${bind_host}"
  set_env FUSIONWEB_WORKER_EXTERNAL_PG_DSN "${pg_dsn}"
  set_env FUSIONWEB_WORKER_EXTERNAL_REDIS_ADDR "${redis_addr}"
  set_env FUSIONWEB_WORKER_EXTERNAL_MINIO_ENDPOINT "${minio_endpoint}"
  info "已自动回填远程 Worker 连接参数：${external_host}"
}

ensure_env() {
  [[ -f "${ENV_EXAMPLE}" ]] || fail "缺少 .env.example。"
  if [[ ! -f "${ENV_FILE}" ]]; then
    cp "${ENV_EXAMPLE}" "${ENV_FILE}" || fail "无法创建 .env。"
    info "已从 .env.example 创建 .env。"
  else
    info "检测到已有 .env，将保留现有配置并只修复缺失或弱默认密钥。"
  fi

  set_env FUSIONWEB_VERSION "$(read_version_file)"
  ensure_secret POSTGRES_PASSWORD change-me-postgres 32
  ensure_secret FUSIONWEB_REDIS_PASSWORD change-me-redis 32
  ensure_secret FUSIONWEB_MINIO_ACCESS_KEY fusionweb 12
  ensure_secret FUSIONWEB_MINIO_SECRET_KEY change-me-minio-secret 32
  ensure_secret FUSIONWEB_JWT_SECRET "" 48
  ensure_secret FUSIONWEB_BASIC_PASS
  ensure_secret FUSIONWEB_WORKER_KEY change-me-worker-key 32
  ensure_secret FUSIONWEB_ENCRYPTION_KEY '' 48
  sync_remote_connection_env
}

validate_image_prefix() {
  local prefix
  prefix="$(get_env FUSIONWEB_IMAGE_PREFIX)"
  [[ -n "${prefix}" ]] || fail ".env 中缺少 FUSIONWEB_IMAGE_PREFIX。"
  [[ "${prefix}" == *cn-hangzhou*/*/fusionweb ]] || \
    warn "当前镜像前缀不是计划中的杭州 ACR FusionWeb 格式：${prefix}"
}

install_docker_linux() {
  command_exists curl || fail "自动安装 Docker 需要 curl。请先安装 curl，或手动安装 Docker Engine。"
  local runner="" installer
  if [[ "$(id -u)" -ne 0 ]]; then
    command_exists sudo || fail "自动安装 Docker 需要 root 或 sudo。"
    runner="sudo"
  fi
  installer="$(mktemp)" || fail "无法创建 Docker 安装临时文件。"
  curl -fsSL https://get.docker.com -o "${installer}" || { rm -f "${installer}"; fail "下载 Docker 安装脚本失败。"; }
  ${runner} sh "${installer}" || { rm -f "${installer}"; fail "Docker 安装失败。"; }
  rm -f "${installer}"
  ${runner} systemctl enable --now docker >/dev/null 2>&1 || true
  if [[ "$(id -u)" -ne 0 ]]; then
    ${runner} usermod -aG docker "${USER}" >/dev/null 2>&1 || true
    warn "已尝试把当前用户加入 docker 组；如仍无权限，请重新登录后再运行。"
  fi
}

check_docker() {
  if ! command_exists docker; then
    warn "未检测到 Docker。"
    if confirm "是否使用 Docker 官方安装脚本自动安装 Docker Engine？"; then
      install_docker_linux
    else
      fail "请先安装 Docker Engine 和 Docker Compose 插件。"
    fi
  fi
  docker info >/dev/null 2>&1 || fail "Docker 服务不可用或当前用户无权访问 Docker。"
  docker compose version >/dev/null 2>&1 || fail "未检测到 Docker Compose v2（docker compose）。"
}

validate_compose() {
  [[ -f "${COMPOSE_FILE}" ]] || fail "缺少 docker-compose.yaml。"
  local bind
  bind="$(get_env FUSIONWEB_INFRA_BIND)"
  if ! is_loopback_host "${bind}" && [[ ! -f "${REMOTE_ACCESS_FILE}" ]]; then
    fail "缺少 docker-compose.remote-access.yaml。"
  fi
  compose config --quiet || fail "Compose 或 .env 配置无效。"
}

check_containers() {
  local failed=0 state
  printf '\n%-24s %-20s\n' "容器" "状态"
  printf '%-24s %-20s\n' "------------------------" "--------------------"
  for container in "${CONTAINERS[@]}"; do
    if ! docker inspect "${container}" >/dev/null 2>&1; then
      printf '%-24s %-20s\n' "${container}" "missing"
      failed=1
      continue
    fi
    state="$(docker inspect --format '{{.State.Status}}{{if .State.Health}} / {{.State.Health.Status}}{{end}}' "${container}" 2>/dev/null)"
    printf '%-24s %-20s\n' "${container}" "${state}"
    [[ "${state}" == running* ]] || failed=1
    [[ "${state}" == *" / unhealthy"* ]] && failed=1
  done
  return "${failed}"
}

show_access() {
  local http_port https_port user pass
  http_port="$(get_env FUSIONWEB_HTTP_PORT)"; http_port="${http_port:-8756}"
  https_port="$(get_env FUSIONWEB_HTTPS_PORT)"; https_port="${https_port:-8988}"
  user="$(get_env FUSIONWEB_BASIC_USER)"; user="${user:-admin}"
  info "FusionWeb 已启动。"
  echo "  HTTP : http://localhost:${http_port}"
  echo "  HTTPS: https://localhost:${https_port}"
  pass="$(get_env FUSIONWEB_BASIC_PASS)"
  if [[ -z "${pass}" ]]; then
    warn "未找到 FUSIONWEB_BASIC_PASS，请先运行 install 生成随机密码。"
    pass='<未生成>'
  fi
  echo "  Basic Auth 用户名: ${user}"
  echo "  Basic Auth 密码: ${pass}"
  echo "  首次访问自签证书时，浏览器会要求确认。"
}

cmd_install() {
  check_docker
  ensure_env
  validate_image_prefix
  validate_compose
  info "正在拉取六个 linux/amd64 镜像……"
  compose pull || fail "镜像拉取失败。请确认 ACR 仓库已公开、命名空间正确且镜像已发布。"
  info "正在启动 PostgreSQL、Redis、MinIO、API、Web 和默认 Worker……"
  compose up -d --remove-orphans --wait --wait-timeout 600 || fail "服务启动失败，请运行 ./fusionweb.sh logs 查看日志。"
  if ! check_containers; then
    fail "至少一个容器未正常运行，请运行 ./fusionweb.sh logs。"
  fi
  show_access
}

require_runtime_env() {
  [[ -f "${ENV_FILE}" ]] || fail "尚未创建 .env，请先运行 ./fusionweb.sh install。"
  validate_image_prefix
  sync_remote_connection_env
}

cmd_start() {
  check_docker; require_runtime_env; validate_compose
  compose up -d --remove-orphans --wait --wait-timeout 600 || fail "启动失败。"
  check_containers || fail "至少一个容器未正常运行。"
  show_access
}

cmd_stop() {
  check_docker; require_runtime_env
  compose stop || fail "停止服务失败。"
  info "FusionWeb 已停止，数据卷保留。"
}

cmd_restart() {
  check_docker; require_runtime_env; validate_compose
  compose stop || fail "停止服务失败。"
  compose up -d --remove-orphans --wait --wait-timeout 600 || fail "重新启动失败。"
  check_containers || fail "至少一个容器未正常运行。"
  show_access
}

cmd_status() {
  check_docker; require_runtime_env
  compose ps
  check_containers || return 1
}

normalize_service() {
  case "${1:-}" in
    api) echo fusionweb-api ;;
    web) echo fusionweb-web ;;
    worker) echo fusionweb-worker ;;
    postgres|redis|minio|fusionweb-api|fusionweb-web|fusionweb-worker) echo "$1" ;;
    ""|all) echo "" ;;
    *) fail "未知服务：$1。可选：postgres redis minio api web worker all" ;;
  esac
}

cmd_logs() {
  check_docker; require_runtime_env
  local service
  service="$(normalize_service "${1:-all}")"
  if [[ -n "${service}" ]]; then
    compose logs -f --tail 200 "${service}"
  else
    compose logs -f --tail 200
  fi
}


cmd_check_update() {
  command_exists git || fail "未检测到 git。"
  git rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "当前目录还不是 Git 仓库，无法检查远程更新。"
  local local_version upstream remote_version
  local_version="$(get_env FUSIONWEB_VERSION)"
  local_version="${local_version:-$(read_version_file)}"
  git fetch --quiet origin || fail "git fetch 失败。"
  upstream="$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)"
  [[ -n "${upstream}" ]] || upstream="origin/main"
  remote_version="$(git show "${upstream}:VERSION" 2>/dev/null | tr -d '\r\n[:space:]')"
  [[ -n "${remote_version}" ]] || fail "无法从 ${upstream} 读取 VERSION。"
  echo "当前部署版本: ${local_version}"
  echo "远程仓库版本: ${remote_version}"
  if [[ "${local_version}" == "${remote_version}" ]]; then
    info "当前已是目标版本。"
  else
    warn "发现版本差异，可运行 ./fusionweb.sh upgrade。"
  fi
}

cmd_upgrade() {
  check_docker
  command_exists git || fail "未检测到 git。"
  git rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "当前目录不是 Git 仓库，无法执行安全升级。"
  [[ -z "$(git status --porcelain)" ]] || fail "Git 工作区存在未提交修改。请先提交、暂存到其他分支或还原修改。"
  [[ -f "${ENV_FILE}" ]] || fail "尚未安装，请先运行 ./fusionweb.sh install。"

  local old_version new_version
  old_version="$(get_env FUSIONWEB_VERSION)"
  old_version="${old_version:-$(read_version_file)}"
  info "正在执行 git pull --ff-only……"
  git pull --ff-only || fail "Git 快进更新失败，未改动运行中的容器。"
  new_version="$(read_version_file)"

  set_env FUSIONWEB_VERSION "${new_version}"
  validate_image_prefix
  sync_remote_connection_env
  validate_compose
  info "正在从 ${old_version} 升级到 ${new_version}……"
  if ! compose pull || ! compose up -d --remove-orphans --wait --wait-timeout 600; then
    set_env FUSIONWEB_VERSION "${old_version}"
    warn "升级失败，.env 已恢复为旧镜像版本 ${old_version}，数据卷未删除。"
    echo "回滚命令：./fusionweb.sh start"
    return 1
  fi
  if ! check_containers; then
    set_env FUSIONWEB_VERSION "${old_version}"
    warn "新版本容器状态异常，.env 已恢复为 ${old_version}，数据卷未删除。"
    echo "回滚命令：./fusionweb.sh start"
    return 1
  fi
  info "升级完成：${old_version} -> ${new_version}。"
}

cmd_uninstall() {
  check_docker
  [[ -f "${ENV_FILE}" ]] || fail "未找到 .env。"
  echo "警告：此操作会删除 FusionWeb 六个容器以及 PostgreSQL、Redis、MinIO、应用、密钥和 SSL 数据卷。"
  echo "源码目录、VERSION 和 .env 不会被删除。"
  local answer
  printf '请输入 DELETE 确认永久删除数据: '
  read -r answer
  [[ "${answer}" == "DELETE" ]] || { info "已取消卸载。"; return 0; }
  compose down -v --remove-orphans || fail "卸载失败。"
  info "容器和数据卷已删除；源码与 .env 已保留。"
}

print_banner() {
  local banner_version="unknown"
  [[ -f "${VERSION_FILE}" ]] && banner_version="$(read_version_file)"
  printf '%b\n' "${BWHITE}"
  cat <<'EOF'
  ███████╗ ██╗   ██╗ ███████╗ ██╗  ██████╗  ███╗   ██╗ ██╗    ██╗ ███████╗ ██████╗
  ██╔════╝ ██║   ██║ ██╔════╝ ██║ ██╔═══██╗ ████╗  ██║ ██║    ██║ ██╔════╝ ██╔══██╗
  █████╗   ██║   ██║ ███████╗ ██║ ██║   ██║ ██╔██╗ ██║ ██║ █╗ ██║ █████╗   ██████╔╝
  ██╔══╝   ██║   ██║ ╚════██║ ██║ ██║   ██║ ██║╚██╗██║ ██║███╗██║ ██╔══╝   ██╔══██╗
  ██║      ╚██████╔╝ ███████║ ██║ ╚██████╔╝ ██║ ╚████║ ╚███╔███╔╝ ███████╗ ██████╔╝
  ╚═╝       ╚═════╝  ╚══════╝ ╚═╝  ╚═════╝  ╚═╝  ╚═══╝  ╚══╝╚══╝  ╚══════╝ ╚═════╝
EOF
  printf '%b' "${ORANGE}"
  printf '  FusionWeb 管理工具  v%s\n' "${SCRIPT_VERSION}"
  printf '  企业级分布式网络安全扫描平台\n'
  printf '  当前版本：%s\n' "${banner_version}"
  printf '  当前时间：%s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
  printf '%b\n' "${RESET}"
}

print_menu() {
  printf '%b' "${BCYAN}"
  cat <<'EOF'

  1. 一键安装
  2. 一键升级
  3. 一键卸载
  4. 查看状态
  5. 查看日志
  6. 启动服务
  7. 停止服务
  8. 重启服务
  9. 检查更新
  0. 退出

EOF
  printf '%b' "${RESET}"
}

menu_logs() {
  local svc=""
  printf '请输入服务名（postgres/redis/minio/api/web/worker/all，默认 all）：'
  read -r svc || true
  cmd_logs "${svc:-all}"
}

menu_loop() {
  local choice
  while :; do
    clear 2>/dev/null || printf '\033[2J\033[H'
    print_banner
    print_menu
    printf '%b请输入选项：%b' "${BWHITE}" "${RESET}"
    choice=""
    if ! read -r choice; then
      echo
      return 0
    fi
    choice="${choice%$'\r'}"
    echo
    case "${choice}" in
      1) ( cmd_install ) ;;
      2) ( cmd_upgrade ) ;;
      3) ( cmd_uninstall ) ;;
      4) ( cmd_status ) ;;
      5) ( menu_logs ) ;;
      6) ( cmd_start ) ;;
      7) ( cmd_stop ) ;;
      8) ( cmd_restart ) ;;
      9) ( cmd_check_update ) ;;
      0) info "已退出 FusionWeb 管理工具。"; return 0 ;;
      *) warn "无效选项：${choice}" ;;
    esac
    echo
    read -r -p "按回车键返回主菜单……" || return 0
  done
}

# 纯交互式菜单模式：不接收命令行参数。
menu_loop

