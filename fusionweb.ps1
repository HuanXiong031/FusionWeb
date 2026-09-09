# FusionWeb 交互式管理菜单（仅菜单模式，不接受命令行参数）。
#Requires -Version 5.1

$SCRIPT_VERSION = '2.0.0'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $SCRIPT_DIR
[Environment]::CurrentDirectory = $SCRIPT_DIR
$COMPOSE_FILE = 'docker-compose.yaml'
$REMOTE_ACCESS_FILE = 'docker-compose.remote-access.yaml'
$ENV_FILE = '.env'
$ENV_EXAMPLE = '.env.example'
$VERSION_FILE = 'VERSION'
$CONTAINERS = @('fusionweb_postgres','fusionweb_redis','fusionweb_minio','fusionweb_api','fusionweb_web','fusionweb_worker')

try {
  [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
  [Console]::InputEncoding  = New-Object System.Text.UTF8Encoding($false)
} catch {}
$E = [char]27

function Info([string]$m) { Write-Host "[FusionWeb] $m" -ForegroundColor Green }
function Warn([string]$m) { Write-Host "[FusionWeb] $m" -ForegroundColor Yellow }

function Read-SourceVersion {
  if (-not (Test-Path $VERSION_FILE)) { throw '缺少 VERSION 文件。' }
  $v = ([IO.File]::ReadAllText($VERSION_FILE)).Trim()
  if (-not $v) { throw 'VERSION 文件为空。' }
  return $v
}

function Get-Env([string]$key) {
  if (-not (Test-Path $ENV_FILE)) { return $null }
  foreach ($line in [IO.File]::ReadAllLines($ENV_FILE)) {
    if ($line.StartsWith("$key=")) { return $line.Substring($key.Length + 1) }
  }
  return $null
}

function Set-Env([string]$key, [string]$value) {
  $lines = if (Test-Path $ENV_FILE) { [IO.File]::ReadAllLines($ENV_FILE) } else { @() }
  $done = $false
  $out = foreach ($line in $lines) {
    if (-not $done -and $line.StartsWith("$key=")) { $done = $true; "$key=$value" }
    elseif ($line.StartsWith("$key=")) { }
    else { $line }
  }
  $out = @($out)
  if (-not $done) { $out += "$key=$value" }
  [IO.File]::WriteAllLines($ENV_FILE, [string[]]$out, (New-Object System.Text.UTF8Encoding($false)))
}

function New-RandomHex([int]$bytes) {
  $b = New-Object byte[] $bytes
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  return ($b | ForEach-Object { $_.ToString('x2') }) -join ''
}

function Test-Password([string]$p) {
  return ($p.Length -ge 20 -and $p -match '[A-Z]' -and $p -match '[a-z]' -and $p -match '\d' -and $p -match '[^A-Za-z0-9]')
}

function New-RandomPassword([int]$len) {
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  $bytes = New-Object byte[] $len
  while ($true) {
    $rng.GetBytes($bytes)
    $candidate = [Convert]::ToBase64String($bytes).TrimEnd('=')
    if (Test-Password $candidate) { return $candidate }
  }
}

function Ensure-Secret([string]$key, [string]$weak, [int]$bytes) {
  $current = Get-Env $key
  if ($key -eq 'FUSIONWEB_BASIC_PASS') {
    if ([string]::IsNullOrEmpty($current)) {
      Set-Env $key (New-RandomPassword 24)
      Info "已生成 $key。"
    }
    return
  }
  if ([string]::IsNullOrEmpty($current) -or ($weak -ne '' -and $current -eq $weak)) {
    Set-Env $key (New-RandomHex $bytes)
    Info "已生成 $key。"
  }
}

function Is-Loopback([string]$h) {
  return ($h -eq '' -or $h -eq '127.0.0.1' -or $h -ieq 'localhost' -or $h -eq '::1')
}

function Get-PrimaryIP {
  $ip = $null
  $route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1
  if ($route) {
    $ip = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue |
      Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
      Select-Object -ExpandProperty IPAddress -First 1
  }
  if (-not $ip) {
    $ip = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
      Select-Object -ExpandProperty IPAddress -First 1
  }
  return $ip
}

function Get-ComposeArgs {
  $list = @('--env-file', $ENV_FILE, '-f', $COMPOSE_FILE)
  $bind = Get-Env 'FUSIONWEB_INFRA_BIND'
  if ([string]::IsNullOrEmpty($bind)) { $bind = '127.0.0.1' }
  if (-not (Is-Loopback $bind) -and (Test-Path $REMOTE_ACCESS_FILE)) { $list += @('-f', $REMOTE_ACCESS_FILE) }
  return $list
}

function Invoke-Compose([string[]]$CmdArgs) {
  $all = (Get-ComposeArgs) + $CmdArgs
  & docker compose $all
}

function Sync-RemoteConnectionEnv {
  $bindHost = Get-Env 'FUSIONWEB_INFRA_BIND'
  if ((Is-Loopback $bindHost) -or $bindHost -eq '0.0.0.0') { $bindHost = Get-PrimaryIP }
  if ([string]::IsNullOrEmpty($bindHost)) { Warn '未能自动探测当前主机 IPv4，已跳过远程 Worker 连接参数回填。'; return }
  $ext = Get-Env 'FUSIONWEB_REMOTE_HOST'
  if (-not $ext) { $ext = $bindHost }
  $pgUser = Get-Env 'POSTGRES_USER'; if (-not $pgUser) { $pgUser = 'fusionweb' }
  $pgPass = Get-Env 'POSTGRES_PASSWORD'
  if (-not $pgPass) { Warn 'POSTGRES_PASSWORD 为空，暂时无法回填 FUSIONWEB_WORKER_EXTERNAL_PG_DSN。'; return }
  $pgDb = Get-Env 'POSTGRES_DB'; if (-not $pgDb) { $pgDb = 'fusionweb' }
  $pgPort = Get-Env 'FUSIONWEB_PG_PORT'; if (-not $pgPort) { $pgPort = '5432' }
  $redisPort = Get-Env 'FUSIONWEB_REDIS_PORT'; if (-not $redisPort) { $redisPort = '6379' }
  $minioPort = Get-Env 'FUSIONWEB_MINIO_PORT'; if (-not $minioPort) { $minioPort = '9000' }
  Set-Env 'FUSIONWEB_INFRA_BIND' $bindHost
  Set-Env 'FUSIONWEB_WORKER_EXTERNAL_PG_DSN' "postgres://${pgUser}:${pgPass}@${ext}:${pgPort}/${pgDb}?sslmode=disable"
  Set-Env 'FUSIONWEB_WORKER_EXTERNAL_REDIS_ADDR' "${ext}:${redisPort}"
  Set-Env 'FUSIONWEB_WORKER_EXTERNAL_MINIO_ENDPOINT' "http://${ext}:${minioPort}"
  Info "已自动回填远程 Worker 连接参数：$ext"
}

function Ensure-Env {
  if (-not (Test-Path $ENV_EXAMPLE)) { throw "缺少 $ENV_EXAMPLE。" }
  if (-not (Test-Path $ENV_FILE)) {
    Copy-Item $ENV_EXAMPLE $ENV_FILE
    Info "已从 $ENV_EXAMPLE 创建 $ENV_FILE。"
  } else {
    Info "检测到已有 $ENV_FILE，将保留现有配置并只修复缺失或弱默认密钥。"
  }
  Set-Env 'FUSIONWEB_VERSION' (Read-SourceVersion)
  Ensure-Secret 'POSTGRES_PASSWORD' 'change-me-postgres' 32
  Ensure-Secret 'FUSIONWEB_REDIS_PASSWORD' 'change-me-redis' 32
  Ensure-Secret 'FUSIONWEB_MINIO_ACCESS_KEY' 'fusionweb' 12
  Ensure-Secret 'FUSIONWEB_MINIO_SECRET_KEY' 'change-me-minio-secret' 32
  Ensure-Secret 'FUSIONWEB_JWT_SECRET' '' 48
  Ensure-Secret 'FUSIONWEB_BASIC_PASS' '' 18
  Ensure-Secret 'FUSIONWEB_WORKER_KEY' 'change-me-worker-key' 32
  Ensure-Secret 'FUSIONWEB_ENCRYPTION_KEY' '' 48
  Sync-RemoteConnectionEnv
}

function Test-ImagePrefix {
  $prefix = Get-Env 'FUSIONWEB_IMAGE_PREFIX'
  if (-not $prefix) { throw "$ENV_FILE 中缺少 FUSIONWEB_IMAGE_PREFIX。" }
  if ($prefix -notlike '*cn-hangzhou*') { Warn "提示：当前镜像前缀不是杭州 ACR 地址：$prefix" }
  if ($prefix -notlike '*/fusionweb') { Warn "提示：当前镜像前缀不是 FusionWeb 仓库前缀：$prefix" }
}

function Check-Docker {
  if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw '未检测到 Docker。请安装并启动 Docker Desktop。' }
  & docker info > $null 2>&1
  if ($LASTEXITCODE -ne 0) { throw 'Docker Desktop 未运行或当前终端无法连接 Docker。' }
  & docker compose version > $null 2>&1
  if ($LASTEXITCODE -ne 0) { throw '未检测到 Docker Compose v2（docker compose）。' }
  $dockerOS = ((& docker info --format '{{.OSType}}' 2>$null) -join '')
  if ($dockerOS -ne 'linux') { throw "Docker Desktop 当前不是 Linux Containers 模式。`n请切换到 Linux Containers 后重试。" }
}

function Test-ComposeConfig {
  if (-not (Test-Path $COMPOSE_FILE)) { throw "缺少 $COMPOSE_FILE。" }
  $bind = Get-Env 'FUSIONWEB_INFRA_BIND'
  if ([string]::IsNullOrEmpty($bind)) { $bind = '127.0.0.1' }
  if (-not (Is-Loopback $bind) -and -not (Test-Path $REMOTE_ACCESS_FILE)) { throw "缺少 $REMOTE_ACCESS_FILE。" }
  $all = (Get-ComposeArgs) + @('config', '--quiet')
  & docker compose $all > $null 2>&1
  if ($LASTEXITCODE -ne 0) { throw 'Compose 或环境配置无效。' }
}

function Test-Containers {
  $failed = $false
  Write-Host ''
  Write-Host ('{0,-26} {1}' -f '容器', '状态')
  foreach ($c in $CONTAINERS) {
    & docker inspect $c > $null 2>&1
    if ($LASTEXITCODE -ne 0) {
      Write-Host ('{0,-26} missing' -f $c)
      $failed = $true
      continue
    }
    $state = ((& docker inspect --format '{{.State.Status}}{{if .State.Health}} / {{.State.Health.Status}}{{end}}' $c 2>$null) -join '')
    Write-Host ('{0,-26} {1}' -f $c, $state)
    if ($state -notlike 'running*' -or $state -like '*unhealthy*') { $failed = $true }
  }
  return (-not $failed)
}

function Show-Access {
  $httpPort = Get-Env 'FUSIONWEB_HTTP_PORT'; if (-not $httpPort) { $httpPort = '8756' }
  $httpsPort = Get-Env 'FUSIONWEB_HTTPS_PORT'; if (-not $httpsPort) { $httpsPort = '8988' }
  $user = Get-Env 'FUSIONWEB_BASIC_USER'; if (-not $user) { $user = 'admin' }
  Info 'FusionWeb 已启动。'
  Write-Host "  HTTP : http://localhost:$httpPort"
  Write-Host "  HTTPS: https://localhost:$httpsPort"
  $pass = Get-Env 'FUSIONWEB_BASIC_PASS'
  if (-not $pass) {
    Warn '未找到 FUSIONWEB_BASIC_PASS，请先执行「一键安装」生成随机密码。'
    $pass = '<未生成>'
  }
  Write-Host "  Basic Auth 用户名: $user"
  Write-Host "  Basic Auth 密码: $pass"
  Write-Host '  首次访问自签证书时，浏览器会要求确认。'
}

function Require-RuntimeEnv {
  if (-not (Test-Path $ENV_FILE)) { throw "尚未创建 $ENV_FILE，请先执行「一键安装」。" }
  Test-ImagePrefix
  Sync-RemoteConnectionEnv
}

function Do-Install {
  Check-Docker
  Ensure-Env
  Test-ImagePrefix
  Sync-RemoteConnectionEnv
  Test-ComposeConfig
  Info '正在拉取六个 linux/amd64 镜像……'
  Invoke-Compose @('pull')
  if ($LASTEXITCODE -ne 0) { throw '镜像拉取失败。请确认 ACR 仓库已公开、命名空间正确且镜像已发布。' }
  Info '正在启动 PostgreSQL、Redis、MinIO、API、Web 和默认 Worker……'
  Invoke-Compose @('up', '-d', '--remove-orphans', '--wait', '--wait-timeout', '600')
  if ($LASTEXITCODE -ne 0) { throw '服务启动失败，请使用菜单「查看日志」排查。' }
  if (-not (Test-Containers)) { throw '至少一个容器未正常运行。' }
  Show-Access
}

function Do-Start {
  Check-Docker
  Require-RuntimeEnv
  Test-ComposeConfig
  Invoke-Compose @('up', '-d', '--remove-orphans', '--wait', '--wait-timeout', '600')
  if ($LASTEXITCODE -ne 0) { throw '启动失败。' }
  if (-not (Test-Containers)) { throw '至少一个容器未正常运行。' }
  Show-Access
}

function Do-Stop {
  Check-Docker
  Require-RuntimeEnv
  Invoke-Compose @('stop')
  if ($LASTEXITCODE -ne 0) { throw '停止服务失败。' }
  Info 'FusionWeb 已停止，数据卷保留。'
}

function Do-Restart {
  Check-Docker
  Require-RuntimeEnv
  Test-ComposeConfig
  Invoke-Compose @('stop')
  if ($LASTEXITCODE -ne 0) { throw '停止服务失败。' }
  Invoke-Compose @('up', '-d', '--remove-orphans', '--wait', '--wait-timeout', '600')
  if ($LASTEXITCODE -ne 0) { throw '重新启动失败。' }
  if (-not (Test-Containers)) { throw '至少一个容器未正常运行。' }
  Show-Access
}

function Do-Status {
  Check-Docker
  Require-RuntimeEnv
  Invoke-Compose @('ps')
  [void](Test-Containers)
}

function Do-Logs {
  Check-Docker
  Require-RuntimeEnv
  $svc = (Read-Host '请输入服务名（postgres/redis/minio/api/web/worker/all，默认 all）').Trim()
  if ($svc -eq '') { $svc = 'all' }
  $name = ''
  switch -Regex ($svc.ToLower()) {
    '^(api|web|worker)$' { $name = "fusionweb-$($Matches[0])"; break }
    '^(postgres|redis|minio|fusionweb-api|fusionweb-web|fusionweb-worker)$' { $name = $svc; break }
    '^all$' { $name = ''; break }
    default { throw "未知服务：$svc。可选：postgres redis minio api web worker all" }
  }
  if ($name) { Invoke-Compose @('logs', '-f', '--tail', '200', $name) }
  else { Invoke-Compose @('logs', '-f', '--tail', '200') }
}

function Do-CheckUpdate {
  if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw '未检测到 git。' }
  & git rev-parse --is-inside-work-tree > $null 2>&1
  if ($LASTEXITCODE -ne 0) { throw '当前目录还不是 Git 仓库，无法检查远程更新。' }
  $local = Get-Env 'FUSIONWEB_VERSION'
  if (-not $local) { $local = Read-SourceVersion }
  & git fetch --quiet origin
  if ($LASTEXITCODE -ne 0) { throw 'git fetch 失败。' }
  $upstream = ((& git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>$null) -join '')
  if (-not $upstream) { $upstream = 'origin/main' }
  $remote = ((& git show "${upstream}:VERSION" 2>$null) -join '').Trim()
  if (-not $remote) { throw "无法从 $upstream 读取 VERSION。" }
  Write-Host "当前部署版本: $local"
  Write-Host "远程仓库版本: $remote"
  if ($local -eq $remote) { Info '当前已是目标版本。' }
  else { Warn '发现版本差异，可执行「一键升级」。' }
}

function Do-Upgrade {
  Check-Docker
  if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw '未检测到 git。' }
  & git rev-parse --is-inside-work-tree > $null 2>&1
  if ($LASTEXITCODE -ne 0) { throw '当前目录不是 Git 仓库，无法执行安全升级。' }
  if (@(& git status --porcelain).Count -gt 0) { throw 'Git 工作区存在未提交修改。请先提交、暂存到其他分支或还原修改。' }
  if (-not (Test-Path $ENV_FILE)) { throw '尚未安装，请先执行「一键安装」。' }
  $old = Get-Env 'FUSIONWEB_VERSION'
  if (-not $old) { $old = Read-SourceVersion }
  Info '正在执行 git pull --ff-only……'
  & git pull --ff-only
  if ($LASTEXITCODE -ne 0) { throw 'Git 快进更新失败，未改动运行中的容器。' }
  $new = Read-SourceVersion
  Set-Env 'FUSIONWEB_VERSION' $new
  Test-ImagePrefix
  Sync-RemoteConnectionEnv
  Test-ComposeConfig
  Info "正在从 $old 升级到 $new……"
  Invoke-Compose @('pull')
  if ($LASTEXITCODE -eq 0) { Invoke-Compose @('up', '-d', '--remove-orphans', '--wait', '--wait-timeout', '600') }
  if ($LASTEXITCODE -ne 0 -or -not (Test-Containers)) {
    Set-Env 'FUSIONWEB_VERSION' $old
    Warn "升级失败，$ENV_FILE 已恢复为旧镜像版本 $old，数据卷未删除。"
    Warn '回滚：使用菜单「启动服务」。'
    return
  }
  Info "升级完成：$old -> $new。"
}

function Do-Uninstall {
  Check-Docker
  if (-not (Test-Path $ENV_FILE)) { throw "未找到 $ENV_FILE。" }
  Write-Host '警告：此操作会删除 FusionWeb 六个容器以及 PostgreSQL、Redis、MinIO、应用、密钥和 SSL 数据卷。'
  Write-Host '源码目录、VERSION 和 .env 不会被删除。'
  $answer = Read-Host '请输入 DELETE 确认永久删除数据'
  if ($answer -cne 'DELETE') { Info '已取消卸载。'; return }
  Invoke-Compose @('down', '-v', '--remove-orphans')
  if ($LASTEXITCODE -ne 0) { throw '卸载失败。' }
  Info '容器和数据卷已删除；源码与 .env 已保留。'
}

function Show-Banner {
  $v = 'unknown'
  if (Test-Path $VERSION_FILE) {
    $v = ([IO.File]::ReadAllText($VERSION_FILE)).Trim()
    if (-not $v) { $v = 'unknown' }
  }
  $now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  $lines = @(
    '  ███████╗ ██╗   ██╗ ███████╗ ██╗  ██████╗  ███╗   ██╗ ██╗    ██╗ ███████╗ ██████╗'
    '  ██╔════╝ ██║   ██║ ██╔════╝ ██║ ██╔═══██╗ ████╗  ██║ ██║    ██║ ██╔════╝ ██╔══██╗'
    '  █████╗   ██║   ██║ ███████╗ ██║ ██║   ██║ ██╔██╗ ██║ ██║ █╗ ██║ █████╗   ██████╔╝'
    '  ██╔══╝   ██║   ██║ ╚════██║ ██║ ██║   ██║ ██║╚██╗██║ ██║███╗██║ ██╔══╝   ██╔══██╗'
    '  ██║      ╚██████╔╝ ███████║ ██║ ╚██████╔╝ ██║ ╚████║ ╚███╔███╔╝ ███████╗ ██████╔╝'
    '  ╚═╝       ╚═════╝  ╚══════╝ ╚═╝  ╚═════╝  ╚═╝  ╚═══╝  ╚══╝╚══╝  ╚══════╝ ╚═════╝'
  )
  Write-Host "${E}[1;37m"
  foreach ($line in $lines) { Write-Host $line }
  Write-Host "${E}[38;5;214m"
  Write-Host "  FusionWeb 管理工具  v$SCRIPT_VERSION"
  Write-Host '  企业级分布式网络安全扫描平台'
  Write-Host "  当前版本：$v"
  Write-Host "  当前时间：$now"
  Write-Host "${E}[0m"
}

function Show-Menu {
  Write-Host "${E}[1;36m"
  Write-Host ''
  Write-Host '  1. 一键安装'
  Write-Host '  2. 一键升级'
  Write-Host '  3. 一键卸载'
  Write-Host '  4. 查看状态'
  Write-Host '  5. 查看日志'
  Write-Host '  6. 启动服务'
  Write-Host '  7. 停止服务'
  Write-Host '  8. 重启服务'
  Write-Host '  9. 检查更新'
  Write-Host '  0. 退出'
  Write-Host ''
  Write-Host "${E}[0m"
}

while ($true) {
  try { Clear-Host } catch {}
  Show-Banner
  Show-Menu
  $choice = (Read-Host '请输入选项').Trim()
  Write-Host ''
  try {
    switch ($choice) {
      '1' { Do-Install; break }
      '2' { Do-Upgrade; break }
      '3' { Do-Uninstall; break }
      '4' { Do-Status; break }
      '5' { Do-Logs; break }
      '6' { Do-Start; break }
      '7' { Do-Stop; break }
      '8' { Do-Restart; break }
      '9' { Do-CheckUpdate; break }
      '0' { Info '已退出 FusionWeb 管理工具。'; exit 0 }
      default { Warn "无效选项：$choice" }
    }
  } catch {
    Write-Host "[FusionWeb] $($_.Exception.Message)" -ForegroundColor Red
  }
  Write-Host ''
  [void](Read-Host '按回车键返回主菜单')
}
