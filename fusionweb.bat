@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul

set "SCRIPT_VERSION=2.0.0"
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%" || exit /b 1
set "COMPOSE_FILE=docker-compose.yaml"
set "REMOTE_ACCESS_FILE=docker-compose.remote-access.yaml"
set "ENV_FILE=.env"
set "ENV_EXAMPLE=.env.example"
set "VERSION_FILE=VERSION"

if "%~1"=="" goto :help
if /I "%~1"=="install" goto :install
if /I "%~1"=="upgrade" goto :upgrade
if /I "%~1"=="check-update" goto :check_update
if /I "%~1"=="start" goto :start
if /I "%~1"=="stop" goto :stop
if /I "%~1"=="restart" goto :restart
if /I "%~1"=="status" goto :status
if /I "%~1"=="logs" goto :logs
if /I "%~1"=="version" goto :version
if /I "%~1"=="uninstall" goto :uninstall
if /I "%~1"=="help" goto :help
if /I "%~1"=="-h" goto :help
if /I "%~1"=="--help" goto :help
echo [FusionWeb] 未知命令：%~1
echo [FusionWeb] 运行 fusionweb.bat help 查看用法。
exit /b 1

:check_docker
where docker >nul 2>&1
if errorlevel 1 (
  echo [FusionWeb] 未检测到 Docker。请安装并启动 Docker Desktop。
  exit /b 1
)
docker info >nul 2>&1
if errorlevel 1 (
  echo [FusionWeb] Docker Desktop 未运行或当前终端无法连接 Docker。
  exit /b 1
)
docker compose version >nul 2>&1
if errorlevel 1 (
  echo [FusionWeb] 未检测到 Docker Compose v2（docker compose）。
  exit /b 1
)
set "DOCKER_OS="
for /f "usebackq delims=" %%I in (`docker info --format "{{.OSType}}" 2^>nul`) do set "DOCKER_OS=%%I"
if /I not "!DOCKER_OS!"=="linux" (
  echo [FusionWeb] Docker Desktop 当前不是 Linux Containers 模式。
  echo [FusionWeb] 请切换到 Linux Containers 后重试。
  exit /b 1
)
exit /b 0

:read_source_version
set "SOURCE_VERSION="
if not exist "%VERSION_FILE%" (
  echo [FusionWeb] 缺少 VERSION 文件。
  exit /b 1
)
for /f "usebackq tokens=* delims=" %%I in ("%VERSION_FILE%") do if not defined SOURCE_VERSION set "SOURCE_VERSION=%%I"
if not defined SOURCE_VERSION (
  echo [FusionWeb] VERSION 文件为空。
  exit /b 1
)
exit /b 0

:get_env
set "ENV_VALUE="
if not exist "%ENV_FILE%" exit /b 0
for /f "usebackq tokens=1,* delims==" %%A in (`findstr /B /L /C:"%~1=" "%ENV_FILE%" 2^>nul`) do if not defined ENV_VALUE set "ENV_VALUE=%%B"
exit /b 0

:set_env
set "FW_ENV_KEY=%~1"
set "FW_ENV_VALUE=%~2"
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ^
  "$p=$env:ENV_FILE; $k=$env:FW_ENV_KEY; $v=$env:FW_ENV_VALUE;" ^
  "$enc=New-Object System.Text.UTF8Encoding($false);" ^
  "$lines=if(Test-Path -LiteralPath $p){[IO.File]::ReadAllLines($p)}else{@()};" ^
  "$done=$false; $out=foreach($line in $lines){if(-not $done -and $line.StartsWith($k+'=')){ $done=$true; $k+'='+$v } elseif($line.StartsWith($k+'=')){ } else { $line }};" ^
  "if(-not $done){$out=@($out)+($k+'='+$v)}; [IO.File]::WriteAllLines($p,[string[]]$out,$enc)"
if errorlevel 1 (
  echo [FusionWeb] 更新 %ENV_FILE% 中的 %~1 失败。
  exit /b 1
)
exit /b 0

:random_hex
set "RANDOM_VALUE="
set "FW_RANDOM_BYTES=%~1"
for /f "usebackq delims=" %%I in (`powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$bytes=New-Object byte[] ([int]$env:FW_RANDOM_BYTES); [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes); -join ($bytes | ForEach-Object { $_.ToString('x2') })"`) do set "RANDOM_VALUE=%%I"
if not defined RANDOM_VALUE (
  echo [FusionWeb] 无法使用系统 PowerShell 生成安全随机密钥。
  exit /b 1
)
exit /b 0

:password_meets_policy
set "PW_VALUE=%~1"
set "PW_SPECIAL=0"
if not "%PW_VALUE:~19%"=="" set "PW_LEN_OK=1" else set "PW_LEN_OK=0"
if "%PW_LEN_OK%"=="0" exit /b 1

echo(!PW_VALUE!| findstr /R "[A-Z]" >nul || exit /b 1
echo(!PW_VALUE!| findstr /R "[a-z]" >nul || exit /b 1
echo(!PW_VALUE!| findstr /R "[0-9]" >nul || exit /b 1
echo(!PW_VALUE!| findstr /R "[^A-Za-z0-9]" >nul || exit /b 1
exit /b 0

:random_password
set "RANDOM_VALUE="
set "FW_RANDOM_BYTES=%~1"
for /f "usebackq delims=" %%I in (`powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$len=[int]$env:FW_RANDOM_BYTES; $rng=[Security.Cryptography.RandomNumberGenerator]::Create(); $bytes=New-Object byte[] $len; while($true){ $rng.GetBytes($bytes); $candidate=[Convert]::ToBase64String($bytes).TrimEnd('='); if($candidate.Length -ge 20 -and $candidate -match '[A-Z]' -and $candidate -match '[a-z]' -and $candidate -match '\d' -and $candidate -match '[^A-Za-z0-9]'){ Write-Output $candidate; break } }"`) do set "RANDOM_VALUE=%%I"
if not defined RANDOM_VALUE (
  echo [FusionWeb] 无法生成随机密码。
  exit /b 1
)
exit /b 0

:ensure_secret
call :get_env "%~1"
set "NEED_SECRET=0"
if not defined ENV_VALUE set "NEED_SECRET=1"
if /I "%~1"=="FUSIONWEB_BASIC_PASS" (
  if "!NEED_SECRET!"=="1" (
    call :random_password 24
    if errorlevel 1 exit /b 1
    call :set_env "%~1" "!RANDOM_VALUE!"
    if errorlevel 1 exit /b 1
    echo [FusionWeb] 已生成 %~1。
  )
  exit /b 0
)
if not "%~2"=="" if "!ENV_VALUE!"=="%~2" set "NEED_SECRET=1"
if "!NEED_SECRET!"=="1" (
  call :random_hex "%~3"
  if errorlevel 1 exit /b 1
  call :set_env "%~1" "!RANDOM_VALUE!"
  if errorlevel 1 exit /b 1
  echo [FusionWeb] 已生成 %~1。
)
exit /b 0

:is_loopback_host
set "HOST_CHECK=%~1"
if not defined HOST_CHECK exit /b 0
if /I "%~1"=="127.0.0.1" exit /b 0
if /I "%~1"=="localhost" exit /b 0
if /I "%~1"=="::1" exit /b 0
exit /b 1

:detect_primary_ip
set "DETECTED_HOST_IP="
for /f "usebackq delims=" %%I in (`powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$route=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1; $ip=$null; if($route){$ip=Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -ExpandProperty IPAddress -First 1}; if(-not $ip){$ip=Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -ExpandProperty IPAddress -First 1}; if($ip){Write-Output $ip}"`) do if not defined DETECTED_HOST_IP set "DETECTED_HOST_IP=%%I"
exit /b 0

:set_compose_args
set COMPOSE_ARGS=--env-file "%ENV_FILE%" -f "%COMPOSE_FILE%"
call :get_env "FUSIONWEB_INFRA_BIND"
set "INFRA_BIND_VALUE=!ENV_VALUE!"
if not defined INFRA_BIND_VALUE set "INFRA_BIND_VALUE=127.0.0.1"
call :is_loopback_host "!INFRA_BIND_VALUE!"
if errorlevel 1 (
  if exist "%REMOTE_ACCESS_FILE%" (
    set COMPOSE_ARGS=!COMPOSE_ARGS! -f "%REMOTE_ACCESS_FILE%"
  )
)
exit /b 0

:sync_remote_connection_env
call :get_env "FUSIONWEB_INFRA_BIND"
set "CURRENT_BIND=!ENV_VALUE!"
set "BIND_HOST=!CURRENT_BIND!"
call :is_loopback_host "!BIND_HOST!"
if not errorlevel 1 set "BIND_HOST="
if /I "!CURRENT_BIND!"=="0.0.0.0" set "BIND_HOST="
if not defined BIND_HOST (
  call :detect_primary_ip
  if defined DETECTED_HOST_IP set "BIND_HOST=!DETECTED_HOST_IP!"
)
if not defined BIND_HOST (
  echo [FusionWeb] 未能自动探测当前主机 IPv4，已跳过远程 Worker 连接参数回填。
  exit /b 0
)
call :get_env "FUSIONWEB_REMOTE_HOST"
set "EXTERNAL_HOST=!ENV_VALUE!"
if not defined EXTERNAL_HOST set "EXTERNAL_HOST=!BIND_HOST!"
call :get_env "POSTGRES_USER"
set "POSTGRES_USER_VALUE=!ENV_VALUE!"
if not defined POSTGRES_USER_VALUE set "POSTGRES_USER_VALUE=fusionweb"
call :get_env "POSTGRES_PASSWORD"
set "POSTGRES_PASSWORD_VALUE=!ENV_VALUE!"
if not defined POSTGRES_PASSWORD_VALUE (
  echo [FusionWeb] POSTGRES_PASSWORD 为空，暂时无法回填 FUSIONWEB_WORKER_EXTERNAL_PG_DSN。
  exit /b 0
)
call :get_env "POSTGRES_DB"
set "POSTGRES_DB_VALUE=!ENV_VALUE!"
if not defined POSTGRES_DB_VALUE set "POSTGRES_DB_VALUE=fusionweb"
call :get_env "FUSIONWEB_PG_PORT"
set "PG_PORT_VALUE=!ENV_VALUE!"
if not defined PG_PORT_VALUE set "PG_PORT_VALUE=5432"
call :get_env "FUSIONWEB_REDIS_PORT"
set "REDIS_PORT_VALUE=!ENV_VALUE!"
if not defined REDIS_PORT_VALUE set "REDIS_PORT_VALUE=6379"
call :get_env "FUSIONWEB_MINIO_PORT"
set "MINIO_PORT_VALUE=!ENV_VALUE!"
if not defined MINIO_PORT_VALUE set "MINIO_PORT_VALUE=9000"
set "PG_DSN=postgres://!POSTGRES_USER_VALUE!:!POSTGRES_PASSWORD_VALUE!@!EXTERNAL_HOST!:!PG_PORT_VALUE!/!POSTGRES_DB_VALUE!?sslmode=disable"
set "REDIS_ADDR=!EXTERNAL_HOST!:!REDIS_PORT_VALUE!"
set "MINIO_ENDPOINT=http://!EXTERNAL_HOST!:!MINIO_PORT_VALUE!"
call :set_env "FUSIONWEB_INFRA_BIND" "!BIND_HOST!"
if errorlevel 1 exit /b 1
call :set_env "FUSIONWEB_WORKER_EXTERNAL_PG_DSN" "!PG_DSN!"
if errorlevel 1 exit /b 1
call :set_env "FUSIONWEB_WORKER_EXTERNAL_REDIS_ADDR" "!REDIS_ADDR!"
if errorlevel 1 exit /b 1
call :set_env "FUSIONWEB_WORKER_EXTERNAL_MINIO_ENDPOINT" "!MINIO_ENDPOINT!"
if errorlevel 1 exit /b 1
echo [FusionWeb] 已自动回填远程 Worker 连接参数：!EXTERNAL_HOST!
exit /b 0

:ensure_env
if not exist "%ENV_EXAMPLE%" (
  echo [FusionWeb] 缺少 %ENV_EXAMPLE%。
  exit /b 1
)
if not exist "%ENV_FILE%" (
  copy /Y "%ENV_EXAMPLE%" "%ENV_FILE%" >nul
  if errorlevel 1 exit /b 1
  echo [FusionWeb] 已从 %ENV_EXAMPLE% 创建 %ENV_FILE%。
) else (
  echo [FusionWeb] 检测到已有 %ENV_FILE%，将保留现有配置并只修复缺失或弱默认密钥。
)
call :read_source_version
if errorlevel 1 exit /b 1
call :set_env "FUSIONWEB_VERSION" "!SOURCE_VERSION!"
if errorlevel 1 exit /b 1
call :ensure_secret "POSTGRES_PASSWORD" "change-me-postgres" "32"
if errorlevel 1 exit /b 1
call :ensure_secret "FUSIONWEB_REDIS_PASSWORD" "change-me-redis" "32"
if errorlevel 1 exit /b 1
call :ensure_secret "FUSIONWEB_MINIO_ACCESS_KEY" "fusionweb" "12"
if errorlevel 1 exit /b 1
call :ensure_secret "FUSIONWEB_MINIO_SECRET_KEY" "change-me-minio-secret" "32"
if errorlevel 1 exit /b 1
call :ensure_secret "FUSIONWEB_JWT_SECRET" "" "48"
if errorlevel 1 exit /b 1
call :ensure_secret "FUSIONWEB_BASIC_PASS" "" "18"
if errorlevel 1 exit /b 1
call :ensure_secret "FUSIONWEB_WORKER_KEY" "change-me-worker-key" "32"
if errorlevel 1 exit /b 1
call :sync_remote_connection_env
exit /b %errorlevel%

:validate_image_prefix
call :get_env "FUSIONWEB_IMAGE_PREFIX"
if not defined ENV_VALUE (
  echo [FusionWeb] %ENV_FILE% 中缺少 FUSIONWEB_IMAGE_PREFIX。
  exit /b 1
)
echo !ENV_VALUE! | findstr /L /C:"cn-hangzhou" >nul
if errorlevel 1 echo [FusionWeb] 提示：当前镜像前缀不是杭州 ACR 地址：!ENV_VALUE!
echo !ENV_VALUE! | findstr /L /C:"/fusionweb" >nul
if errorlevel 1 echo [FusionWeb] 提示：当前镜像前缀不是 FusionWeb 仓库前缀：!ENV_VALUE!
exit /b 0

:validate_compose
if not exist "%COMPOSE_FILE%" (
  echo [FusionWeb] 缺少 %COMPOSE_FILE%。
  exit /b 1
)
call :set_compose_args
if errorlevel 1 exit /b 1
call :get_env "FUSIONWEB_INFRA_BIND"
set "INFRA_BIND_VALUE=!ENV_VALUE!"
if not defined INFRA_BIND_VALUE set "INFRA_BIND_VALUE=127.0.0.1"
call :is_loopback_host "!INFRA_BIND_VALUE!"
if errorlevel 1 if not exist "%REMOTE_ACCESS_FILE%" (
  echo [FusionWeb] 缺少 %REMOTE_ACCESS_FILE%。
  exit /b 1
)
docker compose !COMPOSE_ARGS! config --quiet
if errorlevel 1 (
  echo [FusionWeb] Compose 或环境配置无效。
  exit /b 1
)
exit /b 0

:check_containers
set "CONTAINER_FAILED=0"
echo.
echo 容器                     状态
for %%C in (fusionweb_postgres fusionweb_redis fusionweb_minio fusionweb_api fusionweb_web fusionweb_worker) do (
  docker inspect "%%C" >nul 2>&1
  if errorlevel 1 (
    echo %%C    missing
    set "CONTAINER_FAILED=1"
  ) else (
    set "STATE="
    for /f "usebackq delims=" %%S in (`docker inspect --format "{{.State.Status}}{{if .State.Health}} / {{.State.Health.Status}}{{end}}" "%%C" 2^>nul`) do set "STATE=%%S"
    echo %%C    !STATE!
    echo !STATE! | findstr /B /L /C:"running" >nul || set "CONTAINER_FAILED=1"
    echo !STATE! | findstr /L /C:"unhealthy" >nul && set "CONTAINER_FAILED=1"
  )
)
if "!CONTAINER_FAILED!"=="1" exit /b 1
exit /b 0

:show_access
call :get_env "FUSIONWEB_HTTP_PORT"
set "HTTP_PORT=!ENV_VALUE!"
if not defined HTTP_PORT set "HTTP_PORT=8756"
call :get_env "FUSIONWEB_HTTPS_PORT"
set "HTTPS_PORT=!ENV_VALUE!"
if not defined HTTPS_PORT set "HTTPS_PORT=8988"
call :get_env "FUSIONWEB_BASIC_USER"
set "BASIC_USER=!ENV_VALUE!"
if not defined BASIC_USER set "BASIC_USER=admin"
echo [FusionWeb] FusionWeb 已启动。
echo   HTTP : http://localhost:!HTTP_PORT!
echo   HTTPS: https://localhost:!HTTPS_PORT!
call :get_env "FUSIONWEB_BASIC_PASS"
set "BASIC_PASS_DISPLAY=!ENV_VALUE!"
if not defined BASIC_PASS_DISPLAY (
  echo [FusionWeb] 未找到 FUSIONWEB_BASIC_PASS，请先运行 install 生成随机密码。
  set "BASIC_PASS_DISPLAY=<未生成>"
)
echo   Basic Auth 用户名: !BASIC_USER!
echo   Basic Auth 密码: !BASIC_PASS_DISPLAY!
echo   首次访问自签证书时，浏览器会要求确认。
exit /b 0

:require_runtime_env
if not exist "%ENV_FILE%" (
  echo [FusionWeb] 尚未创建 %ENV_FILE%，请先运行 fusionweb.bat install。
  exit /b 1
)
call :validate_image_prefix
if errorlevel 1 exit /b 1
call :sync_remote_connection_env
exit /b %errorlevel%

:install
call :check_docker
if errorlevel 1 exit /b 1
call :ensure_env
if errorlevel 1 exit /b 1
call :validate_image_prefix
if errorlevel 1 exit /b 1
call :sync_remote_connection_env
if errorlevel 1 exit /b 1
call :validate_compose
if errorlevel 1 exit /b 1
echo [FusionWeb] 正在拉取六个 linux/amd64 镜像……
call :set_compose_args
if errorlevel 1 exit /b 1
docker compose !COMPOSE_ARGS! pull
if errorlevel 1 (
  echo [FusionWeb] 镜像拉取失败。请确认 ACR 仓库已公开、命名空间正确且镜像已发布。
  exit /b 1
)
echo [FusionWeb] 正在启动 PostgreSQL、Redis、MinIO、API、Web 和默认 Worker……
call :set_compose_args
if errorlevel 1 exit /b 1
docker compose !COMPOSE_ARGS! up -d --remove-orphans --wait --wait-timeout 600
if errorlevel 1 (
  echo [FusionWeb] 服务启动失败，请运行 fusionweb.bat logs 查看日志。
  exit /b 1
)
call :check_containers
if errorlevel 1 (
  echo [FusionWeb] 至少一个容器未正常运行。
  exit /b 1
)
call :show_access
exit /b 0

:start
call :check_docker
if errorlevel 1 exit /b 1
call :require_runtime_env
if errorlevel 1 exit /b 1
call :validate_compose
if errorlevel 1 exit /b 1
call :set_compose_args
if errorlevel 1 exit /b 1
docker compose !COMPOSE_ARGS! up -d --remove-orphans --wait --wait-timeout 600
if errorlevel 1 exit /b 1
call :check_containers
if errorlevel 1 exit /b 1
call :show_access
exit /b 0

:stop
call :check_docker
if errorlevel 1 exit /b 1
call :require_runtime_env
if errorlevel 1 exit /b 1
call :set_compose_args
if errorlevel 1 exit /b 1
docker compose !COMPOSE_ARGS! stop
if errorlevel 1 exit /b 1
echo [FusionWeb] FusionWeb 已停止，数据卷保留。
exit /b 0

:restart
call :check_docker
if errorlevel 1 exit /b 1
call :require_runtime_env
if errorlevel 1 exit /b 1
call :validate_compose
if errorlevel 1 exit /b 1
call :set_compose_args
if errorlevel 1 exit /b 1
docker compose !COMPOSE_ARGS! stop
if errorlevel 1 exit /b 1
call :set_compose_args
if errorlevel 1 exit /b 1
docker compose !COMPOSE_ARGS! up -d --remove-orphans --wait --wait-timeout 600
if errorlevel 1 exit /b 1
call :check_containers
if errorlevel 1 exit /b 1
call :show_access
exit /b 0

:status
call :check_docker
if errorlevel 1 exit /b 1
call :require_runtime_env
if errorlevel 1 exit /b 1
call :set_compose_args
if errorlevel 1 exit /b 1
docker compose !COMPOSE_ARGS! ps
call :check_containers
exit /b %errorlevel%

:normalize_service
set "LOG_SERVICE=%~1"
if /I "!LOG_SERVICE!"=="api" set "LOG_SERVICE=fusionweb-api"
if /I "!LOG_SERVICE!"=="web" set "LOG_SERVICE=fusionweb-web"
if /I "!LOG_SERVICE!"=="worker" set "LOG_SERVICE=fusionweb-worker"
if /I "!LOG_SERVICE!"=="all" set "LOG_SERVICE="
if "!LOG_SERVICE!"=="" exit /b 0
for %%S in (postgres redis minio fusionweb-api fusionweb-web fusionweb-worker) do if /I "!LOG_SERVICE!"=="%%S" exit /b 0
echo [FusionWeb] 未知服务：%~1。可选：postgres redis minio api web worker all
exit /b 1

:logs
call :check_docker
if errorlevel 1 exit /b 1
call :require_runtime_env
if errorlevel 1 exit /b 1
set "REQUESTED_SERVICE=%~2"
if not defined REQUESTED_SERVICE set "REQUESTED_SERVICE=all"
call :normalize_service "!REQUESTED_SERVICE!"
if errorlevel 1 exit /b 1
if defined LOG_SERVICE (
  call :set_compose_args
if errorlevel 1 exit /b 1
  docker compose !COMPOSE_ARGS! logs -f --tail 200 "!LOG_SERVICE!"
) else (
  call :set_compose_args
if errorlevel 1 exit /b 1
  docker compose !COMPOSE_ARGS! logs -f --tail 200
)
exit /b %errorlevel%

:version
set "SOURCE_VERSION=unknown"
if exist "%VERSION_FILE%" call :read_source_version >nul 2>&1
set "DEPLOYED_VERSION=not-installed"
if exist "%ENV_FILE%" (
  call :get_env "FUSIONWEB_VERSION"
  if defined ENV_VALUE set "DEPLOYED_VERSION=!ENV_VALUE!"
)
echo FusionWeb 管理脚本: %SCRIPT_VERSION%
echo 源码 VERSION     : !SOURCE_VERSION!
echo 部署镜像版本     : !DEPLOYED_VERSION!
exit /b 0

:check_update
where git >nul 2>&1
if errorlevel 1 (
  echo [FusionWeb] 未检测到 git。
  exit /b 1
)
git rev-parse --is-inside-work-tree >nul 2>&1
if errorlevel 1 (
  echo [FusionWeb] 当前目录还不是 Git 仓库，无法检查远程更新。
  exit /b 1
)
call :read_source_version
if errorlevel 1 exit /b 1
set "LOCAL_VERSION=!SOURCE_VERSION!"
if exist "%ENV_FILE%" (
  call :get_env "FUSIONWEB_VERSION"
  if defined ENV_VALUE set "LOCAL_VERSION=!ENV_VALUE!"
)
git fetch --quiet origin
if errorlevel 1 (
  echo [FusionWeb] git fetch 失败。
  exit /b 1
)
set "UPSTREAM="
for /f "usebackq delims=" %%I in (`git rev-parse --abbrev-ref --symbolic-full-name "@{u}" 2^>nul`) do set "UPSTREAM=%%I"
if not defined UPSTREAM set "UPSTREAM=origin/main"
set "REMOTE_VERSION="
for /f "usebackq tokens=* delims=" %%I in (`git show "!UPSTREAM!:VERSION" 2^>nul`) do if not defined REMOTE_VERSION set "REMOTE_VERSION=%%I"
if not defined REMOTE_VERSION (
  echo [FusionWeb] 无法从 !UPSTREAM! 读取 VERSION。
  exit /b 1
)
echo 当前部署版本: !LOCAL_VERSION!
echo 远程仓库版本: !REMOTE_VERSION!
if "!LOCAL_VERSION!"=="!REMOTE_VERSION!" (
  echo [FusionWeb] 当前已是目标版本。
) else (
  echo [FusionWeb] 发现版本差异，可运行 fusionweb.bat upgrade。
)
exit /b 0

:upgrade
call :check_docker
if errorlevel 1 exit /b 1
where git >nul 2>&1
if errorlevel 1 (
  echo [FusionWeb] 未检测到 git。
  exit /b 1
)
git rev-parse --is-inside-work-tree >nul 2>&1
if errorlevel 1 (
  echo [FusionWeb] 当前目录不是 Git 仓库，无法执行安全升级。
  exit /b 1
)
set "DIRTY="
for /f "usebackq delims=" %%I in (`git status --porcelain`) do if not defined DIRTY set "DIRTY=%%I"
if defined DIRTY (
  echo [FusionWeb] Git 工作区存在未提交修改。请先提交、暂存到其他分支或还原修改。
  exit /b 1
)
if not exist "%ENV_FILE%" (
  echo [FusionWeb] 尚未安装，请先运行 fusionweb.bat install。
  exit /b 1
)
call :get_env "FUSIONWEB_VERSION"
set "OLD_VERSION=!ENV_VALUE!"
if not defined OLD_VERSION (
  call :read_source_version
  if errorlevel 1 exit /b 1
  set "OLD_VERSION=!SOURCE_VERSION!"
)
echo [FusionWeb] 正在执行 git pull --ff-only……
git pull --ff-only
if errorlevel 1 (
  echo [FusionWeb] Git 快进更新失败，未改动运行中的容器。
  exit /b 1
)
call :read_source_version
if errorlevel 1 exit /b 1
set "NEW_VERSION=!SOURCE_VERSION!"
call :set_env "FUSIONWEB_VERSION" "!NEW_VERSION!"
if errorlevel 1 exit /b 1
call :validate_image_prefix
if errorlevel 1 exit /b 1
call :sync_remote_connection_env
if errorlevel 1 exit /b 1
call :validate_compose
if errorlevel 1 exit /b 1
echo [FusionWeb] 正在从 !OLD_VERSION! 升级到 !NEW_VERSION!……
call :set_compose_args
if errorlevel 1 exit /b 1
docker compose !COMPOSE_ARGS! pull
if errorlevel 1 goto :upgrade_failed
call :set_compose_args
if errorlevel 1 exit /b 1
docker compose !COMPOSE_ARGS! up -d --remove-orphans --wait --wait-timeout 600
if errorlevel 1 goto :upgrade_failed
call :check_containers
if errorlevel 1 goto :upgrade_failed
echo [FusionWeb] 升级完成：!OLD_VERSION! -^> !NEW_VERSION!。
exit /b 0

:upgrade_failed
call :set_env "FUSIONWEB_VERSION" "!OLD_VERSION!" >nul 2>&1
echo [FusionWeb] 升级失败，%ENV_FILE% 已恢复为旧镜像版本 !OLD_VERSION!，数据卷未删除。
echo [FusionWeb] 回滚命令：fusionweb.bat start
exit /b 1

:uninstall
call :check_docker
if errorlevel 1 exit /b 1
if not exist "%ENV_FILE%" (
  echo [FusionWeb] 未找到 %ENV_FILE%。
  exit /b 1
)
echo 警告：此操作会删除 FusionWeb 六个容器以及 PostgreSQL、Redis、MinIO、应用、密钥和 SSL 数据卷。
echo 源码目录、VERSION 和 .env 不会被删除。
set "DELETE_CONFIRM="
set /p "DELETE_CONFIRM=请输入 DELETE 确认永久删除数据: "
if not "!DELETE_CONFIRM!"=="DELETE" (
  echo [FusionWeb] 已取消卸载。
  exit /b 0
)
call :set_compose_args
if errorlevel 1 exit /b 1
docker compose !COMPOSE_ARGS! down -v --remove-orphans
if errorlevel 1 exit /b 1
echo [FusionWeb] 容器和数据卷已删除；源码与 .env 已保留。
exit /b 0

:help
echo FusionWeb 一键管理脚本
echo.
echo 用法：fusionweb.bat ^<command^> [service]
echo.
echo 命令：
echo   install       初始化 .env、生成密钥、拉取并启动六个服务
echo   upgrade       Git 快进更新后切换 VERSION 镜像，不删除数据卷
echo   check-update  比较当前部署版本与 Git 上游 VERSION
echo   start         启动或重建服务并等待就绪
echo   stop          停止服务，保留容器和数据卷
echo   restart       重启全部服务并等待就绪
echo   status        显示 Compose 和六个容器状态
echo   logs [name]   跟踪全部或指定服务日志
echo   version       显示管理脚本、源码和部署版本
echo   uninstall     确认后删除容器及全部数据卷，保留源码和 .env
echo   help          显示帮助
echo.
echo 日志服务名：postgres、redis、minio、api、web、worker、all
exit /b 0


