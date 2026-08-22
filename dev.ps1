$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

if (-not (Test-Path -LiteralPath '.env')) {
    Copy-Item -LiteralPath '.env.example' -Destination '.env'
}

Get-Content -LiteralPath '.env' | ForEach-Object {
    $line = $_.Trim()
    if (-not $line -or $line.StartsWith('#') -or -not $line.Contains('=')) { return }
    $parts = $line.Split('=', 2)
    $key = $parts[0].Trim()
    $value = $parts[1].Trim().Trim('"').Trim("'")
    [Environment]::SetEnvironmentVariable($key, $value, 'Process')
}

function Value-OrDefault([string]$Value, [string]$Default) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Default }
    return $Value
}

docker compose -f docker-compose.yaml -f docker-compose.dev.yaml --env-file .env up -d postgres redis minio

$pgUser = Value-OrDefault $env:POSTGRES_USER 'fusionweb'
$pgPassword = Value-OrDefault $env:POSTGRES_PASSWORD 'fusionweb'
$pgPort = Value-OrDefault $env:FUSIONWEB_PG_PORT '5432'
$pgDatabase = Value-OrDefault $env:POSTGRES_DB 'fusionweb'
$redisPort = Value-OrDefault $env:FUSIONWEB_REDIS_PORT '6379'
$minioPort = Value-OrDefault $env:FUSIONWEB_MINIO_PORT '9000'

$env:FUSIONWEB_PG_DSN = "postgres://${pgUser}:${pgPassword}@localhost:${pgPort}/${pgDatabase}?sslmode=disable"
$env:FUSIONWEB_REDIS_ADDR = "localhost:${redisPort}"
$env:FUSIONWEB_REDIS_PASSWORD = Value-OrDefault $env:FUSIONWEB_REDIS_PASSWORD 'fusionweb'
$env:FUSIONWEB_MINIO_ENDPOINT = "http://localhost:${minioPort}"
$env:FUSIONWEB_MINIO_ACCESS_KEY = Value-OrDefault $env:FUSIONWEB_MINIO_ACCESS_KEY 'fusionweb'
$env:FUSIONWEB_MINIO_SECRET_KEY = Value-OrDefault $env:FUSIONWEB_MINIO_SECRET_KEY 'fusionweb-minio-secret'
$env:FUSIONWEB_WORKER_KEY = Value-OrDefault $env:FUSIONWEB_WORKER_KEY 'fusionweb-worker-key'
$env:FUSIONWEB_SERVER = "http://localhost:8082"
$env:FUSIONWEB_KEY = $env:FUSIONWEB_WORKER_KEY
$env:FUSIONWEB_NAME = Value-OrDefault $env:FUSIONWEB_WORKER_NAME 'default-worker-dev'
$env:FUSIONWEB_CONCURRENCY = Value-OrDefault $env:FUSIONWEB_WORKER_CONCURRENCY '5'
$env:FUSIONWEB_LOCAL_CONSUMER = 'false'
$env:FUSIONWEB_DATA_DIR = Join-Path $Root 'data'

Write-Host '基础依赖已启动，并已把 .env 导入当前 PowerShell 进程。'
Write-Host '请在此终端运行 API；Worker 和前端分别在其他终端启动：'
Write-Host '  go run .'
Write-Host '  go run ./worker'
Write-Host '  cd frontend; npm run dev'
