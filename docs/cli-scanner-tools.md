# Worker 扫描工具说明

FusionWeb 的扫描工具安装在 `fusionweb-worker` 镜像中，API 和 Web 镜像不包含扫描工具。默认 Worker 镜像提供：

- `nuclei`
- `httpx`
- `naabu`
- `subfinder`
- `dnsx`
- `ffuf`
- `nmap`
- `masscan`
- `chromium`

## 构建与发布

扫描工具在 GitHub Actions 构建 Worker 镜像时安装。部署服务器不下载源码、不执行 `go install`，也不现场编译扫描工具，只从阿里云 ACR 拉取已发布的 `linux/amd64` Worker 镜像。

Worker Dockerfile 为每个 Go 扫描工具使用独立多阶段构建，并通过 BuildKit/GitHub Actions Cache 复用模块和编译缓存。完整构建可能耗时较长，应交给 CI 完成。

生产部署：

```bash
./fusionweb.sh install
```

或：

```bat
fusionweb.bat install
```

仅开发时才使用源码构建覆盖层：

```bash
docker compose -f docker-compose.yaml -f docker-compose.dev.yaml --env-file .env up -d --build
```

## 工具解析规则

Worker 执行外部工具时按以下顺序解析：

1. 工具专用环境变量，例如 `FUSIONWEB_TOOL_NUCLEI`、`FUSIONWEB_TOOL_HTTPX`；
2. 容器或系统 `PATH`。

项目不维护根目录 `tools/`，也不使用 `FUSIONWEB_TOOLS_DIR` 或 Windows 单二进制旁的工具目录。

## 远程 Worker

远程节点使用与主节点相同的 ACR Worker 镜像。根目录提供 `docker-compose-worker.yaml`，前端“节点管理”页面会生成 Linux 和 Windows PowerShell 一键命令。命令先拉取镜像，再启动 Worker 并等待容器。

## 自定义工具

如需覆盖镜像内工具，可构建派生 Worker 镜像，或在 Worker 容器中挂载可执行文件并设置对应的 `FUSIONWEB_TOOL_<NAME>` 环境变量。
