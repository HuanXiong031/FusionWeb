# FusionWeb Docker 前后端分离运行说明

FusionWeb 使用 Docker Compose 部署，运行配置来自环境变量和 `.env`，不读取 `config.yaml`，也不把前端嵌入 Go 二进制。

## 生产部署

Linux：

```bash
./fusionweb.sh install
```

Windows：

```bat
fusionweb.bat install
```

生产 `docker-compose.yaml` 只引用阿里云 ACR 中的六个镜像，不包含业务服务 `build:`。主 Compose 包含：

- PostgreSQL；
- Redis；
- MinIO；
- API；
- Web；
- 默认 Worker。

访问地址：

- HTTP：`http://localhost:8756`，自动跳转 HTTPS；
- HTTPS：`https://localhost:8988`；
- API：Nginx 通过 `/api/` 反向代理到内部 `fusionweb-api:8082`；
- WebSocket：Nginx 通过 `/ws` 反向代理。

## 远程 Worker 网络开放

主 `docker-compose.yaml` 默认不向宿主机映射 PostgreSQL、Redis、MinIO 端口。只有确实需要远程 Worker 直连时，才叠加：

```bash
docker compose -f docker-compose.yaml -f docker-compose.remote-access.yaml --env-file .env up -d
```

同时在 `.env` 设置：

- `FUSIONWEB_INFRA_BIND`：优先使用 VPN/内网地址；
- `FUSIONWEB_WORKER_EXTERNAL_PG_DSN`；
- `FUSIONWEB_WORKER_EXTERNAL_REDIS_ADDR`；
- `FUSIONWEB_WORKER_EXTERNAL_MINIO_ENDPOINT`。

Compose 会自动把当前 ACR Worker 镜像注入 API。配置完成后重启 `fusionweb-api`，前端“节点管理”页面才会把远程 Worker 一键命令标记为可用。

## 本地开发

```powershell
./dev.ps1
```

或直接运行开发覆盖层：

```bash
docker compose -f docker-compose.yaml -f docker-compose.dev.yaml --env-file .env up -d --build
```

`dev.ps1` 会加载 `.env`、启动开发依赖，并为本地 API 和 Worker 设置环境变量。前端可在 `frontend` 目录单独运行开发服务器。

## 配置原则

完整变量见根目录 `.env.example`。真实 `.env` 不进入镜像、不提交 Git，管理脚本不会覆盖已有密码，只会补齐缺失值或替换模板中的弱默认值。

## 常用排查命令

```bash
./fusionweb.sh status
./fusionweb.sh logs api
./fusionweb.sh logs web
./fusionweb.sh logs worker
```

Windows 将入口替换为 `fusionweb.bat`。
