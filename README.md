# FusionWeb

FusionWeb 是一个面向资产发现、端口扫描、Web 指纹识别、POC 验证与结果分析的安全扫描一体化平台，提供前端控制台、后端 API、默认 Worker 与一键部署脚本，支持本机扫描、远程节点管理和容器化生产部署。

## 项目概览

- **前端**：基于 Next.js + TypeScript 的安全扫描控制台
- **后端**：Go 编写的 API 与扫描流程服务
- **Worker**：独立扫描执行节点，支持单节点并发控制
- **存储**：PostgreSQL、Redis、MinIO
- **部署**：Linux / Windows 一键脚本 + Docker Compose

## 核心能力

- 资产发现与目标管理
- 端口扫描、Web 探测与指纹识别
- POC 验证与漏洞结果展示
- Worker 节点管理、名称修改与并发配置
- 默认本机 Worker 自动消费扫描流程
- 远程 Worker 一键部署与接入
- 生产环境镜像化部署
- Linux / Windows 管理脚本：安装、升级、状态、日志、卸载

## 软件总体流程图

```mermaid
flowchart TD
    U[用户在前端创建扫描任务] --> W[Web 前端提交请求]
    W --> A[API 接收任务并校验参数]
    A --> DB[(PostgreSQL 保存任务与结果)]
    A --> R[(Redis 写入任务队列与节点状态)]
    R --> WK[默认 Worker 或远程 Worker 消费任务]
    WK --> S1[资产发现]
    S1 --> S2[端口扫描 / Web 探测]
    S2 --> S3[指纹识别]
    S3 --> S4[POC 验证]
    S4 --> M[(MinIO 保存报告与产物)]
    S4 --> DB
    DB --> A
    A --> W
    W --> U2[用户查看进度与结果]
```

## 分流程图说明

### 1. 系统架构流程图

```mermaid
flowchart LR
    Browser[浏览器] --> Web[Web 前端]
    Web --> API[API 服务]
    API --> PG[(PostgreSQL)]
    API --> Redis[(Redis)]
    API --> MinIO[(MinIO)]
    Redis --> Worker[Worker 节点]
    Worker --> Redis
    Worker --> PG
    Worker --> MinIO
```

### 2. 扫描任务创建流程图

```mermaid
flowchart TD
    A1[用户填写目标与扫描参数] --> A2[前端发起创建任务请求]
    A2 --> A3[API 校验参数]
    A3 --> A4[写入任务记录]
    A4 --> A5[写入 Redis 队列]
    A5 --> A6[返回任务已创建]
    A6 --> A7[前端进入任务详情页]
```

### 3. Worker 消费任务流程图

```mermaid
flowchart TD
    B1[Worker 启动] --> B2[注册节点信息]
    B2 --> B3[上报心跳与并发能力]
    B3 --> B4[监听 Redis 队列]
    B4 --> B5{是否获取到任务}
    B5 -- 否 --> B4
    B5 -- 是 --> B6[锁定并执行任务]
    B6 --> B7[实时回传状态与进度]
    B7 --> B8[任务完成后释放并发]
    B8 --> B4
```

### 4. 扫描执行流程图

```mermaid
flowchart TD
    C1[读取任务目标] --> C2{扫描模式}
    C2 --> C3[资产发现]
    C3 --> C4[端口扫描]
    C4 --> C5[Web 探测]
    C5 --> C6[指纹识别]
    C6 --> C7[POC 验证]
    C7 --> C8[汇总扫描结果]
```

### 5. 结果写入与展示流程图

```mermaid
flowchart TD
    D1[Worker 产生结果] --> D2[写入 PostgreSQL]
    D1 --> D3[上传报告或产物到 MinIO]
    D2 --> D4[API 聚合任务结果]
    D3 --> D4
    D4 --> D5[WebSocket / API 返回前端]
    D5 --> D6[前端展示资产、漏洞、指纹与日志]
```

### 6. 远程 Worker 接入流程图

```mermaid
flowchart TD
    E1[管理员在节点管理中生成命令] --> E2[复制到 Linux 或 Windows 节点执行]
    E2 --> E3[远程节点拉取 Worker 镜像]
    E3 --> E4[写入连接参数与 Worker Key]
    E4 --> E5[Worker 启动并注册到主节点]
    E5 --> E6[主节点显示在线状态、IP、并发信息]
```

### 7. 一键部署流程图

```mermaid
flowchart TD
    F1[克隆 GitHub 仓库] --> F2[执行 fusionweb.sh install 或 fusionweb.bat install]
    F2 --> F3[检查 Docker / Compose 环境]
    F3 --> F4[生成 .env 与随机密钥]
    F4 --> F5[拉取 API、Web、Worker、PostgreSQL、Redis、MinIO 镜像]
    F5 --> F6[docker compose up -d --wait]
    F6 --> F7[输出访问地址与登录信息]
```

## 技术栈

- **前端**：Next.js、React、TypeScript、Tailwind CSS
- **后端**：Go、Gin
- **基础设施**：Docker、Docker Compose、PostgreSQL、Redis、MinIO

## 快速开始

### 生产部署

```bash
./fusionweb.sh install
```

Windows 环境使用：

```bat
fusionweb.bat install
```

### 开发模式

```bash
docker compose -f docker-compose.yaml -f docker-compose.dev.yaml --env-file .env up -d --build
```

## 目录结构

```text
api/        后端 API
backend/    核心业务与公共模块
frontend/   Web 前端
worker/     Worker 执行器
```
