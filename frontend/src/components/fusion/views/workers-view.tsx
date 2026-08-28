'use client'

import * as React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, Clipboard, Plus, RefreshCw, Server, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { deleteWorker, getWorkerInstallCommand, getWorkers, type WorkerInstallCommand, type WorkerNode } from '@/lib/api'
import { asList, formatTime, unwrap } from '@/lib/utils'
import { Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, EmptyState, Modal, Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui'

async function copyText(value: string, label: string) {
  try {
    await navigator.clipboard.writeText(value)
    toast.success(`已复制${label}`)
  } catch {
    const textarea = document.createElement('textarea')
    textarea.value = value
    textarea.style.position = 'fixed'
    textarea.style.opacity = '0'
    document.body.appendChild(textarea)
    textarea.select()
    document.execCommand('copy')
    textarea.remove()
    toast.success(`已复制${label}`)
  }
}

function Metric({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-card border border-border bg-background px-3 py-2">
      <div className="text-xs text-muted">{label}</div>
      <div className="mt-1 break-all text-sm font-semibold text-foreground">{value}</div>
    </div>
  )
}

function UsageBar({ value }: { value: number }) {
  const safe = Math.max(0, Math.min(100, Number.isFinite(value) ? value : 0))
  return (
    <div className="flex min-w-28 items-center gap-2">
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-raised">
        <div className="h-full rounded-full bg-info transition-[width]" style={{ width: `${safe}%` }} />
      </div>
      <span className="w-12 text-right font-mono text-xs text-muted">{safe.toFixed(1)}%</span>
    </div>
  )
}

function CommandPanel({ value, label }: { value: string; label: string }) {
  return (
    <div className="grid gap-2">
      <div className="flex items-center justify-between gap-3">
        <span className="text-sm font-medium text-foreground">{label}</span>
        <Button size="sm" variant="outline" onClick={() => copyText(value, label)} disabled={!value}>
          <Clipboard className="size-4" />
          复制
        </Button>
      </div>
      <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-card border border-border bg-background p-4 font-mono text-xs leading-6 text-foreground">{value || '暂无内容'}</pre>
    </div>
  )
}

function InstallModal({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const query = useQuery({
    queryKey: ['worker-install-command'],
    queryFn: async () => unwrap<WorkerInstallCommand>(await getWorkerInstallCommand()),
    enabled: open,
    staleTime: 30_000,
  })
  const data = query.data
  const statusTone = data?.ready ? 'success' : 'danger'
  const statusLabel = data?.ready ? '可直接部署' : '需先补齐远程访问'

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title="添加远程 Worker"
      description="在目标机器执行对应命令即可生成 Compose 文件并启动 Worker 容器。下方会同时展示主节点 API、PostgreSQL、Redis、MinIO 的远程连接信息。"
      className="max-w-5xl"
    >
      {query.isLoading ? (
        <div className="flex min-h-52 items-center justify-center text-sm text-muted"><RefreshCw className="mr-2 size-4 animate-spin" />正在生成部署代码...</div>
      ) : query.isError ? (
        <EmptyState title="部署代码生成失败" description={(query.error as any)?.message || '请检查 API 和 Worker 配置'} />
      ) : (
        <div className="grid gap-5">
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            <Metric label="部署状态" value={<Badge tone={statusTone as any}>{statusLabel}</Badge>} />
            <Metric label="主节点 API" value={data?.server || '-'} />
            <Metric label="Worker 镜像" value={data?.image || '-'} />
            <Metric label="PostgreSQL" value={data?.pgDsn || '-'} />
            <Metric label="Redis" value={data?.redisAddr || '-'} />
            <Metric label="MinIO" value={data?.minioEndpoint || '-'} />
          </div>

          {data?.ready ? (
            <div className="rounded-card border border-success/30 bg-success/10 p-3 text-sm leading-6 text-success-foreground">
              部署代码已生成。远程 Worker 需要同时访问主节点 API、PostgreSQL、Redis 和 MinIO；建议只在内网/VPN 环境使用这些命令。
            </div>
          ) : (
            <div className="rounded-card border border-danger/30 bg-danger/10 p-3 text-sm leading-6 text-danger">
              <div className="font-semibold">当前还不能直接添加远程节点</div>
              <div className="mt-1">请先按下方建议修改主节点 .env，并使用 remote-access 覆盖层重启主节点；修改完成后重新打开本弹窗即可得到可用命令。</div>
            </div>
          )}

          {data?.needsRemoteAccess ? (
            <div className="rounded-card border border-warning/30 bg-warning/10 p-3 text-sm leading-6 text-warning-foreground">
              当前命令使用的是主节点自带 PostgreSQL / Redis / MinIO。远程 Worker 接入前，主节点通常需要叠加 <code>docker-compose.remote-access.yaml</code> 暴露基础设施端口。
            </div>
          ) : null}

          {data?.missing?.length ? (
            <div className="rounded-card border border-danger/30 bg-danger/5 p-3">
              <div className="text-sm font-semibold text-danger">待补齐项</div>
              <div className="mt-2 flex flex-wrap gap-2">
                {data.missing.map((item) => <Badge key={item} tone="danger">{item}</Badge>)}
              </div>
            </div>
          ) : null}

          {data?.warnings?.map((warning) => (
            <div key={warning} className="rounded-card border border-warning/30 bg-warning/10 p-3 text-sm leading-6 text-warning-foreground">{warning}</div>
          ))}

          <Tabs defaultValue="linux">
            <TabsList>
              <TabsTrigger value="linux">Linux</TabsTrigger>
              <TabsTrigger value="windows">Windows PowerShell</TabsTrigger>
              <TabsTrigger value="compose">Docker Compose</TabsTrigger>
              <TabsTrigger value="env">.env 建议</TabsTrigger>
            </TabsList>
            <TabsContent value="linux"><CommandPanel value={data?.linux || ''} label="Linux 一键部署命令" /></TabsContent>
            <TabsContent value="windows"><CommandPanel value={data?.windows || ''} label="Windows 一键部署命令" /></TabsContent>
            <TabsContent value="compose"><CommandPanel value={data?.compose || ''} label="Docker Compose 配置" /></TabsContent>
            <TabsContent value="env"><CommandPanel value={data?.suggestedEnv || ''} label="主节点 .env 建议片段" /></TabsContent>
          </Tabs>
        </div>
      )}
    </Modal>
  )
}

export function WorkersView() {
  const queryClient = useQueryClient()
  const [installOpen, setInstallOpen] = React.useState(false)
  const workersQuery = useQuery({
    queryKey: ['workers'],
    queryFn: async () => asList<WorkerNode>(await getWorkers()),
    refetchInterval: 15_000,
  })
  const removeMutation = useMutation({
    mutationFn: deleteWorker,
    onSuccess: (_, name) => {
      toast.success(`节点 ${name} 已删除`)
      queryClient.invalidateQueries({ queryKey: ['workers'] })
    },
    onError: (error: any) => toast.error(error?.message || '删除节点失败'),
  })
  const workers = workersQuery.data || []
  const onlineCount = workers.filter((worker) => worker.status === 'online').length
  const totalConcurrency = workers.filter((worker) => worker.status === 'online').reduce((sum, worker) => sum + (worker.concurrency || 0), 0)
  const activeTasks = workers.reduce((sum, worker) => sum + (worker.activeTasks || 0), 0)

  const removeWorker = (worker: WorkerNode) => {
    if (!window.confirm(`确定删除 Worker“${worker.name}”吗？该节点仍在运行时会在下一次心跳重新注册。`)) return
    removeMutation.mutate(worker.name)
  }

  return (
    <div className="grid gap-5">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-xl font-semibold text-foreground">节点管理</h1>
          <p className="mt-1 text-sm text-muted">查看默认和远程 Worker 状态，生成 Windows / Linux 一键部署代码，并检查远程节点依赖的数据库、Redis、对象存储连接信息。</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => workersQuery.refetch()} disabled={workersQuery.isFetching}>
            <RefreshCw className={workersQuery.isFetching ? 'size-4 animate-spin' : 'size-4'} />
            刷新
          </Button>
          <Button variant="default" onClick={() => setInstallOpen(true)}>
            <Plus className="size-4" />
            添加节点
          </Button>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        <Card><CardContent className="p-4"><div className="text-xs text-muted">在线节点</div><div className="mt-2 text-2xl font-semibold">{onlineCount}<span className="ml-1 text-sm font-normal text-muted">/ {workers.length}</span></div></CardContent></Card>
        <Card><CardContent className="p-4"><div className="text-xs text-muted">可用并发</div><div className="mt-2 text-2xl font-semibold">{totalConcurrency}</div></CardContent></Card>
        <Card><CardContent className="p-4"><div className="text-xs text-muted">执行中任务</div><div className="mt-2 text-2xl font-semibold">{activeTasks}</div></CardContent></Card>
      </div>

      <Card>
        <CardHeader>
          <div>
            <CardTitle>Worker 节点</CardTitle>
            <CardDescription>每 15 秒自动刷新；超过 120 秒未上报心跳的节点标记为离线。</CardDescription>
          </div>
          {workersQuery.isSuccess ? <Badge tone={onlineCount === workers.length && workers.length > 0 ? 'success' : 'warning'}>{onlineCount} 在线</Badge> : null}
        </CardHeader>
        <CardContent className="p-0">
          {workersQuery.isLoading ? (
            <div className="flex min-h-56 items-center justify-center text-sm text-muted"><RefreshCw className="mr-2 size-4 animate-spin" />正在加载节点...</div>
          ) : workersQuery.isError ? (
            <div className="p-5"><EmptyState title="节点列表加载失败" description={(workersQuery.error as any)?.message || 'Redis 或 API 不可用'} /></div>
          ) : workers.length === 0 ? (
            <div className="p-5"><EmptyState title="暂无 Worker 节点" description="请确认默认 Worker 容器已经启动，或点击“添加节点”部署远程 Worker。" /></div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[1120px] text-left text-sm">
                <thead className="border-b border-border bg-raised/50 text-xs text-muted">
                  <tr>
                    <th className="px-4 py-3 font-medium">节点</th><th className="px-4 py-3 font-medium">状态</th><th className="px-4 py-3 font-medium">平台</th><th className="px-4 py-3 font-medium">任务</th><th className="px-4 py-3 font-medium">CPU</th><th className="px-4 py-3 font-medium">内存</th><th className="px-4 py-3 font-medium">最近心跳</th><th className="px-4 py-3 text-right font-medium">操作</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {workers.map((worker) => (
                    <tr key={worker.name} className="hover:bg-raised/35">
                      <td className="px-4 py-3"><div className="flex items-center gap-3"><span className="flex size-8 items-center justify-center rounded-md border border-border bg-background"><Server className="size-4" /></span><div><div className="font-medium text-foreground">{worker.name}</div><div className="mt-0.5 text-xs text-muted">{worker.version || 'version unknown'}</div></div></div></td>
                      <td className="px-4 py-3"><Badge tone={worker.status === 'online' ? 'success' : 'danger'}>{worker.status === 'online' ? <Check className="mr-1 size-3" /> : null}{worker.status === 'online' ? '在线' : '离线'}</Badge></td>
                      <td className="px-4 py-3"><div className="font-mono text-xs text-foreground">{worker.os || '-'} / {worker.arch || '-'}</div><div className="mt-1 text-xs text-muted">并发 {worker.concurrency || 0}</div></td>
                      <td className="px-4 py-3"><div className="text-foreground">活跃 {worker.activeTasks || 0}</div><div className="mt-1 text-xs text-muted">完成 {worker.completedTasks || 0}</div></td>
                      <td className="px-4 py-3"><UsageBar value={worker.cpuPercent} /></td>
                      <td className="px-4 py-3"><UsageBar value={worker.memoryPercent} /></td>
                      <td className="px-4 py-3"><div className="whitespace-nowrap text-xs text-foreground">{formatTime(worker.lastHeartbeat)}</div><div className="mt-1 whitespace-nowrap text-xs text-muted">注册 {formatTime(worker.registeredAt)}</div></td>
                      <td className="px-4 py-3 text-right"><Button size="icon" variant="danger" title="删除节点" disabled={removeMutation.isPending} onClick={() => removeWorker(worker)}><Trash2 className="size-4" /></Button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
      <InstallModal open={installOpen} onOpenChange={setInstallOpen} />
    </div>
  )
}
