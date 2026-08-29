'use client'

import * as React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Check, CheckCircle2, Clipboard, KeyRound, Pencil, Plus, RefreshCw, Server, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { deleteWorker, getWorkerInstallCommand, getWorkers, updateWorker, type WorkerInstallCommand, type WorkerInstallSteps, type WorkerNode } from '@/lib/api'
import { asList, formatTime, unwrap } from '@/lib/utils'
import { Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, EmptyState, Input, Modal, Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui'

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

function getWorkerLabel(worker: WorkerNode) {
  const displayName = String(worker.displayName || '').trim()
  return displayName || worker.name
}

function getWorkerPublicIP(worker: WorkerNode) {
  return String(worker.publicIpAddress || worker.ipAddress || '').trim()
}

function hasCustomWorkerLabel(worker: WorkerNode) {
  return String(worker.displayName || '').trim() !== '' && String(worker.displayName || '').trim() !== worker.name
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

function InstallField({
  label,
  value,
  hint,
  copyLabel,
  tone = 'default',
}: {
  label: string
  value: string
  hint?: string
  copyLabel?: string
  tone?: 'default' | 'accent'
}) {
  const valueClassName = tone === 'accent'
    ? 'border-warning/30 bg-warning/10 text-warning-foreground'
    : 'border-border bg-background text-foreground'

  return (
    <div className="grid gap-2 md:grid-cols-[92px_minmax(0,1fr)] md:items-start">
      <div className="pt-2 text-sm font-medium text-foreground">{label}</div>
      <div className="grid gap-1.5">
        <div className={`flex min-h-11 items-center justify-between gap-3 rounded-card border px-3 py-2 ${valueClassName}`}>
          <div className="min-w-0 break-all font-mono text-sm">{value || '-'}</div>
          {copyLabel ? (
            <Button size="sm" variant="outline" onClick={() => copyText(value, copyLabel)} disabled={!value}>
              <Clipboard className="size-4" />
              复制
            </Button>
          ) : null}
        </div>
        {hint ? <div className="text-xs leading-5 text-muted">{hint}</div> : null}
      </div>
    </div>
  )
}

function CommandStep({ index, title, value, label }: { index: number; title: string; value: string; label: string }) {
  return (
    <div className="grid gap-2 rounded-card border border-border bg-background p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="text-sm font-medium text-foreground">{index}. {title}</div>
        <Button size="sm" variant="outline" onClick={() => copyText(value, label)} disabled={!value}>
          <Clipboard className="size-4" />
          复制
        </Button>
      </div>
      <pre className="overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-card px-3 py-3 font-mono text-xs leading-6 text-foreground">{value || '暂无内容'}</pre>
    </div>
  )
}

function CommonOperationCard({ title, value, label }: { title: string; value: string; label: string }) {
  return (
    <div className="grid gap-2 rounded-card border border-border bg-background p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="text-sm font-medium text-foreground">{title}</div>
        <Button size="sm" variant="outline" onClick={() => copyText(value, label)} disabled={!value}>
          <Clipboard className="size-4" />
          复制
        </Button>
      </div>
      <pre className="overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-card px-3 py-3 font-mono text-xs leading-6 text-foreground">{value || '暂无内容'}</pre>
    </div>
  )
}

function CommandSteps({ title, commands }: { title: string; commands?: WorkerInstallSteps }) {
  if (!commands) return null
  return (
    <div className="grid gap-4">
      <div className="text-sm text-muted">{title}。默认会自动生成 <code>fusionweb-worker</code> 目录；如需自定义节点名，可在执行前额外设置 <code>FUSIONWEB_NAME</code>。</div>
      <div className="grid gap-3">
        <CommandStep index={1} title="下载部署脚本" value={commands.download} label={`${title} - 下载部署脚本`} />
        <CommandStep index={2} title="启动 Worker" value={commands.run} label={`${title} - 启动 Worker`} />
        <CommandStep index={3} title="一键执行" value={commands.oneLiner} label={`${title} - 一键执行`} />
      </div>
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
  const [platform, setPlatform] = React.useState<'linux' | 'windowsPowerShell' | 'windowsCmd'>('linux')
  React.useEffect(() => {
    if (open) setPlatform('linux')
  }, [open])

  const data = query.data
  const statusTone = data?.ready ? 'success' : 'danger'
  const statusLabel = data?.ready ? '可直接部署' : '需先补齐主节点远程访问'
  const activeCommands = platform === 'linux' ? data?.linux : platform === 'windowsPowerShell' ? data?.windowsPowerShell : data?.windowsCmd

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title="安装 Worker 探针"
      className="max-w-6xl"
    >
      {query.isLoading ? (
        <div className="flex min-h-52 items-center justify-center text-sm text-muted"><RefreshCw className="mr-2 size-4 animate-spin" />正在生成部署代码...</div>
      ) : query.isError ? (
        <EmptyState title="部署代码生成失败" description={(query.error as any)?.message || '请检查 API 和 Worker 配置'} />
      ) : (
        <div className="grid gap-5">
          <div className="rounded-card border border-success/30 bg-success/10 px-4 py-3 text-sm leading-6 text-success-foreground">
            保留连接信息，复制下面任一平台的三段命令即可完成 Worker 部署。
          </div>

          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            <Metric label="部署状态" value={<Badge tone={statusTone as any}>{statusLabel}</Badge>} />
            <Metric label="Worker 镜像" value={data?.image || '-'} />
            <Metric label="主节点连接" value={data?.server || '-'} />
          </div>

          <Card>
            <CardContent className="grid gap-4 p-5">
              <InstallField label="安装密钥" value={data?.workerKey || '-'} copyLabel="安装密钥" tone="accent" />
              <InstallField label="服务地址" value={data?.server || '-'} hint="Worker 回连主节点 API 的地址" copyLabel="服务地址" />
              <InstallField label="PostgreSQL 地址" value={data?.pgDsn || '-'} hint="Worker 直连任务数据库地址" copyLabel="PostgreSQL 地址" />
              <InstallField label="Redis 地址" value={data?.redisAddr || '-'} hint="Worker 直连调度层地址" copyLabel="Redis 地址" />
              <InstallField label="MinIO 地址" value={data?.minioEndpoint || '-'} hint="Worker 直连对象存储地址" copyLabel="MinIO 地址" />
            </CardContent>
          </Card>

          {!data?.ready ? (
            <div className="grid gap-4">
              <div className="rounded-card border border-danger/30 bg-danger/10 p-4 text-sm leading-6 text-danger">
                <div className="flex items-center gap-2 font-semibold"><AlertTriangle className="size-4" />当前还不能直接安装远程 Worker</div>
                <div className="mt-1">先把主节点对远程 Worker 所需的 API、PostgreSQL、Redis、MinIO 访问准备好，再重新打开本弹窗即可得到可直接执行的命令。</div>
              </div>

              {data?.missing?.length ? (
                <div className="rounded-card border border-danger/30 bg-danger/5 p-4">
                  <div className="text-sm font-semibold text-danger">待补齐项</div>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {data.missing.map((item) => <Badge key={item} tone="danger">{item}</Badge>)}
                  </div>
                </div>
              ) : null}

              {data?.warnings?.map((warning) => (
                <div key={warning} className="rounded-card border border-warning/30 bg-warning/10 p-4 text-sm leading-6 text-warning-foreground">{warning}</div>
              ))}

              <CommandPanel value={data?.suggestedEnv || ''} label="主节点 .env 建议片段" />
            </div>
          ) : (
            <>
              {data?.needsRemoteAccess ? (
                <div className="rounded-card border border-warning/30 bg-warning/10 p-4 text-sm leading-6 text-warning-foreground">
                  当前远程 Worker 使用的是主节点自带 PostgreSQL / Redis / MinIO。请确认主节点已经叠加 <code>docker-compose.remote-access.yaml</code> 并放行内网端口。
                </div>
              ) : null}

              {data?.warnings?.map((warning) => (
                <div key={warning} className="rounded-card border border-warning/30 bg-warning/10 p-4 text-sm leading-6 text-warning-foreground">{warning}</div>
              ))}

              <div className="rounded-card border border-border bg-card p-4">
                <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-foreground"><KeyRound className="size-4" />Docker 部署命令</div>
                <Tabs value={platform} onValueChange={(value) => setPlatform(value as 'linux' | 'windowsPowerShell' | 'windowsCmd')}>
                  <TabsList>
                    <TabsTrigger value="linux">Linux / macOS</TabsTrigger>
                    <TabsTrigger value="windowsPowerShell">Windows PowerShell</TabsTrigger>
                    <TabsTrigger value="windowsCmd">Windows CMD</TabsTrigger>
                  </TabsList>
                  <TabsContent value="linux" className="mt-4"><CommandSteps title="Linux / macOS" commands={data?.linux} /></TabsContent>
                  <TabsContent value="windowsPowerShell" className="mt-4"><CommandSteps title="Windows PowerShell" commands={data?.windowsPowerShell} /></TabsContent>
                  <TabsContent value="windowsCmd" className="mt-4"><CommandSteps title="Windows CMD" commands={data?.windowsCmd} /></TabsContent>
                </Tabs>
              </div>

              <div className="grid gap-3">
                <div className="flex items-center gap-2 text-sm font-semibold text-foreground"><CheckCircle2 className="size-4" />常用操作</div>
                <div className="grid gap-3 md:grid-cols-2">
                  <CommonOperationCard title="查看日志" value={activeCommands?.logs || ''} label={`${platform} - 查看日志`} />
                  <CommonOperationCard title="停止 Worker" value={activeCommands?.stop || ''} label={`${platform} - 停止 Worker`} />
                  <CommonOperationCard title="重启 Worker" value={activeCommands?.restart || ''} label={`${platform} - 重启 Worker`} />
                  <CommonOperationCard title="更新 Worker" value={activeCommands?.upgrade || ''} label={`${platform} - 更新 Worker`} />
                </div>
              </div>

              <details className="rounded-card border border-border bg-background p-4">
                <summary className="cursor-pointer list-none text-sm font-medium text-foreground">高级方式：查看 docker-compose 模板</summary>
                <div className="mt-4 grid gap-3">
                  <div className="text-sm leading-6 text-muted">脚本会自动下载下面这份模板并写入远程机器的 <code>fusionweb-worker/docker-compose.yaml</code>，通常无需手工编辑。</div>
                  <CommandPanel value={data?.compose || ''} label="docker-compose.yaml 模板" />
                </div>
              </details>
            </>
          )}
        </div>
      )}
    </Modal>
  )
}

export function WorkersView() {
  const queryClient = useQueryClient()
  const [installOpen, setInstallOpen] = React.useState(false)
  const [renameTarget, setRenameTarget] = React.useState<WorkerNode | null>(null)
  const [renameValue, setRenameValue] = React.useState('')
  const workersQuery = useQuery({
    queryKey: ['workers'],
    queryFn: async () => asList<WorkerNode>(await getWorkers()),
    refetchInterval: 15_000,
  })
  const renameMutation = useMutation({
    mutationFn: ({ name, displayName }: { name: string; displayName: string }) => updateWorker(name, { displayName }),
    onSuccess: (_, variables) => {
      const normalized = variables.displayName.trim()
      toast.success(normalized ? '节点名称已更新' : '已恢复默认节点名称')
      queryClient.invalidateQueries({ queryKey: ['workers'] })
      setRenameTarget(null)
      setRenameValue('')
    },
    onError: (error: any) => toast.error(error?.message || '更新节点名称失败'),
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

  const openRenameModal = (worker: WorkerNode) => {
    setRenameTarget(worker)
    setRenameValue(String(worker.displayName || '').trim())
  }

  const submitRename = () => {
    if (!renameTarget || renameMutation.isPending) return
    renameMutation.mutate({ name: renameTarget.name, displayName: renameValue })
  }

  const removeWorker = (worker: WorkerNode) => {
    if (!window.confirm(`确定删除 Worker“${getWorkerLabel(worker)}”吗？该节点仍在运行时会在下一次心跳重新注册。`)) return
    removeMutation.mutate(worker.name)
  }

  return (
    <div className="grid gap-5">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-xl font-semibold text-foreground">节点管理</h1>
          <p className="mt-1 text-sm text-muted">查看默认和远程 Worker 状态，生成更简洁的 Windows / Linux 一键部署命令，并检查远程节点依赖的数据库、Redis、对象存储连接信息。</p>
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
              <table className="w-full min-w-[1280px] text-left text-sm">
                <thead className="border-b border-border bg-raised/50 text-xs text-muted">
                  <tr>
                    <th className="px-4 py-3 font-medium">节点</th><th className="px-4 py-3 font-medium">公网 IP</th><th className="px-4 py-3 font-medium">状态</th><th className="px-4 py-3 font-medium">平台</th><th className="px-4 py-3 font-medium">任务</th><th className="px-4 py-3 font-medium">CPU</th><th className="px-4 py-3 font-medium">内存</th><th className="px-4 py-3 font-medium">最近心跳</th><th className="px-4 py-3 text-right font-medium">操作</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {workers.map((worker) => (
                    <tr key={worker.name} className="hover:bg-raised/35">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-3">
                          <span className="flex size-8 items-center justify-center rounded-md border border-border bg-background"><Server className="size-4" /></span>
                          <div className="group min-w-0">
                            <div className="flex min-w-0 items-center gap-1.5">
                              <div className="truncate font-medium text-foreground">{getWorkerLabel(worker)}</div>
                              <Button
                                size="icon"
                                variant="ghost"
                                title="修改节点名称"
                                className="size-6 shrink-0 opacity-0 transition-opacity duration-150 group-hover:opacity-100 focus-visible:opacity-100"
                                onClick={() => openRenameModal(worker)}
                              >
                                <Pencil className="size-3.5 text-primary" />
                              </Button>
                            </div>
                            {hasCustomWorkerLabel(worker) ? <div className="mt-0.5 text-xs text-muted">标识 {worker.name}</div> : null}
                            <div className="mt-0.5 text-xs text-muted">{worker.version || 'version unknown'}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3"><div className="font-mono text-xs text-foreground">{getWorkerPublicIP(worker) || '-'}</div><div className="mt-1 text-xs text-muted">公网地址</div></td>
                      <td className="px-4 py-3"><Badge tone={worker.status === 'online' ? 'success' : 'danger'}>{worker.status === 'online' ? <Check className="mr-1 size-3" /> : null}{worker.status === 'online' ? '在线' : '离线'}</Badge></td>
                      <td className="px-4 py-3"><div className="font-mono text-xs text-foreground">{worker.os || '-'} / {worker.arch || '-'}</div><div className="mt-1 text-xs text-muted">并发 {worker.concurrency || 0}</div></td>
                      <td className="px-4 py-3"><div className="text-foreground">活跃 {worker.activeTasks || 0}</div><div className="mt-1 text-xs text-muted">完成 {worker.completedTasks || 0}</div></td>
                      <td className="px-4 py-3"><UsageBar value={worker.cpuPercent} /></td>
                      <td className="px-4 py-3"><UsageBar value={worker.memoryPercent} /></td>
                      <td className="px-4 py-3"><div className="whitespace-nowrap text-xs text-foreground">{formatTime(worker.lastHeartbeat)}</div><div className="mt-1 whitespace-nowrap text-xs text-muted">注册 {formatTime(worker.registeredAt)}</div></td>
                      <td className="px-4 py-3 text-right"><div className="flex justify-end gap-2"><Button size="icon" variant="danger" title="删除节点" disabled={removeMutation.isPending} onClick={() => removeWorker(worker)}><Trash2 className="size-4" /></Button></div></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
      <InstallModal open={installOpen} onOpenChange={setInstallOpen} />
      <Modal
        open={!!renameTarget}
        onOpenChange={(open) => {
          if (!open && !renameMutation.isPending) {
            setRenameTarget(null)
            setRenameValue('')
          }
        }}
        title="修改节点名称"
        description="修改后的名称会显示在节点列表和节点选择器中；留空可恢复为默认节点标识。"
        footer={(
          <>
            <Button variant="outline" onClick={() => { setRenameTarget(null); setRenameValue('') }} disabled={renameMutation.isPending}>取消</Button>
            <Button variant="default" onClick={submitRename} disabled={renameMutation.isPending}>
              {renameMutation.isPending ? '保存中...' : '保存'}
            </Button>
          </>
        )}
      >
        <div className="grid gap-4">
          <div className="rounded-card border border-border bg-background px-4 py-3 text-sm text-muted">
            当前节点标识：<span className="font-mono text-foreground">{renameTarget?.name || '-'}</span>
          </div>
          <label className="grid gap-2">
            <span className="text-sm font-medium text-foreground">节点显示名称</span>
            <Input
              value={renameValue}
              onChange={(event) => setRenameValue(event.target.value)}
              placeholder={renameTarget?.name || '请输入节点名称'}
              maxLength={64}
              autoFocus
              onKeyDown={(event) => {
                if (event.key === 'Enter') {
                  event.preventDefault()
                  submitRename()
                }
              }}
            />
            <span className="text-xs leading-5 text-muted">支持 64 个字符以内，留空后保存会恢复默认节点标识。</span>
          </label>
        </div>
      </Modal>
    </div>
  )
}
