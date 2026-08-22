'use client'

import * as React from 'react'
import { createPortal } from 'react-dom'
import { useForm } from 'react-hook-form'
import { z } from 'zod'
import { zodResolver } from '@hookform/resolvers/zod'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ColumnDef } from '@tanstack/react-table'
import { toast } from 'sonner'
import {
  Activity,
  Bell,
  Braces,
  Bug,
  Check,
  Code2,
  Copy,
  Database,
  Download,
  Edit3,
  Eye,
  FileCode2,
  FileDown,
  FileText,
  Fingerprint,
  FolderOpen,
  Globe2,
  History,
  Info,
  KeyRound,
  Layers3,
  LayoutDashboard,
  ListChecks,
  Loader2,
  LogOut,
  MapPin,
  Monitor,
  Moon,
  Network,
  Palette,
  PanelLeftClose,
  PanelLeftOpen,
  Pause,
  Play,
  Plus,
  RadioTower,
  RefreshCw,
  RotateCcw,
  Save,
  ScanLine,
  Search,
  Send,
  Settings,
  ShieldAlert,
  ShieldBan,
  ShieldCheck,
  SlidersHorizontal,
  Square,
  Sun,
  Terminal,
  Trash2,
  Upload,
  User,
  Users,
  X,
  XCircle,
} from 'lucide-react'
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import {
  addToBlacklist,
  addFingerprint,
  addManualVulnVerify,
  addVulnVerifyGroup,
  batchQueryIPs,
  batchCreateUsers,
  changePassword,
  createPocFile,
  createPocTask,
  createTask,
  createUser,
  debugScanPOC,
  deleteAllFingerprints,
  deleteFingerprint,
  deleteManualVulnVerify,
  deletePOC,
  deletePocFile,
  deletePocScanResult,
  deletePocTask,
  deleteTask,
  deleteUser,
  deleteVulnVerifyGroup,
  downloadPocReport,
  downloadUserImportTemplate,
  downloadTaskReport,
  executePocTask,
  exportAllPOCs,
  exportFingerprints,
  exportSelectedPOCs,
  exportSingleFingerprint,
  exportUsers,
  getBlacklistByCategory,
  getDashboardStats,
  getFingerprintCategories,
  getFingerprintResults,
  getFingerprintStatistics,
  getFingerprintsPage,
  getIPDBInfo,
  getManualVulnVerifyListByGroup,
  getPOCList,
  getPOCCategories,
  getPocFileContent,
  getPocScanResultDetail,
  getPocScanResultStatistics,
  getPocScanResults,
  getPocTaskDetail,
  getPocTaskList,
  getPocTaskProgress,
  getLoginLogs,
  getProfile,
  getReconResults,
  getTaskLogs,
  getTaskDetail,
  getTasks,
  getUsers,
  getVulnResults,
  getVulnVerifyWorkbench,
  getVulnVerifyGroups,
  importFingerprint,
  importPocFile,
  login,
  logout,
  pauseTask,
  pausePocTask,
  queryIP,
  removeFromBlacklist,
  reloadIPDB,
  renamePocFile,
  restartTask,
  resumeTask,
  resumePocTask,
  saveBlacklistByCategory,
  saveVulnVerifyWorkbench,
  sendRawRequest,
  stopTask,
  stopDebugScan,
  stopPocTask,
  toggleFingerprintEnabled,
  toggleFingerprintBlacklist,
  updateFingerprint,
  updateManualVulnVerify,
  updatePocFile,
  updateUser,
  updateVulnVerifyGroup,
  validatePOC,
  type DashboardStats,
  type FingerprintRow,
  type PocFileRow,
  type TaskConfig,
  type TaskRow,
  type UserProfile,
} from '@/lib/api'
import { asList, cn, compactNumber, formatTime, getStatusLabel, getStatusTone, parseTargets, unwrap } from '@/lib/utils'
import { Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Drawer, EmptyState, Field, Input, Modal, Select, Tabs, TabsContent, TabsList, TabsTrigger, Textarea } from '@/components/ui'
import { DataTable } from '@/components/data-table'
import { CodeEditor } from '@/components/code-editor'
import {
  demoStats,
  demoTasks,
  demoBlacklistData,
  demoWhitelistData,
  accessPolicyCategories,
  buildSeverityStats,
  getSeverityText,
  getSeverityTone,
  formatUnknown,
  getPocPath,
  downloadContent,
  downloadBlobResponse,
  downloadBlob,
  getFileNameFromDisposition,
  getReportFileName,
  getReportTypeLabel,
  normalizeIPRows,
  getIPDBStatusLabel,
  getIPDBFileName,
  readFileText,
  readFileBase64,
  toCsv,
  blacklistToYaml,
  getBlacklistCategoryLabel,
  normalizeBlacklistConfig,
  pickPolicyConfig,
  parseBlacklistContent,
  parseBatchUsers,
  pickVulnField,
  getVulnTarget,
  getVulnTemplateID,
  getVulnDisplayName,
  normalizeVulnDetail,
  LineNumberedCode,
  HttpCodePanel,
  CodeBlock,
  VulnDetailRow,
  getTaskColumns,
  getTaskId,
  getTaskDisplayName,
  getPocTaskId,
  getPocTaskDisplayName,
  getLogLevelTone,
  toTextList,
  PillList,
  getProgressTone,
  getProgressFillClass,
  getProgressTextClass,
  PageTitle,
  Metric,
  ToggleField,
  PreviewLine,
  SeverityBadge
} from '@/components/fusion/shared'

export function PocTasksView({ demoMode }: { demoMode: boolean }) {
  const queryClient = useQueryClient()
  const [selectedTaskId, setSelectedTaskId] = React.useState('')
  const [createOpen, setCreateOpen] = React.useState(false)
  const [selectorOpen, setSelectorOpen] = React.useState(false)
  const [pocKeyword, setPocKeyword] = React.useState('')
  const [selectedPocPaths, setSelectedPocPaths] = React.useState<string[]>([])
  const [draft, setDraft] = React.useState({ taskName: '', targets: '', selectedPocs: '', concurrency: 20, proxy: '' })
  const tasksQuery = useQuery({ queryKey: ['poc-tasks'], queryFn: () => getPocTaskList({ page: 1, pageSize: 300 }), enabled: !demoMode })
  const tasks = demoMode
    ? [
        { taskId: 'poc-demo-1', taskName: '核心站点 POC 验证', status: 'completed', progress: 100, targetCount: 2, pocCount: 4, found_vulns: 1, createdAt: '2026-07-05 10:20:00', targets: ['https://acme.com', 'https://api.acme.com'], pocs: ['rce/spring-rce.yaml', 'info/nginx-detect.yaml'] },
        { taskId: 'poc-demo-2', taskName: '网关弱点复测', status: 'running', progress: 62, targetCount: 1, pocCount: 2, found_vulns: 0, createdAt: '2026-07-05 10:38:00', targets: ['https://gateway.acme.com'], pocs: ['exposure/git-config.yaml'] },
      ]
    : asList<any>(tasksQuery.data)

  React.useEffect(() => {
    if (selectedTaskId || !tasks.length) return
    setSelectedTaskId(getPocTaskId(tasks[0]))
  }, [selectedTaskId, tasks])

  const selectedTask = tasks.find((task) => getPocTaskId(task) === selectedTaskId)
  const detailQuery = useQuery({ queryKey: ['poc-task-detail', selectedTaskId], queryFn: () => getPocTaskDetail(selectedTaskId), enabled: !!selectedTaskId && !demoMode })
  const progressQuery = useQuery({
    queryKey: ['poc-task-progress', selectedTaskId],
    queryFn: () => getPocTaskProgress(selectedTaskId),
    enabled: !!selectedTaskId && !demoMode,
    refetchInterval: 3000,
  })
  const resultsQuery = useQuery({
    queryKey: ['poc-task-results-preview', selectedTaskId],
    queryFn: () => getPocScanResults(selectedTaskId, { page: 1, pageSize: 10 }),
    enabled: !!selectedTaskId && !demoMode,
  })
  const pocsQuery = useQuery({
    queryKey: ['poc-task-selector-pocs', pocKeyword],
    queryFn: () => getPOCList({ page: 1, pageSize: 500, keyword: pocKeyword }),
    enabled: !demoMode,
  })
  const taskDetail = demoMode ? selectedTask : unwrap<any>(detailQuery.data) || selectedTask || {}
  const taskProgress = demoMode ? selectedTask : unwrap<any>(progressQuery.data) || taskDetail || {}
  const results = demoMode
    ? [{ id: 1, target: 'https://acme.com', name: 'Spring Actuator 暴露', severity: 'high', matched: true, createdAt: '2026-07-05 10:21:00' }]
    : asList<any>(resultsQuery.data)
  const pocRowsSource = demoMode
    ? [
        { category: 'rce', fileName: 'spring-rce.yaml', relativePath: 'rce/spring-rce.yaml', name: 'Spring RCE', severity: 'critical' },
        { category: 'info', fileName: 'nginx-detect.yaml', relativePath: 'info/nginx-detect.yaml', name: 'Nginx Detect', severity: 'info' },
        { category: 'exposure', fileName: 'git-config.yaml', relativePath: 'exposure/git-config.yaml', name: 'Git Config Exposure', severity: 'medium' },
      ]
    : asList<any>(pocsQuery.data)
  const pocRows = pocRowsSource.filter((row) => !pocKeyword.trim() || JSON.stringify(row).toLowerCase().includes(pocKeyword.trim().toLowerCase()))
  const taskTargets = toTextList(taskDetail?.targets || taskDetail?.targetList || taskDetail?.target_list || taskDetail?.targetInput || taskDetail?.target_input)
  const taskPocs = toTextList(taskDetail?.selectedPocs || taskDetail?.selected_pocs || taskDetail?.pocs || taskDetail?.templates)
  const runningTasks = tasks.filter((task) => ['running', 'pending', 'paused'].includes(String(task.status || '').toLowerCase())).length
  const vulnTotal = tasks.reduce((sum, task) => sum + Number(task.found_vulns || task.vulnCount || task.vuln_count || 0), 0)
  const selectedPocsFromDraft = React.useMemo(() => Array.from(new Set([...selectedPocPaths, ...parseTargets(draft.selectedPocs)])), [draft.selectedPocs, selectedPocPaths])

  const mutateTask = useMutation({
    mutationFn: async ({ action, task }: { action: string; task?: any }) => {
      if (demoMode) return { taskId: 'poc-demo-created' }
      const taskId = getPocTaskId(task) || selectedTaskId
      if (action === 'create') {
        if (!parseTargets(draft.targets).length) throw new Error('请输入验证目标')
        if (!selectedPocsFromDraft.length) throw new Error('请选择或填写 POC 模板')
        return createPocTask(
          draft.taskName.trim() || `POC任务_${Date.now()}`,
          parseTargets(draft.targets),
          selectedPocsFromDraft,
          { concurrency: Number(draft.concurrency) || 20, proxy: draft.proxy.trim() }
        )
      }
      if (!taskId) throw new Error('请选择模板任务')
      if (action === 'execute') return executePocTask(taskId)
      if (action === 'pause') return pausePocTask(taskId)
      if (action === 'resume') return resumePocTask(taskId)
      if (action === 'stop') return stopPocTask(taskId)
      if (action === 'delete') return deletePocTask(taskId)
      return null
    },
    onSuccess: (res: any, variables) => {
      const nextTaskId = unwrap<any>(res)?.taskId || unwrap<any>(res)?.task_id || res?.taskId || res?.task_id
      if (variables.action === 'create') {
        toast.success('模板任务已创建')
        setCreateOpen(false)
        setDraft({ taskName: '', targets: '', selectedPocs: '', concurrency: 20, proxy: '' })
        setSelectedPocPaths([])
        if (nextTaskId) setSelectedTaskId(nextTaskId)
      } else {
        toast.success('模板任务操作成功')
      }
      queryClient.invalidateQueries({ queryKey: ['poc-tasks'] })
      queryClient.invalidateQueries({ queryKey: ['poc-task-detail', selectedTaskId] })
      queryClient.invalidateQueries({ queryKey: ['poc-task-progress', selectedTaskId] })
    },
    onError: (error: any) => toast.error(error.message || '模板任务操作失败'),
  })
  const reportMutation = useMutation({
    mutationFn: async (type: 'html' | 'excel' | 'markdown') => {
      if (demoMode) return new Blob([`Demo ${type} report`], { type: 'text/plain' })
      return downloadPocReport(selectedTaskId, type)
    },
    onSuccess: (res: any, type) => {
      downloadBlobResponse(res, `poc-${selectedTaskId}.${type === 'excel' ? 'xlsx' : type === 'markdown' ? 'md' : 'html'}`)
      toast.success(`${getReportTypeLabel(type)} 报告已下载`)
    },
    onError: (error: any) => toast.error(error.message || '报告下载失败'),
  })
  const togglePocPath = (path: string) => {
    setSelectedPocPaths((current) => current.includes(path) ? current.filter((item) => item !== path) : [...current, path])
  }
  const taskColumns: ColumnDef<any>[] = [
    {
      header: '任务',
      accessorKey: 'taskName',
      cell: ({ row }) => {
        const taskId = getPocTaskId(row.original)
        return (
          <div>
            <div className="flex items-center gap-2">
              <span className="font-medium">{row.original.taskName || row.original.task_name || taskId || '-'}</span>
              {taskId === selectedTaskId ? <Badge tone="info">当前</Badge> : null}
            </div>
            <div className="mt-1 font-mono text-xs text-muted">{taskId}</div>
          </div>
        )
      },
    },
    { header: '状态', accessorKey: 'status', cell: ({ row }) => <Badge tone={getStatusTone(row.original.status) as any}>{getStatusLabel(row.original.status)}</Badge> },
    {
      header: '进度',
      accessorKey: 'progress',
      cell: ({ row }) => {
        const value = Math.round(Number(row.original.progress || row.original.percentage || 0))
        const tone = getProgressTone(row.original.status, value)
        return (
          <div className="min-w-28">
            <div className="h-2 rounded-full border border-border bg-raised">
              <div className={cn('h-full rounded-full transition-all', getProgressFillClass(tone))} style={{ width: `${Math.min(100, value)}%` }} />
            </div>
            <div className={cn('mt-1 text-xs font-medium', getProgressTextClass(tone))}>{value}%</div>
          </div>
        )
      },
    },
    { header: '目标/模板/漏洞', cell: ({ row }) => <span className="text-muted">{row.original.targetCount || row.original.target_count || '-'} / {row.original.pocCount || row.original.poc_count || '-'} / {row.original.found_vulns || row.original.vulnCount || row.original.vuln_count || 0}</span> },
    { header: '创建时间', accessorKey: 'createdAt', cell: ({ row }) => <span className="text-muted">{formatTime(row.original.createdAt || row.original.created_at || row.original.createTime)}</span> },
    {
      header: '操作',
      meta: { align: 'right' },
      cell: ({ row }) => (
        <div className="flex justify-end gap-1">
          <Button size="icon" variant="ghost" title="查看详情" onClick={() => setSelectedTaskId(getPocTaskId(row.original))}><Eye className="size-4" /></Button>
          <Button size="icon" variant="ghost" title="执行" onClick={() => mutateTask.mutate({ action: 'execute', task: row.original })}><Play className="size-4" /></Button>
          <Button size="icon" variant="ghost" title="暂停" onClick={() => mutateTask.mutate({ action: 'pause', task: row.original })}><Pause className="size-4" /></Button>
          <Button size="icon" variant="ghost" title="恢复" onClick={() => mutateTask.mutate({ action: 'resume', task: row.original })}><RotateCcw className="size-4" /></Button>
          <Button size="icon" variant="ghost" title="停止" onClick={() => mutateTask.mutate({ action: 'stop', task: row.original })}><Square className="size-4" /></Button>
          <Button size="icon" variant="ghost" title="删除" onClick={() => window.confirm('确定删除这个模板任务吗？') && mutateTask.mutate({ action: 'delete', task: row.original })}><Trash2 className="size-4" /></Button>
        </div>
      ),
    },
  ]
  const resultColumns: ColumnDef<any>[] = [
    { header: '目标', accessorKey: 'target', cell: ({ row }) => <span className="break-all font-mono text-sm">{row.original.target || row.original.url || '-'}</span> },
    { header: '漏洞', accessorKey: 'name', cell: ({ row }) => <span className="font-medium">{row.original.name || row.original.pocName || row.original.templateName || '-'}</span> },
    { header: '等级', accessorKey: 'severity', cell: ({ row }) => <SeverityBadge severity={row.original.severity} /> },
    { header: '结果', accessorKey: 'matched', cell: ({ row }) => <Badge tone={row.original.matched === false ? 'neutral' : 'danger'}>{row.original.matched === false ? '未命中' : '命中'}</Badge> },
  ]

  return (
    <div className="grid gap-4">
      <PageTitle title="模板任务" description="创建模板扫描任务、选择模板、查看进度、暂停/继续/停止、结果预览和报告下载。" />
      <div className="grid gap-4 md:grid-cols-4">
        <Metric label="任务总数" value={tasks.length} icon={ListChecks} tone="info" badgeLabel="任务" />
        <Metric label="运行中" value={runningTasks} icon={Activity} tone="warning" badgeLabel="运行" />
        <Metric label="漏洞发现" value={vulnTotal} icon={ShieldAlert} tone="danger" badgeLabel="漏洞" />
        <Metric label="当前进度" value={`${Math.round(Number(taskProgress?.progress || taskProgress?.percentage || 0))}%`} icon={RadioTower} tone="success" badgeLabel="进度" />
      </div>
      <div className="grid gap-4 xl:grid-cols-[1.25fr_420px]">
        <DataTable
          columns={taskColumns}
          data={tasks}
          searchPlaceholder="搜索模板任务"
          emptyTitle="暂无模板任务"
          paginationStorageKey="poc-tasks"
          toolbar={
            <>
              <Button variant="outline" onClick={() => queryClient.invalidateQueries({ queryKey: ['poc-tasks'] })}><RefreshCw className="size-4" />刷新</Button>
              <Button variant="default" onClick={() => setCreateOpen(true)}><Plus className="size-4" />新建模板任务</Button>
            </>
          }
        />
        <Card className="h-fit">
          <CardHeader>
            <div>
              <CardTitle>{selectedTaskId ? '任务详情' : '请选择任务'}</CardTitle>
              <CardDescription>{selectedTaskId || '查看目标、模板、进度和最近命中结果。'}</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="grid gap-4">
            {selectedTaskId ? (
              <>
                <div className="grid gap-2 text-sm">
                  <PreviewLine label="状态" value={getStatusLabel(taskDetail?.status || taskProgress?.status)} />
                  <PreviewLine label="目标数量" value={taskTargets.length || taskDetail?.targetCount || taskDetail?.target_count || 0} />
                  <PreviewLine label="模板数量" value={taskPocs.length || taskDetail?.pocCount || taskDetail?.poc_count || 0} />
                  <PreviewLine label="发现漏洞" value={taskDetail?.found_vulns || taskDetail?.vulnCount || taskDetail?.vuln_count || results.length || 0} />
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button variant="outline" onClick={() => mutateTask.mutate({ action: 'execute' })}><Play className="size-4" />执行</Button>
                  <Button variant="outline" onClick={() => mutateTask.mutate({ action: 'pause' })}><Pause className="size-4" />暂停</Button>
                  <Button variant="outline" onClick={() => mutateTask.mutate({ action: 'resume' })}><RotateCcw className="size-4" />继续</Button>
                  <Button variant="danger" onClick={() => mutateTask.mutate({ action: 'stop' })}><Square className="size-4" />停止</Button>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button variant="outline" disabled={!selectedTaskId} onClick={() => reportMutation.mutate('html')}><FileText className="size-4" />HTML</Button>
                  <Button variant="outline" disabled={!selectedTaskId} onClick={() => reportMutation.mutate('excel')}><FileDown className="size-4" />Excel</Button>
                  <Button variant="outline" disabled={!selectedTaskId} onClick={() => reportMutation.mutate('markdown')}><Download className="size-4" />Markdown</Button>
                </div>
                <PillList title="目标" items={taskTargets} empty="暂无目标" tone="neutral" />
                <PillList title="模板" items={taskPocs} empty="暂无模板" tone="info" />
              </>
            ) : <EmptyState title="请选择模板任务" />}
          </CardContent>
        </Card>
      </div>
      <DataTable columns={resultColumns} data={results} showSearch={false} emptyTitle={selectedTaskId ? '暂无模板结果' : '请选择任务查看结果'} paginationStorageKey="poc-task-preview-results" />

      <Modal
        open={createOpen}
        onOpenChange={setCreateOpen}
        title="新建模板任务"
        description="选择目标和 POC 模板后提交给后端任务调度器。"
        className="max-w-5xl"
        footer={
          <>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>取消</Button>
            <Button variant="default" disabled={!draft.targets.trim() || !selectedPocsFromDraft.length || mutateTask.isPending} onClick={() => mutateTask.mutate({ action: 'create' })}>
              {mutateTask.isPending ? <Loader2 className="size-4 animate-spin" /> : <Play className="size-4" />}
              创建任务
            </Button>
          </>
        }
      >
        <div className="grid gap-4 lg:grid-cols-[1fr_340px]">
          <div className="grid gap-4">
            <Field label="任务名称" hint="留空会自动生成">
              <Input value={draft.taskName} onChange={(event) => setDraft({ ...draft, taskName: event.target.value })} placeholder="例如：核心站点 POC 验证" />
            </Field>
            <Field label="验证目标" hint="每行一个 URL / IP">
              <Textarea className="min-h-40" value={draft.targets} onChange={(event) => setDraft({ ...draft, targets: event.target.value })} placeholder="https://example.com&#10;https://api.example.com" />
            </Field>
            <Field label="手动 POC 路径" hint="可直接粘贴模板路径；也可以点击右侧按钮选择。">
              <Textarea className="min-h-32" value={draft.selectedPocs} onChange={(event) => setDraft({ ...draft, selectedPocs: event.target.value })} placeholder="rce/spring-rce.yaml&#10;exposure/git-config.yaml" />
            </Field>
            <div className="grid gap-4 md:grid-cols-2">
              <Field label="并发数"><Input type="number" value={draft.concurrency} onChange={(event) => setDraft({ ...draft, concurrency: Number(event.target.value) })} /></Field>
              <Field label="代理"><Input value={draft.proxy} onChange={(event) => setDraft({ ...draft, proxy: event.target.value })} placeholder="http://127.0.0.1:8080" /></Field>
            </div>
          </div>
          <Card>
            <CardHeader>
              <div>
                <CardTitle>已选模板</CardTitle>
                <CardDescription>{selectedPocsFromDraft.length} 个 POC</CardDescription>
              </div>
              <Button variant="outline" onClick={() => setSelectorOpen(true)}><FileCode2 className="size-4" />选择</Button>
            </CardHeader>
            <CardContent>
              <div className="flex max-h-[420px] flex-wrap gap-2 overflow-auto">
                {selectedPocsFromDraft.length ? selectedPocsFromDraft.map((path) => (
                  <button key={path} type="button" className="inline-flex items-center gap-2 rounded-full border border-info/40 bg-info/10 px-2 py-1 text-xs text-info-foreground" onClick={() => setSelectedPocPaths((current) => current.filter((item) => item !== path))}>
                    {path}<X className="size-3" />
                  </button>
                )) : <EmptyState title="未选择模板" description="选择至少一个 POC 后才能创建任务。" />}
              </div>
            </CardContent>
          </Card>
        </div>
      </Modal>

      <Modal open={selectorOpen} onOpenChange={setSelectorOpen} title="选择 POC 模板" description="选中项会用高亮边框标记，可多选。" className="max-w-5xl">
        <div className="grid gap-4">
          <Input value={pocKeyword} onChange={(event) => setPocKeyword(event.target.value)} placeholder="搜索模板名称、路径、分类或等级" />
          <div className="grid max-h-[62vh] gap-2 overflow-auto">
            {pocRows.map((row) => {
              const path = getPocPath(row)
              const selected = selectedPocPaths.includes(path)
              return (
                <button
                  key={path}
                  type="button"
                  className={cn('grid gap-1 rounded-card border border-border bg-background p-3 text-left transition-colors hover:bg-raised', selected && 'border-info bg-info/10 ring-2 ring-info/40')}
                  onClick={() => togglePocPath(path)}
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium">{row.name || row.fileName || row.file_name || path}</span>
                    <SeverityBadge severity={row.severity} />
                    <Badge>{row.category || '-'}</Badge>
                    {selected ? <Badge tone="info">已选中</Badge> : null}
                  </div>
                  <div className="break-all font-mono text-xs text-muted">{path}</div>
                </button>
              )
            })}
            {!pocRows.length ? <EmptyState title="没有匹配的模板" /> : null}
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={() => setSelectedPocPaths([])}>清空选择</Button>
            <Button variant="default" onClick={() => setSelectorOpen(false)}>完成选择</Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
