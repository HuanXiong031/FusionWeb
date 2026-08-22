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

type ReportSource = 'web' | 'port' | 'template'
type ReportType = 'html' | 'excel' | 'markdown'

function normalizeReportTaskType(row: any): Exclude<ReportSource, 'template'> {
  const raw = String(row?.taskType || row?.task_type || row?.scanType || row?.scan_type || 'web').toLowerCase()
  return raw.includes('port') ? 'port' : 'web'
}

function getReportSourceLabel(source: ReportSource) {
  return source === 'web' ? 'Web扫描' : source === 'port' ? '端口扫描' : '模板扫描'
}

export function ReportExportPanel({
  demoMode,
  selectedScanTaskId,
  selectedScanTaskType,
  selectedTaskId,
  selectedSource,
}: {
  demoMode: boolean
  selectedScanTaskId?: string
  selectedScanTaskType?: Exclude<ReportSource, 'template'>
  selectedTaskId?: string
  selectedSource?: ReportSource
}) {
  const controlledSource = selectedSource || selectedScanTaskType
  const controlledTaskId = selectedTaskId || selectedScanTaskId
  const [source, setSource] = React.useState<ReportSource>(controlledSource || 'web')
  const [selectedId, setSelectedId] = React.useState(controlledTaskId || '')
  const tasksQuery = useQuery({ queryKey: ['tasks'], queryFn: getTasks, enabled: !demoMode })
  const pocTasksQuery = useQuery({ queryKey: ['poc-tasks'], queryFn: () => getPocTaskList({ page: 1, pageSize: 300 }), enabled: !demoMode })
  const scanTasks = demoMode ? demoTasks : asList<TaskRow>(tasksQuery.data)
  const pocTasks = demoMode
    ? [{ taskId: 'poc-demo-1', taskName: '核心站点 POC 验证', status: 'completed', progress: 100, found_vulns: 1, createdAt: '2026-07-05 10:20:00' }]
    : asList<any>(pocTasksQuery.data)
  const scanTaskKey = scanTasks.map(getTaskId).filter(Boolean).join('|')
  const scanRows = source === 'template' ? [] : scanTasks.filter((row: any) => normalizeReportTaskType(row) === source)
  const rows = source === 'template' ? pocTasks : scanRows
  const isTemplateSource = source === 'template'
  const sourceLabel = getReportSourceLabel(source)
  const ids = rows.map((row: any) => isTemplateSource ? getPocTaskId(row) : getTaskId(row)).filter(Boolean)

  React.useEffect(() => {
    if (!controlledTaskId || !controlledSource) return
    setSource(controlledSource)
    setSelectedId(controlledTaskId)
  }, [scanTaskKey, controlledTaskId, controlledSource])

  React.useEffect(() => {
    if (selectedId && ids.includes(selectedId)) return
    setSelectedId(ids[0] || '')
  }, [ids.join('|'), selectedId])

  const reportMutation = useMutation({
    mutationFn: async (type: ReportType) => {
      if (!selectedId) throw new Error('请选择任务')
      if (demoMode) return new Blob([`Demo ${sourceLabel} ${type} report`], { type: 'text/plain' })
      return isTemplateSource ? downloadPocReport(selectedId, type) : downloadTaskReport(selectedId, type)
    },
    onSuccess: (res: any, type) => {
      const prefix = isTemplateSource ? 'template-report' : 'scan-report'
      const extension = type === 'excel' ? 'xlsx' : type === 'markdown' ? 'md' : 'html'
      downloadBlobResponse(res, `${prefix}-${selectedId}.${extension}`)
      toast.success(`${getReportTypeLabel(type)} 报告已下载`)
    },
    onError: (error: any) => toast.error(error.message || '报告下载失败'),
  })

  const columns: ColumnDef<any>[] = [
    {
      header: '任务',
      cell: ({ row }) => {
        const id = isTemplateSource ? getPocTaskId(row.original) : getTaskId(row.original)
        const name = isTemplateSource ? getPocTaskDisplayName(row.original) : getTaskDisplayName(row.original)
        return (
          <div>
            <div className="flex items-center gap-2">
              <span className="font-medium">{name}</span>
              {id === selectedId ? <Badge tone="info">当前</Badge> : null}
            </div>
            <div className="mt-1 font-mono text-xs text-muted">{id}</div>
          </div>
        )
      },
    },
    { header: '状态', accessorKey: 'status', cell: ({ row }) => <Badge tone={getStatusTone(row.original.status) as any}>{getStatusLabel(row.original.status)}</Badge> },
    {
      header: '进度',
      cell: ({ row }) => {
        const value = Math.round(Number(row.original.percentage || row.original.progress || 0))
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
    { header: '漏洞', cell: ({ row }) => <Badge tone={Number(row.original.vulnCount || row.original.found_vulns || row.original.vuln_count || 0) > 0 ? 'danger' : 'neutral'}>{row.original.vulnCount || row.original.found_vulns || row.original.vuln_count || 0}</Badge> },
    { header: '创建时间', cell: ({ row }) => <span className="text-muted">{formatTime(row.original.createdAt || row.original.created_at || row.original.createTime)}</span> },
    { header: '操作', meta: { align: 'right' }, cell: ({ row }) => <Button size="sm" variant="outline" onClick={() => setSelectedId(isTemplateSource ? getPocTaskId(row.original) : getTaskId(row.original))}><Check className="size-4" />选择</Button> },
  ]

  return (
    <div className="grid gap-4">
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
        <Metric label="Web任务" value={scanTasks.filter((row: any) => normalizeReportTaskType(row) === 'web').length} icon={Globe2} tone="info" badgeLabel="Web" />
        <Metric label="端口任务" value={scanTasks.filter((row: any) => normalizeReportTaskType(row) === 'port').length} icon={Network} tone="warning" badgeLabel="端口" />
        <Metric label="模板任务" value={pocTasks.length} icon={ShieldAlert} tone="success" badgeLabel="模板" />
        <Metric label="当前类型" value={sourceLabel} icon={FileDown} tone="accent" badgeLabel="类型" />
        <Metric label="当前任务" value={selectedId || '-'} icon={ListChecks} tone="neutral" badgeLabel="任务" />
      </div>
      <Card>
        <CardContent className="grid gap-3 p-4 lg:grid-cols-[160px_1fr_auto]">
          <Select value={source} onChange={(event) => { setSource(event.target.value as ReportSource); setSelectedId('') }}>
            <option value="web">Web扫描</option>
            <option value="port">端口扫描</option>
            <option value="template">模板扫描</option>
          </Select>
          <Select value={selectedId} onChange={(event) => setSelectedId(event.target.value)}>
            <option value="">选择任务</option>
            {rows.map((row: any) => {
              const id = isTemplateSource ? getPocTaskId(row) : getTaskId(row)
              const name = isTemplateSource ? getPocTaskDisplayName(row) : getTaskDisplayName(row)
              return <option key={id} value={id}>{name}</option>
            })}
          </Select>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" disabled={!selectedId || reportMutation.isPending} onClick={() => reportMutation.mutate('html')}><FileText className="size-4" />HTML</Button>
            <Button variant="outline" disabled={!selectedId || reportMutation.isPending} onClick={() => reportMutation.mutate('excel')}><FileDown className="size-4" />Excel</Button>
            <Button variant="outline" disabled={!selectedId || reportMutation.isPending} onClick={() => reportMutation.mutate('markdown')}><Download className="size-4" />Markdown</Button>
          </div>
        </CardContent>
      </Card>
      <DataTable columns={columns} data={rows} searchPlaceholder="搜索报告任务" emptyTitle="暂无可导出的任务" paginationStorageKey="report-center" />
    </div>
  )
}

export function ReportCenterView({ demoMode }: { demoMode: boolean }) {
  return (
    <div className="grid gap-4">
      <PageTitle title="报告导出" description="统一下载 Web、端口和模板扫描报告，支持 HTML、Excel 和 Markdown。" />
      <ReportExportPanel demoMode={demoMode} />
    </div>
  )
}
