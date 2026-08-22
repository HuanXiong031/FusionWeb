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
  severityMetricCards,
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

export function PocResultsCenterView({ demoMode }: { demoMode: boolean }) {
  const queryClient = useQueryClient()
  const [selectedTaskId, setSelectedTaskId] = React.useState('')
  const [severity, setSeverity] = React.useState('')
  const [keyword, setKeyword] = React.useState('')
  const [detail, setDetail] = React.useState<any | null>(null)
  const tasksQuery = useQuery({ queryKey: ['poc-tasks'], queryFn: () => getPocTaskList({ page: 1, pageSize: 200 }), enabled: !demoMode })
  const tasks = demoMode
    ? [{ taskId: 'poc-demo-1', taskName: '核心站点 POC 验证', found_vulns: 1, status: 'completed', progress: 100, createdAt: '2026-07-03 18:30:00' }]
    : asList<any>(tasksQuery.data)
  React.useEffect(() => {
    if (selectedTaskId || !tasks.length) return
    setSelectedTaskId(tasks[0].taskId || tasks[0].task_id || '')
  }, [selectedTaskId, tasks])
  const resultsQuery = useQuery({
    queryKey: ['poc-results-center', selectedTaskId, severity],
    queryFn: () => getPocScanResults(selectedTaskId, { page: 1, pageSize: 500, severity }),
    enabled: !!selectedTaskId && !demoMode,
  })
  const statsQuery = useQuery({
    queryKey: ['poc-results-statistics', selectedTaskId],
    queryFn: () => getPocScanResultStatistics(selectedTaskId),
    enabled: !!selectedTaskId && !demoMode,
  })
  const rowsSource = demoMode
    ? [
        {
          id: 1,
          taskId: 'poc-demo-1',
          template_id: 'spring-rce',
          name: 'Spring RCE',
          target: 'https://acme.com',
          severity: 'critical',
          discovered_at: '2026-07-03 18:31:00',
          request: 'GET /actuator/env HTTP/1.1\nHost: acme.com\n\n',
          response: 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{}',
          metadata: { matcher: 'status' },
        },
      ]
    : asList<any>(resultsQuery.data)
  const normalizedKeyword = keyword.trim().toLowerCase()
  const rows = rowsSource.filter((row) => {
    if (severity && String(row.severity || '').toLowerCase() !== severity) return false
    if (!normalizedKeyword) return true
    return JSON.stringify(row).toLowerCase().includes(normalizedKeyword)
  })
  const stats = unwrap<any>(statsQuery.data) || {}
  const severityStats = buildSeverityStats(rows, stats)
  const detailMutation = useMutation({
    mutationFn: async (row: any) => {
      if (demoMode || !selectedTaskId || !row.id) return row
      const res = await getPocScanResultDetail(selectedTaskId, row.id)
      return unwrap<any>(res) || row
    },
    onSuccess: (data) => setDetail(data),
    onError: (error: any) => toast.error(error.message || '加载详情失败'),
  })
  const deleteMutation = useMutation({
    mutationFn: async (row: any) => {
      if (demoMode) return null
      return deletePocScanResult(Number(row.id), { taskId: selectedTaskId })
    },
    onSuccess: () => {
      toast.success('结果已删除')
      queryClient.invalidateQueries({ queryKey: ['poc-results-center'] })
      queryClient.invalidateQueries({ queryKey: ['poc-results-statistics'] })
    },
    onError: (error: any) => toast.error(error.message || '删除失败'),
  })
  const reportMutation = useMutation({
    mutationFn: async (type: 'html' | 'excel' | 'markdown') => {
      if (demoMode) return new Blob([`Demo ${type} report`], { type: 'text/plain' })
      return downloadPocReport(selectedTaskId, type)
    },
    onSuccess: (res: any, type) => {
      downloadBlobResponse(res, `poc-${selectedTaskId}.${type === 'excel' ? 'xlsx' : type === 'markdown' ? 'md' : 'html'}`)
      toast.success(`${type.toUpperCase()} 报告已下载`)
    },
    onError: (error: any) => toast.error(error.message || '报告下载失败'),
  })
  const copyToVerify = (row: any) => {
    const request = row.request || row.raw_request || ''
    const response = row.response || row.raw_response || ''
    if (!request && !response) {
      toast.warning('该结果没有请求/响应内容')
      return
    }
    try {
      window.localStorage.setItem('fusionweb-vuln-verify-last-request', request)
      window.localStorage.setItem('fusionweb-vuln-verify-last-response', response)
      toast.success('已写入漏洞验证草稿，打开漏洞验证即可查看')
    } catch {
      toast.error('写入漏洞验证草稿失败')
    }
  }
  const columns: ColumnDef<any>[] = [
    { header: '模板ID', accessorKey: 'template_id', cell: ({ row }) => <span className="font-mono text-xs">{row.original.template_id || row.original.templateID || row.original.template || '-'}</span> },
    { header: '漏洞名称', accessorKey: 'name', cell: ({ row }) => <span className="font-medium">{row.original.name || row.original.pocName || row.original.templateName || '-'}</span> },
    { header: '目标', accessorKey: 'target', cell: ({ row }) => <span className="break-all font-mono text-sm">{row.original.target || row.original.url || '-'}</span> },
    { header: '严重程度', accessorKey: 'severity', cell: ({ row }) => <SeverityBadge severity={row.original.severity} /> },
    { header: '发现时间', accessorKey: 'discovered_at', cell: ({ row }) => <span className="text-muted">{formatTime(row.original.discovered_at || row.original.discoveredAt || row.original.createdAt)}</span> },
    {
      header: '操作',
      meta: { align: 'right' },
      cell: ({ row }) => (
        <div className="flex justify-end gap-1">
          <Button size="icon" variant="ghost" title="查看详情" onClick={() => detailMutation.mutate(row.original)}><Eye className="size-4" /></Button>
          <Button size="icon" variant="ghost" title="验证漏洞" onClick={() => copyToVerify(row.original)}><Play className="size-4" /></Button>
          <Button size="icon" variant="ghost" title="删除结果" onClick={() => window.confirm('确定删除这条模板结果吗？') && deleteMutation.mutate(row.original)}><Trash2 className="size-4" /></Button>
        </div>
      ),
    },
  ]
  const detailInfo = normalizeVulnDetail(detail)

  return (
    <div className="grid gap-4">
      <PageTitle title="模板结果" description="查看模板扫描结果：任务筛选、严重程度统计、结果详情、报告下载和验证入口。" />
      <div className="grid gap-4 md:grid-cols-3 xl:grid-cols-6">
        {severityMetricCards.map((item) => (
          <Metric key={item.key} label={item.label} value={severityStats[item.key] || 0} icon={item.icon} tone={item.tone} badgeLabel={item.label} />
        ))}
      </div>
      <Card>
        <CardContent className="grid gap-3 p-4 lg:grid-cols-[1.2fr_180px_1fr_auto]">
          <Select value={selectedTaskId} onChange={(event) => setSelectedTaskId(event.target.value)}>
            <option value="">选择任务</option>
            {tasks.map((task) => {
              const id = task.taskId || task.task_id
              return <option key={id} value={id}>{task.taskName || task.task_name || id}</option>
            })}
          </Select>
          <Select value={severity} onChange={(event) => setSeverity(event.target.value)}>
            <option value="">全部等级</option>
            {severityMetricCards.map((item) => <option key={item.key} value={item.key}>{item.label}</option>)}
          </Select>
          <Input value={keyword} onChange={(event) => setKeyword(event.target.value)} placeholder="搜索模板ID、漏洞名称或目标" />
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" disabled={!selectedTaskId} onClick={() => queryClient.invalidateQueries({ queryKey: ['poc-results-center'] })}><RefreshCw className="size-4" />刷新</Button>
            <Button variant="outline" disabled={!selectedTaskId} onClick={() => reportMutation.mutate('html')}><FileText className="size-4" />HTML</Button>
            <Button variant="outline" disabled={!selectedTaskId} onClick={() => reportMutation.mutate('excel')}><FileDown className="size-4" />Excel</Button>
            <Button variant="outline" disabled={!selectedTaskId} onClick={() => reportMutation.mutate('markdown')}><Download className="size-4" />Markdown</Button>
          </div>
        </CardContent>
      </Card>
      <DataTable columns={columns} data={rows} searchPlaceholder="过滤当前结果" showSearch={false} emptyTitle="请选择任务查看模板结果" paginationStorageKey="poc-results-center" />
      <Drawer open={!!detail} onOpenChange={(open) => !open && setDetail(null)} title="模板结果详情" description={detail?.target || detail?.url || ''} className="max-w-none md:w-[60vw]">
        {detail ? (
          <div className="grid gap-5">
            <section className="rounded-card border border-border bg-background">
              <VulnDetailRow label="目标信息" value={detailInfo.target} mono />
              <VulnDetailRow label="漏洞名称" value={detailInfo.name} />
              <VulnDetailRow label="模板 ID" value={detailInfo.templateID} mono />
              <VulnDetailRow label="模板路径" value={detailInfo.templatePath} mono />
              <VulnDetailRow label="严重程度" value={<SeverityBadge severity={detailInfo.severity} />} />
              {detailInfo.author !== '-' ? <VulnDetailRow label="作者信息" value={detailInfo.author} /> : null}
              <VulnDetailRow label="标签" value={detailInfo.tags} />
              {detailInfo.matcherName !== '-' && detailInfo.matcherName !== detailInfo.tags ? <VulnDetailRow label="匹配器" value={detailInfo.matcherName} /> : null}
              <VulnDetailRow label="匹配位置" value={detail.matched_at || detail.matchedAt || '-'} mono />
              <VulnDetailRow label="发现时间" value={formatTime(detail.discovered_at || detail.discoveredAt || detail.createdAt)} />
            </section>
            {detail.extracted_results || detail.extractedResults ? (
              <CodeBlock title="提取结果" value={formatUnknown(detail.extracted_results || detail.extractedResults)} />
            ) : null}
            {detail.metadata ? <CodeBlock title="元数据" value={formatUnknown(detail.metadata)} /> : null}
            {detail.request || detail.response ? (
              <Tabs defaultValue={detail.request ? 'request' : 'response'}>
                <TabsList>
                  {detail.request ? <TabsTrigger value="request"><FileText className="size-4" />请求 Request</TabsTrigger> : null}
                  {detail.response ? <TabsTrigger value="response"><Terminal className="size-4" />响应 Response</TabsTrigger> : null}
                </TabsList>
                {detail.request ? <TabsContent value="request"><HttpCodePanel title="请求 Request" value={detail.request} /></TabsContent> : null}
                {detail.response ? <TabsContent value="response"><HttpCodePanel title="响应 Response" value={detail.response} /></TabsContent> : null}
              </Tabs>
            ) : null}
          </div>
        ) : null}
      </Drawer>
    </div>
  )
}
