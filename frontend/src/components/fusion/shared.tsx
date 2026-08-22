'use client'

import * as React from 'react'
import * as TooltipPrimitive from '@radix-ui/react-tooltip'
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

export const demoStats: DashboardStats = {
  totalTasks: 8,
  runningTasks: 3,
  completedTasks: 4,
  failedTasks: 1,
  pendingTasks: 0,
  totalAssets: 21638,
  totalVulns: 89,
  portCount: 156,
  siteCount: 2341,
  subdomainCount: 482,
  directoryCount: 128,
  jsCount: 96,
  weakPasswordCount: 7,
  totalFingerprints: 156,
  totalPOCs: 4788,
  vulnLevelDist: { critical: 3, high: 12, medium: 28, low: 34, info: 12 },
  fingerprintTop10: [
    { name: 'nginx', count: 245 },
    { name: 'spring', count: 139 },
    { name: 'tomcat', count: 93 },
  ],
  trendData: [
    { date: '6/27', tasks: 12, vulns: 8 },
    { date: '6/28', tasks: 15, vulns: 11 },
    { date: '6/29', tasks: 18, vulns: 15 },
    { date: '6/30', tasks: 22, vulns: 19 },
    { date: '7/1', tasks: 25, vulns: 24 },
    { date: '7/2', tasks: 28, vulns: 31 },
    { date: '7/3', tasks: 30, vulns: 37 },
  ],
}

export const demoTasks: TaskRow[] = [
  {
    taskID: 'demo-1',
    taskName: 'acme.com',
    taskType: 'web',
    targetInput: 'https://acme.com',
    status: 'completed',
    percentage: 100,
    portCount: 156,
    urlCount: 2341,
    fingerprintCount: 45,
    vulnCount: 89,
    createTime: '2024-12-28 18:00:00',
  },
  {
    taskID: 'demo-2',
    taskName: 'acme.io',
    taskType: 'web',
    targetInput: 'https://acme.io',
    status: 'running',
    percentage: 65,
    portCount: 78,
    urlCount: 892,
    fingerprintCount: 23,
    vulnCount: 12,
    createTime: '2024-12-27 22:30:00',
  },
  {
    taskID: 'demo-3',
    taskName: 'globalfinance.com',
    taskType: 'port',
    targetInput: '10.10.10.0/24',
    status: 'failed',
    percentage: 15,
    portCount: 0,
    urlCount: 0,
    fingerprintCount: 0,
    vulnCount: 0,
    createTime: '2024-12-26 00:20:00',
  },
]

export const demoBlacklistData: Record<string, string[]> = {
  fingerprint: ['ThinkPHP'],
  ip: ['127.0.0.1'],
  domain: ['example.local'],
}

export const demoWhitelistData: Record<string, string[]> = {}

export const accessPolicyCategories = ['ip', 'domain']

export const blacklistCategoryLabels: Record<string, string> = {
  fingerprint: '指纹',
  ip: 'IP',
  domain: '域名',
}

export type SeverityStatKey = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown'

export const severityMetricCards: Array<{ key: SeverityStatKey; label: string; tone: string; icon: React.ElementType }> = [
  { key: 'critical', label: '严重', tone: 'danger', icon: ShieldAlert },
  { key: 'high', label: '高危', tone: 'accent', icon: ShieldAlert },
  { key: 'medium', label: '中危', tone: 'warning', icon: ShieldAlert },
  { key: 'low', label: '低危', tone: 'info', icon: ShieldAlert },
  { key: 'info', label: '信息', tone: 'success', icon: Info },
  { key: 'unknown', label: '未知', tone: 'neutral', icon: FileCode2 },
]

export function normalizeSeverityStatKey(value: any): SeverityStatKey {
  const severity = String(value || '').trim().toLowerCase()
  if (severity === 'critical' || severity === 'high' || severity === 'medium' || severity === 'low' || severity === 'info') return severity
  return 'unknown'
}

export function buildSeverityStats(rows: any[], stats: any) {
  const fromApi = stats?.severity_distribution || stats?.severityDistribution || stats
  const result: Record<SeverityStatKey, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 }
  let hasApiStats = false
  severityMetricCards.forEach(({ key }) => {
    const value = Number(fromApi?.[key])
    if (!Number.isNaN(value) && value > 0) {
      result[key] = value
      hasApiStats = true
    }
  })
  if (hasApiStats) return result
  rows.forEach((row) => {
    result[normalizeSeverityStatKey(row.severity || row.info?.severity)] += 1
  })
  return result
}

export function getSeverityText(level: string) {
  const map: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息', unknown: '未知' }
  return map[String(level).toLowerCase()] || level
}

export function getSeverityTone(level: string) {
  const value = String(level).toLowerCase()
  if (value === 'critical') return 'danger'
  if (value === 'high') return 'accent'
  if (value === 'medium') return 'warning'
  if (value === 'low') return 'info'
  if (value === 'info') return 'success'
  return 'neutral'
}

export function formatUnknown(value: any) {
  if (typeof value === 'string') return value
  return JSON.stringify(value, null, 2)
}

export function getPocPath(row: PocFileRow | any) {
  return row?.relativePath || row?.relative_path || row?.path || (row?.category && (row?.fileName || row?.file_name) ? `${row.category}/${row.fileName || row.file_name}` : row?.fileName || row?.file_name || '')
}

export function downloadContent(content: string, fileName: string, type = 'text/plain;charset=utf-8') {
  const blob = new Blob([content], { type })
  downloadBlob(blob, fileName)
}

export function downloadBlobResponse(response: any, fallbackName: string) {
  const data = response?.data
  const blob = data instanceof Blob ? data : response instanceof Blob ? response : new Blob([data ?? response ?? ''])
  const disposition = response?.headers?.get?.('content-disposition') || response?.headers?.['content-disposition']
  downloadBlob(blob, getFileNameFromDisposition(disposition) || fallbackName)
}

export function downloadBlob(blob: Blob, fileName: string) {
  const url = window.URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = fileName
  link.style.display = 'none'
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  window.setTimeout(() => window.URL.revokeObjectURL(url), 1000)
}

export function getFileNameFromDisposition(disposition?: string) {
  if (!disposition) return ''
  const encoded = disposition.match(/filename\*=UTF-8''([^;]+)/i)?.[1]
  if (encoded) {
    try {
      return decodeURIComponent(encoded)
    } catch {
      return encoded
    }
  }
  const quoted = disposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/)?.[1]
  return quoted ? quoted.replace(/['"]/g, '') : ''
}

export function getReportFileName(taskId: string, type: 'html' | 'excel' | 'markdown') {
  const extension = type === 'excel' ? 'xlsx' : type === 'markdown' ? 'md' : 'html'
  const safeTaskId = String(taskId || 'task').replace(/[<>:"/\\|?*\s]+/g, '_')
  return `scan-report-${safeTaskId}.${extension}`
}

export function getReportTypeLabel(type: 'html' | 'excel' | 'markdown') {
  return type === 'excel' ? 'Excel' : type === 'markdown' ? 'Markdown' : 'HTML'
}

export function normalizeIPRows(value: any) {
  const data = unwrap<any>(value)
  if (Array.isArray(data)) return data
  if (Array.isArray(data?.results)) return data.results
  if (data?.results && typeof data.results === 'object') return Object.values(data.results)
  if (data && typeof data === 'object' && 'ip' in data) return [data]
  if (data && typeof data === 'object') return Object.values(data)
  return []
}

export function getIPDBStatusLabel(info: any, loading: boolean, error: boolean) {
  if (loading) return '加载中'
  if (error) return '异常'
  if (info?.status) return info.status
  if (info?.loaded || info?.is_ipv4 || info?.is_ipv6 || info?.db_path) return 'ready'
  return '-'
}

export function getIPDBFileName(info: any) {
  const path = info?.file || info?.path || info?.db_path
  if (!path || typeof path !== 'string') return '-'
  return path.split(/[\\/]/).filter(Boolean).at(-1) || path
}

export function readFileText(file: File) {
  return new Promise<string>((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result || ''))
    reader.onerror = () => reject(reader.error || new Error('文件读取失败'))
    reader.readAsText(file, 'utf-8')
  })
}

export function readFileBase64(file: File) {
  return new Promise<string>((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result || '').split(',')[1] || '')
    reader.onerror = () => reject(reader.error || new Error('文件读取失败'))
    reader.readAsDataURL(file)
  })
}

export function toCsv(rows: any[]) {
  if (!rows.length) return ''
  const headers: string[] = Array.from(rows.reduce((set, row) => {
    Object.keys(row || {}).forEach((key) => set.add(key))
    return set
  }, new Set<string>()))
  const escape = (value: any) => `"${String(value ?? '').replace(/"/g, '""')}"`
  return [headers.join(','), ...rows.map((row) => headers.map((key) => escape(row?.[key])).join(','))].join('\n')
}

export function blacklistToYaml(config: Record<string, string[]>) {
  return Object.entries(config || {})
    .map(([category, values]) => `${category}:\n${(values || []).map((item) => `  - ${item}`).join('\n')}`)
    .join('\n')
}

export function getBlacklistCategoryLabel(category: string) {
  return blacklistCategoryLabels[category] || category
}

export function normalizeBlacklistConfig(config: Record<string, string[]>) {
  return Object.entries(config || {}).reduce<Record<string, string[]>>((acc, [category, values]) => {
    if (!category) return acc
    acc[category] = Array.isArray(values)
      ? values.map((item) => String(item).trim()).filter(Boolean)
      : []
    return acc
  }, {})
}

export function pickPolicyConfig(config: Record<string, string[]>, categories: string[]) {
  const normalized = normalizeBlacklistConfig(config)
  return categories.reduce<Record<string, string[]>>((acc, category) => {
    acc[category] = normalized[category] || []
    return acc
  }, {})
}

export function parseBlacklistContent(content: string): Record<string, string[]> {
  const trimmed = content.trim()
  if (!trimmed) return {}
  if (trimmed.startsWith('{')) return JSON.parse(trimmed)
  const result: Record<string, string[]> = {}
  let current = ''
  for (const rawLine of trimmed.split(/\r?\n/)) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) continue
    if (line.endsWith(':')) {
      current = line.slice(0, -1).trim()
      result[current] = result[current] || []
      continue
    }
    if (line.startsWith('-') && current) {
      result[current].push(line.slice(1).trim().replace(/^["']|["']$/g, ''))
    }
  }
  return result
}

export function parseBatchUsers(text: string) {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [username, password, email, role = 'user', status = 'active'] = line.split(',').map((item) => item.trim())
      return { username, password, email, role, status }
    })
    .filter((item) => item.username)
}

export function pickVulnField(row: any, keys: string[]) {
  if (!row) return ''
  for (const key of keys) {
    const value = key.split('.').reduce((acc, part) => acc?.[part], row)
    if (value !== undefined && value !== null && value !== '') return value
  }
  return ''
}

export function normalizeTagText(value: any): string {
  if (value === undefined || value === null || value === '') return '-'
  if (Array.isArray(value)) {
    const text = value.map((item) => normalizeTagText(item)).filter((item) => item && item !== '-').join(', ')
    return text || '-'
  }
  if (typeof value === 'object') {
    const text = Object.values(value).map((item) => normalizeTagText(item)).filter((item) => item && item !== '-').join(', ')
    return text || '-'
  }
  return String(value).trim() || '-'
}

export function getVulnTarget(row: any) {
  return String(pickVulnField(row, ['target', 'url', 'matched', 'host']) || '-')
}

export function getVulnTemplateID(row: any) {
  return String(pickVulnField(row, ['templateID', 'templateId', 'template_id', 'template']) || '-')
}

export function getVulnDisplayName(row: any) {
  return String(pickVulnField(row, ['info.name', 'name', 'title', 'templateName', 'templateID', 'templateId', 'template_id']) || '-')
}

export function normalizeVulnDetail(row: any) {
  const rawTags = pickVulnField(row, ['tags', 'info.tags'])
  const tags = normalizeTagText(rawTags !== '' ? rawTags : pickVulnField(row, ['matcherName', 'matcher_name', 'matcher']))
  return {
    target: getVulnTarget(row),
    name: getVulnDisplayName(row),
    templateID: getVulnTemplateID(row),
    templatePath: String(pickVulnField(row, ['templatePath', 'template_path']) || '-'),
    matcherName: String(pickVulnField(row, ['matcherName', 'matcher_name', 'matcher']) || '-'),
    severity: String(pickVulnField(row, ['severity', 'info.severity']) || 'info'),
    author: String(pickVulnField(row, ['author', 'info.author']) || '-'),
    tags,
    description: String(pickVulnField(row, ['description', 'info.description']) || '-'),
    discoveredAt: pickVulnField(row, ['discoveredAt', 'discovered_at', 'createdAt', 'created_at', 'time']),
    request: String(pickVulnField(row, ['request', 'rawRequest', 'raw_request']) || ''),
    response: String(pickVulnField(row, ['response', 'rawResponse', 'raw_response']) || ''),
  }
}

export function LineNumberedCode({ value }: { value: string }) {
  const lines = React.useMemo(() => (value || '').replace(/\r\n/g, '\n').split('\n'), [value])
  const numberWidth = Math.max(2, String(lines.length).length)

  return (
    <div className="h-[520px] overflow-y-auto overflow-x-hidden rounded-card border border-border bg-[#282c34] py-4 font-mono text-xs leading-5 text-[#abb2bf]">
      {lines.map((line, index) => (
        <div key={index} className="grid min-h-5 min-w-0 grid-cols-[auto_minmax(0,1fr)] px-4">
          <span className="select-none pr-4 text-right text-[#636d83]" style={{ minWidth: `${numberWidth}ch` }}>
            {index + 1}
          </span>
          <span className="min-w-0 whitespace-pre-wrap break-all [overflow-wrap:anywhere]">{line || ' '}</span>
        </div>
      ))}
    </div>
  )
}

export function HttpCodePanel({ title, value }: { title: string; value: string }) {
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      toast.success('已复制到剪贴板')
    } catch {
      toast.error('复制失败')
    }
  }

  return (
    <div className="grid gap-3">
      <div className="flex items-center justify-between gap-3">
        <h4 className="text-sm font-semibold text-foreground">{title}</h4>
        <Button size="sm" variant="outline" onClick={handleCopy}>
          <Copy className="size-4" />
          复制
        </Button>
      </div>
      <LineNumberedCode value={value} />
    </div>
  )
}

export function CodeBlock({ title, value }: { title: string; value: string }) {
  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>{title}</CardTitle>
        </div>
      </CardHeader>
      <CardContent>
        <pre className="max-h-[420px] overflow-auto rounded-card border border-border bg-background p-4 font-mono text-xs leading-5 text-foreground">
          {value}
        </pre>
      </CardContent>
    </Card>
  )
}

export function VulnDetailRow({ label, value, mono = false }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="grid border-b border-border last:border-b-0 md:grid-cols-[140px_1fr]">
      <div className="bg-raised px-4 py-3 text-sm font-semibold text-muted">{label}</div>
      <div className={cn('min-w-0 px-4 py-3 text-sm leading-6 text-foreground', mono ? 'break-all font-mono' : 'break-words')}>
        {value || '-'}
      </div>
    </div>
  )
}

const taskTypeLabels: Record<string, string> = {
  web: 'Web扫描',
  port: '端口扫描',
  subdomain: '子域名扫描',
  weak_password: '弱口令扫描',
  directory: '目录扫描',
  js: 'JS扫描',
}

export function getTaskTypeValue(task: any) {
  return String(task?.taskType || task?.task_type || '').toLowerCase()
}

export function getTaskTypeLabel(task: any) {
  const type = getTaskTypeValue(task)
  return taskTypeLabels[type] || 'Web扫描'
}

export function getModuleResultCount(task: any) {
  return task?.moduleResultCount || task?.module_result_count || task?.resultCount || task?.result_count || 0
}

export function isModuleTaskType(type?: string) {
  return ['subdomain', 'weak_password', 'directory', 'js'].includes(String(type || '').toLowerCase())
}

function TaskTargetPreview({ value }: { value?: string }) {
  const text = String(value || '').trim()
  if (!text) return <span className="text-muted">-</span>
  const targets = parseTargets(text)
  const items = targets.length ? targets : text.split(/\s+/).filter(Boolean)
  const visible = items.slice(0, 4)
  const showTargetList = items.length <= 12

  return (
    <TooltipPrimitive.Provider delayDuration={250} skipDelayDuration={100}>
      <TooltipPrimitive.Root>
        <TooltipPrimitive.Trigger asChild>
          <div
            className="max-w-[460px] cursor-help rounded-md outline-none focus-visible:ring-2 focus-visible:ring-info/40"
            tabIndex={0}
            aria-label={`扫描目标，共 ${items.length} 个`}
          >
            <div className="flex items-center justify-between gap-2 text-xs text-muted">
              <span>{items.length} 个目标</span>
              {items.length > visible.length ? <span>+{items.length - visible.length}</span> : null}
            </div>
            <div className="mt-1 grid max-h-20 gap-1 overflow-y-auto rounded-md border border-border bg-background p-2 font-mono text-xs leading-5 text-foreground">
              {visible.map((item, index) => (
                <span key={`${item}-${index}`} className="truncate">{item}</span>
              ))}
            </div>
          </div>
        </TooltipPrimitive.Trigger>
        <TooltipPrimitive.Portal>
          <TooltipPrimitive.Content
            side="right"
            align="start"
            sideOffset={8}
            collisionPadding={16}
            className="z-[80] w-80 max-w-[calc(100vw-32px)] overflow-hidden rounded-md border border-border bg-card text-foreground shadow-xl"
          >
            <div className="flex items-center justify-between gap-3 border-b border-border px-3 py-2 text-xs">
              <span className="font-semibold">扫描目标</span>
              <span className="text-muted">共 {items.length} 个</span>
            </div>
            {showTargetList ? (
              <div className="grid max-h-60 gap-1 overflow-y-auto p-3 font-mono text-xs leading-5">
                {items.map((item, index) => (
                  <span key={`${item}-${index}`} className="break-all">{item}</span>
                ))}
              </div>
            ) : (
              <div className="px-3 py-2 text-xs leading-5 text-muted">
                目标数量较多，列表中仅显示前 4 个。请在任务详情中查看完整列表。
              </div>
            )}
          </TooltipPrimitive.Content>
        </TooltipPrimitive.Portal>
      </TooltipPrimitive.Root>
    </TooltipPrimitive.Provider>
  )
}

export function getTaskColumns(onOpenTask: (taskId: string) => void, onAction?: (action: string, taskId: string) => void): ColumnDef<TaskRow>[] {
  return [
    {
      header: '任务信息',
      accessorKey: 'taskName',
      cell: ({ row }) => (
        <div>
          <div className="font-medium">{row.original.taskName || row.original.task_name || '未命名任务'}</div>
          <div className="mt-1 flex items-center gap-2 text-xs text-muted">
            <Badge>{getTaskTypeLabel(row.original)}</Badge>
            <span>{formatTime(row.original.createTime || row.original.createdAt)}</span>
          </div>
        </div>
      ),
    },
    {
      header: '扫描目标',
      accessorKey: 'targetInput',
      cell: ({ row }) => <TaskTargetPreview value={row.original.targetInput || row.original.target_input} />,
    },
    {
      header: '状态',
      accessorKey: 'status',
      cell: ({ row }) => <Badge tone={getStatusTone(row.original.status) as any}>{getStatusLabel(row.original.status)}</Badge>,
    },
    {
      header: '进度',
      cell: ({ row }) => {
        const value = Math.round(row.original.percentage || row.original.progress || 0)
        const tone = getProgressTone(row.original.status, value)
        return (
          <div className="min-w-32">
            <div className="h-2 rounded-full border border-border bg-raised">
              <div className={cn('h-full rounded-full transition-all', getProgressFillClass(tone))} style={{ width: `${Math.min(100, value)}%` }} />
            </div>
            <div className={cn('mt-1 text-xs font-medium', getProgressTextClass(tone))}>{value}%</div>
          </div>
        )
      },
    },
    {
      header: '扫描结果',
      cell: ({ row }) => (
        isModuleTaskType(getTaskTypeValue(row.original)) ? (
          <div className="text-xs text-muted">
            <span>模块结果 {getModuleResultCount(row.original)}</span>
          </div>
        ) : (
          <div className="grid grid-cols-2 gap-1 text-xs text-muted">
            <span>端口 {row.original.portCount || 0}</span>
            <span>URL {row.original.urlCount || 0}</span>
            <span>指纹 {row.original.fingerprintCount || 0}</span>
            <span className="text-danger-foreground">漏洞 {row.original.vulnCount || 0}</span>
          </div>
        )
      ),
    },
    {
      header: '操作',
      cell: ({ row }) => {
        const taskId = getTaskId(row.original)
        return (
          <div className="flex justify-end gap-1">
            <Button size="icon" variant="ghost" title="查看详情" onClick={() => onOpenTask(taskId)}><Eye className="size-4" /></Button>
            {onAction ? (
              <>
                <Button size="icon" variant="ghost" title="暂停" onClick={() => onAction('pause', taskId)}><Pause className="size-4" /></Button>
                <Button size="icon" variant="ghost" title="恢复" onClick={() => onAction('resume', taskId)}><Play className="size-4" /></Button>
                <Button size="icon" variant="ghost" title="停止" onClick={() => onAction('stop', taskId)}><Square className="size-4" /></Button>
                <Button size="icon" variant="ghost" title="删除" onClick={() => onAction('delete', taskId)}><Trash2 className="size-4" /></Button>
              </>
            ) : null}
          </div>
        )
      },
    },
  ]
}

export function getTaskId(task: TaskRow) {
  return task.taskID || task.taskId || task.task_id || ''
}

export function getTaskDisplayName(task: any) {
  return task?.taskName || task?.task_name || task?.name || getTaskId(task) || '未命名任务'
}

export function getPocTaskId(task: any) {
  return task?.taskID || task?.taskId || task?.task_id || task?.id || ''
}

export function getPocTaskDisplayName(task: any) {
  return task?.taskName || task?.task_name || task?.name || getPocTaskId(task) || '未命名 POC 任务'
}

export function getLogLevelTone(level?: string) {
  const value = String(level || '').toLowerCase()
  if (value.includes('error') || value.includes('fail')) return 'danger'
  if (value.includes('warn')) return 'warning'
  if (value.includes('success') || value.includes('ok') || value.includes('done')) return 'success'
  if (value.includes('debug')) return 'neutral'
  if (value.includes('info')) return 'info'
  return 'neutral'
}

export function toTextList(value: any): string[] {
  if (!value) return []
  if (Array.isArray(value)) {
    return value.flatMap((item) => toTextList(item)).filter(Boolean)
  }
  if (typeof value === 'string') {
    return parseTargets(value)
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return [String(value)]
  }
  if (typeof value === 'object') {
    const direct = value.target || value.url || value.path || value.name || value.id || value.templateId || value.template_id
    if (direct) return [String(direct)]
    return Object.values(value).flatMap((item) => toTextList(item)).filter(Boolean)
  }
  return []
}

export function PillList({ title, items, empty, tone = 'neutral' }: { title: string; items: string[]; empty: string; tone?: any }) {
  const uniqueItems = Array.from(new Set(items.filter(Boolean)))
  return (
    <div className="grid gap-2">
      <div className="text-sm font-medium">{title}</div>
      <div className="flex max-h-28 flex-wrap gap-1 overflow-auto rounded-md border border-border bg-background p-2">
        {uniqueItems.length ? uniqueItems.map((item) => <Badge key={item} tone={tone}>{item}</Badge>) : <span className="text-sm text-muted">{empty}</span>}
      </div>
    </div>
  )
}

export function getHttpStatusTone(statusCode?: string | number | null) {
  const code = Number(String(statusCode ?? '').match(/\d{3}/)?.[0])
  if (!Number.isFinite(code)) return 'neutral'
  if (code >= 200 && code < 300) return 'success'
  if (code >= 300 && code < 400) return 'info'
  if (code >= 400 && code < 500) return 'warning'
  if (code >= 500) return 'danger'
  return 'neutral'
}

export function getProgressTone(status?: string, value = 0) {
  const normalized = String(status || '').toLowerCase()
  if (normalized === 'completed' || value >= 100) return 'success'
  if (normalized === 'running' || normalized === 'canceling') return 'info'
  if (normalized === 'failed' || normalized === 'cancelled') return 'danger'
  if (normalized === 'pending' || normalized === 'paused') return 'warning'
  return 'neutral'
}

export function getProgressFillClass(tone: string) {
  const map: Record<string, string> = {
    success: 'bg-success',
    info: 'bg-info',
    warning: 'bg-warning',
    danger: 'bg-danger',
    neutral: 'bg-muted',
  }
  return map[tone] || map.neutral
}

export function getProgressTextClass(tone: string) {
  const map: Record<string, string> = {
    success: 'text-success-foreground',
    info: 'text-info-foreground',
    warning: 'text-warning-foreground',
    danger: 'text-danger-foreground',
    neutral: 'text-muted',
  }
  return map[tone] || map.neutral
}

export function PageTitle({ title, description }: { title: string; description?: string }) {
  return (
    <div className="mb-4">
      <h2 className="text-xl font-semibold tracking-tight">{title}</h2>
      {description ? <p className="mt-1 text-sm text-muted">{description}</p> : null}
    </div>
  )
}

const metricToneLabels: Record<string, string> = {
  info: '信息',
  warning: '警告',
  success: '成功',
  neutral: '普通',
  danger: '危险',
  accent: '重点',
}

export function Metric({ label, value, icon: Icon, tone = 'neutral', badgeLabel }: { label: string; value: React.ReactNode; icon: React.ElementType; tone?: any; badgeLabel?: string }) {
  const toneLabel = badgeLabel || label || metricToneLabels[String(tone)] || String(tone)
  return (
    <Card>
      <CardContent className="p-5">
        <div className="flex items-center justify-between text-sm text-muted">
          <span className="flex items-center gap-2"><Icon className="size-4" />{label}</span>
          <Badge tone={tone}>{toneLabel}</Badge>
        </div>
        <div className="mt-3 text-2xl font-bold">{value}</div>
      </CardContent>
    </Card>
  )
}

export function ToggleField({ label, checked, onChange }: { label: string; checked: boolean; onChange: (value: boolean) => void }) {
  return (
    <button type="button" className="flex items-center justify-between rounded-md border border-border bg-background px-3 py-2 text-sm" onClick={() => onChange(!checked)}>
      <span>{label}</span>
      <span className={cn('h-5 w-9 rounded-full border transition-colors', checked ? 'border-foreground bg-foreground' : 'border-border bg-raised')}>
        <span className={cn('block size-4 translate-y-0.5 rounded-full bg-background transition-transform', checked ? 'translate-x-4' : 'translate-x-0.5')} />
      </span>
    </button>
  )
}

export function PreviewLine({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex min-w-0 items-start justify-between gap-4 border-b border-border py-2">
      <span className="shrink-0 text-muted">{label}</span>
      <span className="min-w-0 break-all text-right font-mono text-foreground">{value}</span>
    </div>
  )
}

export function SeverityBadge({ severity, className }: { severity?: string; className?: string }) {
  const value = normalizeSeverityStatKey(severity)
  return (
    <Badge className={cn('min-w-12 justify-center whitespace-nowrap px-2.5', className)} tone={getSeverityTone(value) as any}>
      {getSeverityText(value)}
    </Badge>
  )
}
