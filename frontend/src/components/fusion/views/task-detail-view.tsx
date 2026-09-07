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
  Sparkles,
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
  getDirectoryResults,
  getFingerprintCategories,
  getFingerprintResults,
  getFingerprintStatistics,
  getFingerprintsPage,
  getIPDBInfo,
  getJSScanResults,
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
  getSubdomainResults,
  getTaskLogs,
  getTaskDetail,
  getTasks,
  getUsers,
  getWeakPasswordResults,
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
import { ScreenshotPreviewCell } from '@/components/fusion/screenshot-preview-cell'
import { LogConsole } from '@/components/fusion/log-console'
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
  getTaskTypeLabel,
  getTaskTypeValue,
  getModuleResultCount,
  isModuleTaskType,
  getPocTaskId,
  getPocTaskDisplayName,
  getHttpStatusTone,
  toTextList,
  PillList,
  getProgressTone,
  getProgressFillClass,
  getProgressTextClass,
  PageTitle,
  Metric,
  ToggleField,
  SeverityBadge
} from '@/components/fusion/shared'

type TargetRecord = {
  id: string
  index: number
  value: string
}

function getParsedTaskConfig(detail: any) {
  if (!detail?.config) return undefined
  if (typeof detail.config === 'string') {
    try {
      return JSON.parse(detail.config)
    } catch {
      return undefined
    }
  }
  return detail.config
}

function getTaskTargetInput(detail: any) {
  const config = getParsedTaskConfig(detail)
  const candidates = [
    detail?.targetInput,
    detail?.target_input,
    config?.targetInput,
    config?.target_input,
  ]
  for (const candidate of candidates) {
    if (Array.isArray(candidate)) {
      const text = candidate.map((item) => String(item || '').trim()).filter(Boolean).join('\n')
      if (text) return text
      continue
    }
    const text = String(candidate || '').trim()
    if (text) return text
  }
  return ''
}

function buildTaskTargetRecords(input: string): TargetRecord[] {
  const parsed = parseTargets(input)
  const items = parsed.length === 1 && /\s/.test(parsed[0])
    ? parsed[0].split(/\s+/).map((item) => item.trim()).filter(Boolean)
    : parsed

  return items.map((value, index) => ({
    id: `${index}-${value}`,
    index: index + 1,
    value,
  }))
}

function getTargetExportFileName(taskId: string, scope: string) {
  const safeTaskId = String(taskId || 'task').replace(/[^\w.-]+/g, '_').slice(0, 80) || 'task'
  const safeScope = String(scope || 'targets').replace(/[^\w.-]+/g, '_')
  return `${safeTaskId}-targets-${safeScope}.txt`
}

async function copyText(value: string) {
  const content = String(value || '')
  if (!content) throw new Error('没有可复制的内容')
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(content)
      return
    } catch {
      // Fall back for browsers that block clipboard access.
    }
  }
  const textarea = document.createElement('textarea')
  textarea.value = content
  textarea.setAttribute('readonly', 'true')
  textarea.style.position = 'fixed'
  textarea.style.left = '-9999px'
  textarea.style.top = '0'
  document.body.appendChild(textarea)
  textarea.focus()
  textarea.select()
  try {
    const copied = document.execCommand('copy')
    if (!copied) throw new Error('复制失败')
  } finally {
    document.body.removeChild(textarea)
  }
}

export function TaskDetailView({ demoMode, taskId, onBack, onAnalyzeWithAI }: { demoMode: boolean; taskId: string; onBack: () => void; onAnalyzeWithAI?: (context: string) => void }) {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = React.useState('ports')
  const [vulnDetail, setVulnDetail] = React.useState<any | null>(null)
  const [targetDrawerOpen, setTargetDrawerOpen] = React.useState(false)
  const [targetKeyword, setTargetKeyword] = React.useState('')
  const [selectedTargets, setSelectedTargets] = React.useState<Set<string>>(new Set())
  const query = useQuery({ queryKey: ['task-detail', taskId], queryFn: () => getTaskDetail(taskId), enabled: !!taskId && !demoMode, refetchInterval: 3000 })
  const detail = demoMode ? demoTasks.find((task) => getTaskId(task) === taskId) || demoTasks[0] : unwrap<any>(query.data)
  const taskType = getTaskTypeValue(detail)
  const moduleTask = isModuleTaskType(taskType)
  const portsQuery = useQuery({ queryKey: ['task-recon', taskId, 'port'], queryFn: () => getReconResults(taskId, 'port'), enabled: !!taskId && !demoMode, refetchInterval: 2000 })
  const urlsQuery = useQuery({ queryKey: ['task-recon', taskId, 'url'], queryFn: () => getReconResults(taskId, 'url'), enabled: !!taskId && !demoMode, refetchInterval: 3000 })
  const fingerprintsQuery = useQuery({ queryKey: ['task-fingerprints', taskId], queryFn: () => getFingerprintResults(taskId), enabled: !!taskId && !demoMode, refetchInterval: 3000 })
  const vulnsQuery = useQuery({ queryKey: ['task-vulns', taskId], queryFn: () => getVulnResults(taskId), enabled: !!taskId && !demoMode, refetchInterval: 3000 })
  const subdomainResultsQuery = useQuery({ queryKey: ['task-subdomains', taskId], queryFn: () => getSubdomainResults(taskId), enabled: !!taskId && taskType === 'subdomain' && !demoMode, refetchInterval: 3000 })
  const weakPasswordResultsQuery = useQuery({ queryKey: ['task-weak-passwords', taskId], queryFn: () => getWeakPasswordResults(taskId), enabled: !!taskId && taskType === 'weak_password' && !demoMode, refetchInterval: 3000 })
  const directoryResultsQuery = useQuery({ queryKey: ['task-directories', taskId], queryFn: () => getDirectoryResults(taskId), enabled: !!taskId && taskType === 'directory' && !demoMode, refetchInterval: 3000 })
  const jsResultsQuery = useQuery({ queryKey: ['task-js-results', taskId], queryFn: () => getJSScanResults(taskId), enabled: !!taskId && taskType === 'js' && !demoMode, refetchInterval: 3000 })
  const logsQuery = useQuery({ queryKey: ['task-logs', taskId], queryFn: () => getTaskLogs(taskId, { page: 1, pageSize: 200 }), enabled: !!taskId && !demoMode, refetchInterval: 3000 })
  const ports = demoMode
    ? [
        { host: '10.10.10.12', port: 443, protocol: 'https', service: 'nginx', status: 'open', banner: 'nginx/1.24' },
        { host: '10.10.10.12', port: 22, protocol: 'tcp', service: 'ssh', status: 'open', banner: 'OpenSSH' },
      ]
    : asList<any>(portsQuery.data)
  const urls = demoMode
    ? [
        { url: 'https://acme.com', statusCode: 200, title: 'Acme Portal', length: 32891 },
        { url: 'https://acme.com/admin', statusCode: 403, title: 'Forbidden', length: 1204 },
      ]
    : asList<any>(urlsQuery.data)
  const fingerprintRows = demoMode
    ? [
        { url: 'https://acme.com', name: 'nginx', category: 'Web Server', type: 'passive' },
        { url: 'https://acme.com', name: 'Spring Boot', category: 'Framework', type: 'active' },
      ]
    : asList<any>(fingerprintsQuery.data)
  const vulns = demoMode
    ? [
        { id: 1, name: 'Spring Actuator Exposure', severity: 'high', url: 'https://acme.com/actuator/env', request: 'GET /actuator/env HTTP/1.1', response: 'HTTP/1.1 200 OK' },
      ]
    : asList<any>(vulnsQuery.data)
  const logs = demoMode
    ? [
        { time: '2026-07-03 19:20:00', level: 'info', message: '任务开始执行' },
        { time: '2026-07-03 19:21:14', level: 'success', message: '发现开放端口 443' },
      ]
    : asList<any>(logsQuery.data)
  const moduleRows = React.useMemo(() => {
    if (taskType === 'subdomain') return asList<any>(subdomainResultsQuery.data)
    if (taskType === 'weak_password') return asList<any>(weakPasswordResultsQuery.data)
    if (taskType === 'directory') return asList<any>(directoryResultsQuery.data)
    if (taskType === 'js') return asList<any>(jsResultsQuery.data)
    return []
  }, [taskType, subdomainResultsQuery.data, weakPasswordResultsQuery.data, directoryResultsQuery.data, jsResultsQuery.data])
  const moduleResultCount = getModuleResultCount(detail) || moduleRows.length
  const assignedWorker = String(detail?.assignedWorker || detail?.assigned_worker || '').trim()
  const actualWorker = String(detail?.workerID || detail?.workerId || detail?.worker_id || '').trim()
  const actualWorkerLabel = actualWorker || (detail?.status === 'pending' ? (assignedWorker ? `等待 ${assignedWorker} 消费` : '待自动分配') : '-')
  const targetInputText = React.useMemo(() => getTaskTargetInput(detail), [detail])
  const targetRecords = React.useMemo(() => buildTaskTargetRecords(targetInputText), [targetInputText])
  const filteredTargetRecords = React.useMemo(() => {
    const keyword = targetKeyword.trim().toLowerCase()
    if (!keyword) return targetRecords
    return targetRecords.filter((item) => item.value.toLowerCase().includes(keyword) || String(item.index).includes(keyword))
  }, [targetKeyword, targetRecords])
  const selectedTargetRecords = React.useMemo(
    () => targetRecords.filter((item) => selectedTargets.has(item.id)),
    [selectedTargets, targetRecords]
  )
  const allVisibleTargetsSelected = filteredTargetRecords.length > 0 && filteredTargetRecords.every((item) => selectedTargets.has(item.id))

  React.useEffect(() => {
    setSelectedTargets((current) => {
      if (!current.size) return current
      const validIDs = new Set(targetRecords.map((item) => item.id))
      const next = new Set(Array.from(current).filter((id) => validIDs.has(id)))
      if (next.size !== current.size) return next
      for (const id of next) {
        if (!current.has(id)) return next
      }
      return current
    })
  }, [targetRecords])

  React.useEffect(() => {
    if (moduleTask && activeTab !== 'module') {
      setActiveTab('module')
    }
    if (!moduleTask && activeTab === 'module') {
      setActiveTab('ports')
    }
  }, [activeTab, moduleTask])

  const actionMutation = useMutation({
    mutationFn: async (action: string) => {
      if (demoMode) return null
      if (action === 'pause') return pauseTask(taskId)
      if (action === 'resume') return resumeTask(taskId)
      if (action === 'stop') return stopTask(taskId)
      if (action === 'restart') return restartTask(taskId)
      return null
    },
    onSuccess: () => {
      toast.success('任务操作已提交')
      queryClient.invalidateQueries({ queryKey: ['task-detail', taskId] })
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
    },
    onError: (error: any) => toast.error(error.message || '操作失败'),
  })
  const exportMutation = useMutation({
    mutationFn: async (type: 'html' | 'excel' | 'markdown') => {
      if (demoMode) return null
      return downloadTaskReport(taskId, type)
    },
    onSuccess: (res: any, type) => {
      const fallbackName = getReportFileName(taskId, type)
      if (demoMode) {
        downloadContent(`Demo ${type.toUpperCase()} report`, fallbackName)
      } else {
        downloadBlobResponse(res, fallbackName)
      }
      toast.success(`${getReportTypeLabel(type)} 报告已下载`)
    },
    onError: (error: any) => toast.error(error.message || '报告生成失败'),
  })
  const toggleTargetSelection = (id: string, checked: boolean) => {
    setSelectedTargets((current) => {
      const next = new Set(current)
      if (checked) {
        next.add(id)
      } else {
        next.delete(id)
      }
      return next
    })
  }
  const toggleVisibleTargets = () => {
    setSelectedTargets((current) => {
      const next = new Set(current)
      if (allVisibleTargetsSelected) {
        filteredTargetRecords.forEach((item) => next.delete(item.id))
      } else {
        filteredTargetRecords.forEach((item) => next.add(item.id))
      }
      return next
    })
  }
  const clearSelectedTargets = () => setSelectedTargets(new Set())
  const clearTargetSearch = () => setTargetKeyword('')
  const copyTarget = async (target: string) => {
    try {
      await copyText(target)
      toast.success('目标已复制')
    } catch (error: any) {
      toast.error(error.message || '复制失败')
    }
  }
  const exportTargets = (records: TargetRecord[], fileName: string, emptyMessage: string) => {
    if (!records.length) {
      toast.error(emptyMessage)
      return
    }
    downloadContent(records.map((item) => item.value).join('\n') + '\n', fileName)
    toast.success('目标已导出')
  }
  const portColumns: ColumnDef<any>[] = [
    { header: '主机', accessorKey: 'host', meta: { className: 'w-[220px]' }, cell: ({ row }) => <span className="block truncate font-mono" title={row.original.host || row.original.ip || '-'}>{row.original.host || row.original.ip || '-'}</span> },
    { header: '端口', accessorKey: 'port', meta: { align: 'center', className: 'w-[120px]' }, cell: ({ row }) => <Badge tone="info">{row.original.port}</Badge> },
    { header: '协议', accessorKey: 'protocol', meta: { align: 'center', className: 'w-[140px]' }, cell: ({ row }) => row.original.protocol || '-' },
    { header: '服务', accessorKey: 'service', meta: { align: 'center', className: 'w-[220px]' }, cell: ({ row }) => <span className="block truncate" title={row.original.service || '-'}>{row.original.service || '-'}</span> },
    { header: '状态', accessorKey: 'status', meta: { align: 'center', className: 'w-[120px]' }, cell: ({ row }) => <Badge tone={String(row.original.status).includes('open') ? 'success' : 'neutral'}>{row.original.status || '-'}</Badge> },
    { header: 'Banner', accessorKey: 'banner', meta: { className: 'w-[360px] max-w-[360px]' }, cell: ({ row }) => <span className="block max-w-[360px] truncate font-mono text-xs text-muted" title={row.original.banner || '-'}>{row.original.banner || '-'}</span> },
  ]
  const urlColumns: ColumnDef<any>[] = [
    {
      header: 'URL',
      accessorKey: 'url',
      meta: { className: 'w-[420px]' },
      cell: ({ row }) => {
        const url = row.original.displayURL || row.original.display_url || row.original.finalURL || row.original.final_url || row.original.url || row.original.target || '-'
        return <span className="block truncate font-mono text-sm" title={url}>{url}</span>
      },
    },
    { header: '状态码', accessorKey: 'statusCode', meta: { align: 'center', className: 'w-[120px]' }, cell: ({ row }) => {
      const code = row.original.statusCode || row.original.status_code || '-'
      return <Badge tone={getHttpStatusTone(code) as any}>{code}</Badge>
    } },
    { header: '标题', accessorKey: 'title', meta: { align: 'center', className: 'w-[220px]' }, cell: ({ row }) => <span className="block truncate" title={row.original.title || '-'}>{row.original.title || '-'}</span> },
    { header: '长度', accessorKey: 'length', meta: { align: 'center', className: 'w-[100px]' }, cell: ({ row }) => row.original.length || row.original.contentLength || row.original.content_length || 0 },
    { header: '截图', accessorKey: 'screenshotPath', meta: { align: 'center', className: 'w-[96px]' }, cell: ({ row }) => <ScreenshotPreviewCell size="compact" taskId={taskId || ''} resultId={row.original.id} screenshotPath={row.original.screenshotPath || row.original.screenshot_path} label={row.original.displayURL || row.original.display_url || row.original.url || row.original.target || '-'} /> },
  ]
  const getFingerprintTarget = (row: any) => row.url || row.target || row.matchedRules?.url || row.matched_rules?.url || '-'
  const getFingerprintName = (row: any) => row.name || row.fingerprint || row.fingerprintName || row.fingerprint_name || row.matchedRules?.fingerprint || row.matched_rules?.fingerprint || '-'
  const getFingerprintRule = (row: any) => {
    const rules = row.matchedRules || row.matched_rules
    if (Array.isArray(rules)) return rules.map((item) => (typeof item === 'string' ? item : item?.rule || item?.matcher || item?.name || JSON.stringify(item))).join(', ')
    if (rules && typeof rules === 'object') return rules.rule || rules.matcher || rules.name || rules.header || rules.body || row.source || row.matcher || '-'
    return row.source || row.matcher || (typeof rules === 'string' ? rules : '-') || '-'
  }
  const groupedFingerprints = Array.from(
    fingerprintRows.reduce((map, row) => {
      const target = getFingerprintTarget(row)
      const key = target || '-'
      const group = map.get(key) || { target: key, rows: [] as any[] }
      group.rows.push(row)
      map.set(key, group)
      return map
    }, new Map<string, { target: string; rows: any[] }>())
  ).map(([, group]) => {
    const names = Array.from(new Set(group.rows.map(getFingerprintName).filter((name) => name && name !== '-')))
    const categories = Array.from(new Set(group.rows.map((row) => row.category || row.type || row.scanScope || row.scan_scope || 'web').filter(Boolean)))
    const rules = Array.from(new Set(group.rows.map(getFingerprintRule).filter((rule) => rule && rule !== '-')))
    const latestTime = group.rows
      .map((row) => row.identifiedAt || row.identified_at || row.createdAt || row.created_at)
      .filter(Boolean)
      .sort()
      .at(-1)

    return {
      ...group,
      fingerprintNames: names,
      categories,
      rules,
      latestTime,
      fingerprintsText: names.join(' '),
      rulesText: rules.join(' '),
      searchText: [group.target, ...names, ...categories, ...rules].join(' '),
    }
  })
  const fingerprintColumns: ColumnDef<any>[] = [
    { header: '目标', accessorKey: 'target', cell: ({ row }) => <span className="font-mono text-sm">{row.original.target}</span> },
    {
      header: '指纹',
      accessorKey: 'fingerprintsText',
      cell: ({ row }) => (
        <div className="flex max-w-xl flex-wrap gap-1.5">
          {row.original.fingerprintNames.length ? row.original.fingerprintNames.map((name: string) => <Badge key={name} tone="info">{name}</Badge>) : <span className="text-muted">-</span>}
        </div>
      ),
    },
    {
      header: '分类',
      accessorKey: 'categories',
      cell: ({ row }) => (
        <div className="flex flex-wrap gap-1.5">
          {row.original.categories.map((category: string) => <Badge key={category}>{category}</Badge>)}
        </div>
      ),
    },
    { header: '数量', accessorKey: 'rows', cell: ({ row }) => <Badge tone="neutral">{row.original.rows.length}</Badge> },
    { header: '最后识别', accessorKey: 'latestTime', cell: ({ row }) => <span className="text-muted">{formatTime(row.original.latestTime)}</span> },
  ]
  const vulnInfo = normalizeVulnDetail(vulnDetail)
  const vulnColumns: ColumnDef<any>[] = [
    { header: '漏洞', accessorKey: 'name', cell: ({ row }) => <span className="font-medium">{getVulnDisplayName(row.original)}</span> },
    { header: '等级', accessorKey: 'severity', cell: ({ row }) => <SeverityBadge severity={row.original.severity || row.original.info?.severity} /> },
    { header: '目标', accessorKey: 'target', cell: ({ row }) => <span className="font-mono text-sm">{getVulnTarget(row.original)}</span> },
    { header: '模板', accessorKey: 'templateId', meta: { className: 'w-[220px]' }, cell: ({ row }) => {
      const templateId = getVulnTemplateID(row.original)
      return <span className="block truncate font-mono text-xs text-muted" title={templateId}>{templateId}</span>
    } },
    { header: '操作', meta: { align: 'right' }, cell: ({ row }) => <Button size="sm" variant="outline" onClick={() => setVulnDetail(row.original)}><Eye className="size-4" />详情</Button> },
  ]
  const moduleColumns: ColumnDef<any>[] = React.useMemo(() => {
    if (taskType === 'subdomain') {
      return [
        { header: '根域名', accessorKey: 'domain', meta: { className: 'w-[220px]' }, cell: ({ row }) => <span className="font-mono text-sm">{row.original.domain || '-'}</span> },
        { header: '子域名', accessorKey: 'subdomain', meta: { className: 'w-[360px]' }, cell: ({ row }) => <span className="block truncate font-mono text-sm" title={row.original.subdomain || '-'}>{row.original.subdomain || '-'}</span> },
        { header: 'IP', accessorKey: 'ipAddresses', meta: { className: 'w-[300px]' }, cell: ({ row }) => {
          const ips = Array.isArray(row.original.ipAddresses) ? row.original.ipAddresses : Array.isArray(row.original.ip_addresses) ? row.original.ip_addresses : []
          return <span className="block truncate font-mono text-xs text-muted" title={ips.join(', ')}>{ips.length ? ips.join(', ') : '-'}</span>
        } },
        { header: 'CNAME', accessorKey: 'cname', meta: { className: 'w-[280px]' }, cell: ({ row }) => <span className="block truncate font-mono text-xs text-muted" title={row.original.cname || '-'}>{row.original.cname || '-'}</span> },
        { header: '来源', accessorKey: 'source', meta: { align: 'center', className: 'w-[140px]' }, cell: ({ row }) => <Badge tone="info">{row.original.source || 'subfinder'}</Badge> },
        { header: '发现时间', accessorKey: 'discoveredAt', meta: { className: 'w-[180px]' }, cell: ({ row }) => <span className="text-muted">{formatTime(row.original.discoveredAt || row.original.discovered_at)}</span> },
      ]
    }
    if (taskType === 'weak_password') {
      return [
        { header: '目标', accessorKey: 'target', meta: { className: 'w-[260px]' }, cell: ({ row }) => <span className="block truncate font-mono text-sm" title={row.original.target || '-'}>{row.original.target || '-'}</span> },
        { header: '服务', accessorKey: 'service', meta: { align: 'center', className: 'w-[120px]' }, cell: ({ row }) => <Badge tone="info">{row.original.service || '-'}</Badge> },
        { header: '主机', accessorKey: 'host', meta: { className: 'w-[220px]' }, cell: ({ row }) => <span className="font-mono text-sm">{row.original.host || '-'}</span> },
        { header: '端口', accessorKey: 'port', meta: { align: 'center', className: 'w-[100px]' }, cell: ({ row }) => <Badge>{row.original.port || '-'}</Badge> },
        { header: '用户名', accessorKey: 'username', meta: { align: 'center', className: 'w-[160px]' }, cell: ({ row }) => <span className="font-mono text-sm">{row.original.username || '-'}</span> },
        { header: '密码', accessorKey: 'password', meta: { align: 'center', className: 'w-[180px]' }, cell: ({ row }) => <span className="font-mono text-sm">{row.original.password || '-'}</span> },
        { header: '等级', accessorKey: 'severity', meta: { align: 'center', className: 'w-[120px]' }, cell: ({ row }) => <SeverityBadge severity={row.original.severity || 'high'} /> },
        { header: '发现时间', accessorKey: 'discoveredAt', meta: { className: 'w-[180px]' }, cell: ({ row }) => <span className="text-muted">{formatTime(row.original.discoveredAt || row.original.discovered_at)}</span> },
      ]
    }
    if (taskType === 'directory') {
      return [
        { header: 'URL', accessorKey: 'url', meta: { className: 'w-[520px]' }, cell: ({ row }) => <span className="block truncate font-mono text-sm" title={row.original.url || '-'}>{row.original.url || '-'}</span> },
        { header: '路径', accessorKey: 'path', meta: { className: 'w-[220px]' }, cell: ({ row }) => <span className="block truncate font-mono text-sm" title={row.original.path || '-'}>{row.original.path || '-'}</span> },
        { header: '状态码', accessorKey: 'statusCode', meta: { align: 'center', className: 'w-[120px]' }, cell: ({ row }) => <Badge tone={getHttpStatusTone(row.original.statusCode || row.original.status_code) as any}>{row.original.statusCode || row.original.status_code || '-'}</Badge> },
        { header: '长度', accessorKey: 'contentLength', meta: { align: 'center', className: 'w-[120px]' }, cell: ({ row }) => row.original.contentLength || row.original.content_length || 0 },
        { header: '类型', accessorKey: 'contentType', meta: { className: 'w-[220px]' }, cell: ({ row }) => <span className="block truncate text-xs text-muted" title={row.original.contentType || row.original.content_type || '-'}>{row.original.contentType || row.original.content_type || '-'}</span> },
        { header: '跳转', accessorKey: 'redirectLocation', meta: { className: 'w-[320px]' }, cell: ({ row }) => <span className="block truncate font-mono text-xs text-muted" title={row.original.redirectLocation || row.original.redirect_location || '-'}>{row.original.redirectLocation || row.original.redirect_location || '-'}</span> },
        { header: '发现时间', accessorKey: 'discoveredAt', meta: { className: 'w-[180px]' }, cell: ({ row }) => <span className="text-muted">{formatTime(row.original.discoveredAt || row.original.discovered_at)}</span> },
      ]
    }
    if (taskType === 'js') {
      return [
        { header: '类型', accessorKey: 'resultType', meta: { align: 'center', className: 'w-[140px]' }, cell: ({ row }) => <Badge tone="info">{row.original.resultType || row.original.result_type || '-'}</Badge> },
        { header: '发现内容', accessorKey: 'value', meta: { className: 'w-[520px]' }, cell: ({ row }) => <span className="block truncate font-mono text-sm" title={row.original.value || '-'}>{row.original.value || '-'}</span> },
        { header: '来源 JS', accessorKey: 'sourceURL', meta: { className: 'w-[420px]' }, cell: ({ row }) => <span className="block truncate font-mono text-xs text-muted" title={row.original.sourceURL || row.original.source_url || '-'}>{row.original.sourceURL || row.original.source_url || '-'}</span> },
        { header: '目标', accessorKey: 'target', meta: { className: 'w-[260px]' }, cell: ({ row }) => <span className="block truncate font-mono text-sm" title={row.original.target || '-'}>{row.original.target || '-'}</span> },
        { header: '等级', accessorKey: 'severity', meta: { align: 'center', className: 'w-[120px]' }, cell: ({ row }) => <SeverityBadge severity={row.original.severity || 'info'} /> },
        { header: '发现时间', accessorKey: 'discoveredAt', meta: { className: 'w-[180px]' }, cell: ({ row }) => <span className="text-muted">{formatTime(row.original.discoveredAt || row.original.discovered_at)}</span> },
      ]
    }
    return []
  }, [taskType])
  const targetCount = targetRecords.length

  return (
    <div className="grid gap-4">
      <div className="flex items-center justify-between">
        <PageTitle title="任务详情" description={taskId || '请选择任务'} />
        <div className="flex flex-wrap justify-end gap-2">
          <Button variant="outline" onClick={onBack}>返回列表</Button>
          <Button variant="outline" onClick={() => onAnalyzeWithAI?.(`请分析以下 FusionWeb 扫描任务，并给出风险判断、重点验证顺序和修复建议。\n\n任务 ID：${taskId}\n任务名称：${detail?.taskName || detail?.task_name || '-'}\n任务类型：${taskType || '-'}\n目标：${targetInputText || '-'}\n状态：${detail?.status || '-'}\n进度：${Math.round(detail?.percentage || detail?.progress || 0)}%\n端口结果数：${ports.length}\nURL 结果数：${urls.length}\n指纹结果数：${fingerprintRows.length}\n漏洞结果数：${vulns.length}`)} disabled={!taskId || !detail}><Sparkles className="size-4" />用 AI 分析</Button>
          <Button variant="outline" onClick={() => setTargetDrawerOpen(true)} disabled={!taskId}><Globe2 className="size-4" />目标</Button>
          <Button variant="outline" onClick={() => actionMutation.mutate('restart')} disabled={!taskId || actionMutation.isPending}><RotateCcw className="size-4" />重启</Button>
          <Button variant="outline" onClick={() => actionMutation.mutate('pause')} disabled={!taskId || actionMutation.isPending}><Pause className="size-4" />暂停</Button>
          <Button variant="outline" onClick={() => actionMutation.mutate('resume')} disabled={!taskId || actionMutation.isPending}><Play className="size-4" />恢复</Button>
          <Button variant="danger" onClick={() => actionMutation.mutate('stop')} disabled={!taskId || actionMutation.isPending}><Square className="size-4" />停止</Button>
        </div>
      </div>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
        <Metric label="状态" value={getStatusLabel(detail?.status)} icon={Activity} tone={getStatusTone(detail?.status) as any} badgeLabel="状态" />
        <Metric label="进度" value={`${Math.round(detail?.percentage || detail?.progress || 0)}%`} icon={RadioTower} tone="info" badgeLabel="进度" />
        <Metric label="指定节点" value={assignedWorker || '自动分配'} icon={Monitor} tone="accent" badgeLabel="调度" />
        <Metric label="实际执行节点" value={actualWorkerLabel} icon={MapPin} tone="neutral" badgeLabel="调度" />
        <Metric label="创建时间" value={formatTime(detail?.createTime || detail?.createdAt)} icon={History} tone="info" badgeLabel="调度" />
        <Metric label={moduleTask ? '结果' : '漏洞'} value={moduleTask ? moduleResultCount : detail?.vulnCount || vulns.length || 0} icon={moduleTask ? ListChecks : Bug} tone={moduleTask ? 'success' : 'danger'} badgeLabel={moduleTask ? '结果' : '漏洞'} />
        <Metric label="目标" value={targetCount} icon={Globe2} tone="accent" badgeLabel="目标" />
      </div>
      <Card>
        <CardHeader>
          <div>
            <CardTitle>扫描结果</CardTitle>
            <CardDescription>{moduleTask ? `${getTaskTypeLabel(detail)}结果来自独立数据表。` : '端口、URL、指纹、漏洞与运行日志按功能拆分。'}</CardDescription>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="outline" onClick={() => exportMutation.mutate('html')} disabled={!taskId || exportMutation.isPending}><FileText className="size-4" />HTML</Button>
            <Button size="sm" variant="outline" onClick={() => exportMutation.mutate('excel')} disabled={!taskId || exportMutation.isPending}><FileDown className="size-4" />Excel</Button>
            <Button size="sm" variant="outline" onClick={() => exportMutation.mutate('markdown')} disabled={!taskId || exportMutation.isPending}><Download className="size-4" />Markdown</Button>
          </div>
        </CardHeader>
        <CardContent>
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList>
              {moduleTask ? (
                <TabsTrigger value="module"><ListChecks className="size-4" />模块结果</TabsTrigger>
              ) : (
                <>
                  <TabsTrigger value="ports"><Network className="size-4" />端口信息</TabsTrigger>
                  <TabsTrigger value="urls"><Globe2 className="size-4" />目标信息</TabsTrigger>
                  <TabsTrigger value="fingerprints"><Fingerprint className="size-4" />指纹信息</TabsTrigger>
                  <TabsTrigger value="vulns"><Bug className="size-4" />漏洞信息</TabsTrigger>
                </>
              )}
              <TabsTrigger value="logs"><Terminal className="size-4" />运行日志</TabsTrigger>
            </TabsList>
            {moduleTask ? (
              <TabsContent value="module"><DataTable columns={moduleColumns} data={moduleRows} searchPlaceholder="搜索模块结果" tableClassName="table-fixed min-w-[1180px]" paginationStorageKey={`task-detail-module-${taskType}`} /></TabsContent>
            ) : (
              <>
                <TabsContent value="ports"><DataTable columns={portColumns} data={ports} searchPlaceholder="搜索主机、端口或服务" tableClassName="table-fixed min-w-[1220px]" paginationStorageKey="task-detail-ports" /></TabsContent>
                <TabsContent value="urls"><DataTable columns={urlColumns} data={urls} searchPlaceholder="搜索 URL 或标题" tableClassName="table-fixed" paginationStorageKey="task-detail-urls" /></TabsContent>
                <TabsContent value="fingerprints"><DataTable columns={fingerprintColumns} data={groupedFingerprints} searchPlaceholder="搜索指纹或目标" paginationStorageKey="task-detail-fingerprints" /></TabsContent>
                <TabsContent value="vulns"><DataTable columns={vulnColumns} data={vulns} searchPlaceholder="搜索漏洞、模板或目标" paginationStorageKey="task-detail-vulns" /></TabsContent>
              </>
            )}
            <TabsContent value="logs"><LogConsole rows={logs} emptyTitle="暂无运行日志" maxHeightClass="max-h-[520px]" /></TabsContent>
          </Tabs>
        </CardContent>
      </Card>
      <Drawer
        open={targetDrawerOpen}
        onOpenChange={setTargetDrawerOpen}
        title="任务目标"
        description="创建任务时输入的目标"
        className="max-w-none md:w-[720px]"
      >
        <div className="grid min-h-0 gap-4">
          <div className="grid gap-3">
            <div className="flex items-center gap-2">
              <Input value={targetKeyword} onChange={(event) => setTargetKeyword(event.target.value)} placeholder="搜索目标" />
              <Button size="sm" variant="outline" onClick={clearTargetSearch} disabled={!targetKeyword.trim()}>
                <XCircle className="size-4" />
                清空搜索
              </Button>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" variant="outline" onClick={toggleVisibleTargets} disabled={!filteredTargetRecords.length}>
                <ListChecks className="size-4" />
                {allVisibleTargetsSelected ? '取消当前' : '全选当前'}
              </Button>
              <Button size="sm" variant="outline" onClick={clearSelectedTargets} disabled={!selectedTargets.size}>
                <XCircle className="size-4" />
                清空选择
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => exportTargets(selectedTargetRecords, getTargetExportFileName(taskId, 'selected'), '请先选择目标')}
                disabled={!selectedTargetRecords.length}
              >
                <FileDown className="size-4" />
                批量导出
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => exportTargets(targetRecords, getTargetExportFileName(taskId, 'all'), '暂无目标可导出')}
                disabled={!targetRecords.length}
              >
                <Download className="size-4" />
                全部导出
              </Button>
              <Badge tone="neutral">已选 {selectedTargetRecords.length}</Badge>
            </div>
          </div>

          {targetRecords.length ? (
            <div className="min-h-0 overflow-hidden rounded-card border border-border bg-background">
              <div className="flex items-center justify-between gap-3 border-b border-border bg-raised px-4 py-2 text-xs text-muted">
                <span>当前 {filteredTargetRecords.length} / 全部 {targetRecords.length}</span>
                <span>每行一个目标</span>
              </div>
              <div className="grid max-h-[calc(100vh-260px)] gap-0 overflow-auto">
                {filteredTargetRecords.length ? (
                  filteredTargetRecords.map((item) => (
                    <div key={item.id} className="grid min-w-0 grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3 border-b border-border px-4 py-3 last:border-b-0">
                      <input
                        type="checkbox"
                        className="size-4 accent-[var(--info)]"
                        checked={selectedTargets.has(item.id)}
                        onChange={(event) => toggleTargetSelection(item.id, event.target.checked)}
                        aria-label={`选择目标 ${item.index}`}
                      />
                      <div className="min-w-0">
                        <div className="text-xs text-muted">#{String(item.index).padStart(3, '0')}</div>
                        <div className="break-all font-mono text-sm text-foreground">{item.value}</div>
                      </div>
                      <div className="flex shrink-0 items-center gap-1">
                        <Button size="icon" variant="ghost" title="复制目标" aria-label={`复制目标 ${item.index}`} onClick={() => copyTarget(item.value)}>
                          <Copy className="size-4" />
                        </Button>
                        <Button size="icon" variant="ghost" title="导出目标" aria-label={`导出目标 ${item.index}`} onClick={() => exportTargets([item], getTargetExportFileName(taskId, `target-${item.index}`), '暂无目标可导出')}>
                          <FileDown className="size-4" />
                        </Button>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="px-4 py-10 text-center text-sm text-muted">没有匹配目标</div>
                )}
              </div>
            </div>
          ) : (
            <EmptyState title="暂无目标" />
          )}
        </div>
      </Drawer>
      <Drawer
        open={!!vulnDetail}
        onOpenChange={(open) => !open && setVulnDetail(null)}
        title="漏洞详情"
        description={vulnInfo.target}
        className="max-w-none md:w-[60vw]"
      >
        {vulnDetail ? (
          <div className="grid gap-5">
            <section className="rounded-card border border-border bg-background">
              <div className="grid border-b border-border md:grid-cols-[140px_1fr]">
                <div className="bg-raised px-4 py-3 text-sm font-semibold text-muted">目标信息</div>
                <div className="min-w-0 px-4 py-3 font-mono text-sm text-foreground">{vulnInfo.target}</div>
              </div>
              <VulnDetailRow label="漏洞名称" value={vulnInfo.name} />
              <VulnDetailRow label="模板 ID" value={vulnInfo.templateID} mono />
              {vulnInfo.templatePath !== '-' ? <VulnDetailRow label="模板路径" value={vulnInfo.templatePath} mono /> : null}
              <VulnDetailRow label="严重程度" value={<SeverityBadge severity={vulnInfo.severity} />} />
              {vulnInfo.author !== '-' ? <VulnDetailRow label="作者信息" value={vulnInfo.author} /> : null}
              <VulnDetailRow label="标签" value={vulnInfo.tags} />
              {vulnInfo.matcherName !== '-' && vulnInfo.matcherName !== vulnInfo.tags ? <VulnDetailRow label="匹配器" value={vulnInfo.matcherName} /> : null}
              <VulnDetailRow label="漏洞描述" value={vulnInfo.description} />
              <VulnDetailRow label="发现时间" value={formatTime(vulnInfo.discoveredAt)} />
            </section>

            {vulnInfo.request || vulnInfo.response ? (
              <Tabs defaultValue={vulnInfo.request ? 'request' : 'response'}>
                <TabsList>
                  {vulnInfo.request ? <TabsTrigger value="request"><FileText className="size-4" />请求 Request</TabsTrigger> : null}
                  {vulnInfo.response ? <TabsTrigger value="response"><Terminal className="size-4" />响应 Response</TabsTrigger> : null}
                </TabsList>
                {vulnInfo.request ? (
                  <TabsContent value="request">
                    <HttpCodePanel title="请求 Request" value={vulnInfo.request} />
                  </TabsContent>
                ) : null}
                {vulnInfo.response ? (
                  <TabsContent value="response">
                    <HttpCodePanel title="响应 Response" value={vulnInfo.response} />
                  </TabsContent>
                ) : null}
              </Tabs>
            ) : (
              <div className="rounded-card border border-dashed border-border p-8 text-center text-sm text-muted">暂无请求或响应数据</div>
            )}
          </div>
        ) : null}
      </Drawer>
    </div>
  )
}

