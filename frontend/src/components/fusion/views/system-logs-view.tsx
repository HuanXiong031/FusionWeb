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
  clearAccessLogs,
  clearLoginLogs,
  clearOperationLogs,
  clearUnauthorizedAccessLogs,
  getBlacklistByCategory,
  getDashboardStats,
  getAccessLogs,
  getFingerprintCategories,
  getFingerprintResults,
  getFingerprintStatistics,
  getFingerprintsPage,
  getIPDBInfo,
  getManualVulnVerifyListByGroup,
  getOperationLogs,
  getUnauthorizedAccessLogs,
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
import { asList, cn, compactNumber, currentChinaTimeString, formatTime, getStatusLabel, getStatusTone, parseTargets, unwrap } from '@/lib/utils'
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

export function SystemLogsView({ demoMode }: { demoMode: boolean }) {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = React.useState<'login' | 'access' | 'operation' | 'unauthorized'>('login')
  const [loginFilters, setLoginFilters] = React.useState({ username: '', ip: '', result: '' })
  const [accessFilters, setAccessFilters] = React.useState({ ip: '', method: '', path: '', status: '' })
  const [operationFilters, setOperationFilters] = React.useState({ username: '', ip: '', method: '', path: '', action: '', status: '' })
  const [unauthorizedFilters, setUnauthorizedFilters] = React.useState({ ip: '', method: '', path: '', reason: '', status: '' })

  const loginQuery = useQuery({
    queryKey: ['login-logs', loginFilters],
    queryFn: () => getLoginLogs({ all: 1, username: loginFilters.username, ip: loginFilters.ip, result: loginFilters.result }),
    enabled: !demoMode,
    refetchInterval: activeTab === 'login' ? 10000 : false,
  })
  const accessQuery = useQuery({
    queryKey: ['access-logs', accessFilters],
    queryFn: () => getAccessLogs({ all: 1, ip: accessFilters.ip, method: accessFilters.method, path: accessFilters.path, status: accessFilters.status }),
    enabled: !demoMode,
    refetchInterval: activeTab === 'access' ? 5000 : false,
  })
  const operationQuery = useQuery({
    queryKey: ['operation-logs', operationFilters],
    queryFn: () => getOperationLogs({ all: 1, username: operationFilters.username, ip: operationFilters.ip, method: operationFilters.method, path: operationFilters.path, action: operationFilters.action, status: operationFilters.status }),
    enabled: !demoMode,
    refetchInterval: activeTab === 'operation' ? 5000 : false,
  })
  const unauthorizedQuery = useQuery({
    queryKey: ['unauthorized-access-logs', unauthorizedFilters],
    queryFn: () => getUnauthorizedAccessLogs({ all: 1, ip: unauthorizedFilters.ip, method: unauthorizedFilters.method, path: unauthorizedFilters.path, reason: unauthorizedFilters.reason, status: unauthorizedFilters.status }),
    enabled: !demoMode,
    refetchInterval: activeTab === 'unauthorized' ? 5000 : false,
  })

  const loginData = unwrap<any>(loginQuery.data) || {}
  const accessData = unwrap<any>(accessQuery.data) || {}
  const operationData = unwrap<any>(operationQuery.data) || {}
  const unauthorizedData = unwrap<any>(unauthorizedQuery.data) || {}

  const loginRows = demoMode
    ? [
        { id: 1, username: 'admin', ip: '127.0.0.1', location: '局域网', result: 'success', failureReason: '', created: '2026-07-05 11:30:00' },
        { id: 2, username: 'admin', ip: '127.0.0.1', location: '局域网', result: 'failed', failureReason: '密码错误', created: '2026-07-05 11:28:00' },
      ]
    : asList<any>(loginQuery.data)
  const accessRows = demoMode
    ? [
        { id: 1, username: 'admin', ip: '127.0.0.1', location: '局域网', method: 'GET', path: '/api/v1/users', statusCode: 200, latencyMs: 32, created: '2026-07-05 11:31:00' },
        { id: 2, username: 'admin', ip: '127.0.0.1', location: '局域网', method: 'POST', path: '/api/v1/users', statusCode: 201, latencyMs: 81, created: '2026-07-05 11:32:00' },
      ]
    : asList<any>(accessQuery.data)
  const operationRows = demoMode
    ? [
        { id: 1, username: 'admin', ip: '127.0.0.1', location: '局域网', method: 'POST', action: '新增/提交', target: '/api/v1/users', statusCode: 201, latencyMs: 81, created: '2026-07-05 11:32:00' },
        { id: 2, username: 'admin', ip: '127.0.0.1', location: '局域网', method: 'DELETE', action: '删除', target: '/api/v1/users/12', statusCode: 200, latencyMs: 54, created: '2026-07-05 11:33:00' },
      ]
    : asList<any>(operationQuery.data)
  const unauthorizedRows = demoMode
    ? [
        { id: 1, ip: '127.0.0.1', location: '局域网', method: 'GET', path: '/api/v1/tasks', statusCode: 401, reason: '缺少 Token', created: '2026-07-05 11:34:00' },
        { id: 2, ip: '127.0.0.1', location: '局域网', method: 'POST', path: '/api/v1/tasks', statusCode: 401, reason: 'Token 无效或已过期', created: '2026-07-05 11:35:00' },
      ]
    : asList<any>(unauthorizedQuery.data)

  const getLoginResultLabel = (result?: string) => result === 'success' ? '登录成功' : result === 'failed' ? '登录失败' : result || '-'
  const getStatusToneByCode = (code?: number) => {
    if (!code) return 'neutral'
    if (code >= 500) return 'danger'
    if (code >= 400) return 'warning'
    if (code >= 200 && code < 300) return 'success'
    return 'info'
  }
  const exportSheet = (name: string, headers: string[], rows: any[][]) => {
    const escapeCsv = (value: unknown) => `"${String(value ?? '').replace(/"/g, '""')}"`
    const csv = [headers, ...rows].map((row) => row.map(escapeCsv).join(',')).join('\r\n')
    const fileName = `${name}-${currentChinaTimeString().replace(/[-:]/g, '').replace(' ', '-')}.csv`
    downloadBlob(new Blob([`\uFEFF${csv}`], { type: 'text/csv;charset=utf-8' }), fileName)
  }
  const refreshLogs = async (label: string, refetch: () => Promise<{ error: unknown }>) => {
    if (demoMode) {
      toast.success(`${label}已刷新`)
      return
    }
    const result = await refetch()
    if (result.error) {
      toast.error(`刷新${label}失败`)
      return
    }
    toast.success(`${label}已刷新`)
  }
  const clearLoginMutation = useMutation({
    mutationFn: async () => (demoMode ? null : clearLoginLogs()),
    onSuccess: () => {
      setLoginFilters({ username: '', ip: '', result: '' })
      queryClient.invalidateQueries({ queryKey: ['login-logs'] })
      toast.success('登录日志已清空')
    },
    onError: (error: any) => toast.error(error.message || '清空登录日志失败'),
  })
  const clearAccessMutation = useMutation({
    mutationFn: async () => (demoMode ? null : clearAccessLogs()),
    onSuccess: () => {
      setAccessFilters({ ip: '', method: '', path: '', status: '' })
      queryClient.invalidateQueries({ queryKey: ['access-logs'] })
      toast.success('访问日志已清空')
    },
    onError: (error: any) => toast.error(error.message || '清空访问日志失败'),
  })
  const clearOperationMutation = useMutation({
    mutationFn: async () => (demoMode ? null : clearOperationLogs()),
    onSuccess: () => {
      setOperationFilters({ username: '', ip: '', method: '', path: '', action: '', status: '' })
      queryClient.invalidateQueries({ queryKey: ['operation-logs'] })
      toast.success('操作日志已清空')
    },
    onError: (error: any) => toast.error(error.message || '清空操作日志失败'),
  })
  const clearUnauthorizedMutation = useMutation({
    mutationFn: async () => (demoMode ? null : clearUnauthorizedAccessLogs()),
    onSuccess: () => {
      setUnauthorizedFilters({ ip: '', method: '', path: '', reason: '', status: '' })
      queryClient.invalidateQueries({ queryKey: ['unauthorized-access-logs'] })
      toast.success('未授权访问日志已清空')
    },
    onError: (error: any) => toast.error(error.message || '清空未授权访问日志失败'),
  })

  const loginColumns: ColumnDef<any>[] = [
    { header: '用户', accessorKey: 'username', cell: ({ row }) => <span className="font-medium">{row.original.username || '-'}</span> },
    { header: 'IP', accessorKey: 'ip', cell: ({ row }) => <span className="font-mono text-sm">{row.original.ip || row.original.ip_address || '-'}</span> },
    { header: '归属地', accessorKey: 'location', cell: ({ row }) => <span className="text-muted">{row.original.location || '-'}</span> },
    { header: '结果', accessorKey: 'result', cell: ({ row }) => <Badge tone={row.original.result === 'success' ? 'success' : 'danger'}>{getLoginResultLabel(row.original.result)}</Badge> },
    { header: '失败原因', accessorKey: 'failureReason', cell: ({ row }) => <span className="text-muted">{row.original.failureReason || row.original.failure_reason || '-'}</span> },
    { header: '时间', accessorKey: 'created', cell: ({ row }) => <span className="text-muted">{formatTime(row.original.created || row.original.createdAt || row.original.created_at)}</span> },
  ]
  const accessColumns: ColumnDef<any>[] = [
    { header: '用户', accessorKey: 'username', cell: ({ row }) => <span className="font-medium">{row.original.username || '-'}</span> },
    { header: 'IP', accessorKey: 'ip', cell: ({ row }) => <span className="font-mono text-sm">{row.original.ip || row.original.ip_address || '-'}</span> },
    { header: '归属地', accessorKey: 'location', cell: ({ row }) => <span className="text-muted">{row.original.location || '-'}</span> },
    { header: '方法', accessorKey: 'method', cell: ({ row }) => <Badge tone="info">{row.original.method || '-'}</Badge> },
    { header: '路径', accessorKey: 'path', cell: ({ row }) => <span className="font-mono text-xs text-muted">{row.original.path || '-'}</span> },
    { header: '状态码', accessorKey: 'statusCode', cell: ({ row }) => <Badge tone={getStatusToneByCode(Number(row.original.statusCode || row.original.status_code)) as any}>{row.original.statusCode || row.original.status_code || '-'}</Badge> },
    { header: '耗时', accessorKey: 'latencyMs', cell: ({ row }) => <span className="text-muted">{Number(row.original.latencyMs || row.original.latency_ms || 0)} ms</span> },
    { header: '时间', accessorKey: 'created', cell: ({ row }) => <span className="text-muted">{formatTime(row.original.created || row.original.createdAt || row.original.created_at)}</span> },
  ]
  const operationColumns: ColumnDef<any>[] = [
    { header: '用户', accessorKey: 'username', cell: ({ row }) => <span className="font-medium">{row.original.username || '-'}</span> },
    { header: 'IP', accessorKey: 'ip', cell: ({ row }) => <span className="font-mono text-sm">{row.original.ip || row.original.ip_address || '-'}</span> },
    { header: '归属地', accessorKey: 'location', cell: ({ row }) => <span className="text-muted">{row.original.location || '-'}</span> },
    { header: '方法', accessorKey: 'method', cell: ({ row }) => <Badge tone="info">{row.original.method || '-'}</Badge> },
    { header: '操作', accessorKey: 'action', cell: ({ row }) => <Badge tone="accent">{row.original.action || '-'}</Badge> },
    { header: '目标', accessorKey: 'target', cell: ({ row }) => <span className="font-mono text-xs text-muted">{row.original.target || row.original.path || '-'}</span> },
    { header: '状态码', accessorKey: 'statusCode', cell: ({ row }) => <Badge tone={getStatusToneByCode(Number(row.original.statusCode || row.original.status_code)) as any}>{row.original.statusCode || row.original.status_code || '-'}</Badge> },
    { header: '耗时', accessorKey: 'latencyMs', cell: ({ row }) => <span className="text-muted">{Number(row.original.latencyMs || row.original.latency_ms || 0)} ms</span> },
    { header: '时间', accessorKey: 'created', cell: ({ row }) => <span className="text-muted">{formatTime(row.original.created || row.original.createdAt || row.original.created_at)}</span> },
  ]
  const unauthorizedColumns: ColumnDef<any>[] = [
    { header: 'IP', accessorKey: 'ip', cell: ({ row }) => <span className="font-mono text-sm">{row.original.ip || row.original.ip_address || '-'}</span> },
    { header: '归属地', accessorKey: 'location', cell: ({ row }) => <span className="text-muted">{row.original.location || '-'}</span> },
    { header: '方法', accessorKey: 'method', cell: ({ row }) => <Badge tone="warning">{row.original.method || '-'}</Badge> },
    { header: '路径', accessorKey: 'path', cell: ({ row }) => <span className="font-mono text-xs text-muted">{row.original.path || '-'}</span> },
    { header: '状态码', accessorKey: 'statusCode', cell: ({ row }) => <Badge tone={getStatusToneByCode(Number(row.original.statusCode || row.original.status_code)) as any}>{row.original.statusCode || row.original.status_code || '-'}</Badge> },
    { header: '原因', accessorKey: 'reason', cell: ({ row }) => <span className="text-muted">{row.original.reason || '-'}</span> },
    { header: '时间', accessorKey: 'created', cell: ({ row }) => <span className="text-muted">{formatTime(row.original.created || row.original.createdAt || row.original.created_at)}</span> },
  ]

  return (
    <div className="grid gap-4">
      <PageTitle title="日志审计" description="登录、访问与操作日志统一审计查看，当前页签会自动刷新。" />
      <div className="grid gap-4 md:grid-cols-5">
        <Metric label="登录日志" value={loginData.total ?? loginRows.length} icon={History} tone="info" badgeLabel="总数" />
        <Metric label="访问日志" value={accessData.total ?? accessRows.length} icon={Globe2} tone="accent" badgeLabel="总数" />
        <Metric label="操作日志" value={operationData.total ?? operationRows.length} icon={Activity} tone="warning" badgeLabel="总数" />
        <Metric label="未授权访问" value={unauthorizedData.total ?? unauthorizedRows.length} icon={ShieldBan} tone="danger" badgeLabel="总数" />
        <Metric label="成功登录" value={loginRows.filter((row) => row.result === 'success').length} icon={ShieldCheck} tone="success" badgeLabel="成功" />
      </div>
      <Tabs value={activeTab} onValueChange={(value) => setActiveTab(value as any)}>
        <TabsList>
          <TabsTrigger value="login">登录日志</TabsTrigger>
          <TabsTrigger value="access">访问日志</TabsTrigger>
          <TabsTrigger value="operation">操作日志</TabsTrigger>
          <TabsTrigger value="unauthorized">未授权访问</TabsTrigger>
        </TabsList>
        <TabsContent value="login" className="grid gap-4">
          <Card>
            <CardContent className="grid gap-3 p-4 lg:grid-cols-[1fr_1fr_180px_auto]">
              <Input value={loginFilters.username} onChange={(event) => setLoginFilters({ ...loginFilters, username: event.target.value })} placeholder="用户名" />
              <Input value={loginFilters.ip} onChange={(event) => setLoginFilters({ ...loginFilters, ip: event.target.value })} placeholder="IP 地址" />
              <Select value={loginFilters.result} onChange={(event) => setLoginFilters({ ...loginFilters, result: event.target.value })}>
                <option value="">全部结果</option>
                <option value="success">登录成功</option>
                <option value="failed">登录失败</option>
              </Select>
              <div className="flex gap-2">
                <Button variant="outline" disabled={loginQuery.isFetching} onClick={() => refreshLogs('登录日志', () => loginQuery.refetch())}>
                  {loginQuery.isFetching ? <Loader2 className="size-4 animate-spin" /> : <RefreshCw className="size-4" />}
                  刷新
                </Button>
                <Button variant="outline" disabled={clearLoginMutation.isPending} onClick={() => clearLoginMutation.mutate()}>
                  {clearLoginMutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <RotateCcw className="size-4" />}
                  重置
                </Button>
                <Button variant="outline" onClick={() => exportSheet('login-logs', ['用户', 'IP', '归属地', '结果', '失败原因', '时间'], loginRows.map((row) => ([
                  row.username || '-',
                  row.ip || row.ip_address || '-',
                  row.location || '-',
                  getLoginResultLabel(row.result),
                  row.failureReason || row.failure_reason || '-',
                  formatTime(row.created || row.createdAt || row.created_at),
                ])))}>
                  <Download className="size-4" />导出
                </Button>
              </div>
            </CardContent>
          </Card>
          <DataTable columns={loginColumns} data={loginRows} showSearch={false} emptyTitle="暂无登录日志" paginationStorageKey="system-logs-login" />
        </TabsContent>
        <TabsContent value="access" className="grid gap-4">
          <Card>
            <CardContent className="grid gap-3 p-4 lg:grid-cols-[1fr_1fr_1fr_180px_auto]">
              <Input value={accessFilters.ip} onChange={(event) => setAccessFilters({ ...accessFilters, ip: event.target.value })} placeholder="IP 地址" />
              <Input value={accessFilters.method} onChange={(event) => setAccessFilters({ ...accessFilters, method: event.target.value })} placeholder="方法" />
              <Input value={accessFilters.path} onChange={(event) => setAccessFilters({ ...accessFilters, path: event.target.value })} placeholder="路径" />
              <Select value={accessFilters.status} onChange={(event) => setAccessFilters({ ...accessFilters, status: event.target.value })}>
                <option value="">全部状态码</option>
                <option value="200">200</option>
                <option value="401">401</option>
                <option value="403">403</option>
                <option value="404">404</option>
                <option value="500">500</option>
              </Select>
              <div className="flex gap-2">
                <Button variant="outline" disabled={accessQuery.isFetching} onClick={() => refreshLogs('访问日志', () => accessQuery.refetch())}>
                  {accessQuery.isFetching ? <Loader2 className="size-4 animate-spin" /> : <RefreshCw className="size-4" />}
                  刷新
                </Button>
                <Button variant="outline" disabled={clearAccessMutation.isPending} onClick={() => clearAccessMutation.mutate()}>
                  {clearAccessMutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <RotateCcw className="size-4" />}
                  重置
                </Button>
                <Button variant="outline" onClick={() => exportSheet('access-logs', ['用户', 'IP', '归属地', '方法', '路径', '状态码', '耗时', '时间'], accessRows.map((row) => ([
                  row.username || '-',
                  row.ip || row.ip_address || '-',
                  row.location || '-',
                  row.method || '-',
                  row.path || '-',
                  row.statusCode || row.status_code || '-',
                  `${Number(row.latencyMs || row.latency_ms || 0)} ms`,
                  formatTime(row.created || row.createdAt || row.created_at),
                ])))}>
                  <Download className="size-4" />导出
                </Button>
              </div>
            </CardContent>
          </Card>
          <DataTable columns={accessColumns} data={accessRows} showSearch={false} emptyTitle="暂无访问日志" paginationStorageKey="system-logs-access" />
        </TabsContent>
        <TabsContent value="operation" className="grid gap-4">
          <Card>
            <CardContent className="grid gap-3 p-4 lg:grid-cols-[1fr_1fr_1fr_1fr_180px_auto]">
              <Input value={operationFilters.username} onChange={(event) => setOperationFilters({ ...operationFilters, username: event.target.value })} placeholder="用户名" />
              <Input value={operationFilters.ip} onChange={(event) => setOperationFilters({ ...operationFilters, ip: event.target.value })} placeholder="IP 地址" />
              <Input value={operationFilters.method} onChange={(event) => setOperationFilters({ ...operationFilters, method: event.target.value })} placeholder="方法" />
              <Input value={operationFilters.path} onChange={(event) => setOperationFilters({ ...operationFilters, path: event.target.value })} placeholder="路径" />
              <Select value={operationFilters.status} onChange={(event) => setOperationFilters({ ...operationFilters, status: event.target.value })}>
                <option value="">全部状态码</option>
                <option value="200">200</option>
                <option value="201">201</option>
                <option value="400">400</option>
                <option value="401">401</option>
                <option value="403">403</option>
                <option value="500">500</option>
              </Select>
              <div className="flex gap-2">
                <Button variant="outline" disabled={operationQuery.isFetching} onClick={() => refreshLogs('操作日志', () => operationQuery.refetch())}>
                  {operationQuery.isFetching ? <Loader2 className="size-4 animate-spin" /> : <RefreshCw className="size-4" />}
                  刷新
                </Button>
                <Button variant="outline" disabled={clearOperationMutation.isPending} onClick={() => clearOperationMutation.mutate()}>
                  {clearOperationMutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <RotateCcw className="size-4" />}
                  重置
                </Button>
                <Button variant="outline" onClick={() => exportSheet('operation-logs', ['用户', 'IP', '归属地', '方法', '操作', '目标', '状态码', '耗时', '时间'], operationRows.map((row) => ([
                  row.username || '-',
                  row.ip || row.ip_address || '-',
                  row.location || '-',
                  row.method || '-',
                  row.action || '-',
                  row.target || row.path || '-',
                  row.statusCode || row.status_code || '-',
                  `${Number(row.latencyMs || row.latency_ms || 0)} ms`,
                  formatTime(row.created || row.createdAt || row.created_at),
                ])))}>
                  <Download className="size-4" />导出
                </Button>
              </div>
            </CardContent>
          </Card>
          <DataTable columns={operationColumns} data={operationRows} showSearch={false} emptyTitle="暂无操作日志" paginationStorageKey="system-logs-operation" />
        </TabsContent>
        <TabsContent value="unauthorized" className="grid gap-4">
          <Card>
            <CardContent className="grid gap-3 p-4 lg:grid-cols-[1fr_1fr_1fr_1fr_180px_auto]">
              <Input value={unauthorizedFilters.ip} onChange={(event) => setUnauthorizedFilters({ ...unauthorizedFilters, ip: event.target.value })} placeholder="IP 地址" />
              <Input value={unauthorizedFilters.method} onChange={(event) => setUnauthorizedFilters({ ...unauthorizedFilters, method: event.target.value })} placeholder="方法" />
              <Input value={unauthorizedFilters.path} onChange={(event) => setUnauthorizedFilters({ ...unauthorizedFilters, path: event.target.value })} placeholder="路径" />
              <Input value={unauthorizedFilters.reason} onChange={(event) => setUnauthorizedFilters({ ...unauthorizedFilters, reason: event.target.value })} placeholder="原因" />
              <Select value={unauthorizedFilters.status} onChange={(event) => setUnauthorizedFilters({ ...unauthorizedFilters, status: event.target.value })}>
                <option value="">全部状态码</option>
                <option value="401">401</option>
              </Select>
              <div className="flex gap-2">
                <Button variant="outline" disabled={unauthorizedQuery.isFetching} onClick={() => refreshLogs('未授权访问日志', () => unauthorizedQuery.refetch())}>
                  {unauthorizedQuery.isFetching ? <Loader2 className="size-4 animate-spin" /> : <RefreshCw className="size-4" />}
                  刷新
                </Button>
                <Button variant="outline" disabled={clearUnauthorizedMutation.isPending} onClick={() => clearUnauthorizedMutation.mutate()}>
                  {clearUnauthorizedMutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <RotateCcw className="size-4" />}
                  重置
                </Button>
                <Button variant="outline" onClick={() => exportSheet('unauthorized-access-logs', ['IP', '归属地', '方法', '路径', '状态码', '原因', '时间'], unauthorizedRows.map((row) => ([
                  row.ip || row.ip_address || '-',
                  row.location || '-',
                  row.method || '-',
                  row.path || '-',
                  row.statusCode || row.status_code || '-',
                  row.reason || '-',
                  formatTime(row.created || row.createdAt || row.created_at),
                ])))}>
                  <Download className="size-4" />导出
                </Button>
              </div>
            </CardContent>
          </Card>
          <DataTable columns={unauthorizedColumns} data={unauthorizedRows} showSearch={false} emptyTitle="暂无未授权访问日志" paginationStorageKey="system-logs-unauthorized" />
        </TabsContent>
      </Tabs>
    </div>
  )
}
