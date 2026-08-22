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

export function UsersView({ demoMode }: { demoMode: boolean }) {
  const queryClient = useQueryClient()
  const [dialogOpen, setDialogOpen] = React.useState(false)
  const [batchOpen, setBatchOpen] = React.useState(false)
  const [editingUser, setEditingUser] = React.useState<any | null>(null)
  const [draft, setDraft] = React.useState({ username: '', password: '', email: '', realName: '', role: 'user', status: 'active' })
  const getUserStatusLabel = (status?: string) => status === 'disabled' ? '禁用' : '启用'
  const canToggleUserStatus = (row: any) => !(row?.username === 'admin' && row?.status === 'active')
  const [batchText, setBatchText] = React.useState('alice,Passw0rd!,alice@example.com,user,active')
  const query = useQuery({ queryKey: ['users'], queryFn: () => getUsers({ page: 1, pageSize: 200 }), enabled: !demoMode })
  const rows = demoMode
    ? [{ id: 1, username: 'admin', role: 'admin', status: 'active', email: 'admin@example.com', createdAt: '2024-01-01' }]
    : asList<any>(query.data)
  const openCreate = () => {
    setEditingUser(null)
    setDraft({ username: '', password: '', email: '', realName: '', role: 'user', status: 'active' })
    setDialogOpen(true)
  }
  const openEdit = (row: any) => {
    setEditingUser(row)
    setDraft({
      username: row.username || '',
      password: '',
      email: row.email || '',
      realName: row.realName || row.real_name || '',
      role: row.role || 'user',
      status: row.status || 'active',
    })
    setDialogOpen(true)
  }
  const mutation = useMutation({
    mutationFn: async ({ action, row }: { action: string; row?: any }) => {
      if (demoMode) return null
      if (action === 'save') {
        const payload: Record<string, any> = { ...draft }
        if (!payload.password) delete payload.password
        return editingUser ? updateUser(editingUser.id, payload) : createUser(payload)
      }
      if (action === 'disable') return updateUser(row.id, { status: row.status === 'active' ? 'disabled' : 'active' })
      if (action === 'delete') return deleteUser(row.id)
      if (action === 'batch') return batchCreateUsers(parseBatchUsers(batchText))
      return null
    },
    onSuccess: () => {
      toast.success('操作成功')
      setDraft({ username: '', password: '', email: '', realName: '', role: 'user', status: 'active' })
      setDialogOpen(false)
      setBatchOpen(false)
      queryClient.invalidateQueries({ queryKey: ['users'] })
    },
    onError: (error: any) => toast.error(error.message || '操作失败'),
  })
  const handleExport = async () => {
    try {
      if (demoMode) {
        downloadContent(toCsv(rows), 'users.csv', 'text/csv')
      } else {
        const res = await exportUsers()
        downloadBlobResponse(res, 'users.xlsx')
        toast.success('用户列表已下载')
      }
    } catch (error: any) {
      toast.error(error.message || '导出失败')
    }
  }
  const handleTemplate = async () => {
    try {
      if (demoMode) {
        downloadContent('username,password,email,role,status\nalice,Passw0rd!,alice@example.com,user,active', '用户导入模板.csv', 'text/csv')
        return
      }
      const res: any = await downloadUserImportTemplate()
      const blob = res?.data instanceof Blob ? res.data : res instanceof Blob ? res : new Blob([res], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' })
      downloadBlob(blob, '用户导入模板.xlsx')
    } catch (error: any) {
      toast.error(error.message || '下载模板失败')
    }
  }
  const columns: ColumnDef<any>[] = [
    { header: 'ID', accessorKey: 'id' },
    { header: '用户名', accessorKey: 'username', cell: ({ row }) => <span className="font-medium">{row.original.username}</span> },
    { header: '角色', accessorKey: 'role', cell: ({ row }) => <Badge tone={row.original.role === 'admin' ? 'info' : 'neutral'}>{row.original.role}</Badge> },
    { header: '状态', accessorKey: 'status', cell: ({ row }) => <Badge tone={row.original.status === 'active' ? 'success' : 'warning'}>{getUserStatusLabel(row.original.status)}</Badge> },
    { header: '邮箱', accessorKey: 'email' },
    { header: '创建时间', accessorKey: 'createdAt', cell: ({ row }) => <span className="text-muted">{formatTime(row.original.createdAt)}</span> },
    {
      header: '操作',
      meta: { align: 'right' },
      cell: ({ row }) => (
        <div className="flex justify-end gap-2">
          <Button size="sm" variant="outline" onClick={() => openEdit(row.original)}><Edit3 className="size-4" />编辑</Button>
          <button
            type="button"
            role="switch"
            aria-checked={row.original.status === 'active'}
            aria-label={`${row.original.username || '用户'}状态：${getUserStatusLabel(row.original.status)}`}
            title={canToggleUserStatus(row.original) ? getUserStatusLabel(row.original.status) : '内置管理员不能禁用'}
            disabled={mutation.isPending || !canToggleUserStatus(row.original)}
            onClick={() => mutation.mutate({ action: 'disable', row: row.original })}
            className={cn(
              'inline-flex h-6 w-11 items-center rounded-full border px-0.5 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-muted disabled:cursor-not-allowed disabled:opacity-60',
              row.original.status === 'active' ? 'border-success/35 bg-success/40' : 'border-border bg-raised'
            )}
          >
            <span
              className={cn(
                'block size-4 rounded-full bg-background shadow-sm transition-transform',
                row.original.status === 'active' ? 'translate-x-5' : 'translate-x-0'
              )}
            />
          </button>
          <Button size="sm" variant="danger" onClick={() => mutation.mutate({ action: 'delete', row: row.original })}>删除</Button>
        </div>
      ),
    },
  ]
  return (
    <div className="grid gap-4">
      <PageTitle title="用户管理" description="用户 CRUD、批量创建、导出和导入模板下载。" />
      <DataTable
        columns={columns}
        data={rows}
        searchPlaceholder="搜索用户"
        paginationStorageKey="users"
        toolbar={
          <>
            <Button variant="outline" onClick={() => setBatchOpen(true)}><Upload className="size-4" />批量创建</Button>
            <Button variant="outline" onClick={handleExport}><Download className="size-4" />导出</Button>
            <Button variant="outline" onClick={handleTemplate}><FileDown className="size-4" />下载模板</Button>
            <Button variant="default" onClick={openCreate}><Plus className="size-4" />新建用户</Button>
          </>
        }
      />
      <Modal
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        title={editingUser ? '编辑用户' : '新建用户'}
        footer={
          <>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>取消</Button>
            <Button variant="default" onClick={() => mutation.mutate({ action: 'save' })} disabled={!draft.username || (!editingUser && !draft.password) || mutation.isPending}>
              {mutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <Save className="size-4" />}
              保存
            </Button>
          </>
        }
      >
        <div className="grid gap-4 md:grid-cols-2">
          <Field label="用户名"><Input value={draft.username} onChange={(event) => setDraft({ ...draft, username: event.target.value })} /></Field>
          <Field label={editingUser ? '新密码（留空不改）' : '密码'}><Input type="password" value={draft.password} onChange={(event) => setDraft({ ...draft, password: event.target.value })} /></Field>
          <Field label="邮箱"><Input value={draft.email} onChange={(event) => setDraft({ ...draft, email: event.target.value })} /></Field>
          <Field label="状态">
            <Select value={draft.status} onChange={(event) => setDraft({ ...draft, status: event.target.value })}>
              <option value="active">启用</option>
              <option value="disabled">禁用</option>
            </Select>
          </Field>
        </div>
      </Modal>
      <Modal
        open={batchOpen}
        onOpenChange={setBatchOpen}
        title="批量创建用户"
        description="每行一个用户：username,password,email,role,status"
        footer={
          <>
            <Button variant="outline" onClick={() => setBatchOpen(false)}>取消</Button>
            <Button variant="default" onClick={() => mutation.mutate({ action: 'batch' })} disabled={!batchText.trim() || mutation.isPending}>
              {mutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <Upload className="size-4" />}
              提交
            </Button>
          </>
        }
      >
        <Textarea className="min-h-72" value={batchText} onChange={(event) => setBatchText(event.target.value)} />
      </Modal>
    </div>
  )
}
