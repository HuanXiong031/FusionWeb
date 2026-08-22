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
  createDingTalkKey,
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
  deleteDingTalkKey,
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
  getDingTalkKeys,
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
  updateDingTalkKey,
  updateManualVulnVerify,
  updatePocFile,
  updateUser,
  updateVulnVerifyGroup,
  validatePOC,
  type DashboardStats,
  type DingTalkKey,
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

export function SettingsView() {
  const queryClient = useQueryClient()
  const [drawerOpen, setDrawerOpen] = React.useState(false)
  const [editingKey, setEditingKey] = React.useState<DingTalkKey | null>(null)
  const [draft, setDraft] = React.useState<DingTalkKey>(() => createEmptyDingTalkDraft())
  const query = useQuery({ queryKey: ['dingtalk-keys'], queryFn: getDingTalkKeys })
  const keys = unwrap<DingTalkKey[]>(query.data) || []

  const saveMutation = useMutation({
    mutationFn: async () => {
      const payload = {
        ...draft,
        name: String(draft.name || '').trim(),
        accessToken: String(draft.accessToken || '').trim(),
        secret: String(draft.secret || '').trim(),
      }
      if (!payload.name) throw new Error('请输入 Key 名称')
      if (!payload.accessToken) throw new Error('请输入钉钉 access_token')
      if (editingKey?.id) return updateDingTalkKey(editingKey.id, payload)
      return createDingTalkKey(payload)
    },
    onSuccess: () => {
      toast.success('钉钉 Key 已保存')
      setDrawerOpen(false)
      setEditingKey(null)
      setDraft(createEmptyDingTalkDraft())
      queryClient.invalidateQueries({ queryKey: ['dingtalk-keys'] })
    },
    onError: (error: any) => toast.error(error.message || '保存失败'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: number) => deleteDingTalkKey(id),
    onSuccess: () => {
      toast.success('钉钉 Key 已删除')
      queryClient.invalidateQueries({ queryKey: ['dingtalk-keys'] })
    },
    onError: (error: any) => toast.error(error.message || '删除失败'),
  })

  const toggleEnabledMutation = useMutation({
    mutationFn: (row: DingTalkKey) => {
      if (!row.id) throw new Error('Key ID 不正确')
      return updateDingTalkKey(row.id, { ...row, enabled: row.enabled === false })
    },
    onSuccess: (_res, row) => {
      toast.success(row.enabled === false ? '钉钉 Key 已启用' : '钉钉 Key 已禁用')
      queryClient.invalidateQueries({ queryKey: ['dingtalk-keys'] })
    },
    onError: (error: any) => toast.error(error.message || '操作失败'),
  })

  const openCreate = () => {
    setEditingKey(null)
    setDraft(createEmptyDingTalkDraft())
    setDrawerOpen(true)
  }

  const openEdit = (row: DingTalkKey) => {
    setEditingKey(row)
    setDraft({
      ...row,
      accessToken: row.accessToken || '',
      secret: '',
    })
    setDrawerOpen(true)
  }

  const columns: ColumnDef<DingTalkKey>[] = [
    {
      header: 'Key 名称',
      accessorKey: 'name',
      cell: ({ row }) => <span className="font-semibold text-foreground">{row.original.name}</span>,
    },
    {
      header: '状态',
      accessorKey: 'enabled',
      cell: ({ row }) => <Badge tone={row.original.enabled === false ? 'warning' : 'success'}>{row.original.enabled === false ? '停用' : '启用'}</Badge>,
    },
    {
      header: '提醒范围',
      cell: ({ row }) => <span className="text-sm text-muted">{formatDingTalkScopes(row.original)}</span>,
    },
    {
      header: '更新时间',
      accessorKey: 'updatedAt',
      cell: ({ row }) => <span className="font-mono text-sm">{formatTime(row.original.updatedAt)}</span>,
    },
    {
      header: '操作',
      meta: { align: 'right' },
      cell: ({ row }) => (
        <div className="flex justify-end gap-2">
          <Button
            size="sm"
            variant={row.original.enabled === false ? 'default' : 'outline'}
            disabled={toggleEnabledMutation.isPending}
            onClick={() => toggleEnabledMutation.mutate(row.original)}
          >
            {row.original.enabled === false ? <Play className="size-4" /> : <Pause className="size-4" />}
            {row.original.enabled === false ? '启用' : '禁用'}
          </Button>
          <Button size="sm" variant="outline" onClick={() => openEdit(row.original)}>
            <Edit3 className="size-4" />
            编辑
          </Button>
          <Button size="sm" variant="danger" disabled={deleteMutation.isPending} onClick={() => row.original.id && deleteMutation.mutate(row.original.id)}>
            <Trash2 className="size-4" />
            删除
          </Button>
        </div>
      ),
    },
  ]

  return (
    <div className="grid gap-4">
      <PageTitle title="系统设置" description="管理系统级通知 Key，以及每个 Key 可以接收哪些提醒。" />
      <div className="grid gap-4 md:grid-cols-3">
        <Metric label="钉钉 Key" value={String(keys.length)} icon={KeyRound} tone="info" badgeLabel="通知" />
        <Metric label="启用数量" value={String(keys.filter((item) => item.enabled !== false).length)} icon={Bell} tone="success" badgeLabel="启用" />
        <Metric label="提醒范围" value="4 类" icon={Database} tone="neutral" badgeLabel="范围" />
      </div>
      <Card>
        <CardHeader>
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <div>
              <CardTitle>钉钉通知 Key</CardTitle>
              <CardDescription>支持多个机器人 Key；扫描任务中选择其中一个 Key 发送任务结果。</CardDescription>
            </div>
            <Button variant="default" onClick={openCreate}>
              <Plus className="size-4" />
              添加 Key
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <DataTable columns={columns} data={keys} searchPlaceholder="搜索钉钉 Key" emptyTitle="暂无钉钉 Key" paginationStorageKey="settings-dingtalk-keys" />
        </CardContent>
      </Card>
      <Drawer
        open={drawerOpen}
        onOpenChange={setDrawerOpen}
        title={editingKey ? '编辑钉钉 Key' : '添加钉钉 Key'}
        description="选择该 Key 可以接收的提醒范围，未勾选的场景不会发送到这个机器人。"
        className="max-w-xl"
        footer={
          <>
            <Button variant="outline" onClick={() => setDrawerOpen(false)}>
              取消
            </Button>
            <Button variant="default" disabled={saveMutation.isPending} onClick={() => saveMutation.mutate()}>
              {saveMutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <Save className="size-4" />}
              保存
            </Button>
          </>
        }
      >
        <div className="grid gap-4">
          <Field label="Key 名称">
            <Input value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} placeholder="例如：安全通知机器人" />
          </Field>
          <Field label="钉钉 access_token">
            <Input value={draft.accessToken || ''} onChange={(event) => setDraft({ ...draft, accessToken: event.target.value })} placeholder="机器人 webhook 中的 access_token" />
          </Field>
          <Field label="钉钉 Secret" hint={editingKey ? '编辑时留空会保留旧 Secret；后端不会回显密钥。' : '如果机器人未开启加签，可以留空。'}>
            <Input value={draft.secret || ''} onChange={(event) => setDraft({ ...draft, secret: event.target.value })} placeholder="SEC 开头的加签密钥，可留空" />
          </Field>
          <div className="grid gap-3 rounded-card border border-border bg-raised p-3">
            <ToggleField label="添加黑名单时提醒" checked={Boolean(draft.notifyBlacklistAdd)} onChange={(value) => setDraft({ ...draft, notifyBlacklistAdd: value })} />
            <ToggleField label="解除黑名单时提醒" checked={Boolean(draft.notifyBlacklistRemove)} onChange={(value) => setDraft({ ...draft, notifyBlacklistRemove: value })} />
            <ToggleField label="Web 扫描任务结束后提醒" checked={Boolean(draft.notifyWebScanComplete)} onChange={(value) => setDraft({ ...draft, notifyWebScanComplete: value })} />
            <ToggleField label="端口扫描任务结束后提醒" checked={Boolean(draft.notifyPortScanComplete)} onChange={(value) => setDraft({ ...draft, notifyPortScanComplete: value })} />
          </div>
        </div>
      </Drawer>
    </div>
  )
}

function createEmptyDingTalkDraft(): DingTalkKey {
  return {
    name: '',
    accessToken: '',
    secret: '',
    notifyBlacklistAdd: true,
    notifyBlacklistRemove: true,
    notifyWebScanComplete: true,
    notifyPortScanComplete: true,
    enabled: true,
  }
}

function formatDingTalkScopes(item: DingTalkKey) {
  const scopes = [
    item.notifyBlacklistAdd ? '添加黑名单' : '',
    item.notifyBlacklistRemove ? '解除黑名单' : '',
    item.notifyWebScanComplete ? 'Web 扫描结束' : '',
    item.notifyPortScanComplete ? '端口扫描结束' : '',
  ].filter(Boolean)
  return scopes.length ? scopes.join(' / ') : '未选择'
}
