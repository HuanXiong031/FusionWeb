'use client'

import * as React from 'react'
import { useForm } from 'react-hook-form'
import { z } from 'zod'
import { zodResolver } from '@hookform/resolvers/zod'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type { ColumnDef, PaginationState } from '@tanstack/react-table'
import { toast } from 'sonner'
import {
  Activity,
  Bell,
  Braces,
  Bug,
  Check,
  Code2,
  Copy,
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
import { asList, compactNumber, formatTime, getStatusLabel, getStatusTone, parseTargets, unwrap } from '@/lib/utils'
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

type FingerprintTab = 'passive' | 'active' | 'blacklist'

function getPageTotal(value: any, fallback: number) {
  const data = unwrap<any>(value) || {}
  const total = Number(data.total ?? value?.total)
  return Number.isFinite(total) ? total : fallback
}

export function FingerprintView({ demoMode, initialTab = 'passive' }: { demoMode: boolean; initialTab?: FingerprintTab }) {
  const queryClient = useQueryClient()
  const [fingerprintTab, setFingerprintTab] = React.useState<FingerprintTab>(initialTab)
  const isBlacklistTab = fingerprintTab === 'blacklist'
  const activeType: 'passive' | 'active' = fingerprintTab === 'active' ? 'active' : 'passive'
  const [keyword, setKeyword] = React.useState('')
  const [pagination, setPagination] = React.useState<PaginationState>({ pageIndex: 0, pageSize: 10 })
  const [drawerOpen, setDrawerOpen] = React.useState(false)
  const [editing, setEditing] = React.useState<FingerprintRow | null>(null)
  const [draft, setDraft] = React.useState({ name: '', category: '', type: 'passive', description: '', rules: '', isEnabled: true, isBlacklisted: false })
  const fileInputRef = React.useRef<HTMLInputElement | null>(null)
  const query = useQuery({
    queryKey: ['fingerprints', activeType, keyword, pagination.pageIndex, pagination.pageSize],
    queryFn: () => getFingerprintsPage({ page: pagination.pageIndex + 1, pageSize: pagination.pageSize, category: activeType, keyword }),
    enabled: !isBlacklistTab && !demoMode,
  })
  const blacklistQuery = useQuery({
    queryKey: ['fingerprints', 'blacklist', keyword],
    queryFn: async () => {
      const [passive, active] = await Promise.all([
        getFingerprintsPage({ page: 1, pageSize: 10000, category: 'passive', keyword, blacklisted: true }),
        getFingerprintsPage({ page: 1, pageSize: 10000, category: 'active', keyword, blacklisted: true }),
      ])
      return [...asList<any>(passive), ...asList<any>(active)]
    },
    enabled: isBlacklistTab && !demoMode,
  })
  const statsQuery = useQuery({ queryKey: ['fingerprint-statistics'], queryFn: getFingerprintStatistics, enabled: !demoMode })
  const categoriesQuery = useQuery({ queryKey: ['fingerprint-categories'], queryFn: getFingerprintCategories, enabled: !demoMode })
  const stats = demoMode ? { total: 3, passive: 2, active: 1, categories: 3 } : unwrap<any>(statsQuery.data) || {}
  const categories = demoMode ? ['Web Server', 'Framework', 'CMS'] : asList<string>(categoriesQuery.data)
  const demoRows = [
        { name: 'nginx', category: 'Web Server', type: 'passive', rules: ['body="nginx"'], isEnabled: true, isBlacklisted: false },
        { name: 'Spring Boot', category: 'Framework', type: 'active', rules: ['path=/actuator/health'], isEnabled: true, isBlacklisted: false },
        { name: 'ThinkPHP', category: 'CMS', type: 'passive', rules: ['header="ThinkPHP"'], isEnabled: false, isBlacklisted: true },
      ]
  const matchesKeyword = (item: any) => !keyword || `${item.name || ''} ${item.description || ''} ${item.category || ''}`.toLowerCase().includes(keyword.toLowerCase())
  const rows = demoMode
    ? demoRows.filter((item) => (isBlacklistTab ? item.isBlacklisted : item.type === activeType) && matchesKeyword(item))
    : isBlacklistTab ? asList<any>(blacklistQuery.data) : asList<any>(query.data)
  const totalRows = demoMode || isBlacklistTab ? rows.length : getPageTotal(query.data, rows.length)
  const pageCount = demoMode || isBlacklistTab ? undefined : Math.ceil(totalRows / pagination.pageSize)
  const resetPage = () => setPagination((current) => ({ ...current, pageIndex: 0 }))
  const changeTab = (value: string) => {
    setFingerprintTab(value as FingerprintTab)
    resetPage()
  }
  const changeKeyword = (value: string) => {
    setKeyword(value)
    resetPage()
  }
  const openCreate = () => {
    setEditing(null)
    setDraft({ name: '', category: categories[0] || '', type: activeType, description: '', rules: '', isEnabled: true, isBlacklisted: isBlacklistTab })
    setDrawerOpen(true)
  }
  const openEdit = (row: FingerprintRow) => {
    setEditing(row)
    setDraft({
      name: row.name || '',
      category: row.category || '',
      type: row.type || activeType,
      description: row.description || '',
      rules: Array.isArray(row.rules) ? row.rules.join('\n') : String(row.rules || ''),
      isEnabled: row.isEnabled ?? row.enabled ?? true,
      isBlacklisted: row.isBlacklisted ?? row.inBlacklist ?? false,
    })
    setDrawerOpen(true)
  }
  const mutation = useMutation({
    mutationFn: async ({ action, row }: { action: string; row?: FingerprintRow }) => {
      if (demoMode) return null
      if (action === 'toggle' && row?.name) return toggleFingerprintEnabled(row.name)
      if (action === 'blacklist' && row?.name) return toggleFingerprintBlacklist(row.name)
      if (action === 'delete' && row?.name) return deleteFingerprint(row.name)
      if (action === 'deleteAll') return deleteAllFingerprints()
      return null
    },
    onSuccess: () => {
      toast.success('操作成功')
      queryClient.invalidateQueries({ queryKey: ['fingerprints'] })
      queryClient.invalidateQueries({ queryKey: ['fingerprint-statistics'] })
      queryClient.invalidateQueries({ queryKey: ['blacklist'] })
    },
    onError: (error: any) => toast.error(error.message || '操作失败'),
  })
  const saveMutation = useMutation({
    mutationFn: async () => {
      if (demoMode) return null
      const payload: FingerprintRow & { oldName?: string } = {
        oldName: editing?.name,
        name: draft.name.trim(),
        category: draft.category.trim(),
        type: draft.type,
        description: draft.description.trim(),
        rules: draft.rules.split(/\r?\n/).map((item) => item.trim()).filter(Boolean),
        isEnabled: draft.isEnabled,
        isBlacklisted: draft.isBlacklisted,
      }
      return editing ? updateFingerprint(payload) : addFingerprint(payload)
    },
    onSuccess: () => {
      toast.success(editing ? '指纹已更新' : '指纹已新增')
      setDrawerOpen(false)
      queryClient.invalidateQueries({ queryKey: ['fingerprints'] })
      queryClient.invalidateQueries({ queryKey: ['fingerprint-statistics'] })
    },
    onError: (error: any) => toast.error(error.message || '保存失败'),
  })
  const exportMutation = useMutation({
    mutationFn: async (row?: FingerprintRow) => {
      if (demoMode) return { type: 'yaml', content: rows.map((item) => `- name: ${item.name}`).join('\n') }
      if (row?.name) return exportSingleFingerprint(row.name, (row.type as 'active' | 'passive') || activeType)
      return exportFingerprints(activeType)
    },
    onSuccess: (res: any, row?: FingerprintRow) => {
      const data = unwrap<any>(res)
      downloadContent(data?.content || String(data || ''), row?.name ? `${row.name}.yaml` : `fingerprints-${activeType}.yaml`, data?.type === 'zip' ? 'application/zip' : 'text/yaml')
      toast.success('导出成功')
    },
    onError: (error: any) => toast.error(error.message || '导出失败'),
  })
  const importSelectedFile = async (file?: File | null) => {
    if (!file) return
    if (!file.name.endsWith('.yaml') && !file.name.endsWith('.yml')) {
      toast.error('只支持 YAML 文件')
      return
    }
    try {
      const text = await readFileText(file)
      if (!demoMode) await importFingerprint(text, file.name, activeType)
      toast.success('导入成功')
      queryClient.invalidateQueries({ queryKey: ['fingerprints'] })
    } catch (error: any) {
      toast.error(error.message || '导入失败')
    } finally {
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }
  const columns: ColumnDef<any>[] = [
    { header: '指纹名称', accessorKey: 'name', cell: ({ row }) => <span className="font-medium">{row.original.name}</span> },
    { header: '类型', accessorKey: 'type', cell: ({ row }) => <Badge>{row.original.type || activeType}</Badge> },
    { header: '分类', accessorKey: 'category', cell: ({ row }) => <Badge tone="info">{row.original.category || '-'}</Badge> },
    { header: '规则数', cell: ({ row }) => <span className="text-muted">{Array.isArray(row.original.rules) ? row.original.rules.length : '-'}</span> },
    { header: '状态', accessorKey: 'enabled', cell: ({ row }) => <Badge tone={(row.original.isEnabled ?? row.original.enabled) ? 'success' : 'warning'}>{(row.original.isEnabled ?? row.original.enabled) ? '启用' : '禁用'}</Badge> },
    { header: '黑名单', accessorKey: 'inBlacklist', cell: ({ row }) => <Badge tone={(row.original.isBlacklisted ?? row.original.inBlacklist) ? 'danger' : 'neutral'}>{(row.original.isBlacklisted ?? row.original.inBlacklist) ? '已加入' : '否'}</Badge> },
    {
      header: '操作',
      meta: { align: 'right' },
      cell: ({ row }) => (
        <div className="flex justify-end gap-1">
          <Button size="icon" variant="ghost" title="编辑" onClick={() => openEdit(row.original)}><Edit3 className="size-4" /></Button>
          <Button size="icon" variant="ghost" title="导出" onClick={() => exportMutation.mutate(row.original)}><Download className="size-4" /></Button>
          <Button size="icon" variant="ghost" title="切换启用" onClick={() => mutation.mutate({ action: 'toggle', row: row.original })}><SlidersHorizontal className="size-4" /></Button>
          <Button size="icon" variant="ghost" title="切换黑名单" onClick={() => mutation.mutate({ action: 'blacklist', row: row.original })}><ShieldBan className="size-4" /></Button>
          <Button size="icon" variant="ghost" title="删除" onClick={() => mutation.mutate({ action: 'delete', row: row.original })}><Trash2 className="size-4" /></Button>
        </div>
      ),
    },
  ]
  return (
    <div className="grid gap-4">
      <PageTitle title="指纹管理" description="被动/主动指纹库与黑名单；黑名单用于跳过对应指纹的漏洞扫描。" />
      <div className="grid gap-4 md:grid-cols-4">
        <Metric label="指纹总数" value={stats.total || stats.totalCount || rows.length} icon={Fingerprint} tone="accent" badgeLabel="总数" />
        <Metric label="被动指纹" value={stats.passive || stats.passiveCount || '-'} icon={Layers3} tone="neutral" badgeLabel="被动" />
        <Metric label="主动指纹" value={stats.active || stats.activeCount || '-'} icon={RadioTower} tone="success" badgeLabel="主动" />
        <Metric label="分类数" value={stats.categories || stats.categoryCount || categories.length} icon={FolderOpen} tone="warning" badgeLabel="分类" />
      </div>
      <Tabs value={fingerprintTab} onValueChange={changeTab}>
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <TabsList>
            <TabsTrigger value="passive"><Fingerprint className="size-4" />被动指纹</TabsTrigger>
            <TabsTrigger value="active"><RadioTower className="size-4" />主动指纹</TabsTrigger>
            <TabsTrigger value="blacklist"><ShieldBan className="size-4" />黑名单</TabsTrigger>
          </TabsList>
          <div className="flex min-h-9 flex-wrap items-center gap-2">
            <Input className="w-56" value={keyword} onChange={(event) => changeKeyword(event.target.value)} placeholder="搜索指纹" />
            <input ref={fileInputRef} type="file" accept=".yaml,.yml" className="hidden" onChange={(event) => importSelectedFile(event.target.files?.[0])} />
            <Button variant="outline" onClick={() => queryClient.invalidateQueries({ queryKey: ['fingerprints'] })}><RefreshCw className="size-4" />刷新</Button>
            {!isBlacklistTab ? <Button variant="outline" onClick={() => fileInputRef.current?.click()}><Upload className="size-4" />导入</Button> : null}
            {!isBlacklistTab ? <Button variant="outline" onClick={() => exportMutation.mutate(undefined)}><Download className="size-4" />导出</Button> : null}
            {!isBlacklistTab ? <Button variant="danger" onClick={() => window.confirm('确定删除全部指纹吗？') && mutation.mutate({ action: 'deleteAll' })}><Trash2 className="size-4" />全部删除</Button> : null}
            <Button variant="default" onClick={openCreate}><Plus className="size-4" />新增指纹</Button>
          </div>
        </div>
        <TabsContent value="passive">
          <DataTable columns={columns} data={rows} showSearch={false} paginationStorageKey="fingerprints-all" manualPagination={!demoMode} pagination={pagination} onPaginationChange={setPagination} pageCount={pageCount} totalRows={totalRows} />
        </TabsContent>
        <TabsContent value="active">
          <DataTable columns={columns} data={rows} showSearch={false} paginationStorageKey="fingerprints-active" manualPagination={!demoMode} pagination={pagination} onPaginationChange={setPagination} pageCount={pageCount} totalRows={totalRows} />
        </TabsContent>
        <TabsContent value="blacklist">
          <DataTable columns={columns} data={rows} showSearch={false} paginationStorageKey="fingerprints-passive" />
        </TabsContent>
      </Tabs>
      <Drawer
        open={drawerOpen}
        onOpenChange={setDrawerOpen}
        title={editing ? '编辑指纹' : '新增指纹'}
        description="规则按行保存到后端 FingerprintItem.rules；完整 YAML 可通过导入导出处理。"
        footer={
          <>
            <Button variant="outline" onClick={() => setDrawerOpen(false)}>取消</Button>
            <Button variant="default" disabled={!draft.name.trim() || !draft.rules.trim() || saveMutation.isPending} onClick={() => saveMutation.mutate()}>
              {saveMutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <Save className="size-4" />}
              保存
            </Button>
          </>
        }
      >
        <div className="grid gap-4">
          <div className="grid gap-3 md:grid-cols-2">
            <Field label="指纹名称"><Input value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} /></Field>
            <Field label="分类"><Input list="fingerprint-categories" value={draft.category} onChange={(event) => setDraft({ ...draft, category: event.target.value })} /></Field>
            <datalist id="fingerprint-categories">{categories.map((item) => <option key={item} value={item} />)}</datalist>
            <Field label="指纹类型">
              <Select value={draft.type} onChange={(event) => setDraft({ ...draft, type: event.target.value })}>
                <option value="passive">passive</option>
                <option value="active">active</option>
              </Select>
            </Field>
            <Field label="说明"><Input value={draft.description} onChange={(event) => setDraft({ ...draft, description: event.target.value })} /></Field>
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            <ToggleField label="启用指纹" checked={draft.isEnabled} onChange={(value) => setDraft({ ...draft, isEnabled: value })} />
            <ToggleField label="加入黑名单" checked={draft.isBlacklisted} onChange={(value) => setDraft({ ...draft, isBlacklisted: value })} />
          </div>
          <Field label="识别规则" hint='每行一条规则，例如 body="nginx" 或 path=/actuator/health'>
            <CodeEditor value={draft.rules} onChange={(value) => setDraft({ ...draft, rules: value })} minHeight={300} />
          </Field>
        </div>
      </Drawer>
    </div>
  )
}
