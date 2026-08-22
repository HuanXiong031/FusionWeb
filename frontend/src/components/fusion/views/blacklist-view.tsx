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

type BlacklistViewProps = {
  demoMode: boolean
  embedded?: boolean
  categories?: string[]
  showIntro?: boolean
  title?: string
  description?: string
  inputPlaceholder?: string
  searchPlaceholder?: string
  exportFileName?: string
  showRefresh?: boolean
  toolbarPortalId?: string
  toolbarVariant?: 'default' | 'fingerprint'
  tableSearch?: boolean
}

export function BlacklistView({
  demoMode,
  embedded = false,
  categories,
  showIntro = !embedded,
  title = '黑名单管理',
  description = '漏洞扫描黑名单，支持分类、导入导出、源文件编辑和全量保存。',
  inputPlaceholder = '黑名单值',
  searchPlaceholder = '搜索黑名单分类或值',
  exportFileName = 'blacklist.yaml',
  showRefresh = true,
  toolbarPortalId,
  toolbarVariant = 'default',
  tableSearch = true,
}: BlacklistViewProps) {
  const queryClient = useQueryClient()
  const categoriesKey = categories?.filter(Boolean).join('|') || ''
  const limitedCategories = React.useMemo(() => (categoriesKey ? categoriesKey.split('|') : null), [categoriesKey])
  const [category, setCategory] = React.useState(limitedCategories?.[0] || 'fingerprint')
  const [value, setValue] = React.useState('')
  const [keyword, setKeyword] = React.useState('')
  const [addOpen, setAddOpen] = React.useState(false)
  const [sourceOpen, setSourceOpen] = React.useState(false)
  const [sourceContent, setSourceContent] = React.useState('')
  const [toolbarHost, setToolbarHost] = React.useState<HTMLElement | null>(null)
  const importRef = React.useRef<HTMLInputElement | null>(null)
  const query = useQuery({ queryKey: ['blacklist'], queryFn: getBlacklistByCategory, enabled: !demoMode })
  const data = demoMode ? demoBlacklistData : unwrap<Record<string, string[]>>(query.data) || {}
  const blacklistCategories = React.useMemo(() => {
    if (limitedCategories?.length) return limitedCategories
    return Array.from(new Set(['fingerprint', 'ip', 'domain', ...Object.keys(data).filter((item) => item !== 'port')]))
  }, [data, limitedCategories])
  const visibleData = React.useMemo(() => {
    if (!limitedCategories?.length) return data
    return limitedCategories.reduce<Record<string, string[]>>((acc, item) => {
      acc[item] = Array.isArray(data[item]) ? data[item] : []
      return acc
    }, {})
  }, [data, limitedCategories])
  const rows = Object.entries(visibleData).flatMap(([cat, items]) => (Array.isArray(items) ? items : []).map((item) => ({ category: cat, value: item })))
  const filteredRows = rows.filter((row) => {
    if (row.category !== category) return false
    if (!keyword.trim()) return true
    const normalizedKeyword = keyword.trim().toLowerCase()
    return `${getBlacklistCategoryLabel(row.category)} ${row.value}`.toLowerCase().includes(normalizedKeyword)
  })
  const showCategoryTabs = blacklistCategories.length > 1
  React.useEffect(() => {
    if (!blacklistCategories.includes(category)) setCategory(blacklistCategories[0] || 'fingerprint')
  }, [blacklistCategories, category])
  React.useEffect(() => {
    setToolbarHost(toolbarPortalId ? document.getElementById(toolbarPortalId) : null)
  }, [toolbarPortalId])
  const buildSaveConfig = React.useCallback((config: Record<string, string[]>) => {
    const normalized = normalizeBlacklistConfig(config)
    if (!limitedCategories?.length) return normalized
    if (!limitedCategories.some((item) => Object.prototype.hasOwnProperty.call(normalized, item))) {
      throw new Error(`源文件中没有${limitedCategories.map(getBlacklistCategoryLabel).join('、')}分类`)
    }
    return limitedCategories.reduce<Record<string, string[]>>((acc, item) => {
      acc[item] = normalized[item] || []
      return acc
    }, { ...data })
  }, [data, limitedCategories])
  const mutation = useMutation({
    mutationFn: async ({ action, row }: { action: 'add' | 'remove'; row: { category: string; value: string } }) => {
      if (demoMode) return null
      if (action === 'add') return addToBlacklist(row.category, row.value)
      return removeFromBlacklist(row.category, row.value)
    },
    onSuccess: () => {
      toast.success('操作成功')
      setValue('')
      setAddOpen(false)
      queryClient.invalidateQueries({ queryKey: ['blacklist'] })
      queryClient.invalidateQueries({ queryKey: ['fingerprints'] })
      queryClient.invalidateQueries({ queryKey: ['fingerprint-statistics'] })
    },
    onError: (error: any) => toast.error(error.message || '操作失败'),
  })
  const saveMutation = useMutation({
    mutationFn: async (config: Record<string, string[]>) => {
      const nextConfig = buildSaveConfig(config)
      if (demoMode) return null
      return saveBlacklistByCategory(nextConfig)
    },
    onSuccess: () => {
      toast.success('黑名单已保存')
      setSourceOpen(false)
      queryClient.invalidateQueries({ queryKey: ['blacklist'] })
      queryClient.invalidateQueries({ queryKey: ['fingerprints'] })
      queryClient.invalidateQueries({ queryKey: ['fingerprint-statistics'] })
    },
    onError: (error: any) => toast.error(error.message || '保存失败'),
  })
  const openSourceEditor = (target?: string) => {
    const content = target ? blacklistToYaml({ [target]: visibleData[target] || [] }) : blacklistToYaml(visibleData)
    setSourceContent(content)
    setSourceOpen(true)
  }
  const importBlacklist = async (file?: File | null) => {
    if (!file) return
    try {
      const text = await readFileText(file)
      const parsed = parseBlacklistContent(text)
      saveMutation.mutate(parsed)
    } catch (error: any) {
      toast.error(error.message || '导入失败')
    } finally {
      if (importRef.current) importRef.current.value = ''
    }
  }
  const clearVisibleRows = () => {
    if (!window.confirm('确定删除全部黑名单吗？')) return
    const targetCategories = limitedCategories?.length ? limitedCategories : blacklistCategories
    saveMutation.mutate(targetCategories.reduce<Record<string, string[]>>((acc, item) => {
      acc[item] = []
      return acc
    }, {}))
  }
  const editRow = (row: { category: string; value: string }) => {
    const next = window.prompt('修改黑名单值', row.value)
    if (!next || next === row.value) return
    mutation.mutate({ action: 'remove', row })
    window.setTimeout(() => mutation.mutate({ action: 'add', row: { category: row.category, value: next } }), 100)
  }
  const columns: ColumnDef<any>[] = [
    { header: '分类', accessorKey: 'category', cell: ({ row }) => <Badge>{getBlacklistCategoryLabel(row.original.category)}</Badge> },
    { header: '值', accessorKey: 'value', cell: ({ row }) => <span className="font-mono">{row.original.value}</span> },
    {
      header: '操作',
      meta: { align: 'right' },
      cell: ({ row }) => (
        <div className="flex justify-end gap-1">
          <Button size="icon" variant="ghost" title="编辑" onClick={() => editRow(row.original)}><Edit3 className="size-4" /></Button>
          <Button size="icon" variant="ghost" title="导出分类" onClick={() => downloadContent(blacklistToYaml({ [row.original.category]: visibleData[row.original.category] || [] }), `blacklist-${row.original.category}.yaml`, 'text/yaml')}><Download className="size-4" /></Button>
          <Button size="sm" variant="danger" onClick={() => mutation.mutate({ action: 'remove', row: row.original })}>移除</Button>
        </div>
      ),
    },
  ]
  const toolbarControls = toolbarVariant === 'fingerprint' ? (
    <>
      <Input className="w-56" value={keyword} onChange={(event) => setKeyword(event.target.value)} placeholder={searchPlaceholder} />
      <input ref={importRef} type="file" accept=".yaml,.yml,.json,.txt" className="hidden" onChange={(event) => importBlacklist(event.target.files?.[0])} />
      {showRefresh ? <Button variant="outline" onClick={() => queryClient.invalidateQueries({ queryKey: ['blacklist'] })}><RefreshCw className="size-4" />刷新</Button> : null}
      <Button variant="outline" onClick={() => importRef.current?.click()}><Upload className="size-4" />导入</Button>
      <Button variant="outline" onClick={() => downloadContent(blacklistToYaml(visibleData), exportFileName, 'text/yaml')}><Download className="size-4" />导出</Button>
      <Button variant="danger" onClick={clearVisibleRows}><Trash2 className="size-4" />全部删除</Button>
      <Button variant="default" onClick={() => { setValue(''); setAddOpen(true) }}><Plus className="size-4" />新增指纹</Button>
    </>
  ) : (
    <>
      <Input className="w-56" value={value} onChange={(event) => setValue(event.target.value)} placeholder={inputPlaceholder} />
      {showRefresh ? <Button variant="outline" onClick={() => queryClient.invalidateQueries({ queryKey: ['blacklist'] })}><RefreshCw className="size-4" />刷新</Button> : null}
      <Button variant="default" disabled={!value.trim()} onClick={() => mutation.mutate({ action: 'add', row: { category, value } })}>
        <Plus className="size-4" />添加
      </Button>
      <input ref={importRef} type="file" accept=".yaml,.yml,.json,.txt" className="hidden" onChange={(event) => importBlacklist(event.target.files?.[0])} />
      <Button variant="outline" onClick={() => openSourceEditor()}><Edit3 className="size-4" />编辑源文件</Button>
      <Button variant="outline" onClick={() => importRef.current?.click()}><Upload className="size-4" />导入</Button>
      <Button variant="outline" onClick={() => downloadContent(blacklistToYaml(visibleData), exportFileName, 'text/yaml')}><Download className="size-4" />导出</Button>
    </>
  )
  const renderToolbarRow = showCategoryTabs || !toolbarPortalId
  return (
    <div className="grid gap-4">
      {toolbarPortalId && toolbarHost ? createPortal(toolbarControls, toolbarHost) : null}
      {showIntro && embedded ? (
        <div>
          <h3 className="text-base font-semibold tracking-tight">{title}</h3>
          {description ? <p className="mt-1 text-sm text-muted">{description}</p> : null}
        </div>
      ) : null}
      {showIntro && !embedded ? <PageTitle title={title} description={description} /> : null}
      {renderToolbarRow ? <Tabs value={category} onValueChange={setCategory}>
        <div className={cn('flex flex-col gap-3 md:flex-row md:items-center', showCategoryTabs ? 'md:justify-between' : 'md:justify-end')}>
          {showCategoryTabs ? (
            <TabsList>
              {blacklistCategories.map((item) => (
                <TabsTrigger key={item} value={item}><ShieldBan className="size-4" />{getBlacklistCategoryLabel(item)}</TabsTrigger>
              ))}
            </TabsList>
          ) : null}
          {!toolbarPortalId ? <div className="flex flex-wrap gap-2">{toolbarControls}</div> : null}
        </div>
      </Tabs> : null}
      <DataTable columns={columns} data={filteredRows} searchPlaceholder={searchPlaceholder} showSearch={tableSearch} paginationStorageKey="blacklist" />
      <Modal
        open={sourceOpen}
        onOpenChange={setSourceOpen}
        title="编辑黑名单源文件"
        description="支持简单 YAML 或 JSON，保存后会覆盖后端黑名单配置。"
        className="max-w-4xl"
        footer={
          <>
            <Button variant="outline" onClick={() => setSourceOpen(false)}>取消</Button>
            <Button variant="default" onClick={() => saveMutation.mutate(parseBlacklistContent(sourceContent))} disabled={saveMutation.isPending}>
              {saveMutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <Save className="size-4" />}
              保存
            </Button>
          </>
        }
      >
        <CodeEditor value={sourceContent} onChange={setSourceContent} minHeight={520} />
      </Modal>
      <Modal
        open={addOpen}
        onOpenChange={setAddOpen}
        title="新增黑名单"
        description="添加后会跳过对应指纹的漏洞扫描。"
        className="max-w-lg"
        footer={
          <>
            <Button variant="outline" onClick={() => setAddOpen(false)}>取消</Button>
            <Button variant="default" disabled={!value.trim() || mutation.isPending} onClick={() => mutation.mutate({ action: 'add', row: { category, value } })}>
              {mutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <Plus className="size-4" />}
              添加
            </Button>
          </>
        }
      >
        <Field label={getBlacklistCategoryLabel(category)}>
          <Input
            value={value}
            onChange={(event) => setValue(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter' && value.trim()) mutation.mutate({ action: 'add', row: { category, value } })
            }}
            placeholder={inputPlaceholder}
          />
        </Field>
      </Modal>
    </div>
  )
}
