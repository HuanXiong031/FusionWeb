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
  createTask,
  createUser,
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
  getAllPOCFiles,
  getPOCCategories,
  getPocFileContent,
  getPocScanResultDetail,
  getPocScanResultStatistics,
  getPocTaskDetail,
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
import { Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Drawer, EmptyState, Field, Input, Modal, Select, Textarea } from '@/components/ui'
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
  severityMetricCards,
  normalizeSeverityStatKey,
  type SeverityStatKey,
  ToggleField,
  PreviewLine,
  SeverityBadge
} from '@/components/fusion/shared'
import { samplePocTemplate } from '@/components/fusion/views/poc-builder-view'

export function PocView({ demoMode, onCreateTemplate }: { demoMode: boolean; onCreateTemplate?: () => void }) {
  const queryClient = useQueryClient()
  const [keyword, setKeyword] = React.useState('')
  const [category, setCategory] = React.useState('')
  const [severity, setSeverity] = React.useState('')
  const [selectedPaths, setSelectedPaths] = React.useState<string[]>([])
  const [editorOpen, setEditorOpen] = React.useState(false)
  const [editingFile, setEditingFile] = React.useState<PocFileRow | null>(null)
  const [templateDraft, setTemplateDraft] = React.useState({ category: 'custom', fileName: 'new-template.yaml', content: samplePocTemplate })
  const importInputRef = React.useRef<HTMLInputElement | null>(null)
  const query = useQuery({ queryKey: ['pocs'], queryFn: getAllPOCFiles, enabled: !demoMode })
  const categoriesQuery = useQuery({ queryKey: ['poc-categories'], queryFn: getPOCCategories, enabled: !demoMode })
  const categories = demoMode ? ['rce', 'info', 'exposure'] : asList<string>(categoriesQuery.data)
  const allRows = demoMode
    ? [
        { id: 1, category: 'rce', relativePath: 'rce/spring-rce.yaml', fileName: 'spring-rce.yaml', name: 'Spring RCE', severity: 'critical', author: 'nuclei', tags: ['spring', 'rce'] },
        { id: 2, category: 'info', relativePath: 'info/nginx-detect.yaml', fileName: 'nginx-detect.yaml', name: 'Nginx Detect', severity: 'info', author: 'nuclei', tags: ['nginx'] },
      ]
    : asList<any>(query.data)
  const normalizedKeyword = keyword.trim().toLowerCase()
  const rows = allRows.filter((item) => {
    if (category && item.category !== category) return false
    if (severity && normalizeSeverityStatKey(item.severity || item.info?.severity) !== severity) return false
    if (!normalizedKeyword) return true
    return JSON.stringify(item).toLowerCase().includes(normalizedKeyword)
  })
  const templateSeverityStats = React.useMemo(() => {
    const stats: Record<SeverityStatKey, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 }
    rows.forEach((row) => {
      stats[normalizeSeverityStatKey(row.severity || row.info?.severity)] += 1
    })
    return stats
  }, [rows])
  const mutation = useMutation({
    mutationFn: async ({ action, row }: { action: string; row?: any }) => {
      if (demoMode) return null
      if (action === 'delete') return deletePocFile(getPocPath(row))
      return null
    },
    onSuccess: () => {
      toast.success('操作成功')
      queryClient.invalidateQueries({ queryKey: ['pocs'] })
    },
    onError: (error: any) => toast.error(error.message || '操作失败'),
  })
  const refreshTemplates = async () => {
    if (!demoMode) {
      await Promise.all([query.refetch(), categoriesQuery.refetch()])
    }
    toast.success('模板列表已刷新')
  }
  const openCreate = () => {
    if (onCreateTemplate) {
      onCreateTemplate()
      return
    }
    setEditingFile(null)
    setTemplateDraft({ category: category || categories[0] || 'custom', fileName: 'new-template.yaml', content: samplePocTemplate })
    setEditorOpen(true)
  }
  const openEdit = async (row: PocFileRow) => {
    setEditingFile(row)
    const path = getPocPath(row)
    let content = row.content || samplePocTemplate
    if (!demoMode && path) {
      const res = await getPocFileContent(path)
      content = unwrap<any>(res)?.content || content
    }
    setTemplateDraft({ category: row.category || 'custom', fileName: row.fileName || row.file_name || path.split('/').pop() || 'template.yaml', content })
    setEditorOpen(true)
  }
  const saveTemplateMutation = useMutation({
    mutationFn: async () => {
      if (demoMode) return null
      if (editingFile) return updatePocFile(getPocPath(editingFile), templateDraft.content, templateDraft.category, templateDraft.fileName)
      return createPocFile(templateDraft.category, templateDraft.fileName, templateDraft.content)
    },
    onSuccess: () => {
      toast.success(editingFile ? '模板已更新' : '模板已创建')
      setEditorOpen(false)
      queryClient.invalidateQueries({ queryKey: ['pocs'] })
      queryClient.invalidateQueries({ queryKey: ['poc-categories'] })
    },
    onError: (error: any) => toast.error(error.message || '保存失败'),
  })
  const validateMutation = useMutation({
    mutationFn: async () => (demoMode ? { message: 'valid' } : validatePOC(templateDraft.content)),
    onSuccess: () => toast.success('模板校验通过'),
    onError: (error: any) => toast.error(error.message || '模板校验失败'),
  })
  const exportMutation = useMutation({
    mutationFn: async (mode: 'all' | 'selected') => {
      if (demoMode) return { type: 'yaml', content: rows.map((item) => `id: ${item.name}`).join('\n---\n') }
      if (mode === 'selected') return exportSelectedPOCs(selectedPaths)
      return exportAllPOCs()
    },
    onSuccess: (res: any, mode) => {
      const data = unwrap<any>(res)
      downloadContent(data?.content || String(data || ''), mode === 'all' ? 'pocs-export.yaml' : 'pocs-selected.yaml', data?.type === 'zip' ? 'application/zip' : 'text/yaml')
      toast.success('导出成功')
    },
    onError: (error: any) => toast.error(error.message || '导出失败'),
  })
  const importSelectedPoc = async (file?: File | null) => {
    if (!file) return
    if (!file.name.endsWith('.yaml') && !file.name.endsWith('.yml')) {
      toast.error('只支持 YAML 文件')
      return
    }
    try {
      const base64 = await readFileBase64(file)
      if (!demoMode) await importPocFile(category || 'custom', file.name, base64)
      toast.success('导入成功')
      queryClient.invalidateQueries({ queryKey: ['pocs'] })
    } catch (error: any) {
      toast.error(error.message || '导入失败')
    } finally {
      if (importInputRef.current) importInputRef.current.value = ''
    }
  }
  const toggleSelectedPath = (path: string) => {
    setSelectedPaths((current) => (current.includes(path) ? current.filter((item) => item !== path) : [...current, path]))
  }
  const wrapCellClass = 'block max-w-full whitespace-normal break-words [overflow-wrap:anywhere]'
  const getTemplateTags = (tags: unknown) => {
    if (Array.isArray(tags)) return tags.map((item) => String(item).trim()).filter(Boolean)
    if (typeof tags === 'string') return tags.split(/[,，]/).map((item) => item.trim()).filter(Boolean)
    return []
  }
  const columns: ColumnDef<any>[] = [
    {
      id: 'select',
      header: '',
      cell: ({ row }) => {
        const path = getPocPath(row.original)
        return <input type="checkbox" className="size-4 accent-white" checked={selectedPaths.includes(path)} onChange={() => toggleSelectedPath(path)} />
      },
      meta: { className: 'w-12 px-3 text-center' },
    },
    {
      header: '模板ID',
      accessorKey: 'pocId',
      cell: ({ row }) => <span className={cn(wrapCellClass, 'font-mono text-sm')}>{row.original.pocId || row.original.poc_id || row.original.id || '-'}</span>,
      meta: { className: 'w-[16%] min-w-0 max-w-[180px] text-left' },
    },
    {
      header: '文件名称',
      accessorKey: 'fileName',
      cell: ({ row }) => <span className={cn(wrapCellClass, 'font-mono text-sm')}>{row.original.fileName || row.original.file_name || getPocPath(row.original) || '-'}</span>,
      meta: { className: 'w-[17%] min-w-0 max-w-[220px] text-left' },
    },
    {
      header: '漏洞名称',
      accessorKey: 'name',
      cell: ({ row }) => <span className={cn(wrapCellClass, 'font-medium')}>{row.original.name || '-'}</span>,
      meta: { className: 'w-[24%] min-w-0 max-w-[320px] text-left' },
    },
    {
      header: '作者',
      accessorKey: 'author',
      cell: ({ row }) => <span className={cn(wrapCellClass, 'text-muted')}>{row.original.author || '-'}</span>,
      meta: { className: 'w-[11%] min-w-0 max-w-[140px] text-left' },
    },
    {
      header: '等级',
      accessorKey: 'severity',
      cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
      meta: { className: 'w-[88px] text-center' },
    },
    {
      header: '标签',
      accessorKey: 'tags',
      cell: ({ row }) => {
        const tags = getTemplateTags(row.original.tags)
        if (!tags.length) return <span className="text-muted">-</span>
        return (
          <div className="flex max-w-full flex-wrap items-center gap-1 text-xs">
            {tags.map((tag, index) => (
              <span key={`${tag}-${index}`} className="max-w-full rounded-full border border-border bg-raised px-2 py-0.5 leading-5 text-muted whitespace-normal break-words [overflow-wrap:anywhere]">
                {tag}
              </span>
            ))}
          </div>
        )
      },
      meta: { className: 'w-[18%] min-w-0 max-w-[260px] text-left' },
    },
    {
      header: '操作',
      cell: ({ row }) => (
        <div className="flex justify-end gap-2">
          <Button size="icon" variant="ghost" title="编辑" onClick={() => openEdit(row.original)}><Edit3 className="size-4" /></Button>
          <Button size="icon" variant="ghost" title="删除" onClick={() => mutation.mutate({ action: 'delete', row: row.original })}><Trash2 className="size-4" /></Button>
        </div>
      ),
      meta: { align: 'right', className: 'w-[88px] text-right' },
    },
  ]
  return (
    <div className="grid min-w-0 gap-4">
      <PageTitle title="模板管理" description="管理 POC 模板文件，支持搜索、导入、导出、编辑和删除。" />
      <div className="grid gap-4 md:grid-cols-3 xl:grid-cols-7">
        <Metric label="模板总数" value={rows.length} icon={FileCode2} tone="neutral" badgeLabel="总数" />
        {severityMetricCards.map((item) => (
          <Metric key={item.key} label={item.label} value={templateSeverityStats[item.key]} icon={item.icon} tone={item.tone} badgeLabel={item.label} />
        ))}
      </div>
      <div className="mb-3 grid min-w-0 gap-3 md:grid-cols-2 xl:grid-cols-[minmax(180px,220px)_minmax(150px,180px)_minmax(120px,140px)_minmax(0,1fr)] xl:items-start 2xl:grid-cols-[minmax(200px,240px)_minmax(170px,190px)_minmax(130px,150px)_minmax(0,1fr)]">
        <Input className="min-w-0 md:col-span-2 xl:col-span-1" value={keyword} onChange={(event) => setKeyword(event.target.value)} placeholder="搜索模板、分类或标签" />
        <Select className="min-w-0" value={category} onChange={(event) => setCategory(event.target.value)}>
          <option value="">全部分类</option>
          {categories.map((item) => <option key={item} value={item}>{item}</option>)}
        </Select>
        <Select className="min-w-0" value={severity} onChange={(event) => setSeverity(event.target.value)}>
          <option value="">全部等级</option>
          {severityMetricCards.map((item) => <option key={item.key} value={item.key}>{item.label}</option>)}
        </Select>
        <div className="flex min-w-0 flex-wrap items-center gap-2 md:col-span-2 xl:col-span-1 xl:justify-end">
          <input ref={importInputRef} type="file" accept=".yaml,.yml" className="hidden" onChange={(event) => importSelectedPoc(event.target.files?.[0])} />
          <Button variant="outline" disabled={query.isFetching || categoriesQuery.isFetching} onClick={refreshTemplates}>
            <RefreshCw className={cn('size-4', (query.isFetching || categoriesQuery.isFetching) && 'animate-spin')} />刷新
          </Button>
          <Button variant="outline" onClick={() => importInputRef.current?.click()}><Upload className="size-4" />导入</Button>
          <Button variant="outline" onClick={() => exportMutation.mutate('all')}><Download className="size-4" />导出全部</Button>
          <Button variant="outline" disabled={!selectedPaths.length} onClick={() => exportMutation.mutate('selected')}><Check className="size-4" />导出选中</Button>
          <Button variant="default" onClick={openCreate}><Plus className="size-4" />新建模板</Button>
        </div>
      </div>
      <DataTable
        columns={columns}
        data={rows}
        showSearch={false}
        tableClassName="table-fixed"
        paginationStorageKey="poc-templates"
      />
      <Drawer open={editorOpen} onOpenChange={setEditorOpen} title={editingFile ? '编辑 POC 模板' : '新建 POC 模板'}>
        <div className="grid gap-4">
          <div className="grid gap-3 md:grid-cols-2">
            <Field label="分类"><Input value={templateDraft.category} onChange={(event) => setTemplateDraft({ ...templateDraft, category: event.target.value })} /></Field>
            <Field label="文件名"><Input value={templateDraft.fileName} onChange={(event) => setTemplateDraft({ ...templateDraft, fileName: event.target.value })} /></Field>
          </div>
          <CodeEditor value={templateDraft.content} onChange={(value) => setTemplateDraft({ ...templateDraft, content: value })} minHeight={720} />
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={() => validateMutation.mutate()}><ShieldCheck className="size-4" />校验</Button>
            <Button variant="default" onClick={() => saveTemplateMutation.mutate()}><Save className="size-4" />保存</Button>
          </div>
        </div>
      </Drawer>
    </div>
  )
}
