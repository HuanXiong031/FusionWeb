'use client'

import * as React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ColumnDef } from '@tanstack/react-table'
import { toast } from 'sonner'
import { Code2, Database, Download, Edit3, FolderOpen, KeyRound, Layers3, Loader2, Pause, Play, Plus, RefreshCw, Save, Search, ShieldCheck, Trash2, Upload } from 'lucide-react'
import { Badge, Button, Card, CardContent, Drawer, Field, Input, Select, Tabs, TabsList, TabsTrigger, Textarea } from '@/components/ui'
import { DataTable } from '@/components/data-table'
import {
  createScanDictionary,
  deleteScanDictionary,
  deleteScanDictionaryByType,
  getScanDictionary,
  getScanDictionaryStatistics,
  importScanDictionary,
  updateScanDictionary,
  type ScanDictionaryItem,
  type ScanDictionaryType,
} from '@/lib/api'
import { asList, compactNumber, formatTime, unwrap } from '@/lib/utils'
import { Metric, PageTitle, downloadContent, readFileText } from '@/components/fusion/shared'

const tabs: Array<{ value: ScanDictionaryType; label: string; icon: React.ElementType; search: string; placeholder: string }> = [
  { value: 'subdomain_prefix', label: '子域名前缀', icon: Layers3, search: '搜索前缀，例如 api', placeholder: 'api' },
  { value: 'directory_path', label: '目录路径', icon: FolderOpen, search: '搜索路径，例如 admin', placeholder: 'admin' },
  { value: 'weak_username', label: '弱口令账号', icon: KeyRound, search: '搜索账号，例如 root', placeholder: 'admin' },
  { value: 'weak_password', label: '弱口令密码', icon: ShieldCheck, search: '搜索密码，例如 123456', placeholder: '123456' },
  { value: 'js_sensitive_keyword', label: 'JS敏感关键词', icon: Code2, search: '搜索关键词，例如 token', placeholder: 'access_token' },
  { value: 'js_route_keyword', label: 'JS高危路由', icon: Code2, search: '搜索路由，例如 /admin', placeholder: '/admin' },
  { value: 'js_auth_keyword', label: 'JS鉴权关键词', icon: Code2, search: '搜索鉴权关键词，例如 403', placeholder: 'unauthorized' },
]

export function ScanDictionaryView({ demoMode, fixedType }: { demoMode: boolean; fixedType?: ScanDictionaryType }) {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = React.useState<ScanDictionaryType>(fixedType || 'directory_path')
  const [keyword, setKeyword] = React.useState('')
  const [drawerOpen, setDrawerOpen] = React.useState(false)
  const [editing, setEditing] = React.useState<ScanDictionaryItem | null>(null)
  const [draft, setDraft] = React.useState<ScanDictionaryItem>(() => createEmptyDraft(fixedType || 'directory_path'))
  const importRef = React.useRef<HTMLInputElement | null>(null)

  React.useEffect(() => {
    if (!fixedType || fixedType === activeTab) return
    setActiveTab(fixedType)
    setKeyword('')
    setEditing(null)
    setDraft(createEmptyDraft(fixedType))
  }, [activeTab, fixedType])

  const query = useQuery({
    queryKey: ['scan-dictionary', activeTab],
    queryFn: () => getScanDictionary({ type: activeTab }),
    enabled: !demoMode,
  })
  const statsQuery = useQuery({
    queryKey: ['scan-dictionary-statistics'],
    queryFn: getScanDictionaryStatistics,
    enabled: !demoMode,
  })

  const rows = demoMode ? demoRows.filter((item) => item.type === activeTab) : asList<ScanDictionaryItem>(query.data)
  const filteredRows = React.useMemo(() => {
    const needle = keyword.trim().toLowerCase()
    if (!needle) return rows
    return rows.filter((row) => [row.value, row.description, row.type].join(' ').toLowerCase().includes(needle))
  }, [keyword, rows])
  const stats = demoMode ? demoStats : unwrap<Record<string, number>>(statsQuery.data) || {}
  const activeMeta = tabs.find((item) => item.value === activeTab) || tabs[0]
  const ActiveIcon = activeMeta.icon

  const saveMutation = useMutation({
    mutationFn: () => {
      const payload = { ...draft, type: activeTab, value: String(draft.value || '').trim(), enabled: draft.enabled !== false }
      if (!payload.value) throw new Error('请输入字典内容')
      if (editing?.id) return updateScanDictionary(editing.id, payload)
      return createScanDictionary(payload)
    },
    onSuccess: () => {
      toast.success(editing ? `${activeMeta.label}已更新` : `${activeMeta.label}已添加`)
      setDrawerOpen(false)
      setEditing(null)
      setDraft(createEmptyDraft(activeTab))
      invalidateQueries()
    },
    onError: (error: any) => toast.error(error.message || '保存失败'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: number) => deleteScanDictionary(id),
    onSuccess: () => {
      toast.success(`${activeMeta.label}已删除`)
      invalidateQueries()
    },
    onError: (error: any) => toast.error(error.message || '删除失败'),
  })

  const toggleMutation = useMutation({
    mutationFn: (row: ScanDictionaryItem) => {
      if (!row.id) throw new Error('字典 ID 不正确')
      return updateScanDictionary(row.id, { ...row, enabled: row.enabled === false })
    },
    onSuccess: (_res, row) => {
      toast.success(row.enabled === false ? '字典已启用' : '字典已禁用')
      invalidateQueries()
    },
    onError: (error: any) => toast.error(error.message || '操作失败'),
  })

  const deleteAllMutation = useMutation({
    mutationFn: () => deleteScanDictionaryByType(activeTab),
    onSuccess: () => {
      toast.success(`${activeMeta.label}已清空`)
      invalidateQueries()
    },
    onError: (error: any) => toast.error(error.message || '清空失败'),
  })

  const importMutation = useMutation({
    mutationFn: (content: string) => importScanDictionary(activeTab, content),
    onSuccess: (response) => {
      const data = unwrap<any>(response)
      const imported = Number(data?.imported ?? 0)
      const skipped = Number(data?.skipped ?? 0)
      toast.success(`已导入 ${imported} 条，跳过重复 ${skipped} 条`)
      invalidateQueries()
    },
    onError: (error: any) => toast.error(error.message || '导入失败'),
  })

  function invalidateQueries() {
    queryClient.invalidateQueries({ queryKey: ['scan-dictionary'] })
    queryClient.invalidateQueries({ queryKey: ['scan-dictionary-statistics'] })
  }

  const openCreate = () => {
    setEditing(null)
    setDraft(createEmptyDraft(activeTab))
    setDrawerOpen(true)
  }

  const openEdit = (row: ScanDictionaryItem) => {
    setEditing(row)
    setDraft({ ...row, enabled: row.enabled !== false })
    setDrawerOpen(true)
  }

  const columns: ColumnDef<ScanDictionaryItem>[] = [
    {
      header: '内容',
      accessorKey: 'value',
      meta: { className: 'w-[36%]' },
      cell: ({ row }) => (
        <div className="grid gap-1">
          <span className="font-mono text-sm font-semibold text-foreground">{row.original.value}</span>
          <span className="text-xs text-muted">{row.original.description || getTypeDescription(row.original.type)}</span>
        </div>
      ),
    },
    ...(fixedType ? [] : [{
      header: '分类',
      accessorKey: 'type',
      meta: { align: 'center', className: 'w-[14%]' },
      cell: ({ row }) => <Badge tone="info">{getTypeLabel(row.original.type)}</Badge>,
    }] satisfies ColumnDef<ScanDictionaryItem>[]),
    {
      header: '来源',
      accessorKey: 'isBuiltin',
      meta: { align: 'center', className: 'w-[10%]' },
      cell: ({ row }) => <Badge tone={row.original.isBuiltin ? 'neutral' : 'accent'}>{row.original.isBuiltin ? '内置' : '自定义'}</Badge>,
    },
    {
      header: '状态',
      accessorKey: 'enabled',
      meta: { align: 'center', className: 'w-[10%]' },
      cell: ({ row }) => <Badge tone={row.original.enabled === false ? 'warning' : 'success'}>{row.original.enabled === false ? '禁用' : '启用'}</Badge>,
    },
    {
      header: '更新时间',
      accessorKey: 'updatedAt',
      meta: { align: 'center', className: 'w-[14%]' },
      cell: ({ row }) => <span className="font-mono text-sm">{formatTime(row.original.updatedAt)}</span>,
    },
    {
      header: '操作',
      meta: { align: 'right', className: 'w-[16%]' },
      cell: ({ row }) => (
        <div className="flex justify-end gap-2">
          <Button size="sm" variant={row.original.enabled === false ? 'default' : 'outline'} disabled={toggleMutation.isPending} onClick={() => toggleMutation.mutate(row.original)}>
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
      <PageTitle title={`${activeMeta.label}管理`} description={getTypeDescription(activeTab)} />
      <div className="grid gap-4 md:grid-cols-4">
        <Metric label="当前分类总数" value={compactNumber(stats[activeTab] || rows.length)} icon={activeMeta.icon} tone="info" badgeLabel={activeMeta.label} />
        <Metric label="已启用" value={compactNumber(rows.filter((row) => row.enabled !== false).length)} icon={Play} tone="success" badgeLabel="启用" />
        <Metric label="内置字典" value={compactNumber(rows.filter((row) => row.isBuiltin).length)} icon={Database} tone="neutral" badgeLabel="内置" />
        <Metric label="当前筛选" value={compactNumber(filteredRows.length)} icon={Search} tone="accent" badgeLabel="结果" />
      </div>

      <Card className="overflow-hidden">
        <div className="flex flex-col gap-3 border-b border-border p-4 xl:flex-row xl:items-center xl:justify-between">
          {fixedType ? (
            <div className="flex items-center gap-2 text-sm font-semibold">
              <ActiveIcon className="size-4" />
              {activeMeta.label}
            </div>
          ) : (
            <Tabs value={activeTab} onValueChange={(value) => { setActiveTab(value as ScanDictionaryType); setKeyword('') }}>
              <TabsList className="flex-wrap">
                {tabs.map((item) => {
                  const Icon = item.icon
                  return (
                    <TabsTrigger key={item.value} value={item.value}>
                      <Icon className="size-4" />
                      {item.label}
                    </TabsTrigger>
                  )
                })}
              </TabsList>
            </Tabs>
          )}
          <div className="flex min-w-0 flex-wrap items-center gap-2 xl:flex-nowrap">
            <div className="relative min-w-[260px] flex-1 xl:w-[340px] xl:flex-none">
              <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted" />
              <Input className="pl-9" value={keyword} onChange={(event) => setKeyword(event.target.value)} placeholder={activeMeta.search} />
            </div>
            <Button variant="outline" onClick={() => invalidateQueries()}><RefreshCw className="size-4" />刷新</Button>
            <input ref={importRef} type="file" accept=".txt,.dic,.csv" className="hidden" onChange={async (event) => {
              const file = event.target.files?.[0]
              event.target.value = ''
              if (!file) return
              importMutation.mutate(await readFileText(file))
            }} />
            <Button variant="outline" disabled={importMutation.isPending} onClick={() => importRef.current?.click()}>
              {importMutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <Upload className="size-4" />}
              导入
            </Button>
            <Button variant="outline" onClick={() => downloadContent(filteredRows.map((row) => row.value).join('\n'), `scan-${activeTab}-dictionary.txt`, 'text/plain;charset=utf-8')}>
              <Download className="size-4" />
              导出
            </Button>
            <Button variant="danger" disabled={deleteAllMutation.isPending} onClick={() => {
              if (window.confirm(`确定删除全部${activeMeta.label}吗？`)) deleteAllMutation.mutate()
            }}>
              {deleteAllMutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <Trash2 className="size-4" />}
              全部删除
            </Button>
            <Button variant="default" onClick={openCreate}><Plus className="size-4" />添加</Button>
          </div>
        </div>
        <CardContent className="p-0">
          <DataTable columns={columns} data={filteredRows} showSearch={false} emptyTitle={`暂无${activeMeta.label}`} className="rounded-none border-0" paginationStorageKey={`scan-dictionary-${activeTab}`} />
        </CardContent>
      </Card>

      <Drawer
        open={drawerOpen}
        onOpenChange={setDrawerOpen}
        title={editing ? `编辑${activeMeta.label}` : `添加${activeMeta.label}`}
        description="扫描运行时只读取启用状态的数据库字典。"
        className="max-w-xl"
        footer={
          <>
            <Button variant="outline" onClick={() => setDrawerOpen(false)}>取消</Button>
            <Button variant="default" disabled={saveMutation.isPending} onClick={() => saveMutation.mutate()}>
              {saveMutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <Save className="size-4" />}
              保存
            </Button>
          </>
        }
      >
        <div className="grid gap-4">
          {fixedType ? null : (
            <Field label="字典分类">
              <Select value={activeTab} onChange={(event) => setActiveTab(event.target.value as ScanDictionaryType)} disabled={Boolean(editing)}>
                {tabs.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
              </Select>
            </Field>
          )}
          <Field label="字典内容">
            <Input value={draft.value} onChange={(event) => setDraft({ ...draft, value: event.target.value })} placeholder={activeMeta.placeholder} />
          </Field>
          <Field label="状态">
            <Select value={draft.enabled === false ? 'false' : 'true'} onChange={(event) => setDraft({ ...draft, enabled: event.target.value === 'true' })}>
              <option value="true">启用</option>
              <option value="false">禁用</option>
            </Select>
          </Field>
          <Field label="备注">
            <Textarea className="min-h-24" value={draft.description || ''} onChange={(event) => setDraft({ ...draft, description: event.target.value })} placeholder={getTypeDescription(activeTab)} />
          </Field>
        </div>
      </Drawer>
    </div>
  )
}

function createEmptyDraft(type: ScanDictionaryType): ScanDictionaryItem {
  return { type, value: '', enabled: true, description: getTypeDescription(type) }
}

function getTypeLabel(type?: string) {
  return tabs.find((item) => item.value === type)?.label || type || '-'
}

function getTypeDescription(type?: string) {
  if (type === 'subdomain_prefix') return '子域名字典前缀，用于额外 DNS 解析'
  if (type === 'directory_path') return '目录扫描路径'
  if (type === 'weak_username') return '弱口令扫描用户名'
  if (type === 'weak_password') return '弱口令扫描密码'
  if (type === 'js_sensitive_keyword') return 'JS 敏感信息关键词'
  if (type === 'js_route_keyword') return 'JS 高危路由关键词'
  if (type === 'js_auth_keyword') return 'JS 鉴权响应关键词'
  return '扫描字典'
}

const demoStats = {
  subdomain_prefix: 7,
  directory_path: 8,
  weak_username: 8,
  weak_password: 6,
  js_sensitive_keyword: 8,
  js_route_keyword: 4,
  js_auth_keyword: 6,
}

const demoRows: ScanDictionaryItem[] = [
  { id: 1, type: 'directory_path', value: 'admin', enabled: true, isBuiltin: true, description: '目录扫描路径', updatedAt: '2026-08-14 12:12:10' },
  { id: 2, type: 'directory_path', value: '.git/config', enabled: true, isBuiltin: true, description: '目录扫描路径', updatedAt: '2026-08-14 12:12:10' },
  { id: 3, type: 'weak_username', value: 'root', enabled: true, isBuiltin: true, description: '弱口令用户名', updatedAt: '2026-08-14 12:12:10' },
  { id: 4, type: 'weak_password', value: '123456', enabled: true, isBuiltin: true, description: '弱口令密码', updatedAt: '2026-08-14 12:12:10' },
  { id: 5, type: 'js_sensitive_keyword', value: 'access_token', enabled: true, isBuiltin: true, description: 'JS 敏感关键词', updatedAt: '2026-08-14 12:12:10' },
  { id: 6, type: 'subdomain_prefix', value: 'api', enabled: true, isBuiltin: true, description: '子域名前缀', updatedAt: '2026-08-14 12:12:10' },
]
