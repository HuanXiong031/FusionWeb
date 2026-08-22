'use client'

import * as React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ColumnDef } from '@tanstack/react-table'
import { toast } from 'sonner'
import { Download, Edit3, Loader2, Pause, Play, Plus, RadioTower, RefreshCw, Save, Search, Trash2, Upload, User, KeyRound } from 'lucide-react'
import { Badge, Button, Card, CardContent, Drawer, Field, Input, Select, Tabs, TabsList, TabsTrigger, Textarea } from '@/components/ui'
import { DataTable } from '@/components/data-table'
import {
  createRTSPDictionary,
  deleteRTSPDictionary,
  deleteRTSPDictionaryByType,
  getRTSPDictionary,
  getRTSPDictionaryStatistics,
  importRTSPDictionary,
  updateRTSPDictionary,
  type RTSPDictionaryItem,
  type RTSPDictionaryType,
} from '@/lib/api'
import { asList, compactNumber, formatTime, unwrap } from '@/lib/utils'
import { Metric, PageTitle, downloadContent, readFileText } from '@/components/fusion/shared'

const tabs: Array<{ value: RTSPDictionaryType; label: string; icon: React.ElementType; search: string }> = [
  { value: 'path', label: '路径字典', icon: RadioTower, search: '搜索路径，例如 /Streaming/Channels/101' },
  { value: 'username', label: '账号字典', icon: User, search: '搜索账号，例如 admin' },
  { value: 'password', label: '密码字典', icon: KeyRound, search: '搜索密码，例如 123456' },
]

export function RTSPDictionaryView({ demoMode }: { demoMode: boolean }) {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = React.useState<RTSPDictionaryType>('path')
  const [keyword, setKeyword] = React.useState('')
  const [drawerOpen, setDrawerOpen] = React.useState(false)
  const [editing, setEditing] = React.useState<RTSPDictionaryItem | null>(null)
  const [draft, setDraft] = React.useState<RTSPDictionaryItem>(() => createEmptyDraft('path'))
  const importRef = React.useRef<HTMLInputElement | null>(null)

  const query = useQuery({
    queryKey: ['rtsp-dictionary', activeTab],
    queryFn: () => getRTSPDictionary({ type: activeTab }),
    enabled: !demoMode,
  })
  const statsQuery = useQuery({
    queryKey: ['rtsp-dictionary-statistics'],
    queryFn: getRTSPDictionaryStatistics,
    enabled: !demoMode,
  })

  const rows = demoMode ? demoRows.filter((item) => item.type === activeTab) : asList<RTSPDictionaryItem>(query.data)
  const filteredRows = React.useMemo(() => {
    const needle = keyword.trim().toLowerCase()
    if (!needle) return rows
    return rows.filter((row) => [row.value, row.type].join(' ').toLowerCase().includes(needle))
  }, [keyword, rows])
  const stats = demoMode ? { path: 121, username: 10, password: 551 } : unwrap<Record<string, number>>(statsQuery.data) || {}

  const saveMutation = useMutation({
    mutationFn: () => {
      const payload = { ...draft, type: activeTab, value: String(draft.value || '').trim(), enabled: draft.enabled !== false }
      if (!payload.value) throw new Error('请输入字典内容')
      if (editing?.id) return updateRTSPDictionary(editing.id, payload)
      return createRTSPDictionary(payload)
    },
    onSuccess: () => {
      toast.success(editing ? 'RTSP 字典已更新' : 'RTSP 字典已添加')
      setDrawerOpen(false)
      setEditing(null)
      setDraft(createEmptyDraft(activeTab))
      invalidateQueries()
    },
    onError: (error: any) => toast.error(error.message || '保存失败'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: number) => deleteRTSPDictionary(id),
    onSuccess: () => {
      toast.success('RTSP 字典已删除')
      invalidateQueries()
    },
    onError: (error: any) => toast.error(error.message || '删除失败'),
  })

  const toggleMutation = useMutation({
    mutationFn: (row: RTSPDictionaryItem) => {
      if (!row.id) throw new Error('字典 ID 不正确')
      return updateRTSPDictionary(row.id, { ...row, enabled: row.enabled === false })
    },
    onSuccess: (_res, row) => {
      toast.success(row.enabled === false ? '字典已启用' : '字典已禁用')
      invalidateQueries()
    },
    onError: (error: any) => toast.error(error.message || '操作失败'),
  })

  const deleteAllMutation = useMutation({
    mutationFn: () => deleteRTSPDictionaryByType(activeTab),
    onSuccess: () => {
      toast.success('当前字典已清空')
      invalidateQueries()
    },
    onError: (error: any) => toast.error(error.message || '清空失败'),
  })

  const importMutation = useMutation({
    mutationFn: (content: string) => importRTSPDictionary(activeTab, content),
    onSuccess: (response) => {
      const data = unwrap<any>(response)
      const imported = Number(data?.imported ?? data?.count ?? 0)
      const skipped = Number(data?.skipped ?? 0)
      toast.success(`已导入 ${imported} 条，跳过重复 ${skipped} 条`)
      invalidateQueries()
    },
    onError: (error: any) => toast.error(error.message || '导入失败'),
  })

  function invalidateQueries() {
    queryClient.invalidateQueries({ queryKey: ['rtsp-dictionary'] })
    queryClient.invalidateQueries({ queryKey: ['rtsp-dictionary-statistics'] })
  }

  const openCreate = () => {
    setEditing(null)
    setDraft(createEmptyDraft(activeTab))
    setDrawerOpen(true)
  }

  const openEdit = (row: RTSPDictionaryItem) => {
    setEditing(row)
    setDraft({ ...row, enabled: row.enabled !== false })
    setDrawerOpen(true)
  }

  const columns: ColumnDef<RTSPDictionaryItem>[] = [
    {
      header: '内容',
      accessorKey: 'value',
      meta: { className: 'w-[42%]' },
      cell: ({ row }) => (
        <div className="grid gap-1">
          <span className="font-mono text-sm font-semibold text-foreground">{row.original.value}</span>
          <span className="text-xs text-muted">{getTypeDescription(row.original.type)}</span>
        </div>
      ),
    },
    {
      header: '类型',
      accessorKey: 'type',
      meta: { align: 'center', className: 'w-[12%]' },
      cell: ({ row }) => <Badge tone="info">{getTypeLabel(row.original.type)}</Badge>,
    },
    {
      header: '状态',
      accessorKey: 'enabled',
      meta: { align: 'center', className: 'w-[12%]' },
      cell: ({ row }) => <Badge tone={row.original.enabled === false ? 'warning' : 'success'}>{row.original.enabled === false ? '禁用' : '启用'}</Badge>,
    },
    {
      header: '更新时间',
      accessorKey: 'updatedAt',
      meta: { align: 'center', className: 'w-[18%]' },
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

  const activeMeta = tabs.find((item) => item.value === activeTab) || tabs[0]

  return (
    <div className="grid gap-4">
      <PageTitle title="RTSP 字典管理" description="统一维护 RTSP 探测使用的路径、账号和密码字典，扫描时会自动读取已启用的字典。" />
      <div className="grid gap-4 md:grid-cols-4">
        <Metric label="路径字典" value={compactNumber(stats.path || 0)} icon={RadioTower} tone="info" badgeLabel="路径" />
        <Metric label="账号字典" value={compactNumber(stats.username || 0)} icon={User} tone="success" badgeLabel="账号" />
        <Metric label="密码字典" value={compactNumber(stats.password || 0)} icon={KeyRound} tone="warning" badgeLabel="密码" />
        <Metric label="当前筛选" value={compactNumber(filteredRows.length)} icon={Search} tone="neutral" badgeLabel={activeMeta.label} />
      </div>

      <Card className="overflow-hidden">
        <div className="flex flex-col gap-3 border-b border-border p-4 xl:flex-row xl:items-center xl:justify-between">
          <Tabs value={activeTab} onValueChange={(value) => { setActiveTab(value as RTSPDictionaryType); setKeyword('') }}>
            <TabsList>
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
          <div className="flex min-w-0 flex-wrap items-center gap-2 xl:flex-nowrap">
            <div className="relative min-w-[260px] flex-1 xl:w-[340px] xl:flex-none">
              <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted" />
              <Input className="pl-9" value={keyword} onChange={(event) => setKeyword(event.target.value)} placeholder={activeMeta.search} />
            </div>
            <Button variant="outline" onClick={() => invalidateQueries()}>
              <RefreshCw className="size-4" />
              刷新
            </Button>
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
            <Button variant="outline" onClick={() => downloadContent(filteredRows.map((row) => row.value).join('\n'), `rtsp-${activeTab}-dictionary.txt`, 'text/plain;charset=utf-8')}>
              <Download className="size-4" />
              导出
            </Button>
            <Button variant="danger" disabled={deleteAllMutation.isPending} onClick={() => {
              if (window.confirm(`确定删除全部${activeMeta.label}吗？`)) deleteAllMutation.mutate()
            }}>
              {deleteAllMutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <Trash2 className="size-4" />}
              全部删除
            </Button>
            <Button variant="default" onClick={openCreate}>
              <Plus className="size-4" />
              添加
            </Button>
          </div>
        </div>
        <CardContent className="p-0">
          <DataTable columns={columns} data={filteredRows} showSearch={false} emptyTitle="暂无 RTSP 字典" className="rounded-none border-0" paginationStorageKey={`rtsp-dictionary-${activeTab}`} />
        </CardContent>
      </Card>

      <Drawer
        open={drawerOpen}
        onOpenChange={setDrawerOpen}
        title={editing ? '编辑 RTSP 字典' : '添加 RTSP 字典'}
        description="支持保存路径、账号、密码三类字典；扫描时只使用启用状态的内容。"
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
          <Field label="字典类型">
            <Select value={activeTab} onChange={(event) => setActiveTab(event.target.value as RTSPDictionaryType)} disabled={Boolean(editing)}>
              <option value="path">路径字典</option>
              <option value="username">账号字典</option>
              <option value="password">密码字典</option>
            </Select>
          </Field>
          <Field label="字典内容">
            <Input value={draft.value} onChange={(event) => setDraft({ ...draft, value: event.target.value })} placeholder={activeTab === 'path' ? '/Streaming/Channels/101' : activeTab === 'username' ? 'admin' : '123456'} />
          </Field>
          <Field label="状态">
            <Select value={draft.enabled === false ? 'false' : 'true'} onChange={(event) => setDraft({ ...draft, enabled: event.target.value === 'true' })}>
              <option value="true">启用</option>
              <option value="false">禁用</option>
            </Select>
          </Field>
        </div>
      </Drawer>
    </div>
  )
}

function createEmptyDraft(type: RTSPDictionaryType): RTSPDictionaryItem {
  return { type, value: '', enabled: true }
}

function getTypeLabel(type?: string) {
  if (type === 'username') return '账号'
  if (type === 'password') return '密码'
  return '路径'
}

function getTypeDescription(type?: string) {
  if (type === 'username') return 'RTSP 认证用户名'
  if (type === 'password') return 'RTSP 认证密码'
  return 'RTSP DESCRIBE 探测路径'
}

const demoRows: RTSPDictionaryItem[] = [
  { id: 1, type: 'path', value: '/Streaming/Channels/101', enabled: true, updatedAt: '2026-07-25 12:12:10' },
  { id: 2, type: 'path', value: '/cam/realmonitor', enabled: true, updatedAt: '2026-07-25 12:10:38' },
  { id: 3, type: 'username', value: 'admin', enabled: true, updatedAt: '2026-07-25 12:09:12' },
  { id: 4, type: 'username', value: 'root', enabled: true, updatedAt: '2026-07-25 12:08:43' },
  { id: 5, type: 'password', value: '123456', enabled: true, updatedAt: '2026-07-25 12:15:19' },
  { id: 6, type: 'password', value: 'admin123', enabled: true, updatedAt: '2026-07-25 12:13:41' },
]
