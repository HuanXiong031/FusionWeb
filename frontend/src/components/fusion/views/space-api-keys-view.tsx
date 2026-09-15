'use client'

import * as React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ColumnDef } from '@tanstack/react-table'
import { toast } from 'sonner'
import { CheckCircle2, Edit3, Loader2, Pause, Play, Plus, Save, Search, ShieldCheck, Trash2, XCircle } from 'lucide-react'
import { Badge, Button, Drawer, Field, Input, Select, Textarea } from '@/components/ui'
import { DataTable } from '@/components/data-table'
import {
  createSpaceEngineKey,
  deleteSpaceEngineKey,
  getSpaceEngineKeys,
  testSpaceEngineKey,
  updateSpaceEngineKey,
  type SpaceEngineKey,
  type SpaceProvider,
} from '@/lib/api'
import { asList, formatTime } from '@/lib/utils'
import { PageTitle } from '@/components/fusion/shared'

const providers: Array<{ value: SpaceProvider; label: string; description: string; version?: boolean }> = [
  { value: 'fofa', label: 'FOFA', description: 'FOFA 网络空间搜索引擎', version: true },
  { value: 'hunter', label: 'Hunter', description: '奇安信鹰图资产搜索', version: false },
  { value: 'quake', label: 'Quake', description: '360 Quake 网络空间测绘', version: false },
  { value: 'shodan', label: 'Shodan', description: 'Shodan 网络空间搜索引擎', version: false },
  { value: 'zoomeye', label: 'ZoomEye', description: 'ZoomEye 网络空间搜索引擎', version: false },
]

export function SpaceApiKeysView({ demoMode }: { demoMode: boolean }) {
  const queryClient = useQueryClient()
  const [drawerOpen, setDrawerOpen] = React.useState(false)
  const [editing, setEditing] = React.useState<SpaceEngineKey | null>(null)
  const [draft, setDraft] = React.useState<SpaceEngineKey>(() => createEmptyDraft('fofa'))

  const query = useQuery({
    queryKey: ['space-engine-keys'],
    queryFn: getSpaceEngineKeys,
    enabled: !demoMode,
  })
  const rows = demoMode ? demoRows : asList<SpaceEngineKey>(query.data)

  const saveMutation = useMutation({
    mutationFn: () => {
      const payload = normalizeDraft(draft)
      if (!payload.provider) throw new Error('请选择空间引擎')
      if (!payload.name) throw new Error('请输入配置名称')
      if (!editing?.id && !payload.apiKey) throw new Error('请输入 API Key')
      if (editing?.id) return updateSpaceEngineKey(editing.id, payload)
      return createSpaceEngineKey(payload)
    },
    onSuccess: () => {
      toast.success(editing ? '空间引擎配置已更新' : '空间引擎配置已添加')
      setDrawerOpen(false)
      setEditing(null)
      setDraft(createEmptyDraft('fofa'))
      invalidate()
    },
    onError: (error: any) => toast.error(error.message || '保存失败'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: number) => deleteSpaceEngineKey(id),
    onSuccess: () => {
      toast.success('空间引擎配置已删除')
      invalidate()
    },
    onError: (error: any) => toast.error(error.message || '删除失败'),
  })

  const toggleMutation = useMutation({
    mutationFn: (row: SpaceEngineKey) => {
      if (!row.id) throw new Error('配置 ID 不正确')
      return updateSpaceEngineKey(row.id, { ...row, apiKey: '', enabled: row.enabled === false })
    },
    onSuccess: (_res, row) => {
      toast.success(row.enabled === false ? '配置已启用' : '配置已禁用')
      invalidate()
    },
    onError: (error: any) => toast.error(error.message || '操作失败'),
  })

  const testMutation = useMutation({
    mutationFn: (id: number) => testSpaceEngineKey(id),
    onSuccess: (response: any) => {
      if (response?.success) toast.success(response.message || '连接成功')
      else toast.error(response?.message || '连接失败')
      invalidate()
    },
    onError: (error: any) => {
      toast.error(error.message || '连接测试失败')
      invalidate()
    },
  })

  function invalidate() {
    queryClient.invalidateQueries({ queryKey: ['space-engine-keys'] })
  }

  const openCreate = (provider: SpaceProvider = 'fofa') => {
    setEditing(null)
    setDraft(createEmptyDraft(provider))
    setDrawerOpen(true)
  }

  const openEdit = (row: SpaceEngineKey) => {
    setEditing(row)
    setDraft({ ...row, apiKey: '', enabled: row.enabled !== false })
    setDrawerOpen(true)
  }

  const columns: ColumnDef<SpaceEngineKey>[] = [
    {
      header: '空间引擎',
      accessorKey: 'provider',
      meta: { className: 'min-w-[150px]' },
      cell: ({ row }) => (
        <div className="grid gap-1">
          <span className="font-semibold">{getProviderLabel(row.original.provider)}</span>
          <span className="text-xs text-muted">{getProviderDescription(row.original.provider)}</span>
        </div>
      ),
    },
    {
      header: '配置名称',
      accessorKey: 'name',
      meta: { className: 'min-w-[200px]' },
      cell: ({ row }) => (
        <div className="grid gap-1">
          <span className="font-medium">{row.original.name}</span>
          <span className="font-mono text-xs text-muted">{row.original.maskedApiKey || '未设置 Key'}</span>
          {row.original.provider === 'fofa' && row.original.maskedSecretKey ? (
            <span className="font-mono text-xs text-muted">邮箱/Secret：{row.original.maskedSecretKey}</span>
          ) : null}
        </div>
      ),
    },
    {
      header: '版本',
      accessorKey: 'version',
      meta: { align: 'center', className: 'min-w-[90px]' },
      cell: ({ row }) => row.original.provider === 'fofa' ? <Badge tone="info">{row.original.version || 'v1'}</Badge> : <span className="text-muted">-</span>,
    },
    {
      header: '状态',
      accessorKey: 'enabled',
      meta: { align: 'center', className: 'min-w-[100px]' },
      cell: ({ row }) => <Badge tone={row.original.enabled === false ? 'warning' : 'success'}>{row.original.enabled === false ? '禁用' : '启用'}</Badge>,
    },
    {
      header: '测试状态',
      accessorKey: 'lastTestStatus',
      meta: { className: 'min-w-[220px]' },
      cell: ({ row }) => (
        <div className="grid gap-1">
          <span className="flex items-center gap-2 text-sm">
            {row.original.lastTestStatus === 'success' ? <CheckCircle2 className="size-4 text-success-foreground" /> : row.original.lastTestStatus === 'failed' ? <XCircle className="size-4 text-danger-foreground" /> : <ShieldCheck className="size-4 text-muted" />}
            {row.original.lastTestStatus === 'success' ? '连接成功' : row.original.lastTestStatus === 'failed' ? '连接失败' : '未测试'}
          </span>
          <span className="max-w-[280px] truncate text-xs text-muted" title={row.original.lastTestMessage || ''}>
            {row.original.lastTestMessage || formatTime(row.original.lastTestAt)}
          </span>
        </div>
      ),
    },
    {
      header: '更新时间',
      accessorKey: 'updatedAt',
      meta: { align: 'center', className: 'min-w-[150px]' },
      cell: ({ row }) => <span className="font-mono text-sm">{formatTime(row.original.updatedAt)}</span>,
    },
    {
      header: '操作',
      meta: { align: 'right', className: 'min-w-[320px]' },
      cell: ({ row }) => (
        <div className="flex justify-end gap-2">
          <Button size="sm" variant="outline" disabled={testMutation.isPending || !row.original.id} onClick={() => row.original.id && testMutation.mutate(row.original.id)}>
            {testMutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <ShieldCheck className="size-4" />}
            测试
          </Button>
          <Button size="sm" variant={row.original.enabled === false ? 'default' : 'outline'} disabled={toggleMutation.isPending} onClick={() => toggleMutation.mutate(row.original)}>
            {row.original.enabled === false ? <Play className="size-4" /> : <Pause className="size-4" />}
            {row.original.enabled === false ? '启用' : '禁用'}
          </Button>
          <Button size="sm" variant="outline" onClick={() => openEdit(row.original)}>
            <Edit3 className="size-4" />
            编辑
          </Button>
          <Button size="sm" variant="danger" disabled={deleteMutation.isPending} onClick={() => row.original.id && window.confirm('确定删除这个空间引擎配置吗？') && deleteMutation.mutate(row.original.id)}>
            <Trash2 className="size-4" />
            删除
          </Button>
        </div>
      ),
    },
  ]

  return (
    <div className="grid gap-4">
      <PageTitle title="空间测绘 - API 密钥配置" description="维护 FOFA、Hunter、Quake、Shodan、ZoomEye 在线搜索使用的 API Key。" />

      <DataTable
        columns={columns}
        data={rows}
        searchPlaceholder="搜索引擎、名称或测试信息"
        emptyTitle="暂无空间引擎 API Key"
        paginationStorageKey="space-api-keys"
        toolbar={
          <Button variant="default" onClick={() => openCreate()}>
            <Plus className="size-4" />
            新增配置
          </Button>
        }
      />

      <Drawer
        open={drawerOpen}
        onOpenChange={setDrawerOpen}
        title={editing ? '编辑空间引擎配置' : '新增空间引擎配置'}
        description="编辑已有配置时，凭证留空会保留原值。"
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
          <Field label="空间引擎">
            <Select value={draft.provider} onChange={(event) => setDraft(createEmptyDraft(event.target.value as SpaceProvider, draft))}>
              {providers.map((item) => (
                <option key={item.value} value={item.value}>{item.label}</option>
              ))}
            </Select>
          </Field>
          <Field label="配置名称">
            <Input value={draft.name || ''} onChange={(event) => setDraft({ ...draft, name: event.target.value })} placeholder={getProviderLabel(draft.provider)} />
          </Field>
          <Field label="API Key">
            <Input value={draft.apiKey || ''} onChange={(event) => setDraft({ ...draft, apiKey: event.target.value })} placeholder={getApiKeyPlaceholder(draft.provider, editing)} />
          </Field>
          {draft.provider === 'fofa' ? (
            <Field label="账号邮箱 / Secret">
              <Input value={draft.secretKey || ''} onChange={(event) => setDraft({ ...draft, secretKey: event.target.value })} placeholder={editing ? draft.maskedSecretKey || '可选，留空保留原值' : '可选，例如 user@example.com；也可直接在 API Key 填 email:key'} />
            </Field>
          ) : null}
          {draft.provider === 'fofa' ? (
            <Field label="FOFA 版本">
              <Select value={draft.version || 'v1'} onChange={(event) => setDraft({ ...draft, version: event.target.value })}>
                <option value="v1">v1 - fofa.info</option>
                <option value="v5">v5 - v5.fofa.info</option>
              </Select>
            </Field>
          ) : null}
          <Field label="状态">
            <Select value={draft.enabled === false ? 'false' : 'true'} onChange={(event) => setDraft({ ...draft, enabled: event.target.value === 'true' })}>
              <option value="true">启用</option>
              <option value="false">禁用</option>
            </Select>
          </Field>
          <Field label="备注">
            <Textarea className="min-h-24" value={draft.description || ''} onChange={(event) => setDraft({ ...draft, description: event.target.value })} placeholder="例如：团队共享 Key、个人测试 Key" />
          </Field>
        </div>
      </Drawer>
    </div>
  )
}

function createEmptyDraft(provider: SpaceProvider, current?: SpaceEngineKey): SpaceEngineKey {
  const meta = providers.find((item) => item.value === provider) || providers[0]
  return {
    ...current,
    provider,
    name: current?.name || meta.label,
    apiKey: current?.apiKey || '',
    secretKey: provider === 'fofa' ? current?.secretKey || '' : '',
    version: provider === 'fofa' ? current?.version || 'v1' : '',
    enabled: current?.enabled !== false,
    description: current?.description || meta.description,
  }
}

function normalizeDraft(draft: SpaceEngineKey): SpaceEngineKey {
  const provider = String(draft.provider || '').toLowerCase()
  let apiKey = String(draft.apiKey || '').trim()
  let secretKey = provider === 'fofa' ? String(draft.secretKey || '').trim() : ''
  if (provider === 'fofa') {
    const parsed = parseFofaCredential(apiKey, secretKey)
    apiKey = parsed.apiKey
    secretKey = parsed.secretKey
  }
  return {
    ...draft,
    provider,
    name: String(draft.name || '').trim(),
    apiKey,
    secretKey,
    version: provider === 'fofa' ? draft.version || 'v1' : '',
    enabled: draft.enabled !== false,
    description: String(draft.description || '').trim(),
  }
}

function parseFofaCredential(apiKey: string, secretKey: string) {
  const trimmedKey = apiKey.trim()
  const trimmedSecret = secretKey.trim()
  for (const separator of [':', '|']) {
    const index = trimmedKey.indexOf(separator)
    if (index <= 0) continue
    const left = trimmedKey.slice(0, index).trim()
    const right = trimmedKey.slice(index + 1).trim()
    if (left.includes('@') && right) {
      return { apiKey: right, secretKey: trimmedSecret || left }
    }
  }
  return { apiKey: trimmedKey, secretKey: trimmedSecret }
}

function getApiKeyPlaceholder(provider?: string, editing?: SpaceEngineKey | null) {
  if (editing) return editing.maskedApiKey || '留空保留原值'
  if (provider === 'fofa') return '请输入 FOFA API Key，或粘贴 email:key'
  return '请输入 API Key'
}

function getProviderLabel(provider?: string) {
  return providers.find((item) => item.value === provider)?.label || provider || '-'
}

function getProviderDescription(provider?: string) {
  return providers.find((item) => item.value === provider)?.description || '-'
}

const demoRows: SpaceEngineKey[] = [
  { id: 1, provider: 'fofa', name: 'FOFA 主 Key', maskedApiKey: 'abcd****1234', version: 'v1', enabled: true, lastTestStatus: 'success', lastTestMessage: '连接成功', updatedAt: '2026-08-14 12:10:00' },
  { id: 2, provider: 'hunter', name: 'Hunter', maskedApiKey: 'hunt****9f2a', enabled: true, lastTestStatus: 'failed', lastTestMessage: '配额不足或 Key 无效', updatedAt: '2026-08-14 11:30:00' },
  { id: 3, provider: 'quake', name: 'Quake', maskedApiKey: 'quak****7e31', enabled: true, lastTestStatus: 'success', lastTestMessage: '连接成功', updatedAt: '2026-08-14 12:30:00' },
  { id: 4, provider: 'shodan', name: 'Shodan', maskedApiKey: 'shod****21af', enabled: true, lastTestStatus: 'success', lastTestMessage: '连接成功', updatedAt: '2026-08-14 12:40:00' },
  { id: 5, provider: 'zoomeye', name: 'ZoomEye', maskedApiKey: 'zoom****88de', enabled: true, lastTestStatus: 'success', lastTestMessage: '连接成功', updatedAt: '2026-08-14 12:45:00' },
]
