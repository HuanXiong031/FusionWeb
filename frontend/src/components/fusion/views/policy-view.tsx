'use client'

import * as React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ColumnDef } from '@tanstack/react-table'
import { Download, Plus, RefreshCw, ShieldBan, Trash2, Upload } from 'lucide-react'
import { toast } from 'sonner'
import {
  addToAccessBlacklist,
  getAccessBlacklistItems,
  getAccessBlacklistByCategory,
  removeFromAccessBlacklist,
  saveAccessBlacklistByCategory,
} from '@/lib/api'
import { formatTime, unwrap } from '@/lib/utils'
import { DataTable } from '@/components/data-table'
import { Badge, Button, Drawer, Field, Input, Select, Tabs, TabsList, TabsTrigger } from '@/components/ui'
import {
  accessPolicyCategories,
  blacklistToYaml,
  demoBlacklistData,
  downloadContent,
  getBlacklistCategoryLabel,
  parseBlacklistContent,
  pickPolicyConfig,
  readFileText,
  PageTitle,
} from '@/components/fusion/shared'

export function PolicyView({ demoMode }: { demoMode: boolean }) {
  const queryClient = useQueryClient()
  const importRef = React.useRef<HTMLInputElement | null>(null)
  const [category, setCategory] = React.useState(accessPolicyCategories[0])
  const [draftCategory, setDraftCategory] = React.useState(accessPolicyCategories[0])
  const [draftValue, setDraftValue] = React.useState('')
  const [startsAt, setStartsAt] = React.useState('')
  const [expiresAt, setExpiresAt] = React.useState('')
  const [addDrawerOpen, setAddDrawerOpen] = React.useState(false)

  const query = useQuery({
    queryKey: ['access-blacklist'],
    queryFn: getAccessBlacklistByCategory,
    enabled: !demoMode,
  })
  const itemsQuery = useQuery({
    queryKey: ['access-blacklist-items'],
    queryFn: getAccessBlacklistItems,
    enabled: !demoMode,
  })
  const data = demoMode
    ? pickPolicyConfig(demoBlacklistData, accessPolicyCategories)
    : pickPolicyConfig(unwrap<Record<string, string[]>>(query.data) || {}, accessPolicyCategories)

  React.useEffect(() => {
    if (!accessPolicyCategories.includes(category)) {
      setCategory(accessPolicyCategories[0])
    }
  }, [category])

  const rows = demoMode
    ? Object.entries(data).flatMap(([cat, items]) =>
      (Array.isArray(items) ? items : []).map((item) => ({ category: cat, value: item, expiresAt: '' })),
    )
    : unwrap<any[]>(itemsQuery.data) || []
  const filteredRows = rows.filter((row) => row.category === category)

  const addMutation = useMutation({
    mutationFn: async () => {
      const nextValue = draftValue.trim()
      if (!nextValue) throw new Error('请输入要加入黑名单的 IP 或域名')
      if (!startsAt || !expiresAt) throw new Error('请选择拉黑开始时间和结束时间')
      if (demoMode) return null
      return addToAccessBlacklist(draftCategory, nextValue, { startsAt: toBackendDateTime(startsAt), expiresAt: toBackendDateTime(expiresAt) })
    },
    onSuccess: () => {
      toast.success('访问黑名单已添加')
      setDraftValue('')
      setAddDrawerOpen(false)
      queryClient.invalidateQueries({ queryKey: ['access-blacklist'] })
      queryClient.invalidateQueries({ queryKey: ['access-blacklist-items'] })
    },
    onError: (error: any) => toast.error(error.message || '添加失败'),
  })

  const removeMutation = useMutation({
    mutationFn: async (row: { category: string; value: string }) => {
      if (demoMode) return null
      return removeFromAccessBlacklist(row.category, row.value)
    },
    onSuccess: () => {
      toast.success('访问黑名单已移除')
      queryClient.invalidateQueries({ queryKey: ['access-blacklist'] })
      queryClient.invalidateQueries({ queryKey: ['access-blacklist-items'] })
    },
    onError: (error: any) => toast.error(error.message || '移除失败'),
  })

  const saveMutation = useMutation({
    mutationFn: async (config: Record<string, string[]>) => {
      const nextConfig = pickPolicyConfig(config, accessPolicyCategories)
      if (demoMode) return null
      return saveAccessBlacklistByCategory(nextConfig)
    },
    onSuccess: () => {
      toast.success('访问黑名单已导入')
      queryClient.invalidateQueries({ queryKey: ['access-blacklist'] })
      queryClient.invalidateQueries({ queryKey: ['access-blacklist-items'] })
    },
    onError: (error: any) => toast.error(error.message || '导入失败'),
  })

  const importBlacklist = async (file?: File | null) => {
    if (!file) return
    try {
      const text = await readFileText(file)
      saveMutation.mutate(parseBlacklistContent(text))
    } catch (error: any) {
      toast.error(error.message || '导入失败')
    } finally {
      if (importRef.current) importRef.current.value = ''
    }
  }

  const openAddDrawer = () => {
    setDraftCategory(category)
    setDraftValue('')
    const now = new Date()
    setStartsAt(toDateTimeLocalValue(now))
    setExpiresAt(toDateTimeLocalValue(new Date(now.getTime() + 30 * 60 * 1000)))
    setAddDrawerOpen(true)
  }

  const submitAdd = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    addMutation.mutate()
  }

  const columns: ColumnDef<any>[] = [
    {
      header: '分类',
      accessorKey: 'category',
      cell: ({ row }) => <Badge>{getBlacklistCategoryLabel(row.original.category)}</Badge>,
    },
    {
      header: '访问来源',
      accessorKey: 'value',
      cell: ({ row }) => <span className="font-mono">{row.original.value}</span>,
    },
    {
      header: '解锁时间',
      accessorKey: 'expiresAt',
      cell: ({ row }) => row.original.expiresAt
        ? <span className="font-mono text-sm">{formatTime(row.original.expiresAt)}</span>
        : <Badge tone="success">永久</Badge>,
    },
    {
      header: '生效时间',
      accessorKey: 'startsAt',
      cell: ({ row }) => row.original.startsAt
        ? <span className="font-mono text-sm">{formatTime(row.original.startsAt)}</span>
        : <span className="text-muted">立即</span>,
    },
    {
      header: '操作',
      meta: { align: 'right' },
      cell: ({ row }) => (
        <div className="flex justify-end">
          <Button
            size="sm"
            variant="danger"
            disabled={removeMutation.isPending}
            onClick={() => removeMutation.mutate(row.original)}
          >
            <Trash2 className="size-4" />
            移除
          </Button>
        </div>
      ),
    },
  ]

  return (
    <div className="grid gap-4">
      <PageTitle title="策略管理" description="管理谁不能访问 FusionWeb，命中访问黑名单的来源会被拒绝进入系统。" />
      <div className="grid gap-4">
        <Tabs value={category} onValueChange={setCategory}>
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <TabsList>
              {accessPolicyCategories.map((item) => (
                <TabsTrigger key={item} value={item}>
                  <ShieldBan className="size-4" />
                  {getBlacklistCategoryLabel(item)}
                </TabsTrigger>
              ))}
            </TabsList>
            <div className="flex flex-wrap gap-2">
              <Button variant="default" onClick={openAddDrawer}>
                <Plus className="size-4" />
                添加
              </Button>
              <Button
                variant="outline"
                disabled={demoMode}
                onClick={() => {
                  queryClient.invalidateQueries({ queryKey: ['access-blacklist'] })
                  queryClient.invalidateQueries({ queryKey: ['access-blacklist-items'] })
                }}
              >
                <RefreshCw className="size-4" />
                刷新
              </Button>
              <input
                ref={importRef}
                type="file"
                accept=".yaml,.yml,.json,.txt"
                className="hidden"
                onChange={(event) => importBlacklist(event.target.files?.[0])}
              />
              <Button variant="outline" onClick={() => importRef.current?.click()}>
                <Upload className="size-4" />
                导入
              </Button>
              <Button variant="outline" onClick={() => downloadContent(blacklistToYaml(data), 'access-blacklist.yaml', 'text/yaml')}>
                <Download className="size-4" />
                导出
              </Button>
            </div>
          </div>
        </Tabs>
        <DataTable
          columns={columns}
          data={filteredRows}
          searchPlaceholder="搜索访问黑名单"
          showSearch={false}
          paginationStorageKey="policy-access-blacklist"
        />
      </div>
      <Drawer
        open={addDrawerOpen}
        onOpenChange={setAddDrawerOpen}
        title="添加访问黑名单"
        description="添加后，匹配该 IP 或域名的来源将不能访问 FusionWeb。"
        className="max-w-xl"
        footer={
          <>
            <Button variant="outline" onClick={() => setAddDrawerOpen(false)}>
              取消
            </Button>
            <Button type="submit" form="access-blacklist-add-form" disabled={addMutation.isPending}>
              <Plus className="size-4" />
              添加
            </Button>
          </>
        }
      >
        <form id="access-blacklist-add-form" className="grid gap-4" onSubmit={submitAdd}>
          <Field label="类型" hint="IP 支持单个 IP 或 CIDR，例如 192.168.0.1/24；域名支持通配符，例如 *.sec.cn。">
            <Select value={draftCategory} onChange={(event) => setDraftCategory(event.target.value)}>
              {accessPolicyCategories.map((item) => (
                <option key={item} value={item}>
                  {getBlacklistCategoryLabel(item)}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="访问来源" hint="请输入需要拒绝访问 FusionWeb 的 IP、网段或域名。">
            <Input
              autoFocus
              value={draftValue}
              onChange={(event) => setDraftValue(event.target.value)}
              placeholder={draftCategory === 'ip' ? '例如：192.168.0.1 或 192.168.0.0/24' : '例如：evil.sec.cn 或 *.sec.cn'}
            />
          </Field>
          <Field label="拉黑开始时间" hint="精确到年月日时分秒；到开始时间后规则才会生效。">
            <Input type="datetime-local" step={1} value={startsAt} onChange={(event) => setStartsAt(event.target.value)} />
          </Field>
          <Field label="拉黑结束时间" hint="到结束时间后会自动解锁。">
            <Input type="datetime-local" step={1} value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} />
          </Field>
        </form>
      </Drawer>
    </div>
  )
}

function toDateTimeLocalValue(date: Date) {
  const pad = (value: number) => String(value).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

function toBackendDateTime(value: string) {
  return value.replace('T', ' ')
}
