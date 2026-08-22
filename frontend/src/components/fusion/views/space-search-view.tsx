'use client'

import * as React from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { ColumnDef } from '@tanstack/react-table'
import { toast } from 'sonner'
import { Copy, Database, FileDown, KeyRound, Layers3, Loader2, MapPin, RefreshCw, Search } from 'lucide-react'
import { Badge, Button, Card, CardContent, Field, Input, Select } from '@/components/ui'
import { DataTable } from '@/components/data-table'
import { getSpaceEngineKeys, searchSpaceOnline, type SpaceProvider, type SpaceSearchResult } from '@/lib/api'
import { asList, compactNumber, formatTime, unwrap } from '@/lib/utils'
import { Metric, PageTitle, downloadContent, toCsv } from '@/components/fusion/shared'

const providers: Array<{ value: SpaceProvider; label: string; maxSize: number }> = [
  { value: 'fofa', label: 'FOFA', maxSize: 500 },
  { value: 'hunter', label: 'Hunter', maxSize: 100 },
  { value: 'quake', label: 'Quake', maxSize: 100 },
  { value: 'shodan', label: 'Shodan', maxSize: 100 },
  { value: 'zoomeye', label: 'ZoomEye', maxSize: 100 },
]

const quickQueries: Record<SpaceProvider, Array<{ label: string; query: string }>> = {
  fofa: [
    { label: 'IP', query: 'ip="1.1.1.1"' },
    { label: '域名', query: 'domain="example.com"' },
    { label: '标题', query: 'title="admin"' },
    { label: '端口', query: 'port="3389"' },
  ],
  hunter: [
    { label: 'IP', query: 'ip="1.1.1.1"' },
    { label: '域名', query: 'domain.suffix="example.com"' },
    { label: '标题', query: 'web.title="admin"' },
    { label: 'ICP备案', query: 'icp.name="公司名称"' },
  ],
  quake: [
    { label: 'IP', query: 'ip:"1.1.1.1"' },
    { label: '域名', query: 'domain:"example.com"' },
    { label: '标题', query: 'title:"admin"' },
    { label: '服务', query: 'service:"http"' },
  ],
  shodan: [
    { label: 'IP', query: 'ip:1.1.1.1' },
    { label: '产品', query: 'product:nginx' },
    { label: '标题', query: 'title:"admin"' },
    { label: '端口', query: 'port:3389' },
  ],
  zoomeye: [
    { label: 'IP', query: 'ip="1.1.1.1"' },
    { label: '域名', query: 'domain="example.com"' },
    { label: '标题', query: 'title="admin"' },
    { label: '端口', query: 'port="3389"' },
  ],
}

export function SpaceSearchView({ demoMode }: { demoMode: boolean }) {
  const [provider, setProvider] = React.useState<SpaceProvider>('fofa')
  const [queryText, setQueryText] = React.useState('')
  const [page, setPage] = React.useState(1)
  const [pageSize, setPageSize] = React.useState(50)
  const [rows, setRows] = React.useState<SpaceSearchResult[]>([])
  const [total, setTotal] = React.useState(0)
  const [lastSearchedAt, setLastSearchedAt] = React.useState('')

  const keysQuery = useQuery({
    queryKey: ['space-engine-keys'],
    queryFn: getSpaceEngineKeys,
    enabled: !demoMode,
  })
  const keys = demoMode ? demoKeys : asList<any>(keysQuery.data)
  const activeProviderMeta = providers.find((item) => item.value === provider) || providers[0]
  const enabledProviders = new Set(keys.filter((item) => item.enabled !== false).map((item) => String(item.provider).toLowerCase()))
  const currentProviderReady = enabledProviders.has(provider)

  const searchMutation = useMutation({
    mutationFn: async (options?: { page?: number }) => {
      const normalizedQuery = queryText.trim()
      if (!normalizedQuery) throw new Error('请输入查询语句')
      const effectivePage = options?.page || page
      if (demoMode) {
        return {
          provider,
          query: normalizedQuery,
          page: effectivePage,
          pageSize,
          total: demoResults.length,
          list: demoResults.slice(0, Math.min(pageSize, demoResults.length)),
        }
      }
      return searchSpaceOnline({ provider, query: normalizedQuery, page: effectivePage, pageSize })
    },
    onSuccess: (response: any) => {
      const data = unwrap<any>(response) || {}
      setRows(Array.isArray(data.list) ? data.list : [])
      setTotal(Number(data.total || 0))
      setLastSearchedAt(new Date().toISOString())
      toast.success(`查询完成，返回 ${Array.isArray(data.list) ? data.list.length : 0} 条`)
    },
    onError: (error: any) => toast.error(error.message || '查询失败'),
  })

  const handleProviderChange = (value: SpaceProvider) => {
    setProvider(value)
    const nextMeta = providers.find((item) => item.value === value) || providers[0]
    if (pageSize > nextMeta.maxSize) setPageSize(nextMeta.maxSize)
  }

  const columns: ColumnDef<SpaceSearchResult>[] = [
    {
      header: 'Host',
      accessorKey: 'host',
      meta: { className: 'min-w-[260px]' },
      cell: ({ row }) => (
        <div className="grid gap-1">
          <button
            type="button"
            className="max-w-[360px] truncate text-left font-mono text-sm font-semibold text-foreground hover:text-info-foreground"
            title={row.original.host || '-'}
            onClick={() => copyText(row.original.host || '')}
          >
            {row.original.host || '-'}
          </button>
          <span className="max-w-[360px] truncate text-xs text-muted" title={row.original.title || row.original.banner || '-'}>
            {row.original.title || row.original.banner || '-'}
          </span>
        </div>
      ),
    },
    { header: 'IP', accessorKey: 'ip', meta: { className: 'min-w-[140px]' } },
    {
      header: '端口',
      accessorKey: 'port',
      meta: { align: 'center', className: 'min-w-[80px]' },
      cell: ({ row }) => <Badge tone="info">{row.original.port || '-'}</Badge>,
    },
    { header: '协议', accessorKey: 'protocol', meta: { className: 'min-w-[90px]' } },
    { header: '域名', accessorKey: 'domain', meta: { className: 'min-w-[160px]' } },
    { header: '产品', accessorKey: 'product', meta: { className: 'min-w-[150px]' } },
    { header: '服务', accessorKey: 'server', meta: { className: 'min-w-[150px]' } },
    {
      header: '位置',
      meta: { className: 'min-w-[120px]' },
      cell: ({ row }) => [row.original.country, row.original.city].filter(Boolean).join(' / ') || '-',
    },
    { header: 'ICP备案', accessorKey: 'icp', meta: { className: 'min-w-[150px]' } },
  ]

  return (
    <div className="grid gap-4">
      <PageTitle title="空间测绘 - 在线搜索" description="通过已配置的在线资产引擎查询外部空间测绘数据。" />
      <div className="grid gap-4 md:grid-cols-4">
        <Metric label="已启用引擎" value={compactNumber(enabledProviders.size)} icon={Database} tone={enabledProviders.size ? 'success' : 'warning'} badgeLabel="Key" />
        <Metric label="当前引擎" value={activeProviderMeta.label} icon={KeyRound} tone={currentProviderReady ? 'success' : 'warning'} badgeLabel={currentProviderReady ? '可用' : '未启用'} />
        <Metric label="匹配总数" value={compactNumber(total)} icon={Layers3} tone="info" badgeLabel="Total" />
        <Metric label="当前页结果" value={compactNumber(rows.length)} icon={MapPin} tone="accent" badgeLabel={lastSearchedAt ? formatTime(lastSearchedAt) : '结果'} />
      </div>

      <Card>
        <CardContent className="grid gap-4 p-4">
          <div className="grid gap-3 xl:grid-cols-[160px_minmax(0,1fr)_120px_96px_auto] xl:items-end">
            <Field label="空间引擎">
              <Select value={provider} onChange={(event) => handleProviderChange(event.target.value as SpaceProvider)}>
                {providers.map((item) => (
                  <option key={item.value} value={item.value}>{item.label}</option>
                ))}
              </Select>
            </Field>
            <Field label="查询语句">
              <Input value={queryText} onChange={(event) => setQueryText(event.target.value)} placeholder={getProviderPlaceholder(provider)} onKeyDown={(event) => event.key === 'Enter' && searchMutation.mutate({ page })} />
            </Field>
            <Field label="每页数量">
              <Select value={String(pageSize)} onChange={(event) => setPageSize(Number(event.target.value))}>
                {[10, 50, 100, activeProviderMeta.maxSize].filter((item, index, arr) => arr.indexOf(item) === index && item <= activeProviderMeta.maxSize).map((size) => (
                  <option key={size} value={size}>{size}</option>
                ))}
              </Select>
            </Field>
            <Field label="页码">
              <Input type="number" min={1} value={page} onChange={(event) => setPage(Math.max(1, Number(event.target.value) || 1))} />
            </Field>
            <div className="flex flex-wrap gap-2">
              <Button variant="default" disabled={searchMutation.isPending || !queryText.trim()} onClick={() => searchMutation.mutate({ page })}>
                {searchMutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <Search className="size-4" />}
                搜索
              </Button>
              <Button variant="outline" disabled={!queryText.trim()} onClick={() => setQueryText('')}>
                <RefreshCw className="size-4" />
                清空
              </Button>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm text-muted">快捷查询</span>
            {quickQueries[provider].map((item) => (
              <Button key={item.label} size="sm" variant="outline" onClick={() => setQueryText(item.query)}>
                {item.label}
              </Button>
            ))}
          </div>
        </CardContent>
      </Card>

      <DataTable
        columns={columns}
        data={rows}
        searchPlaceholder="过滤当前页结果"
        emptyTitle="暂无空间测绘结果"
        paginationStorageKey="space-online-search"
        toolbar={
          <>
            <Button variant="outline" disabled={page <= 1 || searchMutation.isPending} onClick={() => {
              const nextPage = Math.max(1, page - 1)
              setPage(nextPage)
              searchMutation.mutate({ page: nextPage })
            }}>
              上一页
            </Button>
            <Button variant="outline" disabled={searchMutation.isPending || !rows.length || rows.length < pageSize} onClick={() => {
              const nextPage = page + 1
              setPage(nextPage)
              searchMutation.mutate({ page: nextPage })
            }}>
              下一页
            </Button>
            <Button variant="outline" disabled={!rows.length} onClick={() => downloadContent(toCsv(rows), `space-${provider}-results.csv`, 'text/csv;charset=utf-8')}>
              <FileDown className="size-4" />
              导出当前页
            </Button>
          </>
        }
      />
    </div>
  )
}

function copyText(value: string) {
  if (!value) return
  navigator.clipboard?.writeText(value).then(() => toast.success('已复制')).catch(() => toast.error('复制失败'))
}

const demoKeys = [
  { id: 1, provider: 'fofa', name: 'FOFA', enabled: true },
  { id: 2, provider: 'hunter', name: 'Hunter', enabled: true },
  { id: 3, provider: 'quake', name: 'Quake', enabled: true },
  { id: 4, provider: 'shodan', name: 'Shodan', enabled: true },
  { id: 5, provider: 'zoomeye', name: 'ZoomEye', enabled: true },
]

const demoResults: SpaceSearchResult[] = [
  { host: 'https://example.com', ip: '93.184.216.34', port: 443, protocol: 'https', domain: 'example.com', title: 'Example Domain', server: 'ECS', country: 'US', city: 'Los Angeles', product: 'Akamai' },
  { host: 'http://203.0.113.10:8080', ip: '203.0.113.10', port: 8080, protocol: 'http', domain: 'demo.local', title: 'Admin Console', server: 'nginx', country: 'CN', city: 'Hangzhou', product: 'nginx' },
]

function getProviderPlaceholder(provider: SpaceProvider) {
  if (provider === 'quake') return 'title:"admin" && country:"CN"'
  if (provider === 'shodan') return 'product:nginx country:CN'
  if (provider === 'zoomeye') return 'title="admin" && port="443"'
  return 'title="admin" && port="443"'
}
