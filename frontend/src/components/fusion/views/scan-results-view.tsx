'use client'

import * as React from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ColumnDef } from '@tanstack/react-table'
import { Bug, Download, Eye, FileDown, FileText, Fingerprint, Globe2, Network, RefreshCw, ShieldAlert, Terminal } from 'lucide-react'
import { getFingerprintResults, getPocScanResults, getPocTaskList, getReconResults, getTaskLogs, getTasks, getVulnResults, type TaskRow } from '@/lib/api'
import { asList, formatTime } from '@/lib/utils'
import { Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Drawer, Select, Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui'
import { DataTable } from '@/components/data-table'
import { ScreenshotPreviewCell } from '@/components/fusion/screenshot-preview-cell'
import { LogConsole } from '@/components/fusion/log-console'
import { ReportExportPanel } from '@/components/fusion/views/report-center-view'
import {
  demoTasks,
  downloadContent,
  getHttpStatusTone,
  getPocTaskDisplayName,
  getPocTaskId,
  getTaskDisplayName,
  getTaskId,
  getVulnDisplayName,
  getVulnTarget,
  getVulnTemplateID,
  HttpCodePanel,
  Metric,
  normalizeVulnDetail,
  PageTitle,
  SeverityBadge,
  toCsv,
  VulnDetailRow,
} from '@/components/fusion/shared'

type ResultSource = 'web' | 'port' | 'template'

function getTaskReportType(task?: TaskRow): 'web' | 'port' {
  const raw = String(task?.taskType || task?.task_type || task?.scanType || task?.scan_type || '').toLowerCase()
  return raw.includes('port') ? 'port' : 'web'
}

function getFingerprintTarget(row: any) {
  return row.url || row.target || row.host || row.ip || row.matchedRules?.url || row.matched_rules?.url || '-'
}

function getFingerprintName(row: any) {
  return row.name || row.fingerprint || row.fingerprintName || row.fingerprint_name || row.matchedRules?.fingerprint || row.matched_rules?.fingerprint || '-'
}

function getFingerprintRule(row: any) {
  const rules = row.matchedRules || row.matched_rules
  if (Array.isArray(rules)) return rules.map((item) => (typeof item === 'string' ? item : item?.rule || item?.matcher || item?.name || JSON.stringify(item))).join(', ')
  if (rules && typeof rules === 'object') return rules.rule || rules.matcher || rules.name || rules.header || rules.body || row.source || row.matcher || '-'
  return row.source || row.matcher || (typeof rules === 'string' ? rules : '-') || '-'
}

export function ScanResultsView({ demoMode, onOpenTask }: { demoMode: boolean; onOpenTask: (taskId: string) => void }) {
  const queryClient = useQueryClient()
  const [source, setSource] = React.useState<ResultSource>('web')
  const [selectedTaskId, setSelectedTaskId] = React.useState('')
  const [activeTab, setActiveTab] = React.useState('ports')
  const [vulnDetail, setVulnDetail] = React.useState<any | null>(null)
  const tasksQuery = useQuery({ queryKey: ['tasks'], queryFn: getTasks, enabled: !demoMode, refetchInterval: 3000 })
  const pocTasksQuery = useQuery({ queryKey: ['poc-tasks'], queryFn: () => getPocTaskList({ page: 1, pageSize: 300 }), enabled: !demoMode, refetchInterval: 3000 })
  const scanTasks = demoMode ? demoTasks : asList<TaskRow>(tasksQuery.data)
  const pocTasks = demoMode
    ? [{ taskId: 'poc-demo-1', taskName: '核心站点 POC 验证', found_vulns: 1, status: 'completed', progress: 100, createdAt: '2026-07-03 18:30:00' }]
    : asList<any>(pocTasksQuery.data)
  const tasks = React.useMemo(() => {
    if (source === 'template') return pocTasks
    return scanTasks.filter((task) => getTaskReportType(task) === source)
  }, [source, scanTasks, pocTasks])
  const taskIds = tasks.map((task: any) => (source === 'template' ? getPocTaskId(task) : getTaskId(task))).filter(Boolean)

  React.useEffect(() => {
    if (selectedTaskId && taskIds.includes(selectedTaskId)) return
    setSelectedTaskId(taskIds[0] || '')
  }, [selectedTaskId, taskIds.join('|')])

  const selectedTask = tasks.find((task: any) => (source === 'template' ? getPocTaskId(task) : getTaskId(task)) === selectedTaskId)
  const selectedTaskType = React.useMemo(() => source, [source])
  const isTemplateSource = source === 'template'

  const portsQuery = useQuery({ queryKey: ['scan-results-center', selectedTaskId, 'port'], queryFn: () => getReconResults(selectedTaskId, 'port'), enabled: !!selectedTaskId && !isTemplateSource && !demoMode, refetchInterval: 2000 })
  const urlsQuery = useQuery({ queryKey: ['scan-results-center', selectedTaskId, 'url'], queryFn: () => getReconResults(selectedTaskId, 'url'), enabled: !!selectedTaskId && !isTemplateSource && !demoMode, refetchInterval: 3000 })
  const fingerprintsQuery = useQuery({ queryKey: ['scan-results-center', selectedTaskId, 'fingerprints'], queryFn: () => getFingerprintResults(selectedTaskId), enabled: !!selectedTaskId && !isTemplateSource && !demoMode, refetchInterval: 3000 })
  const vulnsQuery = useQuery({ queryKey: ['scan-results-center', selectedTaskId, 'vulns'], queryFn: () => getVulnResults(selectedTaskId), enabled: !!selectedTaskId && !isTemplateSource && !demoMode, refetchInterval: 3000 })
  const logsQuery = useQuery({ queryKey: ['scan-results-center', selectedTaskId, 'logs'], queryFn: () => getTaskLogs(selectedTaskId, { page: 1, pageSize: 500 }), enabled: !!selectedTaskId && !isTemplateSource && !demoMode, refetchInterval: 3000 })
  const pocResultsQuery = useQuery({ queryKey: ['scan-results-center', selectedTaskId, 'template-results'], queryFn: () => getPocScanResults(selectedTaskId, { page: 1, pageSize: 500 }), enabled: !!selectedTaskId && isTemplateSource && !demoMode, refetchInterval: 3000 })

  const ports = isTemplateSource
    ? []
    : demoMode
      ? [
          { host: '10.10.10.12', port: 443, protocol: 'https', service: 'nginx', status: 'open', banner: 'nginx/1.24' },
          { host: '10.10.10.12', port: 22, protocol: 'tcp', service: 'ssh', status: 'open', banner: 'OpenSSH' },
        ]
      : asList<any>(portsQuery.data)
  const urls = isTemplateSource
    ? []
    : demoMode
      ? [
          { url: 'https://acme.com', statusCode: 200, title: 'Acme Portal', length: 32891 },
          { url: 'https://acme.com/admin', statusCode: 403, title: 'Forbidden', length: 1204 },
        ]
      : asList<any>(urlsQuery.data)
  const fingerprintRows = isTemplateSource
    ? []
    : demoMode
      ? [
          { url: 'https://acme.com', name: 'nginx', category: 'Web Server', type: 'passive' },
          { url: 'https://acme.com', name: 'Spring Boot', category: 'Framework', type: 'active' },
        ]
      : asList<any>(fingerprintsQuery.data)
  const vulns = isTemplateSource
    ? []
    : demoMode
      ? [
          { id: 1, name: 'Spring Actuator Exposure', severity: 'high', url: 'https://acme.com/actuator/env', template_id: 'http/exposures/spring-actuator.yaml', request: 'GET /actuator/env HTTP/1.1', response: 'HTTP/1.1 200 OK' },
        ]
      : asList<any>(vulnsQuery.data)
  const logs = isTemplateSource
    ? []
    : demoMode
      ? [
          { time: '2026-07-03 19:20:00', level: 'info', message: '任务开始执行' },
          { time: '2026-07-03 19:21:14', level: 'success', message: '发现开放端口 443' },
        ]
      : asList<any>(logsQuery.data)
  const templateResults = isTemplateSource
    ? demoMode
      ? [
          { id: 1, taskId: 'poc-demo-1', template_id: 'spring-rce', name: 'Spring RCE', target: 'https://acme.com', severity: 'critical', discovered_at: '2026-07-03 18:31:00', request: 'GET /actuator/env HTTP/1.1', response: 'HTTP/1.1 200 OK' },
        ]
      : asList<any>(pocResultsQuery.data)
    : []

  const groupedFingerprints = React.useMemo(() => {
    return Array.from(
      fingerprintRows.reduce((map, row) => {
        const target = getFingerprintTarget(row)
        const group = map.get(target) || { target, rows: [] as any[] }
        group.rows.push(row)
        map.set(target, group)
        return map
      }, new Map<string, { target: string; rows: any[] }>()),
    ).map(([, group]) => {
      const names = Array.from(new Set(group.rows.map(getFingerprintName).filter((name) => name && name !== '-')))
      const categories = Array.from(new Set(group.rows.map((row) => row.category || row.type || row.scanScope || row.scan_scope || 'web').filter(Boolean)))
      const rules = Array.from(new Set(group.rows.map(getFingerprintRule).filter((rule) => rule && rule !== '-')))
      return { ...group, fingerprintNames: names, categories, rules, rulesText: rules.join(' '), searchText: [group.target, ...names, ...categories, ...rules].join(' ') }
    })
  }, [fingerprintRows])

  const refreshResults = () => {
    if (!selectedTaskId) return
    queryClient.invalidateQueries({ queryKey: ['scan-results-center', selectedTaskId] })
    if (isTemplateSource) queryClient.invalidateQueries({ queryKey: ['poc-tasks'] })
  }

  const getActiveRows = () => {
    if (isTemplateSource) return activeTab === 'reports' ? [] : templateResults
    if (activeTab === 'ports') return ports
    if (activeTab === 'urls') return urls
    if (activeTab === 'fingerprints') return groupedFingerprints
    if (activeTab === 'vulns') return vulns
    if (activeTab === 'logs') return logs
    return []
  }

  const activeRows = getActiveRows()
  const vulnInfo = normalizeVulnDetail(vulnDetail)

  const portColumns: ColumnDef<any>[] = [
    { header: '主机', accessorKey: 'host', meta: { className: 'w-[220px]' }, cell: ({ row }) => <span className="block truncate font-mono" title={row.original.host || row.original.ip || '-'}>{row.original.host || row.original.ip || '-'}</span> },
    { header: '端口', accessorKey: 'port', meta: { align: 'center', className: 'w-[120px]' }, cell: ({ row }) => <Badge tone="info">{row.original.port || '-'}</Badge> },
    { header: '协议', accessorKey: 'protocol', meta: { align: 'center', className: 'w-[140px]' }, cell: ({ row }) => row.original.protocol || '-' },
    { header: '服务', accessorKey: 'service', meta: { align: 'center', className: 'w-[220px]' }, cell: ({ row }) => <span className="block truncate" title={row.original.service || '-'}>{row.original.service || '-'}</span> },
    { header: '状态', accessorKey: 'status', meta: { align: 'center', className: 'w-[120px]' }, cell: ({ row }) => <Badge tone={String(row.original.status).includes('open') ? 'success' : 'neutral'}>{row.original.status || '-'}</Badge> },
    { header: 'Banner', accessorKey: 'banner', meta: { className: 'w-[360px] max-w-[360px]' }, cell: ({ row }) => <span className="block max-w-[360px] truncate font-mono text-xs text-muted" title={row.original.banner || '-'}>{row.original.banner || '-'}</span> },
  ]
  const urlColumns: ColumnDef<any>[] = [
    {
      header: 'URL',
      accessorKey: 'url',
      meta: { className: 'w-[560px]' },
      cell: ({ row }) => {
        const url = row.original.displayURL || row.original.display_url || row.original.finalURL || row.original.final_url || row.original.url || row.original.target || '-'
        return <span className="block truncate font-mono text-sm" title={url}>{url}</span>
      },
    },
    { header: '状态码', accessorKey: 'statusCode', meta: { align: 'center', className: 'w-[120px]' }, cell: ({ row }) => {
      const code = row.original.statusCode || row.original.status_code || '-'
      return <Badge tone={getHttpStatusTone(code) as any}>{code}</Badge>
    } },
    { header: '标题', accessorKey: 'title', meta: { align: 'center', className: 'w-[260px]' }, cell: ({ row }) => <span className="block truncate" title={row.original.title || '-'}>{row.original.title || '-'}</span> },
    { header: '长度', accessorKey: 'length', meta: { align: 'center', className: 'w-[120px]' }, cell: ({ row }) => row.original.length || row.original.contentLength || row.original.content_length || 0 },
    { header: '截图', accessorKey: 'screenshotPath', meta: { align: 'center', className: 'w-[140px]' }, cell: ({ row }) => <ScreenshotPreviewCell taskId={selectedTaskId} resultId={row.original.id} screenshotPath={row.original.screenshotPath || row.original.screenshot_path} label={row.original.displayURL || row.original.display_url || row.original.url || row.original.target || '-'} /> },
  ]
  const fingerprintColumns: ColumnDef<any>[] = [
    { header: '目标', accessorKey: 'target', cell: ({ row }) => <span className="break-all font-mono text-sm">{row.original.target}</span> },
    {
      header: '指纹',
      accessorKey: 'fingerprintsText',
      cell: ({ row }) => (
        <div className="flex max-w-xl flex-wrap gap-1.5">
          {row.original.fingerprintNames.length ? row.original.fingerprintNames.map((name: string) => <Badge key={name} tone="info">{name}</Badge>) : <span className="text-muted">-</span>}
        </div>
      ),
    },
    { header: '分类', accessorKey: 'categories', cell: ({ row }) => <div className="flex flex-wrap gap-1.5">{row.original.categories.map((category: string) => <Badge key={category}>{category}</Badge>)}</div> },
    { header: '数量', accessorKey: 'rows', cell: ({ row }) => <Badge tone="neutral">{row.original.rows.length}</Badge> },
  ]
  const vulnColumns: ColumnDef<any>[] = [
    { header: '漏洞', accessorKey: 'name', cell: ({ row }) => <span className="font-medium">{getVulnDisplayName(row.original)}</span> },
    { header: '等级', accessorKey: 'severity', cell: ({ row }) => <SeverityBadge severity={row.original.severity || row.original.info?.severity} /> },
    { header: '目标', accessorKey: 'target', cell: ({ row }) => <span className="break-all font-mono text-sm">{getVulnTarget(row.original)}</span> },
    { header: '模板', accessorKey: 'templateId', meta: { className: 'w-[220px]' }, cell: ({ row }) => {
      const templateId = getVulnTemplateID(row.original)
      return <span className="block truncate font-mono text-xs text-muted" title={templateId}>{templateId}</span>
    } },
    { header: '操作', meta: { align: 'right' }, cell: ({ row }) => <Button size="sm" variant="outline" onClick={() => setVulnDetail(row.original)}><Eye className="size-4" />详情</Button> },
  ]
  const templateColumns: ColumnDef<any>[] = [
    { header: '模板ID', accessorKey: 'template_id', meta: { className: 'w-[220px]' }, cell: ({ row }) => {
      const templateId = row.original.template_id || row.original.templateID || row.original.template || '-'
      return <span className="block truncate font-mono text-xs" title={templateId}>{templateId}</span>
    } },
    { header: '漏洞名称', accessorKey: 'name', cell: ({ row }) => <span className="font-medium">{row.original.name || row.original.pocName || row.original.templateName || '-'}</span> },
    { header: '目标', accessorKey: 'target', cell: ({ row }) => <span className="break-all font-mono text-sm">{row.original.target || row.original.url || '-'}</span> },
    { header: '严重程度', accessorKey: 'severity', cell: ({ row }) => <SeverityBadge severity={row.original.severity} /> },
    { header: '发现时间', accessorKey: 'discovered_at', cell: ({ row }) => <span className="text-muted">{formatTime(row.original.discovered_at || row.original.discoveredAt || row.original.createdAt)}</span> },
    { header: '操作', meta: { align: 'right' }, cell: ({ row }) => <Button size="sm" variant="outline" onClick={() => setVulnDetail(row.original)}><Eye className="size-4" />详情</Button> },
  ]

  return (
    <div className="grid gap-4">
      <PageTitle title="结果中心" description="端口、URL、指纹、漏洞、运行日志和报告导出都可以直接按任务查询。" />
      <div className="grid gap-4 md:grid-cols-5">
        <Metric label="端口" value={ports.length} icon={Network} tone="info" badgeLabel="端口" />
        <Metric label="URL" value={urls.length} icon={Globe2} tone="success" badgeLabel="链接" />
        <Metric label="指纹目标" value={groupedFingerprints.length} icon={Fingerprint} tone="accent" badgeLabel="指纹" />
        <Metric label="漏洞" value={isTemplateSource ? templateResults.length : vulns.length} icon={isTemplateSource ? ShieldAlert : Bug} tone="danger" badgeLabel="漏洞" />
        <Metric label="日志" value={logs.length} icon={Terminal} tone="warning" badgeLabel="日志" />
      </div>
      <Card>
        <CardContent className="grid gap-3 p-4 lg:grid-cols-[180px_1fr_auto]">
          <Select value={source} onChange={(event) => { setSource(event.target.value as ResultSource); setSelectedTaskId(''); setActiveTab(event.target.value === 'template' ? 'template' : 'ports') }}>
            <option value="web">Web扫描</option>
            <option value="port">端口扫描</option>
            <option value="template">模板扫描</option>
          </Select>
          <Select value={selectedTaskId} onChange={(event) => setSelectedTaskId(event.target.value)}>
            <option value="">选择任务</option>
            {tasks.map((task: any) => {
              const id = isTemplateSource ? getPocTaskId(task) : getTaskId(task)
              const name = isTemplateSource ? getPocTaskDisplayName(task) : getTaskDisplayName(task)
              return <option key={id} value={id}>{name}</option>
            })}
          </Select>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" disabled={!selectedTaskId} onClick={refreshResults}><RefreshCw className="size-4" />刷新</Button>
            <Button variant="outline" disabled={!activeRows.length} onClick={() => downloadContent(toCsv(activeRows), `scan-results-${selectedTaskId || 'task'}-${activeTab}.csv`, 'text/csv')}><Download className="size-4" />导出当前</Button>
            {isTemplateSource ? null : <Button variant="default" disabled={!selectedTaskId} onClick={() => onOpenTask(selectedTaskId)}><Eye className="size-4" />任务详情</Button>}
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <div>
            <CardTitle>{selectedTask ? (isTemplateSource ? getPocTaskDisplayName(selectedTask) : getTaskDisplayName(selectedTask)) : '扫描结果'}</CardTitle>
            <CardDescription>{selectedTaskId || '请选择一个任务查看结果'}</CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList>
              {isTemplateSource ? <TabsTrigger value="template"><ShieldAlert className="size-4" />模板结果</TabsTrigger> : null}
              {isTemplateSource ? null : <TabsTrigger value="ports"><Network className="size-4" />端口信息</TabsTrigger>}
              {isTemplateSource ? null : <TabsTrigger value="urls"><Globe2 className="size-4" />目标信息</TabsTrigger>}
              {isTemplateSource ? null : <TabsTrigger value="fingerprints"><Fingerprint className="size-4" />指纹信息</TabsTrigger>}
              {isTemplateSource ? null : <TabsTrigger value="vulns"><Bug className="size-4" />漏洞信息</TabsTrigger>}
              {isTemplateSource ? null : <TabsTrigger value="logs"><Terminal className="size-4" />运行日志</TabsTrigger>}
              <TabsTrigger value="reports"><FileDown className="size-4" />报告导出</TabsTrigger>
            </TabsList>
            <TabsContent value="template"><DataTable columns={templateColumns} data={templateResults} searchPlaceholder="搜索模板ID、漏洞名称或目标" emptyTitle={selectedTaskId ? '暂无模板结果' : '请选择任务'} paginationStorageKey="scan-results-template" /></TabsContent>
            <TabsContent value="ports"><DataTable columns={portColumns} data={ports} searchPlaceholder="搜索主机、端口或服务" emptyTitle={selectedTaskId ? '暂无端口结果' : '请选择任务'} tableClassName="table-fixed min-w-[1220px]" paginationStorageKey="scan-results-ports" /></TabsContent>
            <TabsContent value="urls"><DataTable columns={urlColumns} data={urls} searchPlaceholder="搜索 URL 或标题" emptyTitle={selectedTaskId ? '暂无 URL 结果' : '请选择任务'} tableClassName="table-fixed min-w-[1380px]" paginationStorageKey="scan-results-urls" /></TabsContent>
            <TabsContent value="fingerprints"><DataTable columns={fingerprintColumns} data={groupedFingerprints} searchPlaceholder="搜索指纹或目标" emptyTitle={selectedTaskId ? '暂无指纹结果' : '请选择任务'} paginationStorageKey="scan-results-fingerprints" /></TabsContent>
            <TabsContent value="vulns"><DataTable columns={vulnColumns} data={vulns} searchPlaceholder="搜索漏洞、模板或目标" emptyTitle={selectedTaskId ? '暂无漏洞结果' : '请选择任务'} paginationStorageKey="scan-results-vulns" /></TabsContent>
            <TabsContent value="logs"><LogConsole rows={logs} emptyTitle={selectedTaskId ? '暂无运行日志' : '请选择任务'} maxHeightClass="max-h-[520px]" /></TabsContent>
            <TabsContent value="reports" className="pt-2"><ReportExportPanel demoMode={demoMode} selectedTaskId={selectedTaskId} selectedSource={selectedTaskType} /></TabsContent>
          </Tabs>
        </CardContent>
      </Card>
      <Drawer open={!!vulnDetail} onOpenChange={(open) => !open && setVulnDetail(null)} title={isTemplateSource ? '模板结果详情' : '漏洞详情'} description={vulnInfo.target} className="max-w-none md:w-[60vw]">
        {vulnDetail ? (
          <div className="grid gap-5">
            <section className="rounded-card border border-border bg-background">
              <VulnDetailRow label="目标信息" value={vulnInfo.target} mono />
              <VulnDetailRow label="漏洞名称" value={vulnInfo.name} />
              <VulnDetailRow label="模板 ID" value={vulnInfo.templateID} mono />
              {vulnInfo.templatePath !== '-' ? <VulnDetailRow label="模板路径" value={vulnInfo.templatePath} mono /> : null}
              <VulnDetailRow label="严重程度" value={<SeverityBadge severity={vulnInfo.severity} />} />
              {vulnInfo.author !== '-' ? <VulnDetailRow label="作者信息" value={vulnInfo.author} /> : null}
              <VulnDetailRow label="标签" value={vulnInfo.tags} />
              {vulnInfo.matcherName !== '-' && vulnInfo.matcherName !== vulnInfo.tags ? <VulnDetailRow label="匹配器" value={vulnInfo.matcherName} /> : null}
              <VulnDetailRow label="漏洞描述" value={vulnInfo.description} />
              <VulnDetailRow label="发现时间" value={formatTime(vulnInfo.discoveredAt)} />
            </section>
            {vulnInfo.request || vulnInfo.response ? (
              <Tabs defaultValue={vulnInfo.request ? 'request' : 'response'}>
                <TabsList>
                  {vulnInfo.request ? <TabsTrigger value="request"><FileText className="size-4" />请求 Request</TabsTrigger> : null}
                  {vulnInfo.response ? <TabsTrigger value="response"><Terminal className="size-4" />响应 Response</TabsTrigger> : null}
                </TabsList>
                {vulnInfo.request ? <TabsContent value="request"><HttpCodePanel title="请求 Request" value={vulnInfo.request} /></TabsContent> : null}
                {vulnInfo.response ? <TabsContent value="response"><HttpCodePanel title="响应 Response" value={vulnInfo.response} /></TabsContent> : null}
              </Tabs>
            ) : null}
          </div>
        ) : null}
      </Drawer>
    </div>
  )
}
