'use client'

import * as React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ColumnDef } from '@tanstack/react-table'
import { toast } from 'sonner'
import { Copy, Loader2, Play, RadioTower, Save, Square, Terminal, Upload } from 'lucide-react'
import { Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Field, Input, Select, Textarea } from '@/components/ui'
import { DataTable } from '@/components/data-table'
import { getRTSPResults, startRTSPScan, stopRTSPScan, type RTSPScanResult, type RTSPScanState } from '@/lib/api'
import { asList, cn, compactNumber, formatTime, parseTargets, unwrap } from '@/lib/utils'
import { Metric, PageTitle, getProgressFillClass, getProgressTextClass, getProgressTone, readFileText } from '@/components/fusion/shared'

type RTSPLog = { time: string; level: string; message: string }
const maxRTSPConsoleLogs = 20000
const RTSP_SCAN_LEFT_WIDTH_KEY = 'fusionweb-rtsp-scan-left-panel-width'

function clampPanelWidth(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value))
}

function loadStoredPanelWidth(key: string, fallback: number, min: number, max: number) {
  if (typeof window === 'undefined') return fallback
  try {
    const value = Number(window.localStorage.getItem(key))
    return Number.isFinite(value) ? clampPanelWidth(value, min, max) : fallback
  } catch {
    return fallback
  }
}

function saveStoredPanelWidth(key: string, value: number) {
  if (typeof window === 'undefined') return
  try {
    window.localStorage.setItem(key, String(value))
  } catch {
    // ignore local storage failures
  }
}

function getDefaultRtspScanLeftWidth() {
  if (typeof window === 'undefined') return 960
  return clampPanelWidth(Math.round(window.innerWidth * 0.48), 520, 1100)
}

function loadInitialRtspScanLeftWidth() {
  if (typeof window === 'undefined') return 960
  try {
    const stored = Number(window.localStorage.getItem(RTSP_SCAN_LEFT_WIDTH_KEY))
    if (Number.isFinite(stored) && stored > 500) {
      return clampPanelWidth(stored, 520, 1100)
    }
  } catch {
    // ignore storage failures and fall back to a balanced default
  }
  return getDefaultRtspScanLeftWidth()
}

export function RTSPScanView({ demoMode }: { demoMode: boolean }) {
  const queryClient = useQueryClient()
  const [targetsText, setTargetsText] = React.useState('192.168.1.10\n192.168.1.11:8554')
  const [port, setPort] = React.useState(554)
  const [threadCount, setThreadCount] = React.useState(5)
  const [timeout, setTimeoutValue] = React.useState(3)
  const [authMethod, setAuthMethod] = React.useState('Digest')
  const [taskState, setTaskState] = React.useState<RTSPScanState | null>(null)
  const [logs, setLogs] = React.useState<RTSPLog[]>([])
  const [liveResults, setLiveResults] = React.useState<RTSPScanResult[]>([])
  const consoleRef = React.useRef<HTMLDivElement | null>(null)
  const targetFileRef = React.useRef<HTMLInputElement | null>(null)
  const [leftPanelWidth, setLeftPanelWidth] = React.useState(() => loadInitialRtspScanLeftWidth())

  const taskId = taskState?.taskId || ''
  const isRunning = taskState?.status === 'running'
  const resultsQuery = useQuery({
    queryKey: ['rtsp-results', taskId],
    queryFn: () => getRTSPResults(taskId ? { taskId } : undefined),
    enabled: !demoMode,
    refetchInterval: isRunning ? 3000 : false,
  })
  const savedResults = asList<RTSPScanResult>(resultsQuery.data)
  const results = taskId ? mergeRTSPResults(liveResults, savedResults) : savedResults

  const startMutation = useMutation({
    mutationFn: async () => {
      const targets = parseTargets(targetsText)
      if (!targets.length) throw new Error('请输入 RTSP 扫描目标')
      return startRTSPScan({ targets, port, threadCount, timeout, authMethod })
    },
    onSuccess: (response) => {
      const state = unwrap<RTSPScanState>(response)
      setTaskState(state)
      setLogs((state.logs || []).slice(-maxRTSPConsoleLogs))
      setLiveResults(state.results || [])
      queryClient.invalidateQueries({ queryKey: ['rtsp-results'] })
      toast.success('RTSP 扫描已启动')
    },
    onError: (error: any) => toast.error(error.message || '启动失败'),
  })

  const stopMutation = useMutation({
    mutationFn: () => stopRTSPScan(taskId),
    onSuccess: () => {
      setTaskState((state) => state ? { ...state, status: 'stopped' } : state)
      toast.success('RTSP 扫描已停止')
    },
    onError: (error: any) => toast.error(error.message || '停止失败'),
  })

  React.useEffect(() => {
    const handleRealtime = (event: Event) => {
      const message = (event as CustomEvent<any>).detail
      const type = String(message?.type || '')
      const data = message?.data || {}
      if (!type.startsWith('rtsp.') || !data?.taskId) return
      setTaskState((state) => {
        if (!state || state.taskId !== data.taskId) return state
        if (type === 'rtsp.progress') return { ...state, progress: Number(data.progress || 0), completed: Number(data.completed || state.completed), totalTargets: Number(data.totalTargets || state.totalTargets) }
        if (type === 'rtsp.status') return { ...state, status: String(data.status || state.status), progress: Number(data.progress || state.progress) }
        if (type === 'rtsp.result') return { ...state, found: Number(data.found || state.found) }
        return state
      })
      if (!taskId || data.taskId !== taskId) return
      if (type === 'rtsp.log' && data.log) {
        setLogs((items) => [...items, data.log].slice(-maxRTSPConsoleLogs))
      }
      if (type === 'rtsp.result' && data.result) {
        setLiveResults((items) => mergeRTSPResults([data.result, ...items], []))
        queryClient.invalidateQueries({ queryKey: ['rtsp-results', data.taskId] })
      }
    }
    window.addEventListener('fusionweb-realtime', handleRealtime)
    return () => window.removeEventListener('fusionweb-realtime', handleRealtime)
  }, [queryClient, taskId])

  React.useEffect(() => {
    const el = consoleRef.current
    if (!el) return
    el.scrollTop = el.scrollHeight
  }, [logs.length])

  React.useEffect(() => {
    saveStoredPanelWidth(RTSP_SCAN_LEFT_WIDTH_KEY, leftPanelWidth)
  }, [leftPanelWidth])

  const columns: ColumnDef<RTSPScanResult>[] = [
    {
      header: '目标',
      accessorKey: 'target',
      cell: ({ row }) => (
        <div className="grid gap-1">
          <span className="font-mono text-sm font-semibold text-foreground">{row.original.host}:{row.original.port}</span>
          <span className="font-mono text-xs text-muted">{row.original.uri || '/'}</span>
        </div>
      ),
    },
    {
      header: '认证',
      accessorKey: 'authMethod',
      cell: ({ row }) => <Badge tone={row.original.authMethod === 'none' ? 'success' : 'info'}>{row.original.authMethod || '-'}</Badge>,
    },
    {
      header: '账号',
      accessorKey: 'username',
      cell: ({ row }) => <span className="font-mono text-sm">{row.original.username || '-'}</span>,
    },
    {
      header: '密码',
      accessorKey: 'password',
      cell: ({ row }) => <span className="font-mono text-sm">{row.original.password || '-'}</span>,
    },
    {
      header: 'RTSP 地址',
      accessorKey: 'rtspUrl',
      cell: ({ row }) => {
        const rtspUrl = getRTSPResultUrl(row.original)
        return <span className="block max-w-[420px] truncate font-mono text-xs text-muted" title={rtspUrl}>{rtspUrl || '-'}</span>
      },
    },
    {
      header: '时间',
      accessorKey: 'createdAt',
      cell: ({ row }) => <span className="font-mono text-sm">{formatTime(row.original.createdAt)}</span>,
    },
    {
      header: '操作',
      cell: ({ row }) => (
        <Button size="sm" variant="outline" onClick={() => copyText(getRTSPResultUrl(row.original))}>
          <Copy className="size-4" />
          复制
        </Button>
      ),
      meta: { align: 'right' },
    },
  ]

  const targetCount = parseTargets(targetsText).length
  const progress = Number(taskState?.progress || 0)

  const handleTargetFileChange = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    try {
      const content = await readFileText(file)
      const normalized = String(content || '').replace(/\r\n/g, '\n').trim()
      if (!normalized) {
        toast.error('文本文件中没有可用的扫描目标')
        return
      }
      setTargetsText(normalized)
      toast.success(`已读取 ${parseTargets(normalized).length} 个扫描目标`)
    } catch (error: any) {
      toast.error(error?.message || '读取文本文件失败')
    }
  }

  const startResize = React.useCallback((event: React.PointerEvent<HTMLDivElement>) => {
    event.preventDefault()
    const startX = event.clientX
    const startWidth = leftPanelWidth
    const handleMove = (moveEvent: PointerEvent) => {
      const nextWidth = clampPanelWidth(startWidth + (moveEvent.clientX - startX), 520, 1100)
      setLeftPanelWidth(nextWidth)
    }
    const handleUp = () => {
      window.removeEventListener('pointermove', handleMove)
      window.removeEventListener('pointerup', handleUp)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'
    window.addEventListener('pointermove', handleMove)
    window.addEventListener('pointerup', handleUp)
  }, [leftPanelWidth])

  return (
    <div className="grid gap-4">
      <PageTitle title="RTSP 扫描" description="使用路径、账号、密码字典对 RTSP 服务进行探测，命中结果会实时显示并保存到数据库。" />
      <div className="grid gap-4 md:grid-cols-4">
        <Metric label="扫描目标" value={compactNumber(targetCount)} icon={RadioTower} tone="info" badgeLabel="目标" />
        <Metric label="已完成" value={`${taskState?.completed || 0}/${taskState?.totalTargets || targetCount || 0}`} icon={Terminal} tone="neutral" badgeLabel="进度" />
        <Metric label="命中结果" value={compactNumber(results.length)} icon={Save} tone="success" badgeLabel="结果" />
        <Metric label="状态" value={taskState ? getRTSPStatusText(taskState.status) : '待开始'} icon={isRunning ? Loader2 : Play} tone={taskState ? getProgressTone(taskState.status) : 'neutral'} badgeLabel={authMethod} />
      </div>

      <div
        className="grid min-h-[620px] gap-4 xl:grid-cols-[minmax(320px,var(--rtsp-left-panel-width))_10px_minmax(0,1fr)] xl:gap-0"
        style={{ '--rtsp-left-panel-width': `${leftPanelWidth}px` } as React.CSSProperties}
      >
        <Card className="overflow-hidden">
          <CardHeader>
            <div>
              <CardTitle>扫描参数</CardTitle>
              <CardDescription>目标支持 IP、IP:端口、rtsp:// 地址；目标带端口时优先使用目标端口，下方端口只作为默认端口。</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="grid gap-4">
            <Field label="扫描目标">
              <div className="grid gap-2">
                <Textarea className="min-h-52 font-mono" value={targetsText} onChange={(event) => setTargetsText(event.target.value)} placeholder="192.168.1.10&#10;192.168.1.11:8554" />
                <div className="flex flex-wrap gap-2">
                  <Button type="button" variant="outline" onClick={() => targetFileRef.current?.click()}>
                    <Upload className="size-4" />
                    从文本读取
                  </Button>
                  <span className="text-xs text-muted">支持 `.txt` 等纯文本文件，每行一个目标。</span>
                </div>
              </div>
            </Field>
            <div className="grid gap-3 md:grid-cols-3">
              <Field label="端口">
                <Input type="text" inputMode="numeric" value={port} onChange={(event) => setPort(parseBoundedNumber(event.target.value, 554, 1, 65535))} />
              </Field>
              <Field label="线程">
                <Input type="text" inputMode="numeric" value={threadCount} onChange={(event) => setThreadCount(parseBoundedNumber(event.target.value, 5, 1, 200))} />
              </Field>
              <Field label="超时">
                <Input type="text" inputMode="numeric" value={timeout} onChange={(event) => setTimeoutValue(parseBoundedNumber(event.target.value, 3, 1, 30))} />
              </Field>
            </div>
            <Field label="认证方式">
              <Select value={authMethod} onChange={(event) => setAuthMethod(event.target.value)}>
                <option value="Digest">Digest</option>
                <option value="Basic">Basic</option>
                <option value="Both">Basic + Digest</option>
              </Select>
            </Field>
            <div className="grid gap-2 rounded-card border border-border bg-raised p-3">
              <div className="flex items-center justify-between text-sm">
                <span className={getProgressTextClass(taskState?.status || '')}>{taskState ? `${progress.toFixed(1)}%` : '0%'}</span>
                <span className="text-muted">{taskState?.taskId || '暂无任务'}</span>
              </div>
              <div className="h-2 overflow-hidden rounded-full bg-background">
                <div className={cn('h-full rounded-full transition-all', getProgressFillClass(taskState?.status || ''))} style={{ width: `${Math.min(progress, 100)}%` }} />
              </div>
            </div>
            <input ref={targetFileRef} type="file" accept=".txt,.csv,.list,.dic,text/plain" className="hidden" onChange={handleTargetFileChange} />
            <div className="flex flex-wrap gap-2">
              <Button variant="default" disabled={startMutation.isPending || isRunning} onClick={() => startMutation.mutate()}>
                {startMutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <Play className="size-4" />}
                开始
              </Button>
              <Button variant="danger" disabled={!taskId || !isRunning || stopMutation.isPending} onClick={() => stopMutation.mutate()}>
                {stopMutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <Square className="size-4" />}
                停止
              </Button>
              <Button variant="outline" disabled={!results.length} onClick={() => copyText(results.map((item) => getRTSPResultUrl(item)).filter(Boolean).join('\n'))}>
                <Copy className="size-4" />
                复制结果
              </Button>
            </div>
          </CardContent>
        </Card>

        <div
          role="separator"
          aria-orientation="vertical"
          className="hidden cursor-col-resize items-stretch justify-center px-1 xl:flex"
          onPointerDown={startResize}
          title="拖拽调整宽度"
        >
          <div className="w-px rounded-full bg-border transition-colors hover:bg-info/60" />
        </div>

        <div className="grid min-h-0 gap-4">
          <Card className="min-h-0 overflow-hidden">
            <CardHeader>
              <div>
                <CardTitle>实时控制台</CardTitle>
                <CardDescription>扫描日志会实时追加，切换页面后仍可继续接收。</CardDescription>
              </div>
              <Badge tone={isRunning ? 'info' : 'neutral'}>{taskState ? getRTSPStatusText(taskState.status) : '未启动'}</Badge>
            </CardHeader>
            <CardContent className="p-0">
              <div ref={consoleRef} className="h-72 overflow-auto bg-[#05070a] p-4 font-mono text-xs leading-6 text-emerald-200">
                {logs.length ? logs.map((log, index) => (
                  <div key={`${log.time}-${index}`} className={cn(log.level === 'ERROR' && 'text-red-300', log.level === 'WARN' && 'text-amber-300', log.level === 'SUCCESS' && !log.message.includes('爆破成功') && 'text-green-300', log.message.includes('爆破成功') && 'font-semibold text-red-400')}>
                    <span className="text-slate-500">[{formatTime(log.time)}]</span> [{log.level}] {log.message}
                  </div>
                )) : <div className="text-slate-500">等待 RTSP 扫描启动...</div>}
              </div>
            </CardContent>
          </Card>

          <DataTable columns={columns} data={results} searchPlaceholder="搜索 RTSP 地址、账号或路径" emptyTitle="暂无 RTSP 命中结果" paginationStorageKey="rtsp-scan-results" />
        </div>
      </div>
    </div>
  )
}

function getRTSPStatusText(status?: string) {
  const map: Record<string, string> = {
    running: '扫描中',
    completed: '已完成',
    stopped: '已停止',
    failed: '失败',
  }
  return map[status || ''] || status || '-'
}

function mergeRTSPResults(primary: RTSPScanResult[], secondary: RTSPScanResult[]) {
  const seen = new Set<string>()
  const merged: RTSPScanResult[] = []
  for (const item of [...primary, ...secondary]) {
    const key = String(item.id || `${item.taskId}:${getRTSPResultUrl(item)}`)
    if (seen.has(key)) continue
    seen.add(key)
    merged.push(item)
  }
  return merged
}

function getRTSPResultUrl(item: RTSPScanResult) {
  const row = item as RTSPScanResult & Record<string, any>
  const explicitUrl = row.rtspUrl || row.rtsp_url
  if (explicitUrl) return String(explicitUrl)

  const host = row.host || ''
  if (!host) return ''

  const port = row.port || 554
  const uri = String(row.uri || '/')
  const normalizedUri = uri.startsWith('/') ? uri : `/${uri}`
  const username = row.username || ''
  const password = row.password || ''
  const auth = username ? `${username}${password ? `:${password}` : ''}@` : ''
  return `rtsp://${auth}${host}:${port}${normalizedUri}`
}

async function copyText(value: string) {
  const text = String(value || '').trim()
  if (!text) {
    toast.error('没有可复制的内容')
    return
  }

  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text)
    } else {
      fallbackCopyText(text)
    }
    toast.success('已复制到剪贴板')
  } catch {
    try {
      fallbackCopyText(text)
      toast.success('已复制到剪贴板')
    } catch {
      toast.error('复制失败')
    }
  }
}

function fallbackCopyText(value: string) {
  const textarea = document.createElement('textarea')
  textarea.value = value
  textarea.setAttribute('readonly', 'readonly')
  textarea.style.position = 'fixed'
  textarea.style.left = '-9999px'
  textarea.style.top = '0'
  document.body.appendChild(textarea)
  textarea.focus()
  textarea.select()
  const copied = document.execCommand('copy')
  document.body.removeChild(textarea)
  if (!copied) throw new Error('copy command failed')
}

function parseBoundedNumber(value: string, fallback: number, min: number, max: number) {
  const digits = String(value || '').replace(/\D/g, '')
  const parsed = Number(digits || fallback)
  if (!Number.isFinite(parsed)) return fallback
  return Math.min(Math.max(parsed, min), max)
}
