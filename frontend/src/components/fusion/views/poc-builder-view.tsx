'use client'

import * as React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { Braces, ChevronDown, Copy, Download, Eye, Loader2, Play, Plus, Save, ShieldCheck, Square, Terminal, Trash2 } from 'lucide-react'

import { createPocFile, debugScanPOC, getPOCCategories, stopDebugScan } from '@/lib/api'
import { cn, parseTargets, unwrap } from '@/lib/utils'
import { Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Drawer, Field, Input, Select, Tabs, TabsContent, TabsList, TabsTrigger, Textarea } from '@/components/ui'
import { CodeEditor } from '@/components/code-editor'
import { downloadContent, PageTitle, SeverityBadge, ToggleField } from '@/components/fusion/shared'

export const samplePocTemplate = `id: custom-template
info:
  name: Custom Vulnerability Template
  author: HuanXiong
  severity: info
  tags: custom

http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
`

type PocBuilderMatcher = {
  type: string
  condition: string
  part: string
  name: string
  value: string
  negative: boolean
}

type PocBuilderRequest = {
  method: string
  path: string
  headers: string
  body: string
  useRawRequest: boolean
  rawRequest: string
  matchersCondition: string
  matchers: PocBuilderMatcher[]
}

type PocBuilderDraft = {
  category: string
  fileName: string
  id: string
  name: string
  author: string
  severity: string
  description: string
  reference: string
  tags: string
  classification: Record<string, string>
  requests: PocBuilderRequest[]
}

type DebugResultRow = {
  duration?: number
  info?: Record<string, any>
  matched_at?: string
  matchedAt?: string
  request?: string
  response?: string
  severity?: string
  status?: string
  target?: string
  template?: string
  templateID?: string
  templateId?: string
  [key: string]: any
}

const severityOptions = [
  { value: 'critical', label: '严重' },
  { value: 'high', label: '高危' },
  { value: 'medium', label: '中危' },
  { value: 'low', label: '低危' },
  { value: 'info', label: '信息' },
]

const matcherTypeOptions = [
  { value: 'dsl', label: 'DSL' },
  { value: 'word', label: 'Word' },
  { value: 'status', label: 'Status' },
  { value: 'regex', label: 'Regex' },
  { value: 'binary', label: 'Binary' },
  { value: 'size', label: 'Size' },
]

const classificationFields = [
  { key: 'cvss-metrics', placeholder: 'cvss-metrics，例如：CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', span: 'full' },
  { key: 'cvss-score', placeholder: 'cvss-score，例如：9.8' },
  { key: 'cve-id', placeholder: 'cve-id，例如：CVE-2023-3836' },
  { key: 'cwe-id', placeholder: 'cwe-id，例如：CWE-434' },
  { key: 'cpe', placeholder: 'cpe，例如：cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*' },
  { key: 'epss-score', placeholder: 'epss-score，例如：0.04304' },
  { key: 'epss-percentile', placeholder: 'epss-percentile，例如：0.91215' },
]

const POC_BUILDER_WIDTH_KEYS = {
  generate: 'fusionweb-poc-builder-generate-right-width',
  debug: 'fusionweb-poc-builder-debug-right-width',
}

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

function createDebugTaskId() {
  return `debug-scan-${Date.now()}-${Math.random().toString(16).slice(2)}`
}

function createTemplateSlug(value: string) {
  const slug = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
  return slug || `custom-template-${Date.now()}`
}

function ensureYamlFileName(value: string) {
  const trimmed = String(value || '').trim()
  if (!trimmed) return ''
  return /\.ya?ml$/i.test(trimmed) ? trimmed : `${trimmed}.yaml`
}

function getDefaultPocFileName(draft: PocBuilderDraft) {
  return ensureYamlFileName(draft.fileName || draft.id || createTemplateSlug(draft.name || 'custom-template'))
}

function getDefaultPocCategory(draft: PocBuilderDraft) {
  return draft.category.trim() || draft.tags.split(',').map((item) => item.trim()).find(Boolean) || 'custom'
}

function validatePocSaveTarget(category: string, fileName: string) {
  const folder = category.trim()
  const name = ensureYamlFileName(fileName)
  if (!folder) throw new Error('请填写指纹名称')
  if (!name) throw new Error('请填写文件名')
  if (/[\\/:*?"<>|]/.test(folder)) throw new Error('指纹名称不能包含路径或文件系统非法字符')
  if (/[\\/:*?"<>|]/.test(name)) throw new Error('文件名不能包含路径或文件系统非法字符')
  return { category: folder, fileName: name }
}

function yamlScalar(value: string) {
  const normalized = String(value ?? '').trim()
  if (!normalized) return '""'
  if (/^[a-zA-Z0-9_.:/@{}-]+$/.test(normalized)) return normalized
  return JSON.stringify(normalized)
}

function yamlIDScalar(value: string) {
  const normalized = String(value ?? '').trim().replace(/\r?\n/g, '-')
  return normalized || 'custom-template'
}

function yamlNameScalar(value: string) {
  const normalized = String(value ?? '').trim()
  if (!normalized) return '""'
  const unsafePlain = /[\r\n]/.test(normalized)
    || /:\s/.test(normalized)
    || /\s#/.test(normalized)
    || /^[\-[\]{}#&*!|>%@`,?:]/.test(normalized)
    || /^(true|false|null|~|yes|no|on|off)$/i.test(normalized)
  return unsafePlain ? JSON.stringify(normalized) : normalized
}

function pushYamlBlock(lines: string[], key: string, value: string, keyIndent = '  ', valueIndent = '    ') {
  const normalized = String(value ?? '').trim()
  if (!normalized) return
  lines.push(`${keyIndent}${key}: |`)
  normalized.split(/\r?\n/).forEach((line) => {
    lines.push(`${valueIndent}${line}`)
  })
}

function parseHeaderLines(value: string) {
  return value.split(/\r?\n/).reduce<Record<string, string>>((acc, line) => {
    const index = line.indexOf(':')
    if (index > 0) acc[line.slice(0, index).trim()] = line.slice(index + 1).trim()
    return acc
  }, {})
}

function createPocBuilderRequest(): PocBuilderRequest {
  return {
    method: 'GET',
    path: '/',
    headers: 'User-Agent: FusionWeb',
    body: '',
    useRawRequest: false,
    rawRequest: 'GET / HTTP/1.1\nHost: {{Hostname}}\nUser-Agent: FusionWeb\n\n',
    matchersCondition: 'and',
    matchers: [],
  }
}

function createDefaultDraft(): PocBuilderDraft {
  return {
    category: 'custom',
    fileName: 'custom-template.yaml',
    id: 'custom-template',
    name: '',
    author: 'HuanXiong',
    severity: 'info',
    description: '',
    reference: '',
    tags: 'custom',
    classification: {
      'cvss-metrics': '',
      'cvss-score': '',
      'cve-id': '',
      'cwe-id': '',
      cpe: '',
      'epss-score': '',
      'epss-percentile': '',
    },
    requests: [createPocBuilderRequest()],
  }
}

function buildVisualPocTemplate(draft: PocBuilderDraft) {
  const lines: string[] = []
  lines.push(`id: ${yamlIDScalar(draft.id || createTemplateSlug(draft.name || 'custom-template'))}`)
  lines.push('')
  lines.push('info:')
  lines.push(`  name: ${yamlNameScalar(draft.name || 'Custom Vulnerability Template')}`)
  lines.push(`  author: ${yamlScalar(draft.author || 'HuanXiong')}`)
  lines.push(`  severity: ${yamlScalar(draft.severity || 'info')}`)
  pushYamlBlock(lines, 'description', draft.description)
  const refs = draft.reference.length > 0 ? parseTargets(draft.reference) : []
  if (refs.length) {
    lines.push('  reference:')
    refs.forEach((item) => lines.push(`    - ${yamlScalar(item)}`))
  } else if (draft.reference.length > 0) {
    lines.push('  reference:')
    lines.push('    -')
  }
  const tags = draft.tags.split(',').map((item) => item.trim()).filter(Boolean)
  if (tags.length) lines.push(`  tags: ${tags.map(yamlScalar).join(',')}`)
  const classification = Object.entries(draft.classification || {}).filter(([, value]) => String(value || '').trim())
  if (classification.length) {
    lines.push('  classification:')
    classification.forEach(([key, value]) => lines.push(`    ${key}: ${yamlScalar(value)}`))
  }
  lines.push('')
  lines.push('http:')
  draft.requests.forEach((request) => {
    if (request.useRawRequest) {
      lines.push('  - raw:')
      lines.push('      - |')
      request.rawRequest.replace(/\r\n/g, '\n').split('\n').forEach((line) => lines.push(`        ${line}`))
    } else {
      lines.push('  - method: ' + yamlScalar(request.method || 'GET'))
      lines.push('    path:')
      lines.push(`      - "{{BaseURL}}${request.path.startsWith('/') ? request.path : `/${request.path || ''}`}"`)
      const headers = parseHeaderLines(request.headers)
      if (Object.keys(headers).length) {
        lines.push('    headers:')
        Object.entries(headers).forEach(([key, value]) => lines.push(`      ${key}: ${yamlScalar(value)}`))
      }
      if (request.body.trim()) {
        lines.push('    body: |')
        request.body.replace(/\r\n/g, '\n').split('\n').forEach((line) => lines.push(`      ${line}`))
      }
    }
    const matchers = request.matchers.filter((matcher) => matcher.value.trim())
    if (!matchers.length) return
    if (request.matchersCondition) lines.push(`    matchers-condition: ${request.matchersCondition}`)
    lines.push('    matchers:')
    matchers.forEach((matcher) => {
      lines.push(`      - type: ${matcher.type}`)
      if (matcher.name.trim()) lines.push(`        name: ${yamlNameScalar(matcher.name.trim())}`)
        if (matcher.type !== 'dsl' && matcher.negative) lines.push('        negative: true')
        if (matcher.type === 'status') {
          lines.push('        status:')
          matcher.value.split(/[,，\s]+/).map((item) => item.trim()).filter(Boolean).forEach((item) => lines.push(`          - ${Number(item) || item}`))
        } else if (matcher.type === 'dsl') {
          lines.push('        dsl:')
          matcher.value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean).forEach((item) => lines.push(`          - ${yamlScalar(item)}`))
        } else if (matcher.type === 'regex') {
          lines.push('        regex:')
          matcher.value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean).forEach((item) => lines.push(`          - ${yamlScalar(item)}`))
        } else if (matcher.type === 'binary') {
          lines.push('        binary:')
          matcher.value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean).forEach((item) => lines.push(`          - ${yamlScalar(item)}`))
        } else if (matcher.type === 'size') {
          lines.push('        size:')
          matcher.value.split(/[,，\s]+/).map((item) => item.trim()).filter(Boolean).forEach((item) => lines.push(`          - ${Number(item) || item}`))
        } else {
          lines.push('        words:')
          matcher.value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean).forEach((item) => lines.push(`          - ${yamlScalar(item)}`))
          if (matcher.condition === 'equals') lines.push('        condition: and')
        }
    })
  })
  return `${lines.join('\n')}\n`
}

function BuilderFormRow({ label, required, children, className }: { label: string; required?: boolean; children: React.ReactNode; className?: string }) {
  return (
    <div className={cn('grid gap-2 md:grid-cols-[96px_minmax(0,1fr)] md:items-start', className)}>
      <label className="pt-2 text-left text-sm font-medium text-muted md:text-right md:pr-3">
        {required ? <span className="text-danger-foreground">* </span> : null}{label}
      </label>
      <div className="min-w-0">{children}</div>
    </div>
  )
}

function getMatcherPlaceholder(type: string) {
  if (type === 'status') return '状态码可多行或逗号分隔，例如：200\n302'
  if (type === 'dsl') return 'DSL 表达式，每行一个，例如：status_code == 200'
  if (type === 'regex') return '正则表达式，每行一个'
  if (type === 'binary') return '二进制十六进制内容，每行一个，例如：504b0304'
  if (type === 'size') return '响应长度，可多行或逗号分隔，例如：1024\n2048'
  return '关键字可多行或逗号分隔，例如：admin'
}

function normalizeDebugResults(value: any): DebugResultRow[] {
  const data = unwrap<any>(value)
  if (Array.isArray(data)) return data
  if (Array.isArray(data?.results)) return data.results
  if (Array.isArray(data?.data)) return data.data
  return data && typeof data === 'object' ? [data] : []
}

function getDebugResultKey(row: DebugResultRow) {
  return [
    getDebugTarget(row),
    getDebugMatchedAt(row),
    getDebugTemplate(row),
    getDebugName(row),
    getDebugSeverity(row),
  ].join(' | ')
}

function mergeDebugResults(current: DebugResultRow[], next: DebugResultRow[]) {
  const rows = new Map<string, DebugResultRow>()
  current.forEach((row) => rows.set(getDebugResultKey(row), row))
  next.forEach((row) => rows.set(getDebugResultKey(row), row))
  return Array.from(rows.values())
}

function getDebugName(row: DebugResultRow) {
  return String(row.info?.name || row.name || row.template || row.templateID || row.templateId || '-')
}

function getDebugTarget(row: DebugResultRow) {
  return String(row.target || row.matched_at || row.matchedAt || row.url || '-')
}

function getDebugMatchedAt(row: DebugResultRow) {
  return String(row.matched_at || row.matchedAt || row.matched || row.target || '-')
}

function getDebugTemplate(row: DebugResultRow) {
  return String(row.template || row.templateID || row.templateId || '-')
}

function getDebugSeverity(row: DebugResultRow) {
  return String(row.severity || row.info?.severity || 'info')
}

function getStatusTone(status: string) {
  const value = status.toLowerCase()
  if (value.includes('matched') || value.includes('success')) return 'success'
  if (value.includes('fail') || value.includes('error')) return 'danger'
  return 'neutral'
}

async function copyText(value: string) {
  const content = String(value || '')
  if (!content) throw new Error('没有可复制的内容')
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(content)
      return
    } catch {
      // Fallback below handles browsers that block clipboard access.
    }
  }
  const textarea = document.createElement('textarea')
  textarea.value = content
  textarea.setAttribute('readonly', 'true')
  textarea.style.position = 'fixed'
  textarea.style.left = '-9999px'
  textarea.style.top = '0'
  document.body.appendChild(textarea)
  textarea.focus()
  textarea.select()
  try {
    const ok = document.execCommand('copy')
    if (!ok) throw new Error('复制失败')
  } finally {
    document.body.removeChild(textarea)
  }
}

function stringifyDebugResult(row: DebugResultRow) {
  try {
    return JSON.stringify(row, (_key, value) => {
      if (typeof value === 'bigint') return String(value)
      return value
    }, 2)
  } catch {
    return [
      `目标: ${getDebugTarget(row)}`,
      `命中位置: ${getDebugMatchedAt(row)}`,
      `漏洞名称: ${getDebugName(row)}`,
      `模板: ${getDebugTemplate(row)}`,
      `等级: ${getDebugSeverity(row)}`,
      row.request ? `请求包:\n${row.request}` : '',
      row.response ? `响应包:\n${row.response}` : '',
    ].filter(Boolean).join('\n\n')
  }
}

function PacketPreview({ title, value }: { title: string; value?: string }) {
  const content = String(value || '')
  if (!content.trim()) return null
  const handleCopy = async () => {
    try {
      await copyText(content)
      toast.success('已复制到剪贴板')
    } catch {
      toast.error('复制失败')
    }
  }

  return (
    <div className="grid gap-2">
      <div className="flex items-center justify-between gap-2">
        <div className="text-sm font-semibold text-foreground">{title}</div>
        <Button size="sm" variant="outline" onClick={handleCopy}><Copy className="size-4" />复制</Button>
      </div>
      <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-all rounded-card border border-border bg-background p-3 font-mono text-xs leading-5 text-foreground">
        {content}
      </pre>
    </div>
  )
}

function DebugResultDrawer({ detail, onOpenChange }: { detail: DebugResultRow | null; onOpenChange: (open: boolean) => void }) {
  const status = String(detail?.status || 'matched')
  return (
    <Drawer open={!!detail} onOpenChange={onOpenChange} title="调试结果详情" description={detail ? getDebugTarget(detail) : undefined} className="max-w-none md:w-[64vw]">
      {detail ? (
        <div className="grid gap-4">
          <div className="grid gap-3 rounded-card border border-border bg-panel p-4 text-sm">
            <div className="grid gap-2 md:grid-cols-[96px_minmax(0,1fr)]">
              <span className="text-muted">目标</span>
              <span className="break-all font-mono text-foreground">{getDebugTarget(detail)}</span>
            </div>
            <div className="grid gap-2 md:grid-cols-[96px_minmax(0,1fr)]">
              <span className="text-muted">命中位置</span>
              <span className="break-all font-mono text-foreground">{getDebugMatchedAt(detail)}</span>
            </div>
            <div className="grid gap-2 md:grid-cols-[96px_minmax(0,1fr)]">
              <span className="text-muted">漏洞名称</span>
              <span className="break-all text-foreground">{getDebugName(detail)}</span>
            </div>
            <div className="grid gap-2 md:grid-cols-[96px_minmax(0,1fr)]">
              <span className="text-muted">模板</span>
              <span className="break-all font-mono text-foreground">{getDebugTemplate(detail)}</span>
            </div>
            <div className="grid gap-2 md:grid-cols-[96px_minmax(0,1fr)] md:items-center">
              <span className="text-muted">等级</span>
              <SeverityBadge className="justify-self-start" severity={getDebugSeverity(detail)} />
            </div>
            <div className="grid gap-2 md:grid-cols-[96px_minmax(0,1fr)] md:items-center">
              <span className="text-muted">状态</span>
              <Badge className="justify-self-start" tone={getStatusTone(status) as any}>{status}</Badge>
            </div>
            <div className="grid gap-2 md:grid-cols-[96px_minmax(0,1fr)]">
              <span className="text-muted">耗时</span>
              <span className="text-foreground">{Number(detail.duration || 0)} ms</span>
            </div>
          </div>
          <PacketPreview title="请求包" value={detail.request} />
          <PacketPreview title="响应包" value={detail.response} />
        </div>
      ) : null}
    </Drawer>
  )
}

function DebugResultPanel({ rows, targets, running, progress }: { rows: DebugResultRow[]; targets: string; running: boolean; progress: number }) {
  const [detail, setDetail] = React.useState<DebugResultRow | null>(null)
  const targetCount = parseTargets(targets).length
  const matchedCount = rows.length
  const sentCount = Math.max(targetCount, rows.length)
  const progressValue = Number.isFinite(progress) ? Math.min(100, Math.max(0, Math.round(progress))) : (running ? 0 : (rows.length ? 100 : 0))

  const copyRow = async (row: DebugResultRow) => {
    try {
      await copyText(stringifyDebugResult(row))
      toast.success('已复制结果')
    } catch {
      toast.error('复制失败')
    }
  }

  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>调试结果</CardTitle>
          <CardDescription>命中后会立即追加到这里，不用等整轮扫描结束。</CardDescription>
        </div>
      </CardHeader>
      <CardContent className="grid gap-4">
        <div className="grid gap-3 sm:grid-cols-3">
          <div className="rounded-card border border-border bg-panel p-3">
            <div className="text-xs text-muted">扫描目标</div>
            <div className="mt-1 text-lg font-semibold text-foreground">{sentCount}</div>
          </div>
          <div className="rounded-card border border-border bg-panel p-3">
            <div className="text-xs text-muted">命中结果</div>
            <div className="mt-1 text-lg font-semibold text-success-foreground">{matchedCount}</div>
          </div>
          <div className="rounded-card border border-border bg-panel p-3">
            <div className="text-xs text-muted">进度</div>
            <div className="mt-1 flex items-center gap-2 text-lg font-semibold text-info-foreground">
              {running ? <Loader2 className="size-4 animate-spin" /> : null}
              {running ? `${progressValue}%` : rows.length ? '100%' : '-'}
            </div>
          </div>
        </div>

        {!rows.length && !running ? (
          <div className="rounded-card border border-dashed border-border bg-background p-4 text-sm text-muted">暂无调试结果。开始调试后，命中结果会实时追加到这里。</div>
        ) : null}
        {!rows.length && running ? (
          <div className="rounded-card border border-dashed border-info/40 bg-info/5 p-4 text-sm text-info-foreground">
            正在扫描中，命中结果会实时出现在这里。
          </div>
        ) : null}

        {rows.length ? (
          <div className="overflow-hidden rounded-card border border-border">
            <div className="grid grid-cols-[44px_minmax(150px,1fr)_96px] border-b border-border bg-raised px-3 py-2 text-xs font-semibold text-muted">
              <div>序号</div>
              <div>目标</div>
              <div className="text-right">操作</div>
            </div>
            <div className="max-h-56 overflow-auto">
              {rows.map((row, index) => {
                const active = detail === row
                return (
                  <div key={`${getDebugTarget(row)}-${index}`} className={cn('grid grid-cols-[44px_minmax(150px,1fr)_96px] items-center gap-0 border-b border-border px-3 py-2 text-sm last:border-b-0', active ? 'bg-info/10' : 'bg-card')}>
                    <div className="text-muted">{index + 1}</div>
                    <div className="min-w-0 truncate font-mono text-xs text-foreground" title={getDebugTarget(row)}>{getDebugTarget(row)}</div>
                    <div className="flex justify-end gap-1">
                      <Button size="sm" variant="ghost" onClick={() => setDetail(row)}><Eye className="size-4" />查看</Button>
                      <Button size="icon" variant="ghost" onClick={() => copyRow(row)}><Copy className="size-4" /></Button>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        ) : null}

        <DebugResultDrawer detail={detail} onOpenChange={(open) => !open && setDetail(null)} />
      </CardContent>
    </Card>
  )
}

export function PocBuilderView({ demoMode }: { demoMode: boolean }) {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = React.useState('generate')
  const [debugTargets, setDebugTargets] = React.useState('')
  const [debugResult, setDebugResult] = React.useState<DebugResultRow[]>([])
  const [debugProgress, setDebugProgress] = React.useState(0)
  const [debugStatus, setDebugStatus] = React.useState<'idle' | 'running' | 'completed' | 'failed' | 'stopped'>('idle')
  const [debugDirty, setDebugDirty] = React.useState(false)
  const [debugLogPackets, setDebugLogPackets] = React.useState(false)
  const [generateRightWidth, setGenerateRightWidth] = React.useState(() => loadStoredPanelWidth(POC_BUILDER_WIDTH_KEYS.generate, 520, 380, 820))
  const [debugRightWidth, setDebugRightWidth] = React.useState(() => loadStoredPanelWidth(POC_BUILDER_WIDTH_KEYS.debug, 520, 360, 760))
  const [classificationOpen, setClassificationOpen] = React.useState(false)
  const [draft, setDraft] = React.useState<PocBuilderDraft>(() => createDefaultDraft())
  const [saveDialogOpen, setSaveDialogOpen] = React.useState(false)
  const [saveTarget, setSaveTarget] = React.useState(() => ({ category: 'custom', fileName: 'custom-template.yaml' }))
  const [saveTemplateContent, setSaveTemplateContent] = React.useState('')
  const activeDebugTaskIdRef = React.useRef('')
  const debugStopRequestedRef = React.useRef(false)
  const template = React.useMemo(() => buildVisualPocTemplate(draft), [draft])
  const [debugTemplate, setDebugTemplate] = React.useState(template)
  const categoriesQuery = useQuery({
    queryKey: ['poc-categories'],
    queryFn: async () => demoMode ? ['custom'] : unwrap<string[]>(await getPOCCategories()),
  })
  const pocCategories = React.useMemo(() => Array.from(new Set((categoriesQuery.data || []).filter(Boolean))), [categoriesQuery.data])

  React.useEffect(() => {
    try {
      window.localStorage.setItem('fusionweb-poc-builder-draft', JSON.stringify(draft))
    } catch {
      // ignore local cache failures
    }
  }, [draft])

  React.useEffect(() => {
    if (!debugDirty) setDebugTemplate(template)
  }, [debugDirty, template])

  React.useEffect(() => {
    saveStoredPanelWidth(POC_BUILDER_WIDTH_KEYS.generate, generateRightWidth)
  }, [generateRightWidth])

  React.useEffect(() => {
    saveStoredPanelWidth(POC_BUILDER_WIDTH_KEYS.debug, debugRightWidth)
  }, [debugRightWidth])

  React.useEffect(() => {
    if (typeof window === 'undefined') return
    const handleRealtime = (event: Event) => {
      const detail = (event as CustomEvent<any>).detail
      if (String(detail?.type || '') !== 'debug-scan-progress') return

      const payload = detail?.data || {}
      const taskId = String(payload?.task_id || '').trim()
      const stage = String(payload?.type || '').trim()
      if (activeDebugTaskIdRef.current && taskId && taskId !== activeDebugTaskIdRef.current) return
      if (!activeDebugTaskIdRef.current && taskId) activeDebugTaskIdRef.current = taskId

      if (stage === 'started') {
        setDebugStatus('running')
        setDebugProgress(0)
        setDebugResult([])
        return
      }

      if (stage === 'progress') {
        if (debugStopRequestedRef.current) return
        const nextProgress = Number(payload?.data?.percentage ?? payload?.data?.progress ?? 0)
        if (Number.isFinite(nextProgress)) setDebugProgress(nextProgress)
        setDebugStatus('running')
        return
      }

      if (stage === 'vuln_found') {
        if (debugStopRequestedRef.current) return
        const rawRow = payload?.data || {}
        const nextRow: DebugResultRow = {
          ...rawRow,
          status: rawRow.status || 'matched',
          template: rawRow.template || rawRow.templateID || rawRow.templateId,
          matched_at: rawRow.matched_at || rawRow.matchedAt || rawRow.matched || rawRow.target,
        }
        setDebugResult((current) => mergeDebugResults(current, [nextRow]))
        const nextProgress = Number(payload?.data?.percentage ?? 0)
        if (Number.isFinite(nextProgress) && nextProgress > 0) setDebugProgress(nextProgress)
        setDebugStatus('running')
        return
      }

      if (stage === 'completed') {
        if (debugStopRequestedRef.current) return
        setDebugStatus('completed')
        setDebugProgress(100)
        return
      }

      if (stage === 'stopped') {
        setDebugStatus('stopped')
        return
      }

      if (stage === 'error') {
        setDebugStatus('failed')
      }
    }

    window.addEventListener('fusionweb-realtime', handleRealtime)
    return () => window.removeEventListener('fusionweb-realtime', handleRealtime)
  }, [])

  const patchDraft = (patch: Partial<PocBuilderDraft>) => setDraft((current) => ({ ...current, ...patch }))
  const patchClassification = (key: string, value: string) => setDraft((current) => ({
    ...current,
    classification: { ...current.classification, [key]: value },
  }))
  const updateRequest = (index: number, patch: Partial<PocBuilderRequest>) => {
    setDraft((current) => ({
      ...current,
      requests: current.requests.map((item, itemIndex) => itemIndex === index ? { ...item, ...patch } : item),
    }))
  }
  const updateMatcher = (requestIndex: number, matcherIndex: number, patch: Partial<PocBuilderMatcher>) => {
    setDraft((current) => ({
      ...current,
      requests: current.requests.map((request, itemIndex) => itemIndex === requestIndex ? {
        ...request,
        matchers: request.matchers.map((matcher, idx) => idx === matcherIndex ? { ...matcher, ...patch } : matcher),
      } : request),
    }))
  }
  const addRequest = () => setDraft((current) => ({ ...current, requests: [...current.requests, createPocBuilderRequest()] }))
  const removeRequest = (index: number) => setDraft((current) => ({ ...current, requests: current.requests.filter((_, itemIndex) => itemIndex !== index) }))
  const addMatcher = (requestIndex: number) => setDraft((current) => ({
    ...current,
    requests: current.requests.map((request, index) => index === requestIndex ? {
      ...request,
        matchers: [...request.matchers, { type: 'status', condition: 'equals', part: '', name: '', value: '', negative: false }],
    } : request),
  }))
  const removeMatcher = (requestIndex: number, matcherIndex: number) => setDraft((current) => ({
    ...current,
    requests: current.requests.map((request, index) => index === requestIndex ? {
      ...request,
      matchers: request.matchers.filter((_, idx) => idx !== matcherIndex),
    } : request),
  }))

  const startGenerateResize = React.useCallback((event: React.PointerEvent<HTMLDivElement>) => {
    event.preventDefault()
    const startX = event.clientX
    const startWidth = generateRightWidth
    const handleMove = (moveEvent: PointerEvent) => {
      const nextWidth = Math.min(820, Math.max(380, startWidth - (moveEvent.clientX - startX)))
      setGenerateRightWidth(nextWidth)
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
  }, [generateRightWidth])

  const startDebugResize = React.useCallback((event: React.PointerEvent<HTMLDivElement>) => {
    event.preventDefault()
    const startX = event.clientX
    const startWidth = debugRightWidth
    const handleMove = (moveEvent: PointerEvent) => {
      const nextWidth = Math.min(760, Math.max(360, startWidth - (moveEvent.clientX - startX)))
      setDebugRightWidth(nextWidth)
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
  }, [debugRightWidth])

  const sendToDebugTemplate = () => {
    setDebugDirty(true)
    setDebugTemplate(template)
    setActiveTab('debug')
    toast.success('已发送到调试模板')
  }
  const openSaveDialog = (content: string) => {
    setSaveTemplateContent(content)
    setSaveTarget({
      category: getDefaultPocCategory(draft),
      fileName: getDefaultPocFileName(draft),
    })
    setSaveDialogOpen(true)
  }
  const handleStopDebugScan = async () => {
    const taskId = activeDebugTaskIdRef.current
    if (!taskId) {
      toast.error('暂无可停止的调试任务')
      return
    }
    debugStopRequestedRef.current = true
    setDebugStatus('stopped')
    try {
      await stopDebugScan(taskId)
      toast.success('已发送停止指令')
    } catch (error: any) {
      toast.error(error.message || '停止失败')
    }
  }
  const saveMutation = useMutation({
    mutationFn: async (target: { category: string; fileName: string; content: string }) => {
      if (!draft.id.trim()) throw new Error('请填写 ID')
      const nextTarget = validatePocSaveTarget(target.category, target.fileName)
      if (demoMode) return null
      return createPocFile(nextTarget.category, nextTarget.fileName, target.content)
    },
    onSuccess: (_res, target) => {
      const nextTarget = validatePocSaveTarget(target.category, target.fileName)
      patchDraft(nextTarget)
      setSaveTarget(nextTarget)
      setSaveDialogOpen(false)
      toast.success('模板已保存')
      queryClient.invalidateQueries({ queryKey: ['pocs'] })
      queryClient.invalidateQueries({ queryKey: ['poc-categories'] })
    },
    onError: (error: any) => toast.error(error.message || '保存失败'),
  })
  const debugMutation = useMutation({
    mutationFn: async () => {
      const targets = parseTargets(debugTargets)
      if (!targets.length) throw new Error('请输入调试目标')
      if (!debugTemplate.trim()) throw new Error('请输入调试模板内容')
      if (demoMode) return { matched: true, results: targets.map((target) => ({ target, template: draft.id, severity: draft.severity, status: 'matched', info: { name: draft.name || draft.id, severity: draft.severity } })) }
      return debugScanPOC(debugTemplate, targets, undefined, true, debugLogPackets, activeDebugTaskIdRef.current)
    },
    onMutate: () => {
      activeDebugTaskIdRef.current = createDebugTaskId()
      debugStopRequestedRef.current = false
      setDebugStatus('running')
      setDebugProgress(0)
      setDebugResult([])
    },
    onSuccess: (res: any) => {
      setDebugResult((current) => mergeDebugResults(current, normalizeDebugResults(unwrap<any>(res))))
      if (debugStopRequestedRef.current) {
        setDebugStatus('stopped')
        return
      }
      setDebugStatus('completed')
      setDebugProgress(100)
      toast.success('调试完成')
    },
    onError: (error: any) => {
      setDebugStatus('failed')
      toast.error(error.message || '调试失败')
    },
  })

  return (
    <div className="flex min-h-0 flex-col gap-4 xl:h-full">
      <PageTitle title="模板生成" description="可视化生成模板：基础信息、多请求、匹配器、实时 YAML 和调试。" />
      <Tabs className="flex min-h-0 flex-1 flex-col" value={activeTab} onValueChange={setActiveTab}>
        <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 rounded-card border border-border bg-card p-1">
          <TabsList className="border-0 bg-transparent p-0">
            <TabsTrigger value="generate"><Braces className="size-4" />生成模板</TabsTrigger>
            <TabsTrigger value="debug"><Terminal className="size-4" />调试模板</TabsTrigger>
          </TabsList>
          {activeTab === 'generate' ? (
            <div className="flex flex-wrap items-center gap-2 pr-1">
              <Button size="sm" variant="outline" onClick={() => copyText(template).then(() => toast.success('已复制')).catch(() => toast.error('复制失败'))}><Copy className="size-4" />复制</Button>
              <Button size="sm" variant="outline" onClick={() => downloadContent(template, draft.fileName || `${draft.id}.yaml`, 'text/yaml')}><Download className="size-4" />下载</Button>
              <Button size="sm" variant="outline" onClick={sendToDebugTemplate}><ShieldCheck className="size-4" />发送</Button>
              <Button size="sm" variant="default" disabled={saveMutation.isPending} onClick={() => openSaveDialog(template)}>
                {saveMutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <Save className="size-4" />}
                保存
              </Button>
            </div>
          ) : null}
        </div>
        <TabsContent value="generate" className="min-h-0 flex-1 xl:overflow-hidden">
          <div
            className="grid min-h-0 gap-4 xl:h-full xl:grid-cols-[minmax(0,1fr)_10px_minmax(380px,var(--generate-right-width))] xl:gap-0"
            style={{ '--generate-right-width': `${generateRightWidth}px` } as React.CSSProperties}
          >
            <div className="grid gap-4 xl:min-h-0 xl:overflow-y-auto xl:pr-2">
              <Card>
                <CardContent className="grid gap-5 p-5">
                  <div>
                    <span className="inline-flex h-8 items-center rounded-md border border-info/25 bg-info/10 px-3 text-sm font-medium text-info-foreground">基础信息</span>
                  </div>
                  <BuilderFormRow label="ID" required>
                    <Input value={draft.id} onChange={(event) => patchDraft({ id: event.target.value })} placeholder="唯一标识符，不能带中文字符" />
                  </BuilderFormRow>
                  <BuilderFormRow label="名称" required>
                    <Input value={draft.name} onChange={(event) => patchDraft({ name: event.target.value, id: draft.id || createTemplateSlug(event.target.value) })} placeholder="漏洞名称" />
                  </BuilderFormRow>
                  <div className="grid gap-4 lg:grid-cols-2">
                    <BuilderFormRow label="作者" required>
                      <Input value={draft.author} onChange={(event) => patchDraft({ author: event.target.value })} placeholder="作者名称" />
                    </BuilderFormRow>
                    <BuilderFormRow label="严重等级" required>
                      <Select value={draft.severity} onChange={(event) => patchDraft({ severity: event.target.value })}>
                        {severityOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
                      </Select>
                    </BuilderFormRow>
                  </div>
                  <BuilderFormRow label="描述">
                    <Textarea className="min-h-20" value={draft.description} onChange={(event) => patchDraft({ description: event.target.value })} placeholder="漏洞描述" />
                  </BuilderFormRow>
                  <BuilderFormRow label="参考">
                    <Textarea className="min-h-24" value={draft.reference} onChange={(event) => patchDraft({ reference: event.target.value })} placeholder="每行一个引用链接" />
                  </BuilderFormRow>
                  <BuilderFormRow label="标签">
                    <Input value={draft.tags} onChange={(event) => patchDraft({ tags: event.target.value })} placeholder="标签，使用英文逗号分隔" />
                  </BuilderFormRow>
                  <div className="grid gap-4 border-t border-border pt-4">
                    <div className="grid gap-2 md:grid-cols-[96px_minmax(0,1fr)] md:items-center">
                      <div className="text-left text-sm font-medium text-muted md:text-right md:pr-3">分类信息</div>
                      <button type="button" className="flex h-8 items-center gap-2 rounded-md text-left text-sm font-semibold text-foreground outline-none hover:text-info-foreground focus-visible:ring-2 focus-visible:ring-info/40" onClick={() => setClassificationOpen((open) => !open)} aria-expanded={classificationOpen}>
                        <ChevronDown className={cn('size-4 text-muted transition-transform', classificationOpen ? 'rotate-0' : '-rotate-90')} />
                        分类信息（可选）
                      </button>
                    </div>
                    {classificationOpen ? (
                    <div className="grid gap-3 md:pl-[108px]">
                      <div className="grid gap-3 lg:grid-cols-2">
                        <Input value={draft.category} onChange={(event) => patchDraft({ category: event.target.value })} placeholder="模板分类，例如：custom" />
                        <Input value={draft.fileName} onChange={(event) => patchDraft({ fileName: event.target.value })} placeholder="文件名称，例如：custom-template.yaml" />
                      </div>
                      <div className="grid gap-3 lg:grid-cols-2">
                        {classificationFields.map((field) => (
                          <Input
                            key={field.key}
                            className={field.span === 'full' ? 'lg:col-span-2' : undefined}
                            value={draft.classification[field.key] || ''}
                            onChange={(event) => patchClassification(field.key, event.target.value)}
                            placeholder={field.placeholder}
                          />
                        ))}
                      </div>
                    </div>
                    ) : null}
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <div>
                    <CardTitle>HTTP 请求</CardTitle>
                    <CardDescription>支持标准请求和 Raw 请求，每个请求可配置匹配器。</CardDescription>
                  </div>
                  <Button variant="default" onClick={addRequest}><Plus className="size-4" />添加请求</Button>
                </CardHeader>
                <CardContent className="grid gap-4">
                  {draft.requests.map((request, requestIndex) => (
                    <div key={requestIndex} className="grid gap-4 rounded-card border border-border bg-panel p-4">
                      <div className="flex items-center justify-between gap-3">
                        <div className="text-sm font-semibold">请求 {requestIndex + 1}</div>
                        <div className="flex gap-2">
                          <ToggleField label="Raw 请求" checked={request.useRawRequest} onChange={(value) => updateRequest(requestIndex, { useRawRequest: value })} />
                          <Button size="sm" variant="danger" disabled={draft.requests.length <= 1} onClick={() => removeRequest(requestIndex)}><Trash2 className="size-4" />删除</Button>
                        </div>
                      </div>
                      {request.useRawRequest ? (
                        <Field label="Raw 请求">
                          <Textarea className="min-h-52 font-mono" value={request.rawRequest} onChange={(event) => updateRequest(requestIndex, { rawRequest: event.target.value })} />
                        </Field>
                      ) : (
                        <div className="grid gap-4">
                          <div className="grid gap-4 md:grid-cols-[140px_1fr]">
                            <Field label="方法">
                              <Select value={request.method} onChange={(event) => updateRequest(requestIndex, { method: event.target.value })}>
                                {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map((method) => <option key={method} value={method}>{method}</option>)}
                              </Select>
                            </Field>
                            <Field label="路径"><Input value={request.path} onChange={(event) => updateRequest(requestIndex, { path: event.target.value })} placeholder="/api/v1/test" /></Field>
                          </div>
                          <Field label="请求头"><Textarea value={request.headers} onChange={(event) => updateRequest(requestIndex, { headers: event.target.value })} placeholder="Content-Type: application/json" /></Field>
                          <Field label="请求体"><Textarea value={request.body} onChange={(event) => updateRequest(requestIndex, { body: event.target.value })} /></Field>
                        </div>
                      )}
                      <div className="grid gap-3 rounded-card border border-info/20 bg-info/5 p-4">
                        <div className="text-sm font-semibold text-foreground">请求匹配器</div>
                        {request.matchers.map((matcher, matcherIndex) => (
                          <div key={matcherIndex} className="grid gap-3 border-b border-border/70 pb-4 last:border-b-0 last:pb-0">
                            <div className="flex flex-wrap items-center gap-3">
                              <Select className="w-56" value={matcher.type} onChange={(event) => updateMatcher(requestIndex, matcherIndex, { type: event.target.value, negative: event.target.value === 'dsl' ? false : matcher.negative })}>
                                {matcherTypeOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
                              </Select>
                              {matcher.type !== 'dsl' ? (
                                <ToggleField label="取反" checked={Boolean(matcher.negative)} onChange={(value) => updateMatcher(requestIndex, matcherIndex, { negative: value })} />
                              ) : null}
                              <Button size="sm" variant="danger" onClick={() => removeMatcher(requestIndex, matcherIndex)}><Trash2 className="size-4" />删除</Button>
                            </div>
                            {matcher.type === 'word' ? (
                              <div className="grid gap-2 md:grid-cols-[140px_minmax(0,1fr)]">
                                <Select value={matcher.condition} onChange={(event) => updateMatcher(requestIndex, matcherIndex, { condition: event.target.value })}>
                                  <option value="contains">包含</option>
                                  <option value="equals">等于</option>
                                </Select>
                                <Input value={matcher.name} onChange={(event) => updateMatcher(requestIndex, matcherIndex, { name: event.target.value })} placeholder="匹配器名称（可选）" />
                              </div>
                            ) : null}
                            {matcher.type === 'dsl' ? (
                              <Input value={matcher.name} onChange={(event) => updateMatcher(requestIndex, matcherIndex, { name: event.target.value })} placeholder="匹配器名称（可选）" />
                            ) : null}
                            <Textarea className="min-h-20" value={matcher.value} onChange={(event) => updateMatcher(requestIndex, matcherIndex, { value: event.target.value })} placeholder={getMatcherPlaceholder(matcher.type)} />
                          </div>
                        ))}
                        <div className="flex flex-wrap items-center gap-3 border-t border-border/70 pt-3">
                          <Select className="w-52" value={request.matchersCondition || 'and'} onChange={(event) => updateRequest(requestIndex, { matchersCondition: event.target.value })}> 
                            <option value="and">AND（所有条件需满足）</option>
                            <option value="or">OR（任一条件满足）</option>
                          </Select>
                          <Button size="sm" variant="default" onClick={() => addMatcher(requestIndex)}><Plus className="size-4" />添加匹配条件</Button>
                        </div>
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>
            </div>
            <div
              role="separator"
              aria-orientation="vertical"
              className="hidden cursor-col-resize items-stretch justify-center px-1 xl:flex"
              onPointerDown={startGenerateResize}
              title="拖拽调整宽度"
            >
              <div className="w-px rounded-full bg-border transition-colors hover:bg-info/60" />
            </div>
            <div className="min-h-0 xl:h-full xl:pl-4">
              <CodeEditor className="h-full min-h-0" value={template} onChange={() => undefined} minHeight={0} fixedHeight={false} readOnly />
            </div>
          </div>
        </TabsContent>
        <TabsContent value="debug" className="min-h-0 flex-1">
          <div
            className="grid min-h-0 gap-4 xl:h-full xl:grid-cols-[minmax(0,1fr)_10px_minmax(360px,var(--debug-right-width))] xl:gap-0"
            style={{ '--debug-right-width': `${debugRightWidth}px` } as React.CSSProperties}
          >
            <div className="min-h-0 xl:h-full">
              <CodeEditor className="h-full min-h-0" value={debugTemplate} onChange={(value) => { setDebugDirty(true); setDebugTemplate(value) }} minHeight={0} fixedHeight={false} />
            </div>
            <div
              role="separator"
              aria-orientation="vertical"
              className="hidden cursor-col-resize items-stretch justify-center px-1 xl:flex"
              onPointerDown={startDebugResize}
              title="拖拽调整宽度"
            >
              <div className="w-px rounded-full bg-border transition-colors hover:bg-info/60" />
            </div>
            <div className="grid gap-4 xl:min-h-0 xl:content-start xl:overflow-y-auto xl:pl-4 xl:pr-2">
              <Card>
                <CardHeader>
                  <div>
                    <CardTitle>调试目标</CardTitle>
                    <CardDescription>使用左侧正在编辑的 YAML 直接执行调试扫描。</CardDescription>
                  </div>
                </CardHeader>
                <CardContent className="grid gap-4">
                  <Textarea className="min-h-36" value={debugTargets} onChange={(event) => setDebugTargets(event.target.value)} placeholder="https://example.com" />
                  <div className="rounded-card border border-border bg-panel p-3">
                    <ToggleField label="命令行显示数据包" checked={debugLogPackets} onChange={setDebugLogPackets} />
                    <p className="mt-2 text-xs leading-5 text-muted">默认关闭。开启后，命中时会把请求包和响应包打印到命令行，前端详情始终可查看数据包。</p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Button className="h-10 rounded-lg px-4" variant="default" disabled={debugMutation.isPending || !debugTargets.trim()} onClick={() => debugMutation.mutate()}>
                      {debugMutation.isPending ? <Loader2 className="size-4 shrink-0 animate-spin" strokeWidth={1.8} /> : <Play className="size-4 shrink-0" strokeWidth={1.8} />}
                      开始
                    </Button>
                    <Button className="h-10 rounded-lg px-4" variant="outline" disabled={debugStatus !== 'running'} onClick={handleStopDebugScan}>
                      <Square className="size-4 shrink-0" strokeWidth={1.8} />
                      停止
                    </Button>
                    <Button className="h-10 rounded-lg px-4" variant="default" disabled={saveMutation.isPending || !debugTemplate.trim()} onClick={() => openSaveDialog(debugTemplate)}>
                      {saveMutation.isPending ? <Loader2 className="size-4 shrink-0 animate-spin" strokeWidth={1.8} /> : <Save className="size-4 shrink-0" strokeWidth={1.8} />}
                      保存
                    </Button>
                  </div>
                </CardContent>
              </Card>
              <DebugResultPanel rows={debugResult} targets={debugTargets} running={debugStatus === 'running'} progress={debugProgress} />
            </div>
          </div>
        </TabsContent>
      </Tabs>
      <Drawer
        open={saveDialogOpen}
        onOpenChange={setSaveDialogOpen}
        title="保存POC模板"
        description="指纹名称会作为分类文件夹，YAML 文件会保存到该文件夹中。"
        className="max-w-xl"
        footer={(
          <>
            <Button variant="outline" onClick={() => setSaveDialogOpen(false)}>取消</Button>
            <Button variant="default" disabled={saveMutation.isPending} onClick={() => saveMutation.mutate({ ...saveTarget, content: saveTemplateContent })}>
              {saveMutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <Save className="size-4" />}
              保存
            </Button>
          </>
        )}
      >
        <div className="grid gap-4">
          <Field label="指纹名称" hint="会创建或使用 data/pocs 下同名文件夹。">
            <Input
              list="poc-builder-save-categories"
              value={saveTarget.category}
              onChange={(event) => setSaveTarget((current) => ({ ...current, category: event.target.value }))}
              placeholder="选择或输入指纹名称"
            />
            <datalist id="poc-builder-save-categories">
              {pocCategories.map((category) => <option key={category} value={category} />)}
            </datalist>
          </Field>
          <Field label="文件名" hint="未填写 .yaml 后缀时会自动补全。">
            <Input
              value={saveTarget.fileName}
              onChange={(event) => setSaveTarget((current) => ({ ...current, fileName: event.target.value }))}
              placeholder="example.yaml"
            />
          </Field>
          <div className="rounded-card border border-border bg-panel p-3 text-sm text-muted">
            保存路径：
            <span className="font-mono text-foreground">data/pocs/{saveTarget.category.trim() || '指纹名称'}/{ensureYamlFileName(saveTarget.fileName) || '文件名.yaml'}</span>
          </div>
        </div>
      </Drawer>
    </div>
  )
}
