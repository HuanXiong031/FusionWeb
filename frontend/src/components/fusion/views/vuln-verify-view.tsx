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
  Copy,
  Database,
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
import { asList, cn, compactNumber, currentChinaTimeString, formatTime, getStatusLabel, getStatusTone, parseTargets, unwrap } from '@/lib/utils'
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

const VULN_VERIFY_RESPONSE_WIDTH_KEY = 'fusionweb-vuln-verify-response-panel-width'

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

export function VulnVerifyView({ demoMode }: { demoMode: boolean }) {
  const [verifyTabs, setVerifyTabs] = React.useState<RawVerifyTab[]>(() => [createRawVerifyTab(1, { id: 'raw-tab-1' })])
  const [activeTabId, setActiveTabId] = React.useState('raw-tab-1')
  const [tabsReady, setTabsReady] = React.useState(false)
  const demoGroups = [{ id: 1, name: '默认分组' }]
  const demoVulns = [
    {
      id: 1,
      name: 'Spring Actuator 暴露',
      group_id: 1,
      request: 'GET /actuator/env HTTP/1.1\nHost: example.com\nUser-Agent: FusionWeb\nAccept: */*\n\n',
      response: 'HTTP/1.1 200 OK',
    },
  ]
  const groupsQuery = useQuery({ queryKey: ['vuln-groups'], queryFn: getVulnVerifyGroups, enabled: !demoMode })
  const groups = demoMode ? demoGroups : asList<any>(groupsQuery.data)
  const currentGroupId = groups[0]?.id
  const vulnsQuery = useQuery({ queryKey: ['vuln-group-items', currentGroupId], queryFn: () => getManualVulnVerifyListByGroup(Number(currentGroupId)), enabled: !!currentGroupId && !demoMode })
  const vulns = demoMode
    ? demoVulns.filter((item) => Number(item.group_id) === Number(currentGroupId))
    : asList<any>(vulnsQuery.data)
  const workbenchQuery = useQuery({ queryKey: ['vuln-verify-workbench'], queryFn: getVulnVerifyWorkbench, enabled: !demoMode })
  const saveWorkbenchTimerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null)
  const activeTab = React.useMemo(
    () => verifyTabs.find((tab) => tab.id === activeTabId) || verifyTabs[0],
    [activeTabId, verifyTabs]
  )
  const rawResponseText = getRawTabResponseText(activeTab)

  React.useEffect(() => {
    if (tabsReady) return
    if (!demoMode && workbenchQuery.isLoading) return

    const remoteWorkbench = demoMode ? null : unwrap<any>(workbenchQuery.data)
    let nextTabs: RawVerifyTab[] | null = Array.isArray(remoteWorkbench?.tabs) && remoteWorkbench.tabs.length
      ? remoteWorkbench.tabs.map((item: any, index: number) => normalizeRawVerifyTab(item, index + 1)).slice(0, 12)
      : null
    let nextActiveTabId = typeof remoteWorkbench?.activeTabId === 'string' ? remoteWorkbench.activeTabId : ''

    if (!nextTabs) {
      const cached = loadRawVerifyWorkbenchFromStorage()
      nextTabs = cached.tabs
      nextActiveTabId = cached.activeTabId
    }

    setVerifyTabs(nextTabs)
    setActiveTabId(nextTabs.some((tab) => tab.id === nextActiveTabId) ? nextActiveTabId : nextTabs[0].id)
    setTabsReady(true)
  }, [demoMode, tabsReady, workbenchQuery.data, workbenchQuery.isLoading])

  React.useEffect(() => {
    if (!tabsReady) return
    const first = vulns[0]
    if (!first) return
    setVerifyTabs((current) => {
      const firstTab = current[0]
      if (!firstTab || firstTab.rawPacket) return current
      return current.map((tab, index) => index === 0 ? { ...tab, rawPacket: first.request || '', responseText: first.response || '' } : tab)
    })
  }, [tabsReady, vulns])

  React.useEffect(() => {
    if (!tabsReady) return
    const currentActiveTabId = activeTab?.id || activeTabId
    persistRawVerifyTabs(verifyTabs, currentActiveTabId)
    if (demoMode) return
    if (saveWorkbenchTimerRef.current) clearTimeout(saveWorkbenchTimerRef.current)
    saveWorkbenchTimerRef.current = setTimeout(() => {
      saveVulnVerifyWorkbench(buildRawVerifyWorkbenchPayload(verifyTabs, currentActiveTabId)).catch(() => undefined)
    }, 500)
    return () => {
      if (saveWorkbenchTimerRef.current) clearTimeout(saveWorkbenchTimerRef.current)
    }
  }, [activeTab?.id, activeTabId, demoMode, tabsReady, verifyTabs])

  React.useEffect(() => {
    if (verifyTabs.length && !verifyTabs.some((tab) => tab.id === activeTabId)) setActiveTabId(verifyTabs[0].id)
  }, [activeTabId, verifyTabs])

  const updateRawVerifyTab = React.useCallback((tabId: string, updater: (tab: RawVerifyTab) => RawVerifyTab) => {
    setVerifyTabs((current) => current.map((tab) => tab.id === tabId ? updater(tab) : tab))
  }, [])

  const updateActiveRawVerifyTab = React.useCallback((updater: (tab: RawVerifyTab) => RawVerifyTab) => {
    if (!activeTab) return
    updateRawVerifyTab(activeTab.id, updater)
  }, [activeTab, updateRawVerifyTab])

  const verifyMutation = useMutation({
    mutationFn: async () => {
      if (!activeTab) throw new Error('请先新建一个验证标签页')
      const request = activeTab.rawPacket
      if (demoMode) {
        return {
          tabId: activeTab.id,
          request,
          result: { raw_response: 'HTTP/1.1 200 OK\r\nServer: demo\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nDemo response' },
        }
      }
      const requestDraft = parseRawRequest(request, { forceHttps: activeTab.forceHttps })
      if (!requestDraft.url.trim()) throw new Error('请输入 URL，或粘贴包含 Host 的完整数据包')
      let headers: Record<string, string> = {}
      try {
        headers = requestDraft.headers.trim() ? JSON.parse(requestDraft.headers) : {}
      } catch {
        throw new Error('Headers 必须是 JSON 对象')
      }
      const res = await sendRawRequest({ method: requestDraft.method, url: requestDraft.url, headers, body: requestDraft.body, timeout: 30 })
      return { tabId: activeTab.id, request, result: unwrap<any>(res) }
    },
    onSuccess: (payload: any) => {
      const sentAt = currentChinaTimeString()
      const result = { ...payload.result, sent_at: sentAt }
      const responseText = formatRawResponse(result)
      const responseMeta = getRawResponseMeta(result, responseText)
      updateRawVerifyTab(payload.tabId, (tab) => ({
        ...tab,
        result,
        responseText,
        responseMeta,
        historyCursor: 0,
        historyItems: prependRawVerifyHistory(tab.historyItems, payload.request, responseText, responseMeta),
      }))
      toast.success('请求已发送')
    },
    onError: (error: any) => toast.error(error.message || '验证失败'),
  })

  const addVerifyTab = () => {
    const nextTab = createRawVerifyTab(getNextRawVerifyTabNumber(verifyTabs))
    setVerifyTabs((current) => [...current, nextTab])
    setActiveTabId(nextTab.id)
  }
  const closeVerifyTab = (tabId: string) => {
    if (verifyTabs.length <= 1) {
      updateRawVerifyTab(tabId, (tab) => ({
        ...tab,
        rawPacket: '',
        responseText: '',
        result: null,
        forceHttps: false,
        historyCursor: null,
        historyItems: [],
      }))
      return
    }
    const closingIndex = verifyTabs.findIndex((tab) => tab.id === tabId)
    const nextTabs = verifyTabs.filter((tab) => tab.id !== tabId)
    setVerifyTabs(nextTabs)
    if (tabId === activeTabId) {
      setActiveTabId(nextTabs[Math.max(0, closingIndex - 1)]?.id || nextTabs[0].id)
    }
  }
  const saveVerifyTabs = () => {
    const currentActiveTabId = activeTab?.id || activeTabId
    persistRawVerifyTabs(verifyTabs, currentActiveTabId)
    if (demoMode) {
      toast.success('当前标签已保存')
      return
    }
    saveVulnVerifyWorkbench(buildRawVerifyWorkbenchPayload(verifyTabs, currentActiveTabId))
      .then(() => toast.success('当前标签已保存到数据库'))
      .catch((error: any) => toast.error(error.message || '保存失败'))
  }
  const beautifyRequest = () => {
    updateActiveRawVerifyTab((tab) => ({ ...tab, rawPacket: beautifyRawPacket(tab.rawPacket), historyCursor: null }))
    toast.success('请求包已美化')
  }
  const beautifyResponse = () => {
    if (!rawResponseText.trim() || rawResponseText === '暂无响应') return
    const formatted = beautifyRawPacket(rawResponseText)
    updateActiveRawVerifyTab((tab) => ({ ...tab, responseText: formatted, result: null, responseMeta: getRawResponseMeta(null, formatted, tab.responseMeta) }))
    toast.success('响应包已美化')
  }
  const selectHistoryItem = (item: RawVerifyHistoryItem, index?: number) => {
    updateActiveRawVerifyTab((tab) => ({
      ...tab,
      rawPacket: item.request,
      responseText: item.response || '',
      result: null,
      responseMeta: item.meta || null,
      historyCursor: typeof index === 'number' ? index : Math.max(0, tab.historyItems.findIndex((entry) => entry.id === item.id)),
    }))
    toast.success('已切换历史数据包')
  }
  return (
    <div className="-m-4 min-h-[calc(100vh-44px)] bg-background p-4">
      <div className="h-[calc(100vh-76px)] min-h-[640px]">
        <RawVerifyWorkbench
          className="h-full"
          tabs={verifyTabs}
          activeTabId={activeTab?.id || activeTabId}
          rawPacket={activeTab?.rawPacket || ''}
          responseText={rawResponseText}
          result={activeTab?.result}
          responseMeta={activeTab?.responseMeta}
          historyCursor={activeTab?.historyCursor ?? null}
          sending={verifyMutation.isPending}
          forceHttps={Boolean(activeTab?.forceHttps)}
          historyItems={activeTab?.historyItems || []}
          onTabChange={setActiveTabId}
          onAddTab={addVerifyTab}
          onCloseTab={closeVerifyTab}
          onSaveTabs={saveVerifyTabs}
          onRawPacketChange={(value) => updateActiveRawVerifyTab((tab) => ({ ...tab, rawPacket: value, historyCursor: null }))}
          onResponseTextChange={(value) => updateActiveRawVerifyTab((tab) => ({ ...tab, responseText: value, result: null, responseMeta: getRawResponseMeta(null, value, tab.responseMeta) }))}
          onForceHttpsChange={(value) => updateActiveRawVerifyTab((tab) => ({ ...tab, forceHttps: value }))}
          onSend={() => verifyMutation.mutate()}
          onBeautifyRequest={beautifyRequest}
          onBeautifyResponse={beautifyResponse}
          onSelectHistory={selectHistoryItem}
        />
      </div>
    </div>
  )
}

type RawVerifyHistoryItem = {
  id: string
  request: string
  response: string
  createdAt: string
  meta?: RawVerifyResponseMeta | null
}

type RawVerifyResponseMeta = {
  bytes: number
  duration: number
  contentType: string
  status: string
  sentAt?: string
}

type RawVerifyTab = {
  id: string
  title: string
  rawPacket: string
  responseText: string
  result: any
  responseMeta?: RawVerifyResponseMeta | null
  historyCursor?: number | null
  forceHttps: boolean
  historyItems: RawVerifyHistoryItem[]
}

type RawVerifyWorkbenchProps = {
  className?: string
  tabs: RawVerifyTab[]
  activeTabId: string
  rawPacket: string
  responseText: string
  result: any
  responseMeta?: RawVerifyResponseMeta | null
  historyCursor?: number | null
  sending: boolean
  forceHttps: boolean
  historyItems: RawVerifyHistoryItem[]
  onTabChange: (id: string) => void
  onAddTab: () => void
  onCloseTab: (id: string) => void
  onSaveTabs: () => void
  onRawPacketChange: (value: string) => void
  onResponseTextChange: (value: string) => void
  onForceHttpsChange: (value: boolean) => void
  onSend: () => void
  onBeautifyRequest: () => void
  onBeautifyResponse: () => void
  onSelectHistory: (item: RawVerifyHistoryItem, index?: number) => void
}

function RawVerifyWorkbench({
  className,
  tabs,
  activeTabId,
  rawPacket,
  responseText,
  result,
  responseMeta,
  historyCursor,
  sending,
  forceHttps,
  historyItems,
  onTabChange,
  onAddTab,
  onCloseTab,
  onSaveTabs,
  onRawPacketChange,
  onResponseTextChange,
  onForceHttpsChange,
  onSend,
  onBeautifyRequest,
  onBeautifyResponse,
  onSelectHistory,
}: RawVerifyWorkbenchProps) {
  const [privacyMode, setPrivacyMode] = React.useState(false)
  const [historyOpen, setHistoryOpen] = React.useState(false)
  const [requestBeforeBeautify, setRequestBeforeBeautify] = React.useState<string | null>(null)
  const [responseBeforeBeautify, setResponseBeforeBeautify] = React.useState<string | null>(null)
  const [responsePanelWidth, setResponsePanelWidth] = React.useState(() => loadStoredPanelWidth(VULN_VERIFY_RESPONSE_WIDTH_KEY, 520, 320, 900))
  const meta = getRawResponseMeta(result, responseText, responseMeta)
  const displayPacket = React.useMemo(() => (privacyMode ? maskRawPacket(rawPacket) : rawPacket), [privacyMode, rawPacket])
  React.useEffect(() => {
    saveStoredPanelWidth(VULN_VERIFY_RESPONSE_WIDTH_KEY, responsePanelWidth)
  }, [responsePanelWidth])
  React.useEffect(() => {
    setRequestBeforeBeautify(null)
    setResponseBeforeBeautify(null)
  }, [activeTabId])
  React.useEffect(() => {
    if (requestBeforeBeautify === null) return
    const beautified = beautifyRawPacket(requestBeforeBeautify)
    if (rawPacket !== beautified && rawPacket !== requestBeforeBeautify) {
      setRequestBeforeBeautify(null)
    }
  }, [rawPacket, requestBeforeBeautify])
  React.useEffect(() => {
    if (responseBeforeBeautify === null) return
    const beautified = beautifyRawPacket(responseBeforeBeautify)
    if (responseText !== beautified && responseText !== responseBeforeBeautify) {
      setResponseBeforeBeautify(null)
    }
  }, [responseText, responseBeforeBeautify])
  const historyIndex = React.useMemo(() => {
    if (!historyItems.length) return -1
    return historyItems.findIndex((item) => item.request === rawPacket)
  }, [historyItems, rawPacket])
  const activeHistoryIndex = typeof historyCursor === 'number' && historyCursor >= 0 && historyCursor < historyItems.length
    ? historyCursor
    : historyIndex
  const goHistory = (direction: 'prev' | 'next') => {
    if (!historyItems.length) return
    const nextIndex = direction === 'prev'
      ? (activeHistoryIndex < 0 ? 0 : Math.min(historyItems.length - 1, activeHistoryIndex + 1))
      : Math.max(0, activeHistoryIndex - 1)
    const item = historyItems[nextIndex]
    if (item) onSelectHistory(item, nextIndex)
  }
  const canGoPrevHistory = historyItems.length > 0 && (activeHistoryIndex < 0 || activeHistoryIndex < historyItems.length - 1)
  const canGoNextHistory = activeHistoryIndex > 0
  const primaryButtonClass = 'border-info/35 bg-info/15 text-info-foreground hover:border-info/60 hover:bg-info/25'
  const activeButtonClass = 'border-info/50 bg-info/20 text-info-foreground hover:bg-info/30'
  const ghostButtonClass = 'border-border bg-raised text-foreground hover:bg-panel'
  const beautifiedButtonClass = 'border-info/55 bg-info/15 text-info-foreground shadow-sm ring-1 ring-info/25 hover:bg-info/25'
  const handleBeautifyRequest = () => {
    if (requestBeforeBeautify !== null) {
      onRawPacketChange(requestBeforeBeautify)
      setRequestBeforeBeautify(null)
      return
    }
    setRequestBeforeBeautify(rawPacket)
    onBeautifyRequest()
  }
  const handleBeautifyResponse = () => {
    if (responseBeforeBeautify !== null) {
      onResponseTextChange(responseBeforeBeautify)
      setResponseBeforeBeautify(null)
      return
    }
    if (!responseText.trim() || responseText === '暂无响应') return
    setResponseBeforeBeautify(responseText)
    onBeautifyResponse()
  }
  const handleRawPacketChange = (value: string) => {
    if (requestBeforeBeautify !== null) setRequestBeforeBeautify(null)
    onRawPacketChange(value)
  }
  const startPacketResize = React.useCallback((event: React.PointerEvent<HTMLDivElement>) => {
    event.preventDefault()
    const startX = event.clientX
    const startWidth = responsePanelWidth
    const handleMove = (moveEvent: PointerEvent) => {
      const nextWidth = Math.min(900, Math.max(320, startWidth - (moveEvent.clientX - startX)))
      setResponsePanelWidth(nextWidth)
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
  }, [responsePanelWidth])

  return (
    <div
      className={cn('flex h-full min-h-0 flex-col overflow-hidden rounded-card border border-border bg-card text-foreground shadow-sm', className)}
      onKeyDown={(event) => {
        if (event.altKey && event.key === 'Enter' && rawPacket.trim() && !sending) onSend()
      }}
    >
      <div className="flex min-h-9 items-end border-b border-border bg-panel px-2 pt-1 text-sm text-muted">
        <div className="flex min-w-0 flex-1 items-end overflow-x-auto">
          {tabs.map((tab) => {
            const active = tab.id === activeTabId
            return (
              <div
                key={tab.id}
                className={cn(
                  'flex h-8 min-w-12 items-center border-r border-border transition-colors',
                  active ? 'bg-card text-info-foreground shadow-sm' : 'bg-panel text-muted hover:bg-raised hover:text-foreground'
                )}
              >
                <button
                  type="button"
                  className="h-full min-w-10 px-4 text-left font-mono text-sm"
                  title={`标签 ${tab.title}`}
                  onClick={() => onTabChange(tab.id)}
                >
                  {tab.title}
                </button>
                {active ? (
                  <button
                    type="button"
                    className="mr-2 inline-flex size-5 items-center justify-center rounded text-muted hover:bg-raised hover:text-foreground"
                    title="关闭标签"
                    aria-label={`关闭标签 ${tab.title}`}
                    onClick={(event) => {
                      event.stopPropagation()
                      onCloseTab(tab.id)
                    }}
                  >
                    <X className="size-3.5" />
                  </button>
                ) : null}
              </div>
            )
          })}
        </div>
        <div className="flex shrink-0 items-end border-l border-border">
          <button
            type="button"
            className="inline-flex h-8 w-10 items-center justify-center bg-panel text-muted hover:bg-raised hover:text-foreground"
            title="保存当前标签"
            aria-label="保存当前标签"
            onClick={onSaveTabs}
          >
            <Save className="size-4" />
          </button>
          <button
            type="button"
            className="inline-flex h-8 w-10 items-center justify-center bg-panel text-muted hover:bg-raised hover:text-foreground"
            title="新建标签页"
            aria-label="新建标签页"
            onClick={onAddTab}
          >
            <Plus className="size-4" />
          </button>
        </div>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border bg-panel px-3 py-2">
        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            className={primaryButtonClass}
            disabled={!rawPacket.trim() || sending}
            onClick={onSend}
          >
            {sending ? <Loader2 className="size-4 animate-spin" /> : <Send className="size-4" />}
            发送 Alt+↵
          </Button>
          <label className={cn('inline-flex h-7 items-center gap-2 rounded-md border px-2 text-xs', ghostButtonClass)}>
            强制 HTTPS
            <input
              type="checkbox"
              checked={forceHttps}
              onChange={(event) => onForceHttpsChange(event.target.checked)}
              className="size-4 accent-info"
            />
          </label>
          <div className="relative">
            <Button size="sm" variant="ghost" className={ghostButtonClass} onClick={() => setHistoryOpen((value) => !value)}>
              <History className="size-4" />
              历史
            </Button>
            {historyOpen ? (
              <div className="absolute left-0 top-full z-30 mt-2 w-96 overflow-hidden rounded-card border border-border bg-card shadow-xl">
                <div className="border-b border-border px-3 py-2 text-xs font-semibold text-muted">历史发送数据包</div>
                <div className="max-h-80 overflow-y-auto p-1">
                  {historyItems.length ? historyItems.map((item, index) => (
                    <button
                      key={item.id}
                      type="button"
                      className="block w-full rounded-md px-3 py-2 text-left hover:bg-panel"
                      onClick={() => {
                        onSelectHistory(item, index)
                        setHistoryOpen(false)
                      }}
                    >
                      <div className="truncate text-sm font-medium text-foreground">{getRawHistoryTitle(item.request)}</div>
                      <div className="mt-0.5 text-xs text-muted">
                        {formatRawHistoryTime(item.createdAt)}
                      </div>
                    </button>
                  )) : (
                    <div className="px-3 py-6 text-center text-sm text-muted">暂无历史数据包</div>
                  )}
                </div>
              </div>
            ) : null}
          </div>
        </div>
      </div>
      <div className="min-h-0 min-w-0 flex-1 overflow-hidden">
        <div
          className="grid h-full min-h-0 min-w-0 bg-border md:grid-cols-[minmax(0,1fr)_10px_minmax(320px,var(--response-panel-width))]"
          style={{ '--response-panel-width': `${responsePanelWidth}px` } as React.CSSProperties}
        >
          <div className="flex min-h-0 min-w-0 flex-col bg-[#2b2f34]">
            <PacketPanelHeader title="请求包">
              <div className="flex items-center gap-1">
                <Button
                  size="sm"
                  variant="ghost"
                  className={cn('h-6 w-7 px-0 text-xs', ghostButtonClass)}
                  disabled={!canGoPrevHistory}
                  title="上一条历史数据包"
                  onClick={() => goHistory('prev')}
                >
                  &lt;
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  className={cn('h-6 w-7 px-0 text-xs', ghostButtonClass)}
                  disabled={!canGoNextHistory}
                  title="下一条历史数据包"
                  onClick={() => goHistory('next')}
                >
                  &gt;
                </Button>
              </div>
              <Button
                size="sm"
                variant="ghost"
                className={cn('h-6 px-2 text-xs', privacyMode ? activeButtonClass : ghostButtonClass)}
                onClick={() => setPrivacyMode((value) => !value)}
              >
                隐私模式
              </Button>
              <Button
                size="sm"
                variant="ghost"
                className={cn('h-6 px-2 text-xs transition-all', requestBeforeBeautify !== null ? beautifiedButtonClass : ghostButtonClass)}
                onClick={handleBeautifyRequest}
              >
                美化
              </Button>
            </PacketPanelHeader>
            <div className="min-h-0 flex-1 p-0">
              <CodeEditor
                key={privacyMode ? 'privacy' : 'editable'}
                className="h-full rounded-none border-0"
                value={displayPacket}
                onChange={privacyMode ? () => undefined : handleRawPacketChange}
                minHeight={0}
                fixedHeight={false}
                readOnly={privacyMode}
                placeholder={'GET /path HTTP/1.1\nHost: example.com\nUser-Agent: FusionWeb\nAccept: */*\n\nbody'}
              />
            </div>
          </div>
          <div
            role="separator"
            aria-orientation="vertical"
            className="hidden cursor-col-resize items-stretch justify-center bg-border px-1 md:flex"
            onPointerDown={startPacketResize}
            title="拖拽调整宽度"
          >
            <div className="w-px rounded-full bg-border transition-colors hover:bg-info/60" />
          </div>
          <div className="flex min-h-0 min-w-0 flex-col bg-[#2b2f34]">
            <PacketPanelHeader
              title={
                <div className="flex min-w-0 items-center gap-2">
                  <ResponseMetaBadge bytes={meta.bytes} duration={meta.duration} />
                </div>
              }
            >
              <Button
                size="sm"
                className={cn('h-6 px-2 text-xs transition-all', responseBeforeBeautify !== null ? beautifiedButtonClass : ghostButtonClass)}
                onClick={handleBeautifyResponse}
              >
                美化
              </Button>
            </PacketPanelHeader>
            <PacketCodeViewer value={responseText} heightClass="h-full min-h-0 flex-1" />
          </div>
        </div>
      </div>
    </div>
  )
}

function PacketPanelHeader({ title, children }: { title: React.ReactNode; children?: React.ReactNode }) {
  return (
    <div className="flex min-h-10 min-w-0 flex-wrap items-center justify-between gap-2 border-b border-border bg-panel px-3 py-2">
      <div className="min-w-0 text-sm font-semibold text-foreground">{title}</div>
      <div className="flex shrink-0 items-center gap-1.5">{children}</div>
    </div>
  )
}

function ResponseMetaBadge({ bytes, duration }: { bytes: number; duration: number }) {
  return (
    <span className="inline-flex h-7 items-center rounded border border-border bg-raised px-2 font-mono text-sm font-semibold text-foreground">
      {bytes}bytes / {duration}ms
    </span>
  )
}

function PacketCodeViewer({ value, heightClass = 'h-[520px]' }: { value: string; heightClass?: string }) {
  const lines = React.useMemo(() => (value || '').replace(/\r\n/g, '\n').split('\n'), [value])
  const numberWidth = Math.max(2, String(lines.length).length)

  return (
    <div
      className={cn(heightClass, 'overflow-y-auto overflow-x-hidden bg-[#2b2f34] py-3 text-[13px] font-normal leading-6 text-[#b9c4d3] selection:bg-[#2f5fb8] selection:text-white [&_*::selection]:bg-[#2f5fb8] [&_*::selection]:text-white')}
      style={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace' }}
    >
      {lines.map((line, index) => (
        <div key={index} className="grid min-h-6 min-w-0 grid-cols-[auto_minmax(0,1fr)] px-4">
          <span className="select-none pr-5 text-right text-[#758194]" style={{ minWidth: `${numberWidth}ch` }}>
            {index + 1}
          </span>
          <span className="min-w-0 whitespace-pre-wrap break-all font-normal [overflow-wrap:anywhere]">{renderPacketLine(line)}</span>
        </div>
      ))}
    </div>
  )
}

function renderPacketLine(line: string) {
  if (!line) return ' '
  const headerIndex = line.indexOf(':')
  if (/^HTTP\/\d(?:\.\d)?\s+\d+/.test(line.trim())) {
    return <span className="text-[#d8dee9]">{renderPacketText(line)}</span>
  }
  if (headerIndex > 0 && headerIndex < 80 && !line.trim().startsWith('<')) {
    return (
      <>
        <span className="text-[#ff6b75]">{line.slice(0, headerIndex)}</span>
        <span className="text-[#7b8494]">:</span>
        <span className="text-[#cbd5e1]">{renderPacketText(line.slice(headerIndex + 1))}</span>
      </>
    )
  }
  if (line.trim().startsWith('<') || line.trim().startsWith('</')) return <span className="text-[#ff8a2a]">{renderPacketText(line)}</span>
  return <span>{renderPacketText(line)}</span>
}

function renderPacketText(value: string) {
  if (!value.includes('[隐私模式]')) return value
  return value.split(/(\[隐私模式\])/g).map((part, index) => (
    part === '[隐私模式]' ? (
      <span key={index} className="mx-1 inline-flex rounded bg-muted/30 px-1.5 py-0.5 text-xs font-semibold text-foreground">隐私模式</span>
    ) : part
  ))
}

function createRawVerifyTab(index: number, overrides: Partial<RawVerifyTab> = {}): RawVerifyTab {
  return {
    id: overrides.id || `raw-tab-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    title: overrides.title || String(index),
    rawPacket: overrides.rawPacket || '',
    responseText: overrides.responseText || '',
    result: overrides.result || null,
    responseMeta: overrides.responseMeta || null,
    forceHttps: Boolean(overrides.forceHttps),
    historyCursor: typeof overrides.historyCursor === 'number' ? overrides.historyCursor : null,
    historyItems: Array.isArray(overrides.historyItems) ? overrides.historyItems.slice(0, 20) : [],
  }
}

function normalizeRawVerifyResponseMeta(value: any): RawVerifyResponseMeta | null {
  if (!value || typeof value !== 'object') return null
  return {
    bytes: Number(value.bytes || 0) || 0,
    duration: Number(value.duration || 0) || 0,
    contentType: typeof value.contentType === 'string' ? value.contentType : '',
    status: typeof value.status === 'string' ? value.status : value.status == null ? '' : String(value.status),
    sentAt: typeof value.sentAt === 'string' ? value.sentAt : typeof value.sent_at === 'string' ? value.sent_at : undefined,
  }
}

function normalizeRawVerifyHistoryItem(value: any): RawVerifyHistoryItem {
  return {
    id: typeof value?.id === 'string' && value.id ? value.id : `${Date.now()}-${Math.random().toString(16).slice(2)}`,
    request: typeof value?.request === 'string' ? value.request : '',
    response: typeof value?.response === 'string' ? value.response : '',
    createdAt: typeof value?.createdAt === 'string' ? value.createdAt : currentChinaTimeString(),
    meta: normalizeRawVerifyResponseMeta(value?.meta),
  }
}

function normalizeRawVerifyTab(value: any, index: number): RawVerifyTab {
  return createRawVerifyTab(index, {
    id: typeof value?.id === 'string' && value.id ? value.id : undefined,
    title: typeof value?.title === 'string' && value.title ? value.title : String(index),
    rawPacket: typeof value?.rawPacket === 'string' ? value.rawPacket : '',
    responseText: typeof value?.responseText === 'string' ? value.responseText : '',
    responseMeta: normalizeRawVerifyResponseMeta(value?.responseMeta),
    forceHttps: Boolean(value?.forceHttps),
    historyCursor: typeof value?.historyCursor === 'number' ? value.historyCursor : null,
    historyItems: Array.isArray(value?.historyItems) ? value.historyItems.map(normalizeRawVerifyHistoryItem) : [],
  })
}

function getNextRawVerifyTabNumber(tabs: RawVerifyTab[]) {
  const used = new Set(tabs.map((tab) => Number(tab.title)).filter((value) => Number.isFinite(value) && value > 0))
  let next = 1
  while (used.has(next)) next += 1
  return next
}

function getRawTabResponseText(tab?: RawVerifyTab) {
  if (!tab) return '暂无响应'
  return tab.responseText || (tab.result ? formatRawResponse(tab.result) : '暂无响应')
}

function prependRawVerifyHistory(historyItems: RawVerifyHistoryItem[], request: string, response: string, meta?: RawVerifyResponseMeta | null) {
  if (!request.trim()) return historyItems
  const createdAt = meta?.sentAt || currentChinaTimeString()
  const item: RawVerifyHistoryItem = {
    id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
    request,
    response,
    createdAt,
    meta: meta || null,
  }
  return [item, ...(historyItems || []).filter((entry) => entry.request !== request)].slice(0, 20)
}

function loadRawVerifyWorkbenchFromStorage() {
  if (typeof window === 'undefined') {
    return { tabs: [createRawVerifyTab(1, { id: 'raw-tab-1' })], activeTabId: 'raw-tab-1' }
  }
  let nextTabs: RawVerifyTab[] | null = null
  try {
    const cachedTabs = JSON.parse(window.localStorage.getItem('fusionweb-vuln-verify-tabs') || '[]')
    if (Array.isArray(cachedTabs) && cachedTabs.length) {
      nextTabs = cachedTabs.map((item, index) => normalizeRawVerifyTab(item, index + 1)).slice(0, 12)
    }
  } catch {
    nextTabs = null
  }
  if (!nextTabs) {
    let cachedHistory: RawVerifyHistoryItem[] = []
    try {
      const parsedHistory = JSON.parse(window.localStorage.getItem('fusionweb-vuln-verify-history') || '[]')
      if (Array.isArray(parsedHistory)) cachedHistory = parsedHistory.map(normalizeRawVerifyHistoryItem).slice(0, 20)
    } catch {
      cachedHistory = []
    }
    nextTabs = [
      createRawVerifyTab(1, {
        id: 'raw-tab-1',
        rawPacket: window.localStorage.getItem('fusionweb-vuln-verify-last-request') || '',
        responseText: window.localStorage.getItem('fusionweb-vuln-verify-last-response') || '',
        historyItems: cachedHistory,
      }),
    ]
  }
  const cachedActiveTabId = window.localStorage.getItem('fusionweb-vuln-verify-active-tab') || ''
  return {
    tabs: nextTabs,
    activeTabId: nextTabs.some((tab) => tab.id === cachedActiveTabId) ? cachedActiveTabId : nextTabs[0].id,
  }
}

function buildRawVerifyWorkbenchPayload(tabs: RawVerifyTab[], activeTabId: string) {
  return {
    activeTabId,
    tabs: tabs.map((tab) => ({
      id: tab.id,
      title: tab.title,
      rawPacket: tab.rawPacket,
      responseText: getRawTabResponseText(tab),
      responseMeta: tab.responseMeta || null,
      forceHttps: tab.forceHttps,
      historyCursor: typeof tab.historyCursor === 'number' ? tab.historyCursor : null,
      historyItems: tab.historyItems,
    })),
  }
}

function persistRawVerifyTabs(tabs: RawVerifyTab[], activeTabId: string) {
  if (typeof window === 'undefined') return
  const payload = buildRawVerifyWorkbenchPayload(tabs, activeTabId)
  window.localStorage.setItem('fusionweb-vuln-verify-tabs', JSON.stringify(payload.tabs))
  window.localStorage.setItem('fusionweb-vuln-verify-active-tab', activeTabId)
  const activeTab = tabs.find((tab) => tab.id === activeTabId) || tabs[0]
  if (activeTab) {
    window.localStorage.setItem('fusionweb-vuln-verify-last-request', activeTab.rawPacket)
    const responseText = getRawTabResponseText(activeTab)
    if (responseText && responseText !== '暂无响应') {
      window.localStorage.setItem('fusionweb-vuln-verify-last-response', responseText)
    }
    window.localStorage.setItem('fusionweb-vuln-verify-history', JSON.stringify(activeTab.historyItems || []))
  }
}

function beautifyRawPacket(raw: string) {
  const normalized = String(raw || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n')
  const separatorMatch = normalized.match(/\n\s*\n/)
  const head = separatorMatch ? normalized.slice(0, separatorMatch.index) : normalized
  const bodyStart = separatorMatch ? (separatorMatch.index || 0) + separatorMatch[0].length : -1
  let body = bodyStart >= 0 ? normalized.slice(bodyStart) : ''
  const headLines = head
    .split('\n')
    .map((line) => line.trimEnd())
    .filter((line, index) => index === 0 || line.trim())
    .map((line, index) => {
      if (index === 0) return line.trim()
      const headerIndex = line.indexOf(':')
      if (headerIndex <= 0) return line.trim()
      return `${line.slice(0, headerIndex).trim()}: ${line.slice(headerIndex + 1).trim()}`
    })

  const trimmedBody = body.trim()
  if (/^[\[{]/.test(trimmedBody)) {
    try {
      body = JSON.stringify(JSON.parse(trimmedBody), null, 2)
    } catch {
      body = body.replace(/[ \t]+$/gm, '')
    }
  } else {
    body = body.replace(/[ \t]+$/gm, '')
  }

  const nextHeadLines = headLines.map((line) => {
    if (!/^content-length\s*:/i.test(line)) return line
    return `Content-Length: ${getByteSize(body)}`
  })

  return `${nextHeadLines.join('\n')}\n\n${body}`.trimEnd()
}

function maskRawPacket(raw: string) {
  return String(raw || '')
    .replace(/\r\n/g, '\n')
    .split('\n')
    .map((line) => {
      const hostMatch = line.match(/^(\s*host\s*:\s*)(.+)$/i)
      if (hostMatch) return `${hostMatch[1]}${maskHostValue(hostMatch[2])}`
      return line.replace(/(https?:\/\/)([^/\s:]+)(:\d+)?/gi, (_match, scheme, _host, port = '') => `${scheme}[隐私模式]${port}`)
    })
    .join('\n')
}

function maskHostValue(value: string) {
  const trimmed = String(value || '').trim()
  if (!trimmed) return '[隐私模式]'
  const withoutScheme = trimmed.replace(/^https?:\/\//i, '')
  const authority = withoutScheme.split(/[/?#]/)[0] || withoutScheme
  const portMatch = authority.match(/:(\d+)$/)
  return `[隐私模式]${portMatch ? `:${portMatch[1]}` : ''}`
}

function getRawHistoryTitle(raw: string) {
  try {
    const request = parseRawRequest(raw)
    const url = request.url ? new URL(request.url) : null
    if (url) return `${request.method} ${url.host}${url.pathname}`
  } catch {
    // Fall through to the raw first line.
  }
  return String(raw || '').split(/\r?\n/)[0] || '未命名请求包'
}

function formatRawHistoryTime(value: string) {
  const formatted = formatTime(value)
  return formatted === '-' ? '' : formatted
}

function parseRawRequest(raw: string, options?: { forceHttps?: boolean }) {
  const normalized = raw.replace(/\r\n/g, '\n')
  const separatorIndex = normalized.indexOf('\n\n')
  const head = separatorIndex >= 0 ? normalized.slice(0, separatorIndex) : normalized
  const body = separatorIndex >= 0 ? normalized.slice(separatorIndex + 2) : ''
  const lines = head.split(/\r?\n/).filter(Boolean)
  const requestLine = lines[0] || ''
  const [lineMethod = 'GET', linePath = ''] = requestLine.startsWith(':') ? [] : requestLine.split(/\s+/)
  let method = lineMethod || 'GET'
  let path = linePath || ''
  const headers: Record<string, string> = {}
  const pseudoHeaders: Record<string, string> = {}
  const headerLines = requestLine.startsWith(':') ? lines : lines.slice(1)
  for (const line of headerLines) {
    const pseudoMatch = line.match(/^:([^:]+):\s*(.*)$/)
    if (pseudoMatch) {
      pseudoHeaders[`:${pseudoMatch[1]}`] = pseudoMatch[2].trim()
      continue
    }
    const index = line.indexOf(':')
    if (index > -1) {
      const key = line.slice(0, index).trim()
      const value = line.slice(index + 1).trim()
      headers[key] = headers[key] ? `${headers[key]}, ${value}` : value
    }
  }
  method = pseudoHeaders[':method'] || method
  path = pseudoHeaders[':path'] || path
  const host = headers.Host || headers.host || pseudoHeaders[':authority'] || ''
  const scheme = pseudoHeaders[':scheme'] || (options?.forceHttps ? 'https' : 'http')
  let url = path.startsWith('http') ? path : host ? `${scheme}://${host}${path.startsWith('/') ? path : `/${path}`}` : ''
  if (options?.forceHttps && url.startsWith('http://')) url = `https://${url.slice('http://'.length)}`
  return {
    method: method || 'GET',
    url,
    headers: JSON.stringify(headers, null, 2),
    body,
  }
}

function formatRawResponse(result: any) {
  if (!result) return '暂无响应'
  if (result.raw_response || result.rawResponse) return String(result.raw_response || result.rawResponse)
  const statusLine = result.status || (result.status_code ? `HTTP/1.1 ${result.status_code}` : 'HTTP/1.1')
  const headers = result.headers && typeof result.headers === 'object'
    ? Object.entries(result.headers).map(([key, value]) => `${key}: ${value}`).join('\n')
    : ''
  const body = result.body == null ? '' : String(result.body)
  return [statusLine, headers, body].filter(Boolean).join('\n\n')
}

function getRawResponseMeta(result: any, responseText: string, fallback?: RawVerifyResponseMeta | null): RawVerifyResponseMeta {
  const headers = result?.headers && typeof result.headers === 'object' ? result.headers : {}
  const contentType = getHeaderValue(headers, 'content-type') || fallback?.contentType || ''
  const rawStatus = result?.status_code || result?.statusCode || String(responseText || '').match(/HTTP\/\d(?:\.\d)?\s+(\d+)/)?.[1] || fallback?.status
  const displayText = responseText === '暂无响应' ? '' : responseText
  const bytes = Number(result?.content_length ?? result?.contentLength ?? fallback?.bytes ?? 0) || getByteSize(displayText)
  const duration = Number(result?.duration ?? result?.response_time ?? result?.responseTime ?? fallback?.duration ?? 0) || 0
  const sentAt = result?.sent_at || result?.sentAt || fallback?.sentAt

  return {
    bytes,
    duration,
    contentType,
    status: rawStatus ? String(rawStatus) : '',
    sentAt: sentAt ? String(sentAt) : undefined,
  }
}

function getHeaderValue(headers: Record<string, any>, name: string) {
  const target = name.toLowerCase()
  const entry = Object.entries(headers || {}).find(([key]) => key.toLowerCase() === target)
  return entry ? String(entry[1]) : ''
}

function getByteSize(value: string) {
  if (!value) return 0
  if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(value).length
  return value.length
}
