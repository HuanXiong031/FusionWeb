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
  getDingTalkKeys,
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
  type DingTalkKey,
  type TaskConfig,
  type TaskRow,
  type UserProfile,
} from '@/lib/api'
import { asList, cn, compactNumber, formatTime, getStatusLabel, getStatusTone, parseTargets, unwrap } from '@/lib/utils'
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
  ToggleField,
  PreviewLine,
  SeverityBadge
} from '@/components/fusion/shared'

const portGroups = [
  { label: 'TOP1000', value: 'top1000', ports: '21,22,23,25,53,80,81,88,135,139,143,443,445,1433,3306,3389,5432,6379,8080,8443,9200,27017' },
  { label: 'TOP2000', value: 'top2000', ports: '1-2000' },
  { label: '高危端口', value: 'high', ports: '21,22,23,25,80,135,139,443,445,1433,1521,3306,3389,5432,6379,8080,27017' },
  { label: '全端口', value: 'all', ports: '1-65535' },
  { label: '自定义', value: 'custom', ports: '' },
]

const scanModeLabels: Record<string, string> = {
  alive: '存活检测',
  fingerprint: '仅指纹扫描',
  fingerprint_poc: '指纹 & POC 扫描',
  poc: '仅 POC 扫描',
  port_service: '端口服务扫描',
  subdomain_scan: '子域名扫描',
  weak_password_scan: '弱口令扫描',
  directory_scan: '目录扫描',
  js_scan: 'JS扫描',
}

export type ScanTaskType = 'web' | 'port' | 'subdomain' | 'weak_password' | 'directory' | 'js'

const taskTypeItems: Array<{ value: ScanTaskType; label: string; icon: React.ElementType; description: string }> = [
  { value: 'web', label: 'Web 扫描', icon: Globe2, description: 'Web 探测、指纹和 POC' },
  { value: 'port', label: '端口扫描', icon: Network, description: 'naabu / masscan 端口发现' },
  { value: 'subdomain', label: '子域名扫描', icon: Layers3, description: 'subfinder 枚举' },
  { value: 'weak_password', label: '弱口令扫描', icon: KeyRound, description: '服务账号密码验证' },
  { value: 'directory', label: '目录扫描', icon: FolderOpen, description: 'ffuf 路径发现' },
  { value: 'js', label: 'JS扫描', icon: Code2, description: 'JS 链接和敏感信息' },
]

const taskTypeLabels: Record<ScanTaskType, string> = taskTypeItems.reduce((acc, item) => {
  acc[item.value] = item.label
  return acc
}, {} as Record<ScanTaskType, string>)

const moduleResultTables: Record<ScanTaskType, string> = {
  web: 'recon_results / fingerprint_results / vuln_results',
  port: 'recon_results',
  subdomain: 'subdomain_results',
  weak_password: 'weak_password_results',
  directory: 'directory_results',
  js: 'js_scan_results',
}

function scanModeForTaskType(type: ScanTaskType) {
  if (type === 'web') return 'fingerprint_poc'
  if (type === 'port') return 'port_service'
  return `${type}_scan`
}

function targetHintForTaskType(type: ScanTaskType) {
  if (type === 'web') return '每行一个 URL'
  if (type === 'port') return '每行一个 IP / CIDR / IP 段，单次最多 10000 条输入'
  if (type === 'subdomain') return '每行一个根域名，例如 example.com'
  if (type === 'weak_password') return '每行一个 host:port 或 service://host:port'
  if (type === 'directory' || type === 'js') return '每行一个 URL 或 Host'
  return '每行一个目标'
}

function targetPlaceholderForTaskType(type: ScanTaskType) {
  if (type === 'web') return 'https://example.com\nhttp://192.168.1.1:8080'
  if (type === 'port') return '192.168.1.1\n192.168.1.0/24\n192.168.1.1-192.168.1.100'
  if (type === 'subdomain') return 'example.com\nexample.org'
  if (type === 'weak_password') return 'ssh://192.168.1.10:22\nmysql://192.168.1.20:3306\n192.168.1.30:6379'
  if (type === 'directory' || type === 'js') return 'https://example.com\nhttp://192.168.1.1:8080'
  return ''
}

function splitOptionList(value: string) {
  return parseTargets(value)
}

function splitNumberList(value: string) {
  return splitOptionList(value)
    .map((item) => Number.parseInt(item, 10))
    .filter((item) => Number.isFinite(item) && item > 0)
}

export function AdvancedScanView({
  demoMode,
  onCreated,
  fixedTaskType,
}: {
  demoMode: boolean
  onCreated: (taskId: string) => void
  fixedTaskType?: ScanTaskType
}) {
  const queryClient = useQueryClient()
  const [draft, setDraft] = React.useState({
    taskName: '',
    taskType: (fixedTaskType || 'web') as ScanTaskType,
    targetInput: '',
    scanMode: scanModeForTaskType(fixedTaskType || 'web'),
    portScanTool: 'naabu',
    portScanType: 'connect',
    portGroup: 'top1000',
    customPortRange: portGroups[0].ports,
    threadCount: 1000,
    portScanTimeout: 3,
    portRetries: 2,
    webTimeout: 20,
    httpProxy: '',
    selectedDicts: '',
    fullPocScan: false,
    enableActiveFingerprint: false,
    enableScreenshot: false,
    scanAllPocsWhenNoFingerprint: false,
    webLink: false,
    hostDiscovery: true,
    icmpPing: true,
    tcpPing: false,
    portsThreshold: 65536,
    synScanRate: 10000,
    portIdentifyService: true,
    portExcludeTargets: '',
    subdomainTimeout: 30,
    subdomainMaxTime: 10,
    subdomainThreads: 10,
    subdomainRateLimit: 0,
    subdomainAll: false,
    subdomainRecursive: false,
    subdomainActive: false,
    subdomainResolveDNS: true,
    subdomainSources: '',
    weakServices: 'ssh\nftp\nmysql\npostgresql\nredis',
    weakUsernames: '',
    weakPasswords: '',
    weakTimeout: 5,
    weakThreads: 10,
    weakStopOnFirst: true,
    weakForceScan: false,
    directoryPaths: '',
    directoryExtensions: '',
    directoryStatusCodes: '200,204,301,302,307,401,403,405,500',
    directoryThreads: 50,
    directoryTimeout: 10,
    directoryFollowRedirect: false,
    directoryRate: 0,
    directoryRecursion: false,
    directoryRecursionDepth: 1,
    jsThreads: 10,
    jsTimeout: 10,
    jsEnableSourcemap: false,
    jsEnableUnauthCheck: true,
    jsMaxJSSizeMB: 5,
    jsMaxJSPerTarget: 200,
    enableDingTalk: false,
    dingTalkKeyId: '',
  })
  React.useEffect(() => {
    if (!fixedTaskType) return
    setDraft((current) => {
      if (current.taskType === fixedTaskType) return current
      return { ...current, taskType: fixedTaskType, scanMode: scanModeForTaskType(fixedTaskType) }
    })
  }, [fixedTaskType])
  const dingTalkKeysQuery = useQuery({ queryKey: ['dingtalk-keys'], queryFn: getDingTalkKeys, enabled: !demoMode })
  const dingTalkKeys = demoMode
    ? [{ id: 1, name: '默认钉钉机器人', notifyWebScanComplete: true, notifyPortScanComplete: true, enabled: true }]
    : unwrap<DingTalkKey[]>(dingTalkKeysQuery.data) || []
  const availableDingTalkKeys = dingTalkKeys.filter((item) => item.enabled !== false)
  const targetCount = parseTargets(draft.targetInput).length
  const currentPortRange = draft.taskType === 'port'
    ? (draft.portGroup === 'custom' ? draft.customPortRange : portGroups.find((item) => item.value === draft.portGroup)?.ports || draft.customPortRange)
    : ''
  const scanTool = React.useMemo(() => {
    if (draft.taskType === 'port') return draft.portScanTool
    if (draft.taskType === 'subdomain') return 'subfinder'
    if (draft.taskType === 'directory') return 'ffuf'
    if (draft.taskType === 'weak_password') return 'bruteforce'
    if (draft.taskType === 'js') return 'jsfinder'
    return ''
  }, [draft.taskType, draft.portScanTool])
  const effectiveThreadCount = React.useMemo(() => {
    if (draft.taskType === 'subdomain') return Number(draft.subdomainThreads) || 10
    if (draft.taskType === 'weak_password') return Number(draft.weakThreads) || 10
    if (draft.taskType === 'directory') return Number(draft.directoryThreads) || 50
    if (draft.taskType === 'js') return Number(draft.jsThreads) || 10
    return Number(draft.threadCount) || 1000
  }, [draft])
  const scanOptions = React.useMemo(() => {
    if (draft.taskType === 'port') {
      return {
        tool: draft.portScanTool,
        scanType: draft.portScanType,
        retries: Number(draft.portRetries) || 2,
        identifyService: draft.portIdentifyService,
        excludeTargets: splitOptionList(draft.portExcludeTargets),
      }
    }
    if (draft.taskType === 'subdomain') {
      return {
        timeout: Number(draft.subdomainTimeout) || 30,
        maxEnumerationTime: Number(draft.subdomainMaxTime) || 10,
        threads: Number(draft.subdomainThreads) || 10,
        rateLimit: Number(draft.subdomainRateLimit) || 0,
        all: draft.subdomainAll,
        recursive: draft.subdomainRecursive,
        active: draft.subdomainActive,
        resolveDNS: draft.subdomainResolveDNS,
        sources: splitOptionList(draft.subdomainSources),
      }
    }
    if (draft.taskType === 'weak_password') {
      return {
        services: splitOptionList(draft.weakServices),
        usernames: splitOptionList(draft.weakUsernames),
        passwords: splitOptionList(draft.weakPasswords),
        timeout: Number(draft.weakTimeout) || 5,
        threads: Number(draft.weakThreads) || 10,
        stopOnFirst: draft.weakStopOnFirst,
        forceScan: draft.weakForceScan,
      }
    }
    if (draft.taskType === 'directory') {
      return {
        paths: splitOptionList(draft.directoryPaths),
        extensions: splitOptionList(draft.directoryExtensions),
        statusCodes: splitNumberList(draft.directoryStatusCodes),
        threads: Number(draft.directoryThreads) || 50,
        timeout: Number(draft.directoryTimeout) || 10,
        followRedirect: draft.directoryFollowRedirect,
        rate: Number(draft.directoryRate) || 0,
        recursion: draft.directoryRecursion,
        recursionDepth: Number(draft.directoryRecursionDepth) || 1,
      }
    }
    if (draft.taskType === 'js') {
      return {
        threads: Number(draft.jsThreads) || 10,
        timeout: Number(draft.jsTimeout) || 10,
        enableSourcemap: draft.jsEnableSourcemap,
        enableUnauthCheck: draft.jsEnableUnauthCheck,
        maxJSSize: Math.max(1, Number(draft.jsMaxJSSizeMB) || 5) * 1024 * 1024,
        maxJSPerTarget: Number(draft.jsMaxJSPerTarget) || 200,
      }
    }
    return {}
  }, [draft])
  const mutation = useMutation({
    mutationFn: async () => {
      if (!draft.targetInput.trim()) throw new Error('请输入扫描目标')
      if (draft.taskType === 'port' && !currentPortRange.trim()) throw new Error('请输入端口范围')
      if (draft.enableDingTalk && !draft.dingTalkKeyId) throw new Error('请选择钉钉 Key')
      if (demoMode) return { data: { taskId: 'demo-advanced-scan' } }
      const selectedDicts = draft.taskType === 'directory' ? splitOptionList(draft.directoryPaths) : splitOptionList(draft.selectedDicts)
      const payload: TaskConfig = {
        task_id: '',
        task_name: draft.taskName.trim() || `${taskTypeLabels[draft.taskType]}_${Date.now()}`,
        task_type: draft.taskType,
        target_input: draft.targetInput.trim(),
        port_range: draft.taskType === 'port' ? currentPortRange : '',
        scan_mode: draft.scanMode || scanModeForTaskType(draft.taskType),
        scan_tool: scanTool,
        scan_options: JSON.stringify(scanOptions),
        thread_count: effectiveThreadCount,
        port_scan_timeout: Number(draft.portScanTimeout) || 3,
        web_timeout: draft.taskType === 'directory' ? Number(draft.directoryTimeout) || 10 : draft.taskType === 'js' ? Number(draft.jsTimeout) || 10 : Number(draft.webTimeout) || 20,
        http_proxy: draft.httpProxy.trim(),
        skip_host_discovery: !draft.hostDiscovery,
        no_icmp_ping: draft.hostDiscovery ? !draft.icmpPing : true,
        tcp_ping: draft.hostDiscovery ? draft.tcpPing : false,
        ports_threshold: Number(draft.portsThreshold) || 65536,
        syn_scan_rate: Number(draft.synScanRate) || 10000,
        web_link: draft.webLink,
        selected_dicts: JSON.stringify(selectedDicts),
        full_poc_scan: draft.fullPocScan,
        scan_all_pocs_when_no_fingerprint: draft.scanAllPocsWhenNoFingerprint,
        enable_active_fingerprint: draft.enableActiveFingerprint,
        enable_screenshot: draft.enableScreenshot,
        ding_talk_key_id: draft.enableDingTalk ? Number(draft.dingTalkKeyId) || 0 : 0,
      }
      return createTask(payload)
    },
    onSuccess: (res: any) => {
      toast.success('扫描任务已创建')
      const taskId = res?.data?.taskId || res?.taskId || res?.data?.task_id || res?.task_id || 'demo-advanced-scan'
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
      onCreated(taskId)
    },
    onError: (error: any) => toast.error(error.message || '任务创建失败'),
  })
  const pageTitle = fixedTaskType ? taskTypeLabels[draft.taskType] : '新建扫描'
  const pageDescription = fixedTaskType
    ? `创建${taskTypeLabels[draft.taskType]}任务，结果会写入 ${moduleResultTables[draft.taskType]}。`
    : '按功能创建独立扫描任务，结果会写入对应的数据表。'

  return (
    <div className="grid min-w-0 gap-4">
      <PageTitle title={pageTitle} description={pageDescription} />
      <div className="grid min-w-0 gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
        <div className="grid min-w-0 gap-4">
          <Card>
            <CardHeader>
              <div>
                <CardTitle>任务基础配置</CardTitle>
                <CardDescription>目标、扫描类型和模式。</CardDescription>
              </div>
            </CardHeader>
            <CardContent className="grid gap-4">
              {!fixedTaskType ? (
                <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
                  {taskTypeItems.map((item) => {
                    const Icon = item.icon
                    return (
                      <Button
                        key={item.value}
                        className="h-auto justify-start px-3 py-3 text-left"
                        variant={draft.taskType === item.value ? 'default' : 'outline'}
                        onClick={() => setDraft({ ...draft, taskType: item.value, scanMode: scanModeForTaskType(item.value) })}
                      >
                        <Icon className="size-4" />
                        <span className="grid gap-0.5">
                          <span>{item.label}</span>
                          <span className="text-xs font-normal opacity-75">{item.description}</span>
                        </span>
                      </Button>
                    )
                  })}
                </div>
              ) : null}
              <div className="grid gap-4 md:grid-cols-2">
                <Field label="任务名称" hint="留空自动生成">
                  <Input value={draft.taskName} onChange={(event) => setDraft({ ...draft, taskName: event.target.value })} placeholder="例如：重点资产扫描" />
                </Field>
                {draft.taskType === 'web' ? (
                  <Field label="扫描模式" reserveHint>
                    <Select value={draft.scanMode} onChange={(event) => setDraft({ ...draft, scanMode: event.target.value })}>
                      <option value="alive">存活检测</option>
                      <option value="fingerprint">仅指纹扫描</option>
                      <option value="fingerprint_poc">指纹 & POC 扫描</option>
                      <option value="poc">仅 POC 扫描</option>
                    </Select>
                  </Field>
                ) : (
                  <Field label="执行功能" reserveHint>
                    <Input value={scanModeLabels[draft.scanMode] || taskTypeLabels[draft.taskType]} readOnly />
                  </Field>
                )}
              </div>
              <Field label="任务目标" hint={targetHintForTaskType(draft.taskType)}>
                <Textarea
                  className="min-h-44"
                  value={draft.targetInput}
                  onChange={(event) => setDraft({ ...draft, targetInput: event.target.value })}
                  placeholder={targetPlaceholderForTaskType(draft.taskType)}
                />
              </Field>
            </CardContent>
          </Card>

          {draft.taskType === 'port' ? (
            <Card>
              <CardHeader>
                <div>
                  <CardTitle>端口扫描参数</CardTitle>
                  <CardDescription>端口组、主机发现、协议识别和 Web 联动。</CardDescription>
                </div>
              </CardHeader>
              <CardContent className="grid gap-4">
                <div className="grid gap-4 md:grid-cols-4">
                  <Field label="扫描工具">
                    <Select value={draft.portScanTool} onChange={(event) => setDraft({ ...draft, portScanTool: event.target.value })}>
                      <option value="naabu">naabu</option>
                      <option value="masscan">masscan</option>
                    </Select>
                  </Field>
                  <Field label="扫描类型">
                    <Select value={draft.portScanType} onChange={(event) => setDraft({ ...draft, portScanType: event.target.value })}>
                      <option value="connect">CONNECT</option>
                      <option value="syn">SYN</option>
                    </Select>
                  </Field>
                  <Field label="速率">
                    <Input type="number" value={draft.synScanRate} onChange={(event) => setDraft({ ...draft, synScanRate: Number(event.target.value) })} />
                  </Field>
                  <Field label="重试次数">
                    <Input type="number" value={draft.portRetries} onChange={(event) => setDraft({ ...draft, portRetries: Number(event.target.value) })} />
                  </Field>
                </div>
                <Field label="端口组">
                  <div className="flex flex-wrap gap-2">
                    {portGroups.map((group) => (
                      <Button key={group.value} variant={draft.portGroup === group.value ? 'default' : 'outline'} onClick={() => setDraft({ ...draft, portGroup: group.value, customPortRange: group.ports || draft.customPortRange })}>
                        {group.label}
                      </Button>
                    ))}
                  </div>
                </Field>
                <Field label="端口范围" hint="支持 80,443,8000-9000">
                  <Textarea value={currentPortRange} onChange={(event) => setDraft({ ...draft, portGroup: 'custom', customPortRange: event.target.value })} />
                </Field>
                <div className="grid gap-3 md:grid-cols-4">
                  <ToggleField label="主机存活探测" checked={draft.hostDiscovery} onChange={(value) => setDraft({ ...draft, hostDiscovery: value })} />
                  <ToggleField label="ICMP Ping" checked={draft.icmpPing} onChange={(value) => setDraft({ ...draft, icmpPing: value })} />
                  <ToggleField label="TCP Ping" checked={draft.tcpPing} onChange={(value) => setDraft({ ...draft, tcpPing: value })} />
                  <ToggleField label="Web 联动" checked={draft.webLink} onChange={(value) => setDraft({ ...draft, webLink: value })} />
                </div>
                <div className="grid gap-4 md:grid-cols-3">
                  <Field label="端口数量阈值"><Input type="number" value={draft.portsThreshold} onChange={(event) => setDraft({ ...draft, portsThreshold: Number(event.target.value) })} /></Field>
                  <Field label="线程数"><Input type="number" value={draft.threadCount} onChange={(event) => setDraft({ ...draft, threadCount: Number(event.target.value) })} /></Field>
                  <Field label="端口超时(秒)"><Input type="number" value={draft.portScanTimeout} onChange={(event) => setDraft({ ...draft, portScanTimeout: Number(event.target.value) })} /></Field>
                </div>
                <div className="grid gap-3 md:grid-cols-3">
                  <ToggleField label="服务识别(Nmap)" checked={draft.portIdentifyService} onChange={(value) => setDraft({ ...draft, portIdentifyService: value })} />
                  <ToggleField label="全量 POC 扫描" checked={draft.fullPocScan} onChange={(value) => setDraft({ ...draft, fullPocScan: value })} />
                  <ToggleField label="页面截图" checked={draft.enableScreenshot} onChange={(value) => setDraft({ ...draft, enableScreenshot: value })} />
                </div>
                <Field label="排除目标" hint="每行一个需要排除的 IP、域名或 host:port">
                  <Textarea value={draft.portExcludeTargets} onChange={(event) => setDraft({ ...draft, portExcludeTargets: event.target.value })} />
                </Field>
              </CardContent>
            </Card>
          ) : null}

          {draft.taskType === 'subdomain' ? (
            <Card>
              <CardHeader>
                <div>
                  <CardTitle>子域名扫描参数</CardTitle>
                  <CardDescription>使用 subfinder 枚举子域名，并写入 subdomain_results。</CardDescription>
                </div>
              </CardHeader>
              <CardContent className="grid gap-4">
                <div className="grid gap-4 md:grid-cols-4">
                  <Field label="超时(秒)"><Input type="number" value={draft.subdomainTimeout} onChange={(event) => setDraft({ ...draft, subdomainTimeout: Number(event.target.value) })} /></Field>
                  <Field label="最大枚举时间(分钟)"><Input type="number" value={draft.subdomainMaxTime} onChange={(event) => setDraft({ ...draft, subdomainMaxTime: Number(event.target.value) })} /></Field>
                  <Field label="线程数"><Input type="number" value={draft.subdomainThreads} onChange={(event) => setDraft({ ...draft, subdomainThreads: Number(event.target.value) })} /></Field>
                  <Field label="速率限制"><Input type="number" value={draft.subdomainRateLimit} onChange={(event) => setDraft({ ...draft, subdomainRateLimit: Number(event.target.value) })} /></Field>
                </div>
                <div className="grid gap-3 md:grid-cols-4">
                  <ToggleField label="全部数据源" checked={draft.subdomainAll} onChange={(value) => setDraft({ ...draft, subdomainAll: value })} />
                  <ToggleField label="递归枚举" checked={draft.subdomainRecursive} onChange={(value) => setDraft({ ...draft, subdomainRecursive: value })} />
                  <ToggleField label="主动枚举" checked={draft.subdomainActive} onChange={(value) => setDraft({ ...draft, subdomainActive: value })} />
                  <ToggleField label="解析 DNS" checked={draft.subdomainResolveDNS} onChange={(value) => setDraft({ ...draft, subdomainResolveDNS: value })} />
                </div>
                <Field label="指定数据源" hint="可选，每行一个 subfinder source 名称">
                  <Textarea value={draft.subdomainSources} onChange={(event) => setDraft({ ...draft, subdomainSources: event.target.value })} placeholder="crtsh&#10;github&#10;alienvault" />
                </Field>
              </CardContent>
            </Card>
          ) : null}

          {draft.taskType === 'weak_password' ? (
            <Card>
              <CardHeader>
                <div>
                  <CardTitle>弱口令扫描参数</CardTitle>
                  <CardDescription>按服务类型验证账号密码，并写入 weak_password_results。</CardDescription>
                </div>
              </CardHeader>
              <CardContent className="grid gap-4">
                <div className="grid gap-4 md:grid-cols-3">
                  <Field label="服务类型" hint="每行一个服务，支持 ssh / ftp / mysql / postgresql / redis">
                    <Textarea value={draft.weakServices} onChange={(event) => setDraft({ ...draft, weakServices: event.target.value })} />
                  </Field>
                  <Field label="用户名字典" hint="留空使用字典管理中的弱口令账号">
                    <Textarea value={draft.weakUsernames} onChange={(event) => setDraft({ ...draft, weakUsernames: event.target.value })} />
                  </Field>
                  <Field label="密码字典" hint="留空使用字典管理中的弱口令密码">
                    <Textarea value={draft.weakPasswords} onChange={(event) => setDraft({ ...draft, weakPasswords: event.target.value })} />
                  </Field>
                </div>
                <div className="grid gap-4 md:grid-cols-4">
                  <Field label="超时(秒)"><Input type="number" value={draft.weakTimeout} onChange={(event) => setDraft({ ...draft, weakTimeout: Number(event.target.value) })} /></Field>
                  <Field label="线程数"><Input type="number" value={draft.weakThreads} onChange={(event) => setDraft({ ...draft, weakThreads: Number(event.target.value) })} /></Field>
                  <ToggleField label="成功后停止" checked={draft.weakStopOnFirst} onChange={(value) => setDraft({ ...draft, weakStopOnFirst: value })} />
                  <ToggleField label="跳过端口预检测" checked={draft.weakForceScan} onChange={(value) => setDraft({ ...draft, weakForceScan: value })} />
                </div>
              </CardContent>
            </Card>
          ) : null}

          {draft.taskType === 'directory' ? (
            <Card>
              <CardHeader>
                <div>
                  <CardTitle>目录扫描参数</CardTitle>
                  <CardDescription>使用 ffuf 扫描路径，并写入 directory_results。</CardDescription>
                </div>
              </CardHeader>
              <CardContent className="grid gap-4">
                <Field label="路径字典" hint="留空使用字典管理中的目录路径；填写后仅本次任务使用这些路径">
                  <Textarea className="min-h-36" value={draft.directoryPaths} onChange={(event) => setDraft({ ...draft, directoryPaths: event.target.value })} />
                </Field>
                <div className="grid gap-4 md:grid-cols-2">
                  <Field label="扩展名" hint="例如 php,aspx,js">
                    <Input value={draft.directoryExtensions} onChange={(event) => setDraft({ ...draft, directoryExtensions: event.target.value })} />
                  </Field>
                  <Field label="匹配状态码">
                    <Input value={draft.directoryStatusCodes} onChange={(event) => setDraft({ ...draft, directoryStatusCodes: event.target.value })} />
                  </Field>
                </div>
                <div className="grid gap-4 md:grid-cols-5">
                  <Field label="线程数"><Input type="number" value={draft.directoryThreads} onChange={(event) => setDraft({ ...draft, directoryThreads: Number(event.target.value) })} /></Field>
                  <Field label="超时(秒)"><Input type="number" value={draft.directoryTimeout} onChange={(event) => setDraft({ ...draft, directoryTimeout: Number(event.target.value) })} /></Field>
                  <Field label="速率限制"><Input type="number" value={draft.directoryRate} onChange={(event) => setDraft({ ...draft, directoryRate: Number(event.target.value) })} /></Field>
                  <Field label="递归深度"><Input type="number" value={draft.directoryRecursionDepth} onChange={(event) => setDraft({ ...draft, directoryRecursionDepth: Number(event.target.value) })} /></Field>
                  <ToggleField label="递归扫描" checked={draft.directoryRecursion} onChange={(value) => setDraft({ ...draft, directoryRecursion: value })} />
                </div>
                <ToggleField label="跟随跳转" checked={draft.directoryFollowRedirect} onChange={(value) => setDraft({ ...draft, directoryFollowRedirect: value })} />
              </CardContent>
            </Card>
          ) : null}

          {draft.taskType === 'js' ? (
            <Card>
              <CardHeader>
                <div>
                  <CardTitle>JS 扫描参数</CardTitle>
                  <CardDescription>提取 JS 链接、接口路径和敏感信息，并写入 js_scan_results。</CardDescription>
                </div>
              </CardHeader>
              <CardContent className="grid gap-4">
                <div className="grid gap-4 md:grid-cols-4">
                  <Field label="线程数"><Input type="number" value={draft.jsThreads} onChange={(event) => setDraft({ ...draft, jsThreads: Number(event.target.value) })} /></Field>
                  <Field label="超时(秒)"><Input type="number" value={draft.jsTimeout} onChange={(event) => setDraft({ ...draft, jsTimeout: Number(event.target.value) })} /></Field>
                  <Field label="最大 JS 大小(MB)"><Input type="number" value={draft.jsMaxJSSizeMB} onChange={(event) => setDraft({ ...draft, jsMaxJSSizeMB: Number(event.target.value) })} /></Field>
                  <Field label="每目标 JS 上限"><Input type="number" value={draft.jsMaxJSPerTarget} onChange={(event) => setDraft({ ...draft, jsMaxJSPerTarget: Number(event.target.value) })} /></Field>
                </div>
                <div className="grid gap-3 md:grid-cols-2">
                  <ToggleField label="检查 Sourcemap" checked={draft.jsEnableSourcemap} onChange={(value) => setDraft({ ...draft, jsEnableSourcemap: value })} />
                  <ToggleField label="未授权关键词检查" checked={draft.jsEnableUnauthCheck} onChange={(value) => setDraft({ ...draft, jsEnableUnauthCheck: value })} />
                </div>
              </CardContent>
            </Card>
          ) : null}

          {draft.taskType === 'web' ? (
            <Card>
              <CardHeader>
                <div>
                  <CardTitle>Web / POC 参数</CardTitle>
                  <CardDescription>主动指纹、全量 POC、代理、字典和通知。</CardDescription>
                </div>
              </CardHeader>
              <CardContent className="grid gap-4">
                <div className="grid gap-3 md:grid-cols-4">
                  <ToggleField label="全量 POC 扫描" checked={draft.fullPocScan} onChange={(value) => setDraft({ ...draft, fullPocScan: value })} />
                  <ToggleField label="无指纹时全量 POC" checked={draft.scanAllPocsWhenNoFingerprint} onChange={(value) => setDraft({ ...draft, scanAllPocsWhenNoFingerprint: value })} />
                  <ToggleField label="主动指纹探测" checked={draft.enableActiveFingerprint} onChange={(value) => setDraft({ ...draft, enableActiveFingerprint: value })} />
                  <ToggleField label="页面截图" checked={draft.enableScreenshot} onChange={(value) => setDraft({ ...draft, enableScreenshot: value })} />
                </div>
                <div className="grid gap-4 md:grid-cols-3">
                  <Field label="线程数"><Input type="number" value={draft.threadCount} onChange={(event) => setDraft({ ...draft, threadCount: Number(event.target.value) })} /></Field>
                  <Field label="端口超时(秒)"><Input type="number" value={draft.portScanTimeout} onChange={(event) => setDraft({ ...draft, portScanTimeout: Number(event.target.value) })} /></Field>
                  <Field label="Web 超时(秒)"><Input type="number" value={draft.webTimeout} onChange={(event) => setDraft({ ...draft, webTimeout: Number(event.target.value) })} /></Field>
                </div>
                <Field label="HTTP 代理">
                  <Input value={draft.httpProxy} onChange={(event) => setDraft({ ...draft, httpProxy: event.target.value })} placeholder="http://127.0.0.1:8080" />
                </Field>
                <Field label="主动指纹字典" hint="每行一个字典名或路径，会保存到 selected_dicts">
                  <Textarea value={draft.selectedDicts} onChange={(event) => setDraft({ ...draft, selectedDicts: event.target.value })} placeholder="dir-small.txt&#10;dir-medium.txt" />
                </Field>
                <ToggleField label="钉钉通知" checked={draft.enableDingTalk} onChange={(value) => setDraft({ ...draft, enableDingTalk: value })} />
                {draft.enableDingTalk ? (
                  <Field label="钉钉 Key" hint="Key 在系统设置中维护；任务结束时会按 Key 的提醒范围发送。">
                    <Select value={draft.dingTalkKeyId} onChange={(event) => setDraft({ ...draft, dingTalkKeyId: event.target.value })}>
                      <option value="">请选择钉钉 Key</option>
                      {availableDingTalkKeys.map((item) => (
                        <option key={item.id} value={item.id}>
                          {item.name}
                        </option>
                      ))}
                    </Select>
                  </Field>
                ) : null}
              </CardContent>
            </Card>
          ) : null}
        </div>

        <Card className="h-fit">
          <CardHeader>
            <div>
              <CardTitle>提交预览</CardTitle>
              <CardDescription>提交给后端任务调度器的关键字段。</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="grid gap-3 text-sm">
            <PreviewLine label="任务类型" value={taskTypeLabels[draft.taskType]} />
            <PreviewLine label="目标数量" value={`${targetCount} 个`} />
            <PreviewLine label="扫描模式" value={scanModeLabels[draft.scanMode] || draft.scanMode} />
            <PreviewLine label="结果表" value={moduleResultTables[draft.taskType]} />
            {scanTool ? <PreviewLine label="工具" value={scanTool} /> : null}
            {draft.taskType === 'port' ? <PreviewLine label="端口范围" value={currentPortRange || '-'} /> : null}
            <PreviewLine label="线程数" value={String(effectiveThreadCount)} />
            {draft.taskType === 'web' ? <PreviewLine label="主动指纹" value={draft.enableActiveFingerprint ? '开启' : '关闭'} /> : null}
            {(draft.taskType === 'web' || draft.taskType === 'port') ? <PreviewLine label="页面截图" value={draft.enableScreenshot ? '开启' : '关闭'} /> : null}
            {draft.taskType === 'web' ? <PreviewLine label="钉钉通知" value={draft.enableDingTalk ? '开启' : '关闭'} /> : null}
            <div className="mt-2 flex justify-end gap-2">
              <Button variant="outline" onClick={() => setDraft({ ...draft, targetInput: '', taskName: '' })}>清空目标</Button>
              <Button variant="default" disabled={mutation.isPending || !draft.targetInput.trim()} onClick={() => mutation.mutate()}>
                {mutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <ScanLine className="size-4" />}
                创建并执行
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
