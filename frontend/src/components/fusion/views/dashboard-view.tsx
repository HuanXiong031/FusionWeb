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

export function DashboardView({ demoMode, onOpenTask }: { demoMode: boolean; onOpenTask: (taskId: string) => void }) {
  const statsQuery = useQuery({ queryKey: ['dashboard-stats'], queryFn: getDashboardStats, enabled: !demoMode })
  const tasksQuery = useQuery({ queryKey: ['tasks'], queryFn: getTasks, enabled: !demoMode })
  const stats = demoMode ? demoStats : unwrap<DashboardStats>(statsQuery.data) || {}
  const tasks = demoMode ? demoTasks : asList<TaskRow>(tasksQuery.data)
  const dist = stats.vulnLevelDist || {}
  const vulnPie = [
    { name: '严重', value: dist.critical || 0, color: '#ef4444' },
    { name: '高危', value: dist.high || 0, color: '#f97316' },
    { name: '中危', value: dist.medium || 0, color: '#eab308' },
    { name: '低危', value: dist.low || 0, color: '#3b82f6' },
    { name: '信息', value: dist.info || 0, color: '#737373' },
  ].filter((item) => item.value > 0 || demoMode)
  const fingerprintTotal = stats.totalFingerprints ?? stats.totalFingerprintCount ?? stats.fingerprintCount ?? 0
  const templateTotal = stats.totalPOCs ?? stats.totalPocs ?? stats.totalTemplates ?? stats.templateCount ?? stats.pocCount ?? 0
  const portCount = stats.portCount || tasks.reduce((sum, task) => sum + Number(task.portCount || 0), 0)
  const siteCount = stats.siteCount || tasks.reduce((sum, task) => sum + Number(task.urlCount || 0), 0)
  const directoryCount = stats.directoryCount || 0
  const jsCount = stats.jsCount || 0
  const subdomainCount = stats.subdomainCount || 0
  const weakPasswordCount = stats.weakPasswordCount || 0
  const criticalHigh = (dist.critical || 0) + (dist.high || 0)
  const completedTasks = stats.completedTasks || tasks.filter((task) => ['completed', 'complete', 'done'].includes(String(task.status || '').toLowerCase())).length
  const totalTasks = stats.totalTasks || tasks.length || 0
  const exposureTotal = portCount + siteCount + directoryCount + jsCount + subdomainCount + weakPasswordCount
  const exposureSources = [
    { key: 'ports', label: '暴露端口', value: portCount, color: '#3b82f6' },
    { key: 'sites', label: '暴露站点', value: siteCount, color: '#8b5cf6' },
    { key: 'dirs', label: '敏感目录', value: directoryCount, color: '#ef4444' },
    { key: 'js', label: 'JS 发现', value: jsCount, color: '#06b6d4' },
    { key: 'weak', label: '弱口令', value: weakPasswordCount, color: '#f97316' },
  ]
  const exposureRings = [
    { key: 'scanned', label: '已完成', value: completedTasks, color: '#22c55e', pct: totalTasks > 0 ? Math.min(100, Math.round((completedTasks / totalTasks) * 100)) : 0 },
    { key: 'vulns', label: '漏洞', value: stats.totalVulns || 0, color: '#f97316', pct: stats.totalVulns ? 100 : 0 },
    { key: 'risk', label: '高危面', value: criticalHigh, color: '#ef4444', pct: stats.totalVulns ? Math.min(100, Math.round((criticalHigh / (stats.totalVulns || 1)) * 100)) : 0 },
  ]
  const statCards = [
    { label: '总任务数', value: totalTasks, delta: '任务', tone: 'neutral', icon: ListChecks, desc: '已创建的扫描任务总量' },
    { label: '运行中任务', value: stats.runningTasks || tasks.filter((task) => task.status === 'running').length || 0, delta: '运行', tone: 'info', icon: Activity, desc: '当前正在执行的任务' },
    { label: '资产总数', value: stats.totalAssets || 0, delta: '资产', tone: 'success', icon: Globe2, desc: '端口、URL 与发现资产' },
    { label: '漏洞总数', value: stats.totalVulns || 0, delta: '漏洞', tone: 'danger', icon: ShieldAlert, desc: '所有扫描发现的漏洞' },
    { label: '指纹总数', value: fingerprintTotal, delta: '指纹', tone: 'accent', icon: Fingerprint, desc: '已收录的指纹规则' },
    { label: '模板总数', value: templateTotal, delta: '模板', tone: 'warning', icon: FileCode2, desc: '可用于验证的 POC 模板' },
  ]
  const columns = getTaskColumns(onOpenTask)

  return (
    <div>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
        {statCards.map((stat) => (
          <Card key={stat.label} className="min-h-[154px]">
            <CardContent className="p-6">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-2 text-sm text-muted">
                  <stat.icon className="size-4" />
                  <span>{stat.label}</span>
                </div>
                <Badge tone={stat.tone as any}>{stat.delta}</Badge>
              </div>
              <div className="mt-3 text-3xl font-bold tracking-tight">{compactNumber(stat.value)}</div>
              <div className="mt-6 text-sm text-muted">{stat.desc}</div>
            </CardContent>
          </Card>
        ))}
      </div>
      <div className="mt-4 flex justify-end text-xs text-muted">统计更新于 {formatTime(currentChinaTimeString())}</div>
      <div className="mt-4 grid gap-4 xl:grid-cols-[1fr_464px]">
        <ExposureOverviewCard total={exposureTotal} sources={exposureSources} rings={exposureRings} subdomainCount={subdomainCount} />
        <Card>
          <CardHeader>
            <div>
              <CardTitle>漏洞分布</CardTitle>
              <CardDescription>按严重程度统计</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="h-[330px]">
            <ResponsiveContainer width="100%" height="82%">
              <PieChart>
                <Pie data={vulnPie} innerRadius={58} outerRadius={92} paddingAngle={2} dataKey="value">
                  {vulnPie.map((item) => (
                    <Cell key={item.name} fill={item.color} stroke="var(--card)" strokeWidth={2} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--foreground)' }} />
              </PieChart>
            </ResponsiveContainer>
            <div className="flex flex-wrap gap-3 border-t border-border pt-3 text-sm">
              {vulnPie.map((item) => (
                <span key={item.name} className="inline-flex items-center gap-2 text-muted">
                  <span className="size-2 rounded-full" style={{ background: item.color }} />
                  {item.name} <b className="text-foreground">{item.value}</b>
                </span>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
      <section className="mt-4">
        <PageTitle title="扫描历史" description="实时任务列表，下一步会接入 SSE 推送。" />
        <DataTable columns={columns} data={tasks} searchPlaceholder="搜索目标或任务" emptyTitle="暂无任务" paginationStorageKey="dashboard-tasks" />
      </section>
    </div>
  )
}

function ExposureOverviewCard({
  total,
  sources,
  rings,
  subdomainCount,
}: {
  total: number
  sources: Array<{ key: string; label: string; value: number; color: string }>
  rings: Array<{ key: string; label: string; value: number; color: string; pct: number }>
  subdomainCount: number
}) {
  const sourcePaths = sources.map((_, index) => {
    const y = 38 + index * 46
    return `M 210 ${y} C 310 ${y}, 350 140, 430 140`
  })
  const ringPaths = rings.map((_, index) => {
    const y = 70 + index * 70
    if (index === 1) {
      return 'M 570 140 C 630 124, 700 156, 790 140'
    }
    return `M 570 140 C 650 140, 690 ${y}, 790 ${y}`
  })
  const flowDots = [0, 0.34, 0.68]

  return (
    <Card className="overflow-hidden">
      <CardHeader>
        <div>
          <CardTitle>暴露面总览</CardTitle>
          <CardDescription>端口、站点、目录、JS 与风险暴露聚合</CardDescription>
        </div>
        <Badge tone="success" className="gap-1.5">
          <span className="size-1.5 rounded-full bg-success" />
          实时
        </Badge>
      </CardHeader>
      <CardContent className="min-h-[330px] p-5">
        <div className="relative grid min-h-[280px] items-center gap-4 lg:grid-cols-[minmax(150px,190px)_minmax(44px,1fr)_180px_minmax(44px,1fr)_96px]">
          <svg className="pointer-events-none absolute inset-0 z-0 hidden size-full overflow-visible lg:block" viewBox="0 0 1000 280" preserveAspectRatio="none" aria-hidden="true">
            <defs>
              <filter id="fusion-exposure-line-glow" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur stdDeviation="1.6" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>
            {sources.map((source, index) => (
              <g key={`source-line-${source.key}`}>
                <path d={sourcePaths[index]} fill="none" stroke={source.color} strokeWidth="1.25" strokeLinecap="round" strokeOpacity="0.58" vectorEffect="non-scaling-stroke" filter="url(#fusion-exposure-line-glow)" />
                {flowDots.map((offset, dotIndex) => (
                  <circle key={`${source.key}-${dotIndex}`} r="2" fill={source.color} opacity="0.9" style={{ color: source.color, filter: 'drop-shadow(0 0 4px currentColor)' }}>
                    <animateMotion path={sourcePaths[index]} dur={`${2.6 + index * 0.12}s`} repeatCount="indefinite" begin={`${-(offset * 2.6 + index * 0.12)}s`} />
                  </circle>
                ))}
              </g>
            ))}
            {rings.map((ring, index) => (
              <g key={`ring-line-${ring.key}`}>
                <path d={ringPaths[index]} fill="none" stroke={ring.color} strokeWidth="1.25" strokeLinecap="round" strokeOpacity="0.58" vectorEffect="non-scaling-stroke" filter="url(#fusion-exposure-line-glow)" />
                {flowDots.map((offset, dotIndex) => (
                  <circle key={`${ring.key}-${dotIndex}`} r="2" fill={ring.color} opacity="0.9" style={{ color: ring.color, filter: 'drop-shadow(0 0 4px currentColor)' }}>
                    <animateMotion path={ringPaths[index]} dur={`${2.6 + index * 0.16}s`} repeatCount="indefinite" begin={`${-(offset * 2.6 + index * 0.16)}s`} />
                  </circle>
                ))}
              </g>
            ))}
          </svg>
          <div className="relative z-10 grid gap-1">
            {sources.map((source) => (
              <div key={source.key} className="flex h-10 items-center gap-2 rounded-md px-3 transition-colors hover:bg-raised">
                <span className="size-2 shrink-0 rounded-full" style={{ background: source.color }} />
                <span className="min-w-0 flex-1 truncate text-xs text-foreground">{source.label}</span>
                <span className="font-mono text-sm font-bold tabular-nums">{compactNumber(source.value)}</span>
              </div>
            ))}
          </div>
          <div className="hidden h-full lg:block" />
          <div className="relative z-10 mx-auto flex size-44 items-center justify-center">
            <div className="absolute inset-0 rounded-full bg-info/10 blur-2xl animate-pulse" />
            <div className="absolute inset-4 rounded-full border border-info/25" />
            <div className="absolute inset-8 rounded-full border border-info/35" />
            <div className="relative flex size-32 flex-col items-center justify-center rounded-full border-2 border-info/45 bg-card shadow-[0_0_42px_rgba(59,130,246,0.18),inset_0_0_28px_rgba(59,130,246,0.08)]">
              <span className="font-mono text-3xl font-black tabular-nums">{compactNumber(total)}</span>
              <span className="mt-1 text-[10px] font-semibold uppercase tracking-[0.08em] text-muted">攻击面</span>
            </div>
          </div>
          <div className="hidden h-full lg:block" />
          <div className="relative z-10 grid justify-items-center gap-3">
            {rings.map((ring) => (
              <div key={ring.key} className="grid justify-items-center gap-1 rounded-md p-1 transition-colors hover:bg-raised">
                <div
                  className="relative flex size-14 items-center justify-center rounded-full shadow-[0_0_10px_currentColor]"
                  style={{
                    color: ring.color,
                    background: `conic-gradient(${ring.color} ${ring.pct}%, var(--raised) ${ring.pct}%)`,
                  }}
                >
                  <span className="absolute inset-1 rounded-full bg-card" />
                  <span className="relative font-mono text-xs font-bold text-foreground">{compactNumber(ring.value)}</span>
                </div>
                <span className="text-[10px] text-muted">{ring.label}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-2 border-t border-border pt-3 text-xs text-muted">
          <Badge tone="info">子域名 {compactNumber(subdomainCount)}</Badge>
          <span>暴露面总数由当前数据库扫描结果实时汇总。</span>
        </div>
      </CardContent>
    </Card>
  )
}
