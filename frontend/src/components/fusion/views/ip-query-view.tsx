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

export function IPQueryView({ demoMode }: { demoMode: boolean }) {
  const qc = useQueryClient()
  const [activeTab, setActiveTab] = React.useState('single')
  const [singleIP, setSingleIP] = React.useState('')
  const [batchInput, setBatchInput] = React.useState('')
  const [result, setResult] = React.useState<any[]>([])
  const dbInfoQuery = useQuery({ queryKey: ['ip-db-info'], queryFn: getIPDBInfo, enabled: !demoMode })
  const dbInfo = demoMode ? { status: 'ready', file: 'qqwry.dat', count: 'demo' } : unwrap<any>(dbInfoQuery.data) || {}
  const dbStatus = getIPDBStatusLabel(dbInfo, dbInfoQuery.isLoading, dbInfoQuery.isError)
  const dbFileName = getIPDBFileName(dbInfo)
  const singleMutation = useMutation({
    mutationFn: async () => (demoMode ? { ip: singleIP || '8.8.8.8', country: 'US', province: '-', city: '-', isp: 'Google', owner_domain: 'google.com' } : queryIP(singleIP.trim())),
    onSuccess: (res: any) => {
      setResult(normalizeIPRows(res))
    },
    onError: (error: any) => toast.error(error.message || '查询失败'),
  })
  const batchMutation = useMutation({
    mutationFn: async () => {
      const ips = parseTargets(batchInput).slice(0, 5000)
      if (demoMode) return Object.fromEntries(ips.map((ip) => [ip, { ip, country: ip === '1.1.1.1' ? 'AU' : 'US', province: '-', city: '-', isp: ip === '1.1.1.1' ? 'Cloudflare' : 'Google', owner_domain: ip === '1.1.1.1' ? 'cloudflare.com' : 'google.com' }]))
      return batchQueryIPs(ips)
    },
    onSuccess: (res: any) => {
      setResult(normalizeIPRows(res))
    },
    onError: (error: any) => toast.error(error.message || '批量查询失败'),
  })
  const reloadMutation = useMutation({
    mutationFn: reloadIPDB,
    onSuccess: () => {
      toast.success('数据库已重载')
      qc.invalidateQueries({ queryKey: ['ip-db-info'] })
    },
    onError: (error: any) => toast.error(error.message || '数据库重载失败'),
  })
  const columns: ColumnDef<any>[] = [
    { header: 'IP地址', accessorKey: 'ip' },
    { header: '洲', accessorKey: 'continent_code' },
    { header: '国家', accessorKey: 'country' },
    { header: '省份', accessorKey: 'province' },
    { header: '城市', accessorKey: 'city' },
    { header: '区县', accessorKey: 'district' },
    { header: '运营商', accessorKey: 'isp' },
    { header: '拥有者', accessorKey: 'owner_domain' },
  ]
  return (
    <div className="grid gap-4">
      <PageTitle title="IP 查询" description="单个 IP、批量 IP、结果导出和 IP 数据库重载。" />
      <div className="grid gap-4 md:grid-cols-4">
        <Metric label="数据库状态" value={dbStatus} icon={Database} tone={dbInfoQuery.isError ? 'danger' : 'success'} badgeLabel="状态" />
        <Metric label="数据库文件" value={dbFileName} icon={FileText} tone="neutral" badgeLabel="文件" />
        <Metric label="批量上限" value="5000" icon={Layers3} tone="info" badgeLabel="上限" />
        <Metric label="结果数量" value={result.length} icon={MapPin} tone="accent" badgeLabel="结果" />
      </div>
      <Card>
        <CardContent className="p-4">
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <TabsList>
                <TabsTrigger value="single"><Search className="size-4" />单个查询</TabsTrigger>
                <TabsTrigger value="batch"><ListChecks className="size-4" />批量查询</TabsTrigger>
              </TabsList>
              <div className="flex flex-wrap gap-2">
                <Button variant="outline" onClick={() => reloadMutation.mutate()} disabled={reloadMutation.isPending}>
                  {reloadMutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <RefreshCw className="size-4" />}重载数据库
                </Button>
                <Button variant="outline" disabled={!result.length} onClick={() => downloadContent(toCsv(result), 'ip-query-results.csv', 'text/csv')}>
                  <FileDown className="size-4" />导出Excel
                </Button>
              </div>
            </div>
            <TabsContent value="single">
              <div className="flex flex-col gap-3 md:flex-row">
                <Input value={singleIP} onChange={(event) => setSingleIP(event.target.value)} placeholder="8.8.8.8" onKeyDown={(event) => event.key === 'Enter' && singleMutation.mutate()} />
                <Button variant="default" onClick={() => singleMutation.mutate()} disabled={singleMutation.isPending || !singleIP.trim()}>
                  {singleMutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <MapPin className="size-4" />}
                  查询
                </Button>
                <Button variant="outline" disabled={!result.length} onClick={() => navigator.clipboard?.writeText(JSON.stringify(result[0], null, 2)).then(() => toast.success('已复制'))}>
                  <Copy className="size-4" />复制结果
                </Button>
              </div>
            </TabsContent>
            <TabsContent value="batch">
              <div className="grid gap-3">
                <Textarea value={batchInput} onChange={(event) => setBatchInput(event.target.value)} placeholder="8.8.8.8&#10;1.1.1.1" />
                <div className="flex justify-end gap-2">
                  <Button variant="outline" onClick={() => setBatchInput('')}>清空</Button>
                  <Button variant="default" onClick={() => batchMutation.mutate()} disabled={batchMutation.isPending || !batchInput.trim()}>
                    {batchMutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <Search className="size-4" />}
                    批量查询
                  </Button>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
      <DataTable columns={columns} data={result} searchPlaceholder="过滤查询结果" emptyTitle="暂无查询结果" paginationStorageKey="ip-query-results" />
    </div>
  )
}
