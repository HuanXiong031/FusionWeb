'use client'

import * as React from 'react'
import { QueryClient, QueryClientProvider, useQuery, useQueryClient } from '@tanstack/react-query'
import { zodResolver } from '@hookform/resolvers/zod'
import { useForm } from 'react-hook-form'
import { z } from 'zod'
import { toast, Toaster } from 'sonner'
import {
  Bell,
  Bot,
  Check,
  ChevronDown,
  ChevronRight,
  Code2,
  Database,
  FileCode2,
  FileDown,
  Fingerprint,
  FolderOpen,
  Globe2,
  History,
  KeyRound,
  Layers3,
  LayoutDashboard,
  ListChecks,
  Loader2,
  LogOut,
  Moon,
  Network,
  Palette,
  PanelLeftClose,
  PanelLeftOpen,
  Plus,
  RadioTower,
  RefreshCw,
  ScanLine,
  Search,
  ShieldAlert,
  ShieldBan,
  Sun,
  Terminal,
  Server,
  User,
  Users,
} from 'lucide-react'
import logoImage from '@/assets/images/logo.png'
import {
  getPocTaskList,
  getPublicAppConfig,
  getTasks,
  login,
  logout,
  getProfile,
  recordAccessVisit,
  type ScanDictionaryType,
  type PublicAppConfig,
  type TaskRow,
  type UserProfile,
} from '@/lib/api'
import { getWebSocketURL } from '@/lib/request'
import { clearPublicKey, encryptPassword, encryptUsername, initPublicKey } from '@/lib/crypto'
import { asList, cn, formatTime, getStatusLabel, unwrap } from '@/lib/utils'
import { Badge, Button, Card, CardContent, Field, Input } from '@/components/ui'
import { ForcedPasswordChangeView } from '@/components/fusion/forced-password-change'
import { DashboardView } from '@/components/fusion/views/dashboard-view'
import { AdvancedScanView, type ScanTaskType } from '@/components/fusion/views/advanced-scan-view'
import { TasksView } from '@/components/fusion/views/tasks-view'
import { TaskDetailView } from '@/components/fusion/views/task-detail-view'
import { TaskLogsView } from '@/components/fusion/views/task-logs-view'
import { ScanResultsView } from '@/components/fusion/views/scan-results-view'
import { FingerprintView } from '@/components/fusion/views/fingerprint-view'
import { PocView } from '@/components/fusion/views/poc-view'
import { PocBuilderView } from '@/components/fusion/views/poc-builder-view'
import { PocTasksView } from '@/components/fusion/views/poc-tasks-view'
import { PocResultsCenterView } from '@/components/fusion/views/poc-results-center-view'
import { ReportCenterView } from '@/components/fusion/views/report-center-view'
import { VulnVerifyView } from '@/components/fusion/views/vuln-verify-view'
import { RTSPScanView } from '@/components/fusion/views/rtsp-scan-view'
import { RTSPDictionaryView } from '@/components/fusion/views/rtsp-dictionary-view'
import { ScanDictionaryView } from '@/components/fusion/views/scan-dictionary-view'
import { IPQueryView } from '@/components/fusion/views/ip-query-view'
import { SpaceSearchView } from '@/components/fusion/views/space-search-view'
import { SpaceApiKeysView } from '@/components/fusion/views/space-api-keys-view'
import { PolicyView } from '@/components/fusion/views/policy-view'
import { UsersView } from '@/components/fusion/views/users-view'
import { SystemLogsView } from '@/components/fusion/views/system-logs-view'
import { SettingsView } from '@/components/fusion/views/settings-view'
import { WorkersView } from '@/components/fusion/views/workers-view'
import { AIChatView } from '@/components/fusion/views/ai-chat-view'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})

type ViewKey =
  | 'dashboard'
  | 'ai-chat'
  | 'web-scan'
  | 'port-scan'
  | 'subdomain-scan'
  | 'weak-password-scan'
  | 'directory-scan'
  | 'js-scan'
  | 'tasks'
  | 'task-detail'
  | 'task-logs'
  | 'scan-results'
  | 'fingerprints'
  | 'pocs'
  | 'poc-builder'
  | 'poc-tasks'
  | 'poc-results'
  | 'report-export'
  | 'vuln-verify'
  | 'rtsp-scan'
  | 'dictionary-subdomain-prefix'
  | 'dictionary-directory-path'
  | 'dictionary-weak-username'
  | 'dictionary-weak-password'
  | 'dictionary-js-sensitive'
  | 'dictionary-js-route'
  | 'dictionary-js-auth'
  | 'rtsp-dictionary'
  | 'ip-query'
  | 'space-search'
  | 'space-api-keys'
  | 'policies'
  | 'settings'
  | 'users'
  | 'system-logs'
  | 'workers'

type ThemeKey =
  | 'vercel'
  | 'vercel-dark'
  | 'violet-bloom'
  | 'bubblegum'
  | 'quantum-rose'
  | 'clean-slate'
  | 'cosmic-night'
  | 'cyberpunk'
  | 'eva-unit-01'

const navSections: Array<{
  title: string
  items: Array<{ key: ViewKey; label: string; icon: React.ElementType }>
}> = [
  {
    title: '扫描功能',
    items: [
      { key: 'dashboard', label: '仪表盘', icon: LayoutDashboard },
      { key: 'web-scan', label: 'Web扫描', icon: Globe2 },
      { key: 'port-scan', label: '端口扫描', icon: Network },
      { key: 'subdomain-scan', label: '子域名扫描', icon: Layers3 },
      { key: 'weak-password-scan', label: '弱口令扫描', icon: KeyRound },
      { key: 'directory-scan', label: '目录扫描', icon: FolderOpen },
      { key: 'js-scan', label: 'JS扫描', icon: Code2 },
      { key: 'rtsp-scan', label: 'RTSP扫描', icon: RadioTower },
    ],
  },
  {
    title: 'AI 助手',
    items: [{ key: 'ai-chat', label: 'AI 对话', icon: Bot }],
  },
  {
    title: '空间测绘',
    items: [
      { key: 'space-search', label: '在线搜索', icon: Search },
      { key: 'space-api-keys', label: 'API密钥配置', icon: KeyRound },
    ],
  },
  {
    title: '任务管理',
    items: [
      { key: 'tasks', label: '任务列表', icon: ListChecks },
      { key: 'task-logs', label: '运行日志', icon: History },
      { key: 'scan-results', label: '结果中心', icon: Network },
      { key: 'report-export', label: '报告导出', icon: FileDown },
    ],
  },
  {
    title: '模板与验证',
    items: [
      { key: 'fingerprints', label: '指纹管理', icon: Fingerprint },
      { key: 'pocs', label: '模板管理', icon: FileCode2 },
      { key: 'poc-builder', label: '模板生成', icon: Plus },
      { key: 'poc-tasks', label: '模板任务', icon: ListChecks },
      { key: 'poc-results', label: '模板结果', icon: ShieldAlert },
      { key: 'vuln-verify', label: '漏洞验证', icon: ShieldBan },
      { key: 'ip-query', label: 'IP 查询', icon: Globe2 },
    ],
  },
  {
    title: '字典管理',
    items: [
      { key: 'dictionary-subdomain-prefix', label: '子域名前缀', icon: Layers3 },
      { key: 'dictionary-directory-path', label: '目录路径', icon: FolderOpen },
      { key: 'dictionary-weak-username', label: '弱口令账号', icon: KeyRound },
      { key: 'dictionary-weak-password', label: '弱口令密码', icon: KeyRound },
      { key: 'dictionary-js-sensitive', label: 'JS敏感关键词', icon: Code2 },
      { key: 'dictionary-js-route', label: 'JS高危路由', icon: Code2 },
      { key: 'dictionary-js-auth', label: 'JS鉴权关键词', icon: Code2 },
      { key: 'rtsp-dictionary', label: 'RTSP字典', icon: Database },
    ],
  },
  {
    title: '系统设置',
    items: [
      { key: 'policies', label: '策略管理', icon: Database },
      { key: 'settings', label: '钉钉机器人配置', icon: KeyRound },
      { key: 'users', label: '用户管理', icon: Users },
      { key: 'system-logs', label: '日志审计', icon: Terminal },
      { key: 'workers', label: '节点管理', icon: Server },
    ],
  },
]

const viewLabels = Object.fromEntries(navSections.flatMap((section) => section.items.map((item) => [item.key, item.label]))) as Record<string, string>

const viewPaths: Record<ViewKey, string> = {
  dashboard: '/dashboard',
  'ai-chat': '/ai/chat',
  'web-scan': '/scans/web',
  'port-scan': '/scans/port',
  'subdomain-scan': '/scans/subdomain',
  'weak-password-scan': '/scans/weak-password',
  'directory-scan': '/scans/directory',
  'js-scan': '/scans/js',
  tasks: '/tasks',
  'task-detail': '/tasks/detail',
  'task-logs': '/tasks/logs',
  'scan-results': '/results',
  fingerprints: '/fingerprints',
  pocs: '/pocs',
  'poc-builder': '/pocs/builder',
  'poc-tasks': '/pocs/tasks',
  'poc-results': '/pocs/results',
  'report-export': '/tasks/reports',
  'vuln-verify': '/vuln-verify',
  'rtsp-scan': '/rtsp/scan',
  'dictionary-subdomain-prefix': '/dictionaries/subdomain-prefix',
  'dictionary-directory-path': '/dictionaries/directory-path',
  'dictionary-weak-username': '/dictionaries/weak-username',
  'dictionary-weak-password': '/dictionaries/weak-password',
  'dictionary-js-sensitive': '/dictionaries/js-sensitive',
  'dictionary-js-route': '/dictionaries/js-route',
  'dictionary-js-auth': '/dictionaries/js-auth',
  'rtsp-dictionary': '/rtsp/dictionary',
  'ip-query': '/ip-query',
  'space-search': '/space/search',
  'space-api-keys': '/space/api-keys',
  policies: '/system/policies',
  settings: '/system/settings',
  users: '/system/users',
  'system-logs': '/system/logs',
  workers: '/system/workers',
}

type TaskNotificationSource = 'scan' | 'poc'
type TaskNotificationTone = 'success' | 'danger' | 'warning' | 'neutral' | 'info' | 'accent'

type TaskSnapshot = {
  id: string
  name: string
  status: string
  source: TaskNotificationSource
  category: string
}

const scanTaskCategoryLabels: Record<string, string> = {
  web: 'Web扫描',
  port: '端口扫描',
  subdomain: '子域名扫描',
  weak_password: '弱口令扫描',
  directory: '目录扫描',
  js: 'JS扫描',
}

const splitScanViews: Array<{ key: ViewKey; type: ScanTaskType }> = [
  { key: 'web-scan', type: 'web' },
  { key: 'port-scan', type: 'port' },
  { key: 'subdomain-scan', type: 'subdomain' },
  { key: 'weak-password-scan', type: 'weak_password' },
  { key: 'directory-scan', type: 'directory' },
  { key: 'js-scan', type: 'js' },
]

const dictionaryViews: Array<{ key: ViewKey; type: ScanDictionaryType }> = [
  { key: 'dictionary-subdomain-prefix', type: 'subdomain_prefix' },
  { key: 'dictionary-directory-path', type: 'directory_path' },
  { key: 'dictionary-weak-username', type: 'weak_username' },
  { key: 'dictionary-weak-password', type: 'weak_password' },
  { key: 'dictionary-js-sensitive', type: 'js_sensitive_keyword' },
  { key: 'dictionary-js-route', type: 'js_route_keyword' },
  { key: 'dictionary-js-auth', type: 'js_auth_keyword' },
]

function KeepAliveView({ active, children }: { active: boolean; children: React.ReactNode }) {
  const [mounted, setMounted] = React.useState(active)

  React.useEffect(() => {
    if (active) setMounted(true)
  }, [active])

  if (!mounted) return null
  return (
    <div className={active ? 'contents' : 'hidden'} aria-hidden={!active}>
      {children}
    </div>
  )
}

type TaskNotification = TaskSnapshot & {
  notificationId: string
  title: string
  description: string
  tone: TaskNotificationTone
  createdAt: number
  unread: boolean
}

const activeTaskStatuses = new Set(['pending', 'queued', 'created', 'starting', 'running', 'executing', 'scanning', 'paused', 'canceling'])
const terminalTaskStatuses = new Set(['completed', 'failed', 'cancelled', 'stopped'])

function normalizeTaskStatus(status?: string) {
  const value = String(status || '').trim().toLowerCase()
  if (!value) return ''
  if (['complete', 'completed', 'done', 'finished', 'finish', 'success', 'succeeded', '已完成', '完成', '成功'].includes(value)) return 'completed'
  if (['fail', 'failed', 'failure', 'error', 'errored', '已失败', '失败', '异常'].includes(value)) return 'failed'
  if (['cancelled', 'canceled', 'cancel', '已取消', '取消'].includes(value)) return 'cancelled'
  if (['stopped', 'stop', '已停止', '停止'].includes(value)) return 'stopped'
  if (['wait', 'waiting', 'queued', 'created', 'pending', '等待中'].includes(value)) return 'pending'
  if (['run', 'running', 'executing', 'scanning', '扫描中', '运行中', '执行中'].includes(value)) return 'running'
  if (['pause', 'paused', '已暂停', '暂停'].includes(value)) return 'paused'
  if (['canceling', 'cancelling', '取消中'].includes(value)) return 'canceling'
  return value
}

function isActiveTaskStatus(status?: string) {
  return activeTaskStatuses.has(normalizeTaskStatus(status))
}

function isTerminalTaskStatus(status?: string) {
  return terminalTaskStatuses.has(normalizeTaskStatus(status))
}

function getTaskStatusText(status?: string) {
  const normalized = normalizeTaskStatus(status)
  if (normalized === 'stopped') return '已停止'
  return getStatusLabel(normalized)
}

function getTaskNotificationTone(status?: string): TaskNotificationTone {
  const normalized = normalizeTaskStatus(status)
  if (normalized === 'completed') return 'success'
  if (normalized === 'failed') return 'danger'
  if (normalized === 'cancelled' || normalized === 'stopped') return 'warning'
  return 'neutral'
}

function getTaskNotificationKey(source: TaskNotificationSource, id: string) {
  return `${source}:${id}`
}

function pickTaskId(task: any) {
  return String(task?.taskID || task?.taskId || task?.task_id || task?.id || '').trim()
}

function pickTaskName(task: any, fallback: string) {
  return String(task?.taskName || task?.task_name || task?.name || fallback || '未命名任务').trim()
}

function buildScanTaskSnapshot(task: TaskRow): TaskSnapshot | null {
  const id = pickTaskId(task)
  if (!id) return null
  const taskType = String(task.taskType || task.task_type || '').toLowerCase()
  return {
    id,
    name: pickTaskName(task, id),
    status: normalizeTaskStatus(task.status),
    source: 'scan',
    category: scanTaskCategoryLabels[taskType] || '扫描任务',
  }
}

function buildPocTaskSnapshot(task: any): TaskSnapshot | null {
  const id = pickTaskId(task)
  if (!id) return null
  return {
    id,
    name: pickTaskName(task, id),
    status: normalizeTaskStatus(task?.status),
    source: 'poc',
    category: '模板扫描',
  }
}

function showTaskToast(notification: TaskNotification) {
  const message = `${notification.category}${getTaskStatusText(notification.status)}：${notification.name}`
  const status = normalizeTaskStatus(notification.status)
  if (status === 'completed') toast.success(message)
  else if (status === 'failed') toast.error(message)
  else toast.warning(message)
}

const themes: Array<{
  key: ThemeKey
  label: string
  labelZh: string
  dark: boolean
  icon: React.ElementType
  swatches: string[]
}> = [
  { key: 'vercel', label: 'Vercel', labelZh: '极简白', dark: false, icon: Sun, swatches: ['#ffffff', '#111111', '#dcdcdf'] },
  { key: 'vercel-dark', label: 'Vercel Dark', labelZh: '极简黑', dark: true, icon: Moon, swatches: ['#000000', '#fafafa', '#262626'] },
  { key: 'violet-bloom', label: 'Violet Bloom', labelZh: '紫藤花', dark: false, icon: Palette, swatches: ['#fbf7ff', '#7c3aed', '#decdf3'] },
  { key: 'bubblegum', label: 'Bubblegum', labelZh: '泡泡糖', dark: false, icon: Palette, swatches: ['#fff7fb', '#db2777', '#f5bfd6'] },
  { key: 'quantum-rose', label: 'Quantum Rose', labelZh: '量子玫瑰', dark: true, icon: Palette, swatches: ['#130810', '#f472b6', '#4b243e'] },
  { key: 'clean-slate', label: 'Clean Slate', labelZh: '清爽蓝灰', dark: false, icon: Sun, swatches: ['#f8fafc', '#0284c7', '#cbd5e1'] },
  { key: 'cosmic-night', label: 'Cosmic Night', labelZh: '宇宙夜', dark: true, icon: Moon, swatches: ['#050712', '#60a5fa', '#27324a'] },
  { key: 'cyberpunk', label: 'Cyberpunk', labelZh: '赛博朋克', dark: true, icon: Palette, swatches: ['#090b0f', '#22d3ee', '#ff2d75'] },
  { key: 'eva-unit-01', label: 'EVA Unit-01', labelZh: '初号机', dark: true, icon: Palette, swatches: ['#0c0712', '#a855f7', '#84cc16'] },
]

function applyTheme(themeKey: string) {
  if (typeof document === 'undefined') return
  const theme = themes.find((item) => item.key === themeKey) || themes[0]
  const root = document.documentElement
  root.dataset.theme = theme.key
  root.classList.remove('light', 'dark')
  root.classList.add(theme.dark ? 'dark' : 'light')
}

function useThemeState() {
  const [theme, setThemeState] = React.useState<ThemeKey>('vercel')

  React.useEffect(() => {
    const saved = localStorage.getItem('fusionweb-theme')
    const resolved = themes.some((item) => item.key === saved) ? (saved as ThemeKey) : ((document.documentElement.dataset.theme as ThemeKey) || 'vercel')
    setThemeState(resolved)
    applyTheme(resolved)
  }, [])

  const setTheme = React.useCallback((nextTheme: ThemeKey) => {
    localStorage.setItem('fusionweb-theme', nextTheme)
    setThemeState(nextTheme)
    applyTheme(nextTheme)
  }, [])

  return { theme, setTheme }
}

export default function FusionApp() {
  return (
    <QueryClientProvider client={queryClient}>
      <FusionRuntime />
    </QueryClientProvider>
  )
}

function FusionRuntime() {
  const [status, setStatus] = React.useState<'checking' | 'runtime-error' | 'login' | 'authenticated'>('checking')
  const [user, setUser] = React.useState<UserProfile | null>(null)
  const [runtimeError, setRuntimeError] = React.useState('')
  const [appTitle, setAppTitle] = React.useState('FusionWeb')
  const { theme, setTheme } = useThemeState()
  const activeTheme = themes.find((item) => item.key === theme) || themes[0]

  React.useEffect(() => {
    let cancelled = false

    const clearSession = () => {
      localStorage.removeItem('token')
      localStorage.removeItem('user')
      localStorage.removeItem('role')
      setUser(null)
    }

    const bootstrap = async () => {
      initPublicKey().catch(() => undefined)
      try {
        const appConfigResponse = await getPublicAppConfig()
        if (cancelled) return
        const nextTitle = unwrap<PublicAppConfig>(appConfigResponse)?.title?.trim() || 'FusionWeb'
        setAppTitle(nextTitle)
        document.title = nextTitle
      } catch (error: any) {
        if (cancelled) return
        clearSession()
        setRuntimeError(error?.message || '无法连接 FusionWeb API')
        setStatus('runtime-error')
        return
      }

      if (!localStorage.getItem('token')) {
        setStatus('login')
        return
      }

      try {
        const response = await getProfile()
        if (cancelled) return
        setUser(unwrap<UserProfile>(response))
        setStatus('authenticated')
      } catch {
        if (cancelled) return
        clearSession()
        setStatus('login')
      }
    }

    bootstrap()
    const handleExpired = () => setStatus('login')
    window.addEventListener('token-expired', handleExpired)
    return () => {
      cancelled = true
      window.removeEventListener('token-expired', handleExpired)
    }
  }, [])

  const handleLogout = React.useCallback(async () => {
    await logout().catch(() => undefined)
    localStorage.removeItem('token')
    localStorage.removeItem('user')
    localStorage.removeItem('role')
    setUser(null)
    setStatus('login')
  }, [])

  const toaster = <Toaster theme={activeTheme.dark ? 'dark' : 'light'} richColors position="top-right" style={{ '--width': '260px' } as React.CSSProperties} />

  if (status === 'checking') {
    return (
      <>
        <div className="flex h-screen items-center justify-center bg-background text-muted">
          <Loader2 className="mr-2 size-5 animate-spin" />
          正在连接 FusionWeb 服务...
        </div>
        {toaster}
      </>
    )
  }

  if (status === 'runtime-error') {
    return (
      <>
        <RuntimeConfigErrorView error={runtimeError} appTitle={appTitle} />
        {toaster}
      </>
    )
  }

  if (status === 'login') {
    return (
      <>
        <LoginView appTitle={appTitle} onSuccess={(nextUser) => { setUser(nextUser); setStatus('authenticated') }} />
        {toaster}
      </>
    )
  }

  // 首次登录（初始密码未修改）强制停留在改密页面，后端也会拦截其他接口。
  if (status === 'authenticated' && user?.mustChangePassword) {
    const resetToLogin = () => {
      localStorage.removeItem('token')
      localStorage.removeItem('user')
      localStorage.removeItem('role')
      setUser(null)
      setStatus('login')
      // Basic Auth 与登录密码同步，刷新让浏览器用新密码重新认证。
      if (typeof window !== 'undefined') window.location.reload()
    }
    return (
      <>
        <ForcedPasswordChangeView appTitle={appTitle} user={user} onDone={resetToLogin} onLogout={handleLogout} />
        {toaster}
      </>
    )
  }

  return (
    <>
      <AppShell demoMode={false} appTitle={appTitle} theme={theme} onThemeChange={setTheme} user={user} onLogout={handleLogout} />
      {toaster}
    </>
  )
}

function RuntimeConfigErrorView({ error, appTitle }: { error: string; appTitle: string }) {
  return (
    <main className="flex min-h-screen items-center justify-center bg-background p-4 text-foreground md:p-6">
      <div className="w-full max-w-3xl rounded-card border border-border bg-card shadow-sm">
        <div className="flex flex-col gap-3 border-b border-border px-5 py-4 md:flex-row md:items-center md:justify-between">
          <div className="flex min-w-0 items-center gap-3">
            <div className="flex size-10 shrink-0 items-center justify-center overflow-hidden">
              <img src={logoImage.src} alt={appTitle} className="h-full w-full object-contain" />
            </div>
            <div className="min-w-0">
              <h1 className="text-lg font-semibold leading-6">{appTitle} 服务连接异常</h1>
              <p className="mt-1 text-sm text-muted">API 或运行依赖尚未就绪</p>
            </div>
          </div>
          <Button type="button" variant="outline" onClick={() => window.location.reload()}>
            <RefreshCw className="size-4" />
            重新检查
          </Button>
        </div>
        <div className="grid gap-4 p-5">
          <div className="rounded-card border border-danger/25 bg-danger/10 p-4 text-sm leading-6 text-danger-foreground">
            {error || '无法连接 FusionWeb API，请检查容器状态和运行依赖。'}
          </div>
          <div className="grid gap-2 text-sm leading-6 text-muted">
            <p>请检查 <code className="rounded bg-raised px-1.5 py-0.5">.env</code>、容器状态和 API 日志：</p>
            <pre className="overflow-auto rounded-card border border-border bg-background p-3 font-mono text-xs text-foreground">docker compose ps{'\n'}docker compose logs --tail 200 fusionweb-api</pre>
          </div>
        </div>
      </div>
    </main>
  )
}

const loginSchema = z.object({
  username: z.string().min(2, '用户名至少 2 位'),
  password: z.string().min(6, '密码至少 6 位'),
})

type LoginFormValues = z.infer<typeof loginSchema>

function LoginView({ appTitle, onSuccess }: { appTitle: string; onSuccess: (user: UserProfile) => void }) {
  const form = useForm<LoginFormValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { username: '', password: '' },
  })
  const username = form.watch('username')
  const password = form.watch('password')
  const [submitting, setSubmitting] = React.useState(false)

  React.useEffect(() => {
    form.reset({ username: '', password: '' })
  }, [form])

  const submit = form.handleSubmit(async (values) => {
    setSubmitting(true)
    try {
      const encryptedLogin = async (forceKey = false) => {
        const publicKey = await initPublicKey(forceKey)
        return login({
          username: await encryptUsername(values.username.trim(), publicKey),
          password: await encryptPassword(values.password.trim(), publicKey),
        })
      }

      let response: any
      try {
        response = await encryptedLogin(false)
      } catch (error: any) {
        if (String(error?.message || '').includes('安全验证失败')) response = await encryptedLogin(true)
        else throw error
      }

      const payload = response?.code !== undefined ? response : response?.data?.code !== undefined ? response.data : response
      const data = payload?.data?.token ? payload.data : payload?.token ? payload : null
      if (payload?.code === 0 && data?.token) {
        localStorage.setItem('token', data.token)
        localStorage.setItem('user', JSON.stringify(data.user || {}))
        localStorage.setItem('role', data.user?.role || 'user')
        toast.success('登录成功')
        onSuccess(data.user || { username: values.username.trim() })
      } else {
        toast.error(payload?.message || '登录失败')
      }
    } catch (error: any) {
      clearPublicKey()
      toast.error(error?.message || '登录失败')
    } finally {
      setSubmitting(false)
    }
  })

  return (
    <main className="flex h-screen items-center justify-center bg-background p-6 text-foreground">
      <Card className="w-full max-w-[420px]">
        <CardContent className="p-8">
          <div className="mb-8 text-center">
            <div className="mx-auto mb-4 flex size-16 items-center justify-center overflow-hidden">
              <img src={logoImage.src} alt={appTitle} className="h-full w-full object-contain" />
            </div>
            <h1 className="text-2xl font-bold">{appTitle}</h1>
            <p className="mt-2 text-sm text-muted">安全扫描平台</p>
          </div>
          <form className="grid gap-4" autoComplete="off" onSubmit={submit}>
            <Field label="用户名">
              <Input autoComplete="new-password" placeholder="请输入用户名" {...form.register('username')} value={username || ''} />
            </Field>
            <Field label="密码">
              <Input type="password" autoComplete="new-password" placeholder="请输入密码" {...form.register('password')} value={password || ''} />
            </Field>
            <Button type="submit" variant="default" disabled={submitting}>
              {submitting ? <Loader2 className="size-4 animate-spin" /> : <KeyRound className="size-4" />}
              登录
            </Button>
          </form>
        </CardContent>
      </Card>
    </main>
  )
}

function AppShell({
  demoMode,
  appTitle,
  theme,
  onThemeChange,
  user,
  onLogout,
}: {
  demoMode: boolean
  appTitle: string
  theme: ThemeKey
  onThemeChange: (theme: ThemeKey) => void
  user: UserProfile | null
  onLogout: () => void
}) {
  const [view, setView] = React.useState<ViewKey>('dashboard')
  const [activeTaskId, setActiveTaskId] = React.useState('')
  const [aiContext, setAIContext] = React.useState('')
  const [collapsed, setCollapsed] = React.useState(false)
  const [collapsedSections, setCollapsedSections] = React.useState<Record<string, boolean>>({})
  const queryClient = useQueryClient()
  const [notificationOpen, setNotificationOpen] = React.useState(false)
  const [notifications, setNotifications] = React.useState<TaskNotification[]>([])
  const previousTaskSnapshotsRef = React.useRef<Map<string, TaskSnapshot>>(new Map())
  const initializedTaskSnapshotsRef = React.useRef(false)
  const notifiedTerminalStatesRef = React.useRef<Set<string>>(new Set())

  const scanTasksQuery = useQuery({
    queryKey: ['tasks'],
    queryFn: getTasks,
    enabled: !demoMode,
    refetchInterval: 3000,
  })
  const pocTasksQuery = useQuery({
    queryKey: ['poc-tasks'],
    queryFn: () => getPocTaskList({ page: 1, pageSize: 300 }),
    enabled: !demoMode,
    refetchInterval: 3000,
  })

  const taskSnapshots = React.useMemo(() => {
    const scanSnapshots = asList<TaskRow>(scanTasksQuery.data).map(buildScanTaskSnapshot).filter((item): item is TaskSnapshot => Boolean(item))
    const pocSnapshots = asList<any>(pocTasksQuery.data).map(buildPocTaskSnapshot).filter((item): item is TaskSnapshot => Boolean(item))
    return [...scanSnapshots, ...pocSnapshots]
  }, [pocTasksQuery.data, scanTasksQuery.data])

  const addTaskNotification = React.useCallback((snapshot: TaskSnapshot) => {
    const status = normalizeTaskStatus(snapshot.status)
    if (!isTerminalTaskStatus(status)) return
    const taskKey = getTaskNotificationKey(snapshot.source, snapshot.id)
    const terminalKey = `${taskKey}:${status}`
    if (notifiedTerminalStatesRef.current.has(terminalKey)) return
    notifiedTerminalStatesRef.current.add(terminalKey)

    const notification: TaskNotification = {
      ...snapshot,
      status,
      notificationId: `${terminalKey}:${Date.now()}`,
      title: `${snapshot.category}${getTaskStatusText(status)}`,
      description: snapshot.name,
      tone: getTaskNotificationTone(status),
      createdAt: Date.now(),
      unread: true,
    }

    setNotifications((items) => [notification, ...items].slice(0, 30))
    showTaskToast(notification)
  }, [])

  React.useEffect(() => {
    if (demoMode) return

    const nextSnapshots = new Map<string, TaskSnapshot>()
    for (const snapshot of taskSnapshots) {
      const taskKey = getTaskNotificationKey(snapshot.source, snapshot.id)
      nextSnapshots.set(taskKey, snapshot)

      if (isActiveTaskStatus(snapshot.status)) {
        terminalTaskStatuses.forEach((status) => notifiedTerminalStatesRef.current.delete(`${taskKey}:${status}`))
      }

      const previous = previousTaskSnapshotsRef.current.get(taskKey)
      if (initializedTaskSnapshotsRef.current && previous && isActiveTaskStatus(previous.status) && isTerminalTaskStatus(snapshot.status)) {
        addTaskNotification(snapshot)
      }
    }

    previousTaskSnapshotsRef.current = nextSnapshots
    initializedTaskSnapshotsRef.current = true
  }, [addTaskNotification, demoMode, taskSnapshots])

  const handleWebSocketMessage = React.useCallback((message: any) => {
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('fusionweb-realtime', { detail: message }))
    }
    const eventType = String(message?.type || '')
    if (eventType === 'recon.found') {
      const data = message?.data || message
      const id = pickTaskId(data)
      const resultType = String(data?.resultType || data?.result_type || '').trim().toLowerCase()
      if (!id) return
      if (resultType) {
        queryClient.invalidateQueries({ queryKey: ['task-recon', id, resultType] })
        queryClient.invalidateQueries({ queryKey: ['scan-results-center', id, resultType] })
      } else {
        queryClient.invalidateQueries({ queryKey: ['task-recon', id] })
        queryClient.invalidateQueries({ queryKey: ['scan-results-center', id] })
      }
      queryClient.invalidateQueries({ queryKey: ['task-detail', id] })
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
      return
    }
    if (eventType !== 'task.status' && eventType !== 'task-status') return

    const data = message?.data || message
    const source: TaskNotificationSource = eventType === 'task-status' ? 'poc' : 'scan'
    const id = pickTaskId(data)
    const status = normalizeTaskStatus(data?.status)
    if (!id) return
    const taskKey = getTaskNotificationKey(source, id)
    const existing = previousTaskSnapshotsRef.current.get(taskKey)
    if (isActiveTaskStatus(status)) {
      terminalTaskStatuses.forEach((terminalStatus) => notifiedTerminalStatesRef.current.delete(`${taskKey}:${terminalStatus}`))
      previousTaskSnapshotsRef.current.set(taskKey, {
        id,
        name: existing?.name || pickTaskName(data, id),
        status,
        source,
        category: existing?.category || (source === 'poc' ? '模板扫描' : '扫描任务'),
      })
      return
    }
    if (!isTerminalTaskStatus(status)) return

    addTaskNotification({
      id,
      name: existing?.name || pickTaskName(data, id),
      status,
      source,
      category: existing?.category || (source === 'poc' ? '模板扫描' : '扫描任务'),
    })
    queryClient.invalidateQueries({ queryKey: ['tasks'] })
    if (source === 'poc') queryClient.invalidateQueries({ queryKey: ['poc-tasks'] })
  }, [addTaskNotification, queryClient])

  React.useEffect(() => {
    if (demoMode || typeof window === 'undefined') return

    let closed = false
    let socket: WebSocket | null = null
    let reconnectTimer: number | undefined

    const connect = () => {
      socket = new WebSocket(getWebSocketURL('/ws'))
      socket.onopen = () => {
        socket?.send(JSON.stringify({ action: 'subscribe', events: ['task.status', 'task-status', 'recon.found', 'debug-scan-progress', 'rtsp.log', 'rtsp.progress', 'rtsp.result', 'rtsp.status'] }))
      }
      socket.onmessage = (event) => {
        try {
          handleWebSocketMessage(JSON.parse(event.data))
        } catch {
          // Ignore malformed realtime messages; polling still keeps task notifications current.
        }
      }
      socket.onerror = () => socket?.close()
      socket.onclose = () => {
        if (closed) return
        reconnectTimer = window.setTimeout(connect, 3000)
      }
    }

    connect()
    return () => {
      closed = true
      if (reconnectTimer) window.clearTimeout(reconnectTimer)
      socket?.close()
    }
  }, [demoMode, handleWebSocketMessage])

  React.useEffect(() => {
    if (!notificationOpen) return
    const close = () => setNotificationOpen(false)
    window.addEventListener('click', close)
    return () => window.removeEventListener('click', close)
  }, [notificationOpen])

  const unreadNotificationCount = notifications.filter((item) => item.unread).length
  const unreadBadge = unreadNotificationCount > 99 ? '99+' : String(unreadNotificationCount)

  const recordViewVisit = React.useCallback((nextView: ViewKey, label?: string) => {
    if (demoMode) return
    recordAccessVisit({ path: viewPaths[nextView] || `/${nextView}`, label: label || viewLabels[nextView] || nextView }).catch(() => undefined)
  }, [demoMode])

  const navigateToView = React.useCallback((nextView: ViewKey, label?: string) => {
    setView(nextView)
    setCollapsedSections((sections) => {
      const owner = navSections.find((section) => section.items.some((item) => item.key === nextView))
      if (!owner || !sections[owner.title]) return sections
      return { ...sections, [owner.title]: false }
    })
    recordViewVisit(nextView, label)
  }, [recordViewVisit])

  const toggleNotifications = React.useCallback(() => {
    if (!notificationOpen) setNotifications((items) => items.map((item) => ({ ...item, unread: false })))
    setNotificationOpen((open) => !open)
  }, [notificationOpen])

  const openNotificationTarget = React.useCallback((notification: TaskNotification) => {
    setNotifications((items) => items.map((item) => item.notificationId === notification.notificationId ? { ...item, unread: false } : item))
    setNotificationOpen(false)
    if (notification.source === 'scan') {
      setActiveTaskId(notification.id)
      navigateToView('task-detail', '任务详情')
    } else {
      navigateToView('poc-tasks')
    }
  }, [navigateToView])

  const openTask = React.useCallback((taskId: string) => {
    setActiveTaskId(taskId)
    navigateToView('task-detail', '任务详情')
  }, [navigateToView])

  const analyzeTaskWithAI = React.useCallback((context: string) => {
    setAIContext(context)
    navigateToView('ai-chat', 'AI 对话')
  }, [navigateToView])

  return (
    <main className="flex h-screen bg-background text-foreground">
      <aside className={cn('hidden shrink-0 border-r border-border bg-sidebar p-2 transition-[width] md:flex md:flex-col', collapsed ? 'w-16' : 'w-52')}>
        <div className={cn('flex h-12 items-center gap-2 px-2', collapsed && 'justify-center px-0')}>
          <div className="flex size-7 items-center justify-center overflow-hidden">
            <img src={logoImage.src} alt={appTitle} className="h-full w-full object-contain" />
          </div>
          {collapsed ? null : <div className="text-base font-bold">{appTitle}</div>}
        </div>
        <div className="mt-2 flex-1 space-y-1 overflow-y-auto pr-1">
          {navSections.map((section) => {
            const sectionCollapsed = collapsedSections[section.title] === true
            return (
              <section key={section.title}>
                {collapsed ? null : (
                  <button
                    type="button"
                    className="flex h-7 w-full items-center justify-between rounded-md px-2 pb-1 text-left text-xs font-semibold text-muted transition-colors hover:bg-raised hover:text-foreground"
                    onClick={() => setCollapsedSections((sections) => ({ ...sections, [section.title]: !sections[section.title] }))}
                  >
                    <span>{section.title}</span>
                    {sectionCollapsed ? <ChevronRight className="size-3.5" /> : <ChevronDown className="size-3.5" />}
                  </button>
                )}
                {collapsed || !sectionCollapsed ? (
                  <div className="grid gap-1">
                    {section.items.map((item) => {
                      const Icon = item.icon
                      return (
                        <button
                          key={item.key}
                          type="button"
                          className={cn(
                            'flex h-8 items-center gap-2 rounded-md px-2 text-sm font-semibold transition-colors',
                            collapsed && 'justify-center px-0',
                            view === item.key ? 'bg-raised text-foreground' : 'text-muted hover:bg-raised hover:text-foreground'
                          )}
                          title={collapsed ? item.label : undefined}
                          onClick={() => navigateToView(item.key)}
                        >
                          <Icon className="size-4" />
                          {collapsed ? null : <span>{item.label}</span>}
                        </button>
                      )
                    })}
                  </div>
                ) : null}
              </section>
            )
          })}
        </div>
        {collapsed ? null : <div className="flex items-center gap-2 px-2 py-3 text-sm font-semibold"><User className="size-4" />{demoMode ? 'preview' : user?.username || 'admin'}</div>}
      </aside>
      <section className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-11 shrink-0 items-center justify-between border-b border-border px-4 md:px-6">
          <div className="flex min-w-0 items-center gap-2">
            <Button variant="ghost" size="icon" onClick={() => setCollapsed((value) => !value)} title={collapsed ? '展开侧边栏' : '收起侧边栏'}>
              {collapsed ? <PanelLeftOpen className="size-4" /> : <PanelLeftClose className="size-4" />}
            </Button>
            <span className="truncate text-sm text-muted">{viewLabels[view] || '任务详情'}</span>
            {demoMode ? <Badge tone="warning">预览模式</Badge> : null}
          </div>
          <div className="flex items-center gap-2">
            <Button className="border-info/30 bg-info/10 text-foreground hover:bg-info/20" variant="outline" onClick={() => navigateToView('web-scan')}>
              <ScanLine className="size-4" />
              快速扫描
            </Button>
            <div className="relative" onClick={(event) => event.stopPropagation()}>
              <Button className="relative" variant="ghost" size="icon" title="通知" onClick={toggleNotifications}>
                <Bell className="size-4" />
                {unreadNotificationCount ? (
                  <span className="absolute -right-1 -top-1 flex min-w-4 items-center justify-center rounded-full border border-background bg-danger px-1 text-[10px] font-bold leading-4 text-white">
                    {unreadBadge}
                  </span>
                ) : null}
              </Button>
              {notificationOpen ? (
                <div className="absolute right-0 top-10 z-50 w-[360px] max-w-[calc(100vw-2rem)] overflow-hidden rounded-card border border-border bg-card shadow-2xl">
                  <div className="flex items-center justify-between gap-3 border-b border-border px-3 py-2">
                    <div className="min-w-0">
                      <div className="text-sm font-semibold text-foreground">任务通知</div>
                      <div className="text-xs text-muted">扫描任务结束后会出现在这里</div>
                    </div>
                    <Button size="sm" variant="ghost" disabled={!notifications.length} onClick={() => setNotifications([])}>
                      清空
                    </Button>
                  </div>
                  <div className="max-h-[420px] overflow-y-auto p-1">
                    {notifications.length ? notifications.map((notification) => (
                      <button
                        key={notification.notificationId}
                        type="button"
                        className="flex w-full gap-3 rounded-md px-2 py-2 text-left transition-colors hover:bg-raised"
                        onClick={() => openNotificationTarget(notification)}
                      >
                        <span className={cn('mt-1 size-2 shrink-0 rounded-full', notification.tone === 'success' && 'bg-success', notification.tone === 'danger' && 'bg-danger', notification.tone === 'warning' && 'bg-warning', notification.tone === 'info' && 'bg-info', notification.tone === 'accent' && 'bg-accent', notification.tone === 'neutral' && 'bg-muted')} />
                        <span className="min-w-0 flex-1">
                          <span className="flex min-w-0 items-center gap-2">
                            <Badge tone={notification.tone}>{notification.title}</Badge>
                            {notification.unread ? <span className="size-1.5 shrink-0 rounded-full bg-danger" /> : null}
                          </span>
                          <span className="mt-1 block truncate text-sm font-medium text-foreground" title={notification.description}>{notification.description}</span>
                          <span className="mt-0.5 block text-xs text-muted">{formatTime(notification.createdAt)}</span>
                        </span>
                      </button>
                    )) : (
                      <div className="flex min-h-28 items-center justify-center px-4 py-6 text-sm text-muted">暂无任务通知</div>
                    )}
                  </div>
                </div>
              ) : null}
            </div>
            <ThemeSwitcher value={theme} onChange={onThemeChange} />
            <Button variant="ghost" size="icon" title="退出登录" onClick={onLogout}>
              <LogOut className="size-4" />
            </Button>
          </div>
        </header>
        <div className="min-h-0 flex-1 overflow-y-auto p-4 [scrollbar-gutter:stable] md:p-6">
          <KeepAliveView active={view === 'dashboard'}><DashboardView demoMode={demoMode} onOpenTask={openTask} /></KeepAliveView>
          <KeepAliveView active={view === 'ai-chat'}><AIChatView initialContext={aiContext} /></KeepAliveView>
          {splitScanViews.map((item) => (
            <KeepAliveView key={item.key} active={view === item.key}>
              <AdvancedScanView demoMode={demoMode} fixedTaskType={item.type} onCreated={() => { setActiveTaskId(''); navigateToView('tasks') }} />
            </KeepAliveView>
          ))}
          <KeepAliveView active={view === 'tasks'}><TasksView demoMode={demoMode} onOpenTask={openTask} /></KeepAliveView>
          <KeepAliveView active={view === 'task-detail'}><TaskDetailView demoMode={demoMode} taskId={activeTaskId} onBack={() => navigateToView('tasks')} onAnalyzeWithAI={analyzeTaskWithAI} /></KeepAliveView>
          <KeepAliveView active={view === 'task-logs'}><TaskLogsView demoMode={demoMode} /></KeepAliveView>
          <KeepAliveView active={view === 'scan-results'}><ScanResultsView demoMode={demoMode} onOpenTask={openTask} onAnalyzeWithAI={analyzeTaskWithAI} /></KeepAliveView>
          <KeepAliveView active={view === 'fingerprints'}><FingerprintView demoMode={demoMode} /></KeepAliveView>
          <KeepAliveView active={view === 'pocs'}><PocView demoMode={demoMode} onCreateTemplate={() => navigateToView('poc-builder')} /></KeepAliveView>
          <KeepAliveView active={view === 'poc-builder'}><PocBuilderView demoMode={demoMode} /></KeepAliveView>
          <KeepAliveView active={view === 'poc-tasks'}><PocTasksView demoMode={demoMode} /></KeepAliveView>
          <KeepAliveView active={view === 'poc-results'}><PocResultsCenterView demoMode={demoMode} /></KeepAliveView>
          <KeepAliveView active={view === 'report-export'}><ReportCenterView demoMode={demoMode} /></KeepAliveView>
          <KeepAliveView active={view === 'vuln-verify'}><VulnVerifyView demoMode={demoMode} /></KeepAliveView>
          <KeepAliveView active={view === 'rtsp-scan'}><RTSPScanView demoMode={demoMode} /></KeepAliveView>
          {dictionaryViews.map((item) => (
            <KeepAliveView key={item.key} active={view === item.key}>
              <ScanDictionaryView demoMode={demoMode} fixedType={item.type} />
            </KeepAliveView>
          ))}
          <KeepAliveView active={view === 'rtsp-dictionary'}><RTSPDictionaryView demoMode={demoMode} /></KeepAliveView>
          <KeepAliveView active={view === 'ip-query'}><IPQueryView demoMode={demoMode} /></KeepAliveView>
          <KeepAliveView active={view === 'space-search'}><SpaceSearchView demoMode={demoMode} /></KeepAliveView>
          <KeepAliveView active={view === 'space-api-keys'}><SpaceApiKeysView demoMode={demoMode} /></KeepAliveView>
          <KeepAliveView active={view === 'policies'}><PolicyView demoMode={demoMode} /></KeepAliveView>
          <KeepAliveView active={view === 'settings'}><SettingsView /></KeepAliveView>
          <KeepAliveView active={view === 'users'}><UsersView demoMode={demoMode} /></KeepAliveView>
          <KeepAliveView active={view === 'system-logs'}><SystemLogsView demoMode={demoMode} /></KeepAliveView>
          <KeepAliveView active={view === 'workers'}><WorkersView /></KeepAliveView>
        </div>
      </section>
    </main>
  )
}

function ThemeSwitcher({ value, onChange }: { value: ThemeKey; onChange: (theme: ThemeKey) => void }) {
  const [open, setOpen] = React.useState(false)
  const activeTheme = themes.find((item) => item.key === value) || themes[0]
  const Icon = activeTheme.icon

  React.useEffect(() => {
    if (!open) return
    const close = () => setOpen(false)
    window.addEventListener('click', close)
    return () => window.removeEventListener('click', close)
  }, [open])

  return (
    <div className="relative" onClick={(event) => event.stopPropagation()}>
      <Button variant="ghost" size="icon" title="切换主题色" onClick={() => setOpen((state) => !state)}>
        <Icon className="size-4" />
      </Button>
      {open ? (
        <div className="absolute right-0 top-10 z-50 w-64 overflow-hidden rounded-card border border-border bg-card p-1 shadow-2xl">
          <div className="px-2 py-1.5 text-xs font-semibold text-muted">切换主题色</div>
          {themes.map((theme) => {
            const selected = theme.key === value
            return (
              <button
                key={theme.key}
                type="button"
                className={cn('flex w-full items-center gap-2 rounded-md px-2 py-2 text-left text-sm transition-colors hover:bg-raised', selected && 'bg-raised text-foreground')}
                onClick={() => {
                  onChange(theme.key)
                  setOpen(false)
                  toast.success(`已切换到 ${theme.labelZh}`)
                }}
              >
                <span className="min-w-0 flex-1">
                  <span className="block truncate">{theme.label}</span>
                  <span className="block truncate text-xs text-muted">{theme.labelZh}</span>
                </span>
                <span className="flex shrink-0 gap-0.5">
                  {theme.swatches.map((color) => <span key={color} className="size-3 rounded-full border border-border" style={{ background: color }} />)}
                </span>
                {selected ? <Check className="size-4" /> : null}
              </button>
            )
          })}
        </div>
      ) : null}
    </div>
  )
}
