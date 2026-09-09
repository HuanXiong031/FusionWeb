'use client'

import request from './request'

export interface UserProfile {
  id?: number
  username: string
  role?: string
  email?: string
  realName?: string
  mustChangePassword?: boolean
}

export interface LoginResponse {
  code: number
  data?: {
    token: string
    user: UserProfile
  }
  message?: string
}

export interface PublicAppConfig {
  title: string
}

export interface WorkerNode {
  name: string
  displayName?: string
  ipAddress?: string
  publicIpAddress?: string
  status: 'online' | 'offline' | string
  os: string
  arch: string
  concurrency: number
  activeTasks: number
  completedTasks: number
  cpuPercent: number
  memoryPercent: number
  version: string
  registeredAt: string
  lastHeartbeat: string
}

export interface WorkerInstallSteps {
  download: string
  run: string
  oneLiner: string
  logs: string
  stop: string
  restart: string
  upgrade: string
}

export interface WorkerInstallCommand {
  ready: boolean
  missing: string[]
  warnings: string[]
  server: string
  workerKey: string
  image: string
  compose: string
  linux: WorkerInstallSteps
  windowsPowerShell: WorkerInstallSteps
  windowsCmd: WorkerInstallSteps
  pgDsn: string
  redisAddr: string
  minioEndpoint: string
  needsRemoteAccess: boolean
  suggestedEnv: string
}

export interface TaskConfig {
  task_id?: string
  task_name: string
  task_type: 'web' | 'port' | 'subdomain' | 'weak_password' | 'directory' | 'js'
  target_input: string
  port_range?: string
  scan_mode?: string
  scan_tool?: string
  scan_options?: string
  thread_count?: number
  port_scan_timeout?: number
  web_timeout?: number
  enable_screenshot?: boolean
  skip_host_discovery?: boolean
  no_icmp_ping?: boolean
  tcp_ping?: boolean
  ports_threshold?: number
  syn_scan_rate?: number
  web_link?: boolean
  selected_dicts?: string
  full_poc_scan?: boolean
  enable_active_fingerprint?: boolean
  assigned_worker?: string
  ding_talk_token?: string
  ding_talk_secret?: string
  ding_talk_key_id?: number
  dingtalk_bot_id?: number
  dingtalk_conversation_id?: string
  dingtalk_conversation_type?: string
  dingtalk_source_user_id?: string
  dingtalk_source_message_id?: string
  [key: string]: any
}

export interface DingTalkBot {
  id?: number
  name: string
  enabled?: boolean
  clientId?: string
  clientSecret?: string
  tenantId?: string
  webhookToken?: string
  webhookSecret?: string
  maskedClientSecret?: string
  maskedWebhookToken?: string
  maskedWebhookSecret?: string
  defaultTargetType?: string
  defaultTargetValue?: string
  clearWebhook?: boolean
  notifyTaskCompleted?: boolean
  notifyTaskFailed?: boolean
  notifyTaskCancelled?: boolean
  notifyBlacklistAdd?: boolean
  notifyBlacklistRemove?: boolean
  notifyWebScanComplete?: boolean
  notifyPortScanComplete?: boolean
  allowTaskCreation?: boolean
  allowAiChat?: boolean
  notificationOnly?: boolean
  streamStatus?: string
  streamLastError?: string
  streamConnectedAt?: string
  migrationPending?: boolean
  createdAt?: string
  updatedAt?: string
}

export interface DingTalkBinding { id?: number; botId: number; userId: number; dingUserId: string; dingUserName?: string; conversationId?: string; enabled?: boolean }
export interface DingTalkMessageDiagnostic { id: number; botId: number; messageId: string; conversationId: string; conversationType: string; senderId: string; senderStaffId: string; content: string; taskId?: string; replyError?: string; repliedAt?: string; createdAt: string }
export interface DingTalkDiagnostics { botId: number; streamStatus: string; bindingCount: number; allowlistCount: number; messageCount: number; latestMessage?: DingTalkMessageDiagnostic }
export interface DingTalkAllowlist { id?: number; botId: number; entryType: 'user' | 'group' | string; entryValue: string; enabled?: boolean; description?: string }

export type AIProvider = 'openai' | 'deepseek' | 'anthropic' | 'openai_compatible' | string

export interface AIAPIKey {
  id?: number
  provider: AIProvider
  name: string
  apiKey?: string
  maskedApiKey?: string
  baseUrl?: string
  model?: string
  enabled?: boolean
  isDefault?: boolean
  description?: string
  lastTestStatus?: string
  lastTestMessage?: string
  lastTestAt?: string
  createdAt?: string
  updatedAt?: string
}

export interface AIChatMessage {
  role: 'system' | 'user' | 'assistant' | string
  content: string
}

export interface AIChatResponse {
  provider: string
  model: string
  content: string
  usage?: Record<string, any>
}

export interface AIAPIKeyTestResult {
  status: string
  message: string
  at: string
}

export interface TaskRow {
  taskID?: string
  taskId?: string
  taskName?: string
  task_name?: string
  taskType?: string
  task_type?: string
  targetInput?: string
  target_input?: string
  status?: string
  assignedWorker?: string
  assigned_worker?: string
  workerID?: string
  workerId?: string
  worker_id?: string
  percentage?: number
  progress?: number
  portCount?: number
  urlCount?: number
  fingerprintCount?: number
  vulnCount?: number
  createTime?: string
  createdAt?: string
  [key: string]: any
}

export interface DashboardStats {
  totalTasks?: number
  runningTasks?: number
  completedTasks?: number
  failedTasks?: number
  pendingTasks?: number
  totalAssets?: number
  totalVulns?: number
  portCount?: number
  siteCount?: number
  subdomainCount?: number
  directoryCount?: number
  jsCount?: number
  weakPasswordCount?: number
  totalFingerprints?: number
  totalPOCs?: number
  totalPocs?: number
  totalTemplates?: number
  totalFingerprintCount?: number
  fingerprintCount?: number
  templateCount?: number
  pocCount?: number
  vulnLevelDist?: Record<string, number>
  fingerprintTop10?: Array<{ name: string; count: number }>
  trendData?: Array<{ date: string; tasks: number; vulns: number }>
}

export interface PageParams {
  page?: number
  pageSize?: number
  keyword?: string
  category?: string
  severity?: string
  createdBy?: number
  sortBy?: string
  sortOrder?: string
}

export interface PocFileRow {
  id?: number
  name?: string
  fileName?: string
  file_name?: string
  relativePath?: string
  relative_path?: string
  category?: string
  severity?: string
  author?: string
  tags?: string[] | string
  description?: string
  updatedAt?: string
  createdAt?: string
  [key: string]: any
}

export interface FingerprintRow {
  name: string
  category?: string
  type?: 'active' | 'passive' | string
  description?: string
  rules?: string[]
  isEnabled?: boolean
  enabled?: boolean
  isBlacklisted?: boolean
  inBlacklist?: boolean
  createdAt?: string
  updatedAt?: string
  [key: string]: any
}

export type RTSPDictionaryType = 'path' | 'username' | 'password'
export type ScanDictionaryType = 'subdomain_prefix' | 'directory_path' | 'weak_username' | 'weak_password' | 'js_sensitive_keyword' | 'js_route_keyword' | 'js_auth_keyword'

export interface RTSPDictionaryItem {
  id?: number
  type: RTSPDictionaryType | string
  value: string
  enabled?: boolean
  createdAt?: string
  updatedAt?: string
  createdBy?: number
}

export interface RTSPScanResult {
  id?: number
  taskId?: string
  target?: string
  host?: string
  port?: number
  uri?: string
  username?: string
  password?: string
  authMethod?: string
  rtspUrl?: string
  response?: string
  status?: string
  userId?: number
  createdAt?: string
}

export interface RTSPScanState {
  taskId: string
  status: string
  progress: number
  totalTargets: number
  completed: number
  found: number
  startedAt?: string
  completedAt?: string
  logs?: Array<{ time: string; level: string; message: string }>
  results?: RTSPScanResult[]
}

export interface RTSPDictionaryImportSummary {
  imported: number
  skipped: number
  total: number
}

export interface ScanDictionaryItem {
  id?: number
  type: ScanDictionaryType | string
  value: string
  enabled?: boolean
  description?: string
  isBuiltin?: boolean
  createdBy?: number
  createdAt?: string
  updatedAt?: string
}

export interface ScanDictionaryImportSummary {
  imported: number
  skipped: number
  total: number
}

export type SpaceProvider = 'fofa' | 'hunter' | 'quake' | 'shodan' | 'zoomeye'

export interface SpaceEngineKey {
  id?: number
  provider: SpaceProvider | string
  name: string
  apiKey?: string
  maskedApiKey?: string
  secretKey?: string
  maskedSecretKey?: string
  version?: string
  enabled?: boolean
  description?: string
  lastTestStatus?: string
  lastTestMessage?: string
  lastTestAt?: string
  createdAt?: string
  updatedAt?: string
}

export interface SpaceSearchResult {
  host?: string
  ip?: string
  port?: number
  protocol?: string
  domain?: string
  title?: string
  server?: string
  country?: string
  city?: string
  banner?: string
  icp?: string
  product?: string
  os?: string
}

export interface SpaceSearchResponse {
  provider: string
  query: string
  page: number
  pageSize: number
  total: number
  list: SpaceSearchResult[]
}

export interface SpaceEngineTestResult {
  success: boolean
  message: string
}

export function login(data: { username: string; password: string }) {
  return request.post<LoginResponse>('/api/auth/login', data)
}

export function getPublicAppConfig() {
  return request.get<{ code: number; data: PublicAppConfig }>('/api/public/app-config', { timeout: 10000 })
}

export function getWorkers() {
  return request.get<{ code: number; data: WorkerNode[]; message?: string }>('/api/v1/workers')
}

export function updateWorker(name: string, data: { displayName?: string; concurrency?: number }) {
  return request.put<{ code: number; data: WorkerNode; message?: string }>(`/api/v1/workers/${encodeURIComponent(name)}`, data)
}

export function deleteWorker(name: string) {
  return request.delete(`/api/v1/workers/${encodeURIComponent(name)}`)
}

export function getWorkerInstallCommand() {
  return request.get<{ code: number; data: WorkerInstallCommand; message?: string }>('/api/v1/workers/install-command')
}

export function getProfile() {
  return request.get<UserProfile>('/api/v1/users/profile')
}

export function logout() {
  return request.post('/api/v1/users/logout')
}

export function changePassword(data: { oldPassword: string; newPassword: string }) {
  return request.put('/api/v1/users/change-password', data)
}

export function getDashboardStats() {
  return request.get<DashboardStats>('/api/v1/dashboard/stats')
}

export function getTasks() {
  return request.get<TaskRow[]>('/api/v1/tasks')
}

export function getTaskDetail(taskId: string) {
  return request.get(`/api/v1/tasks/${taskId}`)
}

export function restartTask(taskId: string) {
  return request.post<{ taskId: string }>(`/api/v1/tasks/${taskId}/restart`)
}

export function createTask(config: TaskConfig) {
  return request.post<{ taskId: string }>('/api/v1/tasks', config, { timeout: 60000 })
}

export function pauseTask(taskId: string) {
  return request.put(`/api/v1/tasks/${taskId}/pause`)
}

export function resumeTask(taskId: string) {
  return request.put(`/api/v1/tasks/${taskId}/resume`)
}

export function stopTask(taskId: string) {
  return request.put(`/api/v1/tasks/${taskId}/stop`)
}

export function deleteTask(taskId: string) {
  return request.delete(`/api/v1/tasks/${taskId}`)
}

export function getTaskProgress(taskId: string) {
  return request.get(`/api/v1/tasks/${taskId}/progress`)
}

export function getTaskLogs(taskId: string, params?: Record<string, any>) {
  return request.get(`/api/v1/tasks/${taskId}/logs`, { params })
}

export function getTaskResults(taskId: string, type?: string) {
  return request.get(`/api/v1/tasks/${taskId}/results`, { params: { type } })
}

export function getReconResults(taskId: string, type?: string) {
  return request.get(`/api/v1/results/${taskId}/recon`, { params: { type } })
}

export function getReconScreenshot(taskId: string, resultId: number | string) {
  return request.get<Blob>(`/api/v1/results/${taskId}/recon/${resultId}/screenshot`, {
    responseType: 'blob',
  })
}

export function getVulnResults(taskId: string) {
  return request.get(`/api/v1/results/${taskId}/vuln`)
}

export function getFingerprintResults(taskId: string) {
  return request.get(`/api/v1/results/${taskId}/fingerprint`)
}

export function getSubdomainResults(taskId: string) {
  return request.get(`/api/v1/results/${taskId}/subdomains`)
}

export function getWeakPasswordResults(taskId: string) {
  return request.get(`/api/v1/results/${taskId}/weak-passwords`)
}

export function getDirectoryResults(taskId: string) {
  return request.get(`/api/v1/results/${taskId}/directories`)
}

export function getJSScanResults(taskId: string) {
  return request.get(`/api/v1/results/${taskId}/js`)
}

export function generateHTMLReport(taskId: string) {
  return request.get<{ filePath: string }>(`/api/v1/reports/${taskId}/html`, { timeout: 60000 })
}

export function generateExcelReport(taskId: string) {
  return request.get<{ filePath: string }>(`/api/v1/reports/${taskId}/excel`, { timeout: 60000 })
}

export function generateMDReport(taskId: string) {
  return request.get<{ filePath: string }>(`/api/v1/reports/${taskId}/markdown`, { timeout: 60000 })
}

export function downloadTaskReport(taskId: string, type: 'html' | 'excel' | 'markdown') {
  return request.get<Blob>(`/api/v1/reports/${taskId}/download/${type}`, {
    timeout: 60000,
    responseType: 'blob',
  })
}

export function getFingerprintsPage(params?: Record<string, any>) {
  return request.get('/api/v1/fingerprints', { params })
}

export function getFingerprintCategories() {
  return request.get<string[]>('/api/v1/fingerprints/categories')
}

export function getAllFingerprints() {
  return request.get<FingerprintRow[]>('/api/v1/fingerprints/all')
}

export function addFingerprint(data: FingerprintRow) {
  return request.post('/api/v1/fingerprints', data)
}

export function updateFingerprint(data: FingerprintRow & { oldName?: string }) {
  return request.put('/api/v1/fingerprints', data)
}

export function deleteFingerprint(name: string) {
  return request.delete(`/api/v1/fingerprints/${encodeURIComponent(name)}`)
}

export function toggleFingerprintEnabled(name: string) {
  return request.put(`/api/v1/fingerprints/${encodeURIComponent(name)}/enabled`)
}

export function toggleFingerprintBlacklist(name: string) {
  return request.put(`/api/v1/fingerprints/${encodeURIComponent(name)}/blacklist`)
}

export function deleteAllFingerprints(createdBy?: number) {
  return request.delete('/api/v1/fingerprints/all', { params: createdBy ? { createdBy } : undefined })
}

export function importFingerprint(yamlContent: string, fileName: string, type?: 'active' | 'passive') {
  return request.post('/api/v1/fingerprints/import', { yamlContent, fileName, type })
}

export function exportFingerprints(type?: 'active' | 'passive' | 'all') {
  return request.get<{ type: string; content: string }>('/api/v1/fingerprints/export', { params: type ? { type } : undefined })
}

export function exportSingleFingerprint(name: string, type: 'active' | 'passive') {
  return request.get<{ type: string; content: string }>('/api/v1/fingerprints/export/single', { params: { name, type } })
}

export function getFingerprintStatistics() {
  return request.get('/api/v1/fingerprints/statistics')
}

export function getPOCList(params?: Record<string, any>) {
  return request.get('/api/v1/poc-files', { params })
}

export function getAllPOCFiles() {
  return request.get('/api/v1/poc-files/all')
}

export function getPOCCategories() {
  return request.get<string[]>('/api/v1/poc-files/categories')
}

export function getPocFileContent(relativePath: string) {
  return request.get<{ content: string }>('/api/v1/poc-files/content', { params: { relativePath } })
}

export function createPocFile(category: string, fileName: string, content: string) {
  return request.post('/api/v1/poc-files', { category, fileName, content })
}

export function updatePocFile(relativePath: string, content: string, category?: string, fileName?: string) {
  return request.put('/api/v1/poc-files', { relativePath, content, category, fileName })
}

export function renamePocFile(oldRelativePath: string, newRelativePath: string) {
  return request.patch('/api/v1/poc-files/rename', { oldRelativePath, newRelativePath })
}

export function deletePOC(idOrPath: number | string) {
  if (typeof idOrPath === 'number') return request.delete(`/api/v1/pocs/${idOrPath}`)
  return request.delete('/api/v1/poc-files', { data: { relativePath: idOrPath } })
}

export function deletePocFile(relativePath: string) {
  return request.delete('/api/v1/poc-files', { data: { relativePath } })
}

export function importPocFile(category: string, fileName: string, base64Content: string) {
  return request.post('/api/v1/poc-files/import', { category, fileName, base64Content }, { timeout: 60000 })
}

export function exportAllPOCs() {
  return request.get<{ type: string; content: string }>('/api/v1/pocs/export/all', { timeout: 60000 })
}

export function exportSelectedPOCs(relativePaths: string[]) {
  return request.post<{ type: string; content: string }>('/api/v1/pocs/export/selected', { relativePaths }, { timeout: 60000 })
}

export function debugScanPOC(templateContent: string, targets: string[], proxy?: string, debug?: boolean, logPackets?: boolean, taskId?: string) {
  return request.post('/api/v1/pocs/debug', { templateContent, targets, proxy, debug, logPackets, taskId }, { timeout: 0 })
}

export function stopDebugScan(taskId: string) {
  return request.post('/api/v1/pocs/debug/stop', { taskId })
}

export function validatePOC(content: string) {
  return request.post('/api/v1/pocs/validate', { content })
}

export function getPocTaskList(params?: Record<string, any>) {
  return request.get('/api/v1/poc-tasks', { params })
}

export function getPocTaskDetail(taskId: string) {
  return request.get(`/api/v1/poc-tasks/${taskId}`)
}

export function createPocTask(taskName: string, targets: string[], selectedPocs: string[], config?: Record<string, any>) {
  return request.post<{ taskId: string }>('/api/v1/poc-tasks', { taskName, targets, selectedPocs, config })
}

export function getPocTaskProgress(taskId: string) {
  return request.get(`/api/v1/poc-tasks/${taskId}/progress`)
}

export function executePocTask(taskId: string) {
  return request.post(`/api/v1/poc-tasks/${taskId}/execute`)
}

export function pausePocTask(taskId: string) {
  return request.put(`/api/v1/poc-tasks/${taskId}/pause`)
}

export function resumePocTask(taskId: string) {
  return request.put(`/api/v1/poc-tasks/${taskId}/resume`)
}

export function stopPocTask(taskId: string) {
  return request.put(`/api/v1/poc-tasks/${taskId}/stop`)
}

export function deletePocTask(taskId: string) {
  return request.delete(`/api/v1/poc-tasks/${taskId}`)
}

export function getPocScanResults(taskId: string, params?: Record<string, any>) {
  return request.get(`/api/v1/poc-results/${taskId}`, { params })
}

export function getPocScanResultDetail(taskId: string, resultId: number | string) {
  return request.get(`/api/v1/poc-results/${taskId}/detail/${resultId}`)
}

export function getPocScanResultStatistics(taskId: string) {
  return request.get(`/api/v1/poc-results/${taskId}/statistics`)
}

export function deletePocScanResult(resultId: number, params?: Record<string, any>) {
  return request.delete(`/api/v1/poc-results/${resultId}`, { params })
}

export function generatePocHTMLReport(taskId: string, params?: Record<string, any>) {
  return request.get<{ filePath: string }>(`/api/v1/poc-reports/${taskId}/html`, { timeout: 60000, params })
}

export function generatePocExcelReport(taskId: string, params?: Record<string, any>) {
  return request.get<{ filePath: string }>(`/api/v1/poc-reports/${taskId}/excel`, { timeout: 60000, params })
}

export function generatePocMDReport(taskId: string, params?: Record<string, any>) {
  return request.get<{ filePath: string }>(`/api/v1/poc-reports/${taskId}/markdown`, { timeout: 60000, params })
}

export function downloadPocReport(taskId: string, type: 'html' | 'excel' | 'markdown') {
  return request.get<Blob>(`/api/v1/poc-reports/${taskId}/download/${type}`, {
    timeout: 60000,
    responseType: 'blob',
  })
}

export function queryIP(ip: string) {
  return request.get(`/api/v1/ip-query?ip=${encodeURIComponent(ip)}`)
}

export function batchQueryIPs(ips: string[]) {
  return request.post('/api/v1/ip-query/batch', { ips })
}

export function reloadIPDB() {
  return request.post('/api/v1/ip-query/reload')
}

export function getIPDBInfo() {
  return request.get('/api/v1/ip-query/info')
}

export function getBlacklistByCategory() {
  return request.get('/api/v1/blacklist/category')
}

export function addToBlacklist(category: string, value: string) {
  return request.post('/api/v1/blacklist', { category, value })
}

export function removeFromBlacklist(category: string, value: string) {
  return request.delete('/api/v1/blacklist', { data: { category, value } })
}

export function saveBlacklistByCategory(config: Record<string, string[]>) {
  return request.post('/api/v1/blacklist/save', config)
}

export function getAccessBlacklistByCategory() {
  return request.get('/api/v1/access-blacklist/category')
}

export function getAccessBlacklistItems() {
  return request.get('/api/v1/access-blacklist')
}

export function addToAccessBlacklist(category: string, value: string, options?: number | { durationMinutes?: number; startsAt?: string; expiresAt?: string }) {
  const payload = typeof options === 'number' ? { durationMinutes: options } : (options || {})
  return request.post('/api/v1/access-blacklist', { category, value, ...payload })
}

export function removeFromAccessBlacklist(category: string, value: string) {
  return request.delete('/api/v1/access-blacklist', { data: { category, value } })
}

export function saveAccessBlacklistByCategory(config: Record<string, string[]>) {
  return request.post('/api/v1/access-blacklist/save', config)
}

export function getDingTalkBots() { return request.get<DingTalkBot[]>('/api/v1/system/dingtalk-bots') }
export function createDingTalkBot(data: DingTalkBot) { return request.post<DingTalkBot>('/api/v1/system/dingtalk-bots', data) }
export function updateDingTalkBot(id: number | string, data: DingTalkBot) { return request.put<DingTalkBot>(`/api/v1/system/dingtalk-bots/${id}`, data) }
export function deleteDingTalkBot(id: number | string) { return request.delete(`/api/v1/system/dingtalk-bots/${id}`) }
export function testDingTalkBot(id: number | string) { return request.post(`/api/v1/system/dingtalk-bots/${id}/test`, {}) }
export function reconnectDingTalkBot(id: number | string) { return request.post(`/api/v1/system/dingtalk-bots/${id}/reconnect`, {}) }
export function getDingTalkBotStatus(id: number | string) { return request.get<DingTalkBot>(`/api/v1/system/dingtalk-bots/${id}/status`) }
export function getDingTalkBotDiagnostics(id: number | string) { return request.get<DingTalkDiagnostics>(`/api/v1/system/dingtalk-bots/${id}/diagnostics`) }
export function generateDingTalkBindingCode(botId: number) { return request.post<{ code: string; expiresAt: string }>(`/api/v1/system/dingtalk-bindings/code`, { botId }) }
export function bindDingTalkUser(data: { botId: number; dingUserId: string; dingUserName?: string; code: string }) { return request.post('/api/v1/system/dingtalk-bindings', data) }
export function listDingTalkBindings(botId: number) { return request.get<DingTalkBinding[]>(`/api/v1/system/dingtalk-bindings?botId=${botId}`) }
export function deleteDingTalkBinding(id: number) { return request.delete(`/api/v1/system/dingtalk-bindings/${id}`) }
export function listDingTalkAllowlist(botId: number) { return request.get<DingTalkAllowlist[]>(`/api/v1/system/dingtalk-allowlist?botId=${botId}`) }
export function saveDingTalkAllowlist(data: DingTalkAllowlist) { return request.post<DingTalkAllowlist>('/api/v1/system/dingtalk-allowlist', data) }
export function updateDingTalkAllowlist(id: number, data: DingTalkAllowlist) { return request.put<DingTalkAllowlist>(`/api/v1/system/dingtalk-allowlist/${id}`, data) }
export function deleteDingTalkAllowlist(id: number) { return request.delete(`/api/v1/system/dingtalk-allowlist/${id}`) }

export function getAIAPIKeys() {
  return request.get<AIAPIKey[]>('/api/v1/system/ai-api-keys')
}

export function createAIAPIKey(data: AIAPIKey) {
  return request.post<AIAPIKey>('/api/v1/system/ai-api-keys', data)
}

export function updateAIAPIKey(id: number | string, data: AIAPIKey) {
  return request.put<AIAPIKey>(`/api/v1/system/ai-api-keys/${id}`, data)
}

export function deleteAIAPIKey(id: number | string) {
  return request.delete(`/api/v1/system/ai-api-keys/${id}`)
}

export function testAIAPIKey(id: number | string) {
  return request.post<AIAPIKeyTestResult>(`/api/v1/system/ai-api-keys/${id}/test`, {}, { timeout: 130000 })
}

export function sendAIChat(data: { keyId?: number; provider?: string; model?: string; systemPrompt?: string; messages: AIChatMessage[]; temperature?: number; maxTokens?: number }) {
  return request.post<AIChatResponse>('/api/v1/ai/chat', data, { timeout: 130000 })
}

export function getUsers(params?: { page?: number; pageSize?: number }) {
  return request.get('/api/v1/users', { params })
}

export function createUser(data: Record<string, any>) {
  return request.post('/api/v1/users', data)
}

export function updateUser(id: number | string, data: Record<string, any>) {
  return request.put(`/api/v1/users/${id}`, data)
}

export function deleteUser(id: number | string) {
  return request.delete(`/api/v1/users/${id}`)
}

export function batchCreateUsers(users: Array<Record<string, any>>) {
  return request.post('/api/v1/users/batch', { users })
}

export function exportUsers() {
  return request.get('/api/v1/users/export', { responseType: 'blob' })
}

export function downloadUserImportTemplate() {
  return request.get('/api/v1/users/import/template', { responseType: 'blob' })
}

export function getVulnVerifyGroups() {
  return request.get('/api/v1/vuln-verify-group')
}

export function addVulnVerifyGroup(name: string) {
  return request.post('/api/v1/vuln-verify-group', { name })
}

export function updateVulnVerifyGroup(id: number, name: string) {
  return request.put(`/api/v1/vuln-verify-group/${id}`, { name })
}

export function deleteVulnVerifyGroup(id: number) {
  return request.delete(`/api/v1/vuln-verify-group/${id}`)
}

export function getManualVulnVerifyList(params?: Record<string, any>) {
  return request.get('/api/v1/vuln-verify', { params })
}

export function getManualVulnVerifyListByGroup(groupId: number) {
  return request.get(`/api/v1/vuln-verify-group/${groupId}/vulns`, { params: { _t: Date.now() } })
}

export function getVulnVerifyWorkbench() {
  return request.get('/api/v1/vuln-verify/workbench')
}

export function saveVulnVerifyWorkbench(data: Record<string, any>) {
  return request.put('/api/v1/vuln-verify/workbench', data)
}

export function addManualVulnVerify(data: { name: string; group_id?: number; groupId?: number; request?: string; response?: string }) {
  return request.post('/api/v1/vuln-verify', data)
}

export function updateManualVulnVerify(id: number, data: Record<string, any>) {
  return request.put(`/api/v1/vuln-verify/${id}`, data)
}

export function deleteManualVulnVerify(id: number) {
  return request.delete(`/api/v1/vuln-verify/${id}`)
}

export function sendRawRequest(data: { method: string; url: string; headers?: Record<string, string>; body?: string; timeout?: number }) {
  return request.post('/api/v1/tools/raw-request', data)
}

export function getLoginLogs(params?: Record<string, any>) {
  return request.get('/api/v1/system/login-logs', { params })
}

export function clearLoginLogs() {
  return request.delete('/api/v1/system/login-logs')
}

export function getAccessLogs(params?: Record<string, any>) {
  return request.get('/api/v1/system/access-logs', { params })
}

export function recordAccessVisit(data: { path?: string; label?: string }) {
  return request.post('/api/v1/system/access-logs/visit', data)
}

export function clearAccessLogs() {
  return request.delete('/api/v1/system/access-logs')
}

export function getOperationLogs(params?: Record<string, any>) {
  return request.get('/api/v1/system/operation-logs', { params })
}

export function clearOperationLogs() {
  return request.delete('/api/v1/system/operation-logs')
}

export function getUnauthorizedAccessLogs(params?: Record<string, any>) {
  return request.get('/api/v1/system/unauthorized-access-logs', { params })
}

export function clearUnauthorizedAccessLogs() {
  return request.delete('/api/v1/system/unauthorized-access-logs')
}

export function getRTSPDictionary(params?: { type?: string; keyword?: string }) {
  return request.get<RTSPDictionaryItem[]>('/api/v1/rtsp/dictionaries', { params })
}

export function getRTSPDictionaryStatistics() {
  return request.get<Record<string, number>>('/api/v1/rtsp/dictionaries/statistics')
}

export function createRTSPDictionary(data: RTSPDictionaryItem) {
  return request.post<RTSPDictionaryItem>('/api/v1/rtsp/dictionaries', data)
}

export function updateRTSPDictionary(id: number | string, data: RTSPDictionaryItem) {
  return request.put<RTSPDictionaryItem>(`/api/v1/rtsp/dictionaries/${id}`, data)
}

export function deleteRTSPDictionary(id: number | string) {
  return request.delete(`/api/v1/rtsp/dictionaries/${id}`)
}

export function deleteRTSPDictionaryByType(type: string) {
  return request.delete('/api/v1/rtsp/dictionaries', { params: { type } })
}

export function importRTSPDictionary(type: string, content: string) {
  return request.post<RTSPDictionaryImportSummary>('/api/v1/rtsp/dictionaries/import', { type, content })
}

export function getScanDictionary(params?: { type?: string; keyword?: string }) {
  return request.get<ScanDictionaryItem[]>('/api/v1/dictionaries/scan', { params })
}

export function getScanDictionaryStatistics() {
  return request.get<Record<string, number>>('/api/v1/dictionaries/scan/statistics')
}

export function createScanDictionary(data: ScanDictionaryItem) {
  return request.post<ScanDictionaryItem>('/api/v1/dictionaries/scan', data)
}

export function updateScanDictionary(id: number | string, data: ScanDictionaryItem) {
  return request.put<ScanDictionaryItem>(`/api/v1/dictionaries/scan/${id}`, data)
}

export function deleteScanDictionary(id: number | string) {
  return request.delete(`/api/v1/dictionaries/scan/${id}`)
}

export function deleteScanDictionaryByType(type: string) {
  return request.delete('/api/v1/dictionaries/scan', { params: { type } })
}

export function importScanDictionary(type: string, content: string) {
  return request.post<ScanDictionaryImportSummary>('/api/v1/dictionaries/scan/import', { type, content })
}

export function startRTSPScan(data: { targets: string[]; port?: number; threadCount?: number; timeout?: number; authMethod?: string }) {
  return request.post<RTSPScanState>('/api/v1/rtsp/scan/start', data, { timeout: 60000 })
}

export function stopRTSPScan(taskId: string) {
  return request.post(`/api/v1/rtsp/scan/${taskId}/stop`)
}

export function getRTSPScanState(taskId: string) {
  return request.get<RTSPScanState>(`/api/v1/rtsp/scan/${taskId}/state`)
}

export function getRTSPResults(params?: { taskId?: string }) {
  return request.get<RTSPScanResult[]>('/api/v1/rtsp/results', { params })
}

export function deleteRTSPResult(id: number | string) {
  return request.delete(`/api/v1/rtsp/results/${id}`)
}

export function getSpaceEngineKeys() {
  return request.get<SpaceEngineKey[]>('/api/v1/space/engines')
}

export function createSpaceEngineKey(data: SpaceEngineKey) {
  return request.post<SpaceEngineKey>('/api/v1/space/engines', data)
}

export function updateSpaceEngineKey(id: number | string, data: SpaceEngineKey) {
  return request.put<SpaceEngineKey>(`/api/v1/space/engines/${id}`, data)
}

export function deleteSpaceEngineKey(id: number | string) {
  return request.delete(`/api/v1/space/engines/${id}`)
}

export function testSpaceEngineKey(id: number | string) {
  return request.post<SpaceEngineTestResult>(`/api/v1/space/engines/${id}/test`)
}

export function searchSpaceOnline(data: { provider: string; query: string; page?: number; pageSize?: number }) {
  return request.post<SpaceSearchResponse>('/api/v1/space/search', data, { timeout: 60000 })
}


