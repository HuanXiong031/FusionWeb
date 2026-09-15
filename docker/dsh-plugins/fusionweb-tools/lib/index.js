// fusionweb-tools —— 把 FusionWeb 安全扫描平台的能力暴露为 DSH 工具。
//
// 设计：
//   * 零依赖、自包含（不 import 任何包），因此可直接放进 profile 的 node_modules；
//   * 工具定义按 dsh-tools 的规范形状手写（parameters/output 为 JSON Schema，render 产出模型可见内容）；
//   * 通过 FusionWeb 的**服务账号令牌**调用 /api/v1/svc/*（最小权限：tasks:read/tasks:write/results:read）。
//
// 配置（环境变量）：
//   FUSIONWEB_SVC_URL    FusionWeb API 基址，默认 http://fusionweb-api:8082（容器内网）
//   FUSIONWEB_SVC_TOKEN  服务账号令牌（fwsvc_ 开头）

export const name = 'fusionweb-tools'
export const inject = ['tools']

const BASE = String(process.env.FUSIONWEB_SVC_URL || 'http://fusionweb-api:8082').replace(/\/+$/, '')
const TOKEN = String(process.env.FUSIONWEB_SVC_TOKEN || '').trim()

async function callAPI(path, init) {
  if (!TOKEN) throw new Error('未配置 FUSIONWEB_SVC_TOKEN，无法调用 FusionWeb')
  const res = await fetch(`${BASE}${path}`, {
    ...(init || {}),
    headers: {
      Authorization: `Bearer ${TOKEN}`,
      'Content-Type': 'application/json',
      ...((init && init.headers) || {}),
    },
  })
  const raw = await res.text()
  let body = null
  if (raw) {
    try {
      body = JSON.parse(raw)
    } catch {
      body = raw
    }
  }
  if (!res.ok) {
    const detail = typeof body === 'string' ? body : JSON.stringify(body)
    throw new Error(`FusionWeb API ${res.status}: ${detail}`)
  }
  return body
}

function renderJSON(value) {
  return [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value) }]
}

function renderText(str) {
  return [{ type: 'text', text: str }]
}

const objectSchema = { type: 'object', additionalProperties: true }

export function apply(ctx) {
  // 单个工具注册失败不应拖垮整个 DSH（插件加载失败会让进程退出）。
  const safeRegister = (definition) => {
    try {
      ctx.tools.register(definition)
    } catch (err) {
      ctx.logger?.warn?.(`fusionweb-tools: 注册工具 ${definition && definition.name} 失败：${(err && err.message) || err}`)
    }
  }

  // ── 建任务 ──────────────────────────────────────────────────────────
  safeRegister({
    name: 'fusionweb_create_task',
    description:
      '在 FusionWeb 安全扫描平台创建扫描任务。task_type: web（网址）/ port（IP）/ subdomain（域名）。' +
      'web 的 scan_mode 可为 alive|fingerprint|fingerprint_poc|poc；port 用 port_service；留空按类型取默认。',
    parameters: {
      type: 'object',
      additionalProperties: false,
      required: ['task_type', 'target'],
      properties: {
        task_type: { type: 'string', enum: ['web', 'port', 'subdomain'], description: '扫描类型' },
        target: { type: 'string', description: '目标：web 传网址、port 传 IP、subdomain 传域名（多个可用换行/逗号分隔）' },
        port_range: { type: 'string', description: '端口范围，如 80,443 或 1-65535（port 任务使用）' },
        scan_mode: { type: 'string', description: '扫描模式，留空按类型取默认' },
        threads: { type: 'integer', description: '并发线程数，默认 10' },
        web_timeout: { type: 'integer', description: 'Web 探测超时（秒），默认 20' },
        port_scan_timeout: { type: 'integer', description: '端口扫描超时（秒），默认 3' },
      },
    },
    output: {
      schema: { type: 'object', additionalProperties: true, required: ['taskId'], properties: { taskId: { type: 'string' } } },
      render: (_args, value) => renderText(`已在 FusionWeb 创建扫描任务，taskId=${value && value.taskId}`),
    },
    timeoutMs: 180000,
    execute: async (args) => {
      const taskType = String(args.task_type)
      const defaultMode = taskType === 'port' ? 'port_service' : 'alive'
      const payload = {
        task_name: `DSH创建-${String(args.target).slice(0, 40)}`,
        task_type: taskType,
        target_input: String(args.target),
        port_range: args.port_range ? String(args.port_range) : '',
        scan_mode: args.scan_mode ? String(args.scan_mode) : defaultMode,
        scan_options: '{}',
        selected_dicts: '[]',
        thread_count: args.threads || 10,
        port_scan_timeout: args.port_scan_timeout || 3,
        web_timeout: args.web_timeout || 20,
        ports_threshold: 65535,
        syn_scan_rate: 10000,
      }
      return await callAPI('/api/v1/svc/tasks', { method: 'POST', body: JSON.stringify(payload) })
    },
  })

  // ── 任务列表 ────────────────────────────────────────────────────────
  safeRegister({
    name: 'fusionweb_list_tasks',
    description: '列出 FusionWeb 上的扫描任务（最近的在前）。',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        limit: { type: 'integer', description: '返回条数上限，默认 10，最多 50' },
      },
    },
    output: {
      schema: { type: 'array', items: objectSchema },
      render: (_args, value) => renderJSON(value),
    },
    timeoutMs: 60000,
    execute: async (args) => {
      const list = await callAPI('/api/v1/svc/tasks')
      const limit = Math.min(Math.max(Number(args.limit) || 10, 1), 50)
      if (!Array.isArray(list)) return []
      return list.slice(0, limit).map((item) => ({
        taskID: item.taskID,
        taskName: item.taskName,
        taskType: item.taskType,
        targetInput: item.targetInput,
        status: item.status,
        stage: item.stage,
        percentage: item.percentage,
        vulnCount: item.vulnCount,
        createTime: item.createTime,
      }))
    },
  })

  // ── 任务进度 ────────────────────────────────────────────────────────
  safeRegister({
    name: 'fusionweb_task_progress',
    description: '查询某个 FusionWeb 扫描任务的进度与阶段。',
    parameters: {
      type: 'object',
      additionalProperties: false,
      required: ['task_id'],
      properties: { task_id: { type: 'string', description: '任务 ID' } },
    },
    output: {
      schema: objectSchema,
      render: (_args, value) => renderJSON(value),
    },
    timeoutMs: 60000,
    execute: async (args) =>
      await callAPI(`/api/v1/svc/tasks/${encodeURIComponent(String(args.task_id))}/progress`),
  })

  // ── 任务漏洞结果 ────────────────────────────────────────────────────
  safeRegister({
    name: 'fusionweb_task_vulns',
    description: '查询某个 FusionWeb 扫描任务发现的漏洞结果。',
    parameters: {
      type: 'object',
      additionalProperties: false,
      required: ['task_id'],
      properties: { task_id: { type: 'string', description: '任务 ID' } },
    },
    output: {
      schema: { type: 'array', items: objectSchema },
      render: (_args, value) => renderJSON(value),
    },
    timeoutMs: 60000,
    execute: async (args) => {
      const value = await callAPI(`/api/v1/svc/tasks/${encodeURIComponent(String(args.task_id))}/vuln`)
      return Array.isArray(value) ? value : []
    },
  })

  // ── 主动推送钉钉消息 ────────────────────────────────────────────────
  safeRegister({
    name: 'notify_dingtalk',
    description: '主动向钉钉推送一条消息（发往机器人默认目标，通常是你的单聊）。',
    parameters: {
      type: 'object',
      additionalProperties: false,
      required: ['text'],
      properties: {
        text: { type: 'string', description: '消息内容（支持 Markdown）' },
        title: { type: 'string', description: '消息标题，默认「DSH 消息」' },
      },
    },
    output: {
      schema: { type: 'object', additionalProperties: true, required: ['sent'], properties: { sent: { type: 'boolean' } } },
      render: (_args, value) => renderText(`钉钉消息${value && value.sent ? '已推送' : '推送失败'}`),
    },
    timeoutMs: 60000,
    execute: async (args) =>
      await callAPI('/api/v1/svc/notify', {
        method: 'POST',
        body: JSON.stringify({ text: String(args.text), title: args.title ? String(args.title) : '' }),
      }),
  })

  // ── 在钉钉上提问并等待确认 ──────────────────────────────────────────
  safeRegister({
    name: 'ask_dingtalk',
    description:
      '在钉钉上向用户提问并等待其回复确认（回复 1 确认 / 0 取消）。适用于执行有副作用或破坏性的操作前征求同意。' +
      '超时未回复视为「不执行」。',
    parameters: {
      type: 'object',
      additionalProperties: false,
      required: ['question'],
      properties: {
        question: { type: 'string', description: '要问用户的问题（会自动附上短码与回复方式）' },
        timeoutSec: { type: 'integer', description: '等待秒数，默认 600，最大 1500' },
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: true,
        required: ['status'],
        properties: {
          status: { type: 'string', description: 'confirmed | denied | expired' },
          answer: { type: 'string' },
          code: { type: 'string' },
        },
      },
      render: (_args, value) => {
        const status = value && value.status
        if (status === 'confirmed') return renderText('用户已在钉钉确认：可以继续执行。')
        if (status === 'denied') return renderText('用户已在钉钉拒绝：不要执行该操作。')
        return renderText('等待超时：用户未在钉钉确认，视为不执行。')
      },
    },
    timeoutMs: 1800000,
    execute: async (args) => {
      const timeoutSec = Math.min(Math.max(Number(args.timeoutSec) || 600, 30), 1500)
      const created = await callAPI('/api/v1/svc/confirmations', {
        method: 'POST',
        body: JSON.stringify({ question: String(args.question), timeoutSec }),
      })
      const id = created && created.id
      if (!id) throw new Error('创建钉钉确认请求失败')
      const deadline = Date.now() + (timeoutSec + 20) * 1000
      while (Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 5000))
        const state = await callAPI(`/api/v1/svc/confirmations/${encodeURIComponent(String(id))}`)
        const status = state && state.status
        if (status && status !== 'pending') {
          return { status, answer: (state && state.answer) || '', code: (state && state.code) || created.code || '' }
        }
      }
      return { status: 'expired', answer: '', code: created.code || '' }
    },
  })

  // ── 扫描能力：以 FusionWeb 为后端（工具名与 dsh-scanner-tools 对齐） ──
  // 说明：这三个工具保持与红队模式 playbook 相同的名字（nuclei_scan / httpx_probe /
  // ffuf_fuzz），但后端换成 FusionWeb 任务——扫描统一由 worker 执行，
  // 结果进入 FusionWeb（有任务、报告、钉钉通知），而不是在 DSH 容器里跑本地 CLI。
  const isTerminal = (status) => ['completed', 'failed', 'cancelled', 'stopped'].includes(String(status || '').toLowerCase())

  async function waitForTask(taskId, timeoutSec) {
    const deadline = Date.now() + timeoutSec * 1000
    while (Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 5000))
      const list = await callAPI('/api/v1/svc/tasks')
      const task = Array.isArray(list) ? list.find((item) => item.taskID === taskId) : null
      if (task && isTerminal(task.status)) return task
    }
    return null
  }

  async function createScanTask(taskType, target, extra) {
    const defaultMode =
      taskType === 'port' ? 'port_service' : taskType === 'directory' ? 'directory' : 'alive'
    const payload = {
      task_name: `${taskType}@${String(target).slice(0, 36)}`,
      task_type: taskType,
      target_input: String(target),
      port_range: '',
      scan_mode: defaultMode,
      scan_options: '{}',
      selected_dicts: '[]',
      thread_count: 10,
      port_scan_timeout: 3,
      web_timeout: 15,
      ports_threshold: 65535,
      syn_scan_rate: 2000,
      ...(extra || {}),
    }
    const created = await callAPI('/api/v1/svc/tasks', { method: 'POST', body: JSON.stringify(payload) })
    const taskId = created && created.taskId
    if (!taskId) throw new Error('FusionWeb 未返回 taskId')
    return taskId
  }

  const scanOutputSchema = {
    type: 'object',
    additionalProperties: true,
    required: ['taskId'],
    properties: {
      taskId: { type: 'string' },
      status: { type: 'string' },
      summary: { type: 'string' },
    },
  }

  safeRegister({
    name: 'httpx_probe',
    description:
      '存活/指纹探测（后端为 FusionWeb：创建 web 扫描任务并等待完成）。' +
      '等价于本机 httpx 的用途，但扫描在 FusionWeb worker 内执行，结果可在 FusionWeb 查看。',
    parameters: {
      type: 'object',
      additionalProperties: false,
      required: ['targets'],
      properties: {
        targets: { type: 'string', description: '目标 URL/域名，多个用换行或逗号分隔' },
        timeoutSec: { type: 'integer', description: '等待扫描完成的秒数，默认 300' },
      },
    },
    output: { schema: scanOutputSchema, render: (_a, v) => renderJSON(v) },
    timeoutMs: 900000,
    execute: async (args) => {
      const taskId = await createScanTask('web', args.targets, { scan_mode: 'alive' })
      const task = await waitForTask(taskId, Math.min(Math.max(Number(args.timeoutSec) || 300, 30), 1500))
      const list = await callAPI('/api/v1/svc/tasks')
      const info = Array.isArray(list) ? list.find((item) => item.taskID === taskId) : null
      return {
        taskId,
        status: (task && task.status) || (info && info.status) || 'running',
        summary: `FusionWeb 存活/指纹探测已提交并${
          task ? '完成' : '仍在执行'
        }：目标 ${info ? info.targetInput || '' : ''}，命中指纹 ${info ? info.fingerprintCount ?? 0 : 0} 个。`,
      }
    },
  })

  safeRegister({
    name: 'nuclei_scan',
    description:
      '模板（POC）扫描（后端为 FusionWeb：创建 web 扫描任务，scan_mode=poc 全量模板）。' +
      '命中结果即漏洞记录，可在 FusionWeb 任务详情与报告中查看。',
    parameters: {
      type: 'object',
      additionalProperties: false,
      required: ['target'],
      properties: {
        target: { type: 'string', description: '目标 URL/域名' },
        scanMode: { type: 'string', description: 'poc（默认，全量模板）或 fingerprint_poc（先指纹再 POC）' },
        timeoutSec: { type: 'integer', description: '等待秒数，默认 600' },
      },
    },
    output: { schema: scanOutputSchema, render: (_a, v) => renderJSON(v) },
    timeoutMs: 1800000,
    execute: async (args) => {
      const mode = String(args.scanMode || 'poc')
      const taskId = await createScanTask('web', args.target, { scan_mode: mode })
      const task = await waitForTask(taskId, Math.min(Math.max(Number(args.timeoutSec) || 600, 30), 1500))
      let vulns = null
      try {
        vulns = await callAPI(`/api/v1/svc/tasks/${encodeURIComponent(taskId)}/vuln`)
      } catch (err) {
        vulns = null
      }
      const count = Array.isArray(vulns) ? vulns.length : 0
      return {
        taskId,
        status: (task && task.status) || 'running',
        vulnCount: count,
        vulns: Array.isArray(vulns) ? vulns.slice(0, 20) : [],
        summary: `FusionWeb POC 扫描（scan_mode=${mode}）${task ? '已完成' : '仍在执行'}，命中 ${count} 条漏洞结果。`,
      }
    },
  })

  safeRegister({
    name: 'ffuf_fuzz',
    description:
      '目录/路径模糊测试（后端为 FusionWeb：创建目录扫描任务，其内核即 ffuf）。' +
      'wordlist 传路径词表（JSON 数组或换行分隔）；不传则用 FusionWeb 的目录字典。',
    parameters: {
      type: 'object',
      additionalProperties: false,
      required: ['url'],
      properties: {
        url: { type: 'string', description: '目标 URL' },
        wordlist: { type: 'string', description: '路径词表：JSON 数组或换行/逗号分隔；留空用 FusionWeb 字典' },
        threads: { type: 'integer', description: '并发数，默认 50' },
        timeoutSec: { type: 'integer', description: '等待秒数，默认 300' },
      },
    },
    output: { schema: scanOutputSchema, render: (_a, v) => renderJSON(v) },
    timeoutMs: 900000,
    execute: async (args) => {
      let dicts = '[]'
      const raw = args.wordlist ? String(args.wordlist).trim() : ''
      if (raw) {
        if (raw.startsWith('[')) {
          dicts = raw
        } else {
          const items = raw
            .split(/[\n,]/)
            .map((item) => item.trim())
            .filter(Boolean)
          dicts = JSON.stringify(items)
        }
      }
      const taskId = await createScanTask('directory', args.url, {
        selected_dicts: dicts,
        thread_count: Number(args.threads) || 50,
      })
      const task = await waitForTask(taskId, Math.min(Math.max(Number(args.timeoutSec) || 300, 30), 1500))
      return {
        taskId,
        status: (task && task.status) || 'running',
        summary: `FusionWeb 目录扫描（ffuf 内核）${task ? '已完成' : '仍在执行'}：${String(args.url)}。`,
      }
    },
  })

  safeRegister({
    name: 'fusionweb_task_results',
    description: '汇总读取某个 FusionWeb 任务的端口/URL/漏洞结果（用于把扫描证据取回对话）。',
    parameters: {
      type: 'object',
      additionalProperties: false,
      required: ['task_id'],
      properties: { task_id: { type: 'string', description: '任务 ID' } },
    },
    output: { schema: { type: 'object', additionalProperties: true }, render: (_a, v) => renderJSON(v) },
    timeoutMs: 120000,
    execute: async (args) => {
      const id = encodeURIComponent(String(args.task_id))
      const out = { task_id: String(args.task_id) }
      const safe = async (path, key) => {
        try {
          out[key] = await callAPI(path)
        } catch (err) {
          out[key] = null
        }
      }
      await safe(`/api/v1/svc/tasks/${id}/progress`, 'progress')
      await safe(`/api/v1/svc/tasks/${id}/vuln`, 'vulns')
      await safe(`/api/v1/svc/tasks/${id}/fingerprint`, 'fingerprints')
      await safe(`/api/v1/svc/tasks/${id}/results`, 'results')
      return out
    },
  })

  ctx.logger?.info?.(`fusionweb-tools 已注册（FusionWeb=${BASE}，令牌${TOKEN ? '已配置' : '缺失'}）`)
}
