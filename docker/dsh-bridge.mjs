// DSH 桥：把「OpenAI 兼容的对话请求」转成一次 DSH headless 运行，并把结果推回钉钉。
//
// 为什么这样设计：
//   * FusionWeb 的钉钉 AI 对话走标准 OpenAI 兼容调用（/v1/chat/completions），因此桥只需伪装成
//     一个模型服务即可，FusionWeb 侧不用改代码；
//   * 一次 DSH 任务可能远超 HTTP 超时，所以这里**立即返回**一句"已交给 DSH 处理"，
//     真正的执行放到后台；完成后由桥调用 FusionWeb 的服务账号接口把结果推到钉钉。
//
// 环境变量：
//   DSH_BRIDGE_PORT       监听端口（默认 8995）
//   FUSIONWEB_SVC_URL     FusionWeb API 基址（默认 http://fusionweb-api:8082）
//   FUSIONWEB_SVC_TOKEN   服务账号令牌（同时用于鉴权本桥与调用 FusionWeb）
//   DSH_BRIDGE_TIMEOUT_MS 单次 DSH 运行超时（默认 30 分钟）
import http from 'node:http'
import { spawn } from 'node:child_process'

const PORT = Number(process.env.DSH_BRIDGE_PORT || 8995)
const API_BASE = String(process.env.FUSIONWEB_SVC_URL || 'http://fusionweb-api:8082').replace(/\/+$/, '')
const TOKEN = String(process.env.FUSIONWEB_SVC_TOKEN || '').trim()
const RUN_TIMEOUT_MS = Number(process.env.DSH_BRIDGE_TIMEOUT_MS || 30 * 60 * 1000)
const WORKSPACE = process.env.DSH_BRIDGE_WORKSPACE || '/workspace'
const ACK_TEXT = '已交给 DSH 处理，完成后我会把结果发到这里。'

// 钉钉渠道的行为约束：用户只看得到最终这段文字，所以要求 DSH 少绕弯、快返回、别长时间轮询
// （任务完成由 FusionWeb 自身通知，无需 DSH 守着）。
const PREAMBLE = [
  '【渠道说明】你正在通过钉钉与用户一对一对话。用户看不到你的中间步骤，只会在稍后收到你这段最终回复。',
  '【行为要求】',
  '1. 需要扫描时直接调用 fusionweb_create_task 建任务，并在最终回复里给出 taskId；',
  '2. 只按用户明确要求建任务，不要自行扩展到其它端口/路径（如确有发现，写在回复里建议即可）；',
  '3. **不要轮询等待扫描完成**（FusionWeb 会在任务完成时自动通知用户），建完任务就结束本轮；',
  '4. 最终回复用简体中文、简短（几句话内），说明你做了什么、taskId 是什么、结果会自动通知。',
].join('\n')

function json(res, code, payload) {
  const body = JSON.stringify(payload)
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) })
  res.end(body)
}

function readBody(req) {
  return new Promise((resolve) => {
    let raw = ''
    req.on('data', (chunk) => {
      raw += chunk
      if (raw.length > 2 * 1024 * 1024) req.destroy()
    })
    req.on('end', () => resolve(raw))
    req.on('error', () => resolve(raw))
  })
}

function messageText(content) {
  if (typeof content === 'string') return content
  if (Array.isArray(content)) {
    return content
      .map((part) => (part && typeof part === 'object' ? part.text || '' : String(part || '')))
      .filter(Boolean)
      .join('\n')
  }
  return ''
}

function buildPrompt(messages) {
  const list = Array.isArray(messages) ? messages : []
  const system = list.filter((m) => m && m.role === 'system').map((m) => messageText(m.content)).filter(Boolean)
  const dialog = list
    .filter((m) => m && m.role !== 'system')
    .map((m) => `${m.role === 'assistant' ? 'assistant' : 'user'}: ${messageText(m.content)}`)
    .filter((line) => line.trim() !== 'user:' && line.trim() !== 'assistant:')
  const parts = []
  if (system.length > 0) parts.push(system.join('\n'))
  parts.push(dialog.join('\n\n'))
  return parts.join('\n\n').trim()
}

async function notifyDingTalk(text, title) {
  if (!TOKEN) return
  try {
    const res = await fetch(`${API_BASE}/api/v1/svc/notify`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, title: title || 'DSH 结果' }),
    })
    if (!res.ok) console.error(`[bridge] 推送钉钉失败: HTTP ${res.status}`)
  } catch (err) {
    console.error(`[bridge] 推送钉钉异常: ${err?.message || err}`)
  }
}

function truncate(text, max) {
  const s = String(text || '').trim()
  return s.length > max ? `${s.slice(0, max)}\n...(已截断)` : s
}

async function runDsh(userPrompt) {
  const prompt = `${PREAMBLE}\n\n【用户消息】\n${userPrompt}`
  console.log(`[bridge] 开始 DSH 运行，用户消息长度=${userPrompt.length}`)
  const child = spawn('dsh', ['--profile', 'headless', prompt], {
    cwd: WORKSPACE,
    env: { ...process.env, HOME: process.env.DSH_HOME ? `${process.env.DSH_HOME}/home` : process.env.HOME },
    stdio: ['ignore', 'pipe', 'pipe'],
  })

  let stdout = ''
  let stderr = ''
  child.stdout.on('data', (c) => {
    stdout += c
  })
  child.stderr.on('data', (c) => {
    stderr += c
  })

  const timer = setTimeout(() => {
    console.error('[bridge] DSH 运行超时，终止')
    child.kill('SIGKILL')
  }, RUN_TIMEOUT_MS)

  const code = await new Promise((resolve) => child.on('close', (c) => resolve(c)))
  clearTimeout(timer)
  console.log(`[bridge] DSH 运行结束，exit=${code}`)

  if (code === 0 && stdout.trim()) {
    await notifyDingTalk(truncate(stdout, 3000), 'DSH 结果')
    return
  }
  // 失败时把详情同时打进容器日志，便于排障（此前只有钉钉里能看到）
  const detail = truncate(stderr || stdout || `exit=${code}`, 1500)
  console.error(`[bridge] DSH 执行失败 exit=${code}\n${detail}`)
  await notifyDingTalk(`DSH 执行未成功（exit=${code}）：\n\n${detail}\n\n可以直接重发一次消息重试。`, 'DSH 执行失败')
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || '/', 'http://localhost')

  if (url.pathname === '/healthz') {
    json(res, 200, { ok: true })
    return
  }

  if (TOKEN) {
    const auth = String(req.headers.authorization || '')
    if (auth !== `Bearer ${TOKEN}`) {
      json(res, 401, { error: { message: 'unauthorized' } })
      return
    }
  }

  if (req.method === 'GET' && url.pathname === '/v1/models') {
    json(res, 200, { object: 'list', data: [{ id: 'dsh', object: 'model', owned_by: 'fusionweb' }] })
    return
  }

  if (req.method === 'POST' && (url.pathname === '/v1/chat/completions' || url.pathname === '/chat/completions')) {
    const raw = await readBody(req)
    let payload = {}
    try {
      payload = raw ? JSON.parse(raw) : {}
    } catch {
      json(res, 400, { error: { message: 'invalid json' } })
      return
    }
    const prompt = buildPrompt(payload.messages)
    if (!prompt) {
      json(res, 400, { error: { message: 'empty prompt' } })
      return
    }
    // 后台执行，立即回执，避免调用方 HTTP 超时
    runDsh(prompt).catch((err) => console.error(`[bridge] 运行异常: ${err?.message || err}`))

    json(res, 200, {
      id: `chatcmpl-dsh-${Date.now()}`,
      object: 'chat.completion',
      created: Math.floor(Date.now() / 1000),
      model: payload.model || 'dsh',
      choices: [{ index: 0, message: { role: 'assistant', content: ACK_TEXT }, finish_reason: 'stop' }],
      usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
    })
    return
  }

  json(res, 404, { error: { message: 'not found' } })
})

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[bridge] DSH 桥已监听 0.0.0.0:${PORT}（FusionWeb=${API_BASE}，令牌${TOKEN ? '已配置' : '缺失'}）`)
})
