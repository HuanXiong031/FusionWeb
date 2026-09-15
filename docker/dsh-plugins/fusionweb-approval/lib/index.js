// fusionweb-approval —— 把「需要用户批准的高危操作」转发到钉钉，按回复决定放行或拒绝。
//
// 背景（DSH 的审批缝）：
//   * 工具管道遇到需要批准的动作时会调用 ctx.approval.request({agent, toolName, callId, reason, signal})；
//   * 应答者是 approval/request 瀑布监听器：返回 allowed-once / rejected / cancelled / unavailable 即为应答，
//     调用 next() 则交给下一个应答者；**没有任何应答者时失败关闭（unavailable）**。
//   * dsh-sec-enforce 的高危类（账号/权限变更、防火墙规则、洪泛压测等）正是走这条缝。
//
// 本插件注册的应答者把请求发到钉钉（复用 FusionWeb 的待确认接口 + 入站回复匹配），
// 你在钉钉回 1 即 allowed-once（仅此一次）、回 0 即 rejected，超时则 unavailable（=不放行）。
//
// 配置（环境变量）：
//   FUSIONWEB_SVC_URL           FusionWeb API 基址，默认 http://fusionweb-api:8082
//   FUSIONWEB_SVC_TOKEN         服务账号令牌（需含 confirm:read/confirm:write）
//   FUSIONWEB_APPROVAL_TIMEOUT  等待钉钉回复的秒数，默认 300
//   FUSIONWEB_APPROVAL_TOOLS    仅这些工具触发钉钉确认（逗号分隔）；留空=所有需要批准的操作

export const name = 'fusionweb-approval'
export const inject = ['approval']

const BASE = String(process.env.FUSIONWEB_SVC_URL || 'http://fusionweb-api:8082').replace(/\/+$/, '')
const TOKEN = String(process.env.FUSIONWEB_SVC_TOKEN || '').trim()
const TIMEOUT_SEC = Math.min(Math.max(Number(process.env.FUSIONWEB_APPROVAL_TIMEOUT) || 300, 30), 1500)
const ONLY_TOOLS = String(process.env.FUSIONWEB_APPROVAL_TOOLS || '')
  .split(',')
  .map((item) => item.trim())
  .filter(Boolean)

async function callAPI(path, init) {
  if (!TOKEN) throw new Error('未配置 FUSIONWEB_SVC_TOKEN')
  const res = await fetch(`${BASE}${path}`, {
    ...(init || {}),
    headers: {
      Authorization: `Bearer ${TOKEN}`,
      'Content-Type': 'application/json',
      ...((init && init.headers) || {}),
    },
  })
  const raw = await res.text()
  const body = raw ? JSON.parse(raw) : null
  if (!res.ok) throw new Error(`FusionWeb ${res.status}: ${raw.slice(0, 200)}`)
  return body && body.data !== undefined ? body.data : body
}

function buildQuestion(req) {
  const lines = [
    '**DSH 需要你批准一个高危操作**',
    '',
    `- 工具：\`${req && req.toolName ? req.toolName : '未知'}\``,
  ]
  if (req && req.reason) lines.push(`- 原因：${String(req.reason).slice(0, 800)}`)
  if (req && req.callId) lines.push(`- 调用：${String(req.callId).slice(0, 64)}`)
  lines.push('', `请回复 **1** 允许执行（仅这一次），回复 **0** 拒绝。${Math.round(TIMEOUT_SEC / 60)} 分钟内有效，超时按拒绝处理。`)
  return lines.join('\n')
}

/** 等待钉钉回复；返回 confirmed / denied / expired / cancelled。 */
async function awaitDingTalk(id, signal) {
  const deadline = Date.now() + (TIMEOUT_SEC + 20) * 1000
  while (Date.now() < deadline) {
    if (signal && signal.aborted) return 'cancelled'
    await new Promise((resolve) => setTimeout(resolve, 5000))
    let state = null
    try {
      state = await callAPI(`/api/v1/svc/confirmations/${encodeURIComponent(String(id))}`)
    } catch (err) {
      continue
    }
    const status = state && state.status
    if (status && status !== 'pending') return status
  }
  return 'expired'
}

export function apply(ctx) {
  ctx.on('approval/request', async (req, next) => {
    const toolName = String((req && req.toolName) || '')
    if (ONLY_TOOLS.length > 0 && !ONLY_TOOLS.includes(toolName)) {
      return next()
    }
    if (!TOKEN) {
      // 没有令牌就无法询问：交给下一个应答者（最终将失败关闭）
      ctx.logger?.warn?.('fusionweb-approval: 未配置 FUSIONWEB_SVC_TOKEN，无法通过钉钉确认')
      return next()
    }

    let created
    try {
      created = await callAPI('/api/v1/svc/confirmations', {
        method: 'POST',
        body: JSON.stringify({ question: buildQuestion(req), timeoutSec: TIMEOUT_SEC }),
      })
    } catch (err) {
      ctx.logger?.warn?.(`fusionweb-approval: 发送钉钉确认失败，失败关闭：${(err && err.message) || err}`)
      return next()
    }

    const id = created && created.id
    if (!id) return next()

    const outcome = await awaitDingTalk(id, req && req.signal)
    if (outcome === 'confirmed') {
      ctx.logger?.info?.(`fusionweb-approval: 钉钉已批准（${toolName}，code=${created.code}）`)
      return 'allowed-once'
    }
    if (outcome === 'cancelled') return 'cancelled'
    ctx.logger?.info?.(
      `fusionweb-approval: 钉钉未批准（${toolName}，结果=${outcome}，code=${created.code}），按拒绝处理`,
    )
    return 'rejected'
  })

  ctx.logger?.info?.(
    `fusionweb-approval 已注册（钉钉确认超时 ${TIMEOUT_SEC}s${
      ONLY_TOOLS.length ? `，仅限工具：${ONLY_TOOLS.join(',')}` : ''
    }）`,
  )
}
