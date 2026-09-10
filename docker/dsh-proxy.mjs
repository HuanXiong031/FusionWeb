// DSH 对外转发 + 首次访问自动引导。
//
// 背景：DSH 的 Web 服务只允许绑 127.0.0.1（CLI 又拒绝 0.0.0.0），且访问需要一次性
// boot token（`GET /?token=...` 会种下 dsh-auth-* 认证 cookie）。这里用纯 TCP 透传
// 暴露端口，并在“尚未持有认证 cookie 且未带 token 的首次页面请求”上做一次 302 引导，
// 使浏览器（含 iframe 嵌入）无需人工拼接 token 即可进入。
import net from 'node:net'

const listenPort = Number(process.env.DSH_PORT || 8990)
const targetHost = '127.0.0.1'
const targetPort = Number(process.env.DSH_INNER_PORT || 8991)
const bootToken = String(process.env.DSH_BOOT_TOKEN || '').trim()

function isBootstrapTarget(headText) {
  if (!bootToken) return false
  const firstLine = headText.split('\r\n', 1)[0] || ''
  // 只引导对首页的 GET，其它请求（静态资源、/api、WebSocket）一律透传
  if (!/^GET \/(\?[^\s]*)? HTTP\/1\.[01]$/.test(firstLine)) return false
  if (/[?&]token=/i.test(firstLine)) return false
  if (/^cookie:[^\r\n]*dsh-auth-/im.test(headText)) return false
  return true
}

const server = net.createServer((client) => {
  let buffer = Buffer.alloc(0)
  let decided = false

  const passthrough = () => {
    const upstream = net.connect(targetPort, targetHost, () => {
      if (buffer.length > 0) upstream.write(buffer)
      client.pipe(upstream)
      upstream.pipe(client)
    })
    const shutdown = () => {
      client.destroy()
      upstream.destroy()
    }
    client.on('error', shutdown)
    upstream.on('error', shutdown)
  }

  const onData = (chunk) => {
    if (decided) return
    buffer = Buffer.concat([buffer, chunk])
    const text = buffer.toString('latin1')
    const headEnd = text.indexOf('\r\n\r\n')
    if (headEnd === -1 && buffer.length < 65536) return // 请求头未收完，继续等
    decided = true
    client.removeListener('data', onData)

    const headText = headEnd === -1 ? text : text.slice(0, headEnd)
    if (isBootstrapTarget(headText)) {
      client.end(
        'HTTP/1.1 302 Found\r\n' +
          `Location: /?token=${bootToken}\r\n` +
          'Cache-Control: no-store\r\n' +
          'Content-Length: 0\r\n' +
          'Connection: close\r\n\r\n',
      )
      return
    }
    passthrough()
  }

  client.on('data', onData)
  client.on('error', () => client.destroy())
})

server.on('error', (err) => {
  console.error(`dsh proxy error: ${err?.message || err}`)
  process.exit(1)
})

server.listen(listenPort, '0.0.0.0', () => {
  console.log(
    `dsh proxy listening on 0.0.0.0:${listenPort} -> ${targetHost}:${targetPort}` +
      (bootToken ? ' (bootstrap token ready)' : ' (no bootstrap token)'),
  )
})
