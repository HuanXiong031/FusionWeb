// DSH 对外转发：DSH 只允许绑 127.0.0.1，这里用纯 TCP 透传把容器端口暴露给同一 Docker 网络内的 nginx。
// 认证与特权接口的 Host/Origin 改写由 FusionWeb 的 nginx 负责（nginx 才是对外入口）。
import net from 'node:net'

const listenPort = Number(process.env.DSH_PORT || 8990)
const targetHost = '127.0.0.1'
const targetPort = Number(process.env.DSH_INNER_PORT || 8991)

const server = net.createServer((client) => {
  const upstream = net.connect(targetPort, targetHost)
  const shutdown = () => {
    client.destroy()
    upstream.destroy()
  }
  client.on('error', shutdown)
  upstream.on('error', shutdown)
  client.pipe(upstream)
  upstream.pipe(client)
})

server.on('error', (err) => {
  console.error(`dsh proxy error: ${err?.message || err}`)
  process.exit(1)
})

server.listen(listenPort, '0.0.0.0', () => {
  console.log(`dsh proxy listening on 0.0.0.0:${listenPort} -> ${targetHost}:${targetPort}`)
})
