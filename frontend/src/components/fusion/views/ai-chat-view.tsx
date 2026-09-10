'use client'

import * as React from 'react'

/**
 * AI 对话页：完全使用 DeepSeek Harness（DSH）自带的 Web UI。
 * 页面本身只做嵌入式承载（iframe），DSH 与本页同级协议（http）以避免浏览器 mixed-content 拦截。
 * DSH 端口可通过 NEXT_PUBLIC_DSH_PORT 覆盖，默认 8990。
 */
const DSH_PORT = Number(process.env.NEXT_PUBLIC_DSH_PORT || 8990)

export function AIChatView({ initialContext }: { initialContext?: string }) {
  const [src, setSrc] = React.useState('')

  React.useEffect(() => {
    if (typeof window === 'undefined') return
    const { protocol, hostname } = window.location
    setSrc(`${protocol}//${hostname}:${DSH_PORT}/`)
  }, [])

  return (
    <div className="flex h-[calc(100vh-3rem)] min-h-[520px] flex-col gap-2">
      {src ? (
        <iframe
          src={src}
          title="DeepSeek Harness"
          className="h-full w-full rounded-card border border-border bg-background"
          allow="clipboard-read; clipboard-write"
        />
      ) : (
        <div className="flex h-full items-center justify-center rounded-card border border-dashed border-border text-sm text-muted">
          正在加载 DeepSeek Harness…
        </div>
      )}
    </div>
  )
}
