'use client'

import * as React from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { toast } from 'sonner'
import { Bot, BrainCircuit, KeyRound, Loader2, RefreshCw, Send, Sparkles, Trash2, User } from 'lucide-react'
import { getAIAPIKeys, sendAIChat, type AIAPIKey, type AIChatMessage } from '@/lib/api'
import { cn, formatTime, unwrap } from '@/lib/utils'
import { Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Field, Select, Textarea } from '@/components/ui'
import { Metric, PageTitle } from '@/components/fusion/shared'

interface ChatMessage extends AIChatMessage {
  id: string
  createdAt: string
}

const defaultSystemPrompt = '你是 FusionWeb 安全扫描一体化平台的 AI 助手，请用中文回答，优先给出清晰、可执行的排查与修复建议。'

const starterPrompts = [
  '帮我梳理一次 Web 扫描任务的结果分析思路。',
  '如何根据端口扫描结果判断重点验证目标？',
  '请给我一份漏洞复测与修复闭环模板。',
  '帮我写一个安全报告摘要的结构。',
]

export function AIChatView({ initialContext }: { initialContext?: string }) {
  const [selectedKeyId, setSelectedKeyId] = React.useState('')
  const [systemPrompt, setSystemPrompt] = React.useState(defaultSystemPrompt)
  const [input, setInput] = React.useState('')
  const [messages, setMessages] = React.useState<ChatMessage[]>([])

  React.useEffect(() => {
    const context = initialContext?.trim()
    if (context) setInput(context)
  }, [initialContext])

  const query = useQuery({ queryKey: ['ai-api-keys'], queryFn: getAIAPIKeys })
  const keys = (unwrap<AIAPIKey[]>(query.data) || []).filter((item) => item.enabled !== false)
  const defaultKey = keys.find((item) => item.isDefault) || keys[0]

  React.useEffect(() => {
    if (!selectedKeyId && defaultKey?.id) setSelectedKeyId(String(defaultKey.id))
  }, [defaultKey?.id, selectedKeyId])

  const selectedKey = keys.find((item) => String(item.id) === selectedKeyId)

  const chatMutation = useMutation({
    mutationFn: async (nextMessages: ChatMessage[]) =>
      sendAIChat({
        keyId: selectedKey?.id,
        systemPrompt,
        messages: nextMessages.map(({ role, content }) => ({ role, content })),
        maxTokens: 4096,
        temperature: 0.3,
      }),
    onSuccess: (response: any) => {
      const data = unwrap<any>(response)
      const assistantMessage: ChatMessage = {
        id: createID(),
        role: 'assistant',
        content: data?.content || '',
        createdAt: new Date().toISOString(),
      }
      setMessages((items) => [...items, assistantMessage])
    },
    onError: (error: any) => toast.error(error?.message || 'AI 对话请求失败'),
  })

  const sendMessage = (content = input) => {
    const text = content.trim()
    if (!text) return
    if (!selectedKey?.id) {
      toast.error('请先在系统设置中添加并启用 AI API Key')
      return
    }
    const userMessage: ChatMessage = {
      id: createID(),
      role: 'user',
      content: text,
      createdAt: new Date().toISOString(),
    }
    const nextMessages = [...messages, userMessage]
    setMessages(nextMessages)
    setInput('')
    chatMutation.mutate(nextMessages)
  }

  const clearChat = () => {
    setMessages([])
    toast.success('当前对话已清空')
  }

  return (
    <div className="grid h-full min-h-0 gap-4">
      <PageTitle title="AI 对话" description="调用系统设置中的 GPT、DeepSeek、Claude Code 或 OpenAI 兼容 Key，辅助分析扫描结果、生成报告建议和排查问题。" />

      <div className="grid gap-4 md:grid-cols-3">
        <Metric label="可用 Key" value={String(keys.length)} icon={KeyRound} tone="info" badgeLabel="AI" />
        <Metric
          label="当前模型"
          value={selectedKey?.model || '未选择'}
          icon={BrainCircuit}
          tone="success"
          badgeLabel={selectedKey ? providerLabel(selectedKey.provider) : '模型'}
        />
        <Metric label="对话轮次" value={String(messages.filter((item) => item.role === 'user').length)} icon={Sparkles} tone="warning" badgeLabel="上下文" />
      </div>

      <div className="grid min-h-[calc(100vh-260px)] gap-4 xl:grid-cols-[360px_minmax(0,1fr)]">
        <Card className="min-h-0">
          <CardHeader className="items-start">
            <div>
              <CardTitle>对话配置</CardTitle>
              <CardDescription>选择要使用的模型 Key，并设置系统提示词。</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="grid gap-4">
            <Field label="模型 Key">
              <Select value={selectedKeyId} onChange={(event) => setSelectedKeyId(event.target.value)}>
                {keys.length === 0 ? <option value="">暂无可用 Key</option> : null}
                {keys.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name} · {item.model}
                  </option>
                ))}
              </Select>
            </Field>
            {selectedKey ? (
              <div className="rounded-card border border-border bg-raised p-3 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-semibold text-foreground">{selectedKey.name}</span>
                  {selectedKey.isDefault ? <Badge tone="warning">默认</Badge> : <Badge tone="info">已启用</Badge>}
                </div>
                <div className="mt-2 grid gap-1 text-muted">
                  <div>服务商：{providerLabel(selectedKey.provider)}</div>
                  <div>
                    模型：
                    <span className="font-mono text-foreground">{selectedKey.model || '-'}</span>
                  </div>
                  <div>
                    Base URL：
                    <span className="font-mono text-foreground">{selectedKey.baseUrl || '默认'}</span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="rounded-card border border-dashed border-border bg-raised p-4 text-sm text-muted">还没有启用的 AI Key，请先到“系统设置 / AI Key”中添加。</div>
            )}
            <Field label="系统提示词">
              <Textarea value={systemPrompt} onChange={(event) => setSystemPrompt(event.target.value)} className="min-h-40" />
            </Field>
            <div className="grid gap-2">
              <div className="text-xs font-semibold text-muted">快捷提问</div>
              {starterPrompts.map((item) => (
                <button
                  key={item}
                  type="button"
                  className="rounded-md border border-border bg-background px-3 py-2 text-left text-xs text-muted transition-colors hover:bg-raised hover:text-foreground"
                  onClick={() => setInput(item)}
                >
                  {item}
                </button>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card className="flex min-h-0 flex-col">
          <CardHeader>
            <div>
              <CardTitle>对话窗口</CardTitle>
              <CardDescription>支持多轮上下文；当前页面刷新后对话不会写入数据库。</CardDescription>
            </div>
            <Button variant="outline" onClick={clearChat} disabled={messages.length === 0}>
              <Trash2 className="size-4" />
              清空
            </Button>
          </CardHeader>
          <CardContent className="flex min-h-0 flex-1 flex-col gap-4">
            <div className="min-h-0 flex-1 overflow-y-auto rounded-card border border-border bg-background p-4">
              {messages.length === 0 ? (
                <div className="flex h-full min-h-72 flex-col items-center justify-center text-center">
                  <div className="flex size-14 items-center justify-center rounded-2xl border border-border bg-raised">
                    <Bot className="size-7 text-info-foreground" />
                  </div>
                  <div className="mt-4 text-sm font-semibold text-foreground">开始一次 AI 辅助分析</div>
                  <div className="mt-2 max-w-md text-sm text-muted">可以粘贴扫描结果、漏洞请求响应、资产列表或报告草稿，让 AI 帮你总结风险、生成修复建议。</div>
                </div>
              ) : (
                <div className="grid gap-4">
                  {messages.map((message) => (
                    <ChatBubble key={message.id} message={message} />
                  ))}
                  {chatMutation.isPending ? (
                    <div className="flex items-center gap-2 text-sm text-muted">
                      <Loader2 className="size-4 animate-spin" />
                      AI 正在生成回复...
                    </div>
                  ) : null}
                </div>
              )}
            </div>
            <div className="grid gap-2">
              <Textarea
                value={input}
                onChange={(event) => setInput(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
                    event.preventDefault()
                    sendMessage()
                  }
                }}
                placeholder="输入问题，Ctrl/⌘ + Enter 发送"
                className="min-h-28"
              />
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-xs text-muted">不会在浏览器中暴露完整 API Key；请求由后端代理发送。</div>
                <div className="flex gap-2">
                  <Button variant="outline" onClick={() => setInput('')} disabled={!input || chatMutation.isPending}>
                    <RefreshCw className="size-4" />
                    重置输入
                  </Button>
                  <Button variant="default" onClick={() => sendMessage()} disabled={!input.trim() || chatMutation.isPending || !selectedKey?.id}>
                    {chatMutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <Send className="size-4" />}
                    发送
                  </Button>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

function ChatBubble({ message }: { message: ChatMessage }) {
  const isUser = message.role === 'user'
  return (
    <div className={cn('flex gap-3', isUser ? 'justify-end' : 'justify-start')}>
      {!isUser ? (
        <div className="mt-1 flex size-8 shrink-0 items-center justify-center rounded-full border border-border bg-raised">
          <Bot className="size-4" />
        </div>
      ) : null}
      <div
        className={cn(
          'max-w-[86%] rounded-2xl border px-4 py-3 text-sm leading-6 shadow-sm',
          isUser ? 'border-info/30 bg-info/10 text-foreground' : 'border-border bg-card text-foreground',
        )}
      >
        <div className="mb-1 flex items-center gap-2 text-xs text-muted">
          {isUser ? '我' : 'AI 助手'}
          <span>·</span>
          <span>{formatTime(message.createdAt)}</span>
        </div>
        <div className="whitespace-pre-wrap break-words">{message.content}</div>
      </div>
      {isUser ? (
        <div className="mt-1 flex size-8 shrink-0 items-center justify-center rounded-full border border-info/30 bg-info/10">
          <User className="size-4" />
        </div>
      ) : null}
    </div>
  )
}

function createID() {
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`
}

function providerLabel(provider?: string) {
  switch (provider) {
    case 'openai':
      return 'GPT/OpenAI'
    case 'deepseek':
      return 'DeepSeek'
    case 'anthropic':
      return 'Claude Code'
    case 'openai_compatible':
      return 'OpenAI 兼容'
    default:
      return provider || 'AI'
  }
}
