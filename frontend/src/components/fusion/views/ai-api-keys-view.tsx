'use client'

import * as React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { Bot, CheckCircle2, Edit3, Eye, EyeOff, KeyRound, Loader2, Plus, RefreshCw, Save, Star, Trash2, Zap } from 'lucide-react'
import {
  createAIAPIKey,
  deleteAIAPIKey,
  getAIAPIKeys,
  testAIAPIKey,
  updateAIAPIKey,
  type AIAPIKey,
  type AIProvider,
} from '@/lib/api'
import { unwrap, cn, formatTime } from '@/lib/utils'
import { Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Drawer, Field, Input, Select, Textarea } from '@/components/ui'
import { Metric, PageTitle, ToggleField } from '@/components/fusion/shared'

const providerPresets = [
  {
    key: 'openai',
    title: 'GPT / OpenAI',
    description: 'GPT-4o、GPT-4.1、o 系列等官方 OpenAI 模型',
    baseUrl: 'https://api.openai.com/v1',
    model: 'gpt-4o-mini',
    tone: 'info',
  },
  {
    key: 'deepseek',
    title: 'DeepSeek',
    description: 'DeepSeek Chat / Reasoner，兼容 OpenAI Chat Completions',
    baseUrl: 'https://api.deepseek.com/v1',
    model: 'deepseek-chat',
    tone: 'success',
  },
  {
    key: 'anthropic',
    title: 'Claude / Claude Code',
    description: 'Claude Sonnet、Opus，以及 Claude Code 使用的 Anthropic API Key',
    baseUrl: 'https://api.anthropic.com/v1',
    model: 'claude-3-5-sonnet-latest',
    tone: 'warning',
  },
  {
    key: 'openai_compatible',
    title: 'OpenAI 兼容',
    description: '兼容 /v1/chat/completions 的中转、私有模型或第三方模型服务',
    baseUrl: '',
    model: '',
    tone: 'accent',
  },
] as const

const providerLabelMap: Record<string, string> = Object.fromEntries(providerPresets.map((item) => [item.key, item.title]))

export function AIAPIKeysView() {
  const queryClient = useQueryClient()
  const [drawerOpen, setDrawerOpen] = React.useState(false)
  const [editingKey, setEditingKey] = React.useState<AIAPIKey | null>(null)
  const [draft, setDraft] = React.useState<AIAPIKey>(() => createEmptyDraft('openai'))
  const [showSecret, setShowSecret] = React.useState(false)

  const query = useQuery({ queryKey: ['ai-api-keys'], queryFn: getAIAPIKeys })
  const keys = unwrap<AIAPIKey[]>(query.data) || []
  const enabledCount = keys.filter((item) => item.enabled !== false).length
  const defaultKey = keys.find((item) => item.isDefault)

  const saveMutation = useMutation({
    mutationFn: () => {
      const payload = { ...draft }
      if (editingKey?.id) return updateAIAPIKey(editingKey.id, payload)
      return createAIAPIKey(payload)
    },
    onSuccess: () => {
      toast.success(editingKey ? 'AI API Key 已更新' : 'AI API Key 已添加')
      setDrawerOpen(false)
      queryClient.invalidateQueries({ queryKey: ['ai-api-keys'] })
    },
    onError: (error: any) => toast.error(error?.message || '保存失败'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: number | string) => deleteAIAPIKey(id),
    onSuccess: () => {
      toast.success('AI API Key 已删除')
      queryClient.invalidateQueries({ queryKey: ['ai-api-keys'] })
    },
    onError: (error: any) => toast.error(error?.message || '删除失败'),
  })

  const testMutation = useMutation({
    mutationFn: (id: number | string) => testAIAPIKey(id),
    onSuccess: (response: any) => {
      const data = unwrap<any>(response)
      toast.success(data?.message || '连接测试成功')
      queryClient.invalidateQueries({ queryKey: ['ai-api-keys'] })
    },
    onError: (error: any) => toast.error(error?.message || '连接测试失败'),
  })

  const openCreate = (provider: AIProvider = 'openai') => {
    setEditingKey(null)
    setDraft(createEmptyDraft(provider))
    setShowSecret(false)
    setDrawerOpen(true)
  }

  const openEdit = (item: AIAPIKey) => {
    setEditingKey(item)
    setDraft({ ...item, apiKey: '' })
    setShowSecret(false)
    setDrawerOpen(true)
  }

  const applyProvider = (provider: AIProvider) => {
    const preset = providerPresets.find((item) => item.key === provider)
    setDraft({
      ...draft,
      provider,
      baseUrl: preset?.baseUrl ?? draft.baseUrl,
      model: preset?.model ?? draft.model,
    })
  }

  return (
    <div className="grid gap-4">
      <PageTitle title="AI API Key 管理" description="统一管理 GPT、DeepSeek、Claude Code 和 OpenAI 兼容模型的密钥，供 AI 对话页面直接调用。" />

      <div className="grid gap-4 md:grid-cols-3">
        <Metric label="Key 总数" value={String(keys.length)} icon={KeyRound} tone="info" badgeLabel="AI" />
        <Metric label="启用数量" value={String(enabledCount)} icon={CheckCircle2} tone="success" badgeLabel="启用" />
        <Metric label="默认模型" value={defaultKey?.model || '未设置'} icon={Star} tone="warning" badgeLabel={defaultKey ? providerLabel(defaultKey.provider) : '默认'} />
      </div>

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        {providerPresets.map((preset) => {
          const count = keys.filter((item) => item.provider === preset.key).length
          return (
            <button
              key={preset.key}
              type="button"
              className="group rounded-card border border-border bg-card p-4 text-left shadow-sm transition-all hover:-translate-y-0.5 hover:border-muted hover:bg-raised hover:shadow-lg"
              onClick={() => openCreate(preset.key)}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="flex size-10 items-center justify-center rounded-xl border border-border bg-background text-foreground">
                  <Bot className="size-5" />
                </span>
                <Badge tone={preset.tone as any}>{count} 个</Badge>
              </div>
              <div className="mt-3 text-base font-semibold text-foreground">{preset.title}</div>
              <div className="mt-1 min-h-10 text-xs leading-5 text-muted">{preset.description}</div>
              <div className="mt-3 flex items-center gap-2 text-xs text-info-foreground opacity-80 group-hover:opacity-100">
                <Plus className="size-3.5" />
                添加该服务商 Key
              </div>
            </button>
          )
        })}
      </div>

      <Card>
        <CardHeader>
          <div>
            <CardTitle>模型服务商配置</CardTitle>
            <CardDescription>每张卡片对应一个可用配置；默认 Key 会优先用于 AI 对话。</CardDescription>
          </div>
          <Button variant="default" onClick={() => openCreate('openai')}>
            <Plus className="size-4" />
            添加 Key
          </Button>
        </CardHeader>
        <CardContent>
          {query.isLoading ? (
            <div className="flex h-36 items-center justify-center text-sm text-muted"><Loader2 className="mr-2 size-4 animate-spin" />加载中...</div>
          ) : keys.length === 0 ? (
            <div className="rounded-card border border-dashed border-border bg-raised p-8 text-center">
              <div className="text-sm font-semibold text-foreground">暂无 AI API Key</div>
              <div className="mt-2 text-sm text-muted">点击上方服务商卡片或“添加 Key”开始配置。</div>
            </div>
          ) : (
            <div className="grid gap-3 lg:grid-cols-2">
              {keys.map((item) => (
                <AIKeyCard
                  key={item.id || `${item.provider}-${item.name}`}
                  item={item}
                  testing={testMutation.isPending}
                  deleting={deleteMutation.isPending}
                  onEdit={() => openEdit(item)}
                  onTest={() => item.id && testMutation.mutate(item.id)}
                  onDelete={() => item.id && window.confirm(`确认删除 ${item.name}？`) && deleteMutation.mutate(item.id)}
                  onSetDefault={() => item.id && updateAIAPIKey(item.id, { ...item, apiKey: '', isDefault: true, enabled: true }).then(() => {
                    toast.success('已设为默认 Key')
                    queryClient.invalidateQueries({ queryKey: ['ai-api-keys'] })
                  }).catch((error: any) => toast.error(error?.message || '设置失败'))}
                  onToggle={() => item.id && updateAIAPIKey(item.id, { ...item, apiKey: '', enabled: item.enabled === false, isDefault: item.enabled === false ? item.isDefault : false }).then(() => {
                    toast.success(item.enabled === false ? '已启用' : '已禁用')
                    queryClient.invalidateQueries({ queryKey: ['ai-api-keys'] })
                  }).catch((error: any) => toast.error(error?.message || '操作失败'))}
                />
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Drawer
        open={drawerOpen}
        onOpenChange={setDrawerOpen}
        title={editingKey ? '编辑 AI API Key' : '添加 AI API Key'}
        description="密钥只在保存时写入，列表中只显示脱敏内容；编辑时留空将保留原密钥。"
        className="max-w-xl"
        footer={
          <>
            <Button variant="outline" onClick={() => setDrawerOpen(false)}>取消</Button>
            <Button variant="default" disabled={saveMutation.isPending} onClick={() => saveMutation.mutate()}>
              {saveMutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <Save className="size-4" />}
              保存
            </Button>
          </>
        }
      >
        <div className="grid gap-4">
          <div className="grid gap-2 sm:grid-cols-2">
            {providerPresets.map((preset) => (
              <button
                key={preset.key}
                type="button"
                className={cn('rounded-card border p-3 text-left transition-colors hover:bg-raised', draft.provider === preset.key ? 'border-foreground bg-raised' : 'border-border bg-background')}
                onClick={() => applyProvider(preset.key)}
              >
                <div className="text-sm font-semibold text-foreground">{preset.title}</div>
                <div className="mt-1 truncate text-xs text-muted">{preset.model || '自定义模型'}</div>
              </button>
            ))}
          </div>
          <Field label="Key 名称">
            <Input value={draft.name || ''} onChange={(event) => setDraft({ ...draft, name: event.target.value })} placeholder="例如：OpenAI 生产 Key" />
          </Field>
          <Field label="服务商">
            <Select value={draft.provider || 'openai'} onChange={(event) => applyProvider(event.target.value)}>
              {providerPresets.map((preset) => <option key={preset.key} value={preset.key}>{preset.title}</option>)}
            </Select>
          </Field>
          <Field label="API Key" hint={editingKey ? `当前：${editingKey.maskedApiKey || '已保存'}，留空则不修改。` : '支持 sk-、sk-ant-、DeepSeek Key 或第三方兼容 Key。'}>
            <div className="flex gap-2">
              <Input type={showSecret ? 'text' : 'password'} value={draft.apiKey || ''} onChange={(event) => setDraft({ ...draft, apiKey: event.target.value })} placeholder={editingKey ? '留空保留原密钥' : '请输入 API Key'} />
              <Button type="button" variant="outline" size="icon" onClick={() => setShowSecret((value) => !value)}>{showSecret ? <EyeOff className="size-4" /> : <Eye className="size-4" />}</Button>
            </div>
          </Field>
          <Field label="Base URL">
            <Input value={draft.baseUrl || ''} onChange={(event) => setDraft({ ...draft, baseUrl: event.target.value })} placeholder="例如：https://api.openai.com/v1" />
          </Field>
          <Field label="默认模型">
            <Input value={draft.model || ''} onChange={(event) => setDraft({ ...draft, model: event.target.value })} placeholder="例如：gpt-4o-mini / deepseek-chat" />
          </Field>
          <Field label="备注">
            <Textarea value={draft.description || ''} onChange={(event) => setDraft({ ...draft, description: event.target.value })} placeholder="用途、额度、归属人等信息" className="min-h-20" />
          </Field>
          <div className="grid gap-3 rounded-card border border-border bg-raised p-3">
            <ToggleField label="启用该 Key" checked={draft.enabled !== false} onChange={(value) => setDraft({ ...draft, enabled: value, isDefault: value ? draft.isDefault : false })} />
            <ToggleField label="设为默认对话 Key" checked={Boolean(draft.isDefault)} onChange={(value) => setDraft({ ...draft, isDefault: value, enabled: value ? true : draft.enabled })} />
          </div>
        </div>
      </Drawer>
    </div>
  )
}

function AIKeyCard({ item, testing, deleting, onEdit, onTest, onDelete, onSetDefault, onToggle }: {
  item: AIAPIKey
  testing: boolean
  deleting: boolean
  onEdit: () => void
  onTest: () => void
  onDelete: () => void
  onSetDefault: () => void
  onToggle: () => void
}) {
  const statusTone = item.enabled === false ? 'neutral' : item.lastTestStatus === 'failed' ? 'danger' : item.lastTestStatus === 'success' ? 'success' : 'info'
  const statusLabel = item.enabled === false ? '已禁用' : item.lastTestStatus === 'failed' ? '测试失败' : item.lastTestStatus === 'success' ? '连接正常' : '未测试'
  return (
    <div className="group rounded-card border border-border bg-background p-4 transition-all hover:border-muted hover:bg-raised hover:shadow-md">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <div className="truncate text-sm font-semibold text-foreground">{item.name}</div>
            {item.isDefault ? <Badge tone="warning"><Star className="mr-1 size-3" />默认</Badge> : null}
            <Badge tone={statusTone as any}>{statusLabel}</Badge>
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted">
            <span>{providerLabel(item.provider)}</span>
            <span>·</span>
            <span className="font-mono">{item.model || '未设置模型'}</span>
          </div>
        </div>
        <div className="flex shrink-0 gap-1 opacity-100 md:opacity-0 md:transition-opacity md:group-hover:opacity-100">
          <Button size="sm" variant="outline" onClick={onEdit}><Edit3 className="size-3.5" />编辑</Button>
          <Button size="sm" variant="outline" disabled={testing || item.enabled === false} onClick={onTest}>{testing ? <Loader2 className="size-3.5 animate-spin" /> : <RefreshCw className="size-3.5" />}测试</Button>
        </div>
      </div>
      <div className="mt-4 grid gap-2 rounded-md border border-border bg-card p-3 text-xs">
        <div className="flex justify-between gap-3"><span className="text-muted">API Key</span><span className="font-mono text-foreground">{item.maskedApiKey || '未保存'}</span></div>
        <div className="flex justify-between gap-3"><span className="text-muted">Base URL</span><span className="max-w-[70%] truncate font-mono text-foreground">{item.baseUrl || '默认'}</span></div>
        <div className="flex justify-between gap-3"><span className="text-muted">更新时间</span><span className="text-foreground">{formatTime(item.updatedAt || item.createdAt || '') || '-'}</span></div>
        {item.lastTestMessage ? <div className="border-t border-border pt-2 text-muted">{item.lastTestMessage}</div> : null}
      </div>
      <div className="mt-3 flex flex-wrap justify-end gap-2">
        <Button size="sm" variant="outline" onClick={onToggle}>{item.enabled === false ? '启用' : '禁用'}</Button>
        <Button size="sm" variant="outline" disabled={item.isDefault || item.enabled === false} onClick={onSetDefault}><Star className="size-3.5" />设为默认</Button>
        <Button size="sm" variant="danger" disabled={deleting} onClick={onDelete}><Trash2 className="size-3.5" />删除</Button>
      </div>
    </div>
  )
}

function createEmptyDraft(provider: AIProvider): AIAPIKey {
  const preset = providerPresets.find((item) => item.key === provider) || providerPresets[0]
  return {
    provider,
    name: preset.title,
    apiKey: '',
    baseUrl: preset.baseUrl,
    model: preset.model,
    enabled: true,
    isDefault: false,
    description: '',
  }
}

function providerLabel(provider?: string) {
  return providerLabelMap[provider || ''] || provider || 'OpenAI 兼容'
}
