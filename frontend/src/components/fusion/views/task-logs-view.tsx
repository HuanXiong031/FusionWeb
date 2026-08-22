'use client'

import * as React from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Bug, Download, Info, ListChecks, RefreshCw, Terminal, XCircle } from 'lucide-react'

import { getTaskLogs, getTasks, getVulnResults, type TaskRow } from '@/lib/api'
import { asList, formatTime, getTimeValue } from '@/lib/utils'
import { Button, Card, CardContent, Input, Select } from '@/components/ui'
import { getLogLevelLabel, getLogText, LogConsole } from '@/components/fusion/log-console'
import {
  demoTasks,
  downloadContent,
  getSeverityText,
  getTaskDisplayName,
  getTaskId,
  getVulnDisplayName,
  getVulnTarget,
  getVulnTemplateID,
  Metric,
  PageTitle,
  toCsv,
} from '@/components/fusion/shared'

type TaskLogRow = {
  id?: string | number
  entryType?: 'log' | 'vuln'
  time?: string
  createdAt?: string
  created_at?: string
  discoveredAt?: string
  discovered_at?: string
  level?: string
  type?: string
  severity?: string
  message?: string
  msg?: string
  content?: string
  target?: string
  templateID?: string
  vulnName?: string
  [key: string]: any
}

function getRowTime(row: TaskLogRow) {
  return row.time || row.createdAt || row.created_at || row.discoveredAt || row.discovered_at || ''
}

function getTimeScore(row: TaskLogRow) {
  return getTimeValue(getRowTime(row))
}

function getRowText(row: TaskLogRow) {
  return getLogText(row)
}

function getVulnLogLevel(severity: string) {
  if (severity === 'critical' || severity === 'high') return 'error'
  if (severity === 'medium') return 'warning'
  return 'info'
}

export function TaskLogsView({ demoMode }: { demoMode: boolean }) {
  const queryClient = useQueryClient()
  const [selectedTaskId, setSelectedTaskId] = React.useState('')
  const [level, setLevel] = React.useState('')
  const [keyword, setKeyword] = React.useState('')
  const tasksQuery = useQuery({ queryKey: ['tasks'], queryFn: getTasks, enabled: !demoMode })
  const tasks = demoMode ? demoTasks : asList<TaskRow>(tasksQuery.data)

  React.useEffect(() => {
    if (selectedTaskId || !tasks.length) return
    setSelectedTaskId(getTaskId(tasks[0]))
  }, [selectedTaskId, tasks])

  const logsQuery = useQuery({
    queryKey: ['task-logs-page', selectedTaskId],
    queryFn: () => getTaskLogs(selectedTaskId, { page: 1, pageSize: 500 }),
    enabled: !!selectedTaskId && !demoMode,
    refetchInterval: 5000,
  })
  const vulnQuery = useQuery({
    queryKey: ['task-logs-vulns', selectedTaskId],
    queryFn: () => getVulnResults(selectedTaskId),
    enabled: !!selectedTaskId && !demoMode,
    refetchInterval: 5000,
  })

  const logs: TaskLogRow[] = demoMode
    ? [
        { time: '2026-07-05 10:12:30', level: 'info', message: '任务开始执行', taskId: 'demo-1' },
        { time: '2026-07-05 10:12:36', level: 'success', message: '发现开放端口 443', taskId: 'demo-1' },
        { time: '2026-07-05 10:13:02', level: 'warning', message: '目标响应超时，已重试', taskId: 'demo-1' },
      ]
    : asList<TaskLogRow>(logsQuery.data)
  const vulns: TaskLogRow[] = demoMode
    ? [
        {
          id: 'demo-vuln-1',
          target: 'https://demo.example.com',
          severity: 'high',
          name: 'Spring Actuator 暴露',
          templateID: 'spring-actuator-exposure',
          discovered_at: '2026-07-05 10:13:18',
        },
      ]
    : asList<TaskLogRow>(vulnQuery.data)

  const vulnLogs = React.useMemo<TaskLogRow[]>(() => vulns.map((vuln, index) => {
    const severity = String(vuln.severity || vuln.info?.severity || 'info').toLowerCase()
    const name = getVulnDisplayName(vuln)
    const target = getVulnTarget(vuln)
    const template = getVulnTemplateID(vuln)
    return {
      id: `vuln-${vuln.id || vuln.resultId || vuln.result_id || index}`,
      entryType: 'vuln',
      time: vuln.discoveredAt || vuln.discovered_at || vuln.createdAt || vuln.created_at || vuln.time,
      level: getVulnLogLevel(severity),
      severity,
      message: `发现漏洞：${name}，等级：${getSeverityText(severity)}，目标：${target}，模板：${template}`,
      vulnName: name,
      target,
      templateID: template,
      taskId: selectedTaskId,
      raw: vuln,
    }
  }), [selectedTaskId, vulns])

  const allLogs = React.useMemo<TaskLogRow[]>(() => [
    ...logs.map((row, index) => ({ id: row.id || `log-${index}`, entryType: 'log' as const, ...row })),
    ...vulnLogs,
  ].sort((left, right) => getTimeScore(right) - getTimeScore(left)), [logs, vulnLogs])

  const normalizedKeyword = keyword.trim().toLowerCase()
  const rows = allLogs.filter((row) => {
    const rowLevel = String(row.level || row.type || 'info').toLowerCase()
    if (level === 'vuln' && row.entryType !== 'vuln') return false
    if (level && level !== 'vuln' && rowLevel !== level) return false
    if (!normalizedKeyword) return true
    return JSON.stringify(row).toLowerCase().includes(normalizedKeyword)
  })
  const errorCount = allLogs.filter((row) => String(row.level || '').toLowerCase().includes('error')).length
  const warnCount = allLogs.filter((row) => String(row.level || '').toLowerCase().includes('warn')).length
  const currentTask = tasks.find((task) => getTaskId(task) === selectedTaskId)

  const exportRows = rows.map((row) => ({
    time: formatTime(getRowTime(row)),
    type: row.entryType === 'vuln' ? '漏洞' : '日志',
    level: row.entryType === 'vuln' ? getSeverityText(row.severity || 'info') : row.level || row.type || 'info',
    content: getRowText(row),
    target: row.target || '',
    templateID: row.templateID || '',
  }))

  return (
    <div className="grid gap-4">
      <PageTitle title="运行日志" description="选择单个扫描任务后，从后端任务日志接口读取该任务的运行日志，并合并展示该任务扫描出的漏洞信息。" />
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <Metric label="日志总数" value={allLogs.length} icon={Terminal} tone="info" badgeLabel="总数" />
        <Metric label="漏洞" value={vulns.length} icon={Bug} tone="danger" badgeLabel="漏洞" />
        <Metric label="错误" value={errorCount} icon={XCircle} tone="accent" badgeLabel="错误" />
        <Metric label="警告" value={warnCount} icon={Info} tone="warning" badgeLabel="警告" />
        <Metric label="当前任务" value={currentTask ? getTaskDisplayName(currentTask) : '-'} icon={ListChecks} tone="neutral" badgeLabel="任务" />
      </div>
      <Card>
        <CardContent className="grid gap-3 p-4 lg:grid-cols-[1.2fr_160px_1fr_auto]">
          <Select value={selectedTaskId} onChange={(event) => setSelectedTaskId(event.target.value)}>
            <option value="">选择单个任务</option>
            {tasks.map((task) => {
              const id = getTaskId(task)
              return <option key={id} value={id}>{getTaskDisplayName(task)}</option>
            })}
          </Select>
          <Select value={level} onChange={(event) => setLevel(event.target.value)}>
            <option value="">全部类型</option>
            <option value="vuln">漏洞</option>
            <option value="info">{getLogLevelLabel('info')}</option>
            <option value="success">{getLogLevelLabel('success')}</option>
            <option value="warning">{getLogLevelLabel('warning')}</option>
            <option value="error">{getLogLevelLabel('error')}</option>
          </Select>
          <Input value={keyword} onChange={(event) => setKeyword(event.target.value)} placeholder="过滤日志或漏洞内容" />
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" disabled={!selectedTaskId} onClick={() => {
              queryClient.invalidateQueries({ queryKey: ['task-logs-page', selectedTaskId] })
              queryClient.invalidateQueries({ queryKey: ['task-logs-vulns', selectedTaskId] })
            }}>
              <RefreshCw className="size-4" />刷新
            </Button>
            <Button variant="outline" disabled={!rows.length} onClick={() => downloadContent(toCsv(exportRows), `task-logs-${selectedTaskId || 'all'}.csv`, 'text/csv')}>
              <Download className="size-4" />导出
            </Button>
          </div>
        </CardContent>
      </Card>
      <LogConsole rows={rows} emptyTitle={selectedTaskId ? '暂无任务日志或漏洞信息' : '请选择任务'} />
    </div>
  )
}
