'use client'

import * as React from 'react'

import { cn, formatTime } from '@/lib/utils'

export type LogConsoleRow = {
  id?: string | number
  entryType?: 'log' | 'vuln' | string
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
  [key: string]: any
}

function normalizeLevel(level?: string) {
  return String(level || 'info').trim().toLowerCase()
}

export function getLogLevelLabel(level?: string) {
  const value = normalizeLevel(level)
  if (value.includes('error') || value.includes('fail')) return '错误'
  if (value.includes('warn')) return '警告'
  if (value.includes('success') || value.includes('ok') || value.includes('done')) return '成功'
  if (value.includes('debug')) return '调试'
  if (value.includes('critical')) return '严重'
  if (value.includes('high')) return '高危'
  if (value.includes('medium')) return '中危'
  if (value.includes('low')) return '低危'
  if (value.includes('info')) return '信息'
  return level || '信息'
}

function getLogLevelClass(level?: string, entryType?: string) {
  const value = normalizeLevel(level)
  if (entryType === 'vuln') return 'text-rose-300'
  if (value.includes('error') || value.includes('fail')) return 'text-rose-300'
  if (value.includes('warn') || value.includes('medium')) return 'text-amber-300'
  if (value.includes('success') || value.includes('ok') || value.includes('done')) return 'text-emerald-300'
  if (value.includes('debug')) return 'text-slate-400'
  if (value.includes('critical') || value.includes('high')) return 'text-rose-300'
  return 'text-sky-300'
}

function getLogTime(row: LogConsoleRow) {
  return row.time || row.createdAt || row.created_at || row.discoveredAt || row.discovered_at || ''
}

export function getLogText(row: LogConsoleRow) {
  return localizeLogText(row.message || row.msg || row.content || JSON.stringify(row))
}

function localizeLogText(value: string) {
  const text = String(value || '').trim()
  const unsignedMatch = text.match(/^Loading\s+(\d+)\s+unsigned\s+templates\s+for\s+scan\.?\s+Use\s+with\s+caution\.?$/i)
  if (unsignedMatch) return `正在加载 ${unsignedMatch[1]} 个未签名模板用于扫描，请谨慎使用。`
  const map: Record<string, string> = {
    'scan completed': '扫描已完成',
    'scan failed': '扫描失败',
    'scan cancelled': '扫描已取消',
    'scan stopped': '扫描已停止',
    'no templates provided for scan': '未提供可用于扫描的模板',
    'no results found': '未发现结果',
  }
  return map[text.toLowerCase()] || text
}

function getLogLineLabel(row: LogConsoleRow) {
  if (row.entryType === 'vuln') return `漏洞/${getLogLevelLabel(row.severity || row.level)}`
  return getLogLevelLabel(row.level || row.type)
}

export function LogConsole({
  rows,
  emptyTitle,
  className,
  maxHeightClass = 'max-h-[620px]',
}: {
  rows: LogConsoleRow[]
  emptyTitle: string
  className?: string
  maxHeightClass?: string
}) {
  return (
    <section className={cn('overflow-hidden rounded-card border border-border bg-[#0b1020] shadow-sm', className)}>
      <div className="flex h-10 items-center justify-between gap-3 border-b border-white/10 bg-[#111827] px-4 text-xs text-slate-300">
        <div className="flex items-center gap-2">
          <span className="size-2.5 rounded-full bg-rose-400" />
          <span className="size-2.5 rounded-full bg-amber-300" />
          <span className="size-2.5 rounded-full bg-emerald-400" />
          <span className="ml-2 font-mono text-slate-200">FusionWeb 终端</span>
        </div>
        <span className="font-mono text-slate-400">{rows.length} 条</span>
      </div>
      <div className={cn('overflow-auto p-4 font-mono text-[13px] leading-6', maxHeightClass)} role="log">
        {rows.length ? rows.map((row, index) => {
          const rowLevel = row.entryType === 'vuln' ? row.severity || row.level : row.level || row.type
          return (
            <div key={row.id || `${getLogTime(row)}-${index}`} className="grid grid-cols-[156px_88px_1fr] gap-3 border-b border-white/[0.04] py-1.5 last:border-b-0">
              <span className="whitespace-nowrap text-slate-500">{formatTime(getLogTime(row))}</span>
              <span className={cn('whitespace-nowrap', getLogLevelClass(rowLevel, row.entryType))}>[{getLogLineLabel(row)}]</span>
              <span className="min-w-0 break-all text-slate-100">{getLogText(row)}</span>
            </div>
          )
        }) : (
          <div className="flex h-40 items-center justify-center text-sm text-slate-500">{emptyTitle}</div>
        )}
      </div>
    </section>
  )
}
