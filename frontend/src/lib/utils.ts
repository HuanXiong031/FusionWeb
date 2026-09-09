import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function unwrap<T = any>(value: any): T {
  if (value && typeof value === 'object' && 'code' in value && 'data' in value) {
    return value.data as T
  }
  if (value && typeof value === 'object' && 'data' in value && !Array.isArray(value.data)) {
    return value.data as T
  }
  return value as T
}

export function asList<T = any>(value: any): T[] {
  const data = unwrap<any>(value)
  if (Array.isArray(data)) return data
  if (Array.isArray(data?.items)) return data.items
  if (Array.isArray(data?.list)) return data.list
  if (Array.isArray(value?.items)) return value.items
  if (Array.isArray(value?.list)) return value.list
  if (Array.isArray(value?.data?.items)) return value.data.items
  if (Array.isArray(value?.data?.list)) return value.data.list
  return []
}

export function formatTime(value?: string | number | Date | null) {
  if (!value) return '-'
  if (typeof value === 'string') {
    const normalized = value.trim()
    const localTimeMatch = normalized.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?$/)
    if (localTimeMatch) {
      const [, year, month, day, hour, minute, second] = localTimeMatch
      return `${year}/${Number(month)}/${Number(day)} ${hour}:${minute}:${second}`
    }
    const goChinaTimeMatch = normalized.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.\d+)? \+0800 CST$/)
    if (goChinaTimeMatch) {
      const [, year, month, day, hour, minute, second] = goChinaTimeMatch
      return `${year}/${Number(month)}/${Number(day)} ${hour}:${minute}:${second}`
    }
    // Postgres timestamptz 格式，例如 "2026-09-09 07:48:24.99421 +0000" / "+08:00"，按偏移换算后显示为北京时间。
    const pgTzMatch = normalized.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?\s*([+-])(\d{2}):?(\d{2})$/)
    if (pgTzMatch) {
      const [, year, month, day, hour, minute, second, sign, offsetHour, offsetMinute] = pgTzMatch
      const offsetMinutes = (Number(offsetHour) * 60 + Number(offsetMinute)) * (sign === '-' ? -1 : 1)
      const epoch = Date.UTC(Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute), Number(second)) - offsetMinutes * 60000
      return formatChinaDisplayTime(new Date(epoch))
    }
  }
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return String(value)
  return formatChinaDisplayTime(date)
}

export function getTimeValue(value?: string | number | Date | null) {
  if (!value) return 0
  if (typeof value === 'string') {
    const normalized = value.trim()
    const localTimeMatch = normalized.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?$/)
    if (localTimeMatch) {
      const [, year, month, day, hour, minute, second] = localTimeMatch.map(Number)
      return new Date(year, month - 1, day, hour, minute, second).getTime()
    }
    const goChinaTimeMatch = normalized.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.\d+)? \+0800 CST$/)
    if (goChinaTimeMatch) {
      const [, year, month, day, hour, minute, second] = goChinaTimeMatch.map(Number)
      return new Date(year, month - 1, day, hour, minute, second).getTime()
    }
    const pgTzMatch = normalized.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?\s*([+-])(\d{2}):?(\d{2})$/)
    if (pgTzMatch) {
      const [, year, month, day, hour, minute, second, sign, offsetHour, offsetMinute] = pgTzMatch
      const offsetMinutes = (Number(offsetHour) * 60 + Number(offsetMinute)) * (sign === '-' ? -1 : 1)
      return Date.UTC(Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute), Number(second)) - offsetMinutes * 60000
    }
  }
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? 0 : date.getTime()
}

function formatChinaDisplayTime(date: Date) {
  const parts = new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai',
    hour12: false,
    hourCycle: 'h23',
    year: 'numeric',
    month: 'numeric',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).formatToParts(date)
  const value = Object.fromEntries(parts.map((part) => [part.type, part.value]))
  return `${value.year}/${Number(value.month)}/${Number(value.day)} ${value.hour}:${value.minute}:${value.second}`
}

export function currentChinaTimeString() {
  const parts = new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).formatToParts(new Date())
  const value = Object.fromEntries(parts.map((part) => [part.type, part.value]))
  return `${value.year}-${value.month}-${value.day} ${value.hour}:${value.minute}:${value.second}`
}

export function compactNumber(value: any) {
  const num = Number(value || 0)
  return new Intl.NumberFormat('zh-CN').format(num)
}

export function getStatusLabel(status?: string) {
  const map: Record<string, string> = {
    pending: '等待中',
    running: '运行中',
    paused: '已暂停',
    completed: '已完成',
    failed: '失败',
    cancelled: '已取消',
    canceling: '取消中',
  }
  return map[status || ''] || status || '-'
}

export function getStatusTone(status?: string) {
  if (status === 'completed') return 'success'
  if (status === 'running') return 'info'
  if (status === 'failed' || status === 'cancelled') return 'danger'
  if (status === 'paused' || status === 'pending') return 'warning'
  return 'neutral'
}

export function parseTargets(input?: string) {
  return (input || '')
    .split(/\r?\n|,|;/)
    .map((item) => item.trim())
    .filter(Boolean)
}
