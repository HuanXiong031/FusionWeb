'use client'

import * as React from 'react'
import {
  ColumnDef,
  OnChangeFn,
  PaginationState,
  functionalUpdate,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  useReactTable,
} from '@tanstack/react-table'
import { Button, EmptyState, Input, Select } from '@/components/ui'
import { cn } from '@/lib/utils'

const PAGE_SIZE_OPTIONS = [10, 30, 50, 100, 300, 500, 1000]
const DEFAULT_PAGINATION: PaginationState = { pageIndex: 0, pageSize: 10 }
const PAGINATION_STORAGE_PREFIX = 'fusionweb:data-table-pagination:'

interface DataTableProps<TData, TValue> {
  columns: ColumnDef<TData, TValue>[]
  data: TData[]
  searchPlaceholder?: string
  showSearch?: boolean
  toolbar?: React.ReactNode
  emptyTitle?: string
  className?: string
  tableClassName?: string
  pagination?: PaginationState
  onPaginationChange?: OnChangeFn<PaginationState>
  paginationStorageKey?: string
  manualPagination?: boolean
  pageCount?: number
  totalRows?: number
}

function readStoredPagination(storageKey?: string): PaginationState {
  if (!storageKey || typeof window === 'undefined') return DEFAULT_PAGINATION
  try {
    const raw = window.localStorage.getItem(`${PAGINATION_STORAGE_PREFIX}${storageKey}`)
    if (!raw) return DEFAULT_PAGINATION
    const parsed = JSON.parse(raw)
    const pageIndex = Number(parsed?.pageIndex)
    const pageSize = Number(parsed?.pageSize)
    return {
      pageIndex: Number.isFinite(pageIndex) && pageIndex >= 0 ? Math.floor(pageIndex) : DEFAULT_PAGINATION.pageIndex,
      pageSize: Number.isFinite(pageSize) && pageSize > 0 ? Math.floor(pageSize) : DEFAULT_PAGINATION.pageSize,
    }
  } catch {
    return DEFAULT_PAGINATION
  }
}

function writeStoredPagination(storageKey: string | undefined, pagination: PaginationState) {
  if (!storageKey || typeof window === 'undefined') return
  window.localStorage.setItem(`${PAGINATION_STORAGE_PREFIX}${storageKey}`, JSON.stringify(pagination))
}

function getColumnAlign(columnDef: { meta?: unknown }) {
  return (columnDef.meta as { align?: 'left' | 'center' | 'right' } | undefined)?.align
}

function getColumnClassName(columnDef: { meta?: unknown }) {
  return (columnDef.meta as { className?: string } | undefined)?.className
}

function getPageButtons(currentPage: number, pageCount: number) {
  if (pageCount <= 7) return Array.from({ length: pageCount }, (_, index) => index)

  const pages = new Set([0, pageCount - 1, currentPage - 1, currentPage, currentPage + 1])

  if (currentPage <= 2) {
    pages.add(1)
    pages.add(2)
    pages.add(3)
  }

  if (currentPage >= pageCount - 3) {
    pages.add(pageCount - 2)
    pages.add(pageCount - 3)
    pages.add(pageCount - 4)
  }

  return Array.from(pages)
    .filter((page) => page >= 0 && page < pageCount)
    .sort((a, b) => a - b)
    .reduce<Array<number | 'ellipsis'>>((items, page) => {
      const previous = items[items.length - 1]
      if (typeof previous === 'number' && page - previous > 1) items.push('ellipsis')
      items.push(page)
      return items
    }, [])
}

export function DataTable<TData, TValue>({
  columns,
  data,
  searchPlaceholder = '搜索...',
  showSearch = true,
  toolbar,
  emptyTitle,
  className,
  tableClassName,
  pagination,
  onPaginationChange,
  paginationStorageKey,
  manualPagination = false,
  pageCount: controlledPageCount,
  totalRows,
}: DataTableProps<TData, TValue>) {
  const [globalFilter, setGlobalFilter] = React.useState('')
  const [pageJump, setPageJump] = React.useState('1')
  const [internalPagination, setInternalPagination] = React.useState<PaginationState>(() => readStoredPagination(paginationStorageKey))
  const activePagination = pagination ?? internalPagination
  const handlePaginationChange = React.useCallback<OnChangeFn<PaginationState>>((updater) => {
    if (pagination) {
      onPaginationChange?.(updater)
      return
    }
    setInternalPagination((current) => functionalUpdate(updater, current))
  }, [onPaginationChange, pagination])

  React.useEffect(() => {
    if (!pagination) setInternalPagination(readStoredPagination(paginationStorageKey))
  }, [pagination, paginationStorageKey])

  React.useEffect(() => {
    writeStoredPagination(paginationStorageKey, activePagination)
  }, [activePagination, paginationStorageKey])

  const table = useReactTable({
    data,
    columns,
    state: { globalFilter, pagination: activePagination },
    onGlobalFilterChange: setGlobalFilter,
    onPaginationChange: handlePaginationChange,
    autoResetPageIndex: false,
    manualPagination,
    pageCount: manualPagination ? controlledPageCount : undefined,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: manualPagination ? undefined : getPaginationRowModel(),
  })
  const pageCount = table.getPageCount()
  const safePageCount = Math.max(pageCount, 1)
  const currentPage = table.getState().pagination.pageIndex
  const pageSize = table.getState().pagination.pageSize
  const pageButtons = getPageButtons(currentPage, pageCount)
  const displayedRows = table.getRowModel().rows.length
  const totalItems = manualPagination ? (totalRows ?? data.length) : table.getFilteredRowModel().rows.length

  React.useEffect(() => {
    if (pageCount > 0 && currentPage >= pageCount) {
      table.setPageIndex(pageCount - 1)
    }
  }, [currentPage, pageCount, table])

  React.useEffect(() => {
    setPageJump(String(Math.min(currentPage + 1, safePageCount)))
  }, [currentPage, safePageCount])

  const jumpToPage = () => {
    const page = Number.parseInt(pageJump, 10)
    if (Number.isNaN(page)) {
      setPageJump(String(currentPage + 1))
      return
    }
    const nextPage = Math.min(Math.max(page, 1), safePageCount)
    table.setPageIndex(nextPage - 1)
    setPageJump(String(nextPage))
  }

  return (
    <div className={cn('w-full min-w-0 overflow-hidden rounded-card border border-border bg-card', className)}>
      {showSearch || toolbar ? (
        <div className="flex flex-col gap-3 border-b border-border p-4 md:flex-row md:items-center md:justify-between">
          {showSearch ? (
            <Input
              className="max-w-sm"
              value={globalFilter ?? ''}
              placeholder={searchPlaceholder}
              onChange={(event) => setGlobalFilter(event.target.value)}
            />
          ) : null}
          {toolbar ? <div className="flex flex-wrap items-center gap-2">{toolbar}</div> : null}
        </div>
      ) : null}
      <div className="min-w-0 max-w-full overflow-x-auto">
        <table className={cn('w-full caption-bottom text-sm', tableClassName)}>
          <thead>
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id} className="border-b border-border text-left text-xs text-muted">
                {headerGroup.headers.map((header) => {
                  const align = getColumnAlign(header.column.columnDef)
                  return (
                    <th
                      key={header.id}
                      className={cn(
                        'h-11 whitespace-nowrap px-4 font-semibold',
                        align === 'right' && 'text-right',
                        align === 'center' && 'text-center',
                        align !== 'right' && align !== 'center' && 'text-left',
                        getColumnClassName(header.column.columnDef)
                      )}
                    >
                      {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                    </th>
                  )
                })}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.length ? (
              table.getRowModel().rows.map((row) => (
                <tr key={row.id} className="border-b border-border transition-colors hover:bg-raised/70">
                  {row.getVisibleCells().map((cell) => {
                    const align = getColumnAlign(cell.column.columnDef)
                    return (
                      <td key={cell.id} className={cn('px-4 py-3 align-middle', getColumnClassName(cell.column.columnDef), align === 'right' && 'text-right', align === 'center' && 'text-center')}>
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    )
                  })}
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={columns.length} className="p-6">
                  <EmptyState title={emptyTitle || '暂无数据'} />
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="flex min-w-0 flex-col gap-3 p-4 text-sm text-muted xl:flex-row xl:items-center xl:justify-between">
        <span>
          已显示 {displayedRows} 项 / 共 {totalItems} 项
        </span>
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <span className="text-xs text-muted">每页</span>
          <Select
            className="h-8 w-[92px] px-2"
            value={String(pageSize)}
            onChange={(event) => {
              table.setPageSize(Number(event.target.value))
              table.setPageIndex(0)
            }}
          >
            {PAGE_SIZE_OPTIONS.map((size) => (
              <option key={size} value={size}>{size}</option>
            ))}
          </Select>
          <Button variant="outline" size="sm" onClick={() => table.previousPage()} disabled={!table.getCanPreviousPage()}>
            上一页
          </Button>
          {pageButtons.map((page, index) =>
            page === 'ellipsis' ? (
              <span key={`ellipsis-${index}`} className="flex h-8 min-w-8 items-center justify-center px-1 text-muted">
                ...
              </span>
            ) : (
              <Button
                key={page}
                variant={page === currentPage ? 'default' : 'outline'}
                size="sm"
                className="min-w-8 px-2"
                onClick={() => table.setPageIndex(page)}
              >
                {page + 1}
              </Button>
            )
          )}
          <Button variant="outline" size="sm" onClick={() => table.nextPage()} disabled={!table.getCanNextPage()}>
            下一页
          </Button>
          <span className="text-xs text-muted">跳至</span>
          <Input
            className="h-8 w-[72px] px-2 text-center"
            type="number"
            min={1}
            max={safePageCount}
            value={pageJump}
            onChange={(event) => setPageJump(event.target.value)}
            onBlur={jumpToPage}
            onKeyDown={(event) => {
              if (event.key === 'Enter') jumpToPage()
            }}
          />
          <span className="text-xs text-muted">页</span>
          <Button variant="outline" size="sm" onClick={jumpToPage} disabled={pageCount <= 1}>
            跳转
          </Button>
        </div>
      </div>
    </div>
  )
}
