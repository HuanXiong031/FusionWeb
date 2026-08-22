'use client'

import * as React from 'react'
import { ImageIcon, Loader2 } from 'lucide-react'
import { getReconScreenshot } from '@/lib/api'
import { Modal } from '@/components/ui'

function resolveBlob(response: any): Blob | null {
  if (response instanceof Blob) return response
  if (response?.data instanceof Blob) return response.data
  return null
}

export function ScreenshotPreviewCell({
  taskId,
  resultId,
  screenshotPath,
  label,
}: {
  taskId?: string
  resultId?: number | string
  screenshotPath?: string
  label?: string
}) {
  const [imageURL, setImageURL] = React.useState('')
  const [isOpen, setIsOpen] = React.useState(false)
  const [failed, setFailed] = React.useState(false)

  React.useEffect(() => {
    if (!taskId || !resultId || !screenshotPath) {
      setImageURL('')
      setFailed(false)
      return
    }

    let objectURL = ''
    let cancelled = false
    setImageURL('')
    setFailed(false)

    getReconScreenshot(taskId, resultId)
      .then((response) => {
        const blob = resolveBlob(response)
        if (!blob || cancelled) return
        objectURL = URL.createObjectURL(blob)
        setImageURL(objectURL)
      })
      .catch(() => {
        if (!cancelled) setFailed(true)
      })

    return () => {
      cancelled = true
      if (objectURL) URL.revokeObjectURL(objectURL)
    }
  }, [taskId, resultId, screenshotPath])

  if (!screenshotPath) {
    return <span className="text-muted">-</span>
  }

  if (failed) {
    return <span className="text-xs text-muted">加载失败</span>
  }

  const title = label || '页面截图'

  return (
    <>
      <button
        type="button"
        className="inline-flex h-12 w-20 items-center justify-center overflow-hidden rounded-md border border-border bg-background text-muted transition-colors hover:border-info/60 hover:bg-raised"
        onClick={() => imageURL && setIsOpen(true)}
        title={imageURL ? '点击放大截图' : '截图加载中'}
      >
        {imageURL ? (
          <img src={imageURL} alt={title} className="h-full w-full object-cover" />
        ) : (
          <Loader2 className="size-4 animate-spin" />
        )}
      </button>
      <Modal
        open={isOpen}
        onOpenChange={setIsOpen}
        title="截图预览"
        description={title}
        className="max-w-none md:w-[82vw]"
      >
        {imageURL ? (
          <div className="flex min-h-[55vh] items-center justify-center rounded-card border border-border bg-background p-3">
            <img src={imageURL} alt={title} className="max-h-[74vh] max-w-full rounded-md object-contain" />
          </div>
        ) : (
          <div className="flex min-h-48 items-center justify-center gap-2 text-muted">
            <ImageIcon className="size-4" />
            暂无截图
          </div>
        )}
      </Modal>
    </>
  )
}
