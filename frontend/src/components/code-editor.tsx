'use client'

import * as React from 'react'
import { basicSetup, EditorView } from 'codemirror'
import { yaml } from '@codemirror/lang-yaml'
import { oneDark } from '@codemirror/theme-one-dark'
import { cn } from '@/lib/utils'

export function CodeEditor({
  value,
  onChange,
  className,
  minHeight = 320,
  placeholder = '输入 YAML 内容...',
  fixedHeight = true,
  readOnly = false,
}: {
  value: string
  onChange: (value: string) => void
  className?: string
  minHeight?: number
  placeholder?: string
  fixedHeight?: boolean
  readOnly?: boolean
}) {
  const hostRef = React.useRef<HTMLDivElement | null>(null)
  const viewRef = React.useRef<EditorView | null>(null)
  const onChangeRef = React.useRef(onChange)

  React.useEffect(() => {
    onChangeRef.current = onChange
  }, [onChange])

  React.useEffect(() => {
    if (!hostRef.current || viewRef.current) return
    const view = new EditorView({
      doc: value,
      parent: hostRef.current,
      extensions: [
        basicSetup,
        yaml(),
        oneDark,
        EditorView.editable.of(!readOnly),
        EditorView.lineWrapping,
        EditorView.theme({
          '&': {
            minHeight: `${minHeight}px`,
            height: fixedHeight ? `${minHeight}px` : '100%',
            backgroundColor: '#2b2f34 !important',
            fontSize: '13px',
          },
          '&.cm-editor, .cm-editor, .cm-content': {
            backgroundColor: '#2b2f34 !important',
          },
          '.cm-scroller': {
            minHeight: fixedHeight ? `${minHeight}px` : 0,
            ...(fixedHeight ? { height: `${minHeight}px` } : { height: '100%' }),
            overflow: 'auto',
            backgroundColor: '#2b2f34 !important',
            fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace',
            lineHeight: '24px',
          },
          '.cm-content': {
            paddingTop: '12px',
            paddingBottom: '12px',
          },
          '.cm-gutters': {
            backgroundColor: '#2b2f34',
            borderRight: '0',
            color: '#758194',
          },
          '.cm-activeLine, .cm-activeLineGutter': {
            backgroundColor: 'transparent',
          },
          '.cm-selectionBackground, .cm-selectionLayer .cm-selectionBackground, &.cm-focused .cm-selectionBackground': {
            background: 'color-mix(in srgb, var(--info) 60%, transparent) !important',
            backgroundColor: 'color-mix(in srgb, var(--info) 60%, transparent) !important',
          },
          '.cm-content ::selection': {
            background: 'color-mix(in srgb, var(--info) 60%, transparent) !important',
            backgroundColor: 'color-mix(in srgb, var(--info) 60%, transparent) !important',
            color: '#ffffff !important',
          },
          '.cm-selectionMatch, .cm-searchMatch, .cm-searchMatch-selected': {
            background: 'color-mix(in srgb, var(--info) 38%, transparent) !important',
            backgroundColor: 'color-mix(in srgb, var(--info) 38%, transparent) !important',
          },
          '.cm-placeholder': {
            color: '#758194',
          },
        }),
        EditorView.updateListener.of((update) => {
          if (update.docChanged) onChangeRef.current(update.state.doc.toString())
        }),
      ],
    })
    viewRef.current = view
    return () => {
      view.destroy()
      viewRef.current = null
    }
  }, [fixedHeight, minHeight, readOnly])

  React.useEffect(() => {
    const view = viewRef.current
    if (!view) return
    const current = view.state.doc.toString()
    if (current !== value) {
      view.dispatch({
        changes: { from: 0, to: current.length, insert: value },
      })
    }
  }, [value])

  return (
    <div className={cn('overflow-hidden rounded-card border border-border bg-background', className)}>
      <div ref={hostRef} className="h-full" data-placeholder={placeholder} />
    </div>
  )
}
