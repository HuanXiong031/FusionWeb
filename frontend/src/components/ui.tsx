'use client'

import * as React from 'react'
import * as DialogPrimitive from '@radix-ui/react-dialog'
import * as TabsPrimitive from '@radix-ui/react-tabs'
import { Slot } from '@radix-ui/react-slot'
import { X } from 'lucide-react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const buttonVariants = cva(
  'inline-flex h-8 shrink-0 items-center justify-center gap-2 whitespace-nowrap rounded-md border px-3 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-muted disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-4',
  {
    variants: {
      variant: {
        default: 'border-foreground bg-foreground text-background hover:border-muted hover:bg-muted hover:text-background',
        secondary: 'border-border bg-panel text-foreground hover:bg-raised',
        ghost: 'border-transparent bg-transparent text-foreground hover:bg-raised',
        danger: 'border-danger/35 bg-danger/10 text-danger-foreground hover:bg-danger/20',
        outline: 'border-border bg-transparent text-foreground hover:bg-raised',
      },
      size: {
        default: 'h-8 px-3',
        sm: 'h-7 px-2 text-xs',
        icon: 'size-8 p-0',
      },
    },
    defaultVariants: {
      variant: 'secondary',
      size: 'default',
    },
  }
)

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : 'button'
    return <Comp className={cn(buttonVariants({ variant, size, className }))} ref={ref} {...props} />
  }
)
Button.displayName = 'Button'

export function Card({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn('rounded-card border border-border bg-card text-foreground shadow-sm', className)}
      {...props}
    />
  )
}

export function CardHeader({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('flex items-center justify-between gap-3 border-b border-border px-6 py-4', className)} {...props} />
}

export function CardTitle({ className, ...props }: React.HTMLAttributes<HTMLHeadingElement>) {
  return <h3 className={cn('text-base font-semibold leading-none text-foreground', className)} {...props} />
}

export function CardDescription({ className, ...props }: React.HTMLAttributes<HTMLParagraphElement>) {
  return <p className={cn('mt-1 text-sm text-muted', className)} {...props} />
}

export function CardContent({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('p-6', className)} {...props} />
}

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        'h-9 w-full rounded-md border border-border bg-background px-3 text-sm text-foreground outline-none transition-colors placeholder:text-subtle focus:border-muted',
        className
      )}
      {...props}
    />
  )
)
Input.displayName = 'Input'

export function Textarea({ className, ...props }: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      className={cn(
        'min-h-28 w-full resize-none overflow-auto rounded-md border border-border bg-background px-3 py-2 font-mono text-sm text-foreground outline-none transition-colors placeholder:text-subtle focus:border-muted',
        className
      )}
      {...props}
    />
  )
}

export function Select({ className, children, ...props }: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={cn(
        'h-9 w-full rounded-md border border-border bg-background px-3 text-sm text-foreground outline-none focus:border-muted',
        className
      )}
      {...props}
    >
      {children}
    </select>
  )
}

const badgeVariants = cva('inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium', {
  variants: {
    tone: {
      neutral: 'border-border bg-raised text-foreground',
      success: 'border-success/35 bg-success/10 text-success-foreground',
      warning: 'border-warning/35 bg-warning/10 text-warning-foreground',
      danger: 'border-danger/35 bg-danger/10 text-danger-foreground',
      info: 'border-info/35 bg-info/10 text-info-foreground',
      accent: 'border-accent/35 bg-accent/10 text-accent-foreground',
    },
  },
  defaultVariants: {
    tone: 'neutral',
  },
})

export function Badge({
  className,
  tone,
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badgeVariants>) {
  return <span className={cn(badgeVariants({ tone, className }))} {...props} />
}

export function Field({
  label,
  hint,
  reserveHint,
  children,
}: {
  label: string
  hint?: string
  reserveHint?: boolean
  children: React.ReactNode
}) {
  return (
    <label className="grid gap-2">
      <span className="text-sm font-medium text-foreground">{label}</span>
      {children}
      {hint ? <span className="text-xs leading-5 text-muted">{hint}</span> : null}
      {!hint && reserveHint ? <span aria-hidden="true" className="invisible text-xs leading-5 text-muted">placeholder</span> : null}
    </label>
  )
}

export function EmptyState({ title = '暂无数据', description }: { title?: string; description?: string }) {
  return (
    <div className="flex min-h-48 flex-col items-center justify-center rounded-card border border-dashed border-border bg-card p-8 text-center">
      <div className="text-sm font-semibold text-foreground">{title}</div>
      {description ? <div className="mt-2 max-w-sm text-sm text-muted">{description}</div> : null}
    </div>
  )
}

export function Modal({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  className,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  description?: string
  children: React.ReactNode
  footer?: React.ReactNode
  className?: string
}) {
  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm" />
        <DialogPrimitive.Content
          className={cn(
            'fixed left-1/2 top-1/2 z-50 flex max-h-[88vh] w-[calc(100vw-32px)] max-w-3xl -translate-x-1/2 -translate-y-1/2 flex-col overflow-hidden rounded-card border border-border bg-card text-foreground shadow-2xl outline-none',
            className
          )}
        >
          <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
            <div>
              <DialogPrimitive.Title className="text-base font-semibold">{title}</DialogPrimitive.Title>
              {description ? <DialogPrimitive.Description className="mt-1 text-sm text-muted">{description}</DialogPrimitive.Description> : null}
            </div>
            <DialogPrimitive.Close asChild>
              <Button variant="ghost" size="icon" aria-label="关闭">
                <X className="size-4" />
              </Button>
            </DialogPrimitive.Close>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden p-5 [scrollbar-gutter:stable]">{children}</div>
          {footer ? <div className="flex justify-end gap-2 border-t border-border px-5 py-4">{footer}</div> : null}
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  )
}

export function Drawer({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  className,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  description?: string
  children: React.ReactNode
  footer?: React.ReactNode
  className?: string
}) {
  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm" />
        <DialogPrimitive.Content
          className={cn(
            'fixed bottom-0 right-0 top-0 z-50 flex w-[calc(100vw-24px)] max-w-3xl flex-col border-l border-border bg-card text-foreground shadow-2xl outline-none',
            className
          )}
        >
          <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
            <div>
              <DialogPrimitive.Title className="text-base font-semibold">{title}</DialogPrimitive.Title>
              {description ? <DialogPrimitive.Description className="mt-1 text-sm text-muted">{description}</DialogPrimitive.Description> : null}
            </div>
            <DialogPrimitive.Close asChild>
              <Button variant="ghost" size="icon" aria-label="关闭">
                <X className="size-4" />
              </Button>
            </DialogPrimitive.Close>
          </div>
          <div className="min-h-0 flex-1 overflow-auto p-5">{children}</div>
          {footer ? <div className="flex justify-end gap-2 border-t border-border px-5 py-4">{footer}</div> : null}
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  )
}

export const Tabs = TabsPrimitive.Root

export function TabsList({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.List>) {
  return <TabsPrimitive.List className={cn('flex flex-wrap gap-1 rounded-card border border-border bg-card p-1', className)} {...props} />
}

export function TabsTrigger({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Trigger>) {
  return (
    <TabsPrimitive.Trigger
      className={cn(
        'inline-flex h-8 items-center justify-center gap-2 rounded-md px-3 text-sm font-medium text-muted outline-none transition-colors data-[state=active]:bg-raised data-[state=active]:text-foreground',
        className
      )}
      {...props}
    />
  )
}

export function TabsContent({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Content>) {
  return <TabsPrimitive.Content className={cn('mt-4 outline-none', className)} {...props} />
}
