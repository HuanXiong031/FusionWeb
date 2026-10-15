'use client'

import * as React from 'react'
import { Check, KeyRound, Loader2, LogOut, ShieldAlert } from 'lucide-react'
import { toast } from 'sonner'
import { changePassword, type UserProfile } from '@/lib/api'
import { clearPublicKey, encryptPassword, initPublicKey } from '@/lib/crypto'
import { Button, Card, CardContent, Field, Input } from '@/components/ui'
import logoImage from '@/assets/images/logo.png'

// passwordRuleError 返回空字符串表示通过，否则返回具体原因。
export function passwordRuleError(password: string): string {
  if (password.length < 8) return '密码长度必须大于等于 8 位'
  const missing: string[] = []
  if (!/[A-Z]/.test(password)) missing.push('大写字母')
  if (!/[a-z]/.test(password)) missing.push('小写字母')
  if (!/[0-9]/.test(password)) missing.push('数字')
  if (!/[^A-Za-z0-9]/.test(password)) missing.push('特殊符号')
  if (missing.length > 0) return `密码必须包含：${missing.join('、')}`
  return ''
}

const rules: Array<{ label: string; test: (value: string) => boolean }> = [
  { label: '长度至少 8 位', test: (value) => value.length >= 8 },
  { label: '包含大写字母', test: (value) => /[A-Z]/.test(value) },
  { label: '包含小写字母', test: (value) => /[a-z]/.test(value) },
  { label: '包含数字', test: (value) => /[0-9]/.test(value) },
  { label: '包含特殊符号', test: (value) => /[^A-Za-z0-9]/.test(value) },
]

export function ForcedPasswordChangeView({
  appTitle,
  user,
  onDone,
  onLogout,
}: {
  appTitle: string
  user: UserProfile
  onDone: () => void
  onLogout: () => void
}) {
  const [oldPassword, setOldPassword] = React.useState('')
  const [newPassword, setNewPassword] = React.useState('')
  const [confirmPassword, setConfirmPassword] = React.useState('')
  const [submitting, setSubmitting] = React.useState(false)
  const [error, setError] = React.useState('')

  const confirmMismatch = confirmPassword.length > 0 && confirmPassword !== newPassword

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError('')

    if (!oldPassword) {
      setError('请输入当前密码')
      return
    }
    const ruleError = passwordRuleError(newPassword)
    if (ruleError) {
      setError(ruleError)
      return
    }
    if (newPassword !== confirmPassword) {
      setError('两次输入的新密码不一致')
      return
    }
    if (newPassword === oldPassword) {
      setError('新密码不能与当前密码相同')
      return
    }

    setSubmitting(true)
    try {
      const submitEncrypted = async (forceKey = false) => {
        const publicKey = await initPublicKey(forceKey)
        return changePassword({
          oldPassword: await encryptPassword(oldPassword.trim(), publicKey),
          newPassword: await encryptPassword(newPassword.trim(), publicKey),
        })
      }

      try {
        await submitEncrypted(false)
      } catch (err: any) {
        if (String(err?.message || '').includes('安全验证失败')) await submitEncrypted(true)
        else throw err
      }

      clearPublicKey()
      toast.success('密码修改成功，请使用新密码重新登录')
      onDone()
    } catch (err: any) {
      const message = err?.message || '密码修改失败'
      setError(message)
      toast.error(message)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-background p-6 text-foreground">
      <Card className="w-full max-w-[480px]">
        <CardContent className="p-8">
          <div className="mb-6 text-center">
            <div className="mx-auto mb-4 flex size-16 items-center justify-center overflow-hidden">
              <img src={logoImage.src} alt={appTitle} className="h-full w-full object-contain" />
            </div>
            <h1 className="text-2xl font-bold">首次登录需修改密码</h1>
            <p className="mt-2 text-sm text-muted">
              当前账号 <span className="font-medium text-foreground">{user.username}</span> 使用的是初始密码，修改后才能进入 {appTitle}。
            </p>
          </div>

          <form className="grid gap-4" autoComplete="off" onSubmit={submit}>
            <Field label="当前密码">
              <Input
                type="password"
                autoComplete="current-password"
                placeholder="请输入当前（初始）密码"
                value={oldPassword}
                onChange={(event) => setOldPassword(event.target.value)}
              />
            </Field>
            <Field label="新密码">
              <Input
                type="password"
                autoComplete="new-password"
                placeholder="请输入新密码"
                value={newPassword}
                onChange={(event) => setNewPassword(event.target.value)}
              />
            </Field>
            <Field label="确认新密码" hint={confirmMismatch ? '两次输入的新密码不一致' : undefined}>
              <Input
                type="password"
                autoComplete="new-password"
                placeholder="请再次输入新密码"
                value={confirmPassword}
                onChange={(event) => setConfirmPassword(event.target.value)}
              />
            </Field>

            <div className="grid gap-1.5 rounded-md border border-border bg-panel p-3">
              {rules.map((rule) => {
                const passed = rule.test(newPassword)
                return (
                  <div key={rule.label} className="flex items-center gap-2 text-xs">
                    <Check className={passed ? 'size-3.5 text-success' : 'size-3.5 text-muted opacity-40'} />
                    <span className={passed ? 'text-foreground' : 'text-muted'}>{rule.label}</span>
                  </div>
                )
              })}
            </div>

            {error ? (
              <div className="flex items-start gap-2 rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-danger">
                <ShieldAlert className="mt-0.5 size-4 shrink-0" />
                <span>{error}</span>
              </div>
            ) : null}

            <Button type="submit" variant="default" disabled={submitting}>
              {submitting ? <Loader2 className="size-4 animate-spin" /> : <KeyRound className="size-4" />}
              确认修改
            </Button>
            <Button type="button" variant="outline" disabled={submitting} onClick={onLogout}>
              <LogOut className="size-4" />
              退出登录
            </Button>
          </form>
        </CardContent>
      </Card>
    </main>
  )
}
