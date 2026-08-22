'use client'

// @ts-ignore
import { sm2 } from 'sm-crypto'
import request from './request'

let publicKey = ''
let publicKeyPromise: Promise<string> | null = null
let publicKeyVersion = 0

export function clearPublicKey() {
  publicKey = ''
  publicKeyPromise = null
  publicKeyVersion += 1
}

export async function initPublicKey(force = false): Promise<string> {
  if (force) clearPublicKey()
  if (publicKey) return publicKey
  if (publicKeyPromise) return publicKeyPromise

  const requestVersion = publicKeyVersion
  publicKeyPromise = request
    .get('/api/auth/public-key')
    .then((res: any) => {
      const key = res?.data?.publicKey || res?.publicKey
      if (!key) throw new Error(res?.message || '响应中未包含公钥')
      if (requestVersion === publicKeyVersion) publicKey = key
      return key
    })
    .catch(() => {
      if (requestVersion === publicKeyVersion) publicKeyPromise = null
      throw new Error('获取登录加密公钥失败，请确认后端服务已启动')
    })

  return publicKeyPromise
}

async function encryptWithSM2(value: string, key?: string) {
  const activePublicKey = key || publicKey || (await initPublicKey())
  if (!activePublicKey) throw new Error('登录加密公钥未初始化')

  const text = `${value}|||${Date.now()}`
  let encrypted = sm2.doEncrypt(text, activePublicKey, 1)
  if (!encrypted.startsWith('04')) encrypted = `04${encrypted}`
  return encrypted.toLowerCase()
}

export function encryptPassword(password: string, key?: string) {
  return encryptWithSM2(password, key)
}

export function encryptUsername(username: string, key?: string) {
  return encryptWithSM2(username, key)
}
