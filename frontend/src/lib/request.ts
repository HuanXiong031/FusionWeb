'use client'

import axios from 'axios'

const configuredAPIBaseURL = () => (process.env.NEXT_PUBLIC_API_BASE_URL || '').trim().replace(/\/+$/, '')

export const getAPIBaseURL = () => {
  const configured = configuredAPIBaseURL()
  if (configured) return configured
  if (typeof window === 'undefined') return ''
  return window.location.origin
}

export const getWebSocketURL = (path = '/ws') => {
  const baseURL = getAPIBaseURL()
  const fallbackOrigin = typeof window === 'undefined' ? 'http://localhost:62486' : window.location.origin
  try {
    const url = new URL(path, baseURL || fallbackOrigin)
    url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
    return url.toString()
  } catch {
    const protocol = typeof window !== 'undefined' && window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = typeof window !== 'undefined' ? window.location.host : 'localhost:62486'
    return `${protocol}//${host}${path.startsWith('/') ? path : `/${path}`}`
  }
}

export const request = axios.create({
  baseURL: getAPIBaseURL(),
  timeout: 30000,
})

request.interceptors.request.use((config) => {
  if (typeof window !== 'undefined') {
    const token = localStorage.getItem('token')
    if (token) config.headers.Authorization = `Bearer ${token}`
  }
  if (!config.headers['Content-Type']) {
    config.headers['Content-Type'] = 'application/json'
  }
  return config
})

request.interceptors.response.use(
  (response) => {
    if (response.config.responseType === 'blob') return response
    return response.data
  },
  (error) => {
    if (error.response?.status === 401 && !error.config?.url?.includes('/auth/login')) {
      localStorage.removeItem('token')
      localStorage.removeItem('user')
      localStorage.removeItem('role')
      window.dispatchEvent(new CustomEvent('token-expired'))
    }
    const responseMessage = error.response?.data?.message || error.message || '请求失败'
    const responseError = error.response?.data?.error
    const message = responseError && responseError !== responseMessage ? `${responseMessage}: ${responseError}` : responseMessage
    return Promise.reject({ ...error, message })
  }
)

export default request
