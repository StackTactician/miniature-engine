const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://localhost:8000'

function toWsBase(httpBase) {
  if (httpBase.startsWith('https://')) return `wss://${httpBase.slice('https://'.length)}`
  if (httpBase.startsWith('http://')) return `ws://${httpBase.slice('http://'.length)}`
  return httpBase
}

const WS_BASE = import.meta.env.VITE_WS_BASE ?? toWsBase(API_BASE)

export async function buildGraph(records) {
  const res = await fetch(`${API_BASE}/graph/build`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ records }),
  })

  if (!res.ok) {
    const text = await res.text()
    throw new Error(`API error ${res.status}: ${text}`)
  }

  return res.json()
}

export async function diffGraph(baselineRecords, candidateRecords) {
  const res = await fetch(`${API_BASE}/graph/diff`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      baseline_records: baselineRecords,
      candidate_records: candidateRecords,
    }),
  })

  if (!res.ok) {
    const text = await res.text()
    throw new Error(`API error ${res.status}: ${text}`)
  }

  return res.json()
}

export async function captureGraph(url) {
  const res = await fetch(`${API_BASE}/capture`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  })

  if (!res.ok) {
    const data = await res.json().catch(() => null)
    const detail = data?.detail ?? `HTTP ${res.status}`
    throw new Error(detail)
  }

  return res.json()
}

export async function createSession(name, graph) {
  const res = await fetch(`${API_BASE}/sessions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, graph }),
  })

  if (!res.ok) {
    const text = await res.text()
    throw new Error(`API error ${res.status}: ${text}`)
  }

  return res.json()
}

export async function listSessions() {
  const res = await fetch(`${API_BASE}/sessions`)
  if (!res.ok) throw new Error(`API error ${res.status}`)
  return res.json()
}

export async function getSession(sessionId) {
  const res = await fetch(`${API_BASE}/sessions/${sessionId}`)
  if (!res.ok) throw new Error(`API error ${res.status}`)
  return res.json()
}

export function captureGraphStream(url, { onProgress, onResult, onError } = {}) {
  const wsUrl = `${WS_BASE}/capture/stream?url=${encodeURIComponent(url)}`
  const socket = new WebSocket(wsUrl)
  let settled = false
  let receivedAnyMessage = false

  const fail = (message, kind = 'backend') => {
    if (settled) return
    settled = true
    const err = new Error(message)
    err.kind = kind
    onError?.(err)
  }

  socket.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data)
      receivedAnyMessage = true
      if (data.type === 'progress') onProgress?.(data.message)
      if (data.type === 'result') {
        if (settled) return
        settled = true
        onResult?.(data.graph)
        return
      }
      if (data.type === 'error') {
        fail(data.message || 'Live capture failed.', 'backend')
      }
    } catch {
      fail('Malformed streaming response from backend.', 'transport')
    }
  }

  socket.onerror = () => {
    // onerror often has no useful details; onclose gives better context.
    if (!receivedAnyMessage) return
    fail('Live capture socket failed.', 'transport')
  }

  socket.onclose = (event) => {
    if (settled) return
    if (event.code === 1000) {
      fail('Live capture ended before a graph result was returned.', 'transport')
      return
    }
    const reason = event.reason?.trim()
    fail(reason || `Live capture socket closed (code ${event.code}).`, 'transport')
  }

  return () => {
    if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
      socket.close()
    }
  }
}
