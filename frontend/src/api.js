const API_BASE = 'http://localhost:8000'
const WS_BASE = 'ws://localhost:8000'

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

  socket.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data)
      if (data.type === 'progress') onProgress?.(data.message)
      if (data.type === 'result') onResult?.(data.graph)
      if (data.type === 'error') onError?.(new Error(data.message))
    } catch {
      onError?.(new Error('Malformed streaming response from backend.'))
    }
  }

  socket.onerror = () => onError?.(new Error('Live capture socket failed.'))

  return () => {
    if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
      socket.close()
    }
  }
}
