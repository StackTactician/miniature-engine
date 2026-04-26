const API_BASE = 'http://localhost:8000'

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
