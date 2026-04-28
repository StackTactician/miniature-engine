import { useState, useRef } from 'react'

const SAMPLE = JSON.stringify(
  [
    { method: 'GET', url: 'https://api.example.com/users', request_headers: {}, request_body: null, response_status: 200, response_headers: { 'content-type': 'application/json' }, response_body: { results: [{ id: 1, name: 'Alice', email: 'alice@example.com', role_id: 1 }], total: 1, next: null } },
    { method: 'GET', url: 'https://api.example.com/users/1', request_headers: { authorization: 'Bearer token' }, request_body: null, response_status: 200, response_headers: { 'content-type': 'application/json' }, response_body: { id: 1, name: 'Alice', email: 'alice@example.com', role_id: 1 } },
    { method: 'POST', url: 'https://api.example.com/users', request_headers: { authorization: 'Bearer token' }, request_body: { name: 'Bob', email: 'bob@example.com' }, response_status: 201, response_headers: { 'content-type': 'application/json' }, response_body: { id: 2, name: 'Bob', email: 'bob@example.com', role_id: 2 } },
    { method: 'DELETE', url: 'https://api.example.com/users/1', request_headers: { authorization: 'Bearer token' }, request_body: null, response_status: 204, response_headers: {}, response_body: null },
    { method: 'GET', url: 'https://api.example.com/roles', request_headers: {}, request_body: null, response_status: 200, response_headers: { 'content-type': 'application/json' }, response_body: { id: 1, name: 'admin', permissions: ['read', 'write'] } },
    { method: 'GET', url: 'https://api.example.com/posts?page=1&limit=20', request_headers: { authorization: 'Bearer token' }, request_body: null, response_status: 200, response_headers: { 'content-type': 'application/json' }, response_body: { results: [], total: 0, next: null, previous: null } },
    { method: 'POST', url: 'https://api.example.com/posts', request_headers: { authorization: 'Bearer token' }, request_body: { title: 'Hello', user_id: 1 }, response_status: 201, response_headers: { 'content-type': 'application/json' }, response_body: { id: 1, title: 'Hello', user_id: 1, created_at: '2024-01-01' } },
    { method: 'PATCH', url: 'https://api.example.com/posts/1', request_headers: { authorization: 'Bearer token' }, request_body: { title: 'Updated' }, response_status: 200, response_headers: { 'content-type': 'application/json' }, response_body: { id: 1, title: 'Updated', user_id: 1, created_at: '2024-01-01' } },
  ],
  null,
  2
)

export function InputPanel({
  onBuild,
  onSaveSession,
  onLoadSession,
  sessions = [],
  loading,
  canSave = false,
}) {
  const [tab, setTab] = useState('json')
  const [jsonText, setJsonText] = useState('')
  const [parseError, setParseError] = useState(null)
  const [harFile, setHarFile] = useState(null)
  const [dragOver, setDragOver] = useState(false)
  const [liveUrl, setLiveUrl] = useState('')
  const [sessionName, setSessionName] = useState('')
  const fileRef = useRef(null)

  function handleJsonChange(e) {
    setJsonText(e.target.value)
    setParseError(null)
  }

  function acceptHarFile(file) {
    if (!file?.name.endsWith('.har')) {
      setParseError('File must be a .har export.')
      return
    }
    setHarFile(file)
    setParseError(null)
  }

  function handleDrop(e) {
    e.preventDefault()
    setDragOver(false)
    acceptHarFile(e.dataTransfer.files[0])
  }

  async function handleBuild() {
    setParseError(null)

    if (tab === 'json') {
      try {
        const records = JSON.parse(jsonText)
        if (!Array.isArray(records)) throw new Error('Input must be a JSON array.')
        onBuild({ type: 'json', records })
      } catch (err) {
        setParseError(err.message)
      }
      return
    }

    if (tab === 'live') {
      const trimmed = liveUrl.trim()
      if (!trimmed.startsWith('http')) {
        setParseError('Enter a full URL starting with http:// or https://')
        return
      }
      onBuild({ type: 'live', url: trimmed })
      return
    }

    if (!harFile) {
      setParseError('No HAR file selected.')
      return
    }
    try {
      const text = await harFile.text()
      const har = JSON.parse(text)
      onBuild({ type: 'har', har })
    } catch {
      setParseError('Could not parse HAR file.')
    }
  }

  const canBuild =
    tab === 'json' ? jsonText.trim().length > 0 :
    tab === 'live' ? liveUrl.trim().length > 0 :
    harFile !== null

  async function handleSaveSessionClick() {
    const trimmed = sessionName.trim()
    if (!trimmed) {
      setParseError('Enter a session name before saving.')
      return
    }
    try {
      await onSaveSession(trimmed)
      setSessionName('')
      setParseError(null)
    } catch (err) {
      setParseError(err.message || 'Failed to save session.')
    }
  }

  return (
    <aside className="input-panel">
      <div className="input-panel__brand">
        <div className="brand-logo">
          <span className="brand-logo__dot" />
          <span className="brand-logo__dot brand-logo__dot--2" />
          <span className="brand-logo__dot brand-logo__dot--3" />
        </div>
        <span className="brand-name">Miniature Engine</span>
      </div>

      <div className="tab-bar">
        <button className={`tab${tab === 'json' ? ' tab--active' : ''}`} onClick={() => setTab('json')}>
          JSON
        </button>
        <button className={`tab${tab === 'har' ? ' tab--active' : ''}`} onClick={() => setTab('har')}>
          HAR File
        </button>
        <button className={`tab${tab === 'live' ? ' tab--active' : ''}`} onClick={() => setTab('live')}>
          Live Capture
        </button>
      </div>

      <div className="input-panel__body">
        {tab === 'json' ? (
          <>
            <div className="label-row">
              <span className="field-label">Traffic Records</span>
              <button className="link-btn" onClick={() => { setJsonText(SAMPLE); setParseError(null) }}>
                Load example
              </button>
            </div>
            <textarea
              className="json-textarea"
              value={jsonText}
              onChange={handleJsonChange}
              placeholder={'[\n  { "method": "GET", "url": "https://...", ... }\n]'}
              spellCheck={false}
            />
          </>
        ) : tab === 'live' ? (
          <>
            <div className="label-row">
              <span className="field-label">Target URL</span>
            </div>
            <input
              type="url"
              className="url-input"
              value={liveUrl}
              onChange={(e) => { setLiveUrl(e.target.value); setParseError(null) }}
              placeholder="https://example.com"
              onKeyDown={(e) => e.key === 'Enter' && !loading && canBuild && handleBuild()}
            />
            <div className="live-capture-info">
              <p>A headless Chromium browser will visit this URL, intercept XHR/fetch requests, and stream capture progress while the graph is built.</p>
              <p className="live-capture-info__note">Allow up to 30 seconds. Works best on SPAs and API-driven sites.</p>
            </div>
          </>
        ) : (
          <>
            <div
              className={`har-drop${dragOver ? ' har-drop--active' : ''}`}
              onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              onClick={() => fileRef.current.click()}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => e.key === 'Enter' && fileRef.current.click()}
            >
              <input
                ref={fileRef}
                type="file"
                accept=".har"
                hidden
                onChange={(e) => acceptHarFile(e.target.files[0])}
              />
              {harFile ? (
                <>
                  <div className="har-drop__filename">{harFile.name}</div>
                  <div className="har-drop__sub">Click to replace</div>
                </>
              ) : (
                <>
                  <div className="har-drop__icon">&#8679;</div>
                  <div className="har-drop__label">Drop .har file or click to browse</div>
                  <div className="har-drop__sub">
                    Chrome DevTools &rarr; Network &rarr; Save all as HAR
                  </div>
                </>
              )}
            </div>
          </>
        )}
      </div>

      {parseError && <p className="input-error">{parseError}</p>}

      <button className="build-btn" onClick={handleBuild} disabled={!canBuild || loading}>
        {loading ? (
          <span className="build-btn__loading">
            <span className="spinner-sm" /> Building...
          </span>
        ) : (
          'Build Graph'
        )}
      </button>

      <div className="session-panel">
        <div className="label-row">
          <span className="field-label">Sessions</span>
        </div>
        <div className="session-save-row">
          <input
            className="session-input"
            type="text"
            placeholder="Session name"
            value={sessionName}
            onChange={(e) => setSessionName(e.target.value)}
          />
          <button
            className="session-save-btn"
            onClick={handleSaveSessionClick}
            disabled={loading || !canSave}
          >
            Save
          </button>
        </div>
        <div className="session-list">
          {sessions.length === 0 ? (
            <div className="session-empty">No saved sessions yet.</div>
          ) : sessions.map((session) => (
            <button
              key={session.id}
              className="session-item"
              onClick={() => onLoadSession(session.id)}
              disabled={loading}
            >
              <div className="session-item__name">{session.name}</div>
              <div className="session-item__meta">
                {session.node_count} nodes · {session.edge_count} edges
              </div>
            </button>
          ))}
        </div>
      </div>

      <div className="input-panel__footer">
        Backend at <code>localhost:8000</code>
      </div>
    </aside>
  )
}
