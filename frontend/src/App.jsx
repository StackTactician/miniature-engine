import { useState, useCallback, useEffect } from 'react'
import { buildGraph, captureGraph, captureGraphStream, createSession, getSession, listSessions } from './api'
import { parseHar } from './harParser'
import { toFlowGraph } from './layout'
import { InputPanel } from './components/InputPanel'
import { GraphCanvas } from './components/GraphCanvas'
import { DetailPanel } from './components/DetailPanel'
import { StatsBar } from './components/StatsBar'

export function App() {
  const [nodes, setNodes] = useState([])
  const [edges, setEdges] = useState([])
  const [selectedNode, setSelectedNode] = useState(null)
  const [loading, setLoading] = useState(false)
  const [loadingMessage, setLoadingMessage] = useState('Building graph...')
  const [error, setError] = useState(null)
  const [currentGraph, setCurrentGraph] = useState(null)
  const [sessions, setSessions] = useState([])
  const [showMainComponentOnly, setShowMainComponentOnly] = useState(false)

  const refreshSessions = useCallback(async () => {
    try {
      const data = await listSessions()
      setSessions(data)
    } catch {
      // Keep graph workflows functional even if session APIs are unavailable.
    }
  }, [])

  useEffect(() => {
    refreshSessions()
  }, [refreshSessions])

  async function handleBuild(input) {
    setLoading(true)
    setError(null)
    setSelectedNode(null)

    try {
      let payload

      if (input.type === 'live') {
        setLoadingMessage('Opening live capture stream...')
        try {
          payload = await new Promise((resolve, reject) => {
            const disconnect = captureGraphStream(input.url, {
              onProgress: (message) => setLoadingMessage(message),
              onResult: (graph) => {
                disconnect()
                resolve(graph)
              },
              onError: (streamErr) => {
                disconnect()
                reject(streamErr)
              },
            })
          })
        } catch (streamErr) {
          const isTransportFailure = streamErr instanceof Error && streamErr.kind === 'transport'
          if (!isTransportFailure) {
            throw streamErr
          }

          // If websocket transport fails (e.g. abnormal close), fall back to
          // one-shot HTTP capture so users still get a concrete backend error/result.
          setLoadingMessage('Live stream unavailable, retrying direct capture...')
          payload = await captureGraph(input.url)
        }
      } else {
        setLoadingMessage('Building graph...')
        let records
        if (input.type === 'har') {
          records = parseHar(input.har)
          if (records.length === 0) {
            throw new Error('No JSON API responses found in HAR file. Try a HAR captured from an API-heavy page.')
          }
        } else {
          records = input.records
        }
        payload = await buildGraph(records)
      }

      if (!payload.nodes.length) {
        throw new Error('Graph is empty — no endpoints or models could be inferred from the records.')
      }

      const { nodes: rfNodes, edges: rfEdges } = toFlowGraph(payload)
      setNodes(rfNodes)
      setEdges(rfEdges)
      setCurrentGraph(payload)
    } catch (err) {
      setError(err.message)
      setNodes([])
      setEdges([])
      setCurrentGraph(null)
    } finally {
      setLoading(false)
    }
  }

  async function handleSaveSession(name) {
    if (!currentGraph) throw new Error('Build a graph before saving a session.')
    await createSession(name, currentGraph)
    await refreshSessions()
  }

  async function handleLoadSession(sessionId) {
    setLoading(true)
    setError(null)
    setSelectedNode(null)
    setLoadingMessage('Loading saved session...')
    try {
      const session = await getSession(sessionId)
      const payload = session.graph
      const { nodes: rfNodes, edges: rfEdges } = toFlowGraph(payload)
      setNodes(rfNodes)
      setEdges(rfEdges)
      setCurrentGraph(payload)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleNodeClick = useCallback((node) => {
    setSelectedNode((prev) => (prev?.id === node.id ? null : node))
  }, [])

  const handleCloseDetail = useCallback(() => setSelectedNode(null), [])

  return (
    <div className="app-shell">
      <InputPanel
        onBuild={handleBuild}
        onSaveSession={handleSaveSession}
        onLoadSession={handleLoadSession}
        sessions={sessions}
        loading={loading}
        canSave={Boolean(currentGraph)}
      />

      <div className="canvas-area">
        {error && (
          <div className="error-banner">
            <strong>Error:</strong> {error}
          </div>
        )}
        <StatsBar nodes={nodes} edges={edges} />
        {nodes.length > 0 && (
          <div className="graph-toolbar">
            <label className="graph-toolbar__toggle">
              <input
                type="checkbox"
                checked={showMainComponentOnly}
                onChange={(e) => setShowMainComponentOnly(e.target.checked)}
              />
              <span>Focus largest connected component</span>
            </label>
          </div>
        )}
        <GraphCanvas
          nodes={nodes}
          edges={edges}
          onNodeClick={handleNodeClick}
          selectedNodeId={selectedNode?.id ?? null}
          showMainComponentOnly={showMainComponentOnly}
          loading={loading}
          loadingMessage={loadingMessage}
        />
      </div>

      <DetailPanel
        node={selectedNode}
        edges={edges}
        allNodes={nodes}
        onClose={handleCloseDetail}
      />
    </div>
  )
}
