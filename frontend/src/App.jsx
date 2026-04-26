import { useState, useCallback } from 'react'
import { buildGraph, captureGraph } from './api'
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

  async function handleBuild(input) {
    setLoading(true)
    setError(null)
    setSelectedNode(null)

    try {
      let payload

      if (input.type === 'live') {
        setLoadingMessage('Launching browser and capturing traffic...\nThis may take up to 30 seconds.')
        payload = await captureGraph(input.url)
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
    } catch (err) {
      setError(err.message)
      setNodes([])
      setEdges([])
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
      <InputPanel onBuild={handleBuild} loading={loading} />

      <div className="canvas-area">
        {error && (
          <div className="error-banner">
            <strong>Error:</strong> {error}
          </div>
        )}
        <StatsBar nodes={nodes} edges={edges} />
        <GraphCanvas
          nodes={nodes}
          edges={edges}
          onNodeClick={handleNodeClick}
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
