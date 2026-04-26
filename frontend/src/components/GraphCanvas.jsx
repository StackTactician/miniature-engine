import { ReactFlow, Background, Controls, MiniMap, BackgroundVariant } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { EndpointNode } from './nodes/EndpointNode'
import { ModelNode } from './nodes/ModelNode'

const nodeTypes = {
  endpointNode: EndpointNode,
  modelNode: ModelNode,
}

function minimapColor(node) {
  if (node.type === 'modelNode') return '#a855f7'
  const method = node.data?.label?.split(' ')[0]
  return (
    { GET: '#22c55e', POST: '#3b82f6', PUT: '#f59e0b', PATCH: '#f59e0b', DELETE: '#ef4444' }[method] ?? '#64748b'
  )
}

export function GraphCanvas({ nodes, edges, onNodeClick, loading, loadingMessage = 'Building graph...' }) {
  if (loading) {
    return (
      <div className="canvas-state">
        <div className="spinner" />
        <p className="canvas-state__text" style={{ whiteSpace: 'pre-line' }}>{loadingMessage}</p>
      </div>
    )
  }

  if (!nodes.length) {
    return (
      <div className="canvas-state">
        <div className="canvas-state__empty">
          <div className="canvas-state__icon">&#x2B21;</div>
          <p className="canvas-state__title">No graph loaded</p>
          <p className="canvas-state__hint">
            Paste traffic records or drop a HAR file in the panel on the left,
            <br />then click <strong>Build Graph</strong>.
          </p>
        </div>
      </div>
    )
  }

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      onNodeClick={(_, node) => onNodeClick(node)}
      fitView
      fitViewOptions={{ padding: 0.15 }}
      colorMode="dark"
      proOptions={{ hideAttribution: true }}
    >
      <Background variant={BackgroundVariant.Dots} gap={24} size={1} color="rgba(255,255,255,0.05)" />
      <Controls showInteractive={false} className="flow-controls" />
      <MiniMap
        nodeColor={minimapColor}
        maskColor="rgba(10,10,20,0.75)"
        className="flow-minimap"
        pannable
        zoomable
      />
    </ReactFlow>
  )
}
