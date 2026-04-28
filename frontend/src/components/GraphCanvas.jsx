import { ReactFlow, Background, Controls, MiniMap, BackgroundVariant } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { EndpointNode } from './nodes/EndpointNode'
import { ModelNode } from './nodes/ModelNode'
import { graphComponents } from '../layout'

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

export function GraphCanvas({
  nodes,
  edges,
  onNodeClick,
  selectedNodeId,
  showMainComponentOnly,
  loading,
  loadingMessage = 'Building graph...',
}) {
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

  const components = graphComponents(nodes, edges)
  const mainComponentIds = new Set(components[0] ?? [])

  const visibleNodes = showMainComponentOnly ? nodes.filter((node) => mainComponentIds.has(node.id)) : nodes
  const visibleNodeIds = new Set(visibleNodes.map((node) => node.id))
  const visibleEdges = edges.filter((edge) => visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target))

  let neighborIds = null
  if (selectedNodeId) {
    neighborIds = new Set([selectedNodeId])
    visibleEdges.forEach((edge) => {
      if (edge.source === selectedNodeId) neighborIds.add(edge.target)
      if (edge.target === selectedNodeId) neighborIds.add(edge.source)
    })
  }

  const styledNodes = visibleNodes.map((node) => {
    const isDimmed = neighborIds ? !neighborIds.has(node.id) : false
    return {
      ...node,
      style: {
        ...(node.style ?? {}),
        opacity: isDimmed ? 0.25 : 1,
        transition: 'opacity 120ms ease',
      },
    }
  })

  const styledEdges = visibleEdges.map((edge) => {
    const isConnectedToSelected = selectedNodeId
      ? edge.source === selectedNodeId || edge.target === selectedNodeId
      : true

    const confidence = edge.data?.confidence ?? 'medium'
    const confidenceOpacity = confidence === 'high' ? 1 : confidence === 'low' ? 0.45 : 0.7
    const isDimmed = selectedNodeId && !isConnectedToSelected

    return {
      ...edge,
      style: {
        ...(edge.style ?? {}),
        opacity: isDimmed ? 0.14 : confidenceOpacity,
      },
      label: isConnectedToSelected ? edge.label : '',
    }
  })

  return (
    <ReactFlow
      nodes={styledNodes}
      edges={styledEdges}
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
