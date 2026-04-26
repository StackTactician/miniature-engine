import dagre from '@dagrejs/dagre'

const NODE_DIMS = {
  endpointNode: { width: 250, height: 68 },
  modelNode: { width: 200, height: 76 },
}

export function applyDagreLayout(nodes, edges) {
  const g = new dagre.graphlib.Graph()
  g.setDefaultEdgeLabel(() => ({}))
  g.setGraph({ rankdir: 'LR', nodesep: 60, ranksep: 120, marginx: 48, marginy: 48 })

  nodes.forEach((node) => {
    const dims = NODE_DIMS[node.type] ?? { width: 220, height: 68 }
    g.setNode(node.id, { ...dims })
  })

  edges.forEach((edge) => g.setEdge(edge.source, edge.target))

  dagre.layout(g)

  return nodes.map((node) => {
    const { x, y } = g.node(node.id)
    const dims = NODE_DIMS[node.type] ?? { width: 220, height: 68 }
    return { ...node, position: { x: x - dims.width / 2, y: y - dims.height / 2 } }
  })
}

// Converts raw API payload { nodes, edges } to React Flow format
export function toFlowGraph(payload) {
  const nodes = payload.nodes.map((n) => ({
    id: n.id,
    type: n.type === 'endpoint' ? 'endpointNode' : 'modelNode',
    data: { label: n.label, nodeType: n.type, ...n.metadata },
    position: { x: 0, y: 0 },
  }))

  const edges = payload.edges.map((e) => ({
    id: `e-${e.source}-${e.target}`,
    source: e.source,
    target: e.target,
    label: e.relation,
    type: 'smoothstep',
    animated: e.relation === 'returns',
    style: {
      stroke: e.relation === 'returns' ? '#6366f1' : '#a855f7',
      strokeWidth: 1.5,
    },
    labelStyle: { fill: '#64748b', fontSize: 11, fontFamily: 'Inter, sans-serif' },
    labelBgStyle: { fill: '#0d0d14', fillOpacity: 1 },
    labelBgPadding: [4, 6],
    labelBgBorderRadius: 4,
  }))

  const laidOut = applyDagreLayout(nodes, edges)
  return { nodes: laidOut, edges }
}
