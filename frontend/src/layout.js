import dagre from '@dagrejs/dagre'
import { MarkerType } from '@xyflow/react'

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
    markerEnd: { type: MarkerType.ArrowClosed },
    animated: e.relation === 'returns',
    data: { confidence: e.metadata?.confidence ?? 'medium', relation: e.relation },
    style: {
      stroke: e.relation === 'returns' ? '#7c8dff' : '#c084fc',
      strokeWidth: e.relation === 'returns' ? 2.8 : 2,
      opacity: e.relation === 'returns' ? 0.95 : 0.8,
    },
    labelStyle: { fill: '#94a3b8', fontSize: 11, fontFamily: 'Inter, sans-serif' },
    labelBgStyle: { fill: '#0d0d14', fillOpacity: 1 },
    labelBgPadding: [4, 6],
    labelBgBorderRadius: 4,
  }))

  const laidOut = applyDagreLayout(nodes, edges)
  return { nodes: laidOut, edges }
}

export function graphComponents(nodes, edges) {
  const adjacency = new Map(nodes.map((node) => [node.id, new Set()]))
  edges.forEach((edge) => {
    if (adjacency.has(edge.source) && adjacency.has(edge.target)) {
      adjacency.get(edge.source).add(edge.target)
      adjacency.get(edge.target).add(edge.source)
    }
  })

  const visited = new Set()
  const components = []
  for (const node of nodes) {
    if (visited.has(node.id)) continue
    const queue = [node.id]
    visited.add(node.id)
    const members = []
    while (queue.length) {
      const current = queue.shift()
      members.push(current)
      for (const next of adjacency.get(current) ?? []) {
        if (!visited.has(next)) {
          visited.add(next)
          queue.push(next)
        }
      }
    }
    components.push(members)
  }

  return components.sort((a, b) => b.length - a.length)
}
