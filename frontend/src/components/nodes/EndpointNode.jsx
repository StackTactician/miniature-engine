import { Handle, Position } from '@xyflow/react'

const METHOD_COLORS = {
  GET:    { bg: 'rgba(34,197,94,0.12)',  border: '#22c55e', badge: '#22c55e' },
  POST:   { bg: 'rgba(59,130,246,0.12)', border: '#3b82f6', badge: '#3b82f6' },
  PUT:    { bg: 'rgba(245,158,11,0.12)', border: '#f59e0b', badge: '#f59e0b' },
  PATCH:  { bg: 'rgba(245,158,11,0.12)', border: '#f59e0b', badge: '#f59e0b' },
  DELETE: { bg: 'rgba(239,68,68,0.12)',  border: '#ef4444', badge: '#ef4444' },
}

const FALLBACK = { bg: 'rgba(100,116,139,0.12)', border: '#64748b', badge: '#64748b' }

export function EndpointNode({ data, selected }) {
  const [method, ...rest] = (data.label ?? '').split(' ')
  const path = rest.join(' ')
  const c = METHOD_COLORS[method] ?? FALLBACK

  return (
    <div
      className={`endpoint-node${selected ? ' endpoint-node--selected' : ''}`}
      style={{ '--node-border': c.border, '--node-bg': c.bg }}
    >
      <Handle type="target" position={Position.Left} className="flow-handle" />
      <span className="endpoint-node__method" style={{ color: c.badge }}>{method}</span>
      <span className="endpoint-node__path">{path}</span>
      {data.has_pagination && (
        <span className="endpoint-node__pill">paginated</span>
      )}
      {!data.is_authenticated && (
        <span className="endpoint-node__pill endpoint-node__pill--warning">unauth</span>
      )}
      {data.is_idor_candidate && (
        <span className="endpoint-node__pill endpoint-node__pill--danger">IDOR Risk</span>
      )}
      <Handle type="source" position={Position.Right} className="flow-handle" />
    </div>
  )
}
