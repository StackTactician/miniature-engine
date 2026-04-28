import { Handle, Position } from '@xyflow/react'

export function NamespaceNode({ data, selected }) {
  const cls = [
    'namespace-node',
    selected && 'namespace-node--selected',
  ].filter(Boolean).join(' ')

  return (
    <div className={cls}>
      <Handle type="target" position={Position.Left} className="flow-handle" />
      <div className="namespace-node__icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path strokeLinecap="round" strokeLinejoin="round" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
        </svg>
      </div>
      <span className="namespace-node__label">{data.label}</span>
      <Handle type="source" position={Position.Right} className="flow-handle" />
    </div>
  )
}
