import { Handle, Position } from '@xyflow/react'

export function ModelNode({ data, selected }) {
  const fieldCount = (data.fields ?? []).length

  return (
    <div className={`model-node${selected ? ' model-node--selected' : ''}`}>
      <Handle type="target" position={Position.Left} className="flow-handle" />
      <div className="model-node__header">
        <span className="model-node__name">{data.label}</span>
        <span className="model-node__count">{fieldCount} {fieldCount === 1 ? 'field' : 'fields'}</span>
      </div>
      <div className="model-node__type-row">
        <div className="model-node__type-label">model</div>
        {data.has_pii && (
          <span className="model-node__pii-badge">PII</span>
        )}
      </div>
      <Handle type="source" position={Position.Right} className="flow-handle" />
    </div>
  )
}
