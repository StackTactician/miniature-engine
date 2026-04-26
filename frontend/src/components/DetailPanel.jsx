import { useEffect } from 'react'

const FIELD_TYPE_COLORS = {
  string:  '#3b82f6',
  integer: '#22c55e',
  number:  '#22c55e',
  boolean: '#f59e0b',
  object:  '#a855f7',
  array:   '#6366f1',
  null:    '#64748b',
}

const OPERATION_LABELS = {
  create: { label: 'CREATE', cls: 'op--create' },
  read:   { label: 'READ',   cls: 'op--read' },
  update: { label: 'UPDATE', cls: 'op--update' },
  delete: { label: 'DELETE', cls: 'op--delete' },
  other:  { label: 'OTHER',  cls: 'op--other' },
}

export function DetailPanel({ node, edges, allNodes, onClose }) {
  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])

  if (!node) return null

  const isEndpoint = node.type === 'endpointNode'

  // Endpoints: which models does this endpoint return?
  // Models: which endpoints/models point to this model?
  const linkedNodes = (isEndpoint
    ? edges.filter((e) => e.source === node.id)
    : edges.filter((e) => e.target === node.id)
  )
    .map((e) => allNodes.find((n) => n.id === (isEndpoint ? e.target : e.source)))
    .filter(Boolean)

  const op = OPERATION_LABELS[node.data?.operation] ?? OPERATION_LABELS.other

  return (
    <aside className="detail-panel">
      <div className="detail-panel__header">
        <span className="detail-panel__kind">{isEndpoint ? 'Endpoint' : 'Model'}</span>
        <button className="detail-panel__close" onClick={onClose} aria-label="Close panel">
          &#x2715;
        </button>
      </div>

      <h2 className="detail-panel__title">{node.data.label}</h2>

      {isEndpoint ? (
        <>
          <div className="detail-row">
            <span className="detail-row__key">Operation</span>
            <span className={`op-chip ${op.cls}`}>{op.label}</span>
          </div>
          <div className="detail-row">
            <span className="detail-row__key">Pagination</span>
            <span className="detail-row__val">{node.data.has_pagination ? 'Yes' : 'No'}</span>
          </div>
          <div className="detail-row">
            <span className="detail-row__key">Authentication</span>
            <span className={`detail-row__val ${!node.data.is_authenticated ? 'text--warning' : ''}`}>
              {node.data.is_authenticated ? 'Required' : 'None detected'}
            </span>
          </div>
          {node.data.is_idor_candidate && (
            <div className="detail-row">
              <span className="detail-row__key">Security Risk</span>
              <span className="detail-row__val text--danger">IDOR Candidate</span>
            </div>
          )}
          {linkedNodes.length > 0 && (
            <div className="detail-section">
              <div className="detail-section__title">Returns</div>
              <div className="chip-group">
                {linkedNodes.map((n) => (
                  <span key={n.id} className="chip chip--model">{n.data.label}</span>
                ))}
              </div>
            </div>
          )}
        </>
      ) : (
        <>
          {(node.data.fields ?? []).length > 0 && (
            <div className="detail-section">
              <div className="detail-section__title">Fields</div>
              <table className="field-table">
                <tbody>
                  {(node.data.fields ?? []).map((f) => {
                    const baseType = f.type.split('|')[0]
                    return (
                      <tr key={f.name} className={`field-table__row ${f.is_pii ? 'field-table__row--pii' : ''}`}>
                        <td className="field-table__name">
                          {f.name}
                          {f.is_pii && <span className="pii-tag">PII</span>}
                        </td>
                        <td
                          className="field-table__type"
                          style={{ color: FIELD_TYPE_COLORS[baseType] ?? '#64748b' }}
                        >
                          {f.type}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
          {linkedNodes.length > 0 && (
            <div className="detail-section">
              <div className="detail-section__title">Referenced by</div>
              <div className="chip-group">
                {linkedNodes.map((n) => (
                  <span key={n.id} className="chip chip--endpoint">{n.data.label}</span>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </aside>
  )
}
