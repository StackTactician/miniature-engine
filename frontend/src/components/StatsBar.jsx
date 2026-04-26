export function StatsBar({ nodes, edges }) {
  if (!nodes.length) return null

  const endpointCount = nodes.filter((n) => n.type === 'endpointNode').length
  const modelCount = nodes.filter((n) => n.type === 'modelNode').length
  const edgeCount = edges.length

  return (
    <div className="stats-bar">
      <span className="stats-bar__item">
        <span className="stats-bar__num">{endpointCount}</span> endpoint{endpointCount !== 1 ? 's' : ''}
      </span>
      <span className="stats-bar__sep">&middot;</span>
      <span className="stats-bar__item">
        <span className="stats-bar__num">{modelCount}</span> model{modelCount !== 1 ? 's' : ''}
      </span>
      <span className="stats-bar__sep">&middot;</span>
      <span className="stats-bar__item">
        <span className="stats-bar__num">{edgeCount}</span> relationship{edgeCount !== 1 ? 's' : ''}
      </span>
    </div>
  )
}
