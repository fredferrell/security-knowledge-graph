'use client';

import type { GraphNode } from '@/lib/types';

interface NodeDetailProps {
  node: GraphNode | null;
  onClose: () => void;
}

/** Panel showing full details for the selected graph node. Returns null when no node is selected. */
export function NodeDetail({ node, onClose }: NodeDetailProps) {
  if (node === null) {
    return null;
  }

  return (
    <div className="node-detail">
      <div className="node-detail-header">
        <h3 className="node-detail-title">{node.label}</h3>
        <button className="close-btn" onClick={onClose} aria-label="Close node detail">
          ✕
        </button>
      </div>
      <dl className="node-detail-body">
        <div className="detail-row">
          <dt>Type</dt>
          <dd>{node.type}</dd>
        </div>
        <div className="detail-row">
          <dt>Group</dt>
          <dd>{node.group}</dd>
        </div>
        {Object.entries(node.properties).map(([key, value]) => (
          <div className="detail-row" key={key}>
            <dt>{key}</dt>
            <dd>{String(value)}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
