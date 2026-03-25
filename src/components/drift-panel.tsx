'use client';

type DriftType = 'in_sync' | 'ip_mismatch' | 'zone_mismatch' | 'missing_from_graph' | 'missing_from_inventory';

interface DriftItem {
  name: string;
  type: string;
  inventoryValue?: string;
  graphValue?: string;
}

interface DriftPanelProps {
  results: {
    driftItems: DriftItem[];
    summary: {
      totalInventory: number;
      totalGraph: number;
      inSync: number;
      drifted: number;
    };
  } | null;
  isLoading: boolean;
}

const DRIFT_LABELS: Record<DriftType, string> = {
  in_sync: 'IN SYNC',
  ip_mismatch: 'IP MISMATCH',
  zone_mismatch: 'ZONE MISMATCH',
  missing_from_graph: 'NOT IN GRAPH',
  missing_from_inventory: 'NOT IN INVENTORY',
};

const DRIFT_CSS: Record<DriftType, string> = {
  in_sync: 'drift-in-sync',
  ip_mismatch: 'drift-mismatch',
  zone_mismatch: 'drift-mismatch',
  missing_from_graph: 'drift-missing',
  missing_from_inventory: 'drift-missing',
};

function driftLabel(type: string): string {
  return DRIFT_LABELS[type as DriftType] ?? type.toUpperCase();
}

function driftCss(type: string): string {
  return DRIFT_CSS[type as DriftType] ?? '';
}

/** Panel displaying configuration drift between Ansible inventory and graph. */
export function DriftPanel({ results, isLoading }: DriftPanelProps) {
  if (isLoading) {
    return <div className="drift-panel"><p className="asset-meta">Checking drift...</p></div>;
  }

  if (results === null) {
    return null;
  }

  const { summary, driftItems } = results;

  return (
    <div className="drift-panel">
      <div className="results-block summary-block">
        <p>Inventory: <strong>{summary.totalInventory}</strong></p>
        <p>Graph: <strong>{summary.totalGraph}</strong></p>
        <p>In Sync: <strong>{summary.inSync}</strong></p>
        <p className={summary.drifted > 0 ? 'gap-warning' : ''}>
          Drifted: <strong>{summary.drifted}</strong>
        </p>
      </div>

      <div className="results-block">
        <h4>Drift Items</h4>
        <ul className="asset-list">
          {driftItems.map((item, i) => (
            <li key={i} className={`drift-item ${driftCss(item.type)}`}>
              <span className="asset-name">{item.name}</span>
              <span className="asset-meta">{driftLabel(item.type)}</span>
              {item.inventoryValue !== undefined && item.inventoryValue !== '' && (
                <span className="asset-meta">Inv: {item.inventoryValue}</span>
              )}
              {item.graphValue !== undefined && item.graphValue !== '' && (
                <span className="asset-meta">Graph: {item.graphValue}</span>
              )}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
