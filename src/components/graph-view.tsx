'use client';

import { useRef, useCallback } from 'react';
import dynamic from 'next/dynamic';
import type { GraphData, GraphNode, GraphLink } from '@/lib/types';
import { nodeColor, linkColor, NODE_LEGEND, LINK_LEGEND } from '@/lib/graph-colors';

// react-force-graph-2d uses canvas APIs — must be imported without SSR.
const ForceGraph2D = dynamic(() => import('react-force-graph-2d'), { ssr: false });

interface GraphViewProps {
  data: GraphData;
  onNodeClick: (node: GraphNode) => void;
  highlightNodes?: Set<string>;
}

interface FGNode {
  id: string;
  label: string;
  type: string;
  group: string;
  properties: Record<string, unknown>;
  x?: number;
  y?: number;
  fx?: number;
  fy?: number;
}

interface FGLink {
  source: string | FGNode;
  target: string | FGNode;
  type: string;
  properties: Record<string, unknown>;
}

/** Resolves a force-graph link endpoint (id string or resolved node object) to its id. */
function resolveId(endpoint: string | FGNode): string {
  return typeof endpoint === 'string' ? endpoint : endpoint.id;
}

/** Interactive 2-D force graph rendering the security knowledge graph. */
export function GraphView({ data, onNodeClick, highlightNodes }: GraphViewProps) {
  const tooltipRef = useRef<HTMLDivElement>(null);

  const handleNodeClick = (node: object) => {
    onNodeClick(node as GraphNode);
  };

  const getNodeColor = (node: object): string => {
    const n = node as FGNode;
    if (highlightNodes && highlightNodes.has(n.id)) {
      return '#ef4444';
    }
    return nodeColor(n.group);
  };

  const getLinkColor = (link: object): string => {
    const l = link as FGLink;
    return linkColor(l.type);
  };

  const handleNodeHover = useCallback((node: object | null) => {
    const tip = tooltipRef.current;
    if (!tip) { return; }
    if (!node) {
      tip.style.display = 'none';
      return;
    }
    const n = node as FGNode;
    const ip = n.properties['ip'] ? ` (${n.properties['ip']})` : '';
    tip.textContent = `${n.id}${ip} — ${n.label}`;
    tip.style.display = 'block';
  }, []);

  const handleLinkHover = useCallback((link: object | null) => {
    const tip = tooltipRef.current;
    if (!tip) { return; }
    if (!link) {
      tip.style.display = 'none';
      return;
    }
    const l = link as FGLink;
    const zone = l.properties['zone'] ? ` [${l.properties['zone']}]` : '';
    tip.textContent = `${l.type}: ${resolveId(l.source)} → ${resolveId(l.target)}${zone}`;
    tip.style.display = 'block';
  }, []);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    const tip = tooltipRef.current;
    if (!tip || tip.style.display === 'none') { return; }
    tip.style.left = `${e.clientX}px`;
    tip.style.top = `${e.clientY - 40}px`;
  }, []);

  return (
    <div onMouseMove={handleMouseMove} style={{ width: '100%', height: '100%' }}>
      <div ref={tooltipRef} className="graph-tooltip" style={{ display: 'none' }} />
      <div className="graph-legend">
        <div className="legend-section">
          <div className="legend-title">Nodes</div>
          {NODE_LEGEND.map((item) => (
            <div key={item.label} className="legend-item">
              <span className="legend-dot" style={{ backgroundColor: item.color }} />
              <span className="legend-label">{item.label}</span>
            </div>
          ))}
        </div>
        <div className="legend-section">
          <div className="legend-title">Links</div>
          {LINK_LEGEND.map((item) => (
            <div key={item.label} className="legend-item">
              <span className="legend-line" style={{ backgroundColor: item.color }} />
              <span className="legend-label">{item.label}</span>
            </div>
          ))}
        </div>
      </div>
      <ForceGraph2D
        graphData={data}
        backgroundColor="#0f172a"
        nodeColor={getNodeColor}
        linkColor={getLinkColor}
        nodeLabel=""
        linkLabel=""
        linkDirectionalArrowLength={6}
        linkDirectionalArrowRelPos={1}
        onNodeClick={handleNodeClick}
        onNodeHover={handleNodeHover}
        onLinkHover={handleLinkHover}
        onNodeDragEnd={(node: object) => {
          const n = node as FGNode;
          n.fx = n.x;
          n.fy = n.y;
        }}
      />
    </div>
  );
}
