'use client';

import dynamic from 'next/dynamic';
import type { GraphData, GraphNode, GraphLink } from '@/lib/types';
import { nodeColor, linkColor } from '@/lib/graph-colors';

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

  const getNodeLabel = (node: object): string => {
    const n = node as FGNode;
    return `${n.label} (${n.type})`;
  };

  const getLinkLabel = (link: object): string => {
    const l = link as FGLink;
    const src = resolveId(l.source);
    const tgt = resolveId(l.target);
    return `${l.type}: ${src} → ${tgt}`;
  };

  return (
    <ForceGraph2D
      graphData={data}
      backgroundColor="#0f172a"
      nodeColor={getNodeColor}
      linkColor={getLinkColor}
      nodeLabel={getNodeLabel}
      linkLabel={getLinkLabel}
      linkDirectionalArrowLength={6}
      linkDirectionalArrowRelPos={1}
      onNodeClick={handleNodeClick}
    />
  );
}
