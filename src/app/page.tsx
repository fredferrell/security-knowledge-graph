/* eslint-disable import/no-default-export */
'use client';

import { useEffect, useState } from 'react';
import type { GraphData, GraphNode } from '@/lib/types';
import { GraphView } from '@/components/graph-view';
import { NodeDetail } from '@/components/node-detail';
import { Sidebar } from '@/components/sidebar';

interface BlastResults {
  cve: string;
  affectedAssets: { name: string; ip: string; zone: string }[];
  exposurePaths: string[][];
  firewallRules: { firewall: string; name: string; sourceZone: string; destZone: string; action: string }[];
}

interface GapResults {
  vulnerableAssets: { name: string; zone: string; cveId: string; severity: string; hasGap: boolean }[];
  summary: { totalVulnerabilities: number; assetsWithGaps: number; coveredAssets: number };
}

/** Wraps useEffect with empty deps to make external-sync intent explicit. */
function useMountEffect(fn: () => void | (() => void)) {
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(fn, []);
}

/** Main dashboard: graph visualization with blast radius and gap analysis controls. */
export default function DashboardPage() {
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [highlightNodes, setHighlightNodes] = useState<Set<string>>(new Set());
  const [blastResults, setBlastResults] = useState<BlastResults | null>(null);
  const [gapResults, setGapResults] = useState<GapResults | null>(null);

  useMountEffect(() => {
    fetch('/api/graph')
      .then((res) => res.json())
      .then((data: GraphData) => setGraphData(data))
      .catch((err) => console.error('Failed to fetch graph:', err));
  });

  const handleBlastRadius = (cveId: string) => {
    fetch(`/api/blast-radius?cve=${encodeURIComponent(cveId)}`)
      .then((res) => res.json())
      .then((data: BlastResults) => {
        setBlastResults(data);
        setGapResults(null);
        const ids = new Set<string>();
        data.affectedAssets.forEach((a) => ids.add(a.name));
        data.exposurePaths.flat().forEach((name) => ids.add(name));
        setHighlightNodes(ids);
      })
      .catch((err) => console.error('Blast radius fetch failed:', err));
  };

  const handleGapAnalysis = () => {
    fetch('/api/gaps')
      .then((res) => res.json())
      .then((data: GapResults) => {
        setGapResults(data);
        setBlastResults(null);
        const ids = new Set<string>(
          data.vulnerableAssets.filter((a) => a.hasGap).map((a) => a.name),
        );
        setHighlightNodes(ids);
      })
      .catch((err) => console.error('Gap analysis fetch failed:', err));
  };

  const handleReset = () => {
    setBlastResults(null);
    setGapResults(null);
    setHighlightNodes(new Set());
    setSelectedNode(null);
  };

  return (
    <div className="dashboard">
      <Sidebar
        onBlastRadius={handleBlastRadius}
        onGapAnalysis={handleGapAnalysis}
        onReset={handleReset}
        blastResults={blastResults}
        gapResults={gapResults}
      />
      <div className="graph-area">
        {graphData === null ? (
          <div className="loading">Loading graph data...</div>
        ) : (
          <GraphView
            data={graphData}
            onNodeClick={setSelectedNode}
            highlightNodes={highlightNodes}
          />
        )}
        <NodeDetail node={selectedNode} onClose={() => setSelectedNode(null)} />
      </div>
    </div>
  );
}
