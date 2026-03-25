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

interface ZeroDayResults {
  vulnerability: Record<string, unknown>;
  affectedAssets: { name: string; ip: string; zone: string }[];
  exposurePaths: string[][];
}

interface DriftResults {
  driftItems: { name: string; type: string; inventoryValue?: string; graphValue?: string }[];
  summary: { totalInventory: number; totalGraph: number; inSync: number; drifted: number };
}

interface AnalyticsResults {
  assets: { name: string; zone: string; riskScore: number; riskLevel: string; metrics: Record<string, number> }[];
  topRisks: { name: string; riskScore: number; riskLevel: string; primaryReason: string }[];
  networkStats: { totalAssets: number; totalVulnerabilities: number; totalTrafficFlows: number; totalCredentials: number; averageRiskScore: number };
}

interface ReportResults {
  generatedAt: string;
  summary: { overallRisk: string; totalAssets: number; totalVulnerabilities: number; protectionCoverage: string; criticalFindings: number };
  vulnerabilityMatrix: { cveId: string; severity: string; affectedAssets: string[]; exposedToInternet: boolean; firewallProtected: boolean }[];
  recommendations: string[];
  credentialMap: { source: string; targets: string[]; credentialTypes: string[] }[];
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
  const [zeroDayResults, setZeroDayResults] = useState<ZeroDayResults | null>(null);
  const [driftResults, setDriftResults] = useState<DriftResults | null>(null);
  const [isSimulating, setIsSimulating] = useState(false);
  const [isDriftLoading, setIsDriftLoading] = useState(false);
  const [analyticsResults, setAnalyticsResults] = useState<AnalyticsResults | null>(null);
  const [reportResults, setReportResults] = useState<ReportResults | null>(null);
  const [isAnalyticsLoading, setIsAnalyticsLoading] = useState(false);
  const [isReportLoading, setIsReportLoading] = useState(false);

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

  const handleSimulateZeroDay = (formData: {
    cveId: string;
    severity: string;
    description: string;
    affectedSoftware: string;
    affectedVersion: string;
  }) => {
    setIsSimulating(true);
    fetch('/api/simulate/zero-day', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(formData),
    })
      .then((res) => res.json())
      .then((data: ZeroDayResults) => {
        setZeroDayResults(data);
        handleBlastRadius(formData.cveId);
      })
      .catch((err) => console.error('Zero-day simulation failed:', err))
      .finally(() => setIsSimulating(false));
  };

  const handleCheckDrift = () => {
    setIsDriftLoading(true);
    fetch('/api/drift')
      .then((res) => res.json())
      .then((data: DriftResults) => setDriftResults(data))
      .catch((err) => console.error('Drift check failed:', err))
      .finally(() => setIsDriftLoading(false));
  };

  const handleRunAnalytics = () => {
    setIsAnalyticsLoading(true);
    fetch('/api/analytics')
      .then((res) => res.json())
      .then((data: AnalyticsResults) => {
        setAnalyticsResults(data);
        const ids = new Set<string>(data.topRisks.map((r) => r.name));
        setHighlightNodes(ids);
      })
      .catch((err) => console.error('Analytics fetch failed:', err))
      .finally(() => setIsAnalyticsLoading(false));
  };

  const handleGenerateReport = () => {
    setIsReportLoading(true);
    fetch('/api/report')
      .then((res) => res.json())
      .then((data: ReportResults) => setReportResults(data))
      .catch((err) => console.error('Report generation failed:', err))
      .finally(() => setIsReportLoading(false));
  };

  const handleReset = () => {
    setBlastResults(null);
    setGapResults(null);
    setZeroDayResults(null);
    setDriftResults(null);
    setAnalyticsResults(null);
    setReportResults(null);
    setHighlightNodes(new Set());
    setSelectedNode(null);
  };

  return (
    <div className="dashboard">
      <Sidebar
        onBlastRadius={handleBlastRadius}
        onGapAnalysis={handleGapAnalysis}
        onReset={handleReset}
        onSimulateZeroDay={handleSimulateZeroDay}
        onCheckDrift={handleCheckDrift}
        onRunAnalytics={handleRunAnalytics}
        onGenerateReport={handleGenerateReport}
        blastResults={blastResults}
        gapResults={gapResults}
        zeroDayResults={zeroDayResults}
        driftResults={driftResults}
        analyticsResults={analyticsResults}
        reportResults={reportResults}
        isSimulating={isSimulating}
        isDriftLoading={isDriftLoading}
        isAnalyticsLoading={isAnalyticsLoading}
        isReportLoading={isReportLoading}
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
