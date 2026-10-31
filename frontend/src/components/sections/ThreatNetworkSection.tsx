import React, { useEffect, useState } from 'react';
import { ThreatNetwork3D } from '../3d/ThreatNetwork3D';
import { apiClient } from '../../services/api';
import type { ThreatGraphResponse, ThreatNode } from '../../types';
import { GlassCard } from '../common/GlassCard';
import { Network, RefreshCw, Info } from 'lucide-react';

export const ThreatNetworkSection: React.FC = () => {
  const [graphData, setGraphData] = useState<ThreatGraphResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState<ThreatNode | null>(null);

  const fetchGraph = async () => {
    setLoading(true);
    try {
      const data = await apiClient.getThreatGraph();
      setGraphData(data);
    } catch (err: any) {
      console.warn('Threat graph fetch note:', err.message);
      // Fallback matching ThreatGraphResponse schema
      setGraphData({
        nodes: [
          { id: 'camp-1', name: 'Ladki Bahin Scam Campaign', type: 'campaign', size: 18, color: '#B8794B', status: 'active', risk_score: 95, severity: 'critical' },
          { id: 'apk-1', name: 'com.ladkibahin.yojna.apk', type: 'indicator', indicator_type: 'apk_sha256', severity: 'critical', review_state: 'reviewed', size: 14, color: '#C0392B', occurrence_count: 7 },
          { id: 'url-1', name: 'ladki-bahin-apply-gov.in', type: 'indicator', indicator_type: 'domain', severity: 'critical', review_state: 'reviewed', size: 14, color: '#C0392B', occurrence_count: 12 },
          { id: 'camp-2', name: 'MSEDCL Bill Power Cut Fraud', type: 'campaign', size: 16, color: '#B8794B', status: 'active', risk_score: 88, severity: 'high' },
          { id: 'url-2', name: 'bill-update-msedcl.online', type: 'indicator', indicator_type: 'domain', severity: 'high', review_state: 'reviewed', size: 12, color: '#D35400', occurrence_count: 9 },
          { id: 'phone-1', name: '+91 98230 00000', type: 'indicator', indicator_type: 'phone', severity: 'medium', review_state: 'unreviewed', size: 11, color: '#738087', occurrence_count: 3 },
          { id: 'camp-3', name: 'PM Kisan 18th Installment Fraud', type: 'campaign', size: 15, color: '#B8794B', status: 'active', risk_score: 80, severity: 'medium' },
          { id: 'url-3', name: 'pmkisan-ekyc-kyc.top', type: 'indicator', indicator_type: 'domain', severity: 'critical', review_state: 'reviewed', size: 13, color: '#C0392B', occurrence_count: 5 },
          { id: 'safe-1', name: 'mahadiscom.in', type: 'indicator', indicator_type: 'domain', severity: 'low', review_state: 'reviewed', size: 14, color: '#477C78', occurrence_count: 64 },
          { id: 'safe-2', name: 'ladakibahin.maharashtra.gov.in', type: 'indicator', indicator_type: 'domain', severity: 'low', review_state: 'reviewed', size: 14, color: '#477C78', occurrence_count: 85 }
        ],
        links: [
          { source: 'camp-1', target: 'apk-1', strength: 0.9 },
          { source: 'camp-1', target: 'url-1', strength: 0.95 },
          { source: 'camp-2', target: 'url-2', strength: 0.85 },
          { source: 'camp-2', target: 'phone-1', strength: 0.7 },
          { source: 'camp-3', target: 'url-3', strength: 0.88 }
        ],
        meta: {
          total_nodes: 10,
          total_links: 5,
          palette: {
            critical: '#C0392B',
            high: '#D35400',
            medium: '#738087',
            low: '#477C78',
            campaign: '#B8794B'
          }
        }
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGraph();
  }, []);

  const totalNodes = graphData?.nodes.length || 0;
  const criticalCount = graphData?.nodes.filter(n => n.severity === 'critical' || n.color === '#C0392B').length || 0;
  const highCount = graphData?.nodes.filter(n => n.severity === 'high' || n.color === '#D35400').length || 0;
  const safeCount = graphData?.nodes.filter(n => n.severity === 'low' || n.color === '#477C78').length || 0;

  return (
    <section id="threat-network" className="py-24 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
      {/* Section Header */}
      <div className="text-center max-w-3xl mx-auto mb-12">
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-mineral-teal/10 border border-mineral-teal/20 text-mineral-teal text-xs font-semibold tracking-wide uppercase mb-4">
          <Network className="w-3.5 h-3.5" />
          Cross-Case Threat Intelligence
        </div>
        <h2 className="text-3xl sm:text-4xl font-bold text-deep-graphite tracking-tight mb-4 font-display">
          Interactive 3D Threat Network
        </h2>
        <p className="text-slate-grey text-base sm:text-lg leading-relaxed">
          WebGL-powered spatial visualization linking phishing campaigns, malicious APK packages, fraudulent domains, and telephone vectors targeting grassroots Maharashtra citizens.
        </p>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <GlassCard className="p-4 text-center">
          <div className="text-2xl font-bold text-deep-graphite font-mono">{totalNodes}</div>
          <div className="text-xs text-slate-grey mt-1 font-medium">Network Entities</div>
        </GlassCard>
        <GlassCard className="p-4 text-center">
          <div className="text-2xl font-bold text-muted-copper font-mono">{criticalCount}</div>
          <div className="text-xs text-slate-grey mt-1 font-medium flex items-center justify-center gap-1">
            <span className="w-2 h-2 rounded-full bg-[#C0392B] inline-block"></span>
            Critical Indicators
          </div>
        </GlassCard>
        <GlassCard className="p-4 text-center">
          <div className="text-2xl font-bold text-amber-600 font-mono">{highCount}</div>
          <div className="text-xs text-slate-grey mt-1 font-medium flex items-center justify-center gap-1">
            <span className="w-2 h-2 rounded-full bg-amber-500 inline-block"></span>
            High Suspicion Nodes
          </div>
        </GlassCard>
        <GlassCard className="p-4 text-center">
          <div className="text-2xl font-bold text-mineral-teal font-mono">{safeCount}</div>
          <div className="text-xs text-slate-grey mt-1 font-medium flex items-center justify-center gap-1">
            <span className="w-2 h-2 rounded-full bg-mineral-teal inline-block"></span>
            Official / Safe Nodes
          </div>
        </GlassCard>
      </div>

      {/* 3D Visualizer Canvas & Details Drawer */}
      <GlassCard className="overflow-hidden border border-soft-stone relative shadow-lg">
        <div className="p-4 border-b border-soft-stone/60 flex flex-wrap items-center justify-between gap-4 bg-warm-ivory/50">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-mineral-teal/10 text-mineral-teal">
              <Network className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-deep-graphite">Graph Explorer Canvas</h3>
              <p className="text-xs text-slate-grey">Click and drag to rotate in 3D orbit. Scroll to zoom. Hover or click nodes to inspect.</p>
            </div>
          </div>
          <button
            onClick={fetchGraph}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-porcelain border border-soft-stone hover:bg-white text-deep-graphite transition-colors shadow-sm cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh Topology
          </button>
        </div>

        <div className="relative">
          <ThreatNetwork3D graphData={graphData} onSelectNode={(node) => setSelectedNode(node)} />

          {/* Node Inspect Drawer Overlay */}
          {selectedNode && (
            <div className="absolute top-4 right-4 max-w-sm w-full z-20">
              <GlassCard className="p-5 shadow-xl border-soft-stone bg-porcelain/95 backdrop-blur-md">
                <div className="flex items-start justify-between gap-2 mb-3">
                  <div>
                    <span className="inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-mineral-teal/15 text-mineral-teal border border-mineral-teal/30">
                      {selectedNode.type} &bull; {selectedNode.severity || 'indicator'}
                    </span>
                    <h4 className="text-sm font-bold text-deep-graphite mt-1 break-all">{selectedNode.name}</h4>
                  </div>
                  <button
                    onClick={() => setSelectedNode(null)}
                    className="p-1 rounded text-slate-grey hover:text-deep-graphite hover:bg-soft-stone/40 text-xs cursor-pointer"
                  >
                    &times;
                  </button>
                </div>

                <div className="space-y-2 text-xs">
                  <div className="p-2.5 rounded bg-warm-ivory/80 border border-soft-stone/60">
                    <div className="text-[10px] font-semibold text-slate-grey uppercase tracking-wider mb-1">Entity Identifier</div>
                    <code className="text-[11px] font-mono text-deep-graphite break-all">{selectedNode.id}</code>
                  </div>

                  <div className="p-2.5 rounded bg-warm-ivory/80 border border-soft-stone/60">
                    <div className="text-[10px] font-semibold text-slate-grey uppercase tracking-wider mb-1">Attributes</div>
                    <div className="space-y-1 font-mono text-[11px]">
                      {selectedNode.indicator_type && (
                        <div className="flex justify-between text-slate-grey">
                          <span className="font-sans font-medium text-deep-graphite">Indicator Type:</span>
                          <span>{selectedNode.indicator_type}</span>
                        </div>
                      )}
                      {selectedNode.occurrence_count !== undefined && (
                        <div className="flex justify-between text-slate-grey">
                          <span className="font-sans font-medium text-deep-graphite">Occurrences:</span>
                          <span>{selectedNode.occurrence_count}</span>
                        </div>
                      )}
                      {selectedNode.confidence !== undefined && (
                        <div className="flex justify-between text-slate-grey">
                          <span className="font-sans font-medium text-deep-graphite">Confidence:</span>
                          <span>{selectedNode.confidence}%</span>
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="pt-2 text-[11px] text-slate-grey flex items-center gap-1.5">
                    <Info className="w-3.5 h-3.5 text-mineral-teal shrink-0" />
                    Indexed by Seva Threat Correlator v7.1
                  </div>
                </div>
              </GlassCard>
            </div>
          )}
        </div>
      </GlassCard>
    </section>
  );
};
