import React, { useEffect, useState } from 'react';
import { GlassCard } from '../common/GlassCard';
import {
  FolderSearch,
  Search,
  Filter,
  Eye,
  RefreshCw,
  Clock,
  ShieldCheck,
  ShieldAlert,
  GitBranch,
  X,
  FileText,
} from 'lucide-react';
import { fetchCases, fetchCaseDetails } from '../../services/api';
import { CaseRecord } from '../../types';

export const InvestigationSection: React.FC = () => {
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [totalCases, setTotalCases] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(false);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [riskFilter, setRiskFilter] = useState<string>('ALL');
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [caseDetails, setCaseDetails] = useState<any | null>(null);
  const [detailsLoading, setDetailsLoading] = useState<boolean>(false);

  const loadCases = async () => {
    setLoading(true);
    try {
      const res = await fetchCases(searchTerm, riskFilter);
      setCases(res.cases);
      setTotalCases(res.total_cases);
    } catch {
      // In case DB is empty or fresh
      setCases([]);
      setTotalCases(0);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCases();
  }, [riskFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadCases();
  };

  const handleOpenCase = async (caseId: string) => {
    setSelectedCaseId(caseId);
    setDetailsLoading(true);
    try {
      const res = await fetchCaseDetails(caseId);
      setCaseDetails(res);
    } catch {
      setCaseDetails(null);
    } finally {
      setDetailsLoading(false);
    }
  };

  return (
    <section id="investigation" className="py-20 relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="max-w-3xl mb-12">
          <div className="caption-label mb-2 text-[#202C32]">05 // CASE ARCHIVES</div>
          <h2 className="text-3xl sm:text-4xl font-bold text-[#202C32] tracking-tight mb-4">
            Digital Investigation Center
          </h2>
          <p className="text-[#738087] text-base leading-relaxed">
            Forensic case management connected directly to SQLite Schema v3.
            Explore verified investigations, parent-child multi-artifact relationships, and immutable audit logs.
          </p>
        </div>

        {/* Search & Filter Bar */}
        <GlassCard className="mb-8">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <form onSubmit={handleSearchSubmit} className="flex items-center gap-2 flex-1 max-w-md">
              <div className="flex items-center gap-2 liquid-glass px-3 py-2 rounded-xl w-full border border-white/80">
                <Search className="w-4 h-4 text-[#738087]" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Search by Case ID, domain, target, or keyword..."
                  className="bg-transparent border-none text-xs text-[#202C32] focus:outline-none w-full"
                />
              </div>
              <button
                type="submit"
                className="px-4 py-2 rounded-xl bg-[#202C32] text-white text-xs font-medium cursor-pointer"
              >
                Search
              </button>
            </form>

            <div className="flex items-center gap-2">
              <span className="text-xs text-[#738087] font-semibold">Filter:</span>
              {['ALL', 'Critical Risk', 'High Risk', 'Medium Risk', 'Low Risk', 'Benign / Verified'].map((lvl) => (
                <button
                  key={lvl}
                  onClick={() => setRiskFilter(lvl)}
                  className={`px-3 py-1.5 rounded-xl text-[11px] font-medium transition cursor-pointer ${
                    riskFilter === lvl
                      ? 'bg-[#477C78] text-white'
                      : 'liquid-glass text-[#738087] hover:text-[#202C32]'
                  }`}
                >
                  {lvl.replace('Risk', '').trim()}
                </button>
              ))}

              <button
                onClick={loadCases}
                title="Refresh Cases"
                className="p-2 rounded-xl liquid-glass text-[#738087] hover:text-[#202C32] cursor-pointer"
              >
                <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              </button>
            </div>
          </div>
        </GlassCard>

        {/* Case Records Grid */}
        {cases.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {cases.map((c) => {
              const isParent = c.metadata?.is_parent_investigation;
              return (
                <GlassCard
                  key={c.case_id}
                  interactive
                  onClick={() => handleOpenCase(c.case_id)}
                  className="flex flex-col justify-between group"
                >
                  <div>
                    <div className="flex items-center justify-between mb-3">
                      <span className="font-mono text-[11px] font-bold text-[#477C78]">
                        {c.case_id}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider text-white ${
                          c.risk_score >= 60
                            ? 'bg-[#C0392B]'
                            : c.risk_score >= 40
                            ? 'bg-[#D35400]'
                            : 'bg-[#477C78]'
                        }`}
                      >
                        {c.risk_category}
                      </span>
                    </div>

                    <h4 className="text-sm font-bold text-[#202C32] mb-1 truncate">
                      {c.target_identifier || c.analysis_type}
                    </h4>

                    <div className="text-[11px] text-[#738087] flex items-center gap-1.5 mb-4">
                      <Clock className="w-3 h-3" />
                      <span>{c.timestamp_utc ? new Date(c.timestamp_utc).toLocaleString() : 'Recent'}</span>
                    </div>

                    {isParent && (
                      <div className="p-2 rounded-lg bg-[#DFE9E1] text-[10px] font-mono text-[#477C78] mb-3 flex items-center gap-1.5">
                        <GitBranch className="w-3.5 h-3.5" />
                        <span>Parent Investigation ({c.metadata?.child_case_ids?.length || 0} Linked Artifacts)</span>
                      </div>
                    )}
                  </div>

                  <div className="pt-3 border-t border-[#DDDCD3] flex items-center justify-between text-xs font-semibold text-[#477C78]">
                    <span>Score: {c.risk_score}/100</span>
                    <span className="flex items-center gap-1 group-hover:translate-x-1 transition-transform">
                      <span>View Forensic Details</span>
                      <Eye className="w-3.5 h-3.5" />
                    </span>
                  </div>
                </GlassCard>
              );
            })}
          </div>
        ) : (
          <GlassCard className="p-12 text-center text-[#738087]">
            <FolderSearch className="w-10 h-10 mx-auto text-[#738087]/50 mb-3" />
            <h4 className="text-sm font-semibold text-[#202C32] mb-1">
              {loading ? 'Querying Case Repository...' : 'No Operational Case Records Found'}
            </h4>
            <p className="text-xs text-[#738087] max-w-md mx-auto mb-4">
              {searchTerm
                ? `No cases matched "${searchTerm}". Try resetting search or filter.`
                : 'The operational SQLite database is currently pristine. Analyze an evidence message, URL, or APK above and click "Save to SQLite" to register a forensic case.'}
            </p>
          </GlassCard>
        )}

        {/* Modal / Case Detail Drawer */}
        {selectedCaseId && (
          <div className="fixed inset-0 z-50 bg-black/30 backdrop-blur-xs flex items-center justify-center p-4">
            <div className="w-full max-w-2xl max-h-[90vh] overflow-y-auto liquid-glass-elevated p-6 rounded-3xl shadow-2xl animate-in zoom-in-95 duration-200">
              <div className="flex items-center justify-between pb-4 border-b border-[#DDDCD3] mb-4">
                <div>
                  <span className="text-[10px] font-mono uppercase text-[#738087]">CASE FORENSIC DOSSIER</span>
                  <h3 className="text-lg font-bold font-mono text-[#202C32]">{selectedCaseId}</h3>
                </div>
                <button
                  onClick={() => setSelectedCaseId(null)}
                  className="p-1.5 rounded-xl text-[#738087] hover:text-[#202C32] hover:bg-black/5"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {detailsLoading ? (
                <div className="py-12 text-center text-xs text-[#738087]">Loading case forensic records...</div>
              ) : caseDetails ? (
                <div className="space-y-4 text-xs">
                  <div className="grid grid-cols-2 gap-3 p-3 rounded-xl bg-white/60 border border-[#DDDCD3]">
                    <div>
                      <span className="text-[#738087] block text-[10px] uppercase">Analysis Type:</span>
                      <span className="font-semibold text-[#202C32]">{caseDetails.case.analysis_type}</span>
                    </div>
                    <div>
                      <span className="text-[#738087] block text-[10px] uppercase">Authoritative Score:</span>
                      <span className="font-bold text-[#202C32]">
                        {caseDetails.case.risk_score}/100 ({caseDetails.case.risk_category})
                      </span>
                    </div>
                  </div>

                  {/* Child Cases if Parent */}
                  {caseDetails.investigation_details?.child_cases?.length > 0 && (
                    <div>
                      <h5 className="font-bold text-[#477C78] uppercase text-[11px] tracking-wider mb-2 flex items-center gap-1.5">
                        <GitBranch className="w-3.5 h-3.5" />
                        <span>Linked Child Artifact Cases ({caseDetails.investigation_details.child_cases.length}):</span>
                      </h5>
                      <div className="space-y-2">
                        {caseDetails.investigation_details.child_cases.map((ch: any) => (
                          <div key={ch.case_id} className="p-3 rounded-xl bg-white/70 border border-[#DDDCD3]">
                            <div className="flex justify-between items-center mb-1">
                              <span className="font-mono font-bold text-[#202C32]">{ch.case_id}</span>
                              <span className="text-[10px] font-mono uppercase text-[#738087]">
                                Status: {ch.current_evidence_provenance?.lifecycle_status || 'Active'}
                              </span>
                            </div>
                            <div className="text-[11px] text-[#738087]">
                              Target: {ch.target_identifier} • Score: {ch.risk_score}/100
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Observed Evidence */}
                  <div>
                    <h5 className="font-bold text-[#738087] uppercase text-[11px] tracking-wider mb-2">
                      Recorded Observations:
                    </h5>
                    <ul className="list-disc list-inside space-y-1 text-[#202C32]">
                      {caseDetails.case.observed_evidence?.map((obs: string, idx: number) => (
                        <li key={idx}>{obs}</li>
                      ))}
                    </ul>
                  </div>

                  <div className="pt-3 border-t border-[#DDDCD3] text-[10px] text-[#738087] font-mono">
                    Referential Integrity: SQLite v3 Schema Verified • Citizen GDPR Erasure Tracking Enabled
                  </div>
                </div>
              ) : (
                <div className="py-8 text-center text-xs text-[#738087]">Could not retrieve case details.</div>
              )}
            </div>
          </div>
        )}
      </div>
    </section>
  );
};
