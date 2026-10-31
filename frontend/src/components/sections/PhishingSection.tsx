import React, { useState } from 'react';
import { GlassCard } from '../common/GlassCard';
import {
  MessageSquareWarning,
  Globe,
  Search,
  CheckCircle2,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Save,
  RotateCcw,
  Sparkles,
} from 'lucide-react';
import { analyzeUnified, saveInvestigation } from '../../services/api';
import { UnifiedAnalysisResponse } from '../../types';

export const PhishingSection: React.FC = () => {
  const [messageText, setMessageText] = useState('');
  const [urlText, setUrlText] = useState('');
  const [loading, setLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<UnifiedAnalysisResponse | null>(null);
  const [saveStatus, setSaveStatus] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Quick Test Lures (Real vernacular phishing threat archetypes)
  const presets = [
    {
      label: 'MSEDCL Bill Disconnection',
      msg: 'तात्काळ: महावितरण वीज बिल थकीत आहे. आजच भरा नाहीतर रात्री 9:30 वाजता वीज पुरवठा खंडित केला जाईल. संपर्क: 9820011223 http://bit.ly/mseb-update',
      url: 'http://bit.ly/mseb-update',
    },
    {
      label: 'Ladki Bahin Yojana Fake Portal',
      msg: 'मुख्यमंत्री माझी लाडकी बहीण योजना 3000 रुपये खात्यात जमा करण्यासाठी अर्ज त्वरित भरा: https://ladkibahin-portal-free.xyz/apply',
      url: 'https://ladkibahin-portal-free.xyz/apply',
    },
    {
      label: 'Banking KYC Freeze Notice',
      msg: 'Dear SBI Customer, your YONO account is locked due to pending KYC verification. Update details immediately: http://192.168.1.100/sbi-kyc',
      url: 'http://192.168.1.100/sbi-kyc',
    },
  ];

  const handleRunAnalysis = async () => {
    if (!messageText.trim() && !urlText.trim()) {
      setErrorMessage('Please provide a suspicious message or a target URL to analyze.');
      return;
    }

    setErrorMessage(null);
    setLoading(true);
    setSaveStatus(null);

    try {
      const formData = new FormData();
      if (messageText.trim()) formData.append('message', messageText.trim());
      if (urlText.trim()) formData.append('urls', urlText.trim());
      formData.append('enable_shadow_ai', 'true');
      formData.append('training_consent', 'false');

      const result = await analyzeUnified(formData);
      setAnalysisResult(result);
    } catch (err: any) {
      setErrorMessage(err.message || 'Analysis failed. Please check local API server.');
    } finally {
      setLoading(false);
    }
  };

  const handleSaveInvestigation = async () => {
    if (!analysisResult) return;
    try {
      const res = await saveInvestigation(analysisResult, false);
      setSaveStatus(
        res.is_idempotent_replay
          ? `Investigation ${res.investigation_id} already saved in SQLite (Idempotent: CASE-UNIF-${res.parent_case_id.slice(-8)})`
          : `Saved successfully! Parent Case: ${res.parent_case_id} (${res.child_case_ids.length} linked child cases)`
      );
    } catch (err: any) {
      setSaveStatus(`Failed to save: ${err.message}`);
    }
  };

  const handleReset = () => {
    setMessageText('');
    setUrlText('');
    setAnalysisResult(null);
    setSaveStatus(null);
    setErrorMessage(null);
  };

  return (
    <section id="phishing" className="py-20 relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="max-w-3xl mb-12">
          <div className="caption-label mb-2 text-[#477C78]">03 // DETECTION ENGINE</div>
          <h2 className="text-3xl sm:text-4xl font-bold text-[#202C32] tracking-tight mb-4">
            Phishing Intelligence Workspace
          </h2>
          <p className="text-[#738087] text-base leading-relaxed">
            Submit vernacular SMS, WhatsApp messages, and suspicious target links. Seva executes deterministic token matching,
            official Maharashtra Government Resolution checks, and PII sanitization in real time.
          </p>
        </div>

        {/* Preset Chips */}
        <div className="flex flex-wrap items-center gap-2 mb-6">
          <span className="text-xs font-semibold text-[#738087] mr-1 flex items-center gap-1">
            <Sparkles className="w-3.5 h-3.5 text-[#B8794B]" />
            <span>Load Reference Lure:</span>
          </span>
          {presets.map((p, idx) => (
            <button
              key={idx}
              onClick={() => {
                setMessageText(p.msg);
                setUrlText(p.url);
                setAnalysisResult(null);
              }}
              className="px-3 py-1 rounded-full liquid-glass hover:bg-white text-xs text-[#202C32] border border-[#DDDCD3] transition cursor-pointer"
            >
              {p.label}
            </button>
          ))}
        </div>

        {/* Input Console */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          <GlassCard className="space-y-3">
            <div className="flex items-center gap-2 text-xs font-semibold text-[#202C32] uppercase tracking-wider">
              <MessageSquareWarning className="w-4 h-4 text-[#477C78]" />
              <span>Suspicious Communication Text (Marathi / English)</span>
            </div>
            <textarea
              rows={5}
              value={messageText}
              onChange={(e) => setMessageText(e.target.value)}
              placeholder="Paste suspicious WhatsApp message, SMS, or email text here... Supports Marathi (देवनागरी), Romanized Marathi, or English."
              className="w-full p-3.5 rounded-xl bg-white/70 border border-[#DDDCD3] text-xs text-[#202C32] placeholder-[#738087]/70 focus:outline-none focus:ring-2 focus:ring-[#477C78]/30 font-sans"
            />
          </GlassCard>

          <GlassCard className="space-y-3">
            <div className="flex items-center gap-2 text-xs font-semibold text-[#202C32] uppercase tracking-wider">
              <Globe className="w-4 h-4 text-[#477C78]" />
              <span>Suspicious Target URLs (One per line)</span>
            </div>
            <textarea
              rows={5}
              value={urlText}
              onChange={(e) => setUrlText(e.target.value)}
              placeholder="https://ladkibahin-portal.cc/apply&#10;http://msedcl-bill-update.xyz/login&#10;http://192.168.1.50/pay.php"
              className="w-full p-3.5 rounded-xl bg-white/70 border border-[#DDDCD3] text-xs text-[#202C32] placeholder-[#738087]/70 focus:outline-none focus:ring-2 focus:ring-[#477C78]/30 font-mono"
            />
          </GlassCard>
        </div>

        {/* Execution Actions */}
        <div className="flex flex-wrap items-center justify-between gap-4 mb-8">
          <div className="flex items-center gap-3">
            <button
              onClick={handleRunAnalysis}
              disabled={loading}
              className="px-6 py-3 rounded-2xl bg-[#477C78] hover:bg-[#3b6764] text-white text-xs font-semibold tracking-wide uppercase shadow-md transition disabled:opacity-50 flex items-center gap-2 cursor-pointer"
            >
              {loading ? (
                <>
                  <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  <span>Executing Local Analysis...</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  <span>Analyze Submitted Evidence</span>
                </>
              )}
            </button>

            <button
              onClick={handleReset}
              className="px-4 py-3 rounded-2xl liquid-glass text-xs text-[#738087] hover:text-[#202C32] font-semibold flex items-center gap-1.5 transition cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Clear</span>
            </button>
          </div>

          <div className="text-xs text-[#738087] font-mono">
            🛡️ Privacy Protected: Auto-Aadhaar & Phone Redaction Active
          </div>
        </div>

        {errorMessage && (
          <div className="p-4 rounded-2xl bg-[#C0392B]/10 border border-[#C0392B]/30 text-[#C0392B] text-xs mb-8 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* Live Analysis Output */}
        {analysisResult && (
          <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-300">
            {/* Banner */}
            <div
              className={`p-6 rounded-2xl liquid-glass-elevated border-l-6 ${
                analysisResult.overall_verdict.score >= 60
                  ? 'border-l-[#C0392B]'
                  : analysisResult.overall_verdict.score >= 40
                  ? 'border-l-[#D35400]'
                  : 'border-l-[#477C78]'
              }`}
            >
              <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
                <div>
                  <div className="text-[11px] font-mono font-bold text-[#738087] uppercase tracking-wider">
                    INVESTIGATION // {analysisResult.investigation_id}
                  </div>
                  <h3 className="text-2xl font-extrabold text-[#202C32] tracking-tight">
                    {analysisResult.overall_verdict.risk_category.toUpperCase()} (Index: {analysisResult.overall_verdict.score}/100)
                  </h3>
                </div>

                <div className="flex items-center gap-3">
                  <span
                    className={`px-3.5 py-1.5 rounded-full text-xs font-bold uppercase tracking-wider text-white ${
                      analysisResult.overall_verdict.score >= 60
                        ? 'bg-[#C0392B]'
                        : analysisResult.overall_verdict.score >= 40
                        ? 'bg-[#D35400]'
                        : 'bg-[#477C78]'
                    }`}
                  >
                    AUTHORITATIVE VERDICT: {analysisResult.overall_verdict.risk_category}
                  </span>

                  <button
                    onClick={handleSaveInvestigation}
                    className="px-4 py-2 rounded-xl bg-[#202C32] hover:bg-[#2c3d46] text-white text-xs font-medium transition flex items-center gap-1.5 cursor-pointer"
                  >
                    <Save className="w-3.5 h-3.5" />
                    <span>Save to SQLite</span>
                  </button>
                </div>
              </div>

              {saveStatus && (
                <div className="p-3 rounded-xl bg-[#DFE9E1] text-[#477C78] text-xs font-medium mb-4 flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 shrink-0" />
                  <span>{saveStatus}</span>
                </div>
              )}

              {/* Key Observations */}
              <div className="space-y-1.5 text-xs text-[#202C32] mb-4">
                <div className="font-semibold text-[#738087] uppercase text-[10px] tracking-wider mb-1">
                  Forensic Summary:
                </div>
                {analysisResult.overall_verdict.key_observations.map((obs, i) => (
                  <div key={i} className="flex items-start gap-2">
                    <span className="text-[#477C78] mt-0.5">•</span>
                    <span>{obs}</span>
                  </div>
                ))}
              </div>

              {/* Cross Correlations */}
              {analysisResult.correlations.length > 0 && (
                <div className="pt-4 border-t border-[#DDDCD3]">
                  <div className="text-[11px] font-bold text-[#B8794B] uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>Cross-Evidence Linkages Detected ({analysisResult.correlations.length}):</span>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {analysisResult.correlations.map((corr, idx) => (
                      <div key={idx} className="p-3 rounded-xl bg-white/60 border border-[#DDDCD3] text-xs space-y-1">
                        <div className="font-mono font-bold text-[10px] text-[#477C78]">
                          [{corr.correlation_type}] (Confidence: {corr.confidence})
                        </div>
                        <div className="font-semibold text-[#202C32]">{corr.headline_en}</div>
                        <div className="text-[#738087] text-[11px]">{corr.headline_mr}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Per-Artifact Deep Dives */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {analysisResult.artifacts.map((art) => (
                <GlassCard key={art.artifact_id} className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-mono uppercase bg-[#FAF8F2] text-[#477C78] border border-[#DDDCD3]">
                      {art.artifact_id} // {art.artifact_type}
                    </span>
                    <span className="font-bold text-xs text-[#202C32]">
                      Score: {art.risk_score}/100 ({art.risk_category})
                    </span>
                  </div>

                  <div className="text-xs font-mono text-[#202C32] break-all">
                    Target: {art.target_identifier}
                  </div>

                  {art.analysis_result?.script_detected && (
                    <div className="text-[11px] text-[#738087]">
                      Detected Script: <span className="font-mono text-[#202C32]">{art.analysis_result.script_detected}</span>
                    </div>
                  )}

                  {art.scored_result?.summary_mr && (
                    <div className="p-2.5 rounded-xl bg-[#FAF8F2] text-[11px] text-[#202C32] leading-relaxed">
                      <strong>मराठी स्पष्टीकरण:</strong> {art.scored_result.summary_mr}
                    </div>
                  )}

                  {art.analysis_result?.extracted_urls?.length > 0 && (
                    <div className="text-[11px] text-[#738087]">
                      <strong>Extracted URLs:</strong>
                      <ul className="list-disc list-inside mt-1 font-mono text-[10px]">
                        {art.analysis_result.extracted_urls.map((u: string, idx: number) => (
                          <li key={idx} className="break-all">{u}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </GlassCard>
              ))}
            </div>
          </div>
        )}
      </div>
    </section>
  );
};
