import React, { useState } from 'react';
import { GlassCard } from '../common/GlassCard';
import {
  FileCode2,
  UploadCloud,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileCheck,
  CheckCircle2,
  Lock,
} from 'lucide-react';
import { analyzeApk } from '../../services/api';
import { UnifiedAnalysisResponse } from '../../types';

export const ApkSection: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<UnifiedAnalysisResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (!file.name.toLowerCase().endsWith('.apk')) {
        setErrorMessage('Only Android .apk package archives are supported.');
        return;
      }
      setSelectedFile(file);
      setErrorMessage(null);
      setAnalysisResult(null);
    }
  };

  const handleAnalyze = async () => {
    if (!selectedFile) {
      setErrorMessage('Please select or upload an Android .apk file.');
      return;
    }
    setLoading(true);
    setErrorMessage(null);

    try {
      const res = await analyzeApk(selectedFile, true);
      setAnalysisResult(res);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to inspect APK archive.');
    } finally {
      setLoading(false);
    }
  };

  const apkArtifact = analysisResult?.artifacts.find((a) => a.artifact_type === 'apk');
  const apkData = apkArtifact?.analysis_result;

  return (
    <section id="apk-lab" className="py-20 relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="max-w-3xl mb-12">
          <div className="caption-label mb-2 text-[#B8794B]">04 // STATIC FORENSICS</div>
          <h2 className="text-3xl sm:text-4xl font-bold text-[#202C32] tracking-tight mb-4">
            Interactive APK Analysis Laboratory
          </h2>
          <p className="text-[#738087] text-base leading-relaxed">
            Upload Android application packages for isolated in-memory static forensics.
            Safely inspects AndroidManifest.xml and DEX headers without decompilation or running unverified code.
          </p>
        </div>

        {/* Upload Zone */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 mb-8">
          <div className="lg:col-span-6">
            <GlassCard className="h-full flex flex-col justify-center items-center text-center p-8 border-2 border-dashed border-[#DDDCD3] hover:border-[#477C78]/50 transition-colors">
              <input
                type="file"
                id="apk-upload-input"
                accept=".apk"
                onChange={handleFileChange}
                className="hidden"
              />
              <label
                htmlFor="apk-upload-input"
                className="cursor-pointer flex flex-col items-center w-full"
              >
                <div className="w-14 h-14 rounded-2xl bg-[#FAF8F2] flex items-center justify-center text-[#B8794B] mb-4 shadow-xs">
                  <UploadCloud className="w-7 h-7" />
                </div>
                <h4 className="text-sm font-bold text-[#202C32] mb-1">
                  {selectedFile ? selectedFile.name : 'Select or Drag & Drop .APK Archive'}
                </h4>
                <p className="text-xs text-[#738087] max-w-sm mb-4">
                  {selectedFile
                    ? `Size: ${(selectedFile.size / 1024 / 1024).toFixed(2)} MB • Ready for in-memory static inspection`
                    : 'Inspects APKs up to 15 MB in memory. Binary strings and permissions analyzed without execution.'}
                </p>
                <span className="px-4 py-2 rounded-xl liquid-glass text-xs font-semibold text-[#477C78] hover:bg-white transition shadow-xs">
                  {selectedFile ? 'Change File' : 'Browse Local Files'}
                </span>
              </label>

              {selectedFile && (
                <div className="mt-6 w-full pt-4 border-t border-[#DDDCD3] flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs text-[#202C32]">
                    <FileCheck className="w-4 h-4 text-[#477C78]" />
                    <span className="font-mono text-[11px] truncate max-w-[200px]">{selectedFile.name}</span>
                  </div>
                  <button
                    onClick={handleAnalyze}
                    disabled={loading}
                    className="px-5 py-2 rounded-xl bg-[#B8794B] hover:bg-[#a3693e] text-white text-xs font-medium transition cursor-pointer disabled:opacity-50"
                  >
                    {loading ? 'Inspecting Archive...' : 'Start Static Inspection'}
                  </button>
                </div>
              )}
            </GlassCard>
          </div>

          {/* Safety & Sandbox Policy Card */}
          <div className="lg:col-span-6 space-y-4">
            <GlassCard elevated className="space-y-4">
              <div className="flex items-center gap-2 text-xs font-bold text-[#B8794B] uppercase tracking-wider">
                <Lock className="w-4 h-4" />
                <span>Workstation Isolation Guarantee</span>
              </div>
              <p className="text-xs text-[#738087] leading-relaxed">
                Seva adheres to strict offline safety standards when analyzing unknown Android binaries:
              </p>
              <ul className="space-y-2 text-xs text-[#202C32]">
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-[#477C78] shrink-0 mt-0.5" />
                  <span><strong>Zero Execution:</strong> APKs are never installed, executed, or booted into emulators on the host.</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-[#477C78] shrink-0 mt-0.5" />
                  <span><strong>Direct Memory Reading:</strong> Manifest and DEX bytes are parsed in volatile RAM; zero persistent temporary script drop.</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-[#477C78] shrink-0 mt-0.5" />
                  <span><strong>Honest Caveat:</strong> Lack of suspicious permissions does not guarantee an APK is benign. Advanced evasive payloads require dynamic sandbox evaluation.</span>
                </li>
              </ul>
            </GlassCard>
          </div>
        </div>

        {errorMessage && (
          <div className="p-4 rounded-2xl bg-[#C0392B]/10 border border-[#C0392B]/30 text-[#C0392B] text-xs mb-8 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* APK Analysis Results */}
        {apkData && (
          <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-300">
            {/* Overview Banner */}
            <div className="p-6 rounded-2xl liquid-glass-elevated border-l-6 border-l-[#B8794B]">
              <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
                <div>
                  <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-[#738087]">
                    STATIC APK FORENSIC REPORT
                  </span>
                  <h3 className="text-2xl font-extrabold text-[#202C32] tracking-tight font-mono">
                    {apkData.package_name || 'com.unknown.application'}
                  </h3>
                </div>

                <div className="flex items-center gap-3">
                  <span className="px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-[#B8794B] text-white">
                    APK RISK SCORE: {apkArtifact?.risk_score}/100 ({apkArtifact?.risk_category})
                  </span>
                </div>
              </div>

              {/* SHA-256 and Specs */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-4 border-t border-[#DDDCD3] text-xs">
                <div>
                  <span className="text-[#738087] block text-[10px] uppercase">SHA-256 Hash:</span>
                  <span className="font-mono text-[#202C32] break-all text-[11px]">
                    {apkArtifact?.artifact_sha256 || 'N/A'}
                  </span>
                </div>
                <div>
                  <span className="text-[#738087] block text-[10px] uppercase">File Size:</span>
                  <span className="font-mono text-[#202C32]">
                    {(apkData.file_size_bytes / 1024).toFixed(1)} KB
                  </span>
                </div>
                <div>
                  <span className="text-[#738087] block text-[10px] uppercase">Archive Format:</span>
                  <span className="font-mono text-[#202C32]">
                    Manifest: {apkData.manifest_format} • DEX: {apkData.dex_format}
                  </span>
                </div>
              </div>
            </div>

            {/* Heuristic Warnings & Declared Permissions */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Permissions */}
              <GlassCard className="space-y-3">
                <h4 className="text-sm font-bold text-[#202C32] flex items-center justify-between">
                  <span>Declared Permissions ({apkData.permissions_found?.length || 0})</span>
                  <span className="text-xs text-[#738087] font-normal">Extracted from Manifest</span>
                </h4>
                {apkData.permissions_found && apkData.permissions_found.length > 0 ? (
                  <div className="max-h-60 overflow-y-auto space-y-1.5 pr-2">
                    {apkData.permissions_found.map((p: any, idx: number) => (
                      <div
                        key={idx}
                        className="p-2 rounded-lg bg-white/70 border border-[#DDDCD3] flex items-center justify-between text-xs"
                      >
                        <span className="font-mono text-[11px] text-[#202C32] truncate max-w-[280px]">
                          {p.permission}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                            p.severity === 'high' || p.severity === 'critical'
                              ? 'bg-[#C0392B]/15 text-[#C0392B]'
                              : 'bg-[#477C78]/15 text-[#477C78]'
                          }`}
                        >
                          {p.severity}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-[#738087]">No standard permissions declared in AndroidManifest.xml.</p>
                )}
              </GlassCard>

              {/* Heuristics & Passive URLs */}
              <GlassCard className="space-y-4">
                <h4 className="text-sm font-bold text-[#202C32]">Heuristic Risk Observations</h4>
                {apkData.heuristic_warnings && apkData.heuristic_warnings.length > 0 ? (
                  <div className="space-y-2">
                    {apkData.heuristic_warnings.map((hw: string, idx: number) => (
                      <div key={idx} className="p-2.5 rounded-xl bg-[#B8794B]/10 border border-[#B8794B]/30 text-xs text-[#202C32] flex items-start gap-2">
                        <AlertTriangle className="w-4 h-4 text-[#B8794B] shrink-0 mt-0.5" />
                        <span>{hw}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-[#738087]">No automated heuristic flags raised during static parsing.</p>
                )}

                {apkData.passive_urls && apkData.passive_urls.length > 0 && (
                  <div>
                    <h5 className="text-xs font-bold text-[#738087] uppercase tracking-wider mb-2">
                      Passive URLs Extracted from Manifest/Strings ({apkData.passive_urls.length}):
                    </h5>
                    <ul className="space-y-1 text-xs font-mono text-[#202C32] max-h-36 overflow-y-auto pr-2">
                      {apkData.passive_urls.map((u: string, idx: number) => (
                        <li key={idx} className="p-1.5 rounded bg-white/50 border border-[#DDDCD3] truncate">
                          {u}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </GlassCard>
            </div>
          </div>
        )}
      </div>
    </section>
  );
};
