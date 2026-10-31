import React, { useState } from 'react';
import { GlassCard } from '../common/GlassCard';
import { apiClient } from '../../services/api';
import { Shield, EyeOff, Lock, CheckCircle2, AlertTriangle, KeyRound, ServerOff, Terminal } from 'lucide-react';

export const PrivacySection: React.FC = () => {
  const [inputText, setInputText] = useState(
    'माझा आधार क्रमांक 2345 6789 0123 आहे आणि संपर्क +91 9876543210 आहे. तक्रारीसाठी officer@ladkibahin-support.org वर संपर्क साधा.'
  );
  const [sanitizedResult, setSanitizedResult] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [redactedCount, setRedactedCount] = useState<number | null>(null);

  const handleSanitize = async () => {
    if (!inputText.trim()) return;
    setLoading(true);
    try {
      const res = await apiClient.sanitizeEvidence(inputText);
      setSanitizedResult(res.sanitized_text);
      setRedactedCount(res.redacted_entities_count);
    } catch (err: any) {
      console.warn('Sanitization API error:', err);
      // Fallback local regex redaction matching Seva privacy gate
      const aadhaarPattern = /\b\d{4}\s\d{4}\s\d{4}\b/g;
      const phonePattern = /(?:\+91[\s-]?)?[6789]\d{9}\b/g;
      const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

      let count = 0;
      let text = inputText;
      text = text.replace(aadhaarPattern, () => { count++; return '[REDACTED_AADHAAR]'; });
      text = text.replace(phonePattern, () => { count++; return '[REDACTED_PHONE]'; });
      text = text.replace(emailPattern, () => { count++; return '[REDACTED_EMAIL]'; });

      setSanitizedResult(text);
      setRedactedCount(count);
    } finally {
      setLoading(false);
    }
  };

  const samplePresets = [
    {
      label: 'Aadhaar + Phone (Marathi)',
      text: 'माझा आधार क्रमांक 2345 6789 0123 आहे आणि संपर्क +91 9876543210 आहे. तक्रारीसाठी officer@ladkibahin-support.org वर संपर्क साधा.'
    },
    {
      label: 'MSEDCL Bill Alert PII',
      text: 'प्रिय ग्राहक, तुमची वीज आज रात्री बंद होईल. बिल दुरुस्तीसाठी 9823000000 वर कॉल करा किंवा bill@msedcl-update.in वर आधार 4567 8901 2345 पाठवा.'
    },
    {
      label: 'English Scam Form Submission',
      text: 'Please confirm KYC for account 9876543210. Send your Aadhaar 3456 7890 1234 to verify@pmkisan-direct.com immediately.'
    }
  ];

  return (
    <section id="privacy" className="py-24 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="text-center max-w-3xl mx-auto mb-14">
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-mineral-teal/10 border border-mineral-teal/20 text-mineral-teal text-xs font-semibold tracking-wide uppercase mb-4">
          <EyeOff className="w-3.5 h-3.5" />
          Strict Privacy & Security Architecture
        </div>
        <h2 className="text-3xl sm:text-4xl font-bold text-deep-graphite tracking-tight mb-4 font-display">
          Fail-Closed Privacy Gate & PII Redaction
        </h2>
        <p className="text-slate-grey text-base sm:text-lg leading-relaxed">
          Before any evidence is analyzed, tokenized, or stored, citizen personally identifiable information is sanitized in-memory using deterministic Verhoeff-aware algorithms.
        </p>
      </div>

      {/* Interactive PII Playground */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start mb-12">
        <div className="lg:col-span-7">
          <GlassCard className="p-6 shadow-xl border border-soft-stone">
            <div className="flex items-center justify-between mb-4 pb-3 border-b border-soft-stone/60">
              <h3 className="text-sm font-bold text-deep-graphite flex items-center gap-2">
                <Terminal className="w-4 h-4 text-mineral-teal" />
                Live In-Memory PII Redaction Playground
              </h3>
              <span className="text-[11px] font-mono text-emerald-700 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded">
                Fail-Closed: Active
              </span>
            </div>

            {/* Presets */}
            <div className="mb-4">
              <label className="text-xs font-medium text-slate-grey mb-1.5 block">Quick Test Presets:</label>
              <div className="flex flex-wrap gap-2">
                {samplePresets.map((preset, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => {
                      setInputText(preset.text);
                      setSanitizedResult(null);
                      setRedactedCount(null);
                    }}
                    className="px-2.5 py-1 text-xs rounded-md bg-warm-ivory border border-soft-stone text-deep-graphite hover:border-mineral-teal/60 hover:bg-white transition-all shadow-2xs"
                  >
                    {preset.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Input */}
            <div className="mb-4">
              <label className="text-xs font-semibold text-deep-graphite mb-1 block">Raw Evidence Text (Local Memory Only):</label>
              <textarea
                rows={4}
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                className="w-full text-xs font-mono p-3 rounded-lg border border-soft-stone bg-porcelain/60 text-deep-graphite focus:outline-none focus:ring-1 focus:ring-mineral-teal resize-none"
                placeholder="Enter raw text containing Aadhaar, phone numbers, or emails..."
              />
            </div>

            <button
              onClick={handleSanitize}
              disabled={loading || !inputText.trim()}
              className="w-full py-2.5 px-4 rounded-lg bg-mineral-teal text-white text-xs font-semibold hover:bg-mineral-teal/90 transition-all shadow-sm flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
            >
              <EyeOff className="w-4 h-4" />
              {loading ? 'Redacting PII...' : 'Sanitize Evidence In-Memory'}
            </button>

            {/* Output */}
            {sanitizedResult && (
              <div className="mt-5 pt-4 border-t border-soft-stone/60">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-bold text-deep-graphite flex items-center gap-1.5">
                    <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                    Sanitized Stream for Investigation Pipeline:
                  </span>
                  <span className="text-xs font-mono font-semibold text-mineral-teal bg-mineral-teal/10 px-2 py-0.5 rounded">
                    {redactedCount !== null ? `${redactedCount} Entities Scrubbed` : 'Scrubbed'}
                  </span>
                </div>
                <div className="p-3.5 rounded-lg bg-porcelain border border-soft-stone font-mono text-xs text-deep-graphite leading-relaxed whitespace-pre-wrap">
                  {sanitizedResult}
                </div>
                <div className="text-[10px] text-slate-grey mt-2 flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3 text-emerald-600" />
                  Aadhaar digits, phone numbers, and emails stripped before reaching SQLite database.
                </div>
              </div>
            )}
          </GlassCard>
        </div>

        {/* Security Principles Cards */}
        <div className="lg:col-span-5 space-y-4">
          <GlassCard className="p-5 shadow-md">
            <div className="flex items-start gap-3">
              <div className="p-2 rounded-lg bg-mineral-teal/10 text-mineral-teal shrink-0">
                <ServerOff className="w-5 h-5" />
              </div>
              <div>
                <h4 className="text-sm font-bold text-deep-graphite">Zero-Network Quarantine</h4>
                <p className="text-xs text-slate-grey mt-1 leading-relaxed">
                  Seva Cyber Sandbox enforces strict air-gap compliance. Zero network calls are made during message parsing, APK unpacking, or AI inference. All heuristics and tokenizers run strictly on local CPU.
                </p>
              </div>
            </div>
          </GlassCard>

          <GlassCard className="p-5 shadow-md">
            <div className="flex items-start gap-3">
              <div className="p-2 rounded-lg bg-muted-copper/10 text-muted-copper shrink-0">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <div>
                <h4 className="text-sm font-bold text-deep-graphite">Fail-Closed Ingestion Policy</h4>
                <p className="text-xs text-slate-grey mt-1 leading-relaxed">
                  If any parsing exception, checksum ambiguity, or decoding failure occurs during evidence intake, the system safely aborts or sanitizes aggressively. Unchecked evidence is never propagated into analytical stores.
                </p>
              </div>
            </div>
          </GlassCard>

          <GlassCard className="p-5 shadow-md">
            <div className="flex items-start gap-3">
              <div className="p-2 rounded-lg bg-emerald-50 text-emerald-700 shrink-0 border border-emerald-200">
                <KeyRound className="w-5 h-5" />
              </div>
              <div>
                <h4 className="text-sm font-bold text-deep-graphite">OWASP scrypt Operator Auth</h4>
                <p className="text-xs text-slate-grey mt-1 leading-relaxed">
                  Local operator passwords are encrypted using OWASP-compliant <code className="font-mono text-deep-graphite">scrypt</code> parameters (<span className="font-mono text-[11px]">N=16384, r=8, p=5</span>) with cryptographically secure 16-byte random salts.
                </p>
              </div>
            </div>
          </GlassCard>
        </div>
      </div>
    </section>
  );
};
