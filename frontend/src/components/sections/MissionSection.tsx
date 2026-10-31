import React from 'react';
import { GlassCard } from '../common/GlassCard';
import { Shield, MapPin, HeartHandshake, CheckCircle2, Award, FileText, ArrowUpRight } from 'lucide-react';

export const MissionSection: React.FC = () => {
  const protectedSchemes = [
    {
      titleMarathi: 'मुख्यमंत्री माझी लाडकी बहीण योजना',
      titleEnglish: 'Mukhyamantri Majhi Ladki Bahin Yojana',
      desc: 'Protection against fake APK installations, phishing registration forms, and malicious OTP requests aimed at rural and grassroots women beneficiaries.',
      tag: 'Social Welfare Fraud'
    },
    {
      titleMarathi: 'महावितरण (MSEDCL) वीज बिल फसवणूक',
      titleEnglish: 'MSEDCL Electricity Power Cut Scams',
      desc: 'Detection of urgent evening SMS threats claiming electric connection suspension, preventing remote access APK deployment and banking compromise.',
      tag: 'Utility Impersonation'
    },
    {
      titleMarathi: 'पीएम किसान सन्मान निधी e-KYC',
      titleEnglish: 'PM Kisan Samman Nidhi e-KYC Phishing',
      desc: 'Identification of deceptive farmer subsidy update portals, spoofed banking verification links, and Aadhaar-harvesting clone websites.',
      tag: 'Agrarian Defense'
    },
    {
      titleMarathi: 'महाडीबीटी शिष्यवृत्ती पोर्टल क्लोन',
      titleEnglish: 'MahaDBT Scholarship Impersonation',
      desc: 'Defending students and educational applicants from fraudulent fee-waiver portals and unauthorized banking credential requests.',
      tag: 'Education & Youth'
    }
  ];

  return (
    <section id="mission" className="py-24 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto border-t border-soft-stone/60">
      {/* Header */}
      <div className="text-center max-w-3xl mx-auto mb-16">
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-mineral-teal/10 border border-mineral-teal/20 text-mineral-teal text-xs font-semibold tracking-wide uppercase mb-4">
          <HeartHandshake className="w-3.5 h-3.5" />
          Indigenous Digital Defense
        </div>
        <h2 className="text-3xl sm:text-4xl font-bold text-deep-graphite tracking-tight mb-4 font-display">
          Maharashtra Cyber Defense Mission
        </h2>
        <p className="text-slate-grey text-base sm:text-lg leading-relaxed">
          Seva Cyber Sandbox was conceived and engineered as an independent, local-first cyber defense tool specifically attuned to the vernacular threat landscape of Maharashtra.
        </p>
      </div>

      {/* Bilingual Mission Statement Banner */}
      <GlassCard className="p-8 sm:p-10 mb-12 shadow-xl border-soft-stone bg-porcelain/90 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-mineral-teal/5 rounded-full blur-3xl -z-10"></div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-center">
          <div>
            <div className="text-xs font-bold text-mineral-teal tracking-wider uppercase mb-2">ध्येय आणि उद्दिष्ट (Marathi)</div>
            <p className="text-base sm:text-lg text-deep-graphite font-serif leading-relaxed italic">
              &ldquo;महाराष्ट्रातील प्रत्येक नागरिकाला, शेतकऱ्याला आणि भगिनीला डिजिटल फसवणुकीपासून सुरक्षित ठेवणे हेच सेवा सायबर सँडबॉक्सचे अंतिम ध्येय आहे. शून्य खर्च, संपूर्ण गोपनीयता आणि स्थानिक विश्लेषणाद्वारे सायबर सुरक्षा सर्वांसाठी उपलब्ध करणे.&rdquo;
            </p>
          </div>
          <div className="border-t md:border-t-0 md:border-l border-soft-stone/80 pt-6 md:pt-0 md:pl-8">
            <div className="text-xs font-bold text-slate-grey tracking-wider uppercase mb-2">Mission Statement (English)</div>
            <p className="text-sm sm:text-base text-slate-grey leading-relaxed">
              &ldquo;To provide indigenous, free, and completely air-gapped cybersecurity analysis to the citizens of Maharashtra. By eliminating dependence on expensive cloud APIs and safeguarding citizen privacy, Seva transforms grassroots cyber defense into an accessible reality.&rdquo;
            </p>
          </div>
        </div>
      </GlassCard>

      {/* Targeted Scheme Protection Grid */}
      <div className="mb-16">
        <h3 className="text-xl font-bold text-deep-graphite mb-6 text-center">
          Grassroots Threat Vectors Countered
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {protectedSchemes.map((scheme, idx) => (
            <GlassCard key={idx} className="p-6 shadow-md border border-soft-stone hover:border-mineral-teal/50 transition-all">
              <div className="flex items-center justify-between mb-3">
                <span className="text-[11px] font-semibold text-mineral-teal bg-mineral-teal/10 px-2.5 py-0.5 rounded-full border border-mineral-teal/20">
                  {scheme.tag}
                </span>
                <Shield className="w-4 h-4 text-slate-grey/60" />
              </div>
              <h4 className="text-base font-bold text-deep-graphite font-serif">{scheme.titleMarathi}</h4>
              <div className="text-xs font-semibold text-slate-grey mb-2">{scheme.titleEnglish}</div>
              <p className="text-xs text-slate-grey leading-relaxed">{scheme.desc}</p>
            </GlassCard>
          ))}
        </div>
      </div>

      {/* Platform Pillars */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-16">
        <GlassCard className="p-6 text-center">
          <div className="w-12 h-12 rounded-full bg-mineral-teal/10 text-mineral-teal flex items-center justify-center mx-auto mb-4">
            <Award className="w-6 h-6" />
          </div>
          <h4 className="text-sm font-bold text-deep-graphite mb-2">&#8377;0 Cloud Sovereignty</h4>
          <p className="text-xs text-slate-grey leading-relaxed">
            Runs entirely on local hardware with zero recurring costs, zero cloud telemetry, and zero foreign API reliance.
          </p>
        </GlassCard>

        <GlassCard className="p-6 text-center">
          <div className="w-12 h-12 rounded-full bg-muted-copper/10 text-muted-copper flex items-center justify-center mx-auto mb-4">
            <CheckCircle2 className="w-6 h-6" />
          </div>
          <h4 className="text-sm font-bold text-deep-graphite mb-2">Mathematical Rigor</h4>
          <p className="text-xs text-slate-grey leading-relaxed">
            Validated by 870 automated pytests. Strict 8-point eligibility gate prevents model poisoning from unreviewed inputs.
          </p>
        </GlassCard>

        <GlassCard className="p-6 text-center">
          <div className="w-12 h-12 rounded-full bg-emerald-100 text-emerald-800 flex items-center justify-center mx-auto mb-4">
            <MapPin className="w-6 h-6" />
          </div>
          <h4 className="text-sm font-bold text-deep-graphite mb-2">Vernacular Intelligence</h4>
          <p className="text-xs text-slate-grey leading-relaxed">
            Native support for Devanagari Unicode homoglyphs, Marathi phonetics, and local Indian banking nomenclature.
          </p>
        </GlassCard>
      </div>

      {/* Footer / Colophon */}
      <div className="border-t border-soft-stone/80 pt-8 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-grey gap-4">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-deep-graphite">Seva Cyber Sandbox</span>
          <span>&bull;</span>
          <span>Liquid Glass Edition v7.1.0</span>
          <span>&bull;</span>
          <span>Released for Public Cyber Defense</span>
        </div>
        <div className="flex items-center gap-4">
          <a
            href="http://localhost:8501"
            target="_blank"
            rel="noreferrer"
            className="text-mineral-teal hover:underline flex items-center gap-1"
          >
            Classic Streamlit Portal <ArrowUpRight className="w-3 h-3" />
          </a>
          <span className="text-slate-grey/50">|</span>
          <span>State of Maharashtra, India</span>
        </div>
      </div>
    </section>
  );
};
