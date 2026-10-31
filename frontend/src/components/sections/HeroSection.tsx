import React, { Suspense } from 'react';
import { ThreeLoadingFallback } from '../common/ThreeLoadingFallback';
import { Shield, ArrowRight, Database, Cpu, Lock, CheckCircle2 } from 'lucide-react';
import { HealthResponse } from '../../types';

const SecurityCore3D = React.lazy(() =>
  import('../3d/SecurityCore3D').then((m) => ({ default: m.SecurityCore3D }))
);

interface HeroSectionProps {
  health?: HealthResponse | null;
  onExploreToolkit?: () => void;
  onOpenPhishing?: () => void;
  onOpenCases?: () => void;
}

export const HeroSection: React.FC<HeroSectionProps> = ({
  health,
  onExploreToolkit = () => document.getElementById('toolkit')?.scrollIntoView({ behavior: 'smooth' }),
  onOpenPhishing = () => document.getElementById('phishing')?.scrollIntoView({ behavior: 'smooth' }),
  onOpenCases = () => document.getElementById('investigation')?.scrollIntoView({ behavior: 'smooth' }),
}) => {
  return (
    <section id="hero" className="relative min-h-[92vh] flex items-center pt-24 pb-16 overflow-hidden">
      {/* Background Soft Refractive Glows */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-[#477C78]/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-[#B8794B]/10 rounded-full blur-3xl pointer-events-none" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 w-full">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
          {/* Left Column: Editorial Hero Typography & CTAs */}
          <div className="lg:col-span-7 space-y-6">
            <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full liquid-glass text-xs text-[#202C32] shadow-sm">
              <span className="w-2 h-2 rounded-full bg-[#477C78] animate-pulse" />
              <span className="font-mono text-[11px] font-semibold tracking-wider uppercase text-[#477C78]">
                MAHARASHTRA CYBER DEFENSE INITIATIVE
              </span>
            </div>

            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold text-[#202C32] tracking-tight leading-[1.12]">
              The Sovereign Local Cyber Defense & Evidence Platform
            </h1>

            <p className="text-base sm:text-lg text-[#738087] leading-relaxed max-w-2xl">
              Engineered for grassroots digital safety across Maharashtra. Combines deterministic
              cybersecurity rules, official Government Resolution verification, and static APK
              forensics with a custom scratch neural network executing in verifiable shadow mode.
            </p>

            {/* CTAs */}
            <div className="flex flex-wrap items-center gap-4 pt-2">
              <button
                onClick={onOpenPhishing}
                className="px-6 py-3.5 rounded-2xl bg-[#477C78] hover:bg-[#3b6764] text-white font-medium text-sm transition-all duration-200 shadow-md hover:shadow-lg flex items-center gap-2 cursor-pointer"
              >
                <span>Launch Unified Evidence Intake</span>
                <ArrowRight className="w-4 h-4" />
              </button>

              <button
                onClick={onExploreToolkit}
                className="px-6 py-3.5 rounded-2xl liquid-glass hover:bg-white/80 text-[#202C32] font-medium text-sm transition-all duration-200 shadow-sm hover:shadow flex items-center gap-2 cursor-pointer"
              >
                <span>Explore Security Toolkit</span>
              </button>

              <button
                onClick={onOpenCases}
                className="px-5 py-3.5 rounded-2xl liquid-glass text-[#738087] hover:text-[#202C32] font-mono text-xs transition cursor-pointer"
              >
                <span>Threat Cases Database</span>
              </button>
            </div>

            {/* Architecture Governance Ribbon */}
            <div className="grid grid-cols-3 gap-3 pt-6 border-t border-[#DDDCD3]/60 max-w-xl">
              <div className="p-3 rounded-xl liquid-glass">
                <div className="flex items-center gap-1.5 text-xs text-[#738087] mb-1">
                  <Shield className="w-3.5 h-3.5 text-[#477C78]" />
                  <span>Rule Engine</span>
                </div>
                <div className="font-mono font-bold text-xs text-[#202C32]">100% Authoritative</div>
              </div>

              <div className="p-3 rounded-xl liquid-glass">
                <div className="flex items-center gap-1.5 text-xs text-[#738087] mb-1">
                  <Cpu className="w-3.5 h-3.5 text-[#B8794B]" />
                  <span>Neural Model</span>
                </div>
                <div className="font-mono font-bold text-xs text-[#202C32]">Shadow (Δ = 0.00)</div>
              </div>

              <div className="p-3 rounded-xl liquid-glass">
                <div className="flex items-center gap-1.5 text-xs text-[#738087] mb-1">
                  <Lock className="w-3.5 h-3.5 text-[#477C78]" />
                  <span>Network Policy</span>
                </div>
                <div className="font-mono font-bold text-xs text-[#202C32]">Zero Cloud Calls</div>
              </div>
            </div>
          </div>

          {/* Right Column: 3D Interactive Security Core */}
          <div className="lg:col-span-5 flex justify-center items-center">
            <div className="w-full max-w-lg aspect-square">
              <Suspense fallback={<ThreeLoadingFallback label="Loading Security Core 3D..." />}>
                <SecurityCore3D onSelectCore={onOpenPhishing} />
              </Suspense>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};
