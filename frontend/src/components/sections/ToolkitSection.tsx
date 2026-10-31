import React from 'react';
import { GlassCard } from '../common/GlassCard';
import {
  MessageSquareWarning,
  FileCode2,
  FolderSearch,
  Network,
  Cpu,
  LockKeyhole,
  ArrowRight,
  ExternalLink,
} from 'lucide-react';

interface ToolkitSectionProps {
  onSelectTool?: (toolId: string) => void;
}

export const ToolkitSection: React.FC<ToolkitSectionProps> = ({
  onSelectTool = (toolId: string) => document.getElementById(toolId)?.scrollIntoView({ behavior: 'smooth' }),
}) => {
  const tools = [
    {
      id: 'phishing',
      icon: MessageSquareWarning,
      tag: 'VERNACULAR & SMS',
      title: 'Phishing Intelligence Radar',
      description:
        'Analyzes Marathi (देवनागरी), Romanized Marathi, and English messages for electricity disconnections, fake banking lures, and fraudulent government scheme portals.',
      color: '#477C78',
      action: 'Launch Radar',
    },
    {
      id: 'apk-lab',
      icon: FileCode2,
      tag: 'IN-MEMORY STATIC',
      title: 'APK Static Security Lab',
      description:
        'Inspects Android `.apk` archives without decompilation or execution. Analyzes AndroidManifest.xml, DEX headers, declared permissions, and embedded network strings.',
      color: '#B8794B',
      action: 'Inspect Package',
    },
    {
      id: 'investigation',
      icon: FolderSearch,
      tag: 'EVIDENCE PROVENANCE',
      title: 'Investigation Center',
      description:
        'Manages multi-artifact cybersecurity investigations. Preserves parent-child links between messages, URLs, and APKs with citizen GDPR withdrawal tracking.',
      color: '#202C32',
      action: 'Explore Cases',
    },
    {
      id: 'threat-network',
      icon: Network,
      tag: '3D TOPOLOGY',
      title: 'Threat Intelligence Network',
      description:
        'Interactive 3D network visualization connecting active campaign clusters, confirmed threat domains, APK hashes, and unreviewed citizen-submitted indicators.',
      color: '#477C78',
      action: 'View 3D Graph',
    },
    {
      id: 'ai-lab',
      icon: Cpu,
      tag: 'SHADOW TELEMETRY',
      title: 'Adaptive AI Laboratory',
      description:
        'Observes custom scratch 3-layer MLP neural classifier. Monitors concordance with deterministic rules in shadow mode while preventing unvetted model self-promotion.',
      color: '#B8794B',
      action: 'Enter AI Lab',
    },
    {
      id: 'privacy',
      icon: LockKeyhole,
      tag: 'FAIL-CLOSED POLICY',
      title: 'Privacy Gate & Sanitizer',
      description:
        'Enforces deterministic Aadhaar and phone number redaction. Zero PII storage in threat intelligence; strictly local execution with zero cloud telemetry.',
      color: '#202C32',
      action: 'Test Sanitizer',
    },
  ];

  return (
    <section id="toolkit" className="py-20 relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Heading */}
        <div className="max-w-3xl mb-12">
          <div className="caption-label mb-2 text-[#477C78]">02 // CORE CAPABILITIES</div>
          <h2 className="text-3xl sm:text-4xl font-bold text-[#202C32] tracking-tight mb-4">
            Unified Cybersecurity Toolkit
          </h2>
          <p className="text-[#738087] text-base leading-relaxed">
            Every security tool runs locally on your workstation. No external API keys, zero paid cloud dependencies,
            and complete preservation of evidence provenance.
          </p>
        </div>

        {/* 6-Card Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {tools.map((tool) => {
            const Icon = tool.icon;
            return (
              <GlassCard
                key={tool.id}
                interactive
                onClick={() => onSelectTool(tool.id)}
                className="flex flex-col justify-between group"
              >
                <div>
                  <div className="flex items-center justify-between mb-4">
                    <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-semibold tracking-wider uppercase bg-[#DFE9E1] text-[#477C78] border border-[#477C78]/20">
                      {tool.tag}
                    </span>
                    <div className="w-9 h-9 rounded-xl bg-[#FAF8F2] flex items-center justify-center text-[#202C32] group-hover:scale-110 transition-transform shadow-xs">
                      <Icon className="w-5 h-5 text-[#477C78]" />
                    </div>
                  </div>

                  <h3 className="text-lg font-bold text-[#202C32] mb-2 group-hover:text-[#477C78] transition-colors">
                    {tool.title}
                  </h3>

                  <p className="text-xs text-[#738087] leading-relaxed mb-6">
                    {tool.description}
                  </p>
                </div>

                <div className="pt-4 border-t border-[#DDDCD3]/60 flex items-center justify-between text-xs font-semibold text-[#477C78] group-hover:text-[#202C32] transition-colors">
                  <span>{tool.action}</span>
                  <ArrowRight className="w-4 h-4 transform group-hover:translate-x-1 transition-transform" />
                </div>
              </GlassCard>
            );
          })}
        </div>
      </div>
    </section>
  );
};
