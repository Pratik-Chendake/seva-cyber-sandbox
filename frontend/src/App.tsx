import React, { useState, useEffect } from 'react';
import { Navbar } from './components/common/Navbar';
import { HeroSection } from './components/sections/HeroSection';
import { ToolkitSection } from './components/sections/ToolkitSection';
import { PhishingSection } from './components/sections/PhishingSection';
import { ApkSection } from './components/sections/ApkSection';
import { InvestigationSection } from './components/sections/InvestigationSection';
import { ThreatNetworkSection } from './components/sections/ThreatNetworkSection';
import { AiLabSection } from './components/sections/AiLabSection';
import { PrivacySection } from './components/sections/PrivacySection';
import { HealthSection } from './components/sections/HealthSection';
import { MissionSection } from './components/sections/MissionSection';
import { apiClient } from './services/api';
import { HealthResponse } from './types';
import { ArrowUp } from 'lucide-react';

export function App() {
  const [activeSection, setActiveSection] = useState<string>('hero');
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [showScrollTop, setShowScrollTop] = useState(false);

  // Poll system health once at mount
  useEffect(() => {
    const fetchHealth = async () => {
      try {
        const data = await apiClient.getHealth();
        setHealth(data);
      } catch (e) {
        console.warn('Initial health check notice:', e);
      }
    };
    fetchHealth();
  }, []);

  // IntersectionObserver to track active section during vertical scroll
  useEffect(() => {
    const sectionIds = [
      'hero',
      'toolkit',
      'phishing',
      'apk-lab',
      'investigation',
      'threat-network',
      'ai-lab',
      'privacy',
      'health',
      'mission'
    ];

    const observers: IntersectionObserver[] = [];

    sectionIds.forEach((id) => {
      const element = document.getElementById(id);
      if (!element) return;

      const observer = new IntersectionObserver(
        (entries) => {
          entries.forEach((entry) => {
            if (entry.isIntersecting) {
              setActiveSection(id);
            }
          });
        },
        { threshold: 0.25, rootMargin: '-80px 0px -40% 0px' }
      );

      observer.observe(element);
      observers.push(observer);
    });

    const handleScroll = () => {
      setShowScrollTop(window.scrollY > 600);
    };

    window.addEventListener('scroll', handleScroll, { passive: true });

    return () => {
      observers.forEach((obs) => obs.disconnect());
      window.removeEventListener('scroll', handleScroll);
    };
  }, []);

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="min-h-screen bg-porcelain text-deep-graphite font-sans selection:bg-mineral-teal/20 selection:text-mineral-teal relative overflow-x-hidden">
      {/* Background ambient liquid glass illumination */}
      <div className="fixed inset-0 pointer-events-none -z-10 overflow-hidden">
        <div className="absolute -top-40 -left-40 w-[600px] h-[600px] rounded-full bg-mineral-teal/5 blur-[120px]" />
        <div className="absolute top-1/3 -right-40 w-[500px] h-[500px] rounded-full bg-muted-copper/5 blur-[140px]" />
        <div className="absolute top-2/3 left-10 w-[550px] h-[550px] rounded-full bg-pale-sage/20 blur-[130px]" />
      </div>

      {/* Floating Liquid Glass Navigation */}
      <Navbar health={health} activeSection={activeSection} />

      {/* Continuous Vertical Narrative Scroll (All 10 Sections) */}
      <main className="relative">
        {/* Section 01: Hero - 3D Security Core */}
        <HeroSection />

        {/* Section 02: Interactive Security Toolkit */}
        <ToolkitSection />

        {/* Section 03: Phishing Intelligence Workspace */}
        <PhishingSection />

        {/* Section 04: Interactive APK Analysis Lab */}
        <ApkSection />

        {/* Section 05: Interactive Investigation Center */}
        <InvestigationSection />

        {/* Section 06: Interactive 3D Threat Network */}
        <ThreatNetworkSection />

        {/* Section 07: Adaptive AI Laboratory */}
        <AiLabSection />

        {/* Section 08: Privacy, Security and Fail-Closed Gate */}
        <PrivacySection />

        {/* Section 09: System Health and Platform Diagnostics */}
        <HealthSection />

        {/* Section 10: Maharashtra Cyber Defense Mission */}
        <MissionSection />
      </main>

      {/* Back to Top floating pill */}
      {showScrollTop && (
        <button
          onClick={scrollToTop}
          className="fixed bottom-6 right-6 z-40 p-3 rounded-full liquid-glass-elevated border border-soft-stone text-deep-graphite hover:text-mineral-teal hover:border-mineral-teal/40 transition-all shadow-lg cursor-pointer"
          aria-label="Scroll to top"
        >
          <ArrowUp className="w-5 h-5" />
        </button>
      )}
    </div>
  );
}

export default App;
